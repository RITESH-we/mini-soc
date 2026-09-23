import os, sys, yaml, io, csv, json, re
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from flask import Flask, render_template, jsonify, request, redirect, url_for, send_file, Response, session
from database.models import get_conn, init_db, check_password, hash_password
from datetime import datetime
from reports.ir_generator import generate_pdf_report
from network.ips_responder import block_ip, unblock_ip, list_blocked_ips
from network.nsm_engine import inspect_network_activity, get_recent_network_alerts
from ai.humanoid_analyst import nova
from detectors.ueba_engine import calculate_entity_risk, get_top_risky_entities
from collectors.unified_parser import parse_windows_event_xml, parse_linux_auth_log_line

CONFIG_PATH = os.path.join(BASE_DIR, 'config.yaml')
if os.path.exists(CONFIG_PATH):
    with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f) or {}
else:
    # CI / fresh-clone fallback — safe defaults, no secrets exposed
    config = {
        'secret_key': os.environ.get('MINISOC_SECRET_KEY', 'minisoc-ci-fallback-key-changeme'),
        'dashboard': {'host': '0.0.0.0', 'port': 5000, 'debug': False},
    }

app = Flask(__name__)
app.secret_key = config.get('secret_key', 'minisoc-enterprise-secret-key-2026-auth')
init_db()

# ── Authentication Gatekeeper & Session Management ────────────
EXEMPT_ROUTES = {
    '/login', '/logout', '/health', '/api/health',
    '/api/v1/telemetry', '/api/v1/ingest/cloud', '/api/v1/cloud/ingest'
}

@app.before_request
def auth_gatekeeper():
    if request.path.startswith('/static') or request.path in EXEMPT_ROUTES:
        return None
    if 'user' not in session:
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Authentication required', 'session_expired': True}), 401
        return redirect(url_for('login_view', next=request.path))

@app.route('/login', methods=['GET', 'POST'])
def login_view():
    error = None
    next_url = request.args.get('next') or request.form.get('next') or '/'
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip().lower()
        password = (request.form.get('password') or '').strip()
        conn = get_conn()
        try:
            user = conn.execute("SELECT * FROM users WHERE LOWER(username)=?", (username,)).fetchone()
            if user and check_password(password, user['password']):
                # Auto-rehash plaintext passwords on first successful login
                if len(user['password']) != 64:
                    conn.execute("UPDATE users SET password=? WHERE id=?",
                                 (hash_password(password), user['id']))
                    conn.commit()
                session['user'] = user['username']
                session['role'] = user['role']
                session['display_name'] = user['display_name'] or user['username']
                return redirect(next_url if (next_url and next_url.startswith('/')) else '/')
            else:
                error = "Invalid User ID or Password. Check credentials and retry."
        finally:
            conn.close()
    return render_template('login.html', error=error, next_url=next_url)

@app.route('/logout')
def logout_view():
    session.clear()
    return redirect(url_for('login_view'))

# ── Real-Time Metrics API (Continuous Stream Sync) ────────────
@app.route('/api/live/metrics')
def api_live_metrics():
    conn         = get_conn()
    total_alerts = conn.execute('SELECT COUNT(*) FROM alerts').fetchone()[0]
    open_alerts  = conn.execute("SELECT COUNT(*) FROM alerts WHERE status='OPEN'").fetchone()[0]
    critical_high= conn.execute("SELECT COUNT(*) FROM alerts WHERE severity IN ('CRITICAL', 'HIGH')").fetchone()[0]
    open_inc     = conn.execute("SELECT COUNT(*) FROM incidents WHERE status!='CLOSED'").fetchone()[0]
    
    total_eps    = conn.execute('SELECT COUNT(*) FROM endpoints').fetchone()[0]
    online_eps   = conn.execute("SELECT COUNT(*) FROM endpoints WHERE status='ONLINE'").fetchone()[0]
    isolated_eps = conn.execute("SELECT COUNT(*) FROM endpoints WHERE status='ISOLATED'").fetchone()[0]
    blocked_count = conn.execute("SELECT COUNT(*) FROM blocked_ips WHERE active=1").fetchone()[0]
    recent       = [dict(r) for r in conn.execute('SELECT * FROM alerts ORDER BY id DESC LIMIT 15').fetchall()]
    conn.close()
    
    return jsonify({
        'total_alerts': total_alerts,
        'open_alerts': open_alerts,
        'critical_high': critical_high,
        'open_inc': open_inc,
        'total_endpoints': total_eps,
        'online_endpoints': online_eps,
        'isolated_endpoints': isolated_eps,
        'blocked_ips_count': blocked_count,
        'recent_alerts': recent,
        'timestamp': datetime.now().isoformat()
    })

def get_all_devices(conn):
    alert_devs = [r[0] for r in conn.execute("SELECT DISTINCT device_name FROM alerts WHERE device_name IS NOT NULL AND device_name!=''").fetchall()]
    ep_devs = [r[0] for r in conn.execute("SELECT DISTINCT hostname FROM endpoints WHERE hostname IS NOT NULL").fetchall()]
    all_devs = sorted(list(set(alert_devs + ep_devs)))
    return all_devs

# ── Home Dashboard ────────────────────────────────────────────
@app.route('/')
def index():
    conn         = get_conn()
    total_alerts = conn.execute('SELECT COUNT(*) FROM alerts').fetchone()[0]
    open_alerts  = conn.execute("SELECT COUNT(*) FROM alerts WHERE status='OPEN'").fetchone()[0]
    critical_high= conn.execute("SELECT COUNT(*) FROM alerts WHERE severity IN ('CRITICAL', 'HIGH')").fetchone()[0]
    open_inc     = conn.execute("SELECT COUNT(*) FROM incidents WHERE status!='CLOSED'").fetchone()[0]
    
    total_eps    = conn.execute('SELECT COUNT(*) FROM endpoints').fetchone()[0]
    online_eps   = conn.execute("SELECT COUNT(*) FROM endpoints WHERE status='ONLINE'").fetchone()[0]
    isolated_eps = conn.execute("SELECT COUNT(*) FROM endpoints WHERE status='ISOLATED'").fetchone()[0]
    
    blocked_count = conn.execute("SELECT COUNT(*) FROM blocked_ips WHERE active=1").fetchone()[0]
    devices      = get_all_devices(conn)
    recent       = conn.execute('SELECT * FROM alerts ORDER BY id DESC LIMIT 15').fetchall()
    
    top_risks_raw = conn.execute('SELECT * FROM entity_risk_scores ORDER BY risk_score DESC LIMIT 5').fetchall()
    top_risks = []
    for r in top_risks_raw:
        item = dict(r)
        try:
            item['factors'] = json.loads(item.get('factors') or '[]')
        except Exception:
            item['factors'] = []
        top_risks.append(item)
    conn.close()
    
    return render_template('index.html',
        total_alerts=total_alerts, open_alerts=open_alerts,
        critical_high=critical_high, open_inc=open_inc,
        total_endpoints=total_eps, online_endpoints=online_eps,
        isolated_endpoints=isolated_eps, blocked_ips_count=blocked_count,
        devices=devices, recent=recent, top_risks=top_risks)

# ── Alerts Triage ─────────────────────────────────────────────
@app.route('/alerts')
def alerts():
    sev      = request.args.get('severity', 'ALL')
    cat      = request.args.get('category', 'ALL')
    device   = request.args.get('device', '')
    conn     = get_conn()
    devices  = get_all_devices(conn)

    query  = 'SELECT * FROM alerts WHERE 1=1'
    params = []

    if sev != 'ALL':
        query += ' AND severity=?'
        params.append(sev)

    if cat != 'ALL':
        query += ' AND threat_category=?'
        params.append(cat)
        
    if device:
        query += ' AND (device_name=? OR src_user=?)'
        params.extend([device, device])

    query += ' ORDER BY id DESC LIMIT 300'
    rows = conn.execute(query, params).fetchall()

    blocked_rows = conn.execute("SELECT ip_address FROM blocked_ips WHERE active=1").fetchall()
    blocked_ips_set = set(r['ip_address'] for r in blocked_rows)
    conn.close()

    return render_template('alerts.html', alerts=rows, severity=sev, category=cat,
                           devices=devices, current_device=device, blocked_ips=blocked_ips_set)

@app.route('/api/alerts/export')
def export_alerts_csv():
    device = request.args.get('device', '')
    cat    = request.args.get('category', 'ALL')
    conn   = get_conn()
    query  = 'SELECT * FROM alerts WHERE 1=1'
    params = []
    if device:
        query += ' AND (device_name=? OR src_user=?)'
        params.extend([device, device])
    if cat != 'ALL':
        query += ' AND threat_category=?'
        params.append(cat)
    query += ' ORDER BY id DESC'
    rows = conn.execute(query, params).fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Timestamp', 'Device', 'Severity', 'Category', 'Rule Name', 'MITRE Technique', 'Target User', 'Source IP', 'VT Score', 'Abuse Score', 'Status', 'Description'])
    
    for r in rows:
        writer.writerow([
            r['id'], r['timestamp'], r['device_name'] or 'Localhost',
            r['severity'], r.get('threat_category', 'GENERAL'), r['rule_name'], r['mitre_technique'] or 'N/A',
            r['src_user'] or '-', r['src_ip'] or '-', r['vt_score'] or '-',
            r['abuse_score'] if r['abuse_score'] is not None else '-',
            r['status'], r['description'] or ''
        ])
    
    filename = f"MiniSOC_Alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename={filename}"}
    )

# ── Threat Hunting Console ────────────────────────────────────
@app.route('/hunting')
def hunting_view():
    return render_template('hunting.html')

@app.route('/api/hunting/run')
def api_hunting_run():
    htype = request.args.get('type', 'lolbins')
    start_t = datetime.now()
    conn = get_conn()

    results = []
    playbook_name = "Custom Hunt"

    if htype == 'lolbins':
        playbook_name = "LOLBins & Script Interpreters (T1059)"
        targets = ['powershell', 'certutil', 'cmd.exe', 'mshta', 'wscript', 'cscript', 'bitsadmin']
        clause = " OR ".join(["LOWER(details) LIKE ?" for _ in targets])
        params = [f"%{t}%" for t in targets]
        results = conn.execute(f"SELECT * FROM telemetry_logs WHERE log_type='PROCESS' AND ({clause}) ORDER BY id DESC LIMIT 50", params).fetchall()

    elif htype == 'suspicious_ports':
        playbook_name = "Anomalous Outbound Ports (T1071)"
        ports = [':4444', ':1337', ':8888', ':7070', ':9001', ':6667', ':31337']
        clause = " OR ".join(["details LIKE ?" for _ in ports])
        params = [f"%{p}%" for p in ports]
        results = conn.execute(f"SELECT * FROM telemetry_logs WHERE log_type='NETWORK_CONN' AND ({clause}) ORDER BY id DESC LIMIT 50", params).fetchall()

    elif htype == 'recon':
        playbook_name = "Host & Network Reconnaissance (T1087 / T1082)"
        tools = ['whoami', 'net user', 'net group', 'tasklist', 'ipconfig', 'nltest', 'systeminfo']
        clause = " OR ".join(["LOWER(details) LIKE ?" for _ in targets if targets] if 'targets' in locals() else ["LOWER(details) LIKE ?" for _ in tools])
        params = [f"%{t}%" for t in tools]
        results = conn.execute(f"SELECT * FROM telemetry_logs WHERE ({clause}) ORDER BY id DESC LIMIT 50", params).fetchall()

    elif htype == 'auth':
        playbook_name = "Cross-Host Authentication Anomalies (T1110)"
        results = conn.execute("SELECT * FROM telemetry_logs WHERE log_type='SECURITY_EVENT' OR details LIKE '%4625%' ORDER BY id DESC LIMIT 50").fetchall()

    conn.close()
    duration = int((datetime.now() - start_t).total_seconds() * 1000)

    return jsonify({
        'playbook_name': playbook_name,
        'duration_ms': duration,
        'results': [dict(r) for r in results]
    })

# ── Escalate Alert to Incident ────────────────────────────────
@app.route('/api/alert/<int:aid>/escalate', methods=['POST'])
def escalate_alert(aid):
    conn = get_conn()
    alert = conn.execute('SELECT * FROM alerts WHERE id=?', (aid,)).fetchone()
    if not alert:
        conn.close()
        return jsonify({'error': 'alert not found'}), 404

    dev = alert['device_name'] or 'Remote Endpoint'
    title = f"SEC-INC: {alert['rule_name']} detected on {dev}"
    summary = (
        f"Incident automatically escalated from Alert #{aid}.\n"
        f"Rule: {alert['rule_name']} (MITRE {alert['mitre_technique'] or 'T1059'})\n"
        f"Target Host: {dev} | User: {alert['src_user'] or 'N/A'} | Source IP: {alert['src_ip'] or 'Local'}\n"
        f"Details: {alert['description'] or 'No extra description.'}"
    )

    cur = conn.execute("""
        INSERT INTO incidents (title, severity, status, analyst, created_at, updated_at, summary)
        VALUES (?, ?, 'OPEN', 'rites', ?, ?, ?)
    """, (title, alert['severity'], datetime.now().isoformat(), datetime.now().isoformat(), summary))
    new_id = cur.lastrowid

    conn.execute("UPDATE alerts SET status='CLOSED' WHERE id=?", (aid,))
    conn.commit()
    conn.close()

    return jsonify({'success': True, 'incident_id': new_id, 'title': title})

# ── Enrich Alert (VT, AbuseIPDB, ThreatFox, OTX) ──────────────
@app.route('/api/alert/<int:aid>/enrich')
def enrich_alert(aid):
    from enrichers.virustotal import lookup_ip as vt_ip
    from enrichers.abuseipdb  import lookup_ip as abuse_ip
    from enrichers.threatfox  import lookup_ioc as tf_lookup
    from enrichers.otx        import lookup_ip as otx_ip
    from network.ips_responder import is_private_ip

    conn  = get_conn()
    try:
        alert = conn.execute('SELECT * FROM alerts WHERE id=?', (aid,)).fetchone()
        if not alert:
            return jsonify({'error': 'not found'}), 404
            
        ip = (alert['src_ip'] or '').strip()

        # Check if internal private or loopback IP (RFC 1918)
        if not ip or is_private_ip(ip):
            vt_score = "Internal (RFC 1918)" if ip else "N/A"
            abuse_score = 0
            conn.execute('UPDATE alerts SET enriched=1, vt_score=?, abuse_score=? WHERE id=?',
                         (vt_score, abuse_score, aid))
            conn.commit()
            return jsonify({
                'vt_score': vt_score,
                'abuse_score': abuse_score,
                'threatfox': {'status': 'Internal RFC 1918 / Loopback Address (External Lookup Skipped)'},
                'otx': {'status': 'Internal Network'},
                'country': 'Local LAN / Host',
                'isp': 'Private RFC 1918'
            })

        vt_key    = config.get('api_keys', {}).get('virustotal')
        abuse_key = config.get('api_keys', {}).get('abuseipdb')
        otx_key   = config.get('api_keys', {}).get('otx')

        vt_result    = vt_ip(ip, vt_key)
        abuse_result = abuse_ip(ip, abuse_key)
        tf_result    = tf_lookup(ip)
        otx_result   = otx_ip(ip, otx_key)

        vt_score    = vt_result.get('score', 'N/A')
        abuse_score = abuse_result.get('score', -1)

        conn.execute('UPDATE alerts SET enriched=1, vt_score=?, abuse_score=? WHERE id=?',
                     (vt_score, abuse_score, aid))
        conn.commit()

        return jsonify({
            'vt_score': vt_score,
            'abuse_score': abuse_score,
            'threatfox': tf_result,
            'otx': otx_result,
            'country': vt_result.get('country', '') or abuse_result.get('country', ''),
            'isp': abuse_result.get('isp', '')
        })
    finally:
        conn.close()

# ── Update Alert Status ───────────────────────────────────────
@app.route('/api/alert/<int:aid>/status', methods=['POST'])
def update_status(aid):
    status = request.json.get('status', 'OPEN')
    conn   = get_conn()
    conn.execute('UPDATE alerts SET status=? WHERE id=?', (status, aid))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})

# ── Alert Full Forensic Details & Surrounding Events (Wazuh-style) ──
@app.route('/api/alert/<int:aid>/details')
def alert_full_details(aid):
    conn = get_conn()
    alert = conn.execute("SELECT * FROM alerts WHERE id=?", (aid,)).fetchone()
    conn.close()
    if not alert:
        return jsonify({"error": "Alert not found"}), 404
    
    d = dict(alert)
    raw = {}
    if d.get("raw_event"):
        try:
            raw = json.loads(d["raw_event"])
        except Exception:
            raw = {"raw_text": d["raw_event"]}
    d["parsed_raw"] = raw
    return jsonify(d)

@app.route('/api/alert/<int:aid>/surrounding')
def alert_surrounding_events(aid):
    conn = get_conn()
    alert = conn.execute("SELECT * FROM alerts WHERE id=?", (aid,)).fetchone()
    if not alert:
        conn.close()
        return jsonify({"error": "Alert not found"}), 404
    
    device = alert["device_name"]
    ts = alert["timestamp"]
    
    # Fetch temporal window: 8 events before and 8 events after on the same device
    before_rows = conn.execute("""
        SELECT * FROM telemetry_logs 
        WHERE hostname=? AND timestamp <= ?
        ORDER BY timestamp DESC LIMIT 8
    """, (device, ts)).fetchall()
    
    after_rows = conn.execute("""
        SELECT * FROM telemetry_logs 
        WHERE hostname=? AND timestamp > ?
        ORDER BY timestamp ASC LIMIT 8
    """, (device, ts)).fetchall()
    conn.close()
    
    events = list(reversed([dict(r) for r in before_rows])) + [dict(r) for r in after_rows]
    return jsonify({
        "alert_id": aid,
        "device": device,
        "alert_timestamp": ts,
        "events": events
    })

# ── Incidents ─────────────────────────────────────────────────
@app.route('/incidents')
def incidents():
    conn = get_conn()
    rows = conn.execute('SELECT * FROM incidents ORDER BY id DESC').fetchall()
    conn.close()
    return render_template('incidents.html', incidents=rows)

@app.route('/incidents/new', methods=['GET', 'POST'])
def new_incident():
    if request.method == 'POST':
        conn = get_conn()
        conn.execute(
            'INSERT INTO incidents (title,severity,summary,created_at,updated_at) VALUES (?,?,?,?,?)',
            (request.form['title'], request.form['severity'],
             request.form['summary'],
             datetime.now().isoformat(), datetime.now().isoformat()))
        conn.commit()
        conn.close()
        return redirect(url_for('incidents'))
    return render_template('new_incident.html')

@app.route('/incidents/<int:iid>/close', methods=['POST'])
def close_incident(iid):
    conn = get_conn()
    conn.execute("UPDATE incidents SET status='CLOSED', updated_at=? WHERE id=?",
                 (datetime.now().isoformat(), iid))
    conn.commit()
    conn.close()
    return redirect(url_for('incidents'))

@app.route('/incidents/<int:iid>/report')
def download_incident_report(iid):
    conn = get_conn()
    inc = conn.execute("SELECT * FROM incidents WHERE id=?", (iid,)).fetchone()
    if not inc:
        conn.close()
        return "Incident not found", 404
    alerts = conn.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 5").fetchall()
    conn.close()
    
    reports_dir = os.path.join(BASE_DIR, 'reports_generated')
    os.makedirs(reports_dir, exist_ok=True)
    pdf_filename = f"Incident_Report_{iid}_{datetime.now().strftime('%Y%m%d%H%M%S')}.pdf"
    output_path = os.path.join(reports_dir, pdf_filename)
    
    generate_pdf_report(
        incident_id=inc['id'],
        title=inc['title'],
        severity=inc['severity'],
        analyst=inc['analyst'],
        created_at=inc['created_at'],
        summary=inc['summary'],
        alerts=[dict(a) for a in alerts],
        output_path=output_path
    )
    return send_file(output_path, as_attachment=True, download_name=pdf_filename)

# ── Network Security Monitoring (NSM) & IPS ───────────────────
@app.route('/network')
def network_view():
    net_alerts = get_recent_network_alerts(limit=50)
    blocked = list_blocked_ips()
    active_blocked = set(b['ip_address'] for b in blocked if b.get('active') == 1)
    return render_template('network.html', net_alerts=net_alerts, blocked_ips=blocked, active_blocked=active_blocked)

@app.route('/network/block', methods=['POST'])
@app.route('/api/network/block', methods=['POST'])
def handle_manual_block():
    req_json = request.get_json(silent=True) or {}
    if not isinstance(req_json, dict):
        req_json = {}
    ip = (req_json.get('ip') or req_json.get('ip_address') or request.form.get('ip') or request.form.get('ip_address') or '').strip()
    reason = req_json.get('reason') or request.form.get('reason', 'Analyst Manual Block')
    containment_profile = req_json.get('containment_profile') or request.form.get('containment_profile', 'BIDIRECTIONAL_DROP')
    if containment_profile not in ['BIDIRECTIONAL_DROP', 'OUTBOUND_C2_DROP', 'HOST_QUARANTINE']:
        containment_profile = 'BIDIRECTIONAL_DROP'
    if ip:
        block_ip(ip, reason=reason, containment_profile=containment_profile)
        # Push proactive EDR drop rule down to all active endpoint agents
        conn = get_conn()
        try:
            cmd_json = json.dumps({"action": "block_remote_ip", "target": ip, "reason": reason, "containment_profile": containment_profile})
            conn.execute("UPDATE endpoints SET pending_command=? WHERE status != 'OFFLINE'", (cmd_json,))
            conn.commit()
        finally:
            conn.close()
    if request.is_json or request.path.startswith('/api/'):
        return jsonify({'success': True, 'ip': ip, 'action': 'blocked', 'containment_profile': containment_profile})
    return redirect(url_for('network_view'))

@app.route('/api/agents/<hostname>/profile', methods=['POST'])
def update_agent_profile(hostname):
    req_json = request.get_json(silent=True) or {}
    new_profile = req_json.get('profile') or request.form.get('profile', 'standard_workstation')
    if new_profile not in ['standard_workstation', 'high_security_server', 'audit_friend']:
        return jsonify({'error': 'Invalid policy profile. Choose standard_workstation, high_security_server, or audit_friend'}), 400
    conn = get_conn()
    try:
        conn.execute("UPDATE endpoints SET profile=? WHERE hostname=?", (new_profile, hostname))
        cmd_json = json.dumps({"action": "set_profile", "profile": new_profile})
        conn.execute("UPDATE endpoints SET pending_command=? WHERE hostname=?", (cmd_json, hostname))
        conn.commit()
    finally:
        conn.close()
    return jsonify({'success': True, 'hostname': hostname, 'profile': new_profile})

@app.route('/network/unblock', methods=['POST'])
@app.route('/api/network/unblock', methods=['POST'])
def handle_unblock():
    req_json = request.get_json(silent=True) or {}
    if not isinstance(req_json, dict):
        req_json = {}
    ip = (req_json.get('ip') or req_json.get('ip_address') or request.form.get('ip') or request.form.get('ip_address') or '').strip()
    if ip:
        unblock_ip(ip)
        # Push unblock command to active endpoints
        conn = get_conn()
        try:
            cmd_json = json.dumps({"action": "unblock_remote_ip", "target": ip})
            conn.execute("UPDATE endpoints SET pending_command=? WHERE status != 'OFFLINE'", (cmd_json,))
            conn.commit()
        finally:
            conn.close()
    if request.is_json or request.path.startswith('/api/'):
        return jsonify({'success': True, 'ip': ip, 'action': 'unblocked'})
    return redirect(url_for('network_view'))

@app.route('/api/network/inspect')
def api_network_inspect():
    auto_ips = config.get('network', {}).get('auto_ips_block', False)
    detected = inspect_network_activity(auto_block=auto_ips)
    return jsonify({"detected_count": len(detected), "alerts": detected})

# ── Endpoint Fleet & Live Telemetry Inspector ─────────────────
@app.route('/agents')
def agents_view():
    conn = get_conn()
    try:
        rows = conn.execute("SELECT * FROM endpoints ORDER BY last_heartbeat DESC").fetchall()
        return render_template('agents.html', endpoints=[dict(r) for r in rows], server_ip="127.0.0.1")
    finally:
        conn.close()

@app.route('/api/agents/<hostname>/logs')
def agent_logs(hostname):
    conn = get_conn()
    try:
        procs = conn.execute("SELECT * FROM telemetry_logs WHERE hostname=? AND log_type='PROCESS' ORDER BY id DESC LIMIT 25", (hostname,)).fetchall()
        conns = conn.execute("SELECT * FROM telemetry_logs WHERE hostname=? AND log_type='NETWORK_CONN' ORDER BY id DESC LIMIT 25", (hostname,)).fetchall()
        evts  = conn.execute("SELECT * FROM telemetry_logs WHERE hostname=? AND log_type='SECURITY_EVENT' ORDER BY id DESC LIMIT 15", (hostname,)).fetchall()
        return jsonify({
            'hostname': hostname,
            'processes': [dict(p) for p in procs],
            'connections': [dict(c) for c in conns],
            'events': [dict(e) for e in evts]
        })
    finally:
        conn.close()

@app.route('/api/v1/telemetry', methods=['POST'])
def receive_telemetry():
    data = request.get_json(force=True, silent=True)
    if not data or 'system' not in data:
        return jsonify({'status': 'invalid payload'}), 400

    sys_info = data['system']
    hostname = sys_info.get('hostname', 'UNKNOWN')
    ip_addr  = sys_info.get('ip_address', '127.0.0.1')
    os_name  = sys_info.get('os', 'Unknown OS')
    arch     = sys_info.get('architecture', 'x86_64')
    ver      = sys_info.get('agent_version', '2.2.0')
    now_iso  = datetime.now().isoformat()
    posture  = data.get('security_posture', {})

    conn = get_conn()
    try:
        # 1. Check for pending SOAR containment / defense commands for this endpoint
        ep_row = conn.execute("SELECT pending_command, status FROM endpoints WHERE hostname=?", (hostname,)).fetchone()
        cmd_to_send = None
        if ep_row and ep_row['pending_command']:
            raw_cmd = ep_row['pending_command']
            if raw_cmd.startswith("{"):
                try:
                    cmd_to_send = json.loads(raw_cmd)
                except Exception:
                    cmd_to_send = {"action": raw_cmd}
            else:
                cmd_to_send = {"action": raw_cmd}
            conn.execute("UPDATE endpoints SET pending_command=NULL WHERE hostname=?", (hostname,))

        # Update or insert endpoint record
        current_status = ep_row['status'] if ep_row else 'ONLINE'
        agent_profile = data.get('profile') or 'standard_workstation'
        active_profile = (ep_row['profile'] if (ep_row and ep_row['profile']) else agent_profile)
        conn.execute("""
            INSERT INTO endpoints (hostname, ip_address, os, architecture, agent_version, last_heartbeat, status, profile)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(hostname) DO UPDATE SET
                ip_address=excluded.ip_address,
                os=excluded.os,
                architecture=excluded.architecture,
                agent_version=excluded.agent_version,
                last_heartbeat=excluded.last_heartbeat
        """, (hostname, ip_addr, os_name, arch, ver, now_iso, current_status, active_profile))

        # Store security posture telemetry if provided
        if posture:
            p_desc = f"Antivirus: {posture.get('antivirus')} | Firewall: {posture.get('firewall')} | Admin Privileges: {posture.get('is_admin')}"
            conn.execute("""
                INSERT INTO telemetry_logs (hostname, timestamp, log_type, details)
                VALUES (?, ?, 'SECURITY_POSTURE', ?)
            """, (hostname, now_iso, p_desc))

        # 2. Store live telemetry into telemetry_logs table
        for p in data.get('processes', [])[:20]:
            p_desc = f"{p.get('name', 'unknown')} | PID: {p.get('pid', '-')} | Mem: {p.get('mem_usage', p.get('mem', '-'))}"
            conn.execute("""
                INSERT INTO telemetry_logs (hostname, timestamp, log_type, details, process_name)
                VALUES (?, ?, 'PROCESS', ?, ?)
            """, (hostname, now_iso, p_desc, p.get('name', '')))

        for c in data.get('connections', [])[:15]:
            c_desc = f"{c.get('proto', 'TCP')} | Remote: {c.get('remote', '-')} | State: {c.get('state', '-')} | PID: {c.get('pid', '-')}"
            remote_ip = c.get('remote', '').split(':')[0] if ':' in c.get('remote', '') else ''
            conn.execute("""
                INSERT INTO telemetry_logs (hostname, timestamp, log_type, details, src_ip)
                VALUES (?, ?, 'NETWORK_CONN', ?, ?)
            """, (hostname, now_iso, c_desc, remote_ip))

        # 3. Process structured security audit events (OCSF/ECS compliant)
        user_seen = None

        for ev in data.get('events', []):
            eid = ev.get('event_id')
            user = ev.get('user') or ''
            if user and not user_seen:
                user_seen = user
            src_ip = ev.get('src_ip') or ip_addr
            proc = ev.get('process') or ''
            cmdline = ev.get('command_line') or ''
            sev = ev.get('severity', 'LOW')
            rname = ev.get('rule_name', 'Security Event')
            tactic = ev.get('mitre_tactic', 'Execution')
            technique = ev.get('mitre_technique', 'T1059 - Command Execution')
            details = ev.get('details') or f"Event {eid} on {hostname}"
            raw_json_str = json.dumps(ev)

            # Store into telemetry_logs with structured columns
            conn.execute("""
                INSERT INTO telemetry_logs (hostname, timestamp, log_type, details, event_id, user_name, src_ip, process_name, raw_json)
                VALUES (?, ?, 'SECURITY_EVENT', ?, ?, ?, ?, ?, ?)
            """, (hostname, now_iso, details, eid, user, src_ip, proc, raw_json_str))

            # Actionable security alerts correlation across Top 5 Attack Use Cases
            should_alert = False
            alert_reason = details
            threat_cat = "GENERAL"
            low_cmd = cmdline.lower()

            # Use Case 1: Ransomware Recovery Inhibition (T1490 / T1486)
            if re.search(r"(vssadmin.*delete\s+shadows|wmic.*shadowcopy\s+delete|wbadmin.*delete\s+catalog|bcdedit.*recoveryenabled\s+no|bcdedit.*ignoreallfailures)", low_cmd) or "Shadow Copy" in rname or "Ransomware" in rname:
                should_alert = True
                rname = "Ransomware Recovery Inhibition (Shadow Copy Deletion)"
                sev = "CRITICAL"
                threat_cat = "RANSOMWARE"
                tactic = "Impact"
                technique = "T1490 - Inhibit System Recovery"
                alert_reason = f"CRITICAL RANSOMWARE ALERT: Shadow copy destruction command executed on {hostname}: {cmdline[:140]}"

            # Use Case 2: In-Memory Credential Dumping & Pass-the-Hash (T1003.001 / T1550.002)
            elif eid == 4648 or re.search(r"(mimikatz|comsvcs\.dll.*minidump|vaultcmd|cmdkey\s+/list|whoami\s+/priv|findstr.*password)", low_cmd):
                should_alert = True
                if eid == 4648:
                    rname = "Logon Attempt with Explicit Credentials (Pass-the-Hash)"
                    tactic = "Lateral Movement"
                    technique = "T1550.002 - Pass the Hash"
                    alert_reason = f"Explicit alternate credential logon from user '{user}' to '{ev.get('raw_fields', {}).get('TargetServerName', 'LOCAL')}'"
                else:
                    rname = "In-Memory Credential Dumping / LSASS Snooping"
                    tactic = "Credential Access"
                    technique = "T1003.001 - LSASS Memory"
                    alert_reason = f"Credential theft command executed on {hostname}: {cmdline[:140]}"
                sev = "HIGH"
                threat_cat = "CREDENTIAL_ACCESS"

            # Use Case 3: Living-off-the-Land Obfuscated PowerShell & Fileless Execution (T1059.001 / T1027)
            elif eid == 4104 and re.search(r"(-enc\s+|-encodedcommand\s+|amsiutils|downloadstring|iex\s*\(|invoke-expression|bitstransfer|system\.net\.webclient)", low_cmd):
                should_alert = True
                rname = "Living-off-the-Land Obfuscated PowerShell Execution"
                sev = "HIGH"
                threat_cat = "LIVING_OFF_THE_LAND"
                tactic = "Execution"
                technique = "T1059.001 - PowerShell"
                alert_reason = f"Obfuscated PowerShell script block executed on {hostname}: {cmdline[:140]}"

            # Use Case 4: Data Staging for Exfiltration (T1560)
            elif re.search(r"(compress-archive|tar\s+-[a-z]*z|7z\s+a|rar\s+a)", low_cmd):
                should_alert = True
                rname = "Data Staging for Exfiltration"
                sev = "HIGH"
                threat_cat = "EXFILTRATION"
                tactic = "Collection"
                technique = "T1560 - Archive Collected Data"
                alert_reason = f"Suspicious archive creation targeting files for exfiltration: {cmdline[:140]}"

            # Use Case 5: Rogue Persistence & Privilege Escalation (T1053.005 / T1078.003 / T1070.001)
            elif eid in [4698, 4697, 4720, 4732, 1102]:
                should_alert = True
                threat_cat = "PERSISTENCE"
                if eid == 1102:
                    rname = "Windows Audit Log Cleared"
                    sev = "CRITICAL"
                    tactic = "Defense Evasion"
                    technique = "T1070.001 - Clear Windows Event Logs"
                    alert_reason = f"Security audit log was cleared/wiped on {hostname} by '{user}' (Anti-Forensics)"
                elif eid == 4698:
                    rname = "Rogue Scheduled Task Created"
                    sev = "HIGH"
                    tactic = "Persistence"
                    technique = "T1053.005 - Scheduled Task"
                elif eid == 4697:
                    rname = "New System Service Installed"
                    sev = "HIGH"
                    tactic = "Persistence"
                    technique = "T1543.003 - Windows Service"
                elif eid == 4732:
                    rname = "Member Added to Security Group"
                    sev = "HIGH"
                    tactic = "Privilege Escalation"
                    technique = "T1078.003 - Local Accounts"
                elif eid == 4720:
                    rname = "Local User Account Created"
                    sev = "HIGH"
                    tactic = "Persistence"
                    technique = "T1136.001 - Local Account"

            # Fallback for standard high-severity audit events & failed logons
            elif eid == 4625:
                should_alert = True
                rname = "Windows Logon Failure"
                sev = "MEDIUM"
                threat_cat = "CREDENTIAL_ACCESS"
                tactic = "Credential Access"
                technique = "T1110 - Brute Force"
            elif sev in ['HIGH', 'CRITICAL']:
                should_alert = True

            if should_alert:
                conn.execute("""
                    INSERT INTO alerts (timestamp, severity, rule_name, description, src_ip, src_user, device_name, process, event_id, mitre_tactic, mitre_technique, raw_event, status, threat_category)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'OPEN', ?)
                """, (now_iso, sev, rname, alert_reason, src_ip, user or hostname, hostname, proc or 'powershell.exe', eid, tactic, technique, raw_json_str, threat_cat))

        # 4. Check for anomalous outbound C2 network connections (Use Case 4: C2 Beaconing T1071)
        C2_PORTS = {4444, 1337, 8888, 7070, 9001, 6667, 31337}
        for c in data.get('connections', []):
            rem = c.get('remote', '')
            if ':' in rem:
                try:
                    rem_ip, rem_port = rem.rsplit(':', 1)
                    if rem_port.isdigit() and int(rem_port) in C2_PORTS:
                        conn.execute("""
                            INSERT INTO alerts (timestamp, severity, rule_name, description, src_ip, src_user, device_name, process, event_id, mitre_tactic, mitre_technique, raw_event, status, threat_category)
                            VALUES (?, 'HIGH', 'Malicious C2 Beaconing Detected', ?, ?, ?, ?, ?, 9002, 'Command and Control', 'T1071.001 - Web Protocols', ?, 'OPEN', 'EXFILTRATION')
                        """, (now_iso, f"Outbound socket connection established to known C2 beacon port :{rem_port} ({rem})", rem_ip, hostname, hostname, f"PID:{c.get('pid', '-')}", json.dumps(c)))
                except Exception:
                    pass

        # 5. Check for suspicious running processes (Automated EDR containment alert)
        SUSPICIOUS_TOOLS = {
            'mimikatz.exe': ('In-Memory Credential Dumping Tool', 'CREDENTIAL_ACCESS', 'T1003.001 - LSASS Memory'),
            'nc.exe': ('Netcat Reverse Shell / C2 Utility', 'EXFILTRATION', 'T1071 - Application Layer Protocol'),
            'ncat.exe': ('Ncat Network Tunneling Tool', 'EXFILTRATION', 'T1071 - Application Layer Protocol'),
            'psexec.exe': ('PsExec Lateral Execution Utility', 'LIVING_OFF_THE_LAND', 'T1569.002 - Service Execution'),
            'wireshark.exe': ('Network Sniffer Utility', 'CREDENTIAL_ACCESS', 'T1040 - Network Sniffing')
        }
        for p in data.get('processes', []):
            pname = p.get('name', '').lower()
            if pname in SUSPICIOUS_TOOLS:
                tool_rname, tool_cat, tool_tech = SUSPICIOUS_TOOLS[pname]
                conn.execute("""
                    INSERT INTO alerts (timestamp, severity, rule_name, description, src_ip, src_user, device_name, process, event_id, mitre_tactic, mitre_technique, raw_event, status, threat_category)
                    VALUES (?, 'HIGH', ?, ?, ?, ?, ?, ?, 1, 'Execution', ?, ?, 'OPEN', ?)
                """, (now_iso, f"Suspicious Tool: {tool_rname}", f"Suspicious tool {pname} actively running on {hostname} (PID: {p.get('pid', '-')})", ip_addr, hostname, hostname, pname, tool_tech, json.dumps(p), tool_cat))

        conn.commit()
    finally:
        conn.close()

    # 5. Dynamic UEBA Behavioral Risk Scoring
    calculate_entity_risk(hostname, "HOST")
    if user_seen:
        calculate_entity_risk(user_seen, "USER")

    res = {'status': 'acknowledged', 'node': hostname, 'profile': active_profile}
    if cmd_to_send:
        res['command'] = cmd_to_send
    return jsonify(res)

# ── Cloud & Syslog Ingestion Webhook (AWS/GCP/Azure/Syslog) ──
@app.route('/api/v1/ingest/cloud', methods=['POST'])
def ingest_cloud():
    """
    Cloud-ready webhook endpoint for AWS CloudTrail, GCP Audit, Azure Monitor, or Syslog JSON payloads.
    """
    payload = request.get_json(force=True, silent=True) or {}
    events = payload.get('events', [payload] if ('event' in payload or 'rule_name' in payload or 'eventName' in payload) else [])
    
    conn = get_conn()
    now_iso = datetime.now().isoformat()
    ingested = 0
    for ev in events:
        host = ev.get('host', ev.get('recipientAccountId', 'cloud-env'))
        user = ev.get('user', ev.get('userIdentity', {}).get('userName', 'cloud-user'))
        rname = ev.get('rule_name', ev.get('eventName', 'Cloud Security Event'))
        tactic = ev.get('mitre_tactic', 'Initial Access')
        technique = ev.get('mitre_technique', 'T1078 - Cloud Accounts')
        desc = ev.get('details', f"Cloud event {rname} on {host} by {user}")
        eid = ev.get('event_id', 9001)
        sev = ev.get('severity', 'MEDIUM')
        
        conn.execute("""
            INSERT INTO telemetry_logs (hostname, timestamp, log_type, details, event_id, user_name, src_ip, process_name, raw_json)
            VALUES (?, ?, 'CLOUD_AUDIT', ?, ?, ?, ?, 'cloud', ?)
        """, (host, now_iso, desc, eid, user, ev.get('src_ip', '0.0.0.0'), json.dumps(ev)))
        
        if sev in ['MEDIUM', 'HIGH', 'CRITICAL']:
            conn.execute("""
                INSERT INTO alerts (timestamp, severity, rule_name, description, src_ip, src_user, device_name, process, event_id, mitre_tactic, mitre_technique, raw_event, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'cloud', ?, ?, ?, ?, 'OPEN')
            """, (now_iso, sev, rname, desc, ev.get('src_ip', '0.0.0.0'), user, host, eid, tactic, technique, json.dumps(ev)))
            
        ingested += 1
    conn.commit()
    conn.close()
    return jsonify({"status": "success", "ingested": ingested})

# ── UEBA Top Risky Entities API ───────────────────────────────
@app.route('/api/ueba/top')
def api_ueba_top():
    return jsonify(get_top_risky_entities(limit=10))

@app.route('/api/agents/<hostname>/isolate', methods=['POST'])
def isolate_agent(hostname):
    conn = get_conn()
    conn.execute("UPDATE endpoints SET pending_command='isolate_host', status='ISOLATED' WHERE hostname=?", (hostname,))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': f'Isolation command queued for {hostname}'})

@app.route('/api/agents/<hostname>/unisolate', methods=['POST'])
def unisolate_agent(hostname):
    conn = get_conn()
    conn.execute("UPDATE endpoints SET pending_command='unisolate_host', status='ONLINE' WHERE hostname=?", (hostname,))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': f'Network restore command queued for {hostname}'})

# ── Nova AI Humanoid Analyst API ──────────────────────────────
@app.route('/api/ai/chat', methods=['POST'])
def ai_chat():
    req = request.get_json(force=True, silent=True) or {}
    message = req.get('message', '')
    reply = nova.chat(message)
    return jsonify({'response': reply})

@app.route('/api/ai/rca/<int:iid>')
def ai_rca(iid):
    rca = nova.generate_rca(iid)
    return jsonify(rca)

# ── Stats API ─────────────────────────────────────────────────
@app.route('/api/stats')
def stats():
    conn       = get_conn()
    by_sev     = conn.execute('SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity').fetchall()
    by_mitre   = conn.execute('SELECT mitre_tactic, COUNT(*) as cnt FROM alerts GROUP BY mitre_tactic ORDER BY cnt DESC LIMIT 6').fetchall()
    by_rule    = conn.execute('SELECT rule_name, COUNT(*) as cnt FROM alerts GROUP BY rule_name ORDER BY cnt DESC LIMIT 5').fetchall()
    conn.close()
    return jsonify({
        'by_severity': [dict(r) for r in by_sev],
        'by_mitre':    [dict(r) for r in by_mitre],
        'by_rule':     [dict(r) for r in by_rule],
    })

# ── System Health & Component Diagnostic API ──────────────────
@app.route('/api/health')
@app.route('/health')
def health():
    import time
    start_time = time.time()
    conn = get_conn()
    try:
        # 1. Database Health & Integrity
        db_path = os.path.join(BASE_DIR, 'minisoc.db')
        db_size_mb = round(os.path.getsize(db_path) / (1024 * 1024), 2) if os.path.exists(db_path) else 0.0
        integrity_row = conn.execute("PRAGMA quick_check;").fetchone()
        integrity = integrity_row[0] if integrity_row else "OK"
        journal_row = conn.execute("PRAGMA journal_mode;").fetchone()
        journal_mode = journal_row[0] if journal_row else "WAL"
        
        alerts_cnt = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        logs_cnt = conn.execute("SELECT COUNT(*) FROM telemetry_logs").fetchone()[0]
        inc_cnt = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        
        # 2. Endpoints Health
        endpoints = conn.execute("SELECT hostname, status, last_heartbeat FROM endpoints").fetchall()
        total_eps = len(endpoints)
        online_eps = 0
        isolated_eps = 0
        now_dt = datetime.now()
        for ep in endpoints:
            if ep['status'] == 'ISOLATED':
                isolated_eps += 1
            if ep['last_heartbeat']:
                try:
                    hb_dt = datetime.fromisoformat(ep['last_heartbeat'])
                    if (now_dt - hb_dt).total_seconds() < 120:
                        online_eps += 1
                except Exception:
                    pass

        # 3. Blocked IPs count
        blocked_cnt = conn.execute("SELECT COUNT(*) FROM blocked_ips").fetchone()[0]
        
        # 4. Latency
        query_latency_ms = round((time.time() - start_time) * 1000, 2)
        
        components = {
            "ingestion_engine": {
                "name": "Telemetry Ingestion Gateway",
                "status": "OPERATIONAL",
                "listening_port": config.get('dashboard', {}).get('port', 5000),
                "protocol": "HTTP/REST + JSON Webhooks",
                "routes": ["/api/v1/telemetry", "/api/v1/cloud/ingest"],
                "details": "Listening on 0.0.0.0:5000"
            },
            "database_storage": {
                "name": "SQLite WAL High-Concurrency Engine",
                "status": "OPERATIONAL" if str(integrity).upper() == "OK" else "DEGRADED",
                "engine": "SQLite 3",
                "journal_mode": str(journal_mode).upper(),
                "file_size_mb": db_size_mb,
                "integrity": integrity,
                "total_alerts": alerts_cnt,
                "total_telemetry_logs": logs_cnt,
                "total_incidents": inc_cnt,
                "query_latency_ms": query_latency_ms,
                "details": f"{db_size_mb} MB on disk, {logs_cnt} logs indexed"
            },
            "endpoint_agents": {
                "name": "Endpoint Agent Fleet & EDR",
                "status": "OPERATIONAL",
                "total_registered": total_eps,
                "online_healthy": online_eps,
                "isolated_quarantined": isolated_eps,
                "details": f"{online_eps}/{total_eps} hosts communicating (heartbeat < 2m)"
            },
            "detection_engine": {
                "name": "Real-Time MITRE ATT&CK v14 Correlator",
                "status": "OPERATIONAL",
                "framework": "MITRE ATT&CK Enterprise Matrix v14",
                "top5_attack_suites": [
                    "Ransomware Recovery Inhibition (T1490)",
                    "Credential Access & PtH (T1003/T1550)",
                    "Living-off-the-Land Scripting (T1059)",
                    "C2 Beaconing & Exfiltration (T1071/T1560)",
                    "Rogue Persistence & Anti-Forensics (T1053/T1070)"
                ],
                "details": "5/5 Critical attack modules & regex rules active"
            },
            "ueba_behavioral_engine": {
                "name": "Behavioral UEBA Risk Engine",
                "status": "OPERATIONAL",
                "scoring_range": "0-100 pts",
                "tier_definitions": "LOW (0-24), MEDIUM (25-49), HIGH (50-74), CRITICAL (75-100)",
                "details": "Active entity risk matrix with multi-factor scoring"
            },
            "threat_intelligence": {
                "name": "Multi-Feed Cyber Threat Intelligence (CTI)",
                "status": "OPERATIONAL",
                "feeds": ["VirusTotal v3", "AbuseIPDB v2", "ThreatFox", "AlienVault OTX"],
                "rfc1918_guard": "ACTIVE",
                "details": "4 Feeds integrated with private RFC 1918 loopback guard"
            },
            "soar_response_fabric": {
                "name": "SOAR Active Defense & Containment",
                "status": "OPERATIONAL",
                "capabilities": [
                    "1-Click Host Network Isolation",
                    "Local Host Firewall IPS Drops (netsh/iptables)",
                    "Remote Process Termination",
                    "NIST SP 800-61 PDF IR Generation"
                ],
                "active_firewall_blocks": blocked_cnt,
                "details": f"{blocked_cnt} active firewall IP containment drops"
            }
        }
        
        all_healthy = (str(integrity).upper() == "OK")
        return jsonify({
            "platform": "MiniSOC Enterprise v2.2",
            "overall_status": "HEALTHY" if all_healthy else "DEGRADED",
            "timestamp": datetime.now().isoformat(),
            "query_latency_ms": query_latency_ms,
            "components": components
        })
    finally:
        conn.close()

if __name__ == '__main__':
    app.run(host=config.get('dashboard', {}).get('host', '0.0.0.0'),
            port=config.get('dashboard', {}).get('port', 5000),
            debug=config.get('dashboard', {}).get('debug', True))
