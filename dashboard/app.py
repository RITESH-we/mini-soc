import os, sys, yaml, io, csv
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from flask import Flask, render_template, jsonify, request, redirect, url_for, send_file, Response
from database.models import get_conn, init_db
from datetime import datetime
from reports.ir_generator import generate_pdf_report
from network.ips_responder import block_ip, unblock_ip, list_blocked_ips
from network.nsm_engine import inspect_network_activity, get_recent_network_alerts
from ai.humanoid_analyst import nova

CONFIG_PATH = os.path.join(BASE_DIR, 'config.yaml')
with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
    config = yaml.safe_load(f)

app = Flask(__name__)
init_db()

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
    
    devices      = get_all_devices(conn)
    recent       = conn.execute('SELECT * FROM alerts ORDER BY id DESC LIMIT 15').fetchall()
    conn.close()
    
    return render_template('index.html',
        total_alerts=total_alerts, open_alerts=open_alerts,
        critical_high=critical_high, open_inc=open_inc,
        total_endpoints=total_eps, online_endpoints=online_eps,
        isolated_endpoints=isolated_eps, devices=devices,
        recent=recent)

# ── Alerts Triage ─────────────────────────────────────────────
@app.route('/alerts')
def alerts():
    sev    = request.args.get('severity', 'ALL')
    device = request.args.get('device', '')
    conn   = get_conn()
    devices = get_all_devices(conn)

    query = 'SELECT * FROM alerts WHERE 1=1'
    params = []

    if sev != 'ALL':
        query += ' AND severity=?'
        params.append(sev)
        
    if device:
        query += ' AND (device_name=? OR src_user=?)'
        params.extend([device, device])

    query += ' ORDER BY id DESC LIMIT 300'
    rows = conn.execute(query, params).fetchall()
    conn.close()

    return render_template('alerts.html', alerts=rows, severity=sev,
                           devices=devices, current_device=device)

@app.route('/api/alerts/export')
def export_alerts_csv():
    device = request.args.get('device', '')
    conn   = get_conn()
    query  = 'SELECT * FROM alerts WHERE 1=1'
    params = []
    if device:
        query += ' AND device_name=?'
        params.append(device)
    query += ' ORDER BY id DESC'
    rows = conn.execute(query, params).fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Timestamp', 'Device', 'Severity', 'Rule Name', 'MITRE Technique', 'Target User', 'Source IP', 'VT Score', 'Abuse Score', 'Status', 'Description'])
    
    for r in rows:
        writer.writerow([
            r['id'], r['timestamp'], r['device_name'] or 'Localhost',
            r['severity'], r['rule_name'], r['mitre_technique'] or 'N/A',
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

    conn  = get_conn()
    alert = conn.execute('SELECT * FROM alerts WHERE id=?', (aid,)).fetchone()
    if not alert:
        conn.close()
        return jsonify({'error': 'not found'}), 404
        
    ip        = alert['src_ip']
    vt_key    = config.get('api_keys', {}).get('virustotal')
    abuse_key = config.get('api_keys', {}).get('abuseipdb')
    otx_key   = config.get('api_keys', {}).get('otx')

    vt_result    = vt_ip(ip, vt_key) if ip else {}
    abuse_result = abuse_ip(ip, abuse_key) if ip else {}
    tf_result    = tf_lookup(ip) if ip else {}
    otx_result   = otx_ip(ip, otx_key) if ip else {}

    vt_score    = vt_result.get('score', 'N/A')
    abuse_score = abuse_result.get('score', -1)

    conn.execute('UPDATE alerts SET enriched=1, vt_score=?, abuse_score=? WHERE id=?',
                 (vt_score, abuse_score, aid))
    conn.commit()
    conn.close()

    return jsonify({
        'vt_score': vt_score,
        'abuse_score': abuse_score,
        'threatfox': tf_result,
        'otx': otx_result,
        'country': vt_result.get('country', '') or abuse_result.get('country', ''),
        'isp': abuse_result.get('isp', '')
    })

# ── Update Alert Status ───────────────────────────────────────
@app.route('/api/alert/<int:aid>/status', methods=['POST'])
def update_status(aid):
    status = request.json.get('status', 'OPEN')
    conn   = get_conn()
    conn.execute('UPDATE alerts SET status=? WHERE id=?', (status, aid))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})

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
    return render_template('network.html', net_alerts=net_alerts, blocked_ips=blocked)

@app.route('/network/block', methods=['POST'])
def handle_manual_block():
    ip = request.form.get('ip_address')
    reason = request.form.get('reason', 'Analyst Manual Block')
    if ip:
        block_ip(ip, reason=reason)
    return redirect(url_for('network_view'))

@app.route('/network/unblock', methods=['POST'])
def handle_unblock():
    ip = request.form.get('ip_address')
    if ip:
        unblock_ip(ip)
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
    rows = conn.execute("SELECT * FROM endpoints ORDER BY last_heartbeat DESC").fetchall()
    conn.close()
    return render_template('agents.html', endpoints=[dict(r) for r in rows], server_ip="127.0.0.1")

@app.route('/api/agents/<hostname>/logs')
def agent_logs(hostname):
    conn = get_conn()
    procs = conn.execute("SELECT * FROM telemetry_logs WHERE hostname=? AND log_type='PROCESS' ORDER BY id DESC LIMIT 25", (hostname,)).fetchall()
    conns = conn.execute("SELECT * FROM telemetry_logs WHERE hostname=? AND log_type='NETWORK_CONN' ORDER BY id DESC LIMIT 25", (hostname,)).fetchall()
    evts  = conn.execute("SELECT * FROM telemetry_logs WHERE hostname=? AND log_type='SECURITY_EVENT' ORDER BY id DESC LIMIT 15", (hostname,)).fetchall()
    conn.close()
    return jsonify({
        'hostname': hostname,
        'processes': [dict(p) for p in procs],
        'connections': [dict(c) for c in conns],
        'events': [dict(e) for e in evts]
    })

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
    ver      = sys_info.get('agent_version', '2.1.0')
    now_iso  = datetime.now().isoformat()

    conn = get_conn()
    
    # 1. Check if an analyst ordered host isolation or network restore
    ep_row = conn.execute("SELECT pending_command, status FROM endpoints WHERE hostname=?", (hostname,)).fetchone()
    cmd_to_send = None
    if ep_row and ep_row['pending_command']:
        cmd_to_send = {"action": ep_row['pending_command']}
        conn.execute("UPDATE endpoints SET pending_command=NULL WHERE hostname=?", (hostname,))

    # Update or insert endpoint record
    current_status = ep_row['status'] if ep_row else 'ONLINE'
    conn.execute("""
        INSERT INTO endpoints (hostname, ip_address, os, architecture, agent_version, last_heartbeat, status)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(hostname) DO UPDATE SET
            ip_address=excluded.ip_address,
            os=excluded.os,
            architecture=excluded.architecture,
            agent_version=excluded.agent_version,
            last_heartbeat=excluded.last_heartbeat
    """, (hostname, ip_addr, os_name, arch, ver, now_iso, current_status))

    # 2. Store live telemetry into telemetry_logs table
    for p in data.get('processes', [])[:20]:
        p_desc = f"{p.get('name', 'unknown')} | PID: {p.get('pid', '-')} | Mem: {p.get('mem_usage', p.get('mem', '-'))}"
        conn.execute("""
            INSERT INTO telemetry_logs (hostname, timestamp, log_type, details)
            VALUES (?, ?, 'PROCESS', ?)
        """, (hostname, now_iso, p_desc))

    for c in data.get('connections', [])[:15]:
        c_desc = f"{c.get('proto', 'TCP')} | Remote: {c.get('remote', '-')} | State: {c.get('state', '-')} | PID: {c.get('pid', '-')}"
        conn.execute("""
            INSERT INTO telemetry_logs (hostname, timestamp, log_type, details)
            VALUES (?, ?, 'NETWORK_CONN', ?)
        """, (hostname, now_iso, c_desc))

    for ev in data.get('events', []):
        raw_snippet = str(ev.get('raw', ''))[:250].replace('\n', ' ')
        e_desc = f"Rule: {ev.get('rule', 'Auth Failure')} | ID: {ev.get('event_id', 4625)} | {raw_snippet}"
        conn.execute("""
            INSERT INTO telemetry_logs (hostname, timestamp, log_type, details)
            VALUES (?, ?, 'SECURITY_EVENT', ?)
        """, (hostname, now_iso, e_desc))
        
        # Trigger an alert on the dashboard with device_name
        conn.execute("""
            INSERT INTO alerts (timestamp, severity, rule_name, description, src_ip, src_user, device_name, process, event_id, mitre_tactic, mitre_technique, raw_event, status)
            VALUES (?, 'MEDIUM', 'Remote Endpoint Failed Login', ?, ?, ?, ?, 'winlogon.exe', 4625, 'Credential Access', 'T1110 - Brute Force', ?, 'OPEN')
        """, (now_iso, f"Logon failure on {hostname}", ip_addr, hostname, hostname, raw_snippet))

    # 3. Check for suspicious processes
    SUSPICIOUS_NAMES = ['mimikatz.exe', 'nc.exe', 'ncat.exe', 'psexec.exe', 'wireshark.exe']
    for p in data.get('processes', []):
        pname = p.get('name', '').lower()
        if any(bad in pname for bad in SUSPICIOUS_NAMES):
            conn.execute("""
                INSERT INTO alerts (timestamp, severity, rule_name, description, src_ip, src_user, device_name, process, event_id, mitre_tactic, mitre_technique, raw_event, status)
                VALUES (?, 'HIGH', 'Suspicious Tool on Remote Endpoint', ?, ?, ?, ?, ?, 1, 'Execution', 'T1059 - Command Execution', ?, 'OPEN')
            """, (now_iso, f"Suspicious binary {pname} running on {hostname}", ip_addr, hostname, hostname, pname, str(p)))

    conn.commit()
    conn.close()

    res = {'status': 'acknowledged', 'node': hostname}
    if cmd_to_send:
        res['command'] = cmd_to_send
    return jsonify(res)

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

if __name__ == '__main__':
    app.run(host=config.get('dashboard', {}).get('host', '0.0.0.0'),
            port=config.get('dashboard', {}).get('port', 5000),
            debug=config.get('dashboard', {}).get('debug', True))
