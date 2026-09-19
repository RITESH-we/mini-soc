import os, sys, yaml
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from flask import Flask, render_template, jsonify, request, redirect, url_for, send_file
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

# ── Home Dashboard ────────────────────────────────────────────
@app.route('/')
def index():
    conn         = get_conn()
    total_alerts = conn.execute('SELECT COUNT(*) FROM alerts').fetchone()[0]
    open_alerts  = conn.execute("SELECT COUNT(*) FROM alerts WHERE status='OPEN'").fetchone()[0]
    critical     = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity='CRITICAL'").fetchone()[0]
    open_inc     = conn.execute("SELECT COUNT(*) FROM incidents WHERE status!='CLOSED'").fetchone()[0]
    recent       = conn.execute('SELECT * FROM alerts ORDER BY id DESC LIMIT 10').fetchall()
    conn.close()
    return render_template('index.html',
        total_alerts=total_alerts, open_alerts=open_alerts,
        critical=critical, open_inc=open_inc, recent=recent)

# ── Alerts ────────────────────────────────────────────────────
@app.route('/alerts')
def alerts():
    sev  = request.args.get('severity', 'ALL')
    conn = get_conn()
    if sev == 'ALL':
        rows = conn.execute('SELECT * FROM alerts ORDER BY id DESC LIMIT 300').fetchall()
    else:
        rows = conn.execute('SELECT * FROM alerts WHERE severity=? ORDER BY id DESC', (sev,)).fetchall()
    conn.close()
    return render_template('alerts.html', alerts=rows, severity=sev)

# ── Alert API (for live refresh) ──────────────────────────────
@app.route('/api/alerts')
def api_alerts():
    conn = get_conn()
    rows = conn.execute('SELECT * FROM alerts ORDER BY id DESC LIMIT 50').fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

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

# ── Endpoint Agent Fleet ──────────────────────────────────────
@app.route('/agents')
def agents_view():
    conn = get_conn()
    rows = conn.execute("SELECT * FROM endpoints ORDER BY last_heartbeat DESC").fetchall()
    conn.close()
    return render_template('agents.html', endpoints=[dict(r) for r in rows], server_ip="127.0.0.1")

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
    ver      = sys_info.get('agent_version', '2.0.0')

    conn = get_conn()
    conn.execute("""
        INSERT INTO endpoints (hostname, ip_address, os, architecture, agent_version, last_heartbeat, status)
        VALUES (?, ?, ?, ?, ?, ?, 'ONLINE')
        ON CONFLICT(hostname) DO UPDATE SET
            ip_address=excluded.ip_address,
            os=excluded.os,
            architecture=excluded.architecture,
            agent_version=excluded.agent_version,
            last_heartbeat=excluded.last_heartbeat,
            status='ONLINE'
    """, (hostname, ip_addr, os_name, arch, ver, datetime.now().isoformat()))
    conn.commit()
    conn.close()

    return jsonify({'status': 'acknowledged', 'node': hostname})

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
    app.run(host=config.get('dashboard', {}).get('host', '127.0.0.1'),
            port=config.get('dashboard', {}).get('port', 5000),
            debug=config.get('dashboard', {}).get('debug', True))
