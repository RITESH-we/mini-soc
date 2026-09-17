import os, sys, yaml
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from flask import Flask, render_template, jsonify, request, redirect, url_for, send_file
from database.models import get_conn, init_db
from datetime import datetime
from reports.ir_generator import generate_pdf_report

CONFIG_PATH = os.path.join(BASE_DIR, 'config.yaml')
with open(CONFIG_PATH) as f:
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

# ── Enrich Alert ──────────────────────────────────────────────
@app.route('/api/alert/<int:aid>/enrich')
def enrich_alert(aid):
    from enrichers.virustotal import lookup_ip as vt_ip
    from enrichers.abuseipdb  import lookup_ip as abuse_ip
    conn  = get_conn()
    alert = conn.execute('SELECT * FROM alerts WHERE id=?', (aid,)).fetchone()
    if not alert:
        return jsonify({'error': 'not found'}), 404
    ip        = alert['src_ip']
    vt_key    = config['api_keys']['virustotal']
    abuse_key = config['api_keys']['abuseipdb']
    vt        = vt_ip(ip, vt_key)    if ip else {}
    abuse     = abuse_ip(ip, abuse_key) if ip else {}
    vt_score    = vt.get('score', 'N/A')
    abuse_score = abuse.get('score', -1)
    conn.execute('UPDATE alerts SET enriched=1, vt_score=?, abuse_score=? WHERE id=?',
                 (vt_score, abuse_score, aid))
    conn.commit()
    conn.close()
    return jsonify({'vt_score': vt_score, 'abuse_score': abuse_score,
                    'country': vt.get('country', ''), 'isp': abuse.get('isp', '')})

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

# ── Stats API (for charts) ────────────────────────────────────
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
    app.run(host=config['dashboard']['host'],
            port=config['dashboard']['port'],
            debug=config['dashboard']['debug'])
