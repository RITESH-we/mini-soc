import time
import socket
import subprocess
import platform
from datetime import datetime, timedelta
from collections import defaultdict
from database.models import get_conn
from network.ips_responder import block_ip

# Port Scan tracker: {remote_ip: [(timestamp, port)]}
_scan_tracker = defaultdict(list)

# Insecure/cleartext ports to flag
UNENCRYPTED_PORTS = {
    21: "FTP (Plaintext Credentials)",
    23: "Telnet (Unencrypted Remote Terminal)",
    69: "TFTP (Unauthenticated File Transfer)",
    80: "HTTP (Cleartext Web Traffic)",
    110: "POP3 (Plaintext Email Retrieval)",
    143: "IMAP (Plaintext Email Retrieval)"
}

def record_network_alert(rule_name, severity, src_ip, dest_port, protocol, details, mitre_technique):
    conn = get_conn()
    conn.execute("""
        INSERT INTO network_alerts (timestamp, rule_name, severity, src_ip, dest_port, protocol, details, mitre_technique)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (datetime.now().isoformat(), rule_name, severity, src_ip, dest_port, protocol, details, mitre_technique))
    conn.commit()
    conn.close()

def inspect_network_activity(auto_block=False):
    """
    Analyzes live socket table and active connection flows.
    """
    alerts = []
    now = datetime.now()
    
    try:
        cmd = ["netstat", "-ano"] if platform.system() == "Windows" else ["netstat", "-tulnpa"]
        output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, universal_newlines=True)
        
        for line in output.splitlines():
            parts = line.strip().split()
            if len(parts) >= 4 and parts[0] in ["TCP", "UDP", "tcp", "udp"]:
                proto = parts[0]
                local = parts[1]
                remote = parts[2]
                state = parts[3] if len(parts) > 4 else "UNKNOWN"
                
                if ":" in remote and not remote.startswith("127.0.0.1") and not remote.startswith("0.0.0.0") and not remote.startswith("[::]"):
                    remote_ip = remote.split(":")[0]
                    try:
                        remote_port = int(remote.split(":")[-1])
                    except ValueError:
                        remote_port = 0
                        
                    # 1. Port scan heuristic: Track ports hit per remote IP in 15 seconds
                    _scan_tracker[remote_ip].append((now, remote_port))
                    _scan_tracker[remote_ip] = [
                        (ts, p) for ts, p in _scan_tracker[remote_ip]
                        if (now - ts).total_seconds() <= 15
                    ]
                    distinct_ports = len(set(p for _, p in _scan_tracker[remote_ip]))
                    
                    if distinct_ports >= 8:
                        desc = f"Inbound port sweep detected from {remote_ip} ({distinct_ports} ports hit in 15s)"
                        record_network_alert("Port Scan Activity", "HIGH", remote_ip, remote_port, proto, desc, "T1046 - Network Service Discovery")
                        _scan_tracker[remote_ip] = [] # Reset after alert
                        if auto_block:
                            block_ip(remote_ip, reason="Automated IPS: Rapid Port Sweep")
                        alerts.append({"rule": "Port Scan", "src": remote_ip, "details": desc})

                    # 2. Insecure plaintext service detection
                    if remote_port in UNENCRYPTED_PORTS:
                        service_name = UNENCRYPTED_PORTS[remote_port]
                        desc = f"Insecure plaintext traffic detected: Connection to {remote_ip}:{remote_port} ({service_name})"
                        record_network_alert("Unencrypted Cleartext Protocol", "LOW", remote_ip, remote_port, proto, desc, "T1040 - Network Sniffing / Cleartext")
                        alerts.append({"rule": "Unencrypted Protocol", "src": remote_ip, "details": desc})

    except Exception as e:
        pass

    return alerts

def get_recent_network_alerts(limit=50):
    conn = get_conn()
    rows = conn.execute("SELECT * FROM network_alerts ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]
