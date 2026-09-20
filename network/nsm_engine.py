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

def get_hidden_subprocess_flags():
    flags = {}
    if platform.system() == "Windows":
        flags["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
        try:
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            si.wShowWindow = 0
            flags["startupinfo"] = si
        except Exception:
            pass
    return flags

def parse_socket_endpoint(endpoint_str: str):
    """Accurately parses IP and port from IPv4 or IPv6 socket string without truncation."""
    endpoint_str = endpoint_str.strip()
    if endpoint_str.startswith("["):
        if "]:" in endpoint_str:
            ip_part, port_part = endpoint_str.split("]:", 1)
            ip = ip_part.lstrip("[")
            port = int(port_part) if port_part.isdigit() else 0
            return ip, port
        return endpoint_str.strip("[]"), 0
    elif ":" in endpoint_str:
        parts = endpoint_str.rsplit(":", 1)
        ip = parts[0]
        port = int(parts[1]) if parts[1].isdigit() else 0
        return ip, port
    return endpoint_str, 0

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
    try:
        conn.execute("""
            INSERT INTO network_alerts (timestamp, rule_name, severity, src_ip, dest_port, protocol, details, mitre_technique)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (datetime.now().isoformat(), rule_name, severity, src_ip, dest_port, protocol, details, mitre_technique))
        conn.commit()
    finally:
        conn.close()

def inspect_network_activity(auto_block=False):
    """
    Analyzes live socket table and active connection flows.
    """
    alerts = []
    now = datetime.now()
    
    try:
        cmd = ["netstat", "-ano"] if platform.system() == "Windows" else ["netstat", "-tulnpa"]
        kwargs = {"stderr": subprocess.DEVNULL, "universal_newlines": True}
        kwargs.update(get_hidden_subprocess_flags())
        output = subprocess.check_output(cmd, **kwargs)
        
        for line in output.splitlines():
            parts = line.strip().split()
            if len(parts) >= 4 and parts[0] in ["TCP", "UDP", "tcp", "udp"]:
                proto = parts[0]
                local = parts[1]
                remote = parts[2]
                state = parts[3] if len(parts) > 4 else "UNKNOWN"
                
                remote_ip, remote_port = parse_socket_endpoint(remote)
                if remote_ip and not remote_ip.startswith("127.0.0.1") and not remote_ip.startswith("0.0.0.0") and remote_ip != "::" and remote_ip != "::1":
                        
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
