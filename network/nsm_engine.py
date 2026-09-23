import time
import socket
import subprocess
import platform
import math
import ipaddress
from datetime import datetime, timedelta
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
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

# Comprehensive Monitored & Insecure Ports
MONITORED_PORTS = {
    # Insecure/Plaintext
    21:   {"name": "FTP (Plaintext Credentials)", "severity": "LOW", "mitre": "T1040 - Network Sniffing / Cleartext"},
    23:   {"name": "Telnet (Unencrypted Remote Terminal)", "severity": "MEDIUM", "mitre": "T1040 - Network Sniffing / Cleartext"},
    69:   {"name": "TFTP (Unauthenticated File Transfer)", "severity": "LOW", "mitre": "T1040 - Network Sniffing / Cleartext"},
    80:   {"name": "HTTP (Cleartext Web Traffic)", "severity": "INFO", "mitre": "T1040 - Network Sniffing / Cleartext"},
    110:  {"name": "POP3 (Plaintext Email Retrieval)", "severity": "LOW", "mitre": "T1040 - Network Sniffing / Cleartext"},
    143:  {"name": "IMAP (Plaintext Email Retrieval)", "severity": "LOW", "mitre": "T1040 - Network Sniffing / Cleartext"},
    # Lateral Movement & Remote Administration
    22:   {"name": "SSH (Remote Admin Access)", "severity": "LOW", "mitre": "T1021.004 - Remote Services: SSH"},
    445:  {"name": "SMB (Lateral Movement / EternalBlue Vector)", "severity": "HIGH", "mitre": "T1021.002 - SMB/Windows Admin Shares"},
    3389: {"name": "RDP (Remote Desktop Protocol)", "severity": "MEDIUM", "mitre": "T1021.001 - Remote Desktop Protocol"},
    5900: {"name": "VNC (Remote Desktop Control)", "severity": "MEDIUM", "mitre": "T1021.005 - VNC Remote Services"},
    5985: {"name": "WinRM HTTP (Windows Remote Management)", "severity": "MEDIUM", "mitre": "T1021.006 - Windows Remote Management"},
    5986: {"name": "WinRM HTTPS (Windows Remote Management)", "severity": "LOW", "mitre": "T1021.006 - Windows Remote Management"},
    # Database Exposures
    1433: {"name": "MSSQL (Database Exposure)", "severity": "MEDIUM", "mitre": "T1190 - Exploit Public-Facing Application"},
    3306: {"name": "MySQL (Database Exposure)", "severity": "MEDIUM", "mitre": "T1190 - Exploit Public-Facing Application"},
    5432: {"name": "PostgreSQL (Database Exposure)", "severity": "LOW", "mitre": "T1190 - Exploit Public-Facing Application"},
    6379: {"name": "Redis (Unauthenticated In-Memory DB)", "severity": "HIGH", "mitre": "T1190 - Exploit Public-Facing Application"},
    27017:{"name": "MongoDB (NoSQL Database Exposure)", "severity": "MEDIUM", "mitre": "T1190 - Exploit Public-Facing Application"},
    # Known Backdoors / C2 Sockets
    4444: {"name": "Metasploit / Reverse Shell Port", "severity": "CRITICAL", "mitre": "T1071 - Application Layer Protocol: C2"},
    1337: {"name": "Backdoor / Elite Port", "severity": "HIGH", "mitre": "T1071 - Application Layer Protocol: C2"},
    7070: {"name": "Suspicious C2 / Proxy Port", "severity": "MEDIUM", "mitre": "T1071 - Application Layer Protocol: C2"},
    9001: {"name": "Tor Network Relay Port", "severity": "HIGH", "mitre": "T1090.003 - Multi-hop Proxy: Tor"},
    31337:{"name": "BackOrifice Trojan Port", "severity": "CRITICAL", "mitre": "T1071 - Application Layer Protocol: C2"}
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

def calculate_shannon_entropy(data: str) -> float:
    """Calculates Shannon entropy to detect DGA domains and encrypted/encoded strings."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    freq = defaultdict(int)
    for char in data:
        freq[char] += 1
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 2)

def detect_dns_tunneling(domain_query: str) -> dict:
    """
    Evaluates domain queries for covert DNS tunneling or Domain Generation Algorithms (DGA).
    Flags high-entropy labels, excessive query length, and suspicious subdomain depth.
    """
    domain = domain_query.strip().lower().rstrip(".")
    if not domain:
        return {"suspicious": False}

    labels = domain.split(".")
    # Skip common top-level and second-level domains
    if len(labels) < 2:
        return {"suspicious": False}

    total_len = len(domain)
    subdomain_part = ".".join(labels[:-2]) if len(labels) > 2 else labels[0]
    entropy = calculate_shannon_entropy(subdomain_part)

    reasons = []
    if total_len > 45:
        reasons.append(f"Excessive domain length ({total_len} chars)")
    if len(labels) >= 4:
        reasons.append(f"Deep subdomain nesting ({len(labels)} labels)")
    if entropy >= 3.8 and len(subdomain_part) > 12:
        reasons.append(f"High Shannon entropy ({entropy}) indicating encrypted/encoded data")

    if len(reasons) >= 2 or (entropy >= 4.2 and len(subdomain_part) > 16):
        return {
            "suspicious": True,
            "domain": domain,
            "entropy": entropy,
            "reasons": reasons,
            "severity": "HIGH",
            "rule": "DNS Tunneling / DGA Beaconing",
            "mitre": "T1071.004 - DNS Exfiltration"
        }
    return {"suspicious": False, "entropy": entropy}

def inspect_network_activity(auto_block=False):
    """
    Analyzes live socket table and active connection flows.
    Detects low-and-slow port sweeps, sensitive lateral movement ports, and backdoors.
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
                    
                    # 1. Low-and-Slow Port Sweep Heuristic:
                    # Tracks ports hit per remote IP across an extended 60-second sliding window.
                    _scan_tracker[remote_ip].append((now, remote_port))
                    _scan_tracker[remote_ip] = [
                        (ts, p) for ts, p in _scan_tracker[remote_ip]
                        if (now - ts).total_seconds() <= 60
                    ]
                    distinct_ports = len(set(p for _, p in _scan_tracker[remote_ip]))
                    
                    # Lowered threshold to 4 distinct ports across 60s
                    if distinct_ports >= 4:
                        desc = f"Stealth port sweep detected from {remote_ip} ({distinct_ports} distinct ports probed in 60s)"
                        record_network_alert("Port Scan Activity", "HIGH", remote_ip, remote_port, proto, desc, "T1046 - Network Service Discovery")
                        _scan_tracker[remote_ip] = []  # Reset after alert
                        if auto_block:
                            block_ip(remote_ip, reason="Automated IPS: Stealth Port Sweep")
                        alerts.append({"rule": "Port Scan", "src": remote_ip, "details": desc})

                    # 2. Monitored & Insecure/Lateral Movement Ports
                    if remote_port in MONITORED_PORTS:
                        info = MONITORED_PORTS[remote_port]
                        desc = f"Connection to sensitive/monitored service: {remote_ip}:{remote_port} ({info['name']})"
                        record_network_alert(info['name'], info['severity'], remote_ip, remote_port, proto, desc, info['mitre'])
                        alerts.append({"rule": info['name'], "src": remote_ip, "details": desc})

    except Exception:
        pass

    return alerts

def get_recent_network_alerts(limit=50):
    conn = get_conn()
    rows = conn.execute("SELECT * FROM network_alerts ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

# ── Active Subnet & IP Discovery Scanner ────────────────────────
def _probe_host_port(ip: str, port: int, timeout: float = 0.3) -> bool:
    """Attempts a rapid TCP connect probe to a specific IP and port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            return result == 0
    except Exception:
        return False

def _probe_host(ip: str, ports_to_check: list, timeout: float = 0.3) -> dict:
    """Probes a single host for live status and open ports."""
    open_ports = []
    is_live = False
    
    # Check open ports
    for p in ports_to_check:
        if _probe_host_port(ip, p, timeout=timeout):
            open_ports.append(p)
            is_live = True

    # If no TCP port open, attempt a fast ping on Windows/Linux to confirm if host is up
    if not is_live:
        try:
            cmd = ["ping", "-n", "1", "-w", "250", ip] if platform.system() == "Windows" else ["ping", "-c", "1", "-W", "1", ip]
            res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **get_hidden_subprocess_flags())
            if res.returncode == 0:
                is_live = True
        except Exception:
            pass

    if is_live:
        hostname = ""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except Exception:
            hostname = "Unknown Host"
        return {
            "ip": ip,
            "hostname": hostname,
            "status": "ONLINE",
            "open_ports": open_ports,
            "discovered_at": datetime.now().isoformat()
        }
    return None

def scan_subnet_range(subnet_str: str, ports=None, timeout=0.3, max_hosts=256) -> dict:
    """
    Actively sweeps an IP subnet range (e.g. 192.168.1.0/24 or single IP)
    discovering live hosts and sensitive open ports using high-concurrency threads.
    """
    if ports is None:
        ports = [21, 22, 80, 443, 445, 3389, 5985, 8080]

    subnet_str = subnet_str.strip()
    try:
        if "/" not in subnet_str and not subnet_str.endswith(".0"):
            net = ipaddress.ip_network(f"{subnet_str}/32", strict=False)
        else:
            net = ipaddress.ip_network(subnet_str, strict=False)
    except ValueError as e:
        return {"error": f"Invalid subnet CIDR format: {e}", "hosts": []}

    target_ips = [str(ip) for ip in net.hosts()]
    if len(target_ips) > max_hosts:
        target_ips = target_ips[:max_hosts]

    start_t = time.time()
    discovered_hosts = []

    with ThreadPoolExecutor(max_workers=min(48, len(target_ips) or 1)) as executor:
        futures = {executor.submit(_probe_host, ip, ports, timeout): ip for ip in target_ips}
        for future in as_completed(futures):
            try:
                res = future.result()
                if res:
                    discovered_hosts.append(res)
            except Exception:
                pass

    discovered_hosts.sort(key=lambda h: socket.inet_aton(h["ip"]) if ":" not in h["ip"] else h["ip"])
    duration_sec = round(time.time() - start_t, 2)

    return {
        "subnet": str(net),
        "scanned_ips": len(target_ips),
        "live_hosts_count": len(discovered_hosts),
        "scan_duration_sec": duration_sec,
        "monitored_ports": ports,
        "hosts": discovered_hosts
    }
