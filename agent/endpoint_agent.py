import os
import sys
import time
import socket
import platform
import json
import subprocess
from datetime import datetime
import urllib.request
import urllib.error

# Live public ngrok server endpoint by default
DEFAULT_SERVER = "https://underfoot-such-italics.ngrok-free.dev/api/v1/telemetry"
AGENT_VERSION = "2.1.0"

def normalize_server_url(url: str) -> str:
    url = url.strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    if not url.endswith("/api/v1/telemetry"):
        if url.endswith("/"):
            url += "api/v1/telemetry"
        else:
            url += "/api/v1/telemetry"
    return url

def get_friendly_os() -> str:
    if platform.system() == "Windows":
        try:
            build = sys.getwindowsversion().build
            if build >= 22000:
                return "Windows 11"
            elif build >= 10240:
                return "Windows 10"
            return f"Windows {platform.release()}"
        except Exception:
            return f"Windows {platform.release()}"
    return f"{platform.system()} {platform.release()}"

def get_system_info():
    hostname = socket.gethostname()
    try:
        ip = socket.gethostbyname(hostname)
    except Exception:
        ip = "127.0.0.1"
    return {
        "hostname": hostname,
        "ip_address": ip,
        "os": get_friendly_os(),
        "architecture": platform.machine(),
        "agent_version": AGENT_VERSION,
        "timestamp": datetime.now().isoformat()
    }

def get_active_connections():
    connections = []
    try:
        cmd = ["netstat", "-ano"] if platform.system() == "Windows" else ["netstat", "-tulnp"]
        output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, universal_newlines=True)
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("TCP") or line.startswith("UDP") or line.startswith("tcp") or line.startswith("udp"):
                parts = line.split()
                if len(parts) >= 4:
                    connections.append({
                        "proto": parts[0],
                        "local": parts[1],
                        "remote": parts[2],
                        "state": parts[3] if len(parts) > 4 else "UNKNOWN",
                        "pid": parts[-1]
                    })
    except Exception as e:
        connections.append({"error": str(e)})
    return connections[:50]

def get_top_processes():
    procs = []
    try:
        if platform.system() == "Windows":
            cmd = ["tasklist", "/FO", "CSV", "/NH"]
            output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, universal_newlines=True)
            for line in output.splitlines():
                if line.strip():
                    cols = [c.strip('"') for c in line.split('","')]
                    if len(cols) >= 5:
                        procs.append({
                            "name": cols[0],
                            "pid": cols[1],
                            "session": cols[2],
                            "mem_usage": cols[4]
                        })
        else:
            cmd = ["ps", "-eo", "pid,user,%cpu,%mem,comm", "--sort=-%mem"]
            output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, universal_newlines=True)
            for line in output.splitlines()[1:30]:
                parts = line.split()
                if len(parts) >= 5:
                    procs.append({
                        "pid": parts[0],
                        "user": parts[1],
                        "cpu": parts[2],
                        "mem": parts[3],
                        "name": parts[4]
                    })
    except Exception as e:
        procs.append({"error": str(e)})
    return procs[:30]

def get_security_audit_events():
    """
    Extracts recent authentication and process execution audit events
    using native OS commands (zero dependencies).
    """
    events = []
    system = platform.system()
    try:
        if system == "Windows":
            # Extract last 5 logon failures (Event ID 4625)
            cmd = ["wevtutil", "qe", "Security", "/q:*[System[(EventID=4625)]]", "/f:text", "/c:5", "/rd:true"]
            out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, universal_newlines=True)
            if out and len(out.strip()) > 0:
                events.append({
                    "event_id": 4625,
                    "rule": "Failed Logon",
                    "raw": out[:600]
                })
        elif system == "Linux":
            # Check /var/log/auth.log for failed logins if readable
            if os.path.exists("/var/log/auth.log"):
                with open("/var/log/auth.log", "r") as f:
                    lines = [l for l in f.readlines() if "Failed password" in l][-5:]
                    for l in lines:
                        events.append({"event_id": 4625, "rule": "Linux Auth Failure", "raw": l.strip()})
    except Exception:
        pass
    return events

def execute_remediation(action_payload):
    action = action_payload.get("action")
    target = action_payload.get("target")
    
    if action == "kill_process" and target:
        if platform.system() == "Windows":
            subprocess.run(["taskkill", "/F", "/PID", str(target)], capture_output=True)
        else:
            subprocess.run(["kill", "-9", str(target)], capture_output=True)
        print(f"[!] Process {target} terminated by MiniSOC command.")
        return f"Process {target} killed"
        
    elif action == "isolate_host":
        if platform.system() == "Windows":
            subprocess.run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                "name=MiniSOC_Endpoint_Quarantine", "dir=out", "action=block"
            ], capture_output=True)
        elif platform.system() == "Linux":
            subprocess.run(["iptables", "-A", "OUTPUT", "-j", "DROP"], capture_output=True)
        print("\n" + "!" * 65)
        print("[!] >>> COMMAND RECEIVED: HOST ISOLATED FROM NETWORK <<<")
        print("[!] Outbound traffic blocked by MiniSOC EDR quarantine rule.")
        print("!" * 65 + "\n")
        return "Host isolated from network"
        
    elif action == "unisolate_host":
        if platform.system() == "Windows":
            subprocess.run([
                "netsh", "advfirewall", "firewall", "delete", "rule",
                "name=MiniSOC_Endpoint_Quarantine"
            ], capture_output=True)
        elif platform.system() == "Linux":
            subprocess.run(["iptables", "-D", "OUTPUT", "-j", "DROP"], capture_output=True)
        print("\n" + "+" * 65)
        print("[+] >>> COMMAND RECEIVED: HOST QUARANTINE REMOVED <<<")
        print("[+] Outbound network connectivity fully restored.")
        print("+" * 65 + "\n")
        return "Host quarantine removed"
        
    return "No action taken"

def send_telemetry(server_url):
    server_url = normalize_server_url(server_url)
    payload = {
        "system": get_system_info(),
        "connections": get_active_connections(),
        "processes": get_top_processes(),
        "events": get_security_audit_events()
    }
    data_bytes = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        server_url,
        data=data_bytes,
        headers={
            "Content-Type": "application/json",
            "User-Agent": f"MiniSOC-Agent/{AGENT_VERSION}",
            "ngrok-skip-browser-warning": "true"
        }
    )
    
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            if response.status == 200:
                res_data = json.loads(response.read().decode("utf-8"))
                if "command" in res_data:
                    execute_remediation(res_data["command"])
                return True, "Telemetry delivered"
    except Exception as e:
        return False, str(e)

def run_agent(server_url=DEFAULT_SERVER, interval=15):
    server_url = normalize_server_url(server_url)
    print("=" * 60)
    print(f"  MiniSOC Endpoint Agent v{AGENT_VERSION} (Log Shipper & EDR)")
    print(f"  Target Server: {server_url}")
    print(f"  Heartbeat Interval: {interval}s")
    print("=" * 60)
    
    while True:
        success, msg = send_telemetry(server_url)
        now_str = datetime.now().strftime("%H:%M:%S")
        if success:
            print(f"[{now_str}] [+] Heartbeat & telemetry delivered to {server_url}")
        else:
            print(f"[{now_str}] [-] Heartbeat delivery failed: {msg}")
        time.sleep(interval)

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_SERVER
    run_agent(target)
