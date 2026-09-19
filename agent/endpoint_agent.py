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

DEFAULT_SERVER = "http://127.0.0.1:5000/api/v1/telemetry"
AGENT_VERSION = "2.0.0"

def get_system_info():
    hostname = socket.gethostname()
    try:
        ip = socket.gethostbyname(hostname)
    except Exception:
        ip = "127.0.0.1"
    return {
        "hostname": hostname,
        "ip_address": ip,
        "os": f"{platform.system()} {platform.release()}",
        "architecture": platform.machine(),
        "agent_version": AGENT_VERSION,
        "timestamp": datetime.now().isoformat()
    }

def get_active_connections():
    connections = []
    try:
        # Use netstat for cross-platform zero-dependency extraction
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
    return connections[:50] # Top 50 connections

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

def execute_remediation(action_payload):
    action = action_payload.get("action")
    target = action_payload.get("target")
    if action == "kill_process" and target:
        if platform.system() == "Windows":
            subprocess.run(["taskkill", "/F", "/PID", str(target)], capture_output=True)
        else:
            subprocess.run(["kill", "-9", str(target)], capture_output=True)
        return f"Process {target} killed"
    elif action == "isolate_host":
        if platform.system() == "Windows":
            # Block all non-local outbound traffic
            subprocess.run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                "name=MiniSOC_Endpoint_Quarantine", "dir=out", "action=block"
            ], capture_output=True)
        return "Host isolated from network"
    return "No action taken"

def send_telemetry(server_url):
    payload = {
        "system": get_system_info(),
        "connections": get_active_connections(),
        "processes": get_top_processes()
    }
    data_bytes = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        server_url,
        data=data_bytes,
        headers={"Content-Type": "application/json", "User-Agent": f"MiniSOC-Agent/{AGENT_VERSION}"}
    )
    
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            if response.status == 200:
                res_data = json.loads(response.read().decode("utf-8"))
                if "command" in res_data:
                    execute_remediation(res_data["command"])
                return True, "Telemetry delivered"
    except Exception as e:
        return False, str(e)

def run_agent(server_url=DEFAULT_SERVER, interval=15):
    print("=" * 55)
    print(f"  MiniSOC Endpoint Agent v{AGENT_VERSION}")
    print(f"  Target Server: {server_url}")
    print(f"  Heartbeat Interval: {interval}s")
    print("=" * 55)
    
    while True:
        success, msg = send_telemetry(server_url)
        now_str = datetime.now().strftime("%H:%M:%S")
        if success:
            print(f"[{now_str}] [+] Heartbeat sent successfully to {server_url}")
        else:
            print(f"[{now_str}] [-] Heartbeat failed: {msg}")
        time.sleep(interval)

if __name__ == "__main__":
    server = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_SERVER
    run_agent(server)
