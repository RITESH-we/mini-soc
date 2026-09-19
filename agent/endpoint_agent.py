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

import tempfile
import re
import xml.etree.ElementTree as ET

# Live public ngrok server endpoint by default
DEFAULT_SERVER = "https://underfoot-such-italics.ngrok-free.dev/api/v1/telemetry"
AGENT_VERSION = "2.2.0"
STATE_FILE = os.path.join(tempfile.gettempdir(), "minisoc_agent_state.json")

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

def load_agent_state() -> dict:
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {"last_records": {}, "linux_offset": 0}

def save_agent_state(state: dict):
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(state, f)
    except Exception:
        pass

def _parse_xml_event(node) -> dict:
    ns = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}
    try:
        sys_node = node.find("e:System", ns) if node.find("e:System", ns) is not None else node.find("System")
        if sys_node is None:
            return None
        eid_el = sys_node.find("e:EventID", ns) if sys_node.find("e:EventID", ns) is not None else sys_node.find("EventID")
        event_id = int(eid_el.text) if eid_el is not None and eid_el.text else 0
        rec_el = sys_node.find("e:EventRecordID", ns) if sys_node.find("e:EventRecordID", ns) is not None else sys_node.find("EventRecordID")
        record_id = int(rec_el.text) if rec_el is not None and rec_el.text else 0
        chan_el = sys_node.find("e:Channel", ns) if sys_node.find("e:Channel", ns) is not None else sys_node.find("Channel")
        channel = chan_el.text if chan_el is not None and chan_el.text else "Security"
        time_el = sys_node.find("e:TimeCreated", ns) if sys_node.find("e:TimeCreated", ns) is not None else sys_node.find("TimeCreated")
        timestamp = time_el.get("SystemTime") if time_el is not None else datetime.now().isoformat()

        data_node = node.find("e:EventData", ns) if node.find("e:EventData", ns) is not None else node.find("EventData")
        fields = {}
        if data_node is not None:
            for d in list(data_node):
                name = d.get("Name")
                val = d.text or ""
                if name:
                    fields[name] = val
                elif val:
                    fields[f"Data_{len(fields)}"] = val

        user = fields.get("TargetUserName") or fields.get("SubjectUserName") or fields.get("User") or ""
        domain = fields.get("TargetDomainName") or fields.get("SubjectDomainName") or ""
        src_ip = fields.get("IpAddress") or fields.get("SourceIp") or ""
        if src_ip == "-" or src_ip.startswith("::"):
            src_ip = "127.0.0.1"
        process = fields.get("NewProcessName") or fields.get("ProcessName") or fields.get("Image") or ""
        cmdline = fields.get("CommandLine") or fields.get("ScriptBlockText") or ""

        if event_id == 4625:
            rule_name = "Windows Logon Failure"
            severity = "MEDIUM"
            mitre_tactic = "Credential Access"
            mitre_technique = "T1110 - Brute Force"
            details = f"Logon failure for user '{user}' from IP {src_ip} (SubStatus: {fields.get('SubStatus', 'N/A')})"
        elif event_id == 4624:
            rule_name = "Windows Successful Logon"
            severity = "INFO"
            mitre_tactic = "Initial Access"
            mitre_technique = "T1078 - Valid Accounts"
            details = f"Successful logon for user '{user}' from IP {src_ip}"
        elif event_id == 4688:
            rule_name = "Process Creation"
            severity = "LOW"
            mitre_tactic = "Execution"
            mitre_technique = "T1059 - Command Execution"
            details = f"Process spawned: {process} | CLI: {cmdline[:100]}"
        elif event_id == 4104:
            rule_name = "PowerShell Script Block"
            severity = "MEDIUM"
            mitre_tactic = "Execution"
            mitre_technique = "T1059.001 - PowerShell"
            details = f"PowerShell execution: {cmdline[:120]}"
        elif event_id == 4720:
            rule_name = "User Account Created"
            severity = "HIGH"
            mitre_tactic = "Persistence"
            mitre_technique = "T1136 - Create Account"
            details = f"New user '{user}' created by '{fields.get('SubjectUserName', 'SYSTEM')}'"
        elif event_id == 4732:
            rule_name = "Member Added to Security Group"
            severity = "HIGH"
            mitre_tactic = "Privilege Escalation"
            mitre_technique = "T1078 - Valid Accounts"
            details = f"Member '{fields.get('MemberName', '')}' added to group '{user}'"
        else:
            rule_name = f"Security Event {event_id}"
            severity = "LOW"
            mitre_tactic = "Execution"
            mitre_technique = "T1059"
            details = f"Event {event_id} on {channel}"

        return {
            "event_id": event_id,
            "record_id": record_id,
            "channel": channel,
            "timestamp": timestamp,
            "rule_name": rule_name,
            "severity": severity,
            "mitre_tactic": mitre_tactic,
            "mitre_technique": mitre_technique,
            "user": user,
            "domain": domain,
            "src_ip": src_ip,
            "process": process,
            "command_line": cmdline,
            "details": details,
            "raw_fields": fields
        }
    except Exception:
        return None

def get_security_audit_events():
    """
    Extracts recent authentication and process execution audit events
    using native OS commands with XML structured parsing and state tracking.
    """
    events = []
    system = platform.system()
    state = load_agent_state()
    last_records = state.get("last_records", {})

    if system == "Windows":
        channels = [
            ("Security", "*[System[(EventID=4624 or EventID=4625 or EventID=4688 or EventID=4720 or EventID=4732)]]"),
            ("Microsoft-Windows-PowerShell/Operational", "*[System[(EventID=4104)]]")
        ]
        
        for chan_name, query in channels:
            try:
                cmd = ["wevtutil", "qe", chan_name, f"/q:{query}", "/f:xml", "/c:10", "/rd:true"]
                out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, universal_newlines=True)
                if not out or not out.strip():
                    continue

                raw_blocks = re.findall(r"(<Event\b[^>]*>.*?</Event>)", out.strip(), re.DOTALL)
                last_rec = last_records.get(chan_name, 0)
                max_rec_in_batch = last_rec

                batch_events = []
                for block in raw_blocks:
                    try:
                        node = ET.fromstring(block)
                        parsed = _parse_xml_event(node)
                        if parsed:
                            rec_id = parsed["record_id"]
                            if rec_id > max_rec_in_batch:
                                max_rec_in_batch = rec_id
                            if last_rec == 0:
                                if len(batch_events) < 2:
                                    batch_events.append(parsed)
                            elif rec_id > last_rec:
                                batch_events.append(parsed)
                    except Exception:
                        continue

                events.extend(batch_events)
                last_records[chan_name] = max_rec_in_batch
            except Exception:
                continue

        state["last_records"] = last_records
        save_agent_state(state)

    elif system == "Linux":
        auth_file = "/var/log/auth.log" if os.path.exists("/var/log/auth.log") else ("/var/log/secure" if os.path.exists("/var/log/secure") else None)
        if auth_file:
            try:
                last_offset = state.get("linux_offset", 0)
                with open(auth_file, "r") as f:
                    f.seek(0, 2)
                    file_size = f.tell()
                    if last_offset == 0 or last_offset > file_size:
                        read_start = max(0, file_size - 5000)
                        f.seek(read_start)
                    else:
                        f.seek(last_offset)
                    
                    new_lines = f.readlines()
                    state["linux_offset"] = f.tell()
                    save_agent_state(state)

                for line in new_lines:
                    if "Failed password" in line:
                        u_m = re.search(r"Failed password for (?:invalid user )?(\S+) from (\S+)", line)
                        user = u_m.group(1) if u_m else "unknown"
                        ip = u_m.group(2) if u_m else "unknown"
                        events.append({
                            "event_id": 4625,
                            "record_id": 0,
                            "channel": "auth.log",
                            "timestamp": datetime.now().isoformat(),
                            "rule_name": "Linux SSH Failed Logon",
                            "severity": "MEDIUM",
                            "mitre_tactic": "Credential Access",
                            "mitre_technique": "T1110 - Brute Force",
                            "user": user,
                            "domain": "LOCAL",
                            "src_ip": ip,
                            "process": "sshd",
                            "command_line": "",
                            "details": f"Failed SSH authentication for '{user}' from {ip}",
                            "raw_fields": {"raw": line.strip()}
                        })
            except Exception:
                pass

    return events[:25]

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
