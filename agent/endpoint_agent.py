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
import base64
import csv
import ipaddress

# Prevent console window flash/popups when running under pythonw or background tasks on Windows
if sys.stdout is None:
    sys.stdout = open(os.devnull, "w", encoding="utf-8")
if sys.stderr is None:
    sys.stderr = open(os.devnull, "w", encoding="utf-8")

LOG_FILE = os.path.join(tempfile.gettempdir(), "minisoc_agent.log")

def log_msg(msg: str):
    """Logs messages safely to stdout (if present) and to a persistent log file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    formatted = f"[{timestamp}] {msg}"
    try:
        if sys.stdout is not None:
            print(formatted)
            sys.stdout.flush()
    except Exception:
        pass
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(formatted + "\n")
    except Exception:
        pass

def get_windows_hidden_flags():
    """Return creationflags and STARTUPINFO to guarantee child console apps never spawn a window."""
    flags = {}
    if platform.system() == "Windows":
        flags["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
        try:
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            si.wShowWindow = 0  # SW_HIDE
            flags["startupinfo"] = si
        except Exception:
            pass
    return flags

def silent_check_output(cmd, **kwargs):
    """Executes a command and returns output with zero console popups on Windows."""
    if platform.system() == "Windows":
        for k, v in get_windows_hidden_flags().items():
            kwargs.setdefault(k, v)
    return subprocess.check_output(cmd, **kwargs)

def silent_run(cmd, **kwargs):
    """Runs a command with zero console popups on Windows."""
    if platform.system() == "Windows":
        for k, v in get_windows_hidden_flags().items():
            kwargs.setdefault(k, v)
    return subprocess.run(cmd, **kwargs)

def silent_popen(cmd, **kwargs):
    """Spawns a process with zero console popups on Windows."""
    if platform.system() == "Windows":
        for k, v in get_windows_hidden_flags().items():
            kwargs.setdefault(k, v)
    return subprocess.Popen(cmd, **kwargs)

# Live public 24/7 cloud server endpoint by default
DEFAULT_SERVER = "https://trishula-soc.onrender.com/api/v1/telemetry"
AGENT_VERSION = "2.2.0"
STATE_FILE = os.path.join(tempfile.gettempdir(), "minisoc_agent_state.json")

# Policy Profiles: 'standard_workstation' (15s), 'high_security_server' (5s), 'audit_friend' (15s safe mode)
CURRENT_PROFILE = "standard_workstation"
CURRENT_INTERVAL = 15

def normalize_profile(p: str) -> str:
    p = (p or '').strip().lower()
    if p in ['server', 'high_security_server', 'prod']:
        return 'high_security_server'
    elif p in ['friend', 'audit_friend', 'safe', 'byod']:
        return 'audit_friend'
    return 'standard_workstation'

def _load_persisted_profile() -> str:
    """Read the last-known profile from STATE_FILE so restarts are non-disruptive."""
    try:
        state = load_agent_state()
        return state.get('profile', 'standard_workstation')
    except Exception:
        return 'standard_workstation'

def sync_profile(new_p: str):
    global CURRENT_PROFILE, CURRENT_INTERVAL
    norm = normalize_profile(new_p)
    changed = (norm != CURRENT_PROFILE)
    CURRENT_PROFILE = norm
    CURRENT_INTERVAL = 5 if CURRENT_PROFILE == "high_security_server" else 15
    if changed:
        log_msg(f"[!] Policy Profile synced from SOC console: {CURRENT_PROFILE} (Heartbeat: {CURRENT_INTERVAL}s)")
    # Always persist — ensures restarts pick up the correct profile
    try:
        state = load_agent_state()
        state['profile'] = CURRENT_PROFILE
        save_agent_state(state)
    except Exception:
        pass


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
    elif "ANDROID_ROOT" in os.environ or "ANDROID_DATA" in os.environ or os.path.exists("/system/build.prop"):
        return f"Android (Linux {platform.release()})"
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
        "profile": CURRENT_PROFILE,
        "timestamp": datetime.now().isoformat()
    }

def deobfuscate_powershell_cmd(cmdline: str) -> str:
    """Detects Base64 encoded PowerShell scripts (-enc / -encodedcommand) and decodes UTF-16LE payload."""
    if not cmdline:
        return ""
    m = re.search(r'(?:-|/)(?:e|enc|encodedcommand)\s+([A-Za-z0-9+/=]{8,})', cmdline, re.IGNORECASE)
    if m:
        b64_str = m.group(1)
        try:
            raw = base64.b64decode(b64_str)
            decoded = raw.decode('utf-16le', errors='ignore').strip()
            if decoded:
                return decoded
        except Exception:
            pass
    return ""

# Honey-Token Canary Trap definition
CANARY_FILE = os.path.join(tempfile.gettempdir(), "minisoc_vault_creds.db")
CANARY_CONTENT = b"# MiniSOC Security Canary Vault -- DO NOT EDIT\n[vault]\nmaster_key_hash=9f83acde923b0918\n"
CANARY_EXPECTED_SIZE = len(CANARY_CONTENT)

def ensure_canary_trap():
    """Plants a honey-token credential file to detect credential stealers and unauthorized tampering."""
    try:
        if not os.path.exists(CANARY_FILE):
            with open(CANARY_FILE, "wb") as f:
                f.write(CANARY_CONTENT)
    except Exception:
        pass

def check_canary_trap() -> dict:
    """Monitors the honey-token canary file. Any modification or deletion fires a critical alert."""
    ensure_canary_trap()
    try:
        if not os.path.exists(CANARY_FILE):
            ensure_canary_trap()
            return {
                "event_id": 9991,
                "record_id": int(time.time()),
                "channel": "MiniSOC-Canary",
                "timestamp": datetime.now().isoformat(),
                "rule_name": "Canary Honey-File Trap Tripped (Deletion/Tampering)",
                "severity": "CRITICAL",
                "mitre_tactic": "Credential Access",
                "mitre_technique": "T1081 - Credentials in Files",
                "user": "SYSTEM",
                "domain": "LOCAL",
                "src_ip": "127.0.0.1",
                "process": "unknown",
                "command_line": "",
                "details": f"CRITICAL DECEPTION ALERT: Honey-token canary '{CANARY_FILE}' was deleted or moved! Active credential theft / ransomware activity suspected.",
                "raw_fields": {"canary_file": CANARY_FILE}
            }
        stat = os.stat(CANARY_FILE)
        if stat.st_size != CANARY_EXPECTED_SIZE and stat.st_size > 0:
            return {
                "event_id": 9992,
                "record_id": int(time.time()),
                "channel": "MiniSOC-Canary",
                "timestamp": datetime.now().isoformat(),
                "rule_name": "Canary Honey-File Tampering Detected",
                "severity": "CRITICAL",
                "mitre_tactic": "Credential Access",
                "mitre_technique": "T1081 - Credentials in Files",
                "user": "SYSTEM",
                "domain": "LOCAL",
                "src_ip": "127.0.0.1",
                "process": "unknown",
                "command_line": "",
                "details": f"CRITICAL DECEPTION ALERT: Honey-token canary '{CANARY_FILE}' was modified (size {stat.st_size} bytes, expected {CANARY_EXPECTED_SIZE}).",
                "raw_fields": {"canary_file": CANARY_FILE}
            }
    except Exception:
        pass
    return None


def check_persistence_registry() -> list:
    """Monitors Windows Run Keys for unauthorized startup persistence (T1547.001)."""
    if platform.system() != "Windows":
        return []
    alerts = []
    state = load_agent_state()
    known_entries = set(state.get("known_run_keys", []))
    current_entries = []

    try:
        ps_cmd = "Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -ErrorAction SilentlyContinue | Select-Object -Property * -ExcludeProperty PS*, Item* | ConvertTo-Json"
        out = silent_check_output(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd], stderr=subprocess.DEVNULL, universal_newlines=True, timeout=5)
        if out and out.strip():
            data = json.loads(out)
            items = data if isinstance(data, list) else [data]
            for block in items:
                if isinstance(block, dict):
                    for k, v in block.items():
                        if k and v and isinstance(v, str):
                            entry_sig = f"{k}={v}"
                            current_entries.append(entry_sig)
                            if known_entries and entry_sig not in known_entries:
                                alerts.append({
                                    "event_id": 9993,
                                    "record_id": int(time.time()),
                                    "channel": "MiniSOC-Persistence",
                                    "timestamp": datetime.now().isoformat(),
                                    "rule_name": "Rogue Persistence: Registry Run Key Added",
                                    "severity": "HIGH",
                                    "mitre_tactic": "Persistence",
                                    "mitre_technique": "T1547.001 - Registry Run Keys / Startup Folder",
                                    "user": "LOCAL",
                                    "domain": "LOCAL",
                                    "src_ip": "127.0.0.1",
                                    "process": "registry",
                                    "command_line": str(v)[:200],
                                    "details": f"New persistence entry added to Windows Run Key: '{k}' -> '{v}'",
                                    "raw_fields": {"key": k, "target": v}
                                })
            state["known_run_keys"] = current_entries
            save_agent_state(state)
    except Exception:
        pass
    return alerts

def check_usb_devices() -> list:
    """Detects newly attached USB mass storage / BadUSB devices (T1091)."""
    if platform.system() != "Windows":
        return []
    alerts = []
    state = load_agent_state()
    known_usb = set(state.get("known_usb_devices", []))
    current_usb = []

    try:
        ps_cmd = "Get-CimInstance Win32_DiskDrive | Where-Object { $_.InterfaceType -eq 'USB' } | Select-Object -Property DeviceID, Model, Size | ConvertTo-Json"
        out = silent_check_output(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd], stderr=subprocess.DEVNULL, universal_newlines=True, timeout=4)
        if out and out.strip():
            data = json.loads(out)
            items = data if isinstance(data, list) else [data]
            for item in items:
                if isinstance(item, dict):
                    dev_id = item.get("DeviceID") or item.get("Model")
                    if dev_id:
                        current_usb.append(dev_id)
                        if known_usb and dev_id not in known_usb:
                            alerts.append({
                                "event_id": 9994,
                                "record_id": int(time.time()),
                                "channel": "MiniSOC-USB",
                                "timestamp": datetime.now().isoformat(),
                                "rule_name": "Removable USB Drive Attached (Physical Access)",
                                "severity": "MEDIUM",
                                "mitre_tactic": "Initial Access",
                                "mitre_technique": "T1091 - Replication Through Removable Media",
                                "user": "LOCAL",
                                "domain": "LOCAL",
                                "src_ip": "127.0.0.1",
                                "process": "kernel",
                                "command_line": "",
                                "details": f"New USB storage device connected: Model '{item.get('Model')}' (DeviceID: {dev_id})",
                                "raw_fields": item
                            })
            state["known_usb_devices"] = current_usb
            save_agent_state(state)
    except Exception:
        pass
    return alerts

def get_active_connections():
    connections = []
    try:
        if platform.system() == "Windows":
            cmd = ["netstat", "-ano"]
        else:
            cmd = ["netstat", "-tulnp"]
        try:
            output = silent_check_output(cmd, stderr=subprocess.DEVNULL, universal_newlines=True)
        except Exception:
            # Fallback for Android / minimal Linux without netstat-tools
            cmd = ["ss", "-ant"]
            output = silent_check_output(cmd, stderr=subprocess.DEVNULL, universal_newlines=True)

        for line in output.splitlines():
            line = line.strip()
            if line.startswith("TCP") or line.startswith("UDP") or line.startswith("tcp") or line.startswith("udp") or line.startswith("LISTEN") or line.startswith("ESTAB"):
                parts = line.split()
                if len(parts) >= 4:
                    connections.append({
                        "proto": parts[0],
                        "local": parts[1] if len(parts) > 3 else "0.0.0.0",
                        "remote": parts[2] if len(parts) > 3 else "0.0.0.0",
                        "state": parts[3] if len(parts) > 4 else parts[1],
                        "pid": parts[-1]
                    })
    except Exception as e:
        connections.append({"error": str(e)})
    return connections[:150]

def get_top_processes():
    """
    Extracts deep process telemetry including executable path, parent process (PPID),
    and command-line arguments to defeat process masquerading.
    """
    procs = []
    if platform.system() == "Windows":
        try:
            ps_cmd = (
                "Get-CimInstance Win32_Process | Select-Object -First 100 ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine, "
                "@{N='MemoryMB';E={[math]::Round($_.WorkingSetSize/1MB,1)}} | ConvertTo-Csv -NoTypeInformation"
            )
            out = silent_check_output(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd], stderr=subprocess.DEVNULL, universal_newlines=True, timeout=5)
            lines = [l.strip() for l in out.splitlines() if l.strip()]
            if len(lines) > 1:
                reader = csv.DictReader(lines)
                for row in reader:
                    name = row.get("Name") or ""
                    if name:
                        procs.append({
                            "name": name,
                            "pid": row.get("ProcessId") or "-",
                            "ppid": row.get("ParentProcessId") or "-",
                            "executable_path": row.get("ExecutablePath") or "",
                            "command_line": (row.get("CommandLine") or "")[:400],
                            "mem_usage": f"{row.get('MemoryMB', '0')} MB"
                        })
        except Exception:
            pass

    if not procs:
        try:
            if platform.system() == "Windows":
                cmd = ["tasklist", "/FO", "CSV", "/NH"]
                output = silent_check_output(cmd, stderr=subprocess.DEVNULL, universal_newlines=True)
                for line in output.splitlines():
                    if line.strip():
                        cols = [c.strip('"') for c in line.split('","')]
                        if len(cols) >= 5:
                            procs.append({
                                "name": cols[0],
                                "pid": cols[1],
                                "ppid": "-",
                                "executable_path": "",
                                "command_line": "",
                                "mem_usage": cols[4]
                            })
            else:
                try:
                    cmd = ["ps", "-eo", "pid,user,%cpu,%mem,comm,args", "--sort=-%mem"]
                    output = silent_check_output(cmd, stderr=subprocess.DEVNULL, universal_newlines=True)
                    for line in output.splitlines()[1:100]:
                        parts = line.split(None, 5)
                        if len(parts) >= 5:
                            procs.append({
                                "pid": parts[0],
                                "user": parts[1],
                                "cpu": parts[2],
                                "mem": parts[3],
                                "name": parts[4],
                                "command_line": parts[5][:300] if len(parts) > 5 else parts[4]
                            })
                except Exception:
                    # Android / BusyBox fallback
                    cmd = ["ps"]
                    output = silent_check_output(cmd, stderr=subprocess.DEVNULL, universal_newlines=True)
                    for line in output.splitlines()[1:100]:
                        parts = line.split()
                        if len(parts) >= 4:
                            procs.append({
                                "pid": parts[0] if parts[0].isdigit() else (parts[1] if len(parts)>1 and parts[1].isdigit() else "-"),
                                "name": parts[-1],
                                "command_line": parts[-1]
                            })
        except Exception as e:
            procs.append({"error": str(e)})
    return procs[:100]


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
        raw_cmdline = fields.get("CommandLine") or fields.get("ScriptBlockText") or ""
        
        # Transparent Base64 De-obfuscation
        decoded_script = deobfuscate_powershell_cmd(raw_cmdline)
        if decoded_script:
            cmdline = f"{raw_cmdline} [DE-OBFUSCATED]: {decoded_script}"
        else:
            cmdline = raw_cmdline

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
        elif event_id == 4648:
            rule_name = "Logon Attempt with Explicit Credentials (PtH)"
            severity = "HIGH"
            mitre_tactic = "Lateral Movement"
            mitre_technique = "T1550.002 - Pass the Hash"
            details = f"Explicit credential logon: user '{user}' connecting to target '{fields.get('TargetServerName', 'LOCAL')}'"
        elif event_id == 4672:
            rule_name = "Admin Token Assigned to New Logon"
            severity = "LOW"
            mitre_tactic = "Privilege Escalation"
            mitre_technique = "T1078.003 - Local Accounts"
            details = f"Special administrative privileges assigned to logon session for '{user}'"
        elif event_id == 4688:
            # Deep CLI Inspection for Top Attack Signatures (runs against both raw & de-obfuscated payload)
            low_cmd = cmdline.lower()
            if re.search(r"(vssadmin.*delete\s+shadows|wmic.*shadowcopy\s+delete|wbadmin.*delete\s+catalog|bcdedit.*recoveryenabled\s+no|bcdedit.*ignoreallfailures)", low_cmd):
                rule_name = "Ransomware Recovery Inhibition (Shadow Copy Deletion)"
                severity = "CRITICAL"
                mitre_tactic = "Impact"
                mitre_technique = "T1490 - Inhibit System Recovery"
                details = f"RANSOMWARE ALERT: Shadow copy destruction command executed: {cmdline[:180]}"
            elif re.search(r"(mimikatz|comsvcs\.dll.*minidump|vaultcmd|cmdkey\s+/list|whoami\s+/priv|findstr.*password)", low_cmd):
                rule_name = "In-Memory Credential Dumping / Snooping"
                severity = "HIGH"
                mitre_tactic = "Credential Access"
                mitre_technique = "T1003.001 - LSASS Memory"
                details = f"Credential access / dumping command executed: {cmdline[:180]}"
            elif re.search(r"(compress-archive|tar\s+-[a-z]*z|7z\s+a|rar\s+a)", low_cmd):
                rule_name = "Data Staging for Exfiltration"
                severity = "HIGH"
                mitre_tactic = "Collection"
                mitre_technique = "T1560 - Archive Collected Data"
                details = f"Data staging archive command executed: {cmdline[:180]}"
            elif re.search(r"(-enc\s+|-encodedcommand\s+|amsiutils|downloadstring|iex\s*\(|certutil.*urlcache|bitsadmin.*transfer|mshta\s+http|rundll32.*javascript)", low_cmd):
                rule_name = "Living-off-the-Land Obfuscated Execution / Download Cradle"
                severity = "HIGH"
                mitre_tactic = "Execution"
                mitre_technique = "T1059.001 - PowerShell / LOLBins"
                details = f"Living-off-the-Land attack execution: {cmdline[:180]}"
            else:
                rule_name = "Process Creation"
                severity = "LOW"
                mitre_tactic = "Execution"
                mitre_technique = "T1059 - Command Execution"
                details = f"Process spawned: {process} | CLI: {cmdline[:120]}"
        elif event_id == 4104:
            low_cmd = cmdline.lower()
            if re.search(r"(-enc\s+|-encodedcommand\s+|amsiutils|downloadstring|iex\s*\(|invoke-expression|bitstransfer|system\.net\.webclient)", low_cmd):
                rule_name = "Suspicious PowerShell Script Block"
                severity = "HIGH"
                mitre_tactic = "Execution"
                mitre_technique = "T1059.001 - PowerShell"
                details = f"Living-off-the-Land script block detected: {cmdline[:180]}"
            else:
                rule_name = "PowerShell Script Block"
                severity = "MEDIUM"
                mitre_tactic = "Execution"
                mitre_technique = "T1059.001 - PowerShell"
                details = f"PowerShell execution: {cmdline[:140]}"
        elif event_id == 4698:
            task_name = fields.get("TaskName", "Unknown")
            rule_name = "Scheduled Task Created"
            severity = "HIGH"
            mitre_tactic = "Persistence"
            mitre_technique = "T1053.005 - Scheduled Task"
            details = f"Rogue scheduled task created: '{task_name}' by '{user or fields.get('SubjectUserName', 'SYSTEM')}'"
        elif event_id == 4697 or event_id == 7045:
            svc_name = fields.get("ServiceName", "Unknown")
            svc_file = fields.get("ImagePath") or fields.get("ServiceFileName", "")
            rule_name = "New System Service Installed"
            severity = "HIGH"
            mitre_tactic = "Persistence"
            mitre_technique = "T1543.003 - Windows Service"
            details = f"New system service installed: '{svc_name}' (Image: {svc_file})"
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
        elif event_id in (1102, 104):
            rule_name = "Windows Event Log Cleared"
            severity = "CRITICAL"
            mitre_tactic = "Defense Evasion"
            mitre_technique = "T1070.001 - Clear Windows Event Logs"
            details = f"Security/System audit log wiped/cleared by user '{user or fields.get('SubjectUserName', 'UNKNOWN')}' (Anti-Forensics)"
        elif event_id == 1116:
            threat_name = fields.get("Threat Name", "Unknown Threat")
            threat_path = fields.get("Path", "")
            rule_name = "Windows Defender Threat Detected"
            severity = "CRITICAL"
            mitre_tactic = "Defense Evasion"
            mitre_technique = "T1204 - User Execution"
            details = f"Windows Defender detected malware threat '{threat_name}' at path '{threat_path}'"
        elif event_id == 1117:
            threat_name = fields.get("Threat Name", "Unknown Threat")
            rule_name = "Windows Defender Action Taken"
            severity = "HIGH"
            mitre_tactic = "Defense Evasion"
            mitre_technique = "T1204 - User Execution"
            details = f"Windows Defender neutralized or quarantined threat '{threat_name}'"
        elif event_id == 5001:
            rule_name = "Windows Defender Real-Time Protection Disabled"
            severity = "CRITICAL"
            mitre_tactic = "Defense Evasion"
            mitre_technique = "T1562.001 - Disable or Modify Tools"
            details = "ALERT: Windows Defender real-time protection was disabled! Potential adversary defense tampering."
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

def commit_agent_state(pending_state: dict):
    """
    At-Least-Once Delivery: Persists high-watermark state to disk ONLY after
    the server confirms receipt with an HTTP 200 status code.
    """
    if not pending_state:
        return
    try:
        state = load_agent_state()
        if "last_records" in pending_state:
            if "last_records" not in state:
                state["last_records"] = {}
            for k, v in pending_state["last_records"].items():
                state["last_records"][k] = max(state["last_records"].get(k, 0), v)
        if "linux_offset" in pending_state:
            state["linux_offset"] = pending_state["linux_offset"]
        save_agent_state(state)
    except Exception as e:
        log_msg(f"[-] Warning: Failed to commit agent state: {e}")

def get_security_posture():
    """
    Audits local host security posture: Windows Defender / Antivirus status,
    Firewall profile state, and administrator execution level.
    """
    posture = {
        "antivirus": "Unknown",
        "firewall": "Unknown",
        "is_admin": False
    }
    system = platform.system()
    if system == "Windows":
        try:
            # Check elevated administrator privileges
            res = silent_run(["net", "session"], capture_output=True)
            posture["is_admin"] = bool(res.returncode == 0)
        except Exception:
            pass

        try:
            # Check Windows Firewall profile state
            fw_out = silent_check_output(["netsh", "advfirewall", "show", "allprofiles", "state"], stderr=subprocess.DEVNULL, universal_newlines=True)
            posture["firewall"] = "ACTIVE" if "ON" in fw_out else "DISABLED"
        except Exception:
            posture["firewall"] = "UNAVAILABLE"

        try:
            # Check Windows Defender service state
            sc_out = silent_check_output(["sc", "query", "WinDefend"], stderr=subprocess.DEVNULL, universal_newlines=True)
            if "RUNNING" in sc_out:
                posture["antivirus"] = "RUNNING (Windows Defender)"
            else:
                posture["antivirus"] = "STOPPED / THIRD-PARTY"
        except Exception:
            posture["antivirus"] = "UNAVAILABLE"

    elif system == "Linux":
        try:
            posture["is_admin"] = (os.geteuid() == 0)
        except Exception:
            pass
        try:
            posture["firewall"] = "iptables native"
        except Exception:
            pass

    return posture

def get_security_audit_events():
    """
    Extracts recent authentication and process execution audit events
    using native OS commands with XML structured parsing.
    Returns (events, pending_state) for transactional At-Least-Once delivery.
    """
    events = []
    system = platform.system()
    state = load_agent_state()
    last_records = state.get("last_records", {})
    pending_records = dict(last_records)
    pending_state = {"last_records": pending_records}

    if system == "Windows":
        channels = [
            ("Security", "*[System[(EventID=4624 or EventID=4625 or EventID=4648 or EventID=4672 or EventID=4688 or EventID=4697 or EventID=4698 or EventID=4720 or EventID=4732 or EventID=1102)]]"),
            ("System", "*[System[(EventID=7045 or EventID=104 or EventID=7036)]]"),
            ("Microsoft-Windows-PowerShell/Operational", "*[System[(EventID=4104)]]"),
            ("Microsoft-Windows-Windows Defender/Operational", "*[System[(EventID=1116 or EventID=1117 or EventID=5001)]]")
        ]
        
        for chan_name, query in channels:
            try:
                cmd = ["wevtutil", "qe", chan_name, f"/q:{query}", "/f:xml", "/c:50", "/rd:true"]
                out = silent_check_output(cmd, stderr=subprocess.DEVNULL, universal_newlines=True)
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
                                if len(batch_events) < 3:
                                    batch_events.append(parsed)
                            elif rec_id > last_rec:
                                batch_events.append(parsed)
                    except Exception:
                        continue

                events.extend(batch_events)
                pending_records[chan_name] = max_rec_in_batch
            except Exception:
                continue

        # ── Deception & Anti-Evasion Probes ────────────────────────
        # 1. Honey-Token Canary File Trap
        canary_alert = check_canary_trap()
        if canary_alert:
            events.append(canary_alert)

        # 2. Persistence Registry Watcher (Run keys)
        persist_alerts = check_persistence_registry()
        if persist_alerts:
            events.extend(persist_alerts)

        # 3. Removable USB Media Monitor
        usb_alerts = check_usb_devices()
        if usb_alerts:
            events.extend(usb_alerts)

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
                    pending_state["linux_offset"] = f.tell()

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

    return events[:50], pending_state


def is_admin() -> bool:
    """Checks if current process has Administrator/root rights."""
    try:
        if platform.system() == "Windows":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False


def run_elevated_powershell(script: str) -> bool:
    """
    Executes a PowerShell script block with Administrator elevation (RunAs)
    using UTF-16LE Base64 -EncodedCommand to eliminate all escaping and quoting issues.
    """
    try:
        encoded_bytes = script.encode("utf-16le")
        b64_str = base64.b64encode(encoded_bytes).decode("ascii")
        ps_cmd = f"Start-Process powershell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -EncodedCommand {b64_str}' -Verb RunAs -WindowStyle Hidden"
        r = silent_run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd], capture_output=True)
        return r.returncode == 0
    except Exception as e:
        log_msg(f"[-] run_elevated_powershell error: {e}")
        return False


def resolve_all_ips(target: str) -> list:
    """
    Discovers all local IPv4 and IPv6 addresses for a target hostname/domain locally on endpoint,
    including canonical variants (both apex and www) to capture CDN IP addresses.
    """
    if not target:
        return []
    clean = str(target).strip()
    if "://" in clean:
        clean = clean.split("://", 1)[1]
    if "/" in clean:
        clean = clean.split("/", 1)[0]
    if clean.count(":") == 1 and not clean.startswith("["):
        parts = clean.rsplit(":", 1)
        if parts[1].isdigit():
            clean = parts[0]

    try:
        ipaddress.ip_address(clean)
        return [clean]
    except ValueError:
        pass

    targets_to_query = [clean]
    if "." in clean and not clean.replace(".", "").isdigit():
        if clean.startswith("www."):
            targets_to_query.append(clean[4:])
        else:
            targets_to_query.append(f"www.{clean}")

    resolved = []
    for tgt in targets_to_query:
        try:
            addr_infos = socket.getaddrinfo(tgt, None)
            for ai in addr_infos:
                ip_str = ai[4][0]
                if ip_str not in resolved:
                    resolved.append(ip_str)
        except Exception:
            pass
    return resolved


def sinkhole_domain(domain: str, remove: bool = False) -> bool:
    """
    Enforces Layer 7 domain sinkholing on the endpoint using the OS hosts file
    and flushes DNS resolver cache so browsers immediately apply the change.
    """
    if not domain:
        return False
    clean = str(domain).strip().lower()
    if "://" in clean:
        clean = clean.split("://", 1)[1]
    if "/" in clean:
        clean = clean.split("/", 1)[0]
    if clean.count(":") == 1 and not clean.startswith("["):
        parts = clean.rsplit(":", 1)
        if parts[1].isdigit():
            clean = parts[0]

    try:
        ipaddress.ip_address(clean)
        return False
    except ValueError:
        pass

    system = platform.system()
    variants = [clean]
    if clean.startswith("www."):
        variants.append(clean[4:])
    else:
        variants.append(f"www.{clean}")
    variants = list(dict.fromkeys(variants))

    hosts_path = r"C:\Windows\System32\drivers\etc\hosts" if system == "Windows" else "/etc/hosts"

    try:
        content = ""
        if os.path.exists(hosts_path):
            with open(hosts_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

        lines = content.splitlines()
        new_lines = []
        for line in lines:
            line_strip = line.strip()
            if any(line_strip.endswith(f" {v}") or line_strip.endswith(f"\t{v}") for v in variants):
                continue
            if line_strip.startswith(f"# MiniSOC EDR Block: {clean}") or line_strip.startswith(f"# TRISHUL EDR Block: {clean}"):
                continue
            new_lines.append(line)

        if not remove:
            new_lines.append(f"# TRISHUL EDR Block: {clean}")
            for v in variants:
                new_lines.append(f"0.0.0.0 {v}")
                new_lines.append(f"::1 {v}")

        new_content = "\n".join(new_lines).strip() + "\n"
        with open(hosts_path, "w", encoding="utf-8") as f:
            f.write(new_content)

        if system == "Windows":
            silent_run(["ipconfig", "/flushdns"], capture_output=True)
        log_msg(f"[{'+' if remove else '!'}] Active Defense: Layer 7 hosts sinkhole {'removed' if remove else 'enforced'} for {clean}.")
        return True
    except (PermissionError, IOError):
        if system == "Windows":
            ps_lines = ['$p = "$env:SystemRoot\\System32\\drivers\\etc\\hosts"']
            ps_filter = " -and ".join([f"$_ -notmatch [regex]::Escape('{v}')" for v in variants])
            ps_lines.append(f"$c = (Get-Content $p | Where-Object {{ {ps_filter} }})")
            ps_lines.append("Set-Content -Path $p -Value $c -Force")
            if not remove:
                entries = "`n".join([f"0.0.0.0 {v}`n::1 {v}" for v in variants])
                ps_lines.append(f"$entry = \"`n# TRISHUL EDR Block: {clean}`n{entries}\"")
                ps_lines.append("Add-Content -Path $p -Value $entry")
            ps_lines.append("ipconfig /flushdns")
            ps_script = "\n".join(ps_lines)
            run_elevated_powershell(ps_script)
            log_msg(f"[!] Active Defense: Executed elevated Layer 7 hosts sinkhole for {clean}.")
            return True
    return False


def execute_remediation(action_payload, server_url=None):
    action = action_payload.get("action")
    target = action_payload.get("target")
    system = platform.system()
    
    if action == "set_profile" and action_payload.get("profile"):
        sync_profile(action_payload.get("profile"))
        return f"Profile updated to {CURRENT_PROFILE}"

    endpoint_scope = action_payload.get("endpoint_scope")
    if endpoint_scope and endpoint_scope not in ("GLOBAL", "ALL", ""):
        my_host = get_system_info().get("hostname", "")
        if endpoint_scope.lower() != my_host.lower():
            log_msg(f"[*] Suppressed command intended for endpoint '{endpoint_scope}' (this host: '{my_host}')")
            return f"Skipped (targeted at {endpoint_scope})"

    # ── audit_friend safe-mode: suppress disruptive automated actions ──────────
    DISRUPTIVE_ACTIONS = {"kill_process", "block_remote_ip"}
    if CURRENT_PROFILE == "audit_friend" and action in DISRUPTIVE_ACTIONS:
        log_msg(f"[*] audit_friend mode: suppressed automated '{action}' on {target}. "
                f"Manual operator commands (isolate, unblock) still execute normally.")
        return f"Suppressed (audit_friend mode): {action} on {target}"

    elif action == "kill_process" and target:
        if system == "Windows":
            silent_run(["taskkill", "/F", "/PID", str(target)], capture_output=True)
        else:
            silent_run(["kill", "-9", str(target)], capture_output=True)
        log_msg(f"[!] Active Defense: Process {target} terminated by MiniSOC EDR command.")
        return f"Process {target} killed"

    elif action == "block_remote_ip" and (target or action_payload.get("targets")):
        domain = action_payload.get("domain")
        original_target = action_payload.get("original_target")
        containment_profile = action_payload.get("containment_profile", "BIDIRECTIONAL_DROP")
        
        target_str = str(target or original_target or "").strip()
        if "://" in target_str:
            target_str = target_str.split("://", 1)[1]
        if "/" in target_str:
            target_str = target_str.split("/", 1)[0]
        if target_str.count(":") == 1 and not target_str.startswith("["):
            parts = target_str.rsplit(":", 1)
            if parts[1].isdigit():
                target_str = parts[0]

        is_domain = False
        if domain:
            is_domain = True
            if "://" in domain:
                domain = domain.split("://", 1)[1]
            if "/" in domain:
                domain = domain.split("/", 1)[0]
            if domain.count(":") == 1 and not domain.startswith("["):
                parts = domain.rsplit(":", 1)
                if parts[1].isdigit():
                    domain = parts[0]
        else:
            try:
                ipaddress.ip_address(target_str)
            except ValueError:
                if "." in target_str and not target_str.replace(".", "").isdigit():
                    domain = target_str
                    is_domain = True

        # 1. Gather all candidate IPs to drop (including apex and www variants)
        ip_set = set()
        if target:
            ip_set.add(str(target).strip())
        for rip in action_payload.get("targets", []):
            if rip:
                ip_set.add(str(rip).strip())
        if is_domain and domain:
            for lip in resolve_all_ips(domain):
                ip_set.add(lip)
        elif target_str:
            for lip in resolve_all_ips(target_str):
                ip_set.add(lip)

        valid_ips = []
        for raw_ip in ip_set:
            try:
                ipaddress.ip_address(raw_ip)
                valid_ips.append(raw_ip)
            except ValueError:
                pass

        if not valid_ips and not is_domain:
            return "No valid IP or domain to block"

        # 2. Check if running with Administrator rights
        admin_mode = is_admin()

        if system == "Windows":
            if admin_mode:
                # Direct instant execution without prompting UAC
                if is_domain and domain:
                    sinkhole_domain(domain, remove=False)
                for target_ip in valid_ips:
                    rule_name = f"MiniSOC_EDR_Drop_{target_ip.replace(':', '_')}"
                    silent_run(["netsh", "advfirewall", "firewall", "add", "rule", f"name={rule_name}", "dir=out", "action=block", f"remoteip={target_ip}"], capture_output=True)
                    if containment_profile == "BIDIRECTIONAL_DROP":
                        silent_run(["netsh", "advfirewall", "firewall", "add", "rule", f"name={rule_name}_in", "dir=in", "action=block", f"remoteip={target_ip}"], capture_output=True)
                log_msg(f"[!] Active Defense: Target {target_str} ({len(valid_ips)} IPs) dropped directly via Administrator privileges.")
                return f"Blocked {target_str} ({len(valid_ips)} IPs)"
            else:
                # Unified elevated PowerShell execution with -EncodedCommand (Single prompt, zero quote errors!)
                ps_lines = []
                if is_domain and domain:
                    variants = [domain]
                    if domain.startswith("www."):
                        variants.append(domain[4:])
                    else:
                        variants.append(f"www.{domain}")
                    variants = list(dict.fromkeys(variants))
                    ps_lines.append('$p = "$env:SystemRoot\\System32\\drivers\\etc\\hosts"')
                    ps_filter = " -and ".join([f"$_ -notmatch [regex]::Escape('{v}')" for v in variants])
                    ps_lines.append(f"$c = (Get-Content $p | Where-Object {{ {ps_filter} }})")
                    ps_lines.append("Set-Content -Path $p -Value $c -Force")
                    entries = "`n".join([f"0.0.0.0 {v}`n::1 {v}" for v in variants])
                    ps_lines.append(f"$entry = \"`n# TRISHUL EDR Block: {domain}`n{entries}\"")
                    ps_lines.append("Add-Content -Path $p -Value $entry")
                    ps_lines.append("ipconfig /flushdns")

                for target_ip in valid_ips:
                    rule_name = f"MiniSOC_EDR_Drop_{target_ip.replace(':', '_')}"
                    ps_lines.append(f'netsh advfirewall firewall add rule name="{rule_name}" dir=out action=block remoteip={target_ip}')
                    if containment_profile == "BIDIRECTIONAL_DROP":
                        ps_lines.append(f'netsh advfirewall firewall add rule name="{rule_name}_in" dir=in action=block remoteip={target_ip}')

                combined_ps = "\n".join(ps_lines)
                run_elevated_powershell(combined_ps)
                log_msg(f"[!] Active Defense: Executed unified elevation for {target_str} (hosts sinkhole + {len(valid_ips)} firewall drops).")
                return f"Blocked {len(valid_ips)} IPs + {domain or ''} (elevation requested)"

        elif system == "Linux":
            if is_domain and domain:
                sinkhole_domain(domain, remove=False)
            for target_ip in valid_ips:
                silent_run(["iptables", "-A", "OUTPUT", "-d", target_ip, "-j", "DROP"], capture_output=True)
                if containment_profile == "BIDIRECTIONAL_DROP":
                    silent_run(["iptables", "-A", "INPUT", "-s", target_ip, "-j", "DROP"], capture_output=True)

        log_msg(f"[!] Active Defense: Target {target_str} (IPs: {', '.join(valid_ips[:4])}{'...' if len(valid_ips)>4 else ''}) contained by MiniSOC EDR ({containment_profile}).")
        return f"Target {target_str} contained ({len(valid_ips)} IPs)"

    elif action == "unblock_remote_ip" and (target or action_payload.get("targets")):
        domain = action_payload.get("domain")
        original_target = action_payload.get("original_target")
        target_str = str(target or original_target or "").strip()
        if "://" in target_str:
            target_str = target_str.split("://", 1)[1]
        if "/" in target_str:
            target_str = target_str.split("/", 1)[0]
        if target_str.count(":") == 1 and not target_str.startswith("["):
            parts = target_str.rsplit(":", 1)
            if parts[1].isdigit():
                target_str = parts[0]

        is_domain = False
        if domain:
            is_domain = True
            if "://" in domain:
                domain = domain.split("://", 1)[1]
            if "/" in domain:
                domain = domain.split("/", 1)[0]
            if domain.count(":") == 1 and not domain.startswith("["):
                parts = domain.rsplit(":", 1)
                if parts[1].isdigit():
                    domain = parts[0]
        else:
            try:
                ipaddress.ip_address(target_str)
            except ValueError:
                if "." in target_str and not target_str.replace(".", "").isdigit():
                    domain = target_str
                    is_domain = True

        ip_set = set()
        if target:
            ip_set.add(str(target).strip())
        for rip in action_payload.get("targets", []):
            if rip:
                ip_set.add(str(rip).strip())
        if is_domain and domain:
            for lip in resolve_all_ips(domain):
                ip_set.add(lip)
        elif target_str:
            for lip in resolve_all_ips(target_str):
                ip_set.add(lip)

        valid_ips = []
        for raw_ip in ip_set:
            try:
                ipaddress.ip_address(raw_ip)
                valid_ips.append(raw_ip)
            except ValueError:
                pass

        admin_mode = is_admin()

        if system == "Windows":
            if admin_mode:
                if is_domain and domain:
                    sinkhole_domain(domain, remove=True)
                for target_ip in valid_ips:
                    rule_name = f"MiniSOC_EDR_Drop_{target_ip.replace(':', '_')}"
                    silent_run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"], capture_output=True)
                    silent_run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}_in"], capture_output=True)
                log_msg(f"[+] Active Defense: Local firewall drop & sinkhole removed for {target_str} ({len(valid_ips)} IPs).")
                return f"Target {target_str} unblocked locally"
            else:
                ps_lines = []
                if is_domain and domain:
                    variants = [domain]
                    if domain.startswith("www."):
                        variants.append(domain[4:])
                    else:
                        variants.append(f"www.{domain}")
                    variants = list(dict.fromkeys(variants))
                    ps_lines.append('$p = "$env:SystemRoot\\System32\\drivers\\etc\\hosts"')
                    ps_filter = " -and ".join([f"$_ -notmatch [regex]::Escape('{v}')" for v in variants])
                    ps_lines.append(f"$c = (Get-Content $p | Where-Object {{ {ps_filter} }})")
                    ps_lines.append("Set-Content -Path $p -Value $c -Force")
                    ps_lines.append("ipconfig /flushdns")

                for target_ip in valid_ips:
                    rule_name = f"MiniSOC_EDR_Drop_{target_ip.replace(':', '_')}"
                    ps_lines.append(f'netsh advfirewall firewall delete rule name="{rule_name}"')
                    ps_lines.append(f'netsh advfirewall firewall delete rule name="{rule_name}_in"')

                combined_ps = "\n".join(ps_lines)
                run_elevated_powershell(combined_ps)
                log_msg(f"[+] Active Defense: Requested elevated removal of sinkhole & {len(valid_ips)} firewall rules for {target_str}.")
                return f"Target {target_str} unblocked locally"

        elif system == "Linux":
            if is_domain and domain:
                sinkhole_domain(domain, remove=True)
            for target_ip in valid_ips:
                silent_run(["iptables", "-D", "OUTPUT", "-d", target_ip, "-j", "DROP"], capture_output=True)
                silent_run(["iptables", "-D", "INPUT", "-s", target_ip, "-j", "DROP"], capture_output=True)

        log_msg(f"[+] Active Defense: Local firewall drop & sinkhole removed for {target_str} ({len(valid_ips)} IPs).")
        return f"Target {target_str} unblocked locally"


        
    elif action == "isolate_host":
        soc_ip = None
        if server_url:
            try:
                soc_host = server_url.split("://")[1].split("/")[0].split(":")[0]
                soc_ip = socket.gethostbyname(soc_host)
            except Exception:
                soc_ip = None

        if system == "Windows":
            # 1. Allow SOC management server IP so agent connectivity survives
            if soc_ip and soc_ip != "127.0.0.1":
                silent_run([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    "name=MiniSOC_EDR_Exemption", "dir=out", "action=allow", f"remoteip={soc_ip}"
                ], capture_output=True)
            # Allow loopback
            silent_run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                "name=MiniSOC_Loopback_Exemption", "dir=out", "action=allow", "remoteip=127.0.0.1"
            ], capture_output=True)
            # 2. Block all other outbound traffic
            silent_run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                "name=MiniSOC_Endpoint_Quarantine", "dir=out", "action=block"
            ], capture_output=True)
        elif system == "Linux":
            if soc_ip and soc_ip != "127.0.0.1":
                silent_run(["iptables", "-A", "OUTPUT", "-d", soc_ip, "-j", "ACCEPT"], capture_output=True)
            silent_run(["iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"], capture_output=True)
            silent_run(["iptables", "-A", "OUTPUT", "-j", "DROP"], capture_output=True)

        log_msg("\n" + "!" * 65)
        log_msg("[!] >>> COMMAND RECEIVED: HOST QUARANTINED FROM NETWORK <<<")
        log_msg("[!] Lateral movement & outbound internet traffic blocked (SOC link preserved).")
        log_msg("!" * 65 + "\n")
        return "Host quarantined"
        
    elif action == "unisolate_host":
        if system == "Windows":
            silent_run(["netsh", "advfirewall", "firewall", "delete", "rule", "name=MiniSOC_Endpoint_Quarantine"], capture_output=True)
            silent_run(["netsh", "advfirewall", "firewall", "delete", "rule", "name=MiniSOC_EDR_Exemption"], capture_output=True)
            silent_run(["netsh", "advfirewall", "firewall", "delete", "rule", "name=MiniSOC_Loopback_Exemption"], capture_output=True)
        elif system == "Linux":
            silent_run(["iptables", "-D", "OUTPUT", "-j", "DROP"], capture_output=True)
        log_msg("\n" + "+" * 65)
        log_msg("[+] >>> COMMAND RECEIVED: HOST QUARANTINE REMOVED <<<")
        log_msg("[+] Full outbound network access restored.")
        log_msg("+" * 65 + "\n")
        return "Host quarantine removed"
        
    return "No action taken"

def send_telemetry(server_url):
    server_url = normalize_server_url(server_url)
    audit_events, pending_state = get_security_audit_events()
    payload = {
        "system": get_system_info(),
        "security_posture": get_security_posture(),
        "connections": get_active_connections(),
        "processes": get_top_processes(),
        "events": audit_events
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
                # Commit watermark state ONLY after confirmed delivery
                commit_agent_state(pending_state)
                res_data = json.loads(response.read().decode("utf-8"))
                if "profile" in res_data:
                    sync_profile(res_data["profile"])
                if "command" in res_data:
                    c_payload = res_data["command"]
                    if isinstance(c_payload, list):
                        for single_c in c_payload:
                            execute_remediation(single_c, server_url=server_url)
                    else:
                        execute_remediation(c_payload, server_url=server_url)
                return True, "Telemetry delivered"
    except Exception as e:
        return False, str(e)

def run_agent(server_url=DEFAULT_SERVER, interval=None, profile="standard_workstation"):
    global CURRENT_PROFILE, CURRENT_INTERVAL
    # If no explicit profile passed (default), restore last-known profile from disk
    explicit_profile = normalize_profile(profile)
    persisted = _load_persisted_profile()
    if explicit_profile == 'standard_workstation' and persisted != 'standard_workstation':
        CURRENT_PROFILE = persisted
        log_msg(f"[*] Restored persisted profile from last session: {CURRENT_PROFILE}")
    else:
        CURRENT_PROFILE = explicit_profile
    CURRENT_INTERVAL = 5 if CURRENT_PROFILE == "high_security_server" else (interval if interval is not None else 15)

    server_url = normalize_server_url(server_url)
    log_msg("=" * 60)
    log_msg(f"  MiniSOC Endpoint Agent v{AGENT_VERSION} (Log Shipper & EDR)")
    log_msg(f"  Target Server: {server_url}")
    log_msg(f"  Active Policy Profile: {CURRENT_PROFILE}")
    log_msg(f"  Heartbeat Interval: {CURRENT_INTERVAL}s")
    log_msg("=" * 60)
    
    while True:
        success, msg = send_telemetry(server_url)
        now_str = datetime.now().strftime("%H:%M:%S")
        if success:
            log_msg(f"[{now_str}] [+] Heartbeat & telemetry delivered to {server_url} (Profile: {CURRENT_PROFILE})")
        else:
            log_msg(f"[{now_str}] [-] Heartbeat delivery failed: {msg}")
        time.sleep(CURRENT_INTERVAL)

def install_service(server_url=DEFAULT_SERVER, profile="standard_workstation"):
    server_url = normalize_server_url(server_url)
    profile = normalize_profile(profile)
    system = platform.system()
    script_path = os.path.abspath(__file__)
    py_exe = sys.executable

    print(f"[*] Installing MiniSOC Endpoint Agent (Profile: {profile}) as a persistent system service...")

    if system == "Windows":
        pyw_exe = os.path.join(os.path.dirname(py_exe), "pythonw.exe")
        runner = pyw_exe if os.path.exists(pyw_exe) else py_exe

        task_name = "MiniSOC_Endpoint_Agent"
        cmd_to_run = f'"{runner}" "{script_path}" "{server_url}" --profile "{profile}"'

        # 1. First, attempt Windows Task Scheduler (ideal if running as Administrator)
        create_cmd = [
            "schtasks", "/Create",
            "/TN", task_name,
            "/TR", cmd_to_run,
            "/SC", "ONLOGON",
            "/RL", "HIGHEST",
            "/F"
        ]
        res = silent_run(create_cmd, capture_output=True, text=True)
        if res.returncode == 0:
            print(f"[+] Successfully registered '{task_name}' in Windows Task Scheduler.")
            print("[+] Trigger: Automatic startup with HIGHEST privileges on user logon / boot.")
            silent_run(["schtasks", "/Run", "/TN", task_name], capture_output=True)
            print("[+] MiniSOC Agent is now running persistently in the background!")
            print("[+] You do NOT need to restart it after rebooting or powering off.")
            return True

        # 2. Fallback: Install into User Startup Folder (Works 100% without Administrator rights!)
        try:
            startup_dir = os.path.join(os.environ.get('APPDATA', ''), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
            if os.path.exists(startup_dir):
                vbs_path = os.path.join(startup_dir, "minisoc_agent.vbs")
                vbs_content = f'Set WshShell = CreateObject("WScript.Shell")\r\nWshShell.Run """{runner}"" ""{script_path}"" ""{server_url}"" --profile ""{profile}""", 0, False\r\n'
                with open(vbs_path, "w") as f:
                    f.write(vbs_content)
                
                print(f"[+] Successfully registered persistent background runner in Windows Startup:")
                print(f"    -> {vbs_path}")
                print("[+] Runs silently in background on every reboot / power-on without showing any black window.")
                silent_popen(["wscript.exe", vbs_path])
                print("[+] MiniSOC Agent launched successfully and active in background!")
                print("[+] Auto-start is fully configured. You never need to run it again manually.")
                return True
        except Exception as e:
            print(f"[-] Startup folder registration error: {e}")

        print("[-] Installation failed. Please run terminal with 'Run as Administrator'.")
        return False

    elif system == "Linux":
        unit_content = f"""[Unit]
Description=MiniSOC Endpoint EDR Agent
After=network.target

[Service]
Type=simple
ExecStart={py_exe} {script_path} {server_url} --profile {profile}
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""
        service_path = "/etc/systemd/system/minisoc-agent.service"
        try:
            with open(service_path, "w") as f:
                f.write(unit_content)
            silent_run(["systemctl", "daemon-reload"], check=True)
            silent_run(["systemctl", "enable", "--now", "minisoc-agent"], check=True)
            print(f"[+] Successfully created and enabled systemd service: {service_path}")
            print("[+] Agent is now running persistently across all system reboots.")
            return True
        except PermissionError:
            print("[-] Permission denied. Please run with sudo: sudo python3 endpoint_agent.py --install")
            return False
        except Exception as e:
            print(f"[-] Systemd installation failed: {e}")
            return False

    print(f"[-] OS {system} service auto-installation not supported.")
    return False

def uninstall_service():
    system = platform.system()
    print("[*] Uninstalling MiniSOC Endpoint Agent service...")
    removed = False

    if system == "Windows":
        task_name = "MiniSOC_Endpoint_Agent"
        silent_run(["schtasks", "/End", "/TN", task_name], capture_output=True)
        res = silent_run(["schtasks", "/Delete", "/TN", task_name, "/F"], capture_output=True)
        if res.returncode == 0:
            print(f"[+] Removed Task Scheduler task '{task_name}'.")
            removed = True

        startup_dir = os.path.join(os.environ.get('APPDATA', ''), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
        vbs_path = os.path.join(startup_dir, "minisoc_agent.vbs")
        if os.path.exists(vbs_path):
            try:
                os.remove(vbs_path)
                print(f"[+] Removed Startup runner '{vbs_path}'.")
                removed = True
            except Exception as e:
                print(f"[-] Could not remove {vbs_path}: {e}")

        # Terminate running pythonw agent process
        silent_run(["taskkill", "/F", "/IM", "pythonw.exe"], capture_output=True)
        if removed:
            print("[+] MiniSOC Agent uninstalled successfully.")
            return True
        else:
            print("[-] No installed MiniSOC background service found.")
            return False

    elif system == "Linux":
        service_path = "/etc/systemd/system/minisoc-agent.service"
        try:
            silent_run(["systemctl", "disable", "--now", "minisoc-agent"], capture_output=True)
            if os.path.exists(service_path):
                os.remove(service_path)
            silent_run(["systemctl", "daemon-reload"], capture_output=True)
            print("[+] MiniSOC systemd service removed.")
            return True
        except Exception as e:
            print(f"[-] Uninstall failed: {e}")
            return False
    return False

if __name__ == "__main__":
    args = sys.argv[1:]
    chosen_profile = "standard_workstation"
    if "--profile" in args:
        idx = args.index("--profile")
        if idx + 1 < len(args):
            chosen_profile = normalize_profile(args[idx + 1])

    if "--install" in args:
        target = DEFAULT_SERVER
        clean_args = [a for a in args if a not in ["--install", "--profile"] and a != chosen_profile and not a.startswith("--")]
        if clean_args:
            target = clean_args[0]
        install_service(target, profile=chosen_profile)
    elif "--uninstall" in args:
        uninstall_service()
    elif "--status" in args:
        if platform.system() == "Windows":
            res = silent_run(["schtasks", "/Query", "/TN", "MiniSOC_Endpoint_Agent", "/FO", "LIST", "/V"], capture_output=True, text=True)
            if res.returncode == 0:
                print(res.stdout)
            else:
                startup_dir = os.path.join(os.environ.get('APPDATA', ''), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
                vbs_path = os.path.join(startup_dir, "minisoc_agent.vbs")
                if os.path.exists(vbs_path):
                    print(f"[+] MiniSOC Agent installed in Startup folder: {vbs_path}")
                else:
                    print("[-] No installed MiniSOC background service found.")
        else:
            subprocess.run(["systemctl", "status", "minisoc-agent"])
    else:
        target = DEFAULT_SERVER
        clean_args = [a for a in args if a not in ["--profile"] and a != chosen_profile and not a.startswith("--")]
        if clean_args:
            target = clean_args[0]
        run_agent(target, profile=chosen_profile)
