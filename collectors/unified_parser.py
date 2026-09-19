import xml.etree.ElementTree as ET
import re
from datetime import datetime
from typing import Dict, Any, List, Optional

# XML Namespaces in Windows Events
NS = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}

# MITRE ATT&CK and categorization map for common Event IDs
EVENT_METADATA_MAP = {
    4624: {
        "category": "Authentication",
        "action": "Successful Logon",
        "severity": "INFO",
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1078 - Valid Accounts"
    },
    4625: {
        "category": "Authentication",
        "action": "Failed Logon",
        "severity": "MEDIUM",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1110 - Brute Force"
    },
    4648: {
        "category": "Authentication",
        "action": "Explicit Credential Logon",
        "severity": "LOW",
        "mitre_tactic": "Lateral Movement",
        "mitre_technique": "T1078 - Valid Accounts"
    },
    4688: {
        "category": "Process",
        "action": "Process Creation",
        "severity": "LOW",
        "mitre_tactic": "Execution",
        "mitre_technique": "T1059 - Command and Scripting Interpreter"
    },
    4698: {
        "category": "Persistence",
        "action": "Scheduled Task Created",
        "severity": "HIGH",
        "mitre_tactic": "Persistence",
        "mitre_technique": "T1053.005 - Scheduled Task"
    },
    4720: {
        "category": "Identity",
        "action": "User Account Created",
        "severity": "HIGH",
        "mitre_tactic": "Persistence",
        "mitre_technique": "T1136 - Create Account"
    },
    4732: {
        "category": "Privilege Escalation",
        "action": "Member Added to Security Group",
        "severity": "HIGH",
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique": "T1078 - Valid Accounts"
    },
    4104: {
        "category": "Execution",
        "action": "PowerShell Script Block Execution",
        "severity": "MEDIUM",
        "mitre_tactic": "Execution",
        "mitre_technique": "T1059.001 - PowerShell"
    },
    1: { # Sysmon 1
        "category": "Process",
        "action": "Sysmon Process Creation",
        "severity": "LOW",
        "mitre_tactic": "Execution",
        "mitre_technique": "T1059 - Command Execution"
    },
    3: { # Sysmon 3
        "category": "Network",
        "action": "Sysmon Network Connection",
        "severity": "LOW",
        "mitre_tactic": "Command and Control",
        "mitre_technique": "T1071 - Application Layer Protocol"
    }
}

LOGON_TYPE_MAP = {
    "2": "Interactive (Local Console)",
    "3": "Network (SMB/RPC/Web)",
    "4": "Batch",
    "5": "Service",
    "7": "Unlock",
    "8": "NetworkCleartext",
    "9": "NewCredentials",
    "10": "RemoteInteractive (RDP)",
    "11": "CachedInteractive"
}

def parse_windows_event_xml(xml_content: str) -> List[Dict[str, Any]]:
    """
    Parses one or multiple Windows Event XML records into structured OCSF/ECS compliant objects.
    """
    parsed_events = []
    if not xml_content or not xml_content.strip():
        return parsed_events

    # Wevtutil can output multiple concatenated <Event> tags without a single root
    # Wrap in a pseudo root if needed
    cleaned = xml_content.strip()
    if not cleaned.startswith("<Events>"):
        wrapped_xml = f"<Events>{cleaned}</Events>"
    else:
        wrapped_xml = cleaned

    try:
        root = ET.fromstring(wrapped_xml)
    except ET.ParseError:
        # Fallback: extract individual <Event ...> ... </Event> chunks via regex
        event_chunks = re.findall(r"(<Event\b[^>]*>.*?</Event>)", cleaned, re.DOTALL)
        for chunk in event_chunks:
            try:
                single_ev = ET.fromstring(chunk)
                norm = _parse_single_event_node(single_ev)
                if norm:
                    parsed_events.append(norm)
            except Exception:
                continue
        return parsed_events

    for event_node in root.findall(".//e:Event", NS) or root.findall(".//Event"):
        norm = _parse_single_event_node(event_node)
        if norm:
            parsed_events.append(norm)

    return parsed_events

def _parse_single_event_node(node: ET.Element) -> Optional[Dict[str, Any]]:
    try:
        sys_node = node.find("e:System", NS) if node.find("e:System", NS) is not None else node.find("System")
        if sys_node is None:
            return None

        # Extract System Header
        event_id_el = sys_node.find("e:EventID", NS) if sys_node.find("e:EventID", NS) is not None else sys_node.find("EventID")
        event_id = int(event_id_el.text) if event_id_el is not None and event_id_el.text else 0

        rec_el = sys_node.find("e:EventRecordID", NS) if sys_node.find("e:EventRecordID", NS) is not None else sys_node.find("EventRecordID")
        record_id = int(rec_el.text) if rec_el is not None and rec_el.text else 0

        chan_el = sys_node.find("e:Channel", NS) if sys_node.find("e:Channel", NS) is not None else sys_node.find("Channel")
        channel = chan_el.text if chan_el is not None and chan_el.text else "Security"

        comp_el = sys_node.find("e:Computer", NS) if sys_node.find("e:Computer", NS) is not None else sys_node.find("Computer")
        computer = comp_el.text if comp_el is not None and comp_el.text else ""

        time_el = sys_node.find("e:TimeCreated", NS) if sys_node.find("e:TimeCreated", NS) is not None else sys_node.find("TimeCreated")
        timestamp = time_el.get("SystemTime") if time_el is not None else datetime.now().isoformat()

        # Extract EventData Key-Values
        data_node = node.find("e:EventData", NS) if node.find("e:EventData", NS) is not None else node.find("EventData")
        fields = {}
        if data_node is not None:
            for d in list(data_node):
                name = d.get("Name")
                val = d.text or ""
                if name:
                    fields[name] = val
                elif not name and val:
                    # Unnamed Data tag, use index
                    fields[f"Data_{len(fields)}"] = val

        # Normalize specific fields
        user = fields.get("TargetUserName") or fields.get("SubjectUserName") or fields.get("User") or ""
        domain = fields.get("TargetDomainName") or fields.get("SubjectDomainName") or ""
        src_ip = fields.get("IpAddress") or fields.get("SourceIp") or ""
        if src_ip == "-" or src_ip.startswith("::"):
            src_ip = "127.0.0.1"

        process = fields.get("NewProcessName") or fields.get("ProcessName") or fields.get("Image") or ""
        cmdline = fields.get("CommandLine") or fields.get("ScriptBlockText") or ""
        parent_process = fields.get("ParentProcessName") or fields.get("ParentImage") or ""
        logon_type_raw = str(fields.get("LogonType", ""))
        logon_type_desc = LOGON_TYPE_MAP.get(logon_type_raw, logon_type_raw)

        meta = EVENT_METADATA_MAP.get(event_id, {
            "category": "System",
            "action": f"Event {event_id}",
            "severity": "LOW",
            "mitre_tactic": "Execution",
            "mitre_technique": "T1059 - Command Execution"
        })

        # Detailed analyst readable summary
        desc = ""
        if event_id == 4625:
            sub = fields.get("SubStatus", "")
            desc = f"Logon failure for user '{user}' from IP {src_ip} (LogonType: {logon_type_desc}, SubStatus: {sub})"
        elif event_id == 4624:
            desc = f"Successful logon for user '{user}' from IP {src_ip} (LogonType: {logon_type_desc})"
        elif event_id == 4688:
            desc = f"Process created: {process} | CLI: {cmdline[:120]}"
        elif event_id == 4104:
            desc = f"PowerShell Script Block executed: {cmdline[:140]}"
        elif event_id == 4720:
            desc = f"New user account created: '{user}' by '{fields.get('SubjectUserName', 'SYSTEM')}'"
        elif event_id == 4732:
            desc = f"User '{fields.get('MemberName', '')}' added to security group '{user}'"
        else:
            desc = f"Windows Event {event_id} on {computer} ({meta['action']})"

        return {
            "event_id": event_id,
            "record_id": record_id,
            "channel": channel,
            "timestamp": timestamp,
            "hostname": computer,
            "rule_name": meta["action"],
            "category": meta["category"],
            "severity": meta["severity"],
            "mitre_tactic": meta["mitre_tactic"],
            "mitre_technique": meta["mitre_technique"],
            "user": user,
            "domain": domain,
            "src_ip": src_ip,
            "process": process,
            "command_line": cmdline,
            "parent_process": parent_process,
            "details": desc,
            "raw_fields": fields
        }
    except Exception as e:
        return None

def parse_linux_auth_log_line(line: str, hostname: str = "linux-host") -> Optional[Dict[str, Any]]:
    """
    Parses Linux /var/log/auth.log line into structured OCSF security event.
    """
    if "Failed password" in line:
        user_match = re.search(r"Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)", line)
        user = user_match.group(1) if user_match else "unknown"
        ip = user_match.group(2) if user_match else "unknown"
        return {
            "event_id": 4625,
            "record_id": 0,
            "channel": "auth.log",
            "timestamp": datetime.now().isoformat(),
            "hostname": hostname,
            "rule_name": "Linux SSH Authentication Failure",
            "category": "Authentication",
            "severity": "MEDIUM",
            "mitre_tactic": "Credential Access",
            "mitre_technique": "T1110 - Brute Force",
            "user": user,
            "domain": "LOCAL",
            "src_ip": ip,
            "process": "sshd",
            "command_line": "",
            "parent_process": "",
            "details": f"Failed SSH login attempt for '{user}' from {ip}",
            "raw_fields": {"raw": line}
        }
    elif "Accepted password" in line or "Accepted publickey" in line:
        user_match = re.search(r"Accepted \S+ for (\S+) from (\S+)", line)
        user = user_match.group(1) if user_match else "unknown"
        ip = user_match.group(2) if user_match else "unknown"
        return {
            "event_id": 4624,
            "record_id": 0,
            "channel": "auth.log",
            "timestamp": datetime.now().isoformat(),
            "hostname": hostname,
            "rule_name": "Linux SSH Successful Logon",
            "category": "Authentication",
            "severity": "INFO",
            "mitre_tactic": "Initial Access",
            "mitre_technique": "T1078 - Valid Accounts",
            "user": user,
            "domain": "LOCAL",
            "src_ip": ip,
            "process": "sshd",
            "command_line": "",
            "parent_process": "",
            "details": f"Successful SSH logon for '{user}' from {ip}",
            "raw_fields": {"raw": line}
        }
    return None
