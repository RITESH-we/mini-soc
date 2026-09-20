"""
MiniSOC Enterprise — Top 5 Critical Cyber Attack Use Cases Test Suite
Verifies telemetry ingestion, detection correlation, threat categorization,
and dynamic UEBA behavioral risk scoring across all 5 attack vectors:
  1. Ransomware Recovery Inhibition (T1490)
  2. Credential Dumping & Pass-the-Hash (T1003 / T1550)
  3. Living-off-the-Land Obfuscated PowerShell (T1059.001)
  4. Malicious C2 Beaconing & Bulk Data Staging (T1071 / T1560)
  5. Rogue Persistence & Anti-Forensics Log Clearing (T1053 / T1070)
"""

import urllib.request
import json
import sqlite3
import os
import sys

BASE_URL = os.environ.get("MINISOC_URL", "http://127.0.0.1:5000")
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "minisoc.db")

def send_telemetry(payload):
    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(
        f"{BASE_URL}/api/v1/telemetry",
        data=data,
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode('utf-8'))

def test_all():
    print("=" * 68)
    print("  MINISOC TOP 5 CRITICAL CYBER ATTACK USE CASES TEST SUITE")
    print("=" * 68)

    host = "TEST-VERIFICATION-PC"

    # Clean prior test run records
    if os.path.exists(DB_PATH):
        c = sqlite3.connect(DB_PATH)
        c.execute("DELETE FROM alerts WHERE device_name=?", (host,))
        c.execute("DELETE FROM telemetry_logs WHERE hostname=?", (host,))
        c.execute("DELETE FROM entity_risk_scores WHERE entity_id=?", (host,))
        c.execute("DELETE FROM endpoints WHERE hostname=?", (host,))
        c.commit()
        c.close()

    # 1. Use Case 1: Ransomware Recovery Inhibition (T1490)
    print("\n[+] Testing Use Case 1: Ransomware Shadow Copy Destruction (T1490)...")
    p1 = {
        "system": {"hostname": host, "ip_address": "10.0.99.15", "os": "Windows 11", "agent_version": "2.3.0"},
        "events": [{
            "event_id": 4688,
            "record_id": 9901,
            "channel": "Security",
            "timestamp": "2026-09-20T23:40:00",
            "rule_name": "Process Creation",
            "severity": "LOW",
            "mitre_tactic": "Execution",
            "mitre_technique": "T1059",
            "user": "attacker",
            "process": "cmd.exe",
            "command_line": "vssadmin.exe delete shadows /all /quiet",
            "details": "Process spawned: cmd.exe | CLI: vssadmin.exe delete shadows /all /quiet"
        }],
        "processes": [],
        "connections": []
    }
    r1 = send_telemetry(p1)
    assert r1['status'] == 'acknowledged', f"Failed: {r1}"
    print("    -> Telemetry acknowledged by MiniSOC server")

    # 2. Use Case 2: In-Memory Credential Dumping & PtH (T1003 / T1550)
    print("\n[+] Testing Use Case 2: Pass-the-Hash & LSASS Credential Theft (T1550 / T1003)...")
    p2 = {
        "system": {"hostname": host, "ip_address": "10.0.99.15", "os": "Windows 11", "agent_version": "2.3.0"},
        "events": [{
            "event_id": 4648,
            "record_id": 9902,
            "channel": "Security",
            "timestamp": "2026-09-20T23:40:05",
            "rule_name": "Logon Attempt with Explicit Credentials (PtH)",
            "severity": "HIGH",
            "mitre_tactic": "Lateral Movement",
            "mitre_technique": "T1550.002 - Pass the Hash",
            "user": "administrator",
            "process": "lsass.exe",
            "command_line": "",
            "details": "Explicit credential logon: user 'administrator' connecting to target 'DC01'",
            "raw_fields": {"TargetServerName": "DC01"}
        }],
        "processes": [{"name": "mimikatz.exe", "pid": "4412", "mem_usage": "24MB"}],
        "connections": []
    }
    r2 = send_telemetry(p2)
    assert r2['status'] == 'acknowledged', f"Failed: {r2}"
    print("    -> Telemetry acknowledged by MiniSOC server")

    # 3. Use Case 3: Living-off-the-Land Obfuscated PowerShell (T1059.001)
    print("\n[+] Testing Use Case 3: Obfuscated PowerShell & Fileless Execution (T1059.001)...")
    p3 = {
        "system": {"hostname": host, "ip_address": "10.0.99.15", "os": "Windows 11", "agent_version": "2.3.0"},
        "events": [{
            "event_id": 4104,
            "record_id": 9903,
            "channel": "Microsoft-Windows-PowerShell/Operational",
            "timestamp": "2026-09-20T23:40:10",
            "rule_name": "Suspicious PowerShell Script Block",
            "severity": "HIGH",
            "mitre_tactic": "Execution",
            "mitre_technique": "T1059.001 - PowerShell",
            "user": "attacker",
            "process": "powershell.exe",
            "command_line": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA... amsiutils bypass",
            "details": "Living-off-the-Land script block detected"
        }],
        "processes": [],
        "connections": []
    }
    r3 = send_telemetry(p3)
    assert r3['status'] == 'acknowledged', f"Failed: {r3}"
    print("    -> Telemetry acknowledged by MiniSOC server")

    # 4. Use Case 4: C2 Beaconing & Bulk Data Staging (T1071 / T1560)
    print("\n[+] Testing Use Case 4: C2 Beaconing & Data Staging (T1071 / T1560)...")
    p4 = {
        "system": {"hostname": host, "ip_address": "10.0.99.15", "os": "Windows 11", "agent_version": "2.3.0"},
        "events": [{
            "event_id": 4688,
            "record_id": 9904,
            "channel": "Security",
            "timestamp": "2026-09-20T23:40:15",
            "rule_name": "Process Creation",
            "severity": "LOW",
            "mitre_tactic": "Execution",
            "mitre_technique": "T1059",
            "user": "attacker",
            "process": "tar.exe",
            "command_line": "tar.exe -czf C:\\Users\\Public\\staged_data.tar.gz C:\\Users\\rites\\Documents",
            "details": "Process spawned: tar.exe"
        }],
        "processes": [],
        "connections": [{
            "proto": "TCP",
            "local": "10.0.99.15:49812",
            "remote": "185.220.101.5:4444",
            "state": "ESTABLISHED",
            "pid": "5520"
        }]
    }
    r4 = send_telemetry(p4)
    assert r4['status'] == 'acknowledged', f"Failed: {r4}"
    print("    -> Telemetry acknowledged by MiniSOC server")

    # 5. Use Case 5: Rogue Persistence & Event Log Wiping (T1053 / T1070)
    print("\n[+] Testing Use Case 5: Rogue Persistence & Anti-Forensics Log Tampering (T1053 / T1070)...")
    p5 = {
        "system": {"hostname": host, "ip_address": "10.0.99.15", "os": "Windows 11", "agent_version": "2.3.0"},
        "events": [
            {
                "event_id": 4698,
                "record_id": 9905,
                "channel": "Security",
                "timestamp": "2026-09-20T23:40:20",
                "rule_name": "Scheduled Task Created",
                "severity": "HIGH",
                "mitre_tactic": "Persistence",
                "mitre_technique": "T1053.005 - Scheduled Task",
                "user": "attacker",
                "process": "schtasks.exe",
                "command_line": "",
                "details": "Rogue scheduled task created: 'UpdaterBackdoor'",
                "raw_fields": {"TaskName": "\\UpdaterBackdoor"}
            },
            {
                "event_id": 1102,
                "record_id": 9906,
                "channel": "Security",
                "timestamp": "2026-09-20T23:40:25",
                "rule_name": "Windows Audit Log Cleared",
                "severity": "CRITICAL",
                "mitre_tactic": "Defense Evasion",
                "mitre_technique": "T1070.001 - Clear Windows Event Logs",
                "user": "attacker",
                "process": "wevtutil.exe",
                "command_line": "wevtutil cl Security",
                "details": "Security audit log was wiped/cleared by user 'attacker'"
            }
        ],
        "processes": [],
        "connections": []
    }
    r5 = send_telemetry(p5)
    assert r5['status'] == 'acknowledged', f"Failed: {r5}"
    print("    -> Telemetry acknowledged by MiniSOC server")

    # Database Verification
    print("\n[+] Verifying Database Records in SQLite...")
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    # Check alert categories
    cats = conn.execute("""
        SELECT threat_category, COUNT(*) as count 
        FROM alerts 
        WHERE device_name=? 
        GROUP BY threat_category
    """, (host,)).fetchall()
    
    print("\n    Alert Breakdown by Threat Category on Target Host:")
    for c in cats:
        print(f"    - {c['threat_category']}: {c['count']} alert(s)")

    found_cats = {c['threat_category'] for c in cats}
    expected = {'RANSOMWARE', 'CREDENTIAL_ACCESS', 'LIVING_OFF_THE_LAND', 'EXFILTRATION', 'PERSISTENCE'}
    missing = expected - found_cats
    assert not missing, f"Missing categories: {missing}"

    # Check Host UEBA Risk Score
    risk = conn.execute("SELECT risk_score, risk_level FROM entity_risk_scores WHERE entity_id=?", (host,)).fetchone()
    print(f"\n    Target Host UEBA Risk Score: {risk['risk_score']}/100 ({risk['risk_level']})")
    assert risk['risk_score'] >= 90, f"Expected risk score >= 90, got {risk['risk_score']}"

    # Check Endpoints table risk score sync
    ep = conn.execute("SELECT risk_score FROM endpoints WHERE hostname=?", (host,)).fetchone()
    assert ep['risk_score'] == risk['risk_score'], f"Endpoints risk score mismatch: {ep['risk_score']} vs {risk['risk_score']}"

    # Cleanup test records
    conn.execute("DELETE FROM alerts WHERE device_name=?", (host,))
    conn.execute("DELETE FROM telemetry_logs WHERE hostname=?", (host,))
    conn.execute("DELETE FROM entity_risk_scores WHERE entity_id=?", (host,))
    conn.execute("DELETE FROM endpoints WHERE hostname=?", (host,))
    conn.commit()
    conn.close()

    print("\n" + "=" * 68)
    print(">>> ALL 5 CRITICAL CYBER ATTACK USE CASES VERIFIED SUCCESSFULLY! <<<")
    print("=" * 68)

if __name__ == "__main__":
    test_all()
