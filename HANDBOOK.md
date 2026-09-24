# 📘 TRISHUL Enterprise v2.4 — Developer & Integration Handbook
### Complete Guide for Integrating External Applications, Cloud Services & Endpoint Fleets
> **Platform:** TRISHUL Enterprise XDR, SIEM & UEBA  
> **Author:** RITESH (`RITESH-we`) | B.Tech CSE Cyber Security  
> **Project Repository:** [https://github.com/RITESH-we/mini-soc](https://github.com/RITESH-we/mini-soc)  
> **Live Cloud Instance:** [https://trishula-soc.onrender.com](https://trishula-soc.onrender.com)  
> **Classification:** TLP:CLEAR / Production & Developer Reference  

---

## 📑 Table of Contents
1. [Architecture & Integration Topology](#1-architecture--integration-topology)
2. [REST API Reference & Data Contracts](#2-rest-api-reference--data-contracts)
3. [Application & Microservice SDK Integrations](#3-application--microservice-sdk-integrations)
   - [Python (FastAPI / Flask / Django)](#31-python-integration)
   - [Node.js & TypeScript](#32-nodejs--typescript-integration)
   - [Go (Golang)](#33-go-golang-integration)
   - [cURL & Shell Scripts](#34-curl--shell-scripts)
4. [Cloud Provider & Syslog Ingestion](#4-cloud-provider--syslog-ingestion)
   - [AWS CloudTrail & GuardDuty](#41-aws-cloudtrail--guardduty)
   - [Google Cloud Platform (GCP) Cloud Audit](#42-google-cloud-platform-gcp-cloud-audit)
   - [Linux Syslog / Rsyslog Forwarding](#43-linux-syslog--rsyslog-forwarding)
5. [Endpoint Fleet Deployment & Policy Control](#5-endpoint-fleet-deployment--policy-control)
   - [Dual-Layer Containment Architecture (L7 + L3/4)](#51-dual-layer-containment-architecture-l7--l34)
   - [Targeted Per-Endpoint Threat Containment](#52-targeted-per-endpoint-threat-containment)
   - [Policy Profiles (Workstation vs Server vs Audit)](#53-policy-profiles)
6. [Detection Engineering & Rule Creation](#6-detection-engineering--rule-creation)
7. [Threat Intelligence & RFC 1918 Guard](#7-threat-intelligence--rfc-1918-guard)
8. [Adversary Emulation & Verification Runbook](#8-adversary-emulation--verification-runbook)
9. [SOC Analyst Interview & Project Defense Playbook](#9-soc-tier-1--tier-2-interview-playbook)

---

## 1. Architecture & Integration Topology

TRISHUL provides a unified RESTful ingestion fabric compliant with **OCSF (Open Cybersecurity Schema Framework)** and **Elastic Common Schema (ECS)**. Any external service—from an internal microservice to cloud infrastructure—can stream audit logs, authenticate users, or trigger active defense containment through standard HTTP JSON interfaces.

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                               EXTERNAL INTEGRATION SOURCES                             │
├─────────────────────┬──────────────────────┬───────────────────┬───────────────────────┤
│ Distributed Agents  │ Custom Microservices │ Cloud Audit Feeds │ SIEM / Webhooks       │
│ (Windows / Linux)   │ (Python, Node.js, Go)│ (AWS, GCP, Azure) │ (Rsyslog, Vector)     │
└──────────┬──────────┴──────────┬───────────┴─────────┬─────────┴───────────┬───────────┘
           │                     │                     │                     │
           └─────────────────────┼─────────────────────┴─────────────────────┘
                                 │ HTTP POST (JSON Payloads)
                                 ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              TRISHUL INGESTION GATEWAY                                 │
│                     URL: https://trishula-soc.onrender.com                             │
├────────────────────────────────────────────────────────────────────────────────────────┤
│  • Endpoint Telemetry Gateway:  /api/v1/telemetry                                      │
│  • Cloud & Syslog Ingestion:    /api/v1/ingest/cloud                                   │
│  • Active IPS & Containment:    /api/network/block & /api/network/unblock              │
│  • Host Isolation & Profiles:   /api/agents/<hostname>/isolate & /profile              │
└────────────────────────────────┬───────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                               TRISHUL CORE PIPELINES                                   │
├────────────────────────────────────────────────────────────────────────────────────────┤
│  1. Parsing & Normalization    (OCSF/ECS fields, Timestamp UTC conversion)             │
│  2. Alert Fatigue Mitigation   (15-minute sliding-window de-duplication)               │
│  3. MITRE ATT&CK Correlator    (Real-time rule matrix & multi-stage attack chaining)   │
│  4. Dynamic UEBA Risk Scorer   (Calculates Host & User Risk Scores [0-100])            │
│  5. Active Defense Dispatcher  (Queues proactive L7+L3 containment down to agents)     │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. REST API Reference & Data Contracts

All endpoints accept and return `application/json`. When testing against a local instance, use `http://127.0.0.1:5000`. When integrating with the cloud production environment, use `https://trishula-soc.onrender.com`.

### 2.1 Ingest Cloud & Application Audit Events
* **Endpoint:** `POST /api/v1/ingest/cloud`
* **Purpose:** Ingests events from custom microservices, web apps, AWS CloudTrail, GCP Audit, Azure Monitor, or Syslog forwarders.
* **Request Payload Format:**
```json
{
  "events": [
    {
      "host": "payment-api-prod-01",
      "user": "service_account_db",
      "rule_name": "Unauthorized Database Access Attempt",
      "severity": "HIGH",
      "details": "User attempted SQL execution on restricted customer_billing table",
      "src_ip": "203.0.113.45",
      "event_id": 9101,
      "mitre_tactic": "Credential Access",
      "mitre_technique": "T1078 - Valid Accounts"
    }
  ]
}
```
* **Response (200 OK):**
```json
{
  "status": "success",
  "ingested": 1
}
```

---

### 2.2 Endpoint Telemetry & Heartbeat Gateway
* **Endpoint:** `POST /api/v1/telemetry`
* **Purpose:** Transmits active endpoint health, running processes, open network sockets, and Windows Security Log events. In return, receives pending defense containment commands.
* **Request Payload (Subset):**
```json
{
  "system": {
    "hostname": "FINANCE-DESKTOP-04",
    "ip_address": "192.168.1.140",
    "os": "Windows 11 Enterprise",
    "architecture": "AMD64",
    "agent_version": "2.4"
  },
  "security_posture": {
    "antivirus": "Windows Defender (Active)",
    "firewall": "Active",
    "is_admin": true
  },
  "profile": "standard_workstation",
  "processes": [
    {"name": "chrome.exe", "pid": 4820, "mem_usage": "145MB"},
    {"name": "powershell.exe", "pid": 9210, "mem_usage": "38MB"}
  ],
  "connections": [
    {"proto": "TCP", "remote": "142.250.182.238:443", "state": "ESTABLISHED", "pid": 4820}
  ],
  "events": []
}
```
* **Response (200 OK):**
```json
{
  "status": "acknowledged",
  "node": "FINANCE-DESKTOP-04",
  "profile": "standard_workstation",
  "command": {
    "action": "block_remote_ip",
    "target": "185.220.101.5",
    "targets": ["185.220.101.5"],
    "domain": null,
    "reason": "Known Adversary C2 Beacon",
    "containment_profile": "BIDIRECTIONAL_DROP",
    "endpoint_scope": "FINANCE-DESKTOP-04"
  }
}
```

---

### 2.3 Enforce Active Firewall & Domain Containment (IPS)
* **Endpoint:** `POST /api/network/block`
* **Purpose:** Proactively drops malicious IPs or domains locally in Windows Firewall and Layer 7 `hosts` sinkholes.
* **Request Payload:**
```json
{
  "ip": "malicious-c2.net",
  "reason": "Phishing URL detected in employee email",
  "containment_profile": "BIDIRECTIONAL_DROP",
  "endpoint_scope": "GLOBAL"
}
```
> **Note on `endpoint_scope`**:
> - Set to `"GLOBAL"` to enforce across **all** enrolled workstations and servers fleet-wide.
> - Set to a specific hostname (e.g. `"HR-LAPTOP-01"`) to contain the threat **only** on that machine without disrupting other systems.
* **Response (200 OK):**
```json
{
  "success": true,
  "action": "blocked",
  "containment_profile": "BIDIRECTIONAL_DROP",
  "endpoint_scope": "GLOBAL",
  "ip": "malicious-c2.net",
  "resolved_ips": ["198.51.100.42", "203.0.113.88"]
}
```

---

### 2.4 Lift Containment (Unblock Target)
* **Endpoint:** `POST /api/network/unblock`
* **Request Payload:**
```json
{
  "ip": "malicious-c2.net",
  "endpoint_scope": "GLOBAL"
}
```

---

### 2.5 Host Network Quarantine & Restoration
* **Quarantine:** `POST /api/agents/<hostname>/isolate`
  - Instructs the agent to sever all outbound and inbound network connections via Windows Firewall, keeping only the TRISHUL SOC management link open.
* **Restore:** `POST /api/agents/<hostname>/unisolate`
  - Lifts quarantine firewall rules and restores normal network connectivity.

---

### 2.6 Real-Time Health & Component Diagnostics
* **Endpoint:** `GET /api/health`
* **Response (200 OK):**
```json
{
  "overall_status": "HEALTHY",
  "query_latency_ms": 3.42,
  "timestamp": "2026-09-24T17:30:00.000000",
  "components": {
    "ingestion_engine": {"name": "Ingestion Gateway", "status": "OPERATIONAL", "details": "Active REST endpoints accepting OCSF/ECS JSON"},
    "database_storage": {"name": "Database & Indexing", "status": "OPERATIONAL", "details": "SQLite WAL mode with multi-tier indexes"},
    "endpoint_agents": {"name": "Endpoint Fleet & EDR", "status": "OPERATIONAL", "details": "Active heartbeat monitoring & telemetry processing"},
    "detection_engine": {"name": "MITRE Detection Engine", "status": "OPERATIONAL", "details": "Real-time attack correlation across 10 vectors"},
    "ueba_behavioral_engine": {"name": "Behavioral UEBA Risk Engine", "status": "OPERATIONAL", "details": "Dynamic entity risk scoring (Host & User)"},
    "soar_response_fabric": {"name": "SOAR Active Defense", "status": "OPERATIONAL", "details": "Proactive endpoint containment & dual-layer IPS"}
  }
}
```

---

## 3. Application & Microservice SDK Integrations

You can integrate TRISHUL into your existing microservices, backend APIs, or web applications with a few lines of code.

### 3.1 Python Integration

Use this helper class in your Python applications (FastAPI, Flask, Django, Celery):

```python
import requests
import socket
from datetime import datetime

class TrishulSecurityClient:
    def __init__(self, soc_url="https://trishula-soc.onrender.com"):
        self.soc_url = soc_url.rstrip("/")
        self.ingest_endpoint = f"{self.soc_url}/api/v1/ingest/cloud"
        self.block_endpoint = f"{self.soc_url}/api/network/block"
        self.hostname = socket.gethostname()

    def send_security_event(self, rule_name: str, severity: str, details: str, user: str = "app_user", src_ip: str = "127.0.0.1", tactic: str = "Execution", technique: str = "T1059"):
        """Ships an audit event to TRISHUL for MITRE ATT&CK correlation."""
        payload = {
            "events": [{
                "host": self.hostname,
                "user": user,
                "rule_name": rule_name,
                "severity": severity.upper(),
                "details": details,
                "src_ip": src_ip,
                "event_id": 9001,
                "mitre_tactic": tactic,
                "mitre_technique": technique
            }]
        }
        try:
            r = requests.post(self.ingest_endpoint, json=payload, timeout=5)
            return r.status_code == 200
        except Exception as e:
            print(f"[!] Trishul telemetry dispatch error: {e}")
            return False

    def trigger_active_containment(self, target_ip_or_domain: str, reason: str, scope: str = "GLOBAL"):
        """Triggers host firewall drops across the fleet or on a specific endpoint."""
        payload = {
            "ip": target_ip_or_domain,
            "reason": reason,
            "endpoint_scope": scope,
            "containment_profile": "BIDIRECTIONAL_DROP"
        }
        try:
            r = requests.post(self.block_endpoint, json=payload, timeout=5)
            return r.json()
        except Exception as e:
            return {"success": False, "error": str(e)}

# Example Usage in Your Application:
if __name__ == "__main__":
    sec = TrishulSecurityClient()
    # 1. Report anomalous application activity
    sec.send_security_event(
        rule_name="Multiple Failed API Keys Provided",
        severity="HIGH",
        details="Client exceeded 10 unauthorized requests to /v1/auth/token within 30s",
        user="api_consumer_unknown",
        src_ip="198.51.100.77",
        tactic="Credential Access",
        technique="T1110 - Brute Force"
    )
    # 2. Block the attacker IP fleet-wide
    sec.trigger_active_containment("198.51.100.77", reason="API brute-force abuse", scope="GLOBAL")
```

---

### 3.2 Node.js & TypeScript Integration

```typescript
import axios from 'axios';
import * as os from 'os';

export class TrishulClient {
  private socUrl: string;

  constructor(socUrl: string = 'https://trishula-soc.onrender.com') {
    this.socUrl = socUrl.replace(/\/$/, '');
  }

  async reportSecurityEvent(params: {
    ruleName: string;
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    details: string;
    user?: string;
    srcIp?: string;
    tactic?: string;
    technique?: string;
  }): Promise<boolean> {
    const payload = {
      events: [{
        host: os.hostname(),
        user: params.user || 'system',
        rule_name: params.ruleName,
        severity: params.severity,
        details: params.details,
        src_ip: params.srcIp || '127.0.0.1',
        event_id: 9200,
        mitre_tactic: params.tactic || 'Initial Access',
        mitre_technique: params.technique || 'T1078 - Valid Accounts'
      }]
    };

    try {
      const res = await axios.post(`${this.socUrl}/api/v1/ingest/cloud`, payload, { timeout: 5000 });
      return res.status === 200;
    } catch (err) {
      console.error('[Trishul] Event dispatch failed:', err);
      return false;
    }
  }

  async blockTarget(target: string, reason: string, scope: string = 'GLOBAL') {
    return axios.post(`${this.socUrl}/api/network/block`, {
      ip: target,
      reason,
      endpoint_scope: scope,
      containment_profile: 'BIDIRECTIONAL_DROP'
    });
  }
}
```

---

### 3.3 Go (Golang) Integration

```go
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

type TrishulEvent struct {
	Host           string `json:"host"`
	User           string `json:"user"`
	RuleName       string `json:"rule_name"`
	Severity       string `json:"severity"`
	Details        string `json:"details"`
	SrcIP          string `json:"src_ip"`
	EventID        int    `json:"event_id"`
	MitreTactic    string `json:"mitre_tactic"`
	MitreTechnique string `json:"mitre_technique"`
}

type TrishulPayload struct {
	Events []TrishulEvent `json:"events"`
}

func SendTrishulEvent(socURL, ruleName, severity, details, srcIP string) error {
	hostname, _ := os.Hostname()
	payload := TrishulPayload{
		Events: []TrishulEvent{{
			Host:           hostname,
			User:           "service_app",
			RuleName:       ruleName,
			Severity:       severity,
			Details:        details,
			SrcIP:          srcIP,
			EventID:        9300,
			MitreTactic:    "Defense Evasion",
			MitreTechnique: "T1036 - Masquerading",
		}},
	}

	data, _ := json.Marshal(payload)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(socURL+"/api/v1/ingest/cloud", "application/json", bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}
	return nil
}
```

---

### 3.4 cURL & Shell Scripts

Forward audit events directly from bash scripts or cron jobs:

```bash
#!/usr/bin/env bash
TRISHUL_URL="https://trishula-soc.onrender.com/api/v1/ingest/cloud"

curl -s -X POST "$TRISHUL_URL" \
  -H "Content-Type: application/json" \
  -d '{
    "events": [{
      "host": "'"$HOSTNAME"'",
      "user": "root",
      "rule_name": "SSH Root Login From Unknown Subnet",
      "severity": "HIGH",
      "details": "Root session established via SSH key without MFA from external IP",
      "src_ip": "198.51.100.99",
      "event_id": 9022,
      "mitre_tactic": "Initial Access",
      "mitre_technique": "T1078.001 - Default Accounts"
    }]
  }'
```

---

## 4. Cloud Provider & Syslog Ingestion

### 4.1 AWS CloudTrail & GuardDuty

Forward CloudTrail logs using an AWS Lambda trigger on your CloudWatch Log Group:

```python
import json
import urllib.request
import gzip
import base64

TRISHUL_WEBHOOK = "https://trishula-soc.onrender.com/api/v1/ingest/cloud"

def lambda_handler(event, context):
    compressed_data = base64.b64decode(event['awslogs']['data'])
    raw_json = gzip.decompress(compressed_data).decode('utf-8')
    log_events = json.loads(raw_json)['logEvents']

    events_to_ship = []
    for item in log_events:
        msg = json.loads(item['message'])
        events_to_ship.append({
            "host": msg.get("recipientAccountId", "aws-account"),
            "user": msg.get("userIdentity", {}).get("userName", "iam-principal"),
            "rule_name": f"AWS: {msg.get('eventName', 'CloudTrail Event')}",
            "severity": "HIGH" if msg.get("errorCode") else "LOW",
            "details": f"AWS event {msg.get('eventName')} from {msg.get('sourceIPAddress')}",
            "src_ip": msg.get("sourceIPAddress", "0.0.0.0"),
            "event_id": 9500,
            "mitre_tactic": "Credential Access",
            "mitre_technique": "T1078.004 - Cloud Accounts"
        })

    req = urllib.request.Request(
        TRISHUL_WEBHOOK,
        data=json.dumps({"events": events_to_ship}).encode('utf-8'),
        headers={"Content-Type": "application/json"}
    )
    urllib.request.urlopen(req, timeout=5)
```

### 4.2 Google Cloud Platform (GCP) Cloud Audit

Forward GCP Cloud Audit Logs using a Cloud Logging Sink to a Pub/Sub topic and a Cloud Function:

```python
import base64
import json
import urllib.request

def forward_to_trishul(event, context):
    pubsub_msg = base64.b64decode(event['data']).decode('utf-8')
    audit_log = json.loads(pubsub_msg)

    payload = {
        "events": [{
            "host": audit_log.get("resource", {}).get("labels", {}).get("project_id", "gcp-project"),
            "user": audit_log.get("protoPayload", {}).get("authenticationInfo", {}).get("principalEmail", "gcp-user"),
            "rule_name": f"GCP: {audit_log.get('protoPayload', {}).get('methodName', 'GCP Audit Event')}",
            "severity": "HIGH" if "setIamPolicy" in audit_log.get('protoPayload', {}).get('methodName', '') else "MEDIUM",
            "details": json.dumps(audit_log.get('protoPayload', {}).get('serviceData', {})),
            "src_ip": audit_log.get("protoPayload", {}).get("requestMetadata", {}).get("callerIp", "0.0.0.0"),
            "event_id": 9600,
            "mitre_tactic": "Privilege Escalation",
            "mitre_technique": "T1078 - Cloud Accounts"
        }]
    }

    req = urllib.request.Request(
        "https://trishula-soc.onrender.com/api/v1/ingest/cloud",
        data=json.dumps(payload).encode('utf-8'),
        headers={"Content-Type": "application/json"}
    )
    urllib.request.urlopen(req, timeout=5)
```

### 4.3 Linux Syslog / Rsyslog Forwarding

Forward Linux authentication and system logs directly to TRISHUL using an `rsyslog` HTTP template:

```ini
# Add to /etc/rsyslog.d/50-trishul.conf
template(name="TrishulJSON" type="list") {
    constant(value="{\"events\":[{\"host\":\"")
    property(name="hostname")
    constant(value="\",\"rule_name\":\"Syslog Security Event\",\"severity\":\"MEDIUM\",\"details\":\"")
    property(name="msg" format="json")
    constant(value="\",\"user\":\"root\",\"src_ip\":\"127.0.0.1\"}]}")
}

# Forward authpriv logs via omhttp:
authpriv.* action(
    type="omhttp"
    server="trishula-soc.onrender.com"
    serverport="443"
    usehttps="on"
    restpath="api/v1/ingest/cloud"
    template="TrishulJSON"
)
```

---

## 5. Endpoint Fleet Deployment & Policy Control

The TRISHUL Endpoint Agent (`agent/endpoint_agent.py`) is a standalone, dependency-free Python client that runs on both Windows and Linux.

### 5.1 Dual-Layer Containment Architecture (L7 + L3/4)

When an analyst blocks a malicious domain (e.g. `badsite.com` or `phish-login.org`):
1. **Layer 7 Domain Sinkhole**: The agent immediately writes `0.0.0.0 badsite.com` and `::1 badsite.com` to `C:\Windows\System32\drivers\etc\hosts` (or `/etc/hosts` on Linux) and executes `ipconfig /flushdns`. Any browser (Chrome, Brave, Edge, Firefox) immediately displays `ERR_CONNECTION_REFUSED`.
2. **Layer 3/4 Local Anycast IP Drops**: The agent resolves the domain locally using `socket.getaddrinfo()` to capture all local ISP/regional Anycast IPs, and applies inbound and outbound block rules in Windows Firewall (`netsh advfirewall`). This prevents non-browser tools (e.g. PowerShell, Curl, custom malware) from establishing socket connections directly to the IP.

### 5.2 Targeted Per-Endpoint Threat Containment

TRISHUL allows precision containment:
* **Global Scope (`GLOBAL`)**: Dispatched to all enrolled endpoints in the fleet. Ideal for blocking external phishing sites, known adversary C2 infrastructure, or compromised remote IPs.
* **Per-Endpoint Scope (`<hostname>`)**: Dispatched **only** to the selected compromised machine. If Host A is infected with lateral-movement ransomware or an aggressive beacon, analysts can isolate Host A's access without impacting Host B or Host C.

### 5.3 Policy Profiles

You can dynamically adjust agent behavior from the **Endpoint Fleet (`/agents`)** view or via CLI:

| Profile | Heartbeat | Behavior & Containment Policy |
| :--- | :--- | :--- |
| **`standard_workstation`** | 15s | Balanced EDR. Automated malware containment, process inspection, and telemetry shipping. |
| **`high_security_server`** | 5s | Accelerated monitoring. Rapid socket inspection and immediate quarantine upon critical alerts. |
| **`audit_friend`** | 15s | Safe telemetry mode. Ingests all metrics but automatically suppresses disruptive actions (no automated firewall drops or process terminations on colleague laptops). |

---

## 6. Detection Engineering & Rule Creation

All behavioral detection rules reside in `detectors/rule_engine.py` and execute inside the sliding-window correlation engine.

### Rule Authoring Template
```python
def _rule_custom_credential_access(event, config):
    """
    Detects unauthorized dumping of LSASS memory or SAM registry hives.
    MITRE ATT&CK: T1003 (OS Credential Dumping)
    """
    proc = (event.get("process") or "").lower()
    cmdline = (event.get("command_line") or "").lower()

    if "comsvcs.dll" in cmdline and "minidump" in cmdline:
        return _alert(
            rule="LSASS MiniDump Process Tampering",
            sev="CRITICAL",
            desc=f"Process {proc} attempted to dump LSASS memory via comsvcs: {cmdline[:120]}",
            event=event,
            tactic="Credential Access",
            tech="T1003.001 - LSASS Memory",
            threat_cat="CREDENTIAL_ACCESS"
        )
    return None
```

---

## 7. Threat Intelligence & RFC 1918 Guard

TRISHUL integrates with four premier Cyber Threat Intelligence (CTI) providers:
* **VirusTotal v3** (AV detection ratios & reputation)
* **AbuseIPDB v2** (Abuse confidence score & report volume)
* **AlienVault OTX** (Active threat pulses & indicator tagging)
* **ThreatFox (abuse.ch)** (Malware family signatures & C2 tracking)

### The RFC 1918 Pre-Flight Guard
Before making external HTTP API calls, all enrichers pass target IPs through `is_public_routable_ip(ip)` in `network/ips_responder.py`.
- **Private Subnets Filtered**: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`, and CGNAT `100.64.0.0/10`.
- **Outcome**: Completely eliminates false CTI lookups, saves API rate limits, and prevents leaking internal corporate topology to public services.

---

## 8. Adversary Emulation & Verification Runbook

Simulate realistic attack scenarios on your test endpoint to verify end-to-end detection:

```powershell
# 1. Ransomware Recovery Inhibition (MITRE T1490)
vssadmin delete shadows /all /quiet

# 2. In-Memory Credential Dumping Simulation (MITRE T1003.001)
cmd.exe /c "findstr /si password *.txt"

# 3. Brute Force Password Spraying (MITRE T1110)
1..5 | ForEach-Object { net use \\127.0.0.1\IPC$ /user:fakeadmin wrongpass$_ 2>$null }

# 4. Persistence via Scheduled Task (MITRE T1053.005)
schtasks /create /tn "SOC_Test_Persistence" /tr "calc.exe" /sc onlogon /f
schtasks /delete /tn "SOC_Test_Persistence" /f
```

---

## 9. SOC Tier 1 / Tier 2 Interview Playbook

When presenting TRISHUL to recruiters, engineering managers, or interviewers:

### Q1: "How does TRISHUL solve Alert Fatigue in real-world SOC operations?"
> *"In TRISHUL, I built a 15-minute sliding-window de-duplication engine. Instead of creating 500 alerts when an automated scanner or misconfigured service repeatedly fails authentication, the engine identifies duplicate (Rule, Host, Process, IP) tuples, updates the `last_seen` timestamp, and increments an occurrence counter (`[Repeated 42x]`). Furthermore, for Windows Event 4625, we enforce thresholding that suppresses single mistyped passwords and only fires if 4 or more failures occur within 5 minutes."*

### Q2: "What is your approach to Active Defense and Host Containment?"
> *"I designed a Dual-Layer Containment architecture. When containing a malicious domain, Layer 3/4 firewall rules often fail because modern web applications use Anycast routing and CDN IP rotation. TRISHUL pairs Layer 7 OS hosts sinkholing (`0.0.0.0 <domain>` + DNS cache flush) with local Anycast IP drops in Windows Firewall. Additionally, we support Targeted Per-Endpoint Containment so analysts can isolate an infection on one workstation without disrupting the rest of the company."*

### Q3: "How does the system ensure non-disruptive monitoring on sensitive systems?"
> *"TRISHUL implements Policy Profiles: Standard Workstation, High-Security Server, and Audit Friend. When deployed on a colleague's laptop in `audit_friend` mode, the agent collects full security telemetry and process lineage but automatically suppresses disruptive actions like automated firewall drops or process terminations, ensuring zero false-positive business interruption."*

---

## 📜 Support & Contributing
For bug reports, feature proposals, or security disclosures, please open an issue on the official GitHub repository:
👉 **[https://github.com/RITESH-we/mini-soc](https://github.com/RITESH-we/mini-soc)**
