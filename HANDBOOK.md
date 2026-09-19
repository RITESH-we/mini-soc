# 📘 MiniSOC v2.0 Enterprise — Developer & Security Analyst Handbook
> **Author:** RITESH (`RITESH-we`) | B.Tech CSE Cyber Security  
> **Project URL:** [https://github.com/RITESH-we/mini-soc](https://github.com/RITESH-we/mini-soc)  
> **Classification:** TLP:CLEAR / Educational Open-Source

---

## 📑 Table of Contents
1. [Architectural Overview & Data Pipelines](#1-architectural-overview--data-pipelines)
2. [Subsystem Breakdown](#2-subsystem-breakdown)
3. [Developer Guide: Engineering Custom Detection Rules](#3-developer-guide-engineering-custom-detection-rules)
4. [Developer Guide: Integrating New Threat Intel Providers](#4-developer-guide-integrating-new-threat-intel-providers)
5. [Distributed Endpoint Agent Deployment Guide](#5-distributed-endpoint-agent-deployment-guide)
6. [Network Security Monitoring (NSM) & Active IPS Runbook](#6-network-security-monitoring-nsm--active-ips-runbook)
7. [Nova — Autonomous AI SOC Analyst Engine](#7-nova--autonomous-ai-soc-analyst-engine)
8. [Adversary Emulation & Testing Lab (Atomic Testing)](#8-adversary-emulation--testing-lab-atomic-testing)
9. [SOC Tier 1 / Tier 2 Interview Playbook](#9-soc-tier-1--tier-2-interview-playbook)

---

## 1. Architectural Overview & Data Pipelines

MiniSOC is an enterprise-grade, lightweight SIEM/XDR and SOC automation platform built in Python.

### Data Flow Pipeline
```
[ Telemetry Sources ] ──► [ Ingestion Engine ] ──► [ Detection Correlator ] ──► [ Threat Intel ] ──► [ Web UI / AI RCA ]
  • Windows Evt 4625        • pywin32 API             • Sliding Window Correl.    • VirusTotal v3       • Flask REST API
  • Sysmon Event 1, 10      • NSM Socket Sniffer      • Threshold Evaluator       • AbuseIPDB v2        • Nova AI Reasoning
  • Endpoint Agents         • HTTP REST /api/v1       • MITRE ATT&CK Mapping      • ThreatFox / OTX     • NIST PDF Reports
```

---

## 2. Subsystem Breakdown

```
mini-soc/
├── agent/                # Cross-platform endpoint telemetry shipper
│   └── endpoint_agent.py # Processes, connections, auth metrics
├── ai/                   # Autonomous AI SOC Analyst Co-Pilot
│   └── humanoid_analyst.py # Automated RCA, blast radius & triage chat
├── collectors/           # Local audit event consumers
│   └── windows_events.py # Security & Sysmon log readers via Win32 API
├── dashboard/            # Web application & visual analytics
│   ├── app.py            # Flask controllers & REST APIs
│   └── templates/        # Dark-mode SOC analyst UI views
├── database/             # Relational persistence
│   ├── models.py         # SQLite connection manager & queries
│   └── schema.sql        # Database schema definitions
├── detectors/            # Behavioral analysis
│   └── rule_engine.py    # Sigma-like detection rules mapped to MITRE
├── enrichers/            # Threat intelligence aggregators
│   ├── abuseipdb.py      # IP confidence scoring
│   ├── otx.py            # AlienVault OTX pulses
│   ├── threatfox.py      # abuse.ch IOC & URL verification
│   └── virustotal.py     # Multi-engine AV verdict ratios
├── network/              # Network layer defense
│   ├── ips_responder.py  # Host firewall blocking engine
│   └── nsm_engine.py     # Socket inspection & port scan detector
└── reports/              # Governance & documentation
    └── ir_generator.py   # NIST SP 800-61 PDF report generator
```

---

## 3. Developer Guide: Engineering Custom Detection Rules

All detection rules live in `detectors/rule_engine.py`. Each rule inspects normalized telemetry and returns an alert object or `None`.

### Rule Template
```python
def _rule_custom_threat(event, config):
    """
    Example: Detect PowerShell downloading remote payload
    MITRE ATT&CK: T1059.001 (PowerShell Execution)
    """
    strings = event.get("strings", [])
    cmdline = strings[4].lower() if len(strings) > 4 else ""
    
    suspicious_flags = ["downloadstring", "invoke-webrequest", "iex", "certutil -urlcache"]
    if any(flag in cmdline for flag in suspicious_flags):
        return _alert(
            rule="Suspicious Remote File Download via CLI",
            sev="HIGH",
            desc=f"PowerShell or CertUtil initiated external download: {cmdline[:80]}",
            event=event,
            tactic="Execution",
            tech="T1059.001 - PowerShell",
            proc=cmdline
        )
    return None
```

To register your rule:
1. Open `detectors/rule_engine.py`.
2. Add your handler inside `evaluate(event, config)`.
3. Restart `main.py`.

---

## 4. Developer Guide: Integrating New Threat Intel Providers

To add a new Threat Intelligence connector (e.g., Shodan, CISA KEV):
1. Create `enrichers/<provider_name>.py`.
2. Implement a standard lookup signature:
```python
def lookup_ip(ip: str, api_key: str = None) -> dict:
    # Query REST API and return normalized verdict
    return {"malicious": True, "score": 85, "tags": ["c2", "ransomware"]}
```
3. Import your connector in `dashboard/app.py` under the `/api/alert/<id>/enrich` route.

---

## 5. Distributed Endpoint Agent Deployment Guide

The `agent/endpoint_agent.py` script is completely self-contained with **zero third-party dependencies** (uses standard Python library only).

### Deploying on Remote Endpoints
```powershell
# Copy agent to target machine
python agent/endpoint_agent.py http://<MINISOC_SERVER_IP>:5000/api/v1/telemetry
```

### Running as a Windows Background Service
```powershell
# In an elevated PowerShell prompt:
Start-Process python -ArgumentList "agent/endpoint_agent.py http://127.0.0.1:5000/api/v1/telemetry" -WindowStyle Hidden
```

### Running on Linux (systemd)
Create `/etc/systemd/system/minisoc-agent.service`:
```ini
[Unit]
Description=MiniSOC Endpoint Telemetry Agent
After=network.target

[Service]
ExecStart=/usr/bin/python3 /opt/mini-soc/agent/endpoint_agent.py http://<SERVER_IP>:5000/api/v1/telemetry
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```
Enable and start: `systemctl enable --now minisoc-agent`

---

## 6. Network Security Monitoring (NSM) & Active IPS Runbook

The NSM engine (`network/nsm_engine.py`) continuously reviews live host connection tables.

### Active IPS Containment
When an adversary launches a rapid port scan or malicious connection:
1. The IPS engine invokes `network/ips_responder.py:block_ip()`.
2. Windows host firewall automatically enforces drops:
```powershell
netsh advfirewall firewall add rule name="MiniSOC_IPS_Block_<IP>" dir=in action=block remoteip=<IP>
```
3. To safely unblock an IP, navigate to the **Network (NSM/IPS)** tab in the web UI and click **Unblock**.

---

## 7. Nova — Autonomous AI SOC Analyst Engine

Nova operates inside `ai/humanoid_analyst.py`. She functions as a Tier 1 / Tier 2 co-pilot for junior analysts.

### Capabilities:
- **Root Cause Analysis (RCA)**: Automatically reads correlated alerts, timeline sequences, and MITRE tactics to draft formal investigation narratives.
- **Conversational Triage**: Available 24/7 on the bottom-right corner of the dashboard to explain complex telemetry or recommend next steps.
- **Offline / Sovereign**: Requires no external cloud dependencies out-of-the-box; works completely isolated in private SOC labs.

---

## 8. Adversary Emulation & Testing Lab (Atomic Testing)

Simulate attacks on your lab system to trigger MiniSOC detection rules:

### Test 1: Trigger Brute Force Alert (T1110)
Attempt 5 rapid logon failures using net use:
```powershell
1..6 | ForEach-Object { net use \\127.0.0.1\C$ /user:fakeadmin wrongpass$_ 2>$null }
```
*Expected Alert:* `[HIGH] Brute Force Login Attempt | T1110`

### Test 2: Trigger Scheduled Task Persistence (T1053)
```powershell
schtasks /create /tn "Atomic_Test_Update" /tr "notepad.exe" /sc minute /mo 10 /f
# Cleanup after alert fires:
schtasks /delete /tn "Atomic_Test_Update" /f
```
*Expected Alert:* `[MEDIUM] Scheduled Task Created | T1053.005`

### Test 3: Test Threat Intelligence Enrichment
Click **Enrich** next to external IP `185.220.101.5` in the UI to observe live VirusTotal, AbuseIPDB, and ThreatFox responses.

---

## 9. SOC Tier 1 / Tier 2 Interview Playbook

### Q1: "What is your experience with SIEM and log ingestion?"
> *"I built MiniSOC, an end-to-end SIEM in Python. I worked directly with the Windows Event API (pywin32) to ingest Security Log Event IDs like 4625 for brute force, 4648 for explicit credential use, and Sysmon ID 1 for process creation. I also built a REST telemetry receiver for remote endpoint agents."*

### Q2: "How do you reduce false positives in detection engineering?"
> *"In MiniSOC, rather than alerting on every single failed logon, I implemented a sliding-window correlation engine that enforces a threshold ($\ge 5$ failures within a 60-second window) per user and IP. Furthermore, I integrated multi-feed Threat Intelligence (VirusTotal and AbuseIPDB) to score indicators before taking aggressive containment action."*

### Q3: "Walk me through your Incident Response process."
> *"I follow the NIST SP 800-61 framework: Preparation, Detection & Analysis, Containment, Eradication, and Post-Incident Review. In MiniSOC, once an incident is created, our automated IPS can immediately quarantine the attacker's IP via host firewall rules, while our PDF report generator auto-compiles an investigation report with evidence timelines for management."*
