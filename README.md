# 🛡️ MiniSOC — Automated SOC Tier 1 Monitoring & Incident Response Platform

[![Python](https://img.shields.io/badge/Python-3.11-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/Web_UI-Flask-000000.svg?logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Framework](https://img.shields.io/badge/Security-MITRE_ATT%26CK-red.svg)](https://attack.mitre.org/)
[![Threat Intel](https://img.shields.io/badge/Threat_Intel-VirusTotal_%7C_AbuseIPDB-green.svg)](https://www.virustotal.com/)
[![License](https://img.shields.io/badge/License-MIT-lightgrey.svg)](LICENSE)

**MiniSOC** is a lightweight, real-time Security Operations Center (SOC) Level 1 orchestration and monitoring platform built from scratch in Python. It continuously captures host telemetry and security audit logs, correlates events using Sigma-like detection engineering rules mapped to the **MITRE ATT&CK framework**, auto-enriches observable IOCs via external Threat Intelligence APIs (**VirusTotal** and **AbuseIPDB**), and delivers an analyst-centric triage dashboard with incident response ticketing and NIST-compliant PDF investigation reports.

---

## 🏗️ System Architecture

```
                                 [ Windows Host Telemetry ]
                                              │
                      ┌───────────────────────┴───────────────────────┐
                      ▼                                               ▼
         [ Windows Security Events ]                     [ Sysmon Telemetry ]
           (Event IDs: 4625, 4648,                         (Event IDs: 1, 3, 7,
              4698, 4720, 4732)                              10, 11, 13, 22)
                      │                                               │
                      └───────────────────────┬───────────────────────┘
                                              ▼
                              ┌──────────────────────────────┐
                              │  Detection & Rule Engine     │
                              │  • MITRE ATT&CK Mapping      │
                              │  • Time-Window Correlation   │
                              │  • Threshold Anomaly Checks  │
                              └──────────────┬───────────────┘
                                             ▼
                                   [ Alert Generator ]
                                             │
                      ┌──────────────────────┴──────────────────────┐
                      ▼                                             ▼
          ┌──────────────────────┐                    ┌────────────────────────┐
          │  Threat Intel Feeds  │                    │     SQLite Database    │
          │  • VirusTotal v3     │                    │  • alerts / incidents  │
          │  • AbuseIPDB v2      │                    │  • IOC reputation log  │
          └──────────┬───────────┘                    └───────────┬────────────┘
                     │                                            │
                     └───────────────────────┬────────────────────┘
                                             ▼
                             ┌────────────────────────────────┐
                             │    MiniSOC Analyst Web UI      │
                             │  • Live KPI & MITRE Heatmap    │
                             │  • 1-Click IOC API Enrichment  │
                             │  • Triage & Status Workflow    │
                             │  • NIST-aligned PDF IR Reports │
                             └────────────────────────────────┘
```

---

## 🎯 Detection Engineering & MITRE ATT&CK Mapping

| Detection Rule | MITRE Tactic | MITRE Technique | Event Source | Description |
|---|---|---|---|---|
| **Brute Force Detection** | Credential Access | **T1110** | Security 4625 | Detects $\ge 5$ logon failures within a 60-second sliding time window. |
| **Pass-the-Hash / Explicit Creds** | Lateral Movement | **T1550.002** | Security 4648 | Flags logon attempts initiated with explicit alternate user credentials. |
| **Suspicious Process Lineage** | Execution | **T1059** | Sysmon 1 | Catches Office binaries (`winword.exe`, etc.) spawning command shells (`cmd.exe`, `powershell.exe`). |
| **LSASS Memory Access** | Credential Access | **T1003.001** | Sysmon 10 | Monitors unauthorized non-system processes opening handles to `lsass.exe` (Mimikatz indicators). |
| **Persistence via Scheduled Task** | Persistence | **T1053.005** | Security 4698 | Detects the registration of new background tasks via Task Scheduler. |
| **Privilege Escalation (Admin Add)** | Privilege Escalation | **T1078.003** | Security 4732 | Alerts immediately whenever an account is added to high-privilege groups (Administrators). |
| **Local Account Creation** | Persistence | **T1136.001** | Security 4720 | Identifies clandestine creation of rogue local user accounts. |

---

## ✨ Key Features

1. **Native Windows Telemetry Ingestion**: Uses `pywin32` APIs (`OpenEventLog`, `ReadEventLog`) for non-blocking extraction of system audit events directly from the Windows Event Subsystem.
2. **Automated Threat Intelligence Enrichment**:
   - **VirusTotal v3**: Direct API query for external source IPs and binary SHA-256 hashes providing multi-engine AV verdict ratios.
   - **AbuseIPDB v2**: Computes actionable Abuse Confidence Scores (0–100%) alongside ISP and geographic geolocations.
3. **Analyst Triage & Lifecycle Tracking**:
   - Filter alerts by severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
   - One-click workflow triage: Mark alerts as `OPEN`, `CLOSED`, or `FP` (False Positive).
4. **NIST SP 800-61 Aligned Incident Reports**:
   - Generates production-ready PDF investigation reports with executive summaries, correlated telemetry evidence tables, and containment recommendations using `reportlab`.

---

## 🚀 Quick Start Guide

### Prerequisites
- Windows 10/11
- Python 3.10+
- Administrative privileges (recommended for reading the Windows `Security` event log)

### 1. Clone & Setup Virtual Environment
```powershell
cd D:\cyber\mini-soc
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure API Keys
Edit `config.yaml` with your API credentials:
```yaml
api_keys:
  virustotal: "YOUR_VIRUSTOTAL_API_KEY"
  abuseipdb:  "YOUR_ABUSEIPDB_API_KEY"

detection:
  brute_force_threshold: 5
  brute_force_window_sec: 60

dashboard:
  host: "127.0.0.1"
  port: 5000
  debug: true
```

### 3. Launch MiniSOC
Open two terminals:

**Terminal 1 — Start the Web Dashboard:**
```powershell
venv\Scripts\activate
python dashboard/app.py
```
*Access UI at `http://127.0.0.1:5000`*

**Terminal 2 — Start the Event Monitor (Run as Administrator):**
```powershell
venv\Scripts\activate
python main.py
```

---

## 💼 Resume & Interview Talking Points

### Resume Bullet Format
```
MiniSOC — Automated SOC Tier 1 Monitoring & Incident Response Platform
• Architected a real-time SIEM-lite monitoring platform in Python capturing Windows Security & Sysmon telemetry via Win32 APIs.
• Engineered 7 behavioral detection rules mapped to MITRE ATT&CK (T1110, T1059, T1003, T1550) with time-window thresholding.
• Integrated VirusTotal v3 and AbuseIPDB v2 REST APIs to automate IOC reputation scoring and reduce analyst triage time.
• Developed a responsive Flask web interface featuring MITRE tactic analytics, one-click enrichment, and automated NIST-aligned PDF incident report generation.
Tech Stack: Python 3, Flask, SQLite, Windows Event Logs (Win32), MITRE ATT&CK, VirusTotal API, AbuseIPDB API, ReportLab, Bootstrap 5.
```

### Technical Interview Answer Template
> *"For my capstone project, I developed MiniSOC to get hands-on with the daily workflow of a SOC Tier 1 analyst. Rather than just viewing logs in commercial tools, I wanted to understand how event pipelines function from the ground up. I wrote custom collectors in Python using pywin32 to monitor Event IDs like 4625 for brute force and Sysmon ID 1 for suspicious child processes. I mapped every rule directly to MITRE ATT&CK techniques, wired automated Threat Intel enrichment using VirusTotal and AbuseIPDB, and built a Flask triage interface that exports formal incident response PDFs aligned with NIST guidelines."*

---

## 📜 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
