# 🛡️ MiniSOC v2.0 Enterprise — Autonomous SOC & Incident Response Platform

[![Python](https://img.shields.io/badge/Python-3.11-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Web UI](https://img.shields.io/badge/Web_UI-Flask-000000.svg?logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Security](https://img.shields.io/badge/Security-MITRE_ATT%26CK-red.svg)](https://attack.mitre.org/)
[![Threat Intel](https://img.shields.io/badge/Threat_Intel-VT_%7C_AbuseIPDB_%7C_ThreatFox_%7C_OTX-green.svg)](https://threatfox.abuse.ch/)
[![AI Analyst](https://img.shields.io/badge/AI_Analyst-Nova_Autonomous_RCA-purple.svg)](#-nova--autonomous-ai-soc-analyst-co-pilot)
[![Handbook](https://img.shields.io/badge/Documentation-Developer_Handbook-orange.svg)](HANDBOOK.md)
[![License](https://img.shields.io/badge/License-MIT-lightgrey.svg)](LICENSE)

**MiniSOC v2.0** is an enterprise-ready, autonomous Security Operations Center (SOC) Level 1/2 monitoring, orchestration, and active defense platform. 

It continuously ingests host audit logs and network telemetry from distributed agents, correlates events against the **MITRE ATT&CK framework**, auto-enriches observable IOCs across multi-feed Threat Intelligence APIs (**VirusTotal**, **AbuseIPDB**, **AlienVault OTX**, **ThreatFox**), enforces active firewall containment (**IPS**), and features **Nova** — an autonomous "humanoid" AI SOC Analyst co-pilot providing real-time Root Cause Analysis (RCA) and triage assistance.

---

## 📘 Comprehensive Developer & Analyst Handbook
> Want to build, customize, or contribute to this platform?  
> Read our complete **[Developer & Security Analyst Handbook (HANDBOOK.md)](HANDBOOK.md)** covering architecture, rule engineering, remote agent deployment, and SOC interview preparation!

---

## 🏗️ v2.0 Distributed Architecture

```
                       [ Distributed Endpoint Agents ]           [ Windows Host Audit ]
                        (Processes, Sockets, Auth)               (Security & Sysmon)
                                    │                                      │
                                    └──────────────────┬───────────────────┘
                                                       ▼
                                         [ Ingestion & NSM Engine ]
                                         (Raw Sockets, Port Sweeps)
                                                       │
                                                       ▼
                                       ┌───────────────────────────────┐
                                       │    Detection & Correlation    │
                                       │    • Sliding-Window Anomaly   │
                                       │    • MITRE ATT&CK Mapping     │
                                       └───────────────┬───────────────┘
                                                       │
                           ┌───────────────────────────┴───────────────────────────┐
                           ▼                                                       ▼
               ┌───────────────────────┐                               ┌───────────────────────┐
               │   Threat Intel Hub    │                               │  Active IPS Defense   │
               │  • VirusTotal v3      │                               │  • Auto Host Firewall │
               │  • AbuseIPDB v2       │                               │    Blocking (netsh)   │
               │  • ThreatFox (abuse)  │                               │  • Host Quarantine    │
               │  • AlienVault OTX     │                               └───────────────────────┘
               └───────────┬───────────┘
                           │
                           ▼
          ┌─────────────────────────────────────────────────────────────────┐
          │                    MiniSOC Web Operations Center                │
          ├────────────────────────────────┬────────────────────────────────┤
          │  Analyst Triage & Event Feed   │  🤖 Nova AI Analyst Co-Pilot   │
          │  Live NSM Network Traffic View │  Autonomous RCA Briefings      │
          │  Endpoint Fleet Management     │  NIST SP 800-61 PDF Reports    │
          └────────────────────────────────┴────────────────────────────────┘
```

---

## 🌟 What's New in v2.0 Enterprise

1. **Multi-Feed Threat Intelligence Hub**:
   - Integrated **AlienVault OTX** pulse indicators.
   - Integrated **abuse.ch ThreatFox & URLhaus** for instant malware C2 and payload tracking (zero API key needed).
2. **Distributed Endpoint Agent (`agent/endpoint_agent.py`)**:
   - Zero-dependency client daemon deployable on Windows or Linux workstations.
   - Pushes process execution trees, active network sockets, and auth states to the central MiniSOC server via authenticated REST API.
3. **Network Security Monitoring (NSM) & Active IPS**:
   - Real-time socket scanner detecting rapid port sweeps and plaintext credential exposure.
   - **Active Host Defense**: Auto-blocks attacking IPs directly via Windows Firewall (`netsh`) or `iptables`.
4. **🤖 Nova — Autonomous AI SOC Analyst Co-Pilot**:
   - Embedded interactive AI co-pilot in the dashboard.
   - **1-Click RCA**: Generates human-grade Root Cause Analysis (RCA) narratives, blast radius estimates, and containment recommendations.
   - Conversational triage assistant answering questions about MITRE tactics, indicators, and investigation procedures.
5. **NIST SP 800-61 Rev 2 PDF Reports**:
   - One-click export of formal executive and technical incident investigation reports.

---

## 🎯 Detection Engineering & MITRE ATT&CK Matrix

| Detection Rule | MITRE Tactic | Technique | Source | Description |
|---|---|---|---|---|
| **Brute Force Detection** | Credential Access | **T1110** | Security 4625 | $\ge 5$ logon failures within 60s window. |
| **Pass-the-Hash / Explicit Creds** | Lateral Movement | **T1550.002** | Security 4648 | Logon attempts using explicit alternate credentials. |
| **Port Sweep / Reconnaissance** | Discovery | **T1046** | NSM Engine | Rapid inbound scanning across multiple ports. |
| **Suspicious Process Lineage** | Execution | **T1059** | Sysmon 1 | Office binaries (`winword.exe`) spawning CLI shells. |
| **LSASS Memory Access** | Credential Access | **T1003.001** | Sysmon 10 | Non-system handles opened to `lsass.exe`. |
| **Persistence via Scheduled Task** | Persistence | **T1053.005** | Security 4698 | Dynamic registration of rogue scheduled tasks. |
| **Privilege Escalation** | Privilege Escalation | **T1078.003** | Security 4732 | Account added to high-privilege Administrators group. |

---

## 🚀 Quickstart Guide

### 1. Start MiniSOC Web Operations Center
```powershell
cd D:\cyber\mini-soc
venv\Scripts\activate
python dashboard/app.py
```
*Access Web Console at: `http://127.0.0.1:5000`*

### 2. Start Windows Security Audit Monitor (Admin)
```powershell
python main.py
```

### 3. Deploy an Endpoint Telemetry Agent
```powershell
python agent/endpoint_agent.py http://127.0.0.1:5000/api/v1/telemetry
```

---

## 📜 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
