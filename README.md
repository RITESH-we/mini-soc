# 🛡️ MiniSOC v2.3 Enterprise — Cloud-Ready SIEM, XDR & UEBA Platform
### Synthesizing the Top 10 Enterprise SIEM Platforms into a Modern Cloud-Native Security Engine

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Web UI](https://img.shields.io/badge/Web_UI-Flask-000000.svg?logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Security](https://img.shields.io/badge/Security-MITRE_ATT%26CK_v14-red.svg)](https://attack.mitre.org/)
[![Schema](https://img.shields.io/badge/Schema-OCSF%20%2F%20ECS-blueviolet.svg)](https://schema.ocsf.io)
[![Top 5 Attacks](https://img.shields.io/badge/EDR-Top_5_Attack_Vectors-critical.svg)](#-top-5-most-critical-cyber-attack-use-cases--advanced-threat-suite)
[![UEBA](https://img.shields.io/badge/UEBA-Behavioral_Risk_Engine-purple.svg)](#-behavioral-ueba-risk-engine-exabeam--securonix-inspiration)
[![Tests](https://img.shields.io/badge/Tests-100%25_Passing-success.svg)](tests/test_top5_attacks.py)
[![Cloud Ready](https://img.shields.io/badge/Deployment-Docker%20%7C%20Cloud-informational.svg)](Dockerfile)
[![Threat Intel](https://img.shields.io/badge/Threat_Intel-VT_%7C_AbuseIPDB_%7C_ThreatFox_%7C_OTX-green.svg)](https://threatfox.abuse.ch/)
[![Architecture](https://img.shields.io/badge/Architecture-Enterprise_Deep_Dive-orange.svg)](ARCHITECTURE.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-lightgrey.svg)](LICENSE)

**MiniSOC** is an enterprise-grade, cloud-ready Security Operations Center (SOC) Level 1/2 monitoring, orchestration, and active defense platform. 

It was engineered by identifying the foundational architectural bottlenecks, proprietary lock-ins, and operational limitations across the **10 leading enterprise SIEM platforms** (**Splunk ES, Microsoft Sentinel, IBM QRadar, Elastic Security, Exabeam, Securonix, Rapid7 InsightIDR, Sumo Logic, LogRhythm, and ManageEngine Log360**) and synthesizing their greatest strengths into a unified, high-performance, open-schema architecture.

---

## 🏛️ Enterprise SIEM Flaw Analysis & MiniSOC Synthesis

| Enterprise Platform | Major Industry Flaws / Pain Points | MiniSOC Next-Gen Architectural Solution |
| :--- | :--- | :--- |
| **Splunk Enterprise Security** | Exorbitant GB/day indexing costs, proprietary SPL lock-in, resource-heavy search heads. | Lightweight OCSF/ECS-compliant JSON schema, zero proprietary query lock-in, sub-second indexing without memory bloat. |
| **Microsoft Sentinel** | Cloud lock-in to Azure, expensive Log Analytics retention tiers, data egress fees. | 100% cloud-agnostic portable architecture (Docker, AWS ECS, GCP Cloud Run, Azure Container Apps, or bare metal). |
| **IBM QRadar** | Outdated legacy UI; fragile Device Support Modules (DSMs) that break on minor log changes; heavy Java stack. | Modern dark-mode SOC analyst console; resilient, dynamic schema-on-read JSON parser; lightweight Python asyncio backend. |
| **Elastic Security** | Steep learning curve for ECS mappings; lacks native out-of-the-box UEBA without expensive Platinum tier; ILM crashes. | Built-in UEBA (User & Entity Behavior Analytics) risk scoring engine included natively with auto-rotating data retention. |
| **ManageEngine Log360** | Slow query engine; primarily compliance/audit oriented; weak real-time threat correlation across non-Windows logs. | Real-time multi-stage correlation engine mapped directly to MITRE ATT&CK Enterprise Matrix v14 for proactive threat detection. |
| **Exabeam** | Heavily dependent on third-party collectors for raw ingestion; complex timeline stitching. | End-to-end integrated stack: from lightweight zero-dependency endpoint agent up to interactive timeline reconstruction. |
| **Securonix** | Opaque black-box ML models; difficult to tune or explain alert causation in SOC L1 triage. | Explainable AI & Humanoid SOC Analyst ("Nova") delivering transparent, step-by-step Root Cause Analysis (RCA) with full evidence breakdown. |
| **Rapid7 InsightIDR** | Rigid LEQL query syntax; limited support for custom log types and deep event parsing. | Universal JSON structured queries with field-level filtering on extracted Windows/Linux/Cloud attributes. |
| **Sumo Logic** | Query timeouts on large multi-tenant data lakes; high variable ingestion costs. | Local & edge pre-filtering with client-side event deduplication, state tracking (Record ID), and structured batch dispatch. |
| **LogRhythm** | Legacy on-premise heritage; complex MDI fabric; rigid manual playbook execution. | Automated zero-touch SOAR playbooks (Host Isolation, Firewall IPS drops, Process Termination) executable in 1 click. |

> 📖 **Deep Dive**: Read the complete architectural blueprint, technical comparison, and interview guide in **[ARCHITECTURE.md](ARCHITECTURE.md)**!

---

## 🏗️ Distributed System Architecture

```
                       [ Distributed Endpoint Agents ]           [ Cloud & Syslog Webhooks ]
                        (Processes, Sockets, XML Events)          (AWS, GCP, Azure, Syslog)
                                    │                                      │
                                    └──────────────────┬───────────────────┘
                                                       ▼
                                          [ OCSF / ECS Parser & Normalizer ]
                                          (EventRecordID Watermark Deduplication)
                                                       │
                                                       ▼
                                        ┌───────────────────────────────┐
                                        │    Detection & UEBA Engine    │
                                        │    • Dynamic Host & User Risk │
                                        │    • MITRE ATT&CK Matrix v14  │
                                        └───────────────┬───────────────┘
                                                       │
                           ┌───────────────────────────┴───────────────────────────┐
                           ▼                                                       ▼
               ┌───────────────────────┐                               ┌───────────────────────┐
               │   Threat Intel Hub    │                               │  Active IPS Defense   │
               │  • VirusTotal v3      │                               │  • Auto Host Firewall │
               │  • AbuseIPDB v2       │                               │    Blocking (netsh)   │
               │  • ThreatFox (abuse)  │                               │  • 1-Click EDR Quarant│
               │  • AlienVault OTX     │                               └───────────────────────┘
               └───────────┬───────────┘
                           │
                           ▼
          ┌─────────────────────────────────────────────────────────────────┐
          │                    MiniSOC Web Operations Center                │
          ├────────────────────────────────┬────────────────────────────────┤
          │  Analyst Triage & Event Feed   │  🤖 Nova AI Analyst Co-Pilot   │
          │  Live NSM Network Traffic View │  Autonomous RCA Briefings      │
          │  Endpoint Fleet & UEBA Matrix  │  NIST SP 800-61 PDF Reports    │
          └────────────────────────────────┴────────────────────────────────┘
```

---

## 🌟 Key Capabilities

### 1. Structured XML Telemetry, Deduplication & At-Least-Once Delivery
- Querying Windows Event Log via `/f:xml` using standard library `xml.etree.ElementTree` (zero third-party dependencies).
- Extracts exact security fields: **`EventID`**, **`TargetUserName`**, **`IpAddress`**, **`LogonType`**, **`Status`**, **`SubStatus`**, **`CommandLine`**, and **`ParentProcessName`**.
- **At-Least-Once Delivery Architecture**: The high-watermark state is only committed to disk *after* the SOC server returns an HTTP 200 acknowledgement. If network connectivity drops or the server reboots, telemetry is retained in memory and re-transmitted, guaranteeing zero event loss.
- **Persistent Auto-Start Daemon**: Survives system reboots and power-offs. Engineered with zero-popup headless execution (`CREATE_NO_WINDOW` and `SW_HIDE` process flags ensuring zero CMD or console flashes during periodic EVTX/socket polling). Features dual-tier auto-start on Windows (zero-privilege headless VBS startup runner + elevated Windows Task Scheduler) and native `systemd` service management on Linux with automatic failure recovery.
- **Continuous Security Posture Auditing**: Automatically reports local Antivirus engine health (Windows Defender service state), Windows Firewall profile enforcement (Domain/Private/Public), and administrative privilege elevation.

### 2. High-Concurrency Storage & Indexing Engine (WAL Mode)
- **SQLite Write-Ahead Logging (WAL)**: Configured `PRAGMA journal_mode = WAL`, `synchronous = NORMAL`, and `busy_timeout = 10000`, enabling non-blocking concurrent reads and writes across simultaneous agent telemetry streams and analyst queries.
- **Compound B-Tree Indexing**: Dedicated multi-column indexes on `alerts(device_name, timestamp)`, `alerts(src_user, timestamp)`, `alerts(status)`, and `telemetry_logs(hostname, timestamp)` eliminating full-table scans.

### 3. Behavioral UEBA Risk Engine (Exabeam & Securonix Inspiration)
- Computes real-time dynamic risk scores (0–100) for both **Hosts** and **Users**.
- Behavioral scoring matrix:
  - Repeated authentication failures: $+15$ pts
  - Suspicious process execution (`mimikatz`, `psexec`, `powershell -enc`): $+40$ pts
  - Privilege tampering & security group additions: $+35$ pts
  - Dynamic risk tiers: `LOW (0-24)`, `MEDIUM (25-49)`, `HIGH (50-74)`, `CRITICAL (75-100)`

### 4. Multi-Feed Threat Intelligence Hub & RFC 1918 Guard
- Integrated **AlienVault OTX**, **VirusTotal v3**, **AbuseIPDB**, and **abuse.ch ThreatFox** (zero API key needed for public feeds).
- **Private RFC 1918 Filter**: Automatically detects internal/loopback traffic, returning instant LAN classification without wasting external API quota.

### 5. Proactive Endpoint Defense & SOAR Containment (EDR)
- **Endpoint-Edge Firewall Drops**: When an analyst or IPS rule blocks an IP, the command is dispatched down to all active endpoint agents, enforcing kernel-level firewall drops (`netsh advfirewall` / `iptables`) on the devices themselves.
- **1-Click Host Quarantine with SOC Fail-Safe**: Instantly isolates compromised endpoints from lateral movement and external networks while preserving the SOC management communication channel.
- **Autonomous Process Termination**: Remote and automated termination of attacker tooling (`mimikatz`, `nc.exe`, `psexec.exe`).
- **Live NSM Inspection**: Robust IPv4/IPv6 socket inspection detecting inbound port sweeps (T1046) and cleartext protocol exposure (T1040).

### 6. 🤖 Nova — Autonomous AI SOC Analyst Co-Pilot
- Interactive AI co-pilot embedded in the dashboard.
- **1-Click RCA**: Generates human-grade Root Cause Analysis narratives, blast radius estimates, and containment recommendations.
- **NIST SP 800-61 Rev 2 Reports**: Generates formal incident PDF reports in 1 click.

### 7. 🕵️ Insider Threat Detection & Behavioral Profiling
- **Data Staging & Exfiltration Detection**: Flags suspicious bulk compression (`Compress-Archive`, `tar -czf`, `7z a`) targeting confidential repositories (`Documents`, `Desktop`, `.aws`, `.ssh`, `.git`) before scheduled employee offboarding.
- **Privilege Tampering & Shadow Accounts**: Real-time auditing of rogue account creation (`Event 4720`) and high-privilege escalation (`Event 4732` member added to local `Administrators`).
- **Anti-Forensics & Tampering**: Detects security event log clearing (`Event 1102` / `wevtutil cl`) and suspicious privilege enumeration (`whoami /priv` with `SeDebugPrivilege`).
- **Dynamic UEBA Risk Escalation**: Automatically aggregates behavioral anomalies, escalating user risk scores to Critical (`>= 75 pts`) and surfacing them on the Top Risky Entities matrix.

### 8. 🎯 Interactive Alert Triage Console & Wazuh-Style Forensic Log Inspector
MiniSOC provides an enterprise-grade alert triage console modeled after **Wazuh Discover**, **OpenSearch Dashboards**, and real-world SOC benchmark investigations (such as **OpenSOC-Lab Case 001**), allowing L1/L2 security analysts to perform deep forensic examinations directly from the alert feed without switching consoles:

```
+---------------------------------------------------------------------------------------------------------+
| [🔍 #16] 2026-09-20 00:42:52 | LENOVO | HIGH | 📜 LOTL / SCRIPT | Suspicious PowerShell Script Block    |
+---------------------------------------------------------------------------------------------------------+
| [WAZUH-STYLE LOG INSPECTOR]  Alert #16 — Suspicious PowerShell Script Block  [HIGH]  Host: LENOVO        |
| Tabs: [ 📋 Forensic Table ]  [ { } Raw JSON ]  [ ⏱️ Surrounding Timeline ]                           [✕] |
+---------------------------------------------------------------------------------------------------------+
|                                                                                                         |
|  [TAB 1: 📋 FORENSIC TABLE VIEW] (Process Lineage & Attribute Breakdown)                                 |
|  • agent.name                     LENOVO                                                                |
|  • data.win.system.eventID        4104                                                                  |
|  • data.win.eventdata.image       C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe             |
|  • data.win.eventdata.processId   9728                                                                  |
|  • data.win.eventdata.parentImage services.exe                                                          |
|  • data.win.eventdata.parentPID   9928                                                                  |
|  • data.win.eventdata.commandLine Set-ExecutionPolicy -ExecutionPolicy ByPass -Scope CurrentUser...     |
|  • data.win.eventdata.hashes      SHA256=AUTHENTICATED_WINDOWS_BINARY                                   |
|  • data.win.eventdata.user        DESKTOP\rites                                                         |
|  • rule.mitre.technique           T1059.001 - PowerShell                                                |
|                                                                                                         |
|  [TAB 2: { } RAW JSON VIEW]                                                                             |
|  • Formatted, syntax-highlighted OCSF/Sysmon JSON payload with a 1-click "📋 Copy JSON" button.         |
|                                                                                                         |
|  [TAB 3: ⏱️ SURROUNDING TIMELINE CONTEXT] ("View Surrounding Documents" Model)                           |
|  • Reconstructs the temporal execution window: queries ±8 events immediately preceding and following    |
|    the incident on the target host, highlighting the exact alert trigger (🚨 [ALERT HIT]).             |
+---------------------------------------------------------------------------------------------------------+
```

- **Expandable In-Place Log Inspector**: Clicking any alert row smoothly toggles the forensic inspection drawer:
  - **📋 Forensic Table Tab**: Two-column key-value attribute view mapping process lineage (`image`, `processId`, `parentImage`, `parentProcessId`, `commandLine`, `parentCommandLine`), security tokens (`user`, `integrityLevel`, `hashes`), and rule definitions (`rule.id`, `rule.level`, `rule.mitre`).
  - **{ } Raw JSON Tab**: Pretty-printed, syntax-highlighted OCSF/Sysmon event payload with 1-click clipboard copying for external reporting and SIEM forwarding.
  - **⏱️ Surrounding Timeline Tab**: Temporal context reconstruction (`/api/alert/<id>/surrounding`) displaying adjacent host telemetry ($\pm 8$ events) before and after the alert to trace root cause processes.
- **Multi-Vector Quick-Filter Controls**: Instantly filter triage queues by specific attack vectors (`Ransomware`, `Credential Access`, `Living-off-the-Land`, `C2 & Exfiltration`, `Persistence`, `All Categories`).
- **Visual Attack Badges**: Color-coded badges with MITRE ATT&CK technique tags directly on alert rows.
- **Direct 1-Click Containment**: Execute host isolation (`🛑 Isolate`) or IP blocks straight from the alert triage row without switching screens.
- **Exportable Evidence**: Full CSV alert exports with MITRE techniques, threat categories, and threat intelligence scores for compliance reporting.

---

## 🛡️ Top 5 Most Critical Cyber Attack Use Cases & Advanced Threat Suite

MiniSOC implements end-to-end telemetry harvesting, real-time correlation, UEBA behavioral risk scoring, and automated SOAR playbooks for the **Top 5 Most Critical Cyber Attack Vectors** encountered in modern enterprise environments:

```
+---------------------------------------------------------------------------------------------------------+
|                                    MINISOC TOP 5 ATTACK DEFENSE SUITE                                   |
+---------------------------------------------------------------------------------------------------------+
| [1. RANSOMWARE]         VSS Shadow Copy Deletion (T1490)      ==> Host Isolation + Process Term (CRIT)  |
| [2. CREDENTIAL THEFT]   LSASS Dumping & Pass-the-Hash (T1003) ==> Process Kill + Credential Revoke(HIGH)|
| [3. LIVING-OFF-THE-LAND]Obfuscated PowerShell / Fileless(T1059)==> AMSI Detection + Script Kill (HIGH)  |
| [4. C2 & EXFILTRATION]  Beaconing & Bulk Staging (T1071/T1560)==> EDR Local Firewall IP Drop (HIGH)     |
| [5. ROGUE PERSISTENCE]  Scheduled Tasks & Anti-Forensics(T1053)==> Log Tamper Alert + Group Audit (CRIT)|
+---------------------------------------------------------------------------------------------------------+
```

### 1. Ransomware Recovery Inhibition & Shadow Copy Destruction (T1490 / T1486)
- **The Threat**: Attackers (LockBit, BlackCat, Akira) systematically delete Volume Shadow Copies and disable system recovery mechanisms immediately before executing mass disk encryption.
- **Signatures & Telemetry**: Event ID 4688 / process telemetry matching `vssadmin delete shadows`, `wmic shadowcopy delete`, `wbadmin delete catalog`, or `bcdedit /set {default} recoveryenabled no`.
- **UEBA Impact**: **$+50$ pts (CRITICAL)**.
- **SOAR Automated Response**: **1-Click Host Network Isolation** (enforcing local firewall quarantine) + immediate kill of the offending parent process.

### 2. In-Memory Credential Dumping & Pass-the-Hash (T1003.001 / T1550.002)
- **The Threat**: Attackers dump cached NTLM hashes from `lsass.exe` memory or replay stolen hashes across the subnet without knowing the user's cleartext password.
- **Signatures & Telemetry**:
  - Event ID 4648 (`Logon using explicit alternate credentials`) from non-domain controller endpoints.
  - CLI executions of `comsvcs.dll, MiniDump`, `mimikatz.exe`, `vaultcmd`, or suspicious `whoami /priv` debugging queries.
- **UEBA Impact**: **$+45$ pts (HIGH)**.
- **SOAR Automated Response**: Autonomous process termination (`kill_process`) + alert escalation to SOC Tier 2 for Kerberos/NTLM credential reset.

### 3. Living-off-the-Land (LotL) Obfuscated PowerShell & Fileless Execution (T1059.001 / T1027)
- **The Threat**: Fileless intrusions evading signature-based antivirus by executing malicious payloads directly inside memory using native Windows binaries (`powershell.exe`, `wscript.exe`, `certutil.exe`).
- **Signatures & Telemetry**:
  - **Event ID 4104 (PowerShell Script Block Logging)** capturing de-obfuscated script blocks.
  - Encoded parameters (`-enc`, `-encodedcommand`), execution policy bypasses (`-ep bypass`), AMSI tampering (`amsiutils`), or memory web cradles (`DownloadString`, `IEX`).
- **UEBA Impact**: **$+40$ pts (HIGH)**.
- **SOAR Automated Response**: Immediate PowerShell process termination + quarantine endpoint host.

### 4. Malicious C2 Beaconing & Bulk Data Staging / Exfiltration (T1071.001 / T1560 / T1048)
- **The Threat**: Compromised endpoints establish recurring command-and-control beacons and compress confidential company assets into encrypted archives prior to data exfiltration.
- **Signatures & Telemetry**:
  - Outbound TCP/UDP socket connections targeting known threat actor C2 ports (`:4444`, `:1337`, `:8888`, `:7070`, `:9001`, `:6667`, `:31337`).
  - Mass command-line archiving utilities (`Compress-Archive`, `tar -czf`, `7z a`, `rar a`) targeting user profiles (`Documents`, `Desktop`, `.aws`, `.ssh`).
- **UEBA Impact**: **$+40$ pts (HIGH)**.
- **SOAR Automated Response**: **Endpoint Firewall IP Drop** (`netsh advfirewall` / `iptables` drop pushed directly to endpoint) + host isolation.

### 5. Rogue Persistence via Scheduled Tasks / Services & Admin Privilege Escalation (T1053.005 / T1078.003 / T1070.001)
- **The Threat**: Threat actors establish persistent access across host reboots by registering rogue scheduled tasks, creating hidden local administrator accounts, and clearing audit logs to cover their tracks.
- **Signatures & Telemetry**:
  - **Event ID 4698**: Scheduled task dynamically registered.
  - **Event ID 4697**: New system service installed.
  - **Event ID 4720 & 4732**: Local account created and added to the `Administrators` security group.
  - **Event ID 1102**: The Windows Security audit log was cleared / wiped (Defense Tampering / Anti-Forensics).
- **UEBA Impact**: **$+45$ to $+50$ pts (HIGH / CRITICAL)**.
- **SOAR Automated Response**: High-priority alert notification + automated forensic case creation in SOC Incidents table.

---

## 🎯 Detection Engineering & MITRE ATT&CK Matrix

| Detection Rule | MITRE Tactic | Technique | Source | Threat Category | Severity |
|---|---|---|---|---|---|
| **Ransomware Shadow Copy Deletion** | Impact | **T1490** | Security 4688 / Sysmon | `RANSOMWARE` | `CRITICAL` |
| **Pass-the-Hash / Explicit Creds** | Lateral Movement | **T1550.002** | Security 4648 | `CREDENTIAL_ACCESS` | `HIGH` |
| **In-Memory LSASS Dumping** | Credential Access | **T1003.001** | Process / Sysmon 10 | `CREDENTIAL_ACCESS` | `HIGH` |
| **Brute Force Detection** | Credential Access | **T1110** | Security 4625 | `CREDENTIAL_ACCESS` | `MEDIUM` |
| **Obfuscated PowerShell / Fileless** | Execution | **T1059.001** | PowerShell 4104 / 4688 | `LIVING_OFF_THE_LAND` | `HIGH` |
| **Data Staging for Exfiltration** | Collection | **T1560** | Security 4688 | `EXFILTRATION` | `HIGH` |
| **Malicious Outbound C2 Beaconing** | Command & Control | **T1071.001** | NSM / Sockets | `EXFILTRATION` | `HIGH` |
| **Rogue Scheduled Task Created** | Persistence | **T1053.005** | Security 4698 | `PERSISTENCE` | `HIGH` |
| **Windows Audit Log Cleared** | Defense Evasion | **T1070.001** | Security 1102 | `PERSISTENCE` | `CRITICAL` |
| **Privilege Escalation (Admin Added)**| Privilege Escalation | **T1078.003** | Security 4732 | `PERSISTENCE` | `HIGH` |

---

## 🚀 Quickstart Guide

### Option A: Local Development & Public Tunnel

#### 1-Click Launch (Dashboard + Ngrok Public Tunnel):
```powershell
.\start_soc.bat
```

#### Or Run Manually in Separate Terminals:
```powershell
# Terminal 1 — Start SOC Dashboard Server:
venv\Scripts\activate
python dashboard/app.py
# Access Web Console at: http://127.0.0.1:5000

# Terminal 2 — Start Ngrok Public Tunnel:
.\ngrok.exe http --url=underfoot-such-italics.ngrok-free.dev 5000
# Access Public Tunnel at: https://underfoot-such-italics.ngrok-free.dev

# Terminal 3 — Deploy Endpoint Telemetry Agent (Interactive Mode):
python agent/endpoint_agent.py http://127.0.0.1:5000/api/v1/telemetry
```

### Option B: Persistent Endpoint Agent Deployment (Survives Reboots)

Deploy the agent once on monitored laptops/servers — it automatically runs silently in the background on every power-on without requiring manual intervention:

#### Windows (1-Click or CLI):
```powershell
# Automated 1-Click Install:
Double-click agent\install_windows.bat

# Or run via PowerShell / CMD:
python agent/endpoint_agent.py --install http://YOUR_SERVER_IP:5000/api/v1/telemetry

# Check service status or remove:
python agent/endpoint_agent.py --status
python agent/endpoint_agent.py --uninstall
```

#### Linux (Systemd Service):
```bash
# Automated 1-Click Install:
sudo bash agent/install_linux.sh http://YOUR_SERVER_IP:5000/api/v1/telemetry

# Or run via Python:
sudo python3 agent/endpoint_agent.py --install http://YOUR_SERVER_IP:5000/api/v1/telemetry

# Inspect daemon status:
systemctl status minisoc-agent.service
```

#### Android Mobile Devices (Termux):
Monitor Android smartphones and tablets directly from MiniSOC:
```bash
# Inside Termux on Android:
pkg update && pkg install python git -y
python endpoint_agent.py http://YOUR_SOC_IP:5000/api/v1/telemetry
```
*Monitors Android network sockets (`ss`/`netstat`), active app processes, device architecture, and IP telemetry.*

### Option C: Mobile SOC Console Access (iOS & Android)
The MiniSOC web dashboard is built on a responsive Bootstrap 5 grid:
- Open `http://<SOC_LAN_IP>:5000` (e.g. `http://10.0.88.38:5000`) on your phone's browser (Safari / Chrome) while on the same Wi-Fi.
- For remote access anywhere, connect via your public tunnel / cloud domain (e.g. `https://<domain>.ngrok-free.dev`).
- **Full On-Call Triage**: Review live incident feeds, ask Nova AI questions, execute 1-click IP blocks, and isolate compromised hosts straight from your phone.

### Option D: Cloud & Container Deployment (Docker)

```bash
# 1-Click Multi-Container Launch
docker-compose up --build -d

# Verify Container Health
docker-compose ps
```

### Option E: Running the Attack Verification Test Suite

Verify that all 5 critical attack use cases, correlation rules, and UEBA risk scoring matrices are functioning at 100%:

```powershell
python tests/test_top5_attacks.py
```

*Simulates Ransomware Shadow Copy destruction, Pass-the-Hash / LSASS dumping, Obfuscated PowerShell, C2 beaconing, and rogue persistence with anti-forensics log clearing, verifying zero-error acknowledgment and instant risk escalation.*

---

## 💼 Top 1% Resume Positioning

```markdown
- Architected and implemented an enterprise-grade Cloud-Ready SIEM, XDR & UEBA platform synthesizing capabilities from Splunk ES, Microsoft Sentinel, and Exabeam, incorporating OCSF-compliant event normalization and real-time MITRE ATT&CK v14 threat mapping.
- Implemented an advanced detection suite covering the Top 5 modern attack vectors (Ransomware VSS deletion T1490, Pass-the-Hash T1550, Living-off-the-Land PowerShell T1059, C2 beaconing T1071, and rogue persistence T1053) with automated SOAR isolation playbooks.
- Engineered a zero-dependency endpoint agent featuring native Windows Event XML parsing (wevtutil/EVTX) and transactional At-Least-Once delivery watermarks, eliminating telemetry loss during network drops and preventing duplicate alert generation.
- Designed a behavioral User & Entity Behavior Analytics (UEBA) engine dynamically calculating host/user risk scores (0-100) based on authentication anomalies, privilege tampering, and unauthorized tool execution.
- Developed integrated SOAR response playbooks enabling 1-click endpoint network isolation and automated Host-based IPS (HIPS) firewall drops with RFC 1918 loopback fail-safes.
- Containerized the platform using multi-stage Docker builds for cloud-native deployment across AWS ECS, GCP Cloud Run, and on-premises environments.
```

---

## 💼 Commercial Use, Enterprise Pitches & Licensing Rights

MiniSOC is released under the **MIT License** with explicit permissions granted for commercial client presentations, enterprise evaluations, and professional service deployments:

- **Client Pitching & Demonstrations**: Fully authorized for commercial presentations, RFP technical evaluations, and venture/client pitches.
- **Enterprise Deployment**: Permitted for production usage across commercial cloud, on-premise, and hybrid environments.
- **MSSP & SOC-as-a-Service**: Can be utilized as the operational detection engine for Managed Security Service Providers without royalty or per-seat fees.
- **Zero Mock / 100% Real Architecture**: Every metric, process, network socket, and security event rendered on the dashboard is grounded in real OS kernel telemetry, live database states, and verified threat intelligence feeds.

See the complete terms in **[LICENSE](LICENSE)**.

---

## 📜 License
This project is licensed under the MIT License with Commercial & Enterprise Pitch Permissions - see the [LICENSE](LICENSE) file for details.

