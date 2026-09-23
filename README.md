# 🔱 TRISHULA Enterprise v2.4 — Cloud-Ready SIEM, XDR & UEBA Platform
### Threat Recognition, Incident Surveillance & Host Unified Lockdown Architecture
*Synthesizing Ancient Sanatana-Vedic Vigilance with Greek Mythic Defense into a Modern Zero-Evasion Security Fabric*

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Web UI](https://img.shields.io/badge/Web_UI-Flask-000000.svg?logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Security](https://img.shields.io/badge/Security-MITRE_ATT%26CK_v14-red.svg)](https://attack.mitre.org/)
[![Schema](https://img.shields.io/badge/Schema-OCSF%20%2F%20ECS-blueviolet.svg)](https://schema.ocsf.io)
[![CI Pipeline](https://img.shields.io/badge/CI-GitHub_Actions_100%25_Passing-success.svg)](.github/workflows/ci.yml)
[![Anti-Evasion](https://img.shields.io/badge/Anti--Evasion-De--obfuscation_%7C_Canary_%7C_Masquerading-orange.svg)](#-enterprise-multi-vector-defense--anti-evasion-fabric)
[![Active Scanning](https://img.shields.io/badge/Network-Active_Subnet_Scanner-informational.svg)](#-active-subnet-ip--port-discovery-scanner)
[![License: MIT](https://img.shields.io/badge/License-MIT-lightgrey.svg)](LICENSE)

---

## 🏛️ The Mythos & Identity: What is TRISHULA?

**TRISHULA** is an enterprise-grade, cloud-ready Security Operations Center (SOC) Level 1/2 monitoring, orchestration, and active defense platform.

The platform draws its identity from two ancient traditions of eternal vigilance:
* **The Sanatana (Vedic) Trishula (त्रिशूल)**: The primordial three-pointed trident of cosmic order and truth. The three prongs represent the three indivisible pillars of modern cybersecurity:
  1. **Endpoint XDR** (Deep Process Lineage, Parent-PID Tracking, Honey-Token Deception Traps)
  2. **Network NSM** (Passive Socket Inspection, Stealth Port-Sweep Detection, Active Subnet Discovery)
  3. **Cloud SIEM & SOAR** (MITRE ATT&CK v14 Correlation, Automated Firewall Containment, Nova AI Analyst)
* **The Greek Trident & Aegis**: Mirroring the ancient sea-sovereign's trident and the unyielding celestial shield (*Aegis*) that no mortal or titan could pierce.

### 📐 The Technical Acronym:
* **T** — **Threat**
* **R** — **Recognition**,
* **I** — **Incident**
* **S** — **Surveillance** &
* **H** — **Host**
* **U** — **Unified**
* **L** — **Lockdown**
* **A** — **Architecture**

---

## 🛡️ Enterprise Multi-Vector Defense & Anti-Evasion Fabric

Modern adversaries rarely attack from a single vector or execute plain `.exe` files. **TRISHULA** features 10 coordinated anti-evasion layers engineered specifically to neutralize stealth tactics:

| Anti-Evasion Capability | Adversary Deception Technique Defeated | Technical Implementation | MITRE ATT&CK |
| :--- | :--- | :--- | :--- |
| **Deep Process Lineage** | **Process Masquerading**: Renaming malware to `svchost.exe` running from `AppData` or `Temp`. | Queries `Win32_Process` via PowerShell/WMI to extract full `ExecutablePath`, `CommandLine`, `ParentProcessId` (PPID), and memory footprint. Flags any system binary running outside `System32`. | **T1036.005** |
| **Base64 De-obfuscation** | **Obfuscated PowerShell**: Hiding download cradles inside `-enc` or `-encodedcommand`. | Transparent real-time UTF-16LE Base64 decoder unwraps payloads in memory and audits the raw script block against attack signatures. | **T1059.001** |
| **Multi-Channel Windows Auditing** | **Blind Spot Exploitation**: Attacking services or wiping logs to blind security agents. | Ingests `Security`, `System` (Services & Log Clearing), `PowerShell/Operational`, and `Windows Defender/Operational` with a high-capacity 50-event batch window. | **T1070.001 / T1543.003** |
| **Deception Honey-Tokens** | **Credential Stealers & Ransomware**: Adversaries scraping local files for passwords. | Plants a monitored canary credential vault (`minisoc_vault_creds.db`). Any unauthorized read, modification, or deletion fires an immediate **CRITICAL** containment alert. | **T1081** |
| **Persistence Watcher** | **Reboot Backdoors**: Modifying registry autorun keys to survive endpoint restarts. | Continuously audits `HKCU` and `HKLM` Windows Run keys and Startup directories. New additions trigger instant escalation. | **T1547.001** |
| **USB Media Monitor** | **Physical Access & BadUSB**: Rubber Ducky / rogue thumb drives inserted into hosts. | Monitors `Win32_DiskDrive` for new USB bus arrivals and logs serial/hardware identifiers. | **T1091** |
| **Stealth Port Sweep NSM** | **Low-and-Slow Scans**: Scanning 1 port every 15s to bypass short rate-limit windows. | Extended 60-second sliding inspection window with a lowered 4-port threshold across sensitive management ports (`22, 445, 3389, 5985, 1433, 3306, 6379`). | **T1046** |
| **DNS Tunneling & DGA** | **Covert C2 Exfiltration**: Smuggling stolen data through DNS `UDP 53` queries. | Calculates Shannon character entropy and evaluates domain nesting depth (>3 subdomains, entropy >3.8) to catch covert channels. | **T1071.004** |
| **Active Subnet Discovery** | **Rogue & Unmanaged Devices**: Shadow IT or unauthorized machines plugged into the LAN. | Multi-threaded `/24` subnet sweeper built into `/network` that probes live hosts and open ports across the entire local IP range. | **T1595** |
| **Multi-Vector Correlator** | **Multi-Stage Attacks**: Phishing &rarr; Credential Theft &rarr; Lateral Movement. | Automatically correlates events spanning multiple MITRE tactics within 15 minutes into unified High-Severity Incidents. | **Multi-Tactic** |

---

## 🏗️ Distributed System Architecture

```
                       [ Distributed TRISHULA Agents ]           [ Cloud & Syslog Webhooks ]
                        (Processes, Lineage, Sockets,             (AWS, GCP, Azure, Syslog)
                         Canary, USB, Multi-Channel EVTX)                     │
                                    │                                         │
                                    └──────────────────┬──────────────────────┘
                                                       ▼
                                          [ OCSF / ECS Parser & Normalizer ]
                                          (EventRecordID Watermark Deduplication)
                                                       │
                                                       ▼
                                        ┌───────────────────────────────┐
                                        │    Detection & UEBA Engine    │
                                        │    • Dynamic Host & User Risk │
                                        │    • MITRE ATT&CK Matrix v14  │
                                        │    • Multi-Vector Correlator  │
                                        └───────────────┬───────────────┘
                                                       │
                           ┌───────────────────────────┴───────────────────────────┐
                           ▼                                                       ▼
               ┌───────────────────────┐                               ┌───────────────────────┐
               │   Threat Intel Hub    │                               │  Active SOAR Defense  │
               │  • VirusTotal v3      │                               │  • Auto Host Firewall │
               │  • AbuseIPDB v2       │                               │    Drops (netsh/ipt)  │
               │  • ThreatFox (abuse)  │                               │  • 1-Click Quarantine │
               │  • AlienVault OTX     │                               │  • Remote Process Kill│
               └───────────┬───────────┘                               └───────────────────────┘
                           │
                           ▼
          ┌─────────────────────────────────────────────────────────────────┐
          │                  TRISHULA Web Operations Center                 │
          ├────────────────────────────────┬────────────────────────────────┤
          │  Analyst Triage & Event Feed   │  🤖 Nova AI Analyst Co-Pilot   │
          │  Active Subnet & NSM Monitor   │  Autonomous RCA Briefings      │
          │  Endpoint Fleet & UEBA Matrix  │  NIST SP 800-61 PDF Reports    │
          │  Threat Hunting Playbooks (8)  │  Deception Honey-Token Console │
          └────────────────────────────────┴────────────────────────────────┘
```

---

## 🚀 Quick Start Guide

### Prerequisites
* Python 3.11 or higher
* Git

### 1-Click Automated Setup (Recommended)

#### Windows:
```cmd
setup.bat
```
*(Automatically creates Python virtualenv, installs locked dependencies, and initializes the high-concurrency database).*

#### Linux / macOS:
```bash
bash setup.sh
```

---

### Manual Deployment

#### Step 1: Install Dependencies
```bash
python -m venv venv
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
```

#### Step 2: Configure Environment
Copy the safe configuration template:
```bash
# Windows:
copy config.example.yaml config.yaml

# Linux/macOS:
cp config.example.yaml config.yaml
```
> 🔒 **Security Notice**: Edit `config.yaml` to set your unique session `secret_key` and add optional Threat Intelligence API keys (VirusTotal, AbuseIPDB, AlienVault OTX, ThreatFox). `config.yaml` is strictly gitignored to protect credentials.

#### Step 3: Launch the Operations Center
```bash
python dashboard/app.py
```
Console is accessible at: **`http://127.0.0.1:5000`**

---

## 🔐 Authentication & Role-Based Access Control (RBAC)

TRISHULA features role-based access control with timing-safe SHA-256 password hashing.

| Role Profile | Access Level | Operational Capabilities |
| :--- | :--- | :--- |
| **`admin`** | **SOC Administrator** | Full fleet policy control, firewall containment drops, host quarantine, settings |
| **`analyst`** | **Security Analyst** | L1/L2 Alert triage, deep forensic inspection, IOC enrichment, incident escalation |

> ⚠️ **IMPORTANT**: On first deployment, authenticate using the initial credentials initialized during database setup and **immediately navigate to settings or database management to rotate your passwords**.

---

## 📡 Deploying the TRISHULA Endpoint Agent

The endpoint agent is lightweight, cross-platform, and zero-dependency.

### Interactive Mode (Testing & Audits):
```powershell
python agent/endpoint_agent.py http://<YOUR_SOC_SERVER_IP>:5000/api/v1/telemetry --profile audit_friend
```

### Agent Policy Profiles:
* **`audit_friend` (Safe Telemetry Mode)**: Full log harvesting and event shipping; automatically suppresses disruptive actions (no automated firewall drops or process kills on friend/colleague laptops).
* **`standard_workstation` (Balanced EDR)**: Standard 15-second heartbeat with automated malware and ransomware containment drops.
* **`high_security_server` (Maximum Vigilance)**: Accelerated 5-second heartbeat, strict network surveillance, and immediate host quarantine upon critical detection.

### Persistent Daemon (Survives Reboots):
* **Windows**: Double-click `agent\install_windows.bat` (Registers elevated background scheduled task).
* **Linux**: `sudo bash agent/install_linux.sh http://<YOUR_SOC_SERVER_IP>:5000/api/v1/telemetry` (Registers systemd daemon).

---

## 🎯 Threat Hunting Playbooks (`/hunting`)

Execute proactive, hypothesis-driven hunts across live endpoint telemetry tables without waiting for static alerts:

1. **LOLBins & Script Interpreters (T1059)**: PowerShell, Certutil, MSHTA, Bitsadmin, Wscript, Curl, Rundll32.
2. **Anomalous Outbound Ports (T1071 / T1021)**: Sockets bound to non-standard or lateral movement ports (`4444, 1337, 8888, 445, 3389, 5985, 22`).
3. **Host Reconnaissance (T1087 / T1082)**: Discovery commands (`whoami, net user, tasklist, ipconfig, nltest`).
4. **Authentication Anomalies (T1110)**: Aggregates failed logon attempts (`Event ID 4625`) across all workstations.
5. **Process Masquerading (T1036)**: System binaries executing from user directories or Temp folders.
6. **Autorun Persistence (T1547 / T1053)**: Windows Run keys, startup files, new services (`7045`), and scheduled tasks (`4698`).
7. **DNS Tunneling & DGA (T1071.004)**: High-entropy subdomains and deep nesting.
8. **Honey-Token Deception Traps (T1081)**: Audits accesses and tampering against planted canary files.

---

## 🧪 Automated Testing & Verification

TRISHULA is continuously verified by an automated test suite integrated into GitHub Actions CI:

```powershell
# Run Multi-Vector & Anti-Evasion Test Suite:
python scripts/test_anti_evasion.py

# Run Flask Route & Auth Smoke Tests:
python scripts/ci_smoke_test.py
```

---

## 📜 License
This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.
