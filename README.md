# TrySentry

> Real EDR for Windows. Kernel-level telemetry, Sigma rules, YARA scanning, auto-response.

TrySentry watches your Windows machine in real time — processes, files, registry, network — detects threats using Sigma-style rules, and responds automatically.

---

## What It Does

| Layer | Capability |
|---|---|
| **Telemetry** | Sysmon events, Windows Event Log, processes, network, registry |
| **Detection** | Sigma rules, YARA memory scan, behavioral chains, MITRE ATT&CK |
| **Response** | Kill tree, quarantine file, firewall block, forensic snapshot |
| **Dashboard** | FastAPI + WebSocket live feed |
| **Report** | Self-contained HTML incident report |

---

## Requirements

- Windows 10 / 11
- Python 3.10+
- Administrator privileges
- **Sysmon** (free, from Microsoft) — for kernel-level telemetry

---

## Install

```bash
git clone https://github.com/7r13x3/trysentry.git
cd trysentry
pip install -r requirements.txt
Install Sysmon (recommended)
Run as Administrator:
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "Sysmon.zip"
Expand-Archive Sysmon.zip -DestinationPath Sysmon
cd Sysmon
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "sysmonconfig.xml"
.\sysmon64.exe -accepteula -i sysmonconfig.xml
Without Sysmon, TrySentry falls back to user-mode telemetry only.
Usage
Interactive Menu
python -m trysentry
  [ 1 ]   Start Monitoring
  [ 2 ]   Stop Monitoring
  [ 3 ]   View Alerts
  [ 4 ]   View Timeline
  [ 5 ]   Forensics Snapshot
  [ 6 ]   Load Rules
  [ 7 ]   Scan Memory (YARA)
  [ 8 ]   Launch Dashboard
  [ 9 ]   Generate Report
  [ 10 ]  Settings
  [ 0 ]   Exit
CLI
python -m trysentry.cli start
python -m trysentry.cli scan-memory --pid 1234
python -m trysentry.cli report --output incident.html
Sample Alert
[ALERT]  CRITICAL                       2026-09-22 14:32:11
  Rule:      Office spawning PowerShell
  MITRE:     T1566.001 — Spearphishing Attachment
  Process:   powershell.exe  (PID 8234)
  Parent:    WINWORD.EXE     (PID 5120)
  Command:   powershell -enc SQBFAFgAKA...
  
  Actions:
    ✓ Killed process tree
    ✓ Quarantined invoice.docm
    ✓ Blocked remote IP
    ✓ Captured forensic snapshot
Legal
Defensive security tool. Reads local telemetry only. Run on systems you own or are authorized to monitor.
