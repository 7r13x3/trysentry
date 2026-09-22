# TrySentry 🔵

> Always watching. Always hunting.
## ⚠️ Legal Disclaimer

TrySentry is a **defensive security tool**. It only reads system telemetry and applies automated response to detected threats on the local machine. It does not attack anything, exfiltrate data, or modify other systems. Run it only on machines you own or are authorized to monitor.

---

## Prerequisites

- **Windows 10 / 11**
- **Python 3.10+**
- **Administrator privileges** (required for full telemetry and response)
- **Sysmon** (free, from Microsoft Sysinternals) — provides kernel-level telemetry

### Install Sysmon (required for full features)

```powershell
# Download
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "Sysmon.zip"
Expand-Archive Sysmon.zip -DestinationPath Sysmon

# Install with SwiftOnSecurity config (the industry-standard config)
cd Sysmon
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "sysmonconfig.xml"
.\sysmon64.exe -accepteula -i sysmonconfig.xml
Features
Layer	Feature
Telemetry	Sysmon, Windows Event Log, ETW, WMI, processes, network, registry
Detection	Sigma rules, YARA scanning, behavioral chains, IOC matching, risk scoring
Response	Kill tree, quarantine, firewall block, network isolation, forensic snapshot
Forensics	Memory dump, handle enumeration, module list, attack timeline
Dashboard	FastAPI + WebSocket + live map + timeline
Report	Self-contained HTML incident report
Installation
git clone https://github.com/7r13x3/trysentry.git
cd trysentry
pip install -r requirements.txt
Usage
python -m trysentry
CLI Commands
License
MIT

**Commit changes.**

---

## 📝 File 3: `LICENSE`

**Add file → Create new file** → name: `LICENSE`

```text
MIT License

Copyright (c) 2026 7r13x3

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
