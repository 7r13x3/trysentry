"""
TrySentry — MITRE ATT&CK mapping
Maps technique IDs to descriptions and tactics.
"""

TECHNIQUES = {
    "T1059.001": ("Command and Scripting Interpreter: PowerShell",
                  "execution"),
    "T1059.003": ("Command and Scripting Interpreter: Windows Command Shell",
                  "execution"),
    "T1059.005": ("Command and Scripting Interpreter: Visual Basic",
                  "execution"),
    "T1055":     ("Process Injection", "defense_evasion"),
    "T1055.012": ("Process Injection: Process Hollowing", "defense_evasion"),
    "T1547.001": ("Registry Run Keys / Startup Folder", "persistence"),
    "T1547.004": ("Winlogon Helper DLL", "persistence"),
    "T1543.003": ("Create or Modify System Process: Windows Service",
                  "persistence"),
    "T1053.005": ("Scheduled Task/Job: Scheduled Task", "persistence"),
    "T1003.001": ("OS Credential Dumping: LSASS Memory", "credential_access"),
    "T1003.002": ("OS Credential Dumping: Security Account Manager",
                  "credential_access"),
    "T1555.003": ("Credentials from Password Stores: Web Browsers",
                  "credential_access"),
    "T1071.001": ("Application Layer Protocol: Web Protocols",
                  "command_and_control"),
    "T1071.004": ("Application Layer Protocol: DNS",
                  "command_and_control"),
    "T1571":     ("Non-Standard Port", "command_and_control"),
    "T1021.001": ("Remote Services: RDP", "lateral_movement"),
    "T1021.002": ("Remote Services: SMB/Windows Admin Shares",
                  "lateral_movement"),
    "T1566.001": ("Phishing: Spearphishing Attachment", "initial_access"),
    "T1566.002": ("Phishing: Spearphishing Link", "initial_access"),
    "T1204.002": ("User Execution: Malicious File", "execution"),
    "T1105":     ("Ingress Tool Transfer", "command_and_control"),
    "T1218":     ("System Binary Proxy Execution", "defense_evasion"),
    "T1218.011": ("System Binary Proxy Execution: Rundll32",
                  "defense_evasion"),
    "T1197":     ("BITS Jobs", "defense_evasion"),
    "T1140":     ("Deobfuscate/Decode Files or Information",
                  "defense_evasion"),
    "T1027":     ("Obfuscated Files or Information", "defense_evasion"),
    "T1486":     ("Data Encrypted for Impact", "impact"),
    "T1490":     ("Inhibit System Recovery", "impact"),
    "T1041":     ("Exfiltration Over C2 Channel", "exfiltration"),
    "T1567":     ("Exfiltration Over Web Service", "exfiltration"),
}


def lookup(technique_id: str) -> dict:
    """Return {id, name, tactic} for a technique ID."""
    if not technique_id:
        return {"id": "", "name": "Unknown", "tactic": "unknown"}
    info = TECHNIQUES.get(technique_id)
    if not info:
        return {"id": technique_id, "name": "Unknown", "tactic": "unknown"}
    return {"id": technique_id, "name": info[0], "tactic": info[1]}
