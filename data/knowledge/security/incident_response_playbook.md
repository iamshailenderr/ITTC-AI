# Defensive Incident Response & SOC Investigation Playbook

## Investigation Methodology

When analyzing security alerts, SOC analysts follow a structured triage methodology:

### 1. Alert Verification & Context Gathering
- Determine alert source (Wazuh HIDS, Suricata NIDS, Sysmon).
- Identify key attributes: Hostname, Username, Source IP, Destination IP, Rule ID, Severity.
- Verify whether the alert represents genuine malicious activity or a known administrative false positive.

### 2. Evidence Correlation & Artifact Analysis
- **Process Lineage:** Inspect Parent Process ID (PPID) and Child Process ID (PID).
- **Command Line Parsing:** Obfuscated, encoded, or long command arguments.
- **Network Telemetry:** Correlate host event timestamp with network flow logs.
- **User Activity:** Check if the user account exhibited recent anomalous logons or password resets.

### 3. Cyber Kill Chain Mapping
Map observed artifacts to the Cyber Kill Chain stage:
- *Reconnaissance / Initial Access:* Phishing, scanning, exploit attempt.
- *Execution:* PowerShell execution, script launching, binary execution.
- *Persistence:* Scheduled tasks, registry run keys, new service creation.
- *Privilege Escalation / Defense Evasion:* LSASS access, obfuscation, clearing event logs.
- *Command & Control:* Outbound beaconing, remote access trojans.
- *Actions on Objectives:* Data staging, exfiltration, ransomware encryption.

## Defensive Recommendations & Remediation

- **Host Containment:** Isolate compromised host from network if active C2 or ransomware is detected.
- **Credential Revocation:** Reset compromised account passwords and revoke active Kerberos/OAuth tokens.
- **Telemetry Enhancement:** Enable Script Block Logging (Event ID 4104) and Process Creation Auditing (Event ID 4688).
- **IOC Hunting:** Sweep enterprise endpoints for identical file hashes, registry keys, or IP connections.
