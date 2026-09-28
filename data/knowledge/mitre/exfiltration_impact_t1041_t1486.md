# Exfiltration Over C2 Channel

**Technique ID:** T1041
**Tactic:** Exfiltration

## Description
Adversaries may steal data by exfiltrating it over an existing command and control channel. Stolen data is encoded into the normal communications channel using the same protocol as command and control communications.

## Attacker Behavior
After collecting sensitive documents, the attacker compresses and encrypts them into a single archive, then uses their established HTTPS beacon to POST the file to their C2 server.

## SOC Evidence
- Abnormally large outbound data transfers (e.g., hundreds of megabytes) over a connection that previously only exhibited small, periodic beaconing behavior.
- Long-running network connections to external IP addresses.

## Detection Clues
Monitor network flow data (NetFlow) for significant anomalies in outbound traffic volume from workstations or internal servers.

## Related Techniques
- T1567: Exfiltration Over Web Service
- T1020: Automated Exfiltration

## Example Alert Context
Suricata detects a massive outbound HTTPS flow (500MB) to an IP address previously flagged for suspicious HTTP beaconing, indicating likely data exfiltration.

## Wazuh Relevance
Wazuh may not see the network volume, but it can detect the preceding steps: the execution of archiving tools (like `rar.exe` or `7z.exe`) and the reading of sensitive files.

## Suricata Relevance
Suricata and network flow monitors are critical for detecting the volume anomaly and identifying the destination of the exfiltrated data.

## Investigation Guidance
Determine what data was accessed prior to the exfiltration event. Review file access logs and process execution history to understand the scope of the breach.

---

# Data Encrypted for Impact

**Technique ID:** T1486
**Tactic:** Impact

## Description
Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability to system and network resources. This is the core technique of ransomware operations.

## Attacker Behavior
Attackers deploy ransomware executables that iterate through local and mapped network drives, encrypting files and appending a specific extension (e.g., `.encrypted`, `.locked`). A ransom note is typically dropped in each affected directory.

## SOC Evidence
- A massive spike in file modification and rename events across the file system.
- Creation of files named `README_FOR_DECRYPT.txt` or similar.
- High CPU utilization from unknown processes.
- Execution of commands to delete Volume Shadow Copies (e.g., `vssadmin delete shadows /all /quiet`).

## Detection Clues
Implement File Integrity Monitoring (FIM) or ransomware tripwires (canary files). Alert immediately on the execution of commands that inhibit system recovery (like `vssadmin` or `bcdedit`).

## Related Techniques
- T1490: Inhibit System Recovery
- T1489: Service Stop

## Example Alert Context
Wazuh generates a critical alert after detecting the execution of `vssadmin.exe delete shadows /all /quiet`, followed by 10,000 file modification events in the `C:\Users` directory within two minutes.

## Wazuh Relevance
Wazuh is highly effective at detecting the precursor commands (inhibiting recovery) and the rapid file modification behavior via its FIM module.

## Suricata Relevance
Suricata cannot detect local file encryption. It may detect the ransomware downloading its encryption keys from a C2 server or the initial ingress of the ransomware payload.

## Investigation Guidance
Isolate the infected host immediately to prevent encryption of network shares. Do not reboot the machine, as some ransomware completes encryption upon reboot or deletes the encryption keys from memory.
