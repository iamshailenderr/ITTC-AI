# SOC Alert Triage and Incident Response

## Description
Alert triage is the process of reviewing incoming security alerts, determining their validity (true positive vs. false positive), assessing their severity, and deciding on the appropriate incident response workflow.

## SOC Application
1. **Triage:** Analysts review the alert context (Source IP, User, Process, Command Line). They look for historical context and known benign administrative behaviors.
2. **Containment:** If an alert is a true positive (e.g., confirmed ransomware or active C2), the host is immediately isolated from the network to prevent lateral movement.
3. **Eradication:** Removing the malicious artifacts (malware, persistence mechanisms, compromised accounts).
4. **Recovery:** Restoring systems from backups, patching vulnerabilities, and returning the host to production.

## Detection Clues
- High severity alerts (e.g., Wazuh Level 12+) should be triaged immediately.
- Multiple alerts firing for the same host across different tactics (e.g., Initial Access followed by Discovery) increase the confidence of a true positive compromise.

## Investigation Guidance
Always verify the scope of the incident. If one host is compromised, look for lateral movement to other hosts. Document all findings and map them to the MITRE ATT&CK framework to ensure all stages of the attack lifecycle have been identified and remediated.
