# SOC Detection Correlation

## Description
Detection correlation is the analytical process of linking disparate security events from multiple data sources (endpoints, network, identity, threat intel) to form a cohesive narrative of a cyber attack. 

## SOC Application
No single security control sees everything.
1. **Network vs. Endpoint:** Suricata sees a malicious payload traversing the wire (Network). Wazuh sees that payload being saved to disk and executed (Endpoint). Correlating these proves the attack was successful.
2. **Identity vs. Endpoint:** Azure AD flags a login from an impossible travel location (Identity). Wazuh sees that same user executing `procdump` on a Domain Controller (Endpoint).
3. **Threat Intel Integration:** A generic Wazuh alert for a network connection becomes a critical incident when Threat Intel identifies the destination IP as a Cobalt Strike Team Server.

## Detection Clues
- Look for temporal proximity: Did a Suricata exploit alert happen within seconds of a Wazuh anomalous process creation alert on the same host?
- Track the entity: Follow the specific User Account or the specific Host IP across all available telemetry sources.

## Example Correlation Scenario
1. **Suricata:** Detects inbound HTTP request containing an SQL Injection payload (T1190).
2. **Wazuh:** Detects the `w3wp.exe` process spawning `cmd.exe` (T1059.003).
3. **Threat Intel:** The source IP of the SQLi is a known malicious TOR exit node.
4. **Wazuh:** Detects a PowerShell command downloading a secondary payload (T1105).
5. **AI Conclusion:** High-confidence true positive. The web server has been compromised via SQLi, resulting in Remote Code Execution and subsequent tool ingress. Immediate containment required.
