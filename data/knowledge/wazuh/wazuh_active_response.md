# Wazuh Active Response

## Description
Active Response is a feature in Wazuh that allows the system to execute scripts or commands on an agent (or the manager) automatically in response to specific alerts or alert severity levels. This enables automated containment and remediation actions.

## SOC Application
Active Response is used to reduce the Mean Time To Respond (MTTR) by taking immediate action without analyst intervention. Common use cases include:
1. **Firewall Blocking:** Automatically adding a malicious source IP to a local firewall blocklist (Windows Firewall, iptables, pfSense) after a brute-force attack or exploit attempt is detected.
2. **Process Termination:** Killing a specific malicious process (e.g., `cmd.exe` spawned by a web server) if a high-severity alert fires.
3. **Account Disable:** Disabling a compromised Active Directory account if Pass-the-Hash or impossible travel is detected.

## Detection Clues
Active Response itself is not a detection mechanism, but its logs indicate that automated containment was applied. Analysts should look for logs indicating `active-response` was triggered to understand the current state of the endpoint.

## Example Wazuh Alert
Wazuh detects a brute force attack (Rule 5712) and automatically triggers the `firewall-drop` active response script to block the source IP for 600 seconds.

## Investigation Guidance
When investigating an alert where Active Response fired, verify if the response was successful. Check if the block broke legitimate functionality (false positive). Do not rely entirely on the automated response; investigate the root cause of the initial alert.
