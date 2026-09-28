# Wazuh Authentication Monitoring

## Description
Wazuh monitors authentication logs across various operating systems, including Windows Security Event Logs (Event IDs 4624, 4625), Linux auth.log, and macOS OpenDirectory. It normalizes these logs into a standard format for rule evaluation.

## SOC Application
Authentication monitoring is vital for detecting Credential Access and Lateral Movement techniques:
1. **Brute Force:** Wazuh tracks failed login attempts and triggers alerts when a threshold is reached from a single IP or against a single user.
2. **Anomalous Logins:** Detecting logins at unusual times or from unexpected geographic locations (impossible travel).
3. **Lateral Movement:** Monitoring Windows Logon Types. For example, a Logon Type 3 (Network) or Logon Type 10 (RemoteInteractive) using an Administrator account from a non-IT workstation is highly suspicious.
4. **Privilege Escalation:** Detecting successful logins using the `root` or `Administrator` accounts.

## Detection Clues
- Look for Event ID 4625 (Failed Logon) followed immediately by Event ID 4624 (Successful Logon) from the same source IP, indicating a successful brute force attack.
- Monitor for Logon Type 9 (NewCredentials), often associated with Pass-the-Hash attacks or `runas /netonly`.

## Example Wazuh Alert
`Rule: 5712 - SSHD brute force trying to get access to the system.`
`Src IP: 192.168.1.100`
`User: root`

## Correlation
Correlate authentication failures with Suricata alerts for network scanning or exploit attempts originating from the same source IP.
