# Brute Force

**Technique ID:** T1110
**Tactic:** Credential Access

## Description
Adversaries may use brute force techniques to guess passwords to gain access to accounts. This includes Password Guessing (testing a single password against many accounts) or Password Spraying (testing a few common passwords against many accounts to avoid lockouts).

## Attacker Behavior
Attackers use automated scripts or tools like Hydra to rapidly attempt logins against exposed services such as RDP, SSH, FTP, or web portals. In a password spray, they might try `Fall2023!` against the entire Active Directory user list.

## SOC Evidence
- A high volume of Windows Security Event ID 4625 (Failed Logon) from a single source IP.
- Multiple lockouts (Event ID 4740) occurring in a short period.
- SSH logs showing continuous `Failed password for root` from an external IP.

## Detection Clues
Implement thresholds to detect bursts of authentication failures. Differentiate between vertical brute force (many passwords, one user) and horizontal password spraying (few passwords, many users).

## Related Techniques
- T1078: Valid Accounts
- T1133: External Remote Services

## Example Alert Context
A Wazuh alert triggers when 50 failed RDP login attempts (Event ID 4625) are recorded targeting the `Administrator` account from a single external IP address within a 2-minute window.

## Wazuh Relevance
Wazuh excels at brute force detection through log aggregation and correlation. It comes with built-in active response capabilities that can automatically block offending IP addresses at the firewall level upon detecting brute force patterns.

## Suricata Relevance
Suricata can detect brute force activity by identifying high rates of repetitive protocol initialization packets (e.g., SSH or RDP handshakes) or by matching specific application-layer error responses (like HTTP 401 Unauthorized) in rapid succession.

## Investigation Guidance
Determine if the brute force attempt was eventually successful by looking for a subsequent Event ID 4624 (Successful Logon) from the same source IP. If successful, investigate the actions taken by the compromised account. If unsuccessful, ensure the source IP is blocked at the perimeter.

---

# Credentials from Password Stores

**Technique ID:** T1555
**Tactic:** Credential Access

## Description
Adversaries may search for common password storage locations to obtain user credentials. Passwords can be stored in various locations on a system, such as web browsers, password managers, system credential managers, or cleartext configuration files.

## Attacker Behavior
Attackers use specialized scripts or binaries to parse web browser databases (e.g., Chrome's "Login Data" SQLite database) or extract saved Windows credentials using tools like `vaultcmd`.

## SOC Evidence
- Anomalous processes reading files within `C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\Login Data`.
- Execution of commands like `cmdkey /list` or access to `vaultcli.dll`.
- Unexpected access to password manager applications by unknown binaries.

## Detection Clues
Monitor file access to known password storage locations by processes other than the application that owns them. Look for the deployment of known credential stealing malware families (like RedLine Stealer or Raccoon).

## Related Techniques
- T1003: OS Credential Dumping
- T1081: Credentials In Files

## Example Alert Context
A Wazuh alert based on Sysmon Event ID 11 (File Create/Access) shows `powershell.exe` attempting to read `Login Data` from the Google Chrome AppData folder.

## Wazuh Relevance
Wazuh can use Sysmon file access events or File Integrity Monitoring to detect unauthorized access to sensitive credential stores.

## Suricata Relevance
Suricata cannot observe local credential theft from password stores. However, it can detect the subsequent exfiltration of these stolen credentials if they are transmitted over unencrypted HTTP or if the C2 communication matches known stealer malware signatures.

## Investigation Guidance
Identify the malicious process extracting the credentials. Assume all credentials stored in the compromised browser or password manager are now known to the attacker. Enforce MFA, reset compromised passwords, and trace the origin of the stealing process.
