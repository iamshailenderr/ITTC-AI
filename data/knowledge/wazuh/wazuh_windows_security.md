# Wazuh Detection: Windows Authentication & Security Events

## Authentication Event Rules

Wazuh processes Windows Event Log security audits to track user access, logon failures, and privilege escalations.

### Rule 60109: Windows Logon Failure (Event ID 4625)
- **Rule ID:** 60109
- **Severity Level:** 5 (Medium)
- **Description:** Detects failed user authentication attempt.
- **Logon Types:**
  - `Logon Type 2`: Interactive logon (keyboard at host).
  - `Logon Type 3`: Network logon (SMB, RDP, shared folders).
  - `Logon Type 10`: Remote Desktop Protocol (RDP).

### Rule 60115: Multiple Failed Logons (Brute Force Detection)
- **Rule ID:** 60115
- **Severity Level:** 10 (High)
- **Description:** Triggers when a threshold of failed logon attempts (Rule 60109) occurs within a short window from the same source IP or user account.

### Rule 60122: User Account Privilege Escalation (Event ID 4728 / 4732)
- **Rule ID:** 60122
- **Severity Level:** 8 (Medium-High)
- **Description:** Detects addition of a user to a sensitive security group (e.g. Administrators, Domain Admins).

## Endpoint Monitoring Best Practices

- Correlate failed logon spikes with subsequent successful interactive logons to detect credential stuffing or brute force success.
- Check source IP addresses against internal subnet maps to distinguish between lateral movement and external attacks.
