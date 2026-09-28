# Wazuh File Integrity Monitoring (FIM)

## Description
File Integrity Monitoring (FIM), provided by the Wazuh Syscheck module, watches designated files and directories for changes. It detects creation, modification, and deletion of files, as well as changes to permissions, ownership, and attributes.

## SOC Application
FIM is crucial for detecting:
1. **Malware Droppers:** Identifying when new executables are placed in `C:\Windows\Temp` or user `Downloads` folders.
2. **Persistence Mechanisms:** Detecting modifications to `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp` or `/etc/rc.local`.
3. **Configuration Tampering:** Identifying unauthorized changes to `/etc/shadow`, `sshd_config`, or Windows registry keys.
4. **Ransomware:** Detecting mass file encryption events (rapid file rename and modification).

## Detection Clues
- A sudden spike in FIM alerts indicates a major system change, potentially ransomware or a malicious script rapidly altering configurations.
- Alerts for files changing in web server root directories (e.g., `/var/www/html`) may indicate web shell installation.

## Example Wazuh Alert
`Rule: 550 - Integrity checksum changed.`
`File: /etc/passwd`
`Action: modified`

## Correlation
FIM alerts should be correlated with Process Creation events (Sysmon Event ID 1) to determine *which process* caused the file modification.
