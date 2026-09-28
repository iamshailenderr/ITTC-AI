# System Information Discovery

**Technique ID:** T1082
**Tactic:** Discovery

## Description
Adversaries may attempt to get detailed information about the operating system and hardware, including version, patches, architecture, and network configuration. This helps them tailor their payloads and choose appropriate exploits.

## Attacker Behavior
Attackers execute native commands like `systeminfo`, `wmic os get`, or `uname -a` immediately after gaining initial access to profile the host.

## SOC Evidence
- Process creation events for `systeminfo.exe`, `hostname.exe`, `wmic.exe`.
- Linux command execution for `uname`, `cat /etc/os-release`.
- Scripts querying WMI classes like `Win32_OperatingSystem`.

## Detection Clues
Look for a rapid sequence of discovery commands executed in a short timeframe, often referred to as "situational awareness" commands. It's highly suspicious when these originate from a web server process or an Office application.

## Related Techniques
- T1083: File and Directory Discovery
- T1016: System Network Configuration Discovery

## Example Alert Context
Wazuh detects a sequence of commands executed within 5 seconds: `whoami`, `systeminfo`, `ipconfig /all`, and `netstat -ano`.

## Wazuh Relevance
Wazuh natively captures process creation events (Event ID 4688 or Sysmon 1) and can correlate multiple discovery commands executed within a short time window.

## Suricata Relevance
Suricata may not see this locally executed discovery, but if the attacker uses an interactive C2 framework, the commands and their outputs might be transmitted across the network. If the channel is unencrypted, Suricata can inspect it.

## Investigation Guidance
Analyze the parent process initiating the discovery commands. Determine how the attacker gained code execution on the host. Look for subsequent actions like lateral movement or payload downloads tailored to the discovered OS version.

---

# Account Discovery

**Technique ID:** T1087
**Tactic:** Discovery

## Description
Adversaries may attempt to get a listing of local system or domain accounts. This information helps them identify potential targets for credential dumping, brute-forcing, or lateral movement.

## Attacker Behavior
Attackers use commands like `net user`, `net localgroup administrators`, or PowerShell cmdlets like `Get-LocalUser` and `Get-ADUser` to enumerate accounts.

## SOC Evidence
- Execution of `net.exe` with `user` or `group` parameters.
- LDAP queries originating from non-standard applications.
- Use of BloodHound/SharpHound for aggressive Active Directory enumeration.

## Detection Clues
Monitor for repeated or broad LDAP queries against Domain Controllers. Alert on the execution of local account enumeration commands by non-administrative users.

## Related Techniques
- T1069: Permission Groups Discovery
- T1482: Domain Trust Discovery

## Example Alert Context
A Wazuh alert triggers on the execution of `net group "Domain Admins" /domain`, a common command used by attackers to identify high-value targets.

## Wazuh Relevance
Wazuh captures the execution of enumeration binaries. Rules are explicitly built to detect `net.exe` usage querying sensitive groups or domain accounts.

## Suricata Relevance
Suricata can detect anomalous LDAP traffic volumes associated with Active Directory enumeration tools like SharpHound.

## Investigation Guidance
Determine which account executed the discovery commands. If it's a compromised standard user, investigate if the attacker attempted to pivot or dump credentials for the discovered administrative accounts.
