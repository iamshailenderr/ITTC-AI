# Remote Services

**Technique ID:** T1021
**Tactic:** Lateral Movement

## Description
Adversaries may use Valid Accounts to log into a service specifically designed to accept remote connections, such as SMB, RDP, SSH, or WinRM. This allows them to move laterally across the network and execute commands on remote systems.

## Attacker Behavior
After compromising credentials on one host, attackers use tools like PsExec over SMB (TCP 445), native RDP (TCP 3389), or SSH (TCP 22) to access other internal servers and workstations, spreading their footprint.

## SOC Evidence
- Windows Event ID 4624 (Logon Type 3 for Network/SMB or Logon Type 10 for RDP).
- Execution of `psexec.exe` or creation of the `PSEXESVC` service on a remote host.
- Network traffic flows indicating RDP or SSH connections between internal workstation subnets (which is often anomalous).

## Detection Clues
Look for administrative logins (Logon Type 3) originating from non-administrative jump boxes. Monitor for the creation of known lateral movement services like `PSEXESVC`. Baseline normal internal remote access patterns to spot deviations.

## Related Techniques
- T1078: Valid Accounts
- T1563: Remote Service Session Hijacking

## Example Alert Context
An alert fires when Suricata detects SMB traffic containing the signature for PsExec, and Wazuh simultaneously logs a Logon Type 3 event on a Domain Controller followed by the installation of the `PSEXESVC` service.

## Wazuh Relevance
Wazuh monitors authentication logs for anomalous lateral movement patterns (e.g., unexpected Logon Type 3 or 10 events) and monitors the system for the creation of temporary services often associated with remote execution tools.

## Suricata Relevance
Suricata is highly relevant here. It can detect protocol anomalies, identify specific lateral movement tools crossing the wire (like PsExec SMB signatures), and monitor for internal port scanning preceding the remote connection.

## Investigation Guidance
Identify the source host initiating the remote service connection; this host is likely already compromised. Determine what commands or payloads were executed on the destination host after the remote session was established.

---

# Remote Service Session Hijacking

**Technique ID:** T1563
**Tactic:** Lateral Movement

## Description
Adversaries may hijack a legitimate user's remote session (e.g., RDP or SSH) to move laterally within an environment. This allows the attacker to assume the identity and privileges of the logged-in user without needing to know their password.

## Attacker Behavior
An attacker with SYSTEM privileges uses tools like `tscon.exe` on Windows to forcefully connect to another user's disconnected or active RDP session.

## SOC Evidence
- Windows Event ID 4778 (A session was reconnected to a Window Station).
- Execution of `tscon.exe` with a destination session ID.
- Processes spawning within an RDP session that was inactive for hours.

## Detection Clues
Monitor for the execution of `tscon.exe` from a command prompt running as SYSTEM. Look for session reconnect events that occur immediately after a privilege escalation event.

## Related Techniques
- T1021: Remote Services
- T1078: Valid Accounts

## Example Alert Context
Wazuh alerts on a Sysmon Event ID 1 showing `tscon.exe 2 /dest:console` executed by the `NT AUTHORITY\SYSTEM` account, indicating an RDP hijacking attempt.

## Wazuh Relevance
Wazuh captures process creation logs and can specifically alert on `tscon.exe` abuse. It also monitors authentication events like session reconnections (Event 4778).

## Suricata Relevance
Suricata cannot detect session hijacking directly, as it occurs internally on the host operating system without generating distinct network signatures beyond normal RDP traffic.

## Investigation Guidance
Identify which user session was hijacked and trace their subsequent actions. The attacker gains the privileges of the hijacked user, so look for access to sensitive files or further lateral movement from that user's context.
