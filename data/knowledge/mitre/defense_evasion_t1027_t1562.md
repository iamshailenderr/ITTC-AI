# Obfuscated/Compressed Files and Information

**Technique ID:** T1027
**Tactic:** Defense Evasion

## Description
Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents on the system or in transit. This is common behavior for evading signature-based antivirus and heuristic detection.

## Attacker Behavior
Attackers use software packers (like UPX), base64 encoding, XOR encryption, or script obfuscators (like Invoke-Obfuscation) to hide strings, URLs, and malicious logic from security controls. 

## SOC Evidence
- Command line arguments containing heavily randomized characters, long base64 strings, or repeated use of string manipulation functions (e.g., `.Replace()`, `[char]`).
- Antivirus alerts indicating a "packed" or "obfuscated" file.
- Execution of known packing tools or utilities like `certutil.exe -decode`.

## Detection Clues
Look for excessively long command lines or PowerShell scripts bypassing execution policies while utilizing Base64 (`-enc`). Monitor for the decoding of files via native binaries (LOLBins) like `certutil`.

## Related Techniques
- T1140: Deobfuscate/Decode Files or Information
- T1059: Command and Scripting Interpreter

## Example Alert Context
A Wazuh alert triggers on a Sysmon Event ID 1 for `powershell.exe` with a 4,000-character command line consisting entirely of Base64 encoded text starting with `JAB` (often decoding to `$`).

## Wazuh Relevance
Wazuh relies on Sysmon or Windows Event logs to capture the command line parameters. Rules can be configured to alert on extremely long command lines or the presence of common obfuscation patterns (`-EncodedCommand`).

## Suricata Relevance
Suricata can detect obfuscated or compressed payloads transmitted over the network by inspecting file signatures in HTTP/SMB streams or identifying known XOR/Base64 patterns in C2 traffic.

## Investigation Guidance
Extract the obfuscated string or packed binary. Use tools like CyberChef to decode Base64/XOR payloads or unpack binaries in a sandbox environment to reveal the true intent, indicators of compromise (IOCs), and C2 addresses.

---

# Impair Defenses

**Technique ID:** T1562
**Tactic:** Defense Evasion

## Description
Adversaries may maliciously modify components of a victim environment to hinder or disable defensive mechanisms. This includes disabling antivirus, terminating security software processes, altering firewall rules, or modifying logging configurations.

## Attacker Behavior
Attackers often use built-in administrative tools like `netsh` to disable the Windows Firewall, `Set-MpPreference` to disable Windows Defender, or `taskkill` to forcefully stop Endpoint Detection and Response (EDR) agents before dropping their primary payload.

## SOC Evidence
- Execution of commands like `netsh advfirewall set allprofiles state off`.
- PowerShell cmdlets such as `Set-MpPreference -DisableRealtimeMonitoring $true`.
- Windows Security Event ID 1102 (The audit log was cleared).
- Services related to security agents suddenly stopping or entering a failed state.

## Detection Clues
Monitor for any command line execution attempting to interact with security software processes or firewall configurations. Alert on the clearance of Windows Event Logs, as this is almost exclusively a malicious or deeply suspicious administrative action.

## Related Techniques
- T1489: Service Stop
- T1070: Indicator Removal

## Example Alert Context
An alert is generated when an administrator account executes `taskkill /f /im sense.exe` to attempt to terminate Microsoft Defender for Endpoint, followed shortly by `wevtutil.exe cl System`.

## Wazuh Relevance
Wazuh has out-of-the-box rules to detect the clearing of event logs (Event ID 1102, 104) and can easily flag command lines that disable Windows Defender or firewall profiles. It can also alert if a monitored security service unexpectedly stops.

## Suricata Relevance
Suricata cannot detect endpoint defense impairment directly. It relies on the endpoint agent (Wazuh) to report these localized administrative actions.

## Investigation Guidance
If defenses are impaired, assume the endpoint is fully compromised. Immediately isolate the machine from the network. Investigate the time immediately preceding the impairment to identify the delivery mechanism or lateral movement technique used to gain the necessary privileges.
