# MITRE ATT&CK — PowerShell Execution (T1059.001)

## Technique Overview

**Technique ID:** T1059.001
**Tactic:** Execution
**Sub-technique of:** T1059 — Command and Scripting Interpreter

Adversaries use PowerShell commands and scripts for execution. PowerShell is a powerful
interactive command-line interface and scripting environment included in the Windows
operating system.

## Encoded Commands

Attackers frequently use the `-EncodedCommand` (or `-enc`) parameter to pass Base64-encoded
PowerShell scripts. This technique is used to:

- Bypass command-line logging that only captures plaintext arguments
- Evade simple string-matching detection rules
- Obfuscate malicious intent from casual inspection

## Common Indicators

- `powershell.exe` launched with `-EncodedCommand`, `-enc`, or `-e` flags
- `powershell.exe` launched with `-WindowStyle Hidden` or `-W Hidden`
- `powershell.exe` spawned by unusual parent processes (e.g., `winword.exe`, `excel.exe`)
- PowerShell downloading content via `Invoke-WebRequest`, `Net.WebClient`, or `Start-BitsTransfer`
- Execution policy bypass with `-ExecutionPolicy Bypass`
- PowerShell connecting to external IP addresses or uncommon domains

## Kill Chain Mapping

- **Delivery:** Encoded command may arrive via phishing attachment or exploit
- **Exploitation:** Script execution leverages PowerShell engine
- **Execution:** The primary kill-chain stage — the encoded command runs on the host
- **Command & Control:** PowerShell may establish outbound connections to C2 servers
- **Actions on Objectives:** Data exfiltration, lateral movement, or persistence

## Risk Assessment

Encoded PowerShell execution is considered **high risk** because:

- It is one of the most common initial access and execution techniques
- Encoding hides the true payload from basic inspection
- PowerShell has deep access to Windows APIs and .NET framework
- Legitimate administrative use makes pure blocking impractical

## Investigation Recommendations

1. Decode the Base64 encoded command to inspect the actual payload
2. Check the parent process that spawned PowerShell
3. Review command-line arguments for download cradles or suspicious patterns
4. Correlate with network logs for outbound connections during execution
5. Check for persistence mechanisms created around the same timestamp
6. Review Windows Event Log IDs 4103, 4104 (script block logging) and 4688 (process creation)
