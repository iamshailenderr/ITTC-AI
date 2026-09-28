# OS Credential Dumping

**Technique ID:** T1003  
**Sub-techniques:** T1003.001 (LSASS Memory), T1003.002 (Security Account Manager)  
**Tactic:** Credential Access  

## Overview

Adversaries attempt to extract credentials (plaintext passwords, NTLM hashes, Kerberos tickets) from operating system memory or security databases. Access to credentials allows lateral movement across the domain.

## Common Techniques & Tools

- **LSASS Dumping (T1003.001):** Memory dumping of `lsass.exe` using Mimikatz, `procdump.exe`, or Comsvcs.dll via `rundll32.exe`.
- **SAM Registry Hive Copying (T1003.002):** Extracting SAM, SYSTEM, and SECURITY registry hives using `reg.exe save hklm\sam sam.hiv`.

## Detection & Indicators

1. Process access to `lsass.exe` with `PROCESS_VM_READ` or `PROCESS_ALL_ACCESS` rights (captured in Sysmon Event ID 10).
2. Command lines referencing `comsvcs.dll, MiniDump` or `procdump.exe -ma lsass.exe`.
3. Commands saving registry hives (`reg save`).
