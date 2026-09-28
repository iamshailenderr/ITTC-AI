# Phishing: Spearphishing Attachment & Link

**Technique ID:** T1566  
**Sub-techniques:** T1566.001 (Spearphishing Attachment), T1566.002 (Spearphishing Link)  
**Tactic:** Initial Access  

## Overview

Adversaries use spearphishing emails with malicious attachments (e.g. ISO, ZIP, Office documents with macros, PDF) or weaponized links to gain initial access to target endpoints.

## Execution Mechanics

1. **Malicious Attachments:** An victim opens an attachment containing VBA macros, executable payloads inside ZIP/RAR archives, or LNK shortcut files.
2. **Child Process Spawning:** Opening the document causes `winword.exe` or `excel.exe` to spawn `powershell.exe`, `cmd.exe`, or `wscript.exe`.
3. **Payload Downloading:** Initial loader script retrieves secondary stage payloads from external C2 domains or compromised cloud services.

## Key Indicators

- Word or Excel spawning command interpreters (`powershell.exe`, `cmd.exe`, `mshta.exe`).
- Email attachments with double extensions (e.g., `invoice.pdf.exe`).
- Rapid network connections to recently registered external IP addresses following email delivery.
