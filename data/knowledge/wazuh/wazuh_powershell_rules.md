# Wazuh Detection: PowerShell & Process Execution Rules

## Overview

Wazuh is an open-source Host-based Intrusion Detection System (HIDS) that processes security events from agents installed on endpoints.

## PowerShell Detection Rules

Wazuh uses specific rule IDs to detect suspicious PowerShell execution:

### Rule 92250: Suspicious PowerShell Execution
- **Rule ID:** 92250
- **Severity Level:** 10 (High)
- **Group:** windows, sysmon, process_creation
- **Description:** Detects PowerShell process execution with suspicious arguments such as `-EncodedCommand`, `-enc`, `-w hidden`, or `-executionpolicy bypass`.
- **Alert Interpretation:** Indicates potential malicious script execution or download cradle. Immediate inspection of the decoded Base64 command is required.

### Rule 92251: PowerShell Download Cradle Detected
- **Rule ID:** 92251
- **Severity Level:** 12 (High)
- **Description:** Triggers when PowerShell command lines contain `Invoke-WebRequest`, `DownloadString`, `Net.WebClient`, or `Start-BitsTransfer`.
- **Alert Interpretation:** Indicates an active payload download attempt from remote external infrastructure.

### Rule 60106: Sysmon Event ID 1 — Process Creation
- **Rule ID:** 60106
- **Severity Level:** 3 (Low/Informational)
- **Description:** Captures standard Windows process creation event with full parent-child process tree and command-line parameters.

## Field Structure in Wazuh Alerts

Wazuh alerts contain normalized fields:
- `win.eventdata.image`: Path to executable (e.g. `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`)
- `win.eventdata.commandLine`: Raw command line executed
- `win.eventdata.parentImage`: Parent executable path
- `win.eventdata.user`: User account under which execution occurred
- `rule.id`: Rule identifier
- `rule.level`: Numerical severity score (0 to 15)

## Response & Investigation Actions

1. Check rule severity and rule ID to categorize the threat.
2. Isolate the target host if rule level >= 12 or confirmed malicious payload execution.
3. Review related Sysmon network logs (Event ID 3) for outbound connections around the alert timestamp.
