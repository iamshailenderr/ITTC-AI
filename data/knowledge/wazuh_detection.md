# Wazuh Detection — Process Creation and PowerShell Alerts

## Wazuh Alert Context

Wazuh is a host-based intrusion detection system (HIDS) that monitors endpoints via
agents. When Wazuh detects suspicious activity, it generates alerts with structured
metadata including rule IDs, severity levels, and event descriptions.

## Process Creation Monitoring

Wazuh monitors process creation events on Windows endpoints through:

- **Sysmon integration:** Captures detailed process creation (Event ID 1)
- **Windows Security Audit:** Process creation events (Event ID 4688)
- **Command-line logging:** Records full command-line arguments

## PowerShell-Related Wazuh Rules

Wazuh includes rules that detect suspicious PowerShell activity:

- Execution of encoded PowerShell commands
- PowerShell downloading files from the internet
- PowerShell executing with suspicious flags (-NoProfile, -NonInteractive, -Hidden)
- Unusual parent-child process relationships involving PowerShell

## Alert Severity Interpretation

- **Low:** Informational PowerShell activity, likely administrative
- **Medium:** Unusual PowerShell flags or execution context
- **High:** Encoded commands, download cradles, or known malicious patterns
- **Critical:** Confirmed malicious payload signatures or active exploitation

## Interpreting Wazuh Alerts in AI Analysis

When analyzing a Wazuh-sourced alert:

1. The alert represents a detection that has ALREADY occurred on the host
2. The `event` field describes what Wazuh observed
3. The `rule_id` maps to a specific Wazuh detection rule
4. The `source` field confirms this came from the Wazuh HIDS
5. Do NOT assume additional telemetry beyond what the alert provides
6. Treat the alert as the starting point for investigation, not a conclusion

## Correlation Guidance

- Cross-reference Wazuh process alerts with network-level detections (Suricata)
- Look for temporal correlation: events within a short window on the same host
- Check if the same user account triggered multiple alerts
- Verify whether the source IP is an internal or external address
