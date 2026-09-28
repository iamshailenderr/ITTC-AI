# Suricata Network Signatures & Rule Documentation

## Overview

Suricata is a high-performance Network Intrusion Detection System (NIDS), Intrusion Prevention System (NIPS), and Network Security Monitoring (NSM) engine. Suricata inspects packet payloads, HTTP headers, TLS handshakes, and DNS requests in real time.

## Suricata Signature Structure

A standard Suricata rule follows this syntax:
`action header (options;)`

Example:
`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN Suspicious PowerShell User-Agent"; flow:established,to_server; content:"PowerShell"; http_user_agent; sid:2014781; rev:3;)`

### Key Rule Fields

- **SID (Signature ID):** Unique numerical identifier for the detection rule.
- **Protocol:** `http`, `tls`, `dns`, `tcp`, `udp`, `icmp`.
- **Severity Classification:** `1` (High - Trojan/Exploit), `2` (Medium - Suspicious User-Agent/Traffic), `3` (Low - Informational).
- **Flow Direction:** `$HOME_NET -> $EXTERNAL_NET` (outbound traffic) or `$EXTERNAL_NET -> $HOME_NET` (inbound attack).

## Common Network Detections

### SID 2014781: Suspicious PowerShell User-Agent
- **Description:** Outbound HTTP request containing `PowerShell` in the User-Agent header string.
- **Context:** PowerShell download cradles (`Invoke-WebRequest`) often use default User-Agent strings.

### SID 2024311: TLS Connection to Suspicious Self-Signed Certificate
- **Description:** Encrypted TLS session established with a destination IP using a self-signed or anomalous SSL/TLS certificate.
- **Context:** Frequently indicates Command & Control (C2) beaconing (Meterpreter, Cobalt Strike).

## Host-to-Network Correlation

When analyzing a Suricata network alert:
1. Extract `src_ip` (internal host) and `dst_ip` (external target / C2).
2. Match `dst_ip` with recent host process logs (Sysmon Event ID 3 or Wazuh network alerts).
3. Identify if the destination IP is hosting malicious payloads or C2 infrastructure.
