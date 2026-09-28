# Suricata Network Detection — Network Indicators

## Suricata Overview

Suricata is a network-based intrusion detection and prevention system (NIDS/NIPS)
that inspects network traffic in real time. It complements host-based detections
(like Wazuh) by providing visibility into network-layer activity.

## Network Indicators Relevant to PowerShell Attacks

When PowerShell-based attacks communicate with external infrastructure, Suricata may detect:

- **Outbound HTTP/HTTPS to suspicious IPs:** Connections to known C2 infrastructure
- **DNS queries to suspicious domains:** Domain generation algorithm (DGA) patterns
- **Unusual TLS certificates:** Self-signed or recently registered certificates
- **Large outbound data transfers:** Potential data exfiltration
- **Beaconing patterns:** Regular interval connections to the same destination

## Correlating Host and Network Evidence

For comprehensive analysis:

1. Match the `dst_ip` from a host alert with Suricata network flow records
2. Check if the destination IP appears in threat intelligence feeds
3. Look for DNS resolution events preceding the connection
4. Identify the volume and direction of data transfer
5. Determine if the connection uses standard or non-standard ports

## External IP Analysis

When an alert includes an external destination IP:

- **Private ranges (10.x, 172.16-31.x, 192.168.x):** Internal lateral movement
- **Public IPs:** Potential C2, data exfiltration, or legitimate external service
- **Known hosting providers:** May indicate cloud-hosted C2 infrastructure
- GitHub/CDN IPs (e.g., 185.199.108.x): Could be legitimate OR used for payload hosting

## Risk Indicators from Network Context

- Connection to external IP shortly after process execution: **High risk**
- Connection on non-standard ports: **Medium-High risk**
- Encrypted traffic to unknown destinations: **Medium risk**
- Connection to well-known services with expected traffic: **Low risk**

## Investigation Steps

1. Resolve the destination IP to identify the hosting provider or organization
2. Check if the IP is listed in threat intelligence databases
3. Review full network session data if available from Suricata
4. Correlate timing between host-level process execution and network connection
5. Assess whether the traffic volume is consistent with expected behavior
