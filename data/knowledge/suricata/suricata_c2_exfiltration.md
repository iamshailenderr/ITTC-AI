# Suricata Network Detection: C2 Beaconing & Data Exfiltration

## Command and Control (C2) Detection Concepts

Command and Control traffic represents communication between compromised internal endpoints and attacker-controlled external infrastructure.

### Beaconing Detection

Adversary implants periodically communicate back to C2 servers to check for new commands.
- **Regular Interval Beacons:** Connections occurring at precise periodic intervals (e.g., every 60 seconds with low jitter).
- **Jittered Beacons:** Connections with randomized sleep delays to evade fixed-interval threshold rules.
- **DNS Tunneling:** Exfiltration or C2 commands encoded within DNS queries to malicious authoritative nameservers (`TXT` or `A` record queries).

## Data Exfiltration Indicators

1. **Large Outbound Volume:** Abnormally high bytes sent (`bytes_toserver`) over standard protocols (HTTP/HTTPS, SSH, FTP).
2. **Non-Standard Ports:** Traffic using non-standard ports (e.g., HTTP over port 8080, 4444, or 8443).
3. **Staging & Cloud Exfiltration:** Outbound transfers to legitimate cloud storage services (Mega, Google Drive, Dropbox) spawned by unauthorized processes.

## Investigation Guidance

- Query DNS telemetry for high-volume unique subdomains under a single root domain (DNS tunneling).
- Compare HTTP POST request body sizes against baseline user activity.
- Verify whether the destination IP address belongs to known cloud infrastructure or malicious ISP networks.
