# Suricata Protocol Detection

## Description
Suricata is a high-performance Network IDS, IPS, and Network Security Monitoring (NSM) engine. One of its core strengths is protocol parsing and detection. It does not just look for strings in raw packets; it decodes protocols like HTTP, DNS, TLS, SMB, SSH, and RDP to analyze their specific fields.

## SOC Application
1. **HTTP:** Suricata inspects URIs, User-Agents, and payloads. It detects SQL injection, XSS, directory traversal, and malicious file downloads.
2. **DNS:** It monitors DNS requests and responses, detecting Fast Flux domains, DGA (Domain Generation Algorithm) activity, and DNS tunneling.
3. **TLS:** Suricata inspects TLS certificates, SNI (Server Name Indication), and JA3 fingerprints to identify malicious encrypted C2 channels without needing to decrypt the payload.
4. **SMB:** It parses SMB traffic to detect lateral movement tools (PsExec), named pipe anomalies, and ransomware iterating over file shares.
5. **SSH/RDP:** It detects brute-force attempts and protocol anomalies on remote access ports.

## Detection Clues
- Look for mismatched protocols on non-standard ports (e.g., HTTP traffic on port 53).
- Analyze JA3 hashes against threat intelligence feeds to identify known malware families communicating over TLS.

## Example Suricata Alert
`ET MALWARE Suspicious User-Agent (Mozilla/4.0 (compatible))` - indicates an outdated or hardcoded User-Agent string commonly used by basic malware.

## Correlation
Suricata network protocol alerts should be correlated with endpoint process network connections (Sysmon Event ID 3) to identify the specific binary initiating the anomalous traffic.
