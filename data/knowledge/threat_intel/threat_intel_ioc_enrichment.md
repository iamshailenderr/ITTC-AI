# Threat Intelligence & IOC Enrichment

## Description
Threat Intelligence involves gathering information about threat actors, their tactics, techniques, and procedures (TTPs), and the specific Indicators of Compromise (IOCs) they use. Enrichment is the process of adding this context to raw SOC alerts.

## SOC Application
1. **IP/Domain Reputation:** Checking external IPs against databases (like VirusTotal, AbuseIPDB, or AlienVault OTX) to see if they are known C2 servers, Tor exit nodes, or malicious scanners.
2. **File Hashes:** Comparing SHA256 hashes of downloaded files or executed processes against malware databases.
3. **Contextualizing Alerts:** Transforming a generic "Suspicious Connection" alert into "Connection to known Trickbot C2 server."

## Detection Clues
- An alert is significantly more severe if the destination IP is present on a known APT threat feed.
- Newly registered domains (NRDs) or domains with poor reputation scores should be treated with high suspicion.

## Investigation Guidance
When an alert triggers, extract the observable (IP, Hash, Domain). Query threat intel platforms to determine its reputation. If malicious, use the intel to understand the malware family's typical behavior (e.g., "This malware usually drops ransomware next").

## Correlation
Enrich both Suricata network flows (IPs/Domains) and Wazuh endpoint events (File Hashes) with threat intelligence to provide a unified risk score for the incident.
