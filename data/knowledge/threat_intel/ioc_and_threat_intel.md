# Threat Intelligence & Indicator of Compromise (IOC) Fundamentals

## Overview

Threat Intelligence enrichment enhances raw security alert evidence by matching extracted Indicators of Compromise (IOCs) against reputation databases and threat feeds.

## Types of Indicators of Compromise (IOCs)

1. **IP Addresses:** External IPv4/IPv6 addresses originating inbound attacks or serving as C2 endpoints.
2. **Domain Names & URLs:** FQDNs used for phishing landing pages, payload hosting, or C2 beaconing.
3. **File Hashes:** Cryptographic hashes (MD5, SHA-1, SHA-256) uniquely identifying malicious executables, scripts, or DLLs.
4. **Registry Keys & File Paths:** Artifacts left by malware persistence mechanisms on endpoints.

## IOC Enrichment Workflow (VirusTotal Integration Concepts)

*Note: Future VirusTotal integration will automatically query extracted alert IOCs.*

### Enrichment Process
1. **Extraction:** Parse alert fields (`src_ip`, `dst_ip`, command line file hashes, domains).
2. **Reputation Lookup:** Query threat intelligence APIs (e.g. VirusTotal API v3) for vendor detections, community scores, and historical threat actor tags.
3. **Scoring & Classification:**
   - **Malicious:** Multi-vendor detection (> 5 engines), flagged as malware/C2.
   - **Suspicious:** Newly registered domain (< 14 days), low vendor detection count, self-signed SSL.
   - **Benign / Known Good:** Trusted CDN (Microsoft, Akamai, Cloudflare), known public infrastructure.

## Threat Intel Analysis Best Practices

- Do NOT classify public cloud or CDN IP addresses (e.g., GitHub, AWS S3) as inherently malicious without evaluating the specific hosted path or domain context.
- Always combine threat intelligence reputation scores with internal host execution evidence before declaring an incident critical.
