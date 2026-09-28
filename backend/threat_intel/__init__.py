"""
Threat Intelligence enrichment layer for ITTC-AI.

Distinct from RAG: RAG provides static cybersecurity knowledge (MITRE, Wazuh, Suricata).
This layer provides IOC-specific enrichment: IP/domain/hash reputation.

Usage:
    from backend.threat_intel import extract_iocs, enrich_iocs, get_provider
"""

from backend.threat_intel.extractor import extract_iocs
from backend.threat_intel.enricher import enrich_iocs, get_provider

__all__ = ["extract_iocs", "enrich_iocs", "get_provider"]
