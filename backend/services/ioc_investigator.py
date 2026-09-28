"""
IOC Investigation Service — provides structured IOC lookups.

For a given IOC (IP/domain/URL/hash), returns:
  - IOC type and value
  - TI reputation and confidence
  - Category and detections
  - Related alerts and incidents

Uses the existing mock TI provider.
Does NOT claim to be live threat intelligence.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel

from backend.models.alert import SecurityAlert
from backend.threat_intel.enricher import get_provider
from backend.threat_intel.extractor import extract_iocs
from backend.services.alerts import get_alerts


class IOCInvestigation(BaseModel):
    """Structured IOC investigation result."""
    ioc_type: str
    value: str
    reputation: str = "unknown"
    confidence: float = 0.0
    malicious: bool = False
    category: List[str] = []
    detections: Optional[int] = None
    malware_families: List[str] = []
    last_seen: Optional[str] = None
    source: str = ""
    related_alert_ids: List[str] = []
    related_incident_ids: List[str] = []


def investigate_ioc(ioc_type: str, ioc_value: str) -> IOCInvestigation:
    """
    Investigate a single IOC and return structured results.

    Args:
        ioc_type: Type of IOC (ip, domain, url, md5, sha1, sha256)
        ioc_value: The IOC value to investigate

    Returns:
        IOCInvestigation with TI enrichment and related alert/incident info
    """
    # 1. TI enrichment via mock provider
    provider = get_provider()
    enrichment = provider.enrich(ioc_type, ioc_value)

    # 2. Find related alerts
    related_alert_ids = []
    try:
        alerts = get_alerts()
        for alert in alerts:
            alert_iocs = extract_iocs(alert)
            for ioc in alert_iocs:
                if ioc.value.lower() == ioc_value.lower():
                    related_alert_ids.append(alert.alert_id)
                    break
    except Exception:
        pass

    # 3. Find related incidents
    related_incident_ids = []
    try:
        from backend.services.incidents import list_incidents
        for incident in list_incidents():
            for ioc in incident.related_iocs:
                if ioc.get("value", "").lower() == ioc_value.lower():
                    related_incident_ids.append(incident.incident_id)
                    break
    except Exception:
        pass

    return IOCInvestigation(
        ioc_type=ioc_type,
        value=ioc_value,
        reputation=enrichment.reputation,
        confidence=enrichment.confidence,
        malicious=enrichment.malicious,
        category=enrichment.categories,
        detections=enrichment.detections,
        malware_families=enrichment.malware_families,
        last_seen=enrichment.last_seen,
        source=enrichment.source,
        related_alert_ids=related_alert_ids,
        related_incident_ids=related_incident_ids,
    )
