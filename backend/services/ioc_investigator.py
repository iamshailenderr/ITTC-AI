"""IOC Investigation Service — structured IOC and threat-intelligence lookup."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from backend.threat_intel.enricher import get_provider
from backend.threat_intel.extractor import extract_iocs
from backend.services.alerts import get_alerts


class IOCInvestigation(BaseModel):
    ioc_type: str
    value: str
    reputation: str = "unknown"
    confidence: float = 0.0
    malicious: bool = False
    source: str = ""
    provider_status: str = "available"
    categories: List[str] = Field(default_factory=list)
    detections: Optional[int] = None
    malicious_count: Optional[int] = None
    suspicious_count: Optional[int] = None
    harmless_count: Optional[int] = None
    undetected_count: Optional[int] = None
    total_engines: Optional[int] = None
    reputation_score: Optional[int] = None
    malware_families: List[str] = Field(default_factory=list)
    last_seen: Optional[str] = None
    analysis_timestamp: Optional[str] = None
    related_alert_ids: List[str] = Field(default_factory=list)
    related_incident_ids: List[str] = Field(default_factory=list)


def investigate_ioc(ioc_type: str, ioc_value: str) -> IOCInvestigation:
    provider = get_provider()
    enrichment = provider.enrich(ioc_type, ioc_value)

    related_alert_ids: List[str] = []
    try:
        alerts = get_alerts()
        for alert in alerts:
            if any(i.value.lower() == ioc_value.lower() for i in extract_iocs(alert)):
                related_alert_ids.append(alert.alert_id)
    except Exception:
        pass

    related_incident_ids: List[str] = []
    try:
        from backend.services.incidents import list_incidents
        for incident in list_incidents():
            if any(i.get("value", "").lower() == ioc_value.lower() for i in incident.related_iocs):
                related_incident_ids.append(incident.incident_id)
    except Exception:
        pass

    return IOCInvestigation(
        ioc_type=ioc_type,
        value=ioc_value,
        reputation=enrichment.reputation,
        confidence=enrichment.confidence,
        malicious=enrichment.malicious,
        source=enrichment.source,
        provider_status=enrichment.provider_status,
        categories=enrichment.categories,
        detections=enrichment.detections,
        malicious_count=enrichment.malicious_count,
        suspicious_count=enrichment.suspicious_count,
        harmless_count=enrichment.harmless_count,
        undetected_count=enrichment.undetected_count,
        total_engines=enrichment.total_engines,
        reputation_score=enrichment.reputation_score,
        malware_families=enrichment.malware_families,
        last_seen=enrichment.last_seen,
        analysis_timestamp=enrichment.analysis_timestamp,
        related_alert_ids=related_alert_ids,
        related_incident_ids=related_incident_ids,
    )
