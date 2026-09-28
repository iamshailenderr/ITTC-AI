"""
Incident Reporting Service — generates structured incident reports.

Aggregates all incident data into a comprehensive JSON report:
  - Incident metadata
  - Related alerts
  - Timeline
  - IOCs with TI enrichment
  - MITRE ATT&CK mappings
  - Risk factors
  - Anomaly score
  - AI analysis results
  - Recommendations
  - Response recommendation
  - RAG sources used
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from backend.services.alerts import get_alert
from backend.services.incidents import get_incident
from backend.threat_intel.enricher import get_provider, enrich_iocs
from backend.threat_intel.extractor import extract_iocs


def generate_incident_report(incident_id: str) -> Optional[Dict[str, Any]]:
    """
    Generate a comprehensive incident report in structured JSON format.

    Args:
        incident_id: The incident ID to generate a report for

    Returns:
        Dict containing the full incident report, or None if incident not found
    """
    incident = get_incident(incident_id)
    if incident is None:
        return None

    # Collect related alerts
    alerts_data = []
    for alert_id in incident.related_alert_ids:
        alert = get_alert(alert_id)
        if alert:
            alerts_data.append(alert.model_dump(mode="json"))

    # Collect IOC enrichment
    ioc_enrichment = []
    provider = get_provider()
    for ioc_info in incident.related_iocs:
        try:
            enrichment = provider.enrich(ioc_info.get("type", "ip"), ioc_info.get("value", ""))
            ioc_enrichment.append(enrichment.model_dump())
        except Exception:
            ioc_enrichment.append(ioc_info)

    # Build timeline data
    timeline_data = [
        {
            "timestamp": entry.timestamp.isoformat() if hasattr(entry.timestamp, 'isoformat') else str(entry.timestamp),
            "event": entry.event,
            "source": entry.source,
            "alert_id": entry.alert_id,
        }
        for entry in incident.timeline
    ]

    # Build report
    report = {
        "report_metadata": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "report_type": "incident_report",
            "version": "1.0",
        },
        "incident": {
            "incident_id": incident.incident_id,
            "created_at": incident.created_at.isoformat() if hasattr(incident.created_at, 'isoformat') else str(incident.created_at),
            "updated_at": incident.updated_at.isoformat() if hasattr(incident.updated_at, 'isoformat') else str(incident.updated_at),
            "status": incident.status,
            "severity": incident.severity,
            "risk_score": incident.risk_score,
            "confidence": incident.confidence,
            "summary": incident.summary,
        },
        "alerts": alerts_data,
        "timeline": timeline_data,
        "iocs": {
            "raw": incident.related_iocs,
            "enrichment": ioc_enrichment,
        },
        "mitre_techniques": incident.mitre_techniques,
        "risk": {
            "score": incident.risk_score,
            "severity": incident.severity,
            "confidence": incident.confidence,
            "factors": incident.risk_factors,
        },
        "anomaly_score": incident.anomaly_score,
        "is_anomalous": incident.is_anomalous,
        "evidence": incident.evidence,
        "recommendations": incident.recommendations,
        "response_recommendation": incident.response_recommendation,
        "analyst_notes": [
            {
                "timestamp": note.timestamp.isoformat() if hasattr(note.timestamp, 'isoformat') else str(note.timestamp),
                "author": note.author,
                "content": note.content,
            }
            for note in incident.analyst_notes
        ],
    }

    return report
