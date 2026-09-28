"""
Incident Correlation Engine — groups related security alerts into incidents.

Correlation rules:
  - Same source IP
  - Same destination/host
  - Same IOC
  - Same MITRE technique
  - Related event/signature type
  - Configurable time window (default 24 hours)

Incidents are stored in-memory for demo/hackathon use.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any

import re
from backend.models.alert import SecurityAlert
from backend.models.incident import (
    Incident, TimelineEntry, AnalystNote,
    IncidentStatusUpdate, IncidentNoteRequest,
)
from backend.threat_intel.extractor import extract_iocs
from backend.services.alerts import get_alerts
from backend.ai.anomaly import detect_anomaly
from backend.ai.risk_explainer import compute_risk_factors
from backend.ai.response import generate_response_recommendation

# In-memory incident store
_incidents: Dict[str, Incident] = {}

# Correlation configuration
CORRELATION_WINDOW_HOURS = 24
VALID_STATUSES = {"OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED"}


def _compute_severity(alerts: List[SecurityAlert]) -> str:
    """Determine incident severity from the highest severity alert."""
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    max_sev = max(severity_order.get(a.severity.lower(), 0) for a in alerts)
    for name, val in severity_order.items():
        if val == max_sev:
            return name
    return "medium"


def _compute_risk_score(alerts: List[SecurityAlert], iocs: List[Dict[str, str]]) -> int:
    """Compute incident risk score based on alert count, severity, and IOCs."""
    severity_scores = {"critical": 35, "high": 25, "medium": 15, "low": 5}

    # Base from highest severity
    base = max(severity_scores.get(a.severity.lower(), 10) for a in alerts)

    # Bonus for multiple alerts
    alert_bonus = min(len(alerts) * 5, 20)

    # Bonus for IOCs
    ioc_bonus = min(len(iocs) * 5, 15)

    return min(base + alert_bonus + ioc_bonus, 100)


def _alerts_correlate(a1: SecurityAlert, a2: SecurityAlert, window_hours: int = CORRELATION_WINDOW_HOURS) -> bool:
    """
    Determine if two alerts should be correlated.

    Correlation criteria (any match within time window):
      1. Same source IP (non-private)
      2. Same host
      3. Same destination IP
      4. Overlapping IOCs
      5. Related event types
    """
    # Time window check
    try:
        t1 = a1.timestamp if isinstance(a1.timestamp, datetime) else datetime.fromisoformat(str(a1.timestamp))
        t2 = a2.timestamp if isinstance(a2.timestamp, datetime) else datetime.fromisoformat(str(a2.timestamp))
        # Make both offset-aware or naive for comparison
        if t1.tzinfo is not None and t2.tzinfo is None:
            t2 = t2.replace(tzinfo=t1.tzinfo)
        elif t2.tzinfo is not None and t1.tzinfo is None:
            t1 = t1.replace(tzinfo=t2.tzinfo)
        if abs((t1 - t2).total_seconds()) > window_hours * 3600:
            return False
    except Exception:
        pass  # If timestamp parsing fails, don't block on time window

    # Same source IP (skip private-only)
    if a1.src_ip and a2.src_ip and a1.src_ip == a2.src_ip:
        return True

    # Same host
    if a1.host and a2.host and a1.host.lower() == a2.host.lower():
        return True

    # Same destination IP
    if a1.dst_ip and a2.dst_ip and a1.dst_ip == a2.dst_ip:
        return True

    # Overlapping IOCs
    try:
        iocs1 = {(i.type, i.value) for i in extract_iocs(a1)}
        iocs2 = {(i.type, i.value) for i in extract_iocs(a2)}
        if iocs1 & iocs2:
            return True
    except Exception:
        pass

    return False


def correlate_alerts(
    alerts: Optional[List[SecurityAlert]] = None,
    window_hours: int = CORRELATION_WINDOW_HOURS,
) -> List[Incident]:
    """
    Run correlation engine on all alerts and create/update incidents.

    Groups correlated alerts into incidents using union-find style clustering.
    """
    if alerts is None:
        alerts = get_alerts()

    if not alerts:
        return []

    # Build correlation clusters using union-find
    n = len(alerts)
    parent = list(range(n))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x, y):
        px, py = find(x), find(y)
        if px != py:
            parent[px] = py

    # Compare all pairs
    for i in range(n):
        for j in range(i + 1, n):
            if _alerts_correlate(alerts[i], alerts[j], window_hours):
                union(i, j)

    # Group alerts by cluster
    clusters: Dict[int, List[int]] = {}
    for i in range(n):
        root = find(i)
        clusters.setdefault(root, []).append(i)

    # Create incidents from clusters
    now = datetime.now(timezone.utc)
    new_incidents: List[Incident] = []

    for cluster_indices in clusters.values():
        cluster_alerts = [alerts[i] for i in cluster_indices]
        alert_ids = [a.alert_id for a in cluster_alerts]

        # Check if an existing incident already covers these alerts
        existing = None
        for inc in _incidents.values():
            if set(alert_ids) & set(inc.related_alert_ids):
                existing = inc
                break

        # Collect IOCs from all alerts in cluster
        all_iocs: List[Dict[str, str]] = []
        seen_iocs = set()
        for a in cluster_alerts:
            try:
                for ioc in extract_iocs(a):
                    key = (ioc.type, ioc.value)
                    if key not in seen_iocs:
                        seen_iocs.add(key)
                        all_iocs.append({"type": ioc.type, "value": ioc.value})
            except Exception:
                pass

        # Build timeline
        sorted_alerts = sorted(cluster_alerts, key=lambda a: a.timestamp)
        timeline = [
            TimelineEntry(
                timestamp=a.timestamp,
                event=a.event[:200],
                source=a.source,
                alert_id=a.alert_id,
            )
            for a in sorted_alerts
        ]

        severity = _compute_severity(cluster_alerts)
        risk_score = _compute_risk_score(cluster_alerts, all_iocs)

        # Extract MITRE techniques from cluster events
        cluster_techs = sorted(list(set(
            re.findall(r"T\d{4}(?:\.\d{3})?", " ".join(a.event for a in cluster_alerts))
        )))

        # Run anomaly detection across cluster alerts
        anom_results = [detect_anomaly(a) for a in cluster_alerts]
        max_anomaly_score = max((r[0] for r in anom_results), default=0.0)
        any_anomalous = any(r[1] for r in anom_results)

        # Identify lead alert for risk explanation & response recommendation
        lead_alert = max(
            cluster_alerts,
            key=lambda a: {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(a.severity.lower(), 0)
        )

        # Generate response recommendation (recommendation only, requires approval)
        rec_obj = generate_response_recommendation(lead_alert, risk_score=risk_score)
        rec_dict = rec_obj.model_dump()

        # Compute explainable risk factors
        risk_factors_objs = compute_risk_factors(
            alert=lead_alert,
            mitre_techniques=cluster_techs,
            anomaly_score=max_anomaly_score,
            is_anomalous=any_anomalous,
            correlated_alert_count=len(cluster_alerts),
        )
        risk_factors_dicts = [f.model_dump() for f in risk_factors_objs]

        if existing:
            # Update existing incident
            existing.related_alert_ids = list(set(existing.related_alert_ids + alert_ids))
            existing.related_iocs = all_iocs
            existing.timeline = timeline
            existing.severity = severity
            existing.risk_score = risk_score
            existing.mitre_techniques = cluster_techs
            existing.anomaly_score = max_anomaly_score
            existing.is_anomalous = any_anomalous
            existing.risk_factors = risk_factors_dicts
            existing.response_recommendation = rec_dict
            existing.updated_at = now
            new_incidents.append(existing)
        else:
            # Create new incident
            incident_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
            incident = Incident(
                incident_id=incident_id,
                created_at=now,
                updated_at=now,
                status="OPEN",
                severity=severity,
                risk_score=risk_score,
                confidence=min(0.5 + len(cluster_alerts) * 0.1, 0.95),
                related_alert_ids=alert_ids,
                related_iocs=all_iocs,
                mitre_techniques=cluster_techs,
                timeline=timeline,
                summary=f"Correlated incident involving {len(cluster_alerts)} alert(s) "
                        f"across host(s): {', '.join(set(a.host for a in cluster_alerts))}",
                evidence=[a.event[:150] for a in cluster_alerts],
                recommendations=[],
                anomaly_score=max_anomaly_score,
                is_anomalous=any_anomalous,
                risk_factors=risk_factors_dicts,
                response_recommendation=rec_dict,
            )
            _incidents[incident_id] = incident
            new_incidents.append(incident)

    return new_incidents


# CRUD operations

def list_incidents() -> List[Incident]:
    """Return all incidents."""
    return list(_incidents.values())


def get_incident(incident_id: str) -> Optional[Incident]:
    """Return a single incident by ID."""
    return _incidents.get(incident_id)


def update_incident_status(incident_id: str, status: str) -> Optional[Incident]:
    """Update an incident's status."""
    incident = _incidents.get(incident_id)
    if incident is None:
        return None
    if status not in VALID_STATUSES:
        raise ValueError(f"Invalid status '{status}'. Valid: {VALID_STATUSES}")
    incident.status = status
    incident.updated_at = datetime.now(timezone.utc)
    return incident


def add_incident_note(incident_id: str, content: str, author: str = "analyst") -> Optional[Incident]:
    """Add an analyst note to an incident."""
    incident = _incidents.get(incident_id)
    if incident is None:
        return None
    note = AnalystNote(
        timestamp=datetime.now(timezone.utc),
        author=author,
        content=content,
    )
    incident.analyst_notes.append(note)
    incident.updated_at = datetime.now(timezone.utc)
    return incident


def clear_incidents() -> None:
    """Clear all incidents (useful for testing)."""
    _incidents.clear()
