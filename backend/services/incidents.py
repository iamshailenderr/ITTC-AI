"""Incident Correlation Engine — groups related security alerts into incidents."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

import re
from backend.models.alert import SecurityAlert
from backend.models.incident import Incident, TimelineEntry, AnalystNote
from backend.threat_intel.extractor import extract_iocs
from backend.threat_intel.enricher import enrich_iocs, get_provider
from backend.services.alerts import get_alerts
from backend.ai.anomaly import detect_anomaly
from backend.ai.risk_explainer import compute_risk_factors
from backend.ai.response import generate_response_recommendation

_incidents: Dict[str, Incident] = {}
CORRELATION_WINDOW_HOURS = 24
VALID_STATUSES = {"OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED"}


def _compute_severity(alerts: List[SecurityAlert]) -> str:
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    max_sev = max(severity_order.get(a.severity.lower(), 0) for a in alerts)
    for name, val in severity_order.items():
        if val == max_sev:
            return name
    return "medium"


def _compute_risk_score(alerts: List[SecurityAlert], iocs: List[Dict[str, str]]) -> int:
    severity_scores = {"critical": 35, "high": 25, "medium": 15, "low": 5}
    base = max(severity_scores.get(a.severity.lower(), 10) for a in alerts)
    alert_bonus = min(len(alerts) * 5, 20)
    ioc_bonus = min(len(iocs) * 5, 15)
    return min(base + alert_bonus + ioc_bonus, 100)


def _alerts_correlate(a1: SecurityAlert, a2: SecurityAlert, window_hours: int = CORRELATION_WINDOW_HOURS) -> bool:
    try:
        t1 = a1.timestamp if isinstance(a1.timestamp, datetime) else datetime.fromisoformat(str(a1.timestamp))
        t2 = a2.timestamp if isinstance(a2.timestamp, datetime) else datetime.fromisoformat(str(a2.timestamp))
        if t1.tzinfo is not None and t2.tzinfo is None:
            t2 = t2.replace(tzinfo=t1.tzinfo)
        elif t2.tzinfo is not None and t1.tzinfo is None:
            t1 = t1.replace(tzinfo=t2.tzinfo)
        if abs((t1 - t2).total_seconds()) > window_hours * 3600:
            return False
    except Exception:
        pass

    if a1.src_ip and a2.src_ip and a1.src_ip == a2.src_ip:
        return True
    if a1.host and a2.host and a1.host.lower() == a2.host.lower():
        return True
    if a1.dst_ip and a2.dst_ip and a1.dst_ip == a2.dst_ip:
        return True
    try:
        if {(i.type, i.value) for i in extract_iocs(a1)} & {(i.type, i.value) for i in extract_iocs(a2)}:
            return True
    except Exception:
        pass
    return False


def _enrich_cluster_iocs(all_iocs: List[Dict[str, str]]) -> List[Dict]:
    """Return normalized TI evidence for the cluster's IOCs."""
    try:
        provider = get_provider()
        enrichments = [provider.enrich(ioc.get("type", "ip"), ioc.get("value", "")) for ioc in all_iocs]
        return [e.model_dump() for e in enrichments]
    except Exception:
        return []


def correlate_alerts(alerts: Optional[List[SecurityAlert]] = None, window_hours: int = CORRELATION_WINDOW_HOURS) -> List[Incident]:
    if alerts is None:
        try:
            alerts = get_alerts()
        except Exception:
            alerts = []
    if not alerts:
        return []

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

    for i in range(n):
        for j in range(i + 1, n):
            if _alerts_correlate(alerts[i], alerts[j], window_hours):
                union(i, j)

    clusters: Dict[int, List[int]] = {}
    for i in range(n):
        clusters.setdefault(find(i), []).append(i)

    now = datetime.now(timezone.utc)
    new_incidents: List[Incident] = []

    for cluster_indices in clusters.values():
        cluster_alerts = [alerts[i] for i in cluster_indices]
        alert_ids = [a.alert_id for a in cluster_alerts]

        existing = None
        for inc in _incidents.values():
            if set(alert_ids) & set(inc.related_alert_ids):
                existing = inc
                break

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

        ioc_intelligence = _enrich_cluster_iocs(all_iocs)
        sorted_alerts = sorted(cluster_alerts, key=lambda a: a.timestamp)
        timeline = [TimelineEntry(timestamp=a.timestamp, event=a.event[:200], source=a.source, alert_id=a.alert_id) for a in sorted_alerts]
        severity = _compute_severity(cluster_alerts)
        risk_score = _compute_risk_score(cluster_alerts, all_iocs)
        cluster_techs = sorted(list(set(re.findall(r"T\d{4}(?:\.\d{3})?", " ".join(a.event for a in cluster_alerts)))))
        anom_results = [detect_anomaly(a) for a in cluster_alerts]
        max_anomaly_score = max((r[0] for r in anom_results), default=0.0)
        any_anomalous = any(r[1] for r in anom_results)
        lead_alert = max(cluster_alerts, key=lambda a: {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(a.severity.lower(), 0))
        rec_dict = generate_response_recommendation(lead_alert, risk_score=risk_score).model_dump()
        risk_factors_dicts = [f.model_dump() for f in compute_risk_factors(alert=lead_alert, enrichments=ioc_intelligence, mitre_techniques=cluster_techs, anomaly_score=max_anomaly_score, is_anomalous=any_anomalous, correlated_alert_count=len(cluster_alerts))]

        if existing:
            existing.related_alert_ids = list(set(existing.related_alert_ids + alert_ids))
            existing.related_iocs = all_iocs
            existing.ioc_intelligence = ioc_intelligence
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
                ioc_intelligence=ioc_intelligence,
                mitre_techniques=cluster_techs,
                timeline=timeline,
                summary=f"Correlated incident involving {len(cluster_alerts)} alert(s) across host(s): {', '.join(set(a.host for a in cluster_alerts))}",
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


def list_incidents() -> List[Incident]:
    return list(_incidents.values())


def get_incident(incident_id: str) -> Optional[Incident]:
    return _incidents.get(incident_id)


def update_incident_status(incident_id: str, status: str) -> Optional[Incident]:
    incident = _incidents.get(incident_id)
    if incident is None:
        return None
    if status not in VALID_STATUSES:
        raise ValueError(f"Invalid status '{status}'. Valid: {VALID_STATUSES}")
    incident.status = status
    incident.updated_at = datetime.now(timezone.utc)
    return incident


def add_incident_note(incident_id: str, content: str, author: str = "analyst") -> Optional[Incident]:
    incident = _incidents.get(incident_id)
    if incident is None:
        return None
    incident.analyst_notes.append(AnalystNote(timestamp=datetime.now(timezone.utc), author=author, content=content))
    incident.updated_at = datetime.now(timezone.utc)
    return incident


def clear_incidents() -> None:
    _incidents.clear()
