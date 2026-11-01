"""Incident Correlation Engine — groups related security alerts into incidents."""

from __future__ import annotations

import json
import logging
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import requests

from backend.models.alert import SecurityAlert
from backend.models.incident import (
    AnalystNote,
    CorrelationGroup,
    CorrelationResult,
    Incident,
    QwenCorrelatedAnalysis,
    RAGFinding,
    ThreatIntelSummary,
    TimelineEntry,
)
from backend.threat_intel.extractor import extract_all_iocs, extract_iocs
from backend.threat_intel.enricher import get_provider
from backend.services.alerts import get_alerts
from backend.ai.anomaly import detect_anomaly
from backend.ai.risk_explainer import compute_risk_factors
from backend.ai.response import generate_response_recommendation
from config.settings import OLLAMA_HOST, OLLAMA_MODEL

logger = logging.getLogger("ittc_ai.incidents")

_incidents: Dict[str, Incident] = {}
_correlation_runs: Dict[str, CorrelationResult] = {}
_latest_correlation_run: Optional[CorrelationResult] = None

CORRELATION_WINDOW_HOURS = 24
VALID_STATUSES = {"OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED"}


def _compute_severity(alerts: List[SecurityAlert]) -> str:
    if not alerts:
        return "low"
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    max_sev = max(severity_order.get(a.severity.lower(), 0) for a in alerts)
    for name, val in severity_order.items():
        if val == max_sev:
            return name
    return "medium"


def _compute_risk_score(alerts: List[SecurityAlert], iocs: List[Dict[str, str]]) -> int:
    if not alerts:
        return 0
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

        cluster_hosts = sorted(list(set(a.host for a in cluster_alerts if getattr(a, "host", None) and a.host not in ("", "N/A"))))

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
            existing.affected_hosts = sorted(list(set(getattr(existing, "affected_hosts", []) + cluster_hosts)))
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
                affected_hosts=cluster_hosts,
            )
            _incidents[incident_id] = incident
            new_incidents.append(incident)

    return new_incidents


# ==============================================================================
# Full Multi-Alert Run Correlation Pipeline
# ==============================================================================

def _check_alert_pair_relationship(
    a1: SecurityAlert,
    a2: SecurityAlert,
    window_hours: int = CORRELATION_WINDOW_HOURS,
) -> tuple[bool, List[str], List[Dict[str, str]]]:
    """
    Evaluate whether two alerts have concrete security relationships.
    Returns: (is_related, relationship_types, shared_iocs)
    """
    reasons: List[str] = []
    shared_iocs: List[Dict[str, str]] = []

    # Check temporal proximity
    try:
        t1 = a1.timestamp if isinstance(a1.timestamp, datetime) else datetime.fromisoformat(str(a1.timestamp))
        t2 = a2.timestamp if isinstance(a2.timestamp, datetime) else datetime.fromisoformat(str(a2.timestamp))
        if t1.tzinfo is not None and t2.tzinfo is None:
            t2 = t2.replace(tzinfo=t1.tzinfo)
        elif t2.tzinfo is not None and t1.tzinfo is None:
            t1 = t1.replace(tzinfo=t2.tzinfo)
        time_diff = abs((t1 - t2).total_seconds())
        if time_diff > window_hours * 3600:
            return False, [], []
    except Exception:
        pass

    # 1. Shared IOCs
    try:
        iocs1 = {(i.type, i.value.lower()) for i in extract_iocs(a1)}
        iocs2 = {(i.type, i.value.lower()) for i in extract_iocs(a2)}
        common_iocs = iocs1 & iocs2
        if common_iocs:
            reasons.append("shared_ioc")
            for itype, ival in common_iocs:
                shared_iocs.append({"type": itype, "value": ival})
    except Exception:
        pass

    # 2. Host relationship
    h1 = (a1.host or "").strip().lower()
    h2 = (a2.host or "").strip().lower()
    if h1 and h2 and h1 == h2 and h1 not in ("unknown", "n/a", "none", ""):
        reasons.append("host")

    # 3. Network communication relationship
    s1, d1 = (a1.src_ip or "").strip(), (a1.dst_ip or "").strip()
    s2, d2 = (a2.src_ip or "").strip(), (a2.dst_ip or "").strip()
    if s1 and s2 and s1 == s2:
        reasons.append("network_source")
    if d1 and d2 and d1 == d2:
        reasons.append("network_destination")
    if (s1 and d2 and s1 == d2) or (d1 and s2 and d1 == s2):
        reasons.append("network_bidirectional")

    # 4. Authenticated user relationship
    u1 = (a1.user or "").strip().lower()
    u2 = (a2.user or "").strip().lower()
    if u1 and u2 and u1 == u2 and u1 not in ("none", "null", "system", ""):
        reasons.append("user_account")

    # 5. Security / attack chain sequence
    et1 = (a1.event_type or "").lower()
    et2 = (a2.event_type or "").lower()
    attack_sequence_pairs = {
        ("initial_access", "execution"),
        ("exploitation", "code_execution"),
        ("process_creation", "network_connection"),
        ("process_creation", "lateral_movement"),
        ("network_connection", "lateral_movement"),
        ("lateral_movement", "credential_access"),
        ("credential_access", "discovery"),
    }
    if (et1, et2) in attack_sequence_pairs or (et2, et1) in attack_sequence_pairs:
        reasons.append("attack_sequence")

    is_related = len(reasons) > 0
    return is_related, list(set(reasons)), shared_iocs


def run_full_correlation_pipeline(
    alerts: Optional[List[SecurityAlert]] = None,
    window_hours: int = CORRELATION_WINDOW_HOURS,
) -> CorrelationResult:
    """
    Execute the full end-to-end Run Correlation pipeline across the whole alert set:
      1. Ingest/normalize all current Wazuh + Suricata alerts
      2. Extract and deduplicate all IOCs
      3. Perform multi-source event correlation with concrete relationship tracking
      4. Detect whether alerts are related or completely independent (No-Relation case)
      5. Safe, resilient VirusTotal threat-intelligence enrichment (no crash on failure)
      6. Query existing RAG system for MITRE ATT&CK guidance and playbooks
      7. Query Qwen3/Ollama for correlated security synthesis (with deterministic fallback)
      8. Produce structured CorrelationResult and cache run by ID
    """
    global _latest_correlation_run

    if alerts is None:
        try:
            alerts = get_alerts()
        except Exception:
            alerts = []

    now = datetime.now(timezone.utc)
    run_id = f"CORR-{now.strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6].upper()}"

    if not alerts:
        result = CorrelationResult(
            correlation_run_id=run_id,
            timestamp=now,
            alerts_analyzed=0,
            status="no_relation",
            message="No alerts currently available for correlation.",
            related_groups=[],
            iocs=[],
            threat_intelligence=[],
            rag_findings=[],
            qwen_analysis=QwenCorrelatedAnalysis(
                summary="No security alerts were present in the ingestion queue.",
                correlation_reasoning="Zero alerts processed.",
                risk_score=0,
                severity="low",
                confidence=1.0,
                evidence=[],
                mitre_techniques=[],
                attack_pattern="None",
                recommendations=["Maintain continuous Wazuh and Suricata telemetry ingestion."],
            ),
            risk=0,
            severity="low",
            evidence=[],
            correlation_reasoning="Zero alerts evaluated.",
        )
        _correlation_runs[run_id] = result
        _latest_correlation_run = result
        return result

    # Step 1: IOC Extraction across all alerts
    extracted_ioc_objs = extract_all_iocs(alerts)
    all_iocs = [{"type": ioc.type, "value": ioc.value} for ioc in extracted_ioc_objs]

    # Step 2: VirusTotal Threat Intelligence Enrichment (Safe & Resilient)
    threat_intel_summaries: List[ThreatIntelSummary] = []
    try:
        provider = get_provider()
        for ioc in all_iocs:
            try:
                enrichment = provider.enrich(ioc["type"], ioc["value"])
                threat_intel_summaries.append(ThreatIntelSummary(
                    ioc=ioc["value"],
                    ioc_type=ioc["type"],
                    reputation=enrichment.reputation,
                    malicious=enrichment.malicious,
                    provider_status=enrichment.provider_status,
                    malicious_count=enrichment.malicious_count,
                    suspicious_count=enrichment.suspicious_count,
                    harmless_count=enrichment.harmless_count,
                    undetected_count=enrichment.undetected_count,
                    total_engines=enrichment.total_engines,
                    reputation_score=enrichment.reputation_score,
                    categories=enrichment.categories,
                    source=enrichment.source,
                    analysis_timestamp=enrichment.analysis_timestamp,
                ))
            except Exception:
                threat_intel_summaries.append(ThreatIntelSummary(
                    ioc=ioc["value"],
                    ioc_type=ioc["type"],
                    reputation="unknown",
                    malicious=False,
                    provider_status="unavailable",
                    source="VirusTotal (unavailable)",
                ))
    except Exception:
        pass

    # Step 3: Event Correlation across the whole alert set
    n = len(alerts)
    parent = list(range(n))
    pair_reasons: Dict[tuple[int, int], List[str]] = {}
    pair_shared_iocs: Dict[tuple[int, int], List[Dict[str, str]]] = {}

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
            is_rel, rel_types, sh_iocs = _check_alert_pair_relationship(alerts[i], alerts[j], window_hours)
            if is_rel:
                union(i, j)
                pair_reasons[(i, j)] = rel_types
                if sh_iocs:
                    pair_shared_iocs[(i, j)] = sh_iocs

    clusters: Dict[int, List[int]] = {}
    for i in range(n):
        clusters.setdefault(find(i), []).append(i)

    # Filter clusters: Only clusters with >= 2 alerts represent actual correlations
    correlated_clusters = [indices for indices in clusters.values() if len(indices) >= 2]

    related_groups: List[CorrelationGroup] = []
    group_counter = 1

    for cluster_indices in correlated_clusters:
        cluster_alerts = [alerts[i] for i in cluster_indices]
        cluster_alert_ids = [a.alert_id for a in cluster_alerts]

        # Gather cluster relationship types
        c_types = set()
        c_shared_iocs: List[Dict[str, str]] = []
        c_iocs_seen = set()

        for i in cluster_indices:
            for j in cluster_indices:
                if i < j and (i, j) in pair_reasons:
                    c_types.update(pair_reasons[(i, j)])
                    for ioc_dict in pair_shared_iocs.get((i, j), []):
                        key = (ioc_dict["type"], ioc_dict["value"].lower())
                        if key not in c_iocs_seen:
                            c_iocs_seen.add(key)
                            c_shared_iocs.append(ioc_dict)

        hosts = sorted(list(set(a.host for a in cluster_alerts if a.host and a.host not in ("N/A", "unknown"))))
        users = sorted(list(set(a.user for a in cluster_alerts if a.user and a.user not in ("none", "null"))))
        lead_sev = _compute_severity(cluster_alerts)
        lead_risk = _compute_risk_score(cluster_alerts, c_shared_iocs)

        rel_type_names = list(c_types) if c_types else ["temporal_proximity"]
        reasoning_parts = []
        if "shared_ioc" in c_types:
            reasoning_parts.append(f"Shared IOC(s): {', '.join(i['value'] for i in c_shared_iocs[:3])}")
        if "host" in c_types:
            reasoning_parts.append(f"Common host endpoint: {', '.join(hosts)}")
        if any(t.startswith("network") for t in c_types):
            reasoning_parts.append("Direct network connection or shared external IP link")
        if "user_account" in c_types:
            reasoning_parts.append(f"Common user: {', '.join(users)}")
        if "attack_sequence" in c_types:
            reasoning_parts.append("Sequential cyber attack chain progression")
        if not reasoning_parts:
            reasoning_parts.append("Temporal proximity and coordinated event timeline")

        grp_reasoning = " | ".join(reasoning_parts)

        details = [
            {
                "alert_id": a.alert_id,
                "host": a.host or "N/A",
                "source": a.source,
                "severity": a.severity,
                "event": a.event[:150],
                "rule_id": a.rule_id or "",
                "timestamp": str(a.timestamp),
            }
            for a in cluster_alerts
        ]

        related_groups.append(CorrelationGroup(
            group_id=f"GRP-{group_counter:02d}",
            alert_ids=cluster_alert_ids,
            relationship_types=rel_type_names,
            reasoning=grp_reasoning,
            shared_iocs=c_shared_iocs,
            hosts=hosts,
            users=users,
            lead_severity=lead_sev,
            lead_risk_score=lead_risk,
            alert_details=details,
        ))
        group_counter += 1

    # Determine correlation status
    is_correlated = len(related_groups) > 0
    status_str = "correlated" if is_correlated else "no_relation"

    if is_correlated:
        overall_severity = max(
            (g.lead_severity for g in related_groups),
            default="medium",
            key=lambda s: {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(s.lower(), 0),
        )
        overall_risk = max((g.lead_risk_score for g in related_groups), default=50)
        status_message = f"Identified {len(related_groups)} correlated incident group(s) across {len(alerts)} alerts."
        correlation_reasoning = (
            f"Correlation engine identified {len(related_groups)} distinct attack cluster(s) "
            f"spanning {len(alerts)} alerts. Key relationships include: "
            + "; ".join(set(g.reasoning for g in related_groups))
            + "."
        )
    else:
        overall_severity = _compute_severity(alerts)
        severity_scores = {"critical": 35, "high": 25, "medium": 15, "low": 5}
        overall_risk = max((severity_scores.get(a.severity.lower(), 10) for a in alerts), default=15)
        status_message = (
            "No related alerts found. All analyzed alerts appear to be independent events "
            "based on IOC, temporal, host, and contextual relationships."
        )
        correlation_reasoning = (
            f"No related alerts found. The {len(alerts)} analyzed alert(s) appear to be independent based on "
            f"IOC, temporal, host, and contextual relationships. No shared external IP addresses, domains, "
            f"user sessions, or contiguous attack timeline patterns were observed across the current alert set."
        )

    # Step 4: RAG Investigation Findings
    rag_findings: List[RAGFinding] = []
    all_techs = sorted(list(set(re.findall(r"T\d{4}(?:\.\d{3})?", " ".join(a.event for a in alerts)))))
    try:
        from backend.rag.retriever import retrieve_for_query
        query_parts = []
        if all_techs:
            query_parts.append(f"MITRE techniques: {' '.join(all_techs)}")
        if all_iocs:
            query_parts.append(f"IOCs: {' '.join(i['value'] for i in all_iocs[:4])}")
        query_parts.append(f"Events: {' '.join(a.event[:80] for a in alerts[:4])}")
        rag_chunks = retrieve_for_query(" ".join(query_parts), top_k=4)
        for c in rag_chunks:
            rag_findings.append(RAGFinding(
                title=c.get("title", ""),
                topic=c.get("topic", ""),
                category=c.get("category", ""),
                similarity_score=round(float(c.get("similarity_score", 0.0)), 4),
                text=c.get("text", "")[:350],
            ))
    except Exception:
        pass

    # Step 5: Qwen3 Correlated Security Analysis
    qwen_analysis: Optional[QwenCorrelatedAnalysis] = None
    try:
        # Attempt to prompt local Ollama Qwen3
        import urllib.request
        import urllib.error

        endpoint = f"{OLLAMA_HOST.rstrip('/')}/api/chat"
        sys_prompt = (
            "You are an expert defensive SOC analyst performing multi-alert correlation analysis. "
            "Respond strictly in valid JSON matching this schema:\n"
            "{\n"
            '  "summary": "<string>",\n'
            '  "correlation_reasoning": "<string>",\n'
            '  "risk_score": <int 0-100>,\n'
            '  "severity": "<string>",\n'
            '  "confidence": <float 0.0-1.0>,\n'
            '  "evidence": ["<string>"],\n'
            '  "mitre_techniques": ["<string>"],\n'
            '  "attack_pattern": "<string>",\n'
            '  "recommendations": ["<string>"]\n'
            "}"
        )
        user_prompt = (
            f"Correlation Status: {status_str}\n"
            f"Alerts Analyzed: {len(alerts)}\n"
            f"Groups Formed: {len(related_groups)}\n"
            f"Extracted IOCs: {all_iocs}\n"
            f"RAG Knowledge: {[rf.text for rf in rag_findings]}\n"
            f"Alerts: {[a.event[:150] for a in alerts[:5]]}"
        )
        payload = {
            "model": OLLAMA_MODEL,
            "messages": [
                {"role": "system", "content": sys_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "stream": False,
            "think": False,
            "format": "json",
            "options": {"temperature": 0.1, "num_predict": 400},
        }
        req = urllib.request.Request(
            endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as u_resp:
            res_data = json.loads(u_resp.read().decode("utf-8"))
            raw_content = res_data.get("message", {}).get("content", "")
            data = json.loads(raw_content)
            qwen_analysis = QwenCorrelatedAnalysis(
                summary=data.get("summary", ""),
                correlation_reasoning=data.get("correlation_reasoning", correlation_reasoning),
                risk_score=int(data.get("risk_score", overall_risk)),
                severity=str(data.get("severity", overall_severity)).lower(),
                confidence=float(data.get("confidence", 0.85)),
                evidence=data.get("evidence", [a.event[:120] for a in alerts[:5]]),
                mitre_techniques=data.get("mitre_techniques", all_techs),
                attack_pattern=data.get("attack_pattern", "Multi-stage Campaign" if is_correlated else "None"),
                recommendations=data.get("recommendations", []),
            )
    except Exception:
        # Safe deterministic synthesis fallback
        pass

    if not qwen_analysis:
        if is_correlated:
            recs = [
                "Isolate affected endpoints identified in the correlation cluster.",
                "Block malicious external IP addresses and C2 domains at perimeter firewalls.",
                "Perform credential rotation for observed administrative user accounts.",
                "Review Wazuh FIM logs and Suricata flow records for persistent artifacts.",
            ]
            qwen_analysis = QwenCorrelatedAnalysis(
                summary=f"Correlated multi-source security incident identified across {len(related_groups)} cluster(s). Activity involves coordinated progression across endpoint and network vectors.",
                correlation_reasoning=correlation_reasoning,
                risk_score=overall_risk,
                severity=overall_severity.lower(),
                confidence=min(0.6 + len(related_groups) * 0.15, 0.95),
                evidence=[a.event[:140] for a in alerts[:6]],
                mitre_techniques=all_techs,
                attack_pattern="Initial Access -> Command and Control -> Lateral Movement",
                recommendations=recs,
            )
        else:
            qwen_analysis = QwenCorrelatedAnalysis(
                summary=f"Evaluation of {len(alerts)} analyzed alert(s) determined that all events are independent. No coordinated attack campaign or lateral movement patterns were observed.",
                correlation_reasoning=correlation_reasoning,
                risk_score=overall_risk,
                severity=overall_severity.lower(),
                confidence=0.85,
                evidence=[a.event[:140] for a in alerts[:5]],
                mitre_techniques=all_techs,
                attack_pattern="Independent Events",
                recommendations=["Continue continuous telemetry ingestion and monitor endpoints for isolated anomalies."],
            )

    evidence_list = [a.event[:140] for a in alerts[:6]]

    result = CorrelationResult(
        correlation_run_id=run_id,
        timestamp=now,
        alerts_analyzed=len(alerts),
        status=status_str,
        message=status_message,
        related_groups=related_groups,
        iocs=all_iocs,
        threat_intelligence=threat_intel_summaries,
        rag_findings=rag_findings,
        qwen_analysis=qwen_analysis,
        risk=overall_risk,
        severity=overall_severity,
        evidence=evidence_list,
        correlation_reasoning=correlation_reasoning,
    )

    # Sync with existing incident store so dashboard incident table stays updated
    try:
        correlate_alerts(alerts)
    except Exception:
        pass

    _correlation_runs[run_id] = result
    _latest_correlation_run = result
    return result


def get_latest_correlation_run() -> Optional[CorrelationResult]:
    """Return the most recent correlation execution result."""
    return _latest_correlation_run


def get_correlation_run(run_id: str) -> Optional[CorrelationResult]:
    """Return a specific correlation result by run_id."""
    return _correlation_runs.get(run_id)


def list_correlation_runs() -> List[CorrelationResult]:
    """Return all stored correlation run results."""
    return list(_correlation_runs.values())


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
    _correlation_runs.clear()
    global _latest_correlation_run
    _latest_correlation_run = None
    try:
        from backend.services.notifications import clear_notification_tracker
        clear_notification_tracker()
    except Exception:
        pass
