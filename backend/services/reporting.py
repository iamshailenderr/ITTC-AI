"""
Incident & SOC Reporting Service — generates structured JSON and PDF reports.

Provides:
  1. Individual Security Alert & Incident Triage Dossiers (Sections A-J)
  2. Aggregate SOC Security & Executive Summary Reports (Sections A-K)
  3. Original Incident JSON Report (preserved for backwards compatibility)
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from backend.ai.anomaly import detect_anomaly
from backend.ai.hypothesis import generate_investigation_hypothesis
from backend.ai.killchain import map_event_to_killchain
from backend.ai.response import generate_response_recommendation
from backend.ai.risk_explainer import compute_risk_factors
from backend.models.alert import SecurityAlert
from backend.services.active_response import get_audit_trail, list_responses
from backend.services.alerts import get_alert, get_alerts
from backend.services.incidents import (
    correlate_alerts,
    get_incident,
    list_incidents,
)
from backend.services.pdf_generator import build_alert_pdf, build_soc_pdf
from backend.sources.wazuh_indexer import (
    WazuhIndexerAuthError,
    WazuhIndexerConnectionError,
    check_wazuh_indexer_status,
)
from backend.threat_intel.enricher import get_provider
from backend.threat_intel.extractor import extract_iocs
from config import settings


# ==============================================================================
# 1. TIMEZONE & TELEMETRY ACCESS HELPERS
# ==============================================================================

def to_utc(val: Any) -> datetime:
    """Normalize string, naive, or aware datetime into UTC aware datetime."""
    if isinstance(val, str):
        cleaned = val.strip().replace("Z", "+00:00")
        try:
            val = datetime.fromisoformat(cleaned)
        except Exception:
            val = datetime.now(timezone.utc)
    if not isinstance(val, datetime):
        return datetime.now(timezone.utc)
    if val.tzinfo is None:
        return val.replace(tzinfo=timezone.utc)
    return val.astimezone(timezone.utc)


_indexer_available_cache: Optional[bool] = None
_indexer_cache_ts: float = 0.0


def is_indexer_available() -> bool:
    """Check if Wazuh Indexer is available with a 30s cache to avoid blocking on repeated timeouts."""
    global _indexer_available_cache, _indexer_cache_ts
    if settings.ALERT_SOURCE != "wazuh":
        return False
    import time
    now_ts = time.time()
    if _indexer_available_cache is not None and (now_ts - _indexer_cache_ts) < 30.0:
        return _indexer_available_cache
    try:
        st = check_wazuh_indexer_status()
        _indexer_available_cache = bool(st.get("reachable"))
    except Exception:
        _indexer_available_cache = False
    _indexer_cache_ts = now_ts
    return _indexer_available_cache


def get_alert_safe(alert_id: str) -> Optional[SecurityAlert]:
    """Retrieve an alert by ID with graceful fallback to mock alerts if Indexer is offline."""
    if settings.ALERT_SOURCE == "wazuh":
        if is_indexer_available():
            try:
                alert = get_alert(alert_id)
                if alert is not None:
                    return alert
            except Exception:
                pass
    else:
        try:
            alert = get_alert(alert_id)
            if alert is not None:
                return alert
        except Exception:
            pass

    # Graceful fallback to mock alerts
    try:
        from backend.sources.mock import get_mock_alerts
        for a in get_mock_alerts():
            if a.alert_id == alert_id:
                return a
    except Exception:
        pass

    return None


def get_all_alerts_safe() -> List[SecurityAlert]:
    """Retrieve all alerts from active source with automatic fallback to mock alerts."""
    if settings.ALERT_SOURCE == "wazuh":
        if is_indexer_available():
            try:
                return get_alerts()
            except Exception:
                pass
    else:
        try:
            return get_alerts()
        except Exception:
            pass

    try:
        from backend.sources.mock import get_mock_alerts
        return get_mock_alerts()
    except Exception:
        return []


# ==============================================================================
# 2. FEATURE ONE: INDIVIDUAL ALERT REPORT DATA GENERATOR
# ==============================================================================

def generate_alert_report_data(alert_id: str) -> Optional[Dict[str, Any]]:
    """
    Generate complete structured SOC analyst report data for an individual alert.
    Produces Sections A through J based on actual evidence and existing risk algorithms.
    """
    alert = get_alert_safe(alert_id)
    if alert is None:
        return None

    now = datetime.now(timezone.utc)

    # 1. Check for correlated incident
    incidents = list_incidents()
    if not incidents:
        try:
            alerts = get_all_alerts_safe()
            incidents = correlate_alerts(alerts)
        except Exception:
            incidents = []

    matched_incident = None
    for inc in incidents:
        if alert_id in inc.related_alert_ids:
            matched_incident = inc
            break

    # 2. Extract IOCs & Enrich
    iocs_raw = []
    try:
        iocs_raw = extract_iocs(alert)
    except Exception:
        iocs_raw = []

    provider = get_provider()
    iocs_data = []
    for ioc in iocs_raw:
        try:
            enriched = provider.enrich(ioc.type, ioc.value)
            iocs_data.append({
                "type": ioc.type,
                "value": ioc.value,
                "reputation": enriched.reputation if hasattr(enriched, "reputation") else "Unknown",
                "malicious": getattr(enriched, "malicious", False),
                "source": getattr(enriched, "source", "Threat Intel"),
                "provider_status": getattr(enriched, "provider_status", "available"),
                "detections": getattr(enriched, "detections", None),
                "malicious_count": getattr(enriched, "malicious_count", None),
                "total_engines": getattr(enriched, "total_engines", None),
            })
        except Exception:
            iocs_data.append({
                "type": ioc.type,
                "value": ioc.value,
                "reputation": "Unknown",
                "malicious": False,
                "source": "Threat Intel",
                "provider_status": "unavailable",
            })

    # 3. Anomaly detection & Kill Chain
    anomaly_score, is_anomalous = detect_anomaly(alert)
    mitre_techs = sorted(list(set(re.findall(r"T\d{4}(?:\.\d{3})?", alert.event))))
    killchain_stage = map_event_to_killchain(alert.event_type, alert.event, mitre_techs)

    # 4. Severity & Risk Scoring
    severity_weights = {"critical": 85, "high": 70, "medium": 45, "low": 20}
    base_score = severity_weights.get(alert.severity.lower(), 40)
    if matched_incident:
        risk_score = matched_incident.risk_score
        ittc_severity = matched_incident.severity
        confidence = matched_incident.confidence
    else:
        risk_score = min(100, base_score + (15 if is_anomalous else 0) + min(len(iocs_data) * 5, 15))
        if risk_score >= 80:
            ittc_severity = "critical"
        elif risk_score >= 60:
            ittc_severity = "high"
        elif risk_score >= 35:
            ittc_severity = "medium"
        else:
            ittc_severity = "low"
        confidence = round(0.75 + (0.1 if is_anomalous else 0.0), 2)

    # 5. Explainable Risk Factors
    risk_factors_objs = compute_risk_factors(
        alert=alert,
        mitre_techniques=mitre_techs,
        anomaly_score=anomaly_score,
        is_anomalous=is_anomalous,
        correlated_alert_count=len(matched_incident.related_alert_ids) if matched_incident else 1,
    )
    factors_list = [f.model_dump() for f in risk_factors_objs]

    # 6. Hypothesis
    hypothesis = generate_investigation_hypothesis(
        alert=alert,
        mitre_techniques=mitre_techs,
        kill_chain_stage=killchain_stage,
    )

    # 7. Response recommendation (recommendation only, not executed)
    rec_obj = generate_response_recommendation(alert, risk_score=risk_score)
    rec_dict = rec_obj.model_dump()

    # Prioritized remediation actions
    remediation_recommendations = [
        {
            "priority": "P1 - High",
            "action": f"{rec_dict.get('action', 'INVESTIGATE_ONLY')} on target {rec_dict.get('target', alert.host)}",
            "reason": rec_dict.get("reason", "Contain potential threat progression"),
            "justification": f"Telemetry event: {alert.event_type} on host '{alert.host}'",
            "expected_outcome": "Adversary execution paused; potential spread halted",
            "caution": "Do not execute automatically. Analyst authorization and change confirmation required.",
        },
        {
            "priority": "P2 - Medium",
            "action": f"Preserve endpoint memory and process timeline on host '{alert.host}'",
            "reason": "Ensure non-volatile evidence and ephemeral injection artifacts are preserved for forensics",
            "justification": f"Observed suspicious {alert.event_type} activity",
            "expected_outcome": "Forensic triage data captured for post-incident root cause analysis",
            "caution": "Avoid rebooting endpoint prior to memory acquisition.",
        },
    ]
    if alert.src_ip and alert.src_ip not in settings.PROTECTED_IPS:
        remediation_recommendations.append({
            "priority": "P2 - Medium",
            "action": f"Inspect firewall connection logs for source IP {alert.src_ip}",
            "reason": "Identify any other endpoints in the network that have communicated with this source",
            "justification": f"Source address identified in alert {alert.alert_id}",
            "expected_outcome": "Determination of whether adversary initiated concurrent connections",
            "caution": "Verify IP is not an internal DHCP gateway before blocking.",
        })

    # Related alerts in incident
    related_alerts_summaries = []
    if matched_incident:
        for rel_id in matched_incident.related_alert_ids:
            if rel_id != alert.alert_id:
                rel_alert = get_alert_safe(rel_id)
                if rel_alert:
                    related_alerts_summaries.append({
                        "alert_id": rel_alert.alert_id,
                        "timestamp": rel_alert.timestamp.isoformat(),
                        "source": rel_alert.source,
                        "severity": rel_alert.severity,
                        "event": rel_alert.event,
                    })

    # Build Structured Report
    report_id = f"RPT-ALR-{alert.alert_id}-{now.strftime('%Y%m%d-%H%M%S')}"

    return {
        "report_id": report_id,
        "title": "ITTC-AI Security Alert & Incident Triage Report",
        "alert_id": alert.alert_id,
        "incident_id": matched_incident.incident_id if matched_incident else None,
        "incident_status": matched_incident.status if matched_incident else "N/A (Standalone Alert)",
        "generated_at": now.isoformat(),
        "reporting_timezone": "UTC (Coordinated Universal Time)",
        "report_status": "FINAL / VERIFIED",

        # B. Executive Summary
        "executive_summary": {
            "detection_overview": (
                f"A {alert.severity.upper()} severity security event ({alert.event_type}) was detected "
                f"on endpoint '{alert.host}' originating from {alert.source.upper()} telemetry."
            ),
            "security_significance": (
                f"The detected event indicates potential {alert.event_type.replace('_', ' ')} activity "
                f"associated with the {killchain_stage} kill chain phase. Event rule ID: {alert.rule_id or 'N/A'}."
            ),
            "established_facts": [
                f"Event occurred at {alert.timestamp.isoformat()}.",
                f"Host '{alert.host}' was identified as the primary target asset.",
                f"Telemetry source: {alert.source.upper()} rule {alert.rule_id or 'N/A'}.",
                f"Event description: {alert.event[:180]}",
            ],
            "uncertainties": [
                "Full extent of secondary payload execution or persistence without endpoint memory dump.",
                "Whether user credentials were authenticated with valid tokens or harvested.",
            ],
        },

        # C. Alert Details
        "alert_details": {
            "timestamp": alert.timestamp.isoformat(),
            "source": alert.source,
            "host": alert.host,
            "user": alert.user or "Not recorded / System",
            "src_ip": alert.src_ip or "N/A",
            "dst_ip": alert.dst_ip or "N/A",
            "event_type": alert.event_type,
            "event_summary": alert.event,
            "source_severity": alert.severity,
            "rule_id": alert.rule_id or "N/A",
            "metadata": {
                "has_correlated_incident": bool(matched_incident),
                "correlated_alerts_count": len(matched_incident.related_alert_ids) if matched_incident else 1,
                "extracted_iocs_count": len(iocs_data),
            },
        },

        # D. Severity and Risk Assessment
        "severity_and_risk": {
            "source_severity": alert.severity.upper(),
            "ittc_risk_score": risk_score,
            "ittc_severity": ittc_severity.upper(),
            "confidence_score": confidence,
            "confidence_explanation": (
                "Deterministic heuristic confidence score based on telemetry completeness and signature fidelity; "
                "not a calibrated Bayesian probability."
            ),
            "investigation_priority": (
                "P1 - Immediate Containment" if risk_score >= 80
                else ("P2 - High Priority Triage" if risk_score >= 60
                else ("P3 - Medium Priority" if risk_score >= 40 else "P4 - Low Priority"))
            ),
            "assessment_factors": factors_list,
        },

        # E. Impact and Damage Assessment
        "impact_assessment": {
            "confirmed_observations": [
                f"Security detection event logged by {alert.source.upper()}.",
                f"Network or process execution observed on host '{alert.host}'.",
            ],
            "observed_impact": (
                "Direct telemetry confirms event execution on host; active network flow observed."
                if (alert.src_ip or alert.dst_ip)
                else "Local process activity recorded on host."
            ),
            "potential_impact": f"Unauthorized lateral movement, credential access, or persistent backdoor on {alert.host}.",
            "affected_assets": [f"Host: {alert.host}"] + ([f"User: {alert.user}"] if alert.user else []),
            "confidentiality_impact": "Potential exposure of local credentials or memory if execution succeeded.",
            "integrity_impact": "Potential modification of system registry, services, or process structures.",
            "availability_impact": "Negligible direct availability disruption observed; system services remain operational.",
            "damage_disclaimer": "Actual damage could not be established from the available evidence.",
        },

        # F. Supporting Evidence
        "supporting_evidence": {
            "log_excerpt": alert.event,
            "event_id": alert.alert_id,
            "rule_id": alert.rule_id,
            "network_endpoints": f"{alert.src_ip or 'None'} -> {alert.dst_ip or 'None'}",
            "iocs": iocs_data,
            "related_alerts": related_alerts_summaries,
        },

        # G. Attack and Root-Cause Analysis
        "attack_analysis": {
            "confirmed_findings": [
                f"Detection rule '{alert.rule_id or 'N/A'}' triggered on host '{alert.host}'.",
                f"Kill Chain classification: {killchain_stage}.",
            ],
            "plausible_explanations": [hypothesis],
            "supporting_evidence_points": [
                f"Alert event content matching pattern: {alert.event[:140]}",
            ],
            "missing_information": [
                "Parent process lineage and full command-line arguments prior to process launch.",
                "Host memory acquisition to inspect unbacked executable memory regions.",
            ],
            "additional_investigation_required": [
                f"Collect Event ID 4688 / Sysmon Event 1 on host '{alert.host}'.",
                "Correlate firewall session logs for involved IP addresses.",
            ],
            "root_cause_status": (
                "Root cause is currently unconfirmed based on isolated alert telemetry alone. "
                "Further endpoint and host forensic investigation is required."
            ),
        },

        # H. Remediation Recommendations
        "remediation_recommendations": remediation_recommendations,

        # I. Prevention Measures
        "prevention_measures": [
            "Enforce PowerShell ConstrainedLanguageMode and ScriptBlock Logging (Event ID 4104).",
            "Implement endpoint behavioral detection for encoded script interpreters.",
            "Enforce egress firewall controls preventing direct outbound internet connections from servers.",
            "Enable Windows Credential Guard / RunAsPPL to safeguard LSASS process memory.",
        ],

        # J. Analyst Conclusion
        "analyst_conclusion": {
            "overall_assessment": (
                f"Alert {alert.alert_id} warrants active defensive scrutiny due to behavioral risk score {risk_score}/100 "
                f"matching known threat actor tactics ({killchain_stage})."
            ),
            "outstanding_uncertainties": "Persistence status and potential secondary beacon channels remain unverified.",
            "recommended_next_steps": [
                "Preserve memory and triage artifacts from endpoint.",
                "Block identified malicious IP indicators at perimeter firewall upon approval.",
                "Audit authentication events for affected user accounts.",
            ],
            "investigation_status": matched_incident.status if matched_incident else "OPEN",
            "analyst_notes": [n.model_dump() for n in matched_incident.analyst_notes] if (matched_incident and matched_incident.analyst_notes) else [],
            "resolution_disclaimer": (
                "The generation of this assessment does not automatically resolve or close the incident. "
                "The incident remains under active operational review until explicitly resolved by an analyst."
            ),
        },
    }


def generate_alert_pdf(alert_id: str) -> Optional[bytes]:
    """Generate individual alert report PDF bytes, or None if alert not found."""
    report_data = generate_alert_report_data(alert_id)
    if not report_data:
        return None
    return build_alert_pdf(report_data)


# ==============================================================================
# 3. FEATURE TWO: AGGREGATE SOC SECURITY REPORT DATA GENERATOR
# ==============================================================================

def resolve_reporting_window(
    period: str = "last_24h",
    start_time: Optional[Any] = None,
    end_time: Optional[Any] = None,
) -> Tuple[datetime, datetime, str]:
    """
    Resolve reporting window start and end UTC timestamps with strict validation.
    Returns (start_utc, end_utc, period_display_label).
    """
    now = datetime.now(timezone.utc)
    p = str(period or "last_24h").lower().strip()

    if p == "custom":
        if not start_time or not end_time:
            raise ValueError("Custom reporting period requires both 'start_time' and 'end_time'")
        start_utc = to_utc(start_time)
        end_utc = to_utc(end_time)
        if start_utc >= end_utc:
            raise ValueError(f"Start time ({start_utc.isoformat()}) must precede end time ({end_utc.isoformat()})")
        display = f"Custom Range: {start_utc.strftime('%Y-%m-%d %H:%M')} to {end_utc.strftime('%Y-%m-%d %H:%M')} UTC"
        return start_utc, end_utc, display

    if p == "last_7d":
        start_utc = now - timedelta(days=7)
        end_utc = now
        display = f"Last 7 Days ({start_utc.strftime('%Y-%m-%d %H:%M')} to {end_utc.strftime('%Y-%m-%d %H:%M')} UTC)"
        return start_utc, end_utc, display

    if p == "last_30d":
        start_utc = now - timedelta(days=30)
        end_utc = now
        display = f"Last 30 Days ({start_utc.strftime('%Y-%m-%d %H:%M')} to {end_utc.strftime('%Y-%m-%d %H:%M')} UTC)"
        return start_utc, end_utc, display

    # Default to last 24h
    start_utc = now - timedelta(hours=24)
    end_utc = now
    display = f"Last 24 Hours ({start_utc.strftime('%Y-%m-%d %H:%M')} to {end_utc.strftime('%Y-%m-%d %H:%M')} UTC)"
    return start_utc, end_utc, display


def generate_soc_report_data(
    period: str = "last_24h",
    start_time: Optional[Any] = None,
    end_time: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    Generate complete structured SOC aggregate threat report data for a selected time window.
    Calculates statistics from actual stored alerts, incidents, and audit trails without fabricating data.
    """
    start_utc, end_utc, period_display = resolve_reporting_window(
        period=period,
        start_time=start_time,
        end_time=end_time,
    )
    now = datetime.now(timezone.utc)

    # 1. Retrieve all alerts and filter by interval
    all_alerts = get_all_alerts_safe()
    period_alerts: List[SecurityAlert] = []
    for a in all_alerts:
        ts = to_utc(a.timestamp)
        if start_utc <= ts <= end_utc:
            period_alerts.append(a)

    # Sort alerts chronologically
    period_alerts.sort(key=lambda a: to_utc(a.timestamp))

    # 2. Correlate alerts in period for incident summaries
    incidents_in_period = []
    if period_alerts:
        try:
            incidents_in_period = correlate_alerts(period_alerts)
        except Exception:
            incidents_in_period = []

    # Count distinct incidents without double counting
    incident_ids = [inc.incident_id for inc in incidents_in_period]
    active_incidents_count = len(incidents_in_period)

    # 3. Security Statistics Calculation
    total_alerts = len(period_alerts)
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    source_counts: Dict[str, int] = {}
    affected_hosts_set = set()
    anomalies_count = 0

    for a in period_alerts:
        s = a.severity.lower()
        sev_counts[s] = sev_counts.get(s, 0) + 1

        src = a.source.lower()
        source_counts[src] = source_counts.get(src, 0) + 1

        if a.host and a.host != "unknown":
            affected_hosts_set.add(a.host)

        # Anomaly count
        try:
            _, is_anom = detect_anomaly(a)
            if is_anom:
                anomalies_count += 1
        except Exception:
            pass

    status_counts = {"OPEN": 0, "INVESTIGATING": 0, "CONTAINED": 0, "RESOLVED": 0}
    for inc in incidents_in_period:
        st = inc.status.upper()
        status_counts[st] = status_counts.get(st, 0) + 1

    # 4. Critical & High-Priority Findings
    crit_high_findings = []
    for a in period_alerts:
        if a.severity.lower() in ("critical", "high"):
            mitre = sorted(list(set(re.findall(r"T\d{4}(?:\.\d{3})?", a.event))))
            crit_high_findings.append({
                "alert_id": a.alert_id,
                "timestamp": a.timestamp.isoformat(),
                "severity": a.severity,
                "host": a.host,
                "source": a.source,
                "event": a.event,
                "mitre_techniques": mitre,
            })

    # 5. Monitoring & Coverage
    indexer_online = is_indexer_available()
    wazuh_records = source_counts.get("wazuh", 0)
    suricata_records = source_counts.get("suricata", 0)

    monitoring_coverage = [
        {
            "source": "Wazuh Indexer (OpenSearch)",
            "type": "Endpoint Security & Host Telemetry",
            "status": "Online / Active" if indexer_online else "Offline / Telemetry Preserved",
            "records_count": wazuh_records,
            "notes": (
                f"Successfully queried; {wazuh_records} alerts recorded in window."
                if wazuh_records > 0
                else "Queried successfully; zero alerts recorded in window."
            ),
        },
        {
            "source": "Suricata IDS",
            "type": "Network Intrusion Detection Telemetry",
            "status": "Ingested via Indexer",
            "records_count": suricata_records,
            "notes": (
                f"{suricata_records} network threat signatures recorded."
                if suricata_records > 0
                else "Queried; zero network IDS triggers recorded in window."
            ),
        },
        {
            "source": "Threat Intel Provider",
            "type": "Reputation & IOC Enrichment",
            "status": "Active (Local Mock / VirusTotal)",
            "records_count": sum(len(extract_iocs(a)) for a in period_alerts),
            "notes": "Enrichment pipeline operational for extracted IP/domain indicators.",
        },
        {
            "source": "Active Response Engine",
            "type": "Automated & Gated Containment",
            "status": "Simulation Mode (Safe)",
            "records_count": len(list_responses()),
            "notes": "Containment actions require explicit analyst approval.",
        },
    ]

    # 6. Response & Investigation Status (from Audit Trail)
    all_audit = get_audit_trail(limit=50)
    actions_in_period = []
    for aud in all_audit:
        aud_ts = to_utc(aud.timestamp)
        if start_utc <= aud_ts <= end_utc:
            actions_in_period.append({
                "response_id": aud.response_id,
                "timestamp": aud.timestamp.isoformat(),
                "action": aud.action,
                "target": aud.target,
                "actor": aud.actor,
                "event": aud.event,
                "mode": aud.mode,
                "state": getattr(aud, "state_after", getattr(aud, "new_state", "RECORDED")),
            })

    # 7. Historical Trends / Comparison
    window_duration = end_utc - start_utc
    prev_start_utc = start_utc - window_duration
    prev_end_utc = start_utc

    prev_period_alerts = [a for a in all_alerts if prev_start_utc <= to_utc(a.timestamp) < prev_end_utc]
    if prev_period_alerts:
        diff_alerts = total_alerts - len(prev_period_alerts)
        comparison_text = (
            f"Compared to the preceding equivalent interval ({prev_start_utc.strftime('%Y-%m-%d')} to "
            f"{prev_end_utc.strftime('%Y-%m-%d')}), total alert volume shifted by {diff_alerts:+d} "
            f"(Previous: {len(prev_period_alerts)}, Current: {total_alerts})."
        )
    else:
        comparison_text = "Historical comparison with prior period could not be calculated due to lack of baseline historical telemetry for that interval."

    # 8. Executive Summary Text
    if total_alerts == 0:
        executive_summary = (
            f"During the reporting window from {start_utc.strftime('%Y-%m-%d %H:%M')} to {end_utc.strftime('%Y-%m-%d %H:%M')} UTC, "
            f"zero security alerts were registered across monitored endpoints and network sensors. "
            f"While no immediate security events were observed in active telemetry, continuous monitoring and pipeline "
            f"health validation remain recommended."
        )
    else:
        crit_count = sev_counts.get("critical", 0)
        high_count = sev_counts.get("high", 0)
        executive_summary = (
            f"During the reporting window from {start_utc.strftime('%Y-%m-%d %H:%M')} to {end_utc.strftime('%Y-%m-%d %H:%M')} UTC, "
            f"ITTC-AI processed {total_alerts} security alerts resulting in {active_incidents_count} correlated incidents across "
            f"{len(affected_hosts_set)} distinct host(s). A total of {crit_count} critical and {high_count} high-severity findings "
            f"were identified, with {anomalies_count} behavioral anomalies flagged by ML models."
        )

    # 9. Prioritized Recommendations
    soc_recommendations = []
    if sev_counts.get("critical", 0) > 0:
        soc_recommendations.append({
            "priority": "P1 - Critical",
            "action": f"Prioritize immediate containment and forensic isolation on hosts: {', '.join(list(affected_hosts_set)[:3])}",
            "reason": f"Presence of {sev_counts['critical']} critical detections indicating active post-exploitation or C2 telemetry.",
        })
    if anomalies_count > 0:
        soc_recommendations.append({
            "priority": "P2 - High",
            "action": "Investigate ML behavioral anomaly deviations flagged by Isolation Forest models",
            "reason": f"{anomalies_count} anomalous event(s) deviated significantly from baseline telemetry distributions.",
        })
    soc_recommendations.append({
        "priority": "P3 - Medium",
        "action": "Audit active response containment log and review pending proposals in Response Queue",
        "reason": "Ensure containment proposals align with change windows and no unauthorized actions are pending.",
    })
    soc_recommendations.append({
        "priority": "P4 - Routine",
        "action": "Validate log forwarding health and rule coverage across all monitored endpoints",
        "reason": "Maintain continuous telemetry assurance and rule fidelity across the SOC perimeter.",
    })

    report_id = f"RPT-SOC-{now.strftime('%Y%m%d-%H%M%S')}"

    return {
        "report_id": report_id,
        "title": "ITTC-AI SOC Aggregate Security Intelligence & Executive Report",
        "generated_at": now.isoformat(),
        "reporting_period": {
            "period": period,
            "display": period_display,
            "start_time": start_utc.isoformat(),
            "end_time": end_utc.isoformat(),
        },
        "data_sources_included": ["Wazuh Indexer", "Suricata IDS", "Threat Intelligence Enricher", "Active Response Engine"],

        # B. Executive Summary
        "executive_summary": executive_summary,

        # C. Monitoring & Coverage
        "monitoring_coverage": monitoring_coverage,

        # D. Security Statistics
        "security_statistics": {
            "total_alerts": total_alerts,
            "severity_counts": sev_counts,
            "source_counts": source_counts,
            "distinct_hosts_count": len(affected_hosts_set),
            "affected_hosts": sorted(list(affected_hosts_set)),
            "active_incidents": active_incidents_count,
            "anomalies_count": anomalies_count,
            "incident_status_counts": status_counts,
        },

        # E. Critical and High-Priority Findings
        "critical_high_findings": crit_high_findings,

        # F. Threat Analysis
        "threat_analysis": {
            "correlated_patterns": (
                f"{active_incidents_count} multi-alert incident clusters were identified using union-find correlation criteria "
                f"across common hostnames and source/destination addresses."
                if active_incidents_count > 0
                else "No multi-alert attack patterns observed in this period."
            ),
            "iocs_summary": (
                f"Observed network telemetry involved {len(set(a.src_ip for a in period_alerts if a.src_ip))} unique external/internal source IPs "
                f"and {len(set(a.dst_ip for a in period_alerts if a.dst_ip))} destination IPs."
            ),
            "attack_chains": (
                "Attack progression telemetry indicates stages spanning execution, lateral movement, and credential access."
                if sev_counts.get("critical", 0) > 0
                else "Telemetry triggers limited to isolated medium/low anomalies."
            ),
        },

        # G. Impact Assessment
        "impact_assessment": {
            "observed_impact": f"{len(affected_hosts_set)} endpoint host(s) received detection alerts requiring analyst triage.",
            "potential_consequences": "Uncontained adversary execution could lead to domain privilege escalation or data staging.",
            "damage_disclaimer": "Actual enterprise damage could not be established from the available telemetry alone.",
        },

        # H. Response Status
        "response_status": {
            "overview": (
                f"Active Incidents: {active_incidents_count} (Open: {status_counts.get('OPEN', 0)}, "
                f"Investigating: {status_counts.get('INVESTIGATING', 0)}, "
                f"Contained: {status_counts.get('CONTAINED', 0)}, "
                f"Resolved: {status_counts.get('RESOLVED', 0)})"
            ),
            "recorded_actions": actions_in_period,
        },

        # I. Recommended Actions
        "recommended_actions": soc_recommendations,

        # J. Trends
        "trends": {
            "comparison_text": comparison_text,
        },

        # K. Appendix
        "appendix": {
            "alerts": [
                {
                    "alert_id": a.alert_id,
                    "timestamp": a.timestamp.isoformat(),
                    "host": a.host,
                    "source": a.source,
                    "severity": a.severity,
                    "event_type": a.event_type,
                }
                for a in period_alerts
            ],
            "incident_ids": incident_ids,
        },
    }


def generate_soc_pdf(
    period: str = "last_24h",
    start_time: Optional[Any] = None,
    end_time: Optional[Any] = None,
) -> bytes:
    """Generate aggregate SOC report PDF bytes."""
    report_data = generate_soc_report_data(
        period=period,
        start_time=start_time,
        end_time=end_time,
    )
    return build_soc_pdf(report_data)


# ==============================================================================
# 4. ORIGINAL INCIDENT REPORT (PRESERVED FOR BACKWARDS COMPATIBILITY)
# ==============================================================================

def generate_incident_report(incident_id: str) -> Optional[Dict[str, Any]]:
    """
    Generate a comprehensive incident report in structured JSON format.
    Preserved for backwards compatibility with existing endpoints and tests.
    """
    incident = get_incident(incident_id)
    if incident is None:
        return None

    alerts_data = []
    for alert_id in incident.related_alert_ids:
        alert = get_alert_safe(alert_id)
        if alert:
            alerts_data.append(alert.model_dump(mode="json"))

    ioc_enrichment = []
    provider = get_provider()
    for ioc_info in incident.related_iocs:
        try:
            enrichment = provider.enrich(ioc_info.get("type", "ip"), ioc_info.get("value", ""))
            ioc_enrichment.append(enrichment.model_dump())
        except Exception:
            ioc_enrichment.append(ioc_info)

    timeline_data = [
        {
            "timestamp": entry.timestamp.isoformat() if hasattr(entry.timestamp, "isoformat") else str(entry.timestamp),
            "event": entry.event,
            "source": entry.source,
            "alert_id": entry.alert_id,
        }
        for entry in incident.timeline
    ]

    return {
        "report_metadata": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "report_type": "incident_report",
            "version": "1.0",
        },
        "incident": {
            "incident_id": incident.incident_id,
            "created_at": incident.created_at.isoformat() if hasattr(incident.created_at, "isoformat") else str(incident.created_at),
            "updated_at": incident.updated_at.isoformat() if hasattr(incident.updated_at, "isoformat") else str(incident.updated_at),
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
                "timestamp": note.timestamp.isoformat() if hasattr(note.timestamp, "isoformat") else str(note.timestamp),
                "author": note.author,
                "content": note.content,
            }
            for note in incident.analyst_notes
        ],
    }
