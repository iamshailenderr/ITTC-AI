"""
SOC Email Notification Module — ITTC-AI.

Responsible for detecting notifiable incidents (LOW, MEDIUM, HIGH, and CRITICAL), building
a structured incident payload, and dispatching webhook requests to n8n.
n8n is responsible for email delivery to SOC analysts.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests
from pydantic import BaseModel, Field

from config import settings
from backend.models.incident import Incident

logger = logging.getLogger("ittc_ai.notifications")

# Notifiable severity threshold: all 4 severities are eligible
NOTIFIABLE_SEVERITIES = {"low", "medium", "high", "critical"}

# In-memory duplicate protection tracker:
# maps incident_id -> last notified severity ("low", "medium", "high", or "critical")
_notification_tracker: Dict[str, str] = {}


class NotificationResult(BaseModel):
    """Result object returned by notification dispatch."""
    success: bool
    notified: bool
    incident_id: Optional[str] = None
    severity: Optional[str] = None
    status_code: Optional[int] = None
    reason: str = ""
    error: Optional[str] = None


def clear_notification_tracker() -> None:
    """Clear all duplicate notification history (used in tests and state resets)."""
    _notification_tracker.clear()


def get_notified_severity(incident_id: str) -> Optional[str]:
    """Return the last notified severity level for an incident, or None."""
    return _notification_tracker.get(incident_id)


def extract_affected_hosts(incident: Incident) -> List[str]:
    """
    Extract a deduplicated, sorted list of affected hostnames from the incident.
    Prioritizes incident.affected_hosts, then alert lookup, then summary parsing.
    """
    hosts: set[str] = set()

    # 1. Direct model attribute if populated
    if getattr(incident, "affected_hosts", None):
        for h in incident.affected_hosts:
            if h and h != "N/A":
                hosts.add(str(h).strip())

    # 2. Look up from related alert records
    if not hosts and getattr(incident, "related_alert_ids", None):
        try:
            from backend.services.alerts import get_alert
            for alert_id in incident.related_alert_ids:
                try:
                    alert = get_alert(alert_id)
                    if alert and getattr(alert, "host", None) and alert.host != "N/A":
                        hosts.add(str(alert.host).strip())
                except Exception:
                    pass
        except Exception:
            pass

    # 3. Fallback: Parse from executive summary if present
    if not hosts and getattr(incident, "summary", None):
        match = re.search(r"host\(s\):\s*([^.\n\r]+)", incident.summary, re.IGNORECASE)
        if match:
            for part in match.group(1).split(","):
                cleaned = part.strip()
                if cleaned and cleaned != "N/A":
                    hosts.add(cleaned)

    return sorted(list(hosts))


def extract_iocs_list(incident: Incident) -> List[str]:
    """
    Extract a deduplicated list of IOC strings from related IOC records.
    Handles both dict format ({'type': ..., 'value': ...}) and raw string items.
    """
    iocs: List[str] = []
    seen: set[str] = set()

    for item in (getattr(incident, "related_iocs", None) or []):
        val = ""
        if isinstance(item, dict):
            val = item.get("value", "")
        elif isinstance(item, str):
            val = item
        val = str(val).strip()
        if val and val not in seen:
            seen.add(val)
            iocs.append(val)

    return iocs


def extract_recommended_action(incident: Incident) -> str:
    """
    Extract a concise, analyst-actionable recommendation string.
    Combines response recommendation action and reason where available.
    """
    rec = getattr(incident, "response_recommendation", None)
    if isinstance(rec, dict):
        action = rec.get("action", "").strip()
        reason = rec.get("reason", "").strip()
        target = rec.get("target", "").strip()

        if action and reason:
            return f"{action}: {reason}"
        if action and target:
            return f"{action} target {target}"
        if action:
            return action

    # Fallback to incident recommendations list
    recs = getattr(incident, "recommendations", None)
    if recs and isinstance(recs, list) and len(recs) > 0 and recs[0]:
        return str(recs[0]).strip()

    return "Analyst review and containment verification required"


def build_notification_payload(incident: Incident) -> Dict[str, Any]:
    """
    Build the structured JSON payload for n8n email delivery.
    Conforms to the required ITTC-AI SOC notification contract.
    """
    # Normalize timestamp
    ts = getattr(incident, "updated_at", None) or getattr(incident, "created_at", None)
    if hasattr(ts, "isoformat"):
        iso_timestamp = ts.isoformat()
    elif ts:
        iso_timestamp = str(ts)
    else:
        iso_timestamp = datetime.now(timezone.utc).isoformat()

    return {
        "source": "ITTC-AI",
        "incident_id": incident.incident_id,
        "severity": incident.severity.upper(),
        "risk_score": int(incident.risk_score),
        "confidence": float(round(incident.confidence, 2)),
        "status": str(incident.status),
        "summary": str(incident.summary),
        "affected_hosts": extract_affected_hosts(incident),
        "iocs": extract_iocs_list(incident),
        "mitre_techniques": list(getattr(incident, "mitre_techniques", None) or []),
        "recommended_action": extract_recommended_action(incident),
        "requires_approval": True,
        "timestamp": iso_timestamp,
    }


def should_notify(incident: Incident) -> Tuple[bool, str]:
    """
    Determine whether an incident qualifies for notification and pass duplicate checks.

    Rules:
    - LOW / MEDIUM / HIGH / CRITICAL -> notify
    - Duplicate protection:
      - Already notified at this severity -> skip
      - Already notified at higher severity -> skip
      - Severity escalated (e.g., LOW -> MEDIUM, HIGH -> CRITICAL) -> allow notification
    """
    sev = (incident.severity or "").strip().lower()

    if sev not in NOTIFIABLE_SEVERITIES:
        return False, f"Severity '{incident.severity}' does not meet threshold"

    last_notified = _notification_tracker.get(incident.incident_id)
    if last_notified is not None:
        severity_rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        current_rank = severity_rank.get(sev, 0)
        previous_rank = severity_rank.get(last_notified, 0)

        if current_rank <= previous_rank:
            return False, (
                f"Duplicate notification prevented: already notified for incident "
                f"{incident.incident_id} at severity '{last_notified.upper()}'"
            )

    return True, "Incident qualifies for notification"


def dispatch_incident_notification(
    incident: Incident,
    webhook_url: Optional[str] = None,
    timeout: Optional[float] = None,
) -> NotificationResult:
    """
    Evaluate incident, construct payload, and POST to configured n8n webhook.
    Guaranteed never to raise exceptions that could break the incident pipeline.
    """
    try:
        qualifies, reason = should_notify(incident)
        if not qualifies:
            logger.debug(
                "Notification skipped for %s (%s): %s",
                incident.incident_id, incident.severity, reason
            )
            return NotificationResult(
                success=True,
                notified=False,
                incident_id=incident.incident_id,
                severity=incident.severity.upper(),
                reason=reason,
            )

        # Resolve webhook URL
        target_url = webhook_url if webhook_url is not None else getattr(settings, "N8N_WEBHOOK_URL", "")
        target_url = (target_url or "").strip()

        if not target_url:
            msg = "Notification delivery is not configured: N8N_WEBHOOK_URL is missing or empty."
            logger.warning(msg)
            return NotificationResult(
                success=False,
                notified=False,
                incident_id=incident.incident_id,
                severity=incident.severity.upper(),
                reason=msg,
            )

        # Resolve request timeout
        req_timeout = timeout if timeout is not None else getattr(settings, "N8N_WEBHOOK_TIMEOUT", 5.0)

        # Build payload
        payload = build_notification_payload(incident)

        logger.info(
            "Dispatching SOC notification for incident %s [%s] to n8n webhook: %s",
            incident.incident_id, incident.severity.upper(), target_url
        )

        response = requests.post(
            target_url,
            json=payload,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "ITTC-AI-Notification-Service/1.0",
            },
            timeout=req_timeout,
        )

        if 200 <= response.status_code < 300:
            # Record duplicate state upon successful delivery
            _notification_tracker[incident.incident_id] = incident.severity.strip().lower()
            logger.info(
                "SOC notification successfully delivered for incident %s to n8n [HTTP %d]",
                incident.incident_id, response.status_code
            )
            return NotificationResult(
                success=True,
                notified=True,
                incident_id=incident.incident_id,
                severity=incident.severity.upper(),
                status_code=response.status_code,
                reason="Notification successfully delivered to n8n webhook",
            )
        else:
            err_msg = f"n8n webhook returned HTTP {response.status_code}: {response.text[:200]}"
            logger.error(
                "n8n notification delivery failed for incident %s: %s",
                incident.incident_id, err_msg
            )
            return NotificationResult(
                success=False,
                notified=False,
                incident_id=incident.incident_id,
                severity=incident.severity.upper(),
                status_code=response.status_code,
                error=err_msg,
                reason="n8n webhook HTTP error response",
            )

    except requests.exceptions.Timeout as e:
        err_msg = f"Timeout after {req_timeout}s connecting to n8n webhook"
        logger.error(
            "Notification timeout for incident %s: %s",
            incident.incident_id, err_msg
        )
        return NotificationResult(
            success=False,
            notified=False,
            incident_id=incident.incident_id,
            severity=incident.severity.upper(),
            error=err_msg,
            reason="n8n webhook connection timeout",
        )

    except requests.exceptions.RequestException as e:
        err_msg = f"Network/HTTP request error: {str(e)}"
        logger.error(
            "Notification request failed for incident %s: %s",
            incident.incident_id, err_msg
        )
        return NotificationResult(
            success=False,
            notified=False,
            incident_id=incident.incident_id,
            severity=incident.severity.upper(),
            error=err_msg,
            reason="n8n webhook request failure",
        )

    except Exception as e:
        err_msg = f"Unexpected notification error: {str(e)}"
        logger.exception(
            "Unexpected error in notification service for incident %s: %s",
            getattr(incident, "incident_id", "unknown"), err_msg
        )
        return NotificationResult(
            success=False,
            notified=False,
            incident_id=getattr(incident, "incident_id", None),
            severity=getattr(incident, "severity", "").upper() if getattr(incident, "severity", None) else None,
            error=err_msg,
            reason="Unexpected internal notification service error",
        )


import base64


# ==============================================================================
# FEATURE: AGGREGATED DAILY SOC SUMMARY NOTIFICATION & N8N WEBHOOK DISPATCH
# ==============================================================================

def build_daily_summary_payload(
    report_data: Dict[str, Any],
    pdf_bytes: bytes,
    filename: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Build structured JSON payload for n8n daily summary email delivery with PDF attachment.
    """
    date_str = report_data.get("report_date", datetime.now(timezone.utc).strftime("%Y-%m-%d"))
    if not filename:
        filename = f"ITTC_AI_Daily_SOC_Summary_{date_str.replace('-', '')}.pdf"

    pdf_b64 = base64.b64encode(pdf_bytes).decode("utf-8")
    monitoring_period = report_data.get("reporting_period", {}).get("display", f"Last 24 Hours ({date_str})")
    total_alerts = report_data.get("total_alerts", 0)
    total_incidents = report_data.get("total_incidents", 0)
    sev_counts = report_data.get("severity_counts", {"critical": 0, "high": 0, "medium": 0, "low": 0})
    risk_summary = report_data.get("overall_risk_summary", "")
    statement = "The comprehensive Daily SOC Summary PDF report is attached with full incident dossiers and telemetry evidence."

    body_text = (
        f"ITTC-AI Security Operations Center — Daily SOC Summary\n"
        f"====================================================\n\n"
        f"Monitoring Period: {monitoring_period}\n"
        f"Total Alerts Processed: {total_alerts}\n"
        f"Total Correlated Incidents: {total_incidents}\n\n"
        f"Incident Severity Breakdown:\n"
        f"  • Critical: {sev_counts.get('critical', 0)}\n"
        f"  • High:     {sev_counts.get('high', 0)}\n"
        f"  • Medium:   {sev_counts.get('medium', 0)}\n"
        f"  • Low:      {sev_counts.get('low', 0)}\n\n"
        f"Risk Summary:\n{risk_summary}\n\n"
        f"{statement}\n"
    )

    return {
        "source": "ITTC-AI",
        "notification_type": "daily_soc_summary",
        "subject": f"ITTC-AI Daily SOC Summary - {date_str}",
        "monitoring_period": monitoring_period,
        "total_alerts": total_alerts,
        "total_incidents": total_incidents,
        "severity_counts": sev_counts,
        "overall_risk_summary": risk_summary,
        "statement": statement,
        "body": body_text,
        "attachment": {
            "filename": filename,
            "content_type": "application/pdf",
            "data_base64": pdf_b64,
            "size_bytes": len(pdf_bytes),
        },
        "pdf_base64": pdf_b64,
        "pdf_filename": filename,
        "incidents": [
            {
                "incident_id": inc.get("incident_id"),
                "severity": inc.get("severity"),
                "risk_score": inc.get("risk_score"),
                "affected_hosts": inc.get("affected_hosts", []),
                "summary": inc.get("summary", ""),
            }
            for inc in report_data.get("incidents", [])
        ],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def dispatch_daily_summary_notification(
    payload: Dict[str, Any],
    webhook_url: Optional[str] = None,
    timeout: Optional[float] = None,
) -> NotificationResult:
    """
    POST structured daily summary payload with attached PDF to configured n8n webhook.
    Guaranteed never to raise exceptions that could break the application pipeline.
    """
    try:
        target_url = webhook_url if webhook_url is not None else getattr(settings, "N8N_WEBHOOK_URL", "")
        target_url = (target_url or "").strip()

        if not target_url:
            msg = "Notification delivery is not configured: N8N_WEBHOOK_URL is missing or empty."
            logger.warning(msg)
            return NotificationResult(
                success=False,
                notified=False,
                reason=msg,
            )

        req_timeout = timeout if timeout is not None else getattr(settings, "N8N_WEBHOOK_TIMEOUT", 5.0)

        logger.info(
            "Dispatching Daily SOC Summary email notification [%s] to n8n webhook: %s",
            payload.get("subject", "Daily SOC Summary"), target_url
        )

        response = requests.post(
            target_url,
            json=payload,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "ITTC-AI-Daily-Summary-Service/1.0",
            },
            timeout=req_timeout,
        )

        if 200 <= response.status_code < 300:
            logger.info("Daily SOC Summary notification successfully delivered to n8n [HTTP %d]", response.status_code)
            return NotificationResult(
                success=True,
                notified=True,
                status_code=response.status_code,
                reason="Daily SOC Summary notification successfully delivered to n8n webhook",
            )
        else:
            err_msg = f"n8n webhook returned HTTP {response.status_code}: {response.text[:200]}"
            logger.error("n8n notification delivery failed: %s", err_msg)
            return NotificationResult(
                success=False,
                notified=False,
                status_code=response.status_code,
                error=err_msg,
                reason="n8n webhook HTTP error response",
            )

    except requests.exceptions.Timeout as e:
        err_msg = f"Timeout after {req_timeout}s connecting to n8n webhook"
        logger.error("Daily summary notification timeout: %s", err_msg)
        return NotificationResult(
            success=False,
            notified=False,
            error=err_msg,
            reason="n8n webhook connection timeout",
        )

    except requests.exceptions.RequestException as e:
        err_msg = f"Network/HTTP request error: {str(e)}"
        logger.error("Daily summary notification request failed: %s", err_msg)
        return NotificationResult(
            success=False,
            notified=False,
            error=err_msg,
            reason="n8n webhook request failure",
        )

    except Exception as e:
        err_msg = f"Unexpected notification error: {str(e)}"
        logger.exception("Unexpected error in daily summary notification service: %s", err_msg)
        return NotificationResult(
            success=False,
            notified=False,
            error=err_msg,
            reason="Unexpected internal notification service error",
        )


def generate_daily_summary_and_notify(
    incidents: Optional[List[Incident]] = None,
    webhook_url: Optional[str] = None,
    timeout: Optional[float] = None,
    period_hours: int = 24,
) -> NotificationResult:
    """
    Orchestrate Daily SOC Summary workflow:
    1. Resolve active 24h incidents (or use provided list).
    2. If 0 incidents, skip notification without error (0 incidents -> no email).
    3. Generate the aggregated Daily SOC Summary PDF.
    4. Construct structured email payload with PDF attached.
    5. Dispatch exactly ONE email to n8n webhook.
    """
    try:
        from backend.services.incidents import list_incidents
        if incidents is None:
            incidents = list_incidents()

        # Requirement: 0 incidents -> no email
        if not incidents:
            logger.info("Daily SOC Summary notification skipped: zero incidents.")
            return NotificationResult(
                success=True,
                notified=False,
                reason="Zero incidents found; daily summary email skipped",
            )

        # 1. Generate Report Data & PDF
        from backend.services.reporting import (
            generate_daily_summary_report_data,
            generate_daily_summary_pdf,
        )
        try:
            report_data = generate_daily_summary_report_data(incidents=incidents, period_hours=period_hours)
            pdf_bytes = generate_daily_summary_pdf(incidents=incidents, period_hours=period_hours)
        except Exception as e:
            err_msg = f"Failed to generate Daily SOC Summary PDF: {str(e)}"
            logger.error(err_msg, exc_info=True)
            return NotificationResult(
                success=False,
                notified=False,
                error=err_msg,
                reason="Daily summary PDF generation error",
            )

        # 2. Build Payload
        payload = build_daily_summary_payload(report_data=report_data, pdf_bytes=pdf_bytes)

        # 3. Dispatch Notification
        return dispatch_daily_summary_notification(
            payload=payload,
            webhook_url=webhook_url,
            timeout=timeout,
        )

    except Exception as e:
        err_msg = f"Unexpected error in generate_daily_summary_and_notify: {str(e)}"
        logger.error(err_msg, exc_info=True)
        return NotificationResult(
            success=False,
            notified=False,
            error=err_msg,
            reason="Internal summary workflow error",
        )
