"""
Unit and integration tests for the SOC Email Notification Module (n8n webhook).
All external HTTP requests are strictly mocked using unittest.mock.
"""

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
import requests

from backend.models.alert import SecurityAlert
from backend.models.incident import Incident, TimelineEntry
from backend.services.incidents import clear_incidents, correlate_alerts, list_incidents
from backend.services.notifications import (
    NotificationResult,
    build_notification_payload,
    clear_notification_tracker,
    dispatch_incident_notification,
    extract_affected_hosts,
    extract_iocs_list,
    extract_recommended_action,
    get_notified_severity,
    should_notify,
)
from config import settings


@pytest.fixture(autouse=True)
def cleanup():
    """Reset incidents and notification history before and after each test."""
    clear_incidents()
    clear_notification_tracker()
    yield
    clear_incidents()
    clear_notification_tracker()


def make_test_incident(
    incident_id: str = "INC-TEST-001",
    severity: str = "high",
    risk_score: int = 75,
    confidence: float = 0.85,
    status: str = "OPEN",
    summary: str = "Correlated incident involving 2 alert(s) across host(s): SRV-DC-01, WKS-10",
    affected_hosts: list[str] = None,
    related_iocs: list = None,
    mitre_techniques: list[str] = None,
    response_recommendation: dict = None,
) -> Incident:
    now = datetime.now(timezone.utc)
    return Incident(
        incident_id=incident_id,
        created_at=now,
        updated_at=now,
        status=status,
        severity=severity,
        risk_score=risk_score,
        confidence=confidence,
        summary=summary,
        affected_hosts=affected_hosts if affected_hosts is not None else ["SRV-DC-01", "WKS-10"],
        related_iocs=related_iocs
        if related_iocs is not None
        else [{"type": "ip", "value": "198.51.100.23"}, {"type": "domain", "value": "evil.c2.net"}],
        mitre_techniques=mitre_techniques if mitre_techniques is not None else ["T1071.001", "T1059.001"],
        response_recommendation=response_recommendation
        if response_recommendation is not None
        else {
            "action": "BLOCK_IP",
            "target": "198.51.100.23",
            "reason": "Block active C2 outbound communication",
            "confidence": 0.9,
            "requires_approval": True,
        },
    )


# ==============================================================================
# Requirement 7.1: HIGH incident triggers notification
# ==============================================================================
def test_high_incident_triggers_notification():
    incident = make_test_incident(incident_id="INC-HIGH-1", severity="high")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = '{"status":"received"}'

    with patch("requests.post", return_value=mock_resp) as mock_post:
        result = dispatch_incident_notification(incident, webhook_url="https://n8n.example.com/webhook/soc")

        assert result.success is True
        assert result.notified is True
        assert result.status_code == 200
        assert mock_post.called
        assert mock_post.call_count == 1

        call_args, call_kwargs = mock_post.call_args
        assert call_args[0] == "https://n8n.example.com/webhook/soc"
        assert call_kwargs["json"]["severity"] == "HIGH"
        assert call_kwargs["json"]["incident_id"] == "INC-HIGH-1"


# ==============================================================================
# Requirement 7.2: CRITICAL incident triggers notification
# ==============================================================================
def test_critical_incident_triggers_notification():
    incident = make_test_incident(incident_id="INC-CRIT-1", severity="critical")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = '{"status":"received"}'

    with patch("requests.post", return_value=mock_resp) as mock_post:
        result = dispatch_incident_notification(incident, webhook_url="https://n8n.example.com/webhook/soc")

        assert result.success is True
        assert result.notified is True
        assert result.status_code == 200
        assert mock_post.call_count == 1
        assert mock_post.call_args[1]["json"]["severity"] == "CRITICAL"


# ==============================================================================
# Requirement: LOW incident triggers notification
# ==============================================================================
def test_low_incident_triggers_notification():
    incident = make_test_incident(incident_id="INC-LOW-1", severity="low")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = '{"status":"received"}'

    with patch("requests.post", return_value=mock_resp) as mock_post:
        result = dispatch_incident_notification(incident, webhook_url="https://n8n.example.com/webhook/soc")

        assert result.success is True
        assert result.notified is True
        assert result.status_code == 200
        assert mock_post.called
        assert mock_post.call_count == 1

        call_args, call_kwargs = mock_post.call_args
        assert call_args[0] == "https://n8n.example.com/webhook/soc"
        assert call_kwargs["json"]["severity"] == "LOW"
        assert call_kwargs["json"]["incident_id"] == "INC-LOW-1"


# ==============================================================================
# Requirement: MEDIUM incident triggers notification
# ==============================================================================
def test_medium_incident_triggers_notification():
    incident = make_test_incident(incident_id="INC-MED-1", severity="medium")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = '{"status":"received"}'

    with patch("requests.post", return_value=mock_resp) as mock_post:
        result = dispatch_incident_notification(incident, webhook_url="https://n8n.example.com/webhook/soc")

        assert result.success is True
        assert result.notified is True
        assert result.status_code == 200
        assert mock_post.called
        assert mock_post.call_count == 1

        call_args, call_kwargs = mock_post.call_args
        assert call_args[0] == "https://n8n.example.com/webhook/soc"
        assert call_kwargs["json"]["severity"] == "MEDIUM"
        assert call_kwargs["json"]["incident_id"] == "INC-MED-1"


# ==============================================================================
# Requirement 7.4: Missing N8N_WEBHOOK_URL does not break application
# ==============================================================================
def test_missing_n8n_webhook_url_does_not_break_application(monkeypatch):
    monkeypatch.setattr(settings, "N8N_WEBHOOK_URL", "")
    incident = make_test_incident(incident_id="INC-HIGH-UNCONFIGURED", severity="high")

    with patch("requests.post") as mock_post:
        result = dispatch_incident_notification(incident, webhook_url=None)
        assert result.success is False
        assert result.notified is False
        assert "not configured" in result.reason
        mock_post.assert_not_called()

    # Also verify correlation engine functions completely normally
    alerts = [
        SecurityAlert(
            alert_id="ALT-001",
            timestamp=datetime.now(timezone.utc),
            source="wazuh",
            severity="high",
            event_type="lateral_movement",
            event="Lateral movement detected via PsExec",
            host="DC-01",
        )
    ]
    incidents = correlate_alerts(alerts)
    assert len(incidents) == 1
    assert incidents[0].severity == "high"


# ==============================================================================
# Requirement 7.5: n8n timeout does not break incident creation
# ==============================================================================
def test_n8n_timeout_does_not_break_incident_creation(monkeypatch):
    monkeypatch.setattr(settings, "N8N_WEBHOOK_URL", "https://n8n.example.com/webhook/soc")
    incident = make_test_incident(incident_id="INC-TIMEOUT-1", severity="high")

    with patch("requests.post", side_effect=requests.exceptions.Timeout("Connection timed out after 5.0s")):
        result = dispatch_incident_notification(incident)
        assert result.success is False
        assert result.notified is False
        assert "Timeout" in result.error

    # Verify correlation pipeline does not raise when timeout happens
    alerts = [
        SecurityAlert(
            alert_id="ALT-TO-1",
            timestamp=datetime.now(timezone.utc),
            source="wazuh",
            severity="critical",
            event_type="ransomware",
            event="Active ransomware encryption",
            host="SRV-FS01",
        )
    ]
    with patch("requests.post", side_effect=requests.exceptions.Timeout("Gateway timeout")):
        correlated = correlate_alerts(alerts)
        assert len(correlated) == 1
        assert correlated[0].severity == "critical"
        assert list_incidents()[0].incident_id == correlated[0].incident_id


# ==============================================================================
# Requirement 7.6: n8n HTTP error does not break incident creation
# ==============================================================================
def test_n8n_http_error_does_not_break_incident_creation(monkeypatch):
    monkeypatch.setattr(settings, "N8N_WEBHOOK_URL", "https://n8n.example.com/webhook/soc")

    error_response = MagicMock()
    error_response.status_code = 502
    error_response.text = "Bad Gateway"

    incident = make_test_incident(incident_id="INC-ERR-1", severity="high")
    with patch("requests.post", return_value=error_response):
        result = dispatch_incident_notification(incident)
        assert result.success is False
        assert result.notified is False
        assert result.status_code == 502
        assert "HTTP 502" in result.error

    # Verify correlation pipeline continues cleanly despite 500 error
    alerts = [
        SecurityAlert(
            alert_id="ALT-ERR-1",
            timestamp=datetime.now(timezone.utc),
            source="wazuh",
            severity="high",
            event_type="c2_communication",
            event="Cobalt Strike Beacon",
            host="WS-05",
        )
    ]
    error_500 = MagicMock()
    error_500.status_code = 500
    error_500.text = "Internal Server Error"
    with patch("requests.post", return_value=error_500):
        correlated = correlate_alerts(alerts)
        assert len(correlated) == 1
        assert correlated[0].severity == "high"


# ==============================================================================
# Requirement 7.7: Duplicate notification is prevented & escalation preserved
# ==============================================================================
def test_duplicate_notification_is_prevented():
    incident = make_test_incident(incident_id="INC-DUP-1", severity="low")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = '{"status":"ok"}'

    with patch("requests.post", return_value=mock_resp) as mock_post:
        # First call (LOW): should notify
        res1 = dispatch_incident_notification(incident, webhook_url="https://n8n.example.com/webhook/soc")
        assert res1.success is True
        assert res1.notified is True
        assert mock_post.call_count == 1

        # Second call (same incident & LOW severity): duplicate prevented!
        res2 = dispatch_incident_notification(incident, webhook_url="https://n8n.example.com/webhook/soc")
        assert res2.success is True
        assert res2.notified is False
        assert "Duplicate notification prevented" in res2.reason
        assert mock_post.call_count == 1

        # Escalation to MEDIUM: should notify!
        incident.severity = "medium"
        res3 = dispatch_incident_notification(incident, webhook_url="https://n8n.example.com/webhook/soc")
        assert res3.success is True
        assert res3.notified is True
        assert mock_post.call_count == 2

        # Duplicate at MEDIUM: prevented!
        res4 = dispatch_incident_notification(incident, webhook_url="https://n8n.example.com/webhook/soc")
        assert res4.notified is False
        assert "Duplicate notification prevented" in res4.reason
        assert mock_post.call_count == 2

        # Escalation to HIGH: should notify!
        incident.severity = "high"
        res5 = dispatch_incident_notification(incident, webhook_url="https://n8n.example.com/webhook/soc")
        assert res5.success is True
        assert res5.notified is True
        assert mock_post.call_count == 3

        # Duplicate at HIGH: prevented!
        res6 = dispatch_incident_notification(incident, webhook_url="https://n8n.example.com/webhook/soc")
        assert res6.notified is False
        assert "Duplicate notification prevented" in res6.reason
        assert mock_post.call_count == 3

        # Escalation to CRITICAL: should notify!
        incident.severity = "critical"
        res7 = dispatch_incident_notification(incident, webhook_url="https://n8n.example.com/webhook/soc")
        assert res7.success is True
        assert res7.notified is True
        assert mock_post.call_count == 4

        # Duplicate at CRITICAL: prevented!
        res8 = dispatch_incident_notification(incident, webhook_url="https://n8n.example.com/webhook/soc")
        assert res8.notified is False
        assert "Duplicate notification prevented" in res8.reason
        assert mock_post.call_count == 4


# ==============================================================================
# Requirement 7.8: Payload contains required incident information
# ==============================================================================
def test_payload_contains_required_incident_information():
    incident = make_test_incident(
        incident_id="INC-PAYLOAD-123",
        severity="critical",
        risk_score=92,
        confidence=0.88,
        status="OPEN",
        summary="Executive summary: active multi-host C2 communication detected.",
        affected_hosts=["SERVER-AD-01", "DB-PROD-02"],
        related_iocs=[
            {"type": "ip", "value": "203.0.113.55"},
            {"type": "domain", "value": "c2-command.xyz"},
        ],
        mitre_techniques=["T1071.001", "T1059.001"],
        response_recommendation={
            "action": "ISOLATE_HOST",
            "target": "SERVER-AD-01",
            "reason": "Prevent lateral propagation across domain controller",
            "confidence": 0.95,
            "requires_approval": True,
        },
    )

    payload = build_notification_payload(incident)

    # 1. source
    assert payload["source"] == "ITTC-AI"
    # 2. incident_id
    assert payload["incident_id"] == "INC-PAYLOAD-123"
    # 3. severity
    assert payload["severity"] == "CRITICAL"
    # 4. risk_score
    assert payload["risk_score"] == 92
    assert isinstance(payload["risk_score"], int)
    # 5. confidence
    assert payload["confidence"] == 0.88
    assert isinstance(payload["confidence"], float)
    # 6. status
    assert payload["status"] == "OPEN"
    # 7. summary
    assert "active multi-host C2" in payload["summary"]
    # 8. affected_hosts
    assert payload["affected_hosts"] == ["DB-PROD-02", "SERVER-AD-01"]
    # 9. iocs
    assert payload["iocs"] == ["203.0.113.55", "c2-command.xyz"]
    # 10. mitre_techniques
    assert payload["mitre_techniques"] == ["T1071.001", "T1059.001"]
    # 11. recommended_action
    assert "ISOLATE_HOST" in payload["recommended_action"]
    assert "lateral propagation" in payload["recommended_action"]
    # 12. requires_approval
    assert payload["requires_approval"] is True
    # 13. timestamp
    assert "T" in payload["timestamp"]
    # Verify ISO format can be parsed
    parsed_dt = datetime.fromisoformat(payload["timestamp"])
    assert parsed_dt is not None


# ==============================================================================
# Helper extraction tests (affected_hosts, iocs, recommended_action)
# ==============================================================================
def test_extract_affected_hosts_fallback_from_summary():
    incident = Incident(
        incident_id="INC-FALLBACK-HOSTS",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
        status="OPEN",
        severity="high",
        summary="Correlated incident across host(s): HOST-A, HOST-B",
    )
    hosts = extract_affected_hosts(incident)
    assert hosts == ["HOST-A", "HOST-B"]


def test_extract_iocs_list_formats():
    incident = Incident(
        incident_id="INC-IOCS",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
        status="OPEN",
        severity="high",
        related_iocs=[
            {"type": "ip", "value": "1.2.3.4"},
            {"type": "hash", "value": "raw-hash-abc"},
            {"type": "domain", "value": "test.com"},
            {"type": "ip", "value": "1.2.3.4"},  # duplicate
        ],
    )
    iocs = extract_iocs_list(incident)
    assert iocs == ["1.2.3.4", "raw-hash-abc", "test.com"]

    # Also test handling when raw string items exist in untyped structure
    class RawIncident:
        related_iocs = ["direct-string-ioc", {"value": "from-dict"}]
    assert extract_iocs_list(RawIncident()) == ["direct-string-ioc", "from-dict"]


def test_extract_recommended_action_default():
    incident = Incident(
        incident_id="INC-DEFAULT-REC",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
        status="OPEN",
        severity="high",
    )
    rec = extract_recommended_action(incident)
    assert "Analyst review" in rec

import base64
from backend.main import trigger_correlation
from backend.services.reporting import (
    generate_daily_summary_report_data,
    generate_daily_summary_pdf,
    generate_incident_report,
)
from backend.services.notifications import (
    generate_daily_summary_and_notify,
    build_daily_summary_payload,
    dispatch_daily_summary_notification,
)


# ==============================================================================
# DAILY SOC SUMMARY NOTIFICATION & PDF ATTACHMENT TESTS
# ==============================================================================

def test_daily_summary_four_incidents_triggers_exactly_one_email():
    """Requirement: 4 incidents -> exactly 1 email with aggregated PDF."""
    incidents = [
        make_test_incident(incident_id=f"INC-{i}", severity=sev)
        for i, sev in enumerate(["critical", "high", "medium", "low"])
    ]
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = '{"status":"ok"}'

    with patch("requests.post", return_value=mock_resp) as mock_post:
        result = generate_daily_summary_and_notify(incidents=incidents, webhook_url="https://n8n.example.com/webhook/soc")
        assert result.success is True
        assert result.notified is True
        assert mock_post.call_count == 1
        payload = mock_post.call_args[1]["json"]
        assert payload["total_incidents"] == 4
        assert payload["notification_type"] == "daily_soc_summary"
        assert "ITTC-AI Daily SOC Summary - " in payload["subject"]


def test_daily_summary_one_incident_triggers_exactly_one_email():
    """Requirement: 1 incident -> exactly 1 email with aggregated PDF."""
    incident = make_test_incident(incident_id="INC-SINGLE-1", severity="high")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = '{"status":"ok"}'

    with patch("requests.post", return_value=mock_resp) as mock_post:
        result = generate_daily_summary_and_notify(incidents=[incident], webhook_url="https://n8n.example.com/webhook/soc")
        assert result.success is True
        assert result.notified is True
        assert mock_post.call_count == 1
        payload = mock_post.call_args[1]["json"]
        assert payload["total_incidents"] == 1


def test_daily_summary_zero_incidents_sends_no_email():
    """Requirement: 0 incidents -> no email dispatched."""
    with patch("requests.post") as mock_post:
        result = generate_daily_summary_and_notify(incidents=[], webhook_url="https://n8n.example.com/webhook/soc")
        assert result.success is True
        assert result.notified is False
        mock_post.assert_not_called()


def test_daily_summary_pdf_is_generated_and_contains_incident_summary():
    """Requirement: PDF is generated and contains the aggregated incident summary."""
    incidents = [
        make_test_incident(
            incident_id="INC-PDF-001",
            severity="critical",
            risk_score=95,
            confidence=0.92,
            affected_hosts=["SERVER-AD-01"],
            related_iocs=[{"type": "ip", "value": "203.0.113.10"}],
            mitre_techniques=["T1071.001"],
            summary="Cobalt strike beaconing detected",
        ),
        make_test_incident(
            incident_id="INC-PDF-002",
            severity="medium",
            risk_score=50,
            confidence=0.75,
            affected_hosts=["WORKSTATION-4"],
            summary="Suspicious port scan",
        ),
    ]

    report_data = generate_daily_summary_report_data(incidents=incidents)
    assert report_data["total_incidents"] == 2
    assert report_data["severity_counts"]["critical"] == 1
    assert report_data["severity_counts"]["medium"] == 1
    assert any(inc["incident_id"] == "INC-PDF-001" for inc in report_data["incidents"])
    assert any(inc["incident_id"] == "INC-PDF-002" for inc in report_data["incidents"])

    pdf_bytes = generate_daily_summary_pdf(incidents=incidents)
    assert isinstance(pdf_bytes, bytes)
    assert pdf_bytes.startswith(b"%PDF-")
    assert len(pdf_bytes) > 2000


def test_daily_summary_pdf_is_attached_to_notification_payload():
    """Requirement: PDF is attached to notification payload with valid base64 data."""
    incident = make_test_incident(incident_id="INC-ATT-1", severity="critical")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = '{"status":"ok"}'

    with patch("requests.post", return_value=mock_resp) as mock_post:
        result = generate_daily_summary_and_notify(incidents=[incident], webhook_url="https://n8n.example.com/webhook/soc")
        assert result.success is True
        assert mock_post.call_count == 1
        payload = mock_post.call_args[1]["json"]

        assert "attachment" in payload
        att = payload["attachment"]
        assert att["content_type"] == "application/pdf"
        assert att["filename"].endswith(".pdf")
        assert "data_base64" in att
        assert "pdf_base64" in payload
        assert att["data_base64"] == payload["pdf_base64"]

        # Validate base64 decodes to valid PDF bytes
        decoded = base64.b64decode(payload["pdf_base64"])
        assert decoded.startswith(b"%PDF-")


def test_email_failure_does_not_break_correlation():
    """Requirement: Email failure does not break correlation process or dashboard."""
    with patch("backend.services.notifications.requests.post", side_effect=requests.exceptions.Timeout("n8n timeout")):
        incidents = trigger_correlation()
        assert isinstance(incidents, list)
        assert len(incidents) >= 1


def test_demo_run_correlation_triggers_summary_workflow_with_exactly_one_email():
    """Requirement: Demo Run Correlation button triggers summary workflow and sends exactly 1 email."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = '{"status":"ok"}'

    with patch("backend.services.notifications.requests.post", return_value=mock_resp) as mock_post:
        incidents = trigger_correlation()
        assert len(incidents) >= 1

        # Exactly ONE daily summary email sent!
        assert mock_post.call_count == 1
        payload = mock_post.call_args[1]["json"]
        assert payload["notification_type"] == "daily_soc_summary"
        assert payload["total_incidents"] == len(incidents)
        assert "pdf_base64" in payload
        assert payload["attachment"]["content_type"] == "application/pdf"


def test_existing_notification_behavior_is_not_duplicated():
    """Requirement: Existing per-incident notification behavior is not duplicated."""
    with patch("requests.post") as mock_post:
        incidents = correlate_alerts()
        assert len(incidents) >= 1
        # correlate_alerts itself does not spam individual emails
        mock_post.assert_not_called()


def test_existing_individual_incident_report_still_works():
    """Requirement: Existing individual incident PDF/report still works intact."""
    incidents = correlate_alerts()
    assert len(incidents) >= 1
    lead_id = incidents[0].incident_id

    report = generate_incident_report(lead_id)
    assert report is not None
    assert "report_metadata" in report
    assert report["report_metadata"]["report_type"] == "incident_report"
    assert "incident" in report
    assert report["incident"]["incident_id"] == lead_id
    assert "timeline" in report
