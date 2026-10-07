"""
P2 FastAPI backend — entry point.
Exposes REST endpoints for the AI pipeline, incident management,
IOC investigation, SOC Copilot, and dashboard.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Security, Depends, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
from starlette.staticfiles import StaticFiles

from config import settings
from backend.models.alert import SecurityAlert
from backend.models.analysis import AIAnalysis
from backend.models.response import (
    ResponseRecord,
    ResponseProposalRequest,
    ResponseApprovalRequest,
    ResponseRejectionRequest,
    AuditLogEntry,
    ResponseAction,
)
from backend.models.incident import (
    Incident,
    IncidentStatusUpdate,
    IncidentNoteRequest,
    CopilotRequest,
    CopilotResponse,
)
from backend.services.alerts import get_alerts, get_alert
from backend.sources.wazuh_indexer import (
    check_wazuh_indexer_status,
    WazuhIndexerConnectionError,
    WazuhIndexerAuthError,
)
from backend.ai.analyzer import analyze_alert
from backend.services.incidents import (
    list_incidents,
    get_incident,
    correlate_alerts,
    update_incident_status,
    add_incident_note,
)
from backend.services.ioc_investigator import investigate_ioc, IOCInvestigation
from backend.services.active_response import (
    propose_response,
    approve_response,
    reject_response,
    rollback_response,
    list_responses,
    get_response,
    get_audit_trail,
    check_wazuh_manager_status,
)
from backend.ai.copilot import copilot_chat
from backend.services.reporting import generate_incident_report

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def verify_api_key(api_key: Optional[str] = Security(api_key_header)) -> bool:
    """
    Enforce API key authentication on sensitive response endpoints when configured.
    If settings.API_KEY is unset/empty, runs in permissive local dev mode.
    """
    configured_key = getattr(settings, "API_KEY", None)
    if configured_key:
        if not api_key or api_key != configured_key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Unauthorized: Missing or invalid X-API-Key header",
            )
    return True


app = FastAPI(title="ITTC AI Security Intelligence API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500",
        "*",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==========================================
# Health & Status
# ==========================================

@app.get("/health")
def health_check() -> dict:
    return {"status": "ok", "service": "ittc-ai"}


@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    from fastapi import Response
    return Response(status_code=204)


@app.get("/api/status/wazuh")
@app.get("/api/wazuh/status")
def get_wazuh_status() -> dict:
    """Return diagnostic status of Wazuh Indexer and Wazuh Manager connections without exposing credentials."""
    return {
        "alert_source": settings.ALERT_SOURCE,
        "indexer": check_wazuh_indexer_status(),
        "manager": check_wazuh_manager_status(),
    }


# ==========================================
# Alert Endpoints (Preserved)
# ==========================================

@app.get("/api/alerts", response_model=List[SecurityAlert])
def list_alerts(fallback: bool = False) -> List[SecurityAlert]:
    """Return all normalized security alerts with graceful error handling."""
    try:
        return get_alerts()
    except (WazuhIndexerConnectionError, WazuhIndexerAuthError) as e:
        if fallback:
            from backend.sources.mock import get_mock_alerts
            return get_mock_alerts()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Wazuh Indexer unavailable: {str(e)}",
        )


@app.get("/api/alerts/{alert_id}", response_model=SecurityAlert)
def read_alert(alert_id: str, fallback: bool = False) -> SecurityAlert:
    """Return a single alert by ID."""
    try:
        alert = get_alert(alert_id)
    except (WazuhIndexerConnectionError, WazuhIndexerAuthError) as e:
        if fallback:
            from backend.sources.mock import get_mock_alerts
            for a in get_mock_alerts():
                if a.alert_id == alert_id:
                    return a
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Wazuh Indexer unavailable: {str(e)}",
        )
    if alert is None:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found")
    return alert


@app.post("/api/analyze/{alert_id}", response_model=AIAnalysis)
def run_analysis(alert_id: str) -> AIAnalysis:
    """Run AI analysis on a specific alert."""
    alert = get_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found")
    try:
        analysis = analyze_alert(alert)
        if analysis.response_recommendation:
            rec = analysis.response_recommendation
            try:
                action_name = rec.action.upper()
                if action_name in ResponseAction.__members__:
                    propose_response(ResponseProposalRequest(
                        action=ResponseAction[action_name],
                        target=rec.target,
                        alert_id=alert_id,
                        reason=rec.reason,
                        confidence=rec.confidence,
                    ))
            except Exception:
                pass  # Proposing should never break the analysis response
        return analysis
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))



# ==========================================
# Incident Endpoints
# ==========================================

@app.get("/api/incidents", response_model=List[Incident])
def get_all_incidents() -> List[Incident]:
    """
    Return all incidents.
    If no incidents exist yet, automatically runs initial correlation.
    """
    incidents = list_incidents()
    if not incidents:
        try:
            incidents = correlate_alerts()
        except (WazuhIndexerConnectionError, WazuhIndexerAuthError):
            incidents = []
    return incidents


@app.get("/api/incidents/{incident_id}", response_model=Incident)
def read_incident(incident_id: str) -> Incident:
    """Return a single incident by ID."""
    incident = get_incident(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")
    return incident


@app.post("/api/incidents/correlate", response_model=List[Incident])
def trigger_correlation() -> List[Incident]:
    """Trigger alert correlation and return resulting incidents."""
    try:
        return correlate_alerts()
    except (WazuhIndexerConnectionError, WazuhIndexerAuthError) as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Wazuh Indexer unavailable: {str(e)}",
        )


@app.patch("/api/incidents/{incident_id}/status", response_model=Incident)
def set_incident_status(incident_id: str, update: IncidentStatusUpdate) -> Incident:
    """Update the status of an incident (OPEN, INVESTIGATING, CONTAINED, RESOLVED)."""
    try:
        incident = update_incident_status(incident_id, update.status)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")
    return incident


@app.post("/api/incidents/{incident_id}/notes", response_model=Incident)
def add_note_to_incident(incident_id: str, note_req: IncidentNoteRequest) -> Incident:
    """Add an analyst note to an incident."""
    incident = add_incident_note(incident_id, note_req.content, note_req.author)
    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")
    return incident


@app.get("/api/incidents/{incident_id}/report")
def get_incident_report_endpoint(incident_id: str) -> Dict[str, Any]:
    """Generate and return a structured JSON incident report."""
    report = generate_incident_report(incident_id)
    if report is None:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")
    return report


# ==========================================
# IOC Investigation Endpoint
# ==========================================

@app.get("/api/ioc/{ioc_type}/{ioc_value:path}", response_model=IOCInvestigation)
def get_ioc_investigation(ioc_type: str, ioc_value: str) -> IOCInvestigation:
    """
    Investigate an IOC (IP, domain, URL, hash).
    Returns threat intelligence enrichment and related alerts/incidents.
    """
    valid_types = {"ip", "domain", "url", "md5", "sha1", "sha256"}
    if ioc_type.lower() not in valid_types:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid IOC type '{ioc_type}'. Valid types: {sorted(list(valid_types))}"
        )
    return investigate_ioc(ioc_type.lower(), ioc_value)


# ==========================================
# AI SOC Copilot Endpoint
# ==========================================
# AI SOC Copilot Endpoint
# ==========================================

@app.post("/api/copilot/chat", response_model=CopilotResponse)
def copilot_chat_endpoint(request: CopilotRequest) -> CopilotResponse:
    """
    Chat with the RAG-grounded AI SOC Copilot.
    Accepts question, optional incident_id, alert_id, and history.
    """
    return copilot_chat(request)


# ==========================================
# Active Response Endpoints
# ==========================================

@app.get("/api/responses", response_model=List[ResponseRecord])
def get_all_responses(
    state: Optional[str] = None,
    alert_id: Optional[str] = None,
) -> List[ResponseRecord]:
    """List all Active Response records with optional state or alert_id filtering."""
    return list_responses(state=state, alert_id=alert_id)


@app.get("/api/responses/{response_id}", response_model=ResponseRecord)
def read_response_record(response_id: str) -> ResponseRecord:
    """Get a specific Active Response record by ID."""
    record = get_response(response_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Response record '{response_id}' not found")
    return record


@app.post("/api/responses/propose", response_model=ResponseRecord, dependencies=[Depends(verify_api_key)])
def propose_active_response(req: ResponseProposalRequest) -> ResponseRecord:
    """Propose an Active Response action with safeguard validation and duplicate protection."""
    try:
        record, is_duplicate = propose_response(req)
        return record
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/responses/{response_id}/approve", response_model=ResponseRecord, dependencies=[Depends(verify_api_key)])
def approve_active_response(
    response_id: str,
    req: ResponseApprovalRequest,
) -> ResponseRecord:
    """Approve and trigger an Active Response action (simulated dry-run by default)."""
    try:
        return approve_response(response_id, req)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Response record '{response_id}' not found")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/responses/{response_id}/reject", response_model=ResponseRecord, dependencies=[Depends(verify_api_key)])
def reject_active_response(
    response_id: str,
    req: ResponseRejectionRequest,
) -> ResponseRecord:
    """Reject a proposed response with analyst justification."""
    try:
        return reject_response(response_id, req)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Response record '{response_id}' not found")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/responses/{response_id}/rollback", response_model=ResponseRecord, dependencies=[Depends(verify_api_key)])
def rollback_active_response(
    response_id: str,
    actor: str = "soc_analyst",
) -> ResponseRecord:
    """Roll back an executed action (e.g. UNBLOCK_IP for BLOCK_IP)."""
    try:
        return rollback_response(response_id, actor=actor)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Response record '{response_id}' not found")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/responses/audit/log", response_model=List[AuditLogEntry])
def get_audit_trail_endpoint(limit: int = 100) -> List[AuditLogEntry]:
    """Retrieve append-only Active Response audit log entries, newest first."""
    return get_audit_trail(limit=limit)


# ==========================================
# Exception Handling
# ==========================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc: HTTPException) -> JSONResponse:
    """Pass through HTTP exceptions with proper status codes and details."""
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request, exc: Exception) -> JSONResponse:
    """Catch unhandled exceptions — log internally and never expose stack traces."""
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )


# ==========================================
# Static Files — Serve Primary SOC UI
# ==========================================

_FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"
if _FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=str(_FRONTEND_DIR), html=True), name="frontend")

