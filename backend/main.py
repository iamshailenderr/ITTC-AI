"""
P2 FastAPI backend — entry point.
Exposes REST endpoints for the AI pipeline, incident management,
IOC investigation, SOC Copilot, and dashboard.
"""

from typing import Any, Dict, List
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from backend.models.alert import SecurityAlert
from backend.models.analysis import AIAnalysis
from backend.models.incident import (
    Incident,
    IncidentStatusUpdate,
    IncidentNoteRequest,
    CopilotRequest,
    CopilotResponse,
)
from backend.services.alerts import get_alerts, get_alert
from backend.ai.analyzer import analyze_alert
from backend.services.incidents import (
    list_incidents,
    get_incident,
    correlate_alerts,
    update_incident_status,
    add_incident_note,
)
from backend.services.ioc_investigator import investigate_ioc, IOCInvestigation
from backend.ai.copilot import copilot_chat
from backend.services.reporting import generate_incident_report

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
# Health
# ==========================================

@app.get("/health")
def health_check() -> dict:
    return {"status": "ok", "service": "ittc-ai"}


# ==========================================
# Alert Endpoints (Preserved)
# ==========================================

@app.get("/api/alerts", response_model=List[SecurityAlert])
def list_alerts() -> List[SecurityAlert]:
    """Return all normalized security alerts."""
    return get_alerts()


@app.get("/api/alerts/{alert_id}", response_model=SecurityAlert)
def read_alert(alert_id: str) -> SecurityAlert:
    """Return a single alert by ID."""
    alert = get_alert(alert_id)
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
        return analyze_alert(alert)
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
        incidents = correlate_alerts()
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
    return correlate_alerts()


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

@app.post("/api/copilot/chat", response_model=CopilotResponse)
def copilot_chat_endpoint(request: CopilotRequest) -> CopilotResponse:
    """
    Chat with the RAG-grounded AI SOC Copilot.
    Accepts question, optional incident_id, alert_id, and history.
    """
    return copilot_chat(request)


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
