"""
Incident model for the ITTC-AI SOC platform.

An Incident groups correlated security alerts into a single investigable entity.
Status lifecycle: OPEN → INVESTIGATING → CONTAINED → RESOLVED
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class TimelineEntry(BaseModel):
    """A single event in the incident timeline."""
    timestamp: datetime
    event: str
    source: str = ""
    alert_id: Optional[str] = None


class AnalystNote(BaseModel):
    """A note added by an analyst during investigation."""
    timestamp: datetime
    author: str = "analyst"
    content: str


class Incident(BaseModel):
    """
    Correlated security incident grouping related alerts.

    Status values:
        OPEN         — newly created, not yet investigated
        INVESTIGATING — analyst is actively working the incident
        CONTAINED    — threat has been contained, pending resolution
        RESOLVED     — incident fully resolved and closed
    """
    incident_id: str
    created_at: datetime
    updated_at: datetime
    status: str = "OPEN"  # OPEN | INVESTIGATING | CONTAINED | RESOLVED
    severity: str = "medium"
    risk_score: int = Field(ge=0, le=100, default=50)
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    related_alert_ids: List[str] = []
    related_iocs: List[Dict[str, str]] = []  # [{"type": "ip", "value": "..."}]
    mitre_techniques: List[str] = []
    timeline: List[TimelineEntry] = []
    summary: str = ""
    evidence: List[str] = []
    recommendations: List[str] = []
    anomaly_score: Optional[float] = None
    is_anomalous: Optional[bool] = None
    risk_factors: Optional[List[Dict[str, Any]]] = None
    response_recommendation: Optional[Dict[str, Any]] = None
    analyst_notes: List[AnalystNote] = []


# Request/response models for API endpoints

class IncidentStatusUpdate(BaseModel):
    """Request body for PATCH /api/incidents/{id}/status"""
    status: str  # OPEN | INVESTIGATING | CONTAINED | RESOLVED


class IncidentNoteRequest(BaseModel):
    """Request body for POST /api/incidents/{id}/notes"""
    content: str
    author: str = "analyst"


class CopilotRequest(BaseModel):
    """Request body for POST /api/copilot/chat"""
    question: str
    incident_id: Optional[str] = None
    alert_id: Optional[str] = None
    history: Optional[List[Dict[str, str]]] = None  # [{"role": "user/assistant", "content": "..."}]


class CopilotResponse(BaseModel):
    """Response body for POST /api/copilot/chat"""
    answer: str
    sources: List[Dict[str, Any]] = []
    context: Dict[str, Any] = {}
