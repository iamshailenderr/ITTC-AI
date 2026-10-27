"""Incident model for the ITTC-AI SOC platform."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class TimelineEntry(BaseModel):
    timestamp: datetime
    event: str
    source: str = ""
    alert_id: Optional[str] = None


class AnalystNote(BaseModel):
    timestamp: datetime
    author: str = "analyst"
    content: str


class Incident(BaseModel):
    incident_id: str
    created_at: datetime
    updated_at: datetime
    status: str = "OPEN"
    severity: str = "medium"
    risk_score: int = Field(ge=0, le=100, default=50)
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    related_alert_ids: List[str] = []
    related_iocs: List[Dict[str, str]] = []
    ioc_intelligence: List[Dict[str, Any]] = []
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


class IncidentStatusUpdate(BaseModel):
    status: str


class IncidentNoteRequest(BaseModel):
    content: str
    author: str = "analyst"


class CopilotRequest(BaseModel):
    question: str
    incident_id: Optional[str] = None
    alert_id: Optional[str] = None
    history: Optional[List[Dict[str, str]]] = None


class CopilotResponse(BaseModel):
    answer: str
    sources: List[Dict[str, Any]] = []
    context: Dict[str, Any] = {}
