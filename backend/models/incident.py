"""Incident and Correlation models for the ITTC-AI SOC platform."""

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
    affected_hosts: List[str] = Field(default_factory=list)


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


# ==============================================================================
# Run Correlation Models
# ==============================================================================

class CorrelationGroup(BaseModel):
    group_id: str
    alert_ids: List[str]
    relationship_types: List[str] = Field(default_factory=list)
    reasoning: str
    shared_iocs: List[Dict[str, str]] = Field(default_factory=list)
    hosts: List[str] = Field(default_factory=list)
    users: List[str] = Field(default_factory=list)
    lead_severity: str = "medium"
    lead_risk_score: int = 50
    alert_details: List[Dict[str, Any]] = Field(default_factory=list)


class ThreatIntelSummary(BaseModel):
    ioc: str
    ioc_type: str
    reputation: str = "unknown"
    malicious: bool = False
    provider_status: str = "available"
    malicious_count: Optional[int] = None
    suspicious_count: Optional[int] = None
    harmless_count: Optional[int] = None
    undetected_count: Optional[int] = None
    total_engines: Optional[int] = None
    reputation_score: Optional[int] = None
    categories: List[str] = Field(default_factory=list)
    source: str = "VirusTotal"
    analysis_timestamp: Optional[str] = None


class RAGFinding(BaseModel):
    title: str = ""
    topic: str = ""
    category: str = ""
    similarity_score: float = 0.0
    text: str = ""


class QwenCorrelatedAnalysis(BaseModel):
    summary: str
    correlation_reasoning: str
    risk_score: int = Field(ge=0, le=100, default=50)
    severity: str = "medium"
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    evidence: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    attack_pattern: str = ""
    recommendations: List[str] = Field(default_factory=list)


class CorrelationResult(BaseModel):
    correlation_run_id: str
    timestamp: datetime
    alerts_analyzed: int
    status: str  # "correlated" or "no_relation"
    message: str
    related_groups: List[CorrelationGroup] = Field(default_factory=list)
    iocs: List[Dict[str, str]] = Field(default_factory=list)
    threat_intelligence: List[ThreatIntelSummary] = Field(default_factory=list)
    rag_findings: List[RAGFinding] = Field(default_factory=list)
    qwen_analysis: Optional[QwenCorrelatedAnalysis] = None
    risk: int = 50
    severity: str = "medium"
    evidence: List[str] = Field(default_factory=list)
    correlation_reasoning: str = ""


class CorrelationRunResponse(BaseModel):
    """
    Response model for /api/incidents/correlate.
    Contains both the updated incident list for the existing dashboard table
    and the structured correlation_result for the popup modal.
    """
    incidents: List[Incident]
    correlation_result: CorrelationResult
