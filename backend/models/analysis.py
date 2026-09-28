"""
AI Analysis data contract.
Defines the output schema for the AI pipeline.
No LLM calls happen here — this is purely the response model.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class RiskFactor(BaseModel):
    """A single explainable risk factor contributing to the overall risk score."""
    factor: str
    impact: int = Field(ge=0, le=100, description="Impact contribution 0-100")
    evidence: str


class ResponseRecommendation(BaseModel):
    """Structured response recommendation — recommendation only, not execution."""
    action: str  # BLOCK_IP, ISOLATE_HOST, DISABLE_USER, TERMINATE_PROCESS, INVESTIGATE_ONLY
    target: str
    reason: str
    confidence: float = Field(ge=0.0, le=1.0)
    requires_approval: bool = True


class RAGSource(BaseModel):
    """A RAG knowledge source used during analysis."""
    document: str
    topic: str = ""
    relevance: float = Field(ge=0.0, le=1.0)
    category: str = ""


class AIAnalysis(BaseModel):
    summary: str
    risk_score: int = Field(ge=0, le=100)
    severity: str
    mitre_techniques: List[str]
    hypothesis: str
    confidence: float = Field(ge=0.0, le=1.0)
    kill_chain_stage: str
    evidence: List[str]
    recommendations: List[str]
    # Optional — populated when TI enrichment is available.
    # Not sent to the LLM schema; attached after LLM parsing.
    ioc_enrichment: Optional[List[Dict[str, Any]]] = None
    # RAG source documents used for grounding
    rag_sources: Optional[List[RAGSource]] = None
    # Explainable risk factors
    risk_factors: Optional[List[RiskFactor]] = None
    # Anomaly detection results
    anomaly_score: Optional[float] = None
    is_anomalous: Optional[bool] = None
    # Response recommendation
    response_recommendation: Optional[ResponseRecommendation] = None
