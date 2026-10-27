"""
Threat Intelligence data models.

IOC: a single extracted indicator (IP, domain, hash, URL).
IOCEnrichment: the result of querying a threat intelligence provider for an IOC.
"""

from __future__ import annotations
from typing import List, Optional
from pydantic import BaseModel


class IOC(BaseModel):
    """A single extracted Indicator of Compromise."""
    type: str   # "ip", "domain", "url", "md5", "sha1", "sha256"
    value: str


class IOCEnrichment(BaseModel):
    """
    Threat intelligence enrichment result for a single IOC.

    provider_status is deliberately explicit so the UI/AI layer can distinguish
    real provider data from an unavailable provider or offline synthetic fallback.
    """
    type: str
    value: str
    reputation: str                         # malicious | suspicious | benign | unknown
    confidence: float                       # 0.0 – 1.0
    malicious: bool
    source: str
    provider_status: str = "available"      # available | fallback | unavailable
    categories: List[str] = []
    detections: Optional[int] = None        # malicious + suspicious detections
    malicious_count: Optional[int] = None
    suspicious_count: Optional[int] = None
    harmless_count: Optional[int] = None
    undetected_count: Optional[int] = None
    total_engines: Optional[int] = None
    reputation_score: Optional[int] = None
    malware_families: List[str] = []
    last_seen: Optional[str] = None
    analysis_timestamp: Optional[str] = None
