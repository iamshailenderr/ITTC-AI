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

    reputation:
        malicious   - confirmed threat
        suspicious  - elevated risk
        benign      - known safe
        unknown     - no data available

    source is labelled "Mock Threat Intelligence (SYNTHETIC)"
    for the local mock provider so analysts know it is not real data.
    """
    type: str
    value: str
    reputation: str                         # malicious | suspicious | benign | unknown
    confidence: float                       # 0.0 – 1.0
    malicious: bool
    source: str
    categories: List[str] = []
    detections: Optional[int] = None        # e.g. 42 out of 72 engines
    malware_families: List[str] = []
    last_seen: Optional[str] = None         # ISO-8601 string or None
