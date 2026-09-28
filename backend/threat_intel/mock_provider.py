"""
Mock Threat Intelligence Provider — SYNTHETIC DATA ONLY.

WARNING: All enrichment data produced by this provider is SYNTHETIC and FICTIONAL.
         It does NOT represent real threat intelligence.
         It is intended only for local development and prototype testing.

The mock dataset uses:
  - 203.0.113.0/24  (TEST-NET-3 — RFC 5737, documentation range, not routable)
  - 198.51.100.0/24 (TEST-NET-2 — RFC 5737, documentation range, not routable)
  - *.test / *.example domains (IANA reserved, not resolvable on the real internet)

These ranges/domains are safe to use as synthetic malicious IOCs in documentation
and testing without misrepresenting any real infrastructure.
"""

from __future__ import annotations

from typing import Optional
from backend.threat_intel.models import IOCEnrichment

# ---------------------------------------------------------------------------
# Synthetic IOC database  (MOCK / SYNTHETIC DATA ONLY)
# ---------------------------------------------------------------------------
# Keys are normalised lowercase values.
# Values contain the raw enrichment fields.

_MOCK_DB: dict[str, dict] = {

    # ---- Synthetic malicious IPs (RFC 5737 TEST-NET ranges) ---------------
    "203.0.113.50": {
        "reputation": "malicious",
        "confidence": 0.97,
        "malicious": True,
        "categories": ["C2", "scanner"],
        "detections": 42,
        "malware_families": ["CobaltStrike"],
        "last_seen": "2026-08-25T14:32:00Z",
    },
    "203.0.113.100": {
        "reputation": "malicious",
        "confidence": 0.91,
        "malicious": True,
        "categories": ["C2", "phishing"],
        "detections": 31,
        "malware_families": ["Emotet"],
        "last_seen": "2026-08-22T09:10:00Z",
    },
    "198.51.100.25": {
        "reputation": "malicious",
        "confidence": 0.88,
        "malicious": True,
        "categories": ["scanner", "brute-force"],
        "detections": 19,
        "malware_families": [],
        "last_seen": "2026-08-27T11:00:00Z",
    },
    "198.51.100.77": {
        "reputation": "suspicious",
        "confidence": 0.65,
        "malicious": False,
        "categories": ["proxy", "anonymizer"],
        "detections": 7,
        "malware_families": [],
        "last_seen": "2026-08-20T06:45:00Z",
    },

    # ---- Synthetic malicious domains (IANA .test / .example) -------------
    "c2-example.test": {
        "reputation": "malicious",
        "confidence": 0.95,
        "malicious": True,
        "categories": ["C2"],
        "detections": 38,
        "malware_families": ["Sliver"],
        "last_seen": "2026-08-26T21:00:00Z",
    },
    "malicious-example.test": {
        "reputation": "malicious",
        "confidence": 0.99,
        "malicious": True,
        "categories": ["phishing", "malware-distribution"],
        "detections": 67,
        "malware_families": ["AgentTesla", "FormBook"],
        "last_seen": "2026-08-28T00:15:00Z",
    },
    "evil-update.example": {
        "reputation": "malicious",
        "confidence": 0.92,
        "malicious": True,
        "categories": ["malware-distribution"],
        "detections": 24,
        "malware_families": ["Raccoon"],
        "last_seen": "2026-08-24T17:30:00Z",
    },
    "sus-domain.example": {
        "reputation": "suspicious",
        "confidence": 0.60,
        "malicious": False,
        "categories": ["newly-registered"],
        "detections": 3,
        "malware_families": [],
        "last_seen": "2026-08-21T08:00:00Z",
    },

    # ---- Synthetic malicious file hashes ----------------------------------
    # SHA256 (64 hex)
    "aabbccdd" * 8: {
        "reputation": "malicious",
        "confidence": 0.98,
        "malicious": True,
        "categories": ["ransomware"],
        "detections": 58,
        "malware_families": ["LockBit"],
        "last_seen": "2026-08-23T12:00:00Z",
    },
    # MD5 (32 hex)
    "deadbeef" * 4: {
        "reputation": "malicious",
        "confidence": 0.85,
        "malicious": True,
        "categories": ["trojan"],
        "detections": 22,
        "malware_families": ["Trickbot"],
        "last_seen": "2026-08-19T10:20:00Z",
    },
}

_SOURCE_LABEL = "Mock Threat Intelligence (SYNTHETIC — not real data)"


class MockThreatIntelProvider:
    """
    Local, offline threat intelligence provider for development and testing.

    All data is SYNTHETIC. Do not interpret results as real threat intelligence.
    """

    def enrich(self, ioc_type: str, value: str) -> IOCEnrichment:
        """
        Return synthetic enrichment for an IOC value.

        If the value is in the synthetic database, return its record.
        Otherwise return an 'unknown' enrichment.
        """
        key = value.strip().lower()
        record = _MOCK_DB.get(key)

        if record:
            return IOCEnrichment(
                type=ioc_type,
                value=value,
                reputation=record["reputation"],
                confidence=record["confidence"],
                malicious=record["malicious"],
                source=_SOURCE_LABEL,
                categories=record.get("categories", []),
                detections=record.get("detections"),
                malware_families=record.get("malware_families", []),
                last_seen=record.get("last_seen"),
            )

        # Not in the synthetic database → unknown
        return IOCEnrichment(
            type=ioc_type,
            value=value,
            reputation="unknown",
            confidence=0.0,
            malicious=False,
            source=_SOURCE_LABEL,
            categories=[],
            detections=None,
            malware_families=[],
            last_seen=None,
        )
