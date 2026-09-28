"""
VirusTotal Threat Intelligence Provider — OPTIONAL.

This provider is only active when the environment variable VIRUSTOTAL_API_KEY is set.
If the key is absent, the system automatically falls back to MockThreatIntelProvider.

Environment variable:
    VIRUSTOTAL_API_KEY   — your VirusTotal public or private API key

SECURITY NOTE:
    - Never hardcode your API key in source code.
    - Add VIRUSTOTAL_API_KEY to .gitignore / environment secrets.
    - The free public API is rate-limited (4 req/min, 500 req/day).

VirusTotal API v3 documentation:
    https://docs.virustotal.com/reference/overview
"""

from __future__ import annotations

import os
from typing import Optional

from backend.threat_intel.models import IOCEnrichment

# Optional dependency — only imported if provider is actually used
try:
    import requests as _requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False

_VT_BASE = "https://www.virustotal.com/api/v3"
_VT_TIMEOUT = 15  # seconds


class VirusTotalProvider:
    """
    Optional VirusTotal v3 API provider.

    Plug-in point for real threat intelligence.
    Only instantiate this class when VIRUSTOTAL_API_KEY is present.
    """

    def __init__(self, api_key: str) -> None:
        if not _REQUESTS_AVAILABLE:
            raise RuntimeError(
                "The 'requests' package is required for VirusTotalProvider. "
                "Install it with: pip install requests"
            )
        self._api_key = api_key
        self._headers = {"x-apikey": api_key, "Accept": "application/json"}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get(self, endpoint: str) -> Optional[dict]:
        """Perform a GET request to the VT API; return parsed JSON or None."""
        try:
            response = _requests.get(
                f"{_VT_BASE}{endpoint}",
                headers=self._headers,
                timeout=_VT_TIMEOUT,
            )
            if response.status_code == 200:
                return response.json()
            # 404 → not found, 429 → rate limited
            return None
        except Exception:
            return None

    def _parse_stats(self, data: dict) -> tuple[str, float, bool, int]:
        """
        Parse analysis_stats from a VT response into
        (reputation, confidence, malicious, detections).
        """
        stats: dict = (
            data.get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
        )
        malicious_count = stats.get("malicious", 0)
        suspicious_count = stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 0
        detections = malicious_count + suspicious_count

        if total == 0:
            return "unknown", 0.0, False, 0

        ratio = detections / total
        if malicious_count >= 3:
            reputation = "malicious"
            malicious = True
        elif suspicious_count >= 3 or ratio >= 0.05:
            reputation = "suspicious"
            malicious = False
        else:
            reputation = "benign"
            malicious = False

        confidence = min(1.0, round(ratio * 2, 2))   # rough heuristic
        return reputation, confidence, malicious, detections

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def enrich(self, ioc_type: str, value: str) -> IOCEnrichment:
        """
        Query VirusTotal for a given IOC and return structured enrichment.

        Supported types: ip, domain, url, md5, sha1, sha256.
        Unknown types return an 'unknown' enrichment without an API call.
        """
        endpoint_map = {
            "ip":     f"/ip_addresses/{value}",
            "domain": f"/domains/{value}",
            "url":    f"/urls/{value}",
            "md5":    f"/files/{value}",
            "sha1":   f"/files/{value}",
            "sha256": f"/files/{value}",
        }

        endpoint = endpoint_map.get(ioc_type.lower())
        if not endpoint:
            return IOCEnrichment(
                type=ioc_type, value=value,
                reputation="unknown", confidence=0.0,
                malicious=False, source="VirusTotal",
            )

        data = self._get(endpoint)
        if not data:
            return IOCEnrichment(
                type=ioc_type, value=value,
                reputation="unknown", confidence=0.0,
                malicious=False, source="VirusTotal",
            )

        reputation, confidence, malicious, detections = self._parse_stats(data)
        attrs = data.get("data", {}).get("attributes", {})

        categories_raw = attrs.get("categories", {})
        if isinstance(categories_raw, dict):
            categories = list(set(categories_raw.values()))
        elif isinstance(categories_raw, list):
            categories = categories_raw
        else:
            categories = []

        # malware families (files only)
        names_raw = attrs.get("popular_threat_classification", {})
        malware_families: list[str] = []
        if isinstance(names_raw, dict):
            malware_families = [
                e.get("value", "") for e in names_raw.get("popular_threat_name", [])
            ]

        last_seen_ts = attrs.get("last_analysis_date") or attrs.get("last_seen_itw_date")
        last_seen: Optional[str] = None
        if last_seen_ts:
            import datetime
            last_seen = datetime.datetime.utcfromtimestamp(last_seen_ts).isoformat() + "Z"

        return IOCEnrichment(
            type=ioc_type,
            value=value,
            reputation=reputation,
            confidence=confidence,
            malicious=malicious,
            source="VirusTotal",
            categories=categories,
            detections=detections,
            malware_families=malware_families,
            last_seen=last_seen,
        )


def get_virustotal_provider() -> Optional[VirusTotalProvider]:
    """
    Return a VirusTotalProvider if VIRUSTOTAL_API_KEY is set in environment.
    Returns None if the key is absent (caller should use MockThreatIntelProvider).
    """
    api_key = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
    if not api_key:
        return None
    return VirusTotalProvider(api_key)
