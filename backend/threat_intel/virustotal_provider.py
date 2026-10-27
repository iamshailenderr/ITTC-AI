"""VirusTotal v3 threat-intelligence provider."""

from __future__ import annotations

import base64
import datetime as _dt
import os
from typing import Optional

from backend.threat_intel.models import IOCEnrichment

try:
    import requests as _requests
except ImportError:  # pragma: no cover
    _requests = None

_VT_BASE = "https://www.virustotal.com/api/v3"
_VT_TIMEOUT = 15


class VirusTotalProvider:
    """VirusTotal API v3 provider for IPs, domains, URLs and file hashes."""

    def __init__(self, api_key: str, timeout: int = _VT_TIMEOUT) -> None:
        if _requests is None:
            raise RuntimeError("The 'requests' package is required for VirusTotalProvider")
        if not api_key or not api_key.strip():
            raise ValueError("VirusTotal API key is required")
        self._api_key = api_key.strip()
        self._timeout = timeout
        self._headers = {"x-apikey": self._api_key, "Accept": "application/json"}

    @staticmethod
    def _url_id(value: str) -> str:
        return base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii").rstrip("=")

    def _unavailable(self, ioc_type: str, value: str, reason: str = "unavailable") -> IOCEnrichment:
        return IOCEnrichment(type=ioc_type, value=value, reputation="unknown", confidence=0.0, malicious=False, source="VirusTotal", provider_status="unavailable", categories=[reason] if reason else [])

    def _get(self, endpoint: str) -> tuple[Optional[dict], Optional[str]]:
        try:
            response = _requests.get(f"{_VT_BASE}{endpoint}", headers=self._headers, timeout=self._timeout)
        except _requests.exceptions.Timeout:
            return None, "timeout"
        except _requests.exceptions.RequestException:
            return None, "network_error"
        except Exception:
            return None, "network_error"
        if response.status_code == 200:
            try:
                return response.json(), None
            except ValueError:
                return None, "invalid_response"
        if response.status_code in (401, 403):
            return None, "invalid_api_key"
        if response.status_code == 404:
            return None, "not_found"
        if response.status_code == 429:
            return None, "rate_limited"
        if 500 <= response.status_code < 600:
            return None, "service_unavailable"
        return None, f"http_{response.status_code}"

    @staticmethod
    def _parse_stats(data: dict) -> dict:
        attrs = data.get("data", {}).get("attributes", {}) or {}
        stats = attrs.get("last_analysis_stats", {}) or {}
        malicious_count = int(stats.get("malicious", 0) or 0)
        suspicious_count = int(stats.get("suspicious", 0) or 0)
        harmless_count = int(stats.get("harmless", 0) or 0)
        undetected_count = int(stats.get("undetected", 0) or 0)
        total = malicious_count + suspicious_count + harmless_count + undetected_count
        detections = malicious_count + suspicious_count

        if total == 0:
            reputation, malicious, confidence = "unknown", False, 0.0
        elif malicious_count >= 3 or (malicious_count > 0 and malicious_count / total >= 0.10):
            reputation, malicious = "malicious", True
            confidence = min(1.0, round(malicious_count / total * 1.5, 2))
        elif suspicious_count >= 3 or suspicious_count / total >= 0.05:
            reputation, malicious = "suspicious", False
            confidence = min(1.0, round(suspicious_count / total * 1.5, 2))
        else:
            reputation, malicious = "benign", False
            confidence = round(max(harmless_count, undetected_count) / total, 2)

        categories_raw = attrs.get("categories", {})
        if isinstance(categories_raw, dict):
            categories = sorted({str(v) for v in categories_raw.values() if v})
        elif isinstance(categories_raw, list):
            categories = [str(v) for v in categories_raw if v]
        else:
            categories = []

        reputation_score = attrs.get("reputation")
        try:
            reputation_score = int(reputation_score) if reputation_score is not None else None
        except (TypeError, ValueError):
            reputation_score = None

        malware_families: list[str] = []
        classification = attrs.get("popular_threat_classification", {}) or {}
        if isinstance(classification, dict):
            names = classification.get("popular_threat_name", []) or []
            if isinstance(names, list):
                malware_families = [str(item.get("value")) for item in names if isinstance(item, dict) and item.get("value")]

        analysis_timestamp = None
        ts = attrs.get("last_analysis_date")
        if ts:
            try:
                analysis_timestamp = _dt.datetime.fromtimestamp(int(ts), tz=_dt.timezone.utc).isoformat()
            except (TypeError, ValueError, OSError):
                pass

        return {"reputation": reputation, "malicious": malicious, "confidence": confidence, "malicious_count": malicious_count, "suspicious_count": suspicious_count, "harmless_count": harmless_count, "undetected_count": undetected_count, "total_engines": total, "detections": detections, "categories": categories, "reputation_score": reputation_score, "malware_families": malware_families, "analysis_timestamp": analysis_timestamp}

    def enrich(self, ioc_type: str, value: str) -> IOCEnrichment:
        normalized_type = ioc_type.lower().strip()
        normalized_value = value.strip()
        endpoint_map = {
            "ip": f"/ip_addresses/{normalized_value}",
            "domain": f"/domains/{normalized_value}",
            "url": f"/urls/{self._url_id(normalized_value)}",
            "md5": f"/files/{normalized_value}",
            "sha1": f"/files/{normalized_value}",
            "sha256": f"/files/{normalized_value}",
        }
        endpoint = endpoint_map.get(normalized_type)
        if not endpoint:
            return self._unavailable(normalized_type, normalized_value, "unsupported_type")
        data, error = self._get(endpoint)
        if data is None:
            return self._unavailable(normalized_type, normalized_value, error or "unavailable")
        parsed = self._parse_stats(data)
        return IOCEnrichment(type=normalized_type, value=normalized_value, source="VirusTotal", provider_status="available", last_seen=parsed["analysis_timestamp"], analysis_timestamp=parsed["analysis_timestamp"], **{k: v for k, v in parsed.items() if k != "analysis_timestamp"})


def get_virustotal_provider() -> Optional[VirusTotalProvider]:
    api_key = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
    if not api_key:
        return None
    try:
        return VirusTotalProvider(api_key)
    except Exception:
        return None
