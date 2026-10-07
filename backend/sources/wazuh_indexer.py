"""Wazuh Indexer (OpenSearch) alert source for ITTC AI."""

from datetime import datetime, timezone
from typing import Any, Optional

import requests

from config import settings
from backend.models.alert import SecurityAlert


class WazuhIndexerError(RuntimeError):
    """Base exception for Wazuh Indexer communication and parsing errors."""
    pass


class WazuhIndexerConnectionError(WazuhIndexerError):
    """Raised when the Wazuh Indexer is unreachable or connection times out."""
    pass


class WazuhIndexerAuthError(WazuhIndexerError):
    """Raised when authentication with the Wazuh Indexer fails."""
    pass


def _severity(level: Any) -> str:
    try:
        value = int(level or 0)
    except (TypeError, ValueError):
        value = 0

    if value >= 12:
        return "critical"
    if value >= 8:
        return "high"
    if value >= 4:
        return "medium"
    return "low"


def _to_alert(hit: dict[str, Any]) -> SecurityAlert:
    """
    Normalize an OpenSearch/Wazuh Indexer search hit into a standard SecurityAlert.
    Supports both native Wazuh agent telemetry and Suricata IDS alerts.
    """
    doc = hit.get("_source", {})
    data = doc.get("data") if isinstance(doc.get("data"), dict) else {}
    rule = doc.get("rule") if isinstance(doc.get("rule"), dict) else {}
    agent = doc.get("agent") if isinstance(doc.get("agent"), dict) else {}
    predecoder = doc.get("predecoder") if isinstance(doc.get("predecoder"), dict) else {}
    groups = rule.get("groups") or []

    # Timestamp normalization
    raw_timestamp = (
        doc.get("@timestamp")
        or doc.get("timestamp")
        or data.get("timestamp")
    )
    try:
        timestamp = datetime.fromisoformat(
            str(raw_timestamp).replace("Z", "+00:00")
        ) if raw_timestamp else datetime.now(timezone.utc)
    except (ValueError, TypeError):
        timestamp = datetime.now(timezone.utc)

    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)

    # Source detection: prioritize explicit data.source, then check groups/predecoder
    source = str(data.get("source") or "").lower()
    suricata_indicators = (
        "suricata" in groups
        or "ids" in groups
        or "suricata" in str(predecoder.get("program_name", "")).lower()
        or "suricata" in str(rule.get("description", "")).lower()
        or isinstance(data.get("alert"), dict)
    )
    if not source:
        source = "suricata" if suricata_indicators else "wazuh"

    # User context extraction with Windows Event / Sysmon fallbacks
    win_data = data.get("win") if isinstance(data.get("win"), dict) else {}
    win_eventdata = win_data.get("eventdata") if isinstance(win_data.get("eventdata"), dict) else {}
    user = (
        data.get("srcuser")
        or data.get("dstuser")
        or data.get("user")
        or win_eventdata.get("targetUserName")
        or win_eventdata.get("subjectUserName")
    )

    # IP extraction with Suricata dest_ip alias and Sysmon fallbacks
    src_ip = (
        data.get("src_ip")
        or data.get("srcip")
        or win_eventdata.get("sourceIp")
    )
    dst_ip = (
        data.get("dst_ip")
        or data.get("dest_ip")
        or data.get("dstip")
        or win_eventdata.get("destinationIp")
    )

    # Suricata nested alert payload handling
    suricata_alert = data.get("alert") if isinstance(data.get("alert"), dict) else {}
    suricata_sig = suricata_alert.get("signature") if suricata_alert else None
    suricata_cat = suricata_alert.get("category") if suricata_alert else None

    # Event description normalization
    event = str(
        rule.get("description")
        or suricata_sig
        or data.get("signature")
        or doc.get("full_log")
        or "Wazuh security event"
    )

    # Event type normalization
    event_type = str(
        suricata_cat
        or data.get("event_type")
        or (groups[0] if groups else "security_alert")
    )

    # Rule ID extraction
    rule_id = None
    if rule.get("id") is not None:
        rule_id = str(rule["id"])
    elif suricata_alert and suricata_alert.get("signature_id") is not None:
        rule_id = str(suricata_alert["signature_id"])

    # Host extraction
    host = str(
        agent.get("name")
        or doc.get("agent", {}).get("name") if isinstance(doc.get("agent"), dict) else None
        or data.get("host")
        or doc.get("hostname")
        or "unknown"
    )

    return SecurityAlert(
        alert_id=str(hit.get("_id") or doc.get("id") or ""),
        timestamp=timestamp,
        source=source,
        severity=_severity(rule.get("level")),
        host=host,
        user=user,
        src_ip=src_ip,
        dst_ip=dst_ip,
        event_type=event_type,
        event=event,
        rule_id=rule_id,
    )


def get_wazuh_alerts(
    limit: Optional[int] = None,
    offset: int = 0,
) -> list[SecurityAlert]:
    """
    Fetch newest alerts from configured Wazuh Indexer with pagination support.
    Raises sanitized exceptions on network/authentication failures.
    """
    base_url = settings.WAZUH_INDEXER_URL.rstrip("/")
    index = settings.WAZUH_INDEXER_INDEX
    effective_limit = limit if limit is not None else settings.WAZUH_INDEXER_LIMIT

    try:
        response = requests.get(
            f"{base_url}/{index}/_search",
            auth=(settings.WAZUH_INDEXER_USERNAME,
                  settings.WAZUH_INDEXER_PASSWORD),
            params={
                "size": effective_limit,
                "from": max(0, offset),
                "sort": "timestamp:desc",
            },
            timeout=10,
            verify=settings.WAZUH_INDEXER_VERIFY_TLS,
        )
    except requests.exceptions.SSLError as e:
        raise WazuhIndexerConnectionError(
            f"TLS verification failed connecting to Wazuh Indexer at '{base_url}'. "
            "Set WAZUH_INDEXER_VERIFY_TLS=false if using self-signed certificates."
        ) from e
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
        raise WazuhIndexerConnectionError(
            f"Unable to connect to Wazuh Indexer at '{base_url}'. "
            "Verify host is reachable and service is running on port 9200."
        ) from e
    except requests.exceptions.RequestException as e:
        raise WazuhIndexerError(f"Wazuh Indexer request error: {e}") from e

    if response.status_code in (401, 403):
        raise WazuhIndexerAuthError(
            f"Authentication failed for Wazuh Indexer at '{base_url}'. "
            "Verify WAZUH_INDEXER_USERNAME and WAZUH_INDEXER_PASSWORD."
        )

    if response.status_code != 200:
        raise WazuhIndexerError(
            f"Wazuh Indexer returned HTTP {response.status_code}: {response.text[:200]}"
        )

    payload = response.json()
    hits = payload.get("hits", {}).get("hits", [])
    return [_to_alert(hit) for hit in hits]


def get_wazuh_alert(alert_id: str) -> SecurityAlert | None:
    """
    Find an alert by querying the configured index pattern directly by _id,
    with fallback to linear scan of recent alerts.
    """
    base_url = settings.WAZUH_INDEXER_URL.rstrip("/")
    index = settings.WAZUH_INDEXER_INDEX

    # Attempt direct targeted search by _id
    search_payload = {
        "query": {
            "ids": {
                "values": [alert_id]
            }
        },
        "size": 1
    }
    try:
        response = requests.post(
            f"{base_url}/{index}/_search",
            auth=(settings.WAZUH_INDEXER_USERNAME,
                  settings.WAZUH_INDEXER_PASSWORD),
            json=search_payload,
            timeout=10,
            verify=settings.WAZUH_INDEXER_VERIFY_TLS,
        )
        if response.status_code == 200:
            hits = response.json().get("hits", {}).get("hits", [])
            if hits:
                return _to_alert(hits[0])
    except Exception:
        pass  # Fall back to scan

    for alert in get_wazuh_alerts():
        if alert.alert_id == alert_id:
            return alert
    return None


def check_wazuh_indexer_status() -> dict[str, Any]:
    """
    Check Wazuh Indexer connectivity safely without exposing credentials.
    Returns status dictionary with connection diagnostics.
    """
    base_url = settings.WAZUH_INDEXER_URL.rstrip("/")
    result: dict[str, Any] = {
        "url": base_url,
        "index": settings.WAZUH_INDEXER_INDEX,
        "verify_tls": settings.WAZUH_INDEXER_VERIFY_TLS,
        "reachable": False,
        "authenticated": False,
        "credentials_configured": bool(
            settings.WAZUH_INDEXER_USERNAME and settings.WAZUH_INDEXER_PASSWORD
        ),
        "error": None,
    }

    try:
        auth = (
            (settings.WAZUH_INDEXER_USERNAME, settings.WAZUH_INDEXER_PASSWORD)
            if result["credentials_configured"]
            else None
        )
        resp = requests.get(
            f"{base_url}/",
            auth=auth,
            timeout=3,
            verify=settings.WAZUH_INDEXER_VERIFY_TLS,
        )
        result["reachable"] = True
        if resp.status_code == 200:
            result["authenticated"] = True
        elif resp.status_code in (401, 403):
            result["error"] = f"Authentication rejected (HTTP {resp.status_code})"
        else:
            result["error"] = f"Unexpected status (HTTP {resp.status_code})"
    except requests.exceptions.SSLError as e:
        result["error"] = "TLS verification failed. Set WAZUH_INDEXER_VERIFY_TLS=false if self-signed."
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
        result["error"] = f"Connection timed out or host unreachable at {base_url}."
    except Exception as e:
        result["error"] = f"Check failed: {str(e)}"

    return result

