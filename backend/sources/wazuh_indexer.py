"""Wazuh Indexer (OpenSearch) alert source for ITTC AI."""

from datetime import datetime, timezone
from typing import Any

import requests

from config import settings
from backend.models.alert import SecurityAlert


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
    doc = hit.get("_source", {})
    data = doc.get("data") or {}
    rule = doc.get("rule") or {}
    agent = doc.get("agent") or {}
    groups = rule.get("groups") or []

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

    source = str(data.get("source") or "")
    if not source:
        source = "suricata" if "suricata" in groups else "wazuh"

    event_type = str(
        data.get("event_type")
        or (groups[0] if groups else "security_alert")
    )

    return SecurityAlert(
        alert_id=str(hit.get("_id") or doc.get("id") or ""),
        timestamp=timestamp,
        source=source,
        severity=_severity(rule.get("level")),
        host=str(agent.get("name") or "unknown"),
        user=data.get("srcuser") or data.get("dstuser") or data.get("user"),
        src_ip=data.get("src_ip"),
        dst_ip=data.get("dst_ip"),
        event_type=event_type,
        event=str(
            rule.get("description")
            or data.get("signature")
            or doc.get("full_log")
            or "Wazuh security event"
        ),
        rule_id=str(rule["id"]) if rule.get("id") is not None else None,
    )


def get_wazuh_alerts() -> list[SecurityAlert]:
    """Fetch the newest alerts from the configured Wazuh Indexer."""
    base_url = settings.WAZUH_INDEXER_URL.rstrip("/")
    index = settings.WAZUH_INDEXER_INDEX
    response = requests.get(
        f"{base_url}/{index}/_search",
        auth=(settings.WAZUH_INDEXER_USERNAME,
              settings.WAZUH_INDEXER_PASSWORD),
        params={"size": settings.WAZUH_INDEXER_LIMIT,
                "sort": "timestamp:desc"},
        timeout=10,
        verify=settings.WAZUH_INDEXER_VERIFY_TLS,
    )
    response.raise_for_status()
    payload = response.json()
    hits = payload.get("hits", {}).get("hits", [])
    return [_to_alert(hit) for hit in hits]


def get_wazuh_alert(alert_id: str) -> SecurityAlert | None:
    """Find an alert by querying the configured index pattern."""
    for alert in get_wazuh_alerts():
        if alert.alert_id == alert_id:
            return alert
    return None
