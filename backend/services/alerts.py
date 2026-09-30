"""Alert service for mock and live Wazuh Indexer sources."""

from typing import Optional
from backend.models.alert import SecurityAlert
from backend.sources.mock import get_mock_alerts
from backend.sources.wazuh_indexer import get_wazuh_alerts, get_wazuh_alert
from config import settings


def _active_alerts(limit: Optional[int] = None, offset: int = 0) -> list[SecurityAlert]:
    """Load alerts from the configured source."""
    if settings.ALERT_SOURCE == "mock":
        alerts = get_mock_alerts()
        if offset > 0:
            alerts = alerts[offset:]
        if limit is not None:
            alerts = alerts[:limit]
        return alerts

    if settings.ALERT_SOURCE == "wazuh":
        if not settings.WAZUH_INDEXER_USERNAME or not settings.WAZUH_INDEXER_PASSWORD:
            raise RuntimeError(
                "Wazuh Indexer credentials are missing. "
                "Set WAZUH_INDEXER_USERNAME and WAZUH_INDEXER_PASSWORD in .env."
            )
        return get_wazuh_alerts(limit=limit, offset=offset)

    raise RuntimeError(
        f"Unsupported ALERT_SOURCE '{settings.ALERT_SOURCE}'. "
        "Use 'mock' or 'wazuh'."
    )


def get_alerts(limit: Optional[int] = None, offset: int = 0) -> list[SecurityAlert]:
    """Return normalized alerts from the active source."""
    return _active_alerts(limit=limit, offset=offset)


def get_alert(alert_id: str) -> SecurityAlert | None:
    """Return a single alert by ID, or None if not found."""
    if settings.ALERT_SOURCE == "wazuh":
        if not settings.WAZUH_INDEXER_USERNAME or not settings.WAZUH_INDEXER_PASSWORD:
            raise RuntimeError(
                "Wazuh Indexer credentials are missing. "
                "Set WAZUH_INDEXER_USERNAME and WAZUH_INDEXER_PASSWORD in .env."
            )
        return get_wazuh_alert(alert_id)

    for alert in _active_alerts():
        if alert.alert_id == alert_id:
            return alert
    return None
