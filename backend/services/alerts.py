"""
Alert service — business logic layer for alert retrieval.
Delegates to the active alert source (mock for now, P1 API later).
"""

from backend.models.alert import SecurityAlert
from backend.sources.mock import get_mock_alerts


def get_alerts() -> list[SecurityAlert]:
    """Return all normalized alerts from the active source."""
    return get_mock_alerts()


def get_alert(alert_id: str) -> SecurityAlert | None:
    """Return a single alert by ID, or None if not found."""
    for alert in get_mock_alerts():
        if alert.alert_id == alert_id:
            return alert
    return None
