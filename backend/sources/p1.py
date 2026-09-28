"""
P1 API alert source — placeholder for future integration.

Future flow:
    P1 API (Wazuh/Suricata) → P1 source adapter → SecurityAlert → AI pipeline

This adapter will translate P1's API response into the shared SecurityAlert model,
ensuring the AI pipeline never depends on Wazuh/Suricata internal formats.
"""

from backend.models.alert import SecurityAlert

# P1 API base URL will come from config/settings.py once integration begins.
# Example: P1_API_URL = settings.P1_API_URL


def get_p1_alerts() -> list[SecurityAlert]:
    """
    Fetch alerts from Person 1's API and convert to SecurityAlert.

    NOT IMPLEMENTED — will be connected in a future integration phase.
    """
    raise NotImplementedError(
        "P1 API integration is not yet implemented. "
        "Use backend.sources.mock.get_mock_alerts() for development."
    )
