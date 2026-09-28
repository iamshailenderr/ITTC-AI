"""
Mock alert source for P2 development and review demonstrations.
Loads alerts from data/alerts.json and returns SecurityAlert instances.
"""

import json
from pathlib import Path

from backend.models.alert import SecurityAlert

DATA_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "alerts.json"


def get_mock_alerts() -> list[SecurityAlert]:
    """Load mock alerts from JSON and return as SecurityAlert instances."""
    with open(DATA_PATH, "r", encoding="utf-8") as f:
        raw_alerts = json.load(f)
    return [SecurityAlert(**alert) for alert in raw_alerts]
