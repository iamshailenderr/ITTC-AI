"""
Pytest configuration for ITTC-AI test suite.
Ensures unit tests run in safe, offline-isolated mode with mock alerts by default.
"""

import pytest
from config import settings


@pytest.fixture(autouse=True)
def isolate_test_environment(monkeypatch):
    """Ensure test suite runs in safe offline mode with mock alerts by default."""
    monkeypatch.setattr(settings, "ALERT_SOURCE", "mock")
