"""
Lightweight anomaly detection for security alerts using Isolation Forest.

Uses available alert features to detect anomalous patterns.
Initializes with a synthetic baseline clearly marked for development/testing.

WARNING: The baseline data is SYNTHETIC and for DEMO purposes only.
Do not interpret anomaly scores as production-grade detection.
"""

from __future__ import annotations

import hashlib
import numpy as np
from datetime import datetime
from typing import Optional

from backend.models.alert import SecurityAlert

# Lazy-loaded model
_model = None
_fitted = False

# Severity encoding
_SEVERITY_MAP = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

# Event type encoding
_EVENT_TYPE_MAP = {
    "process_creation": 1,
    "network_connection": 2,
    "lateral_movement": 3,
    "credential_access": 4,
    "brute_force": 5,
    "data_exfiltration": 6,
    "suspicious_download": 7,
    "phishing": 8,
    "file_modification": 9,
    "authentication_failure": 10,
}


def _extract_features(alert: SecurityAlert) -> np.ndarray:
    """Extract numerical features from a SecurityAlert for anomaly detection."""
    severity = _SEVERITY_MAP.get(alert.severity.lower(), 2)
    event_type = _EVENT_TYPE_MAP.get(alert.event_type.lower(), 0)

    # Hour of day (0-23)
    hour = alert.timestamp.hour if hasattr(alert.timestamp, 'hour') else 12

    # IP hash as numeric feature (provides clustering signal)
    src_hash = 0
    if alert.src_ip:
        src_hash = int(hashlib.md5(alert.src_ip.encode()).hexdigest()[:8], 16) % 1000

    dst_hash = 0
    if alert.dst_ip:
        dst_hash = int(hashlib.md5(alert.dst_ip.encode()).hexdigest()[:8], 16) % 1000

    # Event text length (longer events may indicate more complex attacks)
    event_len = min(len(alert.event), 500) / 500.0

    # Has user context
    has_user = 1.0 if alert.user else 0.0

    return np.array([
        severity,
        event_type,
        hour,
        src_hash,
        dst_hash,
        event_len,
        has_user,
    ], dtype=np.float64)


def _build_synthetic_baseline() -> np.ndarray:
    """
    Generate a synthetic baseline of 'normal' alert feature vectors.

    SYNTHETIC DATA — for development and demo purposes only.
    Represents typical low/medium severity alerts during business hours.
    """
    rng = np.random.RandomState(42)
    n_samples = 200

    # Normal alerts: low-medium severity, common event types, business hours
    severities = rng.choice([1, 2, 2, 2], size=n_samples)
    event_types = rng.choice([1, 2, 9, 10], size=n_samples)
    hours = rng.choice(range(8, 18), size=n_samples)  # business hours
    src_hashes = rng.randint(0, 1000, size=n_samples)
    dst_hashes = rng.randint(0, 1000, size=n_samples)
    event_lens = rng.uniform(0.1, 0.4, size=n_samples)
    has_users = rng.choice([0.0, 1.0, 1.0], size=n_samples)

    baseline = np.column_stack([
        severities, event_types, hours,
        src_hashes, dst_hashes, event_lens, has_users,
    ]).astype(np.float64)

    return baseline


def _ensure_model():
    """Lazily fit the Isolation Forest model."""
    global _model, _fitted

    if _fitted:
        return

    try:
        from sklearn.ensemble import IsolationForest
    except ImportError:
        # sklearn not available — provide fallback
        _fitted = True
        return

    baseline = _build_synthetic_baseline()
    _model = IsolationForest(
        n_estimators=100,
        contamination=0.1,
        random_state=42,
    )
    _model.fit(baseline)
    _fitted = True


def detect_anomaly(alert: SecurityAlert) -> tuple[float, bool]:
    """
    Run anomaly detection on a single SecurityAlert.

    Returns:
        (anomaly_score, is_anomalous)

        anomaly_score: float between 0.0 (normal) and 1.0 (highly anomalous)
        is_anomalous: True if the alert is flagged as anomalous

    If sklearn is not available, returns a heuristic score based on severity.
    """
    _ensure_model()

    features = _extract_features(alert)

    if _model is None:
        # Fallback: heuristic based on severity
        severity = _SEVERITY_MAP.get(alert.severity.lower(), 2)
        score = min(severity / 4.0, 1.0)
        return score, severity >= 3

    # Isolation Forest: decision_function returns negative for anomalies
    raw_score = _model.decision_function(features.reshape(1, -1))[0]
    prediction = _model.predict(features.reshape(1, -1))[0]

    # Normalize: raw_score is typically in [-0.5, 0.5] range
    # Convert to 0.0 (normal) to 1.0 (anomalous)
    normalized = float(max(0.0, min(1.0, 0.5 - raw_score)))
    is_anomalous = bool(prediction == -1)

    return round(normalized, 4), is_anomalous
