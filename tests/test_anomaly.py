"""
Unit tests for Anomaly Detection module (Isolation Forest with synthetic baseline).
"""

import unittest
from datetime import datetime, timezone

from backend.models.alert import SecurityAlert
from backend.ai.anomaly import detect_anomaly, _extract_features


class TestAnomalyDetection(unittest.TestCase):

    def test_feature_extraction(self):
        alert = SecurityAlert(
            alert_id="TEST-01",
            timestamp=datetime(2026, 8, 20, 14, 30, tzinfo=timezone.utc),
            source="wazuh",
            severity="high",
            host="WIN-01",
            user="admin",
            src_ip="203.0.113.195",
            dst_ip="198.51.100.22",
            event_type="process_creation",
            event="Suspicious PowerShell command execution",
        )
        features = _extract_features(alert)
        self.assertEqual(len(features), 7)
        self.assertEqual(features[0], 3.0)  # high severity = 3
        self.assertEqual(features[2], 14.0)  # hour = 14
        self.assertEqual(features[6], 1.0)  # has_user = 1.0

    def test_detect_anomaly_returns_valid_bounds(self):
        alert = SecurityAlert(
            alert_id="TEST-02",
            timestamp=datetime.now(timezone.utc),
            source="wazuh",
            severity="critical",
            host="DC-01",
            event_type="credential_access",
            event="Active Directory database (ntds.dit) extraction attempt",
        )
        score, is_anom = detect_anomaly(alert)
        self.assertIsInstance(score, float)
        self.assertGreaterEqual(score, 0.0)
        self.assertLessEqual(score, 1.0)
        self.assertIsInstance(is_anom, (bool, type(True)))

    def test_detect_anomaly_low_severity(self):
        alert = SecurityAlert(
            alert_id="TEST-03",
            timestamp=datetime(2026, 8, 20, 10, 0, tzinfo=timezone.utc),
            source="wazuh",
            severity="low",
            host="WORKSTATION-12",
            event_type="network_connection",
            event="Standard DNS query to internal resolver",
        )
        score, is_anom = detect_anomaly(alert)
        self.assertGreaterEqual(score, 0.0)
        self.assertLessEqual(score, 1.0)


if __name__ == "__main__":
    unittest.main()
