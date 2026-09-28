"""
Unit tests for Explainable Risk Explainer module.
"""

import unittest
from datetime import datetime, timezone

from backend.models.alert import SecurityAlert
from backend.ai.risk_explainer import compute_risk_factors


class TestRiskExplainer(unittest.TestCase):

    def test_compute_risk_factors_basic(self):
        alert = SecurityAlert(
            alert_id="TEST-01",
            timestamp=datetime.now(timezone.utc),
            source="wazuh",
            severity="critical",
            host="DC-01",
            event_type="credential_access",
            event="Mimikatz LSASS memory dump attempt",
        )
        factors = compute_risk_factors(alert)
        self.assertGreater(len(factors), 0)

        sev_factor = next((f for f in factors if f.factor == "Alert Severity"), None)
        self.assertIsNotNone(sev_factor)
        self.assertEqual(sev_factor.impact, 30)

    def test_compute_risk_factors_with_ti_and_mitre(self):
        alert = SecurityAlert(
            alert_id="TEST-02",
            timestamp=datetime.now(timezone.utc),
            source="suricata",
            severity="high",
            host="WEB-01",
            event_type="network_connection",
            event="Encoded PowerShell command downloaded over HTTP",
        )
        enrichments = [
            {"value": "203.0.113.195", "malicious": True, "reputation": "malicious"}
        ]
        mitre_techs = ["T1059.001", "T1071"]

        factors = compute_risk_factors(
            alert=alert,
            enrichments=enrichments,
            mitre_techniques=mitre_techs,
            anomaly_score=0.75,
            is_anomalous=True,
            correlated_alert_count=3,
        )

        factor_names = [f.factor for f in factors]
        self.assertIn("Alert Severity", factor_names)
        self.assertIn("Malicious IOC Detected", factor_names)
        self.assertIn("High-Risk MITRE Technique", factor_names)
        self.assertIn("Anomaly Detected", factor_names)
        self.assertIn("Multi-Alert Correlation", factor_names)
        self.assertIn("Encoded/Obfuscated Content", factor_names)

        # Ensure all impacts are valid 0-100 integers
        for f in factors:
            self.assertGreaterEqual(f.impact, 0)
            self.assertLessEqual(f.impact, 100)
            self.assertIsInstance(f.evidence, str)


if __name__ == "__main__":
    unittest.main()
