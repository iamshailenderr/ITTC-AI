"""
Unit tests for Response Recommendation Engine (Recommendation only, requires approval).
"""

import unittest
from datetime import datetime, timezone

from backend.models.alert import SecurityAlert
from backend.ai.response import generate_response_recommendation


class TestResponseRecommendation(unittest.TestCase):

    def test_recommendation_requires_approval(self):
        alert = SecurityAlert(
            alert_id="TEST-01",
            timestamp=datetime.now(timezone.utc),
            source="wazuh",
            severity="critical",
            host="HOST-10",
            src_ip="203.0.113.195",
            event_type="credential_access",
            event="Mimikatz credential dump detected",
        )
        rec = generate_response_recommendation(alert, risk_score=85)
        self.assertTrue(rec.requires_approval)
        self.assertEqual(rec.action, "ISOLATE_HOST")
        self.assertEqual(rec.target, "HOST-10")
        self.assertGreater(rec.confidence, 0.5)

    def test_recommendation_block_ip_for_c2(self):
        alert = SecurityAlert(
            alert_id="TEST-02",
            timestamp=datetime.now(timezone.utc),
            source="suricata",
            severity="high",
            host="SRV-01",
            src_ip="198.51.100.88",
            dst_ip="10.0.0.5",
            event_type="network_connection",
            event="C2 beaconing detected to known malicious controller",
        )
        rec = generate_response_recommendation(alert, risk_score=90)
        self.assertTrue(rec.requires_approval)
        self.assertEqual(rec.action, "BLOCK_IP")
        self.assertEqual(rec.target, "198.51.100.88")

    def test_recommendation_isolate_host_for_lateral_movement(self):
        alert = SecurityAlert(
            alert_id="TEST-03",
            timestamp=datetime.now(timezone.utc),
            source="wazuh",
            severity="high",
            host="WORKSTATION-4",
            event_type="lateral_movement",
            event="Lateral movement via PsExec service installation",
        )
        rec = generate_response_recommendation(alert, risk_score=75)
        self.assertTrue(rec.requires_approval)
        self.assertEqual(rec.action, "ISOLATE_HOST")
        self.assertEqual(rec.target, "WORKSTATION-4")

    def test_recommendation_disable_user_for_phishing(self):
        alert = SecurityAlert(
            alert_id="TEST-04",
            timestamp=datetime.now(timezone.utc),
            source="wazuh",
            severity="high",
            host="LAPTOP-7",
            user="jdoe",
            event_type="phishing",
            event="Malicious macro execution in phishing attachment",
        )
        rec = generate_response_recommendation(alert, risk_score=80)
        self.assertTrue(rec.requires_approval)
        self.assertEqual(rec.action, "DISABLE_USER")
        self.assertEqual(rec.target, "jdoe")


if __name__ == "__main__":
    unittest.main()
