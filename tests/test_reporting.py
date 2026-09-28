"""
Unit tests for Incident Reporting service.
"""

import unittest
from datetime import datetime, timezone

from backend.models.alert import SecurityAlert
from backend.services.incidents import correlate_alerts, clear_incidents
from backend.services.reporting import generate_incident_report


class TestIncidentReporting(unittest.TestCase):

    def setUp(self):
        clear_incidents()

    def tearDown(self):
        clear_incidents()

    def test_generate_report(self):
        alerts = [
            SecurityAlert(
                alert_id="A1",
                timestamp=datetime.now(timezone.utc),
                source="wazuh",
                severity="high",
                host="HOST-1",
                src_ip="203.0.113.195",
                dst_ip="10.0.0.1",
                event_type="lateral_movement",
                event="PsExec detected",
            )
        ]
        incidents = correlate_alerts(alerts)
        inc_id = incidents[0].incident_id

        report = generate_incident_report(inc_id)
        self.assertIsNotNone(report)
        self.assertIn("report_metadata", report)
        self.assertIn("incident", report)
        self.assertIn("alerts", report)
        self.assertIn("timeline", report)
        self.assertIn("iocs", report)
        self.assertIn("mitre_techniques", report)
        self.assertIn("risk", report)
        self.assertEqual(report["incident"]["incident_id"], inc_id)

    def test_generate_report_nonexistent_incident(self):
        report = generate_incident_report("NONEXISTENT-INC-ID")
        self.assertIsNone(report)


if __name__ == "__main__":
    unittest.main()
