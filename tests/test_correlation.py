"""
Unit tests for Incident Correlation Engine and Incident Store.
"""

import unittest
from datetime import datetime, timezone, timedelta

from backend.models.alert import SecurityAlert
from backend.services.incidents import (
    correlate_alerts,
    list_incidents,
    get_incident,
    update_incident_status,
    add_incident_note,
    clear_incidents,
    _alerts_correlate,
)


class TestIncidentCorrelation(unittest.TestCase):

    def setUp(self):
        clear_incidents()

    def tearDown(self):
        clear_incidents()

    def test_alerts_correlate_same_src_ip(self):
        a1 = SecurityAlert(
            alert_id="TEST-01",
            timestamp=datetime.now(timezone.utc),
            source="wazuh",
            severity="high",
            host="HOST-A",
            src_ip="203.0.113.55",
            dst_ip="10.0.0.1",
            event_type="credential_access",
            event="Brute force login",
        )
        a2 = SecurityAlert(
            alert_id="TEST-02",
            timestamp=datetime.now(timezone.utc) + timedelta(minutes=5),
            source="suricata",
            severity="medium",
            host="HOST-B",
            src_ip="203.0.113.55",
            dst_ip="10.0.0.2",
            event_type="network_connection",
            event="Inbound SSH connection",
        )
        self.assertTrue(_alerts_correlate(a1, a2))

    def test_alerts_correlate_same_host(self):
        a1 = SecurityAlert(
            alert_id="TEST-01",
            timestamp=datetime.now(timezone.utc),
            source="wazuh",
            severity="high",
            host="WIN-SERVER-01",
            src_ip="192.0.2.1",
            dst_ip="10.0.0.1",
            event_type="process_creation",
            event="PowerShell executed",
        )
        a2 = SecurityAlert(
            alert_id="TEST-02",
            timestamp=datetime.now(timezone.utc) + timedelta(minutes=10),
            source="wazuh",
            severity="critical",
            host="WIN-SERVER-01",
            src_ip="198.51.100.2",
            dst_ip="10.0.0.2",
            event_type="credential_access",
            event="Mimikatz detected",
        )
        self.assertTrue(_alerts_correlate(a1, a2))

    def test_alerts_correlate_time_window_exceeded(self):
        a1 = SecurityAlert(
            alert_id="TEST-01",
            timestamp=datetime.now(timezone.utc),
            source="wazuh",
            severity="high",
            host="WIN-01",
            src_ip="203.0.113.55",
            dst_ip="10.0.0.1",
            event_type="brute_force",
            event="Login failure",
        )
        # 48 hours later (window is 24h)
        a2 = SecurityAlert(
            alert_id="TEST-02",
            timestamp=datetime.now(timezone.utc) + timedelta(hours=48),
            source="wazuh",
            severity="high",
            host="WIN-01",
            src_ip="203.0.113.55",
            dst_ip="10.0.0.1",
            event_type="brute_force",
            event="Login failure",
        )
        self.assertFalse(_alerts_correlate(a1, a2, window_hours=24))

    def test_correlate_alerts_creates_incidents(self):
        alerts = [
            SecurityAlert(
                alert_id="A1",
                timestamp=datetime.now(timezone.utc),
                source="wazuh",
                severity="high",
                host="HOST-1",
                src_ip="203.0.113.55",
                dst_ip="10.0.0.1",
                event_type="lateral_movement",
                event="PsExec execution",
            ),
            SecurityAlert(
                alert_id="A2",
                timestamp=datetime.now(timezone.utc) + timedelta(minutes=2),
                source="wazuh",
                severity="critical",
                host="HOST-1",
                src_ip="203.0.113.55",
                dst_ip="10.0.0.1",
                event_type="credential_access",
                event="LSASS dump",
            ),
            SecurityAlert(
                alert_id="A3",
                timestamp=datetime.now(timezone.utc),
                source="suricata",
                severity="low",
                host="HOST-99",
                src_ip="198.51.100.99",
                dst_ip="10.0.0.99",
                event_type="network_connection",
                event="DNS lookup",
            ),
        ]

        incidents = correlate_alerts(alerts)
        self.assertGreaterEqual(len(incidents), 1)

        # Verify A1 and A2 are grouped together in one incident
        a1_incident = next((inc for inc in incidents if "A1" in inc.related_alert_ids), None)
        self.assertIsNotNone(a1_incident)
        self.assertIn("A2", a1_incident.related_alert_ids)
        self.assertEqual(a1_incident.severity, "critical")
        self.assertEqual(a1_incident.status, "OPEN")
        self.assertGreater(len(a1_incident.timeline), 0)

    def test_incident_status_update(self):
        alerts = [
            SecurityAlert(
                alert_id="A1",
                timestamp=datetime.now(timezone.utc),
                source="wazuh",
                severity="high",
                host="HOST-1",
                event_type="login",
                event="Test event",
            )
        ]
        incidents = correlate_alerts(alerts)
        inc_id = incidents[0].incident_id

        # Update to INVESTIGATING
        updated = update_incident_status(inc_id, "INVESTIGATING")
        self.assertEqual(updated.status, "INVESTIGATING")

        # Update to CONTAINED
        updated = update_incident_status(inc_id, "CONTAINED")
        self.assertEqual(updated.status, "CONTAINED")

        # Update to RESOLVED
        updated = update_incident_status(inc_id, "RESOLVED")
        self.assertEqual(updated.status, "RESOLVED")

        # Invalid status should raise ValueError
        with self.assertRaises(ValueError):
            update_incident_status(inc_id, "INVALID_STATUS")

    def test_incident_analyst_notes(self):
        alerts = [
            SecurityAlert(
                alert_id="A1",
                timestamp=datetime.now(timezone.utc),
                source="wazuh",
                severity="high",
                host="HOST-1",
                event_type="login",
                event="Test event",
            )
        ]
        incidents = correlate_alerts(alerts)
        inc_id = incidents[0].incident_id

        updated = add_incident_note(inc_id, "Investigating host activity", author="analyst_alice")
        self.assertEqual(len(updated.analyst_notes), 1)
        self.assertEqual(updated.analyst_notes[0].content, "Investigating host activity")
        self.assertEqual(updated.analyst_notes[0].author, "analyst_alice")


if __name__ == "__main__":
    unittest.main()
