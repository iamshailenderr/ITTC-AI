"""
End-to-end API tests for all FastAPI endpoints in backend/main.py.
"""

import unittest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from backend.main import app
from backend.services.incidents import clear_incidents


class TestAPIEndpoints(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def setUp(self):
        clear_incidents()

    def tearDown(self):
        clear_incidents()

    def test_health_check(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "ok")
        self.assertEqual(data["service"], "ittc-ai")

    def test_list_alerts(self):
        response = self.client.get("/api/alerts")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIsInstance(data, list)
        self.assertGreaterEqual(len(data), 1)
        self.assertIn("alert_id", data[0])

    def test_read_alert_success(self):
        # ITTC-001 is the first alert in alerts.json
        response = self.client.get("/api/alerts/ITTC-001")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["alert_id"], "ITTC-001")

    def test_read_alert_not_found(self):
        response = self.client.get("/api/alerts/NONEXISTENT-999")
        self.assertEqual(response.status_code, 404)

    def test_get_incidents_auto_correlates(self):
        response = self.client.get("/api/incidents")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIsInstance(data, list)
        self.assertGreater(len(data), 0)
        self.assertIn("incident_id", data[0])
        self.assertIn("status", data[0])

    def test_post_correlate(self):
        response = self.client.post("/api/incidents/correlate")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIsInstance(data, list)
        self.assertGreater(len(data), 0)

    def test_read_incident(self):
        # Create incidents
        corr_res = self.client.post("/api/incidents/correlate")
        inc_id = corr_res.json()[0]["incident_id"]

        response = self.client.get(f"/api/incidents/{inc_id}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["incident_id"], inc_id)

    def test_read_incident_not_found(self):
        response = self.client.get("/api/incidents/INC-NOTFOUND")
        self.assertEqual(response.status_code, 404)

    def test_update_incident_status(self):
        corr_res = self.client.post("/api/incidents/correlate")
        inc_id = corr_res.json()[0]["incident_id"]

        # Update to INVESTIGATING
        patch_res = self.client.patch(
            f"/api/incidents/{inc_id}/status",
            json={"status": "INVESTIGATING"},
        )
        self.assertEqual(patch_res.status_code, 200)
        self.assertEqual(patch_res.json()["status"], "INVESTIGATING")

        # Invalid status returns 400
        bad_res = self.client.patch(
            f"/api/incidents/{inc_id}/status",
            json={"status": "INVALID_STATUS"},
        )
        self.assertEqual(bad_res.status_code, 400)

    def test_add_incident_notes(self):
        corr_res = self.client.post("/api/incidents/correlate")
        inc_id = corr_res.json()[0]["incident_id"]

        note_res = self.client.post(
            f"/api/incidents/{inc_id}/notes",
            json={"content": "Host has been quarantined for memory dump", "author": "lead_analyst"},
        )
        self.assertEqual(note_res.status_code, 200)
        notes = note_res.json()["analyst_notes"]
        self.assertGreaterEqual(len(notes), 1)
        self.assertEqual(notes[-1]["content"], "Host has been quarantined for memory dump")
        self.assertEqual(notes[-1]["author"], "lead_analyst")

    def test_incident_report_endpoint(self):
        corr_res = self.client.post("/api/incidents/correlate")
        inc_id = corr_res.json()[0]["incident_id"]

        rep_res = self.client.get(f"/api/incidents/{inc_id}/report")
        self.assertEqual(rep_res.status_code, 200)
        report = rep_res.json()
        self.assertIn("report_metadata", report)
        self.assertIn("incident", report)
        self.assertIn("alerts", report)
        self.assertIn("timeline", report)
        self.assertIn("iocs", report)

    def test_ioc_investigation_endpoint(self):
        res = self.client.get("/api/ioc/ip/203.0.113.50")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["ioc_type"], "ip")
        self.assertEqual(data["value"], "203.0.113.50")
        self.assertEqual(data["reputation"], "malicious")
        self.assertTrue(data["malicious"])

    def test_ioc_investigation_invalid_type(self):
        res = self.client.get("/api/ioc/unknown_type/123")
        self.assertEqual(res.status_code, 400)

    @patch("backend.ai.copilot.requests.post")
    def test_copilot_chat_endpoint(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "message": {
                "content": "To investigate credential dumping, examine Event ID 4656 or Sysmon Event 10."
            }
        }
        mock_post.return_value = mock_resp

        payload = {
            "question": "How do I investigate credential dumping from LSASS?",
            "history": [],
        }
        res = self.client.post("/api/copilot/chat", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("answer", data)
        self.assertIn("sources", data)
        self.assertGreater(len(data["sources"]), 0)


if __name__ == "__main__":
    unittest.main()
