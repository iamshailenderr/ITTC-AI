"""
Comprehensive End-to-End SOC Pipeline Integration Test.
Validates the complete lifecycle:
Alert Ingestion -> Normalization -> Anomaly Detection -> TI Enrichment ->
RAG Retrieval -> AI Analysis -> Incident Correlation ->
Active Response Proposal -> Safeguard Validation -> Approval & Simulation ->
Audit Logging -> Rollback.
"""

import unittest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from backend.main import app
from backend.services.alerts import get_alerts, get_alert
from backend.services.incidents import clear_incidents, correlate_alerts, list_incidents
from backend.services.active_response import clear_responses_for_testing, list_responses, get_audit_trail
from backend.services.reporting import generate_incident_report
from backend.threat_intel.extractor import extract_iocs
from backend.threat_intel.enricher import enrich_iocs
from backend.ai.anomaly import detect_anomaly
from backend.ai.risk_explainer import compute_risk_factors
from backend.rag.retriever import retrieve_context
from backend.ai.killchain import map_event_to_killchain
from backend.ai.hypothesis import generate_investigation_hypothesis


class TestEndToEndSOCPipeline(unittest.TestCase):

    def setUp(self):
        clear_incidents()
        clear_responses_for_testing()
        self.client = TestClient(app)

    def tearDown(self):
        clear_incidents()
        clear_responses_for_testing()

    def test_complete_soc_investigation_and_response_lifecycle(self):
        # 1. Alert Ingestion & Normalization
        alerts = get_alerts()
        self.assertGreaterEqual(len(alerts), 5)
        lead_alert = alerts[0]
        self.assertEqual(lead_alert.alert_id, "ITTC-001")
        self.assertIn(lead_alert.source, ("wazuh", "suricata"))

        # 2. IOC Extraction & Threat Intelligence Enrichment
        iocs = extract_iocs(lead_alert)
        self.assertGreaterEqual(len(iocs), 1)
        enrichments = enrich_iocs(iocs)
        self.assertGreaterEqual(len(enrichments), 1)
        self.assertEqual(enrichments[0].type, "ip")

        # 3. Anomaly Detection
        anom_score, is_anom = detect_anomaly(lead_alert)
        self.assertIsInstance(anom_score, float)
        self.assertIsInstance(is_anom, bool)

        # 4. RAG Retrieval from FAISS Knowledge Base
        rag_chunks = retrieve_context(lead_alert, top_k=3)
        self.assertGreaterEqual(len(rag_chunks), 1)

        # 5. Incident Correlation
        incidents = correlate_alerts()
        self.assertGreaterEqual(len(incidents), 1)
        active_inc = incidents[0]
        self.assertEqual(active_inc.status, "OPEN")
        self.assertGreaterEqual(len(active_inc.related_alert_ids), 1)

        # 6. AI Analysis & Response Proposal via REST API
        with patch("backend.ai.analyzer.requests.post") as mock_ollama:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {
                "message": {
                    "content": '{"summary": "Cobalt Strike C2 beaconing detected from 203.0.113.50", "risk_score": 90, "severity": "critical", "mitre_techniques": ["T1071.001"], "hypothesis": "Adversary established external C2 channel", "confidence": 0.95, "kill_chain_stage": "Command and Control", "evidence": ["Cobalt Strike Beacon HTTP POST observed"], "recommendations": ["Block C2 IP 203.0.113.50"]}'
                }
            }
            mock_ollama.return_value = mock_resp

            analyze_res = self.client.post("/api/analyze/ITTC-002")
            self.assertEqual(analyze_res.status_code, 200)
            analysis_data = analyze_res.json()
            self.assertEqual(analysis_data["risk_score"], 90)
            self.assertEqual(analysis_data["kill_chain_stage"], "Command and Control")

        # 7. Verify Auto-Proposed Active Response Item
        responses_res = self.client.get("/api/responses?alert_id=ITTC-002")
        self.assertEqual(responses_res.status_code, 200)
        resp_list = responses_res.json()
        self.assertGreaterEqual(len(resp_list), 1)
        proposal = resp_list[0]
        self.assertEqual(proposal["state"], "PENDING_APPROVAL")
        self.assertEqual(proposal["action"], "BLOCK_IP")
        self.assertEqual(proposal["target"], "203.0.113.50")
        resp_id = proposal["response_id"]

        # 8. Analyst Approval & Simulated Dry-Run Execution
        approve_res = self.client.post(
            f"/api/responses/{resp_id}/approve",
            json={"approver": "lead_soc_analyst", "reason": "Confirmed malicious C2 host"},
        )
        self.assertEqual(approve_res.status_code, 200)
        approved_data = approve_res.json()
        self.assertEqual(approved_data["state"], "SIMULATED")
        self.assertEqual(approved_data["approved_by"], "lead_soc_analyst")
        self.assertTrue(approved_data["execution_result"]["success"])
        self.assertEqual(approved_data["execution_result"]["mode"], "simulated")

        # 9. Verify Immutable Audit Trail
        audit_res = self.client.get("/api/responses/audit/log")
        self.assertEqual(audit_res.status_code, 200)
        audit_records = audit_res.json()
        self.assertGreaterEqual(len(audit_records), 2)
        event_types = [a["event"] for a in audit_records]
        self.assertIn("RESPONSE_PROPOSED", event_types)
        self.assertIn("RESPONSE_APPROVED", event_types)
        self.assertIn("RESPONSE_EXECUTED", event_types)

        # 10. Rollback Action (Revert)
        rollback_res = self.client.post(f"/api/responses/{resp_id}/rollback?actor=lead_soc_analyst")
        self.assertEqual(rollback_res.status_code, 200)
        rollback_data = rollback_res.json()
        self.assertEqual(rollback_data["state"], "SIMULATED")
        self.assertEqual(rollback_data["action"], "UNBLOCK_IP")
        self.assertEqual(rollback_data["rollback_of"], resp_id)

        # 11. Final Incident Report Generation
        report = generate_incident_report(active_inc.incident_id)
        self.assertIsNotNone(report)
        self.assertIn("report_metadata", report)
        self.assertIn("incident", report)
        self.assertIn("timeline", report)



if __name__ == "__main__":
    unittest.main()
