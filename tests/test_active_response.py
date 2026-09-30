"""
Comprehensive unit and integration tests for the Active Response subsystem.
Verifies target safeguards, lifecycle state machine, duplicate prevention,
simulated execution, approval/rejection workflows, rollback, and API endpoints.
"""

import unittest
from fastapi.testclient import TestClient

from backend.main import app
from backend.models.response import (
    ResponseAction,
    ResponseState,
    ResponseProposalRequest,
    ResponseApprovalRequest,
    ResponseRejectionRequest,
)
from backend.services.active_response import (
    validate_target_safeguard,
    propose_response,
    approve_response,
    reject_response,
    rollback_response,
    list_responses,
    get_response,
    get_audit_trail,
    clear_responses_for_testing,
)


class TestActiveResponseSubsystem(unittest.TestCase):

    def setUp(self):
        clear_responses_for_testing()
        self.client = TestClient(app)

    def tearDown(self):
        clear_responses_for_testing()

    # ------------------------------------------------------------------------
    # Safeguard & Validation Tests
    # ------------------------------------------------------------------------

    def test_safeguard_valid_external_ip(self):
        valid, msg = validate_target_safeguard(ResponseAction.BLOCK_IP, "203.0.113.50")
        self.assertTrue(valid)

    def test_safeguard_blocks_loopback(self):
        valid, msg = validate_target_safeguard(ResponseAction.BLOCK_IP, "127.0.0.1")
        self.assertFalse(valid)
        self.assertIn("loopback", msg.lower())

    def test_safeguard_blocks_default_gateway(self):
        valid, msg = validate_target_safeguard(ResponseAction.BLOCK_IP, "10.0.0.1")
        self.assertFalse(valid)
        self.assertIn("protected", msg.lower())

    def test_safeguard_blocks_dns(self):
        valid, msg = validate_target_safeguard(ResponseAction.BLOCK_IP, "8.8.8.8")
        self.assertFalse(valid)
        self.assertIn("protected", msg.lower())

    def test_safeguard_blocks_domain_controller(self):
        valid, msg = validate_target_safeguard(ResponseAction.ISOLATE_HOST, "DC-01")
        self.assertFalse(valid)
        self.assertIn("critical", msg.lower())

    def test_safeguard_blocks_root_system_user(self):
        valid, msg = validate_target_safeguard(ResponseAction.DISABLE_USER, "root")
        self.assertFalse(valid)
        self.assertIn("protected", msg.lower())

    def test_safeguard_rejects_empty_or_na(self):
        valid, msg = validate_target_safeguard(ResponseAction.BLOCK_IP, "N/A")
        self.assertFalse(valid)

        valid2, msg2 = validate_target_safeguard(ResponseAction.BLOCK_IP, "not_an_ip")
        self.assertFalse(valid2)

    # ------------------------------------------------------------------------
    # Lifecycle & Execution Tests
    # ------------------------------------------------------------------------

    def test_propose_and_approve_simulated_lifecycle(self):
        prop = ResponseProposalRequest(
            action=ResponseAction.BLOCK_IP,
            target="203.0.113.88",
            alert_id="ITTC-001",
            reason="Block C2 communication",
            confidence=0.85,
        )
        record, is_dup = propose_response(prop)
        self.assertFalse(is_dup)
        self.assertEqual(record.state, ResponseState.PENDING_APPROVAL)
        self.assertTrue(record.requires_approval)

        # Approve
        app_req = ResponseApprovalRequest(
            approver="analyst_alice",
            reason="Verified active malicious beaconing",
            ticket_id="SEC-1042",
        )
        approved = approve_response(record.response_id, app_req)
        self.assertEqual(approved.state, ResponseState.SIMULATED)
        self.assertEqual(approved.approved_by, "analyst_alice")
        self.assertIsNotNone(approved.execution_result)
        self.assertTrue(approved.execution_result.success)
        self.assertEqual(approved.execution_result.mode, "simulated")
        self.assertIn("firewall-drop", approved.execution_result.command_dispatched)

    def test_duplicate_prevention(self):
        prop = ResponseProposalRequest(
            action=ResponseAction.BLOCK_IP,
            target="203.0.113.99",
            alert_id="ITTC-002",
            reason="Block beacon",
        )
        rec1, is_dup1 = propose_response(prop)
        self.assertFalse(is_dup1)

        # Propose same action and target again
        rec2, is_dup2 = propose_response(prop)
        self.assertTrue(is_dup2)
        self.assertEqual(rec1.response_id, rec2.response_id)

    def test_rejection_workflow(self):
        prop = ResponseProposalRequest(
            action=ResponseAction.ISOLATE_HOST,
            target="WORKSTATION-09",
            alert_id="ITTC-003",
            reason="Isolate suspicious workstation",
        )
        record, _ = propose_response(prop)

        rej_req = ResponseRejectionRequest(
            rejected_by="senior_analyst_bob",
            reason="Host confirmed as authorized penetration testing platform",
        )
        rejected = reject_response(record.response_id, rej_req)
        self.assertEqual(rejected.state, ResponseState.REJECTED)
        self.assertEqual(rejected.rejected_by, "senior_analyst_bob")

        # Attempt to approve a rejected record should fail
        with self.assertRaises(ValueError):
            approve_response(record.response_id, ResponseApprovalRequest(approver="bob"))

    def test_rollback_workflow(self):
        prop = ResponseProposalRequest(
            action=ResponseAction.BLOCK_IP,
            target="198.51.100.42",
            alert_id="ITTC-005",
            reason="Block brute force IP",
        )
        record, _ = propose_response(prop)
        approved = approve_response(record.response_id, ResponseApprovalRequest(approver="alice"))
        self.assertEqual(approved.state, ResponseState.SIMULATED)

        # Rollback
        rollback_rec = rollback_response(record.response_id, actor="alice")
        self.assertEqual(rollback_rec.action, ResponseAction.UNBLOCK_IP)
        self.assertEqual(rollback_rec.target, "198.51.100.42")
        self.assertEqual(rollback_rec.state, ResponseState.SIMULATED)

        # Check original record updated
        updated_orig = get_response(record.response_id)
        self.assertEqual(updated_orig.state, ResponseState.ROLLED_BACK)

    def test_audit_trail_logging(self):
        prop = ResponseProposalRequest(
            action=ResponseAction.DISABLE_USER,
            target="compromised_user_44",
            alert_id="ITTC-008",
            reason="Disable compromised user",
        )
        record, _ = propose_response(prop)
        approve_response(record.response_id, ResponseApprovalRequest(approver="lead_analyst"))

        audit = get_audit_trail()
        self.assertGreaterEqual(len(audit), 3)  # PROPOSED, APPROVED, EXECUTED
        events = [a.event for a in audit]
        self.assertIn("RESPONSE_PROPOSED", events)
        self.assertIn("RESPONSE_APPROVED", events)
        self.assertIn("RESPONSE_EXECUTED", events)

    # ------------------------------------------------------------------------
    # API Integration Tests
    # ------------------------------------------------------------------------

    def test_api_propose_and_approve(self):
        prop_payload = {
            "action": "BLOCK_IP",
            "target": "203.0.113.77",
            "alert_id": "ITTC-002",
            "reason": "Block C2 server",
            "confidence": 0.9,
        }
        res = self.client.post("/api/responses/propose", json=prop_payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        resp_id = data["response_id"]
        self.assertEqual(data["state"], "PENDING_APPROVAL")

        # Approve endpoint
        app_res = self.client.post(
            f"/api/responses/{resp_id}/approve",
            json={"approver": "test_analyst", "reason": "Sign-off"},
        )
        self.assertEqual(app_res.status_code, 200)
        self.assertEqual(app_res.json()["state"], "SIMULATED")

    def test_api_safeguard_violation_returns_400(self):
        bad_payload = {
            "action": "BLOCK_IP",
            "target": "127.0.0.1",  # Loopback
            "alert_id": "ITTC-999",
            "reason": "Test bad target",
        }
        res = self.client.post("/api/responses/propose", json=bad_payload)
        self.assertEqual(res.status_code, 400)
        self.assertIn("loopback", res.json()["detail"].lower())

    def test_api_list_and_audit(self):
        # Create a response
        self.client.post("/api/responses/propose", json={
            "action": "TERMINATE_PROCESS",
            "target": "5432",
            "alert_id": "ITTC-001",
            "reason": "Kill suspicious PID",
        })

        list_res = self.client.get("/api/responses")
        self.assertEqual(list_res.status_code, 200)
        self.assertGreaterEqual(len(list_res.json()), 1)

        audit_res = self.client.get("/api/responses/audit/log")
        self.assertEqual(audit_res.status_code, 200)
        self.assertGreaterEqual(len(audit_records := audit_res.json()), 1)

    def test_safeguard_blocks_command_injection(self):
        # Semi-colon command chain
        v1, m1 = validate_target_safeguard(ResponseAction.BLOCK_IP, "203.0.113.50; rm -rf /")
        self.assertFalse(v1)
        self.assertIn("illegal", m1.lower())

        # Ampersand backgrounding / chaining
        v2, m2 = validate_target_safeguard(ResponseAction.ISOLATE_HOST, "HOST-01 & calc.exe")
        self.assertFalse(v2)
        self.assertIn("illegal", m2.lower())

        # Pipe redirection
        v3, m3 = validate_target_safeguard(ResponseAction.TERMINATE_PROCESS, "1234 | nc -e sh")
        self.assertFalse(v3)
        self.assertIn("illegal", m3.lower())

    def test_safeguard_hostname_and_process_formats(self):
        # Valid hostname
        v_h1, _ = validate_target_safeguard(ResponseAction.ISOLATE_HOST, "WORKSTATION-01")
        self.assertTrue(v_h1)

        # Invalid hostname
        v_h2, m_h2 = validate_target_safeguard(ResponseAction.ISOLATE_HOST, "HOST INVALID SPACES")
        self.assertFalse(v_h2)
        self.assertIn("invalid characters", m_h2.lower())

        # Valid process PID
        v_p1, _ = validate_target_safeguard(ResponseAction.TERMINATE_PROCESS, "4096")
        self.assertTrue(v_p1)

        # Valid process name
        v_p2, _ = validate_target_safeguard(ResponseAction.TERMINATE_PROCESS, "powershell.exe")
        self.assertTrue(v_p2)

        # Invalid process name
        v_p3, m_p3 = validate_target_safeguard(ResponseAction.TERMINATE_PROCESS, "bad process name with spaces")
        self.assertFalse(v_p3)
        self.assertIn("invalid characters", m_p3.lower())

    def test_api_validation_rejects_empty_approver(self):
        # Propose valid response
        res = self.client.post("/api/responses/propose", json={
            "action": "BLOCK_IP",
            "target": "203.0.113.60",
            "alert_id": "ITTC-001",
            "reason": "Block attacker",
        })
        resp_id = res.json()["response_id"]

        # Attempt approve with empty approver
        bad_app = self.client.post(
            f"/api/responses/{resp_id}/approve",
            json={"approver": "a", "reason": "ok"},  # min_length is 2
        )
        self.assertEqual(bad_app.status_code, 422)

    def test_live_mode_safety_switch(self):
        # Verify that when ACTIVE_RESPONSE_ENABLED is False, execution stays in simulated mode
        from config import settings
        self.assertFalse(settings.ACTIVE_RESPONSE_ENABLED)

    def test_rollback_audit_trail_state_before(self):
        # Propose and approve response in simulated mode
        res = self.client.post("/api/responses/propose", json={
            "action": "BLOCK_IP",
            "target": "203.0.113.88",
            "alert_id": "ITTC-001",
            "reason": "Block attacker for audit test",
        })
        resp_id = res.json()["response_id"]
        app_res = self.client.post(f"/api/responses/{resp_id}/approve", json={"approver": "senior_analyst"})
        self.assertEqual(app_res.status_code, 200)
        self.assertEqual(app_res.json()["state"], "SIMULATED")

        # Rollback the response
        rb_res = self.client.post(f"/api/responses/{resp_id}/rollback?actor=senior_analyst")
        self.assertEqual(rb_res.status_code, 200)

        # Inspect audit trail
        logs = get_audit_trail(limit=10)
        rb_log = next((l for l in logs if l.event == "RESPONSE_ROLLED_BACK" and l.response_id == resp_id), None)
        self.assertIsNotNone(rb_log)
        # Verify state_before reflects SIMULATED, not hardcoded COMPLETED
        self.assertEqual(rb_log.state_before, "SIMULATED")
        self.assertEqual(rb_log.state_after, "ROLLED_BACK")

    def test_api_key_authentication_enforcement(self):
        from config import settings
        # Propose response
        res = self.client.post("/api/responses/propose", json={
            "action": "BLOCK_IP",
            "target": "203.0.113.99",
            "alert_id": "ITTC-001",
            "reason": "Test auth",
        })
        resp_id = res.json()["response_id"]

        try:
            # Enable API Key protection
            settings.API_KEY = "super-secret-soc-key-12345"

            # Request without key -> 401
            no_key = self.client.post(f"/api/responses/{resp_id}/approve", json={"approver": "analyst"})
            self.assertEqual(no_key.status_code, 401)
            self.assertIn("Unauthorized", no_key.json()["detail"])

            # Request with wrong key -> 401
            bad_key = self.client.post(
                f"/api/responses/{resp_id}/approve",
                json={"approver": "analyst"},
                headers={"X-API-Key": "wrong-key"}
            )
            self.assertEqual(bad_key.status_code, 401)

            # Request with correct key -> 200
            good_key = self.client.post(
                f"/api/responses/{resp_id}/approve",
                json={"approver": "analyst"},
                headers={"X-API-Key": "super-secret-soc-key-12345"}
            )
            self.assertEqual(good_key.status_code, 200)
            self.assertEqual(good_key.json()["state"], "SIMULATED")
        finally:
            settings.API_KEY = None


if __name__ == "__main__":
    unittest.main()


