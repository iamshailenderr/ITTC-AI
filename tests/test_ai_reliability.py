"""
Unit tests for AI and RAG reliability improvements,
Kill Chain mapping, hypothesis generation, and robust schema sanitization.
"""

import unittest
from datetime import datetime, timezone

from backend.models.alert import SecurityAlert
from backend.ai.killchain import normalize_killchain_stage, map_event_to_killchain, KILL_CHAIN_STAGES
from backend.ai.hypothesis import generate_investigation_hypothesis
from backend.ai.analyzer import _sanitize_and_validate_analysis, _extract_and_parse_json


class TestAIReliability(unittest.TestCase):

    def setUp(self):
        self.sample_alert = SecurityAlert(
            alert_id="TEST-REL-01",
            timestamp=datetime.now(timezone.utc),
            source="wazuh",
            severity="high",
            host="DEV-BOX-01",
            user="developer",
            src_ip="10.0.0.45",
            dst_ip="203.0.113.88",
            event_type="process_creation",
            event="Suspicious powershell.exe execution with encoded command T1059.001 downloading payload",
            rule_id="100101",
        )

    def test_killchain_stages_enumeration(self):
        self.assertEqual(len(KILL_CHAIN_STAGES), 7)
        self.assertIn("Reconnaissance", KILL_CHAIN_STAGES)
        self.assertIn("Command and Control", KILL_CHAIN_STAGES)
        self.assertIn("Actions on Objectives", KILL_CHAIN_STAGES)

    def test_normalize_killchain_stage(self):
        self.assertEqual(normalize_killchain_stage("c2"), "Command and Control")
        self.assertEqual(normalize_killchain_stage("Command & Control"), "Command and Control")
        self.assertEqual(normalize_killchain_stage("recon"), "Reconnaissance")
        self.assertEqual(normalize_killchain_stage("initial access"), "Delivery")
        self.assertEqual(normalize_killchain_stage("persistence"), "Installation")
        self.assertEqual(normalize_killchain_stage("lateral movement"), "Actions on Objectives")
        self.assertEqual(normalize_killchain_stage("exfiltration"), "Actions on Objectives")
        self.assertEqual(normalize_killchain_stage("unknown random stage"), "Exploitation")

    def test_map_event_to_killchain(self):
        stage_c2 = map_event_to_killchain(event_type="network_connection", event_text="C2 beaconing detected")
        self.assertEqual(stage_c2, "Command and Control")

        stage_lsass = map_event_to_killchain(event_type="credential_access", event_text="LSASS dump with mimikatz T1003")
        self.assertEqual(stage_lsass, "Actions on Objectives")

        stage_phish = map_event_to_killchain(event_type="phishing", event_text="Invoice attachment downloaded")
        self.assertEqual(stage_phish, "Delivery")

        stage_ps = map_event_to_killchain(event_type="process_creation", event_text="PowerShell encoded command execution T1059")
        self.assertEqual(stage_ps, "Exploitation")

    def test_generate_hypothesis(self):
        hyp = generate_investigation_hypothesis(
            alert=self.sample_alert,
            mitre_techniques=["T1059.001"],
            kill_chain_stage="Exploitation",
            enrichments=[{"value": "203.0.113.88", "malicious": True}],
        )
        self.assertIn("DEV-BOX-01", hyp)
        self.assertIn("developer", hyp)
        self.assertIn("T1059.001", hyp)
        self.assertIn("203.0.113.88", hyp)

    def test_sanitize_and_validate_analysis(self):
        malformed_parsed = {
            "summary": "   ",  # Blank
            "risk_score": 150,  # Clamped to 100
            "severity": "UNKNOWN_SEV",  # Should fall back
            "mitre_techniques": ["t1059.001", "invalid_tech"],
            "hypothesis": "",  # Empty -> should generate
            "confidence": 95,  # Percentage format -> convert to 0.95
            "kill_chain_stage": "c2",  # Should normalize to "Command and Control"
            "evidence": [],  # Should auto-populate from alert
            "recommendations": [],
        }

        sanitized = _sanitize_and_validate_analysis(malformed_parsed, self.sample_alert)
        self.assertTrue(len(sanitized["summary"]) > 0)
        self.assertEqual(sanitized["risk_score"], 100)
        self.assertEqual(sanitized["severity"], "high")
        self.assertIn("T1059.001", sanitized["mitre_techniques"])
        self.assertEqual(sanitized["confidence"], 0.95)
        self.assertEqual(sanitized["kill_chain_stage"], "Command and Control")
        self.assertGreaterEqual(len(sanitized["evidence"]), 1)
        self.assertGreaterEqual(len(sanitized["recommendations"]), 1)
        self.assertTrue(len(sanitized["hypothesis"]) > 10)

    def test_extract_and_parse_json(self):
        raw_with_think = "<think>Analyzing alert...</think>```json\n{\"summary\": \"Test Alert\", \"risk_score\": 75}\n```"
        parsed = _extract_and_parse_json(raw_with_think)
        self.assertEqual(parsed["summary"], "Test Alert")
        self.assertEqual(parsed["risk_score"], 75)


if __name__ == "__main__":
    unittest.main()
