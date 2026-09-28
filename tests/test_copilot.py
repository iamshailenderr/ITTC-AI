"""
Unit tests for SOC AI Copilot prompt building and context formatting.
"""

import unittest
from unittest.mock import patch, MagicMock

from backend.models.incident import CopilotRequest, CopilotResponse
from backend.ai.copilot import (
    _build_copilot_prompt,
    _format_incident_context,
    _format_alert_context,
    copilot_chat,
)
from backend.models.alert import SecurityAlert
from backend.models.incident import Incident
from datetime import datetime, timezone


class TestCopilot(unittest.TestCase):

    def test_build_copilot_prompt_formatting(self):
        rag_chunks = [
            {"source": "MITRE", "title": "T1059 Command and Scripting Interpreter", "text": "Adversaries may abuse PowerShell..."}
        ]
        messages = _build_copilot_prompt(
            question="How do I detect PowerShell abuse?",
            rag_chunks=rag_chunks,
            incident_context="Incident ID: INC-001",
            alert_context="Alert ID: ALT-001",
            history=[{"role": "user", "content": "hello"}, {"role": "assistant", "content": "hi"}],
        )

        self.assertEqual(messages[0]["role"], "system")
        self.assertEqual(messages[1]["role"], "user")
        self.assertEqual(messages[1]["content"], "hello")
        self.assertEqual(messages[2]["role"], "assistant")

        # Last message contains context and question
        last_msg = messages[-1]["content"]
        self.assertIn("PowerShell abuse", last_msg)
        self.assertIn("T1059", last_msg)
        self.assertIn("INC-001", last_msg)
        self.assertIn("ALT-001", last_msg)

    def test_format_incident_context(self):
        incident = Incident(
            incident_id="INC-12345",
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            status="OPEN",
            severity="high",
            risk_score=80,
            confidence=0.85,
            related_alert_ids=["A1", "A2"],
            related_iocs=[{"type": "ip", "value": "203.0.113.5"}],
            mitre_techniques=["T1059.001"],
            summary="Suspicious PowerShell cluster",
        )
        ctx = _format_incident_context(incident)
        self.assertIn("INC-12345", ctx)
        self.assertIn("OPEN", ctx)
        self.assertIn("T1059.001", ctx)
        self.assertIn("203.0.113.5", ctx)

    @patch("backend.ai.copilot.requests.post")
    def test_copilot_chat_mocked_llm(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "message": {
                "content": "PowerShell execution can be detected by monitoring Event ID 4104 (Script Block Logging)."
            }
        }
        mock_post.return_value = mock_resp

        req = CopilotRequest(
            question="How do I detect malicious PowerShell?",
            history=[],
        )
        res = copilot_chat(req)

        self.assertIsInstance(res, CopilotResponse)
        self.assertIn("Event ID 4104", res.answer)
        self.assertGreater(len(res.sources), 0)


if __name__ == "__main__":
    unittest.main()
