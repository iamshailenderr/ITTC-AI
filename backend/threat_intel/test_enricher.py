"""Offline tests for provider selection and fallback behavior."""

import os
import unittest
from unittest.mock import patch

from backend.threat_intel.enricher import get_provider
from backend.threat_intel.models import IOCEnrichment


class ProviderFallbackTests(unittest.TestCase):
    def test_missing_key_uses_existing_mock_provider(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("VIRUSTOTAL_API_KEY", None)
            provider = get_provider()
            result = provider.enrich("ip", "203.0.113.50")
            self.assertIn("Mock Threat Intelligence", result.source)
            self.assertEqual(result.reputation, "malicious")

    @patch("backend.threat_intel.virustotal_provider._requests.get")
    def test_vt_failure_falls_back_to_mock(self, get):
        get.return_value.status_code = 429
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test-key"}, clear=False):
            provider = get_provider()
            result = provider.enrich("ip", "203.0.113.50")
            self.assertEqual(result.provider_status, "fallback")
            self.assertIn("VirusTotal unavailable", result.source)
            self.assertEqual(result.reputation, "malicious")


if __name__ == "__main__":
    unittest.main()
