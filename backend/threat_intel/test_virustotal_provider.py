"""Focused offline tests for the VirusTotal provider.

No real VirusTotal requests are made by these tests.
"""

import unittest
from unittest.mock import Mock, patch

from backend.threat_intel.virustotal_provider import VirusTotalProvider


class VirusTotalProviderTests(unittest.TestCase):
    def setUp(self):
        self.provider = VirusTotalProvider("test-key")

    @staticmethod
    def _response(payload, status=200):
        response = Mock()
        response.status_code = status
        response.json.return_value = payload
        return response

    def _payload(self):
        return {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 8,
                        "suspicious": 2,
                        "harmless": 55,
                        "undetected": 5,
                    },
                    "reputation": -15,
                    "categories": {"a": "malware", "b": "c2"},
                    "last_analysis_date": 1790000000,
                    "popular_threat_classification": {
                        "popular_threat_name": [{"value": "ExampleMalware"}]
                    },
                }
            }
        }

    @patch("backend.threat_intel.virustotal_provider._requests.get")
    def test_ip_lookup(self, get):
        get.return_value = self._response(self._payload())
        result = self.provider.enrich("ip", "203.0.113.50")
        self.assertEqual(result.source, "VirusTotal")
        self.assertEqual(result.provider_status, "available")
        self.assertEqual(result.malicious_count, 8)
        self.assertEqual(result.suspicious_count, 2)
        self.assertEqual(result.harmless_count, 55)
        self.assertEqual(result.undetected_count, 5)
        self.assertEqual(result.total_engines, 70)
        self.assertEqual(result.reputation_score, -15)
        self.assertEqual(result.reputation, "malicious")

    @patch("backend.threat_intel.virustotal_provider._requests.get")
    def test_domain_url_and_hash_endpoints(self, get):
        get.return_value = self._response(self._payload())
        for ioc_type, expected in [
            ("domain", "/domains/example.test"),
            ("url", "/urls/https://example.test/a"),
            ("sha256", "/files/aabbcc"),
        ]:
            with self.subTest(ioc_type=ioc_type):
                self.provider.enrich(ioc_type, "https://example.test/a" if ioc_type == "url" else "example.test" if ioc_type == "domain" else "aabbcc")
                self.assertTrue(get.call_args.args[0].endswith(expected))

    @patch("backend.threat_intel.virustotal_provider._requests.get")
    def test_missing_ioc(self, get):
        get.return_value = self._response({}, 404)
        result = self.provider.enrich("ip", "192.0.2.1")
        self.assertEqual(result.reputation, "unknown")
        self.assertEqual(result.provider_status, "unavailable")

    @patch("backend.threat_intel.virustotal_provider._requests.get")
    def test_invalid_key_and_rate_limit(self, get):
        for status in (401, 403, 429):
            get.return_value = self._response({}, status)
            result = self.provider.enrich("ip", "203.0.113.50")
            self.assertEqual(result.provider_status, "unavailable")

    @patch("backend.threat_intel.virustotal_provider._requests.get")
    def test_timeout(self, get):
        import requests
        get.side_effect = requests.exceptions.Timeout()
        result = self.provider.enrich("ip", "203.0.113.50")
        self.assertEqual(result.provider_status, "unavailable")
        self.assertIn("timeout", result.categories)

    @patch("backend.threat_intel.virustotal_provider._requests.get")
    def test_unexpected_response(self, get):
        get.return_value = self._response({"unexpected": True})
        result = self.provider.enrich("ip", "203.0.113.50")
        self.assertEqual(result.provider_status, "available")
        self.assertEqual(result.reputation, "unknown")

    def test_unsupported_type_does_not_call_api(self):
        with patch("backend.threat_intel.virustotal_provider._requests.get") as get:
            result = self.provider.enrich("unknown", "value")
            get.assert_not_called()
            self.assertEqual(result.provider_status, "unavailable")


if __name__ == "__main__":
    unittest.main()
