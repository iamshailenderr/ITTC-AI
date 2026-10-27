"""Focused offline tests for the VirusTotal provider."""

import base64
import os
import unittest
from unittest.mock import Mock, patch

import requests

from backend.threat_intel.virustotal_provider import (
    VirusTotalProvider,
    get_virustotal_provider,
)


class VirusTotalProviderTests(unittest.TestCase):
    def setUp(self):
        self.api_key = "test-secret-vt-key-12345"
        self.provider = VirusTotalProvider(self.api_key)

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
                    "categories": {"VendorA": "malware", "VendorB": "c2"},
                    "last_analysis_date": 1790000000,
                    "popular_threat_classification": {
                        "popular_threat_name": [{"value": "CobaltStrike"}]
                    },
                }
            }
        }

    # 1. IP Lookup
    @patch("backend.threat_intel.virustotal_provider._requests.get")
    def test_ip_lookup(self, get):
        get.return_value = self._response(self._payload())
        result = self.provider.enrich("ip", "203.0.113.50")
        self.assertEqual(result.source, "VirusTotal")
        self.assertEqual(result.provider_status, "available")
        self.assertTrue(get.call_args.args[0].endswith("/ip_addresses/203.0.113.50"))

    # 2. Domain Lookup
    @patch("backend.threat_intel.virustotal_provider._requests.get")
    def test_domain_lookup(self, get):
        get.return_value = self._response(self._payload())
        result = self.provider.enrich("domain", "C2-Example.Test")
        self.assertEqual(result.source, "VirusTotal")
        self.assertEqual(result.provider_status, "available")
        self.assertTrue(get.call_args.args[0].endswith("/domains/c2-example.test"))

    # 3. URL Lookup
    @patch("backend.threat_intel.virustotal_provider._requests.get")
    def test_url_lookup(self, get):
        get.return_value = self._response(self._payload())
        raw_url = "https://example.test/path?arg=1"
        expected_id = base64.urlsafe_b64encode(raw_url.encode("utf-8")).decode("ascii").rstrip("=")
        result = self.provider.enrich("url", raw_url)
        self.assertEqual(result.provider_status, "available")
        self.assertTrue(get.call_args.args[0].endswith(f"/urls/{expected_id}"))

    # 4. MD5 / SHA1 / SHA256 Hashes
    @patch("backend.threat_intel.virustotal_provider._requests.get")
    def test_hash_lookups_md5_sha1_sha256(self, get):
        get.return_value = self._response(self._payload())
        cases = [
            ("md5", "44D88612FEA8A8F36DE82E1278ABB02E", "/files/44d88612fea8a8f36de82e1278abb02e"),
            ("sha1", "2FD4E1C67A2D28FCED849EE1BB76E7391B93EB12", "/files/2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"),
            ("sha256", "AABBCCDD" * 8, f"/files/{('aabbccdd' * 8)}"),
        ]
        for ioc_type, val, expected_suffix in cases:
            with self.subTest(ioc_type=ioc_type):
                self.provider.enrich(ioc_type, val)
                self.assertTrue(get.call_args.args[0].endswith(expected_suffix))

    # 5. Successful VT Response Parsing
    @patch("backend.threat_intel.virustotal_provider._requests.get")
    def test_successful_vt_response_parsing(self, get):
        get.return_value = self._response(self._payload())
        result = self.provider.enrich("ip", "203.0.113.50")
        self.assertEqual(result.type, "ip")
        self.assertEqual(result.value, "203.0.113.50")
        self.assertEqual(result.reputation, "malicious")
        self.assertTrue(result.malicious)
        self.assertGreater(result.confidence, 0.0)

    # 6. Malicious / Suspicious / Harmless / Undetected / Total Engine Counts
    @patch("backend.threat_intel.virustotal_provider._requests.get")
    def test_engine_counts_parsing(self, get):
        get.return_value = self._response(self._payload())
        result = self.provider.enrich("ip", "203.0.113.50")
        self.assertEqual(result.malicious_count, 8)
        self.assertEqual(result.suspicious_count, 2)
        self.assertEqual(result.harmless_count, 55)
        self.assertEqual(result.undetected_count, 5)
        self.assertEqual(result.total_engines, 70)
        self.assertEqual(result.detections, 10)

    # 7. Reputation Parsing & Score
    @patch("backend.threat_intel.virustotal_provider._requests.get")
    def test_reputation_parsing(self, get):
        # Malicious payload
        get.return_value = self._response(self._payload())
        result = self.provider.enrich("ip", "203.0.113.50")
        self.assertEqual(result.reputation, "malicious")
        self.assertEqual(result.reputation_score, -15)

        # Benign payload
        benign_payload = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 65,
                        "undetected": 5,
                    },
                    "reputation": 20,
                }
            }
        }
        get.return_value = self._response(benign_payload)
        benign_result = self.provider.enrich("ip", "8.8.8.8")
        self.assertEqual(benign_result.reputation, "benign")
        self.assertFalse(benign_result.malicious)

    # 8. Categories Parsing
    @patch("backend.threat_intel.virustotal_provider._requests.get")
    def test_categories_parsing(self, get):
        get.return_value = self._response(self._payload())
        result = self.provider.enrich("ip", "203.0.113.50")
        self.assertIn("c2", result.categories)
        self.assertIn("malware", result.categories)

    # 9. Malware Family Parsing
    @patch("backend.threat_intel.virustotal_provider._requests.get")
    def test_malware_family_parsing(self, get):
        get.return_value = self._response(self._payload())
        result = self.provider.enrich("ip", "203.0.113.50")
        self.assertIn("CobaltStrike", result.malware_families)

    # 10. 404 / Not Found
    @patch("backend.threat_intel.virustotal_provider._requests.get")
    def test_not_found_404(self, get):
        get.return_value = self._response({"error": {"code": "NotFoundError"}}, 404)
        result = self.provider.enrich("ip", "192.0.2.1")
        self.assertEqual(result.reputation, "unknown")
        self.assertEqual(result.provider_status, "unavailable")
        self.assertIn("not_found", result.categories)

    # 11. 401 / 403 Invalid API Key
    @patch("backend.threat_intel.virustotal_provider._requests.get")
    def test_invalid_key_401_403(self, get):
        for status in (401, 403):
            with self.subTest(status=status):
                get.return_value = self._response({}, status)
                result = self.provider.enrich("ip", "203.0.113.50")
                self.assertEqual(result.provider_status, "unavailable")
                self.assertIn("invalid_api_key", result.categories)

    # 12. 429 Rate Limiting
    @patch("backend.threat_intel.virustotal_provider._requests.get")
    def test_rate_limiting_429(self, get):
        get.return_value = self._response({}, 429)
        result = self.provider.enrich("ip", "203.0.113.50")
        self.assertEqual(result.provider_status, "unavailable")
        self.assertIn("rate_limited", result.categories)

    # 13. Timeout Handling
    @patch("backend.threat_intel.virustotal_provider._requests.get")
    def test_timeout(self, get):
        get.side_effect = requests.exceptions.Timeout("Connection timed out")
        result = self.provider.enrich("ip", "203.0.113.50")
        self.assertEqual(result.provider_status, "unavailable")
        self.assertIn("timeout", result.categories)

    # 14. Network Failure
    @patch("backend.threat_intel.virustotal_provider._requests.get")
    def test_network_failure(self, get):
        get.side_effect = requests.exceptions.ConnectionError("DNS failure")
        result = self.provider.enrich("ip", "203.0.113.50")
        self.assertEqual(result.provider_status, "unavailable")
        self.assertIn("network_error", result.categories)

    # 15. Malformed and Unexpected Response
    @patch("backend.threat_intel.virustotal_provider._requests.get")
    def test_malformed_and_unexpected_response(self, get):
        # Non-JSON response
        bad_response = Mock()
        bad_response.status_code = 200
        bad_response.json.side_effect = ValueError("Invalid JSON")
        get.return_value = bad_response
        result = self.provider.enrich("ip", "203.0.113.50")
        self.assertEqual(result.provider_status, "unavailable")
        self.assertIn("invalid_response", result.categories)

        # JSON with null attributes
        get.return_value = self._response({"data": None})
        result_null = self.provider.enrich("ip", "203.0.113.50")
        self.assertEqual(result_null.provider_status, "available")
        self.assertEqual(result_null.reputation, "unknown")

    # 16. Missing API Key Validation
    def test_missing_api_key_validation(self):
        with self.assertRaises(ValueError):
            VirusTotalProvider("")
        with self.assertRaises(ValueError):
            VirusTotalProvider("   ")

    # 17. Unsupported IOC Type
    def test_unsupported_type_does_not_call_api(self):
        with patch("backend.threat_intel.virustotal_provider._requests.get") as get:
            result = self.provider.enrich("cve", "CVE-2024-1234")
            get.assert_not_called()
            self.assertEqual(result.provider_status, "unavailable")
            self.assertIn("unsupported_type", result.categories)

    # 18. API Key Never Exposed in Output
    @patch("backend.threat_intel.virustotal_provider._requests.get")
    def test_api_key_not_exposed_in_response_objects(self, get):
        get.return_value = self._response(self._payload())
        result = self.provider.enrich("ip", "203.0.113.50")
        dump = result.model_dump()
        dump_str = str(dump) + str(result)
        self.assertNotIn(self.api_key, dump_str)

    # 19. Provider Factory helper
    def test_get_virustotal_provider(self):
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "env-key-999"}):
            p = get_virustotal_provider()
            self.assertIsNotNone(p)
            self.assertIsInstance(p, VirusTotalProvider)

        with patch.dict(os.environ, {}, clear=True):
            p = get_virustotal_provider()
            self.assertIsNone(p)


if __name__ == "__main__":
    unittest.main()
