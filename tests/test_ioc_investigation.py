"""
Unit tests for IOC Investigation service.
"""

import unittest

from backend.services.ioc_investigator import investigate_ioc


class TestIOCInvestigation(unittest.TestCase):

    def test_investigate_malicious_ip(self):
        # 203.0.113.50 is configured as malicious in mock TI
        result = investigate_ioc("ip", "203.0.113.50")
        self.assertEqual(result.ioc_type, "ip")
        self.assertEqual(result.value, "203.0.113.50")
        self.assertEqual(result.reputation, "malicious")
        self.assertTrue(result.malicious)
        self.assertGreater(result.confidence, 0.5)
        # Should identify mock source
        self.assertIn("Mock", result.source)

    def test_investigate_malicious_domain(self):
        # c2-example.test is in mock TI
        result = investigate_ioc("domain", "c2-example.test")
        self.assertEqual(result.ioc_type, "domain")
        self.assertEqual(result.reputation, "malicious")
        self.assertTrue(result.malicious)
        self.assertIn("C2", result.category)

    def test_investigate_unknown_ip(self):
        result = investigate_ioc("ip", "192.0.2.1")
        self.assertEqual(result.ioc_type, "ip")
        self.assertEqual(result.reputation, "unknown")
        self.assertFalse(result.malicious)


if __name__ == "__main__":
    unittest.main()
