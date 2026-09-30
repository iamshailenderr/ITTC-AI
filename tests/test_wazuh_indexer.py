"""
Tests for Wazuh Indexer and Suricata Alert Ingestion & Normalization.
Verifies parsing, field normalization, pagination, direct ID lookup,
and error handling on network/auth failures without requiring live infrastructure.
"""

import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone
import requests

from backend.sources.wazuh_indexer import (
    _to_alert,
    _severity,
    get_wazuh_alerts,
    get_wazuh_alert,
    WazuhIndexerError,
    WazuhIndexerConnectionError,
    WazuhIndexerAuthError,
)
from backend.services.alerts import get_alerts, get_alert
from config import settings


class TestWazuhIndexerNormalization(unittest.TestCase):

    def test_severity_mapping(self):
        self.assertEqual(_severity(15), "critical")
        self.assertEqual(_severity(12), "critical")
        self.assertEqual(_severity(10), "high")
        self.assertEqual(_severity(8), "high")
        self.assertEqual(_severity(6), "medium")
        self.assertEqual(_severity(4), "medium")
        self.assertEqual(_severity(2), "low")
        self.assertEqual(_severity(0), "low")
        self.assertEqual(_severity(None), "low")
        self.assertEqual(_severity("invalid"), "low")

    def test_normalize_wazuh_agent_alert(self):
        hit = {
            "_id": "WAZUH-HIT-01",
            "_source": {
                "@timestamp": "2026-08-20T10:15:30Z",
                "agent": {"name": "WIN-SRV-01", "id": "002"},
                "rule": {
                    "id": 100101,
                    "level": 12,
                    "description": "Suspicious PowerShell command execution",
                    "groups": ["windows", "sysmon"],
                },
                "data": {
                    "srcuser": "svc_admin",
                    "src_ip": "10.0.0.12",
                    "dst_ip": "203.0.113.88",
                    "event_type": "process_creation",
                },
            },
        }
        alert = _to_alert(hit)
        self.assertEqual(alert.alert_id, "WAZUH-HIT-01")
        self.assertEqual(alert.source, "wazuh")
        self.assertEqual(alert.severity, "critical")
        self.assertEqual(alert.host, "WIN-SRV-01")
        self.assertEqual(alert.user, "svc_admin")
        self.assertEqual(alert.src_ip, "10.0.0.12")
        self.assertEqual(alert.dst_ip, "203.0.113.88")
        self.assertEqual(alert.event_type, "process_creation")
        self.assertEqual(alert.event, "Suspicious PowerShell command execution")
        self.assertEqual(alert.rule_id, "100101")
        self.assertEqual(alert.timestamp.tzinfo, timezone.utc)

    def test_normalize_suricata_eve_json_alert(self):
        hit = {
            "_id": "SURICATA-HIT-01",
            "_source": {
                "@timestamp": "2026-08-20T11:00:00Z",
                "agent": {"name": "GATEWAY-01"},
                "rule": {
                    "id": 86601,
                    "level": 9,
                    "description": "Suricata: Alert - ET TROJAN Generic C2 Beacon",
                    "groups": ["ids", "suricata"],
                },
                "data": {
                    "src_ip": "198.51.100.99",
                    "dest_ip": "10.0.0.50",  # Suricata uses dest_ip instead of dst_ip
                    "alert": {
                        "signature": "ET TROJAN Generic C2 Beacon",
                        "category": "A Network Trojan was detected",
                        "severity": 1,
                        "signature_id": 2024898,
                    },
                },
            },
        }
        alert = _to_alert(hit)
        self.assertEqual(alert.alert_id, "SURICATA-HIT-01")
        self.assertEqual(alert.source, "suricata")
        self.assertEqual(alert.severity, "high")
        self.assertEqual(alert.host, "GATEWAY-01")
        self.assertEqual(alert.src_ip, "198.51.100.99")
        self.assertEqual(alert.dst_ip, "10.0.0.50")
        self.assertEqual(alert.event_type, "A Network Trojan was detected")
        self.assertEqual(alert.rule_id, "86601")

    def test_normalize_windows_sysmon_event(self):
        hit = {
            "_id": "SYSMON-01",
            "_source": {
                "@timestamp": "2026-08-20T12:00:00Z",
                "agent": {"name": "ENDPOINT-05"},
                "rule": {
                    "id": 60100,
                    "level": 6,
                    "description": "Sysmon Network Connection",
                },
                "data": {
                    "win": {
                        "eventdata": {
                            "sourceIp": "10.0.0.35",
                            "destinationIp": "203.0.113.200",
                            "targetUserName": "john_doe",
                        }
                    }
                },
            },
        }
        alert = _to_alert(hit)
        self.assertEqual(alert.host, "ENDPOINT-05")
        self.assertEqual(alert.user, "john_doe")
        self.assertEqual(alert.src_ip, "10.0.0.35")
        self.assertEqual(alert.dst_ip, "203.0.113.200")
        self.assertEqual(alert.severity, "medium")

    @patch("backend.sources.wazuh_indexer.requests.get")
    def test_get_wazuh_alerts_pagination(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "hits": {
                "hits": [
                    {
                        "_id": "HIT-1",
                        "_source": {
                            "rule": {"id": 1, "level": 5, "description": "Test 1"},
                            "agent": {"name": "agent1"},
                        },
                    },
                    {
                        "_id": "HIT-2",
                        "_source": {
                            "rule": {"id": 2, "level": 10, "description": "Test 2"},
                            "agent": {"name": "agent2"},
                        },
                    },
                ]
            }
        }
        mock_get.return_value = mock_resp

        alerts = get_wazuh_alerts(limit=2, offset=5)
        self.assertEqual(len(alerts), 2)
        mock_get.assert_called_once()
        params = mock_get.call_args[1]["params"]
        self.assertEqual(params["size"], 2)
        self.assertEqual(params["from"], 5)

    @patch("backend.sources.wazuh_indexer.requests.get")
    def test_connection_error_handling(self, mock_get):
        mock_get.side_effect = requests.exceptions.ConnectionError("Connection refused")
        with self.assertRaises(WazuhIndexerConnectionError) as ctx:
            get_wazuh_alerts()
        self.assertIn("Unable to connect to Wazuh Indexer", str(ctx.exception))

    @patch("backend.sources.wazuh_indexer.requests.get")
    def test_auth_error_handling(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_get.return_value = mock_resp

        with self.assertRaises(WazuhIndexerAuthError) as ctx:
            get_wazuh_alerts()
        self.assertIn("Authentication failed", str(ctx.exception))

    @patch("backend.sources.wazuh_indexer.requests.post")
    def test_get_wazuh_alert_direct_lookup(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "hits": {
                "hits": [
                    {
                        "_id": "TARGET-ID-42",
                        "_source": {
                            "rule": {"id": 999, "level": 14, "description": "Critical breach"},
                            "agent": {"name": "PROD-DB-01"},
                        },
                    }
                ]
            }
        }
        mock_post.return_value = mock_resp

        alert = get_wazuh_alert("TARGET-ID-42")
        self.assertIsNotNone(alert)
        self.assertEqual(alert.alert_id, "TARGET-ID-42")
        self.assertEqual(alert.severity, "critical")
        self.assertEqual(alert.host, "PROD-DB-01")


if __name__ == "__main__":
    unittest.main()
