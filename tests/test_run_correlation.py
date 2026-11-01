"""
Unit and Integration tests for the Run Correlation pipeline:
1. Related Alerts Correlation
2. Unrelated Alerts (No-relation mandatory detection)
3. VirusTotal Error/Unavailable Resilience
4. Existing per-alert AI Analysis isolation
5. Existing PDF reports compatibility
"""

import unittest
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

from backend.models.alert import SecurityAlert
from backend.models.incident import CorrelationResult
from backend.threat_intel.extractor import extract_iocs, extract_all_iocs
from backend.services.incidents import (
    run_full_correlation_pipeline,
    get_latest_correlation_run,
    get_correlation_run,
    clear_incidents,
)
from backend.services.pdf_generator import (
    build_correlation_report_pdf,
    build_alert_pdf,
    build_soc_pdf,
    build_daily_summary_pdf,
)
from backend.ai.analyzer import analyze_alert
from backend.sources.mock import get_mock_alerts


class TestRunCorrelationPipeline(unittest.TestCase):

    def setUp(self):
        clear_incidents()

    def tearDown(self):
        clear_incidents()

    def test_1_related_alerts_correlation(self):
        """TEST 1: Correlated alerts should form groups, extract IOCs, enrich VT, and generate PDF."""
        a1 = SecurityAlert(
            alert_id="CORR-01",
            timestamp=datetime.now(timezone.utc),
            source="wazuh",
            severity="high",
            host="WIN-01",
            user="admin",
            src_ip="10.0.0.15",
            dst_ip="203.0.113.50",
            event_type="process_creation",
            event="Suspicious PowerShell execution observed connecting to external IP 203.0.113.50",
            rule_id="100101",
        )
        a2 = SecurityAlert(
            alert_id="CORR-02",
            timestamp=datetime.now(timezone.utc) + timedelta(minutes=4),
            source="suricata",
            severity="critical",
            host="WIN-01",
            user=None,
            src_ip="203.0.113.50",
            dst_ip="10.0.0.15",
            event_type="network_connection",
            event="ET TROJAN Cobalt Strike beacon communication observed to 203.0.113.50 domain c2-test.net",
            rule_id="2024897",
        )
        a3 = SecurityAlert(
            alert_id="CORR-03",
            timestamp=datetime.now(timezone.utc) + timedelta(minutes=10),
            source="wazuh",
            severity="high",
            host="WIN-01",
            user="admin",
            src_ip="10.0.0.15",
            dst_ip="10.0.0.20",
            event_type="lateral_movement",
            event="Remote PsExec service creation on DC-01 from host WIN-01",
            rule_id="100205",
        )

        with patch("requests.post", side_effect=Exception("Ollama offline in unit test")):
            result = run_full_correlation_pipeline([a1, a2, a3])

        self.assertIsInstance(result, CorrelationResult)
        self.assertEqual(result.status, "correlated")
        self.assertEqual(result.alerts_analyzed, 3)
        self.assertGreaterEqual(len(result.related_groups), 1)

        # Check IOC extraction
        iocs = result.iocs
        self.assertTrue(any(i.get("value") == "203.0.113.50" for i in iocs))

        # Check relationship reasoning
        grp = result.related_groups[0]
        self.assertIn("CORR-01", grp.alert_ids)
        self.assertIn("CORR-02", grp.alert_ids)
        self.assertTrue(len(grp.relationship_types) > 0)

        # Check Qwen analysis
        self.assertIsNotNone(result.qwen_analysis)
        self.assertTrue(len(result.qwen_analysis.summary) > 0)
        self.assertGreaterEqual(result.risk, 50)

        # Check PDF generation
        pdf_bytes = build_correlation_report_pdf(result.model_dump())
        self.assertTrue(pdf_bytes.startswith(b"%PDF"))
        self.assertGreater(len(pdf_bytes), 1000)

    def test_2_unrelated_alerts_no_relation(self):
        """TEST 2: Independent alerts must return 'no_relation' without inventing groups."""
        a1 = SecurityAlert(
            alert_id="IND-01",
            timestamp=datetime.now(timezone.utc),
            source="wazuh",
            severity="low",
            host="HOST-ALPHA",
            user="user_alice",
            src_ip="10.1.1.10",
            dst_ip="10.1.1.20",
            event_type="routine_audit",
            event="Routine system service restarted normally on host HOST-ALPHA",
            rule_id="10001",
        )
        a2 = SecurityAlert(
            alert_id="IND-02",
            timestamp=datetime.now(timezone.utc) + timedelta(hours=36),  # outside 24h window
            source="suricata",
            severity="medium",
            host="HOST-BETA",
            user="user_bob",
            src_ip="10.2.2.30",
            dst_ip="10.2.2.40",
            event_type="dns_query",
            event="Standard internal DNS lookup observed for intranet.internal",
            rule_id="20002",
        )

        with patch("requests.post", side_effect=Exception("Ollama offline in unit test")):
            result = run_full_correlation_pipeline([a1, a2])

        self.assertEqual(result.status, "no_relation")
        self.assertIn("No related alerts found", result.message)
        self.assertEqual(len(result.related_groups), 0)

        # PDF must still be valid and generated for the no-relation case
        pdf_bytes = build_correlation_report_pdf(result.model_dump())
        self.assertTrue(pdf_bytes.startswith(b"%PDF"))
        self.assertGreater(len(pdf_bytes), 1000)

    def test_3_virustotal_unavailable_resilience(self):
        """TEST 3: VirusTotal failures/timeouts must not crash the correlation pipeline."""
        mock_provider = MagicMock()
        mock_provider.enrich.side_effect = Exception("VirusTotal API 429 Rate Limit Exceeded")

        with patch("backend.services.incidents.get_provider", return_value=mock_provider), \
             patch("requests.post", side_effect=Exception("Ollama offline in unit test")):
            a1 = SecurityAlert(
                alert_id="VT-01",
                timestamp=datetime.now(timezone.utc),
                source="wazuh",
                severity="high",
                host="HOST-VT",
                src_ip="203.0.113.88",
                event_type="network_connection",
                event="Suspicious outbound communication to 203.0.113.88",
            )
            a2 = SecurityAlert(
                alert_id="VT-02",
                timestamp=datetime.now(timezone.utc) + timedelta(minutes=2),
                source="suricata",
                severity="critical",
                host="HOST-VT",
                src_ip="203.0.113.88",
                event_type="c2_traffic",
                event="Observed beacon to 203.0.113.88",
            )

            # Pipeline should complete without raising any exception
            result = run_full_correlation_pipeline([a1, a2])
            self.assertEqual(result.status, "correlated")
            self.assertEqual(len(result.related_groups), 1)

            # Threat intel summary should indicate safe fallback/unavailable status
            self.assertTrue(len(result.threat_intelligence) > 0)
            for ti in result.threat_intelligence:
                self.assertEqual(ti.provider_status, "unavailable")

            # PDF should still generate cleanly
            pdf_bytes = build_correlation_report_pdf(result.model_dump())
            self.assertTrue(pdf_bytes.startswith(b"%PDF"))

    def test_4_existing_ai_analysis_unmodified(self):
        """TEST 4: Existing per-alert AI Analysis (Alert -> RAG -> Qwen3) remains functional."""
        alert = SecurityAlert(
            alert_id="AI-TEST-01",
            timestamp=datetime.now(timezone.utc),
            source="wazuh",
            severity="high",
            host="TEST-SRV",
            event_type="credential_access",
            event="LSASS memory dump attempt detected T1003.001",
        )
        with patch("requests.post", side_effect=Exception("Ollama offline for unit test")):
            analysis = analyze_alert(alert)
            self.assertIsNotNone(analysis)
            self.assertTrue(hasattr(analysis, "summary"))
            self.assertTrue(hasattr(analysis, "risk_score"))
            self.assertTrue(hasattr(analysis, "mitre_techniques"))
            self.assertIn("T1003.001", analysis.mitre_techniques)

    def test_5_existing_pdf_reports_unmodified(self):
        """TEST 5: Verify existing individual alert and aggregate SOC reports continue working."""
        # 1. Existing individual alert PDF
        alert = SecurityAlert(
            alert_id="PDF-01",
            timestamp=datetime.now(timezone.utc),
            source="wazuh",
            severity="critical",
            host="HOST-PDF",
            event_type="malware_execution",
            event="Ransomware payload execution detected",
        )
        alert_pdf = build_alert_pdf(alert.model_dump())
        self.assertTrue(alert_pdf.startswith(b"%PDF"))

        # 2. Existing SOC Aggregate PDF
        soc_data = {
            "report_id": "SOC-REP-01",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "time_window": "Last 24 Hours",
            "total_alerts": 5,
            "severity_counts": {"critical": 1, "high": 2, "medium": 1, "low": 1},
            "alerts": [alert.model_dump()],
            "incidents": [],
            "mitre_summary": [],
            "threat_actors": [],
            "recommendations": ["Review network logs"],
        }
        soc_pdf = build_soc_pdf(soc_data)
        self.assertTrue(soc_pdf.startswith(b"%PDF"))

        # 3. Existing Daily Summary PDF
        daily_summary_data = {
            "report_id": "DAILY-01",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "reporting_period": {"display": "24-Hour Monitoring Interval"},
            "statistics": {
                "total_alerts": 10,
                "total_incidents": 2,
                "severity_counts": {"critical": 1, "high": 1, "medium": 0, "low": 0},
                "peak_risk": 90,
                "distinct_hosts_count": 2,
            },
            "overall_risk_summary": "Two high/critical incidents observed.",
            "incidents": [],
            "overall_recommendations": ["Patch vulnerability"],
        }
        daily_pdf = build_daily_summary_pdf(daily_summary_data)
        self.assertTrue(daily_pdf.startswith(b"%PDF"))


if __name__ == "__main__":
    unittest.main()
