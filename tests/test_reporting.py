"""
Unit tests for Incident & SOC Reporting services:
  - Individual Alert Report (JSON & PDF)
  - Aggregate SOC Security Report (JSON & PDF)
  - Original Incident JSON Report
  - Validation, Date Filtering, Statistics, Error Handling, and PDF Validity
"""

import unittest
from datetime import datetime, timedelta, timezone

from backend.models.alert import SecurityAlert
from backend.services.incidents import clear_incidents, correlate_alerts
from backend.services.pdf_generator import redact_sensitive, sanitize_text
from backend.services.reporting import (
    generate_alert_pdf,
    generate_alert_report_data,
    generate_incident_report,
    generate_soc_pdf,
    generate_soc_report_data,
    resolve_reporting_window,
    to_utc,
)


class TestIncidentReporting(unittest.TestCase):

    def setUp(self):
        clear_incidents()

    def tearDown(self):
        clear_incidents()

    # ----------------------------------------------------------------------
    # 1. Existing Incident JSON Report Tests (Preserved)
    # ----------------------------------------------------------------------

    def test_generate_report(self):
        alerts = [
            SecurityAlert(
                alert_id="A1",
                timestamp=datetime.now(timezone.utc),
                source="wazuh",
                severity="high",
                host="HOST-1",
                src_ip="203.0.113.195",
                dst_ip="10.0.0.1",
                event_type="lateral_movement",
                event="PsExec detected",
            )
        ]
        incidents = correlate_alerts(alerts)
        inc_id = incidents[0].incident_id

        report = generate_incident_report(inc_id)
        self.assertIsNotNone(report)
        self.assertIn("report_metadata", report)
        self.assertIn("incident", report)
        self.assertIn("alerts", report)
        self.assertIn("timeline", report)
        self.assertIn("iocs", report)
        self.assertIn("mitre_techniques", report)
        self.assertIn("risk", report)
        self.assertEqual(report["incident"]["incident_id"], inc_id)

    def test_generate_report_nonexistent_incident(self):
        report = generate_incident_report("NONEXISTENT-INC-ID")
        self.assertIsNone(report)

    # ----------------------------------------------------------------------
    # 2. Individual Alert Report Data & PDF Tests
    # ----------------------------------------------------------------------

    def test_generate_alert_report_data_valid(self):
        # ITTC-001 is a valid mock alert
        data = generate_alert_report_data("ITTC-001")
        self.assertIsNotNone(data)
        self.assertEqual(data["alert_id"], "ITTC-001")
        self.assertIn("RPT-ALR-ITTC-001-", data["report_id"])
        self.assertEqual(data["reporting_timezone"], "UTC (Coordinated Universal Time)")

        # Section B: Executive Summary
        self.assertIn("executive_summary", data)
        self.assertIn("detection_overview", data["executive_summary"])
        self.assertGreater(len(data["executive_summary"]["established_facts"]), 0)
        self.assertGreater(len(data["executive_summary"]["uncertainties"]), 0)

        # Section C: Alert Details
        details = data["alert_details"]
        self.assertEqual(details["host"], "WIN-01")
        self.assertEqual(details["source"], "wazuh")
        self.assertEqual(details["user"], "admin")
        self.assertEqual(details["src_ip"], "10.0.0.15")
        self.assertEqual(details["dst_ip"], "203.0.113.50")

        # Section D: Severity and Risk Assessment
        sev_risk = data["severity_and_risk"]
        self.assertEqual(sev_risk["source_severity"], "HIGH")
        self.assertGreaterEqual(sev_risk["ittc_risk_score"], 0)
        self.assertLessEqual(sev_risk["ittc_risk_score"], 100)
        self.assertIn(sev_risk["ittc_severity"], ("CRITICAL", "HIGH", "MEDIUM", "LOW"))
        self.assertIn("not a calibrated Bayesian probability", sev_risk["confidence_explanation"])

        # Section E: Impact and Damage Assessment
        impact = data["impact_assessment"]
        self.assertIn("WIN-01", str(impact["affected_assets"]))
        self.assertEqual(impact["damage_disclaimer"], "Actual damage could not be established from the available evidence.")

        # Section F: Supporting Evidence
        evidence = data["supporting_evidence"]
        self.assertIn("powershell.exe", evidence["log_excerpt"].lower())

        # Section G: Attack Analysis
        attack = data["attack_analysis"]
        self.assertGreater(len(attack["confirmed_findings"]), 0)
        self.assertIn("Root cause is currently unconfirmed", attack["root_cause_status"])

        # Section H: Remediation
        recs = data["remediation_recommendations"]
        self.assertGreater(len(recs), 0)
        for r in recs:
            self.assertIn("priority", r)
            self.assertIn("action", r)
            self.assertIn("reason", r)
            self.assertIn("caution", r)

        # Section I: Prevention
        self.assertGreater(len(data["prevention_measures"]), 0)

        # Section J: Analyst Conclusion
        conclusion = data["analyst_conclusion"]
        self.assertIn("overall_assessment", conclusion)
        self.assertIn("does not automatically resolve or close the incident", conclusion["resolution_disclaimer"])

    def test_generate_alert_report_data_unknown(self):
        data = generate_alert_report_data("UNKNOWN-ALERT-999")
        self.assertIsNone(data)

    def test_generate_alert_pdf_valid(self):
        pdf_bytes = generate_alert_pdf("ITTC-001")
        self.assertIsNotNone(pdf_bytes)
        self.assertIsInstance(pdf_bytes, bytes)
        self.assertTrue(pdf_bytes.startswith(b"%PDF-"))
        self.assertGreater(len(pdf_bytes), 1000)

    def test_generate_alert_pdf_unknown(self):
        pdf_bytes = generate_alert_pdf("UNKNOWN-ALERT-999")
        self.assertIsNone(pdf_bytes)

    def test_generate_alert_report_missing_optional_fields(self):
        # ITTC-002 has user=None, etc.
        data = generate_alert_report_data("ITTC-002")
        self.assertIsNotNone(data)
        self.assertEqual(data["alert_id"], "ITTC-002")
        self.assertEqual(data["alert_details"]["user"], "Not recorded / System")
        # PDF should generate without errors
        pdf_bytes = generate_alert_pdf("ITTC-002")
        self.assertIsNotNone(pdf_bytes)
        self.assertTrue(pdf_bytes.startswith(b"%PDF-"))

    # ----------------------------------------------------------------------
    # 3. Aggregate SOC Report Data & PDF Tests
    # ----------------------------------------------------------------------

    def test_resolve_reporting_window(self):
        # Relative last 24h
        s, e, disp = resolve_reporting_window("last_24h")
        self.assertAlmostEqual((e - s).total_seconds(), 24 * 3600, delta=10)
        self.assertIn("Last 24 Hours", disp)

        # Relative last 7d
        s7, e7, disp7 = resolve_reporting_window("last_7d")
        self.assertAlmostEqual((e7 - s7).total_seconds(), 7 * 24 * 3600, delta=10)
        self.assertIn("Last 7 Days", disp7)

        # Custom valid
        s_custom, e_custom, disp_c = resolve_reporting_window(
            "custom", "2026-08-01T00:00:00Z", "2026-08-31T23:59:59Z"
        )
        self.assertLess(s_custom, e_custom)
        self.assertIn("Custom Range", disp_c)

    def test_resolve_reporting_window_invalid(self):
        # Missing start/end
        with self.assertRaises(ValueError):
            resolve_reporting_window("custom", None, "2026-08-31T23:59:59Z")

        # start >= end
        with self.assertRaises(ValueError):
            resolve_reporting_window("custom", "2026-08-31T00:00:00Z", "2026-08-01T00:00:00Z")

    def test_generate_soc_report_data_empty_period(self):
        # A 1-second period in the year 2020 where no alerts exist
        data = generate_soc_report_data("custom", "2020-01-01T00:00:00Z", "2020-01-01T00:00:01Z")
        self.assertIsNotNone(data)
        self.assertEqual(data["security_statistics"]["total_alerts"], 0)
        self.assertEqual(data["security_statistics"]["active_incidents"], 0)
        self.assertIn("zero security alerts were registered", data["executive_summary"])

        # PDF must still generate cleanly for empty dataset
        pdf_bytes = generate_soc_pdf("custom", "2020-01-01T00:00:00Z", "2020-01-01T00:00:01Z")
        self.assertIsNotNone(pdf_bytes)
        self.assertTrue(pdf_bytes.startswith(b"%PDF-"))

    def test_generate_soc_report_data_with_alerts(self):
        # August 2026 contains mock alerts ITTC-001 to ITTC-005
        data = generate_soc_report_data("custom", "2026-08-01T00:00:00Z", "2026-08-31T23:59:59Z")
        self.assertIsNotNone(data)
        stats = data["security_statistics"]
        self.assertGreater(stats["total_alerts"], 0)
        self.assertGreater(stats["active_incidents"], 0)
        self.assertIn("distinct_hosts_count", stats)
        self.assertIn("severity_counts", stats)

        # Check coverage section
        cov = data["monitoring_coverage"]
        self.assertGreater(len(cov), 0)
        sources = [c["source"] for c in cov]
        self.assertIn("Wazuh Indexer (OpenSearch)", sources)

        # Check critical/high findings
        findings = data["critical_high_findings"]
        self.assertGreater(len(findings), 0)
        for f in findings:
            self.assertIn(f["severity"].lower(), ("critical", "high"))
            self.assertIn("alert_id", f)

        # Check recommendations
        self.assertGreater(len(data["recommended_actions"]), 0)

        # Check Appendix
        self.assertEqual(len(data["appendix"]["alerts"]), stats["total_alerts"])

        # Check PDF generation
        pdf_bytes = generate_soc_pdf("custom", "2026-08-01T00:00:00Z", "2026-08-31T23:59:59Z")
        self.assertIsNotNone(pdf_bytes)
        self.assertTrue(pdf_bytes.startswith(b"%PDF-"))
        self.assertGreater(len(pdf_bytes), 2000)

    def test_incident_counting_no_double_count(self):
        # Verifies that total incidents <= total alerts
        data = generate_soc_report_data("custom", "2026-08-01T00:00:00Z", "2026-08-31T23:59:59Z")
        stats = data["security_statistics"]
        self.assertLessEqual(stats["active_incidents"], stats["total_alerts"])

    # ----------------------------------------------------------------------
    # 4. Sanitization and Redaction Helpers
    # ----------------------------------------------------------------------

    def test_sanitize_text(self):
        raw = "Suspicious <script>alert(1)</script> & encoded -- 'cmd' \u2014 test"
        clean = sanitize_text(raw)
        self.assertNotIn("<script>", clean)
        self.assertIn("&lt;script&gt;", clean)
        self.assertIn("&amp;", clean)

    def test_redact_sensitive(self):
        raw = "Executed with password='Secret123!' and token=abc123xyz on host"
        redacted = redact_sensitive(raw)
        self.assertNotIn("Secret123!", redacted)
        self.assertIn("***REDACTED***", redacted)


if __name__ == "__main__":
    unittest.main()
