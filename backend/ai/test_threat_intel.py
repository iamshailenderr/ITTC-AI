"""
Stretch 3 - Threat Intelligence Enrichment Test
backend/ai/test_threat_intel.py

Tests the full pipeline:
  SecurityAlert
    -> IOC extraction (regex, no LLM)
    -> Mock TI enrichment (synthetic data, offline)
    -> RAG retrieval (FAISS semantic)
    -> Qwen3 analysis (RAG + TI context combined)
    -> AIAnalysis output

Synthetic alert uses RFC 5737 documentation IPs and IANA .test domains.
No real infrastructure is represented.
"""

import sys
import datetime

sys.path.insert(0, ".")

from backend.models.alert import SecurityAlert
from backend.threat_intel.extractor import extract_iocs
from backend.threat_intel.mock_provider import MockThreatIntelProvider
from backend.threat_intel.enricher import enrich_iocs, format_enrichment_for_prompt
from backend.rag.retriever import retrieve_context
from backend.ai.analyzer import analyze_alert


# ---------------------------------------------------------------------------
# Synthetic test alert
# ---------------------------------------------------------------------------

SYNTHETIC_ALERT = SecurityAlert(
    alert_id="TI-TEST-001",
    timestamp=datetime.datetime(2026, 8, 28, 8, 0, 0),
    source="Correlated (Suricata + Wazuh)",
    severity="Critical",
    host="WORKSTATION-07",
    user="jsmith",
    src_ip="203.0.113.50",
    dst_ip="10.0.0.55",
    event_type="Exploitation and PowerShell Execution",
    event=(
        "Suricata alert: Suspicious inbound HTTP traffic from 203.0.113.50 "
        "targeting internal web application. Source domain: c2-example.test. "
        "Wazuh alert: powershell.exe launched with -EncodedCommand flag by user "
        "jsmith on WORKSTATION-07, downloading payload from http://c2-example.test/stage2.exe. "
        "Process spawned by WINWORD.EXE indicating macro execution T1059.001."
    ),
    rule_id="92250",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _banner(title):
    print("\n" + "=" * 50)
    print(title)
    print("=" * 50)


def _pass_fail(condition, label):
    print(f"{label}: {'PASS' if condition else 'FAIL'}")
    return condition


# ---------------------------------------------------------------------------
# Test stages
# ---------------------------------------------------------------------------

def stage_ioc_extraction():
    print("\nExtracted IOCs:")
    iocs = extract_iocs(SYNTHETIC_ALERT)
    for ioc in iocs:
        print(f"  - {ioc.type.upper()}: {ioc.value}")

    ip_iocs     = [i for i in iocs if i.type == "ip"]
    domain_iocs = [i for i in iocs if i.type == "domain"]

    has_malicious_ip     = any(i.value == "203.0.113.50" for i in ip_iocs)
    has_c2_domain        = any("c2-example" in i.value for i in domain_iocs)
    private_not_included = all(not i.value.startswith("10.") for i in ip_iocs)

    ok = has_malicious_ip and has_c2_domain and private_not_included
    print(f"\n  [OK] Malicious IP 203.0.113.50 extracted     : {has_malicious_ip}")
    print(f"  [OK] C2 domain c2-example.test extracted     : {has_c2_domain}")
    print(f"  [OK] Private IP 10.0.0.55 correctly excluded : {private_not_included}")
    return ok, iocs


def stage_ti_enrichment(iocs):
    provider    = MockThreatIntelProvider()
    enrichments = enrich_iocs(iocs, provider=provider)

    print("\nThreat Intelligence:")
    for e in enrichments:
        cats = ", ".join(e.categories) if e.categories else "none"
        print(f"\n  - {e.value}")
        print(f"    Reputation : {e.reputation}")
        print(f"    Confidence : {e.confidence:.0%}")
        print(f"    Malicious  : {e.malicious}")
        print(f"    Category   : {cats}")
        print(f"    Detections : {e.detections}")
        print(f"    Source     : {e.source}")

    ip_enriched  = next((e for e in enrichments if e.type == "ip"   and e.value == "203.0.113.50"), None)
    dom_enriched = next((e for e in enrichments if e.type == "domain" and "c2-example" in e.value), None)

    ip_ok  = (ip_enriched  is not None
              and ip_enriched.reputation  == "malicious"
              and ip_enriched.confidence  >= 0.9)
    dom_ok = (dom_enriched is not None
              and dom_enriched.reputation == "malicious"
              and dom_enriched.confidence >= 0.9)

    ok = ip_ok and dom_ok
    print(f"\n  [OK] IP  203.0.113.50    malicious/high-confidence : {ip_ok}")
    print(f"  [OK] Dom c2-example.test malicious/high-confidence : {dom_ok}")
    return ok, enrichments


def stage_rag(alert):
    chunks = retrieve_context(alert, top_k=3)
    ok     = len(chunks) >= 1
    print(f"\n  [OK] Retrieved {len(chunks)} RAG chunk(s)")
    return ok


def stage_ai_analysis(alert):
    print("\n  Calling local Ollama / Qwen3 4b ...")
    try:
        result = analyze_alert(alert)
        return True, result
    except Exception as e:
        print(f"  ERROR: {e}")
        return False, None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    _banner("THREAT INTELLIGENCE ENRICHMENT TEST")

    print(f"\nSynthetic Alert:\n{SYNTHETIC_ALERT.event}")

    ioc_ok,  iocs        = stage_ioc_extraction()
    ti_ok,   enrichments = stage_ti_enrichment(iocs)
    rag_ok               = stage_rag(SYNTHETIC_ALERT)
    ai_ok,   result      = stage_ai_analysis(SYNTHETIC_ALERT)

    _banner("RESULTS")

    all_pass = all([ioc_ok, ti_ok, rag_ok, ai_ok])
    _pass_fail(rag_ok,   "RAG")
    _pass_fail(ioc_ok,   "IOC Extraction")
    _pass_fail(ti_ok,    "Threat Intelligence")
    _pass_fail(ai_ok,    "AI Analysis")
    _pass_fail(all_pass, "Final Correlation")

    if result:
        print("\nAI Output:")
        print(f"  Risk Score  : {result.risk_score}")
        print(f"  MITRE       : {', '.join(result.mitre_techniques)}")
        print(f"  Hypothesis  : {result.hypothesis}")
        print(f"  Confidence  : {result.confidence}")
        print(f"  Kill Chain  : {result.kill_chain_stage}")
        print("  Recommendations:")
        for r in result.recommendations:
            print(f"    - {r}")

        if result.ioc_enrichment:
            print(f"\n  IOC Enrichment records attached to AIAnalysis: {len(result.ioc_enrichment)}")
            for rec in result.ioc_enrichment:
                print(f"    [{rec['type'].upper()}] {rec['value']} -> {rec['reputation']}")

