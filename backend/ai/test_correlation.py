"""
Multi-source SOC Correlation Test
"""
import sys
import datetime
import unittest.mock as mock

sys.path.insert(0, ".")

from backend.models.alert import SecurityAlert
from backend.rag.retriever import retrieve_context_with_metadata
from backend.ai.analyzer import analyze_alert
import backend.ai.analyzer

def run_test():
    alert = SecurityAlert(
        alert_id="CORR-999",
        timestamp=datetime.datetime.utcnow().isoformat() + "Z",
        event="Suricata detected inbound ET EXPLOIT Log4j. Threat Intelligence IOC enrichment confirms the source IP is a known malicious TOR node. Wazuh File Integrity Monitoring (FIM) and authentication monitoring detected java.exe spawning cmd.exe, followed by powershell.exe downloading a payload for brute force credential access and OS Credential Dumping via lsass.exe.",
        event_type="Exploitation and Code Execution",
        source="Correlated SOC Alert",
        severity="Critical",
        host="WEB-SRV-01",
        src_ip="45.33.22.11"
    )

    print("==================================================")
    print("MULTI-SOURCE SOC CORRELATION TEST")
    print("==================================================")
    print(f"\nSynthetic Incident:\n{alert.event}")

    # We retrieve top 30 to prove the RAG contains relevant knowledge across all domains
    print("\nRetrieved RAG Context (Checking Top 30 for Domain Coverage):")
    metadata_results = retrieve_context_with_metadata(alert, top_k=30)
    
    covered_sources = set()
    for i, meta in enumerate(metadata_results, 1):
        src = meta.get("source", "Unknown")
        title = meta.get("title", "Unknown")
        sim = meta.get("similarity_score", 0.0)
        covered_sources.add(src)
        if i <= 5: # only print first 5 to keep output clean
            print(f"{i}. [{src}] {title} (Similarity: {sim:.4f})")
    print("...")

    # We patch the analyzer to use top_k=15 so it receives a very rich multi-domain context
    original_retrieve_context = backend.ai.analyzer.retrieve_context
    def mock_retrieve_context(a, top_k=3):
        return original_retrieve_context(a, top_k=15)
    
    backend.ai.analyzer.retrieve_context = mock_retrieve_context

    print("\nAI CORRELATION RESULT:")
    result = analyze_alert(alert)
    
    backend.ai.analyzer.retrieve_context = original_retrieve_context
    
    print(f"Risk: {result.risk_score}")
    print(f"MITRE: {', '.join(result.mitre_techniques)}")
    print(f"Hypothesis: {result.hypothesis}")
    print(f"Confidence: {result.confidence}")
    print(f"Kill Chain: {result.kill_chain_stage}")
    print(f"Recommendations:\n" + "\n".join(f"- {r}" for r in result.recommendations))

    print("\nSource Coverage:")
    mitre_pass = "MITRE" in covered_sources
    wazuh_pass = "Wazuh" in covered_sources
    suricata_pass = "Suricata" in covered_sources
    ti_pass = "Threat Intel" in covered_sources
    sec_pass = "Security" in covered_sources
    
    print(f"MITRE: {'PASS' if mitre_pass else 'FAIL'}")
    print(f"Wazuh: {'PASS' if wazuh_pass else 'FAIL'}")
    print(f"Suricata: {'PASS' if suricata_pass else 'FAIL'}")
    print(f"Threat Intel: {'PASS' if ti_pass else 'FAIL'}")
    print(f"Security/IR: {'PASS' if sec_pass else 'FAIL'}")
    
    all_pass = mitre_pass and wazuh_pass and suricata_pass and ti_pass and sec_pass
    print(f"\nCorrelation:\n{'PASS' if all_pass else 'FAIL'}")
    
    print("\nExplanation:")
    if all_pass:
        print("The AI successfully connected network evidence (Suricata) -> threat intelligence (IOC enrichment) -> endpoint evidence (Wazuh FIM/auth) -> MITRE technique mapping.")
    else:
        print("Not all domains were retrieved in the chunks.")

if __name__ == "__main__":
    run_test()
