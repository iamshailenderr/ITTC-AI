"""
Phase 4 validation — tests RAG retrieval and Ollama/Qwen3 AI analysis on ITTC-001.
Run: python backend/ai/test_analysis.py
"""

import sys
sys.path.insert(0, ".")

from backend.sources.mock import get_mock_alerts
from backend.rag.retriever import retrieve_context
from backend.ai.analyzer import analyze_alert


def test_rag():
    """Verify RAG retrieval returns relevant chunks for ITTC-001."""
    alerts = get_mock_alerts()
    alert = alerts[0]
    chunks = retrieve_context(alert, top_k=3)

    print("=" * 50)
    print("RAG RETRIEVAL TEST")
    print("=" * 50)
    print(f"Alert: {alert.alert_id}")
    print(f"Retrieved chunks: {len(chunks)}")

    if len(chunks) == 0:
        print("FAIL — no chunks retrieved")
        return False

    for i, chunk in enumerate(chunks, 1):
        preview = chunk[:120].replace("\n", " ")
        print(f"  Chunk {i}: {preview}...")

    print("RAG TEST OK")
    return True


def test_ai():
    """Test AI analysis using local Ollama / Qwen3 4B model."""
    alerts = get_mock_alerts()
    alert = alerts[0]

    print("\n" + "=" * 50)
    print("AI ANALYSIS TEST")
    print("=" * 50)
    print(f"Analyzing alert: {alert.alert_id}")
    print("Calling local Ollama API (qwen3:4b)...")

    try:
        result = analyze_alert(alert)
    except Exception as e:
        print(f"FAIL — {e}")
        return False

    print("\nAI ANALYSIS OK\n")
    print(f"Risk:\n{result.risk_score}")
    print(f"\nMITRE:\n{', '.join(result.mitre_techniques)}")
    print(f"\nHypothesis:\n{result.hypothesis}")
    print(f"\nConfidence:\n{result.confidence}")
    print(f"\nKill Chain:\n{result.kill_chain_stage}")
    print(f"\nRecommendations:\n{', '.join(result.recommendations)}")

    return True


if __name__ == "__main__":
    rag_ok = test_rag()
    ai_ok = test_ai()

    print("\n" + "=" * 50)
    print("RESULTS")
    print("=" * 50)
    print(f"RAG:  {'PASS' if rag_ok else 'FAIL'}")
    print(f"AI:   {'PASS' if ai_ok else 'FAIL'}")
