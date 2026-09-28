"""
RAG Evaluation Module.

Evaluates the FAISS retrieval pipeline using representative cybersecurity questions.
Computes hit rate, mean similarity score, and verifies source attribution metadata.

Run: python backend/rag/evaluate.py
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List

# Ensure project root in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.rag.retriever import retrieve_for_query

# Representative cybersecurity evaluation queries with expected keywords/topics
BENCHMARK_QUERIES = [
    {
        "query": "How to detect PowerShell encoded command execution and defense evasion?",
        "expected_keywords": ["powershell", "encoded", "execution", "t1059"],
        "category": "Execution / Defense Evasion",
    },
    {
        "query": "Indicators of brute force attacks against SSH and Windows RDP login attempts",
        "expected_keywords": ["brute force", "login", "authentication", "failed", "t1110"],
        "category": "Credential Access",
    },
    {
        "query": "Detecting LSASS memory dumping using Mimikatz or procdump",
        "expected_keywords": ["lsass", "credential", "dump", "mimikatz", "t1003"],
        "category": "Credential Access",
    },
    {
        "query": "Command and control beaconing behavior and suspicious outbound HTTP connections",
        "expected_keywords": ["c2", "beacon", "command and control", "traffic", "network", "t1071"],
        "category": "Command and Control",
    },
    {
        "query": "Lateral movement techniques using PsExec, WMI, and SMB",
        "expected_keywords": ["lateral movement", "psexec", "smb", "wmi", "t1021"],
        "category": "Lateral Movement",
    },
    {
        "query": "Wazuh rules for detecting privilege escalation and unauthorized admin rights",
        "expected_keywords": ["wazuh", "privilege", "rule", "escalation", "admin"],
        "category": "Detection Rules",
    },
]


def evaluate_rag(top_k: int = 3, verbose: bool = True) -> Dict[str, Any]:
    """
    Run evaluation against benchmark queries and calculate performance metrics.

    Returns:
        Dict containing total_queries, hits, hit_rate, mean_similarity, and detailed results.
    """
    total = len(BENCHMARK_QUERIES)
    hits = 0
    similarity_scores = []
    results = []

    for item in BENCHMARK_QUERIES:
        query = item["query"]
        expected = item["expected_keywords"]

        retrieved = retrieve_for_query(query, top_k=top_k)

        # Check if any expected keyword is present in retrieved chunk text or title
        hit = False
        matched_keywords = set()
        chunk_scores = []

        for chunk in retrieved:
            text_lower = f"{chunk.get('title', '')} {chunk.get('text', '')} {chunk.get('topic', '')}".lower()
            score = chunk.get("similarity_score", 0.0)
            chunk_scores.append(score)

            for kw in expected:
                if kw in text_lower:
                    hit = True
                    matched_keywords.add(kw)

        if hit:
            hits += 1

        avg_score = sum(chunk_scores) / len(chunk_scores) if chunk_scores else 0.0
        similarity_scores.append(avg_score)

        query_result = {
            "query": query,
            "category": item["category"],
            "hit": hit,
            "matched_keywords": list(matched_keywords),
            "top_source": retrieved[0].get("document", "none") if retrieved else "none",
            "top_score": round(chunk_scores[0], 4) if chunk_scores else 0.0,
            "retrieved_count": len(retrieved),
            "sources": [c.get("document", "") for c in retrieved],
        }
        results.append(query_result)

    hit_rate = round(hits / total, 4) if total > 0 else 0.0
    mean_sim = round(sum(similarity_scores) / len(similarity_scores), 4) if similarity_scores else 0.0

    summary = {
        "total_queries": total,
        "successful_retrievals": hits,
        "hit_rate": hit_rate,
        "mean_similarity_score": mean_sim,
        "benchmark_results": results,
    }

    if verbose:
        print("=" * 65)
        print("RAG BENCHMARK EVALUATION RESULTS")
        print("=" * 65)
        print(f"Total Benchmark Queries:   {total}")
        print(f"Successful Retrievals:     {hits}/{total} ({hit_rate * 100:.1f}%)")
        print(f"Mean Similarity Score:     {mean_sim:.4f}")
        print("-" * 65)
        for r in results:
            status = "PASS" if r["hit"] else "FAIL"
            print(f"[{status}] {r['category']}: score={r['top_score']:.4f} source={r['top_source']}")
            if r["matched_keywords"]:
                print(f"       Matched: {', '.join(r['matched_keywords'])}")
        print("=" * 65)

    return summary


if __name__ == "__main__":
    evaluate_rag()
