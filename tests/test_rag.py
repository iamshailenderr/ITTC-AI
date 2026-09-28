"""
Unit tests for RAG pipeline (retriever, chunk metadata, semantic search).
"""

import unittest
from datetime import datetime, timezone

from backend.models.alert import SecurityAlert
from backend.rag.retriever import retrieve_context, retrieve_context_with_metadata, retrieve_for_query
from backend.rag.evaluate import evaluate_rag


class TestRAGPipeline(unittest.TestCase):

    def test_retrieve_for_query(self):
        chunks = retrieve_for_query("PowerShell encoded command execution", top_k=3)
        self.assertEqual(len(chunks), 3)
        for chunk in chunks:
            self.assertIn("text", chunk)
            self.assertIn("source", chunk)
            self.assertIn("document", chunk)
            self.assertIn("similarity_score", chunk)
            self.assertGreater(chunk["similarity_score"], 0.0)

    def test_retrieve_context_with_metadata_for_alert(self):
        alert = SecurityAlert(
            alert_id="TEST-ALERT",
            timestamp=datetime.now(timezone.utc),
            source="wazuh",
            severity="high",
            host="WIN-01",
            event_type="process_creation",
            event="powershell.exe -enc JABzACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQA...",
        )
        results = retrieve_context_with_metadata(alert, top_k=3)
        self.assertEqual(len(results), 3)
        # Verify first result contains relevant keywords
        top_text = f"{results[0].get('title', '')} {results[0].get('text', '')}".lower()
        self.assertTrue(any(kw in top_text for kw in ["powershell", "execution", "script", "command"]))

    def test_retrieve_context_text_only(self):
        alert = SecurityAlert(
            alert_id="TEST-ALERT-2",
            timestamp=datetime.now(timezone.utc),
            source="suricata",
            severity="critical",
            host="DMZ-SRV",
            event_type="network_connection",
            event="Cobalt Strike beaconing observed to C2 server",
        )
        texts = retrieve_context(alert, top_k=2)
        self.assertEqual(len(texts), 2)
        self.assertIsInstance(texts[0], str)
        self.assertGreater(len(texts[0]), 20)

    def test_rag_evaluation_benchmark(self):
        eval_result = evaluate_rag(top_k=3, verbose=False)
        self.assertGreaterEqual(eval_result["hit_rate"], 0.8)
        self.assertGreaterEqual(eval_result["mean_similarity_score"], 0.3)


if __name__ == "__main__":
    unittest.main()
