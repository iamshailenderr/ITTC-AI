"""
RAG retriever — retrieves relevant knowledge chunks for a security alert.
Uses sentence-transformers and FAISS for semantic local retrieval.
"""

import json
import os
import faiss
from typing import Any

from sentence_transformers import SentenceTransformer
from backend.models.alert import SecurityAlert

# Cache for globals
_MODEL = None
_INDEX = None
_METADATA = None

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
INDEX_PATH = os.path.join(BASE_DIR, "data", "rag", "index.faiss")
METADATA_PATH = os.path.join(BASE_DIR, "data", "rag", "metadata.json")
MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"

def _load_resources():
    global _MODEL, _INDEX, _METADATA
    
    if _MODEL is not None and _INDEX is not None and _METADATA is not None:
        return
        
    if not os.path.exists(INDEX_PATH) or not os.path.exists(METADATA_PATH):
        raise RuntimeError("FAISS index or metadata is missing. Please run: python backend/rag/build_index.py")
        
    print("Loading RAG resources...")
    _INDEX = faiss.read_index(INDEX_PATH)
    with open(METADATA_PATH, "r", encoding="utf-8") as f:
        _METADATA = json.load(f)
        
    _MODEL = SentenceTransformer(MODEL_NAME)
    print(f"Loaded {len(_METADATA)} vectors from FAISS index.")


def _build_query(alert: SecurityAlert) -> str:
    """Build a search query string from alert fields."""
    parts = [
        alert.event,
        alert.event_type,
        alert.source,
        alert.severity,
    ]
    if alert.host:
        parts.append(alert.host)
    if alert.user:
        parts.append(alert.user)
    if alert.rule_id:
        parts.append(alert.rule_id)
    return " ".join(parts)


def _search_index(query_text: str, top_k: int = 3) -> list[dict[str, Any]]:
    """
    Internal: embed a query string and search the FAISS index.
    Returns list of metadata dicts with similarity_score added.
    """
    _load_resources()

    emb = _MODEL.encode([query_text], convert_to_numpy=True)
    faiss.normalize_L2(emb)

    scores, indices = _INDEX.search(emb, top_k)

    results = []
    for score, idx in zip(scores[0], indices[0]):
        if idx < 0 or idx >= len(_METADATA):
            continue
        meta = _METADATA[idx].copy()
        meta["similarity_score"] = float(score)
        results.append(meta)

    return results


def retrieve_context_with_metadata(alert: SecurityAlert, top_k: int = 3) -> list[dict[str, Any]]:
    """
    Retrieve top_k chunks and return similarity scores with metadata.
    Useful for debugging and introspection.
    """
    query = _build_query(alert)
    return _search_index(query, top_k)


def retrieve_context(alert: SecurityAlert, top_k: int = 3) -> list[str]:
    """
    Retrieve the top_k most relevant knowledge chunks for the given alert.

    Uses FAISS and sentence-transformers for semantic search.
    Runs entirely locally.
    """
    results = retrieve_context_with_metadata(alert, top_k)
    return [res["text"] for res in results]


def retrieve_for_query(query_text: str, top_k: int = 5) -> list[dict[str, Any]]:
    """
    Retrieve top_k relevant knowledge chunks for an arbitrary text query.

    Used by the Copilot and other services that need RAG retrieval
    without a SecurityAlert object.

    Returns list of dicts with keys: text, source, category, document,
    title, chunk_id, similarity_score, topic (if available).
    """
    return _search_index(query_text, top_k)
