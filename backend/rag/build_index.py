"""
Build persistent FAISS vector index and metadata for local cybersecurity RAG.
Reads documents from data/knowledge/, generates embeddings using sentence-transformers,
builds a FAISS index, and saves to data/rag/.

Run: python backend/rag/build_index.py
"""

import json
import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import faiss
import numpy as np
from sentence_transformers import SentenceTransformer

from backend.rag.ingest import load_knowledge_chunks, reset_cache

RAG_DIR = PROJECT_ROOT / "data" / "rag"
INDEX_PATH = RAG_DIR / "index.faiss"
METADATA_PATH = RAG_DIR / "metadata.json"

MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"


def build_faiss_index():
    """Build FAISS index and metadata file from knowledge chunks."""
    print("=" * 60)
    print("BUILDING LOCAL CYBERSECURITY FAISS RAG INDEX")
    print("=" * 60)

    # 1. Reset cache and load chunks
    reset_cache()
    chunks = load_knowledge_chunks()

    if not chunks:
        print("ERROR: No knowledge chunks found in data/knowledge/!")
        sys.exit(1)

    unique_docs = len(set(c["document"] for c in chunks))
    print(f"Loaded {len(chunks)} chunks from {unique_docs} knowledge document(s).")

    # 2. Prepare texts for embedding
    embedding_texts = []
    for chunk in chunks:
        # Prepend source and title context to optimize semantic vector matching
        text_to_embed = f"Source: {chunk['source']} | Title: {chunk['title']}\n{chunk['text']}"
        embedding_texts.append(text_to_embed)

    # 3. Load embedding model
    print(f"Loading embedding model: '{MODEL_NAME}'...")
    model = SentenceTransformer(MODEL_NAME)

    # 4. Generate normalized embeddings
    print("Generating chunk embeddings...")
    embeddings = model.encode(
        embedding_texts,
        normalize_embeddings=True,
        show_progress_bar=True,
        convert_to_numpy=True
    ).astype("float32")

    dimension = embeddings.shape[1]
    print(f"Generated {embeddings.shape[0]} embeddings of dimension {dimension}.")

    # 5. Build FAISS IndexFlatIP (Cosine Similarity)
    index = faiss.IndexFlatIP(dimension)
    index.add(embeddings)

    # 6. Save index and metadata
    RAG_DIR.mkdir(parents=True, exist_ok=True)
    faiss.write_index(index, str(INDEX_PATH))

    with open(METADATA_PATH, "w", encoding="utf-8") as f:
        json.dump(chunks, f, indent=2)

    print("\nBUILD SUCCESSFUL!")
    print(f"Documents:           {unique_docs}")
    print(f"Chunks:              {len(chunks)}")
    print(f"Embedding dimension: {dimension}")
    print(f"Index File:          {INDEX_PATH}")
    print(f"Metadata File:       {METADATA_PATH}")
    print("=" * 60)


if __name__ == "__main__":
    build_faiss_index()
