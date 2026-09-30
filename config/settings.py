"""
P2 project settings.
Loads sensitive values from .env — never hardcode API keys here.
"""

import os

from dotenv import load_dotenv

load_dotenv()

OLLAMA_HOST: str = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "qwen3:4b")

# Alert source: "mock" (default) or "wazuh"
ALERT_SOURCE: str = os.getenv("ALERT_SOURCE", "mock").strip().lower()

# Wazuh Indexer / OpenSearch
WAZUH_INDEXER_URL: str = os.getenv(
    "WAZUH_INDEXER_URL", "https://192.168.0.106:9200"
)
WAZUH_INDEXER_USERNAME: str = os.getenv("WAZUH_INDEXER_USERNAME", "")
WAZUH_INDEXER_PASSWORD: str = os.getenv("WAZUH_INDEXER_PASSWORD", "")
WAZUH_INDEXER_INDEX: str = os.getenv(
    "WAZUH_INDEXER_INDEX", "wazuh-alerts-4.x-*"
)
WAZUH_INDEXER_LIMIT: int = int(os.getenv("WAZUH_INDEXER_LIMIT", "100"))
WAZUH_INDEXER_VERIFY_TLS: bool = (
    os.getenv("WAZUH_INDEXER_VERIFY_TLS", "true").strip().lower()
    in {"1", "true", "yes", "on"}
)
