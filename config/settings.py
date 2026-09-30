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

# Active Response Subsystem Configuration
# Mode: "simulated" (default safe dry-run) or "live_wazuh"
ACTIVE_RESPONSE_MODE: str = os.getenv("ACTIVE_RESPONSE_MODE", "simulated").strip().lower()
ACTIVE_RESPONSE_ENABLED: bool = (
    os.getenv("ACTIVE_RESPONSE_ENABLED", "false").strip().lower()
    in {"1", "true", "yes", "on"}
)
WAZUH_MANAGER_URL: str = os.getenv("WAZUH_MANAGER_URL", "https://192.168.0.106:55000")
WAZUH_MANAGER_USER: str = os.getenv("WAZUH_MANAGER_USER", "")
WAZUH_MANAGER_PASSWORD: str = os.getenv("WAZUH_MANAGER_PASSWORD", "")

# Safeguards: Protected Assets that must NEVER be blocked or isolated
PROTECTED_IPS: set[str] = {
    "127.0.0.1", "::1", "0.0.0.0",
    "10.0.0.1", "192.168.0.1", "192.168.1.1", "172.16.0.1",
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"
}
PROTECTED_HOSTS: set[str] = {
    "DC-01", "DC01", "DOMAIN-CONTROLLER", "WAZUH-SERVER", "GATEWAY-01"
}
PROTECTED_USERS: set[str] = {
    "system", "local system", "network service", "root", "administrator"
}

# Optional API Security Key for endpoints (if None, running in open dev mode)
API_KEY: str | None = os.getenv("API_KEY", "").strip() or None
