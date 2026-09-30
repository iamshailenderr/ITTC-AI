# ITTC-AI — Autonomous AI-Driven SOC Copilot

**ITTC-AI** is an intelligent Security Operations Center (SOC) Copilot designed to ingest multi-source telemetry (Wazuh endpoint logs and Suricata network IDS alerts), correlate events into incidents, perform semantic RAG-grounded AI investigations using local LLMs (Qwen3), compute explainable risk scores, and manage an approval-gated Active Response containment lifecycle with automated safeguards and immutable audit logging.

---

## 🏛️ System Architecture

```
                    ┌─────────────────────────┐
                    │      Alert Sources      │
                    │  Suricata (Network IDS) │
                    │   Wazuh (Endpoint Log)  │
                    │   Mock (Test Dataset)   │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │  Ingestion & Normalizer │
                    │   OpenSearch / Indexer  │
                    │   SecurityAlert Model   │
                    └────────────┬────────────┘
                                 │
         ┌───────────────────────┼───────────────────────┐
         ▼                       ▼                       ▼
┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐
│   FAISS Vector   │    │  Threat Intel    │    │ ML Anomaly Model │
│   RAG Semantic   │    │  IOC Extractor   │    │ Isolation Forest │
│  Knowledge Base  │    │  Mock / VT Feed  │    │ Feature Analysis │
└────────┬─────────┘    └────────┬─────────┘    └────────┬─────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 ▼
                    ┌─────────────────────────┐
                    │ AI SOC Analyst (Qwen3)  │
                    │  Hypothesis & MITRE Map │
                    │  Kill Chain & Risk Score│
                    └────────────┬────────────┘
                                 │
         ┌───────────────────────┴───────────────────────┐
         ▼                                               ▼
┌─────────────────────────────────┐    ┌─────────────────────────────────┐
│       Incident Management       │    │     Active Response Engine      │
│  Union-Find Alert Correlation   │    │  Allowlist & Anti-Brick Guards  │
│  Timelines & Analyst Reporting  │    │  Approval-Gated Lifecycle       │
│  Interactive Copilot Chat Q&A   │    │  Simulated Dry-Run / Wazuh AR   │
└────────────────┬────────────────┘    └────────────────┬────────────────┘
                 │                                      │
                 └───────────────────┬──────────────────┘
                                     ▼
                    ┌─────────────────────────────────┐
                    │   FastAPI Backend (Port 8000)   │
                    │   Streamlit Console (Port 8501) │
                    └─────────────────────────────────┘
```

---

## 🚀 Key Features

### 1. Multi-Source Alert Ingestion & Normalization
- Ingests telemetry from **Wazuh Indexer (OpenSearch)** indices (`wazuh-alerts-4.x-*`) and local test datasets (`data/alerts.json`).
- Automatically extracts and normalizes native Wazuh Sysmon/Windows event logs and nested Suricata EVE JSON (`dest_ip`, `data.alert.signature`, `category`).
- Features sanitized error handling preventing credential leakage during network interruptions.

### 2. Semantic RAG & Threat Intelligence Enrichment
- **FAISS Knowledge Index**: Pre-indexed vector store across 28 curated cybersecurity playbooks covering MITRE ATT&CK techniques, Wazuh rules, and Suricata signatures.
- **Deterministic IOC Extractor**: Extracts public IPs, domains, URLs, and file hashes (MD5, SHA1, SHA256), strictly filtering RFC-1918 internal addresses.
- **Threat Intel Providers**: Plug-and-play architecture featuring offline mock enrichment (clearly labeled synthetic data) and VirusTotal integration.

### 3. Grounded AI Analysis & Explainable Risk
- Integrates with local **Ollama (`qwen3:14b`)** with strict JSON schema enforcement and `<think>` token filtering.
- Maps findings to the standard 7-stage **Lockheed Martin Cyber Kill Chain** and MITRE ATT&CK matrix.
- Generates evidence-grounded investigation hypotheses without hallucinating unobserved telemetry.
- Computes explainable risk factors quantifying exact contributions from alert severity, malicious IOCs, MITRE mappings, and anomaly scores.

### 4. Approval-Gated Active Response Subsystem
- **Lifecycle State Machine**: `PROPOSED` ➔ `PENDING_APPROVAL` ➔ `APPROVED` ➔ `SIMULATED` / `COMPLETED` ➔ `ROLLED_BACK`.
- **Action Allowlist**: Restricts execution to approved defensive actions:
  - `BLOCK_IP` & `UNBLOCK_IP` (Firewall containment)
  - `ISOLATE_HOST` & `REINTEGRATE_HOST` (Endpoint isolation)
  - `DISABLE_USER` & `ENABLE_USER` (Credential containment)
  - `TERMINATE_PROCESS` (Process mitigation)
  - `INVESTIGATE_ONLY` (Triage state)
- **Anti-Bricking Safeguards**: Automatically rejects actions targeting loopback addresses (`127.0.0.1`), network gateways (`10.0.0.1`, `192.168.0.1`), public DNS resolvers (`8.8.8.8`, `1.1.1.1`), Domain Controllers (`DC-01`), and critical system accounts (`root`, `system`).
- **Idempotency Protection**: Prevents duplicate executions of identical action-target pairs.
- **Safe Dry-Run Default**: Simulated execution is enforced by default (`ACTIVE_RESPONSE_MODE=simulated`, `ACTIVE_RESPONSE_ENABLED=false`).
- **Immutable Audit Trail**: Append-only log recording every proposal, approval, execution, and rollback with timestamps and analyst attribution.

### 5. Streamlit SOC Intelligence Dashboard
- Real-time alert triage, telemetry viewer, and single-click AI analysis.
- Visual composite risk gauges, Cyber Kill Chain progression, and explainable risk breakdown.
- Active Response management: approve, reject, or roll back containment proposals with clear simulation indicators.
- Central response queue and audit trail history viewer.

---

## 📦 Getting Started

### Prerequisites
- Python 3.10+ (tested on Python 3.13)
- Ollama running locally with `qwen3:14b`:
  ```bash
  ollama pull qwen3:14b
  ollama serve
  ```

### Installation
1. Clone the repository and enter the directory:
   ```bash
   cd ITTC-AI
   ```
2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   pip install sentence-transformers faiss-cpu scikit-learn pytest
   ```
3. Configure environment variables:
   ```bash
   cp .env.example .env
   ```
   *(Ensure `ALERT_SOURCE=mock` and `ACTIVE_RESPONSE_MODE=simulated` for offline development).*

---

## 🏃 Running the Application

### 1. Launch the FastAPI Backend
```bash
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```
API Documentation and Swagger UI will be available at:
`http://127.0.0.1:8000/docs`

### 2. Launch the Streamlit SOC Dashboard
In a separate terminal:
```bash
python -m streamlit run dashboard/app.py --server.port 8501
```
The dashboard will open automatically in your browser at:
`http://localhost:8501`

---

## 📡 REST API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/health` | Service health status |
| `GET` | `/api/alerts` | List all normalized security alerts |
| `GET` | `/api/alerts/{id}` | Read single alert details |
| `POST` | `/api/analyze/{id}` | Run RAG AI investigation and generate response proposal |
| `GET` | `/api/incidents` | List correlated security incidents |
| `GET` | `/api/incidents/{id}/report` | Generate comprehensive incident JSON report |
| `POST` | `/api/copilot/chat` | Conversational RAG Copilot endpoint |
| `GET` | `/api/responses` | List all Active Response records and proposals |
| `POST` | `/api/responses/propose` | Manually propose a response action |
| `POST` | `/api/responses/{id}/approve` | Analyst sign-off to execute response action |
| `POST` | `/api/responses/{id}/reject` | Analyst rejection of proposed action |
| `POST` | `/api/responses/{id}/rollback` | Rollback previously executed action (e.g. unblock IP) |
| `GET` | `/api/responses/audit/log` | Retrieve immutable audit history trail |

---

## 🧪 Testing & Verification

Run the full automated test suite (73 tests):
```bash
python -m pytest
```

Run specific test modules:
```bash
# Wazuh Indexer and Suricata normalization tests
python -m pytest tests/test_wazuh_indexer.py

# Active Response lifecycle, safeguards, and rollback tests
python -m pytest tests/test_active_response.py

# End-to-end SOC pipeline test
python -m pytest tests/test_e2e_soc_pipeline.py
```

---

## 🔒 Production Readiness & Live Wazuh Integration Requirements

Before transitioning Active Response to production live execution:
1. **Network Connectivity**: Verify bidirectional network reachability to Wazuh Indexer (port 9200) and Wazuh Manager API (port 55000).
2. **Manager Credentials**: Configure `WAZUH_MANAGER_USER` and `WAZUH_MANAGER_PASSWORD` with read-write permissions for the `/active-response` endpoint.
3. **Explicit Activation**: In `.env`, set:
   ```env
   ALERT_SOURCE=wazuh
   ACTIVE_RESPONSE_MODE=live_wazuh
   ACTIVE_RESPONSE_ENABLED=true
   ```
4. **Analyst Authorization**: Ensure role-based access control (RBAC) is implemented before exposing approval endpoints to untrusted networks.
