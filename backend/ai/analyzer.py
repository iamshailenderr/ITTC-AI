"""
AI analyzer — SecurityAlert → RAG retrieval → Local Ollama/Qwen3 → AIAnalysis.

Uses local Ollama HTTP API with robust structured JSON extraction.
RAG context is retrieved BEFORE the LLM call and provided as grounding.
Threat Intelligence IOC enrichment is appended as additional evidence.
"""

import json
import re
import requests

from backend.models.alert import SecurityAlert
from backend.models.analysis import AIAnalysis, RiskFactor, ResponseRecommendation, RAGSource
from backend.rag.retriever import retrieve_context_with_metadata
from backend.threat_intel.extractor import extract_iocs
from backend.threat_intel.enricher import enrich_iocs, get_provider, format_enrichment_for_prompt
from backend.ai.anomaly import detect_anomaly
from backend.ai.risk_explainer import compute_risk_factors
from backend.ai.response import generate_response_recommendation
from backend.ai.killchain import normalize_killchain_stage, map_event_to_killchain
from backend.ai.hypothesis import generate_investigation_hypothesis
from config.settings import OLLAMA_HOST, OLLAMA_MODEL


_SYSTEM_PROMPT = """\
You are an expert defensive SOC analyst performing structured security alert analysis.

Analyze only the supplied security alert and retrieved knowledge context.

Rules:
- Base evidence ONLY on what the alert actually contains or retrieved RAG context.
- Do NOT invent telemetry or claim observation of details not in the alert.
- Clearly distinguish between alert evidence, knowledge context, and your hypothesis.
- Identify relevant MITRE ATT&CK techniques (e.g. "T1059.001").
- Estimate risk score between 0 and 100 as an integer.
- Estimate confidence score between 0.0 and 1.0 as a float.
- Identify the most appropriate Cyber Kill Chain stage.
- List concrete evidence observed in the alert.
- Provide practical, defensive investigation recommendations.
- Do NOT recommend executing commands or triggering Active Response.
- Do NOT output reasoning or thinking tags (<think>).
- Respond ONLY with a valid raw JSON object strictly matching this schema:

{
  "summary": "<string>",
  "risk_score": <integer 0-100>,
  "severity": "<string>",
  "mitre_techniques": ["<string>"],
  "hypothesis": "<string>",
  "confidence": <float 0.0-1.0>,
  "kill_chain_stage": "<string>",
  "evidence": ["<string>"],
  "recommendations": ["<string>"]
}
"""


def _build_user_prompt(
    alert: SecurityAlert,
    context_chunks: list[str],
    enrichment_text: str = "",
) -> str:
    """Build the user prompt with alert data, RAG context, and optional TI enrichment."""
    context_text = "\n\n---\n\n".join(context_chunks) if context_chunks else "No additional context available."

    prompt = f"""\
## Security Alert

- Alert ID: {alert.alert_id}
- Timestamp: {alert.timestamp.isoformat()}
- Source: {alert.source}
- Severity: {alert.severity}
- Host: {alert.host}
- User: {alert.user or "N/A"}
- Source IP: {alert.src_ip or "N/A"}
- Destination IP: {alert.dst_ip or "N/A"}
- Event Type: {alert.event_type}
- Event: {alert.event}
- Rule ID: {alert.rule_id or "N/A"}

## Retrieved Knowledge Context

{context_text}"""

    if enrichment_text:
        prompt += f"\n\n{enrichment_text}"

    prompt += "\n\nAnalyze this alert and produce a structured security analysis JSON."
    return prompt


def _extract_and_parse_json(text: str) -> dict:
    """Extract JSON object from LLM response text and parse it."""
    # Remove <think>...</think> tags if Qwen3 outputs thinking tokens
    cleaned = re.sub(r"<think>[\s\S]*?</think>", "", text, flags=re.IGNORECASE).strip()

    # Try direct JSON parsing
    try:
        return json.loads(cleaned)
    except Exception:
        pass

    # Try extracting from markdown ```json ... ``` block
    match = re.search(r"```(?:json)?\s*(\{[\s\S]*?\})\s*```", cleaned, re.IGNORECASE)
    if match:
        try:
            return json.loads(match.group(1))
        except Exception:
            pass

    # Try finding outermost curly braces { ... }
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start != -1 and end != -1 and end > start:
        json_str = cleaned[start : end + 1]
        try:
            return json.loads(json_str)
        except Exception:
            pass

    raise ValueError(f"Could not extract valid JSON from LLM response: {text[:200]}")


def _sanitize_and_validate_analysis(
    parsed: dict,
    alert: SecurityAlert,
    enrichments: list[dict] = None,
) -> dict:
    """
    Sanitize and coerce dictionary values to ensure it strictly conforms to AIAnalysis schema.
    Prevents runtime validation crashes caused by minor LLM format variations.
    """
    # 1. Summary
    summary = str(parsed.get("summary") or "").strip()
    if not summary:
        summary = f"Security alert on host '{alert.host}': {alert.event[:180]}"

    # 2. Risk score (clamp 0-100)
    raw_risk = parsed.get("risk_score")
    try:
        risk_score = int(float(raw_risk))
    except (TypeError, ValueError):
        risk_score = 75 if alert.severity.lower() in ("critical", "high") else 45
    risk_score = max(0, min(100, risk_score))

    # 3. Severity
    severity = str(parsed.get("severity") or alert.severity).lower()
    if severity not in ("critical", "high", "medium", "low"):
        severity = alert.severity.lower() if alert.severity.lower() in ("critical", "high", "medium", "low") else "medium"

    # 4. MITRE techniques
    raw_techniques = parsed.get("mitre_techniques")
    techniques: list[str] = []
    if isinstance(raw_techniques, list):
        for t in raw_techniques:
            found = re.findall(r"T\d{4}(?:\.\d{3})?", str(t), re.IGNORECASE)
            for f in found:
                techniques.append(f.upper())
    # Fallback to regex from alert event if empty
    if not techniques:
        found_in_event = re.findall(r"T\d{4}(?:\.\d{3})?", alert.event, re.IGNORECASE)
        techniques = [t.upper() for t in found_in_event]
    techniques = sorted(list(set(techniques)))

    # 5. Kill chain stage
    raw_kc = parsed.get("kill_chain_stage")
    if raw_kc and str(raw_kc).strip():
        kill_chain_stage = normalize_killchain_stage(str(raw_kc))
    else:
        kill_chain_stage = map_event_to_killchain(
            event_type=alert.event_type,
            event_text=alert.event,
            mitre_techniques=techniques,
        )

    # 6. Hypothesis
    hypothesis = str(parsed.get("hypothesis") or "").strip()
    if not hypothesis or len(hypothesis) < 15:
        hypothesis = generate_investigation_hypothesis(
            alert=alert,
            mitre_techniques=techniques,
            kill_chain_stage=kill_chain_stage,
            enrichments=enrichments,
        )

    # 7. Confidence (clamp 0.0-1.0)
    raw_conf = parsed.get("confidence")
    try:
        conf_val = float(raw_conf)
        if conf_val > 1.0:
            conf_val = conf_val / 100.0
    except (TypeError, ValueError):
        conf_val = 0.8
    confidence = max(0.0, min(1.0, round(conf_val, 2)))

    # 8. Evidence
    raw_evidence = parsed.get("evidence")
    evidence: list[str] = []
    if isinstance(raw_evidence, list):
        evidence = [str(e).strip() for e in raw_evidence if str(e).strip()]
    if not evidence:
        evidence = [alert.event[:200]]
        if alert.src_ip:
            evidence.append(f"Source IP: {alert.src_ip}")
        if alert.dst_ip:
            evidence.append(f"Destination IP: {alert.dst_ip}")

    # 9. Recommendations
    raw_recs = parsed.get("recommendations")
    recs: list[str] = []
    if isinstance(raw_recs, list):
        recs = [str(r).strip() for r in raw_recs if str(r).strip()]
    if not recs:
        recs = [
            f"Review security logs on host '{alert.host}' for related suspicious activity",
            "Verify network connections associated with observed IP addresses",
        ]

    return {
        "summary": summary,
        "risk_score": risk_score,
        "severity": severity,
        "mitre_techniques": techniques,
        "hypothesis": hypothesis,
        "confidence": confidence,
        "kill_chain_stage": kill_chain_stage,
        "evidence": evidence,
        "recommendations": recs,
    }


def analyze_alert(alert: SecurityAlert) -> AIAnalysis:
    """
    Analyze a SecurityAlert and produce an AIAnalysis using local Ollama (Qwen3).

    Flow:
    1. Retrieve relevant RAG context for the alert.
    2. Extract IOCs from the alert (deterministic, no LLM).
    3. Enrich IOCs via the active TI provider (mock or VirusTotal).
    4. Build security-analysis prompt with alert + RAG + TI enrichment.
    5. Send prompt to local Ollama API.
    6. Convert Qwen3 response into AIAnalysis with validation/sanitization.
    7. Return AIAnalysis.
    """
    # Step 1: RAG retrieval with metadata
    raw_chunks = retrieve_context_with_metadata(alert, top_k=3)
    context_chunks = [c.get("text", "") for c in raw_chunks]
    rag_sources = [
        RAGSource(
            document=c.get("document", "unknown"),
            topic=c.get("topic", c.get("title", "")),
            relevance=round(c.get("similarity_score", 0.0), 4),
            category=c.get("category", ""),
        )
        for c in raw_chunks
    ]

    # Step 1b: Anomaly detection
    anomaly_score, is_anomalous = detect_anomaly(alert)

    # Step 2 & 3: IOC extraction + TI enrichment (offline-safe; never fails hard)
    enrichments = []
    enrichment_text = ""
    enrichment_dicts = None
    try:
        iocs = extract_iocs(alert)
        if iocs:
            provider = get_provider()
            enrichments = enrich_iocs(iocs, provider=provider)
            enrichment_text = format_enrichment_for_prompt(enrichments)
            enrichment_dicts = [e.model_dump() for e in enrichments]
    except Exception:
        pass  # TI enrichment is best-effort; never block the core analysis

    # Step 4: Build prompt
    user_prompt = _build_user_prompt(alert, context_chunks, enrichment_text)

    # Step 5: Send to local Ollama API
    endpoint = f"{OLLAMA_HOST.rstrip('/')}/api/chat"
    payload = {
        "model": OLLAMA_MODEL,
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
        "stream": False,
        "think": False,
        "format": "json",
        "options": {
            "temperature": 0.1,
            "num_predict": 500,
        },
    }

    parsed_dict = {}
    try:
        response = requests.post(endpoint, json=payload, timeout=300)
        if response.status_code == 200:
            res_data = response.json()
            raw_content = res_data.get("message", {}).get("content", "")
            if raw_content:
                parsed_dict = _extract_and_parse_json(raw_content)
    except Exception:
        # Fall back to deterministic RAG and hypothesis generation
        parsed_dict = {}

    sanitized = _sanitize_and_validate_analysis(
        parsed=parsed_dict,
        alert=alert,
        enrichments=enrichment_dicts,
    )

    analysis = AIAnalysis.model_validate(sanitized)

    # Attach enrichment data
    if enrichment_dicts:
        analysis.ioc_enrichment = enrichment_dicts

    # Attach RAG sources
    analysis.rag_sources = rag_sources

    # Attach anomaly score and flag
    analysis.anomaly_score = anomaly_score
    analysis.is_anomalous = is_anomalous

    # Attach explainable risk factors
    analysis.risk_factors = compute_risk_factors(
        alert=alert,
        enrichments=enrichment_dicts,
        mitre_techniques=analysis.mitre_techniques,
        anomaly_score=anomaly_score,
        is_anomalous=is_anomalous,
    )

    # Attach response recommendation (recommendation only, requires approval)
    analysis.response_recommendation = generate_response_recommendation(
        alert=alert,
        enrichments=enrichment_dicts,
        risk_score=analysis.risk_score,
    )

    return analysis
