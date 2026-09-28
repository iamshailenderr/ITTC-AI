"""
SOC AI Copilot — RAG-grounded conversational assistant for SOC analysts.

Architecture:
    User question
    + current incident/alert context (when supplied)
    + relevant RAG/FAISS chunks
    + IOC/TI context (when relevant)
    → Qwen3
    → grounded answer with sources

The Copilot:
  - Uses REAL RAG retrieval from the FAISS index
  - Distinguishes retrieved knowledge from incident data
  - Does NOT invent telemetry or claim observations not in context
  - Returns RAG sources used for transparency
"""

from __future__ import annotations

import json
import re
import requests
from typing import Any, Dict, List, Optional

from backend.models.incident import CopilotRequest, CopilotResponse
from backend.rag.retriever import retrieve_for_query
from config.settings import OLLAMA_HOST, OLLAMA_MODEL


_COPILOT_SYSTEM_PROMPT = """\
You are an expert SOC (Security Operations Center) AI Copilot assistant.

Your role is to help security analysts investigate and respond to incidents.

Rules:
- Answer based ONLY on the provided knowledge context and incident/alert data.
- Clearly distinguish between:
  1. Knowledge from the cybersecurity knowledge base (RAG context)
  2. Actual incident/alert data (when provided)
  3. Your expert analysis connecting the two
- Do NOT invent telemetry, logs, or observations not present in the context.
- Do NOT recommend executing commands or triggering active response.
- Be concise, actionable, and security-focused.
- If you don't know something from the provided context, say so.
- Do NOT output reasoning or thinking tags (<think>).
- Respond in plain text (not JSON).
"""


def _build_copilot_prompt(
    question: str,
    rag_chunks: List[Dict[str, Any]],
    incident_context: str = "",
    alert_context: str = "",
    history: Optional[List[Dict[str, str]]] = None,
) -> List[Dict[str, str]]:
    """Build the message list for the Copilot LLM call."""
    messages = [{"role": "system", "content": _COPILOT_SYSTEM_PROMPT}]

    # Add conversation history (last 4 turns max)
    if history:
        for turn in history[-4:]:
            role = turn.get("role", "user")
            if role in ("user", "assistant"):
                messages.append({"role": role, "content": turn.get("content", "")})

    # Build user message with context
    context_parts = []

    if rag_chunks:
        rag_text = "\n\n---\n\n".join(
            f"[Source: {c.get('source', 'Unknown')} | {c.get('title', 'Unknown')}]\n{c.get('text', '')}"
            for c in rag_chunks
        )
        context_parts.append(f"## Cybersecurity Knowledge Context (from RAG retrieval)\n\n{rag_text}")

    if incident_context:
        context_parts.append(f"## Current Incident Data\n\n{incident_context}")

    if alert_context:
        context_parts.append(f"## Current Alert Data\n\n{alert_context}")

    context_block = "\n\n".join(context_parts) if context_parts else "No additional context available."

    user_message = f"""{context_block}

## Analyst Question

{question}

Provide a clear, actionable answer based on the above context."""

    messages.append({"role": "user", "content": user_message})
    return messages


def _format_incident_context(incident) -> str:
    """Format an Incident object into a text context block."""
    lines = [
        f"- Incident ID: {incident.incident_id}",
        f"- Status: {incident.status}",
        f"- Severity: {incident.severity}",
        f"- Risk Score: {incident.risk_score}/100",
        f"- Related Alerts: {', '.join(incident.related_alert_ids)}",
        f"- Summary: {incident.summary}",
    ]
    if incident.related_iocs:
        ioc_str = ", ".join(f"{i.get('type','?')}:{i.get('value','?')}" for i in incident.related_iocs[:10])
        lines.append(f"- IOCs: {ioc_str}")
    if incident.mitre_techniques:
        lines.append(f"- MITRE Techniques: {', '.join(incident.mitre_techniques)}")
    if incident.evidence:
        lines.append("- Evidence:")
        for e in incident.evidence[:5]:
            lines.append(f"  • {e[:200]}")
    if incident.recommendations:
        lines.append("- Recommendations:")
        for r in incident.recommendations[:5]:
            lines.append(f"  • {r}")
    return "\n".join(lines)


def _format_alert_context(alert) -> str:
    """Format a SecurityAlert object into a text context block."""
    return (
        f"- Alert ID: {alert.alert_id}\n"
        f"- Timestamp: {alert.timestamp}\n"
        f"- Source: {alert.source}\n"
        f"- Severity: {alert.severity}\n"
        f"- Host: {alert.host}\n"
        f"- User: {alert.user or 'N/A'}\n"
        f"- Source IP: {alert.src_ip or 'N/A'}\n"
        f"- Destination IP: {alert.dst_ip or 'N/A'}\n"
        f"- Event Type: {alert.event_type}\n"
        f"- Event: {alert.event}\n"
        f"- Rule ID: {alert.rule_id or 'N/A'}"
    )


def copilot_chat(request: CopilotRequest) -> CopilotResponse:
    """
    Process a Copilot chat request using RAG retrieval + Qwen3.

    Flow:
    1. Retrieve relevant RAG chunks for the user's question
    2. Load incident/alert context if IDs are provided
    3. Build grounded prompt with all context
    4. Send to local Ollama/Qwen3
    5. Return answer with sources

    Args:
        request: CopilotRequest with question and optional context IDs

    Returns:
        CopilotResponse with answer, sources, and context info
    """
    # 1. RAG retrieval on user's question
    rag_chunks = retrieve_for_query(request.question, top_k=5)

    # 2. Load incident context if provided
    incident_context = ""
    if request.incident_id:
        try:
            from backend.services.incidents import get_incident
            incident = get_incident(request.incident_id)
            if incident:
                incident_context = _format_incident_context(incident)
        except Exception:
            pass

    # 3. Load alert context if provided
    alert_context = ""
    if request.alert_id:
        try:
            from backend.services.alerts import get_alert
            alert = get_alert(request.alert_id)
            if alert:
                alert_context = _format_alert_context(alert)
        except Exception:
            pass

    # 4. Build prompt
    messages = _build_copilot_prompt(
        question=request.question,
        rag_chunks=rag_chunks,
        incident_context=incident_context,
        alert_context=alert_context,
        history=request.history,
    )

    # 5. Call Qwen3 via Ollama
    endpoint = f"{OLLAMA_HOST.rstrip('/')}/api/chat"
    payload = {
        "model": OLLAMA_MODEL,
        "messages": messages,
        "stream": False,
        "think": False,
        "options": {
            "temperature": 0.3,
            "num_predict": 800,
        },
    }

    try:
        response = requests.post(endpoint, json=payload, timeout=300)
    except requests.exceptions.ConnectionError:
        return CopilotResponse(
            answer="Unable to connect to the AI engine (Ollama). Please ensure Ollama is running locally.",
            sources=[],
            context={"error": "ollama_connection_failed"},
        )
    except requests.exceptions.RequestException as e:
        return CopilotResponse(
            answer=f"AI engine error: {str(e)}",
            sources=[],
            context={"error": str(e)},
        )

    if response.status_code != 200:
        return CopilotResponse(
            answer=f"AI engine returned an error (HTTP {response.status_code}).",
            sources=[],
            context={"error": f"http_{response.status_code}"},
        )

    res_data = response.json()
    raw_answer = res_data.get("message", {}).get("content", "")

    # Clean thinking tags if present
    raw_answer = re.sub(r"<think>[\s\S]*?</think>", "", raw_answer, flags=re.IGNORECASE).strip()

    if not raw_answer:
        raw_answer = "I was unable to generate a response. Please try rephrasing your question."

    # 6. Format sources
    sources = []
    for chunk in rag_chunks:
        sources.append({
            "document": chunk.get("document", "unknown"),
            "topic": chunk.get("topic", chunk.get("title", "")),
            "relevance": round(chunk.get("similarity_score", 0.0), 4),
            "category": chunk.get("category", ""),
            "source": chunk.get("source", ""),
        })

    context_info = {}
    if request.incident_id:
        context_info["incident_id"] = request.incident_id
    if request.alert_id:
        context_info["alert_id"] = request.alert_id

    return CopilotResponse(
        answer=raw_answer,
        sources=sources,
        context=context_info,
    )
