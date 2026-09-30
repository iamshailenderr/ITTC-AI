"""
ITTC-AI SOC Security Intelligence Dashboard

Streamlit application for monitoring normalized security alerts, triggering
RAG-grounded local AI analysis, approval-gated Active Response execution,
explainable risk factors, and tamper-resistant audit logging.
"""

import os
import requests
import streamlit as st

# Configuration
BACKEND_URL = os.getenv("BACKEND_URL", "http://127.0.0.1:8000").rstrip("/")
API_KEY = os.getenv("API_KEY", "").strip()


def _get_headers() -> dict:
    return {"X-API-Key": API_KEY} if API_KEY else {}

# Page Configuration
st.set_page_config(
    page_title="ITTC-AI Security Operations Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom SOC Dark Theme CSS
CUSTOM_CSS = """
<style>
    /* Dark Theme Base Styles */
    .stApp {
        background-color: #0e1117;
        color: #c9d1d9;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    }
    
    /* Header Styling */
    .soc-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 1.2rem 1.8rem;
        background: linear-gradient(90deg, #161b22 0%, #0d1117 100%);
        border-bottom: 1px solid #30363d;
        border-radius: 8px;
        margin-bottom: 1.5rem;
    }
    .soc-title {
        font-size: 1.6rem;
        font-weight: 700;
        color: #58a6ff;
        margin: 0;
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }
    .soc-subtitle {
        font-size: 0.85rem;
        color: #8b949e;
        margin-top: 0.2rem;
    }

    /* Cards & Containers */
    .soc-card {
        background-color: #161b22;
        border: 1px solid #30363d;
        border-radius: 8px;
        padding: 1.25rem;
        margin-bottom: 1rem;
    }
    .soc-card-title {
        font-size: 0.95rem;
        font-weight: 700;
        color: #8b949e;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        margin-bottom: 0.75rem;
        border-bottom: 1px solid #21262d;
        padding-bottom: 0.4rem;
    }

    /* Severity & Status Badges */
    .badge {
        display: inline-block;
        padding: 0.25rem 0.6rem;
        font-size: 0.75rem;
        font-weight: 700;
        border-radius: 4px;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    .badge-critical { background-color: #7f1d1d; color: #fca5a5; border: 1px solid #ef4444; }
    .badge-high { background-color: #7c2d12; color: #fdba74; border: 1px solid #f97316; }
    .badge-medium { background-color: #713f12; color: #fde047; border: 1px solid #eab308; }
    .badge-low { background-color: #14532d; color: #86efac; border: 1px solid #22c55e; }
    .badge-info { background-color: #1e3a8a; color: #93c5fd; border: 1px solid #3b82f6; }

    /* Active Response Lifecycle Badges */
    .badge-pending { background-color: #78350f; color: #fde68a; border: 1px solid #d97706; }
    .badge-simulated { background-color: #064e3b; color: #6ee7b7; border: 1px solid #059669; }
    .badge-completed { background-color: #14532d; color: #86efac; border: 1px solid #22c55e; }
    .badge-rejected { background-color: #374151; color: #9ca3af; border: 1px solid #4b5563; }
    .badge-failed { background-color: #7f1d1d; color: #fca5a5; border: 1px solid #ef4444; }
    .badge-rollback { background-color: #4c1d95; color: #c4b5fd; border: 1px solid #7c3aed; }

    /* Risk Score Gauge Display */
    .risk-score-box {
        text-align: center;
        padding: 1.2rem;
        border-radius: 8px;
        background: #0d1117;
        border: 2px solid #30363d;
    }
    .risk-score-value {
        font-size: 3.5rem;
        font-weight: 800;
        line-height: 1;
        margin: 0.4rem 0;
    }
    .risk-critical { color: #ff4d4f; border-color: #ff4d4f; text-shadow: 0 0 10px rgba(255, 77, 79, 0.3); }
    .risk-high { color: #ffa940; border-color: #ffa940; text-shadow: 0 0 10px rgba(255, 169, 64, 0.3); }
    .risk-medium { color: #ffec3d; border-color: #ffec3d; }
    .risk-low { color: #73d13d; border-color: #73d13d; }

    /* MITRE Technique Tag */
    .mitre-tag {
        display: inline-block;
        background-color: #1f2937;
        color: #38bdf8;
        border: 1px solid #0284c7;
        padding: 0.25rem 0.5rem;
        border-radius: 4px;
        font-family: monospace;
        font-size: 0.85rem;
        margin: 0.2rem;
        font-weight: 600;
    }

    /* List items in results */
    .evidence-item {
        background-color: #0d1117;
        border-left: 3px solid #f97316;
        padding: 0.5rem 0.8rem;
        margin-bottom: 0.4rem;
        border-radius: 0 4px 4px 0;
        font-family: monospace;
        font-size: 0.85rem;
    }
    .recommendation-item {
        background-color: #0d1117;
        border-left: 3px solid #22c55e;
        padding: 0.5rem 0.8rem;
        margin-bottom: 0.4rem;
        border-radius: 0 4px 4px 0;
        font-size: 0.88rem;
    }
    .factor-item {
        background-color: #0d1117;
        border-left: 3px solid #38bdf8;
        padding: 0.5rem 0.8rem;
        margin-bottom: 0.4rem;
        border-radius: 0 4px 4px 0;
        font-size: 0.85rem;
    }
    .banner-simulated {
        background-color: #064e3b22;
        border: 1px solid #059669;
        color: #a7f3d0;
        padding: 0.6rem 1rem;
        border-radius: 6px;
        font-size: 0.85rem;
        margin-bottom: 0.8rem;
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


# ============================================================================
# API Helper Functions
# ============================================================================

@st.cache_data(ttl=5)
def check_health() -> bool:
    """Check if the backend FastAPI service is reachable."""
    try:
        res = requests.get(f"{BACKEND_URL}/health", timeout=3)
        return res.status_code == 200 and res.json().get("status") == "ok"
    except Exception:
        return False


def fetch_alerts() -> list[dict]:
    """Fetch normalized security alerts from backend REST API."""
    try:
        res = requests.get(f"{BACKEND_URL}/api/alerts", timeout=5)
        if res.status_code == 200:
            return res.json()
        st.error(f"Failed to load alerts from backend (HTTP {res.status_code})")
        return []
    except Exception as e:
        st.error(f"Error fetching alerts: {e}")
        return []


def run_ai_analysis(alert_id: str) -> dict | None:
    """Trigger AI analysis for an alert via FastAPI POST endpoint."""
    try:
        res = requests.post(f"{BACKEND_URL}/api/analyze/{alert_id}", timeout=310)
        if res.status_code == 200:
            return res.json()
        elif res.status_code == 404:
            st.error(f"Alert '{alert_id}' not found on backend.")
            return None
        else:
            err_detail = res.json().get("detail", res.text)
            st.error(f"Analysis Failed ({res.status_code}): {err_detail}")
            return None
    except Exception as e:
        st.error(f"Analysis request error: {e}")
        return None


def fetch_responses(alert_id: str | None = None) -> list[dict]:
    """Fetch Active Response records from backend."""
    try:
        params = {"alert_id": alert_id} if alert_id else {}
        res = requests.get(f"{BACKEND_URL}/api/responses", params=params, timeout=5)
        if res.status_code == 200:
            return res.json()
        return []
    except Exception:
        return []


def approve_response_api(response_id: str, approver: str = "soc_analyst", reason: str = "") -> dict | None:
    """Approve and trigger simulated/dry-run Active Response."""
    try:
        payload = {"approver": approver, "reason": reason}
        res = requests.post(f"{BACKEND_URL}/api/responses/{response_id}/approve", json=payload, headers=_get_headers(), timeout=10)
        if res.status_code == 200:
            return res.json()
        st.error(f"Approval failed: {res.json().get('detail', res.text)}")
        return None
    except Exception as e:
        st.error(f"Approval error: {e}")
        return None


def reject_response_api(response_id: str, rejected_by: str = "soc_analyst", reason: str = "") -> dict | None:
    """Reject an active response item."""
    try:
        payload = {"rejected_by": rejected_by, "reason": reason or "Rejected by analyst"}
        res = requests.post(f"{BACKEND_URL}/api/responses/{response_id}/reject", json=payload, headers=_get_headers(), timeout=10)
        if res.status_code == 200:
            return res.json()
        st.error(f"Rejection failed: {res.json().get('detail', res.text)}")
        return None
    except Exception as e:
        st.error(f"Rejection error: {e}")
        return None


def rollback_response_api(response_id: str, actor: str = "soc_analyst") -> dict | None:
    """Roll back an executed response."""
    try:
        res = requests.post(f"{BACKEND_URL}/api/responses/{response_id}/rollback?actor={actor}", headers=_get_headers(), timeout=10)
        if res.status_code == 200:
            return res.json()
        st.error(f"Rollback failed: {res.json().get('detail', res.text)}")
        return None
    except Exception as e:
        st.error(f"Rollback error: {e}")
        return None


def fetch_audit_logs(limit: int = 50) -> list[dict]:
    """Fetch immutable audit log trail."""
    try:
        res = requests.get(f"{BACKEND_URL}/api/responses/audit/log?limit={limit}", timeout=5)
        if res.status_code == 200:
            return res.json()
        return []
    except Exception:
        return []


def get_severity_badge_html(severity: str) -> str:
    """Return HTML string for severity badge."""
    sev = severity.lower()
    if sev == "critical":
        return '<span class="badge badge-critical">CRITICAL</span>'
    elif sev == "high":
        return '<span class="badge badge-high">HIGH</span>'
    elif sev == "medium":
        return '<span class="badge badge-medium">MEDIUM</span>'
    elif sev == "low":
        return '<span class="badge badge-low">LOW</span>'
    else:
        return f'<span class="badge badge-info">{severity.upper()}</span>'


def get_state_badge_html(state: str) -> str:
    """Return HTML string for Active Response state badge."""
    s = state.upper()
    if s == "PENDING_APPROVAL":
        return '<span class="badge badge-pending">PENDING APPROVAL</span>'
    elif s == "SIMULATED":
        return '<span class="badge badge-simulated">SIMULATED (DRY RUN)</span>'
    elif s == "COMPLETED":
        return '<span class="badge badge-completed">COMPLETED (LIVE)</span>'
    elif s == "REJECTED":
        return '<span class="badge badge-rejected">REJECTED</span>'
    elif s == "FAILED":
        return '<span class="badge badge-failed">FAILED</span>'
    elif s == "ROLLED_BACK":
        return '<span class="badge badge-rollback">ROLLED BACK</span>'
    else:
        return f'<span class="badge badge-info">{s}</span>'


# ============================================================================
# Main Dashboard Application
# ============================================================================

def main():
    # Sidebar
    st.sidebar.title("🛡️ ITTC-AI SOC Control")
    
    is_healthy = check_health()
    if is_healthy:
        st.sidebar.success(f"Backend Connected ({BACKEND_URL})")
    else:
        st.sidebar.error(f"Backend Offline ({BACKEND_URL})")
        st.sidebar.info("Start backend with:\n`python -m uvicorn backend.main:app --reload`")

    st.sidebar.markdown("---")
    st.sidebar.markdown("### ⚙️ Operating Modes")
    st.sidebar.info("**Active Response:** `SIMULATED` (Dry-run by default)\n\n"
                    "**Safeguards:** Gateways, DNS & Domain Controllers Protected\n\n"
                    "**Alert Source:** `mock` (Controlled test dataset)")

    if st.sidebar.button("🔄 Refresh Data", use_container_width=True):
        st.cache_data.clear()
        st.rerun()

    # Main Header
    st.markdown("""
    <div class="soc-header">
        <div>
            <div class="soc-title">🛡️ ITTC-AI Security Operations Center</div>
            <div class="soc-subtitle">Suricata & Wazuh Telemetry • Local Qwen3 RAG Copilot • Approval-Gated Active Response</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    if not is_healthy:
        st.warning("⚠️ Backend service is currently unavailable. Please start the FastAPI backend service to access alerts and AI analysis.")
        return

    # Ingest Alerts
    alerts = fetch_alerts()
    if not alerts:
        st.info("No security alerts available.")
        return

    # Dashboard Tabs
    tab_triage, tab_responses, tab_audit = st.tabs([
        "🚨 Alert Triage & AI Copilot",
        "⚡ Active Response Queue",
        "📜 Response Audit Trail"
    ])

    # ========================================================================
    # TAB 1: Alert Triage & AI Copilot
    # ========================================================================
    with tab_triage:
        # Top Metrics
        mcol1, mcol2, mcol3, mcol4 = st.columns(4)
        mcol1.metric("Total Ingested Alerts", len(alerts))
        high_count = sum(1 for a in alerts if a.get("severity", "").lower() in ["high", "critical"])
        mcol2.metric("High/Critical Alerts", high_count)
        sources = set(a.get("source", "N/A").upper() for a in alerts)
        mcol3.metric("Log Sources", ", ".join(sources))
        mcol4.metric("Active Response Mode", "Simulated (Dry-Run)")

        st.markdown("### 📋 Security Alerts Queue")

        # Alert Selection
        alert_ids = [a["alert_id"] for a in alerts]
        if "selected_alert_id" not in st.session_state:
            st.session_state["selected_alert_id"] = alert_ids[0]

        selected_alert = next((a for a in alerts if a["alert_id"] == st.session_state["selected_alert_id"]), alerts[0])

        # Table Header
        cols = st.columns([1.2, 1.8, 1, 1, 1.2, 2.5, 1.2])
        cols[0].markdown("**Alert ID**")
        cols[1].markdown("**Timestamp**")
        cols[2].markdown("**Source**")
        cols[3].markdown("**Severity**")
        cols[4].markdown("**Host**")
        cols[5].markdown("**Event Type / Description**")
        cols[6].markdown("**Action**")

        st.markdown("---")

        for alert in alerts:
            aid = alert["alert_id"]
            c1, c2, c3, c4, c5, c6, c7 = st.columns([1.2, 1.8, 1, 1, 1.2, 2.5, 1.2])
            is_selected = (aid == selected_alert["alert_id"])
            highlight = "👉 " if is_selected else ""
            
            c1.markdown(f"**{highlight}`{aid}`**")
            c2.text(alert.get("timestamp", "")[:19].replace("T", " "))
            c3.text(alert.get("source", "").upper())
            c4.markdown(get_severity_badge_html(alert.get("severity", "medium")), unsafe_allow_html=True)
            c5.text(alert.get("host", "N/A"))
            c6.text(alert.get("event", "")[:45] + "..." if len(alert.get("event", "")) > 45 else alert.get("event", ""))
            
            if c7.button("Inspect", key=f"btn_{aid}", use_container_width=True, type="primary" if is_selected else "secondary"):
                st.session_state["selected_alert_id"] = aid
                st.rerun()

        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown(f"## 🔍 Alert Telemetry & AI Investigation: `{selected_alert['alert_id']}`")

        dcol1, dcol2 = st.columns([1, 1])

        with dcol1:
            st.markdown('<div class="soc-card"><div class="soc-card-title">Alert Telemetry & Context</div>', unsafe_allow_html=True)
            meta1, meta2 = st.columns(2)
            meta1.markdown(f"**Alert ID:** `{selected_alert['alert_id']}`")
            meta1.markdown(f"**Severity:** {get_severity_badge_html(selected_alert['severity'])}", unsafe_allow_html=True)
            meta1.markdown(f"**Source:** {selected_alert['source'].upper()}")
            meta1.markdown(f"**Rule ID:** `{selected_alert.get('rule_id') or 'N/A'}`")
            
            meta2.markdown(f"**Host:** `{selected_alert.get('host') or 'N/A'}`")
            meta2.markdown(f"**User:** `{selected_alert.get('user') or 'N/A'}`")
            meta2.markdown(f"**Source IP:** `{selected_alert.get('src_ip') or 'N/A'}`")
            meta2.markdown(f"**Destination IP:** `{selected_alert.get('dst_ip') or 'N/A'}`")

            st.markdown(f"**Event Type:** `{selected_alert.get('event_type', 'N/A')}`")
            st.markdown("**Raw Event Payload:**")
            st.code(selected_alert.get("event", ""), language="text")
            st.markdown('</div>', unsafe_allow_html=True)

        with dcol2:
            st.markdown('<div class="soc-card"><div class="soc-card-title">AI SOC Copilot & RAG Engine</div>', unsafe_allow_html=True)
            st.markdown("""
            Click below to retrieve semantic RAG knowledge (MITRE ATT&CK, Wazuh rules, Suricata signatures)
            and run local **Qwen3** alert investigation and response proposal.
            """)
            
            analysis_key = f"analysis_result_{selected_alert['alert_id']}"
            analyze_clicked = st.button("⚡ Run AI Analysis & Propose Response", key=f"analyze_btn_{selected_alert['alert_id']}", use_container_width=True, type="primary")

            if analyze_clicked:
                with st.spinner(f"Retrieving RAG knowledge context & executing AI analysis for alert '{selected_alert['alert_id']}'..."):
                    result = run_ai_analysis(selected_alert['alert_id'])
                    if result:
                        st.session_state[analysis_key] = result
                        st.rerun()

            if analysis_key in st.session_state:
                st.success("AI Analysis generated and loaded.")
            else:
                st.info("No analysis run for this alert yet. Click 'Run AI Analysis & Propose Response' above.")
            st.markdown('</div>', unsafe_allow_html=True)

        # AI Results & Response Section
        if analysis_key in st.session_state:
            analysis_data = st.session_state[analysis_key]
            
            st.markdown("---")
            st.markdown("## 🤖 RAG-Grounded AI Analysis Results")

            # Metrics Row
            rcol1, rcol2, rcol3, rcol4 = st.columns([1.2, 1, 1, 1.2])
            risk_score = int(analysis_data.get("risk_score", 0))
            if risk_score >= 80:
                risk_class = "risk-critical"
            elif risk_score >= 60:
                risk_class = "risk-high"
            elif risk_score >= 40:
                risk_class = "risk-medium"
            else:
                risk_class = "risk-low"

            with rcol1:
                st.markdown(f"""
                <div class="risk-score-box {risk_class}">
                    <div style="font-size: 0.8rem; font-weight: 700; color: #8b949e; text-transform: uppercase;">Composite Risk</div>
                    <div class="risk-score-value">{risk_score}</div>
                    <div style="font-size: 0.8rem; color: #8b949e;">Out of 100</div>
                </div>
                """, unsafe_allow_html=True)

            with rcol2:
                st.markdown('<div class="soc-card"><div class="soc-card-title">Severity Assessment</div>', unsafe_allow_html=True)
                st.markdown(get_severity_badge_html(analysis_data.get("severity", "Unknown")), unsafe_allow_html=True)
                st.markdown('</div>', unsafe_allow_html=True)

            with rcol3:
                st.markdown('<div class="soc-card"><div class="soc-card-title">Confidence Score</div>', unsafe_allow_html=True)
                conf = float(analysis_data.get("confidence", 0.0))
                st.markdown(f"<h3 style='margin:0; color:#58a6ff;'>{conf*100:.0f}%</h3>", unsafe_allow_html=True)
                st.markdown('</div>', unsafe_allow_html=True)

            with rcol4:
                st.markdown('<div class="soc-card"><div class="soc-card-title">Cyber Kill Chain</div>', unsafe_allow_html=True)
                kc = analysis_data.get("kill_chain_stage", "N/A")
                st.markdown(f"<h4 style='margin:0; color:#f0883e;'>{kc}</h4>", unsafe_allow_html=True)
                st.markdown('</div>', unsafe_allow_html=True)

            # Deep Breakdown
            res_col1, res_col2 = st.columns(2)

            with res_col1:
                st.markdown('<div class="soc-card"><div class="soc-card-title">Executive Summary</div>', unsafe_allow_html=True)
                st.write(analysis_data.get("summary", "No summary provided."))
                st.markdown('</div>', unsafe_allow_html=True)

                st.markdown('<div class="soc-card"><div class="soc-card-title">Investigation Hypothesis</div>', unsafe_allow_html=True)
                st.write(analysis_data.get("hypothesis", "No hypothesis generated."))
                st.markdown('</div>', unsafe_allow_html=True)

                # MITRE ATT&CK
                st.markdown('<div class="soc-card"><div class="soc-card-title">MITRE ATT&CK Techniques</div>', unsafe_allow_html=True)
                techniques = analysis_data.get("mitre_techniques", [])
                if techniques:
                    html_tags = "".join([f'<span class="mitre-tag">{t}</span>' for t in techniques])
                    st.markdown(html_tags, unsafe_allow_html=True)
                else:
                    st.text("No specific MITRE techniques identified.")
                st.markdown('</div>', unsafe_allow_html=True)

                # Explainable Risk Factors
                risk_factors = analysis_data.get("risk_factors") or []
                if risk_factors:
                    st.markdown('<div class="soc-card"><div class="soc-card-title">Explainable Risk Factors Breakdown</div>', unsafe_allow_html=True)
                    for rf in risk_factors:
                        st.markdown(f'<div class="factor-item"><b>{rf.get("factor")}:</b> {rf.get("evidence")} <i>(+{rf.get("impact")} impact)</i></div>', unsafe_allow_html=True)
                    st.markdown('</div>', unsafe_allow_html=True)

            with res_col2:
                # Evidence
                st.markdown('<div class="soc-card"><div class="soc-card-title">Observed Evidence</div>', unsafe_allow_html=True)
                evidences = analysis_data.get("evidence", [])
                if evidences:
                    for ev in evidences:
                        st.markdown(f'<div class="evidence-item">🔍 {ev}</div>', unsafe_allow_html=True)
                else:
                    st.text("No specific evidence extracted.")
                st.markdown('</div>', unsafe_allow_html=True)

                # Recommendations
                st.markdown('<div class="soc-card"><div class="soc-card-title">Analyst Recommendations</div>', unsafe_allow_html=True)
                recs = analysis_data.get("recommendations", [])
                if recs:
                    for rec in recs:
                        st.markdown(f'<div class="recommendation-item">🛡️ {rec}</div>', unsafe_allow_html=True)
                else:
                    st.text("No recommendations provided.")
                st.markdown('</div>', unsafe_allow_html=True)

                # Anomaly & Threat Intel
                anom_score = analysis_data.get("anomaly_score")
                is_anom = analysis_data.get("is_anomalous")
                if anom_score is not None:
                    st.markdown('<div class="soc-card"><div class="soc-card-title">ML Anomaly Detection (Isolation Forest)</div>', unsafe_allow_html=True)
                    anom_status = "⚠️ ANOMALOUS (Deviates from baseline)" if is_anom else "✅ Normal Activity Profile"
                    st.markdown(f"**Status:** {anom_status} | **Score:** `{anom_score:.2f}`")
                    st.markdown('</div>', unsafe_allow_html=True)

                # RAG Sources Attribution
                rag_sources = analysis_data.get("rag_sources") or []
                if rag_sources:
                    st.markdown('<div class="soc-card"><div class="soc-card-title">Grounding Knowledge Sources (RAG)</div>', unsafe_allow_html=True)
                    for src in rag_sources:
                        st.markdown(f"• **{src.get('document', 'Knowledge Doc')}** ({src.get('category', 'security')} - Relevance: `{src.get('relevance', 0.0)*100:.1f}%`)")
                    st.markdown('</div>', unsafe_allow_html=True)

            # ================================================================
            # Active Response Control for Selected Alert
            # ================================================================
            st.markdown("---")
            st.markdown("## ⚡ Approval-Gated Active Response Control")

            st.markdown("""
            <div class="banner-simulated">
                🛡️ <b>Active Response Mode: SIMULATION / DRY-RUN ACTIVE</b> — Safe dry-run execution enabled. Automated safeguards protect network gateways, DNS resolvers, and Domain Controllers from containment actions.
            </div>
            """, unsafe_allow_html=True)

            alert_responses = fetch_responses(alert_id=selected_alert["alert_id"])

            if not alert_responses and analysis_data.get("response_recommendation"):
                rec = analysis_data["response_recommendation"]
                st.markdown(f"""
                <div class="soc-card">
                    <div class="soc-card-title">Proposed Action Recommendation</div>
                    <p><b>Recommended Action:</b> <code>{rec.get('action')}</code> on target <code>{rec.get('target')}</code></p>
                    <p><b>Justification:</b> {rec.get('reason')}</p>
                </div>
                """, unsafe_allow_html=True)
            elif alert_responses:
                for resp in alert_responses:
                    with st.container():
                        st.markdown(f"""
                        <div class="soc-card">
                            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 0.5rem;">
                                <div>
                                    <h4 style="margin:0; color:#58a6ff;">Action: {resp['action']} &bull; Target: <code>{resp['target']}</code></h4>
                                    <small style="color:#8b949e;">Response ID: {resp['response_id']}</small>
                                </div>
                                <div>
                                    {get_state_badge_html(resp['state'])}
                                </div>
                            </div>
                            <p style="margin: 0.3rem 0;"><b>Reason:</b> {resp['reason']}</p>
                        """, unsafe_allow_html=True)

                        # Actions depending on state
                        if resp["state"] in ("PENDING_APPROVAL", "PROPOSED"):
                            act_col1, act_col2 = st.columns([1, 1])
                            with act_col1:
                                if st.button(f"✅ Approve & Simulate '{resp['action']}'", key=f"app_{resp['response_id']}", type="primary", use_container_width=True):
                                    with st.spinner("Authorizing and executing simulated containment..."):
                                        res = approve_response_api(resp["response_id"], approver="analyst_console", reason="Approved via SOC Dashboard")
                                        if res:
                                            st.success("Action approved and simulated successfully.")
                                            st.rerun()

                            with act_col2:
                                with st.expander("❌ Reject Action Proposal"):
                                    rej_reason = st.text_input("Rejection Rationale", key=f"rej_txt_{resp['response_id']}", value="False positive or authorized operation")
                                    if st.button("Confirm Rejection", key=f"rej_btn_{resp['response_id']}", use_container_width=True):
                                        res = reject_response_api(resp["response_id"], rejected_by="analyst_console", reason=rej_reason)
                                        if res:
                                            st.info("Action proposal rejected.")
                                            st.rerun()

                        elif resp["state"] in ("SIMULATED", "COMPLETED"):
                            exec_res = resp.get("execution_result") or {}
                            st.markdown(f"""
                            <div style="background:#0d1117; padding:0.6rem 0.9rem; border-radius:6px; margin:0.5rem 0; font-size:0.85rem;">
                                <b>Output:</b> {exec_res.get('output_message', 'Action executed.')}<br>
                                <b>Command Dispatched:</b> <code>{exec_res.get('command_dispatched', 'N/A')}</code><br>
                                <b>Execution Time:</b> {exec_res.get('execution_time_ms', 0)} ms &bull; <b>Authorized by:</b> {resp.get('approved_by', 'analyst')}
                            </div>
                            """, unsafe_allow_html=True)

                            if resp.get("rollback_supported"):
                                if st.button(f"↩️ Rollback Action (Revert {resp['action']})", key=f"rb_{resp['response_id']}", use_container_width=True):
                                    with st.spinner("Executing rollback counter-action..."):
                                        rb_res = rollback_response_api(resp["response_id"], actor="analyst_console")
                                        if rb_res:
                                            st.success(f"Rollback counter-action '{rb_res.get('action')}' dispatched successfully.")
                                            st.rerun()

                        elif resp["state"] == "REJECTED":
                            st.markdown(f"<p style='color:#f87171;'><b>Rejection Rationale:</b> {resp.get('rejection_reason')} (by {resp.get('rejected_by')})</p>", unsafe_allow_html=True)

                        st.markdown('</div>', unsafe_allow_html=True)
            else:
                st.info("No active response proposals registered for this alert.")

    # ========================================================================
    # TAB 2: Active Response Queue
    # ========================================================================
    with tab_responses:
        st.markdown("### ⚡ Central Active Response Queue")
        st.markdown("Review, approve, reject, and rollback automated and AI-proposed response actions across all endpoints.")

        all_responses = fetch_responses()

        if not all_responses:
            st.info("No Active Response records found. Run AI analysis on an alert to generate containment proposals.")
        else:
            state_filter = st.selectbox("Filter by Response State", ["ALL", "PENDING_APPROVAL", "SIMULATED", "COMPLETED", "REJECTED", "ROLLED_BACK"])
            
            filtered = all_responses if state_filter == "ALL" else [r for r in all_responses if r["state"].upper() == state_filter]
            st.markdown(f"**Showing {len(filtered)} response record(s)**")

            for r in filtered:
                with st.container():
                    st.markdown(f"""
                    <div class="soc-card">
                        <div style="display:flex; justify-content:space-between; align-items:center;">
                            <div>
                                <h4 style="margin:0; color:#58a6ff;">{r['action']} &bull; Target: <code>{r['target']}</code> (Alert: {r['alert_id']})</h4>
                                <small style="color:#8b949e;">ID: {r['response_id']} &bull; Created: {r['created_at'][:19].replace('T', ' ')}</small>
                            </div>
                            <div>{get_state_badge_html(r['state'])}</div>
                        </div>
                        <p style="margin: 0.4rem 0;"><b>Reason:</b> {r['reason']}</p>
                    """, unsafe_allow_html=True)

                    if r["state"] in ("PENDING_APPROVAL", "PROPOSED"):
                        rcol1, rcol2 = st.columns([1, 1])
                        with rcol1:
                            if st.button(f"Approve '{r['action']}'", key=f"q_app_{r['response_id']}", type="primary", use_container_width=True):
                                approve_response_api(r["response_id"], approver="analyst_queue", reason="Approved from Queue")
                                st.rerun()
                        with rcol2:
                            if st.button(f"Reject '{r['action']}'", key=f"q_rej_{r['response_id']}", use_container_width=True):
                                reject_response_api(r["response_id"], rejected_by="analyst_queue", reason="Declined from Queue")
                                st.rerun()
                    elif r["state"] in ("SIMULATED", "COMPLETED") and r.get("rollback_supported"):
                        if st.button(f"↩️ Rollback {r['action']}", key=f"q_rb_{r['response_id']}"):
                            rollback_response_api(r["response_id"], actor="analyst_queue")
                            st.rerun()

                    st.markdown('</div>', unsafe_allow_html=True)

    # ========================================================================
    # TAB 3: Response Audit Trail
    # ========================================================================
    with tab_audit:
        st.markdown("### 📜 Immutable Active Response Audit Trail")
        st.markdown("Cryptographically timestamped audit history tracking every proposed, approved, executed, and rejected action.")

        logs = fetch_audit_logs(limit=100)
        if not logs:
            st.info("No audit log records recorded yet.")
        else:
            # Audit Table
            acols = st.columns([1.5, 1.2, 1.2, 1.5, 1.5, 1.2])
            acols[0].markdown("**Timestamp**")
            acols[1].markdown("**Actor**")
            acols[2].markdown("**Event**")
            acols[3].markdown("**Action / Target**")
            acols[4].markdown("**State Transition**")
            acols[5].markdown("**Mode**")
            st.markdown("---")

            for log in logs:
                c1, c2, c3, c4, c5, c6 = st.columns([1.5, 1.2, 1.2, 1.5, 1.5, 1.2])
                c1.text(log["timestamp"][:19].replace("T", " "))
                c2.text(log["actor"])
                c3.markdown(f"**{log['event']}**")
                c4.text(f"{log['action']} -> {log['target']}")
                c5.text(f"{log['state_before']} ➔ {log['state_after']}")
                c6.markdown(f"`{log['mode'].upper()}`")


if __name__ == "__main__":
    main()
