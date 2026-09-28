"""
ITTC-AI SOC Security Intelligence Dashboard

Streamlit application for monitoring normalized security alerts and triggering
RAG-grounded local AI analysis via the FastAPI backend.
"""

import os
import requests
import streamlit as st

# Configuration
BACKEND_URL = os.getenv("BACKEND_URL", "http://127.0.0.1:8000").rstrip("/")

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
        padding: 1rem 1.5rem;
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
        font-size: 1rem;
        font-weight: 600;
        color: #8b949e;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        margin-bottom: 0.75rem;
        border-bottom: 1px solid #21262d;
        padding-bottom: 0.4rem;
    }

    /* Severity Badges */
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
        padding: 0.3rem 0.6rem;
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
        font-size: 0.9rem;
    }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


# API Helper Functions
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
    except requests.exceptions.ConnectionError:
        st.error(f"Cannot connect to backend API at {BACKEND_URL}. Ensure FastAPI backend is running.")
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
    except requests.exceptions.ConnectionError:
        st.error(f"Backend API at {BACKEND_URL} became unreachable during analysis.")
        return None
    except Exception as e:
        st.error(f"Analysis request error: {e}")
        return None


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


# Main Layout
def main():
    # Sidebar Status & Refresh
    st.sidebar.title("🛡️ ITTC-AI SOC Control")
    
    is_healthy = check_health()
    if is_healthy:
        st.sidebar.success(f"Backend Connected ({BACKEND_URL})")
    else:
        st.sidebar.error(f"Backend Offline ({BACKEND_URL})")
        st.sidebar.info("Start backend with:\n`python -m uvicorn backend.main:app --reload`")

    if st.sidebar.button("🔄 Refresh Alerts", use_container_width=True):
        st.cache_data.clear()
        st.rerun()

    st.sidebar.markdown("---")
    st.sidebar.subheader("Pipeline Architecture")
    st.sidebar.markdown("""
    **Flow:**
    1. `SecurityAlert` (JSON)
    2. RAG Context Retrieval (TF-IDF)
    3. Ollama API (`qwen3:4b`)
    4. Structured `AIAnalysis`
    """)

    # Main Header
    st.markdown("""
    <div class="soc-header">
        <div>
            <div class="soc-title">🛡️ ITTC-AI Security Intelligence Dashboard</div>
            <div class="soc-subtitle">Real-time Automated Incident Analysis & RAG Context Retrieval</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    if not is_healthy:
        st.warning("⚠️ Backend service is currently unavailable. Please start the FastAPI backend service to view alerts and run AI analysis.")
        return

    # Ingest Alerts
    alerts = fetch_alerts()
    if not alerts:
        st.info("No security alerts available.")
        return

    # Top Overview Metrics
    mcol1, mcol2, mcol3, mcol4 = st.columns(4)
    mcol1.metric("Total Alerts", len(alerts))
    high_count = sum(1 for a in alerts if a.get("severity", "").lower() in ["high", "critical"])
    mcol2.metric("High/Critical Alerts", high_count)
    sources = set(a.get("source", "N/A") for a in alerts)
    mcol3.metric("Log Sources", ", ".join(sources))
    mcol4.metric("AI Engine", "Ollama Qwen3 4B")

    st.markdown("### 📋 Security Alerts")

    # Alert Table / List Display
    alert_ids = [a["alert_id"] for a in alerts]
    
    # Store selected alert index in session state if not set
    if "selected_alert_id" not in st.session_state:
        st.session_state["selected_alert_id"] = alert_ids[0]

    selected_alert = next((a for a in alerts if a["alert_id"] == st.session_state["selected_alert_id"]), alerts[0])

    # Table Layout
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
    st.markdown(f"## 🔍 Alert Details: `{selected_alert['alert_id']}`")

    # Detailed Inspection Tabs / Layout
    dcol1, dcol2 = st.columns([1, 1])

    with dcol1:
        st.markdown('<div class="soc-card"><div class="soc-card-title">Telemetry & Alert Metadata</div>', unsafe_allow_html=True)
        meta1, meta2 = st.columns(2)
        meta1.markdown(f"**Alert ID:** `{selected_alert['alert_id']}`")
        meta1.markdown(f"**Severity:** {get_severity_badge_html(selected_alert['severity'])}", unsafe_allow_html=True)
        meta1.markdown(f"**Source:** {selected_alert['source']}")
        meta1.markdown(f"**Rule ID:** `{selected_alert.get('rule_id') or 'N/A'}`")
        
        meta2.markdown(f"**Host:** `{selected_alert.get('host') or 'N/A'}`")
        meta2.markdown(f"**User:** `{selected_alert.get('user') or 'N/A'}`")
        meta2.markdown(f"**Source IP:** `{selected_alert.get('src_ip') or 'N/A'}`")
        meta2.markdown(f"**Destination IP:** `{selected_alert.get('dst_ip') or 'N/A'}`")

        st.markdown("**Event Type:** " + selected_alert.get("event_type", "N/A"))
        st.markdown("**Raw Event Payload:**")
        st.code(selected_alert.get("event", ""), language="text")
        st.markdown('</div>', unsafe_allow_html=True)

    with dcol2:
        st.markdown('<div class="soc-card"><div class="soc-card-title">AI Security Analysis Engine</div>', unsafe_allow_html=True)
        st.markdown("""
        Click below to run RAG context retrieval and execute local **Qwen3 4B** AI analysis on this security alert.
        """)
        
        analysis_key = f"analysis_result_{selected_alert['alert_id']}"
        
        analyze_clicked = st.button("⚡ Run AI Analysis", key=f"analyze_btn_{selected_alert['alert_id']}", use_container_width=True, type="primary")

        if analyze_clicked:
            with st.spinner(f"Retrieving RAG knowledge context & invoking Ollama Qwen3 4B for alert '{selected_alert['alert_id']}'..."):
                result = run_ai_analysis(selected_alert['alert_id'])
                if result:
                    st.session_state[analysis_key] = result

        if analysis_key in st.session_state:
            st.success("Analysis complete and loaded.")
        else:
            st.info("No analysis run for this alert yet. Click 'Run AI Analysis' above.")
        
        st.markdown('</div>', unsafe_allow_html=True)

    # Render AI Results if available in session_state
    analysis_key = f"analysis_result_{selected_alert['alert_id']}"
    if analysis_key in st.session_state:
        analysis_data = st.session_state[analysis_key]
        
        st.markdown("---")
        st.markdown("## 🤖 RAG-Grounded AI Analysis Results")

        # Executive Metrics Cards Row
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
                <div style="font-size: 0.8rem; font-weight: 700; color: #8b949e; text-transform: uppercase;">Risk Score</div>
                <div class="risk-score-value">{risk_score}</div>
                <div style="font-size: 0.8rem; color: #8b949e;">Out of 100</div>
            </div>
            """, unsafe_allow_html=True)

        with rcol2:
            st.markdown('<div class="soc-card"><div class="soc-card-title">Severity</div>', unsafe_allow_html=True)
            st.markdown(get_severity_badge_html(analysis_data.get("severity", "Unknown")), unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)

        with rcol3:
            st.markdown('<div class="soc-card"><div class="soc-card-title">Confidence</div>', unsafe_allow_html=True)
            conf = float(analysis_data.get("confidence", 0.0))
            st.markdown(f"<h3 style='margin:0; color:#58a6ff;'>{conf*100:.0f}%</h3>", unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)

        with rcol4:
            st.markdown('<div class="soc-card"><div class="soc-card-title">Cyber Kill Chain</div>', unsafe_allow_html=True)
            kc = analysis_data.get("kill_chain_stage", "N/A")
            st.markdown(f"<h4 style='margin:0; color:#f0883e;'>{kc}</h4>", unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)

        # Deep Breakdown Columns
        res_col1, res_col2 = st.columns(2)

        with res_col1:
            # Summary & Hypothesis
            st.markdown('<div class="soc-card"><div class="soc-card-title">Executive Summary</div>', unsafe_allow_html=True)
            st.write(analysis_data.get("summary", "No summary provided."))
            st.markdown('</div>', unsafe_allow_html=True)

            st.markdown('<div class="soc-card"><div class="soc-card-title">Investigation Hypothesis</div>', unsafe_allow_html=True)
            st.write(analysis_data.get("hypothesis", "No hypothesis generated."))
            st.markdown('</div>', unsafe_allow_html=True)

            # MITRE ATT&CK Techniques
            st.markdown('<div class="soc-card"><div class="soc-card-title">MITRE ATT&CK Techniques</div>', unsafe_allow_html=True)
            techniques = analysis_data.get("mitre_techniques", [])
            if techniques:
                html_tags = "".join([f'<span class="mitre-tag">{t}</span>' for t in techniques])
                st.markdown(html_tags, unsafe_allow_html=True)
            else:
                st.text("No specific MITRE techniques identified.")
            st.markdown('</div>', unsafe_allow_html=True)

        with res_col2:
            # Concrete Evidence Observed
            st.markdown('<div class="soc-card"><div class="soc-card-title">Observed Evidence</div>', unsafe_allow_html=True)
            evidences = analysis_data.get("evidence", [])
            if evidences:
                for ev in evidences:
                    st.markdown(f'<div class="evidence-item">🔍 {ev}</div>', unsafe_allow_html=True)
            else:
                st.text("No specific evidence extracted.")
            st.markdown('</div>', unsafe_allow_html=True)

            # Recommendations
            st.markdown('<div class="soc-card"><div class="soc-card-title">Defensive Recommendations</div>', unsafe_allow_html=True)
            recs = analysis_data.get("recommendations", [])
            if recs:
                for rec in recs:
                    st.markdown(f'<div class="recommendation-item">🛡️ {rec}</div>', unsafe_allow_html=True)
            else:
                st.text("No recommendations provided.")
            st.markdown('</div>', unsafe_allow_html=True)


if __name__ == "__main__":
    main()
