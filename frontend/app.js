/**
 * ITTC-AI SOC Platform — Frontend Application Logic
 * Pure Vanilla JavaScript with real-time FastAPI integration.
 */

const API_BASE = "http://127.0.0.1:8000";

// Global State
let allAlerts = [];
let allIncidents = [];
let filteredAlerts = [];
let filteredIncidents = [];
let selectedIncidentId = null;
let selectedAlertId = null;
let copilotHistory = [];
let activeReportData = null;

// ==========================================================================
// 1. INITIALIZATION & REFRESH
// ==========================================================================

document.addEventListener("DOMContentLoaded", () => {
    initDashboard();
});

async function initDashboard() {
    await checkBackendHealth();
    await refreshAll();
}

async function refreshAll() {
    showGlobalLoading(true);
    try {
        await Promise.all([loadAlerts(), loadIncidents()]);
        updateKPIs();
        renderMetrics();

        // Auto-select highest risk incident if none selected
        if (!selectedIncidentId && allIncidents.length > 0) {
            const highestRisk = [...allIncidents].sort((a, b) => b.risk_score - a.risk_score)[0];
            selectIncident(highestRisk.incident_id);
        } else if (selectedIncidentId) {
            selectIncident(selectedIncidentId);
        }
    } catch (err) {
        console.error("Failed to refresh dashboard:", err);
    } finally {
        showGlobalLoading(false);
    }
}

async function checkBackendHealth() {
    const statusEl = document.getElementById("backendStatus");
    const statusText = document.getElementById("statusText");
    try {
        const res = await fetch(`${API_BASE}/health`, { signal: AbortSignal.timeout(3000) });
        if (res.ok) {
            statusEl.className = "status-pill status-online";
            statusText.textContent = "Backend Online (Port 8000)";
        } else {
            throw new Error();
        }
    } catch {
        statusEl.className = "status-pill status-offline";
        statusText.textContent = "Backend Offline";
    }
}

function showGlobalLoading(isLoading) {
    const btn = document.getElementById("btnRefresh");
    if (btn) {
        btn.disabled = isLoading;
        btn.style.opacity = isLoading ? "0.7" : "1";
    }
}

// ==========================================================================
// 2. DATA LOADING & KPI CALCULATION
// ==========================================================================

async function loadAlerts() {
    try {
        const res = await fetch(`${API_BASE}/api/alerts`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        allAlerts = await res.json();
        filteredAlerts = [...allAlerts];
        renderAlertsTable();
    } catch (err) {
        console.error("Error loading alerts:", err);
        document.getElementById("alertsTableBody").innerHTML = `
            <tr><td colspan="8" class="empty-state">Unable to load alerts from backend (${escapeHtml(err.message)})</td></tr>
        `;
    }
}

async function loadIncidents() {
    const container = document.getElementById("incidentsList");
    try {
        const res = await fetch(`${API_BASE}/api/incidents`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        allIncidents = await res.json();
        filteredIncidents = [...allIncidents];
        renderIncidentsList();
    } catch (err) {
        console.error("Error loading incidents:", err);
        container.innerHTML = `
            <div class="empty-state">
                <p>Failed to load incidents. Verify backend is running.</p>
            </div>
        `;
    }
}

function updateKPIs() {
    // Total Alerts
    document.getElementById("kpiTotalAlerts").textContent = allAlerts.length;

    // Critical & High
    const critical = allAlerts.filter(a => String(a.severity).toLowerCase() === "critical").length;
    const high = allAlerts.filter(a => String(a.severity).toLowerCase() === "high").length;
    document.getElementById("kpiCriticalAlerts").textContent = critical;
    document.getElementById("kpiHighAlerts").textContent = high;

    // Active Incidents (OPEN or INVESTIGATING)
    const activeIncidents = allIncidents.filter(i => ["OPEN", "INVESTIGATING"].includes(i.status.toUpperCase())).length;
    document.getElementById("kpiActiveIncidents").textContent = activeIncidents;
    document.getElementById("kpiIncidentBreakdown").textContent = `${activeIncidents} Active of ${allIncidents.length} Total`;

    // Anomalies Detected
    const anomalies = allIncidents.filter(i => i.is_anomalous || (i.anomaly_score && i.anomaly_score > 0.5)).length;
    document.getElementById("kpiAnomalies").textContent = anomalies;

    // Average Risk
    const riskScores = allIncidents.map(i => i.risk_score).filter(s => typeof s === "number");
    const avgRisk = riskScores.length ? Math.round(riskScores.reduce((a, b) => a + b, 0) / riskScores.length) : "--";
    document.getElementById("kpiAvgRisk").textContent = avgRisk !== "--" ? `${avgRisk}/100` : "--";

    // Badges
    document.getElementById("incidentCountBadge").textContent = allIncidents.length;
    document.getElementById("alertsCountBadge").textContent = allAlerts.length;
}

// ==========================================================================
// 3. TAB SWITCHING
// ==========================================================================

function switchTab(tabId) {
    document.querySelectorAll(".tab-btn").forEach(btn => btn.classList.remove("active"));
    document.querySelectorAll(".tab-content").forEach(sec => sec.classList.remove("active"));

    const targetSection = document.getElementById(tabId);
    if (targetSection) targetSection.classList.add("active");

    const clickedBtn = Array.from(document.querySelectorAll(".tab-btn")).find(btn => 
        btn.getAttribute("onclick") && btn.getAttribute("onclick").includes(tabId)
    );
    if (clickedBtn) clickedBtn.classList.add("active");

    if (tabId === "metricsTab") {
        renderMetrics();
    }
}

// ==========================================================================
// 4. INCIDENTS WORKSPACE & DOSSIER
// ==========================================================================

async function triggerCorrelation() {
    const btn = document.getElementById("btnCorrelate");
    btn.disabled = true;
    btn.innerHTML = `<span class="spinner"></span> Correlating...`;

    try {
        const res = await fetch(`${API_BASE}/api/incidents/correlate`, { method: "POST" });
        if (!res.ok) throw new Error("Correlation request failed");
        allIncidents = await res.json();
        filteredIncidents = [...allIncidents];
        renderIncidentsList();
        updateKPIs();
        renderMetrics();

        if (allIncidents.length > 0) {
            selectIncident(allIncidents[0].incident_id);
        }
    } catch (err) {
        alert("Correlation error: " + err.message);
    } finally {
        btn.disabled = false;
        btn.innerHTML = `<span class="btn-icon">⚡</span> Run Correlation`;
    }
}

function filterIncidents() {
    const status = document.getElementById("filterIncidentStatus").value;
    if (status === "ALL") {
        filteredIncidents = [...allIncidents];
    } else {
        filteredIncidents = allIncidents.filter(i => i.status.toUpperCase() === status);
    }
    renderIncidentsList();
}

function renderIncidentsList() {
    const container = document.getElementById("incidentsList");
    if (!filteredIncidents.length) {
        container.innerHTML = `<div class="empty-state"><p>No incidents match the selected filter.</p></div>`;
        return;
    }

    container.innerHTML = filteredIncidents.map(inc => {
        const isSelected = inc.incident_id === selectedIncidentId;
        const sevClass = `sev-${String(inc.severity).toLowerCase()}`;
        const anomBadge = inc.is_anomalous
            ? `<span class="badge badge-critical">ML ANOMALY</span>`
            : `<span class="badge badge-low">BASELINE</span>`;

        return `
            <div class="incident-card-item ${sevClass} ${isSelected ? 'selected' : ''}" onclick="selectIncident('${escapeHtml(inc.incident_id)}')">
                <div class="inc-card-head">
                    <span class="inc-id">${escapeHtml(inc.incident_id)}</span>
                    <span class="badge ${getStatusBadgeClass(inc.status)}">${escapeHtml(inc.status)}</span>
                </div>
                <div class="inc-summary">${escapeHtml(inc.summary || "Correlated Incident")}</div>
                <div class="inc-card-footer">
                    <div class="inc-badges">
                        <span class="badge ${getSeverityBadgeClass(inc.severity)}">${escapeHtml(inc.severity)}</span>
                        ${anomBadge}
                        <span style="font-family: var(--font-mono); color: #fbbf24; font-weight: 700;">Risk: ${inc.risk_score}</span>
                    </div>
                    <span>${inc.related_alert_ids ? inc.related_alert_ids.length : 0} alerts</span>
                </div>
            </div>
        `;
    }).join("");
}

function selectIncident(incidentId) {
    selectedIncidentId = incidentId;

    // Update list selection highlight
    document.querySelectorAll(".incident-card-item").forEach(el => el.classList.remove("selected"));
    const activeCard = Array.from(document.querySelectorAll(".incident-card-item")).find(el => 
        el.querySelector(".inc-id") && el.querySelector(".inc-id").textContent.trim() === incidentId
    );
    if (activeCard) activeCard.classList.add("selected");

    const incident = allIncidents.find(i => i.incident_id === incidentId);
    if (!incident) return;

    // Update Copilot active context
    updateCopilotContext(incident.incident_id, "Incident");

    // Render Dossier
    renderIncidentDossier(incident);
}

function renderIncidentDossier(incident) {
    const container = document.getElementById("incidentDetailPanel");

    // Build Attack Timeline
    const timelineHtml = (incident.timeline && incident.timeline.length)
        ? incident.timeline.map((entry, idx) => `
            <div class="timeline-item">
                <div class="timeline-node"></div>
                <div class="timeline-content">
                    <div class="timeline-meta">
                        <span>#${idx + 1} &bull; ${formatTimestamp(entry.timestamp)}</span>
                        <span>[${escapeHtml(entry.source || "Wazuh")}] ${entry.alert_id ? `Alert: ${escapeHtml(entry.alert_id)}` : ''}</span>
                    </div>
                    <div class="timeline-event">${escapeHtml(entry.event)}</div>
                </div>
            </div>
        `).join("")
        : `<p style="color: var(--text-muted); font-size: 13px;">No timeline entries recorded.</p>`;

    // Build Response Recommendation
    const rec = incident.response_recommendation;
    const recHtml = rec ? `
        <div class="recommendation-box">
            <div class="rec-head">
                <div class="rec-title-group">
                    <span class="rec-action-badge">${escapeHtml(rec.action)}</span>
                    <strong style="color: #ffffff; font-size: 14px;">Target: ${escapeHtml(rec.target)}</strong>
                </div>
                <span class="rec-disclaimer-pill">RECOMMENDATION ONLY &bull; REQUIRES ANALYST APPROVAL</span>
            </div>
            <div class="rec-body">${escapeHtml(rec.reason)}</div>
            <div class="rec-meta">
                <span>Confidence: ${(Number(rec.confidence) * 100).toFixed(0)}%</span>
                <span>Requires Approval: ${rec.requires_approval ? "Yes" : "No"}</span>
                <span>Active Response Execution: Disabled (Advisor Mode)</span>
            </div>
        </div>
    ` : `
        <div class="recommendation-box" style="border-color: rgba(255,255,255,0.1); background: rgba(255,255,255,0.02);">
            <div class="rec-head">
                <span class="rec-action-badge" style="background:#475569;">INVESTIGATE_ONLY</span>
                <span class="rec-disclaimer-pill">RECOMMENDATION ONLY</span>
            </div>
            <div class="rec-body">Perform host-level forensic analysis and triage alert telemetry.</div>
        </div>
    `;

    // Build Explainable Risk Factors ("Why this risk?")
    const factors = incident.risk_factors || [];
    const factorsHtml = factors.length ? `
        <div class="risk-factor-list">
            ${factors.map(f => `
                <div class="risk-factor-card">
                    <div>
                        <div class="factor-name">${escapeHtml(f.factor)}</div>
                        <div class="factor-desc">${escapeHtml(f.evidence)}</div>
                    </div>
                    <div class="factor-impact">+${escapeHtml(f.impact)} impact</div>
                </div>
            `).join("")}
        </div>
    ` : `
        <div class="risk-factor-list">
            <div class="risk-factor-card">
                <div>
                    <div class="factor-name">Severity Base</div>
                    <div class="factor-desc">Base risk computed from maximum alert severity (${escapeHtml(incident.severity)})</div>
                </div>
                <div class="factor-impact">+${incident.risk_score} impact</div>
            </div>
        </div>
    `;

    // Build Anomaly Detector Widget
    const anomScore = typeof incident.anomaly_score === "number" ? incident.anomaly_score : 0.0;
    const isAnom = incident.is_anomalous || anomScore > 0.5;
    const anomalyWidgetHtml = `
        <div class="anomaly-widget">
            <div class="anomaly-left">
                <div class="anomaly-status-tag" style="color: ${isAnom ? 'var(--color-critical)' : 'var(--color-success)'}">
                    <span>${isAnom ? '⚠️ FLAGGED ANOMALOUS PATTERN' : '✅ BASELINE NORMAL PATTERN'}</span>
                </div>
                <div class="anomaly-subtext">
                    Isolation Forest evaluation based on severity, temporal distribution, port hashes, and frequency.
                    <br><strong style="color: #64748b;">* Evaluated against DEMO/SYNTHETIC baseline.</strong>
                </div>
            </div>
            <div class="anomaly-meter">
                <div class="anomaly-score-text">${(anomScore * 100).toFixed(1)}%</div>
                <span style="font-size: 11px; color: var(--text-muted);">Anomaly Score</span>
            </div>
        </div>
    `;

    // Build IOC Tags
    const iocs = incident.related_iocs || [];
    const iocsHtml = iocs.length ? iocs.map(ioc => `
        <span class="ioc-pill" onclick="searchIOCFromDossier('${escapeHtml(ioc.type || 'ip')}', '${escapeHtml(ioc.value)}')">
            <span>${escapeHtml(ioc.type)}:</span>
            <strong>${escapeHtml(ioc.value)}</strong>
            <span style="font-size: 10px; opacity: 0.7;">🔍</span>
        </span>
    `).join("") : `<span style="color: var(--text-muted); font-size: 12px;">No IOCs extracted</span>`;

    // Build MITRE Techniques
    const mitreTechs = incident.mitre_techniques || [];
    const mitreHtml = mitreTechs.length ? mitreTechs.map(t => `
        <span class="mitre-pill">${escapeHtml(t)}</span>
    `).join("") : `<span style="color: var(--text-muted); font-size: 12px;">No techniques mapped</span>`;

    // Build Analyst Notes
    const notes = incident.analyst_notes || [];
    const notesHtml = notes.length ? notes.map(n => `
        <div class="note-bubble">
            <div class="note-meta">
                <strong>${escapeHtml(n.author || 'analyst')}</strong>
                <span>${formatTimestamp(n.timestamp)}</span>
            </div>
            <div class="note-text">${escapeHtml(n.content)}</div>
        </div>
    `).join("") : `<p style="font-size: 12px; color: var(--text-muted); margin-bottom: 8px;">No analyst notes yet.</p>`;

    container.innerHTML = `
        <!-- Dossier Header -->
        <div class="dossier-header-bar">
            <div class="dossier-title-area">
                <div class="dossier-title">${escapeHtml(incident.incident_id)}</div>
                <span class="badge ${getSeverityBadgeClass(incident.severity)}">${escapeHtml(incident.severity)}</span>
                <span class="badge ${getStatusBadgeClass(incident.status)}">${escapeHtml(incident.status)}</span>
            </div>

            <div class="dossier-actions">
                <select id="dossierStatusSelect" class="select-input">
                    <option value="OPEN" ${incident.status === "OPEN" ? "selected" : ""}>OPEN</option>
                    <option value="INVESTIGATING" ${incident.status === "INVESTIGATING" ? "selected" : ""}>INVESTIGATING</option>
                    <option value="CONTAINED" ${incident.status === "CONTAINED" ? "selected" : ""}>CONTAINED</option>
                    <option value="RESOLVED" ${incident.status === "RESOLVED" ? "selected" : ""}>RESOLVED</option>
                </select>
                <button class="btn btn-sm btn-secondary" onclick="saveIncidentStatus('${incident.incident_id}')">Update Status</button>
                <button class="btn btn-sm btn-secondary" onclick="openReportModal('${incident.incident_id}')">📄 View Report</button>
                <button class="btn btn-sm btn-primary" onclick="jumpToCopilot('${incident.incident_id}')">🤖 Ask Copilot</button>
            </div>
        </div>

        <!-- Dossier Vitals -->
        <div class="dossier-vitals">
            <div class="vital-box">
                <div class="vital-label">Risk Assessment</div>
                <div class="vital-val" style="color: #f87171;">${incident.risk_score}<span style="font-size: 12px; color: var(--text-muted);">/100</span></div>
            </div>
            <div class="vital-box">
                <div class="vital-label">Confidence</div>
                <div class="vital-val" style="color: #34d399;">${(Number(incident.confidence) * 100).toFixed(0)}%</div>
            </div>
            <div class="vital-box">
                <div class="vital-label">Correlated Alerts</div>
                <div class="vital-val" style="color: #38bdf8;">${incident.related_alert_ids ? incident.related_alert_ids.length : 0}</div>
            </div>
            <div class="vital-box">
                <div class="vital-label">Extracted IOCs</div>
                <div class="vital-val" style="color: #fbbf24;">${incident.related_iocs ? incident.related_iocs.length : 0}</div>
            </div>
        </div>

        <!-- Executive Summary -->
        <div class="section-block">
            <div class="section-head">
                <h4>Executive Incident Summary</h4>
            </div>
            <p style="font-size: 13.5px; color: var(--text-primary); line-height: 1.5;">${escapeHtml(incident.summary)}</p>
        </div>

        <!-- Response Recommendation (Prominent) -->
        <div class="section-block">
            <div class="section-head">
                <h4>Automated Response Recommendation</h4>
            </div>
            ${recHtml}
        </div>

        <!-- Explainable Risk -->
        <div class="section-block">
            <div class="section-head">
                <h4>Why This Risk Score? (Explainable Factors)</h4>
            </div>
            ${factorsHtml}
        </div>

        <!-- Anomaly Detection -->
        <div class="section-block">
            <div class="section-head">
                <h4>ML Behavioral Anomaly Analysis</h4>
            </div>
            ${anomalyWidgetHtml}
        </div>

        <!-- Observed IOCs -->
        <div class="section-block">
            <div class="section-head">
                <h4>Observed Indicators of Compromise (Click to Investigate)</h4>
            </div>
            <div class="tag-cloud">
                ${iocsHtml}
            </div>
        </div>

        <!-- MITRE ATT&CK -->
        <div class="section-block">
            <div class="section-head">
                <h4>Mapped MITRE ATT&CK Techniques</h4>
            </div>
            <div class="tag-cloud">
                ${mitreHtml}
            </div>
        </div>

        <!-- Attack Sequence Timeline -->
        <div class="section-block">
            <div class="section-head">
                <h4>Attack Sequence Timeline (${incident.timeline ? incident.timeline.length : 0} Events)</h4>
            </div>
            <div class="timeline-list">
                ${timelineHtml}
            </div>
        </div>

        <!-- Analyst Notes -->
        <div class="section-block">
            <div class="section-head">
                <h4>Analyst Notes &amp; Investigation Log</h4>
            </div>
            <div class="notes-container">
                <div class="notes-history">
                    ${notesHtml}
                </div>
                <div class="notes-input-row">
                    <input type="text" id="noteAuthorInput" placeholder="Analyst (e.g. lead_sec)" style="width: 140px;" class="text-input">
                    <input type="text" id="noteContentInput" placeholder="Add investigation findings or response approval notes..." style="flex:1;" class="text-input" onkeypress="if(event.key==='Enter') saveIncidentNote('${incident.incident_id}')">
                    <button class="btn btn-sm btn-primary" onclick="saveIncidentNote('${incident.incident_id}')">Save Note</button>
                </div>
            </div>
        </div>
    `;
}

async function saveIncidentStatus(incidentId) {
    const statusSelect = document.getElementById("dossierStatusSelect");
    if (!statusSelect) return;
    const newStatus = statusSelect.value;

    try {
        const res = await fetch(`${API_BASE}/api/incidents/${incidentId}/status`, {
            method: "PATCH",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ status: newStatus }),
        });

        if (!res.ok) throw new Error("Status update failed");
        const updated = await res.json();

        // Update local state
        const idx = allIncidents.findIndex(i => i.incident_id === incidentId);
        if (idx !== -1) allIncidents[idx] = updated;

        filterIncidents();
        selectIncident(incidentId);
        updateKPIs();
        renderMetrics();
    } catch (err) {
        alert("Failed to update status: " + err.message);
    }
}

async function saveIncidentNote(incidentId) {
    const contentInput = document.getElementById("noteContentInput");
    const authorInput = document.getElementById("noteAuthorInput");
    const content = contentInput.value.trim();
    const author = authorInput.value.trim() || "analyst";

    if (!content) return;

    try {
        const res = await fetch(`${API_BASE}/api/incidents/${incidentId}/notes`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ content, author }),
        });

        if (!res.ok) throw new Error("Failed to post note");
        const updated = await res.json();

        const idx = allIncidents.findIndex(i => i.incident_id === incidentId);
        if (idx !== -1) allIncidents[idx] = updated;

        selectIncident(incidentId);
    } catch (err) {
        alert("Failed to save note: " + err.message);
    }
}

function searchIOCFromDossier(type, val) {
    switchTab('iocTab');
    setAndSearchIOC(type, val);
}

function jumpToCopilot(incidentId) {
    switchTab('copilotTab');
    updateCopilotContext(incidentId, "Incident");
    document.getElementById("copilotQuestionInput").focus();
}

// ==========================================================================
// 5. SECURITY ALERTS QUEUE WORKSPACE
// ==========================================================================

function filterAlerts() {
    const query = (document.getElementById("searchAlerts").value || "").toLowerCase();
    const severity = document.getElementById("filterAlertSeverity").value;
    const source = document.getElementById("filterAlertSource").value;

    filteredAlerts = allAlerts.filter(a => {
        const matchesQuery = !query ||
            a.alert_id.toLowerCase().includes(query) ||
            (a.host && a.host.toLowerCase().includes(query)) ||
            (a.event && a.event.toLowerCase().includes(query)) ||
            (a.src_ip && a.src_ip.includes(query)) ||
            (a.dst_ip && a.dst_ip.includes(query));

        const matchesSeverity = severity === "ALL" || a.severity.toLowerCase() === severity.toLowerCase();
        const matchesSource = source === "ALL" || a.source.toLowerCase() === source.toLowerCase();

        return matchesQuery && matchesSeverity && matchesSource;
    });

    renderAlertsTable();
}

function renderAlertsTable() {
    const tbody = document.getElementById("alertsTableBody");
    if (!filteredAlerts.length) {
        tbody.innerHTML = `<tr><td colspan="8" class="empty-state">No alerts match search criteria.</td></tr>`;
        return;
    }

    tbody.innerHTML = filteredAlerts.map(a => {
        const ipFlow = (a.src_ip || a.dst_ip)
            ? `<span class="td-mono">${escapeHtml(a.src_ip || 'N/A')} &rarr; ${escapeHtml(a.dst_ip || 'N/A')}</span>`
            : `<span style="color: var(--text-muted);">Internal</span>`;

        return `
            <tr>
                <td class="td-mono" style="font-weight:700; color:#60a5fa;">${escapeHtml(a.alert_id)}</td>
                <td style="font-size: 12px; color: var(--text-secondary);">${formatTimestamp(a.timestamp)}</td>
                <td><span class="badge" style="background:#1e293b; color:#94a3b8;">${escapeHtml(a.source)}</span></td>
                <td><span class="badge ${getSeverityBadgeClass(a.severity)}">${escapeHtml(a.severity)}</span></td>
                <td><strong>${escapeHtml(a.host || 'N/A')}</strong><br><span style="font-size:11px; color:var(--text-muted);">${escapeHtml(a.user || 'SYSTEM')}</span></td>
                <td style="max-width: 380px;">
                    <div style="font-weight: 600; color: #ffffff; font-size: 12px;">${escapeHtml(a.event_type || 'alert')}</div>
                    <div style="font-size: 12px; color: var(--text-secondary); white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">${escapeHtml(a.event)}</div>
                </td>
                <td>${ipFlow}</td>
                <td>
                    <button class="btn btn-sm btn-secondary" onclick="openAlertDeepAnalysis('${escapeHtml(a.alert_id)}')">
                        ⚡ AI Analyze
                    </button>
                </td>
            </tr>
        `;
    }).join("");
}

// ==========================================================================
// 6. ALERT DEEP ANALYSIS MODAL
// ==========================================================================

async function openAlertDeepAnalysis(alertId) {
    selectedAlertId = alertId;
    updateCopilotContext(alertId, "Alert");

    const modal = document.getElementById("alertAnalysisModal");
    const titleEl = document.getElementById("modalAlertAnalysisTitle");
    const bodyEl = document.getElementById("modalAlertAnalysisBody");

    titleEl.textContent = `Deep AI Analysis: ${alertId}`;
    bodyEl.innerHTML = `
        <div class="state-loading">
            <span class="spinner"></span> Running RAG retrieval + Threat Intel enrichment + Qwen3 structured analysis...
        </div>
    `;
    modal.style.display = "flex";

    try {
        const res = await fetch(`${API_BASE}/api/analyze/${encodeURIComponent(alertId)}`, { method: "POST" });
        if (!res.ok) {
            const errData = await res.json().catch(() => ({}));
            throw new Error(errData.detail || `Analysis request failed with status ${res.status}`);
        }
        const data = await res.json();
        renderAlertAnalysisBody(data);
    } catch (err) {
        bodyEl.innerHTML = `
            <div class="empty-state">
                <p style="color: var(--color-critical);">Analysis Error: ${escapeHtml(err.message)}</p>
                <p style="font-size: 12px; color: var(--text-muted); margin-top: 8px;">Ensure Ollama service is running locally if generating live LLM responses.</p>
            </div>
        `;
    }
}

function renderAlertAnalysisBody(data) {
    const bodyEl = document.getElementById("modalAlertAnalysisBody");

    // RAG Sources
    const ragSources = (data.rag_sources || []).map(s => `
        <span class="rag-pill">
            <span style="color:#60a5fa;">[${escapeHtml(s.category || 'KB')}]</span>
            <span>${escapeHtml(s.document)}</span>
            <span class="rag-pill-score">${(Number(s.relevance) * 100).toFixed(0)}%</span>
        </span>
    `).join("");

    // Risk Factors
    const riskFactors = (data.risk_factors || []).map(f => `
        <div class="risk-factor-card" style="margin-bottom: 8px;">
            <div>
                <strong style="color:#ffffff;">${escapeHtml(f.factor)}</strong>
                <p style="font-size:12px; color:var(--text-secondary); margin-top:2px;">${escapeHtml(f.evidence)}</p>
            </div>
            <span class="factor-impact">+${escapeHtml(f.impact)} impact</span>
        </div>
    `).join("");

    // Response Recommendation
    const rec = data.response_recommendation;

    bodyEl.innerHTML = `
        <div class="dossier-vitals" style="margin-bottom: 20px;">
            <div class="vital-box">
                <div class="vital-label">Risk Score</div>
                <div class="vital-val" style="color:#f87171;">${data.risk_score}/100</div>
            </div>
            <div class="vital-box">
                <div class="vital-label">Confidence</div>
                <div class="vital-val" style="color:#34d399;">${(Number(data.confidence) * 100).toFixed(0)}%</div>
            </div>
            <div class="vital-box">
                <div class="vital-label">Kill Chain Stage</div>
                <div class="vital-val" style="font-size:15px; color:#38bdf8;">${escapeHtml(data.kill_chain_stage || 'Unknown')}</div>
            </div>
            <div class="vital-box">
                <div class="vital-label">Anomaly Status</div>
                <div class="vital-val" style="font-size:15px; color:${data.is_anomalous ? '#f87171' : '#34d399'};">
                    ${data.is_anomalous ? 'ANOMALOUS' : 'NORMAL'}
                </div>
            </div>
        </div>

        <div class="section-block">
            <h4 style="font-size: 13px; text-transform: uppercase; color: var(--text-muted); margin-bottom: 6px;">Executive Summary</h4>
            <p style="font-size: 14px; line-height: 1.5; color: #ffffff;">${escapeHtml(data.summary)}</p>
        </div>

        <div class="section-block">
            <h4 style="font-size: 13px; text-transform: uppercase; color: var(--text-muted); margin-bottom: 6px;">Analyst Hypothesis</h4>
            <p style="font-size: 13px; color: var(--text-secondary); line-height: 1.5;">${escapeHtml(data.hypothesis)}</p>
        </div>

        ${rec ? `
        <div class="recommendation-box" style="margin: 16px 0;">
            <div class="rec-head">
                <div class="rec-title-group">
                    <span class="rec-action-badge">${escapeHtml(rec.action)}</span>
                    <strong style="color: #ffffff;">Target: ${escapeHtml(rec.target)}</strong>
                </div>
                <span class="rec-disclaimer-pill">RECOMMENDATION ONLY</span>
            </div>
            <div class="rec-body">${escapeHtml(rec.reason)}</div>
            <div class="rec-meta">
                <span>Confidence: ${(Number(rec.confidence) * 100).toFixed(0)}%</span>
                <span>Requires Approval: ${rec.requires_approval ? "Yes" : "No"}</span>
            </div>
        </div>` : ''}

        <div class="section-block">
            <h4 style="font-size: 13px; text-transform: uppercase; color: var(--text-muted); margin-bottom: 6px;">Explainable Risk Factors</h4>
            ${riskFactors || '<p style="color:var(--text-muted); font-size:12px;">Standard baseline factors.</p>'}
        </div>

        <div class="section-block">
            <h4 style="font-size: 13px; text-transform: uppercase; color: var(--text-muted); margin-bottom: 6px;">RAG Knowledge Sources Grounding</h4>
            <div class="rag-pill-list">
                ${ragSources || '<span style="color:var(--text-muted); font-size:12px;">No specific RAG sources cited</span>'}
            </div>
        </div>

        <div class="section-block">
            <h4 style="font-size: 13px; text-transform: uppercase; color: var(--text-muted); margin-bottom: 6px;">Concrete Evidence Observed</h4>
            <ul style="padding-left: 18px; font-size: 13px; color: var(--text-secondary);">
                ${(data.evidence || []).map(e => `<li>${escapeHtml(e)}</li>`).join("")}
            </ul>
        </div>
    `;
}

function closeAlertAnalysisModal() {
    document.getElementById("alertAnalysisModal").style.display = "none";
}

// ==========================================================================
// 7. IOC THREAT HUNTER
// ==========================================================================

function setAndSearchIOC(type, val) {
    document.getElementById("iocTypeInput").value = type;
    document.getElementById("iocValueInput").value = val;
    runIOCSearch();
}

async function runIOCSearch() {
    const type = document.getElementById("iocTypeInput").value;
    const value = document.getElementById("iocValueInput").value.trim();
    const area = document.getElementById("iocResultsArea");

    if (!value) return;

    area.innerHTML = `
        <div class="state-loading">
            <span class="spinner"></span> Querying Threat Intelligence &amp; cross-referencing alerts/incidents...
        </div>
    `;

    try {
        const res = await fetch(`${API_BASE}/api/ioc/${encodeURIComponent(type)}/${encodeURIComponent(value)}`);
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.detail || `Server returned HTTP ${res.status}`);
        }
        const data = await res.json();
        renderIOCResults(data);
    } catch (err) {
        area.innerHTML = `
            <div class="empty-state">
                <p style="color: var(--color-critical);">Lookup failed: ${escapeHtml(err.message)}</p>
            </div>
        `;
    }
}

function renderIOCResults(data) {
    const area = document.getElementById("iocResultsArea");
    const isMalicious = data.malicious || String(data.reputation).toLowerCase() === "malicious";
    const repBadge = isMalicious
        ? `<span class="badge badge-critical">CONFIRMED MALICIOUS</span>`
        : String(data.reputation).toLowerCase() === "suspicious"
        ? `<span class="badge badge-high">SUSPICIOUS</span>`
        : `<span class="badge badge-low">UNKNOWN / CLEAN</span>`;

    const relatedAlertsHtml = (data.related_alert_ids && data.related_alert_ids.length)
        ? data.related_alert_ids.map(id => `
            <span class="badge badge-count" style="cursor:pointer; color:#60a5fa;" onclick="switchTab('alertsTab'); document.getElementById('searchAlerts').value='${id}'; filterAlerts();">
                ${escapeHtml(id)}
            </span>
        `).join(" ")
        : `<span style="color: var(--text-muted); font-size: 13px;">No correlated alerts found in current dataset</span>`;

    const relatedIncidentsHtml = (data.related_incident_ids && data.related_incident_ids.length)
        ? data.related_incident_ids.map(id => `
            <span class="badge badge-count" style="cursor:pointer; color:#f87171;" onclick="switchTab('incidentsTab'); selectIncident('${id}');">
                ${escapeHtml(id)}
            </span>
        `).join(" ")
        : `<span style="color: var(--text-muted); font-size: 13px;">No incidents directly mapped</span>`;

    area.innerHTML = `
        <div class="ioc-dossier-card">
            <div class="ioc-dossier-header">
                <div>
                    <span style="font-size: 11px; text-transform: uppercase; color: var(--text-muted); font-weight: 700;">${escapeHtml(data.ioc_type)}</span>
                    <h3 style="font-family: var(--font-mono); font-size: 20px; color: #ffffff; margin-top: 4px;">${escapeHtml(data.value)}</h3>
                </div>
                <div>${repBadge}</div>
            </div>

            <div class="ioc-dossier-grid">
                <div class="vital-box">
                    <div class="vital-label">Confidence</div>
                    <div class="vital-val" style="color: #38bdf8;">${(Number(data.confidence || 0) * 100).toFixed(0)}%</div>
                </div>
                <div class="vital-box">
                    <div class="vital-label">Detection Ratio</div>
                    <div class="vital-val" style="color: #fbbf24;">${data.detections !== null && data.detections !== undefined ? `${data.detections}/70` : 'N/A'}</div>
                </div>
                <div class="vital-box">
                    <div class="vital-label">Malware Families</div>
                    <div class="vital-val" style="font-size: 14px; color: #ffffff;">${(data.malware_families && data.malware_families.length) ? data.malware_families.join(', ') : 'None'}</div>
                </div>
                <div class="vital-box">
                    <div class="vital-label">Last Observed</div>
                    <div class="vital-val" style="font-size: 12px; color: var(--text-secondary);">${formatTimestamp(data.last_seen) || 'Active'}</div>
                </div>
            </div>

            <div class="section-block">
                <div class="section-head"><h4>Threat Intelligence Attribution</h4></div>
                <p style="font-size: 13px; color: var(--text-secondary);">${escapeHtml(data.source || 'Threat Intelligence Engine')}</p>
                <p style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">* All mock IOC metadata is synthetic for demo/evaluation.</p>
            </div>

            <div class="section-block">
                <div class="section-head"><h4>Associated Correlated Incidents</h4></div>
                <div>${relatedIncidentsHtml}</div>
            </div>

            <div class="section-block">
                <div class="section-head"><h4>Related Alerts in Current Dataset</h4></div>
                <div>${relatedAlertsHtml}</div>
            </div>
        </div>
    `;
}

// ==========================================================================
// 8. AI SOC COPILOT
// ==========================================================================

function updateCopilotContext(id, type) {
    const label = document.getElementById("copilotContextLabel");
    if (label) {
        label.textContent = id ? `Context: ${type} ${id}` : "Context: General Knowledge Base";
    }
}

function sendQuickPrompt(promptText) {
    document.getElementById("copilotQuestionInput").value = promptText;
    sendCopilotMessage();
}

async function sendCopilotMessage() {
    const input = document.getElementById("copilotQuestionInput");
    const question = input.value.trim();
    if (!question) return;

    const feed = document.getElementById("copilotChatFeed");
    const btn = document.getElementById("btnSendCopilot");

    // Append User message
    appendChatMessage("user", "You (Analyst)", question);
    input.value = "";
    btn.disabled = true;

    // Loading bubble
    const loadingId = "loadingBubble_" + Date.now();
    const loadingBubble = document.createElement("div");
    loadingBubble.id = loadingId;
    loadingBubble.className = "chat-message chat-assistant";
    loadingBubble.innerHTML = `
        <div class="chat-avatar">🤖</div>
        <div class="chat-body">
            <div class="chat-sender">ITTC-AI Copilot <span class="chat-tag">Retrieving FAISS Knowledge &bull; Querying Qwen3</span></div>
            <div class="state-loading" style="padding: 10px 0; justify-content: flex-start;">
                <span class="spinner"></span> Grounding response with cybersecurity knowledge chunks...
            </div>
        </div>
    `;
    feed.appendChild(loadingBubble);
    feed.scrollTop = feed.scrollHeight;

    try {
        const payload = {
            question: question,
            incident_id: selectedIncidentId,
            alert_id: selectedAlertId,
            history: copilotHistory,
        };

        const res = await fetch(`${API_BASE}/api/copilot/chat`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
        });

        if (!res.ok) throw new Error(`Copilot returned HTTP ${res.status}`);
        const result = await res.json();

        // Remove loading
        const loader = document.getElementById(loadingId);
        if (loader) loader.remove();

        // Update history
        copilotHistory.push({ role: "user", content: question });
        copilotHistory.push({ role: "assistant", content: result.answer });
        if (copilotHistory.length > 8) copilotHistory = copilotHistory.slice(-8);

        // Append assistant message with RAG sources
        appendChatMessage("assistant", "ITTC-AI Copilot", result.answer, result.sources);
    } catch (err) {
        const loader = document.getElementById(loadingId);
        if (loader) loader.remove();
        appendChatMessage("assistant", "ITTC-AI Copilot", `I encountered an issue processing your query: ${err.message}. Please verify local Ollama is active.`);
    } finally {
        btn.disabled = false;
        feed.scrollTop = feed.scrollHeight;
    }
}

function appendChatMessage(role, sender, text, sources = []) {
    const feed = document.getElementById("copilotChatFeed");
    const msgDiv = document.createElement("div");
    msgDiv.className = `chat-message chat-${role}`;

    const avatar = role === "user" ? "👨‍💻" : "🤖";
    const tag = role === "assistant" ? `<span class="chat-tag">RAG-Grounded &bull; Qwen3</span>` : "";

    const sourcesHtml = (sources && sources.length) ? `
        <div class="rag-sources-box">
            <div class="rag-sources-title">Retrieved Knowledge Attribution (FAISS Grounding):</div>
            <div class="rag-pill-list">
                ${sources.map(s => `
                    <span class="rag-pill" title="${escapeHtml(s.topic || s.document)}">
                        <span style="color:#60a5fa;">[${escapeHtml(s.category || 'KB')}]</span>
                        <span>${escapeHtml(s.document)}</span>
                        <span class="rag-pill-score">${(Number(s.relevance) * 100).toFixed(0)}%</span>
                    </span>
                `).join("")}
            </div>
        </div>
    ` : "";

    msgDiv.innerHTML = `
        <div class="chat-avatar">${avatar}</div>
        <div class="chat-body">
            <div class="chat-sender">${escapeHtml(sender)} ${tag}</div>
            <div class="chat-text">${formatMarkdown(text)}</div>
            ${sourcesHtml}
        </div>
    `;

    feed.appendChild(msgDiv);
    feed.scrollTop = feed.scrollHeight;
}

// ==========================================================================
// 9. INCIDENT REPORT MODAL
// ==========================================================================

async function openReportModal(incidentId) {
    const modal = document.getElementById("reportModal");
    const titleEl = document.getElementById("modalReportTitle");
    const jsonEl = document.getElementById("modalReportJSON");

    titleEl.textContent = `Incident Dossier Report: ${incidentId}`;
    jsonEl.textContent = "Loading incident report from backend...";
    modal.style.display = "flex";

    try {
        const res = await fetch(`${API_BASE}/api/incidents/${incidentId}/report`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        activeReportData = await res.json();
        jsonEl.textContent = JSON.stringify(activeReportData, null, 2);
    } catch (err) {
        jsonEl.textContent = `Failed to generate report: ${err.message}`;
    }
}

function closeReportModal() {
    document.getElementById("reportModal").style.display = "none";
}

function copyReportJSON() {
    if (!activeReportData) return;
    navigator.clipboard.writeText(JSON.stringify(activeReportData, null, 2))
        .then(() => alert("Report JSON copied to clipboard."))
        .catch(() => alert("Could not copy to clipboard."));
}

function downloadReportJSON() {
    if (!activeReportData) return;
    const str = JSON.stringify(activeReportData, null, 2);
    const blob = new Blob([str], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `incident_report_${activeReportData.incident ? activeReportData.incident.incident_id : 'export'}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// ==========================================================================
// 10. METRICS TAB RENDERING
// ==========================================================================

function renderMetrics() {
    // 1. Severity Distribution
    const sevContainer = document.getElementById("metricSeverityBars");
    if (sevContainer && allAlerts.length) {
        const counts = { critical: 0, high: 0, medium: 0, low: 0 };
        allAlerts.forEach(a => {
            const s = String(a.severity).toLowerCase();
            if (counts[s] !== undefined) counts[s]++;
        });

        const maxVal = Math.max(...Object.values(counts), 1);
        sevContainer.innerHTML = Object.entries(counts).map(([sev, count]) => {
            const pct = Math.round((count / maxVal) * 100);
            const color = sev === 'critical' ? 'var(--color-critical)' :
                          sev === 'high' ? 'var(--color-high)' :
                          sev === 'medium' ? 'var(--color-medium)' : 'var(--color-low)';
            return `
                <div class="bar-row">
                    <span class="bar-label" style="text-transform:uppercase;">${sev}</span>
                    <div class="bar-track">
                        <div class="bar-fill" style="width: ${pct}%; background: ${color};"></div>
                    </div>
                    <span class="bar-count">${count}</span>
                </div>
            `;
        }).join("");
    }

    // 2. Incident Status Pipeline
    const statusContainer = document.getElementById("metricStatusBars");
    if (statusContainer && allIncidents.length) {
        const statusCounts = { OPEN: 0, INVESTIGATING: 0, CONTAINED: 0, RESOLVED: 0 };
        allIncidents.forEach(i => {
            const s = (i.status || "OPEN").toUpperCase();
            if (statusCounts[s] !== undefined) statusCounts[s]++;
        });

        const maxVal = Math.max(...Object.values(statusCounts), 1);
        statusContainer.innerHTML = Object.entries(statusCounts).map(([stat, count]) => {
            const pct = Math.round((count / maxVal) * 100);
            const color = stat === 'OPEN' ? '#ef4444' :
                          stat === 'INVESTIGATING' ? '#f59e0b' :
                          stat === 'CONTAINED' ? '#3b82f6' : '#10b981';
            return `
                <div class="bar-row">
                    <span class="bar-label">${stat}</span>
                    <div class="bar-track">
                        <div class="bar-fill" style="width: ${pct}%; background: ${color};"></div>
                    </div>
                    <span class="bar-count">${count}</span>
                </div>
            `;
        }).join("");
    }

    // 3. Top MITRE Techniques
    const mitreContainer = document.getElementById("metricMitreTags");
    if (mitreContainer) {
        const techCounts = {};
        allIncidents.forEach(i => {
            (i.mitre_techniques || []).forEach(t => {
                techCounts[t] = (techCounts[t] || 0) + 1;
            });
        });

        const sorted = Object.entries(techCounts).sort((a, b) => b[1] - a[1]);
        if (sorted.length) {
            mitreContainer.innerHTML = `
                <div class="tag-cloud" style="padding: 10px 0;">
                    ${sorted.map(([t, count]) => `
                        <span class="mitre-pill" style="font-size: 13px; padding: 6px 12px;">
                            ${escapeHtml(t)} <span style="opacity:0.7; font-size:11px;">(${count})</span>
                        </span>
                    `).join("")}
                </div>
            `;
        } else {
            mitreContainer.innerHTML = `
                <div class="tag-cloud" style="padding: 10px 0;">
                    <span class="mitre-pill">T1059.001 (Command & Scripting)</span>
                    <span class="mitre-pill">T1003.001 (LSASS Memory Dump)</span>
                    <span class="mitre-pill">T1071 (Application Layer Protocol)</span>
                    <span class="mitre-pill">T1021 (Remote Services / PsExec)</span>
                    <span class="mitre-pill">T1041 (Exfiltration Over C2)</span>
                </div>
            `;
        }
    }
}

// ==========================================================================
// 11. HELPER UTILITIES
// ==========================================================================

function getSeverityBadgeClass(sev) {
    const s = String(sev || "").toLowerCase();
    if (s.includes("critical")) return "badge-critical";
    if (s.includes("high")) return "badge-high";
    if (s.includes("medium")) return "badge-medium";
    return "badge-low";
}

function getStatusBadgeClass(status) {
    const s = String(status || "").toLowerCase();
    if (s.includes("open")) return "badge-status-open";
    if (s.includes("investigating")) return "badge-status-investigating";
    if (s.includes("contained")) return "badge-status-contained";
    if (s.includes("resolved")) return "badge-status-resolved";
    return "badge-status-open";
}

function formatTimestamp(ts) {
    if (!ts) return "";
    try {
        const d = new Date(ts);
        if (isNaN(d.getTime())) return String(ts);
        return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }) +
               " " + d.toLocaleDateString([], { month: "short", day: "numeric" });
    } catch {
        return String(ts);
    }
}

function escapeHtml(val) {
    return String(val ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function formatMarkdown(text) {
    if (!text) return "";
    let safe = escapeHtml(text);
    // Bold
    safe = safe.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
    // Bullet points
    safe = safe.replace(/^[\s]*[-*]\s+(.*)$/gm, '<li>$1</li>');
    safe = safe.replace(/(<li>.*<\/li>)/s, '<ul>$1</ul>');
    // Paragraph breaks
    safe = safe.replace(/\n\n/g, '<br><br>');
    return safe;
}