"""
Explainable risk scoring for security alerts and incidents.

Produces structured risk factors explaining WHY a risk score is high or low.
Each factor includes: factor name, impact contribution, and supporting evidence.

This module provides deterministic risk factor computation — no LLM required.
The AI-generated risk_score from Qwen3 is preserved; this adds explanation.
"""

from __future__ import annotations

from typing import List, Optional, Dict, Any

from backend.models.alert import SecurityAlert
from backend.models.analysis import RiskFactor


# Severity contribution weights
_SEVERITY_IMPACT = {
    "critical": 30,
    "high": 20,
    "medium": 10,
    "low": 5,
}


def compute_risk_factors(
    alert: SecurityAlert,
    enrichments: Optional[List[Dict[str, Any]]] = None,
    mitre_techniques: Optional[List[str]] = None,
    anomaly_score: Optional[float] = None,
    is_anomalous: Optional[bool] = None,
    correlated_alert_count: int = 0,
) -> List[RiskFactor]:
    """
    Compute explainable risk factors for a security alert.

    Args:
        alert: The security alert being analyzed
        enrichments: IOC enrichment results (from TI provider)
        mitre_techniques: MITRE ATT&CK techniques identified
        anomaly_score: Score from anomaly detector (0-1)
        is_anomalous: Whether the alert is flagged anomalous
        correlated_alert_count: Number of correlated alerts in same incident

    Returns:
        List of RiskFactor objects explaining risk contributions
    """
    factors: List[RiskFactor] = []

    # 1. Severity contribution
    sev = alert.severity.lower()
    sev_impact = _SEVERITY_IMPACT.get(sev, 5)
    factors.append(RiskFactor(
        factor="Alert Severity",
        impact=sev_impact,
        evidence=f"Alert severity is '{alert.severity}' — base risk contribution",
    ))

    # 2. IOC / Threat Intelligence contribution
    if enrichments:
        malicious_iocs = [e for e in enrichments if e.get("malicious", False)]
        suspicious_iocs = [e for e in enrichments if e.get("reputation") == "suspicious"]

        if malicious_iocs:
            ioc_values = ", ".join(e.get("value", "?") for e in malicious_iocs[:3])
            factors.append(RiskFactor(
                factor="Malicious IOC Detected",
                impact=25,
                evidence=f"{len(malicious_iocs)} malicious IOC(s) confirmed by Threat Intelligence: {ioc_values}",
            ))
        if suspicious_iocs:
            factors.append(RiskFactor(
                factor="Suspicious IOC",
                impact=10,
                evidence=f"{len(suspicious_iocs)} suspicious IOC(s) flagged by Threat Intelligence",
            ))

    # 3. MITRE ATT&CK mapping
    if mitre_techniques:
        # Higher-risk techniques
        high_risk = [t for t in mitre_techniques if any(
            t.startswith(p) for p in ["T1003", "T1059", "T1041", "T1486", "T1190", "T1566"]
        )]
        if high_risk:
            factors.append(RiskFactor(
                factor="High-Risk MITRE Technique",
                impact=20,
                evidence=f"Mapped to high-risk technique(s): {', '.join(high_risk)}",
            ))
        elif mitre_techniques:
            factors.append(RiskFactor(
                factor="MITRE ATT&CK Mapping",
                impact=10,
                evidence=f"Mapped to technique(s): {', '.join(mitre_techniques)}",
            ))

    # 4. Anomaly contribution
    if anomaly_score is not None and is_anomalous:
        anomaly_impact = min(int(anomaly_score * 20), 20)
        factors.append(RiskFactor(
            factor="Anomaly Detected",
            impact=anomaly_impact,
            evidence=f"Alert flagged as anomalous (score: {anomaly_score:.2f}). "
                     "Behavior deviates from baseline patterns.",
        ))

    # 5. Correlation contribution
    if correlated_alert_count > 0:
        corr_impact = min(correlated_alert_count * 5, 15)
        factors.append(RiskFactor(
            factor="Multi-Alert Correlation",
            impact=corr_impact,
            evidence=f"Alert is part of an incident with {correlated_alert_count} "
                     "correlated alert(s), suggesting a coordinated attack.",
        ))

    # 6. Event-based heuristic factors
    event_lower = alert.event.lower()

    if "encoded" in event_lower or "obfuscat" in event_lower:
        factors.append(RiskFactor(
            factor="Encoded/Obfuscated Content",
            impact=10,
            evidence="Alert contains evidence of encoded or obfuscated commands/payloads",
        ))

    if "exfiltration" in event_lower or "large outbound" in event_lower:
        factors.append(RiskFactor(
            factor="Potential Data Exfiltration",
            impact=15,
            evidence="Alert indicates potential data exfiltration activity",
        ))

    if "lateral" in event_lower or "psexec" in event_lower:
        factors.append(RiskFactor(
            factor="Lateral Movement Indicator",
            impact=15,
            evidence="Alert contains indicators of lateral movement within the network",
        ))

    return factors
