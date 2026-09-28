"""
Response Recommendation Engine — generates structured response recommendations.

WARNING: This module generates RECOMMENDATIONS ONLY.
It does NOT execute any active response actions.
All recommendations are marked requires_approval=True.

The actual Wazuh Active Response integration is handled by a teammate.
"""

from __future__ import annotations

from typing import List, Optional, Dict, Any

from backend.models.alert import SecurityAlert
from backend.models.analysis import ResponseRecommendation


# Action mapping based on event patterns
_EVENT_ACTION_MAP = [
    {
        "patterns": ["c2", "beacon", "command and control", "cobalt"],
        "action": "BLOCK_IP",
        "target_field": "src_ip",
        "reason_template": "Block C2 communication from {target}",
    },
    {
        "patterns": ["brute force", "multiple failed", "credential spray"],
        "action": "BLOCK_IP",
        "target_field": "src_ip",
        "reason_template": "Block brute force source {target}",
    },
    {
        "patterns": ["lateral movement", "psexec", "remote service"],
        "action": "ISOLATE_HOST",
        "target_field": "host",
        "reason_template": "Isolate compromised host {target} to prevent lateral spread",
    },
    {
        "patterns": ["credential dump", "lsass", "mimikatz", "t1003"],
        "action": "ISOLATE_HOST",
        "target_field": "host",
        "reason_template": "Isolate host {target} — active credential harvesting detected",
    },
    {
        "patterns": ["exfiltration", "large outbound", "data transfer"],
        "action": "BLOCK_IP",
        "target_field": "dst_ip",
        "reason_template": "Block exfiltration destination {target}",
    },
    {
        "patterns": ["malicious macro", "macro execution", "phishing"],
        "action": "DISABLE_USER",
        "target_field": "user",
        "reason_template": "Disable compromised user account {target} pending investigation",
    },
    {
        "patterns": ["encoded command", "powershell.*download"],
        "action": "TERMINATE_PROCESS",
        "target_field": "host",
        "reason_template": "Terminate suspicious process on {target}",
    },
]


def generate_response_recommendation(
    alert: SecurityAlert,
    enrichments: Optional[List[Dict[str, Any]]] = None,
    risk_score: int = 50,
) -> ResponseRecommendation:
    """
    Generate a structured response recommendation for a security alert.

    This is a RECOMMENDATION ONLY — it does not execute any actions.
    All recommendations require analyst approval.

    Args:
        alert: The security alert
        enrichments: IOC enrichment results
        risk_score: AI-assessed risk score (0-100)

    Returns:
        ResponseRecommendation with action, target, reason, confidence
    """
    event_lower = alert.event.lower()
    event_type_lower = alert.event_type.lower()
    combined = f"{event_lower} {event_type_lower}"

    # Check for matching action patterns
    for mapping in _EVENT_ACTION_MAP:
        import re
        if any(re.search(pat, combined, re.IGNORECASE) for pat in mapping["patterns"]):
            # Determine target
            target_field = mapping["target_field"]
            target = getattr(alert, target_field, None) or alert.host

            if not target or target == "N/A":
                continue

            # Calculate confidence based on risk score and enrichment
            confidence = min(0.5 + (risk_score / 200.0), 0.99)

            # Boost confidence if IOC enrichment confirms malicious
            if enrichments:
                malicious_count = sum(1 for e in enrichments if e.get("malicious", False))
                if malicious_count > 0:
                    confidence = min(confidence + 0.1, 0.99)

            return ResponseRecommendation(
                action=mapping["action"],
                target=target,
                reason=mapping["reason_template"].format(target=target),
                confidence=round(confidence, 2),
                requires_approval=True,
            )

    # Default: recommend investigation
    return ResponseRecommendation(
        action="INVESTIGATE_ONLY",
        target=alert.host,
        reason=f"Further investigation recommended for alert on {alert.host}",
        confidence=round(min(0.3 + (risk_score / 200.0), 0.8), 2),
        requires_approval=True,
    )
