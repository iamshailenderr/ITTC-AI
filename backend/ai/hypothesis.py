"""
Hypothesis generation engine for security alert triage.
Constructs evidence-grounded investigation hypotheses linking observed telemetry,
threat actors/patterns, and potential attacker objectives.
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional
from backend.models.alert import SecurityAlert


def generate_investigation_hypothesis(
    alert: SecurityAlert,
    mitre_techniques: Optional[List[str]] = None,
    kill_chain_stage: Optional[str] = None,
    enrichments: Optional[List[Dict[str, Any]]] = None,
) -> str:
    """
    Generate a grounded hypothesis for an alert based on verified evidence.
    Ensures that the hypothesis clearly states the affected asset, suspected threat mechanism,
    and potential impact without inventing unobserved telemetry.
    """
    techniques_str = f" using technique(s) {', '.join(mitre_techniques)}" if mitre_techniques else ""
    stage_str = f" at the {kill_chain_stage} stage" if kill_chain_stage else ""

    host_context = f"on host '{alert.host}'" if alert.host else "in the network environment"
    user_context = f" targeting user account '{alert.user}'" if alert.user else ""

    # Check for malicious external indicators
    malicious_iocs = []
    if enrichments:
        malicious_iocs = [e.get("value") for e in enrichments if e.get("malicious")]

    ioc_note = ""
    if malicious_iocs:
        ioc_note = f" Supported by confirmed malicious IOC(s): {', '.join(malicious_iocs[:2])}."

    event_lower = alert.event.lower()

    if "encoded" in event_lower or "powershell" in event_lower:
        core_mechanism = f"An adversary executed obfuscated PowerShell scripts {host_context}{user_context}{techniques_str}{stage_str} to establish initial execution or download secondary payloads."
    elif "beacon" in event_lower or "c2" in event_lower or "cobalt" in event_lower:
        core_mechanism = f"Compromised asset {host_context} is communicating with external command-and-control infrastructure{techniques_str}{stage_str}."
    elif "lateral" in event_lower or "psexec" in event_lower:
        core_mechanism = f"An adversary is actively moving laterally across internal network boundaries from {host_context}{techniques_str}{stage_str}."
    elif "lsass" in event_lower or "credential" in event_lower or "mimikatz" in event_lower:
        core_mechanism = f"An adversary has gained local execution on {host_context} and is harvesting plaintext credentials or hashes from LSASS memory{techniques_str}{stage_str}."
    elif "exfiltration" in event_lower or "upload" in event_lower:
        core_mechanism = f"Potential sensitive data exfiltration detected originating from {host_context} to an external endpoint{techniques_str}{stage_str}."
    elif "brute force" in event_lower or "failed" in event_lower:
        core_mechanism = f"An external or unauthorized source is conducting automated authentication attacks against {host_context}{user_context} to obtain valid credentials."
    elif "phishing" in event_lower or "macro" in event_lower:
        core_mechanism = f"A user on {host_context} was targeted with a malicious lure resulting in unauthorized code execution{techniques_str}{stage_str}."
    else:
        core_mechanism = f"Suspicious activity ({alert.event_type}) observed {host_context}{user_context}{techniques_str}{stage_str}, indicating unauthorized system interaction."

    return f"{core_mechanism}{ioc_note}"
