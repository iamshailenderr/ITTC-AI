"""
Cyber Kill Chain analysis and stage classification.
Maps security telemetry and MITRE ATT&CK techniques to the 7 Cyber Kill Chain stages.
Ensures standardized, grounded kill-chain identification across all analysis outputs.
"""

from __future__ import annotations
import re
from typing import List, Optional

KILL_CHAIN_STAGES = [
    "Reconnaissance",
    "Weaponization",
    "Delivery",
    "Exploitation",
    "Installation",
    "Command and Control",
    "Actions on Objectives",
]

# Aliases and fuzzy matches for LLM outputs
_STAGE_ALIASES = {
    "recon": "Reconnaissance",
    "reconnaissance": "Reconnaissance",
    "discovery": "Reconnaissance",
    "scanning": "Reconnaissance",
    "weaponization": "Weaponization",
    "weaponize": "Weaponization",
    "delivery": "Delivery",
    "initial access": "Delivery",
    "phishing": "Delivery",
    "exploitation": "Exploitation",
    "exploit": "Exploitation",
    "execution": "Exploitation",
    "installation": "Installation",
    "persistence": "Installation",
    "defense evasion": "Installation",
    "c2": "Command and Control",
    "command and control": "Command and Control",
    "command & control": "Command and Control",
    "beaconing": "Command and Control",
    "actions on objectives": "Actions on Objectives",
    "actions on objective": "Actions on Objectives",
    "exfiltration": "Actions on Objectives",
    "impact": "Actions on Objectives",
    "lateral movement": "Actions on Objectives",
    "credential access": "Actions on Objectives",
}

# Heuristic patterns by stage
_PATTERNS = [
    ("Actions on Objectives", [
        r"exfiltration", r"data transfer", r"credential dump", r"mimikatz", r"lsass",
        r"ransom", r"encrypt", r"destroy", r"lateral movement", r"psexec", r"t1003",
        r"t1041", r"t1486", r"t1021",
    ]),
    ("Command and Control", [
        r"c2", r"beacon", r"command and control", r"cobalt", r"reverse shell",
        r"t1071", r"t1105", r"outbound connection", r"controller",
    ]),
    ("Installation", [
        r"remote service", r"service install", r"scheduled task", r"persistence",
        r"registry run", r"t1547", r"t1053", r"defense evasion", r"t1027",
    ]),
    ("Exploitation", [
        r"exploit", r"powershell.*encoded", r"code execution", r"injection",
        r"buffer overflow", r"t1190", r"t1059", r"macro execution",
    ]),
    ("Delivery", [
        r"phishing", r"attachment", r"invoice\.doc", r"download cradle",
        r"suspicious download", r"t1566", r"spearphishing",
    ]),
    ("Reconnaissance", [
        r"brute force", r"port scan", r"enumeration", r"discovery",
        r"t1110", r"t1087", r"failed login",
    ]),
    ("Weaponization", [
        r"payload generation", r"dropper create", r"macro build",
    ]),
]


def normalize_killchain_stage(stage_raw: Optional[str]) -> str:
    """Normalize any raw stage string into one of the 7 standard Kill Chain stages."""
    if not stage_raw:
        return "Exploitation"

    cleaned = stage_raw.strip().lower()
    for alias, standard in _STAGE_ALIASES.items():
        if alias in cleaned:
            return standard

    return "Exploitation"


def map_event_to_killchain(
    event_type: str = "",
    event_text: str = "",
    mitre_techniques: Optional[List[str]] = None,
) -> str:
    """
    Deterministically map alert telemetry to the most appropriate Cyber Kill Chain stage.
    Used for grounding and validating AI analysis outputs.
    """
    tech_str = " ".join(mitre_techniques or []).lower()
    combined = f"{event_type} {event_text} {tech_str}".lower()

    for stage_name, patterns in _PATTERNS:
        if any(re.search(pat, combined, re.IGNORECASE) for pat in patterns):
            return stage_name

    return "Exploitation"
