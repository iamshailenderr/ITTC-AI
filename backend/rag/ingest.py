"""
RAG document ingestion — loads and chunks knowledge files from data/knowledge/.
Extracts rich metadata for FAISS vector search and grounding.
"""

import re
from pathlib import Path
from typing import Dict, List, Any

KNOWLEDGE_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "knowledge"

# Cached chunk store
_cached_chunks: List[Dict[str, Any]] | None = None


# Topic detection keywords mapped to topic labels
_TOPIC_KEYWORDS = {
    "powershell": "PowerShell Execution",
    "credential": "Credential Access",
    "lsass": "Credential Dumping",
    "brute.?force": "Brute Force",
    "lateral.?movement": "Lateral Movement",
    "psexec": "Lateral Movement",
    "phishing": "Phishing",
    "exfiltration": "Data Exfiltration",
    "ransomware": "Ransomware",
    "c2|command.?and.?control|beacon": "Command and Control",
    "persistence": "Persistence",
    "privilege.?escalation": "Privilege Escalation",
    "defense.?evasion|obfuscat": "Defense Evasion",
    "discovery|enumerat": "Discovery",
    "exploit": "Exploitation",
    "ioc|indicator": "Threat Intelligence",
    "signature|rule": "Detection Signatures",
    "incident.?response": "Incident Response",
    "triage": "Alert Triage",
    "correlation": "Detection Correlation",
    "file.?integrity|fim": "File Integrity Monitoring",
    "authentication|login|logon": "Authentication Monitoring",
    "active.?response": "Active Response",
}

# Platform detection
_PLATFORM_MAP = {
    "wazuh": "Wazuh HIDS",
    "suricata": "Suricata NIDS",
    "mitre": "MITRE ATT&CK",
    "windows": "Windows",
    "linux": "Linux",
}


def _determine_metadata(filepath: Path) -> tuple[str, str]:
    """Determine source and category from filepath."""
    rel_path = filepath.relative_to(KNOWLEDGE_DIR)
    parts = rel_path.parts

    if len(parts) > 1:
        folder = parts[0].lower()
        if folder == "mitre":
            return "MITRE", "attack-technique"
        elif folder == "wazuh":
            return "Wazuh", "hids-detection"
        elif folder == "suricata":
            return "Suricata", "nids-detection"
        elif folder == "security":
            return "Security", "incident-response"
        elif folder in ("threat_intel", "threatintel"):
            return "Threat Intel", "threat-intelligence"

    # Fallback based on filename stem
    stem = filepath.stem.lower()
    if "mitre" in stem:
        return "MITRE", "attack-technique"
    elif "wazuh" in stem:
        return "Wazuh", "hids-detection"
    elif "suricata" in stem:
        return "Suricata", "nids-detection"
    elif "threat" in stem or "ioc" in stem:
        return "Threat Intel", "threat-intelligence"

    return "Security", "general-security"


def _detect_topic(text: str, stem: str) -> str:
    """Detect the primary topic from document content and filename."""
    combined = f"{stem} {text[:2000]}".lower()
    for pattern, topic in _TOPIC_KEYWORDS.items():
        if re.search(pattern, combined, re.IGNORECASE):
            return topic
    return "General Security"


def _detect_platform(text: str, source: str) -> str:
    """Detect the platform/tool from content and source."""
    combined = f"{source} {text[:1000]}".lower()
    for keyword, platform in _PLATFORM_MAP.items():
        if keyword in combined:
            return platform
    return "General"


def _extract_techniques(text: str) -> List[str]:
    """Extract MITRE ATT&CK technique IDs from text."""
    return re.findall(r"T\d{4}(?:\.\d{3})?", text)


def _extract_document_title(text: str, default_stem: str) -> str:
    """Extract document title from first Markdown # heading."""
    match = re.search(r"^#\s+(.+)$", text, re.MULTILINE)
    if match:
        return match.group(1).strip()
    return default_stem.replace("_", " ").title()


def _split_into_chunks(text: str, max_chars: int = 600) -> List[str]:
    """
    Split document text into logical section/paragraph chunks.
    Preserves heading structure and sentence boundaries where possible.
    """
    # Split on markdown headings (## or ###)
    sections = re.split(r"\n(?=##?\s)", text)
    chunks: List[str] = []

    for section in sections:
        section = section.strip()
        if not section:
            continue

        if len(section) <= max_chars:
            chunks.append(section)
        else:
            # Split long section into paragraphs
            paragraphs = section.split("\n\n")
            current = ""
            for para in paragraphs:
                para = para.strip()
                if not para:
                    continue
                if current and len(current) + len(para) + 2 > max_chars:
                    chunks.append(current.strip())
                    current = para
                else:
                    current = f"{current}\n\n{para}" if current else para
            if current.strip():
                chunks.append(current.strip())

    return chunks


def load_knowledge_chunks() -> List[Dict[str, Any]]:
    """
    Load all knowledge markdown files recursively from data/knowledge/
    and return structured chunk dictionaries with rich metadata.
    """
    global _cached_chunks
    if _cached_chunks is not None:
        return _cached_chunks

    chunks: List[Dict[str, Any]] = []
    if not KNOWLEDGE_DIR.exists():
        return chunks

    # Find all .md files recursively
    md_files = sorted(KNOWLEDGE_DIR.glob("**/*.md"))

    for filepath in md_files:
        try:
            text = filepath.read_text(encoding="utf-8")
        except Exception:
            continue

        source, category = _determine_metadata(filepath)
        doc_title = _extract_document_title(text, filepath.stem)
        topic = _detect_topic(text, filepath.stem)
        platform = _detect_platform(text, source)
        techniques = _extract_techniques(text)
        raw_chunks = _split_into_chunks(text)

        for idx, chunk_text in enumerate(raw_chunks):
            # Clean chunk text
            clean_text = chunk_text.strip()
            if not clean_text:
                continue

            chunk_id = f"{source.lower().replace(' ', '_')}-{filepath.stem}-chunk-{idx}"

            chunk_data = {
                "source": source,
                "category": category,
                "document": filepath.name,
                "chunk_id": chunk_id,
                "title": doc_title,
                "text": clean_text,
                "topic": topic,
                "platform": platform,
                "techniques": techniques,
            }
            chunks.append(chunk_data)

    _cached_chunks = chunks
    return chunks


def load_knowledge() -> List[str]:
    """
    Legacy compatibility function.
    Returns list of chunk text strings.
    """
    chunks = load_knowledge_chunks()
    return [chunk["text"] for chunk in chunks]


def reset_cache() -> None:
    """Clear cached chunks (useful for testing)."""
    global _cached_chunks
    _cached_chunks = None
