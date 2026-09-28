"""
Threat Intelligence Enricher.

Orchestrates: IOC list → provider lookup → list[IOCEnrichment].

Provider selection (automatic):
  1. If VIRUSTOTAL_API_KEY env var is set  → VirusTotalProvider
  2. Otherwise                             → MockThreatIntelProvider

The rest of the application only calls enrich_iocs() and get_provider();
it never imports a specific provider directly.
"""

from __future__ import annotations

import os
from typing import List, Protocol, runtime_checkable

from backend.threat_intel.models import IOC, IOCEnrichment


# ---------------------------------------------------------------------------
# Provider protocol (interface)
# ---------------------------------------------------------------------------

@runtime_checkable
class ThreatIntelProvider(Protocol):
    """
    Threat intelligence provider interface.

    Any class that implements enrich(ioc_type, value) -> IOCEnrichment
    satisfies this protocol and can be used as a provider.
    """

    def enrich(self, ioc_type: str, value: str) -> IOCEnrichment:
        ...


# ---------------------------------------------------------------------------
# Provider factory
# ---------------------------------------------------------------------------

def get_provider() -> ThreatIntelProvider:
    """
    Return the active threat intelligence provider.

    Checks VIRUSTOTAL_API_KEY; falls back to MockThreatIntelProvider.
    """
    api_key = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
    if api_key:
        try:
            from backend.threat_intel.virustotal_provider import VirusTotalProvider
            return VirusTotalProvider(api_key)
        except Exception:
            pass  # fall through to mock

    from backend.threat_intel.mock_provider import MockThreatIntelProvider
    return MockThreatIntelProvider()


# ---------------------------------------------------------------------------
# Main enrichment function
# ---------------------------------------------------------------------------

def enrich_iocs(
    iocs: List[IOC],
    provider: ThreatIntelProvider | None = None,
) -> List[IOCEnrichment]:
    """
    Enrich a list of IOCs using the specified (or auto-selected) provider.

    IOCs with reputation 'unknown' are included so analysts can see all
    extracted indicators even when no intelligence is available for them.

    Args:
        iocs:     List of extracted IOC objects.
        provider: Optional explicit provider. Auto-selected if None.

    Returns:
        List of IOCEnrichment results, one per IOC.
    """
    if provider is None:
        provider = get_provider()

    results: List[IOCEnrichment] = []
    for ioc in iocs:
        enrichment = provider.enrich(ioc.type, ioc.value)
        results.append(enrichment)

    return results


# ---------------------------------------------------------------------------
# Formatting helper (used by analyzer prompt builder)
# ---------------------------------------------------------------------------

def format_enrichment_for_prompt(enrichments: List[IOCEnrichment]) -> str:
    """
    Format enrichment results as a concise text block for injection into
    the LLM prompt. Only includes IOCs with non-unknown reputation to
    keep the prompt focused.

    Returns an empty string if there are no enrichments worth including.
    """
    actionable = [e for e in enrichments if e.reputation != "unknown"]
    if not actionable:
        return ""

    lines: List[str] = ["## Threat Intelligence (IOC Enrichment)\n"]
    lines.append(
        "NOTE: The following IOC enrichment data is provided as supporting "
        "evidence. Treat mock/synthetic data as indicative only.\n"
    )

    for e in actionable:
        lines.append(f"- **{e.type.upper()}**: `{e.value}`")
        lines.append(f"  - Reputation: {e.reputation}")
        lines.append(f"  - Confidence: {e.confidence:.0%}")
        lines.append(f"  - Malicious: {e.malicious}")
        if e.categories:
            lines.append(f"  - Categories: {', '.join(e.categories)}")
        if e.detections is not None:
            lines.append(f"  - Detections: {e.detections}")
        if e.malware_families:
            lines.append(f"  - Malware families: {', '.join(e.malware_families)}")
        if e.last_seen:
            lines.append(f"  - Last seen: {e.last_seen}")
        lines.append(f"  - Source: {e.source}")
        lines.append("")

    return "\n".join(lines)
