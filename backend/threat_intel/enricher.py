"""Threat Intelligence provider orchestration.

VirusTotal is preferred when configured. If a live VT lookup fails, the existing
synthetic/offline provider is used so IOC investigation and the rest of the SOC
pipeline continue working.
"""

from __future__ import annotations

import os
from typing import List, Protocol, runtime_checkable

from backend.threat_intel.models import IOC, IOCEnrichment


@runtime_checkable
class ThreatIntelProvider(Protocol):
    def enrich(self, ioc_type: str, value: str) -> IOCEnrichment:
        ...


class _FallbackProvider:
    """Use the preferred provider first, then fall back to the existing mock."""

    def __init__(self, primary: ThreatIntelProvider, fallback: ThreatIntelProvider) -> None:
        self.primary = primary
        self.fallback = fallback

    def enrich(self, ioc_type: str, value: str) -> IOCEnrichment:
        try:
            result = self.primary.enrich(ioc_type, value)
            if result.provider_status != "unavailable":
                return result
        except Exception:
            pass

        result = self.fallback.enrich(ioc_type, value)
        return result.model_copy(
            update={
                "provider_status": "fallback",
                "source": f"{result.source}; VirusTotal unavailable",
            }
        )


def get_provider() -> ThreatIntelProvider:
    """Return VirusTotal when configured, otherwise the existing mock provider."""
    fallback = None
    api_key = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
    if api_key:
        try:
            from backend.threat_intel.virustotal_provider import VirusTotalProvider
            from backend.threat_intel.mock_provider import MockThreatIntelProvider
            fallback = MockThreatIntelProvider()
            return _FallbackProvider(VirusTotalProvider(api_key), fallback)
        except Exception:
            pass

    from backend.threat_intel.mock_provider import MockThreatIntelProvider
    return MockThreatIntelProvider()


def enrich_iocs(
    iocs: List[IOC],
    provider: ThreatIntelProvider | None = None,
) -> List[IOCEnrichment]:
    if provider is None:
        provider = get_provider()
    return [provider.enrich(ioc.type, ioc.value) for ioc in iocs]


def format_enrichment_for_prompt(enrichments: List[IOCEnrichment]) -> str:
    """Format TI data for the LLM while explicitly identifying its provenance."""
    actionable = [e for e in enrichments if e.reputation != "unknown" or e.source == "VirusTotal"]
    if not actionable:
        return ""

    lines: List[str] = ["## Threat Intelligence (IOC Enrichment)\n"]
    for e in actionable:
        lines.append(f"- **{e.type.upper()}**: `{e.value}`")
        lines.append(f"  - Source: {e.source}")
        lines.append(f"  - Provider status: {e.provider_status}")
        lines.append(f"  - Reputation: {e.reputation}")
        lines.append(f"  - Confidence: {e.confidence:.0%}")
        lines.append(f"  - Malicious: {e.malicious}")
        if e.malicious_count is not None:
            lines.append(f"  - VT malicious engines: {e.malicious_count}")
        if e.suspicious_count is not None:
            lines.append(f"  - VT suspicious engines: {e.suspicious_count}")
        if e.harmless_count is not None:
            lines.append(f"  - VT harmless engines: {e.harmless_count}")
        if e.undetected_count is not None:
            lines.append(f"  - VT undetected engines: {e.undetected_count}")
        if e.total_engines is not None:
            lines.append(f"  - VT total engines: {e.total_engines}")
        if e.reputation_score is not None:
            lines.append(f"  - VT reputation score: {e.reputation_score}")
        if e.categories:
            lines.append(f"  - Categories: {', '.join(e.categories)}")
        if e.malware_families:
            lines.append(f"  - Malware families: {', '.join(e.malware_families)}")
        if e.analysis_timestamp:
            lines.append(f"  - Last analysis: {e.analysis_timestamp}")
        if e.provider_status == "fallback":
            lines.append("  - NOTE: This is synthetic/offline fallback data, not live external intelligence.")
        elif e.provider_status == "unavailable":
            lines.append("  - NOTE: VirusTotal was unavailable; no external intelligence was obtained.")
        lines.append("")

    return "\n".join(lines)
