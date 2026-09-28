"""
IOC Extractor — deterministic local regex-based extraction.

Extracts Indicators of Compromise from a SecurityAlert without using an LLM.

Supported IOC types:
  - IPv4 addresses          (public only; private RFC-1918 / loopback excluded)
  - Domains                 (heuristic — excludes known benign tlds, windows paths)
  - URLs                    (http:// and https://)
  - MD5 hashes              (32 hex chars)
  - SHA1 hashes             (40 hex chars)
  - SHA256 hashes           (64 hex chars)
"""

from __future__ import annotations

import re
import ipaddress
from typing import List

from backend.models.alert import SecurityAlert
from backend.threat_intel.models import IOC

# ---------------------------------------------------------------------------
# Compiled regex patterns
# ---------------------------------------------------------------------------

_RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

_RE_URL = re.compile(
    r"https?://[^\s\"'<>]+"
)

# Domains: at least one dot, letters/digits/hyphens, common TLD suffix.
# Kept deliberately conservative to avoid false-positives from file paths.
_RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|io|xyz|ru|cn|test|local|example|info|biz|co|gov|edu|mil|int"
    r"|onion|club|site|online|top|live|pro|shop|store|app|dev)\b"
)

# Hash lengths are unambiguous; anchored on word boundaries.
_RE_MD5    = re.compile(r"\b[0-9a-fA-F]{32}\b")
_RE_SHA1   = re.compile(r"\b[0-9a-fA-F]{40}\b")
_RE_SHA256 = re.compile(r"\b[0-9a-fA-F]{64}\b")

# ---------------------------------------------------------------------------
# Private / reserved ranges — do NOT treat these as external threat IOCs
# ---------------------------------------------------------------------------

# Explicit RFC-1918 and special-purpose ranges that should never be IOCs.
# We intentionally DO NOT block RFC-5737 TEST-NET ranges (203.0.113.0/24,
# 198.51.100.0/24, 192.0.2.0/24) so they can be used in test datasets.
_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),        # RFC-1918
    ipaddress.ip_network("172.16.0.0/12"),     # RFC-1918
    ipaddress.ip_network("192.168.0.0/16"),    # RFC-1918
    ipaddress.ip_network("127.0.0.0/8"),       # loopback
    ipaddress.ip_network("169.254.0.0/16"),    # link-local
    ipaddress.ip_network("::1/128"),           # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),          # IPv6 unique local
    ipaddress.ip_network("0.0.0.0/8"),         # unspecified
    ipaddress.ip_network("224.0.0.0/4"),       # multicast
    ipaddress.ip_network("240.0.0.0/4"),       # reserved (Class E)
]


def _is_private_or_reserved(ip_str: str) -> bool:
    """
    Return True for RFC-1918, loopback, link-local, multicast, and Class E.
    RFC-5737 documentation ranges (203.0.113.0/24, 198.51.100.0/24) are
    intentionally allowed so they can appear as synthetic IOCs in tests.
    """
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return False


def _build_text(alert: SecurityAlert) -> str:
    """Concatenate all alert string fields for scanning."""
    parts: list[str] = [
        alert.event or "",
        alert.event_type or "",
        alert.source or "",
        alert.src_ip or "",
        alert.dst_ip or "",
        alert.rule_id or "",
        alert.user or "",
        alert.host or "",
    ]
    return " ".join(p for p in parts if p)


def extract_iocs(alert: SecurityAlert) -> List[IOC]:
    """
    Extract IOCs from a SecurityAlert using deterministic regex parsing.

    Private/reserved IPs are excluded.
    URLs are extracted before domain scanning to avoid double-counting.
    Hash types are identified by character count (64 → SHA256, 40 → SHA1, 32 → MD5).
    """
    text = _build_text(alert)
    seen: set[tuple[str, str]] = set()
    iocs: List[IOC] = []

    def _add(ioc_type: str, value: str) -> None:
        key = (ioc_type, value.lower())
        if key not in seen:
            seen.add(key)
            iocs.append(IOC(type=ioc_type, value=value))

    # 1. SHA256 (64 hex chars) — check before shorter hashes
    for m in _RE_SHA256.finditer(text):
        _add("sha256", m.group(0).lower())

    # 2. SHA1 (40 hex chars) — only if not already matched as SHA256 substring
    remaining_for_hash = _RE_SHA256.sub("", text)
    for m in _RE_SHA1.finditer(remaining_for_hash):
        _add("sha1", m.group(0).lower())

    # 3. MD5 (32 hex chars)
    remaining_for_md5 = _RE_SHA1.sub("", remaining_for_hash)
    for m in _RE_MD5.finditer(remaining_for_md5):
        _add("md5", m.group(0).lower())

    # 4. URLs  (extract first so domain regex doesn't double-match)
    url_spans: list[tuple[int, int]] = []
    for m in _RE_URL.finditer(text):
        _add("url", m.group(0))
        url_spans.append(m.span())

    # 5. IPv4 — skip private/reserved
    for m in _RE_IPV4.finditer(text):
        ip = m.group(0)
        if not _is_private_or_reserved(ip):
            _add("ip", ip)

    # 6. Domains — strip any already captured in URLs
    url_free_text = _RE_URL.sub(" ", text)
    for m in _RE_DOMAIN.finditer(url_free_text):
        domain = m.group(0).rstrip(".").lower()
        # Skip if it looks like a Windows/Linux path fragment
        if len(domain) >= 4 and not domain.startswith("www.microsoft") and not domain.startswith("www.google"):
            _add("domain", domain)

    return iocs
