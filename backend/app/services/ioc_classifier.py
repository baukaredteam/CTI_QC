"""Shared abused-legitimate IOC classifier.

Whitelist on root legitimate owners only.
An attacker-created subdomain on a hosting/CDN platform is malicious and blockable.
Used by both the Threadlinqs normalizer (M1) and narrative extractor (M6).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Sequence

# Root domains of major legitimate hosting / CDN / cloud providers.
# Only the root domain itself is whitelisted — subdomains are NOT.
LEGITIMATE_ROOT_DOMAINS: frozenset[str] = frozenset(
    {
        "google.com",
        "googleapis.com",
        "microsoft.com",
        "azure.com",
        "amazonaws.com",
        "cloudfront.net",
        "akamai.net",
        "akamaiedge.net",
        "cloudflare.com",
        "fastly.net",
        "github.com",
        "github.io",
        "githubusercontent.com",
        "office365.com",
        "office.com",
        "live.com",
        "outlook.com",
        "onedrive.com",
        "sharepoint.com",
        "windows.net",
        "azureedge.net",
        "digitaloceanspaces.com",
        "herokuapp.com",
        "firebaseapp.com",
        "appspot.com",
        "s3.amazonaws.com",
        "blob.core.windows.net",
    }
)

# Simple domain extraction pattern
_DOMAIN_RE = re.compile(
    r"^(?:https?://)?([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})", re.IGNORECASE
)


class IOCVerdict(Enum):
    MALICIOUS = "malicious"
    LEGITIMATE = "legitimate"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ClassifiedIOC:
    """An IOC with its classification verdict and reason."""

    value: str
    ioc_type: str
    verdict: IOCVerdict
    reason: str


def _extract_domain(value: str) -> str | None:
    """Extract the domain from a URL or hostname string."""
    m = _DOMAIN_RE.match(value.strip())
    if m:
        return m.group(1).lower()
    # Plain domain/hostname
    cleaned = value.strip().lower()
    if "." in cleaned and " " not in cleaned:
        return cleaned
    return None


def _get_root_domain(domain: str) -> str:
    """Extract the registrable (root) domain from a full domain.

    Simple heuristic: take the last two labels, or last three if
    the second-to-last is a known short TLD part (co, com, org, etc.).
    """
    parts = domain.rstrip(".").split(".")
    if len(parts) <= 2:
        return domain
    # Handle cases like co.uk, com.au, etc.
    if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "gov", "edu"):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _is_subdomain_of_legitimate(domain: str) -> bool:
    """Check if domain is a subdomain of a legitimate root domain.

    Returns True only for subdomains (e.g., evil.herokuapp.com),
    NOT for the root domain itself (e.g., herokuapp.com).
    """
    root = _get_root_domain(domain)
    if root in LEGITIMATE_ROOT_DOMAINS:
        # It's a subdomain only if the full domain is longer than the root
        return domain != root
    # Also check if the domain ends with any legitimate root
    for legit in LEGITIMATE_ROOT_DOMAINS:
        if domain.endswith("." + legit) and domain != legit:
            return True
    return False


def classify_ioc(value: str, ioc_type: str = "domain") -> ClassifiedIOC:
    """Classify a single IOC as malicious, legitimate, or unknown.

    Rules:
    - IP addresses: always classified as UNKNOWN (need context)
    - Root legitimate domains: LEGITIMATE
    - Subdomains of legitimate platforms: MALICIOUS (attacker-created)
    - Everything else: UNKNOWN
    """
    if ioc_type in ("ipv4", "ipv6", "ip"):
        return ClassifiedIOC(
            value=value,
            ioc_type=ioc_type,
            verdict=IOCVerdict.UNKNOWN,
            reason="IP addresses require contextual analysis",
        )

    domain = _extract_domain(value)
    if domain is None:
        return ClassifiedIOC(
            value=value,
            ioc_type=ioc_type,
            verdict=IOCVerdict.UNKNOWN,
            reason="Could not extract domain",
        )

    root = _get_root_domain(domain)

    # Root legitimate domain itself → whitelist
    if domain == root and root in LEGITIMATE_ROOT_DOMAINS:
        return ClassifiedIOC(
            value=value,
            ioc_type=ioc_type,
            verdict=IOCVerdict.LEGITIMATE,
            reason=f"Root legitimate domain: {root}",
        )

    # Subdomain of a legitimate platform → malicious (attacker-created)
    if _is_subdomain_of_legitimate(domain):
        return ClassifiedIOC(
            value=value,
            ioc_type=ioc_type,
            verdict=IOCVerdict.MALICIOUS,
            reason=f"Attacker-created subdomain on legitimate platform: {root}",
        )

    # Check if the root itself is legitimate but domain equals it
    # (already handled above)

    return ClassifiedIOC(
        value=value,
        ioc_type=ioc_type,
        verdict=IOCVerdict.UNKNOWN,
        reason="Domain not in legitimate whitelist; requires analysis",
    )


def classify_iocs(
    iocs: Sequence[tuple[str, str]],
) -> list[ClassifiedIOC]:
    """Classify a batch of IOCs.

    Args:
        iocs: Sequence of (value, ioc_type) tuples.

    Returns:
        List of ClassifiedIOC results.
    """
    return [classify_ioc(value, ioc_type) for value, ioc_type in iocs]


def filter_blockable(
    classified: Sequence[ClassifiedIOC],
) -> list[ClassifiedIOC]:
    """Return only IOCs that are safe to block (not legitimate)."""
    return [
        c for c in classified if c.verdict != IOCVerdict.LEGITIMATE
    ]
