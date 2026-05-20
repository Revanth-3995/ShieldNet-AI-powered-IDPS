"""
ShieldNet — Shared Utilities
Reusable pure functions used across pipelines.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
import time
from datetime import datetime, timezone
from typing import Optional

from backend.core.config import settings


# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------
SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def compute_severity(confidence: float) -> str:
    """Map a [0,1] confidence score to a severity label."""
    d = settings.detection
    if confidence >= d.CONFIDENCE_CRITICAL:
        return "critical"
    if confidence >= d.CONFIDENCE_HIGH:
        return "high"
    if confidence >= d.CONFIDENCE_MEDIUM:
        return "medium"
    return "low"


def is_higher_severity(a: str, b: str) -> bool:
    """Return True if severity `a` is strictly higher than `b`."""
    return SEVERITY_ORDER.get(a, 0) > SEVERITY_ORDER.get(b, 0)


def max_severity(a: str, b: str) -> str:
    """Return the higher of two severity labels."""
    return a if SEVERITY_ORDER.get(a, 0) >= SEVERITY_ORDER.get(b, 0) else b


# ---------------------------------------------------------------------------
# IP / network helpers
# ---------------------------------------------------------------------------
_SKIP_SRC = frozenset(["0.0.0.0", "255.255.255.255"])
_MCAST_PREFIXES = ("224.", "239.")


def is_routable_ip(ip: str) -> bool:
    """Return False for broadcast, multicast, or unspecified IPs."""
    if ip in _SKIP_SRC or ip.endswith(".255"):
        return False
    if any(ip.startswith(p) for p in _MCAST_PREFIXES):
        return False
    try:
        parsed = ipaddress.ip_address(ip)
        return not (parsed.is_loopback or parsed.is_unspecified or parsed.is_multicast)
    except ValueError:
        return False


def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Hashing helpers
# ---------------------------------------------------------------------------
def short_hash(seed: str, length: int = 16) -> str:
    """Return a short deterministic hex string derived from `seed`."""
    return hashlib.md5(seed.encode(), usedforsecurity=False).hexdigest()[:length]


def correlation_group_id(source_ip: str) -> str:
    ts = datetime.now(tz=timezone.utc).isoformat()
    return short_hash(f"{source_ip}:{ts}", length=16)


# ---------------------------------------------------------------------------
# Time helpers
# ---------------------------------------------------------------------------
def utcnow() -> datetime:
    """Return timezone-aware UTC datetime."""
    return datetime.now(tz=timezone.utc)


def utcnow_naive() -> datetime:
    """Return naive UTC datetime (for SQLite compatibility)."""
    return datetime.utcnow()


def elapsed_ms(start: float) -> float:
    """Return elapsed milliseconds since `start` (from time.perf_counter())."""
    return (time.perf_counter() - start) * 1000


# ---------------------------------------------------------------------------
# String / data helpers
# ---------------------------------------------------------------------------
def safe_filename(name: str, max_len: int = 200) -> str:
    """Sanitise a filename by removing dangerous characters."""
    sanitised = re.sub(r"[^\w.\-]", "_", name)
    return sanitised[:max_len]


def truncate(text: str, max_len: int = 500) -> str:
    if len(text) <= max_len:
        return text
    return text[:max_len] + "…"


def build_explanation(
    attack_type: str,
    source_ip: str,
    confidence: float,
    rule_triggered: Optional[str] = None,
    top_features: Optional[dict] = None,
    media_label: Optional[str] = None,
    algorithm_detected: Optional[str] = None,
    payload_estimate: Optional[int] = None,
) -> str:
    """Build a human-readable explanation string from detection data."""
    if media_label:
        # Steg event
        parts = [
            f"{media_label} steganographic covert channel detected.",
            f"Algorithm: {algorithm_detected or 'Unknown'}.",
            f"Confidence: {confidence:.0%}.",
        ]
        if payload_estimate is not None:
            parts.append(f"Estimated hidden payload: {payload_estimate} bytes.")
        return " ".join(parts)

    # IDPS event
    if rule_triggered:
        base = f"Rule '{rule_triggered}' triggered. Attack type: {attack_type} from {source_ip} (confidence: {confidence:.2f})."
    else:
        base = f"{attack_type} detected from {source_ip} with {confidence:.0%} confidence."

    if top_features:
        sorted_feats = sorted(top_features.items(), key=lambda x: -x[1])[:3]
        feat_str = ", ".join(f"{k}={v:.3f}" for k, v in sorted_feats)
        base += f" Top features: {feat_str}."

    return base
