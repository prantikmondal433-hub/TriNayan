"""Brand impersonation detection – homoglyph and edit-distance checks.

Exposes `check_brand_impersonation(url) -> list[Finding]` and
`generate_lookalikes(domain) -> list[str]` (used by P3 for CT monitoring).
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from urllib.parse import urlparse

from app.schemas import Finding

# ── homoglyph map (Latin ↔ common look-alikes) ─────────────────────
_HOMOGLYPHS: dict[str, str] = {
    "a": "àáâãäåɑаαа",
    "b": "ƅЬ",
    "c": "сçćĉ",
    "d": "ԁ",
    "e": "èéêëеẹ",
    "f": "ƒ",
    "g": "ɡ",
    "h": "һ",
    "i": "ìíîïıіɪ1l",
    "j": "ϳј",
    "k": "κк",
    "l": "ⅼіl1",
    "m": "ⅿ",
    "n": "ñ",
    "o": "оóòôõöøо0",
    "p": "рρ",
    "q": "ԛ",
    "r": "г",
    "s": "ѕ",
    "t": "τ",
    "u": "ùúûüμ",
    "v": "ν",
    "w": "ω",
    "x": "хẋ",
    "y": "ýуγ",
    "z": "ᴢ",
}

# Build reverse map: confusable char → canonical ASCII
_CONFUSABLE_TO_ASCII: dict[str, str] = {}
for _ascii_char, _confusables in _HOMOGLYPHS.items():
    for _c in _confusables:
        _CONFUSABLE_TO_ASCII[_c] = _ascii_char


def _canonicalize(text: str) -> str:
    """Replace confusable characters with their ASCII equivalents."""
    return "".join(_CONFUSABLE_TO_ASCII.get(ch, ch) for ch in text)


def _edit_distance(a: str, b: str) -> int:
    """Levenshtein distance (standard DP, small strings only)."""
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            curr[j] = min(
                prev[j] + 1,
                curr[j - 1] + 1,
                prev[j - 1] + (0 if ca == cb else 1),
            )
        prev = curr
    return prev[-1]


# ── brand registry ──────────────────────────────────────────────────
_BRANDS_JSON_PATH = Path(__file__).parent / "brands.json"

_brand_cache: list[dict] | None = None


def _load_brands() -> list[dict]:
    global _brand_cache
    if _brand_cache is not None:
        return _brand_cache

    # Allow override via env var for tests / custom deployments
    path = os.environ.get("TRUSTLENS_BRANDS_JSON", str(_BRANDS_JSON_PATH))
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    _brand_cache = data.get("brands", data if isinstance(data, list) else [])
    return _brand_cache


def reload_brands() -> None:
    """Force reload (useful after updating brands.json)."""
    global _brand_cache
    _brand_cache = None
    _load_brands()


# ── public API ──────────────────────────────────────────────────────

def check_brand_impersonation(url: str) -> list[Finding]:
    """Check *url* for brand impersonation via homoglyphs and edit distance.

    Returns a list of Findings (may be empty).  Pure computation, no network.
    """
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
    except ValueError:
        return []

    if not host:
        return []

    # Strip port and extract the registrable part for comparison.
    # We compare against each domain label *and* against keyword occurrences
    # in the full hostname.
    canonical_host = _canonicalize(host)
    findings: list[Finding] = []
    seen_brands: set[str] = set()

    for brand in _load_brands():
        brand_name: str = brand["name"]
        brand_domains: list[str] = brand.get("domains", [])
        brand_keywords: list[str] = brand.get("keywords", [])

        if brand_name in seen_brands:
            continue

        # 1) Exact-domain match → legitimate, skip
        if host in brand_domains or any(host.endswith(f".{d}") for d in brand_domains):
            continue

        matched = False
        match_detail = ""

        # 2) Homoglyph check: canonical form of host contains a brand domain
        for bd in brand_domains:
            canonical_bd = _canonicalize(bd)
            if canonical_bd in canonical_host and bd not in host:
                matched = True
                match_detail = (
                    f"The domain uses look-alike characters to imitate {bd}"
                )
                break

        # 3) Edit-distance check against each brand domain's primary label
        if not matched:
            for bd in brand_domains:
                bd_label = bd.split(".")[0]  # e.g. "sbi" from "sbi.co.in"
                if len(bd_label) < 3:
                    continue
                # For very short brand labels (3 chars), only accept distance 1
                # to avoid excessive false positives.  Longer labels allow up to 2.
                max_dist = 1 if len(bd_label) < 4 else 2
                # Compare against each label of the target host.
                # Also split on hyphens to handle "paypa1-login" → "paypa1".
                for dot_label in host.split("."):
                    if dot_label == "www":
                        continue  # skip the www prefix
                    sub_labels = dot_label.split("-") if "-" in dot_label else [dot_label]
                    for label in sub_labels:
                        if len(label) < 3:
                            continue  # too short for meaningful comparison
                        dist = _edit_distance(label, bd_label)
                        if 0 < dist <= max_dist:
                            matched = True
                            match_detail = (
                                f"'{label}' is {dist} character(s) away from "
                                f"'{bd_label}' ({bd})"
                            )
                            break
                    if matched:
                        break
                if matched:
                    break

        # 4) Keyword-in-host check (e.g. "sbi-secure-login.xyz" contains "sbi")
        if not matched:
            for kw in brand_keywords:
                if len(kw) >= 3 and kw in host:
                    # Must not be a legitimate domain
                    if not any(host.endswith(f".{d}") or host == d for d in brand_domains):
                        matched = True
                        match_detail = (
                            f"Domain contains brand keyword '{kw}' but is not "
                            f"the official site ({', '.join(brand_domains[:2])})"
                        )
                        break

        if matched:
            seen_brands.add(brand_name)
            findings.append(Finding(
                id="THREAT_BRAND_IMPERSONATION",
                severity="high",
                title=f"Possible impersonation of {brand_name}",
                detail=match_detail,
                evidence={
                    "brand": brand_name,
                    "official_domains": brand_domains[:3],
                    "host": host,
                },
            ))

    return findings


def generate_lookalikes(domain: str) -> list[str]:
    """Generate plausible look-alike domains for *domain*.

    Used by P3's certificate monitoring to search CT logs.
    Returns a deduplicated list (not exhaustive, meant for CT queries).
    """
    domain = domain.lower().strip(".")
    parts = domain.split(".")
    if len(parts) < 2:
        return []

    label = parts[0]  # primary label, e.g. "sbi" from "sbi.co.in"
    rest = ".".join(parts[1:])

    lookalikes: set[str] = set()

    # Typos: single-character deletion, insertion, replacement, swap
    for i in range(len(label)):
        # deletion
        variant = label[:i] + label[i + 1:]
        if variant:
            lookalikes.add(f"{variant}.{rest}")

        # adjacent swap
        if i < len(label) - 1:
            swapped = list(label)
            swapped[i], swapped[i + 1] = swapped[i + 1], swapped[i]
            lookalikes.add(f"{''.join(swapped)}.{rest}")

    # Homoglyph substitutions (one character at a time)
    for i, ch in enumerate(label):
        glyphs = _HOMOGLYPHS.get(ch, "")
        for g in glyphs[:3]:  # limit to keep the list manageable
            variant = label[:i] + g + label[i + 1:]
            lookalikes.add(f"{variant}.{rest}")

    # Common TLD swaps
    alt_tlds = ["com", "net", "org", "in", "co", "xyz", "info", "top"]
    for tld in alt_tlds:
        candidate = f"{label}.{tld}"
        if candidate != domain:
            lookalikes.add(candidate)

    # Prefix / suffix tricks
    for affix in ["secure-", "my", "login-", "e", "official-"]:
        lookalikes.add(f"{affix}{label}.{rest}")

    lookalikes.discard(domain)
    return sorted(lookalikes)
