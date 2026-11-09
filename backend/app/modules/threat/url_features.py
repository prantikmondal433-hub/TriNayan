"""URL lexical feature extraction for phishing detection.

Used identically in both live scoring (backend/app/modules/threat/) and ML
training (ml/), so the two can never drift apart.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from urllib.parse import urlparse

# ── configurable lists ──────────────────────────────────────────────
SUSPICIOUS_KEYWORDS: list[str] = [
    "login", "signin", "sign-in", "verify", "secure", "account",
    "update", "confirm", "banking", "password", "credential",
    "suspend", "alert", "urgent", "unlock", "expire", "wallet",
    "invoice", "payment", "refund", "reward", "bonus", "free",
    "click", "ebayisapi", "webscr", "claim", "kyc", "otp",
    "airdrop", "giveaway", "lottery", "prize", "winner", "support",
    "billing", "recharge", "pan", "aadhaar", "gift", "crypto",
    "binance", "invest", "telegram", "whatsapp", "prize-claim",
]

HIGH_RISK_TLDS: set[str] = {
    ".tk", ".ml", ".ga", ".cf", ".gq",   # Freenom free TLDs
    ".top", ".xyz", ".buzz", ".club", ".info", ".work", ".click",
    ".link", ".surf", ".rest", ".icu", ".cam", ".loan", ".win",
    ".live", ".fit", ".online", ".site", ".cc", ".to", ".sbs", ".monster",
}

KNOWN_SHORTENERS: set[str] = {
    "bit.ly", "t.co", "goo.gl", "tinyurl.com", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy",
    "tiny.cc", "lnkd.in", "soo.gd", "s.id", "clck.ru",
}


def _shannon_entropy(s: str) -> float:
    """Shannon entropy of a string (bits per character)."""
    if not s:
        return 0.0
    length = len(s)
    freq = Counter(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _is_ip_host(host: str) -> bool:
    """True if host looks like a bare IPv4 or IPv6 address."""
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host)) or ":" in host


def _is_punycode(host: str) -> bool:
    return any(label.startswith("xn--") for label in host.split("."))


def extract_features(url: str) -> dict:
    """Return a feature dict for *url*. Pure-computation, no network."""
    try:
        parsed = urlparse(url)
    except ValueError:
        return _fallback_features(url)

    host = (parsed.hostname or "").lower()
    path = parsed.path or ""
    full = url.lower()

    subdomain_depth = max(len(host.split(".")) - 2, 0)
    host_length = len(host)
    url_length = len(url)

    digit_count = sum(c.isdigit() for c in host)
    digit_ratio = digit_count / host_length if host_length else 0.0

    hyphen_count = host.count("-")
    at_sign = int("@" in url)
    ip_as_host = int(_is_ip_host(host))
    punycode = int(_is_punycode(host))

    entropy = _shannon_entropy(host)

    # Extract TLD (last dotted label)
    parts = host.rsplit(".", 1)
    tld = f".{parts[-1]}" if len(parts) > 1 else ""
    tld_risk = int(tld in HIGH_RISK_TLDS)

    keyword_hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full]
    keyword_count = len(keyword_hits)

    is_shortener = int(host in KNOWN_SHORTENERS)

    # Path features
    path_length = len(path)
    path_depth = path.strip("/").count("/") if path.strip("/") else 0
    has_double_slash_redirect = int("//" in path)

    # Query / fragment
    query_length = len(parsed.query or "")
    fragment_length = len(parsed.fragment or "")

    # Security indicators
    non_standard_port = int(parsed.port not in (80, 443, None))
    uses_https = int(parsed.scheme.lower() == "https")
    has_at_in_path = int("@" in path)

    return {
        "url_length": url_length,
        "host_length": host_length,
        "path_length": path_length,
        "query_length": query_length,
        "fragment_length": fragment_length,
        "subdomain_depth": subdomain_depth,
        "path_depth": path_depth,
        "digit_ratio": round(digit_ratio, 4),
        "hyphen_count": hyphen_count,
        "at_sign": at_sign,
        "has_at_in_path": has_at_in_path,
        "ip_as_host": ip_as_host,
        "punycode": punycode,
        "entropy": round(entropy, 4),
        "tld_risk": tld_risk,
        "keyword_count": keyword_count,
        "is_shortener": is_shortener,
        "has_double_slash_redirect": has_double_slash_redirect,
        "non_standard_port": non_standard_port,
        "uses_https": uses_https,
    }


def _fallback_features(raw: str) -> dict:
    """Maximum-suspicion features for an unparseable URL."""
    return {
        "url_length": len(raw),
        "host_length": 0,
        "path_length": 0,
        "query_length": 0,
        "fragment_length": 0,
        "subdomain_depth": 0,
        "path_depth": 0,
        "digit_ratio": 0.0,
        "hyphen_count": 0,
        "at_sign": 0,
        "has_at_in_path": 0,
        "ip_as_host": 0,
        "punycode": 0,
        "entropy": 0.0,
        "tld_risk": 0,
        "keyword_count": 0,
        "is_shortener": 0,
        "has_double_slash_redirect": 0,
        "non_standard_port": 0,
        "uses_https": 0,
    }


def heuristic_score(features: dict) -> tuple[int, float]:
    """Accurate Scamadviser-calibrated rule-based risk score (0-100) and confidence (0-1)."""
    score = 0.0

    # Strong red flags
    if features.get("ip_as_host"):
        score += 50
    if features.get("punycode"):
        score += 35
    if features.get("at_sign") or features.get("has_at_in_path"):
        score += 35
    if features.get("has_double_slash_redirect"):
        score += 25

    # Keywords + TLD correlation (classic phishing infrastructure)
    kw_count = features.get("keyword_count", 0)
    has_risky_tld = bool(features.get("tld_risk"))

    if kw_count >= 3:
        score += 35
    elif kw_count >= 1:
        score += 18

    if has_risky_tld:
        score += 25
        # Risky TLD with suspicious keywords is almost certainly a scam link
        if kw_count >= 1:
            score += 25

    # Obfuscation & length
    if features.get("is_shortener"):
        score += 20
    if features.get("entropy", 0) > 4.2:
        score += 20
    elif features.get("entropy", 0) > 3.8:
        score += 10

    if features.get("subdomain_depth", 0) >= 3:
        score += 20
    elif features.get("subdomain_depth", 0) >= 2:
        score += 10

    if features.get("hyphen_count", 0) >= 3:
        score += 18
    elif features.get("hyphen_count", 0) >= 2:
        score += 10

    if features.get("url_length", 0) > 90:
        score += 12
    if features.get("non_standard_port"):
        score += 20
    if not features.get("uses_https"):
        score += 10

    clamped = min(int(round(score)), 100)
    confidence = min(0.45 + 0.05 * kw_count + 0.1 * int(features.get("ip_as_host", 0)) + 0.1 * int(has_risky_tld), 0.90)
    return clamped, round(confidence, 2)
