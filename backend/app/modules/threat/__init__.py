"""Threat-analysis module for TrustLens (P2).

Exposes the contract: ``async def analyze(url, ctx) -> ModuleResult``.

Phase 1 (H2-8):  URL lexical features + brand impersonation.
Phase 2 (H8-16): ML model scoring with SHAP explanations.
Phase 3 (H16-24): Redirect tracing, domain intel, page analysis.
"""
from __future__ import annotations

import logging
from typing import Any

from app.schemas import Finding, ModuleResult, ScanContext

from .brand import check_brand_impersonation
from .url_features import extract_features, heuristic_score

logger = logging.getLogger(__name__)


async def analyze(url: str, ctx: ScanContext) -> ModuleResult:
    """Run all threat-analysis checks and return a unified ModuleResult.

    Never raises – all exceptions are caught and reported via ``error``.
    """
    findings: list[Finding] = []
    errors: list[str] = []

    # ── 1. URL lexical features ─────────────────────────────────────
    try:
        features = extract_features(url)

        # Add informational findings for suspicious features
        _add_feature_findings(features, findings)

    except Exception as exc:  # pragma: no cover – defensive
        logger.exception("url_features failed for %s", url)
        errors.append(f"URL feature extraction failed: {exc}")
        features = {}

    # ── 2. Brand impersonation ──────────────────────────────────────
    try:
        brand_findings = check_brand_impersonation(url)
        findings.extend(brand_findings)
    except Exception as exc:  # pragma: no cover
        logger.exception("brand check failed for %s", url)
        errors.append(f"Brand impersonation check failed: {exc}")

    # ── 3. ML model (placeholder – wired in H8-16) ─────────────────
    ml_score: int | None = None
    ml_confidence: float | None = None
    try:
        ml_score, ml_confidence = _try_ml_predict(url, features)
    except Exception as exc:
        logger.debug("ML model unavailable: %s", exc)

    # ── 4. Compute final score ──────────────────────────────────────
    if ml_score is not None and ml_confidence is not None:
        score = ml_score
        confidence = ml_confidence
    elif features:
        score, confidence = heuristic_score(features)
    else:
        score, confidence = 50, 0.2

    # Brand impersonation bumps score
    if brand_findings:
        score = max(score, 55)
        confidence = max(confidence, 0.6)

    score = min(score, 100)

    return ModuleResult(
        module="threat",
        score=score,
        confidence=round(confidence, 2),
        findings=findings,
        error="; ".join(errors) if errors else None,
    )


# ── helpers ─────────────────────────────────────────────────────────

def _add_feature_findings(features: dict, findings: list[Finding]) -> None:
    """Translate suspicious features into plain-language findings."""

    if features.get("ip_as_host"):
        findings.append(Finding(
            id="THREAT_IP_AS_HOST",
            severity="high",
            title="Website uses a raw IP address instead of a domain name",
            detail="Legitimate websites almost always use named domains.",
        ))

    if features.get("punycode"):
        findings.append(Finding(
            id="THREAT_PUNYCODE",
            severity="medium",
            title="Domain uses special international characters (punycode)",
            detail="This can be used to make a domain look like a well-known brand.",
        ))

    if features.get("tld_risk"):
        findings.append(Finding(
            id="THREAT_RISKY_TLD",
            severity="medium",
            title="Domain uses a high-risk top-level domain",
            detail="Free or cheap TLDs like .tk, .ml, .xyz are heavily abused by phishing sites.",
        ))

    if features.get("is_shortener"):
        findings.append(Finding(
            id="THREAT_URL_SHORTENER",
            severity="medium",
            title="URL uses a link-shortening service",
            detail="Shortened links hide the real destination, which is a common phishing tactic.",
        ))

    if features.get("at_sign") or features.get("has_at_in_path"):
        findings.append(Finding(
            id="THREAT_AT_SIGN",
            severity="high",
            title="URL contains an '@' sign that may redirect to a different site",
            detail="An '@' in a URL can trick browsers into treating everything before it as a username.",
        ))

    kw_count = features.get("keyword_count", 0)
    if kw_count >= 3:
        findings.append(Finding(
            id="THREAT_SUSPICIOUS_KEYWORDS",
            severity="medium",
            title="URL contains multiple suspicious keywords",
            detail=f"Found {kw_count} keywords commonly used in phishing URLs.",
        ))

    if features.get("subdomain_depth", 0) >= 3:
        findings.append(Finding(
            id="THREAT_DEEP_SUBDOMAINS",
            severity="medium",
            title="Domain has unusually many subdomains",
            detail="Excessive subdomains can disguise the real domain.",
            evidence={"subdomain_depth": features["subdomain_depth"]},
        ))

    if features.get("entropy", 0) > 4.5:
        findings.append(Finding(
            id="THREAT_HIGH_ENTROPY",
            severity="low",
            title="Domain name looks randomly generated",
            detail="High randomness in a domain name is unusual for legitimate sites.",
            evidence={"entropy": features["entropy"]},
        ))

    if features.get("non_standard_port"):
        findings.append(Finding(
            id="THREAT_NON_STANDARD_PORT",
            severity="medium",
            title="Website uses a non-standard port",
            detail="Most legitimate websites use port 80 or 443.",
        ))

    if not features.get("uses_https"):
        findings.append(Finding(
            id="THREAT_NO_HTTPS",
            severity="low",
            title="Website does not use HTTPS encryption",
            detail="Sensitive pages should always be served over HTTPS.",
        ))

    if features.get("has_double_slash_redirect"):
        findings.append(Finding(
            id="THREAT_DOUBLE_SLASH_REDIRECT",
            severity="low",
            title="URL path contains a double-slash that may indicate a redirect trick",
        ))


def _try_ml_predict(
    url: str, features: dict
) -> tuple[int, float] | tuple[None, None]:
    """Attempt ML model prediction. Returns (score, confidence) or (None, None).

    Wired properly in H8-16 once the model is trained.
    """
    # TODO(P2-H8-16): Load model.joblib, run predict_proba, SHAP explanations
    return None, None
