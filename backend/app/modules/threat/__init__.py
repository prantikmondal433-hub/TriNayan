"""Threat-analysis module for TrustLens (P2).

Exposes the contract: ``async def analyze(url, ctx) -> ModuleResult``.

Pipeline:
1. URL lexical features (20 features)
2. Brand impersonation detection (homoglyphs + edit-distance)
3. ML model prediction (XGBoost) + SHAP explanations
4. Fallback to heuristic scoring if model unavailable
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from app.schemas import Finding, ModuleResult, ScanContext

from .brand import check_brand_impersonation
from .url_features import extract_features, heuristic_score

logger = logging.getLogger(__name__)

# ── Lazy-loaded model and explainer ──────────────────────────────────
_model = None
_explainer = None
_feature_names = None
_model_load_attempted = False

MODEL_PATH = Path(__file__).resolve().parent.parent.parent.parent.parent / "ml" / "model.joblib"

# SHAP feature → plain-English mapping
FEATURE_EXPLANATIONS: dict[str, str] = {
    "url_length": "The URL is unusually long, which is common in phishing links",
    "host_length": "The domain name is unusually long",
    "path_length": "The URL path is unusually long",
    "query_length": "The URL has a long query string with many parameters",
    "fragment_length": "The URL contains an unusual fragment section",
    "subdomain_depth": "The domain has many subdomains, making the real host hard to see",
    "path_depth": "The URL has a deeply nested path structure",
    "digit_ratio": "The domain name contains an unusual number of digits",
    "hyphen_count": "The domain name contains many hyphens",
    "at_sign": "The URL contains an @ sign that can redirect to a different site",
    "has_at_in_path": "The URL path contains an @ sign",
    "ip_as_host": "The website uses a raw IP address instead of a domain name",
    "punycode": "The domain uses international characters that can mimic real brands",
    "entropy": "The domain name looks randomly generated",
    "tld_risk": "The domain uses a top-level domain often abused by phishing sites",
    "keyword_count": "The URL contains words commonly used in phishing (login, verify, etc.)",
    "is_shortener": "The URL uses a link-shortening service that hides the real destination",
    "has_double_slash_redirect": "The URL contains a redirect trick using double slashes",
    "non_standard_port": "The website uses a non-standard port number",
    "uses_https": "The website does not use secure HTTPS encryption",
}


def _get_model():
    """Lazy-load the model and SHAP explainer once."""
    global _model, _explainer, _feature_names, _model_load_attempted
    if _model_load_attempted:
        return _model, _explainer, _feature_names

    _model_load_attempted = True
    if not MODEL_PATH.exists():
        logger.info("Model not found at %s – will use heuristic scoring", MODEL_PATH)
        return None, None, None

    try:
        import joblib
        import shap

        loaded = joblib.load(MODEL_PATH)
        _model = loaded["model"]
        _feature_names = loaded["feature_names"]
        _explainer = shap.TreeExplainer(_model)
        logger.info("Loaded threat ML model from %s", MODEL_PATH)
    except Exception as exc:
        logger.warning("Failed to load ML model: %s", exc)
        _model = None
        _explainer = None
        _feature_names = None

    return _model, _explainer, _feature_names


def _ml_predict(
    features: dict,
) -> tuple[int, float, list[Finding]] | tuple[None, None, list[Finding]]:
    """Predict phishing probability and return score (0-100), confidence, and SHAP findings."""
    model, explainer, feature_names = _get_model()
    if model is None:
        return None, None, []

    try:
        import pandas as pd

        X = pd.DataFrame([features])
        prob = float(model.predict_proba(X)[0][1])
        score = int(round(prob * 100))
        confidence = 0.85  # ML model with group-split evaluation gives high confidence

        # SHAP explanations
        findings: list[Finding] = []
        if explainer is not None:
            shap_values = explainer.shap_values(X)
            sv = shap_values[1][0] if isinstance(shap_values, list) else shap_values[0]

            contributions = list(zip(feature_names, sv, [features.get(f, 0) for f in feature_names]))
            contributions.sort(key=lambda x: abs(x[1]), reverse=True)

            for fname, shap_val, fval in contributions[:4]:
                if shap_val <= 0.1:
                    continue  # only report features that increase phishing risk

                abs_sv = abs(shap_val)
                if abs_sv > 1.0:
                    severity = "high"
                elif abs_sv > 0.4:
                    severity = "medium"
                else:
                    severity = "low"

                title = FEATURE_EXPLANATIONS.get(fname, f"Suspicious pattern in {fname}")
                findings.append(Finding(
                    id=f"THREAT_ML_{fname.upper()}",
                    severity=severity,
                    title=title,
                    detail=f"Detected pattern: {fname} = {fval}",
                    evidence={"feature": fname, "value": fval, "shap_importance": round(float(shap_val), 3)},
                ))

        return score, confidence, findings

    except Exception as exc:
        logger.warning("ML prediction failed: %s", exc)
        return None, None, []


# ── Public contract ──────────────────────────────────────────────────

MODEL_PATH = Path(__file__).resolve().parent.parent.parent.parent.parent / "ml" / "model.joblib"

# SHAP feature → plain-English mapping
FEATURE_EXPLANATIONS: dict[str, str] = {
    "url_length": "The URL is unusually long, which is common in phishing links",
    "host_length": "The domain name is unusually long",
    "path_length": "The URL path is unusually long",
    "query_length": "The URL has a long query string with many parameters",
    "fragment_length": "The URL contains an unusual fragment section",
    "subdomain_depth": "The domain has many subdomains, making the real host hard to see",
    "path_depth": "The URL has a deeply nested path structure",
    "digit_ratio": "The domain name contains an unusual number of digits",
    "hyphen_count": "The domain name contains many hyphens",
    "at_sign": "The URL contains an @ sign that can redirect to a different site",
    "has_at_in_path": "The URL path contains an @ sign",
    "ip_as_host": "The website uses a raw IP address instead of a domain name",
    "punycode": "The domain uses international characters that can mimic real brands",
    "entropy": "The domain name looks randomly generated",
    "tld_risk": "The domain uses a top-level domain often abused by phishing sites",
    "keyword_count": "The URL contains words commonly used in phishing (login, verify, etc.)",
    "is_shortener": "The URL uses a link-shortening service that hides the real destination",
    "has_double_slash_redirect": "The URL contains a redirect trick using double slashes",
    "non_standard_port": "The website uses a non-standard port number",
    "uses_https": "The website does not use secure HTTPS encryption",
}


def _get_model():
    """Lazy-load the model and SHAP explainer once."""
    global _model, _explainer, _feature_names, _model_load_attempted
    if _model_load_attempted:
        return _model, _explainer, _feature_names

    _model_load_attempted = True
    if not MODEL_PATH.exists():
        logger.info("Model not found at %s – will use heuristic scoring", MODEL_PATH)
        return None, None, None

    try:
        import joblib
        import shap

        loaded = joblib.load(MODEL_PATH)
        _model = loaded["model"]
        _feature_names = loaded["feature_names"]
        _explainer = shap.TreeExplainer(_model)
        logger.info("Loaded threat ML model from %s", MODEL_PATH)
    except Exception as exc:
        logger.warning("Failed to load ML model: %s", exc)
        _model = None
        _explainer = None
        _feature_names = None

    return _model, _explainer, _feature_names


def _ml_predict(
    features: dict,
) -> tuple[int, float, list[Finding]] | tuple[None, None, list[Finding]]:
    """Predict phishing probability and return score (0-100), confidence, and SHAP findings."""
    model, explainer, feature_names = _get_model()
    if model is None:
        return None, None, []

    try:
        import pandas as pd

        X = pd.DataFrame([features])
        prob = float(model.predict_proba(X)[0][1])
        score = int(round(prob * 100))
        confidence = 0.85  # ML model with group-split evaluation gives high confidence

        # SHAP explanations
        findings: list[Finding] = []
        if explainer is not None:
            shap_values = explainer.shap_values(X)
            sv = shap_values[1][0] if isinstance(shap_values, list) else shap_values[0]

            contributions = list(zip(feature_names, sv, [features.get(f, 0) for f in feature_names]))
            contributions.sort(key=lambda x: abs(x[1]), reverse=True)

            for fname, shap_val, fval in contributions[:4]:
                if shap_val <= 0.1:
                    continue  # only report features that increase phishing risk

                abs_sv = abs(shap_val)
                if abs_sv > 1.0:
                    severity = "high"
                elif abs_sv > 0.4:
                    severity = "medium"
                else:
                    severity = "low"

                title = FEATURE_EXPLANATIONS.get(fname, f"Suspicious pattern in {fname}")
                findings.append(Finding(
                    id=f"THREAT_ML_{fname.upper()}",
                    severity=severity,
                    title=title,
                    detail=f"Detected pattern: {fname} = {fval}",
                    evidence={"feature": fname, "value": fval, "shap_importance": round(float(shap_val), 3)},
                ))

        return score, confidence, findings

    except Exception as exc:
        logger.warning("ML prediction failed: %s", exc)
        return None, None, []


# ── Public contract ──────────────────────────────────────────────────

async def analyze(url: str, ctx: ScanContext) -> ModuleResult:
    """Run all threat-analysis checks and return a unified ModuleResult.

    Never raises – all exceptions are caught and reported via ``error``.
    """
    findings: list[Finding] = []
    errors: list[str] = []

    # 1. Feature extraction
    try:
        features = extract_features(url)
        _add_heuristic_findings(features, findings)
    except Exception as exc:
        logger.exception("url_features failed for %s", url)
        errors.append(f"URL feature extraction failed: {exc}")
        features = {}

    # 2. Brand impersonation
    brand_findings: list[Finding] = []
    try:
        brand_findings = check_brand_impersonation(url)
        findings.extend(brand_findings)
    except Exception as exc:
        logger.exception("brand check failed for %s", url)
        errors.append(f"Brand impersonation check failed: {exc}")

    # 3. ML prediction + SHAP
    ml_score = None
    ml_confidence = None
    if features:
        ml_score, ml_confidence, shap_findings = _ml_predict(features)
        findings.extend(shap_findings)

    # 4. Final score & confidence
    if ml_score is not None and ml_confidence is not None:
        score = ml_score
        confidence = ml_confidence
    elif features:
        score, confidence = heuristic_score(features)
    else:
        score, confidence = 50, 0.2

    # Brand impersonation strongly elevates risk
    if brand_findings:
        score = max(score, 60)
        confidence = max(confidence, 0.7)

    score = min(max(score, 0), 100)

    return ModuleResult(
        module="threat",
        score=score,
        confidence=round(confidence, 2),
        findings=findings,
        error="; ".join(errors) if errors else None,
    )


def _add_heuristic_findings(features: dict, findings: list[Finding]) -> None:
    """Fallback findings when ML model is unavailable."""
    if features.get("ip_as_host"):
        findings.append(Finding(
            id="THREAT_IP_AS_HOST",
            severity="high",
            title="Website uses a raw IP address instead of a domain name",
        ))
    if features.get("tld_risk"):
        findings.append(Finding(
            id="THREAT_RISKY_TLD",
            severity="medium",
            title="Domain uses a high-risk top-level domain",
        ))
    if features.get("is_shortener"):
        findings.append(Finding(
            id="THREAT_URL_SHORTENER",
            severity="medium",
            title="URL uses a link-shortening service",
        ))
