"""Risk fusion v2: weighted sum, re-normalised over non-errored modules, plus override rules.

Override rules:
1. Community/feed confirmed phishing (COMMUNITY_BLOCKLISTED) -> risk >= 90 (Dangerous)
2. Brand impersonation + password form + domain age < 30 days -> risk >= 90 (Dangerous)
3. Expired or self-signed certificate + login/password form -> risk >= 70 (Dangerous)
"""
from app.schemas import ModuleResult, Reason

WEIGHTS = {"threat": 0.35, "websec": 0.20, "cert": 0.25, "community": 0.20}
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}

ACTIONS = {
    "Safe": "No major risks found. Still avoid entering passwords unless you trust the site.",
    "Suspicious": "Be careful. Do not enter passwords or payment details until you have "
                  "verified the site through another route.",
    "Dangerous": "Do not enter any information on this site. Close it and report it.",
    "Unknown": "We could not analyse this site. Treat it with caution.",
    "BlocklistOverride": "Confirmed phishing site listed in active threat feeds. Do not visit or enter any data.",
    "CredentialPhishOverride": "Dangerous brand impersonation with credential collection on a newly created domain. Close this page immediately.",
    "InsecureLoginOverride": "Insecure login or password form detected with invalid/self-signed certificate. Do not enter credentials.",
}


def verdict_for(risk: int) -> str:
    if risk >= 70:
        return "Dangerous"
    if risk >= 30:
        return "Suspicious"
    return "Safe"


def top_reasons(results: dict[str, ModuleResult], limit: int = 5) -> list[Reason]:
    items = []
    for name, res in results.items():
        for f in res.findings:
            items.append((SEVERITY_RANK[f.severity], res.score, Reason(
                module=name, id=f.id, severity=f.severity, title=f.title)))
    items.sort(key=lambda t: (t[0], t[1]), reverse=True)
    return [r for _, _, r in items[:limit]]


def apply_overrides(usable: dict[str, ModuleResult], base_risk: int) -> tuple[int, str | None]:
    """Inspect finding IDs across non-errored modules and return (overridden_risk, custom_action)."""
    # Collect all finding IDs from non-errored modules
    active_finding_ids = {
        f.id
        for res in usable.values()
        for f in res.findings
    }

    # Override 1: Community or feed blocklisted
    if "COMMUNITY_BLOCKLISTED" in active_finding_ids:
        return max(base_risk, 95), ACTIONS["BlocklistOverride"]

    # Override 2: Brand impersonation + password form + young domain (<30d)
    has_brand = "THREAT_BRAND_IMPERSONATION" in active_finding_ids
    has_password_form = bool(active_finding_ids & {
        "THREAT_PASSWORD_FORM",
        "WEBSEC_PASSWORD_FORM",
        "THREAT_PASSWORD_FORM_CROSS_DOMAIN",
    })
    has_young_domain = bool(active_finding_ids & {
        "THREAT_YOUNG_DOMAIN",
        "WEBSEC_YOUNG_DOMAIN",
    })

    if has_brand and has_password_form and has_young_domain:
        return max(base_risk, 90), ACTIONS["CredentialPhishOverride"]

    # Override 3: Expired or self-signed cert + login/password form
    has_bad_cert = bool(active_finding_ids & {
        "CERT_EXPIRED",
        "CERT_SELF_SIGNED",
    })
    has_login_form = bool(active_finding_ids & {
        "THREAT_LOGIN_FORM",
        "WEBSEC_LOGIN_FORM",
        "THREAT_PASSWORD_FORM",
        "WEBSEC_PASSWORD_FORM",
    })

    if has_bad_cert and has_login_form:
        return max(base_risk, 75), ACTIONS["InsecureLoginOverride"]

    return base_risk, None


def fuse(results: dict[str, ModuleResult]) -> tuple[int, str, list[Reason], str]:
    """Return (risk, verdict, reasons, recommended_action)."""
    usable = {n: r for n, r in results.items() if r.error is None and n in WEIGHTS}
    if not usable:
        return 50, "Suspicious", [], ACTIONS["Unknown"]

    total_weight = sum(WEIGHTS[n] for n in usable)
    raw = sum(WEIGHTS[n] * r.score for n, r in usable.items()) / total_weight
    base_risk = max(0, min(100, int(round(raw))))

    risk, override_action = apply_overrides(usable, base_risk)
    verdict = verdict_for(risk)
    action = override_action or ACTIONS[verdict]

    return risk, verdict, top_reasons(usable), action
