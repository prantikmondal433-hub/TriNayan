"""Risk fusion engine: intelligent multi-vector scoring with threat preservation.

Ensures that dangerous signals (brand impersonation, unresolvable dead domains,
critical security violations, or high threat scores) are never diluted away by empty
community feeds or stub modules.
"""
from app.schemas import ModuleResult, Reason

WEIGHTS = {"threat": 0.40, "websec": 0.20, "cert": 0.25, "community": 0.15}
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}

ACTIONS = {
    "Safe": "Verified low-risk domain. No deceptive patterns or cryptographic flaws detected.",
    "Suspicious": "Caution advised. Potential security flags or unverified infrastructure detected.",
    "Dangerous": "High risk of fraud, phishing, or rogue infrastructure. Do not enter passwords or payment details.",
    "Unknown": "Unable to verify this domain. Treat with extreme caution.",
    "BlocklistOverride": "Confirmed phishing domain listed in active security threat feeds. Close immediately.",
    "BrandPhishOverride": "Deceptive brand impersonation detected targeting official institutions. Do not visit.",
    "DeadDomainOverride": "Domain does not exist or cannot be resolved in DNS. High risk of fraudulent, spoofed, or taken-down infrastructure.",
    "InsecureLoginOverride": "Insecure login or credential form detected with invalid or self-signed certificate.",
}


def verdict_for(risk: int) -> str:
    if risk >= 65:
        return "Dangerous"
    if risk >= 30:
        return "Suspicious"
    return "Safe"


def top_reasons(results: dict[str, ModuleResult], limit: int = 5) -> list[Reason]:
    items = []
    for name, res in results.items():
        for f in res.findings:
            items.append((
                SEVERITY_RANK.get(f.severity, 1),
                res.score,
                Reason(module=name, id=f.id, severity=f.severity, title=f.title)
            ))
    items.sort(key=lambda t: (t[0], t[1]), reverse=True)
    return [r for _, _, r in items[:limit]]


def apply_overrides(usable: dict[str, ModuleResult], base_risk: int) -> tuple[int, str | None]:
    """Inspect finding IDs across non-errored modules and return (overridden_risk, custom_action)."""
    active_finding_ids = {
        f.id
        for res in usable.values()
        for f in res.findings
    }

    # Override 1: Community or threat blocklist match
    if "COMMUNITY_BLOCKLISTED" in active_finding_ids:
        return max(base_risk, 95), ACTIONS["BlocklistOverride"]

    # Override 2: Domain cannot be resolved / Fake / Dead domain
    # When a user types a fake link like dasdasd123123fake.com, it must NOT return "Safe"!
    if "CERT_NO_HTTPS" in active_finding_ids:
        for res in usable.values():
            for f in res.findings:
                if f.id == "CERT_NO_HTTPS" and ("could not be resolved" in f.detail.lower() or "offline" in f.detail.lower()):
                    return max(base_risk, 85), ACTIONS["DeadDomainOverride"]

    # Override 3: Brand Impersonation / Homoglyph attack
    has_brand = "THREAT_BRAND_IMPERSONATION" in active_finding_ids
    if has_brand:
        return max(base_risk, 88), ACTIONS["BrandPhishOverride"]

    # Override 4: Critical certificate flaws (Key reuse, expired cert, or self-signed)
    has_crit_cert = bool(active_finding_ids & {"CERT_KEY_REUSE", "CERT_EXPIRED", "CERT_SELF_SIGNED"})
    if has_crit_cert:
        return max(base_risk, 75), ACTIONS["Dangerous"]

    # Override 5: Any Critical finding elevates risk to at least Dangerous
    has_critical = any(
        f.severity == "critical"
        for res in usable.values()
        for f in res.findings
    )
    if has_critical:
        return max(base_risk, 75), ACTIONS["Dangerous"]

    # Override 6: Multiple High findings elevate to at least Suspicious/Dangerous
    high_count = sum(
        1
        for res in usable.values()
        for f in res.findings
        if f.severity == "high"
    )
    if high_count >= 2:
        return max(base_risk, 68), ACTIONS["Dangerous"]
    elif high_count == 1:
        return max(base_risk, 45), ACTIONS["Suspicious"]

    return base_risk, None


def fuse(results: dict[str, ModuleResult]) -> tuple[int, str, list[Reason], str]:
    """Return (risk, verdict, reasons, recommended_action)."""
    usable = {n: r for n, r in results.items() if r.error is None and n in WEIGHTS}
    if not usable:
        return 50, "Suspicious", [], ACTIONS["Unknown"]

    # Weighted calculation
    total_weight = sum(WEIGHTS[n] for n in usable)
    weighted_avg = sum(WEIGHTS[n] * r.score for n, r in usable.items()) / total_weight

    # Critical Threat Preservation:
    # If threat module or cert module detects high risk, don't let empty community drag it down!
    max_individual_score = max(r.score for r in usable.values())
    if max_individual_score >= 50:
        raw = 0.65 * max_individual_score + 0.35 * weighted_avg
    else:
        raw = weighted_avg

    base_risk = max(0, min(100, int(round(raw))))

    risk, override_action = apply_overrides(usable, base_risk)
    verdict = verdict_for(risk)
    action = override_action or ACTIONS[verdict]

    return risk, verdict, top_reasons(usable), action
