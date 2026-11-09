"""Risk fusion engine: intelligent multi-vector scoring with threat preservation.

Ensures that dangerous signals (brand impersonation, unresolvable dead domains,
critical security violations, or high threat scores) are never diluted away by empty
community feeds or stub modules.
"""
from urllib.parse import urlparse
from app.schemas import ModuleResult, Reason

WEIGHTS = {"threat": 0.45, "websec": 0.25, "cert": 0.30}
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}

RISKY_TLDS = {
    ".xyz", ".top", ".buzz", ".club", ".icu", ".cam", ".loan", ".win",
    ".work", ".click", ".link", ".live", ".fit", ".online", ".site",
    ".cc", ".to", ".sbs", ".monster", ".tk", ".ml", ".ga", ".cf", ".gq",
}

ACTIONS = {
    "Safe": "Verified low-risk domain. No deceptive patterns or cryptographic flaws detected.",
    "Suspicious": "Caution advised. Potential security flags or unverified infrastructure detected.",
    "Dangerous": "High risk of fraud, phishing, or rogue infrastructure. Do not enter passwords or payment details.",
    "Unknown": "Unable to verify this domain. Treat with extreme caution.",
    "BlocklistOverride": "Confirmed phishing domain listed in active security threat feeds. Close immediately.",
    "BrandPhishOverride": "Deceptive brand impersonation detected targeting official institutions. Do not visit.",
    "DeadDomainOverride": "Domain does not exist or cannot be resolved in DNS. High risk of fraudulent, spoofed, or taken-down infrastructure.",
    "RiskyTLDOverride": "Website is hosted on a high-risk TLD with multiple security deficiencies. High probability of scam/disposable domain.",
}


def verdict_for(risk: int) -> str:
    if risk >= 55:
        return "Dangerous"
    if risk >= 25:
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


def apply_overrides(results: dict[str, ModuleResult], base_risk: int, url: str = "") -> tuple[int, str | None]:
    """Inspect findings across modules and URL features, returning (overridden_risk, custom_action)."""
    active_finding_ids = {
        f.id
        for res in results.values()
        for f in res.findings
    }
    all_findings = [f for res in results.values() for f in res.findings]

    # Parse host and TLD directly from URL for guaranteed detection
    host = ""
    tld = ""
    if url:
        try:
            parsed = urlparse(url if "://" in url else f"https://{url}")
            host = (parsed.hostname or "").lower()
            parts = host.rsplit(".", 1)
            tld = f".{parts[-1]}" if len(parts) > 1 else ""
        except Exception:
            pass

    # Override 1: Community or threat blocklist match
    if "COMMUNITY_BLOCKLISTED" in active_finding_ids:
        return max(base_risk, 95), ACTIONS["BlocklistOverride"]

    # Override 2: Domain cannot be resolved / Fake / Dead domain
    # When a user types a fake link like notarealsite123.com, it must NEVER return "Safe"!
    has_unresolvable = (
        "WEBSEC_DOMAIN_UNRESOLVABLE" in active_finding_ids
        or any("could not be resolved" in f.detail.lower() or "dns failure" in f.title.lower() for f in all_findings)
    )
    if has_unresolvable:
        return max(base_risk, 85), ACTIONS["DeadDomainOverride"]

    # Override 3: Brand Impersonation / Homoglyph attack
    has_brand = (
        "THREAT_BRAND_IMPERSONATION" in active_finding_ids
        or any("impersonation" in f.title.lower() or "look-alike" in f.detail.lower() for f in all_findings)
    )
    if has_brand:
        return max(base_risk, 88), ACTIONS["BrandPhishOverride"]

    # Override 4: High-Risk TLD (e.g. .xyz, .top, .buzz, .club, .online, etc.)
    is_risky_tld = (
        tld in RISKY_TLDS
        or "THREAT_RISKY_TLD" in active_finding_ids
        or any("top-level domain" in f.title.lower() or "tld" in f.id.lower() for f in all_findings)
    )
    if is_risky_tld:
        # A site on a risky TLD with 2 or more security findings is a high-confidence scam/phishing site
        if len(all_findings) >= 2 or base_risk >= 20:
            return max(base_risk, 68), ACTIONS["RiskyTLDOverride"]
        else:
            return max(base_risk, 50), ACTIONS["Suspicious"]

    # Override 5: Critical certificate flaws (Key reuse, expired cert, or self-signed)
    has_crit_cert = bool(active_finding_ids & {"CERT_KEY_REUSE", "CERT_EXPIRED", "CERT_SELF_SIGNED"})
    if has_crit_cert:
        return max(base_risk, 75), ACTIONS["Dangerous"]

    # Override 6: Any Critical finding elevates risk to at least Dangerous
    has_critical = any(f.severity == "critical" for f in all_findings)
    if has_critical:
        return max(base_risk, 75), ACTIONS["Dangerous"]

    # Override 7: Cumulative findings penalty
    # A site with multiple missing headers, incomplete cert chain, or warnings is NOT safe!
    high_count = sum(1 for f in all_findings if f.severity == "high")
    med_count = sum(1 for f in all_findings if f.severity == "medium")

    if high_count >= 2:
        return max(base_risk, 70), ACTIONS["Dangerous"]
    elif high_count == 1:
        return max(base_risk, 52), ACTIONS["Suspicious"]
    elif med_count >= 2 or len(all_findings) >= 4:
        return max(base_risk, 45), ACTIONS["Suspicious"]
    elif len(all_findings) >= 2:
        return max(base_risk, 30), ACTIONS["Suspicious"]

    return base_risk, None


def fuse(results: dict[str, ModuleResult], url: str = "") -> tuple[int, str, list[Reason], str]:
    """Return (risk, verdict, reasons, recommended_action)."""
    usable: dict[str, ModuleResult] = {}
    for n, r in results.items():
        if r.error is not None:
            continue
        if n == "community":
            # Only count community if it actually has votes or findings to avoid diluting threats
            if r.score > 0 or len(r.findings) > 0:
                usable[n] = r
        elif n in WEIGHTS:
            usable[n] = r

    if not usable:
        return 50, "Suspicious", [], ACTIONS["Unknown"]

    # Dynamic weights
    weights = {n: WEIGHTS.get(n, 0.20) for n in usable}
    total_weight = sum(weights.values())
    weighted_avg = sum(weights[n] * usable[n].score for n in usable) / total_weight

    # Peak Threat Preservation:
    # If any individual module detected significant threat, preserve it!
    max_individual_score = max(r.score for r in usable.values())
    if max_individual_score >= 40:
        raw = 0.65 * max_individual_score + 0.35 * weighted_avg
    elif max_individual_score >= 25:
        raw = 0.50 * max_individual_score + 0.50 * weighted_avg
    else:
        raw = weighted_avg

    base_risk = max(0, min(100, int(round(raw))))

    risk, override_action = apply_overrides(results, base_risk, url=url)
    verdict = verdict_for(risk)
    action = override_action or ACTIONS[verdict]

    return risk, verdict, top_reasons(results), action
