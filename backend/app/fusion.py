"""Risk fusion engine: intelligent multi-vector scoring with threat preservation.

Ensures that dangerous signals (brand impersonation, unresolvable dead domains,
critical security violations, or high threat scores) are never diluted away by empty
community feeds or stub modules, while properly identifying verified authentic platforms.
"""
from urllib.parse import urlparse
from app.schemas import ModuleResult, Reason

WEIGHTS = {"threat": 0.35, "websec": 0.20, "cert": 0.25, "community": 0.20}
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
    "Unknown": "Could not verify this domain due to service unavailability. Treat with caution.",
    "BlocklistOverride": "Confirmed phishing domain listed in active security threat feeds. Close immediately.",
    "BrandPhishOverride": "Deceptive brand impersonation detected targeting official institutions. Do not visit.",
    "DeadDomainOverride": "Domain does not exist or cannot be resolved in DNS. High risk of fraudulent, spoofed, or taken-down infrastructure.",
    "CredentialPhishOverride": "Suspicious login form targeting recognized brand credentials on recently registered domain.",
    "InsecureLoginOverride": "Insecure login or credential form detected with invalid or self-signed certificate.",
    "RiskyTLDOverride": "Website is hosted on a high-risk TLD with multiple security deficiencies. High probability of scam/disposable domain.",
    "VerifiedPlatform": "Official verified platform with authenticated infrastructure and established global trust.",
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
            items.append((
                SEVERITY_RANK.get(f.severity, 1),
                res.score,
                Reason(module=name, id=f.id, severity=f.severity, title=f.title)
            ))
    items.sort(key=lambda t: (t[0], t[1]), reverse=True)
    return [r for _, _, r in items[:limit]]


def _is_official_domain(host: str) -> bool:
    """Check if host belongs to an official established platform."""
    from app.modules.threat.brand import is_official_brand_domain
    return is_official_brand_domain(host)


def apply_overrides(usable: dict[str, ModuleResult], base_risk: int, url: str = "") -> tuple[int, str | None]:
    """Inspect findings across non-errored modules and URL features, returning (overridden_risk, custom_action)."""
    active_finding_ids = {
        f.id
        for res in usable.values()
        for f in res.findings
    }
    all_findings = [f for res in usable.values() for f in res.findings]

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

    # Override 2: Credential Phishing (Brand impersonation + Password form + Young domain)
    has_brand = (
        "THREAT_BRAND_IMPERSONATION" in active_finding_ids
        or any("impersonation" in f.title.lower() or "look-alike" in f.detail.lower() for f in all_findings)
    )
    has_pass = "WEBSEC_PASSWORD_FORM" in active_finding_ids
    has_young = "THREAT_YOUNG_DOMAIN" in active_finding_ids
    if has_brand and has_pass and has_young:
        return max(base_risk, 90), ACTIONS["CredentialPhishOverride"]

    # Override 3: Insecure login with bad cert
    has_bad_cert = bool(active_finding_ids & {"CERT_EXPIRED", "CERT_SELF_SIGNED"})
    has_login = "WEBSEC_LOGIN_FORM" in active_finding_ids
    if has_bad_cert and has_login:
        return max(base_risk, 70), ACTIONS["InsecureLoginOverride"]

    # Override 4: Domain cannot be resolved / Fake / Dead domain
    has_unresolvable = (
        "WEBSEC_DOMAIN_UNRESOLVABLE" in active_finding_ids
        or any(f.id == "CERT_NO_HTTPS" and ("could not be resolved" in f.detail.lower() or "offline" in f.detail.lower()) for f in all_findings)
        or any("could not be resolved" in f.detail.lower() or "dns failure" in f.title.lower() for f in all_findings)
    )
    if has_unresolvable:
        return max(base_risk, 85), ACTIONS["DeadDomainOverride"]

    # Override 5: Brand Impersonation / Homoglyph attack
    if has_brand:
        return max(base_risk, 88), ACTIONS["BrandPhishOverride"]

    # Override 6: High-Risk TLD (e.g. .xyz, .top, .buzz, .club, .online, etc.)
    is_risky_tld = (
        tld in RISKY_TLDS
        or "THREAT_RISKY_TLD" in active_finding_ids
        or any("top-level domain" in f.title.lower() or "tld" in f.id.lower() for f in all_findings)
    )
    if is_risky_tld:
        # A site on a risky TLD with 2 or more security findings or elevated risk is a scam/phishing site
        if len(all_findings) >= 2 or base_risk >= 20:
            return max(base_risk, 70), ACTIONS["RiskyTLDOverride"]
        else:
            return max(base_risk, 50), ACTIONS["Suspicious"]

    # Override 7: Verified Official Brand Platform (ScamAdviser-style Trust Boost)
    # Legitimate, established platforms (Google, YouTube, Apple, Microsoft, Amazon, etc.)
    # with no critical or high security issues have verified global authenticity.
    # MUST come BEFORE generic severity overrides so that low-severity web
    # hygiene findings (missing CSP, X-Frame-Options, etc.) don't escalate
    # these well-known domains to "Suspicious".
    if host:
        try:
            if _is_official_domain(host) and not has_bad_cert and not has_unresolvable and not has_brand and not is_risky_tld:
                # Only cap to 0 (Safe) when there are no critical or high findings
                has_critical_or_high = any(
                    f.severity in ("critical", "high") for f in all_findings
                )
                if not has_critical_or_high:
                    return 0, ACTIONS["VerifiedPlatform"]
        except Exception:
            pass

    # Override 8: Critical certificate flaws (Key reuse, expired cert, or self-signed)
    has_crit_cert = bool(active_finding_ids & {"CERT_KEY_REUSE"})
    if has_crit_cert:
        return max(base_risk, 75), ACTIONS["Dangerous"]

    # Override 9: Any Critical finding elevates risk to at least Dangerous
    has_critical = any(f.severity == "critical" for f in all_findings)
    if has_critical:
        return max(base_risk, 75), ACTIONS["Dangerous"]

    # Override 10: Multiple High findings elevate to at least Suspicious/Dangerous
    high_count = sum(1 for f in all_findings if f.severity == "high")
    if high_count >= 2:
        return max(base_risk, 70), ACTIONS["Dangerous"]
    elif high_count == 1:
        return max(base_risk, 45), ACTIONS["Suspicious"]

    return base_risk, None


def fuse(results: dict[str, ModuleResult], url: str = "") -> tuple[int, str, list[Reason], str]:
    """Return (risk, verdict, reasons, recommended_action)."""
    usable: dict[str, ModuleResult] = {}
    for n, r in results.items():
        if r.error is not None:
            continue
        if n in WEIGHTS:
            usable[n] = r

    if not usable:
        return 50, "Suspicious", [], ACTIONS["Unknown"]

    # Dynamic weights
    weights = {n: WEIGHTS[n] for n in usable}
    total_weight = sum(weights.values())
    weighted_avg = sum(weights[n] * usable[n].score for n in usable) / total_weight

    raw = weighted_avg
    base_risk = max(0, min(100, int(round(raw))))

    risk, override_action = apply_overrides(usable, base_risk, url=url)
    verdict = verdict_for(risk)
    action = override_action or ACTIONS[verdict]

    reasons = top_reasons(usable)
    if verdict == "Safe":
        # Safe sites don't alarm users with low-severity web hygiene notices as top risk reasons
        reasons = [r for r in reasons if r.severity in ("medium", "high", "critical")]

    return risk, verdict, reasons, action

