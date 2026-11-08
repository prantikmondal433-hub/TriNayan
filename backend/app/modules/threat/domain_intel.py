"""Domain intelligence: WHOIS registration age and DNS records via dnspython.

Hard rules:
- SSRF safe: validate host with assert_public_url first.
- Handle UnsafeURLError, timeouts, and unresolvable domains gracefully.
- Flag domains younger than 30 days (high risk) and 90 days (medium risk).
- Passive checks only.
- Never crash.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import logging
from urllib.parse import urlparse

import dns.resolver
import whois

from app.safety import UnsafeURLError, assert_public_url
from app.schemas import Finding, ScanContext

logger = logging.getLogger(__name__)


def _extract_domain(host: str) -> str:
    """Extract registrable domain from hostname (fallback)."""
    parts = host.lower().strip(".").split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host.lower()


def _get_creation_date(w) -> datetime | None:
    """Extract creation date from whois response."""
    creation = getattr(w, "creation_date", None)
    if isinstance(creation, list):
        creation = creation[0] if creation else None
    if isinstance(creation, datetime):
        if creation.tzinfo is None:
            creation = creation.replace(tzinfo=timezone.utc)
        return creation
    return None


async def analyze_domain_intel(
    url: str,
    ctx: ScanContext | None = None,
) -> tuple[dict, list[Finding]]:
    """Gather WHOIS age and DNS records for the URL's domain.

    Returns (intel_dict, findings).
    """
    findings: list[Finding] = []
    intel: dict = {
        "domain": "",
        "age_days": None,
        "registrar": None,
        "dns_records": {},
    }

    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if not host:
            return intel, findings

        # Check SSRF before querying network
        try:
            assert_public_url(url)
        except UnsafeURLError as exc:
            findings.append(Finding(
                id="THREAT_DOMAIN_SSRF_BLOCKED",
                severity="high",
                title="Domain resolution blocked by security policy",
                detail=str(exc),
            ))
            return intel, findings

        reg_domain = _extract_domain(host)
        intel["domain"] = reg_domain

        # 1. DNS Records query via dnspython (in asyncio thread)
        loop = asyncio.get_running_loop()
        dns_res = await loop.run_in_executor(None, _query_dns, reg_domain)
        intel["dns_records"] = dns_res

        # If domain has no A/AAAA records at all
        if not dns_res.get("A") and not dns_res.get("AAAA"):
            findings.append(Finding(
                id="THREAT_NO_DNS_A_RECORDS",
                severity="medium",
                title="Domain has no active A/AAAA DNS records",
                detail=f"Could not resolve an IP address for domain {reg_domain}",
            ))

        # 2. WHOIS lookup (in thread pool with timeout)
        timeout_s = ctx.timeout_s if ctx else 8.0
        try:
            w = await asyncio.wait_for(
                loop.run_in_executor(None, whois.whois, reg_domain),
                timeout=min(timeout_s, 6.0),
            )
            if w:
                intel["registrar"] = getattr(w, "registrar", None)
                cdate = _get_creation_date(w)
                if cdate:
                    now = datetime.now(timezone.utc)
                    age_days = (now - cdate).days
                    intel["age_days"] = age_days
                    intel["created_at"] = cdate.isoformat()

                    if age_days < 30:
                        findings.append(Finding(
                            id="THREAT_YOUNG_DOMAIN",
                            severity="high",
                            title=f"Domain registered only {age_days} day(s) ago",
                            detail="Phishing sites are often hosted on brand new domains created days or hours earlier.",
                            evidence={"domain": reg_domain, "age_days": age_days, "created_at": cdate.isoformat()},
                        ))
                    elif age_days < 90:
                        findings.append(Finding(
                            id="THREAT_RECENT_DOMAIN",
                            severity="medium",
                            title=f"Domain was registered recently ({age_days} days ago)",
                            detail="Relatively new domains pose higher risk than established web properties.",
                            evidence={"domain": reg_domain, "age_days": age_days},
                        ))
        except (asyncio.TimeoutError, Exception) as w_exc:
            logger.debug("WHOIS lookup failed or timed out for %s: %s", reg_domain, w_exc)

    except Exception as exc:
        logger.debug("domain_intel error for %s: %s", url, exc)

    return intel, findings


def _query_dns(domain: str) -> dict:
    """Synchronous DNS query helper."""
    records = {"A": [], "AAAA": [], "MX": [], "NS": []}
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.5
    resolver.lifetime = 3.0

    for r_type in ("A", "AAAA", "MX", "NS"):
        try:
            answers = resolver.resolve(domain, r_type)
            for rdata in answers:
                records[r_type].append(str(rdata))
        except Exception:
            pass
    return records

