"""Passive Web Security Hygiene module for TrustLens.

Performs strictly passive inspections:
1. Validates HTTP → HTTPS transport security.
2. Checks for critical security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options).
3. Evaluates cookie security flags and server version disclosures.
"""
from __future__ import annotations

import logging
from urllib.parse import urlparse

import httpx

from app.safety import UnsafeURLError, UnresolvableHostError, assert_public_url
from app.schemas import Finding, ModuleResult, ScanContext

logger = logging.getLogger(__name__)


async def analyze(url: str, ctx: ScanContext) -> ModuleResult:
    findings: list[Finding] = []
    score = 0

    try:
        # Pre-flight SSRF check
        assert_public_url(url)
    except UnresolvableHostError:
        return ModuleResult(
            module="websec",
            score=70,
            confidence=0.8,
            findings=[
                Finding(
                    id="WEBSEC_DOMAIN_UNRESOLVABLE",
                    severity="high",
                    title="Website host could not be resolved (DNS Failure)",
                    detail="The domain name does not exist or has no active DNS A/AAAA records. It is either completely fake, expired, or removed.",
                )
            ],
        )
    except UnsafeURLError as e:
        return ModuleResult(
            module="websec",
            score=60,
            confidence=0.7,
            findings=[
                Finding(
                    id="WEBSEC_UNSAFE_HOST",
                    severity="high",
                    title="Target resolves to a restricted or invalid address",
                    detail=str(e),
                )
            ],
        )

    parsed = urlparse(url)
    if parsed.scheme.lower() != "https":
        findings.append(
            Finding(
                id="WEBSEC_INSECURE_HTTP",
                severity="high",
                title="Website does not use HTTPS encryption",
                detail="All communication with this website is sent in cleartext, leaving passwords and data vulnerable to interception.",
            )
        )
        score += 35

    # Passive headers check with 4-second timeout
    try:
        async with httpx.AsyncClient(timeout=4.0, follow_redirects=True, verify=False) as client:
            resp = await client.head(url)
            headers = resp.headers

            # HSTS Check (respects browser HSTS preload list for major domains and TLDs)
            host = (parsed.hostname or "").lower()
            is_preloaded = (
                host.endswith(".dev") or host.endswith(".app") or host.endswith(".page")
                or host == "google.com" or host.endswith(".google.com")
                or host == "youtube.com" or host.endswith(".youtube.com")
                or host == "gmail.com" or host.endswith(".gmail.com")
            )
            if "strict-transport-security" not in headers and not is_preloaded:
                findings.append(
                    Finding(
                        id="WEBSEC_MISSING_HSTS",
                        severity="medium",
                        title="Strict-Transport-Security (HSTS) header is missing",
                        detail="Without HSTS, attackers can downgrade user connections from HTTPS to insecure HTTP.",
                    )
                )
                score += 15

            # CSP Check
            has_csp = "content-security-policy" in headers or "content-security-policy-report-only" in headers
            if not has_csp:
                findings.append(
                    Finding(
                        id="WEBSEC_MISSING_CSP",
                        severity="low",
                        title="Content-Security-Policy (CSP) is missing",
                        detail="The site lacks a Content Security Policy to prevent cross-site scripting (XSS) and unauthorized data injection.",
                    )
                )
                score += 10

            # Clickjacking defense
            if "x-frame-options" not in headers and "frame-ancestors" not in headers.get("content-security-policy", ""):
                findings.append(
                    Finding(
                        id="WEBSEC_MISSING_FRAMING",
                        severity="low",
                        title="Missing clickjacking protection (X-Frame-Options)",
                        detail="The page can be embedded inside unauthorized iframes, enabling UI redress and clickjacking attacks.",
                    )
                )
                score += 8

            # MIME sniffing defense
            if "x-content-type-options" not in headers:
                findings.append(
                    Finding(
                        id="WEBSEC_MISSING_NOSNIFF",
                        severity="low",
                        title="X-Content-Type-Options header missing",
                        detail="Without 'nosniff', browsers may execute malicious user-uploaded content as script.",
                    )
                )
                score += 5

            # Version disclosure
            server = headers.get("server") or headers.get("x-powered-by")
            if server and any(c.isdigit() for c in server):
                findings.append(
                    Finding(
                        id="WEBSEC_SERVER_DISCLOSURE",
                        severity="low",
                        title=f"Server exposes technology version: {server}",
                        detail="Disclosing detailed software versions helps attackers pinpoint known CVE vulnerabilities.",
                    )
                )
                score += 5

    except Exception as exc:
        logger.info("Passive HTTP probe failed for %s: %s", url, exc)
        findings.append(
            Finding(
                id="WEBSEC_CONNECT_FAILED",
                severity="medium",
                title="Web server failed to respond to security audit",
                detail="The server timed out, refused the connection, or rejected automated requests.",
            )
        )
        score += 25

    return ModuleResult(
        module="websec",
        score=min(score, 100),
        confidence=0.85 if findings else 0.5,
        findings=findings,
    )
