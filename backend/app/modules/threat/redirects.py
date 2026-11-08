"""Redirect chain tracing with strict SSRF validation per hop.

Hard rules:
- Check assert_public_url(url) before EVERY hop.
- Max 5 redirects, timeout <= 8s, response cap 2 MB.
- Passive HEAD/GET only.
- Never crash.
"""
from __future__ import annotations

import logging
from urllib.parse import urljoin, urlparse

import httpx

from app.safety import UnsafeURLError, assert_public_url
from app.schemas import Finding, ScanContext

from .url_features import KNOWN_SHORTENERS

logger = logging.getLogger(__name__)


def _registrable_domain(host: str) -> str:
    """Best-effort registrable domain from hostname."""
    parts = host.lower().strip(".").split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host.lower()


async def trace_redirects(
    url: str,
    ctx: ScanContext | None = None,
) -> tuple[list[str], list[Finding]]:
    """Trace HTTP redirects up to max_redirects (default 5).

    Returns (redirect_chain, findings).
    Every target URL in the chain is strictly checked with assert_public_url.
    """
    timeout_s = ctx.timeout_s if ctx else 8.0
    max_redirects = ctx.max_redirects if ctx else 5
    max_bytes = ctx.max_bytes if ctx else 2_000_000

    chain: list[str] = [url]
    findings: list[Finding] = []
    current_url = url

    try:
        # Validate initial URL
        assert_public_url(current_url)
    except UnsafeURLError as exc:
        findings.append(Finding(
            id="THREAT_SSRF_BLOCKED",
            severity="critical",
            title="Scan blocked: Target resolves to an internal or private address",
            detail=str(exc),
            evidence={"url": current_url},
        ))
        return chain, findings

    initial_host = (urlparse(url).hostname or "").lower()
    initial_reg_domain = _registrable_domain(initial_host)

    for hop in range(max_redirects):
        try:
            # Re-check current URL before outbound call
            assert_public_url(current_url)

            # Manual redirect following to validate each hop against SSRF rules
            async with httpx.AsyncClient(
                verify=True,
                follow_redirects=False,
                timeout=timeout_s,
            ) as client:
                resp = await client.head(
                    current_url,
                    headers={"User-Agent": "TrustLens/1.0 (Passive Threat Scanner)"},
                )

                # Fallback to GET if HEAD method is not allowed by the server
                if resp.status_code in (405, 501):
                    async with client.stream("GET", current_url) as stream_resp:
                        resp = stream_resp

                # Check if this is a redirect response
                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location")
                    if not location:
                        break

                    next_url = urljoin(current_url, location)

                    # Validate the redirected target with assert_public_url
                    try:
                        assert_public_url(next_url)
                    except UnsafeURLError as ssrf_err:
                        findings.append(Finding(
                            id="THREAT_REDIRECT_SSRF_BLOCKED",
                            severity="critical",
                            title="Redirect to a private or internal network address was blocked",
                            detail=f"Hop {hop + 1} attempted redirect to {next_url}: {ssrf_err}",
                            evidence={"from_url": current_url, "to_url": next_url, "hop": hop + 1},
                        ))
                        chain.append(next_url)
                        break

                    # Detect loop
                    if next_url in chain:
                        findings.append(Finding(
                            id="THREAT_REDIRECT_LOOP",
                            severity="medium",
                            title="Redirect loop detected",
                            detail=f"URL loops back to {next_url}",
                            evidence={"chain": chain + [next_url]},
                        ))
                        chain.append(next_url)
                        break

                    chain.append(next_url)
                    current_url = next_url
                else:
                    break

        except (httpx.TimeoutException, httpx.NetworkError, UnsafeURLError) as exc:
            logger.debug("Redirect trace stopped at %s: %s", current_url, exc)
            break
        except Exception as exc:
            logger.debug("Unexpected error during redirect trace: %s", exc)
            break

    # Analyze redirect chain findings
    hops_count = len(chain) - 1
    if hops_count > 0:
        final_url = chain[-1]
        final_host = (urlparse(final_url).hostname or "").lower()
        final_reg_domain = _registrable_domain(final_host)

        # 1. Shortener hop
        for u in chain[:-1]:
            h = (urlparse(u).hostname or "").lower()
            if h in KNOWN_SHORTENERS:
                findings.append(Finding(
                    id="THREAT_SHORTENER_REDIRECT",
                    severity="medium",
                    title="URL shortener redirected to destination",
                    detail=f"Shortener {h} unrolled to {final_url}",
                    evidence={"shortener": h, "destination": final_url, "chain": chain},
                ))
                break

        # 2. Cross-domain redirect
        if initial_reg_domain and final_reg_domain and initial_reg_domain != final_reg_domain:
            findings.append(Finding(
                id="THREAT_CROSS_DOMAIN_REDIRECT",
                severity="medium",
                title="Website redirects to an entirely different domain",
                detail=f"Redirected from '{initial_reg_domain}' to '{final_reg_domain}'",
                evidence={"initial_domain": initial_reg_domain, "final_domain": final_reg_domain, "chain": chain},
            ))

        # 3. Long redirect chain
        if hops_count >= 3:
            findings.append(Finding(
                id="THREAT_REDIRECT_CHAIN_LONG",
                severity="medium",
                title="Suspiciously long redirect chain",
                detail=f"The URL redirected {hops_count} times before reaching the destination",
                evidence={"hops": hops_count, "chain": chain},
            ))

    return chain, findings

