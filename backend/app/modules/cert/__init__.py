"""Certificate validation module for TrustLens.

Exposes the contract: ``async def analyze(url, ctx) -> ModuleResult``.

Runs blocking ssl + cryptography calls via asyncio.to_thread to keep
the event loop free.
"""
from __future__ import annotations

import asyncio
import logging

from app.safety import UnsafeURLError, UnresolvableHostError
from app.schemas import Finding, ModuleResult, ScanContext

from .cert_check import fetch_and_check

logger = logging.getLogger(__name__)

# Severity → risk-score contribution (capped at 100)
_SEVERITY_WEIGHT: dict[str, int] = {
    "critical": 40,
    "high": 25,
    "medium": 12,
    "low": 5,
}


def _score_from_findings(findings: list[Finding]) -> tuple[int, float]:
    """Compute a risk score (0-100) and confidence (0-1) from findings.

    Score is the sum of severity weights, capped at 100.
    Confidence increases with the number and severity of findings.
    """
    if not findings:
        return 0, 0.8  # no issues → low risk, decent confidence

    raw = sum(_SEVERITY_WEIGHT.get(f.severity, 5) for f in findings)
    score = min(raw, 100)

    # Confidence: base 0.5, bumped by finding count and severity
    has_critical = any(f.severity == "critical" for f in findings)
    has_high = any(f.severity == "high" for f in findings)
    confidence = 0.5
    if has_critical:
        confidence += 0.25
    elif has_high:
        confidence += 0.15
    confidence = min(confidence + 0.02 * len(findings), 0.95)

    return score, round(confidence, 2)


async def analyze(url: str, ctx: ScanContext) -> ModuleResult:
    """Run certificate checks on *url* and return a ModuleResult.

    Never raises – all exceptions are caught and reported via ``error``.
    """
    try:
        findings, _meta = await asyncio.to_thread(
            fetch_and_check, url, ctx.timeout_s
        )
        score, confidence = _score_from_findings(findings)
        return ModuleResult(
            module="cert",
            score=score,
            confidence=confidence,
            findings=findings,
        )

    except UnresolvableHostError:
        # A dead/unresolvable domain is common for taken-down phishing sites
        return ModuleResult(
            module="cert",
            score=15,
            confidence=0.2,
            findings=[
                Finding(
                    id="CERT_NO_HTTPS",
                    severity="medium",
                    title="Could not connect to the website",
                    detail=(
                        "The domain could not be resolved. It may be "
                        "offline, misspelled, or recently taken down."
                    ),
                )
            ],
        )

    except UnsafeURLError as exc:
        msg = str(exc)
        # Fallback check for message in case raw UnsafeURLError was raised
        if "Could not resolve" in msg or "No addresses" in msg:
            return ModuleResult(
                module="cert",
                score=15,
                confidence=0.2,
                findings=[
                    Finding(
                        id="CERT_NO_HTTPS",
                        severity="medium",
                        title="Could not connect to the website",
                        detail=(
                            "The domain could not be resolved. It may be "
                            "offline, misspelled, or recently taken down."
                        ),
                    )
                ],
            )
        # Private/loopback/link-local host → error, not a finding
        return ModuleResult(
            module="cert",
            score=0,
            confidence=0.0,
            error=f"Unsafe URL, skipping certificate check: {msg}",
        )

    except (ConnectionRefusedError, ConnectionResetError, OSError) as exc:
        # Connection refused, timeout, network unreachable, etc.
        return ModuleResult(
            module="cert",
            score=25,
            confidence=0.4,
            findings=[
                Finding(
                    id="CERT_NO_HTTPS",
                    severity="high",
                    title="Could not establish a secure connection",
                    detail=(
                        f"Failed to connect on port 443: {type(exc).__name__}. "
                        "The website may not support HTTPS or may be down."
                    ),
                )
            ],
        )

    except Exception as exc:
        logger.exception("Unexpected error in cert module for %s", url)
        return ModuleResult(
            module="cert",
            score=0,
            confidence=0.0,
            error=f"Certificate check failed: {type(exc).__name__}: {exc}",
        )
