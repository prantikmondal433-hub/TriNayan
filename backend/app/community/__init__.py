"""Community module: scores a URL based on user reports and blocklist matches.

Never crashes: all exceptions return ModuleResult with error set.
"""
import datetime
import logging
from urllib.parse import urlparse

from app.schemas import Finding, ModuleResult, ScanContext

logger = logging.getLogger(__name__)


def _extract_domain(url: str) -> str:
    """Extract domain from URL."""
    if "://" not in url:
        url = "https://" + url
    return (urlparse(url).hostname or "").lower()


async def analyze(url: str, ctx: ScanContext) -> ModuleResult:
    """Analyze a URL against community reports and blocklists.

    Scoring:
    - Blocklist match: +60 base score, COMMUNITY_BLOCKLISTED finding
    - Community reports: weighted by reporter reputation, scaled up to +40
    - No data: score 0, confidence 0.1
    """
    try:
        from app.community.models import (
            Blocklist,
            Report,
            ReporterReputation,
            SessionLocal,
        )

        domain = _extract_domain(url)
        if not domain:
            return ModuleResult(module="community", score=0, confidence=0.1)

        db = SessionLocal()
        try:
            findings: list[Finding] = []
            score = 0
            confidence = 0.3

            # Check blocklist
            blocklist_hits = (
                db.query(Blocklist).filter(Blocklist.domain == domain).all()
            )
            if blocklist_hits:
                sources = sorted({b.source for b in blocklist_hits})
                score += 60
                confidence = max(confidence, 0.8)
                findings.append(
                    Finding(
                        id="COMMUNITY_BLOCKLISTED",
                        severity="critical",
                        title=f"Listed in public phishing feed ({', '.join(sources)})",
                        detail=f"Domain {domain} found in: {', '.join(sources)}",
                        evidence={"sources": sources, "domain": domain},
                    )
                )

            # Check community reports (last 30 days)
            now = datetime.datetime.now(datetime.timezone.utc)
            cutoff = now - datetime.timedelta(days=30)
            reports = (
                db.query(Report)
                .filter(Report.domain == domain, Report.created_at >= cutoff)
                .all()
            )

            if reports:
                # Weight reports by reporter reputation
                reporter_ids = {r.reporter_id for r in reports}
                reps = {
                    rep.reporter_id: rep.score
                    for rep in db.query(ReporterReputation)
                    .filter(ReporterReputation.reporter_id.in_(reporter_ids))
                    .all()
                }
                weighted_count = sum(reps.get(r.reporter_id, 0.5) for r in reports)
                # Scale: 1 avg report = ~5 points, cap contribution at 40
                report_score = min(40, int(weighted_count * 5))
                score += report_score
                confidence = max(confidence, min(0.9, 0.3 + 0.1 * len(reports)))

                findings.append(
                    Finding(
                        id="COMMUNITY_REPORTED",
                        severity="high" if len(reports) >= 5 else "medium",
                        title=f"Reported by {len(reports)} user(s) in the last 30 days",
                        detail=f"Weighted report score: {weighted_count:.1f}",
                        evidence={
                            "report_count": len(reports),
                            "weighted_score": round(weighted_count, 2),
                            "categories": sorted({r.category for r in reports}),
                        },
                    )
                )

            score = max(0, min(100, score))
            return ModuleResult(
                module="community",
                score=score,
                confidence=confidence,
                findings=findings,
            )
        finally:
            db.close()

    except Exception as exc:
        logger.exception("Community module error")
        return ModuleResult(
            module="community",
            error=f"{type(exc).__name__}: {str(exc)[:200]}",
        )
