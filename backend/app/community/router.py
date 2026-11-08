"""Community API: POST /report, GET /reports."""
import datetime
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.community.models import (
    ALLOWED_CATEGORIES,
    MAX_COMMENT_LENGTH,
    Blocklist,
    Report,
    ReporterReputation,
    get_db,
    make_reporter_id,
)
from app.limiter import limiter
from app.schemas import ReportRequest

router = APIRouter(tags=["community"])


def _extract_domain(url: str) -> str:
    """Extract the registered domain from a URL (simple version)."""
    if "://" not in url:
        url = "https://" + url
    host = urlparse(url).hostname or ""
    return host.lower()


@router.post("/report", status_code=201)
@limiter.limit("10/minute")
def create_report(req: ReportRequest, request: Request, db: Session = Depends(get_db)):
    """Submit a community report about a suspicious URL."""
    # Validate category
    if req.category not in ALLOWED_CATEGORIES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid category. Allowed: {sorted(ALLOWED_CATEGORIES)}",
        )

    # Validate comment length
    comment = (req.comment or "").strip()[:MAX_COMMENT_LENGTH]

    # Extract domain
    domain = _extract_domain(req.url)
    if not domain:
        raise HTTPException(status_code=400, detail="Could not extract domain from URL")

    # Anonymous reporter identity
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    reporter_id = make_reporter_id(client_ip, user_agent)

    # One vote per reporter per domain
    report = Report(
        url=req.url.strip()[:2048],
        domain=domain,
        category=req.category,
        comment=comment,
        reporter_id=reporter_id,
    )
    try:
        db.add(report)
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="You have already reported this domain",
        )

    # Update reporter reputation (create if new)
    rep = db.query(ReporterReputation).filter_by(reporter_id=reporter_id).first()
    if rep is None:
        rep = ReporterReputation(reporter_id=reporter_id, score=0.5, report_count=1)
        db.add(rep)
    else:
        rep.report_count += 1
        # Slowly increase reputation with more reports (cap at 1.0)
        rep.score = min(1.0, 0.5 + 0.05 * rep.report_count)
    db.commit()

    return {"status": "reported", "domain": domain, "reporter_id": reporter_id}


@router.get("/reports")
def get_reports(domain: str, db: Session = Depends(get_db)):
    """Get community reports for a domain."""
    domain = domain.lower().strip()
    if not domain:
        raise HTTPException(status_code=400, detail="domain parameter required")

    reports = (
        db.query(Report)
        .filter(Report.domain == domain)
        .order_by(Report.created_at.desc())
        .limit(100)
        .all()
    )

    # Also check blocklist
    blocklist_hits = (
        db.query(Blocklist)
        .filter(Blocklist.domain == domain)
        .all()
    )

    return {
        "domain": domain,
        "report_count": len(reports),
        "reports": [
            {
                "url": r.url,
                "category": r.category,
                "comment": r.comment,
                "created_at": r.created_at.isoformat(),
            }
            for r in reports
        ],
        "blocklist_hits": [
            {"source": b.source, "url": b.url, "added_at": b.added_at.isoformat()}
            for b in blocklist_hits
        ],
    }
