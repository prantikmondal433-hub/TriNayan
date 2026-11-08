"""Export confirmed reports to CSV for P2 ML model training."""
import csv
import io
import os
from sqlalchemy.orm import Session

from app.community.models import Blocklist, Report


def export_reports_to_csv(db: Session, output_path: str | None = None) -> str:
    """Export reports and blocklisted URLs to CSV format: url, label, category, source.

    Labels:
      1: malicious/phishing (phishing, malware, scam, impersonation, or blocklisted)
      0: other/unverified
    """
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["url", "domain", "label", "category", "source", "created_at"])

    # User reports
    reports = db.query(Report).all()
    for r in reports:
        label = 1 if r.category in {"phishing", "malware", "scam", "impersonation"} else 0
        writer.writerow([r.url, r.domain, label, r.category, "community", r.created_at.isoformat()])

    # Blocklist entries
    blocklist = db.query(Blocklist).all()
    for b in blocklist:
        writer.writerow([b.url or f"https://{b.domain}/", b.domain, 1, "blocklist", b.source, b.added_at.isoformat()])

    content = output.getvalue()
    if output_path:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8", newline="") as f:
            f.write(content)

    return content
