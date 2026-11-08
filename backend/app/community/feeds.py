"""Feed ingestion for external blocklists (OpenPhish, URLhaus).

Respects TrustLens safety rules:
- Passive GET only
- SSRF checks with assert_public_url
- Timeout <= 8s, response cap 2MB, max redirects 5
- Catch exceptions without crashing
"""
import logging
import os
from urllib.parse import urlparse

import httpx
from sqlalchemy.orm import Session

from app.community.models import Blocklist
from app.safety import assert_public_url

logger = logging.getLogger(__name__)

OPENPHISH_DEFAULT_URL = os.getenv("OPENPHISH_FEED_URL", "")
URLHAUS_DEFAULT_URL = os.getenv("URLHAUS_FEED_URL", "")
MAX_FEED_BYTES = 2_000_000
FEED_TIMEOUT_S = 8.0


def _extract_domain(url: str) -> str:
    if "://" not in url:
        url = "https://" + url
    return (urlparse(url).hostname or "").lower()


async def fetch_feed_lines(feed_url: str) -> list[str]:
    """Safely fetch a public feed text URL and return non-empty lines."""
    if not feed_url:
        return []

    # SSRF guard
    assert_public_url(feed_url)

    async with httpx.AsyncClient(timeout=FEED_TIMEOUT_S, max_redirects=5, follow_redirects=True) as client:
        resp = await client.get(feed_url)
        resp.raise_for_status()

        content = resp.content
        if len(content) > MAX_FEED_BYTES:
            content = content[:MAX_FEED_BYTES]

        text = content.decode("utf-8", errors="replace")
        return [line.strip() for line in text.splitlines() if line.strip()]


async def ingest_openphish(db: Session, feed_url: str | None = None) -> int:
    """Fetch OpenPhish plain-text feed and add entries to Blocklist."""
    target_url = feed_url or OPENPHISH_DEFAULT_URL
    if not target_url:
        logger.info("OpenPhish feed URL not configured, skipping")
        return 0

    lines = await fetch_feed_lines(target_url)
    added = 0
    for url in lines:
        if url.startswith("#"):
            continue
        domain = _extract_domain(url)
        if not domain:
            continue

        existing = db.query(Blocklist).filter_by(url=url, source="openphish").first()
        if not existing:
            db.add(Blocklist(domain=domain, url=url[:2048], source="openphish"))
            added += 1

    db.commit()
    return added


async def ingest_urlhaus(db: Session, feed_url: str | None = None) -> int:
    """Fetch URLhaus text/CSV feed and add entries to Blocklist."""
    target_url = feed_url or URLHAUS_DEFAULT_URL
    if not target_url:
        logger.info("URLhaus feed URL not configured, skipping")
        return 0

    lines = await fetch_feed_lines(target_url)
    added = 0
    for line in lines:
        if line.startswith("#"):
            continue
        # CSV or plain URL
        parts = line.split(",")
        url = parts[2].strip().strip('"') if len(parts) >= 3 else line
        if not url.startswith("http"):
            continue

        domain = _extract_domain(url)
        if not domain:
            continue

        existing = db.query(Blocklist).filter_by(url=url, source="urlhaus").first()
        if not existing:
            db.add(Blocklist(domain=domain, url=url[:2048], source="urlhaus"))
            added += 1

    db.commit()
    return added


async def ingest_all_feeds(db: Session) -> dict[str, int]:
    """Ingest all configured feeds, safely catching errors."""
    results = {"openphish": 0, "urlhaus": 0}
    try:
        results["openphish"] = await ingest_openphish(db)
    except Exception as exc:
        logger.warning("OpenPhish ingestion failed: %s", exc)

    try:
        results["urlhaus"] = await ingest_urlhaus(db)
    except Exception as exc:
        logger.warning("URLhaus ingestion failed: %s", exc)

    return results
