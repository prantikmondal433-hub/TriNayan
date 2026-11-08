"""Tests for the community module: models, router, and analyze()."""
import datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.community.models import (
    ALLOWED_CATEGORIES,
    Base,
    Blocklist,
    Report,
    ReporterReputation,
    get_db,
    make_reporter_id,
)

# Use in-memory SQLite with StaticPool so all threads & sessions share the exact same DB
TEST_ENGINE = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestSession = sessionmaker(bind=TEST_ENGINE)
Base.metadata.create_all(bind=TEST_ENGINE)


def override_get_db():
    db = TestSession()
    try:
        yield db
    finally:
        db.close()


from app.main import app  # noqa: E402

app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)


@pytest.fixture(autouse=True)
def clean_db():
    """Wipe all data between tests but keep the schema."""
    yield
    with TEST_ENGINE.begin() as conn:
        for table in reversed(Base.metadata.sorted_tables):
            conn.execute(table.delete())


# ── Model tests ──────────────────────────────────────────────────────────────


class TestModels:
    def test_make_reporter_id_deterministic(self):
        id1 = make_reporter_id("1.2.3.4", "Mozilla/5.0")
        id2 = make_reporter_id("1.2.3.4", "Mozilla/5.0")
        assert id1 == id2
        assert len(id1) == 16

    def test_make_reporter_id_differs_for_different_inputs(self):
        id1 = make_reporter_id("1.2.3.4", "Mozilla/5.0")
        id2 = make_reporter_id("5.6.7.8", "Mozilla/5.0")
        assert id1 != id2

    def test_report_unique_constraint(self):
        db = TestSession()
        r1 = Report(url="https://evil.com", domain="evil.com",
                     category="phishing", reporter_id="abc123")
        r2 = Report(url="https://evil.com/page", domain="evil.com",
                     category="scam", reporter_id="abc123")
        db.add(r1)
        db.commit()
        db.add(r2)
        with pytest.raises(Exception):  # IntegrityError
            db.commit()
        db.rollback()
        db.close()


# ── Router tests ─────────────────────────────────────────────────────────────


class TestReportEndpoint:
    def test_create_report_success(self):
        r = client.post("/report", json={
            "url": "https://phish.example.com/login",
            "category": "phishing",
            "comment": "Looks like a fake bank",
        })
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["status"] == "reported"
        assert body["domain"] == "phish.example.com"

    def test_invalid_category_rejected(self):
        r = client.post("/report", json={
            "url": "https://evil.com",
            "category": "hacking",
            "comment": "",
        })
        assert r.status_code == 400
        assert "Invalid category" in r.json()["detail"]

    def test_duplicate_report_rejected(self):
        payload = {"url": "https://dupe.com", "category": "scam", "comment": ""}
        r1 = client.post("/report", json=payload)
        assert r1.status_code == 201, r1.text
        r2 = client.post("/report", json=payload)
        assert r2.status_code == 409

    def test_long_comment_truncated(self):
        r = client.post("/report", json={
            "url": "https://spam.com",
            "category": "spam",
            "comment": "x" * 1000,
        })
        assert r.status_code == 201, r.text

    def test_all_categories_accepted(self):
        for i, cat in enumerate(sorted(ALLOWED_CATEGORIES)):
            r = client.post("/report", json={
                "url": f"https://test{i}.example.com",
                "category": cat,
                "comment": "",
            })
            assert r.status_code == 201, f"Category {cat} rejected: {r.text}"


class TestReportsEndpoint:
    def test_get_reports_empty(self):
        r = client.get("/reports", params={"domain": "nonexistent.com"})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["report_count"] == 0
        assert body["reports"] == []

    def test_get_reports_after_submit(self):
        client.post("/report", json={
            "url": "https://bad.example.com",
            "category": "phishing",
            "comment": "test",
        })
        r = client.get("/reports", params={"domain": "bad.example.com"})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["report_count"] == 1
        assert body["reports"][0]["category"] == "phishing"

    def test_get_reports_shows_blocklist(self):
        db = TestSession()
        db.add(Blocklist(domain="blocked.com", url="https://blocked.com/x",
                         source="openphish"))
        db.commit()
        db.close()

        r = client.get("/reports", params={"domain": "blocked.com"})
        assert r.status_code == 200, r.text
        body = r.json()
        assert len(body["blocklist_hits"]) == 1
        assert body["blocklist_hits"][0]["source"] == "openphish"

    def test_missing_domain_param(self):
        r = client.get("/reports", params={"domain": ""})
        assert r.status_code == 400


# ── Analyze tests ────────────────────────────────────────────────────────────


class TestAnalyze:
    @pytest.fixture(autouse=True)
    def _patch_session(self, monkeypatch):
        """Point the analyze function at our test DB."""
        import app.community.models as models
        monkeypatch.setattr(models, "SessionLocal", TestSession)

    async def test_no_data_returns_zero(self):
        from app.community import analyze
        from app.schemas import ScanContext
        result = await analyze("https://clean.example.com", ScanContext())
        assert result.module == "community"
        assert result.score == 0
        assert result.error is None

    async def test_blocklist_hit_high_score(self):
        db = TestSession()
        db.add(Blocklist(domain="evil.com", url="https://evil.com",
                         source="urlhaus"))
        db.commit()
        db.close()

        from app.community import analyze
        from app.schemas import ScanContext
        result = await analyze("https://evil.com/login", ScanContext())
        assert result.score >= 60
        assert any(f.id == "COMMUNITY_BLOCKLISTED" for f in result.findings)

    async def test_community_reports_add_score(self):
        db = TestSession()
        for i in range(5):
            db.add(Report(
                url="https://sus.com", domain="sus.com",
                category="phishing", reporter_id=f"reporter_{i}",
            ))
            db.add(ReporterReputation(
                reporter_id=f"reporter_{i}", score=0.8, report_count=3,
            ))
        db.commit()
        db.close()

        from app.community import analyze
        from app.schemas import ScanContext
        result = await analyze("https://sus.com/page", ScanContext())
        assert result.score > 0
        assert any(f.id == "COMMUNITY_REPORTED" for f in result.findings)

    async def test_never_crashes(self, monkeypatch):
        """Even if the DB is completely broken, analyze returns error, not exception."""
        import app.community.models as models
        broken_engine = create_engine("sqlite:///nonexistent_dir/impossible.db")
        monkeypatch.setattr(models, "SessionLocal", sessionmaker(bind=broken_engine))

        from app.community import analyze
        from app.schemas import ScanContext
        result = await analyze("https://example.com", ScanContext())
        assert result.module == "community"
        assert result.error is not None


# ── Feed ingestion and export tests ──────────────────────────────────────────


class TestFeedsAndExport:
    async def test_ingest_openphish_mock(self, monkeypatch):
        from app.community import feeds
        async def mock_fetch(url):
            return [
                "https://phish1.example.com/login",
                "http://phish2.example.com/verify",
                "# comment line",
            ]
        monkeypatch.setattr(feeds, "fetch_feed_lines", mock_fetch)

        db = TestSession()
        added = await feeds.ingest_openphish(db, "https://openphish.example/feed.txt")
        assert added == 2

        hits = db.query(Blocklist).filter_by(source="openphish").all()
        assert len(hits) == 2
        assert {h.domain for h in hits} == {"phish1.example.com", "phish2.example.com"}
        db.close()

    async def test_ingest_urlhaus_mock(self, monkeypatch):
        from app.community import feeds
        async def mock_fetch(url):
            return [
                '# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter',
                '1,2026-11-08,"http://malware.example.com/payload.exe",online,2026-11-08,malware_download,elf,https://urlhaus.abuse.ch/v/1/,reporter',
            ]
        monkeypatch.setattr(feeds, "fetch_feed_lines", mock_fetch)

        db = TestSession()
        added = await feeds.ingest_urlhaus(db, "https://urlhaus.example/feed.csv")
        assert added == 1

        hits = db.query(Blocklist).filter_by(source="urlhaus").all()
        assert len(hits) == 1
        assert hits[0].domain == "malware.example.com"
        db.close()

    def test_export_reports_to_csv(self):
        from app.community.export import export_reports_to_csv
        db = TestSession()
        db.add(Report(
            url="https://badbank.example.com",
            domain="badbank.example.com",
            category="phishing",
            reporter_id="user1",
        ))
        db.add(Blocklist(
            domain="malicious.example.com",
            url="https://malicious.example.com/bin",
            source="urlhaus",
        ))
        db.commit()

        csv_text = export_reports_to_csv(db)
        lines = csv_text.strip().splitlines()
        assert lines[0] == "url,domain,label,category,source,created_at"
        assert len(lines) == 3
        assert "badbank.example.com" in csv_text
        assert "malicious.example.com" in csv_text
        db.close()
