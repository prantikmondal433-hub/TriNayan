"""Community module: SQLAlchemy models for reports, reputation, and blocklists."""
import datetime
import hashlib
import os

from sqlalchemy import (
    Column,
    DateTime,
    Float,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    create_engine,
)
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///trustlens_community.db")


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc)


# Use aiosqlite for async SQLite if needed later; sync for now.
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {},
    pool_pre_ping=True,
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


class Report(Base):
    """A user-submitted report about a suspicious URL/domain."""
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, autoincrement=True)
    url = Column(String(2048), nullable=False)
    domain = Column(String(255), nullable=False, index=True)
    category = Column(String(50), nullable=False)
    comment = Column(Text, default="")
    reporter_id = Column(String(64), nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    __table_args__ = (
        UniqueConstraint("reporter_id", "domain", name="uq_reporter_domain"),
        Index("ix_reports_domain_created", "domain", "created_at"),
    )


class ReporterReputation(Base):
    """Tracks how trustworthy a reporter is (new reporters count less)."""
    __tablename__ = "reporter_reputation"

    id = Column(Integer, primary_key=True, autoincrement=True)
    reporter_id = Column(String(64), unique=True, nullable=False, index=True)
    score = Column(Float, default=0.5, nullable=False)  # 0.0 to 1.0
    report_count = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)


class Blocklist(Base):
    """Domains/URLs from external blocklist feeds (OpenPhish, URLhaus)."""
    __tablename__ = "blocklist"

    id = Column(Integer, primary_key=True, autoincrement=True)
    domain = Column(String(255), nullable=False, index=True)
    url = Column(String(2048), default="")
    source = Column(String(50), nullable=False)  # e.g. "openphish", "urlhaus"
    added_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    __table_args__ = (
        UniqueConstraint("url", "source", name="uq_blocklist_url_source"),
    )


ALLOWED_CATEGORIES = frozenset({
    "phishing", "malware", "scam", "spam", "impersonation", "other",
})

MAX_COMMENT_LENGTH = 500


def init_db():
    """Create tables if they don't exist."""
    Base.metadata.create_all(bind=engine)


def get_db() -> Session:
    """Yield a database session (for FastAPI Depends)."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def make_reporter_id(ip: str, user_agent: str) -> str:
    """Create an anonymous reporter identity from IP + User-Agent.

    Uses a salted hash so we never store raw IPs.
    """
    salt = os.getenv("REPORTER_SALT", "trustlens-default-salt")
    raw = f"{salt}:{ip}:{user_agent}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]
