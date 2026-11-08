"""Shared contract for TrustLens. Do NOT change without asking P1."""
from typing import Any, Literal

from pydantic import BaseModel, Field

Severity = Literal["low", "medium", "high", "critical"]
ModuleName = Literal["threat", "websec", "cert", "community"]
Verdict = Literal["Safe", "Suspicious", "Dangerous"]


class Finding(BaseModel):
    id: str  # stable id, e.g. CERT_WEAK_RSA
    severity: Severity
    title: str  # plain language, non-technical
    detail: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict)


class ModuleResult(BaseModel):
    module: ModuleName
    score: int = Field(0, ge=0, le=100)  # risk, higher = worse
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    findings: list[Finding] = Field(default_factory=list)
    error: str | None = None


class ScanContext(BaseModel):
    """Shared per-scan info passed to every module."""
    scan_id: str = ""
    timeout_s: float = 8.0
    max_bytes: int = 2_000_000
    max_redirects: int = 5


class ScanRequest(BaseModel):
    url: str


class Reason(BaseModel):
    module: ModuleName
    id: str
    severity: Severity
    title: str


class ScanResponse(BaseModel):
    url: str
    verdict: Verdict
    risk: int = Field(ge=0, le=100)
    reasons: list[Reason]
    recommended_action: str
    modules: dict[str, ModuleResult]


class ReportRequest(BaseModel):
    url: str
    category: str
    comment: str = ""