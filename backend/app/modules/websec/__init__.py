"""websec module STUB (written by P1). P3 replaces the body of analyze().
Keep the signature, and keep `analyze` importable from this package."""
from app.schemas import Finding, ModuleResult, ScanContext


async def analyze(url: str, ctx: ScanContext) -> ModuleResult:
    return ModuleResult(
        module="websec",
        score=20,
        confidence=0.3,
        findings=[
            Finding(
                id="STUB_WEBSEC",
                severity="low",
                title="Placeholder websec result (stub)",
            )
        ],
    )
