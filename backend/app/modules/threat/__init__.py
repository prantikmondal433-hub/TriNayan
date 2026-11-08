"""threat module STUB (written by P1). P2 replaces the body of analyze().
Keep the signature, and keep `analyze` importable from this package."""
from app.schemas import Finding, ModuleResult, ScanContext


async def analyze(url: str, ctx: ScanContext) -> ModuleResult:
    return ModuleResult(
        module="threat",
        score=40,
        confidence=0.3,
        findings=[
            Finding(
                id="STUB_THREAT",
                severity="low",
                title="Placeholder threat result (stub)",
            )
        ],
    )
