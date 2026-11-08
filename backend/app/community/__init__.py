"""community module STUB (written by P1). P1 replaces the body of analyze().
Keep the signature, and keep `analyze` importable from this package."""
from app.schemas import Finding, ModuleResult, ScanContext


async def analyze(url: str, ctx: ScanContext) -> ModuleResult:
    return ModuleResult(
        module="community",
        score=0,
        confidence=0.3,
        findings=[
            Finding(
                id="STUB_COMMUNITY",
                severity="low",
                title="Placeholder community result (stub)",
            )
        ],
    )
