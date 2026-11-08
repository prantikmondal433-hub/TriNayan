"""Risk fusion v1: weighted sum, re-normalised over modules that did not error.
Override rules come in v2."""
from app.schemas import ModuleResult, Reason

WEIGHTS = {"threat": 0.35, "websec": 0.20, "cert": 0.25, "community": 0.20}
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}

ACTIONS = {
    "Safe": "No major risks found. Still avoid entering passwords unless you trust the site.",
    "Suspicious": "Be careful. Do not enter passwords or payment details until you have "
                  "verified the site through another route.",
    "Dangerous": "Do not enter any information on this site. Close it and report it.",
    "Unknown": "We could not analyse this site. Treat it with caution.",
}


def verdict_for(risk: int) -> str:
    if risk >= 70:
        return "Dangerous"
    if risk >= 30:
        return "Suspicious"
    return "Safe"


def top_reasons(results: dict[str, ModuleResult], limit: int = 5) -> list[Reason]:
    items = []
    for name, res in results.items():
        for f in res.findings:
            items.append((SEVERITY_RANK[f.severity], res.score, Reason(
                module=name, id=f.id, severity=f.severity, title=f.title)))
    items.sort(key=lambda t: (t[0], t[1]), reverse=True)
    return [r for _, _, r in items[:limit]]


def fuse(results: dict[str, ModuleResult]) -> tuple[int, str, list[Reason], str]:
    """Return (risk, verdict, reasons, recommended_action)."""
    usable = {n: r for n, r in results.items() if r.error is None and n in WEIGHTS}
    if not usable:
        return 50, "Suspicious", [], ACTIONS["Unknown"]

    total_weight = sum(WEIGHTS[n] for n in usable)
    raw = sum(WEIGHTS[n] * r.score for n, r in usable.items()) / total_weight
    risk = max(0, min(100, int(round(raw))))
    verdict = verdict_for(risk)
    return risk, verdict, top_reasons(usable), ACTIONS[verdict]
