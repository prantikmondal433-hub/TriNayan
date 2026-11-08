import pytest

from app.fusion import fuse
from app.schemas import Finding, ModuleResult


def mk(name, score, findings=None, error=None):
    return ModuleResult(module=name, score=score, confidence=1.0,
                        findings=findings or [], error=error)


def all_modules(score):
    return {n: mk(n, score) for n in ("threat", "websec", "cert", "community")}


def test_all_zero_and_all_hundred():
    assert fuse(all_modules(0))[0] == 0
    assert fuse(all_modules(100))[0] == 100


def test_weights():
    res = {"threat": mk("threat", 100), "websec": mk("websec", 0),
           "cert": mk("cert", 0), "community": mk("community", 0)}
    assert fuse(res)[0] == 35


def test_renormalises_when_modules_error():
    res = {"threat": mk("threat", 80),
           "websec": mk("websec", 0, error="boom"),
           "cert": mk("cert", 0, error="boom"),
           "community": mk("community", 0, error="boom")}
    assert fuse(res)[0] == 80


def test_all_errored_is_unknown_not_safe():
    res = {n: mk(n, 0, error="boom") for n in ("threat", "websec", "cert", "community")}
    risk, verdict, reasons, action = fuse(res)
    assert verdict == "Suspicious" and reasons == [] and "could not" in action.lower()


@pytest.mark.parametrize("score,verdict", [
    (0, "Safe"), (29, "Safe"), (30, "Suspicious"), (69, "Suspicious"),
    (70, "Dangerous"), (100, "Dangerous"),
])
def test_verdict_boundaries(score, verdict):
    assert fuse({"threat": mk("threat", score)})[1] == verdict


def test_reasons_sorted_by_severity_and_capped_at_five():
    findings = [Finding(id=f"F{i}", severity=sev, title=f"t{i}")
                for i, sev in enumerate(["low", "critical", "medium", "high", "low", "low", "medium"])]
    _, _, reasons, _ = fuse({"threat": mk("threat", 50, findings)})
    assert len(reasons) == 5
    assert reasons[0].severity == "critical"
    assert reasons[1].severity == "high"
