import pytest

from app.fusion import ACTIONS, fuse
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


# ── Override Rule 1: Community blocklist ──────────────────────────────────────


def test_override_blocklisted():
    finding = Finding(id="COMMUNITY_BLOCKLISTED", severity="critical", title="In threat feed")
    res = {
        "threat": mk("threat", 10),
        "websec": mk("websec", 10),
        "cert": mk("cert", 10),
        "community": mk("community", 60, findings=[finding]),
    }
    risk, verdict, _, action = fuse(res)
    assert risk >= 90
    assert verdict == "Dangerous"
    assert action == ACTIONS["BlocklistOverride"]


def test_override_blocklisted_does_not_fire_if_module_errored():
    finding = Finding(id="COMMUNITY_BLOCKLISTED", severity="critical", title="In threat feed")
    res = {
        "threat": mk("threat", 10),
        "websec": mk("websec", 10),
        "cert": mk("cert", 10),
        "community": mk("community", 60, findings=[finding], error="DB error"),
    }
    risk, verdict, _, _ = fuse(res)
    # Calculated only from non-errored modules (all score 10)
    assert risk == 10
    assert verdict == "Safe"


# ── Override Rule 2: Brand + Password + Young Domain ──────────────────────────


def test_override_credential_phishing():
    f_brand = Finding(id="THREAT_BRAND_IMPERSONATION", severity="high", title="Brand typo")
    f_pass = Finding(id="WEBSEC_PASSWORD_FORM", severity="high", title="Password field")
    f_young = Finding(id="THREAT_YOUNG_DOMAIN", severity="medium", title="Registered 2 days ago")

    res = {
        "threat": mk("threat", 30, findings=[f_brand, f_young]),
        "websec": mk("websec", 20, findings=[f_pass]),
        "cert": mk("cert", 10),
        "community": mk("community", 0),
    }
    risk, verdict, _, action = fuse(res)
    assert risk >= 90
    assert verdict == "Dangerous"
    assert action == ACTIONS["CredentialPhishOverride"]


def test_override_credential_phishing_requires_all_three():
    # Missing young domain
    f_brand = Finding(id="THREAT_BRAND_IMPERSONATION", severity="high", title="Brand typo")
    f_pass = Finding(id="WEBSEC_PASSWORD_FORM", severity="high", title="Password field")

    res = {
        "threat": mk("threat", 20, findings=[f_brand]),
        "websec": mk("websec", 20, findings=[f_pass]),
        "cert": mk("cert", 10),
        "community": mk("community", 0),
    }
    risk, verdict, _, _ = fuse(res)
    assert risk < 90


# ── Override Rule 3: Bad cert + Login form ────────────────────────────────────


@pytest.mark.parametrize("cert_finding_id", ["CERT_EXPIRED", "CERT_SELF_SIGNED"])
def test_override_bad_cert_login(cert_finding_id):
    f_cert = Finding(id=cert_finding_id, severity="high", title="Invalid cert")
    f_login = Finding(id="WEBSEC_LOGIN_FORM", severity="medium", title="Login form detected")

    res = {
        "threat": mk("threat", 10),
        "websec": mk("websec", 15, findings=[f_login]),
        "cert": mk("cert", 30, findings=[f_cert]),
        "community": mk("community", 0),
    }
    risk, verdict, _, action = fuse(res)
    assert risk >= 70
    assert verdict == "Dangerous"
    assert action == ACTIONS["InsecureLoginOverride"]


def test_override_bad_cert_without_login_form_no_override():
    f_cert = Finding(id="CERT_EXPIRED", severity="high", title="Expired cert")
    res = {
        "threat": mk("threat", 10),
        "websec": mk("websec", 10),
        "cert": mk("cert", 30, findings=[f_cert]),
        "community": mk("community", 0),
    }
    risk, verdict, _, _ = fuse(res)
    assert risk < 70
