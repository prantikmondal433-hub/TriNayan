"""Tests for the threat module: url_features + brand impersonation.

20+ example URLs covering safe sites, phishing patterns, Indian brands,
edge cases, and brand impersonation variants.
"""
from __future__ import annotations

import pytest

from app.modules.threat.url_features import extract_features, heuristic_score
from app.modules.threat.brand import (
    check_brand_impersonation,
    generate_lookalikes,
    _edit_distance,
    _canonicalize,
)
from app.modules.threat import analyze
from app.schemas import ScanContext


# ══════════════════════════════════════════════════════════════════════
#  URL feature extraction tests
# ══════════════════════════════════════════════════════════════════════

class TestExtractFeatures:
    """Covers the 20-feature vector."""

    # 1. Simple safe URL
    def test_google_safe(self):
        f = extract_features("https://www.google.com/search?q=test")
        assert f["uses_https"] == 1
        assert f["ip_as_host"] == 0
        assert f["is_shortener"] == 0
        assert f["tld_risk"] == 0

    # 2. IP-as-host
    def test_ip_host(self):
        f = extract_features("http://192.168.1.1/login")
        assert f["ip_as_host"] == 1
        assert f["uses_https"] == 0

    # 3. Punycode domain
    def test_punycode(self):
        f = extract_features("https://xn--pple-43d.com/")
        assert f["punycode"] == 1

    # 4. Risky TLD
    def test_risky_tld(self):
        f = extract_features("http://free-prize.tk/win")
        assert f["tld_risk"] == 1
        assert f["keyword_count"] >= 1  # "free" and/or "win"

    # 5. URL shortener
    def test_shortener(self):
        f = extract_features("https://bit.ly/3abc123")
        assert f["is_shortener"] == 1

    # 6. @ sign in URL
    def test_at_sign(self):
        f = extract_features("http://legitimate.com@evil.com/path")
        assert f["at_sign"] == 1

    # 7. Deep subdomains
    def test_deep_subdomains(self):
        f = extract_features("http://a.b.c.d.evil.com/login")
        assert f["subdomain_depth"] >= 4

    # 8. Long URL with keywords
    def test_long_url_keywords(self):
        url = "http://login-verify-secure-account-update.example.com/confirm"
        f = extract_features(url)
        assert f["keyword_count"] >= 4
        assert f["url_length"] > 50

    # 9. Non-standard port
    def test_non_standard_port(self):
        f = extract_features("http://example.com:8080/admin")
        assert f["non_standard_port"] == 1

    # 10. Standard port (443)
    def test_standard_port(self):
        f = extract_features("https://example.com:443/")
        assert f["non_standard_port"] == 0

    # 11. Double-slash in path
    def test_double_slash(self):
        f = extract_features("https://evil.com//http://good.com/login")
        assert f["has_double_slash_redirect"] == 1

    # 12. Safe Indian bank
    def test_sbi_safe(self):
        f = extract_features("https://www.onlinesbi.sbi/")
        assert f["tld_risk"] == 0
        assert f["is_shortener"] == 0
        assert f["ip_as_host"] == 0

    # 13. Hyphen-heavy domain
    def test_many_hyphens(self):
        f = extract_features("http://free-login-secure-verify.xyz/update")
        assert f["hyphen_count"] >= 3

    # 14. No host (edge case)
    def test_no_host(self):
        f = extract_features("file:///etc/passwd")
        assert f["ip_as_host"] == 0

    # 15. High entropy domain
    def test_high_entropy(self):
        f = extract_features("http://a1b2c3d4e5f6g7h8.com/login")
        assert f["entropy"] > 3.0

    # 16. Path depth
    def test_path_depth(self):
        f = extract_features("http://example.com/a/b/c/d/login.html")
        assert f["path_depth"] >= 4

    # 17. Query string length
    def test_query_length(self):
        f = extract_features("http://example.com/?token=abc123&redirect=evil")
        assert f["query_length"] > 0

    # 18. Fragment
    def test_fragment(self):
        f = extract_features("http://example.com/page#section-with-data")
        assert f["fragment_length"] > 0

    # 19. Completely clean
    def test_clean_domain(self):
        f = extract_features("https://wikipedia.org")
        assert f["keyword_count"] == 0
        assert f["ip_as_host"] == 0
        assert f["tld_risk"] == 0
        assert f["uses_https"] == 1

    # 20. Malformed URL
    def test_malformed_url(self):
        f = extract_features("not_a_url_at_all")
        assert isinstance(f, dict)
        assert "url_length" in f

    # 21. IRCTC safe
    def test_irctc_safe(self):
        f = extract_features("https://www.irctc.co.in/nget/train-search")
        assert f["uses_https"] == 1
        assert f["ip_as_host"] == 0


class TestHeuristicScore:
    def test_safe_url_low_score(self):
        f = extract_features("https://www.google.com/")
        score, conf = heuristic_score(f)
        assert score < 30

    def test_phishing_url_high_score(self):
        f = extract_features("http://192.168.1.1:8080/login-verify-secure@evil.tk")
        score, conf = heuristic_score(f)
        assert score >= 50

    def test_shortener_moderate(self):
        f = extract_features("https://bit.ly/3xyz")
        score, conf = heuristic_score(f)
        assert score >= 10


# ══════════════════════════════════════════════════════════════════════
#  Brand impersonation tests
# ══════════════════════════════════════════════════════════════════════

class TestBrandImpersonation:
    # Legitimate – should NOT flag
    def test_legit_sbi(self):
        findings = check_brand_impersonation("https://www.onlinesbi.sbi/")
        brand_ids = [f.id for f in findings]
        # onlinesbi.sbi is official → no impersonation finding for SBI
        sbi_findings = [f for f in findings if "SBI" in f.evidence.get("brand", "")
                        or "State Bank" in f.evidence.get("brand", "")]
        assert len(sbi_findings) == 0

    def test_legit_google(self):
        findings = check_brand_impersonation("https://www.google.com/")
        assert len(findings) == 0

    def test_legit_hdfc(self):
        findings = check_brand_impersonation("https://netbanking.hdfcbank.com/")
        hdfc_findings = [f for f in findings if "HDFC" in f.evidence.get("brand", "")]
        assert len(hdfc_findings) == 0

    # Edit-distance impersonation
    def test_sbi_typo(self):
        """'sbl' is edit-distance 1 from 'sbi'."""
        findings = check_brand_impersonation("http://sbl.co.in.phish.tk/login")
        # Should flag brand impersonation (sbl ≈ sbi)
        # Note: 'sbi' is only 3 chars, edit distance 1 from 'sbl'
        ids = [f.id for f in findings]
        assert "THREAT_BRAND_IMPERSONATION" in ids

    def test_paypa1_typo(self):
        """'paypa1' is edit-distance 1 from 'paypal' (l→1)."""
        findings = check_brand_impersonation("http://paypa1-login.xyz/secure")
        ids = [f.id for f in findings]
        assert "THREAT_BRAND_IMPERSONATION" in ids

    def test_amaz0n_typo(self):
        findings = check_brand_impersonation("http://amaz0n-deals.xyz/verify")
        ids = [f.id for f in findings]
        assert "THREAT_BRAND_IMPERSONATION" in ids

    # Keyword-in-host impersonation
    def test_sbi_keyword_in_phish_domain(self):
        """'sbi' keyword appears in a non-official domain."""
        findings = check_brand_impersonation("http://sbi-secure-login.xyz/")
        ids = [f.id for f in findings]
        assert "THREAT_BRAND_IMPERSONATION" in ids

    def test_paytm_keyword_phish(self):
        findings = check_brand_impersonation("http://paytm-refund.tk/claim")
        ids = [f.id for f in findings]
        assert "THREAT_BRAND_IMPERSONATION" in ids

    def test_icici_keyword_phish(self):
        findings = check_brand_impersonation("http://icicibank-update.xyz/")
        ids = [f.id for f in findings]
        assert "THREAT_BRAND_IMPERSONATION" in ids

    # Homoglyph
    def test_homoglyph_google(self):
        """'gооgle' using Cyrillic 'о' instead of Latin 'o'."""
        findings = check_brand_impersonation("http://g\u043e\u043egle.com/login")
        ids = [f.id for f in findings]
        assert "THREAT_BRAND_IMPERSONATION" in ids

    # Clean domains that should NOT be impersonation
    def test_random_domain_no_flag(self):
        findings = check_brand_impersonation("https://randomsite123.com/page")
        assert len(findings) == 0

    def test_unrelated_domain(self):
        findings = check_brand_impersonation("https://myportfolio.dev/about")
        assert len(findings) == 0


class TestEditDistance:
    def test_identical(self):
        assert _edit_distance("abc", "abc") == 0

    def test_one_sub(self):
        assert _edit_distance("abc", "adc") == 1

    def test_one_insert(self):
        assert _edit_distance("abc", "abcd") == 1

    def test_sbi_sbl(self):
        assert _edit_distance("sbi", "sbl") == 1

    def test_paypal_paypa1(self):
        assert _edit_distance("paypal", "paypa1") == 1


class TestCanonicalize:
    def test_cyrillic_o(self):
        assert _canonicalize("g\u043e\u043egle") == "google"

    def test_normal_ascii(self):
        assert _canonicalize("google") == "google"


class TestGenerateLookalikes:
    def test_sbi(self):
        variants = generate_lookalikes("sbi.co.in")
        assert len(variants) > 5
        assert "sbi.co.in" not in variants  # original excluded

    def test_google(self):
        variants = generate_lookalikes("google.com")
        assert any("oogle" in v for v in variants)  # deletion of 'g'
        assert "google.com" not in variants

    def test_short_domain(self):
        # Single-label domain – no lookalikes
        assert generate_lookalikes("localhost") == []


# ══════════════════════════════════════════════════════════════════════
#  Integration: full analyze()
# ══════════════════════════════════════════════════════════════════════

class TestAnalyzeIntegration:
    @pytest.mark.asyncio
    async def test_safe_url(self):
        ctx = ScanContext()
        result = await analyze("https://www.google.com/", ctx)
        assert result.module == "threat"
        assert result.error is None
        assert result.score < 30

    @pytest.mark.asyncio
    async def test_phishing_url(self):
        ctx = ScanContext()
        result = await analyze("http://sbi-secure-login.tk/verify", ctx)
        assert result.module == "threat"
        assert result.score >= 40
        ids = [f.id for f in result.findings]
        assert "THREAT_BRAND_IMPERSONATION" in ids

    @pytest.mark.asyncio
    async def test_ip_url(self):
        ctx = ScanContext()
        result = await analyze("http://192.168.1.1/login", ctx)
        assert result.module == "threat"
        ids = [f.id for f in result.findings]
        assert "THREAT_IP_AS_HOST" in ids

    @pytest.mark.asyncio
    async def test_never_crashes(self):
        """Even a garbage input must return a valid ModuleResult."""
        ctx = ScanContext()
        result = await analyze("", ctx)
        assert result.module == "threat"
        assert isinstance(result.score, int)

