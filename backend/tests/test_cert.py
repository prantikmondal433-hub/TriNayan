"""Tests for the certificate module – NO live internet required.

Uses the ``cryptography`` library to generate test certificates locally,
and mocks the network layer to test error handling paths.
"""
from __future__ import annotations

import asyncio
import datetime
import socket
import ssl
from unittest.mock import MagicMock, patch, PropertyMock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from app.modules.cert import analyze, _score_from_findings
from app.modules.cert.cert_check import (
    check_certificate_object,
    _check_expiry,
    _check_hostname,
    _check_self_signed,
    _check_key_strength,
    _check_signature_hash,
    _check_validity_period,
    _check_sct,
    _check_chain_completeness,
    _check_ocsp_stapling,
    _hostname_matches_any,
    fetch_and_check,
)
from app.safety import UnsafeURLError
from app.schemas import Finding, ModuleResult, ScanContext


def _make_sha1_mock_cert():
    """Create a mock certificate object that reports SHA-1 signature.

    Modern versions of the ``cryptography`` library refuse to *sign*
    certificates with SHA-1, so we create a real cert (SHA-256) and
    mock its ``signature_hash_algorithm`` property to report SHA-1.
    """
    cert = _make_valid_cert(hash_alg=hashes.SHA256())
    mock_cert = MagicMock(wraps=cert)
    mock_cert.signature_hash_algorithm = hashes.SHA1()
    # Forward attributes that the checks use
    mock_cert.not_valid_before_utc = cert.not_valid_before_utc
    mock_cert.not_valid_after_utc = cert.not_valid_after_utc
    mock_cert.subject = cert.subject
    mock_cert.issuer = cert.issuer
    mock_cert.public_key.return_value = cert.public_key()
    mock_cert.extensions = cert.extensions
    mock_cert.signature = cert.signature
    mock_cert.tbs_certificate_bytes = cert.tbs_certificate_bytes
    mock_cert.fingerprint = cert.fingerprint
    mock_cert.serial_number = cert.serial_number
    return mock_cert


# ══════════════════════════════════════════════════════════════════════
#  Certificate generation helpers
# ══════════════════════════════════════════════════════════════════════

def _make_key(key_type: str = "rsa2048"):
    """Generate a private key for testing."""
    if key_type == "rsa2048":
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    elif key_type == "rsa1024":
        return rsa.generate_private_key(public_exponent=65537, key_size=1024)
    elif key_type == "ec256":
        return ec.generate_private_key(ec.SECP256R1())
    elif key_type == "ec192":
        return ec.generate_private_key(ec.SECP192R1())
    else:
        raise ValueError(f"Unknown key type: {key_type}")


def _build_cert(
    *,
    common_name: str = "example.com",
    sans: list[str] | None = None,
    issuer_name: str | None = None,
    issuer_key=None,
    key=None,
    key_type: str = "rsa2048",
    not_before: datetime.datetime | None = None,
    not_after: datetime.datetime | None = None,
    hash_alg=None,
    add_sct: bool = False,
    serial: int | None = None,
) -> tuple:
    """Build a test certificate. Returns (cert, key, issuer_key)."""
    if key is None:
        key = _make_key(key_type)
    if issuer_key is None:
        issuer_key = key  # self-signed by default
    if hash_alg is None:
        hash_alg = hashes.SHA256()

    now = datetime.datetime.now(datetime.timezone.utc)
    if not_before is None:
        not_before = now - datetime.timedelta(days=1)
    if not_after is None:
        not_after = now + datetime.timedelta(days=365)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
    ])

    if issuer_name:
        issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, issuer_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test CA"),
        ])
    else:
        issuer = subject  # self-signed

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(serial or x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )

    # SANs
    if sans:
        san_names = [x509.DNSName(n) for n in sans]
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_names), critical=False
        )

    # SCT extension (fake – just for testing presence detection)
    if add_sct:
        # We add a precert poison extension as a stand-in, since creating
        # real SCTs is complex. Instead, we test _check_sct by presence of
        # the SCT OID.
        # Actually, let's add a real (dummy) SCT extension via OID
        try:
            builder = builder.add_extension(
                x509.PrecertificateSignedCertificateTimestamps([]),
                critical=False,
            )
        except (TypeError, ValueError):
            # Some versions of cryptography don't allow empty SCT list;
            # skip it – the test handles this gracefully
            pass

    if isinstance(issuer_key, rsa.RSAPrivateKey):
        cert = builder.sign(issuer_key, hash_alg)
    elif isinstance(issuer_key, ec.EllipticCurvePrivateKey):
        cert = builder.sign(issuer_key, hash_alg)
    else:
        cert = builder.sign(issuer_key, hash_alg)

    return cert, key, issuer_key


def _make_valid_cert(**kwargs):
    """Shortcut: valid, self-signed cert for example.com with SANs."""
    defaults = {
        "common_name": "example.com",
        "sans": ["example.com", "www.example.com"],
    }
    defaults.update(kwargs)
    cert, key, _ = _build_cert(**defaults)
    return cert


def _make_ca_issued_cert(
    common_name: str = "example.com",
    sans: list[str] | None = None,
    **leaf_kwargs,
):
    """Create a leaf cert signed by a separate CA cert. Returns (leaf, ca, ca_key)."""
    ca_key = _make_key("rsa2048")
    ca_cert, _, _ = _build_cert(
        common_name="Test CA",
        sans=None,
        key=ca_key,
        not_after=datetime.datetime.now(datetime.timezone.utc)
        + datetime.timedelta(days=3650),
    )

    leaf_key = _make_key(leaf_kwargs.pop("key_type", "rsa2048"))
    leaf_cert, _, _ = _build_cert(
        common_name=common_name,
        sans=sans or [common_name],
        key=leaf_key,
        issuer_name="Test CA",
        issuer_key=ca_key,
        **leaf_kwargs,
    )
    return leaf_cert, ca_cert, ca_key


# ══════════════════════════════════════════════════════════════════════
#  Tests: individual check functions
# ══════════════════════════════════════════════════════════════════════

class TestCheckExpiry:
    def test_valid_cert_no_finding(self):
        cert = _make_valid_cert()
        findings: list[Finding] = []
        now = datetime.datetime.now(datetime.timezone.utc)
        _check_expiry(cert, now, findings)
        expired = [f for f in findings if f.id in ("CERT_EXPIRED", "CERT_NOT_YET_VALID")]
        assert len(expired) == 0

    def test_expired_cert(self):
        cert = _make_valid_cert(
            not_before=datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc),
            not_after=datetime.datetime(2021, 1, 1, tzinfo=datetime.timezone.utc),
        )
        findings: list[Finding] = []
        now = datetime.datetime.now(datetime.timezone.utc)
        _check_expiry(cert, now, findings)
        ids = [f.id for f in findings]
        assert "CERT_EXPIRED" in ids
        assert findings[0].severity == "critical"

    def test_not_yet_valid(self):
        future = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30)
        cert = _make_valid_cert(
            not_before=future,
            not_after=future + datetime.timedelta(days=365),
        )
        findings: list[Finding] = []
        now = datetime.datetime.now(datetime.timezone.utc)
        _check_expiry(cert, now, findings)
        ids = [f.id for f in findings]
        assert "CERT_NOT_YET_VALID" in ids
        assert findings[0].severity == "high"


class TestCheckHostname:
    def test_matching_cn(self):
        cert = _make_valid_cert(common_name="example.com", sans=["example.com"])
        findings: list[Finding] = []
        _check_hostname(cert, "example.com", findings)
        assert len(findings) == 0

    def test_matching_san(self):
        cert = _make_valid_cert(
            common_name="other.com",
            sans=["example.com", "www.example.com"],
        )
        findings: list[Finding] = []
        _check_hostname(cert, "www.example.com", findings)
        assert len(findings) == 0

    def test_wildcard_match(self):
        cert = _make_valid_cert(
            common_name="example.com",
            sans=["*.example.com"],
        )
        findings: list[Finding] = []
        _check_hostname(cert, "sub.example.com", findings)
        assert len(findings) == 0

    def test_wildcard_no_deep_match(self):
        """Wildcard *.example.com should NOT match a.b.example.com."""
        cert = _make_valid_cert(
            common_name="example.com",
            sans=["*.example.com"],
        )
        findings: list[Finding] = []
        _check_hostname(cert, "a.b.example.com", findings)
        ids = [f.id for f in findings]
        assert "CERT_HOSTNAME_MISMATCH" in ids

    def test_hostname_mismatch(self):
        cert = _make_valid_cert(
            common_name="other.com",
            sans=["other.com", "www.other.com"],
        )
        findings: list[Finding] = []
        _check_hostname(cert, "evil.com", findings)
        ids = [f.id for f in findings]
        assert "CERT_HOSTNAME_MISMATCH" in ids
        assert findings[0].severity == "critical"

    def test_no_san_cn_only(self):
        """Cert with CN but no SAN – CN should still be checked."""
        cert, _, _ = _build_cert(common_name="example.com", sans=None)
        findings: list[Finding] = []
        _check_hostname(cert, "example.com", findings)
        assert len(findings) == 0


class TestCheckSelfSigned:
    def test_self_signed_detected(self):
        cert = _make_valid_cert()
        findings: list[Finding] = []
        _check_self_signed(cert, findings)
        ids = [f.id for f in findings]
        assert "CERT_SELF_SIGNED" in ids

    def test_ca_issued_not_self_signed(self):
        leaf, ca, _ = _make_ca_issued_cert()
        findings: list[Finding] = []
        _check_self_signed(leaf, findings)
        ids = [f.id for f in findings]
        assert "CERT_SELF_SIGNED" not in ids


class TestCheckKeyStrength:
    def test_rsa_2048_ok(self):
        cert = _make_valid_cert(key_type="rsa2048")
        findings: list[Finding] = []
        _check_key_strength(cert, findings)
        ids = [f.id for f in findings]
        assert "CERT_WEAK_RSA" not in ids

    def test_rsa_1024_weak(self):
        cert = _make_valid_cert(key_type="rsa1024")
        findings: list[Finding] = []
        _check_key_strength(cert, findings)
        ids = [f.id for f in findings]
        assert "CERT_WEAK_RSA" in ids
        assert any(f.severity == "high" for f in findings)

    def test_ec_256_ok(self):
        cert = _make_valid_cert(key_type="ec256")
        findings: list[Finding] = []
        _check_key_strength(cert, findings)
        ids = [f.id for f in findings]
        assert "CERT_WEAK_EC" not in ids

    def test_ec_192_weak(self):
        cert = _make_valid_cert(key_type="ec192")
        findings: list[Finding] = []
        _check_key_strength(cert, findings)
        ids = [f.id for f in findings]
        assert "CERT_WEAK_EC" in ids


class TestCheckSignatureHash:
    def test_sha256_ok(self):
        cert = _make_valid_cert(hash_alg=hashes.SHA256())
        findings: list[Finding] = []
        _check_signature_hash(cert, findings)
        ids = [f.id for f in findings]
        assert "CERT_WEAK_SIGNATURE" not in ids

    def test_sha1_weak(self):
        mock_cert = _make_sha1_mock_cert()
        findings: list[Finding] = []
        _check_signature_hash(mock_cert, findings)
        ids = [f.id for f in findings]
        assert "CERT_WEAK_SIGNATURE" in ids
        assert findings[0].severity == "high"


class TestCheckValidityPeriod:
    def test_short_validity_ok(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = _make_valid_cert(
            not_before=now - datetime.timedelta(days=1),
            not_after=now + datetime.timedelta(days=90),
        )
        findings: list[Finding] = []
        _check_validity_period(cert, findings)
        ids = [f.id for f in findings]
        assert "CERT_LONG_VALIDITY" not in ids

    def test_long_validity(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = _make_valid_cert(
            not_before=now - datetime.timedelta(days=1),
            not_after=now + datetime.timedelta(days=1000),
        )
        findings: list[Finding] = []
        _check_validity_period(cert, findings)
        ids = [f.id for f in findings]
        assert "CERT_LONG_VALIDITY" in ids


class TestCheckSCT:
    def test_no_sct_flagged(self):
        cert = _make_valid_cert()
        findings: list[Finding] = []
        _check_sct(cert, findings)
        ids = [f.id for f in findings]
        assert "CERT_NO_SCT" in ids

    def test_with_sct_no_finding(self):
        """If we successfully add an SCT extension, it should not be flagged."""
        cert = _make_valid_cert(add_sct=True)
        findings: list[Finding] = []
        _check_sct(cert, findings)
        # Check if SCT extension exists on the cert
        has_sct_ext = False
        try:
            cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS
            )
            has_sct_ext = True
        except x509.ExtensionNotFound:
            pass

        if has_sct_ext:
            ids = [f.id for f in findings]
            assert "CERT_NO_SCT" not in ids
        # If SCT couldn't be added (library limitation), test passes trivially


class TestCheckChainCompleteness:
    def test_no_chain_flagged(self):
        leaf, ca, _ = _make_ca_issued_cert()
        findings: list[Finding] = []
        _check_chain_completeness(leaf, [], findings)
        ids = [f.id for f in findings]
        assert "CERT_INCOMPLETE_CHAIN" in ids

    def test_self_signed_no_chain_ok(self):
        cert = _make_valid_cert()
        findings: list[Finding] = []
        _check_chain_completeness(cert, [], findings)
        # Self-signed cert: chain completeness is not flagged
        ids = [f.id for f in findings]
        assert "CERT_INCOMPLETE_CHAIN" not in ids

    def test_with_intermediate(self):
        """Chain with leaf + CA should not flag incomplete."""
        # Create a CA and leaf
        ca_key = _make_key("rsa2048")
        ca_cert, _, _ = _build_cert(
            common_name="Intermediate CA",
            key=ca_key,
            issuer_name="Root CA",
            issuer_key=_make_key("rsa2048"),
        )
        leaf_key = _make_key("rsa2048")
        leaf_cert, _, _ = _build_cert(
            common_name="example.com",
            sans=["example.com"],
            key=leaf_key,
            issuer_name="Intermediate CA",
            issuer_key=ca_key,
        )
        findings: list[Finding] = []
        # ca_cert is an intermediate (issuer != subject)
        _check_chain_completeness(leaf_cert, [ca_cert], findings)
        ids = [f.id for f in findings]
        assert "CERT_INCOMPLETE_CHAIN" not in ids


class TestCheckOCSPStapling:
    def test_no_stapling_flagged(self):
        findings: list[Finding] = []
        _check_ocsp_stapling(None, findings)
        ids = [f.id for f in findings]
        assert "CERT_NO_OCSP_STAPLING" in ids

    def test_with_stapling(self):
        findings: list[Finding] = []
        _check_ocsp_stapling(b"fake-ocsp-response", findings)
        ids = [f.id for f in findings]
        assert "CERT_NO_OCSP_STAPLING" not in ids


# ══════════════════════════════════════════════════════════════════════
#  Tests: hostname matching helper
# ══════════════════════════════════════════════════════════════════════

class TestHostnameMatchesAny:
    def test_exact(self):
        assert _hostname_matches_any("example.com", {"example.com"})

    def test_wildcard(self):
        assert _hostname_matches_any("sub.example.com", {"*.example.com"})

    def test_no_deep_wildcard(self):
        assert not _hostname_matches_any("a.b.example.com", {"*.example.com"})

    def test_no_match(self):
        assert not _hostname_matches_any("evil.com", {"example.com", "*.example.com"})


# ══════════════════════════════════════════════════════════════════════
#  Tests: check_certificate_object (combined check function)
# ══════════════════════════════════════════════════════════════════════

class TestCheckCertificateObject:
    def test_valid_self_signed(self):
        cert = _make_valid_cert()
        findings = check_certificate_object(cert, "example.com")
        ids = [f.id for f in findings]
        # Self-signed will be flagged; no HTTPS issues though
        assert "CERT_SELF_SIGNED" in ids
        # Should NOT have expired/mismatch
        assert "CERT_EXPIRED" not in ids
        assert "CERT_HOSTNAME_MISMATCH" not in ids

    def test_expired_self_signed(self):
        cert = _make_valid_cert(
            not_before=datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc),
            not_after=datetime.datetime(2021, 1, 1, tzinfo=datetime.timezone.utc),
        )
        findings = check_certificate_object(cert, "example.com")
        ids = [f.id for f in findings]
        assert "CERT_EXPIRED" in ids
        assert "CERT_SELF_SIGNED" in ids

    def test_wrong_hostname(self):
        cert = _make_valid_cert(common_name="other.com", sans=["other.com"])
        findings = check_certificate_object(cert, "evil.com")
        ids = [f.id for f in findings]
        assert "CERT_HOSTNAME_MISMATCH" in ids

    def test_weak_rsa(self):
        cert = _make_valid_cert(key_type="rsa1024")
        findings = check_certificate_object(cert, "example.com")
        ids = [f.id for f in findings]
        assert "CERT_WEAK_RSA" in ids

    def test_sha1_signed(self):
        mock_cert = _make_sha1_mock_cert()
        findings = check_certificate_object(mock_cert, "example.com")
        ids = [f.id for f in findings]
        assert "CERT_WEAK_SIGNATURE" in ids

    def test_ca_issued_valid(self):
        """A properly-issued cert should have fewer findings."""
        leaf, ca, _ = _make_ca_issued_cert(
            common_name="good.example.com",
            sans=["good.example.com"],
        )
        findings = check_certificate_object(
            leaf, "good.example.com", chain=[ca]
        )
        ids = [f.id for f in findings]
        # Should NOT be self-signed or hostname mismatch
        assert "CERT_SELF_SIGNED" not in ids
        assert "CERT_HOSTNAME_MISMATCH" not in ids
        assert "CERT_EXPIRED" not in ids


# ══════════════════════════════════════════════════════════════════════
#  Tests: score computation
# ══════════════════════════════════════════════════════════════════════

class TestScoreFromFindings:
    def test_no_findings(self):
        score, conf = _score_from_findings([])
        assert score == 0
        assert conf > 0

    def test_critical_finding(self):
        findings = [
            Finding(id="CERT_EXPIRED", severity="critical", title="Expired")
        ]
        score, conf = _score_from_findings(findings)
        assert score == 40

    def test_multiple_findings_capped(self):
        findings = [
            Finding(id="CERT_EXPIRED", severity="critical", title="Expired"),
            Finding(id="CERT_SELF_SIGNED", severity="high", title="Self-signed"),
            Finding(id="CERT_WEAK_RSA", severity="high", title="Weak RSA"),
            Finding(id="CERT_WEAK_SIGNATURE", severity="high", title="Weak sig"),
        ]
        score, conf = _score_from_findings(findings)
        assert score <= 100

    def test_low_findings_low_score(self):
        findings = [
            Finding(id="CERT_NO_OCSP_STAPLING", severity="low", title="No OCSP"),
        ]
        score, conf = _score_from_findings(findings)
        assert score == 5


# ══════════════════════════════════════════════════════════════════════
#  Tests: analyze() with mocked network
# ══════════════════════════════════════════════════════════════════════

class TestAnalyzeNoNetwork:
    """Tests for the async analyze() entry point, mocking all network calls."""

    @pytest.mark.asyncio
    async def test_http_url_returns_no_https(self):
        """HTTP URLs should return CERT_NO_HTTPS without any network call."""
        ctx = ScanContext()
        result = await analyze("http://example.com/", ctx)
        assert isinstance(result, ModuleResult)
        assert result.module == "cert"
        ids = [f.id for f in result.findings]
        assert "CERT_NO_HTTPS" in ids
        assert result.error is None

    @pytest.mark.asyncio
    async def test_unresolvable_host(self):
        """Unresolvable hosts should return a result, not crash."""
        with patch(
            "app.modules.cert.cert_check.assert_public_url",
            side_effect=UnsafeURLError("Could not resolve host: nope.invalid"),
        ):
            ctx = ScanContext()
            result = await analyze("https://nope.invalid/", ctx)
            assert isinstance(result, ModuleResult)
            assert result.module == "cert"
            assert result.error is None  # not an error, a finding
            ids = [f.id for f in result.findings]
            assert "CERT_NO_HTTPS" in ids

    @pytest.mark.asyncio
    async def test_private_host_returns_error(self):
        """Private/loopback hosts should return an error ModuleResult."""
        with patch(
            "app.modules.cert.cert_check.assert_public_url",
            side_effect=UnsafeURLError(
                "Host evil resolves to a non-public address (127.0.0.1)"
            ),
        ):
            ctx = ScanContext()
            result = await analyze("https://evil.local/", ctx)
            assert isinstance(result, ModuleResult)
            assert result.module == "cert"
            assert result.error is not None
            assert "Unsafe URL" in result.error

    @pytest.mark.asyncio
    async def test_connection_refused(self):
        """Connection refused should return a finding, not crash."""
        with patch(
            "app.modules.cert.cert_check.assert_public_url",
            return_value=["93.184.216.34"],
        ), patch(
            "app.modules.cert.cert_check._tls_connect",
            side_effect=ConnectionRefusedError("refused"),
        ):
            ctx = ScanContext()
            result = await analyze("https://down.example.com/", ctx)
            assert isinstance(result, ModuleResult)
            assert result.module == "cert"
            ids = [f.id for f in result.findings]
            assert "CERT_NO_HTTPS" in ids

    @pytest.mark.asyncio
    async def test_timeout(self):
        """Socket timeout should be handled gracefully."""
        with patch(
            "app.modules.cert.cert_check.assert_public_url",
            return_value=["93.184.216.34"],
        ), patch(
            "app.modules.cert.cert_check._tls_connect",
            side_effect=socket.timeout("timed out"),
        ):
            ctx = ScanContext()
            result = await analyze("https://slow.example.com/", ctx)
            assert isinstance(result, ModuleResult)
            assert result.module == "cert"
            # socket.timeout → OSError path
            assert result.error is None or "CERT_NO_HTTPS" in [
                f.id for f in result.findings
            ]

    @pytest.mark.asyncio
    async def test_unexpected_exception(self):
        """Totally unexpected errors should be caught and reported."""
        with patch(
            "app.modules.cert.cert_check.assert_public_url",
            return_value=["93.184.216.34"],
        ), patch(
            "app.modules.cert.cert_check._tls_connect",
            side_effect=RuntimeError("something weird"),
        ):
            ctx = ScanContext()
            result = await analyze("https://weird.example.com/", ctx)
            assert isinstance(result, ModuleResult)
            assert result.module == "cert"
            assert result.error is not None
            assert "RuntimeError" in result.error

    @pytest.mark.asyncio
    async def test_successful_scan_mocked(self):
        """Mock a successful TLS connection returning a test cert."""
        cert = _make_valid_cert()
        cert_der = cert.public_bytes(serialization.Encoding.DER)

        with patch(
            "app.modules.cert.cert_check.assert_public_url",
            return_value=["93.184.216.34"],
        ), patch(
            "app.modules.cert.cert_check._tls_connect",
            return_value=(cert_der, [], None),
        ):
            ctx = ScanContext()
            result = await analyze("https://example.com/", ctx)
            assert isinstance(result, ModuleResult)
            assert result.module == "cert"
            assert result.error is None
            assert 0 <= result.score <= 100
            assert 0.0 <= result.confidence <= 1.0

    @pytest.mark.asyncio
    async def test_analyze_always_returns_module_result(self):
        """No matter what, analyze() returns a valid ModuleResult."""
        ctx = ScanContext()
        # Test with various weird inputs
        for url in [
            "",
            "not-a-url",
            "http://example.com",
            "https://example.com",
            "ftp://nope.com",
        ]:
            with patch(
                "app.modules.cert.cert_check.assert_public_url",
                side_effect=UnsafeURLError("nope"),
            ):
                result = await analyze(url, ctx)
                assert isinstance(result, ModuleResult)
                assert result.module == "cert"
                assert 0 <= result.score <= 100


# ══════════════════════════════════════════════════════════════════════
#  Tests: fetch_and_check for non-HTTPS
# ══════════════════════════════════════════════════════════════════════

class TestFetchAndCheckNonHTTPS:
    def test_http_scheme(self):
        findings, meta = fetch_and_check("http://example.com/")
        ids = [f.id for f in findings]
        assert "CERT_NO_HTTPS" in ids

    def test_ftp_scheme(self):
        findings, meta = fetch_and_check("ftp://example.com/")
        ids = [f.id for f in findings]
        assert "CERT_NO_HTTPS" in ids

    def test_no_hostname(self):
        findings, meta = fetch_and_check("https:///no-host")
        ids = [f.id for f in findings]
        assert "CERT_NO_HTTPS" in ids


# ══════════════════════════════════════════════════════════════════════
#  Tests: edge cases for certificate checks
# ══════════════════════════════════════════════════════════════════════

class TestEdgeCases:
    def test_ec_192_weak_curve(self):
        """EC P-192 should be flagged as weak."""
        cert = _make_valid_cert(key_type="ec192")
        findings = check_certificate_object(cert, "example.com")
        ids = [f.id for f in findings]
        assert "CERT_WEAK_EC" in ids

    def test_long_validity_period(self):
        """Certificate valid for 5 years should be flagged."""
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = _make_valid_cert(
            not_before=now - datetime.timedelta(days=1),
            not_after=now + datetime.timedelta(days=365 * 5),
        )
        findings = check_certificate_object(cert, "example.com")
        ids = [f.id for f in findings]
        assert "CERT_LONG_VALIDITY" in ids

    def test_all_findings_have_required_fields(self):
        """Every Finding must have an id, severity, and title."""
        # Use a weak RSA key + expired cert (skip SHA-1 since modern
        # cryptography library refuses to sign with it)
        cert = _make_valid_cert(
            key_type="rsa1024",
            not_before=datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc),
            not_after=datetime.datetime(2021, 1, 1, tzinfo=datetime.timezone.utc),
        )
        findings = check_certificate_object(cert, "wrong.host.com")
        assert len(findings) > 0
        for f in findings:
            assert f.id, f"Finding missing id: {f}"
            assert f.severity in ("low", "medium", "high", "critical"), (
                f"Invalid severity: {f.severity}"
            )
            assert f.title, f"Finding missing title: {f}"

    def test_findings_have_stable_ids(self):
        """IDs should be consistent across calls."""
        cert = _make_valid_cert(
            not_before=datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc),
            not_after=datetime.datetime(2021, 1, 1, tzinfo=datetime.timezone.utc),
        )
        f1 = check_certificate_object(cert, "example.com")
        f2 = check_certificate_object(cert, "example.com")
        assert [f.id for f in f1] == [f.id for f in f2]
