"""Certificate analysis for TrustLens – passive TLS checks.

Connects to port 443 using ssl + cryptography, fetches the leaf certificate
and as much of the chain as available, then checks for security issues.

Every outbound connection must go through assert_public_url first (SSRF guard).
All operations are synchronous and expected to be run via asyncio.to_thread.
"""
from __future__ import annotations

import datetime
import hashlib
import logging
import socket
import ssl
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, dsa, padding
from cryptography.x509 import ocsp as x509_ocsp

from app.safety import UnsafeURLError, assert_public_url
from app.schemas import Finding

logger = logging.getLogger(__name__)

# Maximum validity period we consider reasonable (398 days per CA/B baseline)
_MAX_VALIDITY_DAYS = 398

# Weak EC curves (NIST P-192 and smaller, or explicit curves)
_WEAK_EC_CURVES: set[str] = {
    "secp192r1", "prime192v1", "secp160r1", "secp160r2", "secp160k1",
    "secp112r1", "secp112r2", "sect163k1", "sect163r1", "sect163r2",
}


# ── Public entry point ──────────────────────────────────────────────

def fetch_and_check(url: str, timeout: float = 8.0) -> tuple[list[Finding], dict[str, Any]]:
    """Fetch the TLS certificate for *url* and return (findings, metadata).

    This is the main synchronous function.  The ``analyze()`` coroutine in
    ``__init__.py`` calls this via ``asyncio.to_thread``.

    Returns:
        A tuple of (list of Finding objects, dict of metadata for evidence).
    Raises nothing – callers should still wrap in try/except for safety.
    """
    from urllib.parse import urlparse

    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    port = parsed.port or 443
    scheme = (parsed.scheme or "").lower()

    # Non-HTTPS URLs
    if scheme != "https":
        return [
            Finding(
                id="CERT_NO_HTTPS",
                severity="high",
                title="Website does not use HTTPS encryption",
                detail=(
                    "This website does not use an encrypted connection. "
                    "Any information you share could be intercepted."
                ),
            )
        ], {"scheme": scheme}

    if not hostname:
        return [
            Finding(
                id="CERT_NO_HTTPS",
                severity="high",
                title="Could not determine the website address",
                detail="The URL has no hostname; cannot check the certificate.",
            )
        ], {}

    # ── SSRF guard: resolve host and get public IPs ──────────────
    resolved_ips = assert_public_url(url)  # raises UnsafeURLError on failure

    # Pick the first resolved IP for the actual connection
    connect_ip = resolved_ips[0]

    # ── TLS handshake ────────────────────────────────────────────
    leaf_cert, chain_der_list, stapled_ocsp = _tls_connect(
        connect_ip, port, hostname, timeout
    )

    # Parse the leaf with cryptography
    leaf = x509.load_der_x509_certificate(leaf_cert)

    # Parse any chain certs
    chain_certs: list[x509.Certificate] = []
    for der in chain_der_list:
        try:
            chain_certs.append(x509.load_der_x509_certificate(der))
        except Exception:
            pass

    # ── Run all checks ───────────────────────────────────────────
    findings: list[Finding] = []
    now = datetime.datetime.now(datetime.timezone.utc)

    _check_expiry(leaf, now, findings)
    _check_hostname(leaf, hostname, findings)
    _check_self_signed(leaf, findings)
    _check_key_strength(leaf, findings)
    _check_signature_hash(leaf, findings)
    _check_validity_period(leaf, findings)
    _check_sct(leaf, findings)
    _check_chain_completeness(leaf, chain_certs, findings)
    _check_ocsp_stapling(stapled_ocsp, findings)

    # Metadata for evidence
    meta = _build_metadata(leaf, chain_certs, hostname)

    return findings, meta


# ── TLS connection ──────────────────────────────────────────────────

def _tls_connect(
    ip: str, port: int, hostname: str, timeout: float
) -> tuple[bytes, list[bytes], bytes | None]:
    """Connect to *ip*:*port* with SNI=*hostname*, return (leaf_der, chain_ders, stapled_ocsp)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False   # we verify manually
    ctx.verify_mode = ssl.CERT_NONE  # we want to inspect even bad certs
    # Request OCSP stapling
    # Note: not all servers support this
    try:
        ctx.ocsp_staple_callback = lambda *_a: True  # type: ignore[attr-defined]
    except (AttributeError, NotImplementedError):
        pass

    sock = socket.create_connection((ip, port), timeout=timeout)
    try:
        ssock = ctx.wrap_socket(sock, server_hostname=hostname)
    except Exception:
        sock.close()
        raise

    try:
        leaf_der = ssock.getpeercert(binary_form=True)
        if leaf_der is None:
            raise ssl.SSLError("No peer certificate returned")

        # Get chain certs (DER bytes) – available via get_verified_chain or
        # getpeercertchain depending on Python version
        chain_der_list: list[bytes] = []
        try:
            # Python 3.13+ has get_verified_chain() returning list of DER certs
            raw_chain = ssock.get_verified_chain()  # type: ignore[attr-defined]
            if raw_chain:
                for cert_obj in raw_chain:
                    der = cert_obj.public_bytes(ssl._ASN1Object)  # type: ignore[attr-defined]
                    chain_der_list.append(der)
        except (AttributeError, TypeError, Exception):
            pass

        # Try alternative: SSLObject._sslobj.get_peer_cert_chain()
        if not chain_der_list:
            try:
                raw = ssock._sslobj.get_peer_cert_chain()  # type: ignore[attr-defined]
                if raw:
                    chain_der_list = list(raw)
            except (AttributeError, Exception):
                pass

        # OCSP stapled response
        stapled_ocsp: bytes | None = None
        try:
            stapled_ocsp = ssock.get_ocsp_response()  # type: ignore[attr-defined]
        except (AttributeError, Exception):
            pass

        return leaf_der, chain_der_list, stapled_ocsp

    finally:
        ssock.close()


# ── Individual checks ───────────────────────────────────────────────

def _check_expiry(
    cert: x509.Certificate, now: datetime.datetime, findings: list[Finding]
) -> None:
    """Check if certificate is expired or not yet valid."""
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc

    if now > not_after:
        days_expired = (now - not_after).days
        findings.append(Finding(
            id="CERT_EXPIRED",
            severity="critical",
            title="Website's security certificate has expired",
            detail=(
                f"The certificate expired {days_expired} day(s) ago on "
                f"{not_after.strftime('%Y-%m-%d')}. This may mean the site is "
                "abandoned or poorly maintained."
            ),
            evidence={"not_after": not_after.isoformat(), "days_expired": days_expired},
        ))
    elif now < not_before:
        days_early = (not_before - now).days
        findings.append(Finding(
            id="CERT_NOT_YET_VALID",
            severity="high",
            title="Website's security certificate is not yet valid",
            detail=(
                f"The certificate becomes valid on "
                f"{not_before.strftime('%Y-%m-%d')} ({days_early} day(s) from now). "
                "This is unusual and may indicate a misconfiguration."
            ),
            evidence={"not_before": not_before.isoformat(), "days_early": days_early},
        ))


def _check_hostname(
    cert: x509.Certificate, hostname: str, findings: list[Finding]
) -> None:
    """Check if the certificate covers the requested hostname."""
    names: set[str] = set()

    # Common Name from subject
    for attr in cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME):
        names.add(str(attr.value).lower())

    # Subject Alternative Names
    try:
        san_ext = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
        for dns_name in san_ext.value.get_values_for_type(x509.DNSName):
            names.add(dns_name.lower())
    except x509.ExtensionNotFound:
        pass

    if not _hostname_matches_any(hostname, names):
        findings.append(Finding(
            id="CERT_HOSTNAME_MISMATCH",
            severity="critical",
            title="Certificate does not match this website's address",
            detail=(
                f"The certificate is issued for {', '.join(sorted(names)[:5]) or '(unknown)'}, "
                f"but you are visiting '{hostname}'. This could mean someone is "
                "intercepting your connection."
            ),
            evidence={"expected": hostname, "cert_names": sorted(names)[:10]},
        ))


def _hostname_matches_any(hostname: str, names: set[str]) -> bool:
    """Check if hostname matches any name in the set (supports wildcards)."""
    for name in names:
        if name == hostname:
            return True
        # Wildcard match: *.example.com matches sub.example.com
        if name.startswith("*."):
            wildcard_base = name[2:]
            # hostname must have at least one label before the wildcard base
            if hostname.endswith("." + wildcard_base):
                # Only match one level of subdomain
                prefix = hostname[: -(len(wildcard_base) + 1)]
                if "." not in prefix:
                    return True
    return False


def _check_self_signed(
    cert: x509.Certificate, findings: list[Finding]
) -> None:
    """Detect self-signed certificates."""
    if cert.issuer == cert.subject:
        # Double-check by verifying signature
        try:
            pub_key = cert.public_key()
            if isinstance(pub_key, rsa.RSAPublicKey):
                pub_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    cert.signature_hash_algorithm,  # type: ignore[arg-type]
                )
                is_self_signed = True
            elif isinstance(pub_key, ec.EllipticCurvePublicKey):
                pub_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    ec.ECDSA(cert.signature_hash_algorithm),  # type: ignore[arg-type]
                )
                is_self_signed = True
            else:
                # For other key types, subject == issuer is a strong signal
                is_self_signed = True
        except Exception:
            # Verification failed → issuer == subject but different key
            is_self_signed = False

        if is_self_signed:
            findings.append(Finding(
                id="CERT_SELF_SIGNED",
                severity="high",
                title="Website uses a self-signed certificate (not trusted)",
                detail=(
                    "Self-signed certificates are not verified by a trusted "
                    "authority. Anyone can create one, so it provides no "
                    "assurance that you are connected to the real website."
                ),
            ))


def _check_key_strength(
    cert: x509.Certificate, findings: list[Finding]
) -> None:
    """Check the public key type and size."""
    pub_key = cert.public_key()

    if isinstance(pub_key, rsa.RSAPublicKey):
        key_size = pub_key.key_size
        if key_size < 2048:
            findings.append(Finding(
                id="CERT_WEAK_RSA",
                severity="high",
                title=f"Certificate uses a weak {key_size}-bit RSA key",
                detail=(
                    "RSA keys shorter than 2048 bits are considered insecure. "
                    "A determined attacker could break this encryption."
                ),
                evidence={"key_type": "RSA", "key_size": key_size},
            ))

    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        curve_name = pub_key.curve.name.lower()
        if curve_name in _WEAK_EC_CURVES or pub_key.key_size < 224:
            findings.append(Finding(
                id="CERT_WEAK_EC",
                severity="high",
                title="Certificate uses a weak elliptic curve",
                detail=(
                    f"The curve '{pub_key.curve.name}' ({pub_key.key_size}-bit) "
                    "is considered too small for secure communication."
                ),
                evidence={
                    "key_type": "EC",
                    "curve": pub_key.curve.name,
                    "key_size": pub_key.key_size,
                },
            ))

    elif isinstance(pub_key, dsa.DSAPublicKey):
        # DSA is deprecated for TLS
        findings.append(Finding(
            id="CERT_WEAK_RSA",  # group under weak key
            severity="medium",
            title="Certificate uses a deprecated DSA key",
            detail="DSA keys are no longer recommended for TLS certificates.",
            evidence={"key_type": "DSA", "key_size": pub_key.key_size},
        ))


def _check_signature_hash(
    cert: x509.Certificate, findings: list[Finding]
) -> None:
    """Flag SHA-1 or MD5 signature algorithms."""
    sig_alg = cert.signature_hash_algorithm
    if sig_alg is None:
        return  # e.g., Ed25519 – no separate hash

    name = sig_alg.name.lower()
    if "md5" in name:
        findings.append(Finding(
            id="CERT_WEAK_SIGNATURE",
            severity="critical",
            title="Certificate signed with broken MD5 algorithm",
            detail=(
                "MD5 signatures can be forged. This certificate should not "
                "be trusted."
            ),
            evidence={"signature_algorithm": name},
        ))
    elif "sha1" in name:
        findings.append(Finding(
            id="CERT_WEAK_SIGNATURE",
            severity="high",
            title="Certificate signed with outdated SHA-1 algorithm",
            detail=(
                "SHA-1 is no longer considered secure for certificate "
                "signatures. Modern certificates should use SHA-256 or better."
            ),
            evidence={"signature_algorithm": name},
        ))


def _check_validity_period(
    cert: x509.Certificate, findings: list[Finding]
) -> None:
    """Flag certificates with an unusually long validity period."""
    duration = cert.not_valid_after_utc - cert.not_valid_before_utc
    days = duration.days

    if days > _MAX_VALIDITY_DAYS:
        findings.append(Finding(
            id="CERT_LONG_VALIDITY",
            severity="low",
            title="Certificate validity period is unusually long",
            detail=(
                f"This certificate is valid for {days} days "
                f"({days // 365} year(s)), which exceeds the recommended "
                f"maximum of {_MAX_VALIDITY_DAYS} days. Long-lived certificates "
                "are harder to revoke if compromised."
            ),
            evidence={"validity_days": days, "max_recommended": _MAX_VALIDITY_DAYS},
        ))


def _check_sct(
    cert: x509.Certificate, findings: list[Finding]
) -> None:
    """Check for Signed Certificate Timestamps (SCTs) embedded in the cert."""
    try:
        # OID for SCT list: 1.3.6.1.4.1.11129.2.4.2
        cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS
        )
        # SCTs present – good
    except x509.ExtensionNotFound:
        findings.append(Finding(
            id="CERT_NO_SCT",
            severity="medium",
            title="Certificate lacks proof of public logging (no SCT)",
            detail=(
                "Signed Certificate Timestamps (SCTs) prove a certificate was "
                "logged in a public transparency log. Without them, the "
                "certificate may not have been publicly audited."
            ),
        ))


def _check_chain_completeness(
    leaf: x509.Certificate,
    chain: list[x509.Certificate],
    findings: list[Finding],
) -> None:
    """Check if the server sent intermediate certificates."""
    # A complete chain should have at least: leaf → intermediate (→ root).
    # The root is often omitted (it's in the trust store), so we need at
    # least one intermediate unless the leaf IS the root (self-signed).
    if leaf.issuer == leaf.subject:
        return  # self-signed; chain completeness is moot (already flagged)

    if not chain:
        # No chain certs sent at all
        findings.append(Finding(
            id="CERT_INCOMPLETE_CHAIN",
            severity="medium",
            title="Server did not send the full certificate chain",
            detail=(
                "The server did not provide intermediate certificates. "
                "Some devices and browsers may not be able to verify "
                "this website's identity."
            ),
        ))
        return

    # Check if chain has an intermediate (a cert that is neither the leaf
    # nor a self-signed root)
    leaf_fingerprint = leaf.fingerprint(hashes.SHA256())
    has_intermediate = False
    for c in chain:
        c_fp = c.fingerprint(hashes.SHA256())
        if c_fp == leaf_fingerprint:
            continue  # skip the leaf itself
        if c.issuer != c.subject:
            has_intermediate = True
            break
        # It's a root (self-signed) – keep looking for intermediates

    # If chain only has the leaf (or leaf + root but no intermediate)
    # and the leaf is not self-signed, that may be incomplete.
    if not has_intermediate and leaf.issuer != leaf.subject:
        # Check if the only other cert is a root that issued the leaf directly
        root_issued_leaf = False
        for c in chain:
            c_fp = c.fingerprint(hashes.SHA256())
            if c_fp != leaf_fingerprint and c.subject == leaf.issuer:
                root_issued_leaf = True
                break
        if not root_issued_leaf:
            findings.append(Finding(
                id="CERT_INCOMPLETE_CHAIN",
                severity="medium",
                title="Server did not send the full certificate chain",
                detail=(
                    "The server may be missing intermediate certificates. "
                    "Some clients might not be able to verify the certificate."
                ),
            ))


def _check_ocsp_stapling(
    stapled_response: bytes | None, findings: list[Finding]
) -> None:
    """Check if OCSP stapling is present."""
    if not stapled_response:
        findings.append(Finding(
            id="CERT_NO_OCSP_STAPLING",
            severity="low",
            title="Server does not staple a certificate revocation check",
            detail=(
                "OCSP stapling lets the server prove its certificate has not "
                "been revoked, without the browser contacting a third party. "
                "Without it, revocation checks may be slower or skipped."
            ),
        ))


# ── Metadata builder ───────────────────────────────────────────────

def _build_metadata(
    leaf: x509.Certificate,
    chain: list[x509.Certificate],
    hostname: str,
) -> dict[str, Any]:
    """Build an evidence dict with cert metadata (for UI display)."""
    pub_key = leaf.public_key()
    key_type = type(pub_key).__name__.replace("PublicKey", "").replace("_", "")
    key_size = getattr(pub_key, "key_size", None)

    sig_alg = leaf.signature_hash_algorithm
    sig_name = sig_alg.name if sig_alg else "unknown"

    # Subject and issuer common names
    def _cn(name: x509.Name) -> str:
        attrs = name.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        return str(attrs[0].value) if attrs else "(none)"

    # SANs
    sans: list[str] = []
    try:
        san_ext = leaf.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
        sans = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass

    return {
        "hostname": hostname,
        "subject_cn": _cn(leaf.subject),
        "issuer_cn": _cn(leaf.issuer),
        "not_before": leaf.not_valid_before_utc.isoformat(),
        "not_after": leaf.not_valid_after_utc.isoformat(),
        "serial": format(leaf.serial_number, "x"),
        "fingerprint_sha256": leaf.fingerprint(hashes.SHA256()).hex(),
        "key_type": key_type,
        "key_size": key_size,
        "signature_algorithm": sig_name,
        "san_count": len(sans),
        "chain_length": len(chain),
    }


# ── Helpers for analyzing pre-loaded certificates (used by tests) ──

def check_certificate_object(
    cert: x509.Certificate,
    hostname: str = "example.com",
    chain: list[x509.Certificate] | None = None,
    stapled_ocsp: bytes | None = None,
) -> list[Finding]:
    """Analyze a pre-loaded certificate object directly.

    This is useful for testing without a network connection.
    """
    findings: list[Finding] = []
    now = datetime.datetime.now(datetime.timezone.utc)

    _check_expiry(cert, now, findings)
    _check_hostname(cert, hostname, findings)
    _check_self_signed(cert, findings)
    _check_key_strength(cert, findings)
    _check_signature_hash(cert, findings)
    _check_validity_period(cert, findings)
    _check_sct(cert, findings)
    _check_chain_completeness(cert, chain or [], findings)
    _check_ocsp_stapling(stapled_ocsp, findings)

    return findings
