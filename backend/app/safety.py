"""SSRF guard. Every outbound request in TrustLens must call assert_public_url first.

Limitation: DNS can change between this check and the real request (DNS rebinding).
Callers should connect to the IP returned here where practical.
"""
import ipaddress
import socket
from urllib.parse import urlparse

ALLOWED_SCHEMES = {"http", "https"}


class UnsafeURLError(ValueError):
    """Raised when a URL must not be fetched."""


class UnresolvableHostError(UnsafeURLError):
    """Host does not resolve (DNS failure). Not a safety problem by itself."""


def _is_blocked_ip(ip: ipaddress._BaseAddress) -> bool:
    # IPv4-mapped IPv6 (::ffff:127.0.0.1) must be judged as the IPv4 address
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    # not is_global covers private, loopback, link-local (incl. 169.254.169.254
    # cloud metadata), unique-local fc00::/7, CGNAT 100.64/10 and reserved ranges
    return (not ip.is_global) or ip.is_multicast or ip.is_unspecified


def assert_public_url(url: str) -> list[str]:
    """Return the resolved public IPs, or raise UnsafeURLError."""
    try:
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise UnsafeURLError(f"Malformed URL: {exc}") from exc

    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise UnsafeURLError(f"Scheme not allowed: {parsed.scheme!r}")
    if not host:
        raise UnsafeURLError("URL has no host")

    try:
        infos = socket.getaddrinfo(host, port or (443 if parsed.scheme == "https" else 80),
                                   proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise UnresolvableHostError(f"Could not resolve host: {host}") from exc

    ips = sorted({info[4][0] for info in infos})
    if not ips:
        raise UnsafeURLError(f"No addresses for host: {host}")

    for raw in ips:
        ip = ipaddress.ip_address(raw.split("%")[0])
        if _is_blocked_ip(ip):
            raise UnsafeURLError(f"Host {host} resolves to a non-public address ({ip})")
    return ips