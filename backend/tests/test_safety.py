import socket

import pytest

from app.safety import UnsafeURLError, assert_public_url


def fake_dns(*ips):
    def _getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0)) for ip in ips]
    return _getaddrinfo


@pytest.mark.parametrize("url", [
    "http://127.0.0.1/",
    "http://10.0.0.5/admin",
    "http://192.168.1.1/",
    "http://172.16.0.9/",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::1]/",
    "http://[fc00::1]/",
    "http://0.0.0.0/",
    "http://[::ffff:127.0.0.1]/",
    "http://100.64.0.1/",
    "http://localhost/",
])
def test_blocks_private_ip_literals(url):
    with pytest.raises(UnsafeURLError):
        assert_public_url(url)


@pytest.mark.parametrize("url", [
    "file:///etc/passwd",
    "ftp://example.com/",
    "javascript:alert(1)",
    "http://",
    "not a url",
])
def test_blocks_bad_scheme_or_missing_host(url):
    with pytest.raises(UnsafeURLError):
        assert_public_url(url)


def test_blocks_hostname_resolving_to_private(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", fake_dns("10.1.2.3"))
    with pytest.raises(UnsafeURLError):
        assert_public_url("https://evil-looking.example/")


def test_blocks_if_any_resolved_ip_is_private(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", fake_dns("93.184.216.34", "127.0.0.1"))
    with pytest.raises(UnsafeURLError):
        assert_public_url("https://mixed.example/")


def test_blocks_unresolvable_host(monkeypatch):
    def boom(*a, **k):
        raise socket.gaierror("nope")
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    with pytest.raises(UnsafeURLError):
        assert_public_url("https://does-not-exist.example/")


def test_allows_public_host(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", fake_dns("93.184.216.34"))
    assert assert_public_url("https://example.com/path?q=1") == ["93.184.216.34"]
