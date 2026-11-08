import ipaddress
import socket

import pytest
from fastapi.testclient import TestClient

from app import orchestrator
from app.main import app

client = TestClient(app)


@pytest.fixture(autouse=True)
def public_dns(monkeypatch):
    real = socket.getaddrinfo

    def fake(host, port, *a, **k):
        try:
            ipaddress.ip_address(host)
            return real(host, port, *a, **k)  # IP literal: no DNS lookup involved
        except ValueError:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    orchestrator._cache.clear()


def test_health():
    assert client.get("/health").json() == {"status": "ok"}


def test_scan_returns_full_response():
    r = client.post("/scan", json={"url": "https://example.com"})
    assert r.status_code == 200
    body = r.json()
    assert body["verdict"] in {"Safe", "Suspicious", "Dangerous"}
    assert 0 <= body["risk"] <= 100
    assert set(body["modules"]) == {"threat", "websec", "cert", "community"}
    assert body["recommended_action"]


def test_scheme_is_added_when_missing():
    r = client.post("/scan", json={"url": "Example.com"})
    assert r.status_code == 200
    assert r.json()["url"] == "https://example.com/"


@pytest.mark.parametrize("url", [
    "http://127.0.0.1/", "http://169.254.169.254/latest/meta-data/",
    "http://[::1]/", "ftp://example.com/", "file:///etc/passwd",
])
def test_unsafe_urls_rejected(url):
    assert client.post("/scan", json={"url": url}).status_code == 400


def test_crashing_module_does_not_fail_scan(monkeypatch):
    class Boom:
        @staticmethod
        async def analyze(url, ctx):
            raise RuntimeError("kaboom")

    monkeypatch.setitem(orchestrator.MODULES, "cert", Boom)
    r = client.post("/scan", json={"url": "https://example.com"})
    assert r.status_code == 200
    assert "kaboom" in r.json()["modules"]["cert"]["error"]


def test_unresolvable_host_still_scanned(monkeypatch):
    def nxdomain(*a, **k):
        raise socket.gaierror("nxdomain")
    monkeypatch.setattr(socket, "getaddrinfo", nxdomain)
    assert client.post("/scan", json={"url": "https://dead-phish.example/"}).status_code == 200
