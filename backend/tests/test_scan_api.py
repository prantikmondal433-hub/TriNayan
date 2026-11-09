import ipaddress
import socket

import pytest
from fastapi.testclient import TestClient

from app import orchestrator
from app.community.models import init_db
from app.main import app

# Ensure tables exist
init_db()

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
    data = client.get("/health").json()
    assert data["status"] == "ok"
    assert "database" in data
    assert "redis" in data


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


def test_health_reports_components():
    r = client.get("/health")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert data["database"] == "ok"
    assert data["redis"] in {"ok", "disabled", "unreachable"}


@pytest.mark.asyncio
async def test_redis_cache_used_when_available(monkeypatch):
    orchestrator._cache.clear()
    class FakeRedis:
        def __init__(self):
            self.store = {}
        async def get(self, key):
            return self.store.get(key)
        async def set(self, key, val, ex=None):
            self.store[key] = val
        async def ping(self):
            return True

    fake = FakeRedis()
    monkeypatch.setattr(orchestrator, "get_redis_client", lambda: fake)
    monkeypatch.setattr(orchestrator, "REDIS_URL", "redis://fake:6379")

    # Scan once -> should write to redis
    r = await orchestrator.scan("https://cached-test.example.com")
    assert r.url == "https://cached-test.example.com/"
    assert "scan:https://cached-test.example.com/" in fake.store

    # Modify stored verdict in fake redis to verify hit comes from redis
    stored = orchestrator.ScanResponse.model_validate_json(fake.store["scan:https://cached-test.example.com/"])
    stored.risk = 99
    fake.store["scan:https://cached-test.example.com/"] = stored.model_dump_json()

    # Scan again -> should get cached response with risk 99
    r2 = await orchestrator.scan("https://cached-test.example.com")
    assert r2.risk == 99
