"""Runs the four modules concurrently; a failing module never fails the scan."""
import asyncio
import json
import logging
import os
import time
import uuid
from urllib.parse import urlparse, urlunparse

from app import community
from app.fusion import fuse
from app.modules import cert, threat, websec
from app.safety import UnresolvableHostError, UnsafeURLError, assert_public_url
from app.schemas import ModuleResult, ScanContext, ScanResponse

logger = logging.getLogger(__name__)

MODULES = {"threat": threat, "websec": websec, "cert": cert, "community": community}
MODULE_TIMEOUT_S = 15
CACHE_TTL_S = 600
CACHE_MAX_ITEMS = 1000
MAX_URL_LEN = 2048

# In-memory cache fallback
_cache: dict[str, tuple[float, ScanResponse]] = {}

REDIS_URL = os.getenv("REDIS_URL", "")
_redis_client = None


def get_redis_client():
    global _redis_client
    if _redis_client is None and REDIS_URL:
        try:
            import redis.asyncio as aioredis
            _redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
        except Exception as exc:
            logger.warning("Could not initialize Redis: %s", exc)
    return _redis_client


async def check_redis_health() -> bool:
    """Return True if Redis is reachable or not configured."""
    client = get_redis_client()
    if not client:
        return False
    try:
        return await client.ping()
    except Exception:
        return False


async def _get_cached_response(url: str) -> ScanResponse | None:
    # 1. Try Redis
    client = get_redis_client()
    if client:
        try:
            raw = await client.get(f"scan:{url}")
            if raw:
                return ScanResponse.model_validate_json(raw)
        except Exception as exc:
            logger.debug("Redis cache get failed, using in-memory: %s", exc)

    # 2. In-memory fallback
    hit = _cache.get(url)
    if hit and time.monotonic() - hit[0] < CACHE_TTL_S:
        return hit[1]
    return None


async def _set_cached_response(url: str, response: ScanResponse) -> None:
    # 1. Try Redis
    client = get_redis_client()
    if client:
        try:
            await client.set(f"scan:{url}", response.model_dump_json(), ex=CACHE_TTL_S)
        except Exception as exc:
            logger.debug("Redis cache set failed: %s", exc)

    # 2. In-memory fallback
    if len(_cache) >= CACHE_MAX_ITEMS:
        _cache.clear()
    _cache[url] = (time.monotonic(), response)


def normalize_url(url: str) -> str:
    url = url.strip()
    if len(url) > MAX_URL_LEN:
        raise UnsafeURLError("URL is too long")
    if "://" not in url:
        url = "https://" + url
    try:
        p = urlparse(url)
        host = p.hostname
    except ValueError as exc:
        raise UnsafeURLError(f"Malformed URL: {exc}") from exc
    if not host:
        raise UnsafeURLError("URL has no host")
    return urlunparse((p.scheme.lower(), p.netloc.lower(), p.path or "/", p.params, p.query, ""))


async def _run_module(name: str, mod, url: str, ctx: ScanContext) -> ModuleResult:
    try:
        return await asyncio.wait_for(mod.analyze(url, ctx), timeout=MODULE_TIMEOUT_S)
    except asyncio.TimeoutError:
        return ModuleResult(module=name, error=f"{name} timed out after {MODULE_TIMEOUT_S}s")
    except Exception as exc:  # never let one module break the scan
        return ModuleResult(module=name, error=f"{type(exc).__name__}: {str(exc)[:200]}")


async def scan(raw_url: str) -> ScanResponse:
    """Raises UnsafeURLError for URLs we must not touch (private IPs, bad scheme)."""
    url = normalize_url(raw_url)

    cached = await _get_cached_response(url)
    if cached is not None:
        return cached

    try:
        await asyncio.to_thread(assert_public_url, url)
    except UnresolvableHostError:
        pass  # dead domain: still worth a lexical/community check

    ctx = ScanContext(scan_id=uuid.uuid4().hex)
    names = list(MODULES)
    results = await asyncio.gather(*(_run_module(n, MODULES[n], url, ctx) for n in names))
    by_name = dict(zip(names, results))

    risk, verdict, reasons, action = fuse(by_name)
    response = ScanResponse(
        url=url, verdict=verdict, risk=risk, reasons=reasons,
        recommended_action=action, modules=by_name,
    )

    if all(r.error is None for r in results):  # don't cache partial results
        await _set_cached_response(url, response)

    return response
