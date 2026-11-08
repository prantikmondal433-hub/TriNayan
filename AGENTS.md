# TrustLens: agent rules
Project: platform that scores websites for phishing/malicious risk by fusing
four modules: threat, websec, cert, community.

## Stack
Backend: Python 3.11, FastAPI, httpx, pydantic v2, SQLAlchemy + PostgreSQL (SQLite in dev), Redis.
Frontend: Next.js + Tailwind. Extension: Chrome Manifest V3.

## Hard rules
- Every module implements `async def analyze(url, ctx) -> ModuleResult` (see backend/app/schemas.py). Never change the schema without asking.
- Stay inside the folder you were asked to work in.
- PASSIVE scanning only: GET/HEAD requests, no exploit attempts, no brute force, no port scanning.
- SSRF protection: before ANY outbound request, resolve the host and refuse private, loopback, link-local and metadata IPs. Use backend/app/safety.py.
- All outbound calls: timeout <= 8s, response size cap 2 MB, max 5 redirects.
- Never crash: catch exceptions and return ModuleResult with error set.
- Every finding needs a stable `id`, severity, and a plain-language title.
- Write pytest tests for every module; run them before saying you are done.
- No secrets in code; read from environment variables.
