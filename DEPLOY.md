# TrustLens Deployment Guide

TrustLens consists of a FastAPI backend, SQLite/PostgreSQL database, optional Redis cache, and Next.js frontend.

---

## 1. Local Development (No Docker)

### Prerequisites
- Python 3.11+
- Node.js 18+ (for frontend)

### Backend
From the repo root:
```bash
pip install -r backend/requirements.txt
python -m uvicorn app.main:app --reload --app-dir backend --port 8000
```
- API is available at: `http://127.0.0.1:8000`
- Interactive OpenAPI docs: `http://127.0.0.1:8000/docs`

---

## 2. Docker Compose Deployment

Run backend and Redis together with a single command:
```bash
docker compose up --build
```
This starts:
- Redis on `localhost:6379`
- TrustLens FastAPI backend on `http://localhost:8000`

---

## 3. Cloud Deployment (Render / Railway)

### Environment Variables
Set the following environment variables in your cloud provider dashboard:
- `CORS_ORIGINS`: Comma-separated allowed frontend domains (e.g. `https://your-frontend.vercel.app,http://localhost:3000`)
- `REDIS_URL`: (Optional) Connection string to Redis instance (e.g. `rediss://default:token@host:port`). If omitted, backend uses in-memory caching.
- `DATABASE_URL`: (Optional) PostgreSQL URL (e.g. `postgresql://user:pass@host:5432/db`). Defaults to SQLite if omitted.

### Railway / Render Backend Service
- **Root directory:** `/` or `backend`
- **Build command:** `pip install -r backend/requirements.txt`
- **Start command:** `python -m uvicorn app.main:app --host 0.0.0.0 --port $PORT --app-dir backend`
- **Health check path:** `/health`
