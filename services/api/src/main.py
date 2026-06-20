"""
SIEMhunter Control Plane — FastAPI entry point.
Spec: instructions/06-api-control-plane.md §8.

Bind: 127.0.0.1:8080 (never 0.0.0.0).
OpenAPI docs disabled in production.
All paths prefixed with /v1/.

Run with:
  uvicorn services.api.src.main:app --host 127.0.0.1 --port 8080
"""
from __future__ import annotations
import os
import signal
import sys
from contextlib import asynccontextmanager

import structlog
import uvicorn
from fastapi import FastAPI

from .clickhouse_client import get_client
from . import db_incidents
from .routers import (
    ai_summary,
    auth_routes,
    detections,
    events,
    health,
    incidents,
    ingestion,
    metrics,
    query,
    rules,
    search,
    status,
    upload,
)

log = structlog.get_logger(__name__)

# ── Logging config ────────────────────────────────────────────────────────────
_log_level = os.environ.get("LOG_LEVEL", "info").lower()
structlog.configure(
    wrapper_class=structlog.make_filtering_bound_logger(
        {"debug": 10, "info": 20, "warn": 30, "error": 40}.get(_log_level, 20)
    ),
)


# ── Lifespan (startup / shutdown) ─────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: initialise SQLite incident store
    try:
        db_incidents.init_db()
        log.info("incidents_db_ready")
    except Exception as exc:
        log.warning("incidents_db_init_failed", error=str(exc))

    # Startup: verify ClickHouse is reachable
    try:
        client = get_client()
        client.query("SELECT 1")
        log.info("clickhouse_ready")
    except Exception as exc:
        # Non-fatal: log warning and continue (spec §8, startup validation #2)
        log.warning("clickhouse_not_reachable_at_startup", error=str(exc))

    yield

    # Shutdown
    log.info("api_service_stopping")


# ── FastAPI app ───────────────────────────────────────────────────────────────
app = FastAPI(
    title="SIEMhunter Control Plane",
    version="0.1.0",
    docs_url=None,      # Swagger UI disabled (spec §8)
    redoc_url=None,     # Redoc disabled
    openapi_url=None,   # OpenAPI schema endpoint disabled
    lifespan=lifespan,
)

# ── Routers — all under /v1/ prefix ──────────────────────────────────────────
app.include_router(auth_routes.router, prefix="/v1")
app.include_router(health.router, prefix="/v1")
app.include_router(status.router, prefix="/v1")
app.include_router(query.router, prefix="/v1")
app.include_router(rules.router, prefix="/v1")
app.include_router(metrics.router, prefix="/v1")
app.include_router(ingestion.router, prefix="/v1")
app.include_router(detections.router, prefix="/v1")
app.include_router(events.router, prefix="/v1")
app.include_router(incidents.router, prefix="/v1")
app.include_router(ai_summary.router, prefix="/v1")
app.include_router(search.router, prefix="/v1")
app.include_router(upload.router, prefix="/v1")


# ── SIGTERM handler for graceful shutdown ─────────────────────────────────────
def _handle_sigterm(sig, frame):
    log.info("sigterm_received")
    # uvicorn handles the actual graceful shutdown when the process receives SIGTERM;
    # this handler just ensures structlog captures the event.
    sys.exit(0)


signal.signal(signal.SIGTERM, _handle_sigterm)


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    uvicorn.run(
        "services.api.src.main:app",
        host="127.0.0.1",   # MUST NOT be 0.0.0.0 (spec §1, non-negotiable invariant)
        port=8080,
        log_level=_log_level,
    )
