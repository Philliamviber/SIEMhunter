"""
Health endpoints.

GET /v1/health
  — Unauthenticated Docker HEALTHCHECK probe. Returns {"status": "ok"}.
    MUST remain unauthenticated and MUST always return 200.
    Docker's HEALTHCHECK depends on this. Do NOT add auth to this route.

GET /v1/health/{service}
  — Authenticated per-service detail check.
  Valid services: vector | clickhouse | normalization | detection | forwarder
  Returns per-service status with detail notes.
  404 on unknown service name.

Alive-file mechanism (reused from status.py):
  normalization / detection / forwarder each touch /tmp/<service>_alive after
  every successful batch cycle. "alive" = modified within the last 5 minutes.

Vector has no alive-file in this codebase — status reported as "unknown" with
a note rather than guessing.

ClickHouse status is checked via SELECT 1.

Spec: instructions/06-api-control-plane.md §3.4 / changelog2.md Phase 1.
"""
from __future__ import annotations
import pathlib
import time
from typing import Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from ..auth import verify_token
from ..clickhouse_client import get_client

log = structlog.get_logger(__name__)
router = APIRouter()

_ALIVE_MAX_AGE_SECONDS = 300   # 5 minutes — matches status.py

_ALIVE_FILES: dict[str, pathlib.Path] = {
    "normalization": pathlib.Path("/tmp/normalization_alive"),
    "detection":     pathlib.Path("/tmp/detection_alive"),
    "forwarder":     pathlib.Path("/tmp/forwarder_alive"),
}

_VALID_SERVICES = frozenset({"vector", "clickhouse", "normalization", "detection", "forwarder"})


# ── Response models ───────────────────────────────────────────────────────────

class ServiceHealthResponse(BaseModel):
    service: str
    status: str          # "ok" | "degraded" | "unknown" | "error"
    detail: Optional[str]
    alive_file_age_seconds: Optional[float]  # None for clickhouse/vector


# ── Helpers ───────────────────────────────────────────────────────────────────

def _is_alive(path: pathlib.Path) -> tuple[bool, Optional[float]]:
    """
    Return (is_alive, age_seconds).
    age_seconds is None if the file does not exist.
    """
    try:
        mtime = path.stat().st_mtime
        age = time.time() - mtime
        return age < _ALIVE_MAX_AGE_SECONDS, round(age, 1)
    except OSError:
        return False, None


def _check_clickhouse() -> tuple[str, Optional[str]]:
    """Return (status, detail). Runs SELECT 1 to verify connectivity."""
    try:
        client = get_client()
        client.query("SELECT 1")
        return "ok", None
    except Exception as exc:
        return "error", str(exc)


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/health")
async def health() -> dict:
    """Unauthenticated health probe used by Docker HEALTHCHECK."""
    return {"status": "ok"}


@router.get("/health/{service}", response_model=ServiceHealthResponse)
async def health_detail(
    service: str,
    _: None = Depends(verify_token),
) -> ServiceHealthResponse:
    """Return detailed health status for a single named service."""
    svc = service.lower()

    if svc not in _VALID_SERVICES:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": f"Unknown service: {service!r}. "
                         f"Valid services: {sorted(_VALID_SERVICES)}",
                "code": "SERVICE_NOT_FOUND",
            },
        )

    if svc == "clickhouse":
        ch_status, detail = _check_clickhouse()
        return ServiceHealthResponse(
            service="clickhouse",
            status=ch_status,
            detail=detail,
            alive_file_age_seconds=None,
        )

    if svc == "vector":
        # Vector has no alive-file in this codebase — report honestly
        return ServiceHealthResponse(
            service="vector",
            status="unknown",
            detail=(
                "Vector does not write a local alive-file. "
                "Check the vector container logs or Docker health status directly."
            ),
            alive_file_age_seconds=None,
        )

    # normalization | detection | forwarder — alive-file check
    alive_path = _ALIVE_FILES[svc]
    is_alive, age_seconds = _is_alive(alive_path)

    if is_alive:
        svc_status = "ok"
        detail: Optional[str] = None
    elif age_seconds is not None:
        svc_status = "degraded"
        detail = (
            f"Alive file is {age_seconds}s old "
            f"(threshold: {_ALIVE_MAX_AGE_SECONDS}s). "
            "Service may be stuck or restarting."
        )
    else:
        svc_status = "degraded"
        detail = (
            f"Alive file not found at {alive_path}. "
            "Service has not completed a batch cycle since last container start."
        )

    return ServiceHealthResponse(
        service=svc,
        status=svc_status,
        detail=detail,
        alive_file_age_seconds=age_seconds,
    )
