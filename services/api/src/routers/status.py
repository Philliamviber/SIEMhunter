"""
GET /v1/status — pipeline health summary.
Reports ClickHouse connectivity, per-service alive files, and retry queue depth.
Spec: instructions/06-api-control-plane.md §3.4.
"""
from __future__ import annotations
import os
import pathlib
import time
from typing import Any

import structlog
from fastapi import APIRouter, Depends, Request

from ..auth import verify_token
from ..clickhouse_client import get_client

log = structlog.get_logger(__name__)
router = APIRouter()

_ALIVE_MAX_AGE_SECONDS = 300   # 5 minutes
_RETRY_QUEUE_DIR = pathlib.Path(
    os.environ.get("RETRY_QUEUE_PATH", "/app/retry_queue")
)

_ALIVE_FILES = {
    "normalization": pathlib.Path("/tmp/normalization_alive"),
    "detection": pathlib.Path("/tmp/detection_alive"),
    "forwarder": pathlib.Path("/tmp/forwarder_alive"),
}


def _is_alive(path: pathlib.Path) -> bool:
    """Return True if the alive file exists and was modified within the max age window."""
    try:
        mtime = path.stat().st_mtime
        return (time.time() - mtime) < _ALIVE_MAX_AGE_SECONDS
    except OSError:
        return False


def _count_retry_queue() -> int:
    """Count .json files in the retry queue directory."""
    try:
        return len(list(_RETRY_QUEUE_DIR.glob("*.json")))
    except OSError:
        return 0


@router.get("/status")
async def status(
    request: Request,
    _: None = Depends(verify_token),
) -> dict[str, Any]:
    """Return pipeline health summary across all services."""
    # ClickHouse connectivity
    ch_status = "ok"
    try:
        client = get_client()
        client.query("SELECT 1")
    except Exception as exc:
        ch_status = f"error: {exc}"

    return {
        "clickhouse": ch_status,
        "normalization_alive": _is_alive(_ALIVE_FILES["normalization"]),
        "detection_alive": _is_alive(_ALIVE_FILES["detection"]),
        "forwarder_alive": _is_alive(_ALIVE_FILES["forwarder"]),
        "pending_retry_queue": _count_retry_queue(),
    }
