"""
POST /v1/query — read-only ClickHouse query endpoint.
Spec: instructions/06-api-control-plane.md §3.5.

Security controls (non-negotiable):
- SELECT only; any mutation keyword → HTTP 400.
- SSRF: reject SQL containing 169.254 (IMDS address) → HTTP 400.
- Row cap: LIMIT {ROW_CAP} appended if absent; default 10000 per spec, env override.
- Query timeout: max_execution_time 30 seconds on ClickHouse call.
- Parameterized queries via ClickHouse client native interface.
"""
from __future__ import annotations
import re
import time
from typing import Any, Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict

from ..auth import verify_token
from ..clickhouse_client import get_client

log = structlog.get_logger(__name__)
router = APIRouter()

_ROW_CAP = int(__import__("os").environ.get("QUERY_ROW_CAP", "10000"))
_QUERY_TIMEOUT_SECONDS = 30

# Forbidden keywords — checked case-insensitively against the full query
_FORBIDDEN_KEYWORDS = re.compile(
    r"\b(INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE|RENAME|ATTACH|DETACH|OPTIMIZE)\b",
    re.IGNORECASE,
)

# IMDS / link-local address detection
_IMDS_PATTERN = re.compile(r"169\.254", re.IGNORECASE)

# LIMIT clause detection
_LIMIT_PATTERN = re.compile(r"\bLIMIT\s+\d+", re.IGNORECASE)


class QueryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sql: str
    params: Optional[dict[str, Any]] = None


class QueryResponse(BaseModel):
    rows: list[dict[str, Any]]
    row_count: int
    truncated: bool
    execution_time_ms: float


@router.post("/query", response_model=QueryResponse)
async def run_query(
    body: QueryRequest,
    request: Request,
    _: None = Depends(verify_token),
) -> QueryResponse:
    """Execute a read-only SELECT query against ClickHouse."""
    sql = body.sql.strip()

    # Validate: must start with SELECT
    if not sql.upper().startswith("SELECT"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "Only SELECT statements are permitted", "code": "FORBIDDEN_STATEMENT"},
        )

    # Reject forbidden mutation keywords anywhere in the query
    m = _FORBIDDEN_KEYWORDS.search(sql)
    if m:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": f"Forbidden keyword in query: {m.group()}",
                "code": "FORBIDDEN_STATEMENT",
            },
        )

    # SSRF: reject queries that reference the IMDS address
    if _IMDS_PATTERN.search(sql):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "Query references a blocked address", "code": "SSRF_REJECTED"},
        )

    # Apply row cap: append LIMIT if not already present
    if not _LIMIT_PATTERN.search(sql):
        sql = f"{sql} LIMIT {_ROW_CAP}"

    t_start = time.monotonic()
    try:
        client = get_client()
        result = client.query(
            sql,
            parameters=body.params or {},
            settings={"max_execution_time": _QUERY_TIMEOUT_SECONDS},
        )
    except Exception as exc:
        exc_str = str(exc)
        if "timeout" in exc_str.lower() or "exceeded" in exc_str.lower():
            raise HTTPException(
                status_code=408,
                detail={"error": "Query timed out", "code": "QUERY_TIMEOUT"},
            )
        log.error("query_execution_error", error=exc_str)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "ClickHouse query failed", "code": "QUERY_ERROR"},
        )

    elapsed_ms = (time.monotonic() - t_start) * 1000.0

    column_names = result.column_names
    rows = [dict(zip(column_names, row)) for row in result.result_rows]

    truncated = len(rows) >= _ROW_CAP

    return QueryResponse(
        rows=rows,
        row_count=len(rows),
        truncated=truncated,
        execution_time_ms=round(elapsed_ms, 2),
    )
