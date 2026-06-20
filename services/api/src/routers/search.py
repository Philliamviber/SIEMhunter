"""
POST /v1/search — security-gated field-type search endpoint.

Security controls (MUST 8-11 per Wave 2D spec):

MUST 8 — Dedicated endpoint; accepts {field_type, value, start?, end?, incident_id?}.
         No `sql` field. All SQL is built server-side from a fixed template.

MUST 9 — Server-side column allowlist: field_type is mapped to ClickHouse column
         names via FIELD_TYPE_MAP. Unknown field_type → 422. Column names are never
         interpolated from the request body.

MUST 10 — Bounded search: defaults to last 24h, max 30-day window. Inherits 10k
          row cap. 10-second timeout. UnmappedFields substring search not offered.

MUST 11 — Incident scope: if incident_id is present, server appends
          `AND ProvenanceTag LIKE 'manual-upload:incident:{id}:%'` to WHERE.
          The client cannot remove this filter once applied.

Authentication: requires Bearer token (see auth.py). No anonymous access.
"""
from __future__ import annotations

import re
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict

from ..auth import verify_token
from ..clickhouse_client import get_client

log = structlog.get_logger(__name__)
router = APIRouter()

_ROW_CAP = int(__import__("os").environ.get("QUERY_ROW_CAP", "10000"))
_SEARCH_TIMEOUT_SECONDS = 10
_MAX_WINDOW_DAYS = 30

# ── MUST 9: column allowlist ───────────────────────────────────────────────────
# None means the field type uses special routing logic (FileHash: dispatch by length).
FIELD_TYPE_MAP: dict[str, list[str] | None] = {
    "IP": ["SrcIpAddr", "DstIpAddr"],
    "Hostname": ["HostName"],
    "Username": ["SubjectUserName", "TargetUserName"],
    "Port": ["SrcPort", "DstPort"],
    "EventID": ["EventID"],
    "FileHash": None,  # special: routed by hash length (32 → MD5, 64 → SHA256)
    "ProcessName": ["ProcessImagePath", "ParentProcessImagePath"],
}

_VALID_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


# ── Pydantic models ────────────────────────────────────────────────────────────

class SearchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    field_type: str
    value: str
    start: Optional[str] = None
    end: Optional[str] = None
    incident_id: Optional[str] = None


class SearchResponse(BaseModel):
    rows: list[dict]
    row_count: int
    truncated: bool
    execution_time_ms: float
    field_type: str
    columns_searched: list[str]


# ── Helpers ────────────────────────────────────────────────────────────────────

def _parse_datetime(value: str, field_name: str) -> datetime:
    """Parse an ISO datetime string, raising 422 on failure."""
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": f"Invalid datetime for '{field_name}': {value}", "code": "INVALID_DATETIME"},
        )


def _resolve_time_range(
    start_raw: Optional[str], end_raw: Optional[str]
) -> tuple[datetime, datetime]:
    """
    Resolve and validate the time range (MUST 10).
    - Default: last 24 hours if not provided.
    - Max window: 30 days.
    Returns (start_dt, end_dt) as UTC-aware datetimes.
    """
    now = datetime.now(timezone.utc)

    if end_raw is None:
        end_dt = now
    else:
        end_dt = _parse_datetime(end_raw, "end")
        if end_dt.tzinfo is None:
            end_dt = end_dt.replace(tzinfo=timezone.utc)

    if start_raw is None:
        start_dt = end_dt - timedelta(hours=24)
    else:
        start_dt = _parse_datetime(start_raw, "start")
        if start_dt.tzinfo is None:
            start_dt = start_dt.replace(tzinfo=timezone.utc)

    if start_dt >= end_dt:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "'start' must be before 'end'", "code": "INVALID_TIME_RANGE"},
        )

    window = end_dt - start_dt
    if window > timedelta(days=_MAX_WINDOW_DAYS):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error": f"Time range exceeds maximum of {_MAX_WINDOW_DAYS} days",
                "code": "TIME_RANGE_TOO_LARGE",
            },
        )

    return start_dt, end_dt


def _build_sql_and_params(
    field_type: str,
    value: str,
    start_dt: datetime,
    end_dt: datetime,
    incident_id: Optional[str],
    row_cap: int,
) -> tuple[str, dict, list[str]]:
    """
    Build the parameterized ClickHouse SQL and params dict for the given field type.
    Returns (sql, params, columns_searched).
    Column names are NEVER interpolated from the request body.
    """
    start_str = start_dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]  # ms precision
    end_str = end_dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    time_clause = (
        "TimeGenerated >= {start:DateTime64(3,'UTC')} "
        "AND TimeGenerated <= {end:DateTime64(3,'UTC')}"
    )
    params: dict = {"start": start_str, "end": end_str}

    # ── Build field-specific WHERE fragment ────────────────────────────────────

    if field_type == "IP":
        where_field = "(SrcIpAddr = {ip:String} OR DstIpAddr = {ip:String})"
        params["ip"] = value
        columns_searched = ["SrcIpAddr", "DstIpAddr"]

    elif field_type == "Hostname":
        where_field = "HostName = {hostname:String}"
        params["hostname"] = value
        columns_searched = ["HostName"]

    elif field_type == "Username":
        where_field = "(SubjectUserName = {username:String} OR TargetUserName = {username:String})"
        params["username"] = value
        columns_searched = ["SubjectUserName", "TargetUserName"]

    elif field_type == "Port":
        try:
            port_int = int(value)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={"error": "Port must be an integer", "code": "INVALID_PORT"},
            )
        if not (1 <= port_int <= 65535):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={"error": "Port must be between 1 and 65535", "code": "INVALID_PORT"},
            )
        where_field = "(SrcPort = {port:UInt16} OR DstPort = {port:UInt16})"
        params["port"] = port_int
        columns_searched = ["SrcPort", "DstPort"]

    elif field_type == "EventID":
        try:
            eid_int = int(value)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={"error": "EventID must be an integer", "code": "INVALID_EVENT_ID"},
            )
        if eid_int < 0:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={"error": "EventID must be a non-negative integer", "code": "INVALID_EVENT_ID"},
            )
        where_field = "EventID = {event_id:UInt32}"
        params["event_id"] = eid_int
        columns_searched = ["EventID"]

    elif field_type == "FileHash":
        hash_lower = value.lower()
        if not _VALID_HEX_RE.match(hash_lower):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={"error": "FileHash must be a hexadecimal string", "code": "INVALID_HASH"},
            )
        if len(hash_lower) == 32:
            where_field = "FileMD5 = {hash:FixedString(32)}"
            columns_searched = ["FileMD5"]
        elif len(hash_lower) == 64:
            where_field = "FileSHA256 = {hash:FixedString(64)}"
            columns_searched = ["FileSHA256"]
        else:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={
                    "error": "FileHash must be 32 characters (MD5) or 64 characters (SHA-256)",
                    "code": "INVALID_HASH_LENGTH",
                },
            )
        params["hash"] = hash_lower

    elif field_type == "ProcessName":
        where_field = (
            "(ProcessImagePath LIKE {proc:String} OR ParentProcessImagePath LIKE {proc:String})"
        )
        params["proc"] = value + "%"
        columns_searched = ["ProcessImagePath", "ParentProcessImagePath"]

    else:
        # Should not reach here — validated above — but keep as safety net.
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": f"Unknown field_type: {field_type!r}", "code": "UNKNOWN_FIELD_TYPE"},
        )

    # ── MUST 11: incident scope predicate ─────────────────────────────────────
    # Appended server-side; client cannot remove this filter.
    incident_clause = ""
    if incident_id is not None:
        # Validate incident_id is safe (alphanumeric + hyphens only)
        if not re.match(r"^[A-Za-z0-9_\-]+$", incident_id):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={"error": "Invalid incident_id format", "code": "INVALID_INCIDENT_ID"},
            )
        # Server constructs the ProvenanceTag prefix — incident_id is NOT interpolated
        # into the SQL string; it is passed as the {incident_tag:String} parameter.
        incident_clause = "AND ProvenanceTag LIKE {incident_tag:String}"
        params["incident_tag"] = f"manual-upload:incident:{incident_id}:%"

    sql = f"""SELECT * FROM siemhunter.security_events
WHERE {where_field}
AND {time_clause}
{incident_clause}
ORDER BY TimeGenerated DESC
LIMIT {row_cap}"""

    return sql, params, columns_searched


# ── Endpoint ───────────────────────────────────────────────────────────────────

@router.post("/search", response_model=SearchResponse)
async def run_search(
    body: SearchRequest,
    request: Request,
    _: None = Depends(verify_token),
) -> SearchResponse:
    """
    Security-gated field-type search.

    Accepts {field_type, value, start?, end?, incident_id?}.
    Never accepts a raw SQL string.
    All SQL is built server-side from a fixed per-field template.
    """
    # MUST 9: validate field_type against the allowlist
    if body.field_type not in FIELD_TYPE_MAP:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error": f"Unknown field_type: {body.field_type!r}. "
                         f"Allowed values: {list(FIELD_TYPE_MAP.keys())}",
                "code": "UNKNOWN_FIELD_TYPE",
            },
        )

    # MUST 8: value must be non-empty
    if not body.value or not body.value.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "Search value must not be empty", "code": "EMPTY_SEARCH_VALUE"},
        )

    # MUST 10: resolve bounded time range
    start_dt, end_dt = _resolve_time_range(body.start, body.end)

    # Build SQL from fixed server-side template
    sql, params, columns_searched = _build_sql_and_params(
        field_type=body.field_type,
        value=body.value.strip(),
        start_dt=start_dt,
        end_dt=end_dt,
        incident_id=body.incident_id,
        row_cap=_ROW_CAP,
    )

    log.info(
        "search_request",
        field_type=body.field_type,
        columns=columns_searched,
        has_incident_scope=body.incident_id is not None,
    )

    t_start = time.monotonic()
    try:
        client = get_client()
        result = client.query(
            sql,
            parameters=params,
            settings={"max_execution_time": _SEARCH_TIMEOUT_SECONDS},
        )
    except Exception as exc:
        exc_str = str(exc)
        if "timeout" in exc_str.lower() or "exceeded" in exc_str.lower():
            raise HTTPException(
                status_code=408,
                detail={"error": "Search timed out", "code": "QUERY_TIMEOUT"},
            )
        log.error("search_execution_error", error=exc_str)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "Search query failed", "code": "QUERY_ERROR"},
        )

    elapsed_ms = (time.monotonic() - t_start) * 1000.0

    column_names = result.column_names
    rows = [dict(zip(column_names, row)) for row in result.result_rows]

    truncated = len(rows) >= _ROW_CAP

    return SearchResponse(
        rows=rows,
        row_count=len(rows),
        truncated=truncated,
        execution_time_ms=round(elapsed_ms, 2),
        field_type=body.field_type,
        columns_searched=columns_searched,
    )
