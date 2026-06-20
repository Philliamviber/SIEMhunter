"""
GET /v1/detections — filtered, paginated detection hits.

Filters (all optional, all parameterized):
  - severity: one of low | medium | high | critical
  - rule_id: exact match
  - forwarded: "yes" (forwarded_at IS NOT NULL) | "no" (IS NULL)
  - start: ISO-8601 datetime (created_at >=)
  - end: ISO-8601 datetime (created_at <=)

Also returns a timeline: hourly hit counts bucketed by severity for chart rendering.

Data source: siemhunter.detection_hits (local ClickHouse only).

Authentication: required (bearer token).
"""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel

from ..auth import verify_token
from ..clickhouse_client import get_client

log = structlog.get_logger(__name__)
router = APIRouter()

_VALID_SEVERITIES = frozenset({"low", "medium", "high", "critical"})
_VALID_FORWARDED = frozenset({"yes", "no"})
_DEFAULT_LIMIT = 100
_MAX_LIMIT = 1000


# ── Response models ───────────────────────────────────────────────────────────

class DetectionHit(BaseModel):
    hit_id: str
    rule_id: str
    rule_version: str
    batch_start: str
    batch_end: str
    event_record_ids: str   # JSON array string
    hit_count: int
    severity: str
    mitre_tag: str
    anomaly_score: float
    created_at: str
    forwarded_at: Optional[str]


class TimelineBucket(BaseModel):
    hour: str
    severity: str
    hit_count: int


class DetectionsResponse(BaseModel):
    hits: list[DetectionHit]
    total_count: int
    limit: int
    offset: int
    timeline: list[TimelineBucket]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _to_iso(val) -> Optional[str]:
    if val is None:
        return None
    if isinstance(val, datetime):
        if val.tzinfo is None:
            val = val.replace(tzinfo=timezone.utc)
        return val.isoformat()
    return str(val)


def _parse_dt(value: Optional[str], param_name: str) -> Optional[datetime]:
    if value is None:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error": f"Invalid datetime for {param_name}: {value!r}",
                "code": "INVALID_PARAM",
            },
        )


# ── Endpoint ──────────────────────────────────────────────────────────────────

@router.get("/detections", response_model=DetectionsResponse)
async def list_detections(
    severity: Optional[str] = Query(default=None),
    rule_id: Optional[str] = Query(default=None),
    forwarded: Optional[str] = Query(default=None),
    start: Optional[str] = Query(default=None),
    end: Optional[str] = Query(default=None),
    limit: int = Query(default=_DEFAULT_LIMIT, ge=1, le=_MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
    _: None = Depends(verify_token),
) -> DetectionsResponse:
    """Return filtered detection hits plus an hourly severity timeline."""

    # ── Validate query params before touching the DB ──────────────────────────
    if severity is not None and severity.lower() not in _VALID_SEVERITIES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error": f"Invalid severity {severity!r}. Must be one of: {sorted(_VALID_SEVERITIES)}",
                "code": "INVALID_PARAM",
            },
        )
    if forwarded is not None and forwarded.lower() not in _VALID_FORWARDED:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error": "forwarded must be 'yes' or 'no'",
                "code": "INVALID_PARAM",
            },
        )

    start_dt = _parse_dt(start, "start")
    end_dt = _parse_dt(end, "end")

    # Build WHERE clauses and parameter dict
    where_clauses: list[str] = []
    params: dict = {}

    if severity is not None:
        where_clauses.append("severity = {severity:String}")
        params["severity"] = severity.lower()

    if rule_id is not None:
        where_clauses.append("rule_id = {rule_id:String}")
        params["rule_id"] = rule_id

    if forwarded is not None:
        if forwarded.lower() == "yes":
            where_clauses.append("forwarded_at IS NOT NULL")
        else:
            where_clauses.append("forwarded_at IS NULL")

    if start_dt is not None:
        where_clauses.append("created_at >= {start_dt:DateTime64(3)}")
        params["start_dt"] = start_dt

    if end_dt is not None:
        where_clauses.append("created_at <= {end_dt:DateTime64(3)}")
        params["end_dt"] = end_dt

    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    try:
        client = get_client()

        # Total count for pagination metadata
        count_rows = client.query(
            f"SELECT count() FROM siemhunter.detection_hits {where_sql}",
            parameters=params,
        ).result_rows
        total_count = int(count_rows[0][0]) if count_rows else 0

        # Paginated hits
        params_page = dict(params)
        params_page["_limit"] = limit
        params_page["_offset"] = offset
        hit_rows = client.query(
            f"""
            SELECT
                hit_id, rule_id, rule_version,
                batch_start, batch_end,
                event_record_ids, hit_count,
                severity, mitre_tag, anomaly_score,
                created_at, forwarded_at
            FROM siemhunter.detection_hits
            {where_sql}
            ORDER BY created_at DESC
            LIMIT {{_limit:UInt32}}
            OFFSET {{_offset:UInt32}}
            """,
            parameters=params_page,
        ).result_rows

        hits = [
            DetectionHit(
                hit_id=str(r[0]),
                rule_id=str(r[1]),
                rule_version=str(r[2]),
                batch_start=_to_iso(r[3]) or "",
                batch_end=_to_iso(r[4]) or "",
                event_record_ids=str(r[5]),
                hit_count=int(r[6]),
                severity=str(r[7]),
                mitre_tag=str(r[8]),
                anomaly_score=float(r[9]),
                created_at=_to_iso(r[10]) or "",
                forwarded_at=_to_iso(r[11]),
            )
            for r in hit_rows
        ]

        # Timeline: hourly buckets by severity (uses the same filters)
        tl_rows = client.query(
            f"""
            SELECT
                toStartOfHour(created_at) AS hour_bucket,
                severity,
                count() AS cnt
            FROM siemhunter.detection_hits
            {where_sql}
            GROUP BY hour_bucket, severity
            ORDER BY hour_bucket ASC, severity ASC
            """,
            parameters=params,
        ).result_rows

        timeline = [
            TimelineBucket(
                hour=_to_iso(r[0]) or "",
                severity=str(r[1]),
                hit_count=int(r[2]),
            )
            for r in tl_rows
        ]

    except HTTPException:
        raise
    except Exception as exc:
        log.error("detections_query_failed", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "ClickHouse query failed", "code": "QUERY_ERROR"},
        )

    return DetectionsResponse(
        hits=hits,
        total_count=total_count,
        limit=limit,
        offset=offset,
        timeline=timeline,
    )
