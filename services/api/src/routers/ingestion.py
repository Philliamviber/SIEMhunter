"""
GET /v1/ingestion/summary — ingestion pipeline statistics.

Data is sourced entirely from local ClickHouse (siemhunter.security_events).

Sections returned:
  - provenance_breakdown: event count per ProvenanceTag (last 24h)
  - volume_over_time: hourly event counts per source (last 24h)
  - pipeline_latency: avg + p95 of (IngestTimestamp - TimeGenerated) in seconds
  - per_source: per-ProvenanceTag cards with last_seen, events_per_hour, unmapped_%

Rate-limit / flood panel (SELF-002, SELF-004) lives in SIEMHunterHealth_CL which
is a Sentinel-side Log Analytics table — not readable from this API. Those sections
return null with an explanatory note field.

Authentication: required (bearer token).
"""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Optional, Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from ..auth import verify_token
from ..clickhouse_client import get_client

log = structlog.get_logger(__name__)
router = APIRouter()


# ── Response models ───────────────────────────────────────────────────────────

class ProvenanceCount(BaseModel):
    provenance_tag: str
    event_count: int


class HourlyVolume(BaseModel):
    hour: str               # ISO-8601 UTC hour start
    provenance_tag: str
    event_count: int


class PipelineLatency(BaseModel):
    avg_seconds: Optional[float]
    p95_seconds: Optional[float]


class PerSourceStat(BaseModel):
    provenance_tag: str
    last_seen: Optional[str]        # ISO-8601 UTC
    events_per_hour: float          # average over the last 24h
    unmapped_nonempty_pct: float    # % of rows where UnmappedFields != ''


class IngestionSummaryResponse(BaseModel):
    provenance_breakdown: list[ProvenanceCount]
    volume_over_time: list[HourlyVolume]
    pipeline_latency: PipelineLatency
    per_source: list[PerSourceStat]
    rate_limit_flood_panel: None     # Sentinel-side only — see note
    rate_limit_flood_note: str


_SENTINEL_NOTE = (
    "Rate-limit and flood panel data (SELF-002, SELF-004) is sourced from "
    "SIEMHunterHealth_CL, a Sentinel Log Analytics table. "
    "It is not available from this API."
)


# ── Endpoint ──────────────────────────────────────────────────────────────────

@router.get("/ingestion/summary", response_model=IngestionSummaryResponse)
async def ingestion_summary(
    _: None = Depends(verify_token),
) -> IngestionSummaryResponse:
    """Return ingestion pipeline statistics from local ClickHouse."""
    try:
        client = get_client()

        # Provenance breakdown (last 24h)
        prov_rows = client.query(
            """
            SELECT ProvenanceTag, count() AS cnt
            FROM siemhunter.security_events
            WHERE TimeGenerated >= now64(3) - INTERVAL 24 HOUR
            GROUP BY ProvenanceTag
            ORDER BY cnt DESC
            """,
        ).result_rows
        provenance_breakdown = [
            ProvenanceCount(provenance_tag=str(r[0]), event_count=int(r[1]))
            for r in prov_rows
        ]

        # Volume over time: hourly buckets × source (last 24h)
        vol_rows = client.query(
            """
            SELECT
                toStartOfHour(TimeGenerated) AS hour_bucket,
                ProvenanceTag,
                count() AS cnt
            FROM siemhunter.security_events
            WHERE TimeGenerated >= now64(3) - INTERVAL 24 HOUR
            GROUP BY hour_bucket, ProvenanceTag
            ORDER BY hour_bucket ASC, ProvenanceTag ASC
            """,
        ).result_rows
        volume_over_time: list[HourlyVolume] = []
        for r in vol_rows:
            val = r[0]
            if isinstance(val, datetime):
                if val.tzinfo is None:
                    val = val.replace(tzinfo=timezone.utc)
                hour_str = val.isoformat()
            else:
                hour_str = str(val)
            volume_over_time.append(
                HourlyVolume(
                    hour=hour_str,
                    provenance_tag=str(r[1]),
                    event_count=int(r[2]),
                )
            )

        # Pipeline latency: avg + p95 of (IngestTimestamp - TimeGenerated) in seconds
        # Both columns are DateTime64(3, 'UTC'), subtraction yields seconds as Float64
        lat_rows = client.query(
            """
            SELECT
                avg(
                    dateDiff('millisecond', TimeGenerated, IngestTimestamp)
                ) / 1000.0 AS avg_sec,
                quantile(0.95)(
                    dateDiff('millisecond', TimeGenerated, IngestTimestamp)
                ) / 1000.0 AS p95_sec
            FROM siemhunter.security_events
            WHERE TimeGenerated >= now64(3) - INTERVAL 24 HOUR
              AND IngestTimestamp >= TimeGenerated
            """,
        ).result_rows
        if lat_rows and lat_rows[0][0] is not None:
            pipeline_latency = PipelineLatency(
                avg_seconds=round(float(lat_rows[0][0]), 3),
                p95_seconds=round(float(lat_rows[0][1]), 3),
            )
        else:
            pipeline_latency = PipelineLatency(avg_seconds=None, p95_seconds=None)

        # Per-source stats: last_seen, events_per_hour, unmapped_nonempty_%
        src_stat_rows = client.query(
            """
            SELECT
                ProvenanceTag,
                MAX(TimeGenerated)                      AS last_seen,
                count() / 24.0                          AS events_per_hour,
                countIf(UnmappedFields != '') * 100.0
                    / count()                            AS unmapped_pct
            FROM siemhunter.security_events
            WHERE TimeGenerated >= now64(3) - INTERVAL 24 HOUR
            GROUP BY ProvenanceTag
            ORDER BY ProvenanceTag ASC
            """,
        ).result_rows
        per_source: list[PerSourceStat] = []
        for r in src_stat_rows:
            ls_val = r[1]
            if isinstance(ls_val, datetime):
                if ls_val.tzinfo is None:
                    ls_val = ls_val.replace(tzinfo=timezone.utc)
                ls_str: Optional[str] = ls_val.isoformat()
            elif ls_val is not None:
                ls_str = str(ls_val)
            else:
                ls_str = None
            per_source.append(
                PerSourceStat(
                    provenance_tag=str(r[0]),
                    last_seen=ls_str,
                    events_per_hour=round(float(r[2]), 2),
                    unmapped_nonempty_pct=round(float(r[3]), 2),
                )
            )

    except Exception as exc:
        log.error("ingestion_summary_query_failed", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "ClickHouse query failed", "code": "QUERY_ERROR"},
        )

    return IngestionSummaryResponse(
        provenance_breakdown=provenance_breakdown,
        volume_over_time=volume_over_time,
        pipeline_latency=pipeline_latency,
        per_source=per_source,
        rate_limit_flood_panel=None,
        rate_limit_flood_note=_SENTINEL_NOTE,
    )
