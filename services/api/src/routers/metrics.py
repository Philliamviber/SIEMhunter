"""
GET /v1/metrics — aggregated pipeline KPI endpoint.

Returns the key metrics the dashboard Overview page needs:
  - events_by_source: security_events count GROUP BY ProvenanceTag over last 24h
  - detection_hits_24h: total detection_hits in last 24h
  - anomaly_score_distribution: histogram buckets of detection_hits.anomaly_score (24h)
  - last_batch_run_at: MAX(created_at) from detection_hits
  - last_batch_duration_seconds: null (no local batch-duration table; not faked)

Authentication: required (bearer token).
Spec: instructions/06-api-control-plane.md §3 / changelog2.md Phase 1.
"""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from ..auth import verify_token
from ..clickhouse_client import get_client

log = structlog.get_logger(__name__)
router = APIRouter()


# ── Response models ───────────────────────────────────────────────────────────

class SourceCount(BaseModel):
    provenance_tag: str
    event_count: int


class AnomalyBucket(BaseModel):
    bucket_label: str   # e.g. "0.0–0.1"
    count: int


class MetricsResponse(BaseModel):
    events_by_source: list[SourceCount]
    detection_hits_24h: int
    anomaly_score_distribution: Optional[list[AnomalyBucket]]
    last_batch_run_at: Optional[str]       # ISO-8601 UTC
    last_batch_duration_seconds: None      # always null — no local table for this


# ── Helpers ───────────────────────────────────────────────────────────────────

def _build_anomaly_buckets(rows: list) -> Optional[list[AnomalyBucket]]:
    """Convert (bucket_index, count) rows into labelled histogram buckets."""
    if not rows:
        return None
    # 10 buckets: 0.0–0.1, 0.1–0.2, … 0.9–1.0
    labels = [f"{i/10:.1f}–{(i+1)/10:.1f}" for i in range(10)]
    result = []
    counts_by_idx: dict[int, int] = {int(r[0]): int(r[1]) for r in rows}
    for i, label in enumerate(labels):
        cnt = counts_by_idx.get(i, 0)
        result.append(AnomalyBucket(bucket_label=label, count=cnt))
    return result


# ── Endpoint ──────────────────────────────────────────────────────────────────

@router.get("/metrics", response_model=MetricsResponse)
async def get_metrics(
    _: None = Depends(verify_token),
) -> MetricsResponse:
    """Return aggregated pipeline KPIs for the last 24 hours."""
    try:
        client = get_client()

        # events_by_source: GROUP BY ProvenanceTag over last 24h
        src_rows = client.query(
            """
            SELECT ProvenanceTag, count() AS event_count
            FROM siemhunter.security_events
            WHERE TimeGenerated >= now64(3) - INTERVAL 24 HOUR
            GROUP BY ProvenanceTag
            ORDER BY event_count DESC
            """,
        ).result_rows

        events_by_source = [
            SourceCount(provenance_tag=str(r[0]), event_count=int(r[1]))
            for r in src_rows
        ]

        # detection_hits_24h: total count in last 24h
        hits_rows = client.query(
            """
            SELECT count() AS cnt
            FROM siemhunter.detection_hits
            WHERE created_at >= now64(3) - INTERVAL 24 HOUR
            """,
        ).result_rows
        detection_hits_24h = int(hits_rows[0][0]) if hits_rows else 0

        # anomaly_score_distribution: histogram in 0.1-wide buckets over last 24h
        anon_rows = client.query(
            """
            SELECT
                floor(anomaly_score * 10) AS bucket_index,
                count() AS cnt
            FROM siemhunter.detection_hits
            WHERE created_at >= now64(3) - INTERVAL 24 HOUR
              AND anomaly_score >= 0
            GROUP BY bucket_index
            ORDER BY bucket_index
            """,
        ).result_rows
        anomaly_score_distribution = _build_anomaly_buckets(anon_rows)

        # last_batch_run_at: MAX(created_at)
        max_rows = client.query(
            """
            SELECT MAX(created_at)
            FROM siemhunter.detection_hits
            """,
        ).result_rows
        last_batch_run_at: Optional[str] = None
        if max_rows and max_rows[0][0] is not None:
            val = max_rows[0][0]
            if isinstance(val, datetime):
                if val.tzinfo is None:
                    val = val.replace(tzinfo=timezone.utc)
                last_batch_run_at = val.isoformat()
            else:
                last_batch_run_at = str(val)

    except Exception as exc:
        log.error("metrics_query_failed", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "ClickHouse query failed", "code": "QUERY_ERROR"},
        )

    return MetricsResponse(
        events_by_source=events_by_source,
        detection_hits_24h=detection_hits_24h,
        anomaly_score_distribution=anomaly_score_distribution,
        last_batch_run_at=last_batch_run_at,
        last_batch_duration_seconds=None,   # no local source for this; never faked
    )
