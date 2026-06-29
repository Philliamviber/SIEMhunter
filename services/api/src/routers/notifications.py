"""
GET /v1/analyst/notifications — new high/critical detection hits since last seen.

Authentication: analyst session ONLY (require_analyst_session). Stores and
advances a per-analyst 'notifications_last_seen_at' marker in the analyst KV
store so each analyst has an independent cursor.

On the first call for an analyst (no stored marker) the marker is initialised
to the current UTC time and new_count=0 is returned, preventing a flood of
historical hits on first login. Subsequent calls return hits that arrived
after the previous marker.

The marker is advanced to 'now' on every successful ClickHouse query so that
consecutive polls drive the cursor forward without requiring a separate
mark-seen endpoint.
"""
from __future__ import annotations

from datetime import datetime, timezone

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from ..auth_analyst import require_analyst_session, _Session
from .. import db_analyst_prefs
from ..clickhouse_client import get_client

log = structlog.get_logger(__name__)
router = APIRouter()

MARKER_KEY = "notifications_last_seen_at"


class NotificationsResponse(BaseModel):
    new_count: int
    has_new: bool
    checked_at: str  # ISO-8601 UTC timestamp of this check


@router.get("/analyst/notifications", response_model=NotificationsResponse)
async def get_notifications(
    sess: _Session = Depends(require_analyst_session),
) -> NotificationsResponse:
    """Return new high/critical hit count since the analyst's last-seen marker.

    The marker is advanced to now on each successful query so polling this
    endpoint drives the cursor forward. On the analyst's first call the marker
    is initialised to now and new_count=0 is returned.
    """
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()

    try:
        stored = db_analyst_prefs.get_value(sess.username, MARKER_KEY)
    except Exception as exc:
        log.error("notifications_read_marker_failed", username=sess.username, error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "Failed to read notification marker", "code": "DB_ERROR"},
        )

    if stored is None:
        # First call: initialise to now, return zero new hits.
        try:
            db_analyst_prefs.set_value(sess.username, MARKER_KEY, now_iso)
        except Exception as exc:
            log.warning("notifications_set_initial_marker_failed", username=sess.username, error=str(exc))
        return NotificationsResponse(new_count=0, has_new=False, checked_at=now_iso)

    try:
        since_dt = datetime.fromisoformat(stored.replace("Z", "+00:00"))
        if since_dt.tzinfo is None:
            since_dt = since_dt.replace(tzinfo=timezone.utc)
    except ValueError:
        # Corrupted marker: reset to now, return zero.
        log.warning("notifications_corrupt_marker", username=sess.username, stored=stored)
        try:
            db_analyst_prefs.set_value(sess.username, MARKER_KEY, now_iso)
        except Exception:
            pass
        return NotificationsResponse(new_count=0, has_new=False, checked_at=now_iso)

    try:
        client = get_client()
        rows = client.query(
            """
            SELECT count()
            FROM siemhunter.detection_hits
            WHERE severity IN ('high', 'critical')
              AND created_at > {since_dt:DateTime64(3)}
            """,
            parameters={"since_dt": since_dt},
        ).result_rows
        new_count = int(rows[0][0]) if rows else 0
    except Exception as exc:
        log.error("notifications_ch_query_failed", username=sess.username, error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "ClickHouse query failed", "code": "QUERY_ERROR"},
        )

    # Advance the marker to now. Non-fatal if this fails.
    try:
        db_analyst_prefs.set_value(sess.username, MARKER_KEY, now_iso)
    except Exception as exc:
        log.warning("notifications_advance_marker_failed", username=sess.username, error=str(exc))

    return NotificationsResponse(
        new_count=new_count,
        has_new=new_count > 0,
        checked_at=now_iso,
    )
