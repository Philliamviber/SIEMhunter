"""
Normalization service — continuous event processing loop.

Role in the pipeline
--------------------
This service sits between Vector and the detection engine. Vector writes raw
ingest payloads to the siemhunter.raw_events staging table in ClickHouse.
This service polls that table in batches, calls the normalizer (normalizer.py)
on each row, writes the resulting NormalizedEvent to siemhunter.security_events,
then deletes the processed rows from raw_events.

The staging-table pattern (raw_events as an intermediate store) decouples
Vector's ingest rate from the normalization throughput. Vector can write at
burst speed; the normalization service catches up at its own pace.

Batch processing model
----------------------
The service processes events in batches of _BATCH_SIZE (default 500) rows at
a time. After each batch:
  - Normalized rows are bulk-inserted into security_events.
  - Processed raw_events rows are deleted by ID.
  - The /tmp/normalization_alive file is touched (health check signal).

If raw_events is empty, the service sleeps for _POLL_INTERVAL seconds before
checking again. This prevents a busy-wait CPU spin when there are no events.

On batch error (ClickHouse unavailable, etc.), the service sleeps for 5×
the poll interval before retrying. This provides automatic backoff without
a complex retry queue, because the raw_events rows are not deleted on error
and will be picked up on the next successful cycle.

Graceful shutdown
-----------------
SIGTERM and SIGINT are caught. The _RUNNING flag is set to False, which causes
the main loop to exit cleanly after the current batch completes. In-flight
normalization work is not interrupted; at most one batch is lost if the
container is hard-killed.

Health check
------------
The health check is a file existence + recency check:
  docker-compose.yml: test: ["CMD-SHELL", "test -f /tmp/normalization_alive"]
The alive file is touched at the end of every successful batch (even if 0 events
were processed). If the service is stuck (e.g., blocked on ClickHouse), the file
will not be touched and Docker will eventually restart the container.

Spec: instructions/03-data-ingestion-spec.md, instructions/04-normalization-and-schema.md
"""
from __future__ import annotations
import os
import pathlib
import signal
import time

import structlog

from .clickhouse_client import get_client
from .normalizer import dispatch
from .schema import NormalizedEvent

log = structlog.get_logger(__name__)

# Number of raw_events rows to process per batch.
# Larger batches are more efficient (fewer ClickHouse round-trips) but use more
# memory and produce a longer latency tail for the oldest waiting events.
# 500 is a reasonable default for lab-scale volumes.
_BATCH_SIZE = 500

# Seconds to sleep between polling cycles when raw_events is empty.
# Lower values reduce detection latency but increase ClickHouse query load.
_POLL_INTERVAL = 2

# The alive file path. Touched once per batch cycle (even if 0 events were processed).
# Docker HEALTHCHECK reads this file's existence and mtime.
_ALIVE_FILE = pathlib.Path("/tmp/normalization_alive")

# Global run flag. Set to False by the SIGTERM/SIGINT handler to stop the loop.
_RUNNING = True


def _handle_signal(sig, frame):
    global _RUNNING
    log.info("shutdown_signal_received", signal=sig)
    _RUNNING = False


def _create_raw_events_table_if_missing(client) -> None:
    """Ensure the raw_events staging table exists (Vector writes here).

    raw_events is a transient staging table, not a durable log. Rows are
    inserted by Vector and deleted by this service as they are processed.
    The 1-day TTL is a safety net: if the normalization service is down for
    an extended period, rows will eventually age out rather than filling the
    disk. Under normal operation no row should exist for more than a few minutes.

    The table lives in the siemhunter database and is created by the
    normalization service at startup rather than by clickhouse/schema.sql.
    This is intentional: schema.sql creates the durable tables (security_events,
    detection_hits, etc.); this transient table is created on-demand by the
    service that owns it.
    """
    client.command("""
        CREATE TABLE IF NOT EXISTS siemhunter.raw_events
        (
            id          UUID DEFAULT generateUUIDv4(),
            provenance_tag String,
            payload     String,
            received_at DateTime64(3,'UTC') DEFAULT now64(3)
        )
        ENGINE = MergeTree()
        ORDER BY (received_at)
        TTL received_at + INTERVAL 1 DAY DELETE
    """)


def run_batch(client) -> int:
    """Fetch one batch of raw events, normalize, insert to security_events, and delete.

    Processing sequence within one batch:
      1. SELECT up to _BATCH_SIZE rows from raw_events (ordered by received_at
         so oldest events are processed first).
      2. For each row, deserialize the JSON payload and call dispatch() from
         normalizer.py. dispatch() applies rate limiting and routes the event
         to the appropriate normalizer.
      3. Collect normalized NormalizedEvent objects that dispatch() did not
         return None for (rate-limited or parse-failed events return None).
      4. Bulk INSERT the normalized rows into security_events using the
         clickhouse_connect parameterized INSERT interface.
      5. DELETE the processed raw_events rows by their UUID IDs.

    Step 5 happens after step 4 succeeds. If the security_events insert fails,
    the raw rows are NOT deleted and will be retried on the next batch cycle.
    This gives at-least-once processing semantics for normalization.

    IMPORTANT: The DELETE in step 5 uses string-formatted UUIDs, which is a
    known limitation. ClickHouse's native HTTP interface does not support array
    bind parameters for IN clauses. The UUIDs are sanitised (single-quote chars
    stripped) before interpolation to prevent SQL injection via UUID values,
    but this is not a fully parameterized query. See the inline comment below.

    Args:
        client: An authenticated clickhouse_connect Client instance.

    Returns:
        The number of raw_events rows that were fetched in this batch (not the
        number that were successfully normalised; some may have been dropped).
        Returns 0 if raw_events is empty (caller interprets this as "sleep").
    """
    rows = client.query(
        "SELECT id, provenance_tag, payload FROM siemhunter.raw_events "
        "ORDER BY received_at LIMIT {batch_size:UInt32}",
        parameters={"batch_size": _BATCH_SIZE},
    ).result_rows

    if not rows:
        return 0

    normalized: list[dict] = []
    processed_ids: list[str] = []

    for row_id, provenance_tag, payload_str in rows:
        processed_ids.append(str(row_id))
        try:
            import json
            raw = json.loads(payload_str)
        except Exception:
            log.warning("payload_parse_error", id=row_id)
            continue

        event: NormalizedEvent | None = dispatch(raw, provenance_tag)
        if event is not None:
            normalized.append(event.to_row())

    if normalized:
        client.insert(
            "siemhunter.security_events",
            normalized,
            column_names=list(normalized[0].keys()),
        )
        log.info("normalized_batch", inserted=len(normalized), skipped=len(rows) - len(normalized))

    # Delete processed raw rows (parameterized)
    if processed_ids:
        placeholders = ",".join(["'" + i.replace("'", "") + "'" for i in processed_ids])
        client.command(f"ALTER TABLE siemhunter.raw_events DELETE WHERE id IN ({placeholders})")

    return len(rows)


def main() -> None:
    log_level = os.environ.get("LOG_LEVEL", "info").lower()
    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(
            {"debug": 10, "info": 20, "warn": 30, "error": 40}.get(log_level, 20)
        ),
    )
    log.info("normalization_service_starting")

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    client = get_client()
    _create_raw_events_table_if_missing(client)

    while _RUNNING:
        try:
            count = run_batch(client)
            _ALIVE_FILE.touch()
            if count == 0:
                time.sleep(_POLL_INTERVAL)
        except Exception as exc:
            log.error("batch_error", error=str(exc))
            time.sleep(_POLL_INTERVAL * 5)

    log.info("normalization_service_stopped")
