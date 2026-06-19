"""
Normalization service main loop.
Reads raw events written by Vector to the ClickHouse raw_events table,
normalizes each event to OCSF (security_events), and deletes the raw row.

Runs continuously. Writes /tmp/normalization_alive as a health check flag.
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

_BATCH_SIZE = 500
_POLL_INTERVAL = 2       # seconds between polling cycles
_ALIVE_FILE = pathlib.Path("/tmp/normalization_alive")
_RUNNING = True


def _handle_signal(sig, frame):
    global _RUNNING
    log.info("shutdown_signal_received", signal=sig)
    _RUNNING = False


def _create_raw_events_table_if_missing(client) -> None:
    """Ensure the raw_events staging table exists (Vector writes here)."""
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
    """Fetch a batch of raw events, normalize them, insert into security_events."""
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
