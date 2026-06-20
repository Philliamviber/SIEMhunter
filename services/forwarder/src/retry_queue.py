"""
On-disk retry queue for Sentinel forwarding.

Why a file-based queue?
------------------------
When the Sentinel Logs Ingestion API is temporarily unavailable (network outage,
429 rate limit exceeded, Azure maintenance window), the forwarder must not drop
detection hits. It persists failed batches as JSON files in a named Docker volume
(`forwarder_retry_queue`) so they survive container restarts.

The retry queue is checked and replayed at the START of every forward cycle,
before processing new detection_hits from ClickHouse. This "replay first" order
ensures that older failed batches are delivered before newer ones, preserving
approximate delivery order.

Backoff strategy
----------------
Each batch records the time of its next retry (`next_retry_at`) using exponential
backoff: 10 s, 20 s, 40 s, 80 s, 160 s, capped at 300 s (5 minutes). Batches
whose `next_retry_at` is in the future are skipped during `pending_batches()`.

The `retry_count` field tracks how many times a batch has been attempted. This
is used to compute the next backoff period and to detect batches that have
exceeded the maximum retry count (though the current forwarder does not enforce
an absolute abandonment policy — batches stay in the queue indefinitely until
they succeed or are manually removed).

Queue file format
-----------------
Each file is a JSON serialisation of a QueuedBatch dataclass. Files are named
`{batch_id}.json` where batch_id is a UUID. This naming prevents collisions
and makes individual batches easily inspectable:

  cat /app/retry_queue/<uuid>.json | python3 -m json.tool

Spec: instructions/07-sentinel-forwarding.md §2.4.
"""
from __future__ import annotations
import json
import os
import pathlib
import time
import uuid
from dataclasses import dataclass, asdict
from typing import Iterator

import structlog

log = structlog.get_logger(__name__)

_QUEUE_DIR = pathlib.Path(os.environ.get("RETRY_QUEUE_PATH", "/app/retry_queue"))


@dataclass
class QueuedBatch:
    batch_id: str
    table: str
    records: list[dict]
    retry_count: int
    queued_at: float
    next_retry_at: float


def _batch_path(batch_id: str) -> pathlib.Path:
    return _QUEUE_DIR / f"{batch_id}.json"


def enqueue(table: str, records: list[dict], retry_count: int = 0) -> str:
    """Persist a failed batch to the on-disk queue. Returns the batch_id.

    This function is called by the forwarder when send_logs() fails after
    all in-process retries (the _MAX_RETRIES limit in main.py) are exhausted.
    It is also called when replaying a queued batch fails again.

    Args:
        table: The Sentinel custom table name (e.g., "SIEMHunterSecurity_CL").
        records: The list of log records that failed to send.
        retry_count: The number of times this batch has already been attempted.
                     Used to compute the exponential backoff for next_retry_at.

    Returns:
        The batch_id UUID string (also the basename of the queue file).
    """
    _QUEUE_DIR.mkdir(parents=True, exist_ok=True)
    batch_id = str(uuid.uuid4())
    now = time.time()
    # Exponential backoff: 10s, 20s, 40s, 80s, 160s, capped at 300s (5 min).
    # Formula: min(300, 10 × 2^retry_count)
    # retry_count=0 → 10s, retry_count=1 → 20s, ..., retry_count=5 → 300s
    backoff = min(300, 10 * (2 ** retry_count))

    batch = QueuedBatch(
        batch_id=batch_id,
        table=table,
        records=records,
        retry_count=retry_count,
        queued_at=now,
        next_retry_at=now + backoff,
    )
    _batch_path(batch_id).write_text(json.dumps(asdict(batch), default=str))
    log.warning("batch_queued_for_retry", batch_id=batch_id, table=table,
                count=len(records), retry_count=retry_count, next_retry_in_s=backoff)
    return batch_id


def pending_batches() -> Iterator[QueuedBatch]:
    """Yield queued batches whose next_retry_at has passed."""
    if not _QUEUE_DIR.exists():
        return
    now = time.time()
    for path in sorted(_QUEUE_DIR.glob("*.json")):
        try:
            data = json.loads(path.read_text())
            if data.get("next_retry_at", 0) <= now:
                yield QueuedBatch(**data)
        except Exception as exc:
            log.error("queue_read_error", path=str(path), error=str(exc))


def remove(batch_id: str) -> None:
    """Remove a successfully replayed batch from the queue."""
    p = _batch_path(batch_id)
    if p.exists():
        p.unlink()
        log.debug("batch_removed_from_queue", batch_id=batch_id)
