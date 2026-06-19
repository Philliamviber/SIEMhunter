"""
On-disk retry queue for Sentinel forwarding.
Spec: instructions/07-sentinel-forwarding.md §2.4.

When Logs Ingestion API returns 429 or a transient error after max_retries,
the batch is serialised to the retry_queue directory.
The main loop replays queued batches before processing new events.
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
    """Persist a failed batch to the on-disk queue. Returns the batch_id."""
    _QUEUE_DIR.mkdir(parents=True, exist_ok=True)
    batch_id = str(uuid.uuid4())
    now = time.time()
    backoff = min(300, 10 * (2 ** retry_count))    # exponential backoff; cap at 300s

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
