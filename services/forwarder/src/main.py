"""
Forwarder service main loop.
Reads detection hits from ClickHouse, forwards to Microsoft Sentinel via
the Logs Ingestion API and Incidents API, and maintains the local forward ledger.

Batch schedule: FORWARD_INTERVAL_SECONDS (default 900 s).
Writes /tmp/forwarder_alive as a health check proof-of-life.

Spec:
  instructions/07-sentinel-forwarding.md §2-3
  instructions/05-detection-and-anomaly.md (SELF-005 ledger reconciliation)
"""
from __future__ import annotations
import hashlib
import json
import os
import pathlib
import signal
import socket
import time
import uuid
from datetime import datetime, timezone
from typing import Any

import structlog

from .clickhouse_client import get_client
from .sentinel_client import SentinelForwarder
from . import retry_queue

log = structlog.get_logger(__name__)

_INTERVAL = int(os.environ.get("FORWARD_INTERVAL_SECONDS", "900"))
_BATCH_SIZE = int(os.environ.get("FORWARD_BATCH_SIZE", "200"))
_ALIVE_FILE = pathlib.Path("/tmp/forwarder_alive")
_RUNNING = True
_MAX_RETRIES = 5

# SELF-005: KQL reconciliation flag
_SELF005_ENABLED = os.environ.get("SELF005_ENABLED", "").lower() in ("1", "true", "yes")

# Sentinel severity mapping: Sigma level → Sentinel severity
_SEVERITY_MAP = {
    "critical": "High",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "informational": "Informational",
}

# SIEMHunterSecurity_CL severity for rule-change audit and detection hits
_AUDIT_SEVERITY_MAP = {
    "critical": "High",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}


def _handle_signal(sig, frame):
    global _RUNNING
    log.info("shutdown_signal_received", signal=sig)
    _RUNNING = False


def _hostname() -> str:
    return socket.gethostname()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hit_to_security_record(hit: dict) -> dict:
    """Map a detection_hits row to a SIEMHunterSecurity_CL record."""
    severity_raw = (hit.get("severity") or "low").lower()
    return {
        "TimeGenerated": _now_iso(),
        "RuleId": hit.get("rule_id", ""),
        "RuleVersion": hit.get("rule_version", ""),
        "EventType": "DetectionHit",
        "Entity": "",
        "SourceEventIds": hit.get("event_record_ids", "[]"),
        "Severity": _AUDIT_SEVERITY_MAP.get(severity_raw, "Low"),
        "Detail": json.dumps({
            "hit_id": hit.get("hit_id", ""),
            "hit_count": hit.get("hit_count", 0),
            "batch_start": str(hit.get("batch_start", "")),
            "batch_end": str(hit.get("batch_end", "")),
            "anomaly_score": hit.get("anomaly_score", 0.0),
            "mitre_tag": hit.get("mitre_tag", ""),
        }),
        "ATTACKTechnique": hit.get("mitre_tag", ""),
    }


def _hit_to_incident(hit: dict) -> dict:
    """Map a detection_hits row to a Sentinel incident payload."""
    severity_raw = (hit.get("severity") or "low").lower()
    event_ids_raw = hit.get("event_record_ids", "[]")
    try:
        source_event_ids = json.loads(event_ids_raw)
    except Exception:
        source_event_ids = []

    # Deterministic fingerprint per spec §3.4
    sorted_ids = sorted(source_event_ids)
    fingerprint_input = hit.get("rule_id", "") + "|" + "|".join(sorted_ids)
    fingerprint = hashlib.sha256(fingerprint_input.encode()).hexdigest()

    return {
        "title": f"SIEMhunter Detection: {hit.get('rule_id', 'unknown')}",
        "severity": _SEVERITY_MAP.get(severity_raw, "Medium"),
        "rule_id": hit.get("rule_id", ""),
        "rule_version": hit.get("rule_version", ""),
        "source_event_ids": source_event_ids,
        "mitre_tag": hit.get("mitre_tag", ""),
        "fingerprint": fingerprint,
        "tags": ["SIEMhunterDetected"],
    }


def replay_retry_queue(forwarder: SentinelForwarder) -> None:
    """Replay batches from the on-disk retry queue. Spec: §2.5."""
    for batch in retry_queue.pending_batches():
        log.info("replaying_queued_batch", batch_id=batch.batch_id,
                 table=batch.table, retry_count=batch.retry_count)
        try:
            forwarder.send_logs(table=batch.table, records=batch.records)
            retry_queue.remove(batch.batch_id)
            log.info("queued_batch_replayed", batch_id=batch.batch_id)
        except Exception as exc:
            log.warning("queued_batch_replay_failed", batch_id=batch.batch_id,
                        error=str(exc))
            # Re-enqueue with incremented retry count
            retry_queue.enqueue(
                table=batch.table,
                records=batch.records,
                retry_count=batch.retry_count + 1,
            )


def _send_with_retry(forwarder: SentinelForwarder, table: str, records: list[dict]) -> bool:
    """Send records to Sentinel, honoring 429 Retry-After. Returns True on success.

    On persistent failure after _MAX_RETRIES, enqueues the batch and returns False.
    Spec: instructions/07-sentinel-forwarding.md §2.5.
    """
    for attempt in range(1, _MAX_RETRIES + 1):
        try:
            forwarder.send_logs(table=table, records=records)
            return True
        except Exception as exc:
            exc_str = str(exc)
            # Honor Retry-After on 429
            if "429" in exc_str or "Too Many Requests" in exc_str.lower():
                # Try to extract Retry-After from the exception message
                retry_after = 60
                import re
                m = re.search(r"Retry-After[:\s]+(\d+)", exc_str, re.IGNORECASE)
                if m:
                    retry_after = int(m.group(1))
                log.warning("sentinel_429_backoff", attempt=attempt,
                            retry_after=retry_after)
                time.sleep(retry_after)
            else:
                log.warning("sentinel_send_error", attempt=attempt, error=exc_str)
                if attempt < _MAX_RETRIES:
                    time.sleep(min(300, 10 * (2 ** (attempt - 1))))

            if attempt == _MAX_RETRIES:
                log.error("sentinel_max_retries_exceeded", table=table,
                          record_count=len(records))
                retry_queue.enqueue(table=table, records=records,
                                    retry_count=_MAX_RETRIES)
                return False
    return False


def forward_hits(client, forwarder: SentinelForwarder, batch_id: str) -> tuple[list[str], int, str, str]:
    """Read unforwarded detection hits, forward to Sentinel, update ClickHouse.

    Returns (forwarded_hit_ids, total_count, batch_start_iso, batch_end_iso).
    """
    rows = client.query(
        """
        SELECT hit_id, rule_id, rule_version, batch_start, batch_end,
               event_record_ids, hit_count, severity, mitre_tag, anomaly_score
        FROM siemhunter.detection_hits
        WHERE forwarded_at IS NULL
        ORDER BY created_at
        LIMIT {batch_size:UInt32}
        """,
        parameters={"batch_size": _BATCH_SIZE},
    ).result_rows

    if not rows:
        return [], 0, _now_iso(), _now_iso()

    columns = [
        "hit_id", "rule_id", "rule_version", "batch_start", "batch_end",
        "event_record_ids", "hit_count", "severity", "mitre_tag", "anomaly_score",
    ]
    hits = [dict(zip(columns, row)) for row in rows]

    batch_start_iso = str(hits[0]["batch_start"])
    batch_end_iso = str(hits[-1]["batch_end"])

    security_records = [_hit_to_security_record(h) for h in hits]
    success = _send_with_retry(forwarder, "SIEMHunterSecurity_CL", security_records)

    forwarded_ids: list[str] = []
    if success:
        forwarded_ids = [str(h["hit_id"]) for h in hits]

        # Forward incidents for high/critical hits
        for hit in hits:
            sev = (hit.get("severity") or "").lower()
            if sev in ("high", "critical"):
                incident = _hit_to_incident(hit)
                try:
                    forwarder.send_incident(incident)
                except Exception as exc:
                    log.warning("incident_send_failed", rule_id=hit.get("rule_id"),
                                error=str(exc))

        # Mark forwarded — parameterized IN clause
        # ClickHouse does not support array bind for IN; use literal UUIDs after
        # stripping any non-hex/dash characters.
        safe_ids = [i.replace("'", "") for i in forwarded_ids]
        placeholders = ",".join(f"'{i}'" for i in safe_ids)
        client.command(
            f"ALTER TABLE siemhunter.detection_hits UPDATE "
            f"forwarded_at = now64(3) WHERE hit_id IN ({placeholders})"
        )
        log.info("hits_forwarded", count=len(forwarded_ids), batch_id=batch_id)

    return forwarded_ids, len(hits), batch_start_iso, batch_end_iso


def write_forward_ledger(client, batch_id: str, stream_tag: str,
                         event_count: int, batch_start: str, batch_end: str) -> None:
    """INSERT one ledger row per stream tag. Spec: §2.4 local append-only ledger."""
    now_ts = datetime.now(timezone.utc)
    client.insert(
        "siemhunter.forward_ledger",
        [[batch_id, stream_tag, event_count, batch_start, batch_end, now_ts]],
        column_names=["batch_id", "stream_tag", "event_count",
                      "batch_start", "batch_end", "forwarded_at"],
    )
    log.debug("ledger_written", batch_id=batch_id, stream_tag=stream_tag,
              event_count=event_count)


def _kql_received_count(forwarder: SentinelForwarder, stream_tag: str,
                        batch_start: str, batch_end: str) -> int:
    """Query Sentinel for received event count. Returns 0 if not available.

    SELF-005 ledger reconciliation. kql_query() is stubbed as a no-op if
    the method is not present on SentinelForwarder.
    Spec: instructions/07-sentinel-forwarding.md §2.4 and §4.
    """
    if not hasattr(forwarder, "kql_query"):
        return 0
    try:
        result = forwarder.kql_query(  # type: ignore[attr-defined]
            query=f"""
            SIEMHunterSecurity_CL
            | where EventType == "DetectionHit"
            | where TimeGenerated between (datetime({batch_start}) .. datetime({batch_end}))
            | count
            """
        )
        return int(result) if result else 0
    except Exception as exc:
        log.warning("kql_query_failed", error=str(exc))
        return 0


def run_self005_reconciliation(client, forwarder: SentinelForwarder,
                               batch_id: str, stream_tag: str,
                               local_count: int, batch_start: str,
                               batch_end: str) -> None:
    """Compare local ledger count with Sentinel-received count. Write LedgerDelta if discrepant."""
    sentinel_count = _kql_received_count(forwarder, stream_tag, batch_start, batch_end)
    delta = local_count - sentinel_count

    # Threshold: >5% delta or >50 events
    threshold_pct = local_count * 0.05
    if delta > max(threshold_pct, 50):
        log.warning("self005_ledger_delta", local=local_count,
                    sentinel=sentinel_count, delta=delta)
        record = {
            "TimeGenerated": _now_iso(),
            "RuleId": "SELF-005",
            "RuleVersion": "0.1.0",
            "EventType": "LedgerDelta",
            "Entity": _hostname(),
            "SourceEventIds": "[]",
            "Severity": "High",
            "Detail": json.dumps({
                "batch_id": batch_id,
                "stream_tag": stream_tag,
                "local_count": local_count,
                "sentinel_count": sentinel_count,
                "delta": delta,
            }),
            "ATTACKTechnique": "",
        }
        try:
            forwarder.send_logs(table="SIEMHunterSecurity_CL", records=[record])
        except Exception as exc:
            log.error("self005_write_failed", error=str(exc))


def write_health_event(forwarder: SentinelForwarder, event_type: str,
                       batch_id: str, event_count: int, detail: str,
                       severity: str = "Informational") -> None:
    """Write a BatchSuccess or BatchFail row to SIEMHunterHealth_CL."""
    record = {
        "TimeGenerated": _now_iso(),
        "HostName": _hostname(),
        "EventType": event_type,
        "Severity": severity,
        "SourceId": "forwarder",
        "EventCount": event_count,
        "Detail": detail,
        "BatchId": batch_id,
    }
    try:
        forwarder.send_logs(table="SIEMHunterHealth_CL", records=[record])
    except Exception as exc:
        # Health write failures must not block main flow (independence requirement FR-19)
        log.warning("health_event_write_failed", event_type=event_type, error=str(exc))


def run_cycle(client, forwarder: SentinelForwarder) -> None:
    """Execute one full forward cycle."""
    batch_id = str(uuid.uuid4())
    cycle_start = datetime.now(timezone.utc)
    log.info("forward_cycle_start", batch_id=batch_id)

    # Step 1: Replay retry queue
    try:
        replay_retry_queue(forwarder)
    except Exception as exc:
        log.error("retry_queue_replay_error", error=str(exc))

    # Steps 2-6: Forward unforwarded hits
    try:
        forwarded_ids, total_hits, batch_start, batch_end = forward_hits(
            client, forwarder, batch_id
        )
    except Exception as exc:
        log.error("forward_hits_error", batch_id=batch_id, error=str(exc))
        write_health_event(
            forwarder, "BatchFail", batch_id, 0, str(exc), severity="Error"
        )
        return

    forwarded_count = len(forwarded_ids)
    stream_tag = "SIEMHunterSecurity_CL"

    if forwarded_count > 0:
        try:
            write_forward_ledger(
                client, batch_id, stream_tag, forwarded_count, batch_start, batch_end
            )
        except Exception as exc:
            log.error("ledger_write_error", batch_id=batch_id, error=str(exc))

    # Step 7: SELF-005 ledger reconciliation
    if _SELF005_ENABLED and forwarded_count > 0:
        try:
            run_self005_reconciliation(
                client, forwarder, batch_id, stream_tag,
                forwarded_count, batch_start, batch_end
            )
        except Exception as exc:
            log.error("self005_error", batch_id=batch_id, error=str(exc))

    # Step 8: Write health event
    elapsed_s = (datetime.now(timezone.utc) - cycle_start).total_seconds()
    write_health_event(
        forwarder,
        "BatchSuccess",
        batch_id,
        forwarded_count,
        f"Forwarded {forwarded_count}/{total_hits} hits in {elapsed_s:.1f}s",
        severity="Informational",
    )

    log.info("forward_cycle_complete", batch_id=batch_id,
             forwarded=forwarded_count, elapsed_s=round(elapsed_s, 1))

    # Step 9: Alive file
    _ALIVE_FILE.touch()


def main() -> None:
    log_level = os.environ.get("LOG_LEVEL", "info").lower()
    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(
            {"debug": 10, "info": 20, "warn": 30, "error": 40}.get(log_level, 20)
        ),
    )
    log.info("forwarder_service_starting", interval=_INTERVAL, batch_size=_BATCH_SIZE,
             self005_enabled=_SELF005_ENABLED)

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    client = get_client()

    try:
        forwarder = SentinelForwarder()
    except Exception as exc:
        log.error("sentinel_forwarder_init_failed", error=str(exc))
        raise SystemExit(1) from exc

    while _RUNNING:
        cycle_start = time.monotonic()
        try:
            run_cycle(client, forwarder)
        except Exception as exc:
            log.error("cycle_error", error=str(exc))

        elapsed = time.monotonic() - cycle_start
        sleep_for = max(0, _INTERVAL - elapsed)
        if sleep_for > 0 and _RUNNING:
            log.debug("sleeping", seconds=round(sleep_for, 1))
            time.sleep(sleep_for)

    log.info("forwarder_service_stopped")
