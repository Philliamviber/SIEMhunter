"""
Detection service — batch scheduler.
Spec: instructions/05-detection-and-anomaly.md §1, instructions/08-deployment-hybrid.md §1.

Schedule: runs every DETECTION_INTERVAL_SECONDS (default 900 = 15 min).
Writes /tmp/detection_alive as health check proof-of-life.
"""
from __future__ import annotations
import os
import pathlib
import signal
import sys
import time
from datetime import datetime, timezone, timedelta

import structlog

from .clickhouse_client import get_client
from .compiler import compile_rules
from .ml_scorer import load_models
from .runner import run_detection_batch, insert_hits

log = structlog.get_logger(__name__)

_INTERVAL = int(os.environ.get("DETECTION_INTERVAL_SECONDS", "900"))
_SIGMA_PIPELINE = os.environ.get("SIGMA_PIPELINE", "/app/rules/pipelines/clickhouse-asim-ocsf.yaml")
_RULES_DIR = os.environ.get("RULES_DIR", "/app/rules/local")
_ALIVE_FILE = pathlib.Path("/tmp/detection_alive")
_RUNNING = True


def _handle_signal(sig, frame):
    global _RUNNING
    log.info("shutdown_signal_received", signal=sig)
    _RUNNING = False


def _read_secret(path: str) -> str:
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError as exc:
        raise RuntimeError(f"Secret missing: {path}: {exc}") from exc


def _import_clickhouse_client():
    from .clickhouse_client import get_client as _get
    return _get()


def main() -> None:
    log_level = os.environ.get("LOG_LEVEL", "info").lower()
    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(
            {"debug": 10, "info": 20, "warn": 30, "error": 40}.get(log_level, 20)
        ),
    )

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    log.info("detection_service_starting", interval=_INTERVAL, rules_dir=_RULES_DIR)

    client = get_client()
    load_models()

    # Compile rules at startup; recompile on each cycle so operators can
    # hot-update rules without restarting the container.
    last_compile = 0.0
    compiled_rules = []

    while _RUNNING:
        cycle_start = time.monotonic()

        try:
            # Recompile every cycle to pick up rule changes
            compiled_rules = compile_rules(_RULES_DIR, _SIGMA_PIPELINE)
        except RuntimeError as exc:
            log.error("rule_compilation_failed", error=str(exc))
            time.sleep(60)
            continue

        now = datetime.now(timezone.utc)
        batch_end = now.strftime("%Y-%m-%d %H:%M:%S.000")
        batch_start = (now - timedelta(seconds=_INTERVAL)).strftime("%Y-%m-%d %H:%M:%S.000")

        log.info("detection_batch_start", batch_start=batch_start, batch_end=batch_end,
                 rule_count=len(compiled_rules))

        try:
            hits = run_detection_batch(client, compiled_rules, batch_start, batch_end)
            insert_hits(client, hits)
            _ALIVE_FILE.touch()
        except Exception as exc:
            log.error("batch_execution_error", error=str(exc))

        elapsed = time.monotonic() - cycle_start
        sleep_for = max(0, _INTERVAL - elapsed)
        log.info("detection_batch_complete", elapsed_seconds=round(elapsed, 1),
                 sleep_seconds=round(sleep_for, 1))

        if sleep_for > 0 and _RUNNING:
            time.sleep(sleep_for)

    log.info("detection_service_stopped")
