"""
SQLite-backed incident store for SIEMhunter.

The incidents table is intentionally separate from ClickHouse security_events.
DB path is configurable via INCIDENTS_DB_PATH env var; the directory is
created automatically if it does not exist.

Schema note: incident metadata is stored here only — never in security_events.
"""
from __future__ import annotations

import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(os.getenv("INCIDENTS_DB_PATH", "/data/siemhunter_incidents.db"))

_VALID_SEVERITIES = {"low", "medium", "high", "critical"}
_VALID_STATUSES = {"open", "closed", "archived"}


def _get_conn() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with _get_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                severity TEXT NOT NULL CHECK(severity IN ('low','medium','high','critical')),
                status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','closed','archived')),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                event_count INTEGER DEFAULT 0
            )
        """)
        conn.commit()


def create_incident(name: str, description: str | None, severity: str) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    incident_id = str(uuid.uuid4())
    with _get_conn() as conn:
        conn.execute(
            "INSERT INTO incidents (id, name, description, severity, status, created_at, updated_at) VALUES (?,?,?,?,?,?,?)",
            (incident_id, name, description, severity, "open", now, now),
        )
        conn.commit()
    return get_incident(incident_id)


def list_incidents() -> list[dict]:
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM incidents ORDER BY created_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]


def get_incident(incident_id: str) -> dict | None:
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM incidents WHERE id = ?", (incident_id,)
        ).fetchone()
        return dict(row) if row else None


def update_incident_status(incident_id: str, new_status: str) -> dict | None:
    now = datetime.now(timezone.utc).isoformat()
    with _get_conn() as conn:
        conn.execute(
            "UPDATE incidents SET status = ?, updated_at = ? WHERE id = ?",
            (new_status, now, incident_id),
        )
        conn.commit()
    return get_incident(incident_id)
