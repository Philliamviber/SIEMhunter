"""
SQLite-backed incident metadata store for SIEMhunter.

Why SQLite (not ClickHouse)?
----------------------------
Incident records are analyst workspace state — created, updated, and queried
by a single analyst session at a time, with a volume measured in tens to hundreds
of rows over the lifetime of the API service. ClickHouse is optimised for
append-heavy analytical workloads with millions of rows; it is not designed for
low-volume OLTP operations like UPDATE (change incident status) or single-row
lookups by primary key. SQLite handles both natively and requires no separate
service, no connection pool configuration, and no schema migration tooling.

The separation is also intentional from a data-model perspective: security_events
and detection_hits are immutable telemetry (append-only); incidents are mutable
analyst annotations. Mixing them in the same store would complicate retention
policies and backup strategies.

DB path is configurable via INCIDENTS_DB_PATH env var; the directory is created
automatically if it does not exist. Incident metadata is stored here only —
event_count is a cached counter, not a JOIN across security_events.
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

# Whitelisted sort expressions — never interpolate user strings directly.
_SORT_EXPRESSIONS: dict[str, str] = {
    "created_at": "created_at",
    "updated_at": "updated_at",
    "name": "name COLLATE NOCASE",
    "event_count": "event_count",
    "severity": (
        "CASE severity"
        " WHEN 'critical' THEN 4"
        " WHEN 'high' THEN 3"
        " WHEN 'medium' THEN 2"
        " WHEN 'low' THEN 1"
        " ELSE 0 END"
    ),
}


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
        conn.execute("""
            CREATE TABLE IF NOT EXISTS incident_notes (
                id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL REFERENCES incidents(id),
                author TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TEXT NOT NULL
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


def list_incidents(
    severity: str | None = None,
    status: str | None = None,
    search: str | None = None,
    sort_by: str = "created_at",
    sort_dir: str = "desc",
) -> list[dict]:
    where_clauses: list[str] = []
    params: list = []

    if severity and severity in _VALID_SEVERITIES:
        where_clauses.append("severity = ?")
        params.append(severity)

    if status and status in _VALID_STATUSES:
        where_clauses.append("status = ?")
        params.append(status)

    if search:
        where_clauses.append("name LIKE ?")
        params.append(f"%{search}%")

    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
    sort_expr = _SORT_EXPRESSIONS.get(sort_by, "created_at")
    safe_dir = "ASC" if sort_dir.lower() == "asc" else "DESC"

    with _get_conn() as conn:
        rows = conn.execute(
            f"SELECT * FROM incidents {where_sql} ORDER BY {sort_expr} {safe_dir}",
            params,
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


def create_note(incident_id: str, author: str, content: str) -> dict:
    """Append a new note to an incident. Author and timestamp are caller-supplied
    (the caller — the router — must derive these from the authenticated identity,
    never from user-submitted fields).
    """
    now = datetime.now(timezone.utc).isoformat()
    note_id = str(uuid.uuid4())
    with _get_conn() as conn:
        conn.execute(
            "INSERT INTO incident_notes (id, incident_id, author, content, created_at) VALUES (?,?,?,?,?)",
            (note_id, incident_id, author, content, now),
        )
        conn.commit()
    return {"id": note_id, "incident_id": incident_id, "author": author, "content": content, "created_at": now}


def list_notes(incident_id: str) -> list[dict]:
    """Return all notes for an incident, oldest first."""
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT id, incident_id, author, content, created_at FROM incident_notes WHERE incident_id = ? ORDER BY created_at ASC",
            (incident_id,),
        ).fetchall()
        return [dict(r) for r in rows]
