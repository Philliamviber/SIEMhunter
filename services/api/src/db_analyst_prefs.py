"""
Per-analyst key/value persistence layer for SIEMhunter.

Follows the same SQLite access pattern as db_incidents.py. Each row is keyed
by (analyst_id, key); analyst_id is always the server-resolved username from
the authenticated session — never a client-supplied value.

DB path is configurable via ANALYST_PREFS_DB_PATH; the directory is created
automatically if it does not exist.
"""
from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(os.getenv("ANALYST_PREFS_DB_PATH", "/data/siemhunter_analyst_prefs.db"))


def _get_conn() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with _get_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS analyst_kv (
                analyst_id TEXT NOT NULL,
                key        TEXT NOT NULL,
                value      TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (analyst_id, key)
            )
        """)
        conn.commit()


def set_value(analyst_id: str, key: str, value: str) -> None:
    """Upsert a key/value pair for the given analyst. All args are caller-supplied
    and must come from the server-side session — never from the request body."""
    now = datetime.now(timezone.utc).isoformat()
    with _get_conn() as conn:
        conn.execute(
            """
            INSERT INTO analyst_kv (analyst_id, key, value, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(analyst_id, key) DO UPDATE SET value = excluded.value,
                                                        updated_at = excluded.updated_at
            """,
            (analyst_id, key, value, now),
        )
        conn.commit()


def get_value(analyst_id: str, key: str) -> str | None:
    """Return the stored value for (analyst_id, key), or None if absent."""
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT value FROM analyst_kv WHERE analyst_id = ? AND key = ?",
            (analyst_id, key),
        ).fetchone()
        return row["value"] if row else None


def get_all(analyst_id: str) -> dict[str, str]:
    """Return all key/value pairs for a given analyst as a dict."""
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT key, value FROM analyst_kv WHERE analyst_id = ?",
            (analyst_id,),
        ).fetchall()
        return {r["key"]: r["value"] for r in rows}
