"""
Per-analyst saved views and query history endpoints.

Saved views are named filter sets for a specific page, persisted through the
PR2 per-analyst KV store.  Each page's views are stored as a JSON array under
key ``saved_views:{page}``.

Query history records the most recent analyst queries (Query Console SQL) under
key ``query_history``, capped at MAX_HISTORY_ENTRIES (newest first).

All storage is identity-scoped: the analyst_id is always the server-side session
username — no client-supplied owner is trusted.

Routes:
  GET    /v1/analyst/saved-views?page=<page>     list saved views (filtered by page)
  POST   /v1/analyst/saved-views                 upsert a named view
  DELETE /v1/analyst/saved-views/{page}/{name}   remove a named view
  GET    /v1/analyst/query-history               list recent query history
  POST   /v1/analyst/query-history               prepend an entry to query history
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, field_validator

from ..auth_analyst import require_analyst_session, _Session
from .. import db_analyst_prefs

log = structlog.get_logger(__name__)
router = APIRouter()

_VALID_PAGES = {"events", "detections", "query", "search"}
MAX_VIEWS_PER_PAGE = 20
MAX_HISTORY_ENTRIES = 20

# ── KV key helpers ────────────────────────────────────────────────────────────

def _views_key(page: str) -> str:
    return f"saved_views:{page}"

_HISTORY_KEY = "query_history"


def _load_views(analyst_id: str, page: str) -> list[dict[str, Any]]:
    raw = db_analyst_prefs.get_value(analyst_id, _views_key(page))
    if not raw:
        return []
    try:
        data = json.loads(raw)
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, ValueError):
        return []


def _save_views(analyst_id: str, page: str, views: list[dict[str, Any]]) -> None:
    db_analyst_prefs.set_value(analyst_id, _views_key(page), json.dumps(views))


def _load_history(analyst_id: str) -> list[dict[str, Any]]:
    raw = db_analyst_prefs.get_value(analyst_id, _HISTORY_KEY)
    if not raw:
        return []
    try:
        data = json.loads(raw)
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, ValueError):
        return []


def _save_history(analyst_id: str, entries: list[dict[str, Any]]) -> None:
    db_analyst_prefs.set_value(analyst_id, _HISTORY_KEY, json.dumps(entries))


# ── Models ────────────────────────────────────────────────────────────────────

class SavedView(BaseModel):
    name: str
    page: str
    filters: dict[str, Any]

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("name must not be empty")
        if len(v) > 100:
            raise ValueError("name must be 100 characters or fewer")
        return v

    @field_validator("page")
    @classmethod
    def validate_page(cls, v: str) -> str:
        if v not in _VALID_PAGES:
            raise ValueError(f"page must be one of {sorted(_VALID_PAGES)}")
        return v


class SavedViewsResponse(BaseModel):
    views: list[SavedView]


class QueryHistoryEntry(BaseModel):
    sql: str
    run_at: str


class AddHistoryRequest(BaseModel):
    sql: str

    @field_validator("sql")
    @classmethod
    def validate_sql(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("sql must not be empty")
        if len(v) > 32_000:
            raise ValueError("sql must be 32,000 characters or fewer")
        return v


class QueryHistoryResponse(BaseModel):
    entries: list[QueryHistoryEntry]


# ── Saved views endpoints ─────────────────────────────────────────────────────

@router.get("/analyst/saved-views", response_model=SavedViewsResponse)
async def list_saved_views(
    page: Optional[str] = None,
    sess: _Session = Depends(require_analyst_session),
) -> SavedViewsResponse:
    """Return saved views for the authenticated analyst, optionally filtered by page."""
    pages_to_load = [page] if page else list(_VALID_PAGES)
    if page and page not in _VALID_PAGES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": f"page must be one of {sorted(_VALID_PAGES)}", "code": "INVALID_PAGE"},
        )
    try:
        all_views: list[SavedView] = []
        for p in sorted(pages_to_load):
            raw_views = _load_views(sess.username, p)
            for v in raw_views:
                try:
                    all_views.append(SavedView(**v))
                except Exception:
                    pass  # skip malformed entries
        return SavedViewsResponse(views=all_views)
    except Exception as exc:
        log.error("saved_views_list_failed", username=sess.username, error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "Failed to read saved views", "code": "DB_ERROR"},
        )


@router.post("/analyst/saved-views", response_model=SavedViewsResponse)
async def upsert_saved_view(
    body: SavedView,
    sess: _Session = Depends(require_analyst_session),
) -> SavedViewsResponse:
    """Create or overwrite a named saved view for the authenticated analyst."""
    try:
        views = _load_views(sess.username, body.page)
        # Replace existing view with same name, or append if new.
        updated = [v for v in views if v.get("name") != body.name]
        if len(updated) >= MAX_VIEWS_PER_PAGE:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": f"Maximum of {MAX_VIEWS_PER_PAGE} saved views per page reached",
                    "code": "VIEWS_LIMIT_EXCEEDED",
                },
            )
        updated.append(body.model_dump())
        _save_views(sess.username, body.page, updated)
        # Return all views for this page.
        parsed = [SavedView(**v) for v in updated]
        return SavedViewsResponse(views=parsed)
    except HTTPException:
        raise
    except Exception as exc:
        log.error("saved_views_upsert_failed", username=sess.username, error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "Failed to save view", "code": "DB_ERROR"},
        )


@router.delete("/analyst/saved-views/{page}/{name}", response_model=SavedViewsResponse)
async def delete_saved_view(
    page: str,
    name: str,
    sess: _Session = Depends(require_analyst_session),
) -> SavedViewsResponse:
    """Delete a named saved view for the authenticated analyst."""
    if page not in _VALID_PAGES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": f"page must be one of {sorted(_VALID_PAGES)}", "code": "INVALID_PAGE"},
        )
    try:
        views = _load_views(sess.username, page)
        updated = [v for v in views if v.get("name") != name]
        _save_views(sess.username, page, updated)
        parsed = [SavedView(**v) for v in updated]
        return SavedViewsResponse(views=parsed)
    except Exception as exc:
        log.error("saved_views_delete_failed", username=sess.username, error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "Failed to delete view", "code": "DB_ERROR"},
        )


# ── Query history endpoints ───────────────────────────────────────────────────

@router.get("/analyst/query-history", response_model=QueryHistoryResponse)
async def get_query_history(
    sess: _Session = Depends(require_analyst_session),
) -> QueryHistoryResponse:
    """Return the recent query history for the authenticated analyst (newest first)."""
    try:
        raw = _load_history(sess.username)
        entries = [QueryHistoryEntry(**e) for e in raw if isinstance(e, dict) and "sql" in e and "run_at" in e]
        return QueryHistoryResponse(entries=entries)
    except Exception as exc:
        log.error("query_history_get_failed", username=sess.username, error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "Failed to read query history", "code": "DB_ERROR"},
        )


@router.post("/analyst/query-history", response_model=QueryHistoryResponse)
async def add_query_history(
    body: AddHistoryRequest,
    sess: _Session = Depends(require_analyst_session),
) -> QueryHistoryResponse:
    """Prepend a query to the history (capped at MAX_HISTORY_ENTRIES)."""
    try:
        entries = _load_history(sess.username)
        now = datetime.now(timezone.utc).isoformat()
        new_entry = {"sql": body.sql, "run_at": now}
        # Deduplicate: remove any previous entry with the same SQL.
        entries = [e for e in entries if e.get("sql") != body.sql]
        entries.insert(0, new_entry)
        entries = entries[:MAX_HISTORY_ENTRIES]
        _save_history(sess.username, entries)
        parsed = [QueryHistoryEntry(**e) for e in entries]
        return QueryHistoryResponse(entries=parsed)
    except Exception as exc:
        log.error("query_history_add_failed", username=sess.username, error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "Failed to add query history entry", "code": "DB_ERROR"},
        )
