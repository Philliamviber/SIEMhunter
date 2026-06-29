"""
Per-analyst preferences endpoints.

GET  /v1/analyst/preferences  — return the authenticated analyst's preferences
PUT  /v1/analyst/preferences  — upsert one or more preference fields

Authentication: analyst session ONLY (require_analyst_session). Service tokens
are explicitly rejected — preferences are meaningless without a named analyst
identity, and the server-set username is the sole row key (no client-supplied
owner is trusted).

The endpoint reads/writes three well-known preference keys through the general
db_analyst_prefs KV layer so PR3/PR6 can add more consumers without touching
this router.
"""
from __future__ import annotations

from typing import Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, field_validator

from ..auth_analyst import require_analyst_session, _Session
from .. import db_analyst_prefs

log = structlog.get_logger(__name__)
router = APIRouter()

# ── Allowed values (validated server-side) ────────────────────────────────────

_VALID_TIME_RANGES = {"1h", "4h", "24h", "7d", "30d"}
_VALID_DENSITIES = {"compact", "comfortable", "spacious"}
_VALID_LANDING_PAGES = {
    "/", "/events", "/detections", "/rules", "/incidents",
    "/query", "/categories", "/health", "/ingestion", "/correlation",
}

# ── Preference key constants (for use by PR3/PR6 consumers) ──────────────────

PREF_TIME_RANGE = "default_time_range"
PREF_DENSITY = "table_density"
PREF_LANDING = "default_landing_page"

_DEFAULTS: dict[str, str] = {
    PREF_TIME_RANGE: "24h",
    PREF_DENSITY: "comfortable",
    PREF_LANDING: "/",
}


# ── Models ────────────────────────────────────────────────────────────────────

class PreferencesResponse(BaseModel):
    default_time_range: str
    table_density: str
    default_landing_page: str


class PreferencesUpdate(BaseModel):
    default_time_range: Optional[str] = None
    table_density: Optional[str] = None
    default_landing_page: Optional[str] = None

    @field_validator("default_time_range")
    @classmethod
    def validate_time_range(cls, v: str | None) -> str | None:
        if v is not None and v not in _VALID_TIME_RANGES:
            raise ValueError(f"default_time_range must be one of {sorted(_VALID_TIME_RANGES)}")
        return v

    @field_validator("table_density")
    @classmethod
    def validate_density(cls, v: str | None) -> str | None:
        if v is not None and v not in _VALID_DENSITIES:
            raise ValueError(f"table_density must be one of {sorted(_VALID_DENSITIES)}")
        return v

    @field_validator("default_landing_page")
    @classmethod
    def validate_landing(cls, v: str | None) -> str | None:
        if v is not None and v not in _VALID_LANDING_PAGES:
            raise ValueError(f"default_landing_page must be one of {sorted(_VALID_LANDING_PAGES)}")
        return v


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/analyst/preferences", response_model=PreferencesResponse)
async def get_preferences(
    sess: _Session = Depends(require_analyst_session),
) -> PreferencesResponse:
    """Return the authenticated analyst's preferences (with defaults for unset keys)."""
    try:
        stored = db_analyst_prefs.get_all(sess.username)
    except Exception as exc:
        log.error("analyst_prefs_get_failed", username=sess.username, error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "Failed to read preferences", "code": "DB_ERROR"},
        )
    return PreferencesResponse(
        default_time_range=stored.get(PREF_TIME_RANGE, _DEFAULTS[PREF_TIME_RANGE]),
        table_density=stored.get(PREF_DENSITY, _DEFAULTS[PREF_DENSITY]),
        default_landing_page=stored.get(PREF_LANDING, _DEFAULTS[PREF_LANDING]),
    )


@router.put("/analyst/preferences", response_model=PreferencesResponse)
async def update_preferences(
    body: PreferencesUpdate,
    sess: _Session = Depends(require_analyst_session),
) -> PreferencesResponse:
    """Upsert one or more preference fields for the authenticated analyst.

    Only fields present in the request body are written; omitted fields retain
    their existing stored value (or the default if never set). The analyst_id
    is always taken from the server-side session — the request body has no
    owner field.
    """
    updates: dict[str, str] = {}
    if body.default_time_range is not None:
        updates[PREF_TIME_RANGE] = body.default_time_range
    if body.table_density is not None:
        updates[PREF_DENSITY] = body.table_density
    if body.default_landing_page is not None:
        updates[PREF_LANDING] = body.default_landing_page

    try:
        for key, value in updates.items():
            db_analyst_prefs.set_value(sess.username, key, value)
    except Exception as exc:
        log.error("analyst_prefs_put_failed", username=sess.username, error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "Failed to write preferences", "code": "DB_ERROR"},
        )

    stored = db_analyst_prefs.get_all(sess.username)
    return PreferencesResponse(
        default_time_range=stored.get(PREF_TIME_RANGE, _DEFAULTS[PREF_TIME_RANGE]),
        table_density=stored.get(PREF_DENSITY, _DEFAULTS[PREF_DENSITY]),
        default_landing_page=stored.get(PREF_LANDING, _DEFAULTS[PREF_LANDING]),
    )
