"""
Incident management endpoints.

POST   /v1/incidents                       — create a new incident
GET    /v1/incidents                       — list all incidents
GET    /v1/incidents/{incident_id}         — get a single incident
PATCH  /v1/incidents/{incident_id}/status  — update incident status

Authentication: required (bearer token).
Data store: SQLite via db_incidents module (never ClickHouse security_events).
"""
from __future__ import annotations

from typing import Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, field_validator

from ..auth import verify_token, get_request_identity
from .. import db_incidents

log = structlog.get_logger(__name__)
router = APIRouter()

_VALID_SEVERITIES = {"low", "medium", "high", "critical"}
_VALID_STATUSES = {"open", "closed", "archived"}


# ── Request / Response models ─────────────────────────────────────────────────

class CreateIncidentRequest(BaseModel):
    name: str
    description: Optional[str] = None
    severity: str

    @field_validator("severity")
    @classmethod
    def severity_must_be_valid(cls, v: str) -> str:
        if v not in _VALID_SEVERITIES:
            raise ValueError(
                f"severity must be one of {sorted(_VALID_SEVERITIES)}, got {v!r}"
            )
        return v


class IncidentStatusUpdate(BaseModel):
    new_status: str

    @field_validator("new_status")
    @classmethod
    def status_must_be_valid(cls, v: str) -> str:
        if v not in _VALID_STATUSES:
            raise ValueError(
                f"new_status must be one of {sorted(_VALID_STATUSES)}, got {v!r}"
            )
        return v


class IncidentResponse(BaseModel):
    id: str
    name: str
    description: Optional[str]
    severity: str
    status: str
    created_at: str
    updated_at: str
    event_count: int


class IncidentsListResponse(BaseModel):
    incidents: list[IncidentResponse]
    total: int


class CreateNoteRequest(BaseModel):
    content: str

    @field_validator("content")
    @classmethod
    def content_must_not_be_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("content must not be empty")
        if len(v) > 10_000:
            raise ValueError("content must not exceed 10 000 characters")
        return v


class NoteResponse(BaseModel):
    id: str
    incident_id: str
    author: str
    content: str
    created_at: str


class NotesListResponse(BaseModel):
    notes: list[NoteResponse]
    total: int


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/incidents", response_model=IncidentResponse, status_code=status.HTTP_201_CREATED)
async def create_incident(
    body: CreateIncidentRequest,
    _: None = Depends(verify_token),
) -> IncidentResponse:
    """Create a new incident."""
    try:
        row = db_incidents.create_incident(
            name=body.name,
            description=body.description,
            severity=body.severity,
        )
    except Exception as exc:
        log.error("incident_create_failed", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "Failed to create incident", "code": "DB_ERROR"},
        )
    return IncidentResponse(**row)


@router.get("/incidents", response_model=IncidentsListResponse)
async def list_incidents(
    severity: Optional[str] = Query(default=None),
    filter_status: Optional[str] = Query(default=None, alias="status"),
    search: Optional[str] = Query(default=None),
    sort_by: Optional[str] = Query(default=None),
    sort_dir: Optional[str] = Query(default=None),
    _: None = Depends(verify_token),
) -> IncidentsListResponse:
    """Return incidents with optional filtering and sorting."""
    try:
        rows = db_incidents.list_incidents(
            severity=severity,
            status=filter_status,
            search=search,
            sort_by=sort_by or "created_at",
            sort_dir=sort_dir or "desc",
        )
    except Exception as exc:
        log.error("incident_list_failed", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "Failed to list incidents", "code": "DB_ERROR"},
        )
    incidents = [IncidentResponse(**r) for r in rows]
    return IncidentsListResponse(incidents=incidents, total=len(incidents))


@router.get("/incidents/{incident_id}", response_model=IncidentResponse)
async def get_incident(
    incident_id: str,
    _: None = Depends(verify_token),
) -> IncidentResponse:
    """Return a single incident by ID."""
    try:
        row = db_incidents.get_incident(incident_id)
    except Exception as exc:
        log.error("incident_get_failed", incident_id=incident_id, error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "Failed to retrieve incident", "code": "DB_ERROR"},
        )
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": f"Incident {incident_id!r} not found", "code": "NOT_FOUND"},
        )
    return IncidentResponse(**row)


@router.post("/incidents/{incident_id}/notes", response_model=NoteResponse, status_code=status.HTTP_201_CREATED)
async def create_incident_note(
    incident_id: str,
    body: CreateNoteRequest,
    author: str = Depends(get_request_identity),
) -> NoteResponse:
    """Append a note to an incident.

    Author and timestamp are set server-side from the authenticated identity;
    the client cannot supply or override them (#19).  Content is returned as
    plain text — never rendered as HTML.
    """
    try:
        existing = db_incidents.get_incident(incident_id)
    except Exception as exc:
        log.error("note_create_incident_lookup_failed", incident_id=incident_id, error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "Failed to retrieve incident", "code": "DB_ERROR"},
        )
    if existing is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": f"Incident {incident_id!r} not found", "code": "NOT_FOUND"},
        )

    try:
        row = db_incidents.create_note(
            incident_id=incident_id,
            author=author,
            content=body.content,
        )
    except Exception as exc:
        log.error("note_create_failed", incident_id=incident_id, error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "Failed to create note", "code": "DB_ERROR"},
        )
    return NoteResponse(**row)


@router.get("/incidents/{incident_id}/notes", response_model=NotesListResponse)
async def list_incident_notes(
    incident_id: str,
    _: str = Depends(verify_token),
) -> NotesListResponse:
    """Return all notes for an incident, oldest first."""
    try:
        existing = db_incidents.get_incident(incident_id)
    except Exception as exc:
        log.error("note_list_incident_lookup_failed", incident_id=incident_id, error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "Failed to retrieve incident", "code": "DB_ERROR"},
        )
    if existing is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": f"Incident {incident_id!r} not found", "code": "NOT_FOUND"},
        )

    try:
        rows = db_incidents.list_notes(incident_id)
    except Exception as exc:
        log.error("note_list_failed", incident_id=incident_id, error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "Failed to list notes", "code": "DB_ERROR"},
        )
    notes = [NoteResponse(**r) for r in rows]
    return NotesListResponse(notes=notes, total=len(notes))


@router.patch("/incidents/{incident_id}/status", response_model=IncidentResponse)
async def update_incident_status(
    incident_id: str,
    body: IncidentStatusUpdate,
    _: None = Depends(verify_token),
) -> IncidentResponse:
    """Update the status of an existing incident."""
    # Confirm the incident exists before attempting the update
    try:
        existing = db_incidents.get_incident(incident_id)
    except Exception as exc:
        log.error("incident_status_lookup_failed", incident_id=incident_id, error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "Failed to retrieve incident", "code": "DB_ERROR"},
        )
    if existing is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": f"Incident {incident_id!r} not found", "code": "NOT_FOUND"},
        )

    try:
        row = db_incidents.update_incident_status(incident_id, body.new_status)
    except Exception as exc:
        log.error("incident_status_update_failed", incident_id=incident_id, error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "Failed to update incident status", "code": "DB_ERROR"},
        )
    return IncidentResponse(**row)
