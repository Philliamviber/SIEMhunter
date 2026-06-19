"""
GET /v1/health — Docker health check endpoint.
No authentication required. Returns {"status": "ok"}.
Spec: instructions/06-api-control-plane.md §3.4.
"""
from __future__ import annotations
from fastapi import APIRouter

router = APIRouter()


@router.get("/health")
async def health() -> dict:
    """Unauthenticated health probe used by Docker HEALTHCHECK."""
    return {"status": "ok"}
