"""
Compatibility shim for the v3.0.0 dual-auth split (FR #10).

Before v3 this module held the only auth path: a single static bearer token
compared with ``hmac.compare_digest``. v3 splits authentication into two
modules:

  - ``auth_analyst``       — per-analyst username/password login + server-side
                             cookie session + CSRF (``require_analyst_session``).
  - ``auth_service_token`` — the legacy static token, now scoped to
                             automation / break-glass (``require_service_token``).

Every existing router still does ``Depends(verify_token)``. To avoid a flag-day
rewrite, ``verify_token`` stays here as a backward-compatible dependency that
accepts EITHER path (§6.1 "most routes accept either"):

  1. a valid analyst session (cookie + CSRF on writes), or
  2. a valid static service token (audited, browser-origin rejected).

Phase 2 will convert individual routes to the specific dependency they need
(analyst-only vs either) and record ``AuthMethod`` on write/audit-sensitive
routes. The ``record_auth_method`` helper below is provided for that work and is
already wired into the sensitive routes touched in Phase 0.

Backward-compat note: ``_EXPECTED_TOKEN`` is re-exported from
``auth_service_token`` so the existing test suite (conftest patches
``auth._EXPECTED_TOKEN``) keeps working.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional

import structlog
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from . import auth_analyst
from . import auth_service_token
from .auth_analyst import require_analyst_session  # re-export
from .auth_service_token import require_service_token  # re-export

log = structlog.get_logger(__name__)

# Backward-compat: the test suite patches auth._EXPECTED_TOKEN directly. Keep a
# module-level name that mirrors the service-token module's expected token.
_EXPECTED_TOKEN: str = auth_service_token._EXPECTED_TOKEN

_bearer_scheme = HTTPBearer(auto_error=False)

# Sensitive routes record which path authenticated (§6.1). Phase 2 extends this.
SENSITIVE_PATH_HINTS = (
    "/ingestion/upload",
    "/rules/",      # rule status PATCH/PUT
    "/incidents/",  # incident status PATCH, notes (#19)
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _log_auth_failure_async(request: Request) -> None:
    """Best-effort AuthFailure event (preserved from the original auth.py)."""
    try:
        from .audit_client import send_security_event

        send_security_event({
            "TimeGenerated": _now_iso(),
            "RuleId": "",
            "RuleVersion": "",
            "EventType": "AuthFailure",
            "Entity": request.client.host if request.client else "unknown",
            "SourceEventIds": "[]",
            "Severity": "Warning",
            "Detail": json.dumps({
                "method": request.method,
                "path": request.url.path,
            }),
            "ATTACKTechnique": "",
        })
    except Exception as exc:
        log.warning("auth_failure_sentinel_write_failed", error=str(exc))


def record_auth_method(request: Request, method: str) -> None:
    """Emit an ``AuthMethod`` event for write/audit-sensitive routes (§6.1).

    ``method`` is ``"analyst_session"`` or ``"service_token"``. Best-effort.
    """
    try:
        from .audit_client import send_security_event

        send_security_event({
            "TimeGenerated": _now_iso(),
            "RuleId": "",
            "RuleVersion": "",
            "EventType": "AuthMethod",
            "Entity": request.client.host if request.client else "unknown",
            "SourceEventIds": "[]",
            "Severity": "Informational",
            "Detail": json.dumps({
                "method": request.method,
                "path": request.url.path,
                "auth_method": method,
            }),
            "ATTACKTechnique": "",
        })
    except Exception as exc:
        log.warning("auth_method_sentinel_write_failed", error=str(exc))


def _is_sensitive(path: str) -> bool:
    return any(hint in path for hint in SENSITIVE_PATH_HINTS)


async def get_request_identity(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme),
) -> str:
    """Return the caller's identity string for audit / note authorship.

    Analyst session → returns the analyst's username.
    Service token   → returns the literal string "service_token".
    Raises 401/403 if neither path authenticates.

    This is the dependency to use on endpoints that must record WHO acted
    (e.g. incident notes) rather than just WHETHER the request is authenticated.
    """
    provided: Optional[str] = None
    if credentials and credentials.scheme.lower() == "bearer":
        provided = credentials.credentials

    if provided is not None:
        method = await require_service_token(request, credentials)
        if _is_sensitive(request.url.path):
            record_auth_method(request, method)
        return "service_token"

    try:
        sess = await require_analyst_session(request)
    except HTTPException as exc:
        _log_auth_failure_async(request)
        if exc.status_code == status.HTTP_401_UNAUTHORIZED:
            headers = dict(exc.headers or {})
            headers.setdefault("WWW-Authenticate", "Bearer")
            exc.headers = headers
        raise
    if _is_sensitive(request.url.path):
        record_auth_method(request, "analyst_session")
    return sess.username


async def verify_token(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme),
) -> str:
    """Backward-compatible dependency accepting either auth path.

    Resolution order:
      1. If a Bearer token is present, authenticate via the service-token path
         (browser-origin rejection + validity + audit).
      2. Otherwise try the analyst session (cookie + CSRF on writes).

    Returns the AuthMethod label. Raises 401/403 if neither path authenticates.
    On sensitive routes, records which path authenticated.
    """
    # ── Path 1: service token (automation / break-glass) ────────────────────
    provided: Optional[str] = None
    if credentials and credentials.scheme.lower() == "bearer":
        provided = credentials.credentials

    if provided is not None:
        # A bearer token was supplied → this is the service-token path. Enforce
        # its full policy (browser-origin rejection + validity + audit).
        method = await require_service_token(request, credentials)
        if _is_sensitive(request.url.path):
            record_auth_method(request, method)
        return method

    # ── Path 2: analyst session (browser) ───────────────────────────────────
    try:
        await require_analyst_session(request)
    except HTTPException as exc:
        # Preserve the legacy AuthFailure audit event on a hard failure.
        _log_auth_failure_async(request)
        # Backward-compat: a 401 with no credentials at all must still advertise
        # the bearer challenge (RFC 9110), as the original verify_token did.
        if exc.status_code == status.HTTP_401_UNAUTHORIZED:
            headers = dict(exc.headers or {})
            headers.setdefault("WWW-Authenticate", "Bearer")
            exc.headers = headers
        raise
    if _is_sensitive(request.url.path):
        record_auth_method(request, "analyst_session")
    return "analyst_session"
