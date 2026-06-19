"""
Bearer token authentication dependency for the FastAPI control plane.
Spec: instructions/06-api-control-plane.md §2.

Security invariants:
- Token is read once at module import from Docker secret /run/secrets/api_token.
- Comparison uses hmac.compare_digest (constant-time) — never == .
- Auth failure logs to SIEMHunterSecurity_CL (independence: failure must not
  prevent the 401 from being returned to the caller).
- The token value is NEVER written to logs, responses, or exception messages.
"""
from __future__ import annotations
import hmac
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import structlog
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

log = structlog.get_logger(__name__)

_SECRET_PATH = "/run/secrets/api_token"

# Load once at module import. Fail loudly at startup if missing or empty.
def _load_token() -> str:
    try:
        val = Path(_SECRET_PATH).read_text().strip()
    except OSError as exc:
        print(
            f"FATAL: Cannot read api_token from {_SECRET_PATH}: {exc}",
            file=sys.stderr,
        )
        raise SystemExit(1) from exc
    if not val:
        print(
            f"FATAL: {_SECRET_PATH} is present but empty. "
            "API cannot start without authentication.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    return val


_EXPECTED_TOKEN: str = _load_token()

_bearer_scheme = HTTPBearer(auto_error=False)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _log_auth_failure_async(request: Request) -> None:
    """Best-effort: write an AuthFailure event to Sentinel.

    Failures here must NOT prevent the 401 from being returned (FR-19 / §2).
    Runs synchronously but swallows all exceptions.
    """
    try:
        # Import here to avoid circular imports and to defer until runtime
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
        # Independence requirement: swallow, log locally only
        log.warning("auth_failure_sentinel_write_failed", error=str(exc))


async def verify_token(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme),
) -> None:
    """FastAPI dependency. Raises HTTP 401 if token is missing or invalid."""
    provided: Optional[str] = None
    if credentials and credentials.scheme.lower() == "bearer":
        provided = credentials.credentials

    if not provided or not hmac.compare_digest(
        provided.encode("utf-8"),
        _EXPECTED_TOKEN.encode("utf-8"),
    ):
        _log_auth_failure_async(request)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "Invalid or missing bearer token", "code": "AUTH_REQUIRED"},
            headers={"WWW-Authenticate": "Bearer"},
        )
