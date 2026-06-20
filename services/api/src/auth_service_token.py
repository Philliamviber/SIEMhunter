"""
Service-account / break-glass static-token authentication (FR #10).

This is the non-interactive half of the v3.0.0 dual-auth model. It migrates the
original ``hmac.compare_digest`` static-token logic out of ``auth.py``. It is for
automation, CLI, and break-glass recovery — NOT for interactive browser login.

Binding design parameters (GATE B C4):
  (a) auditable on EVERY use — emit a ``ServiceTokenUse`` event to
      SIEMHunterSecurity_CL (best-effort, non-blocking).
  (b) must NOT act as a CSRF bypass for browser-origin requests — if the request
      looks like it came from a browser (it carries an Origin or Referer header),
      reject it. Browsers must go through the analyst session + CSRF path.
  (c) documented rotation owner — see DEPLOYMENT.md "Service token rotation".

The token is loaded ONCE at import from the Docker secret at
``/run/secrets/api_token``. If the secret is missing/empty the module raises
SystemExit(1) — fail-closed, identical to the original behaviour.
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


def _load_token() -> str:
    """Load the static service token from the Docker secret (fail-closed)."""
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
            "API cannot start without a service token.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    return val


_EXPECTED_TOKEN: str = _load_token()

_bearer_scheme = HTTPBearer(auto_error=False)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _emit_service_token_use(request: Request) -> None:
    """Best-effort ``ServiceTokenUse`` audit event (C4a / C6). Non-blocking."""
    try:
        from .audit_client import send_security_event

        send_security_event({
            "TimeGenerated": _now_iso(),
            "RuleId": "",
            "RuleVersion": "",
            "EventType": "ServiceTokenUse",
            "Entity": request.client.host if request.client else "unknown",
            "SourceEventIds": "[]",
            "Severity": "Informational",
            "Detail": json.dumps({
                "method": request.method,
                "path": request.url.path,
            }),
            "ATTACKTechnique": "",
        })
    except Exception as exc:
        log.warning("service_token_sentinel_write_failed", error=str(exc))


def _looks_like_browser_request(request: Request) -> bool:
    """True if the request carries browser-origin signals (Origin/Referer).

    Per C4b the service token must not double as a CSRF bypass for browser
    traffic. Automation does not set Origin/Referer; browsers do. If either is
    present we reject the service-token path and force the analyst-session path.
    """
    return bool(request.headers.get("origin") or request.headers.get("referer"))


def _extract_token(credentials: Optional[HTTPAuthorizationCredentials]) -> Optional[str]:
    if credentials and credentials.scheme.lower() == "bearer":
        return credentials.credentials
    return None


def is_valid_service_token(provided: Optional[str]) -> bool:
    """Constant-time comparison of a provided token against the expected one."""
    if not provided:
        return False
    return hmac.compare_digest(
        provided.encode("utf-8"),
        _EXPECTED_TOKEN.encode("utf-8"),
    )


async def require_service_token(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme),
) -> str:
    """FastAPI dependency: a valid static service token on a non-browser request.

    Returns the literal string ``"service_token"`` as the AuthMethod label so
    callers can record which path authenticated. Raises 401 on a missing/invalid
    token, or 403 if the request looks browser-originated (C4b).
    """
    # C4b: refuse to act as a CSRF bypass for browser-origin requests.
    if _looks_like_browser_request(request):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "Service token is not valid for browser-origin requests",
                "code": "SERVICE_TOKEN_BROWSER_REJECTED",
            },
        )

    provided = _extract_token(credentials)
    if not is_valid_service_token(provided):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "Invalid or missing service token", "code": "AUTH_REQUIRED"},
            headers={"WWW-Authenticate": "Bearer"},
        )

    # C4a: audit every successful service-token use (best-effort).
    _emit_service_token_use(request)
    return "service_token"
