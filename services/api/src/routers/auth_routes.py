"""
Analyst authentication endpoints (FR #10).

  POST /v1/auth/login    — username+password → set session cookie + return CSRF token
  POST /v1/auth/logout   — invalidate server-side session + clear cookie
  GET  /v1/auth/session  — re-validate the current session (used by LoginGate)

Binding design parameters (GATE B):
  - C2  cookie: HttpOnly + Secure + SameSite=Strict + Path=/ + ``__Host-`` prefix
        on HTTPS + explicit Max-Age. CSRF token returned in the JSON body (the
        client echoes it back in the X-CSRF-Token header — double-submit).
  - C5  login fails closed if the API is unseeded.
  - C6  LoginSuccess / LoginFailure / Lockout / Logout events to Sentinel
        (best-effort, non-blocking).
  - These routes NEVER accept the service token — they are interactive-only.
  - All responses carry ``Cache-Control: no-store`` (AC#6).

Secure-cookie / dev-over-HTTP (C2 residual risk): the cookie attributes are
driven by a single ``SESSION_COOKIE_SECURE`` flag. It defaults to TRUE. An
operator may set ``SESSION_COOKIE_SECURE=false`` for local HTTP development, in
which case the non-prefixed cookie name is used and ``Secure`` is dropped. A
release build must NOT ship with that flag flipped — see DEPLOYMENT.md.
"""
from __future__ import annotations

import os

import structlog
from fastapi import APIRouter, HTTPException, Request, Response, status
from pydantic import BaseModel

from .. import auth_analyst as analyst

log = structlog.get_logger(__name__)
router = APIRouter()

# Single switch governing Secure/__Host- (C2). Defaults to secure.
_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "true").lower() != "false"

_COOKIE_NAME = (
    analyst.SESSION_COOKIE_NAME if _COOKIE_SECURE
    else analyst.SESSION_COOKIE_NAME_INSECURE
)


class LoginRequest(BaseModel):
    username: str
    password: str


def _no_store(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"


def _set_session_cookie(response: Response, session_id: str) -> None:
    """Emit the session cookie with the full C2 attribute set."""
    # __Host- prefix requires Secure + Path=/ + no Domain. We satisfy all three
    # when _COOKIE_SECURE is true. Max-Age = absolute session lifetime.
    response.set_cookie(
        key=_COOKIE_NAME,
        value=session_id,
        max_age=analyst.SESSION_ABSOLUTE_LIFETIME_SECONDS,
        httponly=True,
        secure=_COOKIE_SECURE,
        samesite="strict",
        path="/",
    )


def _clear_session_cookie(response: Response) -> None:
    response.delete_cookie(key=_COOKIE_NAME, path="/")


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


@router.post("/auth/login")
async def login(body: LoginRequest, request: Request, response: Response) -> dict:
    """Authenticate an analyst and start a session.

    Emits LoginSuccess / LoginFailure / Lockout to Sentinel (best-effort). The
    error message and HTTP code are IDENTICAL for unknown-user, wrong-password,
    and lockout-cooldown so the response never confirms account existence.
    """
    _no_store(response)
    username = body.username.strip()
    ip = _client_ip(request)

    # C5: fail closed if unseeded.
    if analyst.user_count() == 0:
        analyst._emit_event(
            "LoginFailure",
            {"reason": "unseeded", "username": username, "ip": ip},
            entity=ip,
            severity="Warning",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "Invalid username or password", "code": "AUTH_FAILED"},
        )

    # C3: time-boxed lockout keyed on (username, ip). Same generic 401 — do not
    # reveal that the account is locked vs that the password is wrong.
    if analyst.is_locked_out(username, ip):
        analyst._emit_event(
            "Lockout",
            {"username": username, "ip": ip, "cooldown_seconds": analyst.LOCKOUT_COOLDOWN_SECONDS},
            entity=ip,
            severity="Warning",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "Invalid username or password", "code": "AUTH_FAILED"},
        )

    if not analyst.verify_password(username, body.password):
        analyst.record_failure(username, ip)
        analyst._emit_event(
            "LoginFailure",
            {"reason": "bad_credentials", "username": username, "ip": ip},
            entity=ip,
            severity="Warning",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "Invalid username or password", "code": "AUTH_FAILED"},
        )

    # Success: clear the failure counter, mint a session, set the cookie.
    analyst.reset_failures(username, ip)
    sess = analyst.create_session(username)
    _set_session_cookie(response, sess.session_id)
    analyst._emit_event(
        "LoginSuccess",
        {"username": username, "ip": ip},
        entity=ip,
        severity="Informational",
    )
    return {
        "username": sess.username,
        "csrf_token": sess.csrf_token,
        "expires_at": analyst.session_expires_at(sess),
    }


@router.post("/auth/logout")
async def logout(request: Request, response: Response) -> dict:
    """Invalidate the server-side session and clear the cookie (AC#6)."""
    _no_store(response)
    session_id = analyst._read_session_cookie(request)
    username = None
    if session_id:
        sess = analyst.get_session(session_id)
        if sess is not None:
            username = sess.username
        analyst.revoke_session(session_id)
    _clear_session_cookie(response)
    if username:
        analyst._emit_event(
            "Logout",
            {"username": username, "ip": _client_ip(request)},
            entity=_client_ip(request),
            severity="Informational",
        )
    return {"ok": True}


@router.get("/auth/session")
async def session_info(request: Request, response: Response) -> dict:
    """Re-validate the current session. 401 if missing/expired (AC#6/AC#8)."""
    _no_store(response)
    session_id = analyst._read_session_cookie(request)
    if not session_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "No active session", "code": "AUTH_REQUIRED"},
        )
    sess = analyst.validate_and_touch(session_id)
    if sess is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "Session expired", "code": "AUTH_REQUIRED"},
        )
    return {
        "valid": True,
        "username": sess.username,
        "expires_at": analyst.session_expires_at(sess),
    }
