"""
Per-analyst username/password authentication (FR #10).

This module is one half of the v3.0.0 dual-auth model:

- ``auth_analyst``       — interactive per-analyst login (THIS module). Browser
                           clients authenticate with username+password and then
                           ride a server-side session backed by an
                           HttpOnly/Secure/SameSite=Strict ``__Host-`` cookie plus
                           a CSRF double-submit token.
- ``auth_service_token`` — non-interactive service-account / break-glass path
                           (the legacy static ``hmac.compare_digest`` token).

Binding design parameters (GATE B — see SIEMHunterv3changelogproposal.md §7):

  C1  argon2id with EXPLICIT params (no library defaults): memory_cost=65536
      (64 MiB), time_cost=3, parallelism=1, hash_len=32, salt_len=16. Full
      encoded hash stored; ``needs_rehash`` supported.
  C2  cookie carries HttpOnly + Secure + SameSite=Strict + Path=/ + ``__Host-``
      name prefix + explicit Max-Age. CSRF token mandatory. (Cookie emission
      lives in routers/auth_routes.py; this module owns the session store and
      the CSRF token mint/verify.)
  C3  lockout is a time-boxed, self-healing throttle keyed on username + source
      IP. Default trigger 5 failed attempts; 15-minute cooldown; never permanent.
  C5  first-run fails CLOSED: the API refuses ALL analyst auth until at least one
      user exists. No baked-in default password. ``seed_admin`` is the only way
      to create the first credential.

Production note: the user store and session store here are in-memory dicts,
acceptable for v3 single-instance deployment. Production at scale should move
the session store to Redis (or a signed-token + server-side revocation list)
and the user store to a real DB so credentials survive restarts and shared
across replicas. Both are intentionally isolated behind the small functions
below so that swap is contained.
"""
from __future__ import annotations

import json
import os
import secrets
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import structlog
from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from fastapi import Depends, HTTPException, Request, status

log = structlog.get_logger(__name__)

# ── Argon2id hasher with EXPLICIT pinned params (C1) ─────────────────────────
# Do NOT rely on library defaults — they move between versions. These are the
# named "interactive" profile from the GATE B sign-off.
_ARGON2_MEMORY_COST = 65536   # 64 MiB
_ARGON2_TIME_COST = 3
_ARGON2_PARALLELISM = 1
_ARGON2_HASH_LEN = 32
_ARGON2_SALT_LEN = 16

_hasher = PasswordHasher(
    time_cost=_ARGON2_TIME_COST,
    memory_cost=_ARGON2_MEMORY_COST,
    parallelism=_ARGON2_PARALLELISM,
    hash_len=_ARGON2_HASH_LEN,
    salt_len=_ARGON2_SALT_LEN,
    type=Type.ID,  # argon2id
)

# Constant dummy hash for the unknown-user decoy verify (user-enumeration
# control). Computed once at import with the pinned params so an unknown-user
# login still pays the same argon2id cost as a wrong-password login and returns
# in comparable time. The password value is irrelevant — it is never a real
# credential.
_DUMMY_HASH = _hasher.hash("decoy-password-not-a-real-credential")

# ── Session timing (C2 / AC#7) ───────────────────────────────────────────────
SESSION_IDLE_TIMEOUT_SECONDS = 30 * 60        # 30 min of inactivity
SESSION_ABSOLUTE_LIFETIME_SECONDS = 10 * 60 * 60  # 10 h hard cap (one shift)

# ── Lockout policy (C3) ───────────────────────────────────────────────────────
LOCKOUT_THRESHOLD = 5            # failed attempts before cooldown kicks in
LOCKOUT_COOLDOWN_SECONDS = 15 * 60  # 15-min self-healing cooldown window

# Where the analyst user store is persisted. JSON file mounted from a Docker
# secret/volume; written by the seed CLI. In-memory cache on top.
_USERS_PATH = os.environ.get("ANALYST_USERS_PATH", "/run/secrets/analyst_users")


# ── User store ────────────────────────────────────────────────────────────────

@dataclass
class _User:
    username: str
    password_hash: str  # full argon2id encoded hash


# Guards the in-memory user cache + the file.
_users_lock = threading.RLock()
_users: dict[str, _User] = {}
_users_loaded = False


def _load_users() -> None:
    """Load users from the JSON store into the in-memory cache (idempotent)."""
    global _users_loaded
    with _users_lock:
        if _users_loaded:
            return
        try:
            raw = Path(_USERS_PATH).read_text()
            data = json.loads(raw)
            for entry in data.get("users", []):
                u = _User(username=entry["username"], password_hash=entry["password_hash"])
                _users[u.username] = u
        except (OSError, json.JSONDecodeError, KeyError) as exc:
            # Missing/empty/corrupt store → zero users → fail-closed (C5).
            log.info("analyst_user_store_empty_or_missing", path=_USERS_PATH, error=str(exc))
        _users_loaded = True


def _persist_users() -> None:
    """Write the in-memory user cache back to the JSON store."""
    with _users_lock:
        payload = {
            "users": [
                {"username": u.username, "password_hash": u.password_hash}
                for u in _users.values()
            ]
        }
        path = Path(_USERS_PATH)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            # /run/secrets is often read-only at runtime; seeding is expected to
            # run against a writable path (see seed_admin / ANALYST_USERS_PATH).
            pass
        path.write_text(json.dumps(payload, indent=2))


def user_count() -> int:
    """Number of seeded analyst users. 0 means the API is unseeded (fail-closed)."""
    _load_users()
    with _users_lock:
        return len(_users)


def _get_user(username: str) -> Optional[_User]:
    _load_users()
    with _users_lock:
        return _users.get(username)


def create_user(username: str, password: str) -> None:
    """Create (or overwrite) an analyst user. Used by the seed CLI only."""
    username = username.strip()
    if not username:
        raise ValueError("username must not be empty")
    if not password:
        raise ValueError("password must not be empty")
    pw_hash = _hasher.hash(password)
    with _users_lock:
        _load_users()
        _users[username] = _User(username=username, password_hash=pw_hash)
        _persist_users()


# ── Lockout throttle (C3) — keyed on (username, source IP) ───────────────────

@dataclass
class _Attempts:
    count: int = 0
    first_at: float = 0.0  # epoch seconds of the first failure in the window


_lockout_lock = threading.Lock()
_attempts: dict[tuple[str, str], _Attempts] = {}


def _lockout_key(username: str, ip: str) -> tuple[str, str]:
    return (username, ip)


def is_locked_out(username: str, ip: str) -> bool:
    """True if (username, ip) is currently in its cooldown window.

    Self-healing: once LOCKOUT_COOLDOWN_SECONDS elapses since the first failure,
    the window resets automatically — there is no permanent lock (C3).
    """
    key = _lockout_key(username, ip)
    now = time.time()
    with _lockout_lock:
        rec = _attempts.get(key)
        if rec is None:
            return False
        if now - rec.first_at >= LOCKOUT_COOLDOWN_SECONDS:
            # Window expired — heal.
            _attempts.pop(key, None)
            return False
        return rec.count >= LOCKOUT_THRESHOLD


def record_failure(username: str, ip: str) -> None:
    """Record one failed attempt for (username, ip)."""
    key = _lockout_key(username, ip)
    now = time.time()
    with _lockout_lock:
        rec = _attempts.get(key)
        if rec is None or now - rec.first_at >= LOCKOUT_COOLDOWN_SECONDS:
            _attempts[key] = _Attempts(count=1, first_at=now)
        else:
            rec.count += 1


def reset_failures(username: str, ip: str) -> None:
    """Clear the failure counter for (username, ip) — called on success."""
    with _lockout_lock:
        _attempts.pop(_lockout_key(username, ip), None)


# ── Session store (server-side, revocable — AC#6) ─────────────────────────────

@dataclass
class _Session:
    session_id: str
    username: str
    csrf_token: str
    created_at: float
    last_seen: float


_sessions_lock = threading.Lock()
_sessions: dict[str, _Session] = {}


def create_session(username: str) -> _Session:
    """Mint a new server-side session for a freshly authenticated analyst."""
    now = time.time()
    sess = _Session(
        session_id=secrets.token_urlsafe(32),
        username=username,
        csrf_token=secrets.token_urlsafe(32),
        created_at=now,
        last_seen=now,
    )
    with _sessions_lock:
        _sessions[sess.session_id] = sess
    return sess


def get_session(session_id: str) -> Optional[_Session]:
    with _sessions_lock:
        return _sessions.get(session_id)


def revoke_session(session_id: str) -> bool:
    """Server-side revocation (logout). True if a session was removed."""
    with _sessions_lock:
        return _sessions.pop(session_id, None) is not None


def _session_expiry_reason(sess: _Session, now: float) -> Optional[str]:
    """Return 'idle' / 'absolute' if the session is expired, else None."""
    if now - sess.created_at >= SESSION_ABSOLUTE_LIFETIME_SECONDS:
        return "absolute"
    if now - sess.last_seen >= SESSION_IDLE_TIMEOUT_SECONDS:
        return "idle"
    return None


def session_expires_at(sess: _Session) -> str:
    """ISO timestamp of the earlier of (idle deadline, absolute deadline)."""
    idle_deadline = sess.last_seen + SESSION_IDLE_TIMEOUT_SECONDS
    abs_deadline = sess.created_at + SESSION_ABSOLUTE_LIFETIME_SECONDS
    deadline = min(idle_deadline, abs_deadline)
    return datetime.fromtimestamp(deadline, tz=timezone.utc).isoformat()


def validate_and_touch(session_id: str) -> Optional[_Session]:
    """Return a live session and slide its idle timer, or None if expired/absent.

    Expired sessions are revoked here and a ``SessionExpiry`` event is emitted
    (best-effort) so the timeout is observable in Sentinel (C6).
    """
    now = time.time()
    with _sessions_lock:
        sess = _sessions.get(session_id)
        if sess is None:
            return None
        reason = _session_expiry_reason(sess, now)
        if reason is not None:
            _sessions.pop(session_id, None)
            expired = sess
            expired_reason = reason
        else:
            sess.last_seen = now
            return sess
    # Emit outside the lock.
    _emit_event("SessionExpiry", {"username": expired.username, "reason": expired_reason})
    return None


# ── Password verification (with needs_rehash, C1) ─────────────────────────────

def verify_password(username: str, password: str) -> bool:
    """Verify a username+password pair.

    Unknown-user path runs a DECOY argon2id verify against a constant dummy hash
    so timing is comparable to a wrong-password attempt and the response cannot
    be distinguished (user-enumeration control). Returns False for both unknown
    user and wrong password — the caller must use an identical error message.
    """
    user = _get_user(username)
    if user is None:
        # Decoy verify: pay the same argon2id cost, then fail.
        try:
            _hasher.verify(_DUMMY_HASH, password)
        except (VerifyMismatchError, InvalidHashError):
            pass
        return False

    try:
        _hasher.verify(user.password_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False

    # C1 needs_rehash: if the stored hash used weaker params (e.g. seeded under
    # an older profile), transparently upgrade it now that we have the plaintext.
    try:
        if _hasher.check_needs_rehash(user.password_hash):
            new_hash = _hasher.hash(password)
            with _users_lock:
                user.password_hash = new_hash
                _users[username] = user
                _persist_users()
            log.info("analyst_password_rehashed", username=username)
    except Exception as exc:  # never let a rehash failure break a valid login
        log.warning("analyst_rehash_failed", error=str(exc))

    return True


# ── Best-effort Sentinel event emit (C6) ──────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _emit_event(event_type: str, detail: dict, *, entity: str = "", severity: str = "Informational") -> None:
    """Forward an auth event to SIEMHunterSecurity_CL. Best-effort, non-blocking.

    Mirrors the existing AuthFailure pattern in auth.py: all exceptions are
    swallowed so an unreachable Sentinel never blocks login/logout/401 (C6).
    """
    try:
        from .audit_client import send_security_event

        send_security_event({
            "TimeGenerated": _now_iso(),
            "RuleId": "",
            "RuleVersion": "",
            "EventType": event_type,
            "Entity": entity,
            "SourceEventIds": "[]",
            "Severity": severity,
            "Detail": json.dumps(detail),
            "ATTACKTechnique": "",
        })
    except Exception as exc:
        log.warning("analyst_auth_sentinel_write_failed", event_type=event_type, error=str(exc))


# ── FastAPI dependency: require a live analyst session ────────────────────────

# The cookie name. ``__Host-`` prefix requires Secure + Path=/ + no Domain, which
# the cookie emitter in auth_routes.py guarantees on HTTPS. On plain-HTTP dev the
# emitter falls back to a non-prefixed name; this dependency accepts either so a
# dev build still works, but a release build must run over HTTPS (see C2).
SESSION_COOKIE_NAME = "__Host-siemhunter_session"
SESSION_COOKIE_NAME_INSECURE = "siemhunter_session"
CSRF_HEADER_NAME = "X-CSRF-Token"


def _read_session_cookie(request: Request) -> Optional[str]:
    return (
        request.cookies.get(SESSION_COOKIE_NAME)
        or request.cookies.get(SESSION_COOKIE_NAME_INSECURE)
    )


def _unauthorized(reason: str) -> HTTPException:
    # Identical generic message regardless of cause (no enumeration leak).
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"error": "Authentication required", "code": "AUTH_REQUIRED"},
    )


async def require_analyst_session(request: Request) -> _Session:
    """FastAPI dependency: a valid, non-expired analyst session.

    Enforces CSRF on state-changing methods via the double-submit pattern: the
    ``X-CSRF-Token`` header must equal the session's CSRF token. GET/HEAD/OPTIONS
    are exempt (they are not state-changing and SameSite=Strict already blocks
    cross-site cookie replay for them).
    """
    # Fail-closed if the API is unseeded (C5): no users → no analyst auth at all.
    if user_count() == 0:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "Authentication required", "code": "AUTH_REQUIRED"},
        )

    session_id = _read_session_cookie(request)
    if not session_id:
        raise _unauthorized("no_cookie")

    sess = validate_and_touch(session_id)
    if sess is None:
        raise _unauthorized("expired_or_absent")

    if request.method not in ("GET", "HEAD", "OPTIONS"):
        provided_csrf = request.headers.get(CSRF_HEADER_NAME)
        if not provided_csrf or not secrets.compare_digest(provided_csrf, sess.csrf_token):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"error": "CSRF token missing or invalid", "code": "CSRF_REQUIRED"},
            )

    return sess


# ── First-run seed CLI (C5) ───────────────────────────────────────────────────

def seed_admin(username: str, password: str) -> None:
    """Create the first (or an additional) analyst user from the CLI.

    No default password is ever baked in. The operator must run this explicitly
    before anyone can log in; until then the API is fail-closed.
    """
    create_user(username, password)
    log.info("analyst_user_seeded", username=username)


def _cli(argv: list[str]) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="python -m services.api.src.auth_analyst",
        description="SIEMhunter analyst user management (first-run seed).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    seed = sub.add_parser("seed", help="Create an analyst user.")
    seed.add_argument("--username", required=True)
    seed.add_argument(
        "--password",
        required=False,
        help="Password. If omitted, read from the ANALYST_SEED_PASSWORD env var "
             "(preferred — keeps the secret out of shell history).",
    )

    args = parser.parse_args(argv)

    if args.command == "seed":
        password = args.password or os.environ.get("ANALYST_SEED_PASSWORD")
        if not password:
            print(
                "ERROR: provide --password or set ANALYST_SEED_PASSWORD.",
                file=sys.stderr,
            )
            return 2
        seed_admin(args.username, password)
        print(f"Seeded analyst user '{args.username}'. Total users: {user_count()}.")
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(_cli(sys.argv[1:]))
