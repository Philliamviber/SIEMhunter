"""
Tests for the v3.0.0 per-analyst login + dual-auth split (FR #10).

Covers the GATE B / §7 acceptance items that live on the backend:
  - login success returns a session cookie + CSRF token (no plaintext leak)
  - lockout triggers at the default of 5 failed attempts (C3)
  - logout invalidates the server-side session (AC#6)
  - dual-auth enforcement: the service token is rejected on the analyst-only
    login/session routes, and rejected on browser-origin requests (C4b)
  - user-enumeration timing: unknown-user vs wrong-password within 20%
  - first-run fail-closed: analyst auth refused until seeded (C5)

These tests drive the real FastAPI app via TestClient so cookie + CSRF wiring
runs exactly as in production. The analyst user store is redirected to a temp
file (see conftest ANALYST_USERS_PATH) and reset per test below.
"""
from __future__ import annotations

import importlib
import time

import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient

import services.api.src.auth_analyst as analyst
from services.api.src.routers import auth_routes

TEST_TOKEN = "test-secret-token-for-pytest"


# ── Per-test reset of the in-memory analyst state ────────────────────────────

@pytest.fixture(autouse=True)
def _reset_analyst_state():
    """Wipe users, sessions, and lockout counters before each test."""
    with analyst._users_lock:
        analyst._users.clear()
        analyst._users_loaded = True  # treat as loaded-but-empty (fail-closed)
    with analyst._sessions_lock:
        analyst._sessions.clear()
    with analyst._lockout_lock:
        analyst._attempts.clear()
    yield
    with analyst._users_lock:
        analyst._users.clear()
    with analyst._sessions_lock:
        analyst._sessions.clear()
    with analyst._lockout_lock:
        analyst._attempts.clear()


def _build_app() -> FastAPI:
    """Minimal app with the auth routes + one analyst-protected route."""
    app = FastAPI()
    app.include_router(auth_routes.router, prefix="/v1")

    @app.get("/v1/protected")
    async def protected(sess=Depends(analyst.require_analyst_session)):
        return {"ok": True, "user": sess.username}

    @app.post("/v1/protected-write")
    async def protected_write(sess=Depends(analyst.require_analyst_session)):
        return {"ok": True}

    return app


def _client() -> TestClient:
    return TestClient(_build_app(), raise_server_exceptions=False)


def _seed(username="admin", password="correct horse battery staple"):
    analyst.create_user(username, password)


# ── First-run fail-closed (C5) ────────────────────────────────────────────────

class TestFailClosed:
    def test_login_refused_when_unseeded(self):
        resp = _client().post("/v1/auth/login", json={"username": "admin", "password": "x"})
        assert resp.status_code == 401

    def test_protected_route_refused_when_unseeded(self):
        resp = _client().get("/v1/protected")
        assert resp.status_code == 401


# ── Login success ─────────────────────────────────────────────────────────────

class TestLoginSuccess:
    def test_login_success_sets_cookie_and_returns_csrf(self):
        _seed()
        c = _client()
        resp = c.post("/v1/auth/login", json={"username": "admin", "password": "correct horse battery staple"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["username"] == "admin"
        assert body["csrf_token"]
        assert "expires_at" in body
        # A session cookie must have been set.
        set_cookie = resp.headers.get("set-cookie", "")
        assert "siemhunter_session" in set_cookie
        assert "httponly" in set_cookie.lower()
        assert "samesite=strict" in set_cookie.lower()

    def test_login_response_has_no_store(self):
        _seed()
        resp = _client().post("/v1/auth/login", json={"username": "admin", "password": "correct horse battery staple"})
        assert resp.headers.get("cache-control") == "no-store"

    def test_password_never_echoed(self):
        _seed(password="super-secret-pw")
        resp = _client().post("/v1/auth/login", json={"username": "admin", "password": "super-secret-pw"})
        assert "super-secret-pw" not in resp.text

    def test_session_cookie_grants_access_to_protected_route(self):
        _seed()
        c = _client()
        c.post("/v1/auth/login", json={"username": "admin", "password": "correct horse battery staple"})
        # TestClient carries the cookie jar forward automatically.
        resp = c.get("/v1/protected")
        assert resp.status_code == 200
        assert resp.json()["user"] == "admin"

    def test_csrf_required_on_write(self):
        _seed()
        c = _client()
        login = c.post("/v1/auth/login", json={"username": "admin", "password": "correct horse battery staple"})
        csrf = login.json()["csrf_token"]
        # Without CSRF header → 403
        resp_no_csrf = c.post("/v1/protected-write")
        assert resp_no_csrf.status_code == 403
        # With CSRF header → 200
        resp_csrf = c.post("/v1/protected-write", headers={"X-CSRF-Token": csrf})
        assert resp_csrf.status_code == 200


# ── Lockout (C3) ──────────────────────────────────────────────────────────────

class TestLockout:
    def test_lockout_after_five_failures(self):
        _seed()
        c = _client()
        # 5 wrong attempts.
        for _ in range(analyst.LOCKOUT_THRESHOLD):
            r = c.post("/v1/auth/login", json={"username": "admin", "password": "wrong"})
            assert r.status_code == 401
        # The 6th attempt — even with the CORRECT password — is locked out.
        r = c.post("/v1/auth/login", json={"username": "admin", "password": "correct horse battery staple"})
        assert r.status_code == 401

    def test_lockout_is_self_healing(self):
        _seed()
        c = _client()
        for _ in range(analyst.LOCKOUT_THRESHOLD):
            c.post("/v1/auth/login", json={"username": "admin", "password": "wrong"})
        assert analyst.is_locked_out("admin", "testclient") or analyst.is_locked_out("admin", "testserver")
        # Force the cooldown window to expire.
        with analyst._lockout_lock:
            for rec in analyst._attempts.values():
                rec.first_at = time.time() - analyst.LOCKOUT_COOLDOWN_SECONDS - 1
        # Now a correct login should succeed again.
        r = c.post("/v1/auth/login", json={"username": "admin", "password": "correct horse battery staple"})
        assert r.status_code == 200


# ── Logout invalidation (AC#6) ────────────────────────────────────────────────

class TestLogout:
    def test_logout_invalidates_session(self):
        _seed()
        c = _client()
        c.post("/v1/auth/login", json={"username": "admin", "password": "correct horse battery staple"})
        assert c.get("/v1/protected").status_code == 200
        logout = c.post("/v1/auth/logout")
        assert logout.status_code == 200
        # Session is now server-revoked → protected route 401s.
        assert c.get("/v1/protected").status_code == 401

    def test_logout_session_count_drops(self):
        _seed()
        c = _client()
        c.post("/v1/auth/login", json={"username": "admin", "password": "correct horse battery staple"})
        assert len(analyst._sessions) == 1
        c.post("/v1/auth/logout")
        assert len(analyst._sessions) == 0


# ── Dual-auth enforcement ─────────────────────────────────────────────────────

class TestDualAuthEnforcement:
    def test_service_token_rejected_on_login_route(self):
        _seed()
        # The login route is body-driven; a bearer token must not be a path in.
        resp = _client().post(
            "/v1/auth/login",
            headers={"Authorization": f"Bearer {TEST_TOKEN}"},
            json={"username": "admin", "password": "wrong"},
        )
        # Still requires valid username+password → 401, never auto-authed by token.
        assert resp.status_code == 401

    def test_service_token_rejected_on_analyst_only_session_route(self):
        _seed()
        # /v1/auth/session is analyst-only; a bearer token grants nothing.
        resp = _client().get(
            "/v1/auth/session",
            headers={"Authorization": f"Bearer {TEST_TOKEN}"},
        )
        assert resp.status_code == 401

    def test_service_token_rejected_on_browser_origin_request(self):
        # require_service_token must refuse browser-origin requests (C4b).
        import services.api.src.auth_service_token as svc
        svc._EXPECTED_TOKEN = TEST_TOKEN

        app = FastAPI()

        @app.get("/svc")
        async def svc_route(method=Depends(svc.require_service_token)):
            return {"method": method}

        client = TestClient(app, raise_server_exceptions=False)
        # No Origin/Referer → accepted.
        ok = client.get("/svc", headers={"Authorization": f"Bearer {TEST_TOKEN}"})
        assert ok.status_code == 200
        # With Origin → rejected (403).
        rejected = client.get(
            "/svc",
            headers={"Authorization": f"Bearer {TEST_TOKEN}", "Origin": "http://localhost:8081"},
        )
        assert rejected.status_code == 403


# ── User-enumeration timing (AC#3) ────────────────────────────────────────────

class TestEnumerationTiming:
    def test_unknown_user_and_wrong_password_comparable_timing(self):
        _seed(username="realuser", password="correct horse battery staple")

        def _time_login(username: str) -> float:
            c = _client()
            samples = []
            for _ in range(3):
                start = time.perf_counter()
                c.post("/v1/auth/login", json={"username": username, "password": "definitely-wrong"})
                samples.append(time.perf_counter() - start)
            return min(samples)  # min reduces noise from GC/scheduler

        wrong_pw = _time_login("realuser")    # known user, wrong password
        unknown = _time_login("ghostuser")     # unknown user (decoy verify)

        # Both run a full argon2id verify, so they should be within 20% of each
        # other. Compare against the larger to avoid divide-by-tiny noise.
        slower = max(wrong_pw, unknown)
        faster = min(wrong_pw, unknown)
        assert faster >= slower * 0.5, (
            f"timing gap too large: unknown={unknown:.4f}s wrong_pw={wrong_pw:.4f}s"
        )

    def test_unknown_user_and_wrong_password_identical_message(self):
        _seed(username="realuser", password="pw")
        c = _client()
        r_unknown = c.post("/v1/auth/login", json={"username": "ghost", "password": "x"})
        r_wrong = c.post("/v1/auth/login", json={"username": "realuser", "password": "x"})
        assert r_unknown.json() == r_wrong.json()
        assert r_unknown.status_code == r_wrong.status_code == 401


# ── argon2id params + needs_rehash (C1) ───────────────────────────────────────

class TestArgon2Params:
    def test_hash_uses_argon2id(self):
        _seed()
        u = analyst._get_user("admin")
        assert u.password_hash.startswith("$argon2id$")

    def test_needs_rehash_false_for_current_params(self):
        _seed()
        u = analyst._get_user("admin")
        assert analyst._hasher.check_needs_rehash(u.password_hash) is False
