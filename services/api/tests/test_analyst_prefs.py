"""
Tests for the per-analyst preferences persistence layer (PR2).

Covers:
  - db_analyst_prefs: create/read plus identity scoping (a different analyst
    cannot read or overwrite another analyst's values)
  - GET  /v1/analyst/preferences  — returns defaults when nothing is stored;
                                    returns stored values after a PUT
  - PUT  /v1/analyst/preferences  — stores values keyed to the session identity
  - Identity scoping: values written as analyst A are NOT visible as analyst B
  - Service-token auth is rejected (analyst session required)

Session setup: directly inject a live _Session into the auth_analyst session
store and pass the session cookie + CSRF header so the full FastAPI dependency
stack is exercised without bypassing any auth logic.
"""
from __future__ import annotations

import os
import tempfile

import pytest
from fastapi.testclient import TestClient

import services.api.src.auth_analyst as analyst
import services.api.src.db_analyst_prefs as db_prefs
from services.api.src.main import app

TEST_TOKEN = "test-secret-token-for-pytest"


# ── Per-test isolation ────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _reset_analyst_and_prefs(tmp_path):
    """Wipe in-memory analyst state and redirect the prefs DB to a temp file."""
    # Redirect the prefs DB so tests never touch the real /data path.
    db_file = tmp_path / "test_prefs.db"
    original_path = db_prefs.DB_PATH
    db_prefs.DB_PATH = db_file
    db_prefs.init_db()

    # Reset analyst in-memory state.
    with analyst._users_lock:
        analyst._users.clear()
        analyst._users_loaded = True
    with analyst._sessions_lock:
        analyst._sessions.clear()
    with analyst._lockout_lock:
        analyst._attempts.clear()

    yield

    db_prefs.DB_PATH = original_path

    with analyst._users_lock:
        analyst._users.clear()
    with analyst._sessions_lock:
        analyst._sessions.clear()
    with analyst._lockout_lock:
        analyst._attempts.clear()


def _seed(username: str, password: str = "correct horse battery staple") -> None:
    analyst.create_user(username, password)


def _login_session(username: str) -> analyst._Session:
    """Create a live server-side session for username (user must already be seeded)."""
    return analyst.create_session(username)


def _client_with_session(sess: analyst._Session) -> TestClient:
    """Return a TestClient with the session cookie pre-set."""
    client = TestClient(app, raise_server_exceptions=False)
    # Use the insecure cookie name (test client runs over http://testserver).
    client.cookies.set(analyst.SESSION_COOKIE_NAME_INSECURE, sess.session_id)
    return client


def _csrf(sess: analyst._Session) -> dict[str, str]:
    return {analyst.CSRF_HEADER_NAME: sess.csrf_token}


# ── db_analyst_prefs unit tests ───────────────────────────────────────────────

class TestDbAnalystPrefs:

    def test_get_value_returns_none_when_absent(self):
        assert db_prefs.get_value("alice", "key") is None

    def test_set_and_get_value(self):
        db_prefs.set_value("alice", "default_time_range", "7d")
        assert db_prefs.get_value("alice", "default_time_range") == "7d"

    def test_set_overwrites_existing(self):
        db_prefs.set_value("alice", "table_density", "compact")
        db_prefs.set_value("alice", "table_density", "spacious")
        assert db_prefs.get_value("alice", "table_density") == "spacious"

    def test_get_all_returns_only_this_analysts_keys(self):
        db_prefs.set_value("alice", "k1", "v1")
        db_prefs.set_value("bob", "k1", "v_bob")
        result = db_prefs.get_all("alice")
        assert result == {"k1": "v1"}

    def test_identity_scoping_different_analysts_isolated(self):
        db_prefs.set_value("alice", "default_time_range", "1h")
        db_prefs.set_value("bob", "default_time_range", "30d")
        assert db_prefs.get_value("alice", "default_time_range") == "1h"
        assert db_prefs.get_value("bob", "default_time_range") == "30d"

    def test_bob_cannot_read_alices_value_by_key(self):
        db_prefs.set_value("alice", "secret_key", "secret_value")
        # Bob's view of the same key is absent (returns None).
        assert db_prefs.get_value("bob", "secret_key") is None


# ── GET /v1/analyst/preferences ──────────────────────────────────────────────

class TestGetPreferences:

    def test_returns_defaults_when_nothing_stored(self):
        _seed("alice")
        sess = _login_session("alice")
        client = _client_with_session(sess)
        resp = client.get("/v1/analyst/preferences")
        assert resp.status_code == 200
        data = resp.json()
        assert data["default_time_range"] == "24h"
        assert data["table_density"] == "comfortable"
        assert data["default_landing_page"] == "/"

    def test_returns_stored_values_after_put(self):
        _seed("alice")
        sess = _login_session("alice")
        client = _client_with_session(sess)
        client.put(
            "/v1/analyst/preferences",
            json={"default_time_range": "7d", "table_density": "compact"},
            headers=_csrf(sess),
        )
        resp = client.get("/v1/analyst/preferences")
        assert resp.status_code == 200
        data = resp.json()
        assert data["default_time_range"] == "7d"
        assert data["table_density"] == "compact"
        assert data["default_landing_page"] == "/"

    def test_unauthenticated_returns_401(self):
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/v1/analyst/preferences")
        assert resp.status_code == 401

    def test_service_token_rejected(self):
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get(
            "/v1/analyst/preferences",
            headers={"Authorization": f"Bearer {TEST_TOKEN}"},
        )
        assert resp.status_code == 401


# ── PUT /v1/analyst/preferences ──────────────────────────────────────────────

class TestPutPreferences:

    def test_partial_update_does_not_wipe_other_fields(self):
        _seed("alice")
        sess = _login_session("alice")
        client = _client_with_session(sess)
        # Set all three fields.
        client.put(
            "/v1/analyst/preferences",
            json={"default_time_range": "7d", "table_density": "compact", "default_landing_page": "/events"},
            headers=_csrf(sess),
        )
        # Update only one field.
        client.put(
            "/v1/analyst/preferences",
            json={"table_density": "spacious"},
            headers=_csrf(sess),
        )
        resp = client.get("/v1/analyst/preferences")
        data = resp.json()
        assert data["default_time_range"] == "7d"
        assert data["table_density"] == "spacious"
        assert data["default_landing_page"] == "/events"

    def test_invalid_time_range_returns_422(self):
        _seed("alice")
        sess = _login_session("alice")
        client = _client_with_session(sess)
        resp = client.put(
            "/v1/analyst/preferences",
            json={"default_time_range": "99y"},
            headers=_csrf(sess),
        )
        assert resp.status_code == 422

    def test_invalid_density_returns_422(self):
        _seed("alice")
        sess = _login_session("alice")
        client = _client_with_session(sess)
        resp = client.put(
            "/v1/analyst/preferences",
            json={"table_density": "ultra-compact"},
            headers=_csrf(sess),
        )
        assert resp.status_code == 422

    def test_invalid_landing_page_returns_422(self):
        _seed("alice")
        sess = _login_session("alice")
        client = _client_with_session(sess)
        resp = client.put(
            "/v1/analyst/preferences",
            json={"default_landing_page": "/admin"},
            headers=_csrf(sess),
        )
        assert resp.status_code == 422

    def test_missing_csrf_returns_403(self):
        _seed("alice")
        sess = _login_session("alice")
        client = _client_with_session(sess)
        resp = client.put(
            "/v1/analyst/preferences",
            json={"table_density": "compact"},
            # No CSRF header
        )
        assert resp.status_code == 403

    def test_unauthenticated_returns_401(self):
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.put(
            "/v1/analyst/preferences",
            json={"table_density": "compact"},
        )
        assert resp.status_code == 401


# ── Identity scoping across sessions ──────────────────────────────────────────

class TestIdentityScoping:

    def test_analyst_a_cannot_see_analyst_b_preferences(self):
        _seed("alice")
        _seed("bob")
        sess_a = _login_session("alice")
        sess_b = _login_session("bob")
        client_a = _client_with_session(sess_a)
        client_b = _client_with_session(sess_b)

        # Alice sets a distinctive preference.
        client_a.put(
            "/v1/analyst/preferences",
            json={"default_time_range": "1h"},
            headers=_csrf(sess_a),
        )

        # Bob's view is unaffected — he sees the default, not Alice's value.
        resp_b = client_b.get("/v1/analyst/preferences")
        assert resp_b.status_code == 200
        assert resp_b.json()["default_time_range"] == "24h"

    def test_analyst_b_write_does_not_affect_analyst_a(self):
        _seed("alice")
        _seed("bob")
        sess_a = _login_session("alice")
        sess_b = _login_session("bob")
        client_a = _client_with_session(sess_a)
        client_b = _client_with_session(sess_b)

        client_a.put(
            "/v1/analyst/preferences",
            json={"table_density": "compact"},
            headers=_csrf(sess_a),
        )
        client_b.put(
            "/v1/analyst/preferences",
            json={"table_density": "spacious"},
            headers=_csrf(sess_b),
        )

        resp_a = client_a.get("/v1/analyst/preferences")
        assert resp_a.json()["table_density"] == "compact"

    def test_preferences_survive_across_fresh_sessions(self):
        """A written preference is readable in a new session (durable store)."""
        _seed("alice")
        sess1 = _login_session("alice")
        client1 = _client_with_session(sess1)
        client1.put(
            "/v1/analyst/preferences",
            json={"default_landing_page": "/detections"},
            headers=_csrf(sess1),
        )

        # Simulate a reload: new session for the same analyst.
        sess2 = _login_session("alice")
        client2 = _client_with_session(sess2)
        resp = client2.get("/v1/analyst/preferences")
        assert resp.status_code == 200
        assert resp.json()["default_landing_page"] == "/detections"
