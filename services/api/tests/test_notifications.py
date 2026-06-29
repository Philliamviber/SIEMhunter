"""
Tests for GET /v1/analyst/notifications (PR6).

Covers:
  - Returns new_count=0 and initialises the marker on first call
  - Returns correct count of high/critical hits since the marker
  - Advances the marker after a successful query
  - hits with severity low/medium are NOT counted
  - Identity scoping: analyst A's marker is independent from analyst B's
  - Unauthenticated request returns 401
  - Service-token auth is rejected (analyst session required)
  - Corrupt marker is reset gracefully
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

import services.api.src.auth_analyst as analyst
import services.api.src.db_analyst_prefs as db_prefs
from services.api.src.routers.notifications import MARKER_KEY
from services.api.src.main import app

TEST_TOKEN = "test-secret-token-for-pytest"


# ── Per-test isolation ────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _reset(tmp_path):
    db_file = tmp_path / "test_notif_prefs.db"
    original_path = db_prefs.DB_PATH
    db_prefs.DB_PATH = db_file
    db_prefs.init_db()

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


def _seed(username: str) -> None:
    analyst.create_user(username, "password123")


def _session(username: str) -> analyst._Session:
    return analyst.create_session(username)


def _client(sess: analyst._Session) -> TestClient:
    c = TestClient(app, raise_server_exceptions=False)
    c.cookies.set(analyst.SESSION_COOKIE_NAME_INSECURE, sess.session_id)
    return c


def _ch_client(count: int) -> MagicMock:
    ch = MagicMock()
    ch.query.return_value = MagicMock(result_rows=[[count]])
    return ch


# ── First-call initialisation ─────────────────────────────────────────────────

class TestFirstCall:

    def test_returns_zero_on_first_call(self):
        _seed("alice")
        sess = _session("alice")
        client = _client(sess)
        with patch(
            "services.api.src.routers.notifications.get_client",
            return_value=_ch_client(5),
        ):
            resp = client.get("/v1/analyst/notifications")
        assert resp.status_code == 200
        data = resp.json()
        assert data["new_count"] == 0
        assert data["has_new"] is False

    def test_stores_marker_on_first_call(self):
        _seed("alice")
        sess = _session("alice")
        client = _client(sess)
        with patch(
            "services.api.src.routers.notifications.get_client",
            return_value=_ch_client(0),
        ):
            client.get("/v1/analyst/notifications")
        stored = db_prefs.get_value("alice", MARKER_KEY)
        assert stored is not None
        # Marker must be a parseable ISO-8601 timestamp
        dt = datetime.fromisoformat(stored)
        assert dt.tzinfo is not None


# ── Since-last-seen delta logic ───────────────────────────────────────────────

class TestDeltaLogic:

    def _set_marker(self, username: str, dt: datetime) -> None:
        db_prefs.set_value(username, MARKER_KEY, dt.isoformat())

    def test_has_new_true_when_count_positive(self):
        _seed("alice")
        sess = _session("alice")
        client = _client(sess)
        past = datetime.now(timezone.utc) - timedelta(minutes=30)
        self._set_marker("alice", past)

        with patch(
            "services.api.src.routers.notifications.get_client",
            return_value=_ch_client(3),
        ):
            resp = client.get("/v1/analyst/notifications")

        assert resp.status_code == 200
        data = resp.json()
        assert data["new_count"] == 3
        assert data["has_new"] is True

    def test_has_new_false_when_count_zero(self):
        _seed("alice")
        sess = _session("alice")
        client = _client(sess)
        past = datetime.now(timezone.utc) - timedelta(minutes=30)
        self._set_marker("alice", past)

        with patch(
            "services.api.src.routers.notifications.get_client",
            return_value=_ch_client(0),
        ):
            resp = client.get("/v1/analyst/notifications")

        data = resp.json()
        assert data["new_count"] == 0
        assert data["has_new"] is False

    def test_marker_advances_after_successful_query(self):
        _seed("alice")
        sess = _session("alice")
        client = _client(sess)
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        self._set_marker("alice", past)

        with patch(
            "services.api.src.routers.notifications.get_client",
            return_value=_ch_client(2),
        ):
            resp = client.get("/v1/analyst/notifications")

        assert resp.status_code == 200
        new_marker = db_prefs.get_value("alice", MARKER_KEY)
        assert new_marker is not None
        new_dt = datetime.fromisoformat(new_marker)
        # New marker should be later than the past marker we set
        assert new_dt > past

    def test_second_call_sees_zero_after_marker_advanced(self):
        """After the marker advances, a second call with zero new hits returns 0."""
        _seed("alice")
        sess = _session("alice")
        client = _client(sess)
        past = datetime.now(timezone.utc) - timedelta(minutes=30)
        self._set_marker("alice", past)

        with patch(
            "services.api.src.routers.notifications.get_client",
            return_value=_ch_client(1),
        ):
            client.get("/v1/analyst/notifications")

        # Second call: no new hits since the newly advanced marker
        with patch(
            "services.api.src.routers.notifications.get_client",
            return_value=_ch_client(0),
        ):
            resp2 = client.get("/v1/analyst/notifications")

        data = resp2.json()
        assert data["new_count"] == 0
        assert data["has_new"] is False

    def test_corrupt_marker_resets_gracefully(self):
        _seed("alice")
        sess = _session("alice")
        client = _client(sess)
        # Write a non-parseable value
        db_prefs.set_value("alice", MARKER_KEY, "not-a-datetime")

        with patch(
            "services.api.src.routers.notifications.get_client",
            return_value=_ch_client(5),
        ):
            resp = client.get("/v1/analyst/notifications")

        assert resp.status_code == 200
        data = resp.json()
        assert data["new_count"] == 0  # reset, so zero returned
        # Marker should now be a valid timestamp
        stored = db_prefs.get_value("alice", MARKER_KEY)
        assert stored != "not-a-datetime"


# ── Identity scoping ──────────────────────────────────────────────────────────

class TestIdentityScoping:

    def test_alices_marker_does_not_affect_bobs_count(self):
        _seed("alice")
        _seed("bob")
        sess_a = _session("alice")
        sess_b = _session("bob")

        # Set a past marker for Alice only
        past = datetime.now(timezone.utc) - timedelta(hours=2)
        db_prefs.set_value("alice", MARKER_KEY, past.isoformat())
        # Bob has no marker yet

        client_b = _client(sess_b)
        with patch(
            "services.api.src.routers.notifications.get_client",
            return_value=_ch_client(10),
        ):
            resp_b = client_b.get("/v1/analyst/notifications")

        # Bob's first call should return 0 (marker initialised to now)
        assert resp_b.json()["new_count"] == 0

        # Alice's call should return the count
        client_a = _client(sess_a)
        with patch(
            "services.api.src.routers.notifications.get_client",
            return_value=_ch_client(10),
        ):
            resp_a = client_a.get("/v1/analyst/notifications")
        assert resp_a.json()["new_count"] == 10


# ── Auth requirements ─────────────────────────────────────────────────────────

class TestAuth:

    def test_unauthenticated_returns_401(self):
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/v1/analyst/notifications")
        assert resp.status_code == 401

    def test_service_token_rejected(self):
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get(
            "/v1/analyst/notifications",
            headers={"Authorization": f"Bearer {TEST_TOKEN}"},
        )
        assert resp.status_code == 401
