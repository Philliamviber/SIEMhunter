"""
Tests for saved views and query history endpoints (PR3).

Covers:
  - Saving a named view and reopening it restores the filters for that analyst only
  - Identity scoping: views saved by analyst A are not visible to analyst B
  - Deleting a saved view removes it
  - Query history re-run: recording an entry and retrieving it
  - History is capped at MAX_HISTORY_ENTRIES and deduplicates by SQL
  - Unauthenticated / service-token requests are rejected

Session setup mirrors test_analyst_prefs.py — injecting live _Sessions directly.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import services.api.src.auth_analyst as analyst
import services.api.src.db_analyst_prefs as db_prefs
from services.api.src.main import app
from services.api.src.routers.saved_views import MAX_HISTORY_ENTRIES, MAX_VIEWS_PER_PAGE


# ── Per-test isolation ────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _reset(tmp_path):
    db_file = tmp_path / "test_saved_views.db"
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
    analyst.create_user(username, "correct horse battery staple")


def _session(username: str) -> analyst._Session:
    return analyst.create_session(username)


def _client(sess: analyst._Session) -> TestClient:
    c = TestClient(app, raise_server_exceptions=False)
    c.cookies.set(analyst.SESSION_COOKIE_NAME_INSECURE, sess.session_id)
    return c


def _csrf(sess: analyst._Session) -> dict[str, str]:
    return {analyst.CSRF_HEADER_NAME: sess.csrf_token}


# ── Saved views: save / restore ───────────────────────────────────────────────

class TestSavedViews:

    def test_save_and_list_restores_filters_for_same_analyst(self):
        """Saving a named view and listing it returns the stored filters."""
        _seed("alice")
        sess = _session("alice")
        client = _client(sess)

        resp = client.post(
            "/v1/analyst/saved-views",
            json={"name": "Logon failures", "page": "events", "filters": {"event_id": 4625, "hostname": "dc01"}},
            headers=_csrf(sess),
        )
        assert resp.status_code == 200
        views = resp.json()["views"]
        assert len(views) == 1
        assert views[0]["name"] == "Logon failures"
        assert views[0]["filters"]["event_id"] == 4625
        assert views[0]["filters"]["hostname"] == "dc01"

        # GET returns the same data in a fresh list call.
        get_resp = client.get("/v1/analyst/saved-views?page=events")
        assert get_resp.status_code == 200
        assert len(get_resp.json()["views"]) == 1
        assert get_resp.json()["views"][0]["filters"]["event_id"] == 4625

    def test_saved_view_is_scoped_to_analyst_only(self):
        """Analyst B cannot see analyst A's saved views."""
        _seed("alice")
        _seed("bob")
        sess_a = _session("alice")
        sess_b = _session("bob")
        client_a = _client(sess_a)
        client_b = _client(sess_b)

        client_a.post(
            "/v1/analyst/saved-views",
            json={"name": "Alice private", "page": "events", "filters": {"hostname": "alice-host"}},
            headers=_csrf(sess_a),
        )

        resp_b = client_b.get("/v1/analyst/saved-views?page=events")
        assert resp_b.status_code == 200
        assert resp_b.json()["views"] == []

    def test_upsert_overwrites_existing_view_with_same_name(self):
        _seed("alice")
        sess = _session("alice")
        client = _client(sess)

        client.post(
            "/v1/analyst/saved-views",
            json={"name": "My view", "page": "detections", "filters": {"severity": "high"}},
            headers=_csrf(sess),
        )
        # Overwrite with updated filters.
        client.post(
            "/v1/analyst/saved-views",
            json={"name": "My view", "page": "detections", "filters": {"severity": "critical"}},
            headers=_csrf(sess),
        )
        resp = client.get("/v1/analyst/saved-views?page=detections")
        assert resp.status_code == 200
        views = resp.json()["views"]
        assert len(views) == 1
        assert views[0]["filters"]["severity"] == "critical"

    def test_delete_view_removes_it(self):
        _seed("alice")
        sess = _session("alice")
        client = _client(sess)

        client.post(
            "/v1/analyst/saved-views",
            json={"name": "To remove", "page": "query", "filters": {"sql": "SELECT 1"}},
            headers=_csrf(sess),
        )
        resp = client.get("/v1/analyst/saved-views?page=query")
        assert len(resp.json()["views"]) == 1

        del_resp = client.delete("/v1/analyst/saved-views/query/To remove", headers=_csrf(sess))
        assert del_resp.status_code == 200
        assert del_resp.json()["views"] == []

        # Confirm deletion is durable.
        resp2 = client.get("/v1/analyst/saved-views?page=query")
        assert resp2.json()["views"] == []

    def test_list_all_pages_when_no_page_filter(self):
        _seed("alice")
        sess = _session("alice")
        client = _client(sess)

        client.post(
            "/v1/analyst/saved-views",
            json={"name": "E view", "page": "events", "filters": {}},
            headers=_csrf(sess),
        )
        client.post(
            "/v1/analyst/saved-views",
            json={"name": "D view", "page": "detections", "filters": {}},
            headers=_csrf(sess),
        )
        resp = client.get("/v1/analyst/saved-views")
        assert resp.status_code == 200
        pages = {v["page"] for v in resp.json()["views"]}
        assert pages == {"events", "detections"}

    def test_invalid_page_returns_422(self):
        _seed("alice")
        sess = _session("alice")
        client = _client(sess)

        resp = client.post(
            "/v1/analyst/saved-views",
            json={"name": "Bad", "page": "admin", "filters": {}},
            headers=_csrf(sess),
        )
        assert resp.status_code == 422

    def test_empty_name_returns_422(self):
        _seed("alice")
        sess = _session("alice")
        client = _client(sess)

        resp = client.post(
            "/v1/analyst/saved-views",
            json={"name": "  ", "page": "events", "filters": {}},
            headers=_csrf(sess),
        )
        assert resp.status_code == 422

    def test_unauthenticated_returns_401(self):
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/v1/analyst/saved-views")
        assert resp.status_code == 401

    def test_missing_csrf_returns_403(self):
        _seed("alice")
        sess = _session("alice")
        client = _client(sess)
        resp = client.post(
            "/v1/analyst/saved-views",
            json={"name": "No CSRF", "page": "events", "filters": {}},
        )
        assert resp.status_code == 403

    def test_views_survive_across_sessions(self):
        """Saved view written in session 1 is readable in session 2 (durable store)."""
        _seed("alice")
        sess1 = _session("alice")
        client1 = _client(sess1)
        client1.post(
            "/v1/analyst/saved-views",
            json={"name": "Persistent", "page": "search", "filters": {"field_type": "IP", "value": "10.0.0.1"}},
            headers=_csrf(sess1),
        )
        sess2 = _session("alice")
        client2 = _client(sess2)
        resp = client2.get("/v1/analyst/saved-views?page=search")
        assert resp.status_code == 200
        assert resp.json()["views"][0]["name"] == "Persistent"


# ── Query history: record / retrieve / re-run ─────────────────────────────────

class TestQueryHistory:

    def test_history_empty_by_default(self):
        _seed("alice")
        sess = _session("alice")
        client = _client(sess)
        resp = client.get("/v1/analyst/query-history")
        assert resp.status_code == 200
        assert resp.json()["entries"] == []

    def test_add_and_retrieve_entry(self):
        """Adding a query history entry and retrieving it returns the SQL."""
        _seed("alice")
        sess = _session("alice")
        client = _client(sess)
        sql = "SELECT TimeGenerated FROM siemhunter.security_events LIMIT 10"
        resp = client.post(
            "/v1/analyst/query-history",
            json={"sql": sql},
            headers=_csrf(sess),
        )
        assert resp.status_code == 200
        entries = resp.json()["entries"]
        assert len(entries) == 1
        assert entries[0]["sql"] == sql
        assert "run_at" in entries[0]

    def test_history_newest_first(self):
        _seed("alice")
        sess = _session("alice")
        client = _client(sess)
        for i in range(3):
            client.post(
                "/v1/analyst/query-history",
                json={"sql": f"SELECT {i}"},
                headers=_csrf(sess),
            )
        resp = client.get("/v1/analyst/query-history")
        entries = resp.json()["entries"]
        assert entries[0]["sql"] == "SELECT 2"
        assert entries[1]["sql"] == "SELECT 1"
        assert entries[2]["sql"] == "SELECT 0"

    def test_history_capped_at_max_entries(self):
        _seed("alice")
        sess = _session("alice")
        client = _client(sess)
        for i in range(MAX_HISTORY_ENTRIES + 5):
            client.post(
                "/v1/analyst/query-history",
                json={"sql": f"SELECT unique_{i}"},
                headers=_csrf(sess),
            )
        resp = client.get("/v1/analyst/query-history")
        assert len(resp.json()["entries"]) == MAX_HISTORY_ENTRIES

    def test_duplicate_sql_deduplicated_and_promoted(self):
        """Re-running the same SQL moves it to the top instead of duplicating it."""
        _seed("alice")
        sess = _session("alice")
        client = _client(sess)
        sql = "SELECT 1"
        client.post("/v1/analyst/query-history", json={"sql": sql}, headers=_csrf(sess))
        client.post("/v1/analyst/query-history", json={"sql": "SELECT 2"}, headers=_csrf(sess))
        client.post("/v1/analyst/query-history", json={"sql": sql}, headers=_csrf(sess))

        resp = client.get("/v1/analyst/query-history")
        entries = resp.json()["entries"]
        assert entries[0]["sql"] == sql
        sqls = [e["sql"] for e in entries]
        assert sqls.count(sql) == 1

    def test_history_is_scoped_to_analyst(self):
        _seed("alice")
        _seed("bob")
        sess_a = _session("alice")
        sess_b = _session("bob")
        client_a = _client(sess_a)
        client_b = _client(sess_b)

        client_a.post(
            "/v1/analyst/query-history",
            json={"sql": "SELECT * FROM alice_table"},
            headers=_csrf(sess_a),
        )
        resp_b = client_b.get("/v1/analyst/query-history")
        assert resp_b.json()["entries"] == []

    def test_history_unauthenticated_returns_401(self):
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/v1/analyst/query-history")
        assert resp.status_code == 401

    def test_history_missing_csrf_returns_403(self):
        _seed("alice")
        sess = _session("alice")
        client = _client(sess)
        resp = client.post(
            "/v1/analyst/query-history",
            json={"sql": "SELECT 1"},
        )
        assert resp.status_code == 403

    def test_history_empty_sql_returns_422(self):
        _seed("alice")
        sess = _session("alice")
        client = _client(sess)
        resp = client.post(
            "/v1/analyst/query-history",
            json={"sql": "  "},
            headers=_csrf(sess),
        )
        assert resp.status_code == 422
