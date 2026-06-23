"""
Tests for incident notes endpoints (FR #19).

Endpoints covered:
  POST /v1/incidents/{id}/notes   — append a note (author/timestamp server-set)
  GET  /v1/incidents/{id}/notes   — list notes for an incident

Append-only guarantee: no PUT/PATCH/DELETE routes exist for individual notes.
Server authorship: the author field is derived from the authenticated identity;
  the client cannot supply or override it (CreateNoteRequest has no author field).
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

import pytest
from fastapi.testclient import TestClient

from services.api.src.main import app

TEST_TOKEN = "test-secret-token-for-pytest"
AUTH = {"Authorization": f"Bearer {TEST_TOKEN}"}


def _make_incident_row(incident_id: str | None = None) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    return {
        "id": incident_id or str(uuid.uuid4()),
        "name": "Test Incident",
        "description": None,
        "severity": "high",
        "status": "open",
        "created_at": now,
        "updated_at": now,
        "event_count": 0,
    }


def _make_note_row(
    incident_id: str,
    *,
    author: str = "service_token",
    content: str = "Investigation ongoing.",
    note_id: str | None = None,
) -> dict:
    return {
        "id": note_id or str(uuid.uuid4()),
        "incident_id": incident_id,
        "author": author,
        "content": content,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


def _client() -> TestClient:
    return TestClient(app, raise_server_exceptions=False)


# ── POST /v1/incidents/{id}/notes ─────────────────────────────────────────────

class TestCreateNote:

    def test_create_returns_201(self):
        inc = _make_incident_row()
        note = _make_note_row(inc["id"])
        with patch("services.api.src.routers.incidents.db_incidents") as mock_db:
            mock_db.get_incident.return_value = inc
            mock_db.create_note.return_value = note
            resp = _client().post(
                f"/v1/incidents/{inc['id']}/notes",
                json={"content": "Investigation ongoing."},
                headers=AUTH,
            )
        assert resp.status_code == 201

    def test_create_response_has_required_fields(self):
        inc = _make_incident_row()
        note = _make_note_row(inc["id"])
        with patch("services.api.src.routers.incidents.db_incidents") as mock_db:
            mock_db.get_incident.return_value = inc
            mock_db.create_note.return_value = note
            resp = _client().post(
                f"/v1/incidents/{inc['id']}/notes",
                json={"content": "Check logs."},
                headers=AUTH,
            )
        body = resp.json()
        for field in ("id", "incident_id", "author", "content", "created_at"):
            assert field in body, f"Missing field: {field}"

    def test_create_author_is_service_token_for_bearer_auth(self):
        """Server sets author from auth identity; bearer token → 'service_token'."""
        inc = _make_incident_row()
        note = _make_note_row(inc["id"], author="service_token")
        with patch("services.api.src.routers.incidents.db_incidents") as mock_db:
            mock_db.get_incident.return_value = inc
            mock_db.create_note.return_value = note
            resp = _client().post(
                f"/v1/incidents/{inc['id']}/notes",
                json={"content": "Evidence gathered."},
                headers=AUTH,
            )
        assert resp.json()["author"] == "service_token"

    def test_create_author_cannot_be_overridden_by_client(self):
        """CreateNoteRequest has no author field; extra JSON keys are silently ignored."""
        inc = _make_incident_row()
        note = _make_note_row(inc["id"], author="service_token")
        with patch("services.api.src.routers.incidents.db_incidents") as mock_db:
            mock_db.get_incident.return_value = inc
            mock_db.create_note.return_value = note
            resp = _client().post(
                f"/v1/incidents/{inc['id']}/notes",
                # Client attempts to supply author — FastAPI ignores unknown fields.
                json={"content": "Attempting override.", "author": "attacker"},
                headers=AUTH,
            )
        assert resp.status_code == 201
        # The author in the response comes from the server (mock returns service_token).
        assert resp.json()["author"] == "service_token"

    def test_create_db_receives_server_supplied_author(self):
        """Verify db_incidents.create_note is called with the auth identity, not a client value."""
        inc = _make_incident_row()
        note = _make_note_row(inc["id"], author="service_token", content="Confirmed IOC.")
        with patch("services.api.src.routers.incidents.db_incidents") as mock_db:
            mock_db.get_incident.return_value = inc
            mock_db.create_note.return_value = note
            _client().post(
                f"/v1/incidents/{inc['id']}/notes",
                json={"content": "Confirmed IOC.", "author": "hacker"},
                headers=AUTH,
            )
            call_kwargs = mock_db.create_note.call_args
            assert call_kwargs is not None
            # author kwarg must be "service_token" (from server), never "hacker".
            assert call_kwargs.kwargs.get("author") == "service_token"

    def test_create_incident_not_found_returns_404(self):
        with patch("services.api.src.routers.incidents.db_incidents") as mock_db:
            mock_db.get_incident.return_value = None
            resp = _client().post(
                "/v1/incidents/ghost/notes",
                json={"content": "Test note."},
                headers=AUTH,
            )
        assert resp.status_code == 404
        assert resp.json()["detail"]["code"] == "NOT_FOUND"

    def test_create_no_token_returns_401(self):
        resp = _client().post(
            "/v1/incidents/any-id/notes",
            json={"content": "Unauth note."},
        )
        assert resp.status_code == 401

    def test_create_empty_content_returns_422(self):
        resp = _client().post(
            "/v1/incidents/any-id/notes",
            json={"content": "   "},
            headers=AUTH,
        )
        assert resp.status_code == 422

    def test_create_missing_content_returns_422(self):
        resp = _client().post(
            "/v1/incidents/any-id/notes",
            json={},
            headers=AUTH,
        )
        assert resp.status_code == 422

    def test_create_content_too_long_returns_422(self):
        resp = _client().post(
            "/v1/incidents/any-id/notes",
            json={"content": "x" * 10_001},
            headers=AUTH,
        )
        assert resp.status_code == 422

    def test_create_timestamp_is_in_response(self):
        inc = _make_incident_row()
        note = _make_note_row(inc["id"])
        with patch("services.api.src.routers.incidents.db_incidents") as mock_db:
            mock_db.get_incident.return_value = inc
            mock_db.create_note.return_value = note
            resp = _client().post(
                f"/v1/incidents/{inc['id']}/notes",
                json={"content": "Note with timestamp."},
                headers=AUTH,
            )
        assert "created_at" in resp.json()


# ── GET /v1/incidents/{id}/notes ──────────────────────────────────────────────

class TestListNotes:

    def test_list_returns_200(self):
        inc = _make_incident_row()
        with patch("services.api.src.routers.incidents.db_incidents") as mock_db:
            mock_db.get_incident.return_value = inc
            mock_db.list_notes.return_value = []
            resp = _client().get(f"/v1/incidents/{inc['id']}/notes", headers=AUTH)
        assert resp.status_code == 200

    def test_list_response_has_notes_array(self):
        inc = _make_incident_row()
        with patch("services.api.src.routers.incidents.db_incidents") as mock_db:
            mock_db.get_incident.return_value = inc
            mock_db.list_notes.return_value = []
            resp = _client().get(f"/v1/incidents/{inc['id']}/notes", headers=AUTH)
        body = resp.json()
        assert "notes" in body
        assert isinstance(body["notes"], list)

    def test_list_returns_total_count(self):
        inc = _make_incident_row()
        notes = [_make_note_row(inc["id"]) for _ in range(3)]
        with patch("services.api.src.routers.incidents.db_incidents") as mock_db:
            mock_db.get_incident.return_value = inc
            mock_db.list_notes.return_value = notes
            resp = _client().get(f"/v1/incidents/{inc['id']}/notes", headers=AUTH)
        body = resp.json()
        assert body["total"] == 3
        assert len(body["notes"]) == 3

    def test_list_note_has_all_fields(self):
        inc = _make_incident_row()
        note = _make_note_row(inc["id"], author="analyst1", content="Pivoted on IP.")
        with patch("services.api.src.routers.incidents.db_incidents") as mock_db:
            mock_db.get_incident.return_value = inc
            mock_db.list_notes.return_value = [note]
            resp = _client().get(f"/v1/incidents/{inc['id']}/notes", headers=AUTH)
        item = resp.json()["notes"][0]
        assert item["author"] == "analyst1"
        assert item["content"] == "Pivoted on IP."
        assert "created_at" in item

    def test_list_incident_not_found_returns_404(self):
        with patch("services.api.src.routers.incidents.db_incidents") as mock_db:
            mock_db.get_incident.return_value = None
            resp = _client().get("/v1/incidents/ghost/notes", headers=AUTH)
        assert resp.status_code == 404

    def test_list_no_token_returns_401(self):
        resp = _client().get("/v1/incidents/any-id/notes")
        assert resp.status_code == 401


# ── Append-only guarantee ─────────────────────────────────────────────────────

class TestAppendOnly:
    """Verify that no edit or delete routes exist for individual notes."""

    INC_ID = "test-incident-id"
    NOTE_ID = "test-note-id"

    def test_put_note_not_routed(self):
        resp = _client().put(
            f"/v1/incidents/{self.INC_ID}/notes/{self.NOTE_ID}",
            json={"content": "Modified."},
            headers=AUTH,
        )
        assert resp.status_code in (404, 405)

    def test_patch_note_not_routed(self):
        resp = _client().patch(
            f"/v1/incidents/{self.INC_ID}/notes/{self.NOTE_ID}",
            json={"content": "Modified."},
            headers=AUTH,
        )
        assert resp.status_code in (404, 405)

    def test_delete_note_not_routed(self):
        resp = _client().delete(
            f"/v1/incidents/{self.INC_ID}/notes/{self.NOTE_ID}",
            headers=AUTH,
        )
        assert resp.status_code in (404, 405)
