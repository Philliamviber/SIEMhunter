"""
Tests for services/api/src/routers/incidents.py

Endpoints covered:
  POST   /v1/incidents                      — create incident
  GET    /v1/incidents                      — list incidents
  GET    /v1/incidents/{id}                 — get by id
  PATCH  /v1/incidents/{id}/status         — update status

Strategy
--------
db_incidents is patched at the router's local name so no real SQLite database
is ever created or read during the test run.  Each test class controls the
mock's return value to exercise the specific code path it targets.
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

# ── Shared fixture row factory ────────────────────────────────────────────────

def _make_incident_row(
    *,
    incident_id: str | None = None,
    name: str = "Test Incident",
    description: str | None = "A test incident",
    severity: str = "high",
    status: str = "open",
) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    return {
        "id": incident_id or str(uuid.uuid4()),
        "name": name,
        "description": description,
        "severity": severity,
        "status": status,
        "created_at": now,
        "updated_at": now,
        "event_count": 0,
    }


def _client():
    return TestClient(app, raise_server_exceptions=False)


# ── POST /v1/incidents ────────────────────────────────────────────────────────

class TestCreateIncident:

    def test_create_returns_201(self):
        row = _make_incident_row()
        with patch("services.api.src.routers.incidents.db_incidents") as mock_db:
            mock_db.create_incident.return_value = row
            resp = _client().post(
                "/v1/incidents",
                json={"name": "Brute Force Campaign", "severity": "high"},
                headers=AUTH,
            )
        assert resp.status_code == 201

    def test_create_returns_id_in_response(self):
        row = _make_incident_row(name="Brute Force Campaign")
        with patch("services.api.src.routers.incidents.db_incidents") as mock_db:
            mock_db.create_incident.return_value = row
            resp = _client().post(
                "/v1/incidents",
                json={"name": "Brute Force Campaign", "severity": "high"},
                headers=AUTH,
            )
        body = resp.json()
        assert "id" in body
        assert body["id"] == row["id"]

    def test_create_response_has_expected_fields(self):
        row = _make_incident_row()
        with patch("services.api.src.routers.incidents.db_incidents") as mock_db:
            mock_db.create_incident.return_value = row
            resp = _client().post(
                "/v1/incidents",
                json={"name": "X", "severity": "low"},
                headers=AUTH,
            )
        body = resp.json()
        for field in ("id", "name", "severity", "status", "created_at", "updated_at", "event_count"):
            assert field in body, f"Missing field: {field}"

    def test_create_with_description(self):
        row = _make_incident_row(name="With Description", description="Details here")
        with patch("services.api.src.routers.incidents.db_incidents") as mock_db:
            mock_db.create_incident.return_value = row
            resp = _client().post(
                "/v1/incidents",
                json={"name": "With Description", "description": "Details here", "severity": "medium"},
                headers=AUTH,
            )
        assert resp.status_code == 201
        assert resp.json()["description"] == "Details here"

    def test_create_invalid_severity_returns_422(self):
        resp = _client().post(
            "/v1/incidents",
            json={"name": "Bad Severity", "severity": "extreme"},
            headers=AUTH,
        )
        assert resp.status_code == 422

    def test_create_missing_name_returns_422(self):
        resp = _client().post(
            "/v1/incidents",
            json={"severity": "low"},
            headers=AUTH,
        )
        assert resp.status_code == 422

    def test_create_missing_severity_returns_422(self):
        resp = _client().post(
            "/v1/incidents",
            json={"name": "No severity"},
            headers=AUTH,
        )
        assert resp.status_code == 422

    def test_create_no_token_returns_401(self):
        resp = _client().post(
            "/v1/incidents",
            json={"name": "Unauth", "severity": "low"},
        )
        assert resp.status_code == 401

    def test_create_all_valid_severities_accepted(self):
        for sev in ("low", "medium", "high", "critical"):
            row = _make_incident_row(severity=sev)
            with patch("services.api.src.routers.incidents.db_incidents") as mock_db:
                mock_db.create_incident.return_value = row
                resp = _client().post(
                    "/v1/incidents",
                    json={"name": f"Incident-{sev}", "severity": sev},
                    headers=AUTH,
                )
            assert resp.status_code == 201, f"Expected 201 for severity={sev}"


# ── GET /v1/incidents ─────────────────────────────────────────────────────────

class TestListIncidents:

    def test_list_returns_200(self):
        with patch("services.api.src.routers.incidents.db_incidents") as mock_db:
            mock_db.list_incidents.return_value = []
            resp = _client().get("/v1/incidents", headers=AUTH)
        assert resp.status_code == 200

    def test_list_response_has_incidents_array(self):
        with patch("services.api.src.routers.incidents.db_incidents") as mock_db:
            mock_db.list_incidents.return_value = []
            resp = _client().get("/v1/incidents", headers=AUTH)
        body = resp.json()
        assert "incidents" in body
        assert isinstance(body["incidents"], list)

    def test_list_response_has_total_field(self):
        with patch("services.api.src.routers.incidents.db_incidents") as mock_db:
            mock_db.list_incidents.return_value = []
            resp = _client().get("/v1/incidents", headers=AUTH)
        assert "total" in resp.json()

    def test_list_returns_all_incidents(self):
        rows = [_make_incident_row(name=f"INC-{i}") for i in range(3)]
        with patch("services.api.src.routers.incidents.db_incidents") as mock_db:
            mock_db.list_incidents.return_value = rows
            resp = _client().get("/v1/incidents", headers=AUTH)
        body = resp.json()
        assert body["total"] == 3
        assert len(body["incidents"]) == 3

    def test_list_no_token_returns_401(self):
        resp = _client().get("/v1/incidents")
        assert resp.status_code == 401


# ── GET /v1/incidents/{id} ────────────────────────────────────────────────────

class TestGetIncident:

    def test_get_existing_incident_returns_200(self):
        row = _make_incident_row()
        inc_id = row["id"]
        with patch("services.api.src.routers.incidents.db_incidents") as mock_db:
            mock_db.get_incident.return_value = row
            resp = _client().get(f"/v1/incidents/{inc_id}", headers=AUTH)
        assert resp.status_code == 200

    def test_get_returns_correct_id(self):
        row = _make_incident_row()
        inc_id = row["id"]
        with patch("services.api.src.routers.incidents.db_incidents") as mock_db:
            mock_db.get_incident.return_value = row
            resp = _client().get(f"/v1/incidents/{inc_id}", headers=AUTH)
        assert resp.json()["id"] == inc_id

    def test_get_returns_detail_fields(self):
        row = _make_incident_row(name="Detailed Incident")
        inc_id = row["id"]
        with patch("services.api.src.routers.incidents.db_incidents") as mock_db:
            mock_db.get_incident.return_value = row
            resp = _client().get(f"/v1/incidents/{inc_id}", headers=AUTH)
        body = resp.json()
        assert body["name"] == "Detailed Incident"
        assert body["severity"] == "high"
        assert body["status"] == "open"

    def test_get_nonexistent_returns_404(self):
        with patch("services.api.src.routers.incidents.db_incidents") as mock_db:
            mock_db.get_incident.return_value = None
            resp = _client().get("/v1/incidents/does-not-exist", headers=AUTH)
        assert resp.status_code == 404

    def test_get_404_body_has_not_found_code(self):
        with patch("services.api.src.routers.incidents.db_incidents") as mock_db:
            mock_db.get_incident.return_value = None
            resp = _client().get("/v1/incidents/ghost-id", headers=AUTH)
        assert resp.json()["detail"]["code"] == "NOT_FOUND"

    def test_get_no_token_returns_401(self):
        resp = _client().get("/v1/incidents/any-id")
        assert resp.status_code == 401


# ── PATCH /v1/incidents/{id}/status ──────────────────────────────────────────

class TestUpdateIncidentStatus:

    def test_patch_status_to_closed_returns_200(self):
        row = _make_incident_row()
        inc_id = row["id"]
        updated = {**row, "status": "closed"}
        with patch("services.api.src.routers.incidents.db_incidents") as mock_db:
            mock_db.get_incident.return_value = row
            mock_db.update_incident_status.return_value = updated
            resp = _client().patch(
                f"/v1/incidents/{inc_id}/status",
                json={"new_status": "closed"},
                headers=AUTH,
            )
        assert resp.status_code == 200

    def test_patch_status_response_reflects_new_status(self):
        row = _make_incident_row()
        inc_id = row["id"]
        updated = {**row, "status": "closed"}
        with patch("services.api.src.routers.incidents.db_incidents") as mock_db:
            mock_db.get_incident.return_value = row
            mock_db.update_incident_status.return_value = updated
            resp = _client().patch(
                f"/v1/incidents/{inc_id}/status",
                json={"new_status": "closed"},
                headers=AUTH,
            )
        assert resp.json()["status"] == "closed"

    def test_patch_status_to_archived(self):
        row = _make_incident_row()
        inc_id = row["id"]
        updated = {**row, "status": "archived"}
        with patch("services.api.src.routers.incidents.db_incidents") as mock_db:
            mock_db.get_incident.return_value = row
            mock_db.update_incident_status.return_value = updated
            resp = _client().patch(
                f"/v1/incidents/{inc_id}/status",
                json={"new_status": "archived"},
                headers=AUTH,
            )
        assert resp.status_code == 200
        assert resp.json()["status"] == "archived"

    def test_patch_invalid_status_returns_422(self):
        resp = _client().patch(
            "/v1/incidents/any-id/status",
            json={"new_status": "deleted"},
            headers=AUTH,
        )
        assert resp.status_code == 422

    def test_patch_nonexistent_incident_returns_404(self):
        with patch("services.api.src.routers.incidents.db_incidents") as mock_db:
            mock_db.get_incident.return_value = None
            resp = _client().patch(
                "/v1/incidents/ghost/status",
                json={"new_status": "closed"},
                headers=AUTH,
            )
        assert resp.status_code == 404

    def test_patch_no_token_returns_401(self):
        resp = _client().patch(
            "/v1/incidents/any-id/status",
            json={"new_status": "closed"},
        )
        assert resp.status_code == 401

    def test_patch_missing_new_status_returns_422(self):
        resp = _client().patch(
            "/v1/incidents/any-id/status",
            json={},
            headers=AUTH,
        )
        assert resp.status_code == 422
