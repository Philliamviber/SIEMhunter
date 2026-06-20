"""
Tests for services/api/src/routers/upload.py

POST /v1/ingestion/upload

Security controls exercised:
  MUST 1  — ProvenanceTag is always server-assigned; value from file body is stripped.
  MUST 3  — Hard size cap (413 when file > UPLOAD_MAX_BYTES).
  MUST 4  — Extension allowlist; unsupported extension → 415.

Strategy
--------
ClickHouse client is patched at the router's import via the session-scoped
autouse fixture in conftest.py.  For tests that need to verify ClickHouse insert
was called, we apply an additional patch on the upload router's local name.

File uploads are sent as multipart/form-data via the FastAPI TestClient.
"""
from __future__ import annotations

import io
import json
from unittest.mock import patch, MagicMock

import pytest
from fastapi.testclient import TestClient

from services.api.src.main import app
from services.api.src.routers.upload import _UPLOAD_MAX_BYTES

TEST_TOKEN = "test-secret-token-for-pytest"
AUTH = {"Authorization": f"Bearer {TEST_TOKEN}"}

UPLOAD_URL = "/v1/ingestion/upload"


def _client():
    return TestClient(app, raise_server_exceptions=False)


def _json_file(content: dict | list, filename: str = "events.json") -> tuple[str, io.BytesIO, str]:
    """Return a (filename, file-like, content-type) tuple for multipart upload."""
    raw = json.dumps(content).encode("utf-8")
    return (filename, io.BytesIO(raw), "application/json")


def _patched_client():
    """Return a TestClient with the upload router's ClickHouse get_client patched."""
    mock_ch = MagicMock()
    mock_ch.insert.return_value = None
    with patch("services.api.src.routers.upload.get_client", return_value=mock_ch):
        yield TestClient(app, raise_server_exceptions=False), mock_ch


# ── Authentication ─────────────────────────────────────────────────────────────

class TestUploadAuth:

    def test_no_token_returns_401(self):
        resp = _client().post(
            UPLOAD_URL,
            files={"file": _json_file({"HostName": "test"})},
        )
        assert resp.status_code == 401

    def test_wrong_token_returns_401(self):
        resp = _client().post(
            UPLOAD_URL,
            files={"file": _json_file({"HostName": "test"})},
            headers={"Authorization": "Bearer wrong-token"},
        )
        assert resp.status_code == 401


# ── File size cap (MUST 3) ────────────────────────────────────────────────────

class TestUploadSizeCap:

    def test_oversized_file_returns_413(self):
        # Create a file that is exactly one byte over the limit
        oversized_content = b"x" * (_UPLOAD_MAX_BYTES + 1)
        resp = _client().post(
            UPLOAD_URL,
            files={"file": ("big.json", io.BytesIO(oversized_content), "application/json")},
            headers=AUTH,
        )
        assert resp.status_code == 413

    def test_oversized_file_413_body_has_file_too_large_code(self):
        oversized_content = b"x" * (_UPLOAD_MAX_BYTES + 1)
        resp = _client().post(
            UPLOAD_URL,
            files={"file": ("big.json", io.BytesIO(oversized_content), "application/json")},
            headers=AUTH,
        )
        assert resp.json()["detail"]["code"] == "FILE_TOO_LARGE"


# ── Extension allowlist (MUST 4) ─────────────────────────────────────────────

class TestUploadExtensionAllowlist:

    def test_unsupported_extension_returns_415(self):
        resp = _client().post(
            UPLOAD_URL,
            files={"file": ("malware.exe", io.BytesIO(b"MZ\x90\x00"), "application/octet-stream")},
            headers=AUTH,
        )
        assert resp.status_code == 415

    def test_evtx_extension_returns_415(self):
        resp = _client().post(
            UPLOAD_URL,
            files={"file": ("events.evtx", io.BytesIO(b"ELFFILE"), "application/octet-stream")},
            headers=AUTH,
        )
        assert resp.status_code == 415

    def test_415_body_has_unsupported_file_type_code(self):
        resp = _client().post(
            UPLOAD_URL,
            files={"file": ("payload.bin", io.BytesIO(b"binary"), "application/octet-stream")},
            headers=AUTH,
        )
        assert resp.json()["detail"]["code"] == "UNSUPPORTED_FILE_TYPE"

    def test_zip_extension_returns_415(self):
        resp = _client().post(
            UPLOAD_URL,
            files={"file": ("archive.zip", io.BytesIO(b"PK\x03\x04"), "application/zip")},
            headers=AUTH,
        )
        assert resp.status_code == 415

    def test_csv_extension_is_accepted(self):
        csv_content = "HostName,EventID\ndc01,4624\n".encode("utf-8")
        mock_ch = MagicMock()
        mock_ch.insert.return_value = None
        with patch("services.api.src.routers.upload.get_client", return_value=mock_ch):
            resp = _client().post(
                UPLOAD_URL,
                files={"file": ("events.csv", io.BytesIO(csv_content), "text/csv")},
                headers=AUTH,
            )
        assert resp.status_code == 200


# ── Happy-path JSON upload ────────────────────────────────────────────────────

class TestUploadHappyPath:

    def test_valid_json_returns_200(self):
        event = {"HostName": "dc01", "EventID": 4624, "ChannelName": "Security"}
        mock_ch = MagicMock()
        mock_ch.insert.return_value = None
        with patch("services.api.src.routers.upload.get_client", return_value=mock_ch):
            resp = _client().post(
                UPLOAD_URL,
                files={"file": _json_file(event)},
                headers=AUTH,
            )
        assert resp.status_code == 200

    def test_response_contains_expected_fields(self):
        event = {"HostName": "dc01", "EventID": 4624}
        mock_ch = MagicMock()
        mock_ch.insert.return_value = None
        with patch("services.api.src.routers.upload.get_client", return_value=mock_ch):
            resp = _client().post(
                UPLOAD_URL,
                files={"file": _json_file(event)},
                headers=AUTH,
            )
        body = resp.json()
        for field in ("filename", "provenance_tag", "events_parsed", "events_written", "status"):
            assert field in body, f"Missing field: {field}"

    def test_events_parsed_is_one_for_single_event(self):
        event = {"HostName": "dc01", "EventID": 4624}
        mock_ch = MagicMock()
        mock_ch.insert.return_value = None
        with patch("services.api.src.routers.upload.get_client", return_value=mock_ch):
            resp = _client().post(
                UPLOAD_URL,
                files={"file": _json_file(event)},
                headers=AUTH,
            )
        assert resp.json()["events_parsed"] == 1

    def test_events_written_equals_events_parsed_on_success(self):
        events = [{"HostName": f"host-{i}", "EventID": 4624} for i in range(5)]
        mock_ch = MagicMock()
        mock_ch.insert.return_value = None
        with patch("services.api.src.routers.upload.get_client", return_value=mock_ch):
            resp = _client().post(
                UPLOAD_URL,
                files={"file": _json_file(events)},
                headers=AUTH,
            )
        body = resp.json()
        assert body["events_written"] == body["events_parsed"]
        assert body["status"] == "success"

    def test_status_is_success_on_clean_upload(self):
        event = {"HostName": "dc01", "EventID": 4624}
        mock_ch = MagicMock()
        mock_ch.insert.return_value = None
        with patch("services.api.src.routers.upload.get_client", return_value=mock_ch):
            resp = _client().post(
                UPLOAD_URL,
                files={"file": _json_file(event)},
                headers=AUTH,
            )
        assert resp.json()["status"] == "success"


# ── ProvenanceTag security invariant (MUST 1) ─────────────────────────────────

class TestUploadProvenanceTagSecurity:
    """
    MUST 1: ProvenanceTag is always server-assigned.
    A ProvenanceTag value inside the file body must never appear in the response.
    """

    def test_provenance_tag_starts_with_manual_upload_prefix(self):
        event = {"HostName": "dc01", "EventID": 4624}
        mock_ch = MagicMock()
        mock_ch.insert.return_value = None
        with patch("services.api.src.routers.upload.get_client", return_value=mock_ch):
            resp = _client().post(
                UPLOAD_URL,
                files={"file": _json_file(event)},
                headers=AUTH,
            )
        assert resp.json()["provenance_tag"].startswith("manual-upload:")

    def test_provenance_tag_from_file_body_is_ignored(self):
        """
        If the uploaded JSON contains a ProvenanceTag field, that value must NOT
        appear in the response's provenance_tag.  The server always generates its own.
        """
        evil_tag = "attacker-controlled-source"
        event = {
            "HostName": "dc01",
            "EventID": 4624,
            "ProvenanceTag": evil_tag,
        }
        mock_ch = MagicMock()
        mock_ch.insert.return_value = None
        with patch("services.api.src.routers.upload.get_client", return_value=mock_ch):
            resp = _client().post(
                UPLOAD_URL,
                files={"file": _json_file(event)},
                headers=AUTH,
            )
        returned_tag = resp.json()["provenance_tag"]
        assert returned_tag != evil_tag
        assert "attacker-controlled-source" not in returned_tag

    def test_provenance_tag_from_file_not_written_to_clickhouse(self):
        """
        The ProvenanceTag inserted to ClickHouse must be the server-assigned one,
        never the value from the file.
        """
        evil_tag = "injected-source:malicious"
        event = {
            "HostName": "dc01",
            "EventID": 4624,
            "ProvenanceTag": evil_tag,
        }
        mock_ch = MagicMock()
        mock_ch.insert.return_value = None
        with patch("services.api.src.routers.upload.get_client", return_value=mock_ch):
            resp = _client().post(
                UPLOAD_URL,
                files={"file": _json_file(event)},
                headers=AUTH,
            )

        assert mock_ch.insert.called
        # Verify that the injected tag does not appear in any row passed to insert
        call_args = mock_ch.insert.call_args
        rows = call_args[1].get("data") or call_args[0][1]
        column_names = call_args[1].get("column_names") or call_args[0][2]
        prov_idx = column_names.index("ProvenanceTag")
        for row in rows:
            assert row[prov_idx] != evil_tag
            assert "injected-source:malicious" not in row[prov_idx]

    def test_siemhunter_internal_provenance_field_stripped(self):
        """
        The _siemhunter_provenance field (Vector export artifact) is also stripped.
        """
        event = {
            "HostName": "dc01",
            "EventID": 4624,
            "_siemhunter_provenance": "vector-injected",
        }
        mock_ch = MagicMock()
        mock_ch.insert.return_value = None
        with patch("services.api.src.routers.upload.get_client", return_value=mock_ch):
            resp = _client().post(
                UPLOAD_URL,
                files={"file": _json_file(event)},
                headers=AUTH,
            )
        returned_tag = resp.json()["provenance_tag"]
        assert "vector-injected" not in returned_tag

    def test_incident_mode_tag_contains_incident_id(self):
        """Mode=incident produces a provenance_tag that includes the incident_id."""
        event = {"HostName": "dc01", "EventID": 4624}
        mock_ch = MagicMock()
        mock_ch.insert.return_value = None
        with patch("services.api.src.routers.upload.get_client", return_value=mock_ch):
            resp = _client().post(
                UPLOAD_URL,
                files={"file": _json_file(event)},
                data={"mode": "incident", "incident_id": "inc-abc123"},
                headers=AUTH,
            )
        assert resp.status_code == 200
        tag = resp.json()["provenance_tag"]
        assert "manual-upload:incident:inc-abc123" in tag

    def test_jsonl_file_with_one_log_line_returns_200(self):
        """A .jsonl file with one log line produces a valid upload response."""
        line = json.dumps({"HostName": "ws01", "EventID": 4688}) + "\n"
        mock_ch = MagicMock()
        mock_ch.insert.return_value = None
        with patch("services.api.src.routers.upload.get_client", return_value=mock_ch):
            resp = _client().post(
                UPLOAD_URL,
                files={"file": ("events.jsonl", io.BytesIO(line.encode()), "application/jsonl")},
                headers=AUTH,
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["events_parsed"] == 1
        assert body["provenance_tag"].startswith("manual-upload:")
