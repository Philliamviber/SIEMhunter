"""
Tests for services/api/src/routers/search.py

POST /v1/search

Security controls exercised (MUST 8-11):
  MUST 8  — No sql field accepted; schema uses extra="forbid".
  MUST 9  — Unknown field_type → 422.
  MUST 10 — Missing or empty value → 422.
  MUST 11 — incident_id scope; client cannot remove filter once applied.

Strategy
--------
ClickHouse is patched at the router's local name.  Every test that needs
ClickHouse to return data replaces the router-level get_client with a
controlled mock.  The session-scoped autouse patch in conftest.py provides
a baseline so no real connection is attempted.
"""
from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest
from fastapi.testclient import TestClient

from services.api.src.main import app

TEST_TOKEN = "test-secret-token-for-pytest"
AUTH = {"Authorization": f"Bearer {TEST_TOKEN}"}
SEARCH_URL = "/v1/search"


def _client():
    return TestClient(app, raise_server_exceptions=False)


def _mk_ch(column_names=None, rows=None):
    """Return a mock ClickHouse client that returns the given result rows."""
    mock = MagicMock()
    result = MagicMock()
    result.column_names = column_names or []
    result.result_rows = rows or []
    mock.query.return_value = result
    return mock


def _post(body: dict, headers=AUTH):
    mock_ch = _mk_ch()
    with patch("services.api.src.routers.search.get_client", return_value=mock_ch):
        return _client().post(SEARCH_URL, json=body, headers=headers), mock_ch


# ── Authentication ────────────────────────────────────────────────────────────

class TestSearchAuth:

    def test_no_token_returns_401(self):
        resp = _client().post(SEARCH_URL, json={"field_type": "IP", "value": "10.0.0.1"})
        assert resp.status_code == 401

    def test_wrong_token_returns_401(self):
        resp = _client().post(
            SEARCH_URL,
            json={"field_type": "IP", "value": "10.0.0.1"},
            headers={"Authorization": "Bearer wrong-token"},
        )
        assert resp.status_code == 401


# ── Input validation (MUST 9 + MUST 8) ───────────────────────────────────────

class TestSearchValidation:

    def test_unknown_field_type_returns_422(self):
        resp, _ = _post({"field_type": "EVIL", "value": "something"})
        assert resp.status_code == 422

    def test_unknown_field_type_body_has_unknown_field_type_code(self):
        resp, _ = _post({"field_type": "SQL_INJECTION", "value": "'; DROP TABLE--"})
        body = resp.json()
        assert body["detail"]["code"] == "UNKNOWN_FIELD_TYPE"

    def test_missing_value_field_returns_422(self):
        resp, _ = _post({"field_type": "IP"})
        assert resp.status_code == 422

    def test_empty_value_returns_422(self):
        resp, _ = _post({"field_type": "IP", "value": ""})
        assert resp.status_code == 422

    def test_whitespace_only_value_returns_422(self):
        resp, _ = _post({"field_type": "IP", "value": "   "})
        assert resp.status_code == 422

    def test_missing_field_type_returns_422(self):
        resp, _ = _post({"value": "10.0.0.1"})
        assert resp.status_code == 422

    def test_sql_field_is_rejected_with_422(self):
        """
        MUST 8: The endpoint must NOT accept a 'sql' field.
        SearchRequest uses extra='forbid', so extra keys → 422.
        """
        resp, _ = _post({
            "field_type": "IP",
            "value": "10.0.0.1",
            "sql": "SELECT * FROM siemhunter.security_events",
        })
        # extra='forbid' in SearchRequest causes 422 for unknown fields
        assert resp.status_code == 422

    def test_extra_arbitrary_field_rejected(self):
        """Extra fields beyond the schema must not pass through."""
        resp, _ = _post({
            "field_type": "IP",
            "value": "10.0.0.1",
            "arbitrary_injection": "payload",
        })
        assert resp.status_code == 422

    def test_invalid_port_value_returns_422(self):
        resp, _ = _post({"field_type": "Port", "value": "not-a-port"})
        assert resp.status_code == 422

    def test_port_out_of_range_returns_422(self):
        resp, _ = _post({"field_type": "Port", "value": "99999"})
        assert resp.status_code == 422

    def test_invalid_event_id_returns_422(self):
        resp, _ = _post({"field_type": "EventID", "value": "not-an-int"})
        assert resp.status_code == 422

    def test_negative_event_id_returns_422(self):
        resp, _ = _post({"field_type": "EventID", "value": "-1"})
        assert resp.status_code == 422

    def test_invalid_file_hash_length_returns_422(self):
        # 10 hex chars — not 32 (MD5) or 64 (SHA256)
        resp, _ = _post({"field_type": "FileHash", "value": "abcdef1234"})
        assert resp.status_code == 422

    def test_non_hex_file_hash_returns_422(self):
        resp, _ = _post({"field_type": "FileHash", "value": "x" * 32})
        assert resp.status_code == 422


# ── Happy paths ───────────────────────────────────────────────────────────────

class TestSearchHappyPath:

    def test_ip_search_returns_200(self):
        resp, _ = _post({"field_type": "IP", "value": "10.0.0.1"})
        assert resp.status_code == 200

    def test_ip_search_response_has_rows_array(self):
        resp, _ = _post({"field_type": "IP", "value": "10.0.0.1"})
        body = resp.json()
        assert "rows" in body
        assert isinstance(body["rows"], list)

    def test_ip_search_response_shape(self):
        resp, _ = _post({"field_type": "IP", "value": "10.0.0.1"})
        body = resp.json()
        for field in ("rows", "row_count", "truncated", "execution_time_ms", "field_type", "columns_searched"):
            assert field in body, f"Missing field: {field}"

    def test_ip_search_field_type_echoed_in_response(self):
        resp, _ = _post({"field_type": "IP", "value": "192.168.1.1"})
        assert resp.json()["field_type"] == "IP"

    def test_ip_search_columns_searched(self):
        resp, _ = _post({"field_type": "IP", "value": "10.0.0.1"})
        assert set(resp.json()["columns_searched"]) == {"SrcIpAddr", "DstIpAddr"}

    def test_hostname_search_returns_200(self):
        resp, _ = _post({"field_type": "Hostname", "value": "dc01"})
        assert resp.status_code == 200

    def test_username_search_returns_200(self):
        resp, _ = _post({"field_type": "Username", "value": "jdoe"})
        assert resp.status_code == 200

    def test_port_search_returns_200(self):
        resp, _ = _post({"field_type": "Port", "value": "445"})
        assert resp.status_code == 200

    def test_event_id_search_returns_200(self):
        resp, _ = _post({"field_type": "EventID", "value": "4624"})
        assert resp.status_code == 200

    def test_file_hash_md5_search_returns_200(self):
        md5 = "a" * 32
        resp, _ = _post({"field_type": "FileHash", "value": md5})
        assert resp.status_code == 200

    def test_file_hash_sha256_search_returns_200(self):
        sha256 = "b" * 64
        resp, _ = _post({"field_type": "FileHash", "value": sha256})
        assert resp.status_code == 200

    def test_process_name_search_returns_200(self):
        resp, _ = _post({"field_type": "ProcessName", "value": "C:\\Windows\\explorer.exe"})
        assert resp.status_code == 200

    def test_rows_are_returned_as_list_of_dicts(self):
        mock_ch = _mk_ch(
            column_names=["SrcIpAddr", "EventID"],
            rows=[["10.0.0.1", 4624]],
        )
        with patch("services.api.src.routers.search.get_client", return_value=mock_ch):
            resp = _client().post(
                SEARCH_URL,
                json={"field_type": "IP", "value": "10.0.0.1"},
                headers=AUTH,
            )
        assert resp.status_code == 200
        rows = resp.json()["rows"]
        assert rows[0]["SrcIpAddr"] == "10.0.0.1"
        assert rows[0]["EventID"] == 4624

    def test_row_count_reflects_result_size(self):
        mock_ch = _mk_ch(
            column_names=["SrcIpAddr"],
            rows=[["10.0.0.1"], ["10.0.0.2"], ["10.0.0.3"]],
        )
        with patch("services.api.src.routers.search.get_client", return_value=mock_ch):
            resp = _client().post(
                SEARCH_URL,
                json={"field_type": "IP", "value": "10.0.0.1"},
                headers=AUTH,
            )
        assert resp.json()["row_count"] == 3

    def test_empty_result_has_zero_row_count(self):
        resp, _ = _post({"field_type": "IP", "value": "192.0.2.1"})
        assert resp.json()["row_count"] == 0

    def test_execution_time_ms_is_non_negative(self):
        resp, _ = _post({"field_type": "IP", "value": "10.0.0.1"})
        assert resp.json()["execution_time_ms"] >= 0


# ── Incident scope (MUST 11) ─────────────────────────────────────────────────

class TestSearchIncidentScope:

    def test_incident_id_is_accepted(self):
        resp, _ = _post({
            "field_type": "IP",
            "value": "10.0.0.1",
            "incident_id": "inc-abc123",
        })
        assert resp.status_code == 200

    def test_invalid_incident_id_format_returns_422(self):
        """incident_id containing special chars beyond [A-Za-z0-9_-] must be rejected."""
        resp, _ = _post({
            "field_type": "IP",
            "value": "10.0.0.1",
            "incident_id": "'; DROP TABLE incidents--",
        })
        assert resp.status_code == 422

    def test_incident_id_scope_predicate_is_included_in_sql(self):
        """
        When incident_id is provided, the ProvenanceTag LIKE predicate must appear
        in the SQL forwarded to ClickHouse.
        """
        captured: list[str] = []
        captured_params: list[dict] = []

        mock_ch = MagicMock()
        result = MagicMock()
        result.column_names = []
        result.result_rows = []

        def capture_query(sql, parameters=None, settings=None):
            captured.append(sql)
            if parameters:
                captured_params.append(parameters)
            return result

        mock_ch.query.side_effect = capture_query

        with patch("services.api.src.routers.search.get_client", return_value=mock_ch):
            _client().post(
                SEARCH_URL,
                json={
                    "field_type": "IP",
                    "value": "10.0.0.1",
                    "incident_id": "inc-xyz789",
                },
                headers=AUTH,
            )

        assert len(captured) == 1
        # ProvenanceTag LIKE predicate must be in the SQL
        assert "ProvenanceTag" in captured[0]
        # The incident_id value must appear in the query parameters, never interpolated
        assert any(
            "inc-xyz789" in str(v) for params in captured_params for v in params.values()
        )

    def test_without_incident_id_no_provenance_filter_in_sql(self):
        """If no incident_id, no ProvenanceTag filter should be added."""
        captured: list[str] = []

        mock_ch = MagicMock()
        result = MagicMock()
        result.column_names = []
        result.result_rows = []
        mock_ch.query.side_effect = lambda sql, **kw: (captured.append(sql) or result)

        with patch("services.api.src.routers.search.get_client", return_value=mock_ch):
            _client().post(
                SEARCH_URL,
                json={"field_type": "IP", "value": "10.0.0.1"},
                headers=AUTH,
            )

        assert len(captured) == 1
        assert "ProvenanceTag" not in captured[0]
