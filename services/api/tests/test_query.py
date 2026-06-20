"""
Tests for services/api/src/routers/query.py — POST /v1/query.

ClickHouse is mocked at the source via the session-scoped autouse fixture in
conftest.py (_patch_clickhouse_at_source).  Tests that need to verify the SQL
forwarded to ClickHouse add an additional patch on the router's local name.

Auth is bypassed by setting auth_mod._EXPECTED_TOKEN = TEST_TOKEN (done by
the autouse _reset_expected_token fixture in conftest.py) and providing the
correct Bearer token in every request.

Security controls exercised:
  1. Non-SELECT statement → 400 FORBIDDEN_STATEMENT
  2. SELECT with forbidden mutation keyword anywhere → 400 FORBIDDEN_STATEMENT
  3. SELECT referencing 169.254 (IMDS) → 400 SSRF_REJECTED
  4. Valid SELECT without LIMIT → row cap appended to forwarded SQL
  5. Valid SELECT with LIMIT already present → no second LIMIT appended
  6. Valid SELECT → 200 with expected response shape
"""
from __future__ import annotations

from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from services.api.src.main import app

TEST_TOKEN = "test-secret-token-for-pytest"
AUTH_HEADER = {"Authorization": f"Bearer {TEST_TOKEN}"}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _mk_result(column_names=None, rows=None):
    r = MagicMock()
    r.column_names = column_names or []
    r.result_rows = rows or []
    return r


def _mk_client(column_names=None, rows=None):
    c = MagicMock()
    c.query.return_value = _mk_result(column_names=column_names, rows=rows)
    return c


def _post(client: TestClient, sql: str, params: dict = None):
    body: dict = {"sql": sql}
    if params is not None:
        body["params"] = params
    return client.post("/v1/query", json=body, headers=AUTH_HEADER)


def _patched_client(mock_ch=None):
    """Return a TestClient with the query router's get_client replaced."""
    ch = mock_ch if mock_ch is not None else _mk_client()
    with patch("services.api.src.routers.query.get_client", return_value=ch):
        return TestClient(app, raise_server_exceptions=False)


# ── Non-SELECT rejection ──────────────────────────────────────────────────────

class TestNonSelectRejection:

    def test_insert_statement_rejected(self):
        client = _patched_client()
        resp = _post(client, "INSERT INTO foo VALUES (1)")
        assert resp.status_code == 400
        assert resp.json()["detail"]["code"] == "FORBIDDEN_STATEMENT"

    def test_delete_statement_rejected(self):
        client = _patched_client()
        resp = _post(client, "DELETE FROM foo WHERE id = 1")
        assert resp.status_code == 400
        assert resp.json()["detail"]["code"] == "FORBIDDEN_STATEMENT"

    def test_drop_statement_rejected(self):
        client = _patched_client()
        resp = _post(client, "DROP TABLE foo")
        assert resp.status_code == 400
        assert resp.json()["detail"]["code"] == "FORBIDDEN_STATEMENT"

    def test_create_statement_rejected(self):
        client = _patched_client()
        resp = _post(client, "CREATE TABLE evil (x Int32)")
        assert resp.status_code == 400
        assert resp.json()["detail"]["code"] == "FORBIDDEN_STATEMENT"

    def test_update_statement_rejected(self):
        client = _patched_client()
        resp = _post(client, "UPDATE foo SET x = 1")
        assert resp.status_code == 400
        assert resp.json()["detail"]["code"] == "FORBIDDEN_STATEMENT"

    def test_truncate_statement_rejected(self):
        client = _patched_client()
        resp = _post(client, "TRUNCATE TABLE foo")
        assert resp.status_code == 400
        assert resp.json()["detail"]["code"] == "FORBIDDEN_STATEMENT"

    def test_empty_sql_rejected(self):
        client = _patched_client()
        resp = _post(client, "   ")
        assert resp.status_code == 400

    def test_mixed_case_insert_rejected(self):
        """Keyword check must be case-insensitive."""
        client = _patched_client()
        resp = _post(client, "insert into foo values (1)")
        assert resp.status_code == 400
        assert resp.json()["detail"]["code"] == "FORBIDDEN_STATEMENT"

    def test_alter_statement_rejected(self):
        client = _patched_client()
        resp = _post(client, "ALTER TABLE foo ADD COLUMN x Int32")
        assert resp.status_code == 400
        assert resp.json()["detail"]["code"] == "FORBIDDEN_STATEMENT"

    def test_rename_statement_rejected(self):
        client = _patched_client()
        resp = _post(client, "RENAME TABLE foo TO bar")
        assert resp.status_code == 400
        assert resp.json()["detail"]["code"] == "FORBIDDEN_STATEMENT"


# ── SELECT with embedded forbidden keyword ────────────────────────────────────

class TestForbiddenKeywordInSelect:
    """A SELECT that contains a mutation keyword anywhere must still be rejected."""

    def test_select_with_embedded_drop(self):
        client = _patched_client()
        resp = _post(client, "SELECT * FROM foo; DROP TABLE foo")
        assert resp.status_code == 400
        assert resp.json()["detail"]["code"] == "FORBIDDEN_STATEMENT"

    def test_select_with_embedded_insert(self):
        client = _patched_client()
        resp = _post(client, "SELECT * FROM (INSERT INTO t VALUES (1))")
        assert resp.status_code == 400
        assert resp.json()["detail"]["code"] == "FORBIDDEN_STATEMENT"

    def test_select_with_embedded_optimize(self):
        client = _patched_client()
        resp = _post(client, "SELECT OPTIMIZE(foo) FROM bar")
        assert resp.status_code == 400
        assert resp.json()["detail"]["code"] == "FORBIDDEN_STATEMENT"

    def test_select_with_embedded_alter(self):
        client = _patched_client()
        resp = _post(client, "SELECT 1 WHERE 1=1; ALTER TABLE foo RENAME COLUMN x TO y")
        assert resp.status_code == 400
        assert resp.json()["detail"]["code"] == "FORBIDDEN_STATEMENT"


# ── SSRF: IMDS address ────────────────────────────────────────────────────────

class TestSsrfRejection:

    def test_imds_literal_rejected(self):
        client = _patched_client()
        resp = _post(client, "SELECT url('http://169.254.169.254/metadata')")
        assert resp.status_code == 400
        assert resp.json()["detail"]["code"] == "SSRF_REJECTED"

    def test_imds_partial_address_rejected(self):
        """Even a partial match of 169.254 must be caught."""
        client = _patched_client()
        resp = _post(client, "SELECT * FROM remote('169.254.1.1', 'db', 'table')")
        assert resp.status_code == 400
        assert resp.json()["detail"]["code"] == "SSRF_REJECTED"

    def test_imds_select_start_still_rejected(self):
        """SSRF check must fire even when the statement starts with SELECT."""
        client = _patched_client()
        resp = _post(client, "SELECT url('http://169.254.169.254/latest/meta-data/')")
        assert resp.status_code == 400
        assert resp.json()["detail"]["code"] == "SSRF_REJECTED"


# ── Row cap enforcement ───────────────────────────────────────────────────────

class TestRowCap:

    def test_select_without_limit_appends_limit(self):
        """When no LIMIT clause is present, LIMIT must be appended."""
        captured: list[str] = []
        mock_client = MagicMock()
        mock_client.query.side_effect = lambda sql, **kw: (
            captured.append(sql) or _mk_result()
        )

        with patch("services.api.src.routers.query.get_client", return_value=mock_client):
            client = TestClient(app, raise_server_exceptions=False)
            _post(client, "SELECT 1 FROM siemhunter.security_events")

        assert len(captured) == 1
        assert "LIMIT" in captured[0].upper()

    def test_select_with_limit_not_doubled(self):
        """A query that already has LIMIT must NOT get a second LIMIT."""
        captured: list[str] = []
        mock_client = MagicMock()
        mock_client.query.side_effect = lambda sql, **kw: (
            captured.append(sql) or _mk_result()
        )

        with patch("services.api.src.routers.query.get_client", return_value=mock_client):
            client = TestClient(app, raise_server_exceptions=False)
            _post(client, "SELECT 1 FROM siemhunter.security_events LIMIT 50")

        assert len(captured) == 1
        # Exactly one LIMIT keyword in the forwarded SQL
        assert captured[0].upper().count("LIMIT ") == 1

    def test_select_with_limit_preserves_caller_value(self):
        """The user's LIMIT value must appear in the forwarded SQL unchanged."""
        captured: list[str] = []
        mock_client = MagicMock()
        mock_client.query.side_effect = lambda sql, **kw: (
            captured.append(sql) or _mk_result()
        )

        with patch("services.api.src.routers.query.get_client", return_value=mock_client):
            client = TestClient(app, raise_server_exceptions=False)
            _post(client, "SELECT 1 FROM t LIMIT 42")

        assert "42" in captured[0]

    def test_limit_keyword_is_case_insensitive(self):
        """The row-cap check must recognise lowercase 'limit' as already present."""
        captured: list[str] = []
        mock_client = MagicMock()
        mock_client.query.side_effect = lambda sql, **kw: (
            captured.append(sql) or _mk_result()
        )

        with patch("services.api.src.routers.query.get_client", return_value=mock_client):
            client = TestClient(app, raise_server_exceptions=False)
            _post(client, "SELECT 1 FROM t limit 99")

        assert captured[0].upper().count("LIMIT ") == 1


# ── Happy path ────────────────────────────────────────────────────────────────

class TestHappyPath:

    def test_valid_select_returns_200(self):
        client = _patched_client()
        resp = _post(client, "SELECT 1")
        assert resp.status_code == 200

    def test_response_has_expected_fields(self):
        client = _patched_client()
        resp = _post(client, "SELECT 1")
        body = resp.json()
        for field in ("rows", "row_count", "truncated", "execution_time_ms"):
            assert field in body

    def test_empty_result_has_zero_row_count(self):
        client = _patched_client()
        resp = _post(client, "SELECT 1")
        assert resp.json()["row_count"] == 0

    def test_result_rows_are_serialised_as_dicts(self):
        """Rows must be a list of column-name → value dicts."""
        ch = _mk_client(column_names=["a", "b"], rows=[[1, "hello"], [2, "world"]])

        with patch("services.api.src.routers.query.get_client", return_value=ch):
            client = TestClient(app, raise_server_exceptions=False)
            resp = _post(client, "SELECT a, b FROM t LIMIT 10")

        assert resp.status_code == 200
        rows = resp.json()["rows"]
        assert rows[0] == {"a": 1, "b": "hello"}
        assert rows[1] == {"a": 2, "b": "world"}
        assert resp.json()["row_count"] == 2

    def test_unauthenticated_request_rejected(self):
        """Query endpoint must require auth — no token → 401."""
        client = _patched_client()
        resp = client.post("/v1/query", json={"sql": "SELECT 1"})
        assert resp.status_code == 401
