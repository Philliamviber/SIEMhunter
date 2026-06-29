"""
Tests for POST /v1/sigma/compile and POST /v1/sigma/dryrun.

pySigma is NOT imported in this test module.  compile_sigma_to_sql() is mocked
at the router level so the tests work in any Python environment regardless of
whether pySigma is installed.

get_readonly_client() is patched via the session-scoped fixture in conftest.py.

Security controls exercised:
  1. compile: invalid / badly-formed Sigma YAML → 422 SIGMA_COMPILE_ERROR
  2. compile: valid Sigma YAML → 200 with SQL preview (mocked)
  3. dryrun: valid compile + SELECT → 200 with sample rows
  4. dryrun: semicolon injection → 400 FORBIDDEN_STATEMENT
  5. dryrun: non-SELECT statement (INSERT) → 400 FORBIDDEN_STATEMENT
  6. dryrun: forbidden keyword buried in subquery → 400 FORBIDDEN_STATEMENT
  7. No code path writes to rule_registry (verified by checking insert calls)
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient

from services.api.src.main import app

TEST_TOKEN = "test-secret-token-for-pytest"
AUTH_HEADER = {"Authorization": f"Bearer {TEST_TOKEN}"}

_VALID_SIGMA = """
title: Kerberoasting Detected
id: test-rule-001
status: test
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4769
        ServiceName|endswith: '$'
    condition: selection
level: high
"""

_COMPILED_SQL = (
    "SELECT * FROM siemhunter.security_events "
    "WHERE EventID = 4769 AND ServiceName LIKE '%$'"
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _compile_client(mock_compile=None, mock_ch=None):
    """TestClient with compile_sigma_to_sql mocked."""
    compile_fn = mock_compile or (lambda y: (_COMPILED_SQL, "Kerberoasting Detected", "test-rule-001"))
    patches = [
        patch("services.api.src.routers.sigma_author.compile_sigma_to_sql", side_effect=compile_fn),
        patch("services.api.src.routers.sigma_author._PYSIGMA_AVAILABLE", True),
    ]
    if mock_ch:
        patches.append(patch("services.api.src.routers.sigma_author.get_readonly_client", return_value=mock_ch))
    started = [p.start() for p in patches]
    client = TestClient(app, raise_server_exceptions=False)
    return client, started, patches


def _mk_ch_result(column_names=None, rows=None):
    r = MagicMock()
    r.column_names = column_names or []
    r.result_rows = rows or []
    return r


def _mk_ch_client(column_names=None, rows=None):
    c = MagicMock()
    c.query.return_value = _mk_ch_result(column_names=column_names, rows=rows)
    return c


def _stop_patches(started, patches):
    for p in patches:
        try:
            p.stop()
        except RuntimeError:
            pass


# ── compile endpoint ──────────────────────────────────────────────────────────

def test_compile_success():
    """Valid Sigma YAML returns 200 with SQL, title, and rule_id."""
    client, started, patches = _compile_client()
    try:
        res = client.post(
            "/v1/sigma/compile",
            json={"sigma_yaml": _VALID_SIGMA},
            headers=AUTH_HEADER,
        )
        assert res.status_code == 200, res.text
        body = res.json()
        assert body["sql"] == _COMPILED_SQL
        assert body["title"] == "Kerberoasting Detected"
        assert body["rule_id"] == "test-rule-001"
    finally:
        _stop_patches(started, patches)


def test_compile_error_returns_422():
    """A compile failure returns 422 SIGMA_COMPILE_ERROR."""
    def bad_compile(yaml_content):
        raise ValueError("unknown Sigma field: BadField")

    client, started, patches = _compile_client(mock_compile=bad_compile)
    try:
        res = client.post(
            "/v1/sigma/compile",
            json={"sigma_yaml": "not valid sigma"},
            headers=AUTH_HEADER,
        )
        assert res.status_code == 422, res.text
        detail = res.json()["detail"]
        assert detail["code"] == "SIGMA_COMPILE_ERROR"
        assert "compile error" in detail["error"].lower()
    finally:
        _stop_patches(started, patches)


def test_compile_requires_auth():
    """Compile endpoint rejects unauthenticated requests."""
    with patch("services.api.src.routers.sigma_author._PYSIGMA_AVAILABLE", True):
        client = TestClient(app, raise_server_exceptions=False)
        res = client.post("/v1/sigma/compile", json={"sigma_yaml": _VALID_SIGMA})
    assert res.status_code == 401


def test_compile_no_rule_registry_write():
    """The compile endpoint never calls client.insert (no rule_registry write)."""
    mock_ch = _mk_ch_client()
    client, started, patches = _compile_client(mock_ch=mock_ch)
    try:
        client.post(
            "/v1/sigma/compile",
            json={"sigma_yaml": _VALID_SIGMA},
            headers=AUTH_HEADER,
        )
        mock_ch.insert.assert_not_called()
    finally:
        _stop_patches(started, patches)


# ── dryrun endpoint ───────────────────────────────────────────────────────────

def test_dryrun_success():
    """Valid Sigma + SELECT → 200 with sample rows and match_count."""
    mock_ch = _mk_ch_client(
        column_names=["EventID", "HostName"],
        rows=[(4769, "dc01"), (4769, "dc02")],
    )
    client, started, patches = _compile_client(mock_ch=mock_ch)
    try:
        res = client.post(
            "/v1/sigma/dryrun",
            json={"sigma_yaml": _VALID_SIGMA},
            headers=AUTH_HEADER,
        )
        assert res.status_code == 200, res.text
        body = res.json()
        assert body["match_count"] == 2
        assert len(body["sample_rows"]) == 2
        assert body["sql"] == _COMPILED_SQL
        assert body["execution_time_ms"] >= 0
    finally:
        _stop_patches(started, patches)


def test_dryrun_no_results():
    """Dry-run with zero matches returns match_count=0 and empty sample_rows."""
    mock_ch = _mk_ch_client(column_names=["EventID"], rows=[])
    client, started, patches = _compile_client(mock_ch=mock_ch)
    try:
        res = client.post(
            "/v1/sigma/dryrun",
            json={"sigma_yaml": _VALID_SIGMA},
            headers=AUTH_HEADER,
        )
        assert res.status_code == 200, res.text
        body = res.json()
        assert body["match_count"] == 0
        assert body["sample_rows"] == []
    finally:
        _stop_patches(started, patches)


def test_dryrun_no_rule_registry_write():
    """The dryrun endpoint never calls client.insert (no rule_registry write)."""
    mock_ch = _mk_ch_client()
    client, started, patches = _compile_client(mock_ch=mock_ch)
    try:
        client.post(
            "/v1/sigma/dryrun",
            json={"sigma_yaml": _VALID_SIGMA},
            headers=AUTH_HEADER,
        )
        mock_ch.insert.assert_not_called()
    finally:
        _stop_patches(started, patches)


# ── SELECT-only guard ─────────────────────────────────────────────────────────

def _dryrun_with_compiled_sql(compiled_sql: str):
    """Run a dry-run where compile_sigma_to_sql returns the given compiled_sql."""
    def mock_compile(yaml_content):
        return compiled_sql, "title", "id"

    mock_ch = _mk_ch_client()
    client, started, patches = _compile_client(mock_compile=mock_compile, mock_ch=mock_ch)
    try:
        return client.post(
            "/v1/sigma/dryrun",
            json={"sigma_yaml": _VALID_SIGMA},
            headers=AUTH_HEADER,
        )
    finally:
        _stop_patches(started, patches)


def test_dryrun_rejects_semicolon():
    """Semicolon in compiled SQL is rejected with 400 FORBIDDEN_STATEMENT."""
    res = _dryrun_with_compiled_sql(
        "SELECT * FROM security_events; DROP TABLE security_events"
    )
    assert res.status_code == 400, res.text
    assert res.json()["detail"]["code"] == "FORBIDDEN_STATEMENT"


def test_dryrun_rejects_non_select():
    """Non-SELECT compiled SQL (e.g. INSERT) is rejected with 400 FORBIDDEN_STATEMENT."""
    res = _dryrun_with_compiled_sql(
        "INSERT INTO security_events SELECT * FROM other_table"
    )
    assert res.status_code == 400, res.text
    assert res.json()["detail"]["code"] == "FORBIDDEN_STATEMENT"


def test_dryrun_rejects_drop_in_subquery():
    """DROP keyword buried in a subquery is rejected with 400 FORBIDDEN_STATEMENT."""
    res = _dryrun_with_compiled_sql(
        "SELECT * FROM security_events WHERE EventID IN (SELECT 1 FROM (DROP TABLE x))"
    )
    assert res.status_code == 400, res.text
    assert res.json()["detail"]["code"] == "FORBIDDEN_STATEMENT"


def test_dryrun_rejects_system_keyword():
    """SYSTEM keyword (e.g. SYSTEM FLUSH LOGS) is rejected."""
    res = _dryrun_with_compiled_sql(
        "SELECT SYSTEM FLUSH LOGS"
    )
    assert res.status_code == 400, res.text
    assert res.json()["detail"]["code"] == "FORBIDDEN_STATEMENT"


def test_dryrun_rejects_alter():
    """ALTER keyword is rejected with 400 FORBIDDEN_STATEMENT."""
    res = _dryrun_with_compiled_sql(
        "SELECT * FROM (ALTER TABLE security_events ADD COLUMN x Int32)"
    )
    assert res.status_code == 400, res.text
    assert res.json()["detail"]["code"] == "FORBIDDEN_STATEMENT"


def test_dryrun_compile_error_returns_422():
    """Compile error during dryrun returns 422 SIGMA_COMPILE_ERROR."""
    def bad_compile(yaml_content):
        raise ValueError("bad sigma")

    mock_ch = _mk_ch_client()
    client, started, patches = _compile_client(mock_compile=bad_compile, mock_ch=mock_ch)
    try:
        res = client.post(
            "/v1/sigma/dryrun",
            json={"sigma_yaml": "invalid yaml"},
            headers=AUTH_HEADER,
        )
        assert res.status_code == 422, res.text
        assert res.json()["detail"]["code"] == "SIGMA_COMPILE_ERROR"
    finally:
        _stop_patches(started, patches)


def test_dryrun_requires_auth():
    """Dryrun endpoint rejects unauthenticated requests."""
    with patch("services.api.src.routers.sigma_author._PYSIGMA_AVAILABLE", True):
        client = TestClient(app, raise_server_exceptions=False)
        res = client.post("/v1/sigma/dryrun", json={"sigma_yaml": _VALID_SIGMA})
    assert res.status_code == 401
