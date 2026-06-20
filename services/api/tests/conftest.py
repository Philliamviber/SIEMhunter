"""
Shared fixtures for the SIEMhunter API test suite.

Key design notes
----------------
- auth.py calls _load_token() at module-import time, which reads
  /run/secrets/api_token from disk.  We must patch Path.read_text *before*
  the module is first imported.  pytest_configure() runs before collection
  and handles this.

- main.py runs a ClickHouse connectivity check in its lifespan startup
  function.  TestClient triggers the lifespan on first request.  We provide
  an autouse session-scoped fixture that patches clickhouse_client.get_client
  at the source, so no real ClickHouse connection is ever attempted during
  tests.

- Individual test files that need a specific ClickHouse mock (e.g., to capture
  the SQL that was forwarded) add their own patch on top of the baseline.
"""
from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch


# ── Token used throughout the test suite ─────────────────────────────────────
TEST_TOKEN = "test-secret-token-for-pytest"


# ── Pre-empt the module-level _load_token() call ─────────────────────────────

def pytest_configure(config):
    """Called very early — before any test modules are imported.

    v3 dual-auth split: ``auth_service_token`` does
    ``_EXPECTED_TOKEN = _load_token()`` at module scope (reading the Docker
    secret), and ``auth`` re-exports it. We patch Path.read_text before either
    module is imported so the real filesystem is never touched, then pin the
    expected token in both the service-token module and the shim.

    The analyst user store is also redirected to a temp file so analyst auth
    never touches /run/secrets and starts unseeded (fail-closed) by default.
    """
    import os
    import tempfile

    # Redirect the analyst user store to a writable temp path for the suite.
    os.environ.setdefault(
        "ANALYST_USERS_PATH",
        os.path.join(tempfile.gettempdir(), "siemhunter_test_analyst_users.json"),
    )

    # TestClient runs over plain http://testserver, which won't echo a Secure
    # cookie. Run the suite in dev-cookie mode so the session cookie round-trips.
    # (Production defaults to secure=true; see SESSION_COOKIE_SECURE in
    # routers/auth_routes.py and the DEPLOYMENT.md note.)
    os.environ.setdefault("SESSION_COOKIE_SECURE", "false")

    with patch("pathlib.Path.read_text", return_value=TEST_TOKEN):
        try:
            import services.api.src.auth_service_token as _svc_mod
            _svc_mod._EXPECTED_TOKEN = TEST_TOKEN
        except Exception:
            pass
        try:
            import services.api.src.auth as _auth_mod
            _auth_mod._EXPECTED_TOKEN = TEST_TOKEN
        except Exception:
            # Module may already be imported; tests will set _EXPECTED_TOKEN directly.
            pass


# ── Session-scoped baseline ClickHouse patch ──────────────────────────────────

def make_ch_result(column_names=None, rows=None):
    """Return a mock that looks like a clickhouse_connect QueryResult."""
    result = MagicMock()
    result.column_names = column_names or []
    result.result_rows = rows or []
    return result


def make_ch_client(column_names=None, rows=None):
    """Return a mock ClickHouse client whose .query() returns make_ch_result()."""
    client = MagicMock()
    client.query.return_value = make_ch_result(column_names=column_names, rows=rows)
    return client


@pytest.fixture(autouse=True, scope="session")
def _patch_clickhouse_at_source():
    """Patch get_client everywhere it is used for the entire test session.

    main.py imports get_client directly: `from .clickhouse_client import get_client`.
    That creates a module-level binding in services.api.src.main.  The lifespan
    startup handler calls that binding, so we must patch the binding in main's
    namespace as well as in the source module.

    Similarly, each router imports get_client into its own namespace, so we
    patch the source module (which covers future router imports) and all
    known router namespaces explicitly.

    Individual tests that need to capture the exact SQL forwarded to ClickHouse
    add a narrower patch on the specific router's local name inside the test.
    """
    baseline_client = make_ch_client()
    patches = [
        patch("services.api.src.clickhouse_client.get_client", return_value=baseline_client),
        patch("services.api.src.main.get_client", return_value=baseline_client),
        patch("services.api.src.routers.query.get_client", return_value=baseline_client),
        patch("services.api.src.routers.rules.get_client", return_value=baseline_client),
        patch("services.api.src.routers.events.get_client", return_value=baseline_client),
        patch("services.api.src.routers.metrics.get_client", return_value=baseline_client),
        patch("services.api.src.routers.detections.get_client", return_value=baseline_client),
        patch("services.api.src.routers.ingestion.get_client", return_value=baseline_client),
        patch("services.api.src.routers.status.get_client", return_value=baseline_client),
        patch("services.api.src.routers.health.get_client", return_value=baseline_client),
        patch("services.api.src.routers.ai_summary.get_client", return_value=baseline_client),
    ]
    started = []
    for p in patches:
        try:
            p.start()
            started.append(p)
        except (AttributeError, ModuleNotFoundError):
            # Module may not be importable in the test environment
            pass
    yield
    for p in started:
        try:
            p.stop()
        except RuntimeError:
            pass


@pytest.fixture(autouse=True)
def _reset_expected_token():
    """Ensure every test starts with the correct token in both auth modules."""
    import services.api.src.auth as auth_mod
    import services.api.src.auth_service_token as svc_mod
    original = auth_mod._EXPECTED_TOKEN
    original_svc = svc_mod._EXPECTED_TOKEN
    auth_mod._EXPECTED_TOKEN = TEST_TOKEN
    svc_mod._EXPECTED_TOKEN = TEST_TOKEN
    yield
    auth_mod._EXPECTED_TOKEN = original
    svc_mod._EXPECTED_TOKEN = original_svc


# ── Fixtures available to individual test files ───────────────────────────────

@pytest.fixture
def ch_client_empty():
    """A mock ClickHouse client that returns no rows."""
    return make_ch_client()


@pytest.fixture
def ch_client_factory():
    """Callable fixture: ch_client_factory(columns, rows) → mock client."""
    return make_ch_client
