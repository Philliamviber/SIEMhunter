"""
Tests for services/api/src/auth.py — verify_token dependency.

Strategy
--------
auth.py calls _load_token() at module scope, so by the time pytest imports
this file the module is already loaded (conftest.pytest_configure ran first and
set _EXPECTED_TOKEN).  The autouse _reset_expected_token fixture in conftest.py
ensures each test starts with TEST_TOKEN.

We test verify_token via a minimal FastAPI app + fastapi.testclient.TestClient
so that FastAPI's dependency injection and HTTPBearer extraction run exactly as
they do in production.

We also test against a route in the real app to confirm auth is wired correctly.
"""
from __future__ import annotations

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

import services.api.src.auth as auth_mod
from services.api.src.auth import verify_token

TEST_TOKEN = "test-secret-token-for-pytest"
WRONG_TOKEN = "definitely-not-the-right-token"


# ── Minimal FastAPI test app ──────────────────────────────────────────────────

def _build_minimal_app() -> FastAPI:
    """A tiny FastAPI app with one protected endpoint, no lifespan side-effects."""
    test_app = FastAPI()

    @test_app.get("/protected")
    async def protected(_: None = Depends(verify_token)):
        return {"ok": True}

    return test_app


def _client() -> TestClient:
    """Return a TestClient against the minimal app with the token set."""
    auth_mod._EXPECTED_TOKEN = TEST_TOKEN
    return TestClient(_build_minimal_app(), raise_server_exceptions=False)


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestVerifyToken:
    """Arrange-act-assert tests for the verify_token FastAPI dependency."""

    def test_correct_token_returns_200(self):
        """A valid Bearer token must pass through without raising."""
        resp = _client().get("/protected", headers={"Authorization": f"Bearer {TEST_TOKEN}"})
        assert resp.status_code == 200
        assert resp.json() == {"ok": True}

    def test_missing_authorization_header_returns_401(self):
        """No Authorization header → HTTP 401."""
        resp = _client().get("/protected")
        assert resp.status_code == 401

    def test_missing_auth_header_returns_auth_required_code(self):
        """The 401 body must carry the AUTH_REQUIRED error code."""
        detail = _client().get("/protected").json().get("detail", {})
        assert detail.get("code") == "AUTH_REQUIRED"

    def test_wrong_token_returns_401(self):
        """A Bearer token that does not match → HTTP 401."""
        resp = _client().get("/protected", headers={"Authorization": f"Bearer {WRONG_TOKEN}"})
        assert resp.status_code == 401

    def test_wrong_token_returns_auth_required_code(self):
        """Wrong token detail must still carry AUTH_REQUIRED code."""
        resp = _client().get("/protected", headers={"Authorization": f"Bearer {WRONG_TOKEN}"})
        assert resp.json()["detail"]["code"] == "AUTH_REQUIRED"

    def test_empty_authorization_header_returns_401(self):
        """An Authorization header that is blank → HTTP 401.

        HTTPBearer with auto_error=False yields credentials=None when the
        header value is empty or malformed, so verify_token must still reject.
        """
        resp = _client().get("/protected", headers={"Authorization": ""})
        assert resp.status_code == 401

    def test_bearer_prefix_without_token_returns_401(self):
        """'Authorization: Bearer ' (no value after the scheme) must be rejected."""
        resp = _client().get("/protected", headers={"Authorization": "Bearer "})
        assert resp.status_code == 401

    def test_non_bearer_scheme_returns_401(self):
        """'Authorization: Basic ...' must be rejected (scheme must be bearer)."""
        resp = _client().get("/protected", headers={"Authorization": f"Basic {TEST_TOKEN}"})
        assert resp.status_code == 401

    def test_token_value_not_in_error_response(self):
        """The actual token value must never appear in the 401 response body.

        This is a hard security invariant: tokens must not leak in responses
        (spec §2: 'Token value is NEVER written to logs, error responses, or
        exception messages').
        """
        resp = _client().get("/protected", headers={"Authorization": f"Bearer {WRONG_TOKEN}"})
        body_text = resp.text
        assert TEST_TOKEN not in body_text
        assert WRONG_TOKEN not in body_text

    def test_www_authenticate_header_present_on_401(self):
        """HTTP 401 responses must include a WWW-Authenticate header (RFC 9110)."""
        resp = _client().get("/protected")
        header_names = {k.lower() for k in resp.headers.keys()}
        assert "www-authenticate" in header_names

    def test_timing_attack_protection_uses_hmac_compare_digest(self):
        """verify_token must use hmac.compare_digest, not plain == comparison.

        Read the source to assert the invariant rather than trying to measure
        timing, which would be flaky.
        """
        from pathlib import Path
        src = (Path(__file__).parent.parent / "src" / "auth.py").read_text()
        assert "hmac.compare_digest" in src, (
            "auth.py must use hmac.compare_digest for constant-time comparison "
            "to prevent timing-based token enumeration attacks."
        )
