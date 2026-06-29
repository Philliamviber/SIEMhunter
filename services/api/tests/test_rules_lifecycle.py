"""
Tests for PR8 — Sigma rule lifecycle: admin gate + fail-closed audit.

Acceptance criteria verified here
----------------------------------
AC1  A non-admin promote attempt is rejected (401 / 403).
AC2  An admin promote writes the Sentinel audit record BEFORE activating the rule
     in ClickHouse; on success the ClickHouse insert is called.
AC3  A simulated Sentinel audit failure blocks the promotion (503) and leaves
     ClickHouse untouched.
AC4  The SELF-006 YAML rule fires on a RuleChangeAudit event (structural check).

Authentication model
--------------------
Mutations (PUT /v1/rules/{id}/status, POST /v1/rules) require the service token
(require_service_token dependency).  Analyst session callers are rejected with
401 because no Bearer token is present.

ClickHouse and Sentinel are mocked throughout so no live infra is needed.
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest
import yaml
from fastapi.testclient import TestClient

from services.api.src.main import app

TEST_TOKEN = "test-secret-token-for-pytest"
ADMIN_HEADER = {"Authorization": f"Bearer {TEST_TOKEN}"}
CSRF_HEADER = "test-csrf-token"

_SELF006_PATH = (
    Path(__file__).parent.parent.parent.parent
    / "rules" / "local" / "self_detection" / "self_rule_status_mutation.yaml"
)

# Canonical mock rule row returned by _get_rule
_MOCK_RULE_ROW = (
    "test-rule-001",   # rule_id
    "1.0.0",           # rule_version
    "draft",           # status
    "/app/rules/local/windows_ad/test_rule.yaml",  # file_path
    "2026-06-29T00:00:00+00:00",  # updated_at
)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_ch_result(rows):
    r = MagicMock()
    r.result_rows = rows
    return r


def _make_rule_client(existing_row=None, post_update_row=None):
    """Return a mock ClickHouse client for rule lifecycle tests.

    existing_row:  the row returned by _get_rule on the FIRST call (pre-mutation).
    post_update_row: the row returned by _get_rule on the SECOND call (post-mutation).
    """
    client = MagicMock()
    first_result = _make_ch_result([existing_row] if existing_row else [])
    second_result = _make_ch_result(
        [post_update_row] if post_update_row else ([existing_row] if existing_row else [])
    )
    client.query.side_effect = [first_result, second_result]
    return client


# ── AC1: non-admin callers are rejected ──────────────────────────────────────

class TestAdminGate:
    """PUT and POST mutations require the service token; everything else is 401."""

    def test_put_no_auth_returns_401(self):
        """No auth at all on a PUT → 401."""
        with TestClient(app) as client:
            resp = client.put(
                "/v1/rules/test-rule-001/status",
                json={"new_status": "production"},
            )
        assert resp.status_code == 401, resp.text

    def test_put_wrong_token_returns_401(self):
        """Wrong service token → 401."""
        with TestClient(app) as client:
            resp = client.put(
                "/v1/rules/test-rule-001/status",
                json={"new_status": "production"},
                headers={"Authorization": "Bearer wrong-token"},
            )
        assert resp.status_code == 401, resp.text

    def test_put_browser_origin_with_valid_token_returns_403(self):
        """Browser-origin header with valid service token → 403 (C4b)."""
        with TestClient(app) as client:
            resp = client.put(
                "/v1/rules/test-rule-001/status",
                json={"new_status": "production"},
                headers={
                    "Authorization": f"Bearer {TEST_TOKEN}",
                    "Origin": "http://localhost:3000",
                },
            )
        assert resp.status_code == 403, resp.text

    def test_post_no_auth_returns_401(self):
        """No auth on POST /v1/rules → 401."""
        with TestClient(app) as client:
            resp = client.post(
                "/v1/rules",
                json={"rule_id": "new-rule", "rule_version": "1.0.0"},
            )
        assert resp.status_code == 401, resp.text

    def test_get_list_accepts_service_token(self):
        """GET /v1/rules is open to service-token callers (read-only)."""
        with TestClient(app) as client:
            resp = client.get("/v1/rules", headers=ADMIN_HEADER)
        assert resp.status_code == 200, resp.text

    def test_get_single_rule_returns_404_with_valid_token(self):
        """GET /v1/rules/{id} with valid token returns 404 when rule not found."""
        with TestClient(app) as client:
            resp = client.get("/v1/rules/nonexistent", headers=ADMIN_HEADER)
        assert resp.status_code == 404, resp.text

    def test_put_with_only_session_cookie_returns_401(self):
        """Analyst session cookie without Bearer token → 401 on PUT.

        require_service_token checks for a Bearer token; a session cookie with
        no Authorization header is treated as no credential.  This ensures that
        a logged-in analyst without the break-glass token cannot promote rules.
        """
        with TestClient(app) as client:
            resp = client.put(
                "/v1/rules/test-rule-001/status",
                json={"new_status": "production"},
                cookies={"siemhunter_session": "any-session-id"},  # no Bearer
            )
        assert resp.status_code == 401, resp.text

    def test_post_with_only_session_cookie_returns_401(self):
        """Analyst session cookie without Bearer token → 401 on POST."""
        with TestClient(app) as client:
            resp = client.post(
                "/v1/rules",
                json={"rule_id": "new-rule"},
                cookies={"siemhunter_session": "any-session-id"},
            )
        assert resp.status_code == 401, resp.text


# ── AC2: admin promote — audit-before-effect ──────────────────────────────────

class TestAdminPromoteAuditBeforeEffect:
    """An admin promote writes Sentinel audit first, then ClickHouse."""

    def test_promote_writes_audit_then_clickhouse(self):
        """Service token PUT: Sentinel write succeeds → ClickHouse insert called."""
        post_update = ("test-rule-001", "1.0.0", "production",
                       "/app/rules/local/test.yaml", "2026-06-29T01:00:00+00:00")
        ch_client = _make_rule_client(
            existing_row=_MOCK_RULE_ROW,
            post_update_row=post_update,
        )

        sentinel_calls: list[dict] = []

        def _capture_audit(record):
            sentinel_calls.append(record)

        with (
            patch("services.api.src.routers.rules.get_client", return_value=ch_client),
            patch("services.api.src.routers.rules.send_security_event", side_effect=_capture_audit),
            patch("services.api.src.routers.rules._update_yaml_status"),
        ):
            with TestClient(app) as client:
                resp = client.put(
                    "/v1/rules/test-rule-001/status",
                    json={"new_status": "production", "reason": "Approved in review cycle"},
                    headers=ADMIN_HEADER,
                )

        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["status"] == "production"

        # Audit MUST have been written (at least one RuleChangeAudit record)
        audit_records = [r for r in sentinel_calls if r.get("EventType") == "RuleChangeAudit"]
        assert len(audit_records) == 1, "Expected exactly one RuleChangeAudit sentinel record"
        detail = json.loads(audit_records[0]["Detail"])
        assert detail["old_status"] == "draft"
        assert detail["new_status"] == "production"
        assert detail["actor"] == "service_token"

        # ClickHouse insert MUST have been called (after audit)
        ch_client.insert.assert_called_once()
        insert_args = ch_client.insert.call_args
        # Column list must include status and updated_by
        col_names = insert_args.kwargs.get("column_names") or insert_args[1].get("column_names", [])
        assert "status" in col_names
        assert "updated_by" in col_names

    def test_promote_audit_record_has_high_severity_for_production(self):
        """Promotion to production triggers High severity in the audit record."""
        post_update = ("test-rule-001", "1.0.0", "production",
                       "/app/rules/local/test.yaml", "2026-06-29T01:00:00+00:00")
        ch_client = _make_rule_client(
            existing_row=_MOCK_RULE_ROW,
            post_update_row=post_update,
        )

        captured: list[dict] = []

        with (
            patch("services.api.src.routers.rules.get_client", return_value=ch_client),
            patch("services.api.src.routers.rules.send_security_event", side_effect=lambda r: captured.append(r)),
            patch("services.api.src.routers.rules._update_yaml_status"),
        ):
            with TestClient(app) as client:
                resp = client.put(
                    "/v1/rules/test-rule-001/status",
                    json={"new_status": "production"},
                    headers=ADMIN_HEADER,
                )

        assert resp.status_code == 200, resp.text
        audit = next(r for r in captured if r.get("EventType") == "RuleChangeAudit")
        assert audit["Severity"] == "High"

    def test_promote_updates_yaml_file(self):
        """After ClickHouse update, _update_yaml_status is called with the new status."""
        post_update = ("test-rule-001", "1.0.0", "test",
                       "/app/rules/local/test.yaml", "2026-06-29T01:00:00+00:00")
        ch_client = _make_rule_client(
            existing_row=_MOCK_RULE_ROW,
            post_update_row=post_update,
        )

        yaml_calls: list[tuple] = []

        def _capture_yaml(file_path, new_status):
            yaml_calls.append((file_path, new_status))

        with (
            patch("services.api.src.routers.rules.get_client", return_value=ch_client),
            patch("services.api.src.routers.rules.send_security_event"),
            patch("services.api.src.routers.rules._update_yaml_status", side_effect=_capture_yaml),
        ):
            with TestClient(app) as client:
                resp = client.put(
                    "/v1/rules/test-rule-001/status",
                    json={"new_status": "test"},
                    headers=ADMIN_HEADER,
                )

        assert resp.status_code == 200, resp.text
        assert len(yaml_calls) == 1
        _, called_status = yaml_calls[0]
        assert called_status == "test"


# ── AC3: audit failure → 503, ClickHouse untouched ────────────────────────────

class TestFailClosedAudit:
    """A Sentinel audit write failure must block the rule status change."""

    def test_audit_failure_returns_503(self):
        """When Sentinel raises, PUT returns 503."""
        ch_client = _make_rule_client(existing_row=_MOCK_RULE_ROW)

        with (
            patch("services.api.src.routers.rules.get_client", return_value=ch_client),
            patch(
                "services.api.src.routers.rules.send_security_event",
                side_effect=RuntimeError("Sentinel unreachable"),
            ),
            patch("services.api.src.routers.rules.send_health_event"),
        ):
            with TestClient(app) as client:
                resp = client.put(
                    "/v1/rules/test-rule-001/status",
                    json={"new_status": "production"},
                    headers=ADMIN_HEADER,
                )

        assert resp.status_code == 503, resp.text
        data = resp.json()
        assert data["detail"]["code"] == "AUDIT_WRITE_FAILED"

    def test_audit_failure_leaves_clickhouse_untouched(self):
        """When Sentinel raises, ClickHouse insert is NOT called."""
        ch_client = _make_rule_client(existing_row=_MOCK_RULE_ROW)

        with (
            patch("services.api.src.routers.rules.get_client", return_value=ch_client),
            patch(
                "services.api.src.routers.rules.send_security_event",
                side_effect=RuntimeError("Sentinel unreachable"),
            ),
            patch("services.api.src.routers.rules.send_health_event"),
        ):
            with TestClient(app) as client:
                client.put(
                    "/v1/rules/test-rule-001/status",
                    json={"new_status": "production"},
                    headers=ADMIN_HEADER,
                )

        ch_client.insert.assert_not_called()

    def test_audit_failure_writes_health_event(self):
        """When Sentinel raises, an AuditWriteFailure health event is emitted."""
        ch_client = _make_rule_client(existing_row=_MOCK_RULE_ROW)
        health_calls: list[dict] = []

        with (
            patch("services.api.src.routers.rules.get_client", return_value=ch_client),
            patch(
                "services.api.src.routers.rules.send_security_event",
                side_effect=RuntimeError("Sentinel unreachable"),
            ),
            patch(
                "services.api.src.routers.rules.send_health_event",
                side_effect=lambda r: health_calls.append(r),
            ),
        ):
            with TestClient(app) as client:
                client.put(
                    "/v1/rules/test-rule-001/status",
                    json={"new_status": "production"},
                    headers=ADMIN_HEADER,
                )

        assert any(r.get("EventType") == "AuditWriteFailure" for r in health_calls), (
            "Expected an AuditWriteFailure health event when Sentinel is unreachable"
        )

    def test_post_audit_failure_returns_503(self):
        """POST /v1/rules: audit failure → 503, ClickHouse insert not called."""
        ch_client = MagicMock()
        ch_client.query.return_value = _make_ch_result([])  # no existing rule

        with (
            patch("services.api.src.routers.rules.get_client", return_value=ch_client),
            patch(
                "services.api.src.routers.rules.send_security_event",
                side_effect=RuntimeError("Sentinel unreachable"),
            ),
            patch("services.api.src.routers.rules.send_health_event"),
        ):
            with TestClient(app) as client:
                resp = client.post(
                    "/v1/rules",
                    json={"rule_id": "new-rule", "rule_version": "1.0.0"},
                    headers=ADMIN_HEADER,
                )

        assert resp.status_code == 503, resp.text
        ch_client.insert.assert_not_called()


# ── AC4: SELF-006 Sigma rule fires on RuleChangeAudit ──────────────────────────

class TestSelf006Rule:
    """Structural validation of SELF-006 Sigma rule (GATE I)."""

    def test_self006_yaml_exists(self):
        """The SELF-006 YAML file exists in the expected location."""
        assert _SELF006_PATH.exists(), (
            f"SELF-006 rule not found at {_SELF006_PATH}. "
            "Expected rules/local/self_detection/self_rule_status_mutation.yaml"
        )

    def test_self006_is_valid_yaml(self):
        """SELF-006 file parses as valid YAML."""
        content = _SELF006_PATH.read_text(encoding="utf-8")
        rule = yaml.safe_load(content)
        assert isinstance(rule, dict), "SELF-006 YAML must be a mapping"

    def test_self006_targets_rule_change_audit(self):
        """SELF-006 detection selects on EventType: RuleChangeAudit."""
        rule = yaml.safe_load(_SELF006_PATH.read_text(encoding="utf-8"))
        detection = rule.get("detection", {})
        selection = detection.get("selection", {})
        assert selection.get("EventType") == "RuleChangeAudit", (
            "SELF-006 must select on EventType: RuleChangeAudit to fire on rule-status mutations"
        )

    def test_self006_condition_is_selection(self):
        """SELF-006 condition must include 'selection' (fires on every RuleChangeAudit)."""
        rule = yaml.safe_load(_SELF006_PATH.read_text(encoding="utf-8"))
        condition = rule.get("detection", {}).get("condition", "")
        assert "selection" in str(condition), (
            "SELF-006 condition must include 'selection' so it fires on every RuleChangeAudit"
        )

    def test_self006_logsource_targets_siemhunter_security(self):
        """SELF-006 must target the siemhunter-security log source (SIEMHunterSecurity_CL)."""
        rule = yaml.safe_load(_SELF006_PATH.read_text(encoding="utf-8"))
        logsource = rule.get("logsource", {})
        assert logsource.get("product") == "siemhunter", (
            "SELF-006 logsource.product must be 'siemhunter'"
        )
        assert logsource.get("service") == "siemhunter-security", (
            "SELF-006 logsource.service must be 'siemhunter-security'"
        )

    def test_self006_has_high_level(self):
        """SELF-006 must be level: high (rule lifecycle changes are security-sensitive)."""
        rule = yaml.safe_load(_SELF006_PATH.read_text(encoding="utf-8"))
        assert rule.get("level") == "high", (
            "SELF-006 must have level: high — rule lifecycle changes are security-sensitive"
        )

    def test_self006_fires_on_simulated_rule_change_event(self):
        """Simulate a RuleChangeAudit event and verify SELF-006 selection matches it."""
        rule = yaml.safe_load(_SELF006_PATH.read_text(encoding="utf-8"))
        selection = rule.get("detection", {}).get("selection", {})

        # Simulate the event emitted by rules.py on every status mutation
        event = {
            "EventType": "RuleChangeAudit",
            "RuleId": "test-rule-001",
            "RuleVersion": "1.0.0",
            "Entity": "/app/rules/local/windows_ad/test.yaml",
            "Severity": "High",
            "Detail": json.dumps({
                "old_status": "draft",
                "new_status": "production",
                "reason": "Approved",
                "actor": "service_token",
            }),
        }

        # Check every key in selection matches the event (field equality)
        for field, expected in selection.items():
            assert event.get(field) == expected, (
                f"SELF-006 selection field {field!r} = {expected!r} "
                f"does not match simulated event value {event.get(field)!r}"
            )


# ── Additional: POST /v1/rules registration ───────────────────────────────────

class TestRuleRegistration:
    """POST /v1/rules registers a new rule in draft status with fail-closed audit."""

    def test_register_new_rule_returns_201(self):
        """Happy path: register a new rule → 201 with draft status."""
        ch_client = MagicMock()
        # First query (existence check): no rows
        # Second query (post-insert fetch): the new row
        new_row = ("new-rule-id", "1.0.0", "draft", "/app/rules/local/new_rule.yaml",
                   "2026-06-29T02:00:00+00:00")
        ch_client.query.side_effect = [
            _make_ch_result([]),         # existence check: not found
            _make_ch_result([new_row]),  # post-insert fetch
        ]

        with (
            patch("services.api.src.routers.rules.get_client", return_value=ch_client),
            patch("services.api.src.routers.rules.send_security_event"),
        ):
            with TestClient(app) as client:
                resp = client.post(
                    "/v1/rules",
                    json={
                        "rule_id": "new-rule-id",
                        "rule_version": "1.0.0",
                        "file_path": "/app/rules/local/new_rule.yaml",
                    },
                    headers=ADMIN_HEADER,
                )

        assert resp.status_code == 201, resp.text
        data = resp.json()
        assert data["rule_id"] == "new-rule-id"
        assert data["status"] == "draft"

    def test_register_duplicate_rule_returns_409(self):
        """Registering an already-registered rule_id → 409 Conflict."""
        ch_client = MagicMock()
        ch_client.query.return_value = _make_ch_result([_MOCK_RULE_ROW])

        with (
            patch("services.api.src.routers.rules.get_client", return_value=ch_client),
        ):
            with TestClient(app) as client:
                resp = client.post(
                    "/v1/rules",
                    json={"rule_id": "test-rule-001"},
                    headers=ADMIN_HEADER,
                )

        assert resp.status_code == 409, resp.text
        assert resp.json()["detail"]["code"] == "RULE_EXISTS"

    def test_register_writes_audit_first(self):
        """Audit record is written before ClickHouse insert on POST /v1/rules."""
        ch_client = MagicMock()
        new_row = ("reg-rule", "0.0.1", "draft", "", "2026-06-29T02:00:00+00:00")
        ch_client.query.side_effect = [
            _make_ch_result([]),        # existence check
            _make_ch_result([new_row]), # post-insert fetch
        ]

        call_order: list[str] = []

        def _audit(record):
            call_order.append("audit")

        def _ch_insert(*args, **kwargs):
            call_order.append("clickhouse")

        ch_client.insert.side_effect = _ch_insert

        with (
            patch("services.api.src.routers.rules.get_client", return_value=ch_client),
            patch("services.api.src.routers.rules.send_security_event", side_effect=_audit),
        ):
            with TestClient(app) as client:
                client.post(
                    "/v1/rules",
                    json={"rule_id": "reg-rule"},
                    headers=ADMIN_HEADER,
                )

        assert call_order == ["audit", "clickhouse"], (
            f"Expected audit before ClickHouse insert, got: {call_order}"
        )


# ── Idempotency: same-status update is a no-op ────────────────────────────────

class TestIdempotency:
    """Updating to the same status is a no-op — no audit or insert."""

    def test_same_status_is_noop(self):
        """PUT to the same status returns 200 without writing audit or ClickHouse."""
        # Rule is already in draft status; requesting draft again
        ch_client = MagicMock()
        ch_client.query.return_value = _make_ch_result([_MOCK_RULE_ROW])

        sentinel_calls: list = []

        with (
            patch("services.api.src.routers.rules.get_client", return_value=ch_client),
            patch(
                "services.api.src.routers.rules.send_security_event",
                side_effect=lambda r: sentinel_calls.append(r),
            ),
        ):
            with TestClient(app) as client:
                resp = client.put(
                    "/v1/rules/test-rule-001/status",
                    json={"new_status": "draft"},
                    headers=ADMIN_HEADER,
                )

        assert resp.status_code == 200, resp.text
        # No audit or insert on a no-op
        assert not sentinel_calls, "No audit should be written for a no-op status update"
        ch_client.insert.assert_not_called()
