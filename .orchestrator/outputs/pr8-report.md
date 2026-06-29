# PR8 Audit Report — Sigma Rule Lifecycle + Promotion (planversion9.md)

## Branch / Commits

- Branch: `4.0`
- Commit SHA: `fbcb083`
- Message: `feat(pr8): rule lifecycle — admin-gated promotion + fail-closed audit + SELF-006`

## Files Changed

| File | Change |
|---|---|
| `services/api/src/routers/rules.py` | Modified — admin-gated mutations, actor tracking, path traversal guard, YAML hot-reload |
| `rules/local/self_detection/self_rule_status_mutation.yaml` | New — SELF-006 |
| `services/api/tests/test_rules_lifecycle.py` | New — 26 tests |
| `CHANGELOG.md` | Updated — PR8 section added |

## Scope Delivered

### Auth split (FR #10 dual-auth)
- `GET /v1/rules` and `GET /v1/rules/{rule_id}`: retained `verify_token` (any authenticated analyst).
- `POST /v1/rules` (register → draft) and `PUT /v1/rules/{id}/status` (lifecycle transition): switched to `require_service_token` — only the break-glass service token is accepted. Analyst-session callers receive 401 (verified by test).

### Fail-closed audit sequence
`send_security_event` (→ `SIEMHunterSecurity_CL`, EventType: `RuleChangeAudit`) is called **before** `client.insert` (→ ClickHouse `rule_registry`) in both POST and PUT. Sentinel failure → HTTP 503, `AuditWriteFailure` in `SIEMHunterHealth_CL`, ClickHouse insert skipped. Actor identity (string `"service_token"`) propagated through `_build_audit_record` and stored in `updated_by` column.

### Detection hot-reload
`_update_yaml_status` rewrites the `status:` field in the Sigma YAML on disk after each successful ClickHouse write. The detection service re-compiles from YAML files on every 15-minute batch cycle, picking up the change without a container restart. API container has writable rules mount confirmed in `docker-compose.yml` (`./rules:/app/rules`). Regex: `r"^(status:[ \t]*).*"` with `count=1` replaces entire line tail (handles quoted values; YAML block-scalar content is always indented and cannot match `^status:`).

### Path traversal guard
`_validate_file_path` resolves the user-supplied `file_path` and asserts it is within `_RULES_ROOT` (`/app/rules` by default). Returns HTTP 422 `INVALID_FILE_PATH` otherwise. Called in `register_rule` (POST) before any ClickHouse or Sentinel interaction.

### SELF-006 — `self_rule_status_mutation.yaml`
Added `rules/local/self_detection/self_rule_status_mutation.yaml` (ID: SELF-006, level: high). Logsource: `product: siemhunter / service: siemhunter-security`. Selection: `EventType: RuleChangeAudit`. Condition: `selection` (no status filter). Fires on ALL RuleChangeAudit events — covers promotions that SELF-003 (demotion-only) excludes. Satisfies GATE I.

## Acceptance Criteria

### AC1 — Non-admin promote attempt is rejected
- `test_put_no_auth_returns_401` — PASS
- `test_put_wrong_token_returns_401` — PASS
- `test_put_browser_origin_with_valid_token_returns_403` — PASS
- `test_put_with_only_session_cookie_returns_401` — PASS (analyst session = no Bearer = 401)
- `test_post_with_only_session_cookie_returns_401` — PASS

### AC2 — Admin promote writes Sentinel audit first, then activates the rule
- `test_promote_writes_audit_then_clickhouse` — PASS
  - `send_security_event` called with `EventType: RuleChangeAudit`, `actor: service_token`
  - `client.insert` called once, after audit
- `test_promote_audit_record_has_high_severity_for_production` — PASS
- `test_register_writes_audit_first` — PASS (call_order: `["audit", "clickhouse"]`)

### AC3 — Simulated audit failure blocks the promotion
- `test_audit_failure_returns_503` — PASS
- `test_audit_failure_leaves_clickhouse_untouched` — PASS (`client.insert.assert_not_called()`)
- `test_audit_failure_writes_health_event` — PASS
- `test_post_audit_failure_returns_503` — PASS

### AC4 — SELF-006 fires on rule-status change (covered by test)
- `test_self006_yaml_exists` — PASS
- `test_self006_is_valid_yaml` — PASS
- `test_self006_targets_rule_change_audit` — PASS
- `test_self006_condition_is_selection` — PASS
- `test_self006_logsource_targets_siemhunter_security` — PASS
- `test_self006_has_high_level` — PASS
- `test_self006_fires_on_simulated_rule_change_event` — PASS

## Code-Reviewer Loop

One bounded review-fix loop. Four findings addressed:

| Priority | Finding | Resolution |
|---|---|---|
| MUST FIX | `\S+` regex can miss quoted values on `status:` line | Changed to `.*` (replace full line tail) |
| MUST FIX | POST `register_rule` missing `_update_yaml_status` call | Added call after ClickHouse insert |
| SHOULD FIX | Path traversal via user-supplied `file_path` | Added `_validate_file_path` guard |
| SHOULD FIX | No test for analyst-session rejection on mutations | Added 2 session-cookie tests |

## Test Suite Result

- New tests: 26 (all PASS)
- Full suite: **263 passed, 0 failed** (up from 261 in PR7)
- All prior tests continue to pass (no regressions)

## Deviations

None. All scope items delivered as specified.

## PR9 Handoff Notes

1. Version surfaces still at `4.0.0-dev`; PR9 bumps all three to `4.0.0`.
2. **GATE H evidence** for PR9 gate-status doc: `require_service_token` is the sole dependency on both mutation routes; fail-closed sequence verified by `test_audit_failure_leaves_clickhouse_untouched`.
3. **GATE I evidence**: SELF-006 YAML + 7 `TestSelf006Rule` tests.
4. `rule_registry` uses `ReplacingMergeTree(updated_at)`; SELECTs use `FINAL` (invariant tested in `test_rules_final.py`).
5. No new DB migrations required; `rule_registry` schema exists from earlier PRs.
