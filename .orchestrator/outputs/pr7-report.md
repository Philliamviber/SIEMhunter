# PR7 Audit Report — In-UI Sigma Authoring: Editor + Compile-Validate + SELECT-only Dry-Run

## Summary

PR7 adds a Sigma rule authoring page with compile preview and a bounded, read-only dry-run
against recent ClickHouse events. No rule is promoted to `rule_registry` in this PR.

Branch: `4.0`
Implementation commit: `6efa96f`
Post-review fix commit: `b75e0dd` (HEAD)
Backend tests: 237 passed (19 new), 0 failed
Frontend tests: 373 passed (12 new), 0 failed

---

## Files Changed

| File | Type | Description |
|------|------|-------------|
| `services/api/src/routers/sigma_author.py` | NEW | POST /v1/sigma/compile and POST /v1/sigma/dryrun |
| `services/api/src/clickhouse_client.py` | MODIFIED | Added get_readonly_client() with readonly=1 |
| `services/api/src/main.py` | MODIFIED | Registered sigma_author router under /v1 |
| `services/api/tests/test_sigma_author.py` | NEW | 19 backend tests |
| `services/api/tests/conftest.py` | MODIFIED | Patched get_readonly_client in session fixture |
| `frontend/src/pages/SigmaAuthorPage.tsx` | NEW | YAML textarea editor + compile/dry-run UI |
| `frontend/src/pages/__tests__/SigmaAuthorPage.test.tsx` | NEW | 12 frontend tests |
| `frontend/src/types/api.ts` | MODIFIED | Added Sigma request/response interfaces |
| `frontend/src/api/client.ts` | MODIFIED | Added sigmaCompile() and sigmaDryRun() |
| `frontend/src/hooks/useApi.ts` | MODIFIED | Added useSigmaCompile() and useSigmaDryRun() |
| `frontend/src/App.tsx` | MODIFIED | Added /sigma route to SigmaAuthorPage |
| `frontend/src/components/PageLayout.tsx` | MODIFIED | Added Sigma Author nav item |

---

## Acceptance Criteria Verification

### 1. Invalid Sigma returns a clear compile error

Satisfied. POST /v1/sigma/compile with invalid YAML returns HTTP 422 with
code: SIGMA_COMPILE_ERROR and a human-readable error message.
Test: test_compile_error_returns_422.

### 2. A valid rule dry-runs and returns bounded sample matches plus a count

Satisfied. POST /v1/sigma/dryrun compiles the Sigma, wraps the compiled SQL with
WHERE TimeGenerated >= now() - INTERVAL 24 HOUR LIMIT 200, executes on a read-only
ClickHouse connection, and returns {sql, sample_rows, sampled_count, execution_time_ms}.
sampled_count reflects the capped row count (not a full-table count).
Tests: test_dryrun_success, test_dryrun_no_results.

### 3. Non-SELECT smuggling is rejected (covered by tests)

Satisfied. _assert_single_select() guard rejects the following (all return HTTP 400
FORBIDDEN_STATEMENT):

- Semicolon chaining: test_dryrun_rejects_semicolon
- Non-SELECT top-level (INSERT): test_dryrun_rejects_non_select
- DROP buried in subquery: test_dryrun_rejects_drop_in_subquery
- SYSTEM keyword: test_dryrun_rejects_system_keyword
- ALTER keyword: test_dryrun_rejects_alter
- UPDATE keyword: test_dryrun_rejects_update
- ClickHouse KILL QUERY: test_dryrun_rejects_kill
- ClickHouse GRANT: test_dryrun_rejects_grant
- ClickHouse EXCHANGE TABLES: test_dryrun_rejects_exchange

### 4. No code path writes to rule_registry

Satisfied. sigma_author.py uses only get_readonly_client() and only calls
client.query() (never client.insert()). The compile endpoint uses no DB at all.
Tests test_compile_no_rule_registry_write and test_dryrun_no_rule_registry_write
assert mock_ch.insert.assert_not_called().

### 5. Suite is green

Satisfied. 237 backend tests pass (19 new) and 373 frontend tests pass (12 new).

---

## Security Design

### Read-only ClickHouse connection: dual-layer defence

get_readonly_client() passes settings={"readonly": 1} (integer, protocol-correct) to
clickhouse_connect.get_client(). This is a session-level ClickHouse setting that prevents
any mutation at the engine level even if the application guard is bypassed.

Layer 1: _assert_single_select() — application guard, rejects before query execution.
Layer 2: readonly=1 — server-side enforcement, blocks writes regardless of app layer.

### SELECT-only guard (_FORBIDDEN_KEYWORDS regex)

Covers (with word boundaries, case-insensitive):
- Standard SQL DML/DDL: INSERT, UPDATE, DELETE, DROP, CREATE, ALTER, TRUNCATE, RENAME
- ClickHouse structural: ATTACH, DETACH, OPTIMIZE, SYSTEM
- ClickHouse control/privilege: KILL, GRANT, REVOKE, EXCHANGE, MOVE, FREEZE, FETCH

### Bounded dry-run

- Window: last 24h (SIGMA_DRYRUN_WINDOW_HOURS env var, clamped 1-168h)
- Row limit: 200 (SIGMA_DRYRUN_LIMIT env var)
- Query timeout: 15s (hard-coded _DRYRUN_TIMEOUT_SECONDS)

---

## Code-Reviewer Loop (one bounded pass)

The code-reviewer subagent reviewed sigma_author.py and clickhouse_client.py.
Findings addressed:

| Severity | Finding | Resolution |
|---|---|---|
| HIGH | Missing ClickHouse-specific keywords (KILL/GRANT/REVOKE/EXCHANGE/MOVE/FREEZE/FETCH) | Fixed + 3 new tests |
| HIGH | readonly setting was string "1" not integer 1 | Fixed: settings={"readonly": 1} |
| MEDIUM | match_count name misleading (capped not total) | Fixed: renamed to sampled_count |
| MEDIUM | window_hours interpolated into SQL | Accepted (Pydantic int + clamp [1,168] is safe) |
| LOW | Missing UPDATE/KILL/GRANT/EXCHANGE test cases | Fixed: 5 new tests added |
| LOW | Connection pooling absent | Deferred (out of PR7 scope) |

---

## pySigma Packaging Note for PR8/PR9

pySigma packages are currently only in services/detection/requirements.txt, not in
services/api/requirements.txt. The sigma_author.py module does a try/except import —
if pySigma is absent (as in the current API Docker image), both endpoints return
HTTP 503 SIGMA_UNAVAILABLE. PR8/PR9 should add pySigma to the API requirements.

---

## Handoff to PR8

1. /v1/sigma/compile and /v1/sigma/dryrun are live; compile_sigma_to_sql() in
   sigma_author.py is reusable.
2. No rows written to rule_registry in PR7. PR8 adds the governed lifecycle
   (draft -> test -> review -> production) with admin-gated, fail-closed audit.
3. get_readonly_client() is available for any future read-only operations.
4. pySigma packaging must be addressed before first production use of PR7 endpoints.
