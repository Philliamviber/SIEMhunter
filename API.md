# API Reference

SIEMhunter exposes a read-only control plane API at `http://127.0.0.1:8080`.
It is accessible from the local host only — never from the LAN.

All endpoints except `/v1/health` require a Bearer token in the `Authorization` header.
The token is stored in `secrets/api_auth_token.txt`.

```sh
TOKEN=$(cat secrets/api_auth_token.txt)
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/v1/status
```

OpenAPI/Swagger UI is **disabled** in all environments. This document is the
canonical API reference.

---

## Authentication

```
Authorization: Bearer <token>
```

The token is compared using `hmac.compare_digest` (constant-time comparison) to
prevent timing attacks. The token value is never logged or returned in error
responses.

**Auth failure response (HTTP 401):**
```json
{
  "error": "Invalid or missing bearer token",
  "code": "AUTH_REQUIRED"
}
```

Every auth failure is logged locally and asynchronously forwarded to
`SIEMHunterSecurity_CL` in Sentinel as an `AuthFailure` event. The Sentinel write
does not block the 401 response.

---

## Endpoints

### GET /v1/health

Health check for Docker's HEALTHCHECK instruction. No authentication required.

**Response 200:**
```json
{"status": "ok"}
```

This endpoint always returns 200 while the API process is running. It does not
check ClickHouse or other services.

---

### GET /v1/status

Returns a pipeline health summary: ClickHouse connectivity, per-service alive
file recency, and retry queue depth.

**Request:**
```sh
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/v1/status
```

**Response 200:**
```json
{
  "clickhouse": "ok",
  "normalization_alive": true,
  "detection_alive": true,
  "forwarder_alive": true,
  "pending_retry_queue": 0
}
```

**Field descriptions:**

| Field | Type | Description |
|-------|------|-------------|
| `clickhouse` | string | `"ok"` or `"error: <message>"` if the API cannot connect |
| `normalization_alive` | bool | True if `/tmp/normalization_alive` was modified within the last 5 minutes |
| `detection_alive` | bool | True if `/tmp/detection_alive` was modified within the last 5 minutes |
| `forwarder_alive` | bool | True if `/tmp/forwarder_alive` was modified within the last 5 minutes |
| `pending_retry_queue` | int | Number of `.json` files in the forwarder retry queue directory |

**Alive file semantics:** Each worker service touches its alive file at the end of
every batch cycle. If a service is stuck (blocked on a network call, in a tight
error loop, etc.), its alive file will not be updated and `_alive` will return false
within 5 minutes.

---

### POST /v1/query

Execute a read-only SELECT query against ClickHouse. Results are returned as JSON.

**Request:**
```sh
curl -s -X POST http://localhost:8080/v1/query \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "sql": "SELECT TimeGenerated, HostName, EventID FROM security_events WHERE EventID = {eid:UInt32} LIMIT 10",
    "params": {"eid": 4624}
  }'
```

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `sql` | string | Yes | A SELECT query. Must start with `SELECT`. |
| `params` | object | No | Named parameters for ClickHouse's `{name:type}` placeholder syntax. |

**Response 200:**
```json
{
  "rows": [
    {"TimeGenerated": "2026-06-19 12:00:00.000", "HostName": "dc01", "EventID": 4624}
  ],
  "row_count": 1,
  "truncated": false,
  "execution_time_ms": 42.1
}
```

**Response fields:**

| Field | Type | Description |
|-------|------|-------------|
| `rows` | array | Query result rows as objects (column name → value) |
| `row_count` | int | Number of rows returned |
| `truncated` | bool | True if the row cap (default 10,000) was reached; query may have more results |
| `execution_time_ms` | float | ClickHouse query execution time in milliseconds |

**Security controls applied:**
- Query must start with `SELECT` → else HTTP 400 `FORBIDDEN_STATEMENT`
- Forbidden keywords (INSERT, UPDATE, DELETE, DROP, CREATE, ALTER, TRUNCATE, RENAME, ATTACH, DETACH, OPTIMIZE) anywhere in the query → HTTP 400 `FORBIDDEN_STATEMENT`
- Query containing `169.254` (IMDS address) → HTTP 400 `SSRF_REJECTED`
- No `LIMIT` clause → `LIMIT 10000` appended automatically
- Query timeout: 30 seconds → HTTP 408 `QUERY_TIMEOUT`

**Error responses:**

| Status | Code | When |
|--------|------|------|
| 400 | `FORBIDDEN_STATEMENT` | Query is not SELECT, or contains mutation keywords |
| 400 | `SSRF_REJECTED` | Query references blocked address |
| 408 | `QUERY_TIMEOUT` | Query took longer than 30 seconds |
| 500 | `QUERY_ERROR` | ClickHouse returned an error |

---

### GET /v1/rules

List all rules in the rule registry.

**Request:**
```sh
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/v1/rules
```

**Response 200:**
```json
[
  {
    "rule_id": "SELF-001",
    "rule_version": "0.1.0",
    "status": "production",
    "file_path": "/app/rules/local/self_detection/SELF-001-cert-anomaly.yml",
    "updated_at": "2026-06-19T12:00:00.000Z"
  },
  {
    "rule_id": "WIN-AD-001",
    "rule_version": "0.1.0",
    "status": "test",
    "file_path": "/app/rules/local/windows_ad/kerberoasting.yml",
    "updated_at": "2026-06-19T11:30:00.000Z"
  }
]
```

Rules are ordered by `updated_at` descending (most recently changed first).

---

### GET /v1/rules/{rule_id}

Get the current status of a single rule.

**Request:**
```sh
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/v1/rules/SELF-001
```

**Response 200:**
```json
{
  "rule_id": "SELF-001",
  "rule_version": "0.1.0",
  "status": "production",
  "file_path": "/app/rules/local/self_detection/SELF-001-cert-anomaly.yml",
  "updated_at": "2026-06-19T12:00:00.000Z"
}
```

**Response 404:**
```json
{
  "error": "Rule not found: SELF-999",
  "code": "RULE_NOT_FOUND"
}
```

---

### PUT /v1/rules/{rule_id}/status

Promote or demote a rule's lifecycle status. This is the most security-sensitive
endpoint: every status change is audited to Sentinel BEFORE the change is applied
(fail-closed audit sequence).

**Valid status values:** `draft`, `test`, `review`, `production`, `disabled`

**Request:**
```sh
curl -s -X PUT http://localhost:8080/v1/rules/WIN-AD-001/status \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"new_status": "production", "reason": "Verified against 2 weeks of live data"}'
```

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `new_status` | string | Yes | Target status. Must be one of the valid values above. |
| `reason` | string | No | Human-readable reason for the change. Stored in the audit record. |

**Fail-closed sequence (what happens internally):**

1. Validate `new_status` is a recognised value → else HTTP 422
2. Look up current rule state → else HTTP 404
3. If current status == new status → return 200 immediately (idempotent no-op)
4. Build audit record for `SIEMHunterSecurity_CL` (EventType: `RuleChangeAudit`)
5. Write audit record to Sentinel (synchronous) → if this fails → HTTP 503 (rule NOT changed)
6. Update `siemhunter.rule_registry` in ClickHouse → if this fails → HTTP 500 (audit committed, ClickHouse failed — operator must reconcile)
7. Return 200 with new rule state

**Response 200:**
```json
{
  "rule_id": "WIN-AD-001",
  "rule_version": "0.1.0",
  "status": "production",
  "file_path": "/app/rules/local/windows_ad/kerberoasting.yml",
  "updated_at": "2026-06-19T12:15:00.000Z"
}
```

**Error responses:**

| Status | Code | When |
|--------|------|------|
| 404 | `RULE_NOT_FOUND` | No rule with this ID in the registry |
| 422 | `INVALID_STATUS` | `new_status` is not a valid lifecycle status |
| 503 | `AUDIT_WRITE_FAILED` | Sentinel write failed; rule change rejected |
| 500 | `CLICKHOUSE_UPDATE_FAILED` | Sentinel write succeeded but ClickHouse update failed; operator must reconcile |

---

## Error response shape

All error responses use this shape:

```json
{
  "error": "Human-readable description of what went wrong",
  "code": "MACHINE_READABLE_CODE"
}
```

Error codes:
- `AUTH_REQUIRED` — missing or invalid bearer token
- `RULE_NOT_FOUND` — rule ID not in registry
- `INVALID_STATUS` — invalid rule lifecycle status value
- `FORBIDDEN_STATEMENT` — query is not SELECT or contains mutation keywords
- `SSRF_REJECTED` — query references a blocked address
- `QUERY_TIMEOUT` — query exceeded 30-second timeout
- `QUERY_ERROR` — ClickHouse returned an error
- `AUDIT_WRITE_FAILED` — Sentinel audit write failed; operation rejected
- `CLICKHOUSE_UPDATE_FAILED` — ClickHouse update failed after Sentinel audit committed

---

## Query examples for common tasks

**Find recent high-severity detection hits:**
```json
{
  "sql": "SELECT hit_id, rule_id, severity, created_at, hit_count FROM detection_hits WHERE severity IN ('High') AND forwarded_at IS NULL ORDER BY created_at DESC LIMIT 20"
}
```

**Hunt for Kerberoasting indicators (EID 4769 with RC4 encryption):**
```json
{
  "sql": "SELECT TimeGenerated, HostName, SubjectUserName, ServiceName, TargetUserName FROM security_events WHERE EventID = 4769 AND ServiceName NOT LIKE '%$' ORDER BY TimeGenerated DESC LIMIT 100"
}
```

**Check ingest volume by source over the last hour:**
```json
{
  "sql": "SELECT ProvenanceTag, count() AS event_count FROM security_events WHERE TimeGenerated >= now() - INTERVAL 1 HOUR GROUP BY ProvenanceTag ORDER BY event_count DESC"
}
```

**Find events with high anomaly scores:**
```json
{
  "sql": "SELECT rule_id, anomaly_score, hit_count, created_at FROM detection_hits WHERE anomaly_score > 0.7 ORDER BY anomaly_score DESC LIMIT 20"
}
```
