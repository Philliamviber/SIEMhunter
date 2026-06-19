# SIEMhunter — API Control Plane

**Document:** 06-api-control-plane.md
**Version:** 0.1.0-draft
**Date:** 2026-06-19
**Status:** Authoritative — governs all FastAPI control-plane design and implementation decisions for v0.1.0
**Owner:** implementer
**Audience:** implementer (FastAPI service), security-reviewer, cloud-security-engineer (forwarder config endpoints), detection-engineer (rule management endpoints)

---

## 1. Overview

The FastAPI control plane is the administrative surface of SIEMhunter. It exists to make the system easy to operate — registering sources, managing detection rules, inspecting pipeline health, and running ad-hoc queries — without requiring direct access to ClickHouse, Vector config files, or Docker secrets. It is not a user interface; it is an API that a local admin or a thin future frontend calls.

Two architectural facts shape every design decision in this document:

**The control plane is not internet-facing.** It binds to `127.0.0.1` inside the Docker internal network. There is no published port, no reverse proxy, and no TLS terminator facing outward. The threat model (see `14-threat-model.md`) treats the control plane's attacker class as a compromised analyst with authenticated local access — not an external adversary.

**The control plane is the audit chokepoint.** Every mutation to the system — source registration, rule promotion, forwarder config update — passes through this API. This means the control plane is the natural enforcement point for audit logging and for the fail-closed rule-change mechanism described in §4. Nothing should bypass it; anything that does bypass it (e.g., a direct ClickHouse write) is invisible to the audit trail and is a security gap.

All endpoints are versioned under `/v1/`. OpenAPI documentation is disabled in production (no Swagger UI, no Redoc). The API accepts and returns JSON.

---

## 2. Authentication

### Mechanism

All endpoints require a bearer token. The token is a pre-shared secret that is:

- Stored as a Docker secret
- Injected at container start into `/run/secrets/api_token`
- Read once at startup by the FastAPI application; never written to disk, environment variables, or logs

Every request must include:

```
Authorization: Bearer {token}
```

Requests missing this header, presenting a malformed header, or presenting an incorrect token receive a `401 Unauthorized` response.

### Token comparison

Token comparison uses `hmac.compare_digest` (Python standard library `hmac` module). This is a constant-time comparison that prevents timing-based token enumeration. A naive string equality check (`==`) leaks timing information proportional to the length of the matching prefix; `hmac.compare_digest` does not.

```python
import hmac

def verify_token(provided: str, expected: str) -> bool:
    return hmac.compare_digest(provided.encode(), expected.encode())
```

The expected token value is the content of `/run/secrets/api_token`, stripped of trailing whitespace. If the file is missing or empty at startup, the application must refuse to start and log the failure to stderr.

### Auth failure logging

Every authentication failure is logged to `SIEMHunterSecurity_CL` with the following fields:

| Field | Value |
|-------|-------|
| `EventType` | `AuthFailure` |
| `Entity` | Source IP address of the request |
| `Detail` | Endpoint path and HTTP method |
| `Severity` | `Warning` |
| `TimeGenerated` | UTC timestamp of the failure |

Auth failures are written to `SIEMHunterSecurity_CL` (not `SIEMHunterHealth_CL`) because repeated failures from the same source IP constitute a brute-force signal that a Sentinel analytics rule may alert on. The independence requirement from `04-normalization-and-schema.md` §7 applies: a failure to write the auth-failure event to Sentinel must not prevent the `401` from being returned to the caller.

### Secrets never returned

No endpoint returns the bearer token value, the forwarder certificate, the forwarder private key, or any other secret value injected via Docker secrets. Endpoints that display configuration redact secret-class fields. See §3 (Forwarder configuration) for the specific redaction rules.

---

## 3. API Endpoints

All paths are prefixed with `/v1/`. The base URL when called from the Docker host is `http://127.0.0.1:{PORT}/v1/`.

### 3.1 Source Management

These endpoints manage the registration of telemetry sources. Registration drives Vector pipeline configuration as documented in `03-data-ingestion-spec.md` §3.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/sources` | List all registered sources |
| `POST` | `/v1/sources` | Register a new source |
| `DELETE` | `/v1/sources/{source_id}` | Deregister a source |
| `GET` | `/v1/sources/{source_id}/health` | Per-source health metrics |

#### GET /v1/sources

Returns a JSON array of registered source objects. Each object includes:

| Field | Type | Description |
|-------|------|-------------|
| `source_id` | string | Stable UUID assigned at registration |
| `name` | string | Human-readable name |
| `type` | string | One of: `syslog`, `windows_event_log`, `netflow`, `file`, `azure_pull` |
| `status` | string | `active`, `paused`, or `deregistered` |
| `provenance_tag` | string | Immutable tag in format `{type}-{source_id_short}` (e.g., `syslog-tcp-6514`) |
| `registered_at` | string | ISO 8601 UTC timestamp |

Connection parameters (host, port, credentials) are **not** returned in the list response. They are available only via a separate per-source detail endpoint if one is added in a future version. This limits credential exposure surface.

#### POST /v1/sources

Registers a new source. Request body (Pydantic model, `extra = "forbid"`):

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Human-readable label |
| `type` | string | yes | Source type (enum: `syslog`, `windows_event_log`, `netflow`, `file`, `azure_pull`) |
| `connection_params` | object | yes | Type-specific connection parameters (see below) |

The `connection_params` object is validated per source type. For syslog: `host`, `port`, `protocol` (tcp/udp/tls). For `azure_pull`: `workspace_id`, `query`. Any URL-valued field in `connection_params` is validated against the SSRF allowlist described in §5 before the source is accepted.

On success:
- Assigns a stable UUID `source_id`
- Assigns an immutable `ProvenanceTag`
- Renders and validates the Vector pipeline config fragment
- Sends SIGHUP to Vector (no restart)
- Returns `201 Created` with the full source object

On failure (invalid params, SSRF-blocked URL, Vector config validation error): returns `422 Unprocessable Entity` with a structured error body. The Vector config is not applied if validation fails.

#### DELETE /v1/sources/{source_id}

Deregisters the source. Effects:
- Sets source `status` to `deregistered`
- Removes the source's fragment from the Vector pipeline config
- Sends SIGHUP to Vector to stop collection

**Historical events in ClickHouse are NOT deleted.** The `ProvenanceTag` for the deregistered source remains in `security_events` rows. Deregistered source IDs are never reused; if the same physical source is re-added, a new UUID and a new `ProvenanceTag` are issued.

Returns `200 OK` with the final source state. Returns `404` if `source_id` is unknown.

#### GET /v1/sources/{source_id}/health

Returns a health snapshot for the source:

| Field | Type | Description |
|-------|------|-------------|
| `source_id` | string | Source identifier |
| `last_event_at` | string | ISO 8601 UTC timestamp of the most recent event received |
| `events_per_hour` | integer | Rolling 1-hour event count |
| `parse_error_rate` | float | Fraction of events that produced a parse error in the last hour (0.0–1.0) |
| `status` | string | Current source status |

Values are derived from `SIEMHunterHealth_CL`. If no events have been received in the last hour, `last_event_at` is the timestamp of the most recent event ever received (may be null for a newly registered source), and `events_per_hour` is `0`.

---

### 3.2 Detection Rule Management

These endpoints manage the lifecycle of local Sigma detection rules. Rules are compiled by pySigma against the ClickHouse pipeline (`rules/pipelines/clickhouse-asim-ocsf.yaml`) as documented in `04-normalization-and-schema.md` §8.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/rules` | List all rules |
| `GET` | `/v1/rules/{rule_id}` | Get rule details |
| `POST` | `/v1/rules` | Create a new rule |
| `PUT` | `/v1/rules/{rule_id}/status` | Promote or demote rule status |
| `DELETE` | `/v1/rules/{rule_id}` | Soft-delete a rule |

#### Rule status lifecycle

```
draft → test → review → production
         ↑         ↓
         ← ← ← ← ←
              ↓
           disabled   (soft-delete; terminal state reachable from any status)
```

Status transitions in either direction (promotion or demotion) and deletion are **fail-closed audit operations** — see §4.

#### GET /v1/rules

Returns a JSON array of rule metadata objects:

| Field | Type | Description |
|-------|------|-------------|
| `rule_id` | string | Stable UUID |
| `name` | string | Rule display name |
| `status` | string | Current lifecycle status |
| `last_modified` | string | ISO 8601 UTC timestamp of last status change |
| `attack_technique` | string | ATT&CK technique ID (e.g., `T1558.003`); null if not tagged |
| `author` | string | Rule author (from Sigma YAML) |

#### GET /v1/rules/{rule_id}

Returns full rule metadata plus the Sigma YAML source. The **compiled SQL is never returned** — it is an internal artifact used by the detection engine and is not part of the API contract. Returning compiled SQL would expose the ClickHouse schema in a form that simplifies SQL-injection exploration.

Response includes all fields from the list response plus:

| Field | Type | Description |
|-------|------|-------------|
| `sigma_yaml` | string | The Sigma YAML source for the rule |
| `compile_warnings` | array | Any pySigma compilation warnings (must be empty for `production` rules) |
| `created_at` | string | ISO 8601 UTC creation timestamp |

#### POST /v1/rules

Creates a new rule in `draft` status. Request body:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `sigma_yaml` | string | yes | Full Sigma YAML content |

The API:
1. Parses and validates the Sigma YAML (schema validation; rejects malformed YAML immediately)
2. Runs pySigma compilation against `rules/pipelines/clickhouse-asim-ocsf.yaml`
3. If compilation produces errors: returns `422` with the compile error list; the rule is not stored
4. If compilation succeeds (warnings are allowed at `draft` status but are flagged): stores the rule with `status = draft` and returns `201 Created`

The compilation step is synchronous. A rule that fails to compile is never stored. This prevents rules with unmapped fields from silently producing zero results (see `04-normalization-and-schema.md` §8, "Silent zero-result risk").

#### PUT /v1/rules/{rule_id}/status

Promotes or demotes a rule's lifecycle status. This endpoint is subject to the **fail-closed audit sequence** in §4.

Request body:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `new_status` | string | yes | Target status (one of: `draft`, `test`, `review`, `production`, `disabled`) |
| `reason` | string | no | Human-readable reason for the change (recommended for audit legibility) |

The API enforces that `production` status requires zero pySigma compilation warnings. A rule with outstanding warnings cannot be promoted to `production`; the caller receives `422` explaining which warnings must be resolved.

Returns `200 OK` with the updated rule state on success. Returns `503 Service Unavailable` if the Sentinel audit write fails (see §4).

#### DELETE /v1/rules/{rule_id}

Soft-deletes the rule: sets `status` to `disabled`. The rule record and its Sigma YAML are retained in the database for audit purposes. The rule is removed from the active detection batch.

This endpoint is subject to the **fail-closed audit sequence** in §4.

Returns `200 OK` with the final rule state. Returns `404` if `rule_id` is unknown or already `disabled`.

---

### 3.3 Forwarder Configuration

These endpoints manage the Sentinel forwarder configuration. **Secrets (certificate content, private key, tokens) can only be updated by rotating the Docker secret and redeploying the container.** The API manages only non-secret configuration values.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/forwarder/config` | Return forwarder config (secrets redacted) |
| `PUT` | `/v1/forwarder/config` | Update non-secret forwarder config |
| `GET` | `/v1/forwarder/health` | Return forwarder health metrics |

#### GET /v1/forwarder/config

Returns the current forwarder configuration. Secret-class fields are always redacted in the response:

| Field | Type | Returned | Description |
|-------|------|----------|-------------|
| `dce_uri` | string | yes | Data Collection Endpoint URI |
| `dcr_id` | string | yes | Data Collection Rule immutable ID |
| `workspace_id` | string | yes | Log Analytics workspace ID |
| `batch_interval_seconds` | integer | yes | How often the forwarder flushes (default: 900) |
| `cert_path` | string | **REDACTED** | Docker secret path for the certificate; shown as `"[REDACTED]"` |
| `cert_content` | — | **never returned** | Certificate PEM content is never included in any response |
| `private_key` | — | **never returned** | Private key is never included in any response |
| `api_token` | — | **never returned** | Bearer token is never included in any response |

The response for a redacted field contains the literal string `"[REDACTED]"` for fields where the path is informational (like `cert_path`). Fields whose values are entirely secret (cert content, key content, token values) are omitted from the response body entirely — they do not appear with a redacted placeholder, because the field name itself may be informational to an attacker.

#### PUT /v1/forwarder/config

Updates non-secret forwarder configuration. Request body (`extra = "forbid"`):

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `dce_uri` | string | no | New DCE URI |
| `dcr_id` | string | no | New DCR immutable ID |
| `workspace_id` | string | no | New workspace ID |
| `batch_interval_seconds` | integer | no | New batch interval (minimum: 60; maximum: 3600) |

Any URL-valued field (`dce_uri`) is validated against the SSRF allowlist in §5 before the config is updated. A `dce_uri` that resolves to a loopback, link-local, or non-approved private address is rejected with `422`.

Returns `200 OK` with the full updated config (secrets still redacted). Secrets cannot be updated through this endpoint under any circumstances.

#### GET /v1/forwarder/health

Returns:

| Field | Type | Description |
|-------|------|-------------|
| `last_successful_forward_at` | string | ISO 8601 UTC timestamp of last successful batch forward |
| `events_forwarded_24h` | integer | Total events forwarded in the last 24 hours |
| `last_error` | string | Last error message from the forwarder; null if no recent errors |
| `last_error_at` | string | Timestamp of the last error; null if no recent errors |

---

### 3.4 Health and Pipeline Status

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/health` | Overall system health across all services |
| `GET` | `/v1/health/{service}` | Per-service health details |
| `GET` | `/v1/metrics` | Aggregate event and detection metrics |

#### GET /v1/health

Returns a summary health object:

| Field | Type | Description |
|-------|------|-------------|
| `status` | string | `healthy`, `degraded`, or `unhealthy` |
| `services` | object | Map of service name to service status |
| `checked_at` | string | ISO 8601 UTC timestamp |

Service names in the `services` map: `vector`, `clickhouse`, `normalization`, `detection`, `forwarder`.

`status` is `healthy` if all services report healthy. `degraded` if one or more non-critical services report a warning. `unhealthy` if any critical service (ClickHouse, normalization) reports a failure.

#### GET /v1/health/{service}

Valid `service` values: `vector`, `clickhouse`, `normalization`, `detection`, `forwarder`.

Returns a service-specific detail object. At minimum:

| Field | Type | Description |
|-------|------|-------------|
| `service` | string | Service name |
| `status` | string | `healthy`, `warning`, or `unhealthy` |
| `last_check_at` | string | ISO 8601 UTC timestamp of last health check |
| `detail` | string | Human-readable status detail or error message |

Returns `404` for unknown service names.

#### GET /v1/metrics

Returns aggregate pipeline metrics for the last 24 hours:

| Field | Type | Description |
|-------|------|-------------|
| `events_by_source` | object | Map of `provenance_tag` → event count (last 24h) |
| `detection_hits_24h` | integer | Total Sigma rule hits in the last 24 hours |
| `anomaly_score_distribution` | object | Histogram buckets for ML anomaly scores (last 24h); null if ML scoring not yet run |
| `last_batch_run_at` | string | ISO 8601 UTC timestamp of the last completed detection batch |
| `last_batch_duration_seconds` | float | Duration of the last detection batch run |

---

### 3.5 Query API

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v1/query` | Execute a read-only ClickHouse query |

This endpoint is intended for ad-hoc analyst queries against the local ClickHouse store. It is not a general SQL interface; it enforces strict restrictions to prevent misuse.

#### POST /v1/query

Request body:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `query` | string | yes | SQL query to execute |
| `params` | object | no | Named parameters for the query (key-value pairs) |

**Restrictions enforced server-side before execution:**

1. **SELECT only.** The query string is checked for the presence of forbidden keywords: `INSERT`, `UPDATE`, `DELETE`, `DROP`, `CREATE`, `ALTER`, `TRUNCATE`, `RENAME`, `ATTACH`, `DETACH`, `OPTIMIZE`. The check is case-insensitive and applies to the full query string including comments. A query containing any forbidden keyword is rejected with `422` before it reaches ClickHouse.

2. **Parameterized only.** User-supplied values must be passed in the `params` object and referenced in the query as named parameters (ClickHouse parameter syntax: `{param_name:Type}`). The API must never interpolate any value from `params` into the `query` string via string concatenation. The ClickHouse client library's native parameterized query interface handles substitution.

3. **Query timeout: 30 seconds.** ClickHouse is configured with a `max_execution_time` of 30 seconds for queries submitted via this endpoint. Queries exceeding the timeout are cancelled and the caller receives `408 Request Timeout`.

4. **Result size cap: 10,000 rows.** A `LIMIT 10000` clause is appended server-side to every query if the query does not already include a `LIMIT` clause. If the query includes a `LIMIT` clause larger than 10,000, the server-side cap overrides it. This prevents memory exhaustion from unbounded result sets.

Response on success: `200 OK` with a JSON body:

```json
{
  "rows": [ { "col": "value", ... }, ... ],
  "row_count": 42,
  "truncated": false,
  "execution_time_ms": 187
}
```

`truncated` is `true` if the result was capped at 10,000 rows (i.e., the underlying query would have returned more rows). This tells the caller they should add a more specific `WHERE` clause.

Returns `422` for forbidden keyword violations or parameterization errors. Returns `408` for timeout. Returns `500` for ClickHouse execution errors (error message included; no internal ClickHouse stack traces in the response body).

---

## 4. Fail-Closed Rule-Change Audit

This is the most security-critical control in the control plane. It applies to two endpoints: `PUT /v1/rules/{rule_id}/status` and `DELETE /v1/rules/{rule_id}`.

### Purpose

The fail-closed audit mechanism ensures that any change to a detection rule — promotion, demotion, or deletion — is **durably recorded in Sentinel before the change takes effect locally**. An attacker who gains authenticated access to the control plane and disables a detection rule cannot also suppress the audit record: the audit record lands in Sentinel first. The attacker would need to separately compromise the Sentinel workspace to erase evidence of what they did.

### Mandatory sequence

The following sequence must be followed exactly. Any deviation — including reordering steps 2 and 4 — breaks the tamper-evidence property.

```
Step 1: Validate the request
         ↓
Step 2: Construct the audit record
         ↓
Step 3: Write the audit record to Sentinel (SIEMHunterSecurity_CL)
         ↓
     ┌── SUCCESS? ──┐
     │ NO           │ YES
     ↓              ↓
 Return 503     Step 4: Apply the rule change in ClickHouse
 Log to                  ↓
 Health_CL           Return 200 with new rule state
```

**Step 1 — Validate the request.** Authenticate the bearer token. Validate the request body. Verify the `rule_id` exists and that the requested transition is valid (e.g., a rule already in `disabled` status cannot be deleted again). Return `401`, `404`, or `422` as appropriate for validation failures. No audit record is written for validation failures.

**Step 2 — Construct the audit record.** Build the `SIEMHunterSecurity_CL` row:

| Field | Value |
|-------|-------|
| `TimeGenerated` | UTC timestamp at the moment of the request |
| `RuleId` | The `rule_id` from the path parameter |
| `RuleVersion` | Current rule version at the time of the change |
| `EventType` | `RuleChangeAudit` |
| `SourceEventIds` | Empty array (this is a control-plane event, not a telemetry event) |
| `Entity` | The rule name |
| `Detail` | JSON-serialized string: `{"old_status": "...", "new_status": "...", "reason": "...", "actor": "API/bearer"}` |
| `Severity` | `Informational` for draft/test/review transitions; `High` for transitions to `production` or `disabled` |

The `actor` field in `Detail` identifies the authentication context. In v0.1.0, this is always `"API/bearer"` (bearer token auth). If RBAC is added in a future version, `actor` should carry the token identity or username.

**Step 3 — Write to Sentinel.** Submit the audit record to `SIEMHunterSecurity_CL` via the Logs Ingestion API (DCE/DCR path documented in `07-sentinel-forwarding.md`). This write is **synchronous and blocking** — the control-plane request does not proceed until the Sentinel write completes or fails.

If the Sentinel write **fails** (network error, authentication failure, DCR error, timeout):
- Do **not** apply the rule change in ClickHouse
- Return `503 Service Unavailable` to the caller with a body indicating the audit write failed
- Log the failure to `SIEMHunterHealth_CL` with `EventType = "AuditWriteFailure"`, the `rule_id`, the attempted `new_status`, and the Sentinel error detail
- The rule state in ClickHouse is unchanged

If the Sentinel write **succeeds** (HTTP 204 from the Logs Ingestion API):
- Proceed to step 4

**Step 4 — Apply the change in ClickHouse.** Update the rule's status in the ClickHouse rules table. If this ClickHouse write fails after a successful Sentinel write, the audit record already exists in Sentinel. Return `500` to the caller and log the ClickHouse failure. The operator can reconcile the state manually; the audit trail is intact.

**Step 5 — Return to caller.** Return `200 OK` with the updated rule state (including the new `status` and `last_modified` timestamp).

### Why fail-closed matters

A detection-rule disable that bypasses this sequence (e.g., a direct ClickHouse write) produces no audit record in Sentinel. The rule-disable self-detection (FR-09 self-detection 3) — which reads `SIEMHunterSecurity_CL` looking for `RuleChangeAudit` entries — would not see the change and would not fire an alert. The fail-closed sequence is what makes the self-detection meaningful.

An attacker who disables detection via the control plane leaves a durable trace in Sentinel before their change lands. Sentinel is outside the attacker's reach unless they have separately compromised the Azure workspace — a significantly higher bar.

### Timeout and retry policy for the Sentinel audit write

The synchronous Sentinel write for audit records uses a **shorter timeout than normal forwarder batches**: 10 seconds (versus the normal batch timeout). If the Logs Ingestion API does not respond within 10 seconds, the write is treated as a failure (step 3 failure path above). There is **no retry** on the synchronous path — the write either succeeds within 10 seconds or the rule change is rejected. Retrying with unbounded backoff would leave the control-plane request hanging, which is a DoS vector.

Failed audit writes are recorded in `SIEMHunterHealth_CL` and can be retried by the operator by re-submitting the original rule-change request after the Sentinel connectivity issue is resolved.

---

## 5. SSRF Protection

The control plane makes outbound HTTP requests in two contexts: the Sentinel audit write (§4) and Vector config validation (`POST /sources`). Additionally, `PUT /v1/forwarder/config` accepts a DCE URI that the forwarder will later use for outbound requests. All URL inputs must be validated to prevent Server-Side Request Forgery.

### Blocked address ranges

Outbound HTTP requests initiated by the API service are blocked to:

| Range | Description |
|-------|-------------|
| `127.0.0.0/8` | Loopback (all localhost addresses) |
| `169.254.0.0/16` | Link-local, including Azure IMDS (`169.254.169.254`) |
| `10.0.0.0/8` | RFC 1918 private (except allowlisted exceptions) |
| `172.16.0.0/12` | RFC 1918 private (except allowlisted exceptions) |
| `192.168.0.0/16` | RFC 1918 private (except allowlisted exceptions) |
| `::1` | IPv6 loopback |
| `fc00::/7` | IPv6 unique local |

### Allowlisted exceptions

The following destinations are explicitly permitted because they are required for the system to function:

| Destination | Justification |
|-------------|---------------|
| ClickHouse internal IP (Docker network) | Required for all API operations that read/write ClickHouse |
| Sentinel DCE endpoint (`https://*.ingest.monitor.azure.com`) | Required for audit writes and forwarder batches |

All other private-range destinations are blocked. The allowlist is configuration-driven (not hardcoded), but the operator must explicitly add entries; there is no "allow all private" option.

### Validation implementation

URL validation is applied to:

- `connection_params` fields in `POST /v1/sources` (any field containing a URL or hostname)
- `dce_uri` in `PUT /v1/forwarder/config`

Validation steps:

1. Parse the URL. Reject non-`https` schemes (for Sentinel endpoints) or any scheme other than what the source type expects (e.g., `syslog-tls` sources expect a hostname, not a URL).
2. Resolve the hostname to an IP address using the system resolver.
3. Check the resolved IP against the blocked ranges table above.
4. Verify the resolved IP matches one of the allowlisted destinations.
5. If any check fails: return `422` with a specific error indicating the URL failed SSRF validation. Do not include the resolved IP address in the error response (it may be informational to an attacker).

**DNS rebinding note.** IP validation is performed at request time, not at the time the resolved URL is actually used. DNS rebinding (where the hostname resolves to a safe IP during validation but is changed to a blocked IP before use) is a known limitation. Mitigations: use Docker's internal DNS which does not accept external TTL overrides; pin the Sentinel DCE endpoint as an allowlisted FQDN rather than resolving it dynamically.

---

## 6. Error Handling and Logging

### API error logging

Every non-2xx response is logged to `SIEMHunterHealth_CL` with:

| Field | Value |
|-------|-------|
| `EventType` | `APIError` |
| `Message` | `"{method} {path} → {status_code}: {error_message}"` |
| `Severity` | `Warning` for 4xx; `Error` for 5xx |
| `Count` | `1` |

Authentication failures use `SIEMHunterSecurity_CL` instead (see §2).

### Secret scrubbing

Before any value is written to a log field, it must pass through a secret scrubber. The scrubber:

- Rejects any string that matches the pattern of the Docker secret token (length, entropy heuristic, or prefix if a prefix convention is adopted)
- Replaces any field whose key name is in the deny-list (`token`, `key`, `secret`, `password`, `cert`, `credential`, `authorization`) with `"[REDACTED]"`
- Never logs request headers verbatim (the `Authorization` header contains the bearer token)

The scrubber must run on both the `Message` field and the `Detail` field of any log entry. A log entry that bypasses scrubbing and contains a token value has effectively exposed the token to anyone with access to the `SIEMHunterHealth_CL` or `SIEMHunterSecurity_CL` tables.

### Structured errors

All error responses use a consistent JSON body:

```json
{
  "error": "human-readable message",
  "code": "MACHINE_READABLE_CODE",
  "detail": { }
}
```

Internal exception messages (stack traces, ClickHouse error strings) are included in `detail` only in non-production deployments. In production, `detail` is omitted for 5xx errors to avoid leaking internal implementation details.

---

## 7. Rate Limiting

Rate limiting is enforced per source IP, tracked in memory (or a Redis sidecar if the operator requires cross-restart persistence — not required in v0.1.0).

| Endpoint group | Limit | Window |
|---------------|-------|--------|
| All endpoints (default) | 100 requests | 60 seconds |
| Rule mutation endpoints (`POST`, `PUT`, `DELETE` on `/v1/rules/*`) | 10 requests | 60 seconds |

Rule mutation endpoints carry a stricter limit because they are high-value targets: an attacker who can call them at volume can rapidly disable a large ruleset before the fail-closed audit mechanism triggers an alert. The stricter limit buys time for the Sentinel alert to reach an operator.

On limit breach: return `429 Too Many Requests` with a `Retry-After` header indicating when the window resets. Log the breach to `SIEMHunterHealth_CL` with `EventType = "RateLimitExceeded"` and the source IP.

Rate limit thresholds are configurable in the operator config file; the values above are defaults. Setting any threshold to `0` disables rate limiting for that group (not recommended; document this as an explicit operator choice).

---

## 8. FastAPI Design Notes

### Pydantic models

Every request body and response body is defined as a Pydantic v2 model with `model_config = ConfigDict(extra="forbid")`. Extra fields in request bodies are rejected with `422`. This prevents field-smuggling attacks where an attacker sends extra JSON fields hoping one is processed by a downstream component.

Response models are defined separately from request models. Never reuse an input model as a response model — response models control exactly what is returned and can omit internal fields (compiled SQL, ClickHouse row IDs, etc.).

### Idempotency

Mutation endpoints are idempotent where the operation is naturally so:

- `PUT /v1/rules/{rule_id}/status` with the same `new_status` as the current status is a no-op: the audit write is skipped and `200` is returned with the current state unchanged. (There is nothing to audit if nothing changed.)
- `DELETE /v1/sources/{source_id}` on a source already in `deregistered` status returns `200` with the current state (not `404`).
- `PUT /v1/forwarder/config` with values identical to the current config is a no-op returning `200`.

`POST /v1/rules` is not idempotent: submitting the same Sigma YAML twice creates two rule records (different UUIDs). The caller is responsible for deduplication.

### API versioning

All paths are under `/v1/`. A future breaking change would introduce `/v2/` routes. `/v1/` routes are not removed when `/v2/` is introduced; they are deprecated and then removed on a published schedule. There are no unversioned routes (no `/health` without the version prefix).

### OpenAPI documentation

In production deployments:

```python
app = FastAPI(
    title="SIEMhunter Control Plane",
    version="0.1.0",
    docs_url=None,      # Swagger UI disabled
    redoc_url=None,     # Redoc disabled
    openapi_url=None,   # OpenAPI schema endpoint disabled
)
```

All three must be explicitly set to `None`. Leaving them at defaults makes the schema discoverable to any process on the host that can reach the API port, which provides an attacker with a complete map of the available endpoints and their input schemas.

In development deployments the OpenAPI schema may be enabled at the developer's discretion on a non-default path.

### Startup validation

On startup, the FastAPI application must verify:

1. `/run/secrets/api_token` exists and is non-empty. If not: log to stderr and exit with a non-zero code. Do not start with no authentication.
2. ClickHouse is reachable (simple `SELECT 1` health check). If not: log a `Warning` to stderr and continue (the API can still serve health checks and config reads; ClickHouse-dependent endpoints return `503` until connectivity is restored).
3. The Sentinel DCE endpoint is reachable (HEAD request or equivalent). If not: log a `Warning`. This is non-fatal at startup; the forwarder will retry on its batch schedule.

---

## 9. References

| Document | Relationship |
|----------|-------------|
| `03-data-ingestion-spec.md` | Source onboarding sequence (§3 of that document) is the upstream spec for `POST /sources` and the Vector config update behavior |
| `04-normalization-and-schema.md` | ClickHouse schema queried by `POST /v1/query`; field canonical table that bounds what columns are valid in query results; `SIEMHunterSecurity_CL` and `SIEMHunterHealth_CL` column layouts used by all logging in this document |
| `07-sentinel-forwarding.md` | Logs Ingestion API details used by the fail-closed audit write in §4; DCE/DCR configuration |
| `09-security-and-iam.md` | Auth design and RBAC (when RBAC is added in a future version); Docker secrets model |
| `14-threat-model.md` | Adversary model for the control plane ("insider / compromised analyst" class) that motivates the fail-closed design and SSRF protection |
| `16-hardening-checklist.md` | API hardening checklist items that reference the controls defined in this document (bearer token auth, OpenAPI disabled, rate limiting, SSRF protection, secret scrubbing) |
