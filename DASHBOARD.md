# SIEMhunter Dashboard — User Guide

The SIEMhunter dashboard is a React/nginx web application served at `http://localhost:8081`. It provides read-only visibility into the local security pipeline: raw events collected in ClickHouse, detection hits produced by the rule engine, rule lifecycle management, ingestion health, and an ad-hoc query console. All data displayed comes from the local API at `http://localhost:8080` unless otherwise noted. The dashboard is localhost-only and is not reachable from the LAN.

---

## Prerequisites and first login

**What you need before opening the dashboard:**

- `docker compose up -d` must be running (see `README.md` for the full startup sequence).
- The API bearer token from `secrets/api_auth_token.txt`.

**Token gate**

Every time you open the dashboard in a new tab (or after closing and reopening the tab), you will see the authentication screen. Paste the contents of `secrets/api_auth_token.txt` into the token field and click "Access Console."

```sh
# Read your token
cat secrets/api_auth_token.txt
```

The token is stored in `sessionStorage` for the lifetime of the browser tab. It is automatically cleared when the tab is closed. It is never sent to any external service. If you refresh the page or open the same URL in a new tab, you will be prompted to paste the token again.

**Data refresh cadence**

All pages auto-refresh their data every 30 seconds. You can also force a page reload with F5 or Ctrl+R, which will re-present the token gate — have your token ready.

---

## Page reference

### Overview (`/`)

The landing page. It gives a snapshot of the last 24 hours across all pipeline stages.

- **KPI cards** (top row): Events (24h), Detection Hits (24h), Active Rules, Last Batch, and Sentinel Forward status. "Active Rules" always shows "— / See Rules page" because the Overview page does not independently query the rule count; navigate to `/rules` for the exact count by status.
- **Last Batch Duration** always shows "Not available locally (Sentinel-side)." The `last_batch_duration_seconds` field is written to Sentinel, not to the local ClickHouse instance. This is expected behavior, not an error.
- **System health banner** appears below the KPI row. It reflects the live output of `GET /v1/status`. A red banner means the forwarder is impaired or ClickHouse is unreachable.
- **AI Security Summary card** is visible only if an Anthropic API key is configured. When the key is absent or the API is unreachable, the card shows "AI summary unavailable — Anthropic API key not configured or service unreachable." See the [AI Summary section](#ai-summary-optional-feature) below.
- **Anomaly Score Distribution chart** shows the distribution of `anomaly_score` values across detection hits for the last 24 hours, bucketed by score range. This data comes from `siemhunter.detection_hits`, not `security_events`. If no hits fired in the last 24 hours, the chart area shows "No anomaly data."
- **Recent High Severity Hits table** lists the 10 most recent detection hits where severity is `high` or above. Columns: Rule, Severity, MITRE tag, hit count, and time. Click "View all →" to go to the Detections page.

---

### Events (`/events`)

A paginated view of raw security events stored in `siemhunter.security_events`. The default window covers the last 30 days. Pages are 50 rows each.

- **Filter bar** (top): Start/End datetime range, Hostname, Event ID (integer), Username (`SubjectUserName`), Source IP (`SrcIpAddr`), and Provenance Tag. All filters are optional and combinable. Fill in fields and click "Apply." Click "Clear" to reset all filters.
- **Provenance Tag** identifies the collection source (example: `wef:security` for Windows Event Forwarding, Security channel). Use this filter to isolate a specific collector or log source.
- **Table columns**: Time, Host, EID (EventID), User, Src IP, Source (ProvenanceTag). Rows are sortable by display order only; no column-sort controls exist.
- **Row detail panel**: Click any row to open a slide-in panel on the right showing all normalized fields: TimeGenerated, HostName, EventID, SubjectUserName, SubjectUserSid, TargetUserName, LogonType, ServiceName, ProcessImagePath, CommandLine, ParentCommandLine, GrantedAccess, file hashes, registry keys, network fields (SrcIpAddr, SrcPort, DstIpAddr, DstPort, NetworkProtocol), ProvenanceTag, IngestTimestamp, and UnmappedFields (raw JSON for any fields the normalization service did not map). Empty fields are hidden.
- **AnomalyScore is not shown on event rows.** The anomaly score is a property of a detection hit, not of an individual event. The detail panel includes a note to this effect. To find events associated with a high anomaly score, use the Query console to join `detection_hits` and `security_events` on shared fields such as EventID, HostName, and TimeGenerated.
- **Pagination**: Previous and Next buttons appear below the table. The total event count for the active filter is shown.

---

### Detections (`/detections`)

Detection hits produced by the rule engine, stored in `siemhunter.detection_hits`.

- **Hit Timeline chart** (top): A stacked area chart showing hit volume per hour, broken down by severity (LOW, MEDIUM, HIGH, CRITICAL). Hover a point to see counts per severity for that hour.
- **Facet sidebar** (left): Filter by Severity (dropdown: All / Critical / High / Medium / Low), Rule ID (dropdown populated from hits currently in view), and Forwarded status (All / Forwarded / Pending). Changing any facet immediately re-queries the API and resets to page 1.
- **Hit table columns**: Rule, Severity, MITRE tag, Hits (hit_count), Anomaly score (color-coded: red above 0.7, yellow above 0.4, gray below 0.4), Forwarded (Yes / Pending), Time.
- **Rule detail panel**: Click any row to expand an inline panel showing the rule ID, total hit count for that rule in the current view, MITRE tag, and the time of the most recent hit. Click the same row again to collapse.
- **Forwarded column**: "Yes" means `forwarded_at` is populated — the hit was confirmed sent to Microsoft Sentinel. "Pending" means `forwarded_at IS NULL`. Use the "Unforwarded detection hits" query template in the Query console to list all pending hits.
- **Pagination**: 50 hits per page.

---

### Rules (`/rules`)

The rule registry and lifecycle management board.

- **Kanban board**: Rules are organized into five columns by status: `draft`, `test`, `review`, `production`, `disabled`. Each column shows a count badge. The status lifecycle flows left to right: draft → test → review → production. Rules can also be moved to disabled from any status.
- **Rule cards**: Each card shows the rule ID (monospace), the filename from the rule's `file_path`, and the last-updated timestamp.
- **Rule detail panel**: Click a card to open the detail panel below the board. The panel shows the rule ID, version, last-updated timestamp, and the Sigma YAML viewer.
- **Sigma YAML viewer**: Shows registry metadata (rule ID, version, status, file path, updated timestamp) and a note that the full Sigma YAML is loaded from the container filesystem by the detection service, not stored in ClickHouse. The dashboard does not display the full YAML content.
- **Status change (fail-closed)**: With a rule selected, click any status button in the detail panel ("Move to: draft / test / review / production / disabled") to initiate a status change. A confirmation modal appears explaining the fail-closed behavior: the API writes an audit record to Sentinel's `SIEMHunterSecurity_CL` table (`EventType: RuleChangeAudit`) **before** updating ClickHouse. If Sentinel is unreachable at the moment you confirm, the API returns HTTP 503 and the status change is **not applied**. An optional reason field is available for audit notes.
- **Reason field**: Optional free text recorded in the Sentinel audit event. Useful for change-management traceability (example: "Verified against 2 weeks of live data, FP rate acceptable").
- **If the status change button returns an error**: Verify Sentinel connectivity with `docker compose logs --since 5m forwarder`. A 503 means Sentinel was unreachable at the time of the request.

---

### Ingestion (`/ingestion`)

Visibility into event collection: what is flowing in, from where, and at what rate.

- **Source Breakdown donut chart**: Event count per `ProvenanceTag` for the last 24 hours. Hover a segment to see the exact count. An empty chart means no events were ingested in the last 24 hours.
- **Pipeline Latency**: Shows average and p95 ingest-to-normalize latency (in seconds) for the last 24 hours, derived from `IngestTimestamp` vs. `TimeGenerated` in `siemhunter.security_events`.
- **Rate-Limit / Flood Panel**: Always shows "Not available locally (Sentinel-side)." Flood detection and rate-limit counters (corresponding to self-detection rules SELF-002 and SELF-004) are evaluated Sentinel-side. This panel is intentionally blank in the local dashboard.
- **Event Volume Over Time chart**: A stacked area chart showing events per hour per source for the last 24 hours. Each `ProvenanceTag` is a separate area series. Gaps in a source's line indicate no events were received during that hour.
- **Per-Source Stats cards**: One card per active `ProvenanceTag`. Each card shows: Last Seen (most recent event timestamp), Events/hr (rolling average), and Unmapped % (the percentage of events where `UnmappedFields` is non-empty). Unmapped % above 20% is highlighted in yellow — this indicates the normalization service is receiving fields it has no mapping rule for, which may mean a schema change on the source.

---

### Health (`/health`)

Pipeline operational status. Data comes from three API endpoints: `GET /v1/status`, `GET /v1/health/{service}`, and a combination of `GET /v1/rules` plus `GET /v1/detections?rule_id=SELF-00x` for the self-detection board.

**Service Status grid**

Five service tiles: `vector`, `clickhouse`, `normalization`, `detection`, `forwarder`. Each tile shows a colored status dot (green = ok, red = error/degraded, gray = unknown), the status string returned by `GET /v1/health/{service}`, and optional detail text.

- **vector tile**: The vector service (log collector) does not write a local alive-file. Its status will show as `unknown` unless the service actively reports a status via the health endpoint. A gray "unknown" dot for vector is expected when vector is running but has not reported status. Check vector logs directly: `docker compose logs --since 5m vector`.
- All other services report `ok`, `degraded`, or `error` based on alive-file age or active health checks.

**Pipeline Summary panel**

A condensed view of `GET /v1/status` showing ClickHouse, Normalization, Detection, Forwarder, and the pending retry queue depth. If the retry queue is non-zero, hits are waiting to be forwarded to Sentinel.

**Self-Detection Rules board (SELF-001 through SELF-005)**

Shows the lifecycle status and recent firing activity of the five built-in self-monitoring rules:

| Rule | Purpose |
|------|---------|
| SELF-001 | ClickHouse write latency exceeded threshold |
| SELF-002 | Sentinel rate-limit or flood (Sentinel-side — local hits may not reflect full scope) |
| SELF-003 | Normalization parse error rate exceeded threshold |
| SELF-004 | Ingest flood (Sentinel-side) |
| SELF-005 | Forwarder ledger delta (local vs Sentinel counts diverged) |

Each row shows: rule status (from `/v1/rules`), recent hit count, and the last time the rule fired (severity badge + timestamp). SELF-002 and SELF-004 may show zero local hits even when the flood condition is active, because their primary detection logic runs Sentinel-side.

**Forward Ledger panel**

Shows the pending retry queue depth (number of detection hits with `forwarded_at IS NULL` that the forwarder is retrying). The "Sentinel-side count" field always shows "Not available locally." The ledger delta (SELF-005) is computed in Sentinel Log Analytics:

```kql
SIEMHunterHealth_CL | where EventType == "LedgerDelta"
```

**Auth and Audit Feed panel**

Notes that `SIEMHunterSecurity_CL` is Sentinel-side only. Auth failures and rule change audit records are forwarded asynchronously and cannot be read from the local API. Query them in Log Analytics:

```kql
SIEMHunterSecurity_CL | where EventType == "AuthFailure"
SIEMHunterSecurity_CL | where EventType == "RuleChangeAudit"
```

---

### Query (`/query`)

An ad-hoc SQL console that runs SELECT queries directly against ClickHouse through the API (`POST /v1/query`).

- **SELECT-only enforcement**: The API rejects any query containing mutation keywords (INSERT, UPDATE, DELETE, DROP, ALTER, TRUNCATE, CREATE, REPLACE, and similar). Submitting a non-SELECT statement returns a 400 error. This is enforced server-side, not just client-side.
- **Row cap and timeout**: Results are capped at 10,000 rows. Queries that exceed 30 seconds are cancelled by the API.
- **Running a query**: Type or paste SQL into the editor, then click "Run Query" or press Ctrl+Enter (Windows/Linux) / Cmd+Enter (Mac).
- **Templates**: Six built-in templates are available as buttons above the editor. Clicking a template loads its SQL into the editor without running it, so you can review or modify it before executing.
- **Result display**: Results appear below the editor in a scrollable table. The row count is shown in the result header.
- **Clear button**: Clears the editor and dismisses any current result or error without navigating away.
- **Error display**: API errors appear in a red panel below the editor, showing the error code and message (example: `[QUERY_FORBIDDEN] Mutation statements are not allowed`).

---

## Query templates

All six built-in templates are listed below with their exact SQL. Load any template from the Query page by clicking its button, modify as needed, then run.

### 1. Recent events — last hour

```sql
SELECT TimeGenerated, HostName, EventID, SubjectUserName, SrcIpAddr, ProvenanceTag
FROM siemhunter.security_events
WHERE TimeGenerated >= now() - INTERVAL 1 HOUR
ORDER BY TimeGenerated DESC
LIMIT 100
```

Returns the 100 most recent events across all sources. Extend the interval or add a `AND ProvenanceTag = 'wef:security'` clause to narrow scope.

### 2. Top rule hits — last 24h

```sql
SELECT rule_id, severity, count() AS hit_count, max(anomaly_score) AS max_anomaly
FROM siemhunter.detection_hits
WHERE created_at >= now() - INTERVAL 24 HOUR
GROUP BY rule_id, severity
ORDER BY hit_count DESC
LIMIT 50
```

Shows which rules fired most in the last 24 hours and the highest anomaly score seen per rule. Useful for identifying noisy rules or spike events.

### 3. Event count by source

```sql
SELECT ProvenanceTag, count() AS event_count
FROM siemhunter.security_events
WHERE TimeGenerated >= now() - INTERVAL 24 HOUR
GROUP BY ProvenanceTag
ORDER BY event_count DESC
```

Volume breakdown by collector source for the last 24 hours. A source missing from this list has sent no events in the window.

### 4. High anomaly scores

```sql
SELECT rule_id, anomaly_score, hit_count, severity, created_at
FROM siemhunter.detection_hits
WHERE anomaly_score > 0.7
ORDER BY anomaly_score DESC
LIMIT 50
```

Lists detection hits with an anomaly score above 0.7 (the threshold used by the Detections page to highlight scores in red). Adjust the threshold as needed for your environment.

### 5. Kerberoasting candidates (EID 4769)

```sql
SELECT TimeGenerated, HostName, SubjectUserName, ServiceName, TargetUserName
FROM siemhunter.security_events
WHERE EventID = 4769 AND ServiceName NOT LIKE '%$'
ORDER BY TimeGenerated DESC
LIMIT 100
```

Windows Event 4769 is a Kerberos service ticket request. The `ServiceName NOT LIKE '%$'` predicate filters out machine account service names (which end with `$`), leaving requests for user-defined service accounts — a common Kerberoasting indicator. This is a raw event query, not a detection hit query; it runs against `security_events` directly.

### 6. Unforwarded detection hits

```sql
SELECT hit_id, rule_id, severity, hit_count, created_at
FROM siemhunter.detection_hits
WHERE forwarded_at IS NULL
ORDER BY created_at DESC
LIMIT 100
```

Lists detection hits not yet confirmed forwarded to Sentinel. A growing result set here, combined with a non-zero retry queue on the Health page, indicates a forwarder problem. Check `docker compose logs --since 10m forwarder`.

---

## AI Summary (optional feature)

The AI Security Summary card on the Overview page is disabled by default.

### Enabling the feature

Place an Anthropic API key in `secrets/anthropic_api_key.txt`, then restart the api service:

```sh
echo "sk-ant-..." > secrets/anthropic_api_key.txt
docker compose restart api
```

The api service reads the key at startup. If the file is absent or the key is invalid, the card shows "AI summary unavailable — Anthropic API key not configured or service unreachable."

### What the model receives

The AI summary feature sends **aggregated statistics only** to the Anthropic API. The model receives:

- Total event counts and detection hit counts by severity
- Anomaly score distribution buckets (not individual scores)
- Health status deltas (which services changed state since the previous batch)
- Forward ledger summary (pending count, confirmed count)

The model does **not** receive raw events, hostnames, usernames, IP addresses, CommandLine values, or any other event-level identifiers. Only aggregated counts and status flags are included in the prompt.

### What the card shows

When enabled and the API key is valid, the card displays:

- A narrative paragraph (3–5 sentences) describing the current security posture based on the aggregated statistics.
- A "Notable items" bullet list of items that warrant attention (e.g., rules with elevated hit rates, services in degraded state).
- A disclaimer noting that the summary is AI-generated from aggregated data.
- The source window (the time range covered by the statistics) and a "Generated at" timestamp.

The summary is cached per batch cycle. It does not regenerate on every 30-second dashboard refresh — it regenerates when the underlying batch metrics change.

### Model

The feature uses `claude-opus-4-8`.

---

## Keyboard shortcuts and browser tips

The dashboard has no custom keyboard bindings beyond the standard browser and one console shortcut.

| Action | Shortcut |
|--------|----------|
| Run query (Query console) | Ctrl+Enter (Windows/Linux) / Cmd+Enter (Mac) |
| Navigate back | Alt+Left arrow |
| Navigate forward | Alt+Right arrow |
| Reload page (triggers token gate) | F5 or Ctrl+R |
| Focus address bar (type `/events`, `/rules`, etc.) | Ctrl+L |
| Full-screen | F11 |

**Page navigation tip**: The sidebar navigation links are the intended way to move between pages. You can also type the path directly in the address bar (Ctrl+L then type `http://localhost:8081/detections`, for example), but reloading the page this way will re-present the token gate.

**Closing the event detail panel**: Click the X button in the panel header, or click any other row in the table to switch selection.

---

## Troubleshooting

### Token expired or "Failed to load" errors on every page

The token is stored in `sessionStorage` and is not persisted across page reloads. If you reloaded the page, refreshed the tab, or the session was cleared, the token gate will appear. Paste the token from `secrets/api_auth_token.txt` again.

If you see red "Failed to load" banners on pages after re-authenticating, verify the API is reachable:

```sh
TOKEN=$(cat secrets/api_auth_token.txt)
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8080/v1/status
```

A 401 response means the token in the dashboard does not match the current token on disk. Clear the token gate by closing and reopening the tab, then paste the current token.

### "Not available locally (Sentinel-side)" is shown on several fields

This is expected and not an error. The following fields are computed or stored Sentinel-side and cannot be read through the local API:

- Last Batch Duration (Overview KPI)
- Rate-Limit / Flood Panel (Ingestion page)
- Sentinel-side count in the Forward Ledger (Health page)
- SELF-005 ledger delta (Health page)

To view these values, query the corresponding Sentinel tables in Log Analytics Workspace.

### Query console returns a 400 error

The query contains a mutation keyword. Only SELECT statements are permitted. Check for INSERT, UPDATE, DELETE, DROP, ALTER, CREATE, TRUNCATE, or REPLACE in your SQL.

### Query console returns a 408 or timeout error

The query exceeded the 30-second server-side timeout. Add a narrower WHERE clause (smaller time window, specific ProvenanceTag, lower LIMIT) to reduce execution time.

### vector service shows "unknown" status on the Health page

The vector service does not write a local alive-file that the health endpoint can read. A gray "unknown" status for vector is expected when vector is running normally. Confirm vector is running and processing events:

```sh
docker compose ps vector
docker compose logs --since 5m vector
```

If vector is running and events appear in the Events page, the "unknown" status is cosmetic only.

### Rule status change returns 503

Sentinel was unreachable at the moment the status change was submitted. The change was not applied. Check forwarder connectivity:

```sh
docker compose logs --since 5m forwarder | grep -i error
```

Once Sentinel connectivity is restored, retry the status change from the Rules page.

### Detections page shows zero hits but rules are in production

Confirm the detection service is running and that events have been ingested:

```sh
docker compose logs --since 10m detection | grep -i error
# Check that events exist in the last 24h
TOKEN=$(cat secrets/api_auth_token.txt)
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8080/v1/events?limit=1" | python3 -m json.tool
```

If events exist but no detections are firing, check that your rules are in `production` status on the Rules page.

---

## Related documents

- `README.md` — Setup, quick start, and Docker Compose reference
- `API.md` — Full control plane endpoint reference with request/response examples
- `TROUBLESHOOTING.md` — Diagnostics beyond the dashboard (container logs, ClickHouse queries, network checks)
- `rules/RULES_README.md` — Rule schema, Sigma YAML authoring guide, and field name reference
