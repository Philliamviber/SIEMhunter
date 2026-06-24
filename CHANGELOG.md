# Changelog

All notable changes to SIEMhunter are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [3.0.0] - 2026-06-23

### Added

#### Authentication & identity (FR #10)
- Per-analyst login with argon2id-hashed credentials (`/v1/auth/login` and `/v1/auth/logout`) replacing the single shared static Bearer token.
- Dual-auth split: service-to-service calls continue with the static bearer token; analyst-facing UI requires session cookie.
- `LoginGate` React component: unauthenticated users are redirected to the login page; 401 responses trigger automatic redirect.
- First-run admin seed documented in `DEPLOYMENT.md`.

#### Incident notes (FR #19)
- Server-side, append-only incident notes replacing `localStorage` notes; author identity and timestamp set server-side from the authenticated analyst session (never client-supplied).
- New endpoints: `POST /v1/incidents/{id}/notes`, `GET /v1/incidents/{id}/notes`.
- Note content is stored and rendered as plain text (no HTML sink / no XSS).

#### Export and IOC copy (FR #16, FR #25)
- Shared CSV/JSON export utility consumed by Events, Detections, and GlobalSearch result sets.
- CSV-injection neutralisation: leading `=`, `+`, `-`, `@` characters are prefixed with a tab.
- Truncation note propagated into exported files when the server truncated the result set.
- `EventDetailPanel` export and one-click IOC copy actions (FR #25).

#### Incident status confirmation and feedback (FR #18)
- Confirmation dialog before destructive incident status changes (Close / Archive).
- Success and error feedback surfaced via the global `ToastProvider` on every status PATCH.

#### Incidents list filter/sort/search (FR #17)
- Filter by status and severity, sort by created/updated date, and keyword search on the Incidents list.
- Active filters persisted in the URL query string for shareable / reloadable views.

#### Upload progress, cancel, multi-file (FR #12)
- `UploadZone` supports multi-file selection with per-file XHR progress indicators.
- In-flight uploads cancellable via `AbortController`.
- Post-upload query invalidation triggers automatic refresh of Events and Ingestion views.

#### Correlation graph controls (FR #13, FR #14)
- Node/edge tooltips on the force-directed correlation graph.
- In-graph search to highlight matching entities.
- Zoom in, zoom out, and reset controls.
- Fixed entity↔event panel stacking and back-navigation (FR #14).

#### Category drill-down truncation and UX (FR #21)
- Truncation banner ("Showing 500 of N") when a category query hits the 500-row cap.
- Load-more / refine CTA in the truncation banner to fetch the next page.
- Distinct empty-state and error-state renders on all Category pages.

#### IncidentSelector accessibility (FR #20)
- `IncidentSelector` upgraded to an ARIA combobox with correct `role`, `aria-expanded`, `aria-activedescendant`, and `aria-controls` attributes.
- Full keyboard navigation: Arrow Up/Down to move between options, Enter to select, Escape to close.
- Focus managed on open/close; selection announced via active-descendant pattern.

#### Responsive layout and collapsible sidebar (FR #22)
- All dashboard pages remain usable at ≥768 px viewport width with no horizontal overflow.
- Sidebar is collapsible; collapsed/expanded state persisted in `localStorage` across navigation.

#### Global AI chatbar — single instance (FR #9)
- `ClaudeChatbar` hoisted into `PageLayout`, rendered once for the whole SPA instead of per-page.
- Panel state (`sessionStorage`) and floating position preserved across in-SPA navigation.

#### Observability and CI
- Global toast notification system (`ToastProvider`) with imperative bridge for the 401 interceptor.
- GitHub Actions CI/CD pipeline: frontend lint/typecheck/Vitest, API pytest, dependency-hash sentinel check.

### Changed
- Version bumped from `3.0.0-dev` to `3.0.0` across all surfaces: `frontend/package.json`, FastAPI `version=`, and the `siemhunter/frontend` Docker image tag.
- Pivot links, global search scope, and timestamp timezone display fixed (issues #11, #15, #24).
- `docs/RELEASING.md` added: single source of truth, tagging procedure, and historical tag table.

### Security
- Analyst credentials stored as argon2id hashes; no plaintext credential storage.
- Session token in `sessionStorage` only; cleared on tab close.
- Incident notes: author and timestamp are server-set; note content is plain text only (no HTML render path).
- CSV export neutralises injection-prone leading characters before writing to file.
- All PyPI dependency lines carry real `--hash=sha256:` pins; CI fails on the `placeholder_regenerate_before_deploy` sentinel (GATE F).

---

## [2.0.0] - 2026-06-20

### Added

#### Dashboard (React + nginx frontend)
- 11-page React dashboard: Overview, Events, Detections, Rules, Ingestion, Health, Query, Categories, Incidents, Incident Detail, Correlation
- nginx frontend container proxying `/v1/*` to the API service; binds `127.0.0.1:8081` only
- `ClaudeChatbar`: floating AI Analysis panel accessible from any page (bottom-right, survives page navigation within the SPA tab via sessionStorage)
- `EventDetailPanel`: slide-in panel showing all canonical fields plus raw `UnmappedFields` JSON and pivot links for one-click host/user/IP pivots
- `GlobalSearchBar`: app-wide field-type search accessible from the navigation bar
- `UploadZone`: drag-and-drop file upload widget with incident scoping

#### Incident management
- Create, track, and update incidents: `POST /v1/incidents`, `GET /v1/incidents`, `GET /v1/incidents/{id}`, `PATCH /v1/incidents/{id}/status`
- Incidents stored in a SQLite database (separate from ClickHouse — analyst workspace state vs. event telemetry)
- Incident note-taking persisted in browser `localStorage` (not sent to the API)
- File uploads and global search can be scoped to an active incident via `IncidentProvider` context

#### Forensic file upload
- `POST /v1/ingestion/upload`: drag-and-drop or programmatic upload; accepts `.json`, `.jsonl`, `.csv`, `.log`, `.txt`; maximum 100 MiB per file
- Upload mode: `global` (unscoped) or `incident` (scoped to an incident ID)
- Response reports `events_parsed`, `events_written`, `events_unmapped`, `error_count`, and `status` (`success` / `partial` / `failed`)

#### AI narrative summary
- `GET /v1/ai/summary`: sends aggregated statistics only to the Claude API (event counts, detection counts, top rule IDs) — no raw event fields (CommandLine, hostnames, IPs, usernames) are transmitted
- Response cached per detection batch cycle to avoid redundant Claude API calls
- API service added to the egress Docker network for outbound Claude API access (explicit in `docker-compose.yml`)
- `anthropic_api_key` added as a Docker secret

#### Entity correlation graph
- ECharts force-directed graph on the Correlation page linking Host, User, IP Address, and Process entities derived from `security_events` rows
- 200-node cap enforced in the frontend (browser canvas performance guard); truncation warning shown when exceeded
- Four time-range presets: Last 1h, Last 6h, Last 24h, Last 7d; graphs load on demand (not auto-polled)
- Click a node to open an entity side panel showing all related events; click an event row to open `EventDetailPanel`

#### Category dashboard
- Security domain drill-down page covering: Active Directory, Network, DNS, Malware Analysis, Log Analysis

#### Global search
- `POST /v1/search`: field-type-based search across `siemhunter.security_events`
- Supported field types: `IP`, `Hostname`, `Username`, `Port`, `EventID`, `FileHash`, `ProcessName`
- Response includes `columns_searched` (which ClickHouse columns were queried for the field type) and `truncated` flag
- Search is user-initiated (not auto-polled); implemented as a TanStack Query `useMutation` to prevent background refresh overwriting analyst results

#### New API endpoints
- `GET /v1/metrics`: aggregated event counts by source, detection hit counts (24h), anomaly score histogram, last batch timestamp
- `GET /v1/ingestion/summary`: provenance breakdown, hourly volume, pipeline latency p95, per-source cards
- `GET /v1/events`: paginated, filterable `security_events` with a 30-day default window; filters: `hostname`, `event_id`, `subject_user_name`, `src_ip_addr`, `provenance_tag`, `start`, `end`, `limit`, `offset`
- `GET /v1/detections`: paginated, filterable `detection_hits` with severity timeline; filters: `severity`, `rule_id`, `forwarded` (`yes`/`no`), `start`, `end`
- `GET /v1/health/{service}`: per-service health detail including `alive_file_age_seconds`

#### Tests
- Vitest test suite covering all 11 pages and key components
- pytest integration tests covering all API endpoints

### Changed
- API application metadata updated to reflect v2.0.0 feature additions (note: the FastAPI `version=` field was not independently bumped in code at this boundary; version coherence is enforced from v3.0.0-dev onward)
- `docker-compose.yml`: added `frontend` service (React + nginx), added `anthropic_api_key` secret, added `api` service to the egress network for Claude API outbound calls
- Rule status change endpoint (`PUT /v1/rules/{rule_id}/status`) now requires an explicit `reason` field to be included in Sentinel audit records; the field remains optional in the request body but is recorded as empty string if omitted

### Security
- Frontend service binds `127.0.0.1:8081` only — not accessible on `0.0.0.0`
- Bearer token stored in `sessionStorage` only; cleared automatically on tab close (not persisted across sessions)
- AI summary endpoint (`GET /v1/ai/summary`) never transmits raw event data to the Claude API; only aggregated numeric statistics are included in the prompt
- API service egress network access is explicit and limited to what is required for Claude API calls

---

## [1.0.0] - 2026-04-15

### Added

#### Data collection (Vector)
- Vector log collector accepting: syslog UDP/TCP/TLS (port 514), Windows Event Forwarding over HTTP (WEF, port 5985), Netflow/IPFIX (port 2055), and forensic artifact file drop (`/var/siemhunter/drop/`)
- ProvenanceTag assigned at ingest time by Vector transforms; never overrideable by event payload content (tamper-evidence mechanism)

#### Storage (ClickHouse)
- ClickHouse columnar store with six tables: `security_events`, `detection_hits`, `rule_registry`, `forward_ledger`, `detection_state`, `raw_events`
- `security_events` schema: OCSF/ASIM field set with `UnmappedFields` (JSON string) for fields not in the canonical schema

#### Normalization service
- OCSF/ASIM field mapping for all four source types: Windows Event Log, syslog, Netflow/IPFIX, forensic artifact
- ProvenanceTag-based routing: `syslog:*` → syslog normalizer, `wef:*` → Windows normalizer, `netflow:*`/`ipfix:*` → Netflow normalizer, `forensic:*` → forensic normalizer; unknown prefixes fall back to Windows normalizer with a warning
- Deterministic `EventRecordID` computation (SHA-256 of provenance tag + sorted event content) for at-least-once deduplication
- Rate limiter: 10,000 events per minute per ProvenanceTag prefix (second-line defence behind Vector's `rate_throttle` transform)
- Sysmon `Hashes` field parsing: splits `MD5=...,SHA256=...` into separate `FileMD5`/`FileSHA256` FixedString columns (required for case-sensitive ClickHouse comparisons)

#### Detection service
- pySigma → ClickHouse SQL compilation via the custom `clickhouse-asim-ocsf.yaml` pipeline
- Isolation Forest ML advisory anomaly scoring (`anomaly_score` in [0, 1]); score is advisory only — does not gate alert creation
- Rule hot-reload: the detection service polls for rule file changes without a service restart
- Sigma rule hot-reload via `rule_registry` table status column; rules in `production` status are active

#### Forwarder service
- Microsoft Sentinel Logs Ingestion API (DCE + DCR) for normalized events (`SIEMHunterSecurity_CL`) and health events (`SIEMHunterHealth_CL`)
- Microsoft Sentinel Incidents API (ARM management plane) for the five self-detection rules only; general detection hits go via `SIEMHunterSecurity_CL` to avoid double-alerting
- Certificate credential authentication (`CertificateCredential` from `azure-identity`); no client secrets used anywhere
- Exponential backoff with jitter on transient API errors; on-disk retry queue for persistent failures
- SELF-005 ledger reconciliation: `forward_ledger` tracks which detection hits have been forwarded; the forwarder reconciles on startup and after failures
- SSRF protection: RFC 1918 ranges, loopback, and the Azure IMDS endpoint (`169.254.169.254`) are blocked before outbound connections; DCE URI validated against a strict allowlist regex

#### FastAPI control plane
- `GET /v1/status`: pipeline liveness check
- `GET /v1/rules`: rule registry listing
- `PUT /v1/rules/{rule_id}/status`: fail-closed rule lifecycle transitions (Sentinel audit written before ClickHouse update; 503 if Sentinel unreachable)
- `POST /v1/query`: SELECT-only ClickHouse query proxy; mutation keywords rejected server-side with 400
- Bearer token authentication via Docker secret (`api_auth_token.txt`); constant-time comparison (`hmac.compare_digest`) prevents timing attacks; auth failures forwarded to Sentinel as `AuthFailure` events (SELF-003)
- API refuses to start if the token secret is missing or empty (fail-closed)

#### Sigma detection rules
- 5 self-detection rules: SELF-001 (ingest anomaly), SELF-002 (detection gap), SELF-003 (auth failure), SELF-004 (forwarder failure), SELF-005 (ledger desync)
- 6 Windows/AD TTP rules:
  - Kerberoasting — T1558.003 (EID 4769, non-machine service tickets)
  - AS-REP Roasting — T1558.004 (EID 4768, no pre-auth)
  - DCSync — T1003.006 (EID 4662, DS-Replication-Get-Changes on domain root)
  - LSASS access — T1003.001 (EID 10 Sysmon, `lsass.exe` `GrantedAccess` 0x1010/0x1410)
  - SMB lateral movement — T1021.002 (EID 5145)
  - RDP lateral movement — T1021.001 (EID 4624 LogonType 10)
- pySigma pipeline (`rules/pipelines/clickhouse-asim-ocsf.yaml`): field mapping from standard Sigma field names to ClickHouse column names

#### Infrastructure
- Docker Compose stack: Vector, ClickHouse, normalization, detection, forwarder, FastAPI
- Security hardening applied to all containers: `cap_drop: ALL`, non-root UIDs, read-only root filesystem, explicit `tmpfs` mounts for writable paths
- Network segmentation: `ingest` network (Vector → ClickHouse), `internal` network (all services), `egress` network (forwarder → internet)
- Docker secrets for all credentials: `clickhouse_password`, `api_auth_token`, `forwarder_cert_push`, `forwarder_cert_pull`

#### Documentation
- `ARCHITECTURE.md`, `API.md`, `DEPLOYMENT.md`, `DEVELOPMENT.md`, `TROUBLESHOOTING.md`, `DASHBOARD.md`, `rules/RULES_README.md`
