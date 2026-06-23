> **SUPERSEDED** — This document was a mis-titled frontend planning artifact (originally named
> `changelog2.md` at repo root). It has been relocated to `docs/history/` for reference only.
> Current planning lives in `docs/newreleaseplan/proposalplan.md` and `docs/plan.md`.

# SIEMhunter Frontend Dashboard — Implementation Plan

## Context

SIEMhunter is a localhost-only Docker Compose security collector. It ingests syslog, WEF, Netflow, and forensic artifacts; normalizes to OCSF/ClickHouse; runs batch Sigma detections every 15–60 min; and forwards hits to Microsoft Sentinel. The backend (FastAPI at localhost:8080) is spec'd and partially implemented. No frontend exists. This plan builds a full-featured dark security dashboard as a new Docker Compose service, with an AI summary section powered by Claude API and all ingestion/detection data surfaced in one place.

**User decisions:**
- AI backend: Claude API (aggregated stats only, never raw events; API key stored as Docker secret)
- Auth model: Token in browser sessionStorage (user pastes token on first load)

---

## Tech Stack

| Layer | Choice | Reason |
|-------|--------|--------|
| Framework | React + TypeScript + Vite | Fast build, small output, TS safety for API shapes |
| Charts | Apache ECharts (via echarts-for-react) | Rich stacked area, donut, heatmap for security data |
| Styling | Tailwind CSS + shadcn/ui dark theme | Pre-built security console aesthetic, severity color tokens |
| Data fetching | TanStack Query | Auto-retry, poll intervals, cache |
| Container | nginx (multi-stage Vite build → static) | Tiny runtime, proxies `/api/*` to FastAPI |
| Auth | sessionStorage bearer token | User pastes token; injected on every API call |

---

## Dashboard Pages

### 1. Overview (default landing)
- KPI cards: Events (24h), Detection Hits (24h), Active Rules, Last Batch Time, Sentinel Forward Status
- **AI Summary card** — narrative from `/v1/ai/summary` (Claude API, aggregated stats only)
- Severity breakdown bar (low / medium / high / critical)
- Recent high/critical hits table (last 10)
- System health status banner (green/amber/red per service)

### 2. Events
- Filterable, paginated table over `security_events` (30d)
- Filters: time range, HostName, EventID, SubjectUserName, SrcIpAddr, ProvenanceTag
- Row drill-in: all fields including CommandLine, UnmappedFields JSON, AnomalyScore badge

### 3. Detections
- `detection_hits` (90d) timeline (stacked area by severity)
- Facet sidebar: severity, rule_id, forwarded vs unforwarded
- Rule detail panel: hit count trend, MITRE tag, last fired

### 4. Rules Management
- `rule_registry` kanban/board by status lifecycle (draft → test → review → production → disabled)
- Per-rule: Sigma YAML viewer, severity badge, MITRE tag, last_modified
- Status-change action with **fail-closed audit warning** modal (writes to Sentinel before ClickHouse)

### 5. Ingestion Context
- Source breakdown donut by `ProvenanceTag`
- Stacked area: event volume over time per source (with batch boundaries)
- Pipeline latency sparkline: `IngestTimestamp − TimeGenerated` gap
- Rate-limit / flood panel from `SIEMHunterHealth_CL` (SELF-002, SELF-004 hits)
- Per-source cards: last-seen, events/hour, parse-error rate, UnmappedFields %

### 6. Health
- Per-service status (vector, clickhouse, normalization, detection, forwarder, api)
- Forward ledger reconciliation: local count vs Sentinel-received (SELF-005 delta)
- Self-detection rule status board (SELF-001 through SELF-005)
- Auth-failure / audit feed from `SIEMHunterSecurity_CL`

### 7. Query Console
- Guarded ad-hoc console over `POST /v1/query`
- SELECT-only enforcement (server-side; surface error if non-SELECT submitted)
- Result table with truncation warning + execution time display
- Pre-built query templates for common lookups

---

## AI Summary Section

**Endpoint:** `GET /v1/ai/summary`

**What it sends to Claude (never raw events):**
- Event counts by provenance/source (last 24h, 7d)
- Top detection hits by severity + rule name
- AnomalyScore outlier buckets (p95, p99)
- Health deltas (service restarts, flood events, ledger discrepancies)
- Forward ledger: local vs Sentinel count
- Time window + batch cadence

**Output shown in UI:**
- Short narrative paragraph (3–5 sentences)
- "Notable items" bullet list
- Explicit disclaimer: "ML scores are advisory only; not a replacement for analyst review"
- Source window + generated-at timestamp
- Cached per batch cycle; invalidated on new batch completion

**Docker secret:** `anthropic_api_key.txt` mounted to the API container; set `ANTHROPIC_API_KEY` from it in the summarizer module. Add `egress` network to the `api` service (forwarder already uses it; flag for security review per repo conventions).

---

## New API Endpoints Required

All follow existing router conventions: `Depends(verify_token)`, Pydantic v2 response models (`extra="forbid"`), parameterized ClickHouse queries, `FINAL` on `rule_registry`, structured error bodies.

| Endpoint | Source | Status |
|----------|--------|--------|
| `GET /v1/metrics` | ClickHouse aggregates | Spec'd in `instructions/06-api-control-plane.md`, not built |
| `GET /v1/health` / `GET /v1/health/{service}` | Docker/service status | Spec'd, not built |
| `GET /v1/ingestion/summary` | `security_events`, `SIEMHunterHealth_CL` | New |
| `GET /v1/detections` | `detection_hits` (filtered) | New |
| `GET /v1/events` | `security_events` (paginated, filtered) | New |
| `GET /v1/ai/summary` | Aggregated bundle → Claude API | New |

---

## New Docker Service

Add to `docker-compose.yml`:

```yaml
frontend:
  build:
    context: ./frontend
    dockerfile: Dockerfile   # multi-stage: node build → nginx static
  image: siemhunter/frontend:0.1.0
  restart: unless-stopped
  user: "1000:1000"
  cap_drop: [ALL]
  security_opt: [no-new-privileges:true]
  read_only: true
  tmpfs: [/var/cache/nginx, /var/run]
  networks: [internal]
  ports: ["127.0.0.1:8081:8081"]   # never 0.0.0.0
  depends_on:
    api:
      condition: service_healthy
  healthcheck:
    test: ["CMD", "curl", "-f", "http://localhost:8081/healthz"]
    interval: 30s
    timeout: 5s
    retries: 3
  deploy:
    resources:
      limits: { memory: 128m, cpus: "0.25" }
  logging:
    driver: json-file
    options: { max-size: 10m, max-file: "3" }
```

nginx config: serves `/` from static dist, proxies `/api/*` → `http://api:8080/v1/*`. The bearer token stays in sessionStorage (user-pasted); the JS fetch layer adds `Authorization: Bearer <token>` header on every request. The API's `hmac.compare_digest` auth handles validation.

Anthropic API key: add `anthropic_api_key` to the `api` service secrets and add `api` to the `egress` network (alongside `forwarder`). Flag in security review that a second service now has egress.

---

## Critical Files to Modify / Create

| File | Action |
|------|--------|
| `docker-compose.yml` | Add `frontend` service; add `anthropic_api_key` secret; add `api` to `egress` network |
| `services/api/src/main.py` | Register new routers |
| `services/api/src/routers/metrics.py` | New — implement spec from `instructions/06-api-control-plane.md` |
| `services/api/src/routers/health.py` | New — implement spec |
| `services/api/src/routers/ingestion.py` | New |
| `services/api/src/routers/detections.py` | New |
| `services/api/src/routers/events.py` | New |
| `services/api/src/routers/ai_summary.py` | New — Claude API integration |
| `frontend/` | New directory: Vite project, all pages/components |
| `frontend/Dockerfile` | Multi-stage build |
| `frontend/nginx.conf` | Static serve + `/api` proxy |
| `secrets/anthropic_api_key.txt` | New secret (already covered by `.gitignore`) |

**Reference files (read, don't change):**
- `services/api/src/routers/rules.py` — router convention template
- `services/api/src/auth.py` — auth dep pattern
- `clickhouse/schema.sql` — exact column names for all queries
- `instructions/06-api-control-plane.md` — `/v1/metrics` and `/v1/health` spec

---

## Delegation Order

| Step | Agent | Task |
|------|-------|------|
| 1 | **implementer** | Build new FastAPI routers (metrics, health, ingestion, detections, events, ai_summary). Follow `rules.py` conventions exactly. ai_summary calls Claude API with aggregated bundle. |
| 2 | **implementer** | Scaffold React+TS+Vite frontend project in `frontend/`. Build all 7 pages + shared components (KPI cards, severity table, ECharts wrappers, AI summary card, rule board, query console). TanStack Query for data fetching with 30s poll. SessionStorage token flow. |
| 3 | **devops-engineer** | Add hardened `frontend` service to `docker-compose.yml`. Write multi-stage Dockerfile + nginx.conf. Wire `anthropic_api_key` secret to `api` service + add `api` to `egress` network. |
| 4 | **test-engineer** | Backend: auth tests, SELECT-only enforcement, parameterization, FINAL on rule_registry. Frontend: render tests for each page. Compose smoke test: verify 127.0.0.1 binding, healthchecks pass, api/frontend both healthy. |
| 5 | **code-reviewer** | Review against repo hardening conventions. Check: no 0.0.0.0, no secrets in env/logs, no raw events to Claude, token never logged, `FINAL` on ReplacingMergeTree queries. |
| 6 | **tech-writer** | Document new endpoints (request/response shapes), dashboard usage guide, Claude AI opt-in instructions, compose startup. Add "Dashboard" section to README. |

Steps 1 and 2 can run in parallel. Step 3 depends on both. Steps 4–6 are sequential after 3.

---

## Verification

1. `docker compose up --build` — all services healthy, no 0.0.0.0 bindings
2. Open `http://localhost:8081` — login with API token, Overview page loads with KPI cards
3. Ingest a test syslog event; verify it appears in Events page after batch cycle
4. Fire a Sigma rule manually; verify it appears in Detections page + hit count increments
5. Click "Get AI Summary" on Overview — verify Claude response is aggregated stats only (no raw events in the summary text)
6. Change a rule status on Rules page — verify 503 if Sentinel unreachable (fail-closed behavior)
7. Ingestion page shows provenance breakdown and volume-over-time chart
8. Health page shows all 5 self-detection rules + per-service status

---

## Build Status & Handoff (Tech Lead, 2026-06-19)

### Phase 1 — Backend routers: ✅ COMPLETE & REVIEWED (PASS)

Delegated to **implementer**, reviewed by **tech-lead** against repo conventions and the
hardening checklist. All endpoints follow `rules.py`/`query.py` conventions: `verify_token`
dependency, Pydantic v2 response models, **fully parameterized** ClickHouse queries (no user
value is ever string-interpolated into SQL), structured `{error, code}` bodies.

**Delivered (all pass `python -m py_compile`):**
| File | Endpoint | Notes |
|------|----------|-------|
| `services/api/src/routers/metrics.py` | `GET /v1/metrics` | events_by_source, hits 24h, anomaly histogram, last batch |
| `services/api/src/routers/health.py` | `GET /v1/health/{service}` | ADDED; unauth `/v1/health` Docker probe left intact |
| `services/api/src/routers/ingestion.py` | `GET /v1/ingestion/summary` | provenance, volume/hr, latency p95, per-source |
| `services/api/src/routers/detections.py` | `GET /v1/detections` | filtered + paginated + severity timeline |
| `services/api/src/routers/events.py` | `GET /v1/events` | filtered + paginated over security_events |
| `services/api/src/routers/ai_summary.py` | `GET /v1/ai/summary` | Claude `claude-opus-4-8`, aggregated bundle only |
| `services/api/src/main.py` | — | all 9 routers registered |
| `services/api/requirements.txt` | — | `anthropic` added |

### ⚠️ Governance reality-checks baked into Phase 1 (read before building the frontend)

These are **deliberate, correct** decisions — the frontend must be built around them, not "fixed":

1. **Sentinel-side data is NOT locally readable.** `SIEMHunterHealth_CL` / `SIEMHunterSecurity_CL`
   live in Log Analytics; this API has no Sentinel read client. The following return empty/null
   **with an explanatory note field** — the frontend must render them as "Not available locally
   (Sentinel-side)", NOT as zero/missing:
   - `/v1/ingestion/summary` → `rate_limit_flood_panel: null` (SELF-002/004 flood panel)
   - `/v1/metrics` → `last_batch_duration_seconds: null` (no local duration table)
   - `/v1/health/vector` → `status: "unknown"` (Vector writes no local alive-file)
   - SELF-005 ledger *delta* (local vs Sentinel-received) → local side only; Sentinel side noted.
2. **`security_events` has NO anomaly-score column.** AnomalyScore is per-detection-hit
   (`detection_hits.anomaly_score`), not per-event. The Events page must NOT show an AnomalyScore
   badge per event — drop that from the Events drill-in (plan §Pages/Events overstated this).
3. **Health page data sources:** the rich per-service health view should consume the existing
   **authenticated `GET /v1/status`** (gives clickhouse + normalization/detection/forwarder alive +
   retry-queue depth in one call) PLUS `GET /v1/health/{service}` for per-service detail. The
   unauth `GET /v1/health` is the Docker probe only — do not use it for the dashboard.
4. **Self-detection rule board (SELF-001..005):** rule *status* comes from `/v1/rules` (rule_registry);
   live *firing* data for SELF rules comes from `/v1/detections?rule_id=SELF-00x`. There is no single
   "self-detection status" endpoint — compose the board from those two.

### Follow-ups for a later pass (non-blocking, noted for whoever does Phase 3 devops/deps)

- **Pin `anthropic` properly.** Current floor is `anthropic>=0.28.0` — the only `>=` line in
  `requirements.txt` and an old floor. Pin to a recent `==` release that supports `claude-opus-4-8`.
- **`output_config={"effort":"low"}`** was omitted from the Claude call (implementer's SDK knowledge
  was stale; it IS a valid param on current SDKs). Add it once the SDK is pinned to a current version
  to cut summary cost. Non-blocking.
- The `--hash=sha256:placeholder_regenerate_before_deploy` placeholders are a **pre-existing** repo
  convention (every line uses them) — regenerate real hashes before any deploy (Phase 3).

### ▶ NEXT: Phase 2 — Frontend (ready to assign to implementer / implementation-lead)

Scope unchanged from "Dashboard Pages" + "Delegation Order Step 2" above, with these bindings locked:
- React + TS + Vite + Tailwind/shadcn + ECharts + TanStack Query (30s poll), sessionStorage bearer token.
- Wire pages to the **actual** endpoints now built (table above) + existing `/v1/status`, `/v1/rules`,
  `/v1/query`. Honor the 4 reality-checks above — render Sentinel-side gaps as explicit "not available"
  states, drop the per-event AnomalyScore badge, build Health from `/v1/status` + `/v1/health/{service}`.
- Do NOT build docker-compose/Dockerfile/nginx yet — that is **Phase 3 (devops-engineer)**, which
  depends on the frontend dir existing.

### Remaining phases (sequential after Phase 2)
- **Phase 3 — devops-engineer:** hardened `frontend` compose service + multi-stage Dockerfile + nginx
  (`/api` proxy), wire `anthropic_api_key` secret to `api` service, add `api` to `egress` network
  (flag for security review: 2nd service with egress). Also pin deps/regenerate hashes.
- **Phase 4 — test-engineer:** backend auth/SELECT-only/parameterization/FINAL tests + frontend render
  tests + compose smoke test (127.0.0.1 binding, healthchecks).
- **Phase 5 — code-reviewer:** hardening pass (no 0.0.0.0, no secrets in env/logs, no raw events to
  Claude, token never logged).
- **Phase 6 — tech-writer:** document new endpoints + dashboard usage + AI opt-in + README "Dashboard".
