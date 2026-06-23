> **SUPERSEDED** — This frontend sprint plan was a planning-phase artifact (originally at repo root
> as `frontendplan.md`). It has been relocated to `docs/history/` for reference only.
> Current planning lives in `docs/newreleaseplan/proposalplan.md` and `docs/plan.md`.

# SIEMhunter Frontend Sprint Plan — v0.2.0

**Document type:** Sprint planning artifact  
**Status:** DRAFT — awaiting security-architect review (ClickHouse section), then tech-lead approval  
**Prepared by:** requirements-analyst  
**Date:** 2026-06-20  
**Version bump:** v0.1.0 → v0.2.0  
**Handoff chain:** requirements-analyst → security-architect (fills §5) → tech-lead (approves) → SDLC (builds)

---

## 1. Purpose and Version Context

SIEMhunter v0.1.0 shipped a functional backend pipeline (ClickHouse ingestion, Sigma detection, Sentinel forwarding) and a read-only React dashboard for monitoring. The existing frontend pages — Overview, Events, Detections, Ingestion, Query, Rules, Health — are all display surfaces; none of them accept user-supplied data, support active upload, or produce contextual AI analysis beyond the single Overview summary.

This document defines the requirements for **v0.2.0**, a rapid frontend sprint resolving all eight open GitHub feature-request issues in one coordinated effort. The sprint introduces the first interactive surfaces: drag-and-drop file ingestion, incident management, cross-view AI analysis, correlation graphs, category dashboards, smart search, and consistent timestamping with intelligent drill-down. Several of these features require new backend endpoints and one requires a net-new upload pathway into the normalization pipeline. The security-architect must review the ClickHouse and ingestion security questions in §5 before any file-upload or search construction work begins.

---

## 2. Sprint Goal and Scope

**Goal:** In a single coordinated sprint, extend the SIEMhunter frontend from a read-only monitoring dashboard to an analyst-grade investigation workbench by shipping all eight GitHub feature requests. The sprint resolves drag-and-drop log ingestion (with incident scoping), a Claude AI chatbar on every analysis view, an ECharts-based correlation/event-stitching graph, a per-incident tracker, category drill-down dashboards, a smart structured search bar, UTC-with-EST timestamp consistency across every surface, and clickable intelligent drill-down on all query and event outputs.

**In scope:**
- All eight GitHub issues (#1–#8) as defined in their verbatim issue bodies
- New FastAPI endpoints required to support the frontend features (file upload, structured search, incident management)
- Timestamp formatting utility shared globally across the frontend
- A shared Claude AI chatbar component wired to the existing `/v1/ai/summary` router
- A shared drill-down interaction pattern applied to all tables and query results
- Security-architect review of ClickHouse upload and search query handling (§5)
- Vitest and pytest test coverage for all new components and endpoints

**Out of scope for this sprint:**
- Changes to the ClickHouse schema `security_events` canonical columns (any schema change requires the change protocol in `instructions/04-normalization-and-schema.md §8`)
- Sigma rule authoring or detection-engine changes
- Sentinel forwarding changes or DCR column updates
- Multi-user RBAC (single bearer token remains the auth model per `instructions/09-security-and-iam.md §3.4`)
- Azure Key Vault integration (deferred to v0.3 per `instructions/09-security-and-iam.md §2.5`)
- Mobile or small-screen layout optimization
- EVTX binary parsing within the API itself (see open question OQ-1)
- The Redpanda queue insertion between Vector and ClickHouse
- The `detection_state` table correlation (reserved for v0.2 detection work, not this frontend sprint)

---

## 3. Cross-Cutting Requirements

These requirements apply globally and must be designed before any per-issue work begins. They are not owned by a single issue.

### 3.1 UTC-with-(EST) Timestamp Formatting — Global Display Rule (#7)

**Rule:** Every timestamp displayed anywhere in the application — table cells, chart axis labels, KPI cards, detail panels, log lines, drill-down panels, incident records, chatbar responses — must be formatted as:

```
2026-06-20 14:32:05 UTC (10:32:05 EST)
```

The format is: `YYYY-MM-DD HH:MM:SS UTC (HH:MM:SS EST)`.

**Implementation requirement:** A single shared TypeScript utility function, `formatTimestamp(isoString: string): string`, must be created and imported everywhere a timestamp is rendered. The existing `formatTime()` helper functions scattered across `OverviewPage.tsx`, `EventsPage.tsx`, `DetectionsPage.tsx`, and `IngestionPage.tsx` all call `new Date(iso).toLocaleString()` using the browser's locale. Those must be replaced with the shared utility. No page may implement its own timestamp formatting logic.

**EST note:** EST is UTC-5. The utility displays the EST offset as a fixed label, not as a time-zone-aware conversion that adjusts for Daylight Saving Time. If the team prefers a DST-aware Eastern Time label, this is an open question — flag it as OQ-4.

**Scope:** This utility is a sprint prerequisite. No other issue may ship timestamp displays before this utility exists and is reviewed.

### 3.2 Claude AI Chatbar — Shared Component on Every Analysis View (#2)

**Rule:** A collapsible Claude AI chatbar component must appear on every analysis view. "Analysis view" means: Overview, Events, Detections, Ingestion, Query, and any new pages added in this sprint (Category Dashboard, Incident Tracker, Correlation Graph).

**Behavior:** The chatbar sends a request to the existing `GET /v1/ai/summary` endpoint and displays the `narrative` and `notable_items` in a conversational panel. The chatbar must be a single reusable React component (`ClaudeChatbar`) that any page can include without duplicating logic.

**Constraint:** The existing `ai_summary` router sends only aggregated statistics to Claude — counts, labels, numeric scores — never raw event content. This constraint is architectural and must not be changed in this sprint. The chatbar must not pass row-level event data (CommandLine, HostName, UserNames, IPs) to the Claude API. This is documented in `services/api/src/routers/ai_summary.py` lines 7-10 and is a data-privacy requirement.

**Context awareness:** The chatbar may accept an optional context hint (e.g., the current page name or selected incident ID) that the backend uses to scope the summary query. Whether the backend `ai_summary` endpoint needs to accept a context parameter is an open question (OQ-5).

**Degraded state:** If the Anthropic API key is not configured, the chatbar renders a clear "AI unavailable" state without crashing. This already works on the Overview page and must be preserved in the shared component.

### 3.3 Intelligent Drill-Down — Shared Interaction Pattern (#8)

**Rule:** Clicking any row in any table, or any result item in any query output, must open a detail panel that shows: (a) all canonical fields with non-empty values labeled in plain English with the field name expanded (not raw column names), (b) the `UnmappedFields` JSON rendered as formatted JSON, (c) a human-readable description of the `EventID` where the record includes one (see OQ-6 for EventID description source), and (d) links to pivot to related events by HostName, SubjectUserName, SrcIpAddr, or EventID.

**The `EventDetailPanel` in `EventsPage.tsx` is the starting point.** It already implements fields (a) and (b) above. It must be extracted into a shared `EventDetailPanel` component and extended with (c) and (d).

**Scope:** This pattern applies to: Events table, Detections table, Query result rows, Category Dashboard event lists, and Incident Tracker event lists. It does not need to apply to chart tooltips.

---

## 4. Per-Issue Requirement Breakdown

---

### Issue #1 — Drag-and-Drop File Ingestor

**User story:** As a security analyst, I want to drag and drop log files, EVTX files, and other unstructured data into the SIEM so that I can ingest evidence without setting up a Vector source or a network pipeline.

**Two upload modes must be supported:**
1. **Global ingest:** The uploaded file is processed through the normalization pipeline and stored in `siemhunter.security_events` as persistent data, with a `ProvenanceTag` that identifies it as a manual upload.
2. **Incident-scoped ingest:** The uploaded file is associated with a specific open incident (Issue #4) and its events are available for analysis within that incident context. Whether incident-scoped data persists to the global `security_events` table is a product decision (see OQ-2).

**Acceptance criteria:**

1. Given a user drops one or more supported files onto the upload zone, the zone highlights on drag-enter and the file names are listed before confirmation.
2. Given the user confirms the upload, the files are sent to a new API endpoint (`POST /v1/ingestion/upload`) via multipart form-data. The upload does not use the existing `/v1/ingestion/summary` GET endpoint, which is read-only.
3. Given a successful upload, the page displays a status card showing: file name, number of events parsed, number of events successfully written, number of events that could not be mapped to canonical columns (stored in `UnmappedFields`), and the `ProvenanceTag` assigned to the batch.
4. Given an upload failure (file too large, unsupported format, parse error, backend error), the page displays a specific error message without crashing. The error must not expose raw stack traces from the backend.
5. Given the user selects "incident-scoped" mode before uploading, the upload request includes the incident ID and the backend associates the events with that incident.
6. Given a file that exceeds the configured maximum upload size, the frontend rejects it before sending, displaying the limit clearly. The limit value must come from a configuration constant (not hardcoded in JSX).
7. Given the user uploads a `.evtx` binary file, the frontend indicates whether EVTX binary parsing is supported in the current build (see OQ-1). If not supported, it guides the user to convert to JSON first.
8. The upload zone must be accessible via keyboard (tab focus, Enter to open file picker) in addition to drag-and-drop.

**Frontend touchpoints:**
- `frontend/src/pages/IngestionPage.tsx` — modified to add the upload zone section below the existing summary panels
- New component: `frontend/src/components/UploadZone.tsx`
- New component: `frontend/src/components/UploadStatusCard.tsx`
- `frontend/src/api/client.ts` — new `uploadFile(file: File, mode: 'global' | 'incident', incidentId?: string)` function using `multipart/form-data` (the existing `request` helper sends `Content-Type: application/json` and cannot be reused for file uploads without modification)
- New type additions to `frontend/src/types/api.ts`: `UploadResponse`, `UploadMode`

**Backend/API touchpoints:**
- **New endpoint required:** `POST /v1/ingestion/upload` in `services/api/src/routers/ingestion.py`. This is a net-new endpoint; the existing router only has `GET /v1/ingestion/summary`.
- The endpoint must enforce bearer-token auth (same `verify_token` dependency), file-size limit, and MIME type or extension validation.
- The endpoint must assign a `ProvenanceTag` in the format `manual-upload:{filename_hash}:{timestamp}` — the ProvenanceTag must be assigned by the API server, never derived from file content, consistent with the rule in `instructions/03-data-ingestion-spec.md §2.1`.
- The endpoint hands the file content to the normalization layer for parsing and insertion. How the API communicates with the normalization service (direct call, queue, or file drop into `drop/`) is a design decision for `devops-engineer` and `implementer`, sequenced under `tech-lead`'s orchestration.
- The normalization service must be capable of parsing the uploaded file format. For `.evtx` binary files, this may require a new parser; see OQ-1.

**Data-model implications:**
- Uploaded events enter `siemhunter.security_events` with a `ProvenanceTag` distinguishing them from pipeline-ingested events. The schema does not change.
- Fields that cannot be mapped to canonical columns go into `UnmappedFields` (JSON string), consistent with `instructions/04-normalization-and-schema.md §4`.
- Incident-scoped upload implies a mechanism for filtering events by incident. This requires a field or metadata approach — see Issue #4.
- The `IngestTimestamp` on uploaded events is set by the normalization layer at processing time, not derived from file timestamps. This is already the rule per schema design.

**Dependencies:** Issue #4 (incident model must exist before incident-scoped upload can reference an incident ID). Issue #7 (timestamps on the status card must use the shared utility).

---

### Issue #2 — Claude AI Chatbar on Every Analysis View

**User story:** As a security analyst, I want a Claude AI analysis chatbar available at every step of the ingestion and investigation workflow, so that I can get contextual AI assistance without switching pages.

**Acceptance criteria:**

1. Given any analysis page (Overview, Events, Detections, Ingestion, Query, Category Dashboard, Incident Tracker, Correlation Graph), a Claude chatbar panel is visible or accessible via a persistent toggle button.
2. Given the user opens the chatbar, it displays the most recent AI summary narrative and notable items fetched from `GET /v1/ai/summary`.
3. Given the chatbar has fetched a response, the response displays: the narrative, the notable items list, the disclaimer text, the source window description, and the `generated_at` timestamp formatted with the shared timestamp utility from §3.1.
4. Given the Anthropic API key is not configured, the chatbar displays "AI analysis unavailable — API key not configured" without an error toast or crash.
5. Given the user is on a page that is unrelated to detection hits (e.g., the Ingestion page), the chatbar response may be less relevant — the chatbar does not crash or display stale data from a different page context; it displays whatever the `ai_summary` endpoint returns.
6. Given the user collapses the chatbar, its collapsed state persists for the current browser session (using `sessionStorage`).
7. The chatbar component renders independently of the page it is embedded in; removing it from a page does not affect page functionality.

**Frontend touchpoints:**
- New shared component: `frontend/src/components/ClaudeChatbar.tsx`
- All existing pages and new pages from this sprint: import and render `ClaudeChatbar`
- `frontend/src/hooks/useApi.ts` — `useAiSummary` hook already exists; `ClaudeChatbar` reuses it
- No new API endpoints required for the base chatbar; it reuses `GET /v1/ai/summary`

**Backend/API touchpoints:**
- `services/api/src/routers/ai_summary.py` — no changes required for the base chatbar
- If context-aware summaries are needed in the future (OQ-5), the endpoint would need a `?context=` query parameter; that is out of scope for this sprint unless tech-lead approves it

**Data-model implications:** None. The `ai_summary` endpoint sends only aggregated statistics to Claude, never row-level event data. This constraint must not be relaxed.

**Dependencies:** Issue #7 (timestamp utility for `generated_at` display).

---

### Issue #3 — Visual Graphics and Event Stitching (Correlation Graph)

**User story:** As a security analyst, I want a visual correlation graph that stitches related security events together — similar to Microsoft Sentinel's investigation graph or BloodHound's entity relationship view — so that I can see lateral movement, user activity chains, and entity relationships without writing SQL.

**Acceptance criteria:**

1. Given the analyst navigates to a new Correlation Graph view (suggested route: `/correlation`), an interactive node-link graph renders showing entities (hosts, users, IPs, processes) as nodes and security events as edges connecting them.
2. Given the graph is loaded, nodes are color-coded by entity type: host (blue), user (green), IP address (orange), process (purple). Edges are labeled with the EventID or event category.
3. Given the analyst clicks a node, a side panel opens showing all events involving that entity in the current time window, using the shared drill-down pattern from §3.3.
4. Given the analyst clicks an edge (event link), the full event detail panel from §3.3 opens for that specific event.
5. Given the analyst selects a time range, the graph updates to show only entities and events within that range.
6. Given more than a configurable maximum number of nodes (suggested default: 200), the graph displays a warning and suggests narrowing the time range or filtering by entity type.
7. The graph uses **ECharts** (already a dependency via `echarts-for-react`) with the `graph` series type. The issue mentions Node.js or BloodHound style — ECharts graph series satisfies this without adding a new dependency. If the team determines ECharts graph is insufficient, adding a dedicated graph library (e.g., `vis-network` or `react-force-graph`) is an option for tech-lead to decide (OQ-7).
8. The graph must render without crashing when there are zero events in the selected window.

**Frontend touchpoints:**
- New page: `frontend/src/pages/CorrelationPage.tsx`
- New component: `frontend/src/components/CorrelationGraph.tsx` (ECharts graph series wrapper)
- Route added to the router in the app entry point
- Navigation link added to the sidebar/nav

**Backend/API touchpoints:**
- New endpoint required or the existing `POST /v1/query` endpoint is sufficient to fetch the data needed to build graph edges. The correlation graph can be built from two queries: one for entities (SELECT DISTINCT HostName, SubjectUserName, SrcIpAddr FROM security_events WHERE ...) and one for relationships (SELECT HostName, SubjectUserName, SrcIpAddr, DstIpAddr, EventID FROM security_events WHERE ...). No new endpoint is strictly required if the Query page pattern is reused, but a dedicated `GET /v1/correlation/graph?start=&end=&incident_id=` endpoint would be cleaner and easier to test. Tech-lead to decide.

**Data-model implications:**
- Graph data is derived from existing `security_events` canonical columns. No schema changes needed.
- `UnmappedFields` is not used in graph construction (it is not indexed per `instructions/04-normalization-and-schema.md §4`).

**Dependencies:** Issue #7 (timestamps on the time range selector and edge labels). Issue #8 (drill-down panel on node/edge click). Issue #4 (optional: filter graph to a single incident's data).

---

### Issue #4 — Single Incident Setting (Incident Tracker)

**User story:** As a security analyst, I want to create named incidents and work on them independently, so that I can investigate a specific alert or case without mixing its evidence with other log ingestion activity happening at the same time.

**Two sub-features:**

**4A — Incident creation and management:**
- The analyst can create a new incident with a name, description, severity, and creation timestamp.
- Open incidents are listed in an Incident Tracker page (suggested route: `/incidents`).
- The analyst can mark an incident as closed or archived.
- Multiple incidents can be open simultaneously; switching between them preserves their state for the session.

**4B — Incident-scoped data isolation:**
- When the analyst selects an active incident, all views that display events can optionally filter to show only events associated with that incident.
- When uploading a file (Issue #1), the analyst can choose to associate it with a specific incident. Events from an incident-scoped upload are tagged so they can be isolated.
- The incident creator decides whether uploaded data is: (a) incident-only (visible only when that incident is selected) or (b) added to the global SIEM dataset (always visible).

**Acceptance criteria:**

1. Given the analyst navigates to `/incidents`, they see a list of all incidents with name, severity, status, creation time, and event count.
2. Given the analyst clicks "New Incident", a form lets them enter name, description, and severity. Submitting creates the incident and returns to the incident list.
3. Given an incident exists, the analyst can click into it to see its detail view: associated events, upload history, and a notes field.
4. Given the analyst selects an active incident from a top-bar or sidebar selector, all event-bearing pages (Events, Detections, Correlation Graph, Category Dashboard) show an "Incident scope active" indicator and can optionally filter to incident-scoped events only.
5. Given the analyst uploads a file with "incident-scoped" mode, the upload is tagged with the incident ID and the events' `ProvenanceTag` includes the incident identifier.
6. Given "incident-only" mode was chosen at upload time, those events do not appear in the global Events page unless the filter is explicitly set to include that provenance tag.
7. Given the analyst closes an incident, it moves to archived status and can be recalled later. Archived incidents are read-only.
8. The incident selector state persists for the browser session (using `sessionStorage`).

**Frontend touchpoints:**
- New page: `frontend/src/pages/IncidentsPage.tsx`
- New page: `frontend/src/pages/IncidentDetailPage.tsx`
- New component: `frontend/src/components/IncidentSelector.tsx` (top-bar or sidebar selector)
- New shared context: `frontend/src/context/IncidentContext.tsx` (provides active incident ID to child pages)
- `frontend/src/types/api.ts` — new types: `Incident`, `IncidentStatus`, `CreateIncidentRequest`, `IncidentSummaryResponse`
- `frontend/src/api/client.ts` — new methods for incident CRUD

**Backend/API touchpoints:**
- **New endpoints required** (all under `/v1/incidents/`):
  - `POST /v1/incidents` — create incident
  - `GET /v1/incidents` — list incidents with summary stats
  - `GET /v1/incidents/{id}` — incident detail
  - `PATCH /v1/incidents/{id}/status` — close or archive
- **New router:** `services/api/src/routers/incidents.py`
- The backend must store incident metadata. Options: a new ClickHouse table `siemhunter.incidents`, or a local JSON/SQLite file. Tech-lead to decide based on operational simplicity (see OQ-3).
- The `/v1/events` endpoint must accept an optional `incident_id` query parameter to filter by incident-scoped `ProvenanceTag`.

**Data-model implications:**
- Incident-scoped events are distinguishable by their `ProvenanceTag` (e.g., `manual-upload:incident:{incident_id}:{hash}`). This does not require a schema column change.
- If a new `siemhunter.incidents` table is needed, it requires the change protocol in `instructions/04-normalization-and-schema.md §8`. However, since this is a new table (not a change to `security_events`), the schema DDL addition is lower risk. Security-architect should comment on whether incident metadata belongs in ClickHouse or in a separate lightweight store.

**Dependencies:** Issue #1 (upload must be able to reference an incident ID). Issue #7 (timestamps on incident records). Issue #3 (graph can filter to incident scope). Issue #8 (drill-down panel on incident event list).

---

### Issue #5 — Dashboard with Event Categories and Drill-Downs

**User story:** As a security analyst, I want a category dashboard that organizes events into drill-down sections by security domain — Active Directory, Network, DNS, Network Analysis, Malware Analysis, Log Analysis — so that I can quickly focus on the category most relevant to my current investigation without writing a custom query.

**Acceptance criteria:**

1. Given the analyst navigates to a new Category Dashboard page (suggested route: `/categories`), they see a summary grid of security domain cards, each showing a category name, event count for the past 24 hours, and a trend indicator (up/down from the previous 24 hours).
2. Given the analyst clicks a category card (e.g., "Active Directory"), a drill-down view expands showing a filtered event table for that category, scoped to relevant EventIDs and ChannelNames.
3. The six minimum categories and their ClickHouse filter logic are:

   | Category | Primary ClickHouse filter |
   |----------|--------------------------|
   | Active Directory | EventID IN (4720, 4722, 4724, 4725, 4726, 4728, 4732, 4756, 4768, 4769, 4771, 4776) OR ChannelName = 'Security' |
   | Network | NetworkProtocol != '' OR SrcIpAddr != '' |
   | DNS | EventID IN (4 /* Sysmon DNS */, 3008 /* Windows DNS */) OR ServiceName LIKE '%dns%' |
   | Network Analysis | DstPort IN (80, 443, 8080, 8443) AND SrcIpAddr != '' |
   | Malware Analysis | FileSHA256 != '' OR FileMD5 != '' OR CommandLine LIKE '%powershell%' OR CommandLine LIKE '%cmd.exe%' |
   | Log Analysis | ProvenanceTag != '' (all events, for raw log review) |

   Note: These filters are a starting point. The detection-engineer should validate them against the canonical field table in `instructions/04-normalization-and-schema.md §5` before implementation.

4. Given the drill-down view is open, each row is clickable and opens the shared EventDetailPanel from §3.3.
5. Given the analyst selects a time range (defaulting to last 24 hours), all category counts and the drill-down table update accordingly.
6. Given the active incident scope is set (Issue #4), the category counts and drill-down table optionally filter to incident-scoped events only, with a visible scope indicator.
7. Each category card displays an ECharts mini-sparkline showing event volume over the last 24 hours in hourly buckets (reusing the ECharts dependency).

**Frontend touchpoints:**
- New page: `frontend/src/pages/CategoryDashboardPage.tsx`
- New component: `frontend/src/components/CategoryCard.tsx`
- Navigation link added to sidebar/nav
- Reuses `DataTable`, `EventDetailPanel` (shared per §3.3), and timestamp utility

**Backend/API touchpoints:**
- The category counts and sparkline data can be served by `POST /v1/query` using the existing query endpoint with parameterized queries. No new endpoints are strictly required.
- Alternatively, a `GET /v1/categories/summary` endpoint could pre-compute the category counts in a single multi-query ClickHouse call for better performance. Tech-lead to decide.

**Data-model implications:**
- Category drill-downs query `siemhunter.security_events` using existing canonical columns. No schema changes needed.
- Category filter definitions are frontend-side configuration; they are not stored in ClickHouse.

**Dependencies:** Issue #7 (timestamps on cards and table). Issue #8 (drill-down on row click). Issue #4 (incident scope filter). Issue #2 (chatbar on this page).

---

### Issue #6 — Rich Search Queries at the Top

**User story:** As a security analyst, I want a structured search bar at the top of the application that lets me search across all events by IP address, hostname, username, TCP port, or other key fields, so that I can find relevant events immediately without opening the Query Console and writing SQL.

**Acceptance criteria:**

1. Given a persistent search bar component visible at the top of the application layout, the analyst can type a search term and select a field type from a dropdown (IP Address, Hostname, Username, TCP Port, EventID, File Hash, Process Name).
2. Given the analyst selects "IP Address" and enters a value, the search constructs a parameterized ClickHouse query that searches both `SrcIpAddr` and `DstIpAddr` for the entered value. The entered value is passed as a named parameter (`{ip:String}`), never concatenated into SQL as a string literal.
3. Given the analyst selects "TCP Port" and enters a port number, the search queries both `SrcPort` and `DstPort`. The value is passed as a named parameter (`{port:UInt16}`).
4. Given the analyst selects "File Hash" and enters a 32-character value, the search queries `FileMD5`. Given a 64-character value, it queries `FileSHA256`. Given neither length, it queries both with a LIKE match as a fallback.
5. Given the analyst submits a search, the results are displayed in a results panel using the shared DataTable component with pagination. Results show up to the existing row cap (10,000 per the `query.py` row cap setting).
6. Given zero results are returned, the panel shows a clear "No events matched" message rather than an empty table.
7. Given the analyst clicks any result row, the shared EventDetailPanel from §3.3 opens with full field expansion and pivot links.
8. Given the analyst enters a blank search term, the search button is disabled and no request is sent.
9. Given the backend returns an error (timeout, forbidden keyword), the search panel shows the error code and a plain-English explanation. Raw SQL error messages from ClickHouse are not shown to the user.
10. The search bar does not allow free-text SQL input. Field type selection is mandatory. This is a security requirement (see §5 below for the ClickHouse injection risk discussion).

**Frontend touchpoints:**
- New shared component: `frontend/src/components/GlobalSearchBar.tsx`
- Integrated into the main application layout (not inside any single page)
- New page or panel: `frontend/src/pages/SearchResultsPage.tsx` or a slide-in results panel
- `frontend/src/api/client.ts` — new `search(fieldType: SearchFieldType, value: string)` method that maps the field selection to a parameterized `QueryRequest` and calls `POST /v1/query`
- New type: `SearchFieldType` enum in `frontend/src/types/api.ts`

**Backend/API touchpoints:**
- The existing `POST /v1/query` endpoint in `services/api/src/routers/query.py` can serve search requests if the frontend constructs a safe parameterized SQL query and passes the value through the `params` field.
- The frontend MUST use the `{name:type}` native parameterized query syntax supported by `query.py` (line 45 in `query.py` documents this). It must never concatenate user input into the SQL string.
- Example safe approach: for an IP search, the frontend sends `{"sql": "SELECT ... FROM siemhunter.security_events WHERE SrcIpAddr = {ip:String} OR DstIpAddr = {ip:String} LIMIT 1000", "params": {"ip": "192.168.1.1"}}`.
- A dedicated `POST /v1/search` endpoint with a structured request body (field type + value) would be safer than relying on the frontend to construct parameterized SQL correctly. This is a recommendation for the security-architect to evaluate in §5.

**Data-model implications:**
- Searches query existing canonical columns in `security_events`. `UnmappedFields` is not searched (it is not indexed).
- File hash searches against `FileMD5 FixedString(32)` and `FileSHA256 FixedString(64)` require the submitted value to be lowercase hex of the correct length. The frontend must validate length and case before sending.

**Dependencies:** Issue #7 (timestamps in search results). Issue #8 (drill-down on result row click). Issue #2 (chatbar available on the results view).

---

### Issue #7 — Time Synchronization

**User story:** As a security analyst, I want all timestamps displayed in the SIEM to be shown in UTC with the EST equivalent in parentheses, so that I can correlate events with my local time without ambiguity.

**Acceptance criteria:**

1. Given any timestamp rendered anywhere in the frontend, it is formatted as `YYYY-MM-DD HH:MM:SS UTC (HH:MM:SS EST)` using the shared `formatTimestamp` utility.
2. Given the existing `formatTime()` local functions in `OverviewPage.tsx`, `EventsPage.tsx`, `DetectionsPage.tsx`, and `IngestionPage.tsx`, those are replaced with the shared utility in this sprint.
3. Given a null or empty timestamp value, the utility returns the string `—` (em dash) without throwing an error.
4. Given a malformed ISO string that cannot be parsed, the utility returns the original string unchanged rather than crashing.
5. Given the timestamp utility is imported by a component under Vitest, the utility's output for a known UTC input matches the expected formatted string exactly.
6. All charts that display time on an axis (the stacked area charts in `DetectionsPage.tsx`, `IngestionPage.tsx`) must use the timestamp utility for axis label formatting where feasible within ECharts configuration.

**Frontend touchpoints:**
- New file: `frontend/src/utils/formatTimestamp.ts` — the single authoritative timestamp utility
- Modified: `OverviewPage.tsx`, `EventsPage.tsx`, `DetectionsPage.tsx`, `IngestionPage.tsx` — replace local `formatTime()` calls
- All new pages and components in this sprint: must import `formatTimestamp` rather than writing local formatting logic

**Backend/API touchpoints:** None. Timestamp formatting is a display-layer concern. The backend already returns `DateTime64(3,'UTC')` as ISO-8601 strings.

**Data-model implications:** None.

**Dependencies:** None. This is a sprint prerequisite — it should be the first work item completed.

---

### Issue #8 — Intelligent Drill-Down

**User story:** As a security analyst, I want clicking into any query result or event to show me expanded, contextual information — including what an EventID means, all available fields, and quick links to pivot to related events — so that I can investigate without needing to open a separate reference guide or write follow-up queries.

**Acceptance criteria:**

1. Given the analyst clicks any row in any event table (Events page, Category Dashboard, Incident Tracker, Search results), a detail panel opens on the right side of the screen.
2. Given the detail panel opens for a `SecurityEvent`, it displays all non-empty canonical fields with their plain-English labels (not raw column names), formatted values, and the `UnmappedFields` content as formatted JSON. This extends the existing `EventDetailPanel` in `EventsPage.tsx`.
3. Given the detail panel displays an `EventID`, it shows a human-readable description of that EventID (e.g., EventID 4769 = "A Kerberos service ticket was requested"). See OQ-6 for the source of EventID descriptions.
4. Given the detail panel is open, pivot links are available for: "Find all events from this host", "Find all events by this user", "Find all events from this source IP", "Find all events with this EventID". Clicking a pivot link navigates to the Events page pre-filtered, or opens a new search result using the global search bar (Issue #6).
5. Given the analyst clicks a row in the Query Console result table (existing `QueryResult` component in `frontend/src/components/QueryResult.tsx`), the detail panel opens if the row contains a field matching an `EventRecordID` column (since query results are untyped, the panel should attempt to match columns to the known `SecurityEvent` shape).
6. Given the detail panel is open on a narrow viewport, it overlays the table rather than pushing it aside.
7. The detail panel can be closed via an X button, the Escape key, or clicking outside the panel.

**Frontend touchpoints:**
- `frontend/src/components/EventDetailPanel.tsx` — extract from `EventsPage.tsx` into a shared component and extend with EventID descriptions and pivot links
- `frontend/src/components/QueryResult.tsx` — modified to support row-click opening the shared `EventDetailPanel`
- All pages that display event tables: import `EventDetailPanel`
- New utility: `frontend/src/utils/eventIdDescriptions.ts` — a static lookup object mapping common EventIDs to descriptions (see OQ-6)

**Backend/API touchpoints:** None for the drill-down panel itself. Pivot links navigate the frontend to filtered views; they do not require new backend endpoints.

**Data-model implications:** None. The panel reads data already returned by existing API responses.

**Dependencies:** Issue #7 (timestamps in the detail panel). Issue #6 (pivot links use the global search or Events page filter). All other issues that display tables depend on this being available as a shared component.

---

## 5. Security Architecture — ClickHouse and Unstructured Front-End Inputs (security-architect to complete)

This section describes the attack surface and open security questions introduced by two issues in this sprint. The security-architect must review and fill the "Findings and Controls" subsection before any implementation begins on Issue #1 (file upload) or Issue #6 (search query construction).

### 5.1 Issue #1 — File Upload and Normalization Attack Surface

The upload path in Issue #1 introduces a net-new surface: unauthenticated (from ClickHouse's perspective) data entering the `security_events` table via an analyst-controlled file. The following questions and risks need security-architect assessment:

**Q-S1: ProvenanceTag spoofing via uploaded content.**
The existing ingest paths (syslog, WEF, netflow) assign `ProvenanceTag` in Vector before normalization — the tag cannot be spoofed by event content. For uploaded files, the API server assigns the `ProvenanceTag`. If the normalization parser reads a `ProvenanceTag` field from within the uploaded file content and includes it in the normalized event, an attacker could inject a crafted file that masquerades as a different source. The normalization layer must ignore any `ProvenanceTag` or `IngestTimestamp` fields present in uploaded file content. How is this enforced and verified?

**Q-S2: Mapping uploaded fields to UnmappedFields vs. canonical columns.**
For pipeline ingestion, the Vector-to-normalization mapping is fixed and deterministic. For uploaded files, the mapping from arbitrary log field names to canonical ClickHouse columns is ambiguous. If the normalization layer uses a flexible field-name matching strategy for uploads, a crafted upload could potentially inject values into canonical columns (CommandLine, ProcessImagePath) that would be picked up by Sigma detection rules. What is the correct policy: strict canonical mapping only (everything else to `UnmappedFields`), or heuristic matching?

**Q-S3: File type validation and malicious file handling.**
Uploaded files are analyst-supplied, potentially from compromised evidence sources. File type validation based on extension is trivially bypassed. Should the API server validate file content (magic bytes), and what happens if a valid-looking log file contains embedded exploit content targeting the parser? Is the normalization service sandboxed against parser exploits?

**Q-S4: File size ceiling.**
The existing per-event size cap (64 KB per `instructions/03-data-ingestion-spec.md §2.1`) applies to network-received events. Uploaded files may contain millions of events in a single file. What is the maximum upload file size? What is the maximum number of events the upload endpoint will process from a single file before stopping? These bounds must be enforced server-side before parsing begins.

**Q-S5: Incident-scoped vs. global data isolation — ClickHouse enforcement.**
Issue #4 requires that incident-only uploads are not visible in the global Events view. The proposed mechanism is `ProvenanceTag` filtering. ClickHouse has no row-level access control; isolation relies entirely on the API layer filtering queries by `ProvenanceTag`. If the analyst bypasses the frontend and calls `POST /v1/query` directly with a SELECT that omits the ProvenanceTag filter, they see all data. Is this acceptable given the single-tenant model, or does the sprint need to enforce incident isolation at the query layer?

**Q-S6: Malware in uploaded files.**
Uploaded log files may come from compromised hosts and could include malware artifacts embedded in log fields (e.g., base64-encoded shellcode in CommandLine fields). These are stored in ClickHouse as strings. The SIEM is a read environment for this data, not an execution environment, so storage risk is low. However, if the frontend renders CommandLine or similar fields as HTML without proper escaping, a stored XSS via an uploaded log field is possible. What is the XSS posture for rendering arbitrary string fields from ClickHouse?

### 5.2 Issue #6 — Free-Text Search and SQL Construction

**Q-S7: SQL injection via structured search.**
Issue #6 requires the frontend to construct ClickHouse queries based on user input. The existing `query.py` endpoint supports native parameterized queries using `{name:type}` syntax. If the frontend passes values as parameters (not concatenated into SQL strings), SQL injection is prevented at the ClickHouse level. However, the field-type mapping (user selects "IP Address" → `SrcIpAddr`/`DstIpAddr`) means the frontend is selecting which columns to query, not just supplying values. An attacker who intercepts the API call and sends a fabricated `sql` field could still construct arbitrary SELECT queries. Does the sprint need a dedicated `/v1/search` endpoint with a structured request body (field type enum + value) that the backend maps to SQL — preventing the frontend from ever sending raw SQL for search operations?

**Q-S8: Column name injection in the field-type selector.**
If the frontend constructs SQL by inserting a user-supplied or frontend-derived column name into the SQL string (e.g., `SELECT ... WHERE {column_name} = {value}`), column name injection is possible if `column_name` is not from a fixed allowlist. The field-type enum approach (frontend maps "IP Address" → hard-coded `SrcIpAddr`/`DstIpAddr`) prevents this, but only if the mapping is done in verified frontend code and not derivable from user input. The backend must not trust the column name from the request body; if a `/v1/search` endpoint is used, it must map the field type enum to column names server-side.

**Q-S9: SSRF via IP address search.**
The existing `query.py` blocks queries containing `169.254` (IMDS). A search for IP address `169.254.169.254` would pass the entered value as a parameter, not a URL, so there is no SSRF risk at the ClickHouse query layer. However, if any future enrichment step (e.g., reverse DNS lookup for a searched IP) involves the backend making outbound HTTP calls based on the searched IP, SSRF applies. Confirm no enrichment calls are in scope for this sprint.

**Q-S10: Search result volume and denial of service.**
The existing query endpoint caps results at 10,000 rows (configurable via `QUERY_ROW_CAP`). The search endpoint must inherit this cap. A search for a very common value (e.g., IP `0.0.0.0` or username `SYSTEM`) could match millions of rows; the cap prevents the API from returning an oversized response but the ClickHouse query still runs. Should the search endpoint enforce a stricter cap than the general query endpoint, or add a query timeout shorter than the 30-second general timeout?

---

### Findings and Controls (security-architect)

> **Reviewer:** security-architect · **Date:** 2026-06-20 · **Status:** Complete — blocking findings flagged in the MUST list below.
>
> **Framework mapping.** Controls below are mapped to **OWASP ASVS 4.0** (Application Security Verification Standard — the recognized control catalogue for web app inputs/outputs), the project's own **STRIDE threat model** (`14-threat-model.md`), and the **hardening checklist** (`16-hardening-checklist.md`). Where a control already exists in v0.1.0 I say "reinforce existing"; where it is net-new for this sprint I say "new." Nothing below invents a compliance mandate — these are engineering controls justified by the threat model, not regulatory requirements.

#### Trust-boundary statement (read this first)

v0.1.0's threat model (`14-threat-model.md §3`) drew trust boundary **TB1 (ingest edge)** at *external source → Vector → ClickHouse*. The browser was a **read-only consumer** sitting safely inside TB2 (local store). This sprint moves the browser to the **untrusted** side of a new boundary. After v0.2 the following are all **untrusted input** and must be treated as adversary-controlled:

1. **The browser / front-end client.** Anyone with the single bearer token (`09-security-and-iam.md §3.4`) can call the API directly with `curl`, bypassing every client-side check. **Client-side validation is UX, not security.** Every control below is server-side or it does not count.
2. **The uploaded file bytes (Issue #1).** This is a *new TB1 ingest path that does not pass through Vector.* Vector is where ProvenanceTag assignment, size caps, rate limits, and decompression caps live today (`16 §4`). The upload endpoint bypasses all of that, so those controls must be **re-implemented on the upload path** — they do not come for free.
3. **The search text (Issue #6).** Free text that is turned into a database query. The classic injection surface.

The single most important framing: **the analyst is semi-trusted, but the data they upload is fully untrusted** (it may be evidence from a compromised host — `5.1 Q-S6`), and **the network path is untrusted** (the token can be replayed or the analyst can craft raw requests). Design for "the client is the attacker."

#### Findings table — analyst questions Q-S1 … Q-S10

| Q | Topic | Verdict | Control (summary) |
|---|-------|---------|-------------------|
| **Q-S1** | ProvenanceTag / IngestTimestamp spoofing via file content | **Confirmed risk — MUST fix.** This is STRIDE-**Spoofing** at the new TB1 edge and the upload analogue of threat-model finding #2. | Server assigns `ProvenanceTag` and `IngestTimestamp`; normalization **strips/ignores** any `ProvenanceTag`, `IngestTimestamp`, and `HostName`-as-identity fields found inside the file before mapping. Per `04-normalization-and-schema.md §4` ("Provenance fields are always flat… never sourced from the event content") and `03-data-ingestion-spec.md §2.1`. |
| **Q-S2** | Flexible field-name matching could inject into canonical columns | **Confirmed risk — MUST constrain.** STRIDE-**Tampering**; a crafted upload that lands attacker text in `CommandLine`/`ProcessImagePath` becomes visible to Sigma rules and pollutes detections. | **Strict allowlist mapping only.** Map a source field to a canonical column **only** when its name exactly matches the canonical field table (`04 §5`). Everything else → `UnmappedFields`. **No heuristic / fuzzy matching.** This is the safe default and the analyst questions correctly suspected it. |
| **Q-S3** | File-type validation + parser exploits | **Partly valid — extension check is necessary but not sufficient.** STRIDE-**Elevation of privilege** (parser RCE) and **DoS**. Magic-byte sniffing is defense-in-depth; the real control is sandboxing + resource limits. | Allowlist extensions **and** verify magic bytes; reject mismatches. Run parsing in the **normalization service, never in the API process** (`14 §4` boundary-1 "E" row: non-root, read-only FS, `cap_drop ALL`, `no-new-privileges` per `16 §1`). Enforce a parse timeout (`16 §4`, default 30s/file). The API only stages bytes; it must not parse. |
| **Q-S4** | File-size / event-count ceiling | **Valid — MUST set hard bounds.** STRIDE-**DoS**; the 64 KB *per-event* cap (`16 §4`) does not bound a *file* with millions of events. | Enforce, **server-side, before parsing begins**: max file size, max events per file, max bytes per field, max `UnmappedFields` bytes, decompression-ratio cap (`16 §4`, default 100:1). Concrete numbers in the MUST list. |
| **Q-S5** | Incident vs. global isolation has no DB enforcement | **Valid and important — MUST enforce at the API, document the residual gap.** STRIDE-**Information disclosure**. ClickHouse has no row-level security; today the single token sees everything. | The new end-user search/event endpoints **inject a server-side `incident_id`/ProvenanceTag predicate** the client cannot remove. The raw `/v1/query` operator endpoint stays bearer-gated and is **explicitly documented as able to see all data** — it is an operator tool, not an end-user tenant boundary. True isolation needs multi-tenant RBAC (deferred, `09 §3.4`) → hand to **iam-engineer**. |
| **Q-S6** | Stored XSS + malware artifacts in rendered fields | **Valid — MUST verify output encoding.** STRIDE-**Tampering** of the analyst's browser. Storage of malware *strings* is low risk (SIEM is a read environment), but **rendering** them is the live risk. | No `dangerouslySetInnerHTML` anywhere event-derived content is shown (drill-down #8, tables, `UnmappedFields` JSON). Rely on React's default JSX escaping; render `UnmappedFields`/`CommandLine` as text/`<pre>` nodes. Treat any content sent to Claude (#2) as untrusted → **prompt-injection** note below. ASVS V5.3 (output encoding). |
| **Q-S7** | SQL injection via search construction | **Valid — MUST add a dedicated endpoint.** STRIDE-**Tampering/EoP**. The plan's "front-end builds parameterized SQL" approach is unsafe because the *client is untrusted* and can send any `sql`. | **New `POST /v1/search` endpoint** takes `{field_type, value}` (no SQL). Backend maps field_type→column server-side and binds the value with ClickHouse `{name:type}` parameters — the same native parameterization `query.py` already uses (`query.py` §"Security controls" item 5). End users get `/v1/search`; raw `/v1/query` stays **operator-gated** and is **not** exposed in the global search bar. |
| **Q-S8** | Column / identifier injection | **Valid — parameters bind values, never identifiers.** Project threat-model finding #11 (identifier injection). | The `field_type` enum maps to column names from a **fixed server-side allowlist**. Never interpolate a column name derived from request data. Reject unknown `field_type` with `422`. Mirrors the existing rule "Sigma metadata is never interpolated as a column name" (`16 §4`). |
| **Q-S9** | SSRF via IP search | **Low risk for this sprint, but the real fix is overdue.** Threat-model finding #9. Passing an IP as a `{ip:String}` *value* is safe; the danger is ClickHouse's `url()/remote()/file()` functions, which `query.py` itself flagged it cannot fully close. | **Confirm no enrichment/outbound calls are in scope** (the plan says none — keep it that way). **Close the gap `query.py` flagged**: apply a `readonly`/function-restricted ClickHouse profile that disables `url`, `remote`, `remoteSecure`, `file`, `jdbc`, etc. See SHOULD list — this also hardens the existing `/v1/query`. |
| **Q-S10** | Search DoS via common values / full scans | **Valid — MUST bound search.** STRIDE-**DoS**. The 10k row cap (`query.py`) bounds the *response*, not the *scan*; a `%substring%` over `UnmappedFields` or a match on `SYSTEM` still scans the table. | `/v1/search` requires a **bounded time range** (default + max window), inherits the row cap, and uses a **shorter timeout** than the 30s operator timeout. **Disallow `UnmappedFields` substring/`ILIKE '%…%'` search** in the end-user path (it is unindexed by design — `04 §4/§6`). Lean on the `users.xml` backstops (`max_rows_to_read`, `max_execution_time`). |

#### Prioritized control list

##### MUST — sprint-blocking (Wave 1C sign-off; gate Wave 2B upload and 2D search)

Each is concrete and testable. "Server-side" means enforced in the API/normalization layer and provable with a `curl` request that bypasses the browser.

**Upload path (Issue #1):**

1. **Server overwrites provenance.** `POST /v1/ingestion/upload` assigns `ProvenanceTag` (format `manual-upload:{actor}:{ts}` or `manual-upload:incident:{incident_id}:{ts}`) and `IngestTimestamp` server-side. The normalization step **deletes any `ProvenanceTag`, `IngestTimestamp`, and host-identity fields present in file content** before mapping. *Test:* upload a file whose body contains `"ProvenanceTag":"wef:http:1"` → stored tag is the server `manual-upload:…` value, never `wef:http:1`. (Q-S1; `03 §2.1`, `04 §4`.)
2. **Strict allowlist field-mapping; everything else quarantined.** Map source fields to canonical columns **only on exact match** to `04 §5`; all other fields serialize into `UnmappedFields`. No fuzzy/heuristic matching. *Test:* a field named `Cmd` or `cmdline` does **not** populate `CommandLine`; it lands in `UnmappedFields`. (Q-S2.)
3. **Hard input bounds enforced before parsing.** Reject server-side, with a specific (non-stack-trace) error: file > **100 MB** (`UPLOAD_MAX_BYTES`, configurable), > **1,000,000 events/file** (`UPLOAD_MAX_EVENTS`), any single field > **64 KB** (reuse the per-event cap convention, `16 §4`), `UnmappedFields` > **256 KB/row**, decompression ratio > **100:1** for `.zip`/`.gz`/`.evtx` (`16 §4`). *Test:* a 1 KB zip that expands to 10 GB is rejected at the decompression cap, not after. (Q-S3, Q-S4.)
4. **Extension allowlist + magic-byte check.** Allow only `.json`, `.jsonl`, `.csv`, `.log`, `.txt`, `.evtx`, `.zip`, `.gz` (final list = tech-lead). Verify magic bytes and reject extension/content mismatch. Reject path-traversal/odd filenames (no `..`, no NUL, normalize before any disk write to `drop/`). *Test:* a `.json` file that is actually a PE binary is rejected. (Q-S3.)
5. **Parsing runs outside the API process.** The API stages bytes only (to `drop/` or a queue); the **normalization service** parses under `cap_drop: ALL`, `no-new-privileges`, read-only FS, non-root (`16 §1`), with the parse timeout (`16 §4`). Malformed UTF-8, embedded NUL, oversized lines, and any XML/EVTX path must be handled defensively (no external-entity expansion — disable DTDs/entities on any XML parser; billion-laughs defense). *Test:* a malformed-UTF-8 / NUL-laden file fails the single file without taking down the API or the service. (Q-S3, ASVS V12/V5.)
6. **Validate-before-insert with typed/parameterized inserts.** Coerce and validate every value against the ClickHouse column type **before** insert: `EventID`→`UInt32` (non-numeric → `0` + warning, per `04 §3`), ports→`UInt16` (reject/clamp out-of-range), hashes→lowercase hex of exact length for `FixedString(32)/(64)` (else → `UnmappedFields`), timestamps→`DateTime64(3,'UTC')` (reject rows with empty `TimeGenerated`, per `04 §6`). **Use the client's typed/parameterized insert path — never build INSERT text by string concatenation** (`16 §4`, threat-model finding #2). *Test:* a row with `EventID:"; DROP"` stores `EventID=0`, inserts no SQL. (Q-S2.)
7. **No `dangerouslySetInnerHTML` on event-derived content.** Drill-down (#8), all tables, and `UnmappedFields`/`CommandLine`/`ObjectName` rendering use React default escaping / text nodes. *Test:* a `CommandLine` containing `<img src=x onerror=alert(1)>` renders as inert text, no script executes. (Q-S6; ASVS V5.3.)

**Search path (Issue #6):**

8. **New `POST /v1/search` endpoint; never expose raw `/v1/query` to end users.** Request body is `{field_type: enum, value: str, start: datetime, end: datetime}` — **no `sql` field**. Backend maps `field_type`→column(s) from a server-side allowlist and binds `value` as a ClickHouse `{name:Type}` parameter. Raw `/v1/query` stays **bearer + operator-gated** and is not wired to the global search bar. *Test:* sending `{"field_type":"IP","value":"' OR 1=1 --"}` returns zero rows and runs one parameterized query; there is no request shape that lets the search bar submit arbitrary SQL. (Q-S7, Q-S8; reinforces `query.py` parameterization.)
9. **Column allowlist for field_type.** Enum→column mapping is fixed server-side (`IP`→`SrcIpAddr,DstIpAddr`; `Port`→`SrcPort,DstPort` as `UInt16`; `Hash`→length-routed `FileMD5`/`FileSHA256`; `EventID`→`UInt32`; etc.). Unknown `field_type` → `422`. Never interpolate a column name from the body. (Q-S8; finding #11.)
10. **Bounded search semantics.** `/v1/search` **requires a time range** (default last 24h, max window e.g. 30d/tech-lead), inherits the 10k row cap, and uses a **shorter timeout** than the 30s operator timeout (e.g. 10s). **`UnmappedFields` substring search is not offered** in the end-user path. *Test:* a search for `SYSTEM` with no time range is rejected/defaulted; it cannot trigger an unbounded full scan. (Q-S10.)
11. **Server-enforced incident scope.** When an incident scope is active, the backend appends the `incident_id`/ProvenanceTag predicate to event and search queries; the client cannot supply or remove the scope filter. Incident-only uploads are excluded from the global view by the **server**, not by a client flag. *Test:* a direct `/v1/search` call cannot return incident-only rows unless the server-side scope is set for that request. (Q-S5; ties Issue #4.)

##### SHOULD — fast-follow (high value, not strictly sprint-blocking)

1. **Apply a function-restricted ClickHouse profile (`readonly` + disabled functions).** Create a profile (in `users.xml`) that disables `url`, `remote`, `remoteSecure`, `file`, `jdbc`, `s3`, `hdfs`, `mysql`, `postgresql` and sets the search/query connection to a read-only role. **This closes the SSRF gap `query.py` itself flagged** and is the real control behind the `169.254` regex (which is a stopgap, not a boundary). Reinforces `16 §6` SSRF item and threat-model finding #9. *Note:* the normalization insert path needs its own write-capable role; do not apply read-only to it.
2. **Rate-limit the upload and search endpoints.** Vector's per-source rate limit (`16 §4`) does not cover the new endpoints. Add per-token request limits to blunt upload-flood / search-flood DoS (STRIDE-**DoS**, finding #4 analogue).
3. **Treat content sent to Claude as untrusted (prompt-injection).** The chatbar (#2) already sends **only aggregated stats**, never row-level content (`ai_summary.py`); **keep that boundary.** If any future change sends event text to Claude, label it untrusted and assume embedded prompt-injection — do not let model output drive privileged actions. Document this so OQ-5 (context-aware summaries) does not silently cross the line.
4. **Audit uploads to `SIEMHunterSecurity_CL`.** Emit an audit record per upload (actor, ProvenanceTag, file hash, event counts, incident scope). Gives **non-repudiation** (STRIDE-**Repudiation**) for a manual evidence-injection path, consistent with the fail-closed audit pattern used for rule changes (`06`/`09 §6`).
5. **Incident metadata store.** Re: the analyst's question in Issue #4 — for a single-analyst lab, a lightweight local store (SQLite, OQ-3 option b) avoids the `security_events` schema-change protocol (`04 §8`) and keeps incident bookkeeping off the hot detection table. A new `siemhunter.incidents` table is also acceptable (it is an additive DDL, not a change to `security_events`). Either is fine; **do not** add incident columns to `security_events`. Final call: tech-lead.

#### Residual risk and hand-offs

- **Single-token model is the dominant residual risk (accepted for v0.1/v0.2).** Per `09 §3.4`, all callers share one token and one trust level. Incident isolation (Q-S5) is therefore an **API-layer convenience boundary, not a security boundary** — any token holder using the raw `/v1/query` operator endpoint can read all data, including incident-only uploads. This is acceptable **only** under the documented single-analyst assumption. If two trust levels ever exist, this becomes a finding and needs an ADR before deploy (as `09 §3.4` already states).
- **Host compromise remains game-over (unchanged from `14 §8`).** Nothing in this sprint changes that; the upload path does not touch the forwarder certificate.
- **Defer to threat-modeler:** a focused **STRIDE pass on the new upload surface** (the net-new, Vector-bypassing TB1 ingest path). Specifically: parser exploit chains for each accepted format (EVTX/zip/gz), the decompression-bomb and field-cardinality DoS vectors, and whether the upload endpoint warrants its own finding number alongside findings #2/#4/#7. The Wave 1C note in §7 already routes this correctly.
- **Defer to iam-engineer:** (1) confirm the server-assigned ProvenanceTag scheme meets the spoof-prevention contract in `03 §2.1` (the plan already routes this); (2) own the **incident-scope authorization** design and the decision on whether v0.2 needs the multi-tenant RBAC that would turn Q-S5's convenience boundary into a real one.

#### Offer — ADR

Two decisions here are significant enough to capture as ADRs (Architecture Decision Records — Context / Decision / Consequences) so they are defensible later: **(A)** "End-user search uses a dedicated `/v1/search` structured endpoint; raw `/v1/query` is operator-only" (Q-S7/Q-S8), and **(B)** "Incident isolation is an API-layer predicate, not a DB-enforced boundary, under the single-token model" (Q-S5). If tech-lead wants, I will write these to `docs/adr/` before Wave 2 begins.

---

## 6. Proposed Sprint Sequencing

Work is organized into three waves. Wave 1 items are blockers for all other work. Wave 2 items can begin once Wave 1 is merged. Wave 3 items can begin in parallel once their specific Wave 2 dependencies are met.

### Wave 1 — Foundation (sprint blockers)

These items must be complete before most other work can proceed. They can be built in parallel with each other.

| Item | Description | Parallel? |
|------|-------------|-----------|
| 1A. Timestamp utility (#7) | Create `formatTimestamp.ts` and replace all existing `formatTime()` calls | Yes — independent |
| 1B. Shared `EventDetailPanel` (#8) | Extract from `EventsPage.tsx`, add EventID descriptions, add pivot links | Yes — independent |
| 1C. Security-architect review (§5) | Finalize ClickHouse controls for upload and search before any backend work begins | Yes — blocks 2B and 2D |
| 1D. Incident data model (#4) | Design the incident storage approach and create the backend incidents router | Yes — blocks 2B and 2C |

### Wave 2 — Core Features

These items begin once their Wave 1 dependencies are met. Several can be parallelized across team members.

| Item | Description | Depends on |
|------|-------------|------------|
| 2A. Claude chatbar (#2) | Build `ClaudeChatbar` shared component and integrate into all pages | 1A (timestamps) |
| 2B. File upload endpoint + IngestionPage zone (#1) | Backend upload endpoint + frontend `UploadZone` component | 1C (security review), 1D (incident model) |
| 2C. Incident Tracker pages (#4) | `IncidentsPage`, `IncidentDetailPage`, `IncidentContext`, sidebar selector | 1D (data model) |
| 2D. Global search bar (#6) | `GlobalSearchBar`, search result panel, parameterized query wiring | 1B (drill-down), 1C (security review) |
| 2E. Category Dashboard (#5) | `CategoryDashboardPage`, `CategoryCard`, category filter definitions | 1A (timestamps), 1B (drill-down) |

### Wave 3 — Correlation Graph and Polish

These items build on Wave 2 and can be parallelized.

| Item | Description | Depends on |
|------|-------------|------------|
| 3A. Correlation Graph (#3) | `CorrelationPage`, `CorrelationGraph` ECharts component | 1A, 1B, 2C (incident scope filter) |
| 3B. Chatbar integration sweep (#2 finish) | Add `ClaudeChatbar` to all new Wave 2 and 3 pages | 2A, all Wave 2 pages |
| 3C. Test coverage | Vitest unit tests for all new components, pytest for new API endpoints | All Wave 2 items |
| 3D. Cross-browser and accessibility pass | Keyboard navigation, ARIA labels, focus management on panels | All Wave 2 items |

---

## 7. Agent Delegation Recommendations for Tech-Lead

The following table maps each sprint work item to the recommended subagent from the bench. Tech-lead reviews and may adjust assignments before delegation.

| Work item | Recommended agent(s) | Rationale |
|-----------|---------------------|-----------|
| Wave 1A — Timestamp utility (#7) | `implementer` | Single-spec utility function with clear input/output contract; no coordination needed. |
| Wave 1B — Shared EventDetailPanel (#8) | `implementer` | Extract-and-extend refactor of an existing component with a clear spec; single-owner work. |
| Wave 1C — Security review of ClickHouse upload and search (§5) | `security-architect` | Already engaged for this section; owns Q-S1 through Q-S10 and the Findings and Controls subsection. Also flag to `threat-modeler` for STRIDE on the new upload surface (new unauthenticated-content ingest path warrants a focused STRIDE pass). |
| Wave 1D — Incident data model (#4 backend) | `tech-lead` (orchestrates) → `implementer` (builds) | The incident model decision (ClickHouse table vs. SQLite vs. JSON store) has downstream consequences for multiple agents; `tech-lead` owns sequencing the decision and its dependent gates, and `implementer` builds the chosen model once resolved. |
| Wave 2A — Claude chatbar (#2) | `implementer` | Single-component build with a clear spec and an existing API endpoint to wire to. |
| Wave 2B — File upload endpoint + UI (#1) | `tech-lead` (orchestrates) → `implementer` (builds) + `devops-engineer` | The upload path crosses the frontend (UploadZone component), API (new endpoint), normalization service (new file parser dispatch), and potentially Docker Compose (file size env vars, temp storage for upload processing). `tech-lead` sequences the end-to-end build across services; `implementer` builds each piece; `devops-engineer` handles any Compose or container-level changes needed for the upload staging path. `iam-engineer` should review the ProvenanceTag assignment logic for uploaded files to confirm it meets the spoof-prevention requirement from `instructions/03-data-ingestion-spec.md §2.1`. |
| Wave 2C — Incident Tracker pages (#4 frontend) | `implementer` | Once the data model from 1D is settled, this is standard CRUD page work with a clear spec. |
| Wave 2D — Global search bar (#6) | `implementer` + `security-architect` sign-off | `implementer` builds the component using the parameterized query approach; `security-architect` must sign off on the SQL construction approach (Q-S7, Q-S8) before the PR is merged. |
| Wave 2E — Category Dashboard (#5) | `implementer` + `detection-engineer` input | `implementer` builds the page; `detection-engineer` must validate the category EventID filter lists against the canonical field table in `instructions/04-normalization-and-schema.md §5` to confirm the queries will return results (no silent-zero-result risk from type mismatches). |
| Wave 3A — Correlation Graph (#3) | `implementer` | ECharts graph series work within a single page; self-contained once the query data shape is known. |
| Wave 3B — Chatbar integration sweep (#2 finish) | `implementer` | Mechanical integration of `ClaudeChatbar` into all new pages once 2A is done. |
| Wave 3C — Test coverage | `test-engineer` | Write Vitest component tests for all new frontend components and pytest for all new FastAPI endpoints. `test-engineer` should treat each numbered acceptance criterion in §4 as a candidate test case. |
| Wave 3D — Accessibility and cross-browser pass | `code-reviewer` | Final review pass for ARIA, keyboard navigation, and focus management across all new interactive surfaces (upload zone, incident selector, correlation graph, drill-down panels, chatbar). |
| Post-sprint — Docs update | `docs-maintainer` | Update `ARCHITECTURE.md` with new routes and components; update `API.md` with new endpoints; update `DASHBOARD.md` with new page descriptions. |

---

## 8. Risks, Open Questions, and Assumptions

### Open Questions (require product/user decision before implementation)

| ID | Question | Blocks |
|----|----------|--------|
| OQ-1 | Does EVTX binary parsing need to work in this sprint? The EVTX format is a structured binary format requiring a dedicated parser library (e.g., `python-evtx`). If yes, this adds a new Python dependency to the normalization service and extends Wave 2B significantly. If no, the frontend upload zone shows a clear message directing the analyst to convert EVTX files to JSON (via `EvtxECmd` or similar) before uploading. | Wave 2B scope and timeline |
| OQ-2 | For incident-scoped uploads: when an incident is closed or archived, do the associated events get deleted from `security_events`, remain forever, or follow the standard TTL? This is a data lifecycle decision with ClickHouse TTL implications. | Wave 1D data model |
| OQ-3 | Where does incident metadata live? Options: (a) a new `siemhunter.incidents` ClickHouse table — consistent with existing storage but requires a schema DDL addition; (b) a local SQLite file — simpler, no ClickHouse schema change, but adds a new file dependency; (c) in-memory only (lost on container restart) — simplest but not durable. For a home-lab/single-analyst tool, (b) may be the right tradeoff. | Wave 1D, Wave 2C |
| OQ-4 | Should the EST offset display adjust for Daylight Saving Time (becoming EDT in summer)? EST is fixed at UTC-5; Eastern Time adjusts between UTC-5 and UTC-4. The simpler implementation uses a fixed "-5" label; the more accurate implementation requires DST-aware time zone handling. | Wave 1A |
| OQ-5 | Should the Claude chatbar pass the current page name or active incident ID as context to `/v1/ai/summary`, so the narrative can be scoped? If yes, the `ai_summary` endpoint needs a new optional query parameter and additional ClickHouse query branching. If no, the chatbar shows the same global summary on every page. | Wave 2A; potentially Wave 1 if endpoint changes are needed |
| OQ-6 | What is the authoritative source for EventID descriptions shown in the drill-down panel? Options: (a) a static lookup table bundled in the frontend (covers the most common ~200 Windows EventIDs); (b) a call to an external reference (requires network access from the browser, which may not be available in air-gapped deployments); (c) omit EventID descriptions from this sprint. Option (a) is recommended but needs a curated EventID list. | Wave 1B |
| OQ-7 | Is ECharts graph series sufficient for the correlation graph, or does the visual requirement ("BloodHound style") require a force-directed graph library with physics simulation (e.g., `react-force-graph`, `vis-network`)? ECharts supports a `graph` series with force layout but it is less interactive than dedicated graph visualization libraries. This is a must-have vs. stretch decision. | Wave 3A scope |

### Assumptions

- The existing bearer-token single-tenant auth model (`instructions/09-security-and-iam.md §3.4`) is not changed in this sprint. All new endpoints use the same `verify_token` dependency.
- The ECharts library (`echarts-for-react`) already installed is used for all new charts and graphs unless OQ-7 is resolved otherwise.
- The React Router 7 and TanStack Query patterns already in use are continued for all new pages and data fetching.
- All new API endpoints follow the `/v1/` prefix convention and return structured JSON error responses consistent with existing routers.
- The `services/normalization/` layer can be extended to accept uploaded file content without a full Docker Compose restructure.
- The `drop/` directory visible in the repo (`.gitkeep` present) is the intended staging area for forensic artifact drops, consistent with `instructions/03-data-ingestion-spec.md §1`. The upload endpoint may drop files here for pickup by the normalization service.

### Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| EVTX binary parsing scope creep (OQ-1) | High | Sprint timeline slippage on Wave 2B | Decide OQ-1 before Wave 2B begins; scope to JSON-only upload if EVTX is deferred |
| Security-architect review delays Wave 2B and 2D | Medium | Upload and search features blocked | Begin Wave 2B and 2D design work (no code) in parallel with §5 review; freeze implementation on those items until sign-off |
| ECharts graph series inadequate for correlation graph (OQ-7) | Medium | Wave 3A requires a new library dependency | Prototype ECharts graph series in Wave 2 as a spike; decide OQ-7 before Wave 3A implementation |
| Incident data model choice creates schema migration work (OQ-3) | Medium | Delays Wave 1D | Decide OQ-3 at sprint kickoff; SQLite avoids ClickHouse schema change protocol overhead |
| Timestamp utility breaks existing tests | Low | Wave 1A creates regressions | `test-engineer` runs existing Vitest suite immediately after Wave 1A merge; failing tests are a blocker |
| `UnmappedFields` XSS risk in rendered drill-down content (Q-S6) | Medium | Stored XSS via uploaded log file content | `code-reviewer` must confirm all `UnmappedFields` and `CommandLine` rendering uses React's default JSX escaping (not `dangerouslySetInnerHTML`); the existing `EventDetailPanel` renders these as `<pre>` / text nodes which is safe |

---

## 9. Sprint Definition of Done

The sprint is complete and v0.2.0 is ready for release when all of the following are true:

1. All eight GitHub feature-request issues (#1–#8) have a corresponding implementation where every numbered acceptance criterion in §4 has a passing automated test (Vitest for frontend, pytest for backend) or a documented manual verification step where automation is not feasible.
2. The shared `formatTimestamp` utility is in use on every timestamp displayed in the application and the old `formatTime()` helpers have been removed.
3. The shared `ClaudeChatbar` component is present on every analysis view.
4. The shared `EventDetailPanel` component is used on all event-displaying pages.
5. The security-architect has completed §5 ("Findings and Controls") and any blocking findings from that review have been addressed.
6. All new FastAPI endpoints are covered by pytest integration tests that verify: authentication required (401 without token), input validation (400 on bad input), expected response shape, and at least one happy-path case.
7. The `code-reviewer` has confirmed no raw SQL string concatenation in the frontend search implementation (parameterized queries only).
8. The `docs-maintainer` has updated `ARCHITECTURE.md`, `API.md`, and `DASHBOARD.md` to reflect all new routes, components, and endpoints.
9. The existing CI test suite (Vitest and any existing pytest) passes without regression.
10. Tech-lead has reviewed and approved the final PR.

---

## Handoff

This document next goes to **security-architect** to complete §5 ("Findings and Controls") with specific findings and recommended controls for the ClickHouse upload path (Q-S1 through Q-S6) and the search query construction path (Q-S7 through Q-S10). The security-architect's findings may introduce additional acceptance criteria or modify the scope of Wave 2B and 2D before those items are delegated.

After the security-architect completes §5, the document goes to **tech-lead** for sprint approval and final agent delegation. Tech-lead's approval converts this planning artifact into the active build specification for SDLC.

> **Status — 2026-06-20:** ✅ security-architect §5 complete · ✅ tech-lead reviewed — **APPROVED WITH CONDITIONS** (see below). This document is now the active build spec for **v0.2.0**, contingent on Conditions 1–6 being met at sprint kickoff.

---

# Tech-Lead Review & Approval

**Reviewer:** tech-lead · **Date:** 2026-06-20 · **Scope:** all sections + security-architect §5

## 1. Verdict

**APPROVED WITH CONDITIONS.**

The plan is well-grounded — every load-bearing claim was verified against the actual tree: the `EventDetailPanel` and `formatTime()` extraction targets exist in `frontend/src/pages/EventsPage.tsx`; `query.py` has exactly the SELECT-only / IMDS / row-cap / `{name:type}` model described; `ai_summary.py` provably sends only aggregated stats; the `request` helper in `client.ts` hardcodes `Content-Type: application/json`, confirming a new multipart path is genuinely required; the schema columns all match. The security-architect's §5 is decisive and every citation (TB1/TB2, threat-model findings #7/#9, 09 §3.4 single-token) is accurate. The conditions below are about **scope realism for a "rapid" sprint** and **agent-assignment precision**, not correctness of the analysis.

## 2. Conditions / Required Changes (SDLC must address before/at Wave 1 kickoff)

1. **Cross-service orchestration ownership.** Per the requestor's clarification, the orchestrator role is **`tech-lead`**, not a separate `implementation-lead` agent. `tech-lead` owns the delegation plan and the gate-to-gate sequencing; the **main conversation enacts that plan at runtime** (a subagent cannot spawn other subagents); and **`implementer`** does the hands-on build within each step. All former `implementation-lead` assignments (Waves 1D, 2B) are reassigned on this model — see the "Orchestration model" note after this review.
2. **The security-architect's entire MUST list (items 1–11) is sprint-blocking and must be wired as explicit merge-gates**, not advisory. MUST 1–7 gate the Wave 2B upload PR; MUST 8–11 gate the Wave 2D search PR. No upload or search PR merges without `security-architect` + `code-reviewer` sign-off confirming the named `curl`-level tests pass. Add this to §9 DoD.
3. **Lock the MVP line (see §5) before Wave 1 starts.** "Resolve all 8 issues in one rapid sprint" is not realistic at the written depth (EVTX binary parsing + a BloodHound-grade graph + 11 server-side controls + full coverage). Defer stretch items explicitly so the timeline is honest.
4. **Resolve the four blocking open questions (OQ-1, OQ-3, OQ-6, OQ-7) at kickoff** — they gate Wave 1/early Wave 2. OQ-2, OQ-4, OQ-5 can be defaulted.
5. **Write the two ADRs the security-architect offered — accept the offer.** Author: `security-architect`; review: `tech-lead`; land in `docs/adr/` **before** Wave 2B/2D code starts.
6. **Several acceptance criteria are not testable as written and must be tightened** before `test-engineer` can gate them (see §7).

## 3. Security Gating + ADR Decision

- **MUST list = sprint-blocking: CONFIRMED.** Treat MUST 1–11 as security acceptance criteria. Upload controls (1–7) → Wave 2B; search controls (8–11) → Wave 2D. Each MUST item ships with a `curl`/bypass-the-browser test — `test-engineer` writes them as pytest integration tests, `code-reviewer` confirms at merge. "Client-side validation is UX, not security; every control is server-side or it doesn't count" — non-negotiable.
- **ADR offer: ACCEPTED.** Both authored by **`security-architect`**, reviewed by `tech-lead`, landed **before** Wave 2B/2D:
  - **ADR-A:** End-user search uses a dedicated `POST /v1/search` structured endpoint; raw `POST /v1/query` stays operator-only and is never wired to the global search bar. (Q-S7/Q-S8)
  - **ADR-B:** Incident isolation is an API-layer predicate, not a DB-enforced boundary, under the single-token model. (Q-S5) — `iam-engineer` co-signs (owns the residual-risk hand-off).

## 4. Confirmed / Revised Delegation Plan (wave-by-wave, ordered)

Legend: **entry gate** = what must be true to start; **exit gate** = what must be true to merge.

### Wave 1 — Foundation (all four run in PARALLEL)

| Step | Owning agent(s) | Entry gate | Exit gate |
|------|-----------------|-----------|-----------|
| **1A** Timestamp util `formatTimestamp.ts` (#7) | `implementer` | OQ-4 defaulted (fixed `-5 EST`, no DST) | Unit test matches exact format string; Vitest suite green; old `formatTime()` removed from the 4 pages |
| **1B** Extract shared `EventDetailPanel` (#8) | `implementer` | OQ-6 decided (static bundled lookup) | Renders fields + `UnmappedFields` `<pre>` (no `dangerouslySetInnerHTML`); EventID descriptions + pivot links present |
| **1C** Security review §5 + STRIDE pass | `security-architect` (lead) + `threat-modeler` (STRIDE on the Vector-bypassing upload surface) | — (drafted) | §5 MUST/SHOULD final; `threat-modeler` confirms parser/zip/EVTX exploit chains; **blocks 2B + 2D** |
| **1D** Incident data-model decision + incidents router skeleton (#4) | `tech-lead` (orchestrates) → `implementer` (build) + `iam-engineer` (scope authz) | OQ-2 + OQ-3 decided (recommend SQLite) | New `incidents.py` router scaffolded; `iam-engineer` signs the server-enforced scope-predicate contract; **blocks 2B + 2C** |

> `iam-engineer` owns (a) confirming the server-assigned `ProvenanceTag` scheme meets `03 §2.1` spoof-prevention, and (b) the **incident-scope authorization** design (MUST 11).

### Wave 2 — Core Features (start when named Wave 1 deps merge)

| Step | Owning agent(s) | Entry gate | Exit gate |
|------|-----------------|-----------|-----------|
| **2A** `ClaudeChatbar` shared component (#2) | `implementer` | 1A merged | Reuses `/v1/ai/summary`; "AI unavailable" 503 state preserved; collapse persists via `sessionStorage` |
| **2B** Upload endpoint + `UploadZone`/`UploadStatusCard` (#1) | `tech-lead` (orchestrates) → `implementer` (builds FE+API+normalization) + `devops-engineer` (Compose/staging/ClickHouse profile) + `iam-engineer` (ProvenanceTag review) | 1C **and** 1D merged; ADR-A/B landed | **MUST 1–7 proven via curl tests**; `security-architect` + `code-reviewer` sign-off; `devops-engineer` lands upload staging path + write-capable normalization role |
| **2C** Incident Tracker pages + `IncidentContext` (#4 FE) | `implementer` | 1D merged | CRUD against `incidents.py`; selector persists per session; scope indicator wired |
| **2D** `GlobalSearchBar` + `POST /v1/search` (#6) | `implementer` (build) + `security-architect` (sign-off) | 1B **and** 1C merged; ADR-A landed | **MUST 8–11 proven**; no `sql` field reaches the client path; `code-reviewer` confirms zero SQL string-concat |
| **2E** Category Dashboard (#5) | `implementer` + `detection-engineer` (validate filter lists vs `04 §5`) | 1A + 1B merged | `detection-engineer` confirms EventID/Channel filters return rows (no silent-zero); drill-down wired to 1B panel |

### Wave 3 — Graph, Sweep, Test, Review

| Step | Owning agent(s) | Entry gate | Exit gate |
|------|-----------------|-----------|-----------|
| **3A** Correlation Graph (#3) — **STRETCH, see §5** | `implementer` | 1A, 1B, 2C; OQ-7 decided | ECharts `graph` series renders; node/edge click opens 1B panel; node-cap warning; empty-window no-crash |
| **3B** Chatbar integration sweep (#2 finish) | `implementer` | 2A + all Wave 2 pages | `ClaudeChatbar` on every analysis view |
| **3C** Test coverage (Vitest + pytest) | `test-engineer` | Each Wave 2 item merged | Each §4 acceptance criterion → a test or documented manual step; auth/validation/shape/happy-path on every new endpoint |
| **3D** A11y + cross-browser pass | `code-reviewer` | All Wave 2 merged | Keyboard nav (upload zone, selector, panels, chatbar), ARIA, focus mgmt, **XSS confirmation (MUST 7)** |
| **Docs** API.md / ARCHITECTURE.md / DASHBOARD.md | `docs-maintainer` | After 3C | New endpoints, routes, components documented; ADRs cross-linked |

**Parallelizable:** all of Wave 1 (1A/1B/1C/1D); within Wave 2, 2A/2C/2E alongside each other; 2B and 2D are the security-gated long poles — staff them first once 1C/1D clear. 3A/3B/3C/3D parallelize once their Wave 2 deps merge.

**`devops-engineer`** (at 2B) owns the upload staging mechanism, Compose env-var/size-limit wiring, and the **SHOULD-1 function-restricted ClickHouse profile** (disable `url`/`remote`/`file`/`s3` in `users.xml`) — confirmed net-new (no such profile exists today), plus a separate write-capable role for the normalization insert path.

## 5. MVP Line — ships in the rapid sprint vs. deferred

**Ships (MVP):** #7 timestamp util · #8 shared drill-down panel · #2 Claude chatbar (reuses existing endpoint) · #1 upload **JSON/JSONL/CSV/log/txt only** with **all 11 MUST controls** · #4 incident tracker on **SQLite** with server-enforced scope predicate · #6 global search via **`POST /v1/search`** · #5 category dashboard with `detection-engineer`-validated filters.

**Deferred (stretch — cut to protect the timeline):**
- **EVTX binary parsing (OQ-1) — DEFER.** Adds `python-evtx`, a new parser exploit surface, and major 2B work. MVP shows "convert to JSON first" guidance (AC #7). Biggest scope risk; cutting it is what makes "rapid" honest.
- **#3 correlation graph (OQ-7) — STRETCH.** Ship an ECharts `graph`-series MVP if time allows; a BloodHound-grade force-directed lib is a follow-up. If the timeline tightens, cut #3 to v0.2.1 — least foundational, most dependent.
- **Context-aware AI summaries (OQ-5)** — out of scope; no `?context=` param this sprint (re-opens the prompt-injection boundary).
- **`.zip`/`.gz` archive upload** — if accepted, the decompression-ratio cap (MUST 3) is mandatory; if constrained, defer archives, plain files only in MVP.

**De-risking fact:** the API binds `127.0.0.1` only (`services/api/src/main.py`) and is single-token single-tenant — the threat model is "the token-holder is the adversary," not "the internet is." That keeps incident isolation legitimately an API-convenience boundary (ADR-B) for v0.2 and supports cutting stretch items without a security regression.

## 6. Pre-Wave-1 Decisions That Must Be Locked

| OQ | Decision needed | Recommendation |
|----|-----------------|----------------|
| **OQ-1 (EVTX)** — blocks 2B scope | In or out? | **OUT for MVP.** JSON-first; show convert guidance. |
| **OQ-3 (incident store)** — blocks 1D | ClickHouse table vs SQLite vs in-memory | **SQLite.** Avoids `04 §8` schema-change protocol; keeps incident bookkeeping off the hot detection table. Never add incident columns to `security_events`. |
| **OQ-6 (EventID descriptions)** — blocks 1B | Static bundle vs external vs omit | **Static bundled lookup** (`eventIdDescriptions.ts`, ~200 common Windows IDs). Air-gap safe. |
| **OQ-7 (graph library)** — blocks 3A | ECharts vs dedicated graph lib | **ECharts `graph` series for MVP**, dedicated lib deferred. |
| **OQ-2 (incident TTL)** — defaultable | Delete/keep/standard TTL on close | Standard `security_events` TTL; incident metadata in SQLite persists. |
| **OQ-4 (DST)** — defaultable | Fixed EST vs DST-aware | Fixed `-5 EST` label for MVP (matches issue text). |
| **OQ-5 (AI context)** — defaultable | Add `?context=` param | No — keep the aggregated-stats boundary intact. |
| **Upload max size** | Confirm numbers | Accept security-architect defaults: **100 MB / 1M events / 64 KB per field / 256 KB UnmappedFields / 100:1 decompression**, all `*_MAX_*` env-configurable. |

## 7. Gaps / Risks / Non-Testable Criteria

- **Tighten before `test-engineer` gates:** #3 AC1/AC7 (subjective "BloodHound style") → restate as concrete assertions (node count, color-by-type, click opens panel). #2 AC5 ("may be less relevant… does not crash") → "renders without error and shows the global summary." #8 AC3 → bind to the static lookup so a test can assert exact text. Until reworded, mark these "manual verification" in §9.
- **`QueryResult` row-click (#8 AC5):** query results are untyped (`query.py` returns `dict[str,Any]`); the panel must defensively match columns to the `SecurityEvent` shape and degrade gracefully. Add an explicit AC for the "row doesn't match the shape" case.
- **Sequencing:** Wave 1 blockers correctly identified and ordered; only fix is the orchestration-ownership clarification (Condition 1).
- **Residual risk:** incident isolation is not a security boundary under the single token (ADR-B documents this). Acceptable for v0.2; becomes an ADR-before-deploy trigger the moment a second trust level exists (09 §3.4) — `iam-engineer` owns that trigger.

## 8. Sign-off Note to SDLC (for v0.2.0)

Approved to become the active build spec once Conditions 1–6 are met. Start by locking OQ-1/OQ-3/OQ-6/OQ-7 and landing ADR-A/ADR-B (`security-architect`). Then dispatch all four Wave 1 items in parallel. Hold all upload (2B) and search (2D) implementation until §5 / `threat-modeler` clears 1C — the 11 MUST controls are merge-gates with named `curl` tests, enforced by `security-architect` + `code-reviewer`. Build the security-gated long poles (2B, 2D) first once unblocked; 2A/2C/2E alongside. Treat EVTX and the BloodHound-grade graph as cut/stretch — ship the JSON-upload + ECharts-graph MVP. `test-engineer` and `code-reviewer` gate every wave; `docs-maintainer` closes out API.md / ARCHITECTURE.md / DASHBOARD.md before the v0.2.0 tag.

---

### Orchestration model (per requestor clarification)

The orchestrator is **`tech-lead`** — it owns the delegation plan and the gate-to-gate sequencing (e.g. "hold 2B until 1C clears"). Because `tech-lead` plans rather than executes, and because a subagent cannot invoke other subagents, the **main conversation enacts `tech-lead`'s plan at runtime**, dispatching each step. The hands-on build within each step is done by **`implementer`** (with `devops-engineer`, `iam-engineer`, `security-architect`, and others contributing per the tables). **There is no separate `implementation-lead` role in this plan** — that responsibility splits into "`tech-lead` orchestrates → `implementer` builds." The delegation tables in §4 and §7 reflect this.
