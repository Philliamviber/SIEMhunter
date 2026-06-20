# Feature Request Resolution — v2.0.0

This document records the disposition of the eight feature requests filed as GitHub
issues (#1–#8) against SIEMhunter. **All eight were delivered in the `2.0.0` release
(2026-06-20).** Each was verified against the actual implementation — not just the
changelog — before its issue was closed.

See [CHANGELOG.md](../CHANGELOG.md) `## [2.0.0]` for the release-level summary.

---

## Summary

| Issue | Request | Status | Primary deliverables |
|------:|---------|:------:|----------------------|
| #1 | Drag-and-drop ingestor | ✅ Completed | `UploadZone.tsx`, `POST /v1/ingestion/upload` |
| #2 | Claude chatbar on every analysis view | ✅ Completed | `ClaudeChatbar.tsx`, `GET /v1/ai/summary` |
| #3 | Visual graphics & event stitching | ✅ Completed | `CorrelationPage.tsx` (ECharts force graph) |
| #4 | Single-incident setting | ✅ Completed | `IncidentsPage.tsx`, `routers/incidents.py`, `db_incidents.py` |
| #5 | Dashboard with event categories | ✅ Completed | `CategoryDashboardPage.tsx` |
| #6 | Rich search queries at the top | ✅ Completed | `GlobalSearchBar.tsx`, `POST /v1/search` |
| #7 | Time synchronization (UTC + EST) | ✅ Completed | `utils/formatTimestamp.ts` |
| #8 | Intelligent drill-down | ✅ Completed | `EventDetailPanel.tsx`, `utils/eventIdDescriptions.ts` |

---

## Per-request detail

### #1 — Drag-and-drop ingestor
> *"log files, evt files, and other unstructured data should be able to get dragged
> and dropped into the SIEM for both into the overall aggregator, and another option
> for individual analysis of the upload only."*

- **Frontend:** `frontend/src/components/UploadZone.tsx` — drag-and-drop widget with
  an explicit scope selector.
- **Backend:** `services/api/src/routers/upload.py` → `POST /v1/ingestion/upload`.
  Accepts `.json`, `.jsonl`, `.csv`, `.log`, `.txt` (max 100 MiB). `mode=global`
  routes to the overall aggregator; `mode=incident` scopes the upload to a single
  incident only — satisfying both halves of the request ("overall aggregator" vs.
  "individual analysis of the upload only").
- Response reports `events_parsed` / `events_written` / `events_unmapped` /
  `error_count` / `status`.

### #2 — Claude chatbar on every analysis view
> *"A core feature of this build is to have claude analysis at every step of the
> ingestion."*

- `frontend/src/components/ClaudeChatbar.tsx` — floating AI Analysis panel reachable
  from any of the 11 pages; survives in-SPA navigation via `sessionStorage`.
- Backed by `GET /v1/ai/summary`, which sends **aggregated statistics only** (event
  counts, detection counts, top rule IDs) to the Claude API — no raw event fields.

### #3 — Visual graphics & event stitching
> *"Think like the sentinel correlation graphs but maybe use node.js or a bloodhound
> style correlator."*

- `frontend/src/pages/CorrelationPage.tsx` — ECharts force-directed graph linking
  Host, User, IP Address, and Process entities derived from `security_events`.
- 200-node frontend cap with truncation warning; four time-range presets (1h/6h/24h/7d);
  click a node → entity side panel → click an event row → `EventDetailPanel`.

### #4 — Single-incident setting
> *"Some kind of incident tracker … the incident creator gets to decide whether to
> allow the incident imports to be specific to only its session's data … OR it can be
> added to the global SIEM section."*

- `frontend/src/pages/IncidentsPage.tsx` + `IncidentDetailPage.tsx`, backed by
  `services/api/src/routers/incidents.py` and `db_incidents.py` (SQLite — analyst
  workspace state, kept separate from ClickHouse event telemetry).
- `POST /v1/incidents`, `GET /v1/incidents`, `GET /v1/incidents/{id}`,
  `PATCH /v1/incidents/{id}/status`.
- File uploads and global search can be scoped to an active incident via
  `IncidentProvider` — directly implementing the "specific to this session vs. global
  SIEM" decision the request asked for.

### #5 — Dashboard with event categories
> *"Drill downs into scan type categories. AD, Network, DNS, network analysis, malware
> analysis, log analysis."*

- `frontend/src/pages/CategoryDashboardPage.tsx` — security-domain drill-down covering
  Active Directory, Network, DNS, Malware Analysis, and Log Analysis.

### #6 — Rich search queries at the top
> *"front end search queries to parse or find unstructured data. Should be able to take
> an IP search, hostname search, username search, TCP port search, etc."*

- `frontend/src/components/GlobalSearchBar.tsx` in the nav bar, backed by
  `POST /v1/search` (`services/api/src/routers/search.py`).
- Supported field types: `IP`, `Hostname`, `Username`, `Port`, `EventID`, `FileHash`,
  `ProcessName` — covering every example named in the request and more. Response
  includes `columns_searched` and a `truncated` flag.

### #7 — Time synchronization
> *"All data must have timestamps in UTC with (EST) in parenthesis. Dates and timestamps
> on all logs are mandatory within all dashboarding."*

- `frontend/src/utils/formatTimestamp.ts` is the single authoritative formatter. It
  renders `YYYY-MM-DD HH:MM:SS UTC (HH:MM:SS EST)` — exactly the requested format.
- EST is a fixed UTC-5 offset (no DST), per decision OQ-4, documented in the source.
- Covered by `frontend/src/utils/__tests__/formatTimestamp.test.ts`.

### #8 — Intelligent drill-down
> *"the output should have intelligent drill down info so you can click in to see much
> more data … the search may be for event ID, but clicking in it should show you event
> ID descriptions and all data expanded."*

- `frontend/src/components/EventDetailPanel.tsx` — slide-in panel showing **all**
  canonical fields, the raw `UnmappedFields` JSON, and one-click pivot links
  (host / user / IP / EventID).
- The exact "event ID descriptions" ask is met via
  `frontend/src/utils/eventIdDescriptions.ts` (`getEventIdDescription`), which renders
  a human-readable **Event Description** row beside the numeric EventID.

---

## Verification method

Each request was checked against shipped source, not the changelog alone:

- #7 verified by reading `formatTimestamp.ts` and confirming the literal
  `UTC (… EST)` output string.
- #8 verified by reading `EventDetailPanel.tsx` and confirming the
  `getEventIdDescription` import and the rendered "Event Description" row.
- #1–#6 verified by confirming both the frontend component and the backend
  router/endpoint exist under `frontend/src/` and `services/api/src/`.

All eight issues were closed as completed on 2026-06-20 with a comment linking to this
document.
