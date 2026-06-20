# Feature Request Backlog — post-v2.0 (UX wave)

These requests were raised from a tech-lead UX review of the v2.0 front-end (issues
#1–#8, see [feature-request-resolution-v2.0.md](../feature-request-resolution-v2.0.md)).
The review read the shipped `frontend/src/` source directly and picked apart the new
components for UX gaps, missing states, accessibility, and error handling — with security
kept in mind throughout (this is a SIEM; analyst trust, audit, and data handling matter).

Numbering continues from #8. Each file is written so it can be filed 1:1 as a GitHub
issue. Two items (**#11**, **#15**) are shipped-but-broken bugs verified against source,
not just enhancements.

## Backlog

| FR | Title | Priority | Size | Type | Primary file(s) |
|---:|-------|:--------:|:----:|------|-----------------|
| [#9](FR-009-global-ai-chatbar.md) | Render the AI Analysis chatbar once globally | P2 | S | refactor | ClaudeChatbar.tsx, PageLayout.tsx |
| [#10](FR-010-secure-local-login.md) | Secure local username/password login gate | **P1** | L | security | TokenGate.tsx, client.ts, App.tsx |
| [#11](FR-011-fix-pivot-links.md) | Fix dead EventDetailPanel pivot links | **P1** | M | bug | EventDetailPanel.tsx, EventsPage.tsx |
| [#12](FR-012-upload-progress.md) | Upload progress, cancel, multi-file, refresh | P2 | M | enhancement | UploadZone.tsx, IngestionPage.tsx |
| [#13](FR-013-correlation-controls.md) | Correlation graph tooltips, search, reset | P2 | M | enhancement | CorrelationPage.tsx |
| [#14](FR-014-correlation-panel-stacking.md) | Correlation entity↔event panel stacking | P3 | S | ux | CorrelationPage.tsx |
| [#15](FR-015-search-incident-scope.md) | Apply incident scope to global search | **P1** | S | bug | GlobalSearchBar.tsx |
| [#16](FR-016-search-state-export.md) | Search empty-state, persistence, export | P2 | M | enhancement | GlobalSearchBar.tsx |
| [#17](FR-017-incidents-list-controls.md) | Incidents list filter/sort/search | P2 | M | enhancement | IncidentsPage.tsx |
| [#18](FR-018-incident-status-feedback.md) | Incident status confirm + feedback | P2 | S | ux | IncidentDetailPage.tsx |
| [#19](FR-019-incident-notes-editor.md) | Functional incident Notes editor | P2 | M | enhancement | IncidentDetailPage.tsx |
| [#20](FR-020-incident-selector-a11y.md) | IncidentSelector keyboard/ARIA | P2 | S | accessibility | IncidentSelector.tsx |
| [#21](FR-021-category-drilldown.md) | Category drill-down truncation/refine | P2 | M | enhancement | CategoryDashboardPage.tsx |
| [#22](FR-022-responsive-layout.md) | Responsive/mobile + collapsible sidebar | P3 | M | ux | PageLayout.tsx + panels |
| [#23](FR-023-toast-system.md) | Global toast/notification system | P2 | M | enhancement | app-wide |
| [#24](FR-024-timestamp-timezone.md) | Correct timezone in formatTimestamp | P2 | S | bug | formatTimestamp.ts |
| [#25](FR-025-event-detail-export.md) | EventDetailPanel copy/export | P3 | S | enhancement | EventDetailPanel.tsx |

**Must-fix first:** #10 (no real auth / no logout), #11 (drill-down pivots are dead),
#15 (search silently ignores active incident scope).
