# FR #9 — Render the AI Analysis chatbar once globally, not per-page

**Priority:** P2 · **Size:** S · **Labels:** ux, refactor, enhancement

## Problem / motivation
`ClaudeChatbar.tsx` is imported and rendered separately inside `OverviewPage`,
`EventsPage`, `DetectionsPage`, `IngestionPage`, `CategoryDashboardPage`,
`IncidentsPage`, `IncidentDetailPage`, and `CorrelationPage`. It is **not** rendered in
`PageLayout.tsx`. Consequences:

- The Health page (`/health`) has no AI Analysis panel at all — an inconsistent surface.
- Every page mount unmounts/remounts the panel (it relies on `sessionStorage` to survive
  this), wasting the `useAiSummary` poll and re-reading storage on each navigation.
- Future pages must remember to add it manually — easy to forget (as Health shows).

## Proposed solution
Render `<ClaudeChatbar />` exactly once in `PageLayout.tsx` (e.g. after `<main>`), and
remove the eight per-page imports/renders. The panel is `fixed`-positioned, so it does
not need to live inside page content.

## Acceptance criteria
1. Given any route (including `/health`), when the page renders, then exactly one AI
   Analysis toggle is visible bottom-right.
2. Given I open the panel and navigate to another page, when the new page mounts, then the
   panel stays open without a flicker and does not re-fetch beyond the normal 30s poll.
3. `ClaudeChatbar` is imported only in `PageLayout.tsx`; no page component imports it.
4. There is never more than one chatbar in the DOM at a time (test asserts a single
   `[aria-label="Toggle AI Analysis panel"]`).
