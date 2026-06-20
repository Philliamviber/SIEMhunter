# FR #21 — Surface Category drill-down truncation and add per-category drill error/empty clarity

**Priority:** P2 · **Size:** M · **Labels:** ux, enhancement

## Problem / motivation
`CategoryDashboardPage.tsx` drill-down runs `LIMIT 500` and shows "(limit reached)" only
when `drillEvents.length === 500`. There is no way to load more or refine, and counts on the
cards (which can be far larger than 500) make the gap jarring — a card showing 40,000 events
drills into exactly 500 with a tiny note. Counts and drill use raw `api.query` with
hand-built SQL; on count error a card shows "—" with no explanation. The category SQL filters
are also not incident-scoped despite the app's incident concept.

## Proposed solution
- Add pagination or "Load more" to the drill table, or a clear "Refine in Query Console /
  Events" call-to-action that carries the category filter over.
- Make the truncation note prominent and show "showing 500 of N".
- Give failed counts a tooltip/explanation rather than a bare dash.
- Optionally respect the active incident scope.

## Acceptance criteria
1. Given a category with >500 events, when I drill in, then I see "showing 500 of N" and a
   way to load more or jump to a filtered Events/Query view.
2. Given a count query fails, when the card renders, then the dash has a tooltip/explainer
   ("count unavailable — retry").
3. Given an active incident scope, when I drill a category, then results can optionally be
   scoped to it (clearly indicated).
4. Given the drill returns 0 rows, when it completes, then the empty message distinguishes
   "no matches" from "not yet loaded".
