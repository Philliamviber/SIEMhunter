# FR #23 — Add a global toast/notification system and consistent error surfacing

**Priority:** P2 · **Size:** M · **Labels:** ux, accessibility, enhancement

## Problem / motivation
Errors and successes are handled ad hoc per component: inline red boxes ("Failed to load
incidents." in `IncidentsPage`, "Failed to load incident." in `IncidentDetailPage`), a silent
upload result card, and no feedback at all for incident status changes (FR #18) or AI errors
beyond a muted line. There is no unified, non-blocking notification surface, so transient
successes (upload done, status changed, note saved) and background failures (a poll 401) are
easy to miss. A 401 from an expired session currently surfaces only as a generic query error,
not a re-auth prompt (ties to FR #10).

## Proposed solution
Introduce a single toast/notification provider used app-wide for success/error/info, plus a
consistent pattern for query errors with a Retry affordance. Route 401s to the login flow.

## Acceptance criteria
1. Given any mutation succeeds (upload, incident create/status, note), when it completes, then
   a success toast appears and auto-dismisses.
2. Given a background query fails, when the error occurs, then a non-blocking notification
   with Retry appears (not just a static red box).
3. Given a 401 from any request, when it returns, then the user is sent to login with a
   "session expired" message.
4. Toasts are screen-reader announced (`aria-live`) and dismissible by keyboard.
