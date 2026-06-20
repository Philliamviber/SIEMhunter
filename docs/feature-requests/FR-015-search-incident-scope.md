# FR #15 — Apply the active incident scope to global search (and show that scope in the bar)

**Priority:** P1 · **Size:** S · **Labels:** security, ux, bug

## Problem / motivation
`IncidentContext.tsx`'s own doc comment claims GlobalSearchBar "scopes search results to
the incident (`incident_id` in request)," and `SearchRequest` includes
`incident_id?: string`. But `GlobalSearchBar.tsx` never calls `useIncidentContext()` and
never passes `incident_id` to `search.mutate(...)`. So when an analyst has set an incident
scope (shown in the sidebar), global search still returns global results — a silent scope
mismatch that could cause an analyst to draw conclusions on out-of-scope data.

> Verified against source: `GlobalSearchBar.tsx` contains no reference to
> `useIncidentContext`, `incident_id`, or `activeIncident`.

## Proposed solution
Read `activeIncidentId` in `GlobalSearchBar` and include it in the search request when set.
Show a visible "Scoped to: &lt;incident&gt;" chip in or beside the search bar, with a
one-click way to search globally instead.

## Acceptance criteria
1. Given an active incident scope, when I search, then the request includes `incident_id`
   and results are scoped to that incident.
2. Given an active scope, when the search bar renders, then a visible chip indicates the
   scope.
3. Given a scope is active, when I click "Search all", then a single search ignores the
   scope without clearing it.
4. Given no active scope, when I search, then behavior is unchanged (global).
