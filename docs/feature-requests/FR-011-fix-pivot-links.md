# FR #11 — Make EventDetailPanel pivot links actually filter the Events page

**Priority:** P1 · **Size:** M · **Labels:** bug, ux, enhancement

## Problem / motivation
`EventDetailPanel.tsx` renders pivot `<Link>`s to `/events?hostname=…`, `/events?user=…`,
`/events?src_ip=…`, `/events?event_id=…` (verified at `EventDetailPanel.tsx:149` etc.).
But `EventsPage.tsx` initializes `form`/`applied` to `{}` (`EventsPage.tsx:54`) and never
imports/reads `useSearchParams`/`useLocation`. Result: clicking any pivot navigates to a
fresh, **unfiltered** Events page — the analyst's intended pivot silently fails. This is
the headline drill-down feature of v2.0 and it is broken end-to-end.

> Verified against source: `EventsPage.tsx` has no `useSearchParams` import; filters start
> as `useState<EventsFilter>({})`.

## Proposed solution
On `EventsPage` mount (and on query-string change), parse URL params (`hostname`, `user`,
`src_ip`, `event_id`, optionally `start`/`end`) into the filter state and run the query.
Align param names between the two files (the panel emits `user` and `src_ip`; confirm the
`EventsFilter` field names map, e.g. `src_ip_addr`).

## Acceptance criteria
1. Given an open event, when I click "All events from this host", then Events opens
   pre-filtered to that hostname and the host field shows the value.
2. Same for the user, source IP, and EventID pivots.
3. Given I edit a filter on the pre-filtered page, when I Apply, then the URL updates to
   reflect active filters (shareable/bookmarkable deep link).
4. Given a pivot link with a param name that does not match an `EventsFilter` key, when the
   page loads, then it is mapped correctly (no silently-dropped filter).
5. Given I land on `/events` with no params, when the page loads, then behavior is
   unchanged (no filter).
