# FR #16 — Add empty/zero-state, persistence, and export to global search results

**Priority:** P2 · **Size:** M · **Labels:** ux, enhancement

## Problem / motivation
`GlobalSearchBar.tsx` only renders a results panel after a search runs. Before that there
is no guidance (no example queries, no recent searches). Results live only in the
`useSearch` mutation's in-memory `data`; navigating away or changing the field type
(`search.reset()` on field change) wipes them. For a SIEM, analysts routinely need to
export the matched events (CSV/JSON) for tickets/IR notes — there is no export. Result rows
also have no inline copy for IOC values (IP/hash/host).

## Proposed solution
- Add a pre-search helper (recent searches and/or example placeholders per field type).
- Persist the last result across navigation (or at least warn before it is discarded on
  field-type change).
- Add Export (CSV + JSON) of the current result set, respecting the 10,000-row truncation
  note already shown.
- Add copy-to-clipboard on IOC cells.

## Acceptance criteria
1. Given no search yet, when the bar is focused, then I see example formats and/or my recent
   searches.
2. Given results are shown, when I navigate to another page and back, then results are still
   present (or I was warned before they were cleared).
3. Given results exist, when I click Export, then I can download CSV and JSON of the rows,
   with a note when results were truncated at 10,000.
4. Given a result row, when I click a host/IP/hash, then its value is copied to the
   clipboard with a toast.
