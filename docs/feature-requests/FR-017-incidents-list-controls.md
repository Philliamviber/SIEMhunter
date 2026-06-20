# FR #17 — Add filtering, sorting, search, and an open-only toggle to the Incidents list

**Priority:** P2 · **Size:** M · **Labels:** ux, enhancement

## Problem / motivation
`IncidentsPage.tsx` renders all incidents in a `DataTable` with no status filter, no search,
and no sort controls. The sidebar `IncidentSelector` only lists `status === 'open'`
incidents, so closed/archived incidents are reachable only by scrolling the full table. As
incident count grows this becomes unusable, and there is no way to quickly find "my open
criticals." There is also no pagination on this table.

## Proposed solution
Add a filter/search row above the table: free-text name search, status filter
(open/closed/archived/all), severity filter, and column sorting (created, severity,
event_count). Default to showing open incidents first. Add pagination if the count is large.

## Acceptance criteria
1. Given many incidents, when I type in the search box, then the table filters by name in
   real time.
2. Given the status filter, when I pick "Open", then only open incidents show; "All" shows
   everything.
3. Given the table, when I click a sortable column header, then rows sort by it (asc/desc
   toggle).
4. Given the filters, when I reload or share the URL, then the active filters are preserved
   in the query string.
