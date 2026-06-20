# FR #13 — Give the Correlation graph node/edge tooltips, search, and reset/zoom controls

**Priority:** P2 · **Size:** M · **Labels:** ux, enhancement

## Problem / motivation
`CorrelationPage.tsx` renders a force graph but: tooltips are enabled
(`tooltip: { trigger: 'item' }`) yet nodes/edges have no `tooltip.formatter`, so hovering
shows just the raw node name with no entity type or context. Edge labels show only a single
`EventID` (last write wins per node pair — `addEdge` dedupes by `s||t`, so co-occurring
multiple EIDs collapse to one). There is no way to search/locate a specific entity in a
200-node graph, no zoom-to-fit/reset-view button after the user pans away, and the node cap
silently biases toward hosts/users (documented in the file comment but not surfaced to the
analyst beyond "showing top 200").

## Proposed solution
- Add `tooltip.formatter` for nodes (name + category label + degree) and edges
  (source → target + list of EventIDs).
- Add a "Find entity" input that highlights/centers a matching node.
- Add Reset View / Zoom-to-fit buttons.
- When truncated, state which categories were dropped or offer a category filter.

## Acceptance criteria
1. Given a loaded graph, when I hover a node, then a tooltip shows the entity name, its type
   (Host/User/IP/Process), and its connection count.
2. Given a node pair with multiple co-occurring EventIDs, when I hover the edge, then all
   distinct EventIDs are listed (not just one).
3. Given a large graph, when I type an entity name in "Find entity", then the matching node
   is highlighted and centered.
4. Given I have panned/zoomed, when I click Reset View, then the graph returns to
   fit-to-screen.
5. Given the graph is truncated, when the warning shows, then it indicates the bias and
   offers a way to narrow (category or shorter range).
