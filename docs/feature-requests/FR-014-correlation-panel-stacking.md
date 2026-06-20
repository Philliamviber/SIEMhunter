# FR #14 — Fix Correlation entity panel ↔ event panel stacking and return navigation

**Priority:** P3 · **Size:** S · **Labels:** ux, bug

## Problem / motivation
In `CorrelationPage.tsx`, clicking a node opens `EntityPanel` (fixed right, z-50). Clicking
a row opens `EventDetailPanel` (also fixed right, z-50, with its own full-screen z-40
backdrop). The code gates the entity panel with `{selectedEntity && !selectedEvent && …}`,
so opening an event hides the entity panel; closing the event panel only does
`setSelectedEvent(null)` — the comment even says "Return to entity panel if entity is still
selected" but the entity reappears abruptly with no transition, and the `EventDetailPanel`
backdrop (z-40) sits over the graph, so an outside click closes the event but the user can
be confused about which layer they are on. Two same-z fixed panels are fragile.

## Proposed solution
Make the flow an explicit stack/breadcrumb: Entity panel → Event detail, with a "Back to
entity" affordance in the event panel header when launched from an entity, and consistent
z-index layering so the backdrop only dims the graph, not the entity panel.

## Acceptance criteria
1. Given I open an entity then an event, when I close the event, then I return to the same
   entity panel with its scroll position preserved.
2. Given the event panel is open from an entity, when I view its header, then a "Back to
   entity" control is present.
3. Given any panel is open, when I press Escape, then only the topmost panel closes (event
   first, then entity).
4. The entity panel and event panel never render visually overlapping at the same z-index.

## Notes
Candidate to fold into FR #13 if trimming the backlog.
