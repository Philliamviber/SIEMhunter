# FR #18 — Add confirmation, success feedback, and error handling to incident status changes

**Priority:** P2 · **Size:** S · **Labels:** ux, enhancement

## Problem / motivation
In `IncidentDetailPage.tsx`, `changeStatus` calls `updateStatus({ id, newStatus })` with no
confirmation and no `onError`/`onSuccess` handling. Close/Archive/Reopen fire immediately on
a single click; if the mutation fails, the user sees nothing (the button just re-enables) —
a destructive-feeling action with no feedback. Archiving in particular is consequential for
IR records.

## Proposed solution
Add a confirmation dialog for Close/Archive (Reopen can be lighter), a success toast on
completion, and an inline error message on failure. Optionally an undo window for the
just-changed status.

## Acceptance criteria
1. Given I click Archive, when the confirm dialog appears, then the change only happens after
   I confirm.
2. Given a status change succeeds, when it completes, then a success toast/inline
   confirmation appears and the badge updates.
3. Given a status change fails, when the error returns, then a clear inline error is shown
   and the prior status is retained.
4. Given the action is in flight, when I look at the button, then it shows a pending state
   (already partially present via `isPending`) and cannot be double-fired.
