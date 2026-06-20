# FR #25 — Add export and copy actions to EventDetailPanel; clarify empty fields

**Priority:** P3 · **Size:** S · **Labels:** ux, enhancement

## Problem / motivation
`EventDetailPanel.tsx` renders all event fields but offers no way to copy a single field
value or export the whole event (JSON) for a ticket/IR note — analysts must hand-select text.
Empty fields are hidden entirely (`val ? … : null`), which is reasonable, but there is no
"show empty fields" option for analysts who need to confirm a field is genuinely empty versus
omitted. The `UnmappedFields` raw JSON has no copy button despite being the most forensically
valuable block.

## Proposed solution
Add per-row copy-to-clipboard, a "Copy event as JSON" / "Download JSON" action, and an
optional "show empty fields" toggle. Keep all rendering as plain text (no
`dangerouslySetInnerHTML`, consistent with existing security posture).

## Acceptance criteria
1. Given an open event, when I click a field's copy icon, then its value is copied and a toast
   confirms.
2. Given an open event, when I click "Copy as JSON" / "Download", then I get the full event as
   valid JSON.
3. Given the empty-fields toggle, when enabled, then previously-hidden empty fields appear
   marked as empty.
4. Given the UnmappedFields block, when I copy it, then the pretty-printed JSON is copied
   verbatim.

## Notes
Candidate to fold into FR #16 (shared copy/export utilities) if trimming the backlog.
