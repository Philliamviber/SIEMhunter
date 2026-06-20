# FR #19 — Make the incident Notes editor functional (audit-aware)

**Priority:** P2 · **Size:** M · **Labels:** ux, security, enhancement

## Problem / motivation
`IncidentDetailPage.tsx` hardcodes a Notes section that says "Read-only in this release /
Notes editor coming in a future release." For an incident tracker in a SIEM, analyst notes
are core IR workflow (timeline, actions taken, decisions). Today there is nowhere to record
investigation context against an incident.

## Proposed solution
Add an editable, append-style notes/timeline for incidents: each note timestamped and
attributed to the logged-in analyst (ties into FR #10 identity), stored server-side,
immutable once saved (append-only for audit integrity) or with edit history.

## Acceptance criteria
1. Given an incident, when I add a note and save, then it persists server-side and appears in
   the timeline with timestamp and author.
2. Given existing notes, when I reload, then they are shown newest-first (or chronological,
   consistently).
3. Given the audit requirement, when a note is saved, then it cannot be silently
   deleted/altered without a recorded history (append-only or versioned).
4. Given a save fails, when the error returns, then my draft text is preserved, not lost.

## Notes
Depends on FR #10 for per-analyst author attribution.
