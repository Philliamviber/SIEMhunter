# FR #24 — Fix timestamp display: real local time / timezone label instead of hardcoded UTC-5 "EST"

**Priority:** P2 · **Size:** S · **Labels:** ux, bug

## Problem / motivation
`formatTimestamp.ts` renders every timestamp as `… UTC (… EST)` using a hardcoded `-5h`
offset with an explicit "no DST adjustment" decision. For roughly half the year in the US
Eastern zone this is wrong by an hour (EDT is UTC-4), and for analysts in any other timezone
the "EST" label is misleading. In a SIEM, an off-by-one-hour timestamp can corrupt an incident
timeline.

> Note: this format was an explicit v2.0 decision (OQ-4). This FR proposes revisiting it
> because the fixed offset is factually wrong for half the year.

## Proposed solution
Show UTC plus the viewer's actual local time using `Intl.DateTimeFormat` (correct DST,
correct zone label), or make the display timezone a user setting. Always label the zone
accurately. Keep UTC as the canonical anchor.

## Acceptance criteria
1. Given any timestamp, when it renders, then the secondary local time uses the browser's
   actual timezone with correct DST and an accurate zone abbreviation.
2. Given a user in a non-Eastern timezone, when they view a timestamp, then it is not labeled
   "EST".
3. Given UTC is shown, when compared to the source event, then the UTC value is
   unchanged/canonical.
4. Optional: a timezone preference toggles the secondary display consistently across all
   pages.
