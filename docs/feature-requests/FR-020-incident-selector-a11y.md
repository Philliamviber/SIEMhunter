# FR #20 — Add keyboard accessibility and ARIA roles to IncidentSelector dropdown

**Priority:** P2 · **Size:** S · **Labels:** accessibility, ux, bug

## Problem / motivation
`IncidentSelector.tsx` sets `aria-haspopup="listbox"` and `aria-expanded`, but the dropdown
is not keyboard-operable: it opens on Enter/Space, yet the option list has no
`role="listbox"`/`role="option"`, no arrow-key navigation, no focus management, and does not
close on Escape (only outside mousedown). The nested Clear `<button>` inside the trigger
`<button>` is also invalid HTML (button-in-button), which breaks keyboard tab order and
screen-reader semantics.

## Proposed solution
Either adopt a proper accessible combobox/listbox pattern (roles, `aria-activedescendant`,
arrow/Escape handling, focus return to trigger on close) or refactor to a `<select>`-backed
control. Move the Clear action out of the trigger button to a sibling element.

## Acceptance criteria
1. Given the closed selector, when I focus it and press Enter/Space/Down, then it opens and
   the first/active option is focused.
2. Given the open list, when I press Up/Down, then focus moves between options; Enter
   selects; Escape closes and returns focus to the trigger.
3. The option list exposes `role="listbox"` and each option `role="option"` with
   `aria-selected`.
4. There are no nested interactive elements (no button inside button); Clear is a separate
   control reachable by keyboard.
