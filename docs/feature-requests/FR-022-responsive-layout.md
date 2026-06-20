# FR #22 — Add responsive/mobile layout and a collapsible sidebar

**Priority:** P3 · **Size:** M · **Labels:** ux, accessibility, enhancement

## Problem / motivation
`PageLayout.tsx` uses a fixed `w-56` sidebar and a horizontally dense `GlobalSearchBar`
(`max-w-5xl` row of select+input+buttons). Several panels are fixed-width
(`EventDetailPanel` w-480px, `EntityPanel` w-440px, AI chatbar w-96), which overflow on
narrow viewports/tablets. There is no way to collapse the sidebar to reclaim space on smaller
screens, and the slide-in panels will exceed the viewport width on a phone, hiding the close
button.

## Proposed solution
Make the sidebar collapsible (hamburger on small screens), make slide-in panels
max-width-capped to the viewport (`w-full max-w-[480px]`), and let the search bar wrap
gracefully. Confirm key flows work down to ~768px.

## Acceptance criteria
1. Given a viewport < 768px, when the app loads, then the sidebar is collapsed behind a
   toggle and the content uses full width.
2. Given a narrow viewport, when a slide-in panel opens, then it never exceeds the viewport
   width and its close button is always visible/reachable.
3. Given the search bar on a narrow viewport, when it renders, then controls wrap instead of
   overflowing.
4. No horizontal page scrollbar appears at 768px on any route.
