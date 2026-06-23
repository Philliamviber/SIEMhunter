# SIEMhunter v3.0.0 "UX Wave" — Orchestration Plan

This is the AutomationOrchestrator-runnable form of the analysis in
`docs/newreleaseplan/proposalplan.md` (read that for the full reasoning, ground-truth
verification, and open owner decisions). Each `## PR<N>` below is one fresh `claude -p`
session that does ONLY its Scope and gates on a GREEN/RED flag.

Sequence: a cheap hygiene sprint (PR0–PR3) to make the release credible, then the 12
remaining UX feature requests in priority order (PR4–PR13), then cut and tag v3.0.0
(PR14). The net-new "v4.0.0 Analyst Workstation" work (proposal §8) and its scope
decisions (§10) are intentionally NOT encoded here — they are an owner decision, handed
off at the end of PR14, not an autonomous default.

## PR0 — Version coherence + retroactive tags
### Scope
- Pick one source-of-truth version and align all surfaces to `3.0.0-dev`: `frontend/package.json` (currently `0.0.0`), the FastAPI `version=` in `services/api/src/main.py` (currently `0.1.0`), and the `siemhunter/frontend` image tag in `docker-compose.yml` (currently `0.1.0`).
- Reconcile `CHANGELOG.md`: keep the `[1.0.0]` and `[2.0.0]` history, add an `[Unreleased] — v3.0.0 (UX Wave)` section, and correct the "API bumped to 0.2.0" line so code and changelog agree.
- Create LOCAL annotated git tags `v1.0.0` and `v2.0.0` on the boundary commits (v1.0.0 = last backend-only commit; v2.0.0 = last dashboard commit before the auth/UX-wave commits `ba0c721`/`25fa437`), per proposal §10.5 recommended decision.
- Add a short `docs/RELEASING.md` note recording the single source of truth and that tags are cut at release time.
### Gate
Local, deterministic edits and local tags only; do NOT push tags (push is a manual post-chain step).
### Acceptance
- All three version surfaces read the same `3.0.0-dev` value; no `0.0.0` / `0.1.0` drift remains.
- `git tag` lists `v1.0.0` and `v2.0.0` pointing at the documented boundary commits.
- `CHANGELOG.md` no longer claims a `0.2.0` API bump that the code contradicts.
### Handoff
Version identity is coherent; PR1 can wire the dependency-hash supply-chain gate.

## PR1 — Dependency hash pinning (GATE F)
### Scope
- Regenerate real `--hash=sha256:` pins for all four service requirement files — `services/api`, `services/detection`, `services/forwarder`, `services/normalization` — replacing the `placeholder_regenerate_before_deploy` sentinel.
- Extend the existing `.github/workflows/dependency-check.yml` with a check that FAILS if the sentinel string appears in any tracked `requirements*.txt`.
- Scope that check to tracked paths only, so the stray agent worktree (removed in PR2) does not false-positive.
### Gate
Pinned versions must resolve and install cleanly; no unresolved version conflicts.
### Acceptance
- No tracked `requirements*.txt` contains `placeholder_regenerate_before_deploy`.
- Every dependency line carries a real `--hash=sha256:` pin.
- CI fails on a seeded sentinel string and passes once it is removed.
### Handoff
The supply-chain gate is enforced; PR2 cleans the repo hygiene the gate's grep depends on.

## PR2 — Repo hygiene: gitignore, stray worktree, doc consolidation
### Scope
- Add `.claude/` and `.orchestrator/` to `.gitignore`.
- Remove the stray `worktree-agent-aeffe313fd07e98d1` branch and its worktree.
- Consolidate stale/mis-named planning docs under `docs/history/` with a "superseded" header: `changelog2.md` (a mis-titled frontend plan), `advise.md`, and `frontendplan.md`; keep README + standard top-level docs at root.
- Add an "as-built update" header to `SIEMHunterv3changelogproposal.md` pointing at `docs/newreleaseplan/proposalplan.md`.
### Gate
Relocate docs with `git mv` to preserve history; do not delete content.
### Acceptance
- `.claude/` and `.orchestrator/` are git-ignored.
- The `worktree-agent-aeffe313fd07e98d1` branch no longer appears in `git branch -a`.
- The repo root holds only README + standard docs; planning history lives under `docs/history/`.
### Handoff
Repo hygiene is clean; PR3 verifies and closes the already-fixed feature requests.

## PR3 — Verify and close the 5 fixed-but-open FRs (GATE D)
### Scope
- End-to-end verify the five FRs that are fixed in code but still OPEN as issues: #10 (per-analyst login), #11 (pivot links), #15 (incident scope on search), #23 (toasts), #24 (timestamp timezone).
- Run the full backend (pytest) and frontend (vitest) suites on a clean checkout; fix any red tests so GATE D = "suite green on a clean checkout", not merely patched.
- Close issues #10 / #11 / #15 / #23 / #24 with a comment linking the implementing commit.
### Gate
The suite must be green on a clean checkout before any issue is closed (fail-closed).
### Acceptance
- `pytest` and `vitest` both pass on a clean checkout with zero failures.
- Each of the 5 FRs has a written verification note (what was exercised, and the result).
- Issues #10 / #11 / #15 / #23 / #24 are closed with linking comments.
### Handoff
The baseline is green and the tracker matches the code; PR4 begins net-new UX work on the new identity.

## PR4 — FR #19 server-side incident notes (audit-aware)
### Scope
- Replace the `localStorage` incident notes with a server-side, append-only notes store keyed to an incident, persisted via the API + the SQLite incidents DB.
- Set author and timestamp SERVER-SIDE from the authenticated analyst identity (#10); never trust client-supplied author or time.
- Use parameterized queries and render note content as text only (no HTML sink / no XSS).
- Add pytest + vitest coverage for create/list and for the append-only + server-authorship guarantees.
### Gate
Notes are append-only and author/timestamp are server-set; note content is never rendered as raw HTML.
### Acceptance
- A note created by analyst A records A's identity and a server timestamp the client cannot override.
- Notes cannot be edited or deleted via the API (append-only), proven by a test.
- New tests pass and the existing suite stays green.
### Handoff
Attributed notes shipped; PR5 removes the per-page chatbar duplication.

## PR5 — FR #9 global AI chatbar
### Scope
- Render `ClaudeChatbar` once, hoisted into `PageLayout`, instead of the ~8 per-page renders.
- Preserve existing behavior (floating panel, session persistence) with the single instance.
- Remove the now-dead per-page chatbar render sites.
### Gate
Pure refactor; no change to the `/v1/ai/summary` aggregated-only contract.
### Acceptance
- Exactly one `ClaudeChatbar` instance mounts and it persists across in-SPA navigation.
- No page renders its own chatbar; vitest is updated and the suite is green.
### Handoff
The chatbar is global; PR6 builds the shared export utility.

## PR6 — FR #16 + #25 export and IOC copy
### Scope
- Build one shared CSV/JSON export utility; #25 (EventDetailPanel export + copy actions) consumes it.
- Add empty/zero-state and result persistence to global search (#16), plus export to search results and event detail.
- Escape CSV-injection-prone leading characters (`=`, `+`, `-`, `@`) and carry any truncation note into the exported file.
### Gate
Export uses LOCAL results only — zero call edges to `/v1/ai/summary` or any API round-trip for the export itself.
### Acceptance
- Exporting a field that begins with `=` / `+` / `-` / `@` neutralizes it (prefixed or quoted), covered by a test.
- Truncated result sets carry the truncation note in the exported file.
- No export path imports or calls the AI summary client; the suite is green.
### Handoff
A shared export utility exists; PR7 wires status-change confirmations onto the toast system.

## PR7 — FR #18 incident status confirm + feedback
### Scope
- Add a confirmation dialog for destructive incident status changes (Close / Archive).
- Surface success and error via the shipped toast system (#23) on every status PATCH.
- Handle and toast API failures (no silent failure).
### Gate
Reuse the existing `ToastProvider`; introduce no new notification mechanism.
### Acceptance
- Close / Archive requires explicit confirmation before the PATCH fires.
- Both success and failure produce a visible toast, covered by vitest; the suite is green.
### Handoff
Status changes are safe and legible; PR8 scales the incidents list.

## PR8 — FR #17 incidents list filter/sort/search
### Scope
- Add filtering, sorting, and search to the Incidents list.
- Persist the active filters in the URL so the view is shareable and restorable.
### Gate
Filter server-side where the API supports it; no unbounded client-side fetch.
### Acceptance
- Filter / sort / search narrow the list as specified and survive a reload via URL state.
- vitest covers filtering and URL persistence; the suite is green.
### Handoff
The incident workflow scales; PR9 improves the forensic upload UX.

## PR9 — FR #12 upload progress, cancel, multi-file
### Scope
- Add upload progress, cancel via `AbortController`, and multi-file selection to `UploadZone`.
- Invalidate and refetch the relevant queries after a successful upload.
### Gate
Respect the existing 100 MiB-per-file limit and accepted types; incident scoping is unchanged.
### Acceptance
- A multi-file upload shows per-file progress and cancel aborts an in-flight upload.
- After upload, the Events / Ingestion views refresh without a manual reload; the suite is green.
### Handoff
Upload UX is complete; PR10 makes the correlation graph navigable.

## PR10 — FR #13 + #14 correlation controls + panel stacking
### Scope
- Add node/edge tooltips, in-graph search, and reset/zoom controls to the correlation graph (#13).
- Fix the entity↔event panel stacking and return navigation (#14, folded into #13).
### Gate
Keep the 200-node frontend cap and truncation warning; the graph stays load-on-demand (no auto-poll).
### Acceptance
- Tooltips, search, and zoom/reset all work, and the entity/event panels stack and return correctly.
- The 200-node cap and truncation warning still fire; the suite is green.
### Handoff
Correlation is navigable; PR11 clarifies category drill-down limits.

## PR11 — FR #21 category drill-down truncation + load-more
### Scope
- Surface drill-down truncation ("showing 500 of N") and add a refine / load-more CTA.
- Add clear error and empty states to the Category pages.
### Gate
No change to the category query contract; truncation is surfaced, not removed.
### Acceptance
- Truncated drill-downs show "showing X of N" plus a refine / load-more affordance.
- Empty and error states render distinctly; the suite is green.
### Handoff
Category UX is clarified; PR12 starts the accessibility polish.

## PR12 — FR #20 IncidentSelector ARIA combobox
### Scope
- Make `IncidentSelector` a keyboard-accessible ARIA combobox: correct `role` / `aria-*` attributes, arrow-key navigation, and Enter/Escape handling.
- Manage focus and announce open/close and selection state to assistive tech (active-descendant or equivalent).
### Gate
Accessibility only; no behavioral or data change.
### Acceptance
- The selector is fully keyboard-operable (open, arrow-navigate, select, dismiss) with correct ARIA roles.
- A vitest test covers keyboard navigation and the ARIA attributes; the suite is green.
### Handoff
Selector accessibility is done; PR13 finishes the responsive layout.

## PR13 — FR #22 responsive layout + collapsible sidebar
### Scope
- Add a responsive layout that remains usable down to ~768px across the dashboard pages.
- Make the sidebar collapsible, preserving the collapsed/expanded state across navigation.
### Gate
No data or behavior change; layout and CSS only.
### Acceptance
- Pages remain usable at ~768px with no horizontal overflow or clipped controls.
- The sidebar collapses and expands and its state persists; the suite is green.
### Handoff
All 12 v3 UX feature requests are landed; PR14 cuts the v3.0.0 release.

## PR14 — Cut v3.0.0 (gates + tag)
### Scope
- Bump the single source-of-truth version from `3.0.0-dev` to `3.0.0` across all surfaces.
- Finalize the `CHANGELOG.md` `[3.0.0]` section from the FRs landed in PR4–PR13.
- Write `docs/release/v3.0.0-gate-status.md` enumerating gates D / E / F / H / I / J with evidence and an owner for each.
- Create the LOCAL annotated tag `v3.0.0`.
### Gate
All prior PRs green and the full pytest + vitest suite green on a clean checkout (GATE D/E) before tagging.
### Acceptance
- All version surfaces read `3.0.0` and the `CHANGELOG.md` `[3.0.0]` section is complete.
- The gate-status doc records each gate's evidence; GATE F (no placeholder hashes) and GATE D (suite green) are demonstrably met.
- The annotated tag `v3.0.0` exists locally.
### Handoff
GATE J (human security sign-off), pushing the tags, and the v4.0.0 "Analyst Workstation" scope decision (proposal §8/§10) are manual post-chain steps — not authorized by this plan.
