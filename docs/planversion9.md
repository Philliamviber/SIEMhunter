# SIEMhunter v4.0.0 "Analyst Workstation" — Orchestration Plan

This is the AutomationOrchestrator-runnable plan for SIEMhunter **v4.0.0 "Analyst Workstation."**
It is derived from `docs/newreleaseplan/proposalplan.md` (§8 backlog) and follows the conventions of
the already-executed v3 plan in `docs/plan.md`. Each `## PR<N>` below is one fresh `claude -p`
session that does ONLY its Scope and gates on a GREEN/RED flag.

Run it on a dedicated `4.0` dev branch (PR0 creates it) so `master` stays clean. The chain commits
locally and closes the verified v3 issues via `gh`, but does **NOT** push — pushing the branch and
the `v4.0.0` tag, merging to `master`, and the human GATE J security sign-off are manual post-chain
steps. The still-pending v3.0.0 GATE J and tag push are separate manual steps and out of scope here.

Sequence: reconcile the v3 baseline (PR0–PR1), build Tier-1 analyst quality-of-life (PR2–PR6), add
the security-sensitive in-UI Sigma authoring pair (PR7–PR8), then cut and tag v4.0.0 (PR9). RBAC,
Sentinel read-back, and a Pi deployment are intentionally out of scope for this release.

Validate before running (expect 0 warnings — every PR has a `### Scope`):
`Get-AutomationPlan -Repo c:\Data\repo\siemhunter -PlanPath docs\planversion9.md`

Run (commit + close-issues allow-listed; no push):
`Build-AutomationRepo -Repo c:\Data\repo\siemhunter -PlanPath docs\planversion9.md -ClaudeArgs '--allowedTools','Bash(git *),Bash(gh issue *),Bash(npm *),Bash(npx *),Bash(python *),Bash(pytest *),Bash(docker *)'`

## PR0 — v4 baseline: branch, green check, version bump
### Scope
- Create and check out a dedicated dev branch `4.0` off the current `master` tip; all v4 work happens here so `master` stays clean and clear of your other concurrent prompts.
- Re-run the full backend suite (`pytest services/api/tests`) and the frontend suite (`npm test` in `frontend/`) on a clean checkout; fix any red before proceeding so the baseline is genuinely green, not just patched.
- Bump the three canonical version surfaces from `3.0.0` to `4.0.0-dev`: `frontend/package.json`, the `version=` argument in the `FastAPI(...)` constructor in `services/api/src/main.py`, and the `siemhunter/frontend` image tag in `docker-compose.yml`.
- Add a `CHANGELOG.md` `[Unreleased] — 4.0.0 (Analyst Workstation)` section to collect entries from PR2–PR8.
### Gate
Local edits and a local branch only; both test suites must be green on a clean checkout before the version bump, and nothing is pushed.
### Acceptance
- Branch `4.0` exists and is checked out.
- All three version surfaces read `4.0.0-dev`, with no leftover `3.0.0` drift.
- `pytest` and `vitest` both pass with zero failures on a clean checkout.
- `CHANGELOG.md` carries the new `[Unreleased] — 4.0.0` section.
### Handoff
A clean, green v4 baseline exists on branch `4.0`; PR1 reconciles the issue tracker.

## PR1 — Verify and close the 12 implemented v3 FRs
### Scope
- For each of the twelve still-open feature requests — #9, #12, #13, #14, #16, #17, #18, #19, #20, #21, #22, #25 — locate the implementing commit and confirm the feature is present in the code on `4.0`.
- Close each issue with `gh issue close <n>` and a comment linking the implementing commit SHA.
- Leave the local `v3.0.0` tag, the pending v3 GATE J sign-off, and all pushes untouched.
### Gate
Close an issue only when its implementing commit is identified and the feature is verified in code; the test suites stay green.
### Acceptance
- `gh issue list --state open` lists none of the twelve FRs.
- Every closed issue carries a comment linking the implementing commit.
- No tag is moved and nothing is pushed to origin.
### Handoff
The GitHub tracker now matches the shipped code; PR2 starts the net-new work with the per-analyst persistence layer.

## PR2 — Per-analyst persistence layer + preferences
### Scope
- Add a per-analyst key/value persistence layer to the API, following the SQLite access pattern in `services/api/src/db_incidents.py`.
- Key every row to the authenticated analyst identity resolved server-side from `services/api/src/auth_analyst.py`; never trust a client-supplied owner.
- Ship per-analyst preferences as the first consumer: default time range, table density, and default landing page, read on load and applied to the dashboard.
- Add the API router plus the frontend context/hooks to read and write preferences; use parameterized queries and render stored values as text only (no HTML sink).
### Gate
Every per-analyst row is scoped to the server-set identity; no client-supplied owner is trusted.
### Acceptance
- A preference written by analyst A is readable only as A and survives a reload.
- pytest covers the store (create/read plus identity scoping); vitest covers the preferences UI.
- The full suite stays green.
### Handoff
A durable, identity-scoped per-analyst store exists; PR3 and PR6 build on it.

## PR3 — Saved views & query history
### Scope
- Add named, per-analyst saved views (saved filter sets) for the Query Console, Global Search, Events, and Detections pages, persisted through the PR2 store.
- Add a query history that records recent queries and offers one-click re-run.
- Surface saved views in the UI so they can later be reached from the command palette.
### Gate
Reuse the PR2 per-analyst store; introduce no new persistence mechanism and keep identity scoping intact.
### Acceptance
- Saving a named view and reopening it restores the filters for that analyst only.
- Query history re-run reissues the recorded query.
- vitest covers save/restore and re-run; the suite is green.
### Handoff
Saved views exist as navigation targets; PR4 adds the command palette.

## PR4 — Command palette (Ctrl-K)
### Scope
- Add a `Ctrl-K` / `Cmd-K` command palette that fuzzy-searches and jumps to any page, incident, or saved view (PR3).
- Include quick actions (for example create incident, export current view) in the palette.
- Mount the palette once, hoisted into `frontend/src/components/PageLayout.tsx`, so it is available on every page.
- Make it accessible: focus trap on open, ARIA listbox/option roles, arrow-key navigation, and Escape to close.
### Gate
Frontend-only; no backend endpoint or data-contract change.
### Acceptance
- The palette opens on Ctrl-K, fuzzy-filters destinations and actions, and is fully keyboard-operable.
- Escape closes it and focus returns correctly.
- vitest covers open / filter / navigate / select; the suite is green.
### Handoff
Navigation is fast and central; PR5 adds incident report export.

## PR5 — Incident report export (PDF / Markdown / JSON)
### Scope
- Add a one-click "export incident" that bundles the incident's events, its server-side notes (#19), a correlation snapshot, and a timeline into a downloadable report.
- Offer Markdown, JSON, and PDF formats; generate PDF from the browser print stylesheet (or one vetted local library) with no dependency that makes network calls.
- Reuse the shared `frontend/src/utils/exportUtils.ts` utility so the existing CSV-injection neutralisation (leading `=`, `+`, `-`, `@`) and truncation-note handling apply to the report.
### Gate
The export draws on local data only — zero call edges to `/v1/ai/summary` or any new outbound request.
### Acceptance
- Markdown, JSON, and PDF reports generate from local incident data.
- A field beginning with `=` / `+` / `-` / `@` is neutralised in the export (covered by a test), and any truncation note carries into the report.
- No export path imports or calls the AI summary client; the suite is green.
### Handoff
The triage-to-report loop is closed; PR6 adds batch-hit notifications.

## PR6 — Batch-hit notifications
### Scope
- Add a per-analyst "last seen" marker (stored in the PR2 store) and an API endpoint that returns detection hits newer than a given timestamp.
- Surface "new high/critical hits since you last looked" through the existing `frontend/src/components/ToastProvider.tsx` toast system (#23).
- Poll gently on window focus or a modest interval — no tight auto-poll loop (the detection batch runs every 15 minutes).
### Gate
Reuse the existing toast system and respect current poll/rate limits; the last-seen marker is identity-scoped.
### Acceptance
- A new high/critical hit since the analyst's last-seen marker raises exactly one toast, and the marker then advances.
- vitest covers the since-last-seen delta logic.
- The suite is green.
### Handoff
Tier-1 analyst quality-of-life is complete; PR7 begins the security-sensitive Sigma authoring.

## PR7 — In-UI Sigma authoring: editor + compile-validate + SELECT-only dry-run
### Scope
- Add a Sigma rule authoring page with a YAML editor in the dashboard.
- Add a server-side endpoint that compiles submitted Sigma to ClickHouse SQL using the existing pySigma pipeline (`rules/pipelines/clickhouse-asim-ocsf.yaml`; compile path in `services/detection/src/runner.py`) and returns either compile errors or a SQL preview.
- Implement a SELECT-only dry-run: execute the compiled SQL against recent events through a read-only ClickHouse connection (`readonly=1` profile or a dedicated read-only user), bounded by a time window (for example the last 24h), a row `LIMIT`, and a query timeout; return sample matches and a count.
- Guard the dry-run server-side: reject anything that is not a single `SELECT` (no `;` chaining, no `INSERT` / `ALTER` / `DROP` / `CREATE` / `SYSTEM`).
- Write no rows to `rule_registry` in this PR.
- Run one bounded implement-review-fix loop with the code-reviewer subagent (security focus) inside this PR only.
### Gate
The dry-run path is provably read-only — a read-only connection AND a server-side single-SELECT allow-list — and no rule promotion or `rule_registry` write happens here.
### Acceptance
- Invalid Sigma returns a clear compile error; a valid rule dry-runs and returns bounded sample matches plus a count.
- An attempt to smuggle a non-SELECT statement through the dry-run is rejected (covered by a test).
- No code path in this PR writes to `rule_registry`; the suite is green.
### Handoff
Authoring and a safe dry-run exist; PR8 adds the governed promotion lifecycle.

## PR8 — Sigma rule lifecycle + promotion (admin-gated, fail-closed audit)
### Scope
- Add API endpoints for the `rule_registry` lifecycle (`clickhouse/schema.sql`): draft → test → review → production → disabled.
- Require the admin / break-glass auth tier (the FR#10 dual-auth split) for mutating transitions (promote, disable); keep list/read open to any authenticated analyst.
- Enforce fail-closed audit: every mutation writes an audit record to Sentinel via `services/api/src/audit_client.py` BEFORE the registry change takes effect, and the mutation is refused if that audit write fails.
- Let the detection service pick up newly promoted production rules through its existing hot-reload.
- Add a SELF- Sigma rule that fires on rule-status mutations so the new admin action is itself detectable (GATE I).
- Run one bounded implement-review-fix loop with the code-reviewer subagent inside this PR only.
### Gate
Rule mutation is admin-gated AND audited-before-effect (fail-closed) — a failed audit write blocks the change.
### Acceptance
- A non-admin promote attempt is rejected.
- An admin promote writes the Sentinel audit record first and only then activates the rule; a simulated audit failure blocks the promotion.
- The new SELF- rule fires on a rule-status change (covered by a test); the suite is green.
### Handoff
In-UI Sigma authoring is complete and governed; PR9 cuts the release.

## PR9 — Cut v4.0.0 (gates + local tag)
### Scope
- Bump the three version surfaces from `4.0.0-dev` to `4.0.0`.
- Finalize the `CHANGELOG.md` `[4.0.0]` section from the work landed in PR2–PR8.
- Write `docs/release/v4.0.0-gate-status.md` in the format of `docs/release/v3.0.0-gate-status.md`, enumerating gate D (pytest green), E (vitest green), F (no placeholder dependency hashes, still enforced by `.github/workflows/dependency-check.yml`), H (code review confirms the Sigma SELECT-only dry-run, admin-gated mutation, and fail-closed audit), I (the rule-mutation SELF- rule fires and is forwarded), K (a threat-model note for the new stored per-analyst data — parameterized, no HTML sink, identity-scoped), and J (final human security sign-off, manual).
- Create the local annotated tag `v4.0.0`.
### Gate
All prior PRs are green and the full pytest + vitest suite is green on a clean checkout before the tag is created.
### Acceptance
- All three version surfaces read `4.0.0` and the `CHANGELOG.md` `[4.0.0]` section is complete.
- `docs/release/v4.0.0-gate-status.md` records evidence for gates D / E / F / H / I / K as met and marks J as the pending manual step.
- The local annotated tag `v4.0.0` exists.
### Handoff
GATE J (human security sign-off), merging `4.0` into `master`, and pushing the commits and the `v4.0.0` tag are manual post-chain steps and are not authorized by this plan.
