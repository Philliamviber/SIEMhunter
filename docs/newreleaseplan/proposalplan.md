# SIEMhunter — Major Release Proposal & Quality-of-Life Plan

> **Status:** Proposal / planning artifact. **No code changes are authorized by this document.**
> It exists to (1) reconcile the repo's *actual* state against its contradictory planning docs,
> (2) recommend what to tackle next, clean up, and fix, and (3) propose net-new quality-of-life
> capabilities worthy of a major release.
>
> **Authored by:** main orchestrator (Claude Code), 2026-06-23, after a direct read of source,
> git history, GitHub issues, and the existing planning docs.
> **Independently re-verified:** 2026-06-23 (same session, fresh read of `git log`, `gh issue
> list`, version strings, `requirements.txt`, and the auth source). The §2 ground truth holds;
> deltas and one plan-changing finding (GATE H is largely *met in code*, not merely "code exists")
> are recorded in **§12**. Read §12 before grilling — it narrows the open work.
> **Intended next step:** this plan is handed to a reviewing agent to be **grilled** into
> `grilledupproposalplan.md`. §11 tells that reviewer exactly where to push hardest.
>
> **Companion doc:** `SIEMHunterv3changelogproposal.md` (the narrow "UX Wave" auth proposal).
> This document is the **umbrella** plan; it supersedes that doc's *current-state assumptions*
> (which are now stale — see §2) but keeps its security design (GATE B / conditions C1–C7) intact.

---

## 0. Contents

1. [TL;DR](#1-tldr)
2. [Ground truth — what is *actually* built right now](#2-ground-truth--what-is-actually-built-right-now)
3. [The core problem: three contradictory planning docs + no release coherence](#3-the-core-problem)
4. [Recommended release strategy](#4-recommended-release-strategy)
5. [What to tackle next](#5-what-to-tackle-next-finish-the-ux-wave)
6. [What to clean up](#6-what-to-clean-up-tech-debt--hygiene)
7. [What to fix](#7-what-to-fix-correctness--release-gates)
8. [Net-new quality-of-life capabilities](#8-net-new-quality-of-life-capabilities)
9. [Proposed sequencing & milestones](#9-proposed-sequencing--milestones)
10. [Decisions / open questions for the owner](#10-decisions--open-questions-for-the-owner)
11. [Where to grill this plan](#11-where-to-grill-this-plan-for-the-reviewing-agent)
12. [Independent verification + deltas (added this revision)](#12-independent-verification--deltas)

---

## 1. TL;DR

- **The "v3.0.0 UX Wave" is already half-built on `master`, unreleased and untagged.** The
  existing `SIEMHunterv3changelogproposal.md` reads as if it's all still ahead of us — it isn't.
  Phase 0 (auth #10, toasts #23, greenfield CI) and Phase 1 (bug fixes #11/#15/#24) are
  **committed**. ~12 UX feature requests remain.
- **There is no release coherence.** No git tags exist *at all* (not even v1.0.0/v2.0.0).
  Three different version numbers are live simultaneously (`frontend` = `0.0.0`, API/image =
  `0.1.0`, CHANGELOG *claims* `0.2.0`), and the changelog narrates a "v2.0.0" that was never
  tagged. This is the single biggest credibility risk for any "major release."
- **Recommended path:** *don't* invent a brand-new feature surface yet. **Land v3.0.0 first**
  by (a) finishing the 12 remaining UX FRs, (b) cleaning up version/dep/hygiene debt, and (c)
  closing the release gates the UX proposal already defined. **Then** stage net-new QoL work
  (§8) as **v4.0.0**, where most ideas build directly on the brand-new per-analyst identity from
  FR #10 (saved views, RBAC, per-user prefs, attributed reporting).
- **Top three "tackle next" picks:** ① version + release hygiene (tag the history, fix the
  `0.0.0/0.1.0/0.2.0` drift, regenerate the placeholder dependency hashes); ② finish the
  high-value UX FRs that the new auth identity unblocks (#19 server-side notes, #9 global
  chatbar, #16/#25 export); ③ verify-and-close the 5 FRs already fixed in code but still open as
  GitHub issues.

---

## 2. Ground truth — what is *actually* built right now

Verified from `git log`, source files, and `gh issue list` on 2026-06-23.

### Shipped capability (in code, on `master`)
- **v1.0.0 backend**: Vector ingest (syslog/WEF/Netflow/forensic), ClickHouse store, OCSF/ASIM
  normalization, pySigma→ClickHouse detection + Isolation-Forest advisory scoring, Sentinel
  forwarder (cert auth, SSRF guards, ledger reconciliation), FastAPI control plane, 5 self-rules
  + 6 Windows/AD TTP rules, hardened Docker Compose.
- **v2.0.0 "dashboard"**: 11-page React/nginx frontend; incident tracker (SQLite); AI summary
  (`/v1/ai/summary`, aggregated-only); forensic upload; correlation graph; category dashboard;
  global search; new API routers (metrics, events, detections, ingestion, health, search,
  incidents, upload).
- **v3.0.0 "UX Wave" — PARTIALLY DONE & committed (8 commits, unreleased):**

| FR | What | Evidence |
|---:|------|----------|
| **#10** | Per-analyst login (argon2id), dual-auth split, static token → break-glass | `auth_analyst.py`, `auth_service_token.py`, `auth_routes.py`, `audit_client.py`, `LoginGate.tsx`; commits `ba0c721`, `75890a8` |
| **#23** | Global toast system + 401→login routing | `ToastProvider.tsx`; commit `c288ae8` |
| **#11** | Dead `EventDetailPanel` pivot links fixed | commit `89364ba` |
| **#15** | Global search now sends active `incident_id` | commit `89364ba` |
| **#24** | `formatTimestamp` timezone fix | commit `89364ba` |
| CI/CD | Greenfield GitHub Actions (`ci.yml`, `dependency-check.yml`) | commit `25fa437` |
| Docs | First-run seed, dual-auth operator notes, migration | commit `28cc40c` |

### Still genuinely open (12 UX FRs)
`#9` global chatbar · `#12` upload UX · `#13`+`#14` correlation controls/stacking · `#16`+`#25`
search/event export · `#17` incidents list controls · `#18` status confirm/feedback · `#19`
server-side notes · `#20` `IncidentSelector` a11y · `#21` category drill-down · `#22` responsive.

### GitHub issue reality
**All of #9–#25 are still OPEN**, including the 5 already fixed in code. Issues #1–#8 are closed
(delivered in v2.0). → *Process gap: code shipped, issues never verified/closed.*

---

## 3. The core problem

Three planning docs disagree with each other and with the code:

1. **`changelog2.md`** — titled "changelog" but it is actually a *frontend implementation plan*
   whose build-status section says **"Phase 2 — Frontend … ready to assign"**, i.e. *not built*.
   Reality: the entire 11-page frontend shipped months of commits ago. **This doc is stale and
   mis-named.**
2. **`SIEMHunterv3changelogproposal.md`** — excellent security design, but its "grounded facts"
   claim **"No CI exists"** and treat `LoginGate`/toasts as unbuilt. Both now exist on `master`.
   **Its plan is ~40% already executed.**
3. **`CHANGELOG.md`** — narrates `[2.0.0]` and `[1.0.0]` as released and claims the API was
   "bumped to `0.2.0`". Reality: **no git tags exist**, and `services/api/src/main.py` reads
   `version="0.1.0"`, while `frontend/package.json` reads `0.0.0`.

**Consequence:** anyone (human or agent) reading the docs to decide "what's next" will plan work
that's already done, or ship a "major release" on top of an incoherent version baseline. Fixing
this reconciliation is itself a deliverable of the next release — and it's cheap.

---

## 4. Recommended release strategy

**Two releases, in order. Do not blur them.**

### v3.0.0 — "UX Wave" (finish what's started)
Close out the 12 remaining UX FRs + the release gates the companion proposal already defined
(GATE E coverage, F dep-hashes, H code-review, I detection coverage, J security sign-off). This
is a **major** bump because FR #10 already changed the auth contract (token-paste → per-analyst
login + first-run admin seed). Most of the risk (auth) is already paid down.

### v4.0.0 — "Analyst Workstation" (net-new QoL) — *proposed, this document's main contribution*
A capability release that turns SIEMhunter from "a dashboard with login" into a multi-analyst
workstation. **Almost every idea in §8 is only possible because FR #10 introduced per-analyst
identity** — saved views, per-user preferences, RBAC, and attributed reporting all hang off it.
Sequencing net-new work *after* v3 means it's built on a stable identity + toast + CI foundation
instead of racing it.

> **Why not fold everything into one giant v3?** Because v3 is already in flight with a written
> security gate; bolting an open-ended feature surface onto it delays the auth release that's 60%
> done and makes the security sign-off (GATE J) a moving target. Ship the foundation, then build
> on it.

---

## 5. What to tackle next (finish the UX Wave)

Recommended order within v3.0.0. Identity-dependent items first (they unlock the rest), then the
broad-value items, then polish. This refines — and de-dupes against reality — the companion
proposal's Phase 2/3.

| Order | FR(s) | Why now | Notes / dependency |
|:---:|---|---|---|
| 1 | **#19** server-side incident notes | The new per-analyst identity (#10) finally makes attributed, append-only notes possible — highest analyst value | Depends on #10 (done). Author/timestamp **server-set**; append-only; parameterized; no HTML sink |
| 2 | **#9** global AI chatbar | Pure refactor; removes 8 duplicate per-page renders; low risk, immediate consistency win | Hoist into `PageLayout` |
| 3 | **#16 + #25** export + IOC copy | Build the shared CSV/JSON export util once; #25 consumes it | **Hard constraint:** export uses local results only, *zero* call edges to `/v1/ai/summary`; carry truncation note; escape CSV-injection (`= + - @`) |
| 4 | **#18** status confirm/feedback | Consumes the now-shipped toast system (#23) | Confirm dialog for Close/Archive |
| 5 | **#17** incidents list filter/sort/search | Scales the incident workflow as volume grows | URL-persisted filters |
| 6 | **#12** upload progress/cancel/multi-file | Forensic upload UX; `AbortController` + post-upload query invalidation | |
| 7 | **#13 + #14** correlation tooltips/search/zoom + panel stacking | Make the correlation graph actually navigable | Fold #14 into #13 |
| 8 | **#21** category drill-down truncation/load-more | "showing 500 of N" + refine CTA | |
| 9 | **#20** `IncidentSelector` ARIA combobox | Accessibility | Polish phase |
| 10 | **#22** responsive + collapsible sidebar | Works to ~768px | Polish phase |

**Closeout gates (carry over from the companion proposal, still required):** GATE E (coverage),
**GATE F (regenerate placeholder dep hashes — see §6/§7)**, GATE H (code review confirms auth
design implemented), GATE I (new auth events detectable in Sentinel; SELF-003 still fires), GATE
J (final security sign-off) → then **tag `v3.0.0`**.

---

## 6. What to clean up (tech-debt & hygiene)

| # | Item | Evidence | Fix |
|:--:|---|---|---|
| C1 | **No git tags anywhere** | `git tag` is empty | Retroactively tag `v1.0.0`, `v2.0.0` on the right commits; make tagging part of the release checklist |
| C2 | **Version drift (3 numbers)** | `frontend/package.json` `0.0.0`; `main.py` `0.1.0`; CHANGELOG claims `0.2.0`; compose image `siemhunter/frontend:0.1.0` | Adopt one source of truth; bump all three to the release version at tag time |
| C3 | **Placeholder dependency hashes** | `placeholder_regenerate_before_deploy` in **all 4** service `requirements.txt` (api, detection, forwarder, normalization) | Regenerate real `--hash` pins; enforce as **GATE F** (fail CI if the sentinel string appears) — `dependency-check.yml` already exists to hang this on |
| C4 | **Leftover agent worktree committed-adjacent** | `.claude/worktrees/agent-aeffe313fd07e98d1/` exists; `.claude/` is **not** in `.gitignore` (shows as untracked) | Add `.claude/` to `.gitignore`; remove the stale worktree |
| C5 | **Stale/mis-named planning docs** | `changelog2.md` is a frontend *plan* mis-titled "changelog" and says the frontend is unbuilt | Move to `docs/history/` (or delete); add a header noting it's superseded |
| C6 | **Companion proposal's "grounded facts" are stale** | claims no CI, treats LoginGate/toasts as unbuilt | Add an "as-built update" note to `SIEMHunterv3changelogproposal.md` pointing here |
| C7 | **5 fixed FRs still open as issues** | #10/#11/#15/#23/#24 fixed in code, issues OPEN | Verify against source (the v2 doc set the precedent) and close with a linking comment |
| C8 | **Root dir is cluttered with planning `.md`** | `advise.md`, `frontendplan.md`, `changelog2.md`, the v3 proposal all at repo root | Consolidate planning/history under `docs/`; keep root to README + the standard top-level docs |

---

## 7. What to fix (correctness & release gates)

| # | Item | Severity | Detail |
|:--:|---|:--:|---|
| F1 | **API version string wrong** | Med | `main.py` `version="0.1.0"` contradicts the CHANGELOG's "bumped to 0.2.0" claim and the shipped v2 feature set. Pick the truth and make code + changelog agree. |
| F2 | **Placeholder hashes are a supply-chain hole** | High (for a *security* product) | Shipping a SIEM with unverifiable dependency pins undercuts the whole hardening story. Block the tag on it (GATE F). |
| F3 | **Verify the 5 in-code FR fixes actually work end-to-end** | Med | They're committed but unreleased and their issues are unverified. Especially #15 (incident-scope leak class) and #10 (auth) deserve a real end-to-end check, not just "it compiles." |
| F4 | **Confirm the FR #10 security conditions C1–C7 are met as built** | High | The companion proposal *approved with conditions* (argon2id params pinned, HttpOnly/Secure/SameSite cookie + CSRF, self-healing lockout, fail-closed seed, old `sessionStorage` bearer fully removed, new auth events detectable). Code exists — **now confirm each condition is real** (this is GATE H, not yet done). |
| F5 | **EST is a fixed UTC-5 (no DST) by design — re-confirm post-#24** | Low | v2 decided EST = fixed offset; #24 reworked `formatTimestamp`. Make sure the fix didn't silently change the documented contract or break the DST tests. |
| F6 | **Test suite was recently red — make "green in CI" a hard gate (GATE D)** | Med | Commit `09741f9` is literally *"repair 7 pre-existing test failures ahead of GATE D"* — i.e. the suite was broken at HEAD~N and was patched to unblock the release, not because coverage improved. A SIEM must not tag with a flaky/just-patched suite. Promote **GATE D = full backend+frontend suite green in CI on a clean checkout** to a named, non-skippable tag blocker alongside E/F/H/I/J. (8 pytest files + 14 vitest files exist today.) |

---

## 8. Net-new quality-of-life capabilities

Proposed for **v4.0.0 "Analyst Workstation."** Tiered by value/effort. The recurring theme:
**leverage the per-analyst identity (#10) the v3 release introduces.** Every item flagged 🔐
has a security implication the reviewing agent should weigh.

### Tier 1 — high value, build on existing foundations
1. **Saved views & query history.** Persist named search/query-console filters per analyst.
   Query Console gets history + re-run; GlobalSearch + Events/Detections filters become saveable.
   *Builds on #10 identity + #16 export work; SQLite incidents DB already shows the storage
   pattern.*
2. **Command palette (⌘K / Ctrl-K).** Fuzzy navigation to any page/incident/saved view +
   quick actions. Single biggest "feels like a real tool" QoL win; low backend cost.
3. **Per-analyst preferences.** Default time range, table density, default landing page, theme
   density — stored against the identity. *Natural follow-on to #10.*
4. **Incident report export (PDF/Markdown/JSON).** One-click "export incident" bundling events,
   notes (#19), correlation snapshot, and timeline. Closes the loop from triage → report. 🔐
   *(reuse the #16 export util; reports must honor the same truncation/CSV-injection rules.)*
5. **Batch-completion / detection-hit notifications** via the now-shipped toast system (#23):
   surface "new high/critical hits since last batch" without a manual refresh.

### Tier 2 — meaningful capability, more design
6. **RBAC: analyst vs. admin roles.** 🔐 The dual-auth split (#10) is the seam for this. Admin-
   only: rule status changes, user seeding, service-token rotation. Analyst: read + incidents +
   notes. *This is arguably the headline v4 feature and the most defensible "major" justification.*
7. **In-UI Sigma rule authoring + dry-run.** 🔐 `rule_registry` exists with a lifecycle
   (draft→test→review→production→disabled) but no in-app authoring/test. Add a Sigma editor with
   a **SELECT-only dry-run** against recent events before promotion. *Must keep the fail-closed
   Sentinel-audit-before-ClickHouse contract.*
8. **Pipeline observability over time.** Today's `/v1/metrics` + `/v1/health` are point-in-time.
   Add short-horizon history (events/hr trend, parse-error rate trend, forward-latency trend) so
   analysts can spot degradation, not just current state.
9. **Sentinel-side read-back (closes the v2 "not available locally" gaps).** 🔐 v2 deliberately
   left `rate_limit_flood_panel`, batch duration, Vector status, and the SELF-005 *delta* as
   "Sentinel-side, not locally readable." A scoped Log-Analytics **read** client would fill them.
   **Heavy security trade-off:** adds a second egress consumer + a reader credential; must go
   through threat-modeling before it's in scope. *Flag, don't assume.*
10. **In-UI audit log viewer (admin-only).** 🔐 `audit_client.py` already emits an auth/audit
    trail (login, lockout, status changes) — but nothing surfaces it in the dashboard. An admin
    "Activity" page (read-only, paginated, filter by actor/action) is a high-value, low-cost win
    that *reuses an existing producer* and is the natural companion to RBAC (#6). This is the
    "who did what" view a multi-analyst tool needs and currently lacks. **Tier 1-grade value at
    Tier 2 effort** — recommend pulling into the v4 minimal set with RBAC.

### Tier 3 — nice-to-have / platform
11. **Playwright e2e smoke** (login → ingest → detect → correlate → export) wired into CI as a
    release gate. Hardens every future release.
12. **OpenAPI spec publication + generated typed client** so the React `client.ts` stays in sync
    with FastAPI shapes automatically.
13. **Correlation graph scaling.** The 200-node frontend cap is a hard wall; move aggregation
    server-side with progressive expansion for large incidents.
14. **First-run setup wizard** that pairs with the new admin-seed step (#10) — guided secrets
    check, admin creation, health verification.

---

## 9. Proposed sequencing & milestones

```
NOW ──► [Hygiene sprint]  C1–C8 cleanup + F1/F2 fixes        (small, unblocks credibility)
          │
          ├─► [v3.0.0 finish]  §5 FRs #19,#9,#16/#25,#18,#17,#12,#13/#14,#21,#20,#22
          │        │
          │        └─► Gates E/F/H/I/J  ──►  TAG v3.0.0   ◄── version coherence lands here
          │
          └─► [v4.0.0 plan lock]  pick from §8 (recommend Tier 1 + RBAC #6)
                   │
                   └─► build ──► Gates ──► TAG v4.0.0
```

- **Hygiene sprint is first and cheap.** It makes every later claim ("major release") credible
  and removes the placeholder-hash supply-chain hole before any tag.
- **v3 finish** is the bulk of near-term work; it's well-specified already (companion proposal +
  §5 ordering).
- **v4 scope is a decision, not a default** — see §10. Recommended minimal v4 = Tier 1 + RBAC.

---

## 10. Decisions / open questions for the owner

These need a ruling before the relevant work starts (the reviewing agent should pressure-test the
*recommended* answers, not just collect them):

1. **Release split — confirm two releases?** *Recommended:* yes — finish v3.0.0, then v4.0.0.
   *Alternative:* fold §8 Tier 1 into v3.0.0 (bigger, later, riskier security sign-off).
2. **v4 scope.** *Recommended:* Tier 1 (saved views, command palette, prefs, incident report,
   notifications) **+ RBAC (#6)**. Defer Sigma-authoring (#7) and Sentinel read-back (#9) to a
   later cycle given their security weight.
3. **Sentinel read-back (§8 #9) — in or out?** 🔐 Adds egress + a reader credential. *Recommended:*
   **out** of v4 until a threat model is done; it reopens the egress-surface question v2 was
   careful about.
4. **RBAC model depth.** Two fixed roles (analyst/admin) vs. configurable permissions.
   *Recommended:* start with two fixed roles; the dual-auth seam already supports it.
5. **Retroactive tagging.** OK to tag `v1.0.0`/`v2.0.0` on historical commits, or start clean
   from `v3.0.0`? *Recommended:* retro-tag for an honest history.
6. **What to do with the stale docs** (`changelog2.md`, the companion proposal's stale facts).
   *Recommended:* move to `docs/history/` + add superseded headers, don't delete (audit trail).

---

## 11. Where to grill this plan (for the reviewing agent)

Push hardest here — these are the load-bearing assumptions:

1. **The reconciliation in §2 is the foundation.** Re-verify it independently: is the UX-Wave
   really committed on `master`, or did I misread the git log? If §2 is wrong, §4–§9 shift.
2. **Is "two releases" right, or am I over-engineering process?** Argue the case for one release,
   or for shipping net-new QoL *before* finishing the UX wave. What does the owner actually get
   sooner under each option?
3. **RBAC as the v4 headline.** Is per-analyst RBAC genuinely "major," or is it scope creep on a
   single-operator localhost tool? Who are the multiple analysts on a localhost-only SIEM?
4. **The placeholder-hash gate (F2/GATE F).** Am I over-weighting it, or is it correctly a
   hard blocker for a security product? Could it be a fast-follow instead of a tag blocker?
5. **Sentinel read-back (§8 #9).** I recommended deferring it on security grounds — but it's the
   only thing that closes the v2 "not available locally" UX gaps. Is deferring it the right call,
   or am I leaving the dashboard permanently half-blind?
6. **Did I under-spec security for v4?** This is a SIEM. Every Tier-1 item that persists
   per-analyst state (saved views, prefs, reports) is new stored, attacker-relevant data. Where's
   the threat model? (I deliberately left it for the reviewer to demand.)
7. **Effort/value tiers in §8** are my judgment, not measured. Challenge any item's tier —
   especially command palette (claimed cheap) and incident report export (claimed reuse).
8. **Have I missed anything the issues/docs imply?** I read all 17 FRs, the v2 resolution, the
   red-team advisory (`advise.md`), and the architecture docs — but the grill should check whether
   any open FR is *also* already fixed in code (like the 5 I found), which would shrink §5.

---

## 12. Independent verification + deltas

*Added 2026-06-23 in the same session, by re-deriving the facts from the repo rather than trusting
the prose above. This is the §11.1 "re-verify the reconciliation" demand, executed. The next
reviewer should grill **these** findings, not re-run the same checks from scratch.*

### 12.1 §2 ground truth — CONFIRMED
- **No tags.** `git tag` is empty. Only branches: `master` + the stray
  `worktree-agent-aeffe313fd07e98d1` (confirms C4). ✅
- **Version drift is real and exactly as described:** `frontend/package.json` = `0.0.0`;
  `services/api/src/main.py:79` = `version="0.1.0"`; `docker-compose.yml:377` =
  `siemhunter/frontend:0.1.0`; `CHANGELOG.md` narrates `[2.0.0] - 2026-06-20` as released. Four
  surfaces, no tag backing any of them. ✅ (Note: the changelog header is `[2.0.0]`, while commit
  subjects say `v0.2.0` — the drift is even messier than §2's "three numbers"; it's *four*.)
- **Placeholder hashes confirmed in all 4 services** (`api`, `detection`, `forwarder`,
  `normalization`) — and *also* duplicated inside the stray worktree, which will trip any naive
  `grep`-based GATE F. The gate must scope to tracked paths or the worktree must be removed first
  (reinforces C4 → do C4 *before* wiring GATE F). ✅
- **All of #9–#25 still OPEN, #1–#8 CLOSED** — verified via `gh issue list --state all`. The 5
  fixed-but-open FRs (#10/#11/#15/#23/#24) confirmed. ✅
- **UX-Wave commits are on `master`, unreleased** — `ba0c721`, `75890a8`, `c288ae8`, `89364ba`,
  `25fa437`, `28cc40c` all present in `git log`. ✅

### 12.2 PLAN-CHANGING FINDING — GATE H is largely *met in code*, not just "code exists"
§7/F4 treats the FR #10 security conditions as "code exists — now confirm each is real." I
confirmed them by reading the source. They are **implemented and self-documented against the
condition IDs**:
- **C1 (argon2id explicit params):** `auth_analyst.py` pins `memory_cost=65536`, `time_cost=3`,
  `parallelism=1`, `hash_len=32`, `salt_len=16` — no library defaults. `needs_rehash` upgrade path
  present. ✅
- **C2 (cookie + CSRF):** `__Host-`-prefixed, `HttpOnly + Secure + SameSite=Strict + Path=/` with
  explicit `Max-Age`; CSRF double-submit via `X-CSRF-Token` using `secrets.compare_digest`,
  enforced on state-changing methods, GET/HEAD/OPTIONS exempt. ✅
- **C3 (self-healing lockout):** time-boxed throttle keyed on username + source, threshold 5,
  15-min cooldown. ✅
- **C5 (fail-closed seed):** API refuses *all* analyst auth until ≥1 user exists; no baked-in
  default password; `seed_admin` CLI is the only enrolment path. ✅
- **C6 (old bearer removed):** `client.ts` explicitly documents the XSS-readable
  `siemhunter_token` sessionStorage bearer is **gone**; what remains in sessionStorage is only the
  CSRF token (correct — it is *not* the credential; the session is the HttpOnly cookie). ✅

**Consequence for the plan:** GATE H is mostly a *confirmation/code-review* exercise, not new
build. This **shrinks v3 closeout risk** and means the security sign-off (GATE J) is reviewing a
real, intentional implementation. The grill should down-weight "auth is risky/unfinished" and
instead pressure: *are C4 (CSRF) and C7 (new auth events detectable in Sentinel — GATE I) actually
exercised by a test, and does the lockout state survive nothing because it's in-memory?* (see
12.4).

### 12.3 New hygiene item the proposal missed — test health (now folded in as F6 / GATE D)
Commit `09741f9` = *"fix(tests): repair 7 pre-existing test failures ahead of GATE D."* The suite
was **red at HEAD~N and patched to unblock**, which is exactly the kind of thing that hides
regressions. Treat "full suite green in CI on a clean checkout" as a named tag blocker (GATE D),
not an assumption. Today: 8 backend pytest files + 14 frontend vitest files.

### 12.4 Sharpened grilling targets for the next reviewer (in addition to §11)
1. **In-memory session + lockout state.** The analyst session store and the lockout throttle live
   in process memory (`threading.RLock`, in-memory cache). Implications the headline v4 RBAC story
   must answer: (a) an API restart logs out every analyst and **resets lockout counters** — a
   trivial brute-force reset via crash/restart; (b) it cannot scale past one API replica. Fine for
   a single-node localhost tool *today*, but RBAC-for-multiple-analysts (§8 #6) is sold as the
   "major" v4 feature on top of a session layer that doesn't persist. **Decide: is v4 RBAC honest
   without durable sessions?** This is the strongest counter to §11.3.
2. **GATE F vs. the stray worktree.** Wire the gate after C4 cleanup, or it false-positives on
   `.claude/worktrees/...`. Cheap, but a real ordering bug in §9's "hygiene first" sequence.
3. **Audit viewer (§8 #10) vs. RBAC ordering.** The audit producer already exists; surfacing it is
   arguably *more* defensible as the v4 headline than RBAC, since it delivers value even with two
   fixed roles and needs no new persistence model. Challenge whether RBAC or the audit/activity
   view is the true v4 anchor.
4. **"Major" semver honesty.** With no prior tags, the first real tag being `v3.0.0` asserts two
   major releases that were never cut. Either retro-tag (§10.5) or start the public history at
   `v1.0.0` and let the changelog narrate the pre-tag history — but don't tag `v3.0.0` as the
   *first* tag, which reads as vanity versioning for a security tool whose credibility is the
   product.

### 12.5 What I did NOT independently verify (open for the next agent)
- End-to-end runtime behavior of the 5 in-code fixes (F3) — I confirmed they're *committed*, not
  that they *work* against a live stack. Still genuinely open.
- GATE I (new auth events actually land in Sentinel / SELF-003 still fires) — `audit_client.py`
  exists as the producer, but the Sentinel-side detection was not exercised here.
- Whether the placeholder-hash regeneration (GATE F) has any pinned-version conflicts — untested.

---

*End of proposal. This document makes recommendations only; it authorizes no code changes,
no tags, and no destructive cleanup until the owner rules on §10. §12 reflects an independent
re-verification; the runtime checks in §12.5 remain open for the grilling agent.*
