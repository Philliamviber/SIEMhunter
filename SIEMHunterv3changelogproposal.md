> **AS-BUILT UPDATE (PR2 — 2026-06-23):** The authoritative orchestration plan derived from
> this proposal has been executed as `docs/newreleaseplan/proposalplan.md`. Refer to that
> document for the current task sequence, gate status, and per-PR handoff notes.

# SIEMhunter v3.0.0 — "UX Wave" Major Release Proposal & SDLC Orchestration Plan

> **Status:** Planning artifact — proposal only. No code changes are authorized by this
> document. It defines the scope, phased delegation, quality gates, and security sign-off
> for shipping the 17 open UX feature requests (FR #9–#25) as a single **v3.0.0 major
> release** on top of the shipped **v2.0.0**.
>
> **Authored by:** main orchestrator, folding in the `tech-lead` delegation plan and the
> `security-architect` GATE B sign-off.
> **Date:** 2026-06-20 · **Target version:** 3.0.0 · **Current shipped:** 2.0.0

---

## 0. How to read this document

1. [Release framing](#1-release-framing) — why this is a major bump, the one-line theme.
2. [Scope](#2-scope--17-open-feature-requests-9-25) — the 17 FRs, folds, dependencies.
3. [Phased plan](#3-phased-plan) — P0 → P3 sequencing.
4. [Per-phase delegation tables](#4-per-phase-delegation-tables) — every FR → owning subagent.
5. [SDLC quality gates](#5-sdlc-quality-gates) — the ordered gate sequence A–J.
6. [Decisions / open questions](#6-decisions--open-questions) — rulings, with owner asks.
7. [Security design sign-off (GATE B)](#7-security-design-sign-off--gate-b) — conditions C1–C7
   and the acceptance checklist that gates the tag.
8. [Release / versioning mechanics](#8-release--versioning-mechanics).
9. [Ready-to-run invocations](#9-ready-to-run-invocations) — the build, step by step.
10. [Proposed CHANGELOG.md entry](#10-proposed-changelogmd-entry-draft).

---

## 1. Release framing

- **Version:** **v3.0.0 (major).** Current shipped is v2.0.0; `frontend/package.json` still
  reads `0.0.0` and must be corrected to `3.0.0`.
- **Why major (breaking):** FR #10 replaces the paste-token `TokenGate` with a per-analyst
  `LoginGate`. The client auth contract changes (a server-issued session credential instead
  of a pasted static token), and the operator must perform a **first-run admin seed** before
  anyone can log in. This is a breaking operational change to the auth contract, so SemVer
  requires a major bump.
- **Theme (one line):** *Turn a working-but-rough console into a usable, accountable, secure
  analyst workstation — real per-analyst login, fixed navigation/scoping bugs, and a cohesive
  UX layer (toasts, search export, responsive, accessibility).*

### Grounded facts confirmed by repo read

- **No CI exists.** `.github/workflows/` is absent. The P0 pipeline is greenfield.
- **Static-token auth** lives in `services/api/src/auth.py`: loaded once from
  `/run/secrets/api_token`, compared with `hmac.compare_digest`, and `verify_token` is the
  `Depends(...)` on protected routes. `AuthFailure` events already flow to
  `SIEMHunterSecurity_CL` in Sentinel (SELF-003 path), best-effort and non-blocking.
- **Client** (`frontend/src/api/client.ts`): the bearer is read from `sessionStorage` key
  `siemhunter_token` and injected on every `request()` and `uploadFile()`. `clearToken()`
  exists but is **never called** — there is no logout anywhere.
- **Gate placement** (`frontend/src/App.tsx`): `TokenGate` renders **outside** the Router and
  **outside** `QueryClientProvider`. The new `LoginGate` must preserve that outside-Router
  placement.
- **Incident notes** are currently `localStorage`-only and never sent to the API. FR #19
  makes them server-side — this is net-new API + storage.
- **Incident search scope is already server-enforced.** `services/api/src/routers/search.py`
  applies the `incident_id` filter server-side (MUST-11, parameterized). FR #15 is a
  **front-end plumbing bug** — `GlobalSearchBar.tsx` never sends the active `incident_id` —
  not a server authz gap. (Confirmed by security review.)
- **AI posture:** `GET /v1/ai/summary` sends aggregated statistics only — no raw event
  fields — to the Claude API, enforced by the system prompt in
  `services/api/src/routers/ai_summary.py`. This contract must be preserved by #16/#25.
- **Owner comment on FR #10 (GitHub):** *"token insert still needs to be provided and
  available."* → the static token is **retained as a non-interactive service-account /
  break-glass path** alongside the new per-analyst login.

---

## 2. Scope — 17 open feature requests (#9–#25)

Full specs: `docs/feature-requests/FR-0NN-*.md`. Two items (**#11**, **#15**) are
shipped-but-broken bugs verified against source; **#24** is also a correctness bug.

| FR | Title | Pri | Size | Type |
|---:|-------|:---:|:----:|------|
| #9 | Render the AI chatbar once globally (in `PageLayout`) | P2 | S | refactor |
| **#10** | **Secure per-analyst username/password login gate** | **P1** | L | **security** |
| **#11** | **Fix dead `EventDetailPanel` pivot links** | **P1** | M | **bug** |
| #12 | Upload progress, cancel, multi-file, post-upload refresh | P2 | M | enhancement |
| #13 | Correlation graph tooltips, search, reset/zoom | P2 | M | enhancement |
| #14 | Correlation entity↔event panel stacking | P3 | S | ux (**fold → #13**) |
| **#15** | **Apply active incident scope to global search** | **P1** | S | **bug + security** |
| #16 | Search empty-state, persistence, CSV/JSON export, IOC copy | P2 | M | enhancement |
| #17 | Incidents list filter/sort/search | P2 | M | enhancement |
| #18 | Incident status confirm + success/error feedback | P2 | S | ux |
| #19 | Functional server-side incident Notes (audit-aware) | P2 | M | security |
| #20 | `IncidentSelector` keyboard/ARIA combobox | P2 | S | accessibility |
| #21 | Category drill-down truncation / load-more / scope | P2 | M | enhancement |
| #22 | Responsive/mobile layout + collapsible sidebar | P3 | M | ux |
| #23 | Global toast/notification system + 401→login routing | P2 | M | enhancement |
| **#24** | **Fix `formatTimestamp` hardcoded UTC-5 "EST"** | P2 | S | **bug** |
| #25 | `EventDetailPanel` copy/export JSON + show-empty-fields | P3 | S | ux (**fold → #16**) |

### Folds (explicit)

- **#14 → #13** — same components, one PR; correlation panel stacking ships with the
  correlation controls work.
- **#25 → #16** — both need a shared **export utility** (CSV/JSON serializer + clipboard IOC
  copy). Build it once in #16; #25 consumes it.

### Dependency ordering

- **#19 depends on #10** — note author attribution requires the per-analyst identity #10
  introduces. #19 build cannot start until #10's identity model is implemented and reviewed.
- **#23 pairs with #10** — build the toast provider in parallel, but wire 401→login after
  #10's session contract is fixed.
- **#16 builds the export util; #25 consumes it** (so #25 follows #16).
- **#18 consumes #23** (status feedback uses the toast system).

---

## 3. Phased plan

### Phase 0 — Platform foundations (blocks everything; security-gated by GATE B)

Greenfield CI/CD pipeline · FR #10 secure login · FR #23 toast + 401 routing.

### Phase 1 — Bugs (high-value, low-risk; can run alongside late P0)

#11 (dead pivot links / `EventsPage` ignores URL params) · #15 (front-end never sends the
active `incident_id` scope) · #24 (`formatTimestamp` hardcoded UTC-5 "EST").

### Phase 2 — Enhancements

#9 (global chatbar) · #12 (upload UX) · #13 (+#14 correlation controls + stacking) ·
#16 (+#25 search export + IOC copy + shared util) · #17 (incidents list controls) ·
#18 (status confirm/feedback) · #19 (server-side notes — *after #10*) · #21 (category
drill-down).

### Phase 3 — Polish / a11y / responsive

#20 (`IncidentSelector` combobox) · #22 (responsive + collapsible sidebar) · fold
verification (#14 in #13, #25 in #16).

---

## 4. Per-phase delegation tables

Bench legend: `requirements-analyst`, `security-architect`, `threat-modeler`, `iam-engineer`,
`implementer`, `implementation-lead`, `debugger`, `test-engineer`, `code-reviewer`,
`devops-engineer`, `cloud-security-engineer`, `detection-engineer`, `docs-maintainer`,
`tech-writer`.

### Phase 0 — Foundations

| Item | Primary | Supporting | Deliverable |
|---|---|---|---|
| Requirements lock for P0 | `requirements-analyst` | — | Confirmed acceptance criteria for #10/#23 + dual-auth route-matrix questions for owner |
| **#10 security design** (auth model, dual-auth split, session mechanism, lockout, seed) | `security-architect` | `iam-engineer`, `threat-modeler` | Auth design doc → **GATE B** (see §7) |
| #10 threat model | `threat-modeler` | `security-architect` | STRIDE of login surface (CSRF, session fixation, enumeration, lockout-as-DoS, token-in-storage XSS, break-glass misuse) → feeds GATE C |
| **CI/CD pipeline (greenfield)** | `devops-engineer` | `cloud-security-engineer` | `.github/workflows/`: frontend (tsc/eslint/vitest+coverage), API (pytest), Docker build, dependency-hash verification; branch protection requiring green |
| #10 backend build (login/logout/session, argon2id store, lockout, seed CLI, dual-auth deps) | `iam-engineer` | `implementer`, `implementation-lead` | New `auth_login` module + endpoints; `auth.py` refactored into `require_analyst_session` + `require_service_token` with distinct audit labels |
| #10 frontend build (`LoginGate`, logout, idle timeout, session-credential wiring) | `implementer` | `implementation-lead` | `LoginGate.tsx`, logout control, updated `client.ts` |
| #23 toast system + 401→login routing | `implementer` | — | Global toast provider; central 401 interceptor in `client.ts` |
| #10/#23 tests | `test-engineer` | — | API: login, lockout default 5, logout invalidation, dual-auth enforcement, no-plaintext, enumeration timing; vitest: LoginGate/idle/401-redirect |
| #10/#23 code review | `code-reviewer` | `security-architect` | Confirms the GATE B design was actually implemented → **GATE H** |
| #10 docs | `docs-maintainer` | `tech-writer` | First-run admin seed, dual-auth operator guide, auth migration notes |

### Phase 1 — Bugs

| FR | Primary | Supporting | Deliverable |
|---|---|---|---|
| #11 `EventsPage` ignores URL params | `debugger` | `implementer`, `test-engineer` | Parse pivot URL params into filter state; URL reflects active filters; regression test |
| #15 search ignores active `incident_id` | `debugger` | `security-architect`, `test-engineer` | `GlobalSearchBar` reads `activeIncidentId` and sends it; scope chip + "Search all" opt-out; confirm server still enforces scope (no regression) |
| #24 `formatTimestamp` hardcoded UTC-5 | `implementer` | `test-engineer` | Replace with `Intl.DateTimeFormat`; DST-boundary tests |

### Phase 2 — Enhancements

| FR | Primary | Supporting | Deliverable |
|---|---|---|---|
| #9 global AI chatbar | `implementer` | `code-reviewer` | Single chatbar hoisted into `PageLayout`; eight per-page renders removed |
| #12 upload progress/cancel/multi-file/refresh | `implementer` | `test-engineer` | XHR/`AbortController` upload with progress + cancel + multi-file queue + post-upload query invalidation |
| #13 (+#14) correlation controls + panel stacking | `implementer` | `test-engineer` | Node/edge tooltips, find-entity, reset/zoom, multi-EID edges; folded panel-stacking fix |
| #16 (+#25) search export + IOC copy + **shared util** | `implementer` | `security-architect`, `test-engineer` | CSV+JSON export utility (shared), clipboard IOC copy, persistence/empty-state; CSV-injection escaping; truncation note surfaced |
| #25 `EventDetailPanel` copy/export JSON | `implementer` | — | Consumes #16 export util (after #16) |
| #17 incidents list filter/sort/search | `implementer` | `test-engineer` | Status/severity filter, name search, column sort, URL-persisted filters |
| #18 incident status confirm + feedback | `implementer` | — | Confirm dialog for Close/Archive + toast feedback (consumes #23) |
| #19 server-side incident notes (append-only, attributed) — **after #10** | `implementer` | `security-architect`, `iam-engineer`, `test-engineer` | Notes API + schema (`db_incidents`), server-set timestamp+author, append-only, plain-text-safe |
| #21 category drill-down truncation/load-more/scope | `implementer` | `test-engineer` | "showing 500 of N" + load-more / refine CTA + failed-count explainer + optional scope |

### Phase 3 — Polish / a11y / responsive + closeout

| Item | Primary | Supporting | Deliverable |
|---|---|---|---|
| #20 `IncidentSelector` combobox | `implementer` | `test-engineer` | WAI-ARIA listbox, arrow/Escape nav, focus return, Clear moved out of trigger |
| #22 responsive + collapsible sidebar | `implementer` | `test-engineer` | Collapsible sidebar, viewport-capped panels, wrapping search bar; works to ~768px |
| Fold verification (#14 in #13, #25 in #16) | `code-reviewer` | — | Confirms folded scope landed |
| Full regression pass | `test-engineer` | — | Coverage meets gate threshold → **GATE E** |
| Detection coverage of new auth events | `detection-engineer` | — | New auth events labeled + detectable in Sentinel; SELF-003 still fires → **GATE I** |
| Final code review | `code-reviewer` | — | All FRs reviewed |
| Final security sign-off | `security-architect` | `cloud-security-engineer` | → **GATE J** |
| Version bump + CHANGELOG + tag + migration notes | `docs-maintainer` | `tech-writer` | v3.0.0 release notes |

---

## 5. SDLC quality gates

Ordered flow: **A → B (+C) → [P0 build under D] → H → [P1/P2/P3 build under D/E] → F → I → J → tag.**

| Gate | Name | Owner | Blocks | Pass criteria |
|---|---|---|---|---|
| **A** | Requirements lock | `requirements-analyst` | P0 design start | #10/#23 acceptance criteria confirmed; dual-auth questions escalated to owner |
| **B** | **Security design approval** | `security-architect` | **ALL Phase 0 build** | Auth design + threat model approved (see §7 — **conditionally passed**) |
| **C** | Threat model accepted | `threat-modeler` | merged into B | Must enumerate: account-DoS via lockout, XSS→session-theft (old + new storage), CSRF on write routes, break-glass token misuse |
| **D** | CI green | `devops-engineer` | every merge to main | Lint + type-check + unit/integration tests pass |
| **E** | Test coverage threshold | `test-engineer` | phase exit | Coverage at/above bar; #10 paths (lockout, logout, dual-auth, enumeration timing, no-plaintext, 401→login) explicitly covered |
| **F** | Dependency-hash regen | `devops-engineer` | v3.0.0 tag | No hash equals the `placeholder` sentinel; lockfile regenerated from a trusted resolver run |
| **H** | **Code review confirms security design implemented** | `code-reviewer` + `security-architect` | auth-dependent build (#19) and tag | Implementation matches GATE B design and the §7 checklist — not just "it works" |
| **I** | Detection coverage of new auth events | `detection-engineer` | GATE J | login/fail/lockout/logout/expiry/service-token-use reach `SIEMHunterSecurity_CL`; brute-force detection fires; audit writes remain best-effort/non-blocking |
| **J** | **Final security sign-off before tag** | `security-architect` | v3.0.0 git tag | All security FRs verified end-to-end against §7 checklist; gates D/E/F/H/I closed |

---

## 6. Decisions / open questions

These are the rulings carried into GATE B. Items marked **OWNER** need a yes/no before that
phase's build; the rest are decided.

1. **FR #10 dual-auth reconciliation** *(decided; route matrix = **OWNER**)*
   Keep the static token as a **non-interactive service-account / break-glass** credential,
   removed from the interactive login UI. Implement two distinct FastAPI dependencies:
   - `require_analyst_session` — per-analyst login session; all browser-facing routes.
   - `require_service_token` — existing `hmac.compare_digest` static-token path; automation /
     CLI / break-glass.
   Most routes accept **either**, but write/audit-sensitive routes (notes #19, status PATCH,
   rule status, uploads) record **which path authenticated** (`AuthMethod=analyst_session`
   vs `service_token`). Login/logout/session routes **never** accept the service token.
   **OWNER ask:** confirm the exact route-by-route matrix (which routes allow the service
   token, which are analyst-only).
  **Owner answer:** use your best judgement. Upon launching the site, there should be an option.


2. **Session mechanism** *(decided)*
   **HttpOnly + Secure + SameSite=Strict cookie + CSRF token**, over the current
   XSS-readable `sessionStorage` bearer. Service-token path keeps `Authorization: Bearer`.
   The "fall back to short-lived bearer-in-JS" option is **rejected** by security review (it
   reintroduces the XSS exposure this change exists to remove). If CSRF token wiring proves
   too costly, the only acceptable fallback is HttpOnly cookie + SameSite=Strict + a
   server-side `Origin`/`Referer` allowlist on state-changing requests. See §7 / C2.

3. **FR #19 notes — append-only vs versioned** *(decided)*
   **Append-only**: each note an immutable, timestamped, attributed row; "edit" = a new
   appended entry. Plain-text/escaped rendering, no `dangerouslySetInnerHTML`. Author +
   timestamp set **server-side** from the authenticated identity (never client-supplied).

4. **FR #16/#25 export vs AI posture** *(decided — hard constraint)*
   Export/clipboard operate on **client-side query/search results only** and never route
   through `GET /v1/ai/summary`; the aggregated-only AI contract is untouched. Exports must
   carry the **10,000-row truncation note** when results are capped, and CSV cells starting
   with `= + - @` must be escaped against CSV injection.

5. **Release hygiene — dependency hashes** *(decided)*
   `--hash=sha256:placeholder_regenerate_before_deploy` must be regenerated as a **hard
   v3.0.0 CI gate (GATE F)**, not a follow-up. Shipping a major *security* release with
   placeholder hashes contradicts the supply-chain posture.

---

## 7. Security design sign-off — GATE B

**Reviewer:** `security-architect` (advisory). **Decision:** this section is GATE B.
**Verdict: APPROVED WITH CONDITIONS.** The design is a genuine improvement over the shared
static-token model and is **not** sent back for redesign. Approval is conditional on the
following being treated as **binding design parameters**, not implementer's-choice.

### Conditions (all must hold at GATE J)

- **C1.** Argon2id parameters pinned to a named profile — interactive baseline **memory
  19–64 MiB, time cost 2–3, parallelism 1**, 16-byte salt, 32-byte output, via
  `argon2-cffi` `PasswordHasher` with **explicit** constructor args (no moving library
  default); store the full encoded hash and support `needs_rehash`. bcrypt acceptable only at
  cost ≥ 12 with password byte-length capped (72-byte truncation footgun).
- **C2.** Session cookie carries the full attribute set — `HttpOnly`, `Secure`,
  `SameSite=Strict`, explicit `Path=/`, explicit expiry/`Max-Age`, and a `__Host-` name
  prefix on single-host HTTPS. **CSRF defense is mandatory** for the cookie path (double-
  submit or synchronizer token). The "bearer-in-JS fallback" is **rejected**. Dev-over-HTTP
  must not silently drop `Secure`/`__Host-` into a release artifact.
- **C3.** Lockout is a **time-boxed, self-healing throttle** keyed on **username + source
  IP**, not a permanent hard lock — to avoid turning FR #10 into an account-DoS during a live
  incident. Default 5 is the cooldown trigger; break-glass (service token) is the documented
  recovery path.
- **C4.** The service-token break-glass path must be (a) auditable on every use, (b) excluded
  from acting as a CSRF bypass for browser-origin requests, and (c) documented with a named
  rotation owner.
- **C5.** First-run admin seed **fails closed**: the API refuses authenticated analyst
  sessions until a credential exists and never auto-creates a default password (no TOCTOU
  window where the app is up, unseeded, and an attacker seeds the first admin).
- **C6.** New auth events (login success/failure, lockout, logout, session-expiry,
  service-token use on sensitive routes) reach `SIEMHunterSecurity_CL` with detection
  coverage (GATE I) before GATE J; audit writes stay best-effort/non-blocking.
- **C7.** The old `sessionStorage` bearer (`siemhunter_token`) is **fully removed** from the
  browser path once the cookie session lands — deleted, not commented out. Shipping both is a
  net XSS regression.

### Per-ruling assessment (maps to §6)

1. **Dual-auth — CONFIRMED**, with C1/C3/C4 and the user-enumeration control: identical
   message *and* comparable timing for unknown-user vs wrong-password (run a decoy argon2id
   verify on the unknown-user path); lockout messaging must not confirm account existence.
2. **Session mechanism — CONFIRMED (cookie); fallback REJECTED (C2).** Add two timers — idle
   timeout (~15–30 min) **and** an absolute session lifetime (~8–12 h / one shift). Sessions
   must be **server-side revocable** (a server session store or signed token + revocation
   list) so logout truly invalidates (FR #10 AC#6). Authenticated responses set
   `Cache-Control: no-store`; `LoginGate` re-validates the session on mount/focus, not from a
   stale in-memory flag (AC#6 back-button requirement).
3. **#19 notes — CONFIRMED, no change.** Author/timestamp server-set; parameterized inserts;
   React default escaping; no HTML/markdown sink.
4. **#16/#25 export — CONFIRMED as a hard constraint.** Verified `ai_summary.py` sends
   aggregated-only with the API key secret-only/never-logged. Export must have **zero call
   edges** to `/v1/ai/summary` or the Anthropic client; surface `truncated`; escape CSV
   injection.
5. **Dependency hashes — CONFIRMED** as a blocking gate (GATE F); fail if any hash equals the
   `placeholder` sentinel.

### Gate confirmation

GATE B/H/J **confirmed**. Added gates **confirmed**, with two strengthenings: GATE C must
explicitly enumerate the four threats in C-row above; GATE I is **not optional** — a new auth
system with no detection on its own abuse is a blind spot (extend the existing SELF-003 /
`AuthFailure` path).

### Residual risks to watch during build

1. **Two credential paths coexisting** (highest) — enforce C7; the dead bearer path must be
   deleted.
2. **Local-HTTP dev vs Secure cookies** — don't let the relaxation leak into the release.
3. **Session revocation** — beware drift toward stateless tokens that can't be revoked
   server-side (breaks AC#6).
4. **Lockout during live incidents** — keep cooldown sane; test break-glass recovery.
5. **CSV injection** in exports of attacker-controlled fields.
6. **First-run seed TOCTOU** (C5).
7. **Audit-write independence regression** — preserve the existing best-effort,
   non-blocking Sentinel write for the new events.

### Security acceptance checklist (verified at GATE H and GATE J)

**Authentication & password storage**
- [ ] argon2id (or pinned-cost bcrypt) with explicit documented params (C1); `needs_rehash` path exists.
- [ ] No plaintext password in code, config, logs, responses, or client storage (bundle + network grep clean) (AC#5).
- [ ] Unknown-user and wrong-password return identical message **and** comparable timing (decoy verify) (AC#3).

**Session**
- [ ] HttpOnly + Secure + SameSite=Strict cookie with explicit Path + expiry; `__Host-` where single-host HTTPS (C2).
- [ ] No interactive-session credential readable by JS; old `sessionStorage` `siemhunter_token` removed (C7).
- [ ] CSRF protection on all state-changing browser routes (C2).
- [ ] Idle timeout **and** absolute lifetime enforced server-side (AC#7).
- [ ] Logout invalidates server-side and clears the cookie; session is server-revocable (AC#6).
- [ ] Authenticated responses `Cache-Control: no-store`; back button does not restore the console post-logout (AC#6).
- [ ] Any API 401 hard-redirects to login; `LoginGate` re-validates session on mount (AC#8).

**Lockout / rate limiting**
- [ ] Time-boxed, self-healing throttle+lockout keyed on username+IP; default trigger 5; server-enforced; never permanent without admin/break-glass reset (C3, AC#4).

**Dual-auth & break-glass**
- [ ] `require_analyst_session` and `require_service_token` are distinct deps; login/logout/session routes reject the service token.
- [ ] All state-changing/audit routes record `AuthMethod`.
- [ ] Static service token retained, Docker-secret-only, documented break-glass with named rotation owner (C4).

**First-run**
- [ ] Operator-driven initial-admin seed; no baked-in default; API refuses analyst auth until seeded, fail-closed (C5, AC#9).

**Notes (#19)**
- [ ] Append-only immutable rows; edit = new entry; parameterized inserts.
- [ ] Author + timestamp server-set from authenticated identity; client-supplied author ignored.
- [ ] Plain-text/escaped rendering; no `dangerouslySetInnerHTML`/unsanitized sink.

**Search scope (#15)**
- [ ] Scope enforced server-side (already met by `search.py` MUST-11); client cannot strip the filter; "Search all" is an explicit per-search opt-out, not a default leak.

**Export / AI posture (#16/#25)**
- [ ] Export/clipboard use local results only; zero call edges to `/v1/ai/summary` or the Anthropic client.
- [ ] AI summary remains aggregated-only; API key secret-only, never logged.
- [ ] Truncation note surfaced in every export; CSV cells with leading `= + - @` escaped.

**Detection & audit (GATE I)**
- [ ] login-success/failure, lockout, logout, session-expiry, service-token-use-on-sensitive-route reach `SIEMHunterSecurity_CL` (C6).
- [ ] Brute-force/lockout detection fires; audit writes best-effort and never block login/401.

**Supply chain**
- [ ] No dependency hash equals the `placeholder` sentinel; lockfile regenerated from a trusted resolver run (GATE F).

> Optional follow-up offered by the reviewer: capture the dual-auth split, cookie-over-
> sessionStorage decision, and the rejected bearer-in-JS fallback as an ADR under
> `docs/adr/`. Not required for this proposal.

---

## 8. Release / versioning mechanics

Owner: `docs-maintainer` (with `tech-writer`), after GATE J.

- **Bump** `frontend/package.json` `0.0.0 → 3.0.0`; bump the FastAPI app metadata version and
  the `docker-compose.yml` image tags for consistency.
- **CHANGELOG.md** — new `## [3.0.0]` entry (draft in §10): **Added** / **Changed
  (BREAKING)** / **Fixed** / **Security**.
- **Migration notes (breaking auth)** — headline operator actions:
  - First-run **admin seed** procedure (env-seeded one-time or CLI; never a baked-in default).
  - Analysts now log in with username/password; the pasted static token is no longer the
    interactive path.
  - `secrets/api_auth_token.txt` is **retained** as the service-account / break-glass
    credential — document which routes accept it and how its use is audited (`AuthMethod`).
  - Session/idle-timeout behaviour and logout.
- **Git tag** `v3.0.0` only after GATE J passes and gates D/E/F/H/I are green.

---

## 9. Ready-to-run invocations

The main conversation executes these; a subagent cannot call another subagent. Dispatch
independent steps together; serialize only the dependency edges (#19 after #10, #25 after #16,
all P0 build after GATE B, #18 after #23).

**Phase 0**
- `requirements-analyst`: lock acceptance criteria for FR #10 and FR #23; surface the dual-auth route-matrix questions for owner sign-off. *(GATE A)*
- `security-architect`: produce the FR #10 auth design — session mechanism, route-by-route dual-auth matrix, distinct audit labels, argon2id params, lockout policy (default 5), first-run admin seed. *(GATE B — see §7)*
- `threat-modeler`: STRIDE the new login surface (CSRF, session fixation, enumeration, lockout-as-DoS, token-in-storage XSS, break-glass misuse). *(GATE C)*
- `devops-engineer`: create the greenfield `.github` CI/CD pipeline (frontend tsc/eslint/vitest+coverage, API pytest, Docker build, dependency-hash verification) + branch protection. *(GATE D/F)*
- `iam-engineer`: build the FR #10 backend — login/logout/session endpoints, argon2id store, server-side lockout, first-run seed CLI; refactor `auth.py` into `require_analyst_session` + `require_service_token`.
- `implementer`: build the FR #10 frontend `LoginGate` (replacing `TokenGate`), sidebar logout, idle timeout, session-credential wiring in `client.ts`.
- `implementer`: build the FR #23 toast system + central 401→login routing in `client.ts`.
- `test-engineer`: API + vitest tests for #10/#23 (login, lockout, logout invalidation, dual-auth enforcement, enumeration timing, no-plaintext, 401 redirect).
- `code-reviewer` (+`security-architect`): confirm the GATE B design was implemented. *(GATE H)*
- `docs-maintainer`: document first-run seed, dual-auth operator guide, auth migration notes.

**Phase 1**
- `debugger`: fix FR #11 (`EventsPage` URL params / dead pivot links) + regression test.
- `debugger`: fix FR #15 (`GlobalSearchBar` send active `incident_id`); `security-architect` confirms no server-scope regression.
- `implementer`: fix FR #24 — `Intl.DateTimeFormat` in `formatTimestamp.ts` + DST-boundary tests.

**Phase 2**
- `implementer`: FR #9 single global AI chatbar in `PageLayout`.
- `implementer`: FR #12 upload progress/cancel/multi-file/post-upload refresh.
- `implementer`: FR #13 correlation tooltips/search/reset-zoom + fold #14 panel stacking.
- `implementer`: FR #16 search empty-state/persistence/CSV+JSON export + IOC clipboard + shared export util (preserve AI posture + truncation note; CSV-injection escaping).
- `implementer`: FR #25 `EventDetailPanel` copy/export JSON + show-empty-fields (consumes #16 util).
- `implementer`: FR #17 incidents list filter/sort/search.
- `implementer`: FR #18 incident status confirm + feedback (uses #23 toasts).
- `implementer`: FR #19 server-side append-only incident notes (server-set author/timestamp, plain-text-safe) — after #10.
- `implementer`: FR #21 category drill-down truncation/load-more/scope.

**Phase 3 + closeout**
- `implementer`: FR #20 `IncidentSelector` keyboard/ARIA combobox.
- `implementer`: FR #22 responsive/mobile + collapsible sidebar.
- `test-engineer`: full v3.0.0 regression pass + coverage gate. *(GATE E)*
- `detection-engineer`: verify new auth events labeled/detectable in Sentinel; SELF-003 still fires. *(GATE I)*
- `code-reviewer`: final review across all FRs + fold verification (#14 in #13, #25 in #16).
- `security-architect`: final v3.0.0 security sign-off before tag. *(GATE J)*
- `docs-maintainer` (+`tech-writer`): bump `frontend/package.json` to 3.0.0, write the CHANGELOG v3.0.0 entry + auth-breaking migration notes, prepare the `v3.0.0` tag.

---

## 10. Proposed CHANGELOG.md entry (draft)

```markdown
## [3.0.0] - 2026-XX-XX

"UX Wave" — 17 UX feature requests (#9–#25) on top of v2.0.0.

### Changed (BREAKING)
- Auth: replaced the paste-the-token `TokenGate` with a per-analyst username/password
  `LoginGate`. Operators must perform a first-run admin seed before login (#10).
- The static API token is retained as a non-interactive service-account / break-glass
  credential only; it is no longer the interactive login path (#10).

### Added
- Per-analyst login with argon2id-hashed credentials, server-signed sessions,
  lockout, idle/absolute timeout, and explicit logout (#10).
- Global toast/notification system with consistent error surfacing and 401→login
  routing (#23).
- Server-side, append-only incident Notes timestamped and attributed to the
  logged-in analyst (#19).
- Search & event export: CSV/JSON export, clipboard IOC copy, empty-state and
  persistence (#16, #25).
- Correlation graph tooltips, entity search, reset/zoom, multi-EventID edges, and
  improved entity↔event panel stacking (#13, #14).
- Upload progress, cancel, multi-file, and post-upload refresh (#12).
- Incidents list filtering, sorting, and search (#17); status-change confirmation
  and feedback (#18); category drill-down "showing 500 of N" with load-more (#21).
- Single global AI Analysis chatbar across all pages, including Health (#9).
- Responsive/mobile layout with a collapsible sidebar (#22); accessible
  `IncidentSelector` combobox (#20).

### Fixed
- `EventDetailPanel` pivot links now actually filter the Events page (#11).
- Global search now applies the active incident scope instead of silently ignoring
  it (#15).
- Timestamps now show correct local time/timezone via `Intl.DateTimeFormat` instead
  of a hardcoded UTC-5 "EST" (#24).

### Security
- Removed the XSS-readable `sessionStorage` bearer; session credential is now an
  HttpOnly/Secure/SameSite=Strict cookie with CSRF protection (#10).
- Dual-auth model with per-path audit attribution (`AuthMethod`) and new auth-event
  detection coverage in Sentinel (#10).
- Regenerated all dependency hashes (removed `placeholder` sentinels) as a release
  gate.
```
