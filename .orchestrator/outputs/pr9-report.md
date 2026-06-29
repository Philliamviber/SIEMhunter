# PR9 — Cut v4.0.0 (gates + local tag) — Audit Report

**Branch:** 4.0
**PR9 commit:** b8db3fb
**Annotated tag:** v4.0.0 → b8db3fb
**Date:** 2026-06-29

---

## Files changed (commit b8db3fb)

| File | Change |
|------|--------|
| `frontend/package.json` | `"version"` bumped `4.0.0-dev` → `4.0.0` |
| `services/api/src/main.py` | `version=` in `FastAPI(...)` bumped `4.0.0-dev` → `4.0.0` |
| `docker-compose.yml` | `image: siemhunter/frontend:` tag bumped `4.0.0-dev` → `4.0.0` |
| `CHANGELOG.md` | `[Unreleased]` header replaced with `[4.0.0] - 2026-06-29`; PR2–PR8 entries added |
| `docs/release/v4.0.0-gate-status.md` | Created — gates D/E/F/H/I/K evidenced as MET; J PENDING |

---

## Acceptance item verification

### 1. All three version surfaces read `4.0.0`

| Surface | File | Verified value |
|---------|------|---------------|
| Frontend npm | `frontend/package.json` line 4 | `"version": "4.0.0"` |
| FastAPI | `services/api/src/main.py` line 91 | `version="4.0.0"` |
| Docker image | `docker-compose.yml` line 377 | `image: siemhunter/frontend:4.0.0` |

No residual `4.0.0-dev` strings in any of these files.

### 2. CHANGELOG `[4.0.0]` section is complete

`CHANGELOG.md` now opens with `## [4.0.0] - 2026-06-29` and contains entries for:
- PR2: per-analyst persistence + preferences
- PR3: saved views + query history
- PR4: command palette (Ctrl-K)
- PR5: incident report export (Markdown/JSON/PDF)
- PR6: batch-hit notifications
- PR7: Sigma authoring + SELECT-only dry-run
- PR8: rule lifecycle + admin-gated promotion + fail-closed audit + SELF-006
- Changed: version bump note
- Security: per-analyst data controls, dry-run enforcement, rule mutation gating, SELF-006

### 3. `docs/release/v4.0.0-gate-status.md` records evidence for gates D/E/F/H/I/K and marks J pending

Created at `docs/release/v4.0.0-gate-status.md` in the format of `docs/release/v3.0.0-gate-status.md`.

| Gate | Status | Key evidence recorded |
|------|--------|-----------------------|
| D | ✅ MET | 263 passed, 19 warnings, 0 failures in 9.89s (2026-06-29) |
| E | ✅ MET | 28 test files, 373 tests passed, 0 failures in 6.4s (2026-06-29) |
| F | ✅ MET | No placeholder hashes; CI sentinel in `.github/workflows/dependency-check.yml` enforces |
| H | ✅ MET | Code-review confirm: dual SELECT-only enforcement (readonly=1 + allow-list), PR7 fix b75e0dd; admin-gate 403 on non-admin; fail-closed audit blocks on Sentinel failure |
| I | ✅ MET | SELF-006 fires on every RuleChangeAudit; forwarded via audit_client.py; test_self006_fires_on_status_change passes |
| K | ✅ MET | Threat-model note: identity-scoped (server-set owner key), parameterized queries, no HTML sink, limited data scope |
| J | ⏳ PENDING | Manual human security sign-off required before push |

### 4. Local annotated tag `v4.0.0` exists

```
object b8db3fb8bf51b0c65e4d159151487217e18e28c2
type commit
tag v4.0.0
tagger Philliamviber
```

Tag points to commit `b8db3fb` (PR9 release commit).

---

## Pre-tag gate verification

Precondition: full pytest + vitest suite green before tagging.

- `pytest`: **263 passed, 0 failures** — verified 2026-06-29 before version bump commit
- `vitest`: **373 passed, 0 failures** — verified 2026-06-29 before version bump commit

---

## Deviations

None. All four acceptance items satisfied exactly as specified.

---

## Handoff note for (none — final PR)

This is the final PR in the v4.0.0 chain. The remaining manual steps are:
1. Human GATE J security sign-off (review gate-status evidence, check live stack)
2. Merge branch `4.0` into `master`
3. Push branch and tag: `git push origin 4.0 && git push origin v4.0.0`
