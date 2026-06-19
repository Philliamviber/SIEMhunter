# SIEMhunter — Agent Task Matrix

**Document:** 13-agent-task-matrix.md
**Version:** 0.1.0-draft
**Date:** 2026-06-19
**Owner:** `tech-lead`

---

## Purpose

This document is a quick-reference index of the full agent execution plan: it maps every build step to its specialist agent, deliverable, dependencies, parallel flag, wave, milestone, and security owner. It is a lookup table, not a narrative. For the authoritative orchestration plan — including hand-off contracts, deliverable acceptance details, and go/no-go gates — see `00-orchestration-plan.md`.

---

## 1. Agent task matrix

All 21 steps (0–20), in execution order.

| Step | Agent | Deliverable | Depends on steps | Parallel | Wave | Milestone | Security owner |
|------|-------|-------------|------------------|----------|------|-----------|----------------|
| 0 | main thread | repo scaffold + `instructions\` + `rules\pipelines\` | — | — | 0 (Scaffold) | M1 | — |
| 1 | tech-lead | `00-orchestration-plan.md` | 0 | with 2–4 | A | M2 | tech-lead |
| 2 | requirements-analyst | `02-requirements.md` | 0 | yes | A | M2 | security-architect |
| 3 | security-architect | `01-architecture-overview.md` | 0 | yes | A | M2 | security-architect |
| 4 | tech-writer | `11-glossary.md` | 0 | yes | A | M2 | — |
| 5 | threat-modeler | `14-threat-model.md` + root `advise.md` | 2 | with 6 | B | M3 | threat-modeler |
| 6 | iam-engineer | `15-adr-forwarder-credential.md` | 2 | with 5 | B | M3 | iam-engineer |
| 7 | implementer | `04-normalization-and-schema.md` | 2, 3 | gate | C | M4 | detection-engineer (co-review) |
| 8 | implementer | `03-data-ingestion-spec.md` | 2, 3 | with 7 | C | M4 | cloud-security-engineer |
| 9 | detection-engineer | `rules/pipelines/clickhouse-asim-ocsf.yaml` + `05-detection-and-anomaly.md`; co-review `04` | 7, 5 | after 7 | D | M5 | detection-engineer |
| 10 | implementer | `06-api-control-plane.md` | 7 | with 9 | D | M4 | iam-engineer |
| 11 | implementer | `12-data-retention-and-lifecycle.md` | 7 | with 9, 10 | D | M4 | cloud-security-engineer |
| 12 | cloud-security-engineer | `07-sentinel-forwarding.md` | 6, 5 | after 6 | E | M6 | cloud-security-engineer |
| 13 | devops-engineer | `08-deployment-hybrid.md` + root `.gitignore` | 5 | with 12 | E | M6 | cloud-security-engineer |
| 14 | iam-engineer | `09-security-and-iam.md` | 6, 12 | after 12 | F | M6 | iam-engineer |
| 15 | incident-responder | 3 IR runbooks (folded into `05`/`09`) | 14 | after 14 | F | M6 | incident-responder |
| 16 | cloud-security-engineer | `16-hardening-checklist.md` | 8, 9, 12, 13, 14 | late | G | M6 | cloud-security-engineer |
| 17 | requirements-analyst | `10-acceptance-criteria.md` | all content | late | G | M7 | security-architect |
| 18 | tech-lead | `13-agent-task-matrix.md` + finalize `00` | all | last | H | M7 | tech-lead |
| 19 | readme-specialist | root `README.md` | all | last | H | M7 | — |
| 20 | docs-maintainer | cross-reference sweep | 18, 19 | last | H | M7 | — |

---

## 2. Milestone definitions

| Milestone | Theme | Steps completed |
|-----------|-------|-----------------|
| M1 | Scaffold | Step 0 |
| M2 | Frame | Steps 1–4 |
| M3 | Threat | Steps 5–6 |
| M4 | Backend core | Steps 7–8, 10–11 |
| M5 | Detection | Step 9 |
| M6 | Azure + hardening + IR | Steps 12–16 |
| M7 | Close-out | Steps 17–20 |

---

## 3. Security task owners

Agents carrying a security review responsibility and their scope.

| Agent | Files owned | Security scope |
|-------|-------------|----------------|
| security-architect | `01` | Architecture trust boundaries, secure-by-design principles |
| threat-modeler | `14`, `advise.md` | STRIDE analysis, attack trees, findings table, red-team handoff |
| iam-engineer | `15`, `09` | Azure RBAC, cert lifecycle, control plane auth, IR runbooks |
| cloud-security-engineer | `07`, `08`, `16` | CIS Docker, DCE/DCR hardening, Azure RBAC, supply chain |
| detection-engineer | `05`, pipeline | Rule lifecycle, self-detections, pySigma CI gate |
| incident-responder | folds into `05`/`09` | IR-001 cert theft, IR-002 ledger gap, IR-003 rule disable |

---

## 4. LATER — not this task

The docs-first phase ends at Step 20. The following work is explicitly out of scope for the current plan and is gated behind the documentation set.

| Agent | Task | Gate |
|-------|------|------|
| implementer | Application code, Dockerfiles, Compose files | All docs complete + §7 go/no-go in `00` |
| devops-engineer | CI/CD pipelines, Azure IaC | All docs complete |
| cloud-security-engineer | Azure resource provisioning | All docs complete |
| iam-engineer | App registration + cert provisioning | All docs complete |
| test-engineer | Unit, integration, regression tests | Code complete |
| code-reviewer | Pre-ship review | Tests passing |
| ad-redteamer | Phase 5 adversarial validation | System built + authorization obtained |

---

## 5. References

- `00-orchestration-plan.md` — authoritative plan with hand-off contracts and go/no-go gates
- `10-acceptance-criteria.md` — definition of done for docs phase and build phase
- `16-hardening-checklist.md` — pre-build security checklist
