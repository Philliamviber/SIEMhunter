# SIEMhunter — Master Orchestration Plan (00)

> **Document role:** This is the master multi-agent orchestration plan for SIEMhunter. It is the single source of truth for *who builds what, in what order, and with what hand-off contracts*. Future agents MUST read this file before acting. Owner: `tech-lead`. Status: v0.1.0 docs-first phase.

---

## 1. Project overview

SIEMhunter is a lightweight **on-premise collector agent** that ingests security telemetry (syslog, netflow/IPFIX, Windows Event Logs, Azure logs), normalizes it locally via **OCSF → ASIM**, runs **batch Sigma + baseline ML detections**, and forwards normalized data plus alerts to **Microsoft Sentinel** as the SIEM of record. It targets lab / home-lab scale, runs on a **batch cadence (15–60 min)**, and deploys via **Docker Compose** on-premise.

This task is **docs-first**: it produces a complete set of planning, architecture, requirements, threat-model, detection, deployment, and security specifications — **not application code**. The output is a reviewed documentation set that becomes the definition of done for the later build phase.

---

## 2. v0.1.0 scope boundary

### IN v0.1.0
- Ingestion sources: **syslog**, **Windows Event Logs** (Domain Controller security logs + **Sysmon**), **netflow/IPFIX**
- Local store: **ClickHouse**
- Normalization: **OCSF → ASIM** mapping layer
- Detections: **batch Sigma** rules
- ML: **baseline-only anomaly detection** (no model training pipeline beyond baselines)
- **5 self-detections** (canonical built-in detections shipped with v0.1.0; ownership table defined in `05`)
- Sentinel forwarding: **Logs Ingestion API via DCE/DCR** + **Incidents API**
- Control plane: **FastAPI**
- Deployment: **Docker Compose** (on-premise)

### DEFERRED (NOT in v0.1.0)
- AI/LLM red-team detection (requires HTTP proxy / LLM gateway logs)
- OWASP web-layer TTPs (requires WAF logs)
- APT multi-stage correlation (requires streaming)
- OpenSearch
- PCAP / memory forensics
- Real-time / streaming path
- Multi-tenant RBAC
- Reporting UI

---

## 3. Agent bench

| Agent | Role | Owns |
|-------|------|------|
| tech-lead | Orchestration + task matrix | 00, 13 |
| security-architect | Architecture design | 01 |
| requirements-analyst | Requirements + acceptance | 02, 10 |
| implementer | Backend core specs | 03, 04, 06, 12 |
| detection-engineer | Detection pipeline + rules spec | 05, rules/pipelines/clickhouse-asim-ocsf.yaml |
| devops-engineer | Deployment + CI/CD | 08, .gitignore |
| cloud-security-engineer | Sentinel forwarder + hardening | 07, 16 |
| iam-engineer | Identity + credentials ADR | 09, 15 |
| threat-modeler | STRIDE + attack trees | 14, advise.md |
| incident-responder | IR runbooks | folds into 05, 09 |
| readme-specialist | Front-door README | README.md |
| tech-writer | Glossary | 11 |
| docs-maintainer | Cross-ref sweep | final pass |

**File numbering legend (instructions\ unless noted):** 00 orchestration-plan · 01 architecture-overview · 02 requirements · 03 data-ingestion-spec · 04 normalization-and-schema · 05 detection-and-anomaly · 06 api-control-plane · 07 sentinel-forwarding · 08 deployment-hybrid · 09 security-and-iam · 10 acceptance-criteria · 11 glossary · 12 data-retention-and-lifecycle · 13 agent-task-matrix · 14 threat-model · 15 adr-forwarder-credential · 16 hardening-checklist. Root files: README.md, advise.md, .gitignore. Pipeline spec: rules\pipelines\clickhouse-asim-ocsf.yaml.

---

## 4. Dependency graph

Serial backbones (must respect ordering):

- **Detection backbone:** `02 → 04 → (pySigma pipeline) → 05`
  - Requirements feed the normalization/schema design; the canonical schema feeds the pySigma ClickHouse pipeline; the pipeline feeds the detection spec.
- **Forwarding/identity backbone:** `15 → 07 → 09`
  - The credential ADR (incl. DCR resource-ID placeholder) feeds the Sentinel forwarder design, which feeds the consolidated security/IAM spec.

Everything else parallelizes in **waves** (see §5). The two backbones run concurrently; their outputs converge at the hardening checklist (`16`) and acceptance criteria (`10`).

---

## 5. 20-step execution table

| Step | Agent | Deliverable | Depends on | Parallel |
|------|-------|-------------|-----------|---------|
| 0 | main thread | create repo + instructions\ + rules\pipelines\ | — | — |
| 1 | tech-lead | 00 (draft skeleton) | 0 | with 2–4 |
| 2 | requirements-analyst | 02-requirements | 0 | yes |
| 3 | security-architect | 01-architecture-overview | 0 | yes |
| 4 | tech-writer | 11-glossary | 0 | yes |
| 5 | threat-modeler | 14-threat-model + root advise.md | 2 | with 6 |
| 6 | iam-engineer | 15-adr-forwarder-credential | 2 | with 5 |
| 7 | implementer | 04-normalization-and-schema | 2,3 | gate for 9 |
| 8 | implementer | 03-data-ingestion-spec | 2,3 | with 7 |
| 9 | detection-engineer | rules\pipelines\clickhouse-asim-ocsf.yaml (spec) + 05-detection-and-anomaly; co-review 04 | 7,5 | after 7 |
| 10 | implementer | 06-api-control-plane | 7 | with 9 |
| 11 | implementer | 12-data-retention-and-lifecycle | 7 | with 9,10 |
| 12 | cloud-security-engineer | 07-sentinel-forwarding | 6,5 | after 6 |
| 13 | devops-engineer | 08-deployment-hybrid + root .gitignore | 5 | with 12 |
| 14 | iam-engineer | 09-security-and-iam | 6,12 | after 12 |
| 15 | incident-responder | 3 IR runbooks folded into 05/09 | 14 | after 14 |
| 16 | cloud-security-engineer | 16-hardening-checklist | 8,9,12,13,14 | late |
| 17 | requirements-analyst | 10-acceptance-criteria | all content | late |
| 18 | tech-lead | 13-agent-task-matrix + finalize 00 | all | last |
| 19 | readme-specialist | root README.md | all | last |
| 20 | docs-maintainer | cross-reference sweep | 18,19 | last |

### Wave summary
- **Wave A (after Step 0):** Steps 1, 2, 3, 4 — dispatch together.
- **Wave B:** Steps 5, 6 — dispatch together (both depend on 2).
- **Wave C:** Steps 7, 8 — dispatch together (depend on 2,3). Step 7 gates Step 9.
- **Wave D:** Steps 9, 10, 11 — dispatch together after 7 (9 also needs 5).
- **Wave E:** Steps 12, 13 — dispatch together (12 after 6; 13 after 5).
- **Wave F:** Step 14 (after 12), then Step 15 (after 14).
- **Wave G (late):** Step 16, then Step 17.
- **Wave H (last):** Step 18, then 19, then 20.

---

## 6. Hand-off contracts

These are the binding outputs one agent must deliver before a dependent agent may start.

- **`04` → Step 9 (detection):** `04-normalization-and-schema` must export the **canonical field table** — for every field: *Sigma name / OCSF path / ClickHouse column + type* — before Step 9 begins. This table is the contract the pySigma pipeline compiles against.
- **`15` → `07` and `09`:** `15-adr-forwarder-credential` must specify the **exact DCR resource-ID placeholder** (and its naming/format convention) before `07-sentinel-forwarding` and `09-security-and-iam` start.
- **`advise.md` → Phase 5 (`ad-redteamer`):** `advise.md` must contain the **5 red-team hand-off objectives** before the (later, deferred) adversarial-validation phase runs. Authored at Step 5.
- **`05` → `07`:** `05-detection-and-anomaly` must include the **local-vs-Sentinel ownership table** (which detections fire locally vs. which are forwarded/owned in Sentinel) before `07-sentinel-forwarding` is finalized.

---

## 7. Go / No-go gates

The **later code phase** (see §8) may begin only when ALL of the following are met:

- **Docs complete:** All 17 numbered docs + `advise.md` + `README.md` + `.gitignore` present; all cross-references resolve (verified by `docs-maintainer` sweep, Step 20).
- **Acceptance signed off:** `10-acceptance-criteria` is approved as the **definition of done**.
- **Azure prereqs identified:** Sentinel workspace, **DCR + DCE**, and the **DCR resource-ID placeholder** documented in `15`.
- **Identity prereqs:** app-registration plan, **certificate generation/rotation runbook**, **two RBAC scopes** defined, **Entra P1** assumed for Conditional Access.
- **Telemetry prereqs (per detection):** DC audit policy settings, **Sysmon EID 10** (and other required EIDs), Entra **diagnostic settings** documented per the 5 self-detections.
- **Secrets plan:** **Docker secrets** primary for v0.1.0; **Key Vault** in v0.2 with **fail-closed** behavior documented.
- **Supply-chain plan:** **pinned dependencies/digests**, **SBOM** generation, **Trivy/Grype** scanning, and a **pinned SigmaHQ commit** for rule provenance.

---

## 8. LATER — NOT this task

This docs-first task does **not** include the following. They run only after the documentation set passes the §7 gates:

- `implementer` / `devops-engineer` / `cloud-security-engineer` / `iam-engineer` build **application code, Dockerfiles, Compose files, CI pipelines, and Azure resources**.
- `test-engineer` writes **tests**.
- `code-reviewer` performs the **pre-ship review**.
- `ad-redteamer` runs **Phase 5 adversarial validation** — authorization-gated, only after the system is actually built (consumes the 5 objectives in `advise.md`).

---

## 9. Milestones

| Milestone | Theme | Deliverables |
|-----------|-------|--------------|
| **M1** | Scaffold | Repo + `instructions\` + `rules\pipelines\` created (Step 0) |
| **M2** | Frame | 00, 01, 02, 11 |
| **M3** | Threat | 14, advise.md, 15 |
| **M4** | Backend | 03, 04, 06, 12 + pipeline (clickhouse-asim-ocsf.yaml) |
| **M5** | Detection | 05 |
| **M6** | Azure + hardening | 07, 08, 09, 16 + IR runbooks |
| **M7** | Close-out | 10, 13, finalize 00, README, cross-ref sweep |

---

> **Reminder:** This is a planning/reference document. The **main conversation executes** the steps above by dispatching the named subagents. Independent steps within the same wave can and should be dispatched together. Subagents cannot invoke other subagents — each step returns to the main thread, which advances the waves and enforces the §6 hand-off contracts and §7 go/no-go gates.
