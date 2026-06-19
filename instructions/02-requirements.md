# SIEMhunter — Requirements
**Document:** 02-requirements.md
**Version:** 0.1.0-draft
**Date:** 2026-06-18
**Status:** Baseline — awaiting stakeholder sign-off before implementation begins

---

## Summary

SIEMhunter is a lightweight, on-premise collector agent for lab and home-lab environments. It ingests security data from multiple local sources, normalizes each event to a common schema, runs scheduled Sigma rule and machine-learning anomaly detections in batch, and forwards results to Microsoft Sentinel as the authoritative SIEM of record. It is not a standalone SIEM and has no end-user dashboards of its own.

---

## User Stories

1. As a home-lab defender, I want syslog, Windows Event Log, and netflow data ingested automatically so that I do not have to manually copy logs before running detections.

2. As a home-lab defender, I want Sigma rules to run on a 15–60 minute schedule so that I receive detection results without needing a 24/7 streaming pipeline.

3. As a home-lab defender, I want detections mapped to MITRE ATT&CK technique IDs so that I can quickly understand what adversary behavior a hit represents.

4. As a home-lab defender, I want detection hits pushed to Microsoft Sentinel as incidents so that I have a single investigation pane across all my data sources.

5. As a home-lab defender, I want the agent to detect signs of tampering with itself — such as a disabled rule or a certificate anomaly — before it alerts on anything else, so that I can trust the system's own integrity.

6. As a home-lab defender, I want forensic JSON exports from tools such as Velociraptor or Volatility ingested alongside live logs so that offline artifact analysis feeds the same detection pipeline.

7. As a home-lab defender, I want the system to optionally pull Azure and Sentinel logs via KQL so that I can enrich on-premise data with cloud context without building a separate pipeline.

8. As a home-lab defender, I want all credentials stored as Docker secrets — never in environment blocks or the repository — so that a leaked image or compose file does not expose my Azure app registration.

9. As a home-lab defender, I want the control plane reachable only on localhost so that no management surface is exposed to my lab LAN.

10. As a home-lab defender, I want machine-learning anomaly scores to be advisory and never to trigger automatic responses so that I remain in control of every action taken in my environment.

---

## Functional Requirements

### FR-01 — Syslog Ingestion (UDP, TCP, TLS)

The system must accept syslog messages in both RFC 3164 (BSD syslog) and RFC 5424 (structured syslog) formats over UDP, TCP, and TCP with TLS. All three transports must be independently configurable so the operator can enable only what is needed. Each received message must be tagged with a collector-assigned provenance field before it enters the normalization stage.

### FR-02 — Windows Event Log Ingestion

The system must ingest Windows Event Log data delivered via Windows Event Forwarding (WEF) and via direct EVTX file import. At a minimum, the system must process Domain Controller security events for Event IDs 4768, 4769, 4762, 4624, and 4625, and Sysmon Event ID 10 (process access on LSASS). These event IDs are the telemetry baseline for the Windows and Active Directory detection rules in FR-10. If these events are absent from the ingest stream at detection time, affected Sigma rules must produce zero hits rather than a false negative or an error.

### FR-03 — Netflow and IPFIX Ingestion

The system must receive NetFlow v5/v9 and IPFIX records from network devices. Flow records must be normalized to the same canonical internal schema used by all other ingest paths (see FR-06). Volume spikes in flow records must be subject to the same ingest rate limits defined in FR-17.

### FR-04 — Forensic Artifact Ingestion

The system must accept structured JSON and plain-text artifacts exported by off-line forensic tools, specifically Velociraptor query exports, Volatility output, and EVTX-to-JSON conversions. Artifacts are treated as a batch-upload ingest path; they are not expected to arrive in real time. Each artifact file must be validated for size before parsing, and decompression is subject to the ratio cap in FR-17.

### FR-05 — Azure and Sentinel Log Pull via KQL (Optional)

The system must provide an optional, configurable ingest path that queries a Sentinel Log Analytics workspace using the Logs Query API and KQL. The purpose is to pull Azure-side data (for example, Entra ID sign-in logs or Microsoft Sentinel analytics rule outputs) into the local ClickHouse store for correlation or enrichment. This path is optional; if it is disabled or the workspace is unreachable, all other ingest paths must continue to function normally.

### FR-06 — Event Normalization to OCSF with ASIM Mapping

Every event from every ingest path must be normalized to the Open Cybersecurity Schema Framework (OCSF) as the canonical internal model before it is stored in ClickHouse or processed by detection rules. In addition, every normalized event must carry an ASIM (Advanced Security Information Model) mapping so that it can be forwarded to Sentinel custom tables without a second transformation step. The pySigma pipeline file is the authoritative schema contract for this mapping; changes to field names must be reflected in that file before they reach any other component.

### FR-07 — Sigma Rule Batch Detection via ClickHouse SQL

The system must compile Sigma rules from a pinned SigmaHQ community snapshot to ClickHouse SQL using pySigma and must execute them against the normalized event store on a configurable schedule between 15 and 60 minutes. Rules must be compiled to SQL — they must never be interpolated as raw strings at query time. If a rule cannot be compiled cleanly, it must be rejected at load time with a logged error rather than silently skipped or run in a degraded state.

### FR-08 — Baseline-Only ML Anomaly Scoring

The system must run baseline anomaly-scoring models (scikit-learn) against normalized events as part of the batch schedule. Model outputs are advisory scores attached to events and detections; they must not trigger automated responses or block forwarding. Models are retrained manually and offline only; the system must never initiate retraining against live ingest data. Model artifacts must be hash-verified on load (see NFR-08).

### FR-09 — Five Self-Detections Ship First

Before any third-party Sigma rules are enabled in a deployment, the following five self-detections must be active and returning valid results:

1. Certificate or secondary-IP anomaly on the forwarder connection — detects a change in the TLS certificate or source IP used to reach the Sentinel DCE endpoint.
2. Ingest flood heuristic — detects an abnormal spike in events per minute on any ingest path.
3. Rule-disable audit alert — detects when any active Sigma or self-detection rule is moved out of production status without a matching audit log entry written first (see FR-14).
4. Decompression-ratio cap trip — detects when an incoming compressed payload exceeds the configured expansion ratio, indicating a possible zip-bomb or malformed input.
5. Ledger-reconciliation delta — detects a mismatch between the count of events accepted by the ingest stage and the count stored in ClickHouse, indicating possible data loss or tampering.

These self-detections must be defined using the same Sigma rule structure and lifecycle as all other rules.

### FR-10 — MITRE ATT&CK Mapping for Windows and AD TTPs

Every detection rule must carry a MITRE ATT&CK technique identifier in its metadata. The initial rule set must cover at minimum the following Windows and Active Directory techniques, contingent on the telemetry events defined in FR-02 being present:

- Kerberoasting — T1558.003 (requires EID 4769)
- AS-REP Roasting — T1558.004 (requires EID 4768)
- DCSync — T1003.006 (requires EID 4662)
- LSASS Access — T1003.001 (requires Sysmon EID 10)
- Lateral Movement via Remote Services — T1021.x (requires EID 4624 and network context)

If the required telemetry event is absent from the ingest stream, the corresponding rule must return no results and must log a warning identifying the missing event type.

### FR-11 — Forward Normalized Events to Sentinel via Logs Ingestion API

The system must forward normalized events to the Microsoft Sentinel workspace using the Azure Monitor Logs Ingestion API (DCE/DCR model). Events must be forwarded to ASIM-aligned custom tables as defined in the pySigma pipeline contract. Forwarding must use the two-table structure defined in FR-19. Authentication must use an Azure app registration with certificate credential; client secrets are prohibited. TLS verification on the outbound connection must always be enabled and must not be configurable to disabled.

### FR-12 — Push Detection Hits to Sentinel as Incidents

When a Sigma or self-detection rule produces a hit, the system must create or update a corresponding incident in the Sentinel workspace using the Microsoft Sentinel Incidents API. Each incident payload must include at minimum: the rule ID, rule version, the MITRE ATT&CK technique identifier, and the stable event IDs of the source events that triggered the hit (see FR-18). This ensures an analyst can navigate from a Sentinel incident back to the raw evidence in the custom tables.

### FR-13 — FastAPI Control Plane

The system must expose a FastAPI-based control plane on localhost only. The control plane must support at minimum the following operations: adding or removing an ingest source, creating, updating, or deleting a Sigma rule (subject to FR-14), viewing and updating forwarder configuration, checking system health, and querying recent detection hits. All control-plane endpoints must require authentication. The control plane must not be reachable from the host LAN.

### FR-14 — Rule-Change Audit Written to Sentinel Before ClickHouse Update (Fail-Closed)

Any change to a Sigma rule's production status — including promotion, demotion, or deletion — must be recorded as an audit log entry in the Sentinel SIEMHunterSecurity_CL table before the change is committed to ClickHouse. If the Sentinel write fails, the rule change must be rejected and the current ClickHouse state must remain unchanged. This behavior is fail-closed: the local rule store must not drift from the audit record. This audit entry is also what the rule-disable self-detection in FR-09 reads.

### FR-15 — Docker Compose Deployment with Non-Root Containers and Isolated ClickHouse

The system must be deployable using a single Docker Compose file. Every container must run as a non-root user. The ClickHouse container must not bind any port to the host network or to the LAN; it must be reachable only from other containers within the Compose internal network. Read-only file systems must be applied to containers wherever the application does not require write access to the file system.

### FR-16 — Secrets via Docker Secrets Only

All sensitive values — including the Azure app registration certificate, the ClickHouse credentials, and any API keys — must be supplied via Docker secrets mounted at runtime. They must not appear in environment variable blocks in the Compose file, in Dockerfile instructions, in committed .env files, or in any other form visible in the repository or the image layer history.

### FR-17 — Anti-DoS Input Controls

The system must enforce the following input limits on all ingest paths:

- A maximum per-event payload size, rejected before parsing begins.
- A per-source ingest rate limit (events per minute), after which excess events are dropped and a warning is logged.
- A decompression-ratio cap: if a compressed input expands beyond the configured ratio, decompression must be aborted and the payload rejected.
- A parse timeout: if parsing a single event exceeds the configured duration, the event must be dropped and logged as a parse failure.

These controls apply equally to syslog, Windows Event Log, netflow, and forensic artifact ingest paths.

### FR-18 — Stable Event IDs and Deduplication on Forward

Each event must be assigned a stable, deterministic ID when it is first accepted by the ingest stage. This ID must survive normalization and forwarding unchanged. The Sentinel forwarding path must track which event IDs have already been sent and must not forward the same event twice (anti-replay). Every alert and incident created under FR-12 must reference the stable event IDs of the contributing source events so that an analyst can retrieve them from the custom tables.

### FR-19 — Two Sentinel Internal Log Tables

The system must write operational and security data to exactly two custom tables in the Sentinel workspace:

| Table | Purpose | Expected Volume | Retention Guidance |
|---|---|---|---|
| SIEMHunterHealth_CL | Operational events: pipeline heartbeats, ingest counts, parse errors, forwarding status | High — every batch cycle | Short (7–30 days suggested) |
| SIEMHunterSecurity_CL | Security-relevant events: detection hits, rule-change audit entries, self-detection results | Lower — alert-rate driven | Longer (90+ days suggested); feeds Sentinel analytics rules |

Retention values are configured in the Sentinel workspace and are outside the scope of this system's code. The system must write to both tables independently; a failure to write to one table must not block writes to the other.

### FR-20 — Supply Chain Controls

The system's Docker images must use pinned digests (not floating tags) in the Compose file and in all Dockerfiles. All Python dependencies must be declared in a lockfile. A Software Bill of Materials (SBOM) must be generated as part of the CI pipeline. Container image vulnerability scanning using Trivy or Grype must run in CI, and the build must fail if critical or high severity vulnerabilities are found in first-party layers.

---

## Non-Functional Requirements

### NFR-01 — Scale

The system is sized for lab and home-lab use: a target throughput of a few thousand events per hour across all ingest paths combined. A Redpanda message queue may optionally be added to the Compose stack as a buffer to absorb short bursts, but it is not required for v0.1.0. The system must not be architected in a way that prevents Redpanda from being inserted between ingest and normalization in a future version.

### NFR-02 — Detection Latency

The primary detection path is batch-based with a configurable cycle of 15 to 60 minutes, consistent with how Sentinel scheduled analytics rules work. An always-on ingest-flood heuristic must run continuously outside the batch cycle — implemented as a condition in the Vector pipeline — so that volume anomalies are flagged without waiting for the next batch window. No other real-time or streaming detection path exists in v0.1.0.

### NFR-03 — Availability

The system targets best-effort availability for a single-operator lab environment. There is no uptime SLA. Failure of the Sentinel forwarding path must not crash or halt the ingest and detection pipeline; the system must log the failure and continue operating locally.

### NFR-04 — Local Retention

ClickHouse is the local hot store. It is sized for lab scale and is not intended to be the source of truth for long-term retention. Sentinel is the source of truth. Local ClickHouse retention periods are set by the operator to match available disk space; there is no minimum retention mandated by this system.

### NFR-05 — Treat All Ingested Data as Hostile Input

The system must treat every byte of every ingest payload as potentially malicious. Parsing must use strict libraries with bounded input; schema validation must occur before any field value reaches business logic. All queries against ClickHouse must use parameterized statements — never string concatenation or interpolation. Every stored event must carry a collector-assigned provenance tag identifying the ingest path, transport, and timestamp of arrival; this tag must not be overridable by content within the event itself.

### NFR-06 — Authentication and Access Control

The Sentinel forwarding credential must be an Azure app registration with a certificate; client secrets are not permitted. The FastAPI control plane must require authentication on every endpoint and must bind only to the loopback interface. All containers must run as non-root users. Container file systems must be mounted read-only wherever the process does not need to write to the file system at runtime.

### NFR-07 — Outbound-Only Forwarder with Mandatory TLS

The Sentinel forwarding path must be outbound-only over HTTPS. TLS certificate verification must be enabled and must not be configurable to disabled; any code path or configuration option that would allow disabling TLS verification is prohibited. The system must not accept inbound connections from Sentinel or any other external system.

### NFR-08 — Model Artifact Security

Machine-learning model artifacts must be stored with a cryptographic hash. On load, the system must verify the artifact hash before the model is used for scoring. Models must never be loaded from a path that is writable by the ingest pipeline or by any untrusted process. Python pickle deserialization of model files sourced from untrusted paths is prohibited; use a serialization format that allows schema validation, or load only from a verified, operator-controlled path.

### NFR-09 — Portability

The entire system must be deployable via a single Docker Compose invocation on any host with Docker installed. On-premise is the primary deployment target. The Compose configuration must be structured so that it can be migrated to an Azure-hosted Docker environment (for example, Azure Container Instances or a single Azure VM) without rewriting the application code.

### NFR-10 — Maintainability and Rule Lifecycle

The pySigma pipeline file is the single source of truth for the OCSF-to-ASIM field mapping contract. Any change to normalized field names must be reflected in that file first and then propagated to ClickHouse schema migrations, Sentinel custom table schemas, and Sigma rule field references in that order. Sigma rules must follow a four-stage lifecycle — draft, test, review, production — and may only produce live detection hits when in production status. Promotion between stages must be recorded in the audit log under FR-14.

---

## v0.1.0 Scope Boundary

The table below defines what is and is not in scope for the initial release. Deferred items must not be architected into v0.1.0 in a way that blocks their addition in v0.2.0, but no placeholder code should be written for them.

| Capability | v0.1.0 | Deferred to |
|---|---|---|
| Syslog ingestion (UDP/TCP/TLS) | In scope | — |
| Windows Event Log ingestion (WEF + EVTX) | In scope | — |
| Netflow/IPFIX ingestion | In scope | — |
| Forensic artifact ingestion (JSON/text) | In scope | — |
| Azure/Sentinel log pull via KQL | In scope | — |
| OCSF normalization with ASIM mapping | In scope | — |
| Sigma/ClickHouse batch detection | In scope | — |
| Baseline-only ML anomaly scoring | In scope | — |
| Five self-detections | In scope (ship first) | — |
| Windows/AD TTP Sigma rules | In scope (telemetry-gated) | — |
| Sentinel forwarding (Logs Ingestion API + Incidents API) | In scope | — |
| FastAPI control plane (localhost-only) | In scope | — |
| Docker Compose deployment | In scope | — |
| Supply chain controls (pinned digests, SBOM, scan) | In scope | — |
| AI/LLM red-team detection | — | v0.2 — requires HTTP proxy or LLM gateway logs |
| OWASP web-layer TTP detection | — | v0.2 — requires WAF log source |
| APT multi-stage correlation | — | v0.2 — requires streaming pipeline |
| OpenSearch integration | — | v0.2 |
| PCAP or memory-image forensic analysis | — | v0.2 |
| Real-time/streaming detection path | — | v0.2 — requires Redpanda as mandatory component |
| Multi-tenant RBAC | — | v0.2 |
| Reporting or analysis UI | — | Deferred indefinitely |

---

## Constraints

The following behaviors are prohibited in any version of this system. They are listed here so that design and implementation reviewers can check for them explicitly.

1. ClickHouse must not bind any port to the host network interface or the LAN network. Access is container-internal only.

2. Credentials — including the Azure app registration certificate, ClickHouse password, and any API key — must not appear in environment variable blocks, Dockerfile instructions, committed .env files, image layer history, or the repository in any form.

3. Machine-learning model artifacts must not be loaded via Python pickle from any path that is writable by the ingest pipeline or not under operator control.

4. TLS verification on the Sentinel forwarder must not be disabled. No configuration option or code path that sets verify=False or its equivalent is permitted.

5. ML model retraining must not be triggered automatically against live or unreviewed ingest data. Retraining is a manual, offline-only process.

6. Sigma rules must be compiled to ClickHouse SQL before execution. Rule logic must not be built by interpolating rule field values into SQL strings at query time.

---

## Assumptions and Prerequisites

The following conditions must be true before SIEMhunter v0.1.0 can produce meaningful detection results. They are outside the system's control and must be confirmed by the operator before deployment. If any of these are not in place, the system will ingest and forward data but specific detection categories will return zero results.

| ID | Assumption | Impact if False |
|---|---|---|
| A-01 | Microsoft Entra ID AuditLogs and SignInLogs are streaming to the Sentinel workspace | FR-05 KQL pull returns no cloud identity data; self-detections relying on Entra data return zero |
| A-02 | Domain Controller advanced audit policy is configured to generate EIDs 4768, 4769, 4762, 4624, and 4625 | FR-02 ingest receives no DC security events; all AD TTP rules in FR-10 return zero hits |
| A-03 | Sysmon is deployed on endpoints with a configuration that captures process access events (EID 10) | LSASS access detection (T1003.001) in FR-10 returns zero hits |
| A-04 | An Azure app registration has been provisioned with a certificate credential (not a client secret) and has been granted the necessary permissions on the Sentinel DCE and workspace | FR-11 and FR-12 forwarding fails; FR-05 KQL pull fails |
| A-05 | Docker secrets have been populated with the certificate, ClickHouse credentials, and any required API values before the first docker compose up | All containers that require secrets will fail to start |
| A-06 | The host running Docker Compose has outbound HTTPS access to the Azure Monitor ingestion endpoint and the Sentinel API endpoints | FR-11 and FR-12 forwarding fails silently; local ingest and detection continue |
| A-07 | The operator has configured the two Sentinel custom tables (SIEMHunterHealth_CL and SIEMHunterSecurity_CL) with the ASIM-aligned schemas derived from the pySigma pipeline file before first run | Forwarding succeeds but table ingestion in Sentinel fails until schemas are created |

---

## Open Questions

The following items require a human decision before the design or build phase can resolve them. None of these block writing the requirements document, but all of them block finalizing the design.

1. Syslog TLS: Does the operator have an existing internal CA or self-signed certificate infrastructure for syslog TLS, or does the system need to generate and manage its own listener certificates? The answer affects the secrets model and the container start-up sequence.

2. Windows Event Forwarding transport: Will WEF use HTTP (port 5985) or HTTPS (port 5986)? If HTTPS, who provisions the WEF listener certificate inside the Docker environment?

3. Netflow sources: Which network devices will send flow records, and do they all support IPFIX, or is NetFlow v5/v9 required? This determines whether a single collector covers all sources.

4. Sentinel workspace: Is there an existing Log Analytics workspace and Sentinel instance, or does the operator need to provision one? This affects A-04 and A-07.

5. Ingest rate limit values: The requirements say rate limits must exist (FR-17) but do not specify default values. What are the acceptable defaults for events per minute per source and for decompression ratio? These become configuration file defaults.

6. ClickHouse retention defaults: What default retention period should be pre-configured in the Compose stack for local hot storage? This is a disk-space trade-off the operator must make.

7. Sigma rule snapshot pin: Which specific SigmaHQ release tag or commit hash should be used as the pinned snapshot for v0.1.0? This needs to be decided and recorded before the rule compilation pipeline is built.

8. ML model scope: The requirements describe baseline anomaly scoring without specifying which features or algorithms. What behavioral baselines are in scope for v0.1.0 — for example, login time-of-day, source IP frequency, or event-type rate? Without this, the model cannot be designed or trained.

9. Control-plane authentication mechanism: The requirements mandate authentication on the FastAPI control plane but do not specify the mechanism. Options include API key, mTLS, or local token. Which is acceptable for the lab context?

10. CI environment: Where will the CI pipeline (for SBOM generation and image scanning in FR-20) run — GitHub Actions, a local runner, or another system? This determines what tooling is pre-available.
