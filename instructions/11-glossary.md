# SIEMhunter — Glossary

**Document:** 11-glossary.md
**Version:** 0.1.0-draft
**Date:** 2026-06-18
**Status:** Baseline

---

## Purpose

This file defines every specialized term used across the SIEMhunter instruction set. Any agent or reader who encounters an unfamiliar term in another document should look it up here first. Definitions are precise and scoped to how SIEMhunter uses each term; where a term has a broader industry meaning, that meaning is noted only if relevant.

Terms are grouped by subject area and ordered alphabetically within each group.

---

## Ingestion / Data Pipeline

**Fluent Bit** — A lightweight, open-source log and metrics collector, used in SIEMhunter as an alternate collector to Vector. Suitable for environments where Vector's full feature set is not needed or where Fluent Bit is already deployed.

**EVTX** — Windows Event Log binary format (`.evtx`). The native on-disk format for Windows Event Log files. SIEMhunter ingests EVTX files via direct file import as a batch ingest path (FR-04), complementing the live WEF forwarding path.

**IPFIX** — IP Flow Information Export. The IETF standard (RFC 7011) for exporting network flow records from routers, switches, and probes. SIEMhunter accepts IPFIX records via softflowd or nfcapd, which forward them to the Vector collector.

**Netflow** — Cisco's original flow export format, available as NetFlow v5 and v9. Predates and inspired IPFIX; the two terms are often used interchangeably in practice. SIEMhunter supports both v5/v9 and IPFIX on the netflow ingest path (FR-03).

**Redpanda** — A Kafka-compatible streaming message queue. Used as an optional durable buffer between the Vector collector and ClickHouse. Not required at lab scale; can be inserted between ingest and normalization in a future version without rewriting application code (NFR-01).

**softflowd / nfcapd** — Open-source netflow and IPFIX collection daemons. `softflowd` probes live network interfaces and exports flow records; `nfcapd` receives and stores flow records from network devices. In SIEMhunter, both act as the network-facing capture layer that forwards records to Vector for parsing and normalization.

**Sysmon** — Windows System Monitor. A free Microsoft Sysinternals tool that runs as a Windows service and logs detailed telemetry — process creation, process access, network connections, file creation, and registry changes — to the Windows Event Log. SIEMhunter requires Sysmon Event ID 10 (process access targeting LSASS) for the LSASS-access detection (T1003.001) defined in FR-10.

**Vector** — The primary collector in SIEMhunter. A single Rust binary that natively supports syslog (UDP, TCP, TLS), file tailing, HTTP sources, journald, and Windows Event Log sources. Vector parses raw events, assigns provenance tags, and writes to ClickHouse (directly at lab scale, or via Redpanda if the buffer is enabled).

**WEF** — Windows Event Forwarding. Microsoft's built-in mechanism for pushing Windows Event Log entries from source hosts to a central collector using the WS-Management protocol (HTTP port 5985 or HTTPS port 5986). SIEMhunter receives WEF-forwarded events on the Windows Event Log ingest path (FR-02).

---

## Normalization / Schema

**ASIM** — Advanced Security Information Model. Microsoft's normalized schema for Microsoft Sentinel. ASIM defines standard table schemas for common log types — `NetworkSession`, `Authentication`, `Process`, `FileEvent`, and others — so that Sentinel analytics rules and KQL queries can run against any vendor's logs without source-specific field-name mappings. SIEMhunter maps every internally normalized OCSF event to an ASIM-compatible form before forwarding to Sentinel custom tables.

**DCE** — Data Collection Endpoint. An Azure Monitor resource that provides the HTTPS ingestion endpoint for the Logs Ingestion API. SIEMhunter's forwarder sends all outbound event data to the DCE URL; the DCE routes the payload to the associated DCR for transformation and landing.

**DCR** — Data Collection Rule. An Azure Monitor resource that defines what data to collect, how to transform it using an embedded KQL expression (the DCR transform), and which Log Analytics table to send it to. The push identity's `Monitoring Metrics Publisher` role is scoped to the specific DCR resource ID — not the resource group or subscription.

**DCR transform** — A KQL expression embedded inside a DCR that validates and reshapes incoming log data before it lands in the target Log Analytics table. Used to enforce schema conformance on data arriving via the Logs Ingestion API; errors in the transform cause the DCR to reject the payload.

**ECS** — Elastic Common Schema. Elasticsearch's field-naming standard for security and observability data. ECS compatibility is noted for reference but is not the primary normalization target in SIEMhunter; OCSF is the internal canonical model and ASIM is the Sentinel output model.

**KQL** — Kusto Query Language. The query language used in Microsoft Sentinel, Azure Monitor, and Log Analytics workspaces. SIEMhunter uses KQL in three places: the optional log-pull path from Sentinel (FR-05), DCR transform expressions, and Sentinel analytics rules that operate on the forwarded custom tables.

**Logs Ingestion API** — The Azure Monitor REST API for pushing custom log data to a Log Analytics workspace. Callers POST JSON payloads to the DCE endpoint, referencing a specific DCR stream; the DCR applies its transform and routes the data to the configured table. SIEMhunter's forwarder uses this API (via the `azure-monitor-ingestion` SDK) for all event and detection forwarding (FR-11).

**OCSF** — Open Cybersecurity Schema Framework. A vendor-neutral open standard for security event schemas, maintained by an industry consortium. OCSF defines event classes (Authentication, Network Activity, File System Activity, etc.) with precisely typed fields and a shared taxonomy. SIEMhunter uses OCSF as its canonical internal data model: every event from every ingest path is normalized to OCSF before storage or detection, and ASIM mappings are derived from the OCSF representation.

---

## Detection / Rules

**ATT&CK** — MITRE ATT&CK framework. A globally accessible knowledge base of adversary tactics, techniques, and procedures (TTPs), organized as a matrix of tactics (columns) and techniques/sub-techniques (rows). SIEMhunter uses ATT&CK technique IDs as mandatory metadata on every detection rule (FR-10), and uses the ATT&CK Navigator to visualize detection coverage.

**ASIM pipeline** — In the pySigma context, the YAML file at `rules/pipelines/clickhouse-asim-ocsf.yaml` that maps Sigma rule field names to OCSF paths and then to ClickHouse column names and types. This file is the binding schema contract between the normalization layer and the detection engine. Any change to a normalized field name must be made here first before propagating to ClickHouse schema migrations, Sentinel table schemas, or Sigma rule field references (NFR-10).

**always-on flood heuristic** — A condition defined in the Vector pipeline that runs continuously — outside the batch detection schedule — and emits a health event to `SIEMHunterHealth_CL` when the ingest event rate on any path exceeds a configured threshold. One of the five self-detections (FR-09 item 2). Because it runs in Vector rather than the batch engine, it can fire between batch cycles.

**batch cadence** — The configurable interval, between 15 and 60 minutes, at which the detection engine queries ClickHouse for new events and executes compiled Sigma rules. The batch cadence defines the minimum detection latency for all rules except the always-on flood heuristic.

**detection_state** — The ClickHouse table used by SIEMhunter for stateful multi-event correlation. Columns: `rule_id`, `entity_key`, `window`, `count`, `payload`, `expiry`. Allows rules to track running counts or accumulated evidence across multiple events within a time window without requiring a streaming pipeline.

**Navigator layer** — A JSON file formatted for the ATT&CK Navigator tool (https://mitre-attack.github.io/attack-navigator/) that marks which ATT&CK techniques SIEMhunter has active detection rules for. Used to visualize detection coverage and identify gaps in the ATT&CK matrix.

**pySigma** — A Python library that compiles Sigma rules to backend-specific query languages. SIEMhunter uses pySigma with the ClickHouse backend to produce parameterized ClickHouse SQL from Sigma YAML rule files. Rules that cannot be compiled cleanly are rejected at load time, not silently skipped (FR-07).

**rule lifecycle** — The four-stage promotion path for detection rules in SIEMhunter: `draft` → `test` → `review` → `production`. Rules only produce live detection hits when in `production` status. Every promotion or demotion between stages must be recorded as an audit log entry in `SIEMHunterSecurity_CL` before the ClickHouse rule state is updated (FR-14, NFR-10).

**self-detections** — The five built-in detections that monitor SIEMhunter itself, which must be active before any third-party Sigma rules are enabled. They are: (1) certificate or secondary-IP anomaly on the forwarder connection; (2) ingest flood heuristic; (3) rule-disable audit alert; (4) decompression-ratio cap trip; (5) ledger-reconciliation delta. Defined in FR-09.

**Sigma** — A generic, vendor-neutral detection rule format for SIEM queries. Rules are written in YAML with a standardized structure (title, status, detection logic, ATT&CK metadata) and compiled to target-backend query languages via pySigma. SIEMhunter compiles Sigma rules to ClickHouse SQL for local batch detection and to KQL for forwarded Sentinel analytics rules.

**SigmaHQ** — The community repository of open-source Sigma detection rules (https://github.com/SigmaHQ/sigma). SIEMhunter pins a specific commit hash from SigmaHQ as its rule snapshot to ensure reproducible builds and avoid unreviewed upstream rule changes entering the detection pipeline.

**T1098.001** — MITRE ATT&CK technique: Account Manipulation / Additional Cloud Credentials. In the SIEMhunter context, this technique is used to detect unauthorized addition of credentials (certificates or client secrets) to the Azure app registration used by the forwarder, which could allow an attacker to forward forged events to Sentinel.

**TTP** — Tactic, Technique, and Procedure. The building blocks of the MITRE ATT&CK framework. Tactics are the adversary's high-level goals (e.g., Credential Access); techniques are the methods used to achieve them (e.g., OS Credential Dumping); procedures are specific real-world implementations observed in threat reporting. Every SIEMhunter detection rule must reference at least one ATT&CK technique ID.

**UEBA** — User and Entity Behavior Analytics. The practice of establishing behavioral baselines for users and devices and detecting deviations from those baselines as potential indicators of compromise. In SIEMhunter v0.1.0, UEBA takes the form of advisory-only ML anomaly scoring using scikit-learn baseline models (FR-08); it does not trigger automated responses.

---

## Azure / Sentinel

**App registration** — An Azure Entra ID object representing a non-human (workload) identity. SIEMhunter uses one app registration, with a certificate credential (no client secrets permitted), to authenticate the Sentinel forwarder. The push and pull functions use separate identities, each with a different RBAC scope.

**Conditional Access** — An Entra ID policy engine that enforces access controls on identities, including workload identities. SIEMhunter's security design assumes Entra ID P1 licensing and uses Conditional Access to restrict the forwarder app registration to named-location IP ranges, reducing the risk of the certificate being used from an unexpected network.

**Entra ID** — Microsoft's cloud identity and access management service, formerly known as Azure Active Directory (Azure AD). Entra ID issues and validates the credentials used by SIEMhunter's forwarder app registration and enforces Conditional Access policies on those identities.

**Incidents API** — The Microsoft Sentinel REST API for programmatically creating or updating incidents in the Sentinel workspace. SIEMhunter's forwarder calls this API when a Sigma or self-detection rule produces a hit, creating a Sentinel incident that includes the rule ID, ATT&CK technique, and stable event IDs of the contributing source events (FR-12).

**Log Analytics Reader** — The Azure RBAC role granted to the pull identity (the app registration used for the optional KQL log-pull path). This role is scoped to the Log Analytics workspace only — not the resource group or subscription — and gives read-only access to run KQL queries.

**Log Analytics workspace** — The underlying Azure data store for Microsoft Sentinel. All data ingested by Sentinel, including SIEMhunter's forwarded events, lands in the Log Analytics workspace. SIEMhunter writes to two custom tables in the workspace: `SIEMHunterHealth_CL` and `SIEMHunterSecurity_CL`.

**Monitoring Metrics Publisher** — The Azure RBAC role granted to the push identity (the app registration used to forward events via the Logs Ingestion API). This role is scoped to the specific DCR resource ID only — not the resource group, not the subscription, and not the DCE — giving the forwarder the minimum permission needed to send data.

**Sentinel** — Microsoft Sentinel. The cloud-native SIEM (Security Information and Event Management) and SOAR (Security Orchestration, Automation, and Response) platform that serves as the SIEM of record for SIEMhunter. Sentinel provides the analyst investigation surface, alert triage, case management, and long-term retention; SIEMhunter never tries to replace these functions.

**SIEMHunterHealth_CL** — The custom Log Analytics table for SIEMhunter operational and pipeline health events: batch heartbeats, ingest counts, parse errors, forwarding status, and always-on flood heuristic results. Expected to receive high event volumes; suggested retention is 7–30 days (FR-19).

**SIEMHunterSecurity_CL** — The custom Log Analytics table for SIEMhunter security-relevant events: detection hits, rule-change audit entries, and self-detection results. Lower volume than the health table; feeds Sentinel analytics rules. Suggested retention is 90 or more days (FR-19). Rule-change audit entries must be written here before the corresponding ClickHouse update is applied (FR-14).

---

## Security / Hardening

**AppArmor** — A Linux Security Module (LSM) that enforces mandatory access control on processes via per-application profiles. Applied per-container in SIEMhunter where the host kernel supports it, as part of the CIS Docker Benchmark hardening profile.

**cap_drop** — A Docker Compose and runtime directive that removes Linux capabilities from a container process. SIEMhunter uses `cap_drop: ALL` on all containers to eliminate inherited capabilities; individual capabilities are added back only if a specific container requires them.

**CIS Docker Benchmark** — The Center for Internet Security's hardening standard for Docker containers and the Docker daemon. SIEMhunter uses it as the reference for container hardening decisions, including `cap_drop`, `no-new-privileges`, `seccomp`, read-only file systems, non-root users, and `userns-remap`.

**Docker secrets** — Docker's native mechanism for injecting sensitive values (certificates, passwords, API keys) into running containers via in-memory `tmpfs` mounts at `/run/secrets/`. Values are never written to disk, never appear in environment variable blocks, and are not visible in image layer history. The mandatory credential delivery method for all SIEMhunter secrets (FR-16).

**fail-closed** — A design principle where a system denies or blocks an action if a required dependency is unavailable, rather than falling back to a less-secure alternative. In SIEMhunter, this applies to rule-change auditing: if the Sentinel write fails, the rule change is rejected and the ClickHouse rule state is not updated (FR-14). The system does not silently accept rule changes that cannot be audited.

**gitleaks / truffleHog** — Open-source secret-scanning tools that detect credentials, certificates, and other sensitive values committed to a git repository. Both run as CI gates in SIEMhunter's supply chain pipeline to prevent credential commits from reaching the repository.

**HELK** — Hunting ELK. An open-source threat-hunting platform that combines Elasticsearch, Logstash, Kibana, and Kafka. SIEMhunter's architecture is conceptually inspired by HELK but is significantly lighter: ClickHouse replaces the ELK stack, and Vector replaces Logstash, to reduce resource requirements at lab scale.

**ledger reconciliation** — The process of comparing the count of events that the ingest stage accepted against the count actually stored in ClickHouse, to detect data loss or tampering in the ingest pipeline. One of the five self-detections (FR-09 item 5). A mismatch triggers a `SIEMHunterSecurity_CL` alert.

**no-new-privileges** — A Docker security option (`security_opt: no-new-privileges:true`) that prevents container processes from acquiring new Linux privileges through setuid or setgid binaries. Applied to all SIEMhunter containers as part of the CIS Docker Benchmark hardening profile.

**provenance tag** — A metadata field assigned by the collector (Vector) at the moment an event is first received. Records the ingest pipeline identifier, source host or transport, and collection timestamp. Downstream components trust the provenance tag rather than any source-supplied field, because source-supplied fields may be attacker-controlled. The provenance tag must not be overridable by content within the event itself (NFR-05).

**SBOM** — Software Bill of Materials. A machine-readable inventory of all software components, libraries, and dependencies included in the SIEMhunter container images. Generated as part of the CI pipeline (FR-20) and used to track vulnerable components and license obligations.

**seccomp** — Secure Computing Mode. A Linux kernel feature that restricts which system calls a process may make. Docker applies a default seccomp profile to all containers; SIEMhunter does not override it, ensuring that containers cannot make syscalls outside the default allowed set.

**STRIDE** — Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege. A threat-modeling framework used to enumerate threats against a system. SIEMhunter's threat model (`14-threat-model.md`) uses STRIDE as the organizing structure for analyzing each trust boundary and component.

**Trivy / Grype** — Open-source vulnerability scanners for container images and software dependency manifests. Both run in the SIEMhunter CI pipeline (FR-20); the build fails if either tool reports a critical or high severity finding in a first-party image layer.

**userns-remap** — A Docker daemon feature that maps container user IDs (UIDs) to a non-root UID range on the host. Even if a process inside a container runs as UID 0 (root within the container namespace), it maps to an unprivileged UID on the host, limiting the blast radius of a container escape.

**WORM** — Write Once, Read Many. A storage property meaning data cannot be modified or deleted after it is written. Microsoft Sentinel's Log Analytics workspace approximates this behavior for ingested data: events appended via the Logs Ingestion API cannot be modified in place, providing tamper evidence for forensic purposes.

---

## SDLC / Operations

**429 / back-pressure** — HTTP status code 429 Too Many Requests. The Logs Ingestion API returns 429 when the forwarder exceeds the ingestion rate limit for the workspace or DCR. SIEMhunter must read the `Retry-After` header from the 429 response and apply exponential backoff before retrying; ignoring 429 responses can result in data loss or a temporary block from the ingestion endpoint.

**ClickHouse** — A columnar OLAP (Online Analytical Processing) database used in SIEMhunter as both the local hot event store and the batch detection engine. Sigma rules are compiled by pySigma to ClickHouse SQL and executed directly against the stored OCSF-normalized events. ClickHouse is not exposed to the host network or LAN; it is reachable only from other containers in the internal Docker Compose network (FR-15).

**DuckDB** — A lightweight embedded analytics database. Referenced in SIEMhunter for CI and testing contexts only — for example, running schema validation or pipeline query tests without a full ClickHouse instance. Not used in the production deployment.
