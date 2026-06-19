# SIEMhunter — Acceptance Criteria

**Document:** 10-acceptance-criteria.md
**Version:** 0.1.0-draft
**Date:** 2026-06-19
**Status:** Active — sign-off required before build agents are invoked
**Owner:** requirements-analyst
**Audience:** tech-lead (gate enforcement), all agents, docs-maintainer (cross-ref sweep)

---

## 1. Purpose

This document is the contract between the docs-first phase and the build phase.

The docs-first phase produces a complete set of specifications — architecture,
requirements, threat model, detection rules, deployment, and security design —
before a single line of application code is written. This phase is complete when
every item in Section 2 is checked and countersigned by the docs-maintainer.

The build phase produces working software — containers, detection rules, Sentinel
forwarding, CI pipelines, and Azure resources — verified against these criteria.
The build phase is complete, and v0.1.0 is considered production-ready for a home-lab
environment, when every item in Section 3 is checked.

**Neither phase may begin until its predecessor's gate is passed:**

- Build agents MUST NOT be invoked until Section 2 is fully checked.
- v0.1.0 MUST NOT be declared production-ready until Section 3 is fully checked.

When a checkbox is verified by a human or agent, it should be marked with the
verifier's identity and date alongside the checkbox, for example:

```
- [x] `instructions/02-requirements.md` — verified: docs-maintainer 2026-06-19
```

---

## 2. Docs-First Phase Acceptance

> All items in this section must be checked before build begins.
> The docs-maintainer cross-reference sweep (Step 20 in `00-orchestration-plan.md`)
> must be completed before this section is declared done.

---

### 2.1 Documentation Completeness

Each file below must exist at the listed path, be internally consistent, and
contain the content described in the master orchestration plan (`00-orchestration-plan.md`)
and the relevant agent-task matrix (`13-agent-task-matrix.md`).

- [ ] `instructions/00-orchestration-plan.md` — master plan with 20-step execution
      table, agent bench, wave summary, hand-off contracts, and go/no-go gates

- [ ] `instructions/01-architecture-overview.md` — component and service table,
      Mermaid data-flow diagram, trust boundary definitions, and security design
      principles that shape the system

- [ ] `instructions/02-requirements.md` — functional requirements FR-01 through
      FR-20, non-functional requirements NFR-01 through NFR-10, v0.1.0 scope
      table, constraints listing, assumptions table (A-01 through A-07), and
      open questions

- [ ] `instructions/03-data-ingestion-spec.md` — all six source types (syslog,
      WEF/EVTX, Netflow/IPFIX, forensic artifact, Azure KQL pull, and the
      always-on flood heuristic path), at least one sample raw event per source,
      per-source security controls, and the Vector-level size, rate, and
      decompression cap enforcement

- [ ] `instructions/04-normalization-and-schema.md` — three-layer normalization
      strategy (OCSF internal, ASIM destination, per-class mapping); canonical
      field table with all 30 fields showing Sigma name, OCSF path, ClickHouse
      column and type; ASIM table mapping per OCSF event class; ClickHouse DDL
      for the `security_events` table; the `SIEMHunterHealth_CL` and
      `SIEMHunterSecurity_CL` column layouts; and the documented pySigma
      translation limits

- [ ] `instructions/05-detection-and-anomaly.md` — three-tier detection model;
      all five self-detections (SELF-001 through SELF-005) with rule YAML, primary
      source, ClickHouse source, and production status; all six Windows/AD TTP
      rules (T1558.003, T1558.004, T1003.006, T1003.001, T1021.002, T1021.001)
      with rule YAML, required EventIDs, required audit policy, and required source;
      prerequisites table with verification steps; local-vs-Sentinel ownership
      table; `detection_state` table DDL; always-on flood heuristic mechanism;
      ML baseline-only scoring spec; rule lifecycle (draft → test → review →
      production); and ATT&CK coverage matrix

- [ ] `instructions/06-api-control-plane.md` — all FastAPI endpoints with method,
      path, authentication requirement, and expected error behavior; the
      fail-closed rule-change audit mechanism (Sentinel write before ClickHouse
      update); SSRF protection (IMDS and private-range block); bearer token auth
      design with `hmac.compare_digest` requirement; and the localhost-only binding
      constraint

- [ ] `instructions/07-sentinel-forwarding.md` — Logs Ingestion API forward path
      (DCE/DCR model, payload format, batching parameters, anti-replay dedup,
      local append-only ledger, back-pressure and retry handling); Incidents API
      alert push (incident structure, severity mapping, idempotency via fingerprint,
      local-vs-Sentinel ownership table); optional KQL pull (auth, query mechanics,
      latency note); `SIEMHunterHealth_CL` schema; `SIEMHunterSecurity_CL` schema;
      two Sentinel analytics rule stubs; table-level RBAC; IaC notes

- [ ] `instructions/08-deployment-hybrid.md` — six-service Docker Compose topology
      (vector, clickhouse, normalization, detection, forwarder, api); three-network
      model (ingest, internal, egress) with trust level per network; CIS Docker
      Benchmark hardening controls (non-root, cap_drop: ALL, read-only filesystem,
      no Docker socket mount, no host-network port for ClickHouse); secrets
      discipline (Docker secrets only, no env var secrets); CI/CD gates
      (gitleaks/truffleHog, SBOM, Trivy/Grype, pySigma compile check)

- [ ] `instructions/09-security-and-iam.md` — secrets handling for all credential
      types; Azure RBAC role assignments for push and pull identities; certificate
      generation and rotation runbook; at least three incident response runbooks
      (certificate theft, rule disable, ingestion flood); supply-chain controls
      (pinned digests, lockfile, SBOM, Trivy/Grype, pinned SigmaHQ commit); Entra
      Conditional Access named-location policy for workload identities

- [ ] `instructions/10-acceptance-criteria.md` — this file (self-referential;
      present and internally consistent)

- [ ] `instructions/11-glossary.md` — all 40 or more terms defined; coverage
      includes at minimum every acronym and technical term introduced across the
      numbered documents

- [ ] `instructions/12-data-retention-and-lifecycle.md` — per-source local
      retention tiers; ClickHouse TTL policy per table; Sentinel workspace-level
      retention for `SIEMHunterHealth_CL` (30 days) and `SIEMHunterSecurity_CL`
      (90 days minimum); replay and purge handling for the local retry queue;
      operator guidance for disk space trade-offs

- [ ] `instructions/13-agent-task-matrix.md` — all agents listed with their
      deliverable files, dependencies, parallel eligibility flags, milestone
      assignments, and security owner designations; consistent with the 20-step
      table in `00-orchestration-plan.md`

- [ ] `instructions/14-threat-model.md` — STRIDE analysis for all three trust
      boundaries (ingest edge, internal pipeline, Sentinel forwarding); at least
      two Mermaid attack trees (one for certificate theft pivot, one for ingest
      injection); findings table with at minimum 13 rows, each row showing threat
      category, finding description, current control, and residual risk

- [ ] `instructions/15-adr-forwarder-credential.md` — Architecture Decision
      Record covering Context, Decision, and Consequences; two separate app
      registrations (push identity and pull identity) documented; DCR resource-ID
      placeholder in the exact format
      `/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}/providers/Microsoft.Insights/dataCollectionRules/{DCR_NAME}`;
      certificate-only credential decision (client secrets rejected); Docker
      secrets delivery path for the private key; cert rotation runbook stub

- [ ] `instructions/16-hardening-checklist.md` — per-requirement checkbox
      controls covering container hardening, secrets discipline, network isolation,
      TLS verification, Entra diagnostic settings, RBAC verification, gitleaks/
      truffleHog CI gate, SBOM generation, and image scanning; a go/no-go gate
      section that must be passed before deployment to any environment beyond
      local development

- [ ] `advise.md` (repository root) — three adversary profiles (external log-feeder,
      host-landed attacker, insider/compromised analyst); six kill-chain categories;
      at least two attack trees; findings aligned with `14-threat-model.md`; at
      least five red-team hand-off objectives for the deferred Phase 5 adversarial
      validation; at least three ASIM/KQL sketch queries; authorization gate
      statement confirming that no red-team activity may occur until after the
      build phase is complete

- [ ] `README.md` (repository root) — plain-language project description; current
      status displayed as "Design phase — docs-first"; pointer to `instructions/`
      for all specification documents; no build instructions (those are deferred
      to the build phase)

- [ ] `.gitignore` (repository root) — rules covering at minimum: secrets and key
      files, Python bytecode and virtual environments, Terraform state and override
      files, Docker Compose override files, local data volumes and ClickHouse data
      directories, ML model artifacts, compiled pySigma SQL output
      (`rules/compiled/`), and ATT&CK Navigator layer (`rules/navigator-layer.json`
      when auto-generated)

---

### 2.2 Cross-Reference Integrity

These items verify that the documents agree with each other. The docs-maintainer
must check each item explicitly during the Step 20 cross-reference sweep.

- [ ] Every in-document reference to another file (for example, "see
      `07-sentinel-forwarding.md`") resolves to an existing file at the referenced
      path. No dangling references.

- [ ] The canonical field table in `04-normalization-and-schema.md` §5 and the
      `field_mappings` section of `rules/pipelines/clickhouse-asim-ocsf.yaml`
      contain exactly the same set of field names, ClickHouse column names, and
      column types. Any field present in one and absent from the other is a
      blocking discrepancy.

- [ ] The local-vs-Sentinel ownership table in `05-detection-and-anomaly.md` §5
      and the equivalent table in `07-sentinel-forwarding.md` §3.3 are consistent.
      Every detection row that appears in `05` must appear in `07` with the same
      incident-creation path and tag value, and vice versa. No detection may be
      listed as owned by SIEMhunter in one table and by Sentinel in the other.

- [ ] The DCR resource-ID placeholder format in `15-adr-forwarder-credential.md`
      §4.1 is reproduced verbatim in `07-sentinel-forwarding.md` §2.2 and
      referenced consistently in `09-security-and-iam.md`. The placeholder format
      must be identical across all three documents; it must not be paraphrased or
      abbreviated in any of them.

- [ ] The five self-detection IDs (SELF-001 through SELF-005) and their names
      (`CertAnomalyDetected`, `IngestFloodDetected`, `RuleDisableAudit`,
      `DecompressionCapTrip`, `LedgerReconciliationDelta`) are identical across
      `05-detection-and-anomaly.md`, `07-sentinel-forwarding.md`, and `advise.md`.
      No document may introduce a sixth self-detection ID or rename an existing one
      without a corresponding update to all three.

- [ ] The `SIEMHunterHealth_CL` column layout in `07-sentinel-forwarding.md` §5
      matches every reference to that table's columns in `05-detection-and-anomaly.md`,
      `06-api-control-plane.md`, and `09-security-and-iam.md`. Specifically: the
      permitted `EventType` values (`IngestFlood`, `ParseError`, `DecompressionRatioCap`,
      `ForwardRetry`, `ForwardFail`, `BatchSuccess`, `PurgeBeforeForward`) are used
      consistently without variation in spelling or casing.

- [ ] The `SIEMHunterSecurity_CL` column layout in `07-sentinel-forwarding.md` §6
      matches every reference to that table's columns in `05-detection-and-anomaly.md`,
      `06-api-control-plane.md`, and `09-security-and-iam.md`. Specifically: the
      permitted `EventType` values (`CertAnomalyDetected`, `IngestFloodDetected`,
      `RuleDisableDetected`, `DecompressionCapTrip`, `LedgerDelta`, `DetectionHit`,
      `RuleChangeAudit`) are consistent without variation.

---

### 2.3 Prerequisites Identified

These items confirm that the decisions and external dependencies needed for the
build phase have been identified and documented. None of these require the
infrastructure to actually exist yet; they require that a plan or decision is
recorded in the documents. Items marked as a human decision require explicit
confirmation from the operator before build begins.

- [ ] **Azure Sentinel workspace:** An existing or planned Sentinel workspace is
      identified. The workspace ID and Log Analytics workspace resource ID are
      either recorded in `15-adr-forwarder-credential.md` §4 (as placeholder
      values or real values) or the operator has confirmed they will be supplied
      before the first deployment.

- [ ] **DCR and DCE resource names:** The DCR name and DCE name are planned and
      recorded in `15-adr-forwarder-credential.md` §4.1 and §4.2. The DCR
      resource-ID placeholder is populated with the correct subscription ID and
      resource group (even if the DCR has not yet been provisioned — the naming
      convention must be decided before IaC is written).

- [ ] **App registration plan:** Both the push identity (`siemhunter-push-prod`
      or equivalent) and the pull identity (`siemhunter-pull-prod` or equivalent)
      are planned. The plan is documented in `15-adr-forwarder-credential.md` §2
      with the intended display names, required API permissions, and RBAC role
      assignments. Certificate generation commands are documented in
      `09-security-and-iam.md`.

- [ ] **Entra P1 license confirmed:** The operator has confirmed that Entra ID P1
      licensing is available for the target tenant. This is required for the
      Conditional Access named-location policy referenced in
      `15-adr-forwarder-credential.md` §2.7 and `07-sentinel-forwarding.md` §7
      (Rule 2). Without Entra P1, the named-location policy cannot be applied and
      the certificate theft detection path is weakened.

- [ ] **DC audit policy requirements documented:** For each Windows/AD TTP rule in
      `05-detection-and-anomaly.md` §3, the required audit subcategory and the
      verification command (`auditpol /get /subcategory:...`) are documented in the
      prerequisites table in `05` §4. The operator must confirm that these policies
      can be applied to the Domain Controllers in the target lab environment.

- [ ] **Sysmon deployment confirmed for endpoints:** The operator has confirmed
      that Sysmon can be deployed on the endpoints that will be monitored for
      T1003.001 (LSASS memory access). The required Sysmon configuration XML
      (including a `ProcessAccess` rule targeting `lsass.exe`) is documented in
      `05-detection-and-anomaly.md` §4. Without this, the LSASS detection rule
      produces zero results with no error.

- [ ] **Entra AuditLogs and SignInLogs diagnostic settings plan documented:** The
      operator has confirmed that Entra diagnostic settings will be configured to
      stream `AuditLogs` and `SignInLogs` to the Sentinel workspace before SELF-001
      is promoted to production status. The verification steps are documented in
      `05-detection-and-anomaly.md` §2 (SELF-001 prerequisite) and
      `07-sentinel-forwarding.md` §4.1. This is documented as assumption A-01 in
      `02-requirements.md`.

- [ ] **Docker secrets strategy confirmed:** The operator has confirmed the
      Docker secrets delivery strategy for the on-premise deployment. At minimum,
      the list of required secrets (app registration private key certificate,
      ClickHouse credentials, FastAPI bearer token) is documented in
      `09-security-and-iam.md` and the Compose `secrets` block design is documented
      in `08-deployment-hybrid.md`. This corresponds to assumption A-05 in
      `02-requirements.md`.

- [ ] **Supply-chain plan confirmed:** The following four supply-chain decisions
      are documented in `09-security-and-iam.md` and/or `08-deployment-hybrid.md`:
      (a) pinned image digests in all Dockerfiles and the Compose file;
      (b) Python dependency lockfile (requirements.txt with hashes or Poetry
      lock file);
      (c) SBOM generation tool and output format;
      (d) the specific SigmaHQ commit hash or release tag to pin as the community
      rule snapshot for v0.1.0. Item (d) is noted as open question 7 in
      `02-requirements.md` and must be decided and recorded before the build
      phase starts.

---

## 3. Build Phase Acceptance (v0.1.0 Definition of Done)

> All items in this section must be checked before v0.1.0 is declared
> production-ready. Items are grouped by subsystem. Each item describes a
> verifiable outcome; the test-engineer translates these directly into test cases.

---

### 3.1 Ingestion

- [ ] Syslog messages in RFC 3164 format are accepted on the configured UDP port
      and appear as rows in the `security_events` ClickHouse table with correct
      `ProvenanceTag` and `IngestTimestamp` values.

- [ ] Syslog messages in RFC 5424 format are accepted on the configured TCP port
      and on the TLS port (default 6514) and appear in `security_events` with
      correct `ProvenanceTag` and `IngestTimestamp` values.

- [ ] Windows Event Log events (DC security events and Sysmon EID 10) arrive via
      WEF or EVTX-to-JSON file drop and appear as normalized rows in
      `security_events` with `ChannelName` correctly set to `Security` or
      `Microsoft-Windows-Sysmon/Operational` respectively.

- [ ] Netflow/IPFIX records arrive via the softflowd-to-Vector path and appear
      as normalized rows in `security_events` mapped to OCSF Network Activity
      class (OCSF 4001) with `DstPort` correctly populated.

- [ ] Forensic artifact JSON drops placed in the watched directory are ingested
      and appear in `security_events` with the forensic artifact `ProvenanceTag`.

- [ ] Every event row in `security_events` has a non-null `ProvenanceTag` and a
      non-null `IngestTimestamp`. Sending an event with a source-controlled
      hostname or identity field does not overwrite either of these collector-
      assigned fields.

- [ ] Sending an event that exceeds the per-event size cap causes the event to
      be dropped before parsing. A corresponding `ParseError` or equivalent
      `EventType` row appears in `SIEMHunterHealth_CL` in Sentinel indicating
      the oversized drop.

- [ ] Sending events at a rate that exceeds the per-source rate limit causes
      excess events to be dropped and the rate limit trip to be logged. The
      ingest rate limit is enforced independently per `ProvenanceTag`.

- [ ] Submitting a compressed forensic artifact with a decompression ratio that
      exceeds the configured cap causes decompression to be aborted and the
      artifact to be rejected. A `DecompressionRatioCap` row appears in
      `SIEMHunterHealth_CL`.

- [ ] Submitting an event whose parsing exceeds the configured parse timeout
      causes the event to be dropped. A parse failure row appears in
      `SIEMHunterHealth_CL`.

---

### 3.2 Normalization

- [ ] Every event from every ingest path is stored in ClickHouse using the OCSF
      canonical internal schema before any detection rule or forwarding step
      processes it.

- [ ] All 30 fields in the canonical field table in `04-normalization-and-schema.md`
      §5 are present in the `security_events` ClickHouse table schema. Fields that
      are not applicable to a given event class are stored as the appropriate null
      or zero value for their column type; they are never missing from the schema.

- [ ] The `EventID` column in `security_events` is declared as `UInt32` in the
      ClickHouse table DDL. Inserting a Windows Event Log with `EventID` as a
      string causes the normalization layer to coerce it to `UInt32` before
      insertion. Inserting an event with a non-numeric `EventID` causes it to be
      coerced to `0` and a parse warning to be logged.

- [ ] All ClickHouse inserts use parameterized queries. No field value from any
      ingested event is concatenated or interpolated into a SQL string at any
      point in the normalization or detection pipeline. A code review or static
      analysis check confirms this.

---

### 3.3 Detection

- [ ] SELF-001 (`CertAnomalyDetected`): The Sentinel analytics rule using the KQL
      in `05-detection-and-anomaly.md` §2 is deployed in the Sentinel workspace
      and has been verified to return results when the SIEMhunter app registration
      signs in from a second IP. Entra AuditLogs and SignInLogs have been confirmed
      streaming to the workspace before this rule is promoted to production status.

- [ ] SELF-002 (`IngestFloodDetected`): When the Vector flood heuristic fires
      (events-per-second exceeds threshold for 60 consecutive seconds), a
      `FloodHeuristic` row appears in `SIEMHunterHealth_CL`. The batch detection
      run picks it up and writes an `IngestFloodDetected` row to
      `SIEMHunterSecurity_CL`. A Sentinel analytics rule generates an incident.

- [ ] SELF-003 (`RuleDisableAudit`): When any Sigma rule is moved out of
      production status via the FastAPI control plane, a `RuleChangeAudit` row
      appears in `SIEMHunterSecurity_CL` in Sentinel before the ClickHouse rule
      state is updated. If the Sentinel write fails, the rule change is rejected
      and ClickHouse retains the prior state (fail-closed behavior verified by
      simulating a Sentinel write failure).

- [ ] SELF-004 (`DecompressionCapTrip`): When a compressed forensic artifact
      exceeds the decompression ratio cap, a `DecompressionRatioCap` row appears
      in `SIEMHunterHealth_CL`. The batch detection run writes a
      `DecompressionCapTrip` row to `SIEMHunterSecurity_CL` and a Sentinel
      incident is generated.

- [ ] SELF-005 (`LedgerReconciliationDelta`): At end of a batch cycle, the
      forwarder queries Sentinel for the event count received in the prior window
      and compares it with the local ledger count. A test simulating a count
      discrepancy (by injecting a ledger entry for events that were not actually
      forwarded) results in a `LedgerDelta` row in `SIEMHunterSecurity_CL` and a
      Sentinel incident.

- [ ] Kerberoasting rule (T1558.003, `windows-ad-001`) is in `production` status.
      A positive test event (EID 4769, non-machine-account service name) produces
      a detection hit. A negative test event (EID 4769, machine-account service
      name ending in `$`) does not produce a hit.

- [ ] AS-REP Roasting rule (T1558.004, `windows-ad-002`) is in `production` status.
      A positive test event (EID 4768, non-machine-account target) produces a hit.
      A negative test event (EID 4768, machine-account target ending in `$`) does
      not produce a hit.

- [ ] DCSync rule (T1003.006, `windows-ad-003`) is in `production` status. A
      positive test event (EID 4662, `ObjectName` containing `DC=`,
      `SubjectUserName` not ending in `$`) produces a hit. A negative test event
      (EID 4662, `SubjectUserName` ending in `$`) does not produce a hit
      (machine account exclusion verified).

- [ ] LSASS rule (T1003.001, `windows-ad-004`) is in `production` status. A
      positive test event (Sysmon EID 10, `TargetImage` ending in `\lsass.exe`,
      `GrantedAccess` matching one of `0x1010`, `0x1038`, `0x143a`, `0x40`)
      produces a hit. A negative test event with `GrantedAccess` not in that list
      does not produce a hit.

- [ ] SMB lateral movement rule (T1021.002, `windows-ad-005`) is in `test` or
      `production` status. CI gates pass (positive and negative test events pass).

- [ ] RDP lateral movement rule (T1021.001, `windows-ad-006`) is in `test` or
      `production` status. CI gates pass (positive and negative test events pass).

- [ ] All rules with status `production` compile against
      `rules/pipelines/clickhouse-asim-ocsf.yaml` with zero warnings. Any
      pySigma compilation warning for a production-status rule fails the CI gate.

- [ ] All rules with status `production` have corresponding positive and negative
      test event files under `rules/tests/<rule_id>/positive.json` and
      `rules/tests/<rule_id>/negative.json`. The DuckDB-based test runner executes
      these files and all tests pass in CI.

- [ ] The ATT&CK Navigator layer at `rules/navigator-layer.json` has been
      auto-generated by the CI pipeline on the most recent merge to main and
      reflects only production-status rules.

- [ ] The `detection_state` table exists in ClickHouse with the DDL defined in
      `05-detection-and-anomaly.md` §6, including the `TTL expiry DELETE` clause.
      (No rules use it in v0.1.0; the table must exist so the schema is in place
      for v0.2.)

- [ ] The baseline ML model has been trained on at least 7 days of historical
      data from the `security_events` table. The model artifact's SHA-256 hash
      is stored in a separate operator-controlled file. On startup, the detection
      engine verifies the hash before loading the model; a deliberately corrupted
      hash file causes the engine to refuse to load the model and write a `Warning`
      event to `SIEMHunterHealth_CL`.

- [ ] The always-on Vector flood heuristic is active in the Vector pipeline. It
      evaluates the events-per-second rate continuously and does not require the
      batch detection cycle to fire.

---

### 3.4 Sentinel Forwarding

- [ ] Normalized events from the `security_events` ClickHouse table are forwarded
      to the Sentinel workspace via the Logs Ingestion API. Events appear in the
      correct ASIM-aligned custom tables (for example, `ASimAuthentication`,
      `ASimNetworkSession`) within the expected latency window.

- [ ] The `SIEMHunterHealth_CL` table is receiving events from the SIEMhunter
      pipeline on every batch cycle. A spot-check query
      (`SIEMHunterHealth_CL | take 5`) returns results.

- [ ] The `SIEMHunterSecurity_CL` table is receiving events for detection hits
      and self-detection results. A spot-check query
      (`SIEMHunterSecurity_CL | take 5`) returns results.

- [ ] Sentinel incidents are created by the forwarder for self-detections
      (SELF-001 through SELF-005) via the Incidents API, with the correct
      severity mapping (Sigma `critical`/`high` → Sentinel `High`, `medium` →
      `Medium`, `low` → `Low`), correct `rule_id` label, and a `source_event_ids`
      custom property referencing the triggering event UIDs.

- [ ] SELF-005 ledger reconciliation: after a complete batch cycle, the
      forwarder's local ledger count for a specific stream matches the event count
      returned by the Sentinel KQL query for the same stream and time window. The
      test window must contain at least 100 events to provide a meaningful
      comparison.

- [ ] HTTP 429 back-pressure: when the Logs Ingestion API returns 429, the
      forwarder reads the `Retry-After` header and waits the specified duration
      before retrying. After 5 failed retries, the batch is moved to the local
      on-disk retry queue. No events are silently dropped during this sequence.
      A `ForwardFail` event appears in `SIEMHunterHealth_CL`.

- [ ] TLS verification is active on all outbound HTTPS connections (Logs
      Ingestion API, Incidents API, KQL pull). Pointing the forwarder at a test
      HTTPS endpoint with an invalid or self-signed certificate that the system
      does not trust results in a connection error; the forwarder does not connect
      and logs the failure. There is no configuration option to disable TLS
      verification.

---

### 3.5 Control Plane

- [ ] The FastAPI control plane is reachable at `http://127.0.0.1:<port>` from
      the Docker host and is not reachable from any other host on the lab LAN.
      A connection attempt from a second machine on the same LAN fails or times
      out.

- [ ] Every API endpoint returns `401 Unauthorized` for requests that do not
      include a valid `Authorization: Bearer {token}` header. This includes
      `GET` endpoints and health-check endpoints.

- [ ] The fail-closed rule-change audit is verified: simulating a Sentinel write
      failure during a rule status change (for example, by pointing the forwarder
      at an unreachable endpoint for the test) causes the FastAPI endpoint to
      return a `5xx` error and leaves the ClickHouse rule state unchanged.

- [ ] The `/query` endpoint (or equivalent ad-hoc query endpoint) rejects any
      statement that is not a `SELECT`. Submitting a `DROP TABLE` statement or
      `INSERT` statement returns a `400 Bad Request`. The `SELECT` is also subject
      to a row cap and a query timeout; a query that would return more than the
      configured row cap is truncated at the cap with a clear indication in the
      response.

- [ ] The SSRF protection is verified: sending a request to the `/query` or any
      forwarder-config endpoint that encodes the Azure IMDS address
      (`169.254.254.169`) or any RFC 1918 private-range address as a destination
      is blocked. The forwarder does not attempt an outbound connection to those
      addresses.

---

### 3.6 Deployment

- [ ] Running `docker compose up` on a clean host (no pre-existing images or
      volumes beyond what the Compose file defines) starts all six services
      without manual intervention. All six services are in the `running` state
      within the expected start-up window.

- [ ] All containers run as a non-root user. Running `docker inspect <container>`
      for each service confirms that the `User` field is not empty and is not
      `root` or `0`.

- [ ] `cap_drop: ALL` is in effect for every container. Running
      `docker inspect <container>` and checking `HostConfig.CapDrop` confirms
      the value is `["ALL"]` for each service.

- [ ] ClickHouse has no published ports. Running `docker inspect clickhouse` and
      checking `NetworkSettings.Ports` confirms no host binding. A connection
      attempt to the ClickHouse port from the Docker host or from the LAN fails.

- [ ] No container has the Docker socket mounted. Running `docker inspect
      <container>` for each service confirms that `/var/run/docker.sock` does not
      appear in `Mounts`.

- [ ] All credentials (app registration private key, ClickHouse password, FastAPI
      bearer token) are injected via Docker secrets mounted at `/run/secrets/`.
      Running `docker inspect <container>` for each service confirms that no
      secrets appear in `Config.Env` (environment variable blocks). The repository
      contains no `.env` file with secret values.

- [ ] The gitleaks and truffleHog CI gate passes on the main branch. Running the
      gate manually against the repository produces zero findings.

---

## 4. Explicitly Out of Scope for v0.1.0

The following items are deferred. They must NOT be included in the v0.1.0 build
acceptance checklist, and build agents must NOT write code, configuration, or
infrastructure for them unless explicitly authorized by a superseding decision.
Including placeholder code, stub endpoints, or commented-out configuration for
these items is also prohibited.

| Deferred item | Reason for deferral | Target version |
|---|---|---|
| AI/LLM red-team detection | Requires HTTP proxy or LLM gateway log source not available in v0.1.0 | v0.2 |
| OWASP web-layer TTP detection | Requires WAF log source | v0.2 |
| APT multi-stage kill-chain correlation | Requires streaming pipeline (Redpanda as mandatory component) | v0.2 |
| OpenSearch integration | Not required for lab scale; ClickHouse is the sole store | v0.2 |
| PCAP and memory-image forensic ingestion | Distinct toolchain; out of scope for collector agent | v0.2 |
| Real-time / streaming detection path | Requires Redpanda; Redpanda is optional buffer only in v0.1.0 | v0.2 |
| Multi-tenant RBAC | Single-operator lab scope; RBAC model is single-tenant in v0.1.0 | v0.2 |
| Reporting and analysis front end | No user-facing UI in scope; control plane is API-only | Deferred indefinitely |
| `ad-redteamer` Phase 5 adversarial validation | Authorization-gated; system must be built and deployed before red-team activity | After build complete |
| Azure Key Vault integration for secret storage | Docker secrets are the v0.1.0 model; Key Vault is a v0.2 upgrade | v0.2 |
| Azure Private Link for DCE | Public DCE endpoint is the v0.1.0 topology; Private Link adds network isolation | v0.2 |
| Automated ML model retraining | Retraining is manual and offline-only in v0.1.0 | v0.2 |
| Per-entity ML model versioning and rollback | Not required for baseline-only advisory scoring | v0.2 |

---

## 5. Sign-Off Record

> This section is completed at gate time, not at document authoring time.
> Each phase's gate requires the listed roles to countersign.

### Docs-First Phase Gate (Section 2)

All Section 2 items must be checked before this gate is signed.

| Role | Name / Agent | Date | Signature / Confirmation |
|------|-------------|------|--------------------------|
| docs-maintainer | | | |
| tech-lead | | | |
| requirements-analyst | | | |

### Build Phase Gate (Section 3)

All Section 3 items must be checked before this gate is signed.
The docs-first gate must be signed before build begins.

| Role | Name / Agent | Date | Signature / Confirmation |
|------|-------------|------|--------------------------|
| test-engineer | | | |
| code-reviewer | | | |
| tech-lead | | | |

---

## 6. Cross-References

| Document | Relationship to this document |
|----------|------------------------------|
| `00-orchestration-plan.md` | Defines the 20-step execution sequence; §7 go/no-go gates are the preconditions this document verifies |
| `02-requirements.md` | Every FR and NFR must have at least one corresponding acceptance criterion in §3 |
| `05-detection-and-anomaly.md` | Source of self-detection IDs, rule names, rule YAML, and ownership table verified in §2.2 and §3.3 |
| `07-sentinel-forwarding.md` | Source of table schemas and forwarding design verified in §2.2 and §3.4 |
| `14-threat-model.md` | Threat findings that motivated controls verified in §3.3 (self-detections), §3.4 (TLS verification, SSRF), §3.6 (container hardening) |
| `15-adr-forwarder-credential.md` | DCR resource-ID placeholder format verified in §2.2; cert-only credential and Docker secrets delivery verified in §2.3 and §3.6 |
| `16-hardening-checklist.md` | The go/no-go gate in `16` is a prerequisite for the §3.6 deployment checks; both must pass before v0.1.0 is declared production-ready |
