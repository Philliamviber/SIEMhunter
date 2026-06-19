# 07 — Sentinel Forwarding

> **Document role:** Specifies the complete Microsoft Sentinel output path for the SIEMhunter forwarder. This document is a first-class deliverable in the forwarding/identity backbone (`15 → 07 → 09`). It consumes the DCR resource-ID placeholder and identity design from `15-adr-forwarder-credential.md`, the ASIM table mapping and custom table layouts from `04-normalization-and-schema.md`, and the local-vs-Sentinel ownership table from `05-detection-and-anomaly.md`. Later documents `09-security-and-iam.md` and `16-hardening-checklist.md` extend and operationalize the decisions made here. Future agents MUST NOT deviate from the forwarding design recorded here without a superseding ADR.
>
> **Status:** Accepted — v0.1.0
> **Owner:** cloud-security-engineer
> **Date:** 2026-06-19

---

## 1. Architecture Overview

SIEMhunter is **outbound-only** toward Sentinel. It opens no inbound ports on the forwarder path; there are no inbound listeners, no webhooks from Azure, and no agent-side server sockets. All communication is SIEMhunter-initiated HTTPS.

### Two output channels, one optional input

| Direction | Channel | Protocol / API | Purpose |
|-----------|---------|----------------|---------|
| Outbound | Data forward | Logs Ingestion API via DCE + DCR | Push normalized ASIM events to custom tables |
| Outbound | Alert push | Sentinel Incidents API | Create Sentinel incidents for detection hits |
| Inbound (SIEMhunter-initiated) | KQL pull (optional) | Azure Log Analytics Query API | Pull Entra / Sentinel context for local enrichment |

**TLS requirement:** Mandatory certificate verification on every HTTPS call. Verification must never be disabled — not in lab environments, not during development, not under any operational pressure. Any code path that sets `verify=False` (or equivalent) is a defect, not a configuration option.

### High-level data flow

```
On-prem SIEMhunter (Docker Compose)
│
│  [OCSF-normalized events, ASIM-mapped at forward time]
│  [Detection hits: Sigma + ML + self-detections]
│
▼  HTTPS outbound only — no inbound ports
──────────────────────────────────────────────
Microsoft Entra ID  ←── MSAL token exchange (certificate auth)
──────────────────────────────────────────────
         │
         ├─► Logs Ingestion API → DCE → DCR → Log Analytics workspace
         │       [ASIM tables + SIEMHunterHealth_CL + SIEMHunterSecurity_CL]
         │
         └─► Incidents API → Sentinel incident queue
                 [Self-detection incidents only; see §3 ownership table]

Optional (KQL pull, read-only, SIEMhunter-initiated):
Log Analytics Query API → workspace → Entra AuditLogs / SignInLogs
```

---

## 2. Logs Ingestion API — Data Forward Path

### 2.1 Data Collection Endpoint (DCE)

The DCE is the HTTPS ingress point for the Logs Ingestion API.

| Attribute | Value |
|-----------|-------|
| Endpoint pattern | `https://{dce-name}.{region}.ingest.monitor.azure.com` |
| Protocol | HTTPS; TLS verification mandatory |
| v0.1.0 topology | Public DCE endpoint |
| v0.2 topology | Azure Private Link DCE (deferred) |
| URI source | IaC output variable; injected as config at deploy time |
| URI in code | Never hardcoded; never in version control |

The DCE URI is an output of the Terraform or Bicep IaC that provisions the endpoint. It is delivered to the forwarder container via a Docker config object (not an environment variable — environment variables appear in `docker inspect` output). The forwarder validates that the URI is non-empty and matches the expected pattern `https://*.ingest.monitor.azure.com` at startup before attempting authentication.

### 2.2 Data Collection Rule (DCR)

One dedicated DCR per ASIM table in scope. A single shared DCR across multiple tables is not permitted because it conflates schemas and makes it impossible to apply per-table injection defenses.

#### DCR resource ID

Consumed verbatim from `15-adr-forwarder-credential.md` §4.1. The exact placeholder format is:

```
/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}/providers/Microsoft.Insights/dataCollectionRules/{DCR_NAME}
```

This resource ID is the RBAC scope for the push identity's `Monitoring Metrics Publisher` role assignment. The value in the running config must match the value in the role assignment exactly. A mismatch is a misconfiguration that blocks ingestion at token validation.

#### Required DCR transform clauses

Every DCR stream definition MUST include both of the following KQL transform clauses. These are server-side controls, not client-side options.

**`where` clause — schema validation gate**

Reject any event that is missing mandatory ASIM fields before the event is written to the table. Example for `ASimAuthentication`:

```kql
where isnotempty(TimeGenerated)
    and isnotempty(EventType)
    and isnotempty(ActorUsername)
    and isnotempty(DvcHostname)
```

The specific mandatory fields vary per ASIM table. The field list is derived from the ASIM schema specification for each table class. Events that fail the `where` clause are silently dropped by the DCR (they never land in the workspace). The forwarder's local ledger (§2.4) detects the resulting count discrepancy during reconciliation.

**`project` clause — column allow-list**

Explicitly enumerate every expected ASIM column. Any field present in the inbound payload that is not listed in `project` is dropped server-side.

```kql
project TimeGenerated, EventType, EventResult, EventSeverity,
        ActorUsername, ActorUserId, ActorUserDomain,
        TargetUsername, TargetUserId,
        SrcIpAddr, SrcPortNumber,
        DvcHostname, EventOriginalUid,
        AdditionalFields
```

**Why both clauses are required — injection defense**

A crafted log source that controls field values in an event could attempt to write arbitrary columns by supplying extra JSON keys. Without the `project` clause, the DCR would forward attacker-controlled fields to the workspace. The `project` clause drops them server-side, before they touch the Log Analytics table schema. The `where` clause adds a second layer by ensuring that events without mandatory identity anchors never reach the workspace at all, which limits the usefulness of sparse injected events for covering tracks.

These two clauses together implement the server-side injection defense described in `14-threat-model.md` §4 (Boundary 3, Tampering threat).

### 2.3 Payload format and batching

| Parameter | Value |
|-----------|-------|
| Format | JSON array |
| Max payload size | 1 MB per batch |
| Max events per batch | 500 |
| Auth token scope | `https://monitor.azure.com/.default` |
| SDK | `azure-monitor-ingestion` (Python) |
| Token acquisition | MSAL Python; certificate-based; token cached until 5 min before expiry |

The forwarder constructs each batch by pulling normalized events from the local queue in FIFO (first-in, first-out) order, applying the OCSF-to-ASIM field mapping for the target table, and serializing to JSON. Batches are bounded by both the 1 MB limit and the 500-event limit; whichever is reached first closes the batch.

Each JSON object in the array must include `TimeGenerated` (UTC ISO 8601) and `EventOriginalUid` (the stable dedup key). Missing either field causes the DCR `where` clause to drop the event server-side.

### 2.4 Anti-replay and deduplication

**EventOriginalUid**

Every forwarded event carries `EventOriginalUid`, mapped from `EventRecordID` (the `base_event.uid` OCSF field, sourced from `EventRecordID` in Windows Event Logs or an equivalent stable UID for syslog). This field is defined as the stable dedup key in `04-normalization-and-schema.md` §5. It is present in every payload and is preserved by the DCR `project` clause.

Sentinel does not deduplicate on `EventOriginalUid` natively. Dedup is the forwarder's responsibility: the forwarder must not re-submit an event whose `EventOriginalUid` was included in a previously confirmed batch unless ledger reconciliation determines the event was not ingested.

**Local append-only ledger**

The forwarder maintains a local append-only ledger (a flat log file or a lightweight SQLite table, never modified after write) that records each batch submission:

| Field | Description |
|-------|-------------|
| `batch_id` | UUID generated per batch at submission time |
| `submitted_at` | UTC timestamp of the API call |
| `stream_name` | DCR stream name (e.g., `Custom-ASimAuthentication`) |
| `event_count` | Number of events in the batch |
| `first_event_uid` | `EventOriginalUid` of the first event |
| `last_event_uid` | `EventOriginalUid` of the last event |
| `http_status` | Response status code |
| `confirmed` | Boolean; set true on 2xx response |

Ledger entries are never deleted or overwritten. A compaction or rotation policy may archive old entries (retain at minimum 7 days of ledger locally), but the Sentinel-side `SIEMHunterSecurity_CL` table holds the durable audit record.

**Ledger reconciliation self-detection**

Once per batch cycle, the forwarder queries Sentinel via the KQL pull path (§4) to count events received in the prior window and compares against the ledger's confirmed event count for the same window and stream. A discrepancy beyond the threshold (default: more than 5% delta or more than 50 events) generates a `LedgerDelta` event in `SIEMHunterSecurity_CL`. This is self-detection SELF-005 and is the primary control against finding #6 in `14-threat-model.md` (Sentinel forgery or loss).

### 2.5 Back-pressure and retry handling

The Logs Ingestion API may return HTTP 429 (Too Many Requests) under load. The forwarder must handle this without dropping events.

| Condition | Forwarder behavior |
|-----------|-------------------|
| HTTP 429 received | Read `Retry-After` header; wait exactly that duration before first retry |
| `Retry-After` absent | Default wait: 60 seconds |
| Persistent 429 (retry 2) | Double the wait (exponential backoff, base 60 s) |
| Persistent 429 (retry 3) | Halve batch size from 500 to 250 events |
| Persistent 429 (retry 4) | Halve batch size again to 125 events |
| Max retries (5) exceeded | Emit `ForwardFail` event to `SIEMHunterHealth_CL`; move batch to local retry queue |
| Local retry queue | On-disk bounded queue; max 10,000 events; FIFO drain on next successful cycle |

**No silent drops.** A batch that cannot be delivered after 5 retries goes to the local retry queue. It is never silently discarded. If the retry queue reaches capacity, the oldest batches are evicted and a `PurgeBeforeForward` event is emitted to `SIEMHunterHealth_CL` at Critical severity.

---

## 3. Incidents API — Alert Push

### 3.1 Purpose

When SIEMhunter produces a detection hit that requires immediate analyst attention, it creates a Sentinel incident via the Sentinel Incidents API. This is a separate call from the Logs Ingestion API and uses a different permission model (the push identity must be granted `Microsoft Sentinel Contributor` or an equivalent role at the workspace scope to create incidents — see `09-security-and-iam.md` for the exact role assignment).

### 3.2 Incident structure

| Field | Value / mapping |
|-------|----------------|
| `title` | Sigma rule name or self-detection display name |
| `severity` | See severity mapping table below |
| `status` | `New` at creation |
| `description` | Rule description + ATT&CK technique IDs (semicolon-separated) |
| `labels` | `rule_id`, `rule_version`, tag (see §3.3) |
| Custom property: `rule_id` | Stable Sigma rule ID or self-detection ID (e.g., `SELF-001`) |
| Custom property: `rule_version` | Semantic version of the rule at detection time |
| Custom property: `source_event_ids` | JSON array of `EventOriginalUid` values from triggering events |
| Custom property: `tag` | `SIEMhunterDetected` or `SIEMhunterSelfDetection` (see §3.3) |

**Severity mapping (Sigma level → Sentinel severity):**

| Sigma rule level | Sentinel incident severity |
|-----------------|---------------------------|
| `critical` | High |
| `high` | High |
| `medium` | Medium |
| `low` | Low |
| `informational` | Informational |

Sentinel does not have a `Critical` severity in the Incidents API response model; `critical` and `high` Sigma rules both produce `High` severity incidents. If this mapping needs to be distinguishable in the SOC (Security Operations Center) workflow, use a label (e.g., `sigma_level:critical`) as a supplementary signal.

### 3.3 Local-vs-Sentinel ownership table (anti-double-alerting)

This table is the co-authoring contract between `05-detection-and-anomaly.md` (which defines the self-detections) and this document (which defines the forwarding behavior). The SOC must understand the ownership split to avoid creating duplicate analytics rules in Sentinel.

| Detection category | Source | Incident created by | Tag on incident |
|-------------------|--------|--------------------|----|
| Self-detection SELF-001: Cert anomaly (2nd IP on SP) | Sentinel `SignInLogs` (Entra diagnostic settings → workspace) | Sentinel analytics rule queries `SignInLogs`; creates incident directly | `SIEMhunterSelfDetection` |
| Self-detection SELF-002: Ingest flood | SIEMhunter batch Sigma on `SIEMHunterHealth_CL` | Detection result written to `SIEMHunterSecurity_CL`; one Sentinel analytics rule creates incident | `SIEMhunterSelfDetection` |
| Self-detection SELF-003: Rule disable | SIEMhunter batch Sigma on `SIEMHunterSecurity_CL` | Detection result written to `SIEMHunterSecurity_CL`; one Sentinel analytics rule creates incident | `SIEMhunterSelfDetection` |
| Self-detection SELF-004: Decompression cap trip | SIEMhunter batch Sigma on `SIEMHunterHealth_CL` | Detection result written to `SIEMHunterSecurity_CL`; one Sentinel analytics rule creates incident | `SIEMhunterSelfDetection` |
| Self-detection SELF-005: Ledger delta | SIEMhunter ledger reconciliation via KQL pull | Detection result written to `SIEMHunterSecurity_CL`; one Sentinel analytics rule creates incident | `SIEMhunterSelfDetection` |
| All other Sigma detections | SIEMhunter batch | Forward tagged event; one Sentinel analytics rule creates the incident | `SIEMhunterDetected` |
| ML advisory alerts | SIEMhunter batch (advisory) | Forward as enriched event; Sentinel analytics rule decides | `SIEMhunterDetected` |

**Anti-double-alerting rule:**
- For `SIEMhunterDetected` rows: exactly **one** Sentinel analytics rule owns incident creation — it queries `SIEMHunterSecurity_CL` for `EventType == "DetectionHit"` and `tag == "SIEMhunterDetected"`. No secondary rule may fire on the same event subset.
- For SELF-002 through SELF-005: exactly **one** Sentinel analytics rule per detection queries `SIEMHunterSecurity_CL` for its specific `EventType` (e.g. `IngestFloodDetected`, `RuleDisableDetected`) and creates the incident.
- SELF-001 is the sole exception: it is a dedicated Sentinel analytics rule running on `SignInLogs` directly (data never lands in ClickHouse). No other rule should create incidents for the same SELF-001 event subset.

The SOC must audit Sentinel analytics rules to confirm no overlap before enabling any forwarding path.

### 3.4 Idempotency

The forwarder computes a deterministic incident ID before every Incidents API call:

```
incident_fingerprint = SHA-256(rule_id + "|" + sorted_joined_source_event_ids)
```

Where `sorted_joined_source_event_ids` is the lexicographically sorted list of `EventOriginalUid` values joined with `|`.

Before submitting, the forwarder queries the Incidents API (or a local cache of submitted fingerprints, TTL 24 hours) to check whether an incident with this fingerprint was already created. If it exists, the forwarder skips creation and logs a dedup hit to `SIEMHunterHealth_CL` at Informational severity.

This prevents duplicate incidents when the forwarder retries after a transient failure where the API returned an error but the incident was in fact created.

---

## 4. Optional KQL Pull — Enrichment

### 4.1 Critical prerequisite — Entra diagnostic settings

> **HARD PREREQUISITE.** The KQL pull path, and all self-detections that query Entra-derived tables (`AuditLogs`, `SignInLogs`), produce **zero results with no error** if Entra diagnostic settings are not configured to stream those log categories to the Sentinel Log Analytics workspace. There is no error message from the API — queries succeed and return empty result sets. This is the silent failure mode documented as finding #12 in `14-threat-model.md`.
>
> **Before enabling the KQL pull or any self-detection that queries Entra tables, the operator must verify:**
> 1. Microsoft Entra ID → Diagnostic settings → a setting exists that targets the Sentinel Log Analytics workspace.
> 2. The setting includes both `AuditLogs` and `SignInLogs` categories.
> 3. At least one event from each category has arrived in the workspace within the past 2 hours (confirmed via a KQL spot-check).
>
> This verification is a required item in `16-hardening-checklist.md`. SELF-001 in particular depends on both `AuditLogs` and `SignInLogs` being present. The T1098.001 credential-add detection defined in `09-security-and-iam.md` §4.4 also requires `AuditLogs`. SELF-002 through SELF-005 depend only on SIEMhunter's own internal tables and do not require Entra diagnostic settings.

### 4.2 Authentication

The KQL pull uses the separate pull identity defined in `15-adr-forwarder-credential.md` §2.3:

| Attribute | Value |
|-----------|-------|
| Identity | `siemhunter-pull-prod` (or `-lab`) app registration |
| Role | `Log Analytics Reader` |
| Scope | Log Analytics workspace resource ID (from `15-adr-forwarder-credential.md` §4.2) |
| SDK | `azure-loganalytics` Python SDK |
| Token scope | `https://api.loganalytics.io/.default` |

This identity is provisioned only when the KQL pull feature is enabled in the SIEMhunter deployment configuration. If the feature is disabled, the pull identity must not be provisioned (per `15-adr-forwarder-credential.md` §2.3).

### 4.3 Query mechanics

| Parameter | Value |
|-----------|-------|
| API | Azure Log Analytics Query API (`POST /query`) |
| Workspace ID | From deployment config; not hardcoded |
| Timespan | ISO 8601 duration; default `PT1H` (1-hour lookback) |
| Overlap | 5-minute overlap between consecutive windows (prevents gap if cycle runs slightly late) |
| Cadence | Every batch cycle (15–60 minutes, matching the detection batch cadence) |
| Max result rows | 10,000 per query; queries that would exceed this must be broken into sub-queries |

The 1-hour lookback window is deliberately wider than the batch cadence to absorb Entra-to-Sentinel diagnostic setting latency, which can be 5–30 minutes. A self-detection querying the last 15 minutes could miss events that have not yet arrived in the workspace. The 5-minute overlap prevents a gap between consecutive 1-hour windows when the batch cycle runs slightly late.

### 4.4 Latency note

Entra diagnostic settings introduce a pipeline delay before events appear in the Log Analytics workspace. This delay is typically 5–15 minutes but can reach 30 minutes under load. The 1-hour lookback in §4.3 is sized to absorb this delay. Do not reduce the lookback window below 30 minutes without confirming that Entra-to-workspace latency in the target tenant is consistently under 10 minutes.

---

## 5. SIEMHunterHealth_CL — Operational Table Schema

**Purpose:** Operational telemetry from the SIEMhunter pipeline. Written on every batch cycle and continuously by the ingest-flood heuristic. This is a plumbing-health table, not a security event table. Failures to write to this table must not block writes to `SIEMHunterSecurity_CL` (independence requirement from `04-normalization-and-schema.md` §7, FR-19).

**Retention:** 30 days (set as a workspace-level table retention policy via IaC). Generating high volume (one or more rows per batch cycle), this table has low forensic value beyond a recent operational window.

| Column | Type | Description |
|--------|------|-------------|
| `TimeGenerated` | `datetime` | UTC timestamp of the operational event; required by Log Analytics for table indexing |
| `HostName` | `string` | Hostname of the SIEMhunter instance that produced the event; maps to ASIM `DvcHostname` convention |
| `EventType` | `string` | Category of operational event; see permitted values below |
| `Severity` | `string` | `Informational`, `Warning`, `Error`, or `Critical` |
| `SourceId` | `string` | `ProvenanceTag` of the affected source (identifies the ingest path and transport) |
| `EventCount` | `int` | Number of events affected by the operational event |
| `Detail` | `string` | Human-readable description; free text for operator context |
| `BatchId` | `string` | UUID of the forward batch (matches the local ledger `batch_id`; used for ledger reconciliation) |

**Permitted `EventType` values:**

| EventType | Meaning |
|-----------|---------|
| `IngestFlood` | Always-on Vector flood heuristic fired for the tagged source |
| `ParseError` | Event could not be parsed; dropped from the batch |
| `DecompressionRatioCap` | Decompression-ratio cap tripped; source throttled |
| `ForwardRetry` | Batch submission retried after 429 or transient error |
| `ForwardFail` | Batch failed after max retries; moved to local retry queue |
| `BatchSuccess` | Batch submitted and confirmed (2xx response) |
| `PurgeBeforeForward` | Local retry queue at capacity; oldest batch evicted before delivery |

---

## 6. SIEMHunterSecurity_CL — Security Table Schema

**Purpose:** Security-relevant events generated by the SIEMhunter pipeline, including detection hits (Sigma, ML, self-detections), rule-change audit entries (FR-14), and self-detection results. This table is the evidence base for Sentinel incidents generated by SIEMhunter detections and the durable audit record for the rule-change audit chain. Failures to write to this table must not block writes to `SIEMHunterHealth_CL` (independence requirement, FR-19).

**Retention:** 90 days minimum. This is enforced by a workspace-level table retention policy provisioned via IaC and an Azure Policy that rejects retention values below 90 days (see §9). The rule-change audit (FR-14) and ledger reconciliation (SELF-005) both depend on querying historical entries in this table; shorter retention silently breaks those self-detections.

| Column | Type | Description |
|--------|------|-------------|
| `TimeGenerated` | `datetime` | UTC timestamp; required by Log Analytics |
| `RuleId` | `string` | Stable Sigma rule ID (UUID or SIGMAHQ identifier) or self-detection ID (`SELF-001` through `SELF-005`) |
| `RuleVersion` | `string` | Semantic version of the rule at the time of detection |
| `EventType` | `string` | Category of security event; see permitted values below |
| `Entity` | `string` | Primary entity involved: hostname, username, or IP address (whichever is most relevant to the detection) |
| `SourceEventIds` | `string` | JSON-serialized array of `EventOriginalUid` values from the triggering source events; enables analyst navigation from incident to evidence in ClickHouse |
| `Severity` | `string` | `Low`, `Medium`, `High`, or `Critical` |
| `Detail` | `string` | Human-readable finding; rule-specific context for the analyst |
| `ATTACKTechnique` | `string` | MITRE ATT&CK technique ID (e.g., `T1558.003`); empty string if not applicable |

**Permitted `EventType` values:**

| EventType | Meaning |
|-----------|---------|
| `CertAnomalyDetected` | Self-detection SELF-001: sign-in to push app registration from a second IP |
| `IngestFloodDetected` | Self-detection SELF-002: ingest volume anomaly confirmed at detection layer |
| `RuleDisableDetected` | Self-detection SELF-003: Sigma rule disabled without corresponding audit entry |
| `DecompressionCapTrip` | Self-detection SELF-004: decompression-ratio cap tripped; potential zip-bomb |
| `LedgerDelta` | Self-detection SELF-005: forwarded event count diverges from Sentinel query count |
| `DetectionHit` | A Sigma rule (non-self-detection) matched events in the current batch |
| `RuleChangeAudit` | Rule enabled, disabled, or version-changed; written to Sentinel BEFORE the ClickHouse update is applied (fail-closed) |

---

## 7. Sentinel Analytics Rule Stubs — SOC Authoring Required

The following two analytics rules must be authored by the SOC in the Sentinel workspace. SIEMhunter does not create these rules; it produces the data they query. Both rules should be reviewed against the anti-double-alerting constraint in §3.3 before activation.

### Rule 1 — Ingestion-volume anomaly (always-on heuristic)

**Target table:** `SIEMHunterHealth_CL`

**Logic description:** Query `SIEMHunterHealth_CL` filtered to `EventType == "IngestFlood"`. Any row matching this filter represents a fired ingest-flood heuristic in the Vector pipeline. This is an always-on heuristic (not a statistical threshold), so any hit is a confirmed signal rather than a statistical anomaly.

**Recommended incident severity:** High.

**Rationale:** An ingest flood can blind the detection engine during the batch window (finding #4 in `14-threat-model.md`). The SOC should treat any `IngestFlood` entry as a potential log-source attack until the source is confirmed legitimate. The rule should alert on the first occurrence per source (`SourceId`) per 15-minute window to avoid alert fatigue during a sustained flood.

**Do not create a duplicate rule** for `DecompressionCapTrip` events — that event type in `SIEMHunterHealth_CL` has its own self-detection path (`SELF-004`) that creates a Sentinel incident directly via the Incidents API.

### Rule 2 — Unexpected DCR writer (certificate theft detection)

**Target table:** Workspace ingestion metadata / Azure Monitor diagnostic logs for the DCR.

**Logic description:** Query the workspace ingestion logs (or Azure Monitor resource logs, if enabled for the DCR) for writes arriving at any SIEMhunter DCR stream from a source IP that is not the known egress IP of the SIEMhunter host. Cross-reference the known egress IP from the named location configured in Entra Conditional Access (see `15-adr-forwarder-credential.md` §2.7).

**Recommended incident severity:** Critical.

**Rationale:** This rule detects finding #1 in `14-threat-model.md`: an attacker who steals the forwarder private key and uses it to inject forged events from a different host. A successful write to the DCR stream from an unexpected IP means the certificate is in adversarial hands. The Conditional Access named-location policy is the primary control; this rule is the detection layer that fires if Conditional Access fails or is misconfigured.

**Dependency:** Entra Conditional Access for workload identities requires Entra ID P1 licensing. The SOC must verify the license and confirm that the named-location policy is active before considering this rule as a primary control. See `09-security-and-iam.md` for the Conditional Access setup steps.

---

## 8. Table-Level RBAC

The following access model applies to all SIEMhunter-owned tables in the Log Analytics workspace. The full RBAC specification, including ARM role assignment commands and the access review cadence, lives in `09-security-and-iam.md`.

| Identity | Tables accessible | Access type | Mechanism |
|----------|------------------|-------------|-----------|
| Push identity (`siemhunter-push-prod`) | `SIEMHunterHealth_CL`, `SIEMHunterSecurity_CL`, ASIM tables | Write-only via DCR | `Monitoring Metrics Publisher` on DCR resource ID; no direct workspace read |
| Pull identity (`siemhunter-pull-prod`) | All tables in workspace | Read-only | `Log Analytics Reader` at workspace scope; scope carefully — this identity can read all tables |
| SOC analyst | `SIEMHunterSecurity_CL`, ASIM tables | Read | Sentinel built-in reader role or a custom role with `read` on security tables |
| SOC analyst | `SIEMHunterHealth_CL` | Read | Same role; health table is operational not sensitive |
| SOC analyst | Raw SIEMhunter DCR source tables | No access | Sentinel RBAC table-level restriction; analysts work via `SIEMHunterSecurity_CL` and ASIM tables |

**Pull identity scope warning:** `Log Analytics Reader` at workspace scope grants read access to all tables in the workspace, including tables that may contain sensitive investigation data. The pull identity's certificate and credentials must be protected with the same rigor as the push identity. If the KQL pull feature is not enabled, do not provision this identity (per `15-adr-forwarder-credential.md` §2.3).

**Push identity cannot read.** The `Monitoring Metrics Publisher` role scoped to the DCR resource ID grants the push identity no read access to the workspace. The push identity cannot query its own ingested data. This is by design — the push identity is a one-way write pipe.

---

## 9. IaC Notes

The infrastructure resources that support this document are provisioned via Terraform or Bicep. Authoring those templates is deferred (not this task). The following constraints bind the IaC author when that work is undertaken.

| Resource | IaC requirement |
|----------|----------------|
| DCE | Provisioned as a `Microsoft.Insights/dataCollectionEndpoints` resource; URI exported as an output variable; injected into forwarder config (never hardcoded) |
| DCR (per ASIM table) | Provisioned as `Microsoft.Insights/dataCollectionRules`; resource ID exported as output variable; must match the RBAC scope in `15-adr-forwarder-credential.md` §4.1 exactly |
| Custom table schemas | `SIEMHunterHealth_CL` and `SIEMHunterSecurity_CL` provisioned via ARM/Bicep custom table resource or via DCR `outputStream`; column definitions must match §5 and §6 of this document |
| `SIEMHunterHealth_CL` retention | 30 days; set as workspace table retention override in IaC |
| `SIEMHunterSecurity_CL` retention | 90 days minimum; enforced by IaC and by an Azure Policy assignment |
| Azure Policy — retention gate | Policy definition that audits or denies workspace table retention settings below 90 days for `SIEMHunterSecurity_CL`; must be assigned at the resource group scope |
| Azure Policy — DCR stream drift | Policy definition that audits DCR stream definitions against the expected column list; prevents schema drift that would silently drop columns |
| DCE URI delivery | Docker config object (`docker config create`); not an environment variable; validated non-empty at forwarder startup |
| DCR resource ID delivery | Docker config object; validated as a well-formed ARM resource ID string at forwarder startup |

**IaC output → config → RBAC traceability requirement.** The DCR resource ID value must flow from IaC output → deployment config → RBAC scope assignment without manual transcription. A manual copy-paste of a resource ID between these three places is a misconfiguration risk. Use IaC variable references or deployment pipeline variable passing to enforce the same value end-to-end.

---

## 10. References

| Document | Relationship to this document |
|----------|------------------------------|
| `15-adr-forwarder-credential.md` | Upstream hand-off: auth design, two identity registrations, DCR resource-ID placeholder format, Docker secrets delivery, cert rotation runbook stub. This document must not redefine any credential design. |
| `04-normalization-and-schema.md` | Upstream hand-off: ASIM table mapping (§2), custom table column layouts (§7), `EventOriginalUid` as the stable dedup key (§5 canonical field table). |
| `05-detection-and-anomaly.md` | Co-authored: local-vs-Sentinel ownership table (§3.3 above); self-detection IDs SELF-001 through SELF-005. |
| `09-security-and-iam.md` | Downstream: full RBAC model, role assignment commands, certificate generation commands, complete rotation runbook, Entra Conditional Access setup, access review cadence. Extends and operationalizes this document. |
| `14-threat-model.md` | Threat context: Boundary 3 STRIDE analysis (§4); findings #1, #3, #4, #6, #12 that the controls in this document address. |
| `16-hardening-checklist.md` | Downstream: checklist items for Entra diagnostic prereq (finding #12), table RBAC verification, DCE public endpoint checklist, DCR transform clause verification, TLS verification. |
