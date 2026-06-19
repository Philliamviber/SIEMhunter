# SIEMhunter — Normalization and Schema

**Document:** 04-normalization-and-schema.md
**Version:** 0.1.0-draft
**Date:** 2026-06-18
**Status:** Gate document — `05-detection-and-anomaly` and `rules/pipelines/clickhouse-asim-ocsf.yaml` may not begin until this document is finalized and cross-referenced.
**Owner:** implementer
**Audience:** detection-engineer (Step 9), implementer (normalization layer), cloud-security-engineer (DCR/table design), docs-maintainer (cross-ref sweep)

---

## 1. Normalization Strategy

SIEMhunter uses a deliberate three-layer normalization model. Each layer has a distinct role and a distinct audience. They must not be conflated or collapsed.

### Layer 1 — OCSF (Canonical Internal Schema)

The Open Cybersecurity Schema Framework (OCSF) is the internal representation that every ingest path produces and that every detection rule reads. It is vendor-neutral, covers all source types present in v0.1.0 (network, endpoint, identity, system activity), and is owned by SIEMhunter rather than by any cloud vendor.

Every event — regardless of whether it arrived as syslog, a Windows Event Log, a netflow record, or a forensic JSON artifact — must be normalized to OCSF before it is written to ClickHouse. The Sigma rules compiled by the pySigma pipeline query the OCSF-aligned ClickHouse columns exclusively. This means the detection layer is fully decoupled from the particularities of each upstream source. When a new source type is added in a later version, only the ingest-to-OCSF mapping needs to be written; the rules are untouched.

Why OCSF for the internal layer:

- It covers the event classes relevant to SIEMhunter v0.1.0: authentication, network activity, DNS, process activity, file activity, registry activity, account change, and scheduled job activity.
- It provides a stable schema that Sigma rules can compile against without needing per-source rule variants.
- It decouples the ingestion work (Vector, parsing, provenance tagging) from the Sentinel-specific output format.
- It keeps the detection engine portable: if the Sentinel destination were replaced in a later version, the rules would not need to be rewritten.

### Layer 2 — ASIM (Sentinel-Destination Schema)

The Advanced Security Information Model (ASIM) is Microsoft Sentinel's normalized schema. It defines the standard table names and field names that Sentinel analytics rules, hunting queries, and built-in workbooks expect. ASIM is applied at forward time, not at storage time.

Why ASIM at the Sentinel destination:

- Sentinel built-in analytics rules and hunting queries reference ASIM table names (`ASimAuthentication`, `ASimNetworkSession`, etc.) and ASIM field names (`ActorUsername`, `SrcIpAddr`, etc.). Events that do not conform to these names are invisible to those queries.
- The two SIEMhunter internal custom tables (`SIEMHunterHealth_CL` and `SIEMHunterSecurity_CL`) use ASIM field naming conventions for the fields they share with ASIM (for example, `TimeGenerated`, `DvcHostname`) so that cross-table KQL queries compose naturally.
- The Data Collection Rule (DCR) transform enforces the ASIM schema server-side before data lands in the Log Analytics workspace. Any field not declared in the DCR column list is dropped silently. This makes the DCR the enforcement point, not optional client-side logic.

### Layer 3 — Per-Event-Class ASIM ↔ OCSF Mapping

There is no universal one-to-one translation between OCSF and ASIM that works across all event types. The mapping is per-event-class. An OCSF Authentication event maps to the `ASimAuthentication` table with its specific field set; an OCSF Network Activity event maps to `ASimNetworkSession` with a different field set. The normalization layer must apply the correct per-class mapping at forward time.

The authoritative expression of this mapping is the canonical field table in §5 of this document and the pySigma pipeline file at `rules/pipelines/clickhouse-asim-ocsf.yaml`. Any change to a field name must be reflected in both locations simultaneously. The pipeline file is the build-time contract; this document is the human-readable specification.

---

## 2. ASIM Table Mapping (Per Event Class)

| OCSF Event Class | OCSF Class ID | ASIM Table | Notes |
|-----------------|--------------|-----------|-------|
| Authentication | 3002 | ASimAuthentication | Login/logoff, Kerberos (EID 4768/4769), NTLM (EID 4624/4625) |
| Network Activity | 4001 | ASimNetworkSession | Syslog network events, netflow/IPFIX records |
| DNS Activity | 4003 | ASimDns | DNS query logs |
| Process Activity | 1007 | ASimProcessEvent | Sysmon process create (EID 1) and terminate (EID 5) |
| File Activity | 1001 | ASimFileEvent | Sysmon file create (EID 11) and delete |
| Registry Key Activity | 201001 | ASimRegistryEvent | Sysmon registry events (EID 12, 13, 14) |
| Account Change | 3001 | ASimUserManagement | AD account events (EID 4720, 4722, 4728, 4732, 4756, etc.) |
| Scheduled Job Activity | 5003 | ASimScheduledTask | Scheduled task creation |
| Health/Ops (SIEMhunter internal) | N/A | SIEMHunterHealth_CL | SIEMhunter operational events; not an OCSF class |
| Security (SIEMhunter internal) | N/A | SIEMHunterSecurity_CL | SIEMhunter self-detection events and rule-change audit; not an OCSF class |

The two internal tables (`*_CL`) have no OCSF class ID because they are not normalized from telemetry sources. They are generated by the SIEMhunter pipeline itself (the health table from operational instrumentation; the security table from detection hits and the rule-change audit path described in FR-14). See §7 for their column layouts.

---

## 3. EventID Type Handling

**EventID is stored as `UInt32` in ClickHouse.** This is a fixed constraint, not a preference. The rationale and consequences are documented here because mixed types are the most common source of silent zero-result Sigma rules in ClickHouse deployments.

- Windows Event Log sources emit `EventID` as an unsigned integer. RFC 3164/5424 syslog sources may emit an equivalent field as a string. Netflow records do not use EventID.
- The normalization layer must coerce every EventID value to `UInt32` before the event is inserted into ClickHouse. If the source value cannot be parsed as an unsigned integer (for example, it is an empty string or a non-numeric value), the normalization layer must assign `0` and log a parse warning.
- A Sigma rule that specifies `EventID: 4769` compiles via pySigma to `WHERE EventID = 4769` — an integer comparison. If the column were `String`, this comparison would either fail to compile or produce zero results silently.
- The pySigma pipeline file at `rules/pipelines/clickhouse-asim-ocsf.yaml` must declare `EventID` with type `UInt32`. Any type annotation of `String` or `Int32` in that file is an error.
- There is no mechanism for mixed types in a single ClickHouse column. Do not allow a migration or schema patch to change `EventID` to `String` under any circumstances. A schema change of that kind would invalidate every compiled rule.

---

## 4. Array and Nested Field Policy

ClickHouse supports nested structures and `Array(T)` columns, but their query semantics differ from flat columns in ways that complicate pySigma rule compilation. The following constraints apply for v0.1.0.

**No nested maps.** ClickHouse `Map` columns and `Nested` types are not used in the `security_events` table in v0.1.0. Every OCSF field that would naturally be expressed as a nested object is flattened to a top-level column with a CamelCase name encoding the path. For example, the OCSF path `process.parent_process.file.path` becomes the column `ParentProcessImagePath`. The flattening rules are defined in the canonical field table in §5.

**Array columns for multi-value fields.** Fields that are genuinely multi-valued in the source — for example, the list of hash values attached to a Sysmon file event — are stored as separate typed columns rather than as an array where possible (see `FileMD5` and `FileSHA256` in §5). Where an array is unavoidable (for example, a process command-line split into tokens by the source), the column type is `Array(String)` and Sigma rules against that field must use the `hasToken()` function, not a substring match. The pySigma pipeline must emit `hasToken(column, value)` for any field declared as `Array(String)`.

**Catch-all column for unmapped fields.** Every event will carry source fields that have no OCSF counterpart and therefore no column in `security_events`. These fields are JSON-serialized as a single string and stored in the `UnmappedFields` column of type `String`. This column is never referenced in Sigma rules. Its sole purpose is to preserve the original event for forensic review without polluting the schema. It is not indexed, and it does not participate in ClickHouse sort or partition keys.

**Provenance fields are always flat.** The `ProvenanceTag` and `IngestTimestamp` columns are assigned by the collector and normalization layer respectively. They are never sourced from the event content and are never nullable.

---

## 5. Canonical Field Table

This table is the hand-off contract to the detection-engineer and the definitive input to `rules/pipelines/clickhouse-asim-ocsf.yaml`. Every Sigma rule field reference must appear in column 1 of this table. A field absent from this table does not exist in ClickHouse; pySigma will emit a warning and produce SQL that queries a non-existent column, returning zero results silently.

Additions to this table require a coordinated change to: (1) the pySigma pipeline file, (2) the ClickHouse `security_events` table schema, (3) the Sentinel custom table DCR column list, and (4) the Sigma rule if the field was previously treated as unmapped. This coordination order is mandatory per NFR-10.

| Sigma Field Name | OCSF Path | ClickHouse Column | ClickHouse Type | ASIM Field Name | Notes |
|-----------------|-----------|-------------------|----------------|----------------|-------|
| EventID | base_event.id | EventID | UInt32 | EventID | Integer; coerce at ingest; see §3 |
| EventRecordID | base_event.uid | EventRecordID | String | EventOriginalUid | Stable dedup key per FR-18 |
| Computer | device.hostname | HostName | LowCardinality(String) | DvcHostname | Collector-assigned provenance; not overridable by event content |
| SubjectUserName | actor.user.name | SubjectUserName | String | ActorUsername | |
| SubjectUserSid | actor.user.uid | SubjectUserSid | String | ActorUserId | |
| SubjectDomainName | actor.user.domain | SubjectDomainName | LowCardinality(String) | ActorUserDomain | |
| TargetUserName | target.user.name | TargetUserName | String | TargetUsername | |
| TargetUserSid | target.user.uid | TargetUserSid | String | TargetUserId | |
| TargetDomainName | target.user.domain | TargetDomainName | LowCardinality(String) | TargetUserDomain | |
| ServiceName | service.name | ServiceName | String | NetworkApplicationProtocol | Meaning is context-dependent; authentication context: service being authenticated to; network context: application protocol |
| Image | process.file.path | ProcessImagePath | String | ActingProcessName | Full executable path |
| CommandLine | process.cmd_line | CommandLine | String | ActingProcessCommandLine | Full command line as a single string |
| ParentImage | process.parent_process.file.path | ParentProcessImagePath | String | ParentProcessName | |
| ParentCommandLine | process.parent_process.cmd_line | ParentCommandLine | String | ParentProcessCommandLine | |
| GrantedAccess | process.granted_access | GrantedAccess | String | — | Sysmon EID 10 (process access) only; no ASIM equivalent |
| TargetObject | reg_key.path | RegistryKey | String | RegistryKey | Registry events (ASimRegistryEvent) only |
| ObjectName | file.path | ObjectName | String | FilePath | File and object auditing |
| LogonType | authentication.logon_type | LogonType | UInt8 | LogonMethod | Windows logon type integer (2=interactive, 3=network, etc.) |
| IpAddress | src_endpoint.ip | SrcIpAddr | String | SrcIpAddr | Source IP as a string; use isIPAddressInRange() for CIDR matching |
| IpPort | src_endpoint.port | SrcPort | UInt16 | SrcPortNumber | |
| DestAddress | dst_endpoint.ip | DstIpAddr | String | DstIpAddr | |
| DestPort | dst_endpoint.port | DstPort | UInt16 | DstPortNumber | |
| Protocol | network.protocol_name | NetworkProtocol | LowCardinality(String) | NetworkProtocol | Lowercase string: tcp, udp, icmp |
| TimeCreated | metadata.logged_time | TimeGenerated | DateTime64(3,'UTC') | TimeGenerated | UTC; millisecond precision; partition and sort key anchor |
| Channel | log.name | ChannelName | LowCardinality(String) | — | Windows Event Channel (e.g., Security, Sysmon); no ASIM equivalent |
| Provider | metadata.product.name | ProviderName | LowCardinality(String) | EventProduct | Source product name (e.g., Microsoft-Windows-Security-Auditing) |
| Hashes.MD5 | file.hashes[0].value | FileMD5 | FixedString(32) | — | Sysmon file hash; lowercase hex; no ASIM equivalent |
| Hashes.SHA256 | file.hashes[1].value | FileSHA256 | FixedString(64) | — | Lowercase hex; no ASIM equivalent |
| ProvenanceTag | — | ProvenanceTag | LowCardinality(String) | — | Assigned by collector; never sourced from event content; identifies ingest path and transport |
| IngestTimestamp | — | IngestTimestamp | DateTime64(3,'UTC') | — | Time SIEMhunter received the event; assigned by normalization layer; never from event content |

**Key for the ASIM column:** A dash (—) means this field is stored in ClickHouse for local detection but has no direct ASIM mapping and is therefore not forwarded to Sentinel ASIM tables. It may appear in `UnmappedFields` on the Sentinel side if the operator wants to preserve it.

**Key for ClickHouse Type:** `LowCardinality(String)` should be used for all string columns whose value set is bounded and small (fewer than approximately 10,000 distinct values in practice). It enables dictionary encoding and significantly reduces storage. Do not apply it to free-text fields such as `CommandLine` or `ObjectName`.

---

## 6. ClickHouse Table Design

The primary event storage table for all normalized security events is `security_events`.

```sql
CREATE TABLE security_events
(
    -- Time and identity anchors (sort key + partition)
    TimeGenerated       DateTime64(3, 'UTC'),
    HostName            LowCardinality(String),
    EventID             UInt32,

    -- Event metadata
    EventRecordID       String,
    ChannelName         LowCardinality(String),
    ProviderName        LowCardinality(String),

    -- Actor (subject)
    SubjectUserName     String,
    SubjectUserSid      String,
    SubjectDomainName   LowCardinality(String),

    -- Target (user)
    TargetUserName      String,
    TargetUserSid       String,
    TargetDomainName    LowCardinality(String),

    -- Authentication
    LogonType           UInt8,
    ServiceName         String,

    -- Process
    ProcessImagePath    String,
    CommandLine         String,
    ParentProcessImagePath String,
    ParentCommandLine   String,
    GrantedAccess       String,

    -- File
    ObjectName          String,
    FileMD5             FixedString(32),
    FileSHA256          FixedString(64),

    -- Registry
    RegistryKey         String,

    -- Network
    SrcIpAddr           String,
    SrcPort             UInt16,
    DstIpAddr           String,
    DstPort             UInt16,
    NetworkProtocol     LowCardinality(String),

    -- SIEMhunter pipeline fields
    ProvenanceTag       LowCardinality(String),
    IngestTimestamp     DateTime64(3, 'UTC'),

    -- Catch-all for unmapped OCSF fields
    UnmappedFields      String
)
ENGINE = MergeTree()
ORDER BY (TimeGenerated, HostName, EventID)
PARTITION BY toYYYYMM(TimeGenerated)
TTL TimeGenerated + INTERVAL {RETENTION_DAYS} DAY DELETE;
```

**Key design notes:**

**Sort key ordering.** The sort key is `(TimeGenerated, HostName, EventID)`. Time comes first because all detection queries include a time-range predicate matching the batch window. HostName comes second because it is the most common secondary filter in detection rules (restricting a rule to specific hosts or host groups). EventID comes third because single-event-class rules (for example, all EID 4769 rows) benefit from the granularity without adding sort overhead for queries that do not filter on EventID.

**Partition by month.** Monthly partitions allow the TTL-based DELETE to drop entire partitions at expiry rather than merging and rewriting large chunks of data. For lab-scale volumes this is sufficient; finer partitioning (by day) is unnecessary and increases the number of parts ClickHouse must manage.

**TTL placeholder.** `{RETENTION_DAYS}` is a configuration placeholder that must be substituted at table creation time from the operator's configuration. There is no default value mandated by this document; see NFR-04 and the open question in `02-requirements.md` (OQ-6). The value must be a positive integer. A value of `0` is not valid; the operator must explicitly choose a retention period.

**No foreign keys or constraints.** ClickHouse does not enforce referential integrity. Data integrity is the responsibility of the normalization layer. If the normalization layer produces a row with a null or empty `TimeGenerated`, ClickHouse will store it and it will be invisible to time-range queries. The normalization layer must validate and reject such rows before insert rather than relying on the database to detect them.

**LowCardinality usage.** All columns declared `LowCardinality(String)` in the canonical field table (§5) must also be declared `LowCardinality(String)` in the table DDL. The two must be kept in sync. If a column's cardinality grows beyond the `LowCardinality` threshold in practice (approximately 10,000 distinct values), the type should be migrated to plain `String` in a schema migration; do not leave a high-cardinality column declared as `LowCardinality` because this degrades compression rather than improving it.

**UnmappedFields.** This column stores a JSON-serialized string of all source fields that could not be mapped to any OCSF path. It is not part of any sort key, index, or TTL expression. It must not be queried in any Sigma rule. Its sole use is forensic: an analyst can retrieve the raw unmapped content from ClickHouse directly if needed.

---

## 7. DCR and Custom Table Layout

The two SIEMhunter internal tables in the Sentinel workspace have fixed schemas. These schemas are distinct from the ASIM normalized tables (`ASimAuthentication`, etc.) and are not managed by pySigma. They are created by the operator as custom tables in the Log Analytics workspace using the DCR/DCE ingestion path. The schemas below are the source of truth for the DCR column list; any mismatch between this document and the DCR will cause ingestion to drop columns silently.

### SIEMHunterHealth_CL

Purpose: operational telemetry from the SIEMhunter pipeline itself. This table is written every batch cycle and continuously by the ingest-flood heuristic. It is not a security table; it is a plumbing-health table.

| Column | Type | Description |
|--------|------|-------------|
| TimeGenerated | datetime | UTC timestamp of the operational event; required by Log Analytics |
| HostName | string | Hostname of the SIEMhunter instance (maps to DvcHostname convention) |
| EventType | string | Category of operational event (e.g., IngestCycleComplete, ParseError, ForwarderFailure, FloodHeuristic) |
| Message | string | Human-readable description of the event |
| Severity | string | Informational, Warning, or Error |
| Count | int | Numeric value relevant to the event (for example, events processed in a cycle, events dropped due to rate limit, error count) |

Suggested retention: 7 to 30 days. This table generates high volume (one or more rows per batch cycle plus continuous flood-heuristic rows) and has low forensic value beyond recent operational context.

### SIEMHunterSecurity_CL

Purpose: security-relevant events generated by the SIEMhunter pipeline. This table receives detection hits (from Sigma rules and self-detections), rule-change audit entries (required by FR-14), and self-detection results. This is the table that Sentinel analytics rules and the rule-disable self-detection read from.

| Column | Type | Description |
|--------|------|-------------|
| TimeGenerated | datetime | UTC timestamp; required by Log Analytics |
| RuleId | string | Stable identifier of the Sigma rule or self-detection that fired |
| RuleVersion | string | Semantic version of the rule at the time of the hit |
| EventType | string | DetectionHit, RuleChangeAudit, SelfDetection, or LedgerDelta |
| SourceEventIds | dynamic | Array of `EventRecordID` values from the source events that triggered the hit; enables analyst navigation from incident to evidence |
| Entity | string | Primary entity involved (for example, a username, hostname, or IP address) |
| Detail | string | Rule-specific detail string; free text for analyst context |
| Severity | string | Informational, Low, Medium, High, or Critical |

Suggested retention: 90 days or longer. This table is the audit trail for rule changes (FR-14) and the evidence base for Sentinel incidents. The rule-disable self-detection (FR-09, self-detection 3) reads this table via the optional KQL pull path to detect gaps in the audit chain.

**Independence requirement (FR-19).** A failure to write to `SIEMHunterHealth_CL` must not block writes to `SIEMHunterSecurity_CL` and vice versa. The forwarder must maintain independent write paths for the two tables with independent retry queues.

---

## 8. pySigma Pipeline Reference

The file `rules/pipelines/clickhouse-asim-ocsf.yaml` is the authoritative build-time schema contract between this normalization specification and the detection rules. It is authored by the detection-engineer (Step 9 in the orchestration plan) using this document as its sole input. No Sigma rule may be written before this pipeline file exists and compiles cleanly.

**What the pipeline file contains:**

- A `field_mappings` section that maps every Sigma field name (column 1 of §5) to the corresponding ClickHouse column name (column 3 of §5).
- Type annotations for each mapped column matching the ClickHouse types declared in column 4 of §5.
- The `EventID` field annotated as `UInt32` (see §3 for the rationale; this annotation must not be overridden).
- Any field-transform rules needed for array columns (see §4).

**What the pipeline file does not contain:**

- Any field not listed in §5. Adding a field to the pipeline without first adding it to this document and to the ClickHouse DDL will produce SQL against a non-existent column. pySigma does not validate column existence; it will compile the SQL successfully, but the query will return zero rows.

**Silent zero-result risk.** pySigma emits a warning when a Sigma rule references a field that is not in the pipeline's `fieldmappings` section, but it still emits compilable SQL. The SQL will contain a reference to the unmapped field name as-is, which ClickHouse will reject at query time with a column-not-found error — or, in some pySigma backends, the field will be omitted entirely, causing the rule to match everything. The detection-engineer must treat any pipeline compilation warning as a blocking error.

**CI gate.** Every Sigma rule in the repository must compile successfully against `rules/pipelines/clickhouse-asim-ocsf.yaml` as a required CI step. A rule that produces a compilation warning must not be promoted to production status (see NFR-10). This gate is the enforcement mechanism for the canonical field table.

**Change protocol.** If a ClickHouse column is renamed or a new field is added:

1. Update this document (§5 and §6 DDL) first.
2. Update `rules/pipelines/clickhouse-asim-ocsf.yaml`.
3. Apply a ClickHouse schema migration (ADD COLUMN or rename via a migration script).
4. Update the Sentinel DCR column list if the field is forwarded.
5. Update any Sigma rules that reference the old name.

Steps 3 through 5 may not proceed until steps 1 and 2 are complete and reviewed.

---

## 9. Known pySigma → ClickHouse Translation Limits

The following Sigma constructs either have no direct ClickHouse equivalent or require special handling in the pipeline. The detection-engineer must be aware of these limits before authoring rules. Rules that rely on unsupported constructs will either fail to compile or produce incorrect results.

**`base64offset|contains`** — ClickHouse has no native base64 decode function. Rules that need to detect base64-encoded payloads must use Python pre-processing to decode the field value before inserting it into ClickHouse. The decoded value can be stored in a separate column (not defined in v0.1.0 canonical table; add it if needed). Do not write a Sigma rule with `base64offset|contains` expecting it to work against the raw stored string.

**Regex lookaheads** — ClickHouse uses the RE2 regular expression engine, which does not support lookahead or lookbehind assertions. Any Sigma rule using a `re|` modifier with a lookahead pattern will compile but will produce a ClickHouse error at query time. Rewrite such patterns as multiple positive conditions combined with `AND`.

**`cidr` modifier** — pySigma compiles `IpAddress|cidr: 10.0.0.0/8` to a ClickHouse `isIPAddressInRange(SrcIpAddr, '10.0.0.0/8')` call. This is supported and is the correct approach. Do not attempt to rewrite CIDR matching as a string prefix match; it will produce incorrect results for non-contiguous subnets.

**`contains|all` on array columns** — For columns declared as `Array(String)` (see §4), the pySigma pipeline must emit `hasToken(column, value)` rather than a substring `LIKE` match. `hasToken()` performs token-based matching, not substring matching. A token is a word boundary-delimited string. This distinction matters for short values that appear as substrings of longer tokens. If exact substring matching is required on an array column, this must be implemented as a Python post-filter step, not in the compiled SQL.

**`near` and `sequence`** — Sigma `near` and `sequence` constructs express temporal correlation between multiple events. ClickHouse SQL has no direct equivalent for event sequencing. These constructs require a Python state machine that reads from a `detection_state` table (not defined in v0.1.0) and correlates events across batch windows. Any rule requiring `near` or `sequence` must be deferred to a later version or reimplemented as a Python-layer correlation outside the pySigma compilation path.

**`timespan`** — Sigma `timespan` specifies a time window within which correlated events must occur. In the batch detection model, the batch window is the outer time boundary, but a Sigma `timespan` of (for example) 60 seconds within a 30-minute batch is not expressible as a single SQL query without a sub-aggregation. Rules using `timespan` must be re-expressed as SQL sub-aggregations with an explicit time-window predicate in the compiled SQL. The pySigma pipeline should document the expected SQL pattern for the detection-engineer.

**Integer vs. string comparisons on EventID** — As documented in §3, `EventID` is `UInt32`. A Sigma rule that quotes the value (`EventID: '4769'`) may cause pySigma to emit a string literal in the SQL. The pipeline must configure pySigma to treat `EventID` comparisons as integer literals. Verify this behavior explicitly when the pipeline file is authored.

---

## 10. Cross-References

- `01-architecture-overview.md` §2 (component table), §3 (data flow), §4 (trust boundaries) — architecture context for the three-layer model.
- `02-requirements.md` FR-06 (normalization mandate), FR-07 (Sigma/SQL compilation), NFR-10 (change protocol), FR-14 (rule-change audit), FR-18 (stable event IDs), FR-19 (two custom tables), OQ-6 (retention default).
- `03-data-ingestion-spec.md` — provenance tag assignment, decompression cap, per-source parsing details that feed the normalization layer.
- `05-detection-and-anomaly.md` — consumes §5 canonical field table; must not be started until this document is finalized.
- `07-sentinel-forwarding.md` — consumes §2 (ASIM table mapping) and §7 (custom table layouts) for DCR/DCE configuration.
- `12-data-retention-and-lifecycle.md` — consumes §6 (TTL placeholder, partition strategy).
- `rules/pipelines/clickhouse-asim-ocsf.yaml` — is the machine-readable expression of §5; must be authored from this document and reviewed against it.
