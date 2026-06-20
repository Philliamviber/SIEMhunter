-- SIEMhunter v0.1.0 — ClickHouse database schema
--
-- Spec: instructions/04-normalization-and-schema.md §5-6
--
-- Template variable: {RETENTION_DAYS}
--   This placeholder is substituted at container startup by clickhouse/init.sh
--   using the RETENTION_DAYS environment variable (default: 30 days).
--   Setting RETENTION_DAYS=0 would create a TTL of 0 days, which causes
--   ClickHouse to delete rows immediately upon insertion. DO NOT set 0.
--   See NFR-04 and OQ-6 in instructions/02-requirements.md.
--
-- Table overview:
--   siemhunter.security_events  — primary normalized event store (all ingest paths write here)
--   siemhunter.detection_state  — stateful correlation scratch space (reserved for v0.2)
--   siemhunter.detection_hits   — detection hit ledger (detection service writes; forwarder reads)
--   siemhunter.forward_ledger   — per-batch forward counts (SELF-005 reconciliation)
--   siemhunter.rule_registry    — detection rule lifecycle state (FastAPI control plane writes)
--
-- Change protocol (see instructions/04-normalization-and-schema.md §8):
--   1. Update services/normalization/src/schema.py first.
--   2. Update rules/pipelines/clickhouse-asim-ocsf.yaml.
--   3. Run this file's ALTER TABLE / ADD COLUMN migration on the live DB.
--   4. Update Sentinel DCR column list if the field is forwarded.
--   5. Update Sigma rules that reference the old field name.
--   Steps 3-5 must not proceed until 1-2 are reviewed and merged.

CREATE DATABASE IF NOT EXISTS siemhunter;

-- ── Primary event store ──────────────────────────────────────────────────────
-- This is the central table. All four ingest paths (syslog, WEF, Netflow, forensic)
-- write normalized events here after the normalization service processes them from
-- raw_events. The detection service queries this table with compiled Sigma SQL.
--
-- Engine: MergeTree() — the standard ClickHouse table engine for analytical workloads.
-- MergeTree handles background merges of sorted data parts and TTL deletion.
--
-- Sort key: ORDER BY (TimeGenerated, HostName, EventID)
-- Rationale: almost every Sigma rule filters on EventID within a time range, and
-- many also filter on HostName (e.g., "events from a DC"). The sort key makes
-- these the fastest possible query patterns. Other columns (SubjectUserName,
-- SrcIpAddr, etc.) are not in the sort key but benefit from ClickHouse's column
-- store compression and min/max index skipping.
--
-- Partitioning: PARTITION BY toYYYYMM(TimeGenerated)
-- One partition per calendar month. TTL DELETE operates at the partition level:
-- when an entire partition is older than RETENTION_DAYS, it is dropped in a single
-- metadata operation rather than row-by-row. This is far more efficient than
-- row-level TTL for large tables.
--
-- LowCardinality(String) columns: applied to columns with a small, bounded
-- value set (hostname, channel, protocol, etc.). LowCardinality encodes values
-- as dictionary IDs, reducing storage and speeding up GROUP BY / WHERE = queries.
-- Do NOT apply LowCardinality to high-cardinality columns (CommandLine, ObjectName,
-- etc.); it would increase storage and reduce performance for those columns.
CREATE TABLE IF NOT EXISTS siemhunter.security_events
(
    -- Time and identity anchors
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
    -- These are assigned by the collector (Vector) and normalization service.
    -- They are NEVER derived from event content; a log source cannot spoof them.
    -- ProvenanceTag format: "{transport}:{source}:{collector_timestamp}" e.g. "wef:http:1704067200"
    ProvenanceTag       LowCardinality(String),
    -- IngestTimestamp: when the normalization service processed this event.
    -- This differs from TimeGenerated (the event's own timestamp) and is useful
    -- for measuring pipeline latency (TimeGenerated vs IngestTimestamp gap).
    IngestTimestamp     DateTime64(3, 'UTC'),

    -- Catch-all for unmapped fields
    -- Any raw event field not in the canonical schema above is serialised to JSON
    -- and stored here. This column is NOT indexed and NOT queryable via Sigma rules.
    -- It is available for ad-hoc forensic queries and should not be relied upon
    -- for detection logic. Use it to investigate what data was in an event that
    -- didn't fit the schema.
    UnmappedFields      String
)
ENGINE = MergeTree()
ORDER BY (TimeGenerated, HostName, EventID)
PARTITION BY toYYYYMM(TimeGenerated)
TTL TimeGenerated + INTERVAL {RETENTION_DAYS} DAY DELETE;

-- ── Stateful correlation state ───────────────────────────────────────────────
-- Scratch space for multi-event temporal correlation rules (Sigma near/sequence).
-- These rules require a Python state machine that tracks partial rule matches
-- across multiple detection batch cycles. The state machine reads from and
-- writes to this table.
--
-- No v0.1.0 rules use this table — all v0.1.0 rules are single-pass SQL.
-- The table is created now so the schema is in place for v0.2.
-- Spec: instructions/05-detection-and-anomaly.md §6
CREATE TABLE IF NOT EXISTS siemhunter.detection_state
(
    rule_id       String,
    entity_key    String,
    window_start  DateTime64(3, 'UTC'),
    event_count   UInt32,
    payload       String,
    expiry        DateTime64(3, 'UTC')
)
ENGINE = MergeTree()
ORDER BY (rule_id, entity_key, window_start)
TTL expiry DELETE;

-- ── Detection hit ledger (local) ──────────────────────────────────────────────
-- Written by the detection service (runner.py) when a Sigma rule matches events.
-- Read by the forwarder service to determine what to send to Sentinel.
--
-- Each row represents one rule firing once in one batch window. A rule that
-- matches events in three consecutive 15-minute windows produces three rows.
--
-- forwarded_at: NULL means the hit has not yet been forwarded to Sentinel.
-- The forwarder queries WHERE forwarded_at IS NULL, forwards the rows, then
-- updates forwarded_at = now64(3) for the successfully forwarded rows.
-- This is the anti-replay mechanism: once forwarded_at is set, the row is
-- not forwarded again.
--
-- hit_id: deterministic SHA-256(rule_id + sorted event_record_ids + batch_start).
-- This allows idempotent Sentinel incident creation for self-detection rules
-- (the same hit ID → same ARM incident name → idempotent PUT).
--
-- TTL: 90 days. Detection hits are kept longer than the raw events (30 days)
-- because they are the audit trail for what SIEMhunter detected and forwarded.
CREATE TABLE IF NOT EXISTS siemhunter.detection_hits
(
    hit_id          String,        -- deterministic: SHA-256(rule_id + event_record_ids + batch_start)
    rule_id         String,
    rule_version    String,
    batch_start     DateTime64(3, 'UTC'),
    batch_end       DateTime64(3, 'UTC'),
    event_record_ids String,       -- JSON array of triggering EventRecordID values
    hit_count       UInt32,
    severity        LowCardinality(String),
    mitre_tag       String,
    anomaly_score   Float32,       -- 0.0 if ML scoring not applicable
    created_at      DateTime64(3, 'UTC'),
    forwarded_at    Nullable(DateTime64(3, 'UTC'))
)
ENGINE = MergeTree()
ORDER BY (created_at, rule_id)
TTL created_at + INTERVAL 90 DAY DELETE;

-- ── Forward ledger ────────────────────────────────────────────────────────────
-- Append-only ledger of forwarding activity, one row per batch per stream.
-- Written by the forwarder service after each successful forward cycle.
--
-- Purpose: SELF-005 (LedgerReconciliationDelta) compares the local event_count
-- with the count of events received by Sentinel (queried via KQL). A significant
-- discrepancy indicates data loss or a forwarding failure.
--
-- stream_tag: the Sentinel custom table name (e.g., "SIEMHunterSecurity_CL").
-- event_count: the number of detection hits forwarded to that stream in this batch.
-- TTL: 30 days (shorter than detection_hits since this is aggregate, not per-event).
CREATE TABLE IF NOT EXISTS siemhunter.forward_ledger
(
    batch_id        String,
    stream_tag      LowCardinality(String),
    event_count     UInt64,
    batch_start     DateTime64(3, 'UTC'),
    batch_end       DateTime64(3, 'UTC'),
    forwarded_at    DateTime64(3, 'UTC')
)
ENGINE = MergeTree()
ORDER BY (forwarded_at, stream_tag)
TTL forwarded_at + INTERVAL 30 DAY DELETE;

-- ── Rule state registry ───────────────────────────────────────────────────────
-- Tracks the lifecycle status of each Sigma detection rule.
-- Written by the FastAPI control plane (PUT /v1/rules/{rule_id}/status).
-- Read by the detection service to determine which rules to execute.
--
-- IMPORTANT: The FastAPI endpoint writes the Sentinel audit record BEFORE
-- writing to this table (fail-closed). If Sentinel is unreachable, the
-- status change is rejected and this table is NOT updated. See the rule
-- lifecycle endpoint in services/api/src/routers/rules.py.
--
-- Engine: ReplacingMergeTree(updated_at)
-- Each status change is an INSERT of a new row. ReplacingMergeTree deduplicates
-- rows with the same ORDER BY key (rule_id), keeping the row with the highest
-- updated_at value after a background merge. This gives us a simple "upsert"
-- pattern without requiring a true UPDATE statement.
-- Queries must use FINAL to see the merged (latest) state rather than waiting
-- for background merges: SELECT ... FROM rule_registry FINAL WHERE rule_id = '...'
--
-- status values: draft, test, review, production, disabled
-- updated_by: the identity that made the change (e.g., "API/bearer").
CREATE TABLE IF NOT EXISTS siemhunter.rule_registry
(
    rule_id         String,
    rule_version    String,
    -- Valid values: draft | test | review | production | disabled
    -- The detection service skips draft and disabled rules.
    -- Rules in test/review/production are compiled and executed.
    status          LowCardinality(String),
    file_path       String,                   -- path to the Sigma YAML on disk
    updated_at      DateTime64(3, 'UTC'),      -- ReplacingMergeTree merge key: keep latest
    updated_by      String                    -- actor (e.g., "API/bearer")
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (rule_id);
