-- SIEMhunter v0.1.0 — ClickHouse schema
-- Spec: instructions/04-normalization-and-schema.md §5-6
-- {RETENTION_DAYS} is substituted by init.sh from the RETENTION_DAYS env var.
-- DO NOT set a value of 0 — see NFR-04 and OQ-6 in 02-requirements.md.

CREATE DATABASE IF NOT EXISTS siemhunter;

-- ── Primary event store ──────────────────────────────────────────────────────
-- All ingest paths write here after OCSF normalization.
-- Sort key: (TimeGenerated, HostName, EventID)
-- Rationale: time is the primary detection filter; HostName is the most common
-- secondary filter; EventID is the tertiary for single-class rules.
-- Partition by month enables efficient TTL DROP of entire partitions at expiry.
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

    -- SIEMhunter pipeline fields (collector-assigned; never overridable by event content)
    ProvenanceTag       LowCardinality(String),
    IngestTimestamp     DateTime64(3, 'UTC'),

    -- Catch-all for unmapped OCSF fields (not queryable in Sigma; forensic only)
    UnmappedFields      String
)
ENGINE = MergeTree()
ORDER BY (TimeGenerated, HostName, EventID)
PARTITION BY toYYYYMM(TimeGenerated)
TTL TimeGenerated + INTERVAL {RETENTION_DAYS} DAY DELETE;

-- ── Stateful correlation state ───────────────────────────────────────────────
-- Used by the Python correlation engine for multi-event temporal rules.
-- No v0.1.0 rules use this; table exists so the schema is in place for v0.2.
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
-- Tracks detection hits before they are forwarded to Sentinel.
-- Forwarder reads from this table. Anti-replay: forwarded_at IS NOT NULL rows
-- are already in Sentinel.
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
-- Tracks event counts forwarded per batch cycle for SELF-005 reconciliation.
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
-- Tracks per-rule status (draft/test/review/production).
-- The FastAPI control plane writes here (after writing to Sentinel first — fail-closed).
CREATE TABLE IF NOT EXISTS siemhunter.rule_registry
(
    rule_id         String,
    rule_version    String,
    status          LowCardinality(String),   -- draft, test, review, production
    file_path       String,
    updated_at      DateTime64(3, 'UTC'),
    updated_by      String
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (rule_id);
