# SIEMhunter — Data Retention and Lifecycle

**Document:** 12-data-retention-and-lifecycle.md
**Version:** 0.1.0-draft
**Date:** 2026-06-19
**Status:** Authoritative for v0.1.0
**Owner:** implementer
**Audience:** implementer, cloud-security-engineer, ops

---

## 1. Retention Philosophy

SIEMhunter uses a two-tier retention model. Each tier has a distinct purpose, and they must not be treated as interchangeable.

### Tier 1 — ClickHouse (local hot store)

ClickHouse is a **best-effort local buffer**, not a durable archive and not a source of truth.

Its purpose is narrow and specific:

- **Batch detection window.** Sigma-as-SQL rules need a local query surface covering at least one correlation window (typically minutes to hours). ClickHouse provides that surface without a round-trip to Sentinel on every detection run.
- **Replay buffer.** If Sentinel forwarding is temporarily unavailable (network partition, 429 rate-limit, service disruption), unforwarded events remain locally available for retry up to the local retention period for their source type.

ClickHouse local data must be considered **lossy by design**:

- It is **not WORM** (Write Once Read Many). There is no immutability guarantee, no append-only enforcement at the storage level, and no cryptographic seal on stored rows.
- It is **not a durable archive**. TTL-based deletion runs as a background process. Partition drops are irrecoverable.
- The **tamper-evidence anchor is Sentinel**, not ClickHouse. If a local row is modified or deleted before forwarding, there is no local record of that fact. The forwarding ledger (see `07-sentinel-forwarding.md`) is the control that detects divergence between what was ingested and what reached Sentinel.

Acceptable local retention windows are **days to weeks**, driven by the source volume and the correlation window requirement, not by compliance or forensic preservation goals.

### Tier 2 — Microsoft Sentinel (cloud SIEM of record)

Sentinel is the **authoritative store** for all security events and self-detection hits forwarded by SIEMhunter.

- All events forwarded by SIEMhunter are confirmed via the Logs Ingestion API response. The forwarding ledger records the Sentinel-assigned identifier.
- Sentinel provides the investigation surface, alert triage, case management, and long-term retention. SIEMhunter has no analyst console of its own.
- Retention in Sentinel is **90 days to multiple years**, depending on workspace configuration and table-level overrides. The workspace owner controls this in Azure — it is not a SIEMhunter setting.
- Events in Sentinel are the **only copy that can be relied upon for incident response, compliance, or audit purposes**.

---

## 2. Per-Source Local Retention Tiers (ClickHouse)

All values below are `{RETENTION_DAYS}` configuration parameters. They are never hardcoded. Each source type has its own named variable (e.g. `SYSLOG_RETENTION_DAYS`, `WINEVENT_RETENTION_DAYS`) set in the deployment configuration file.

| Source | Default local retention | Rationale |
|--------|------------------------|-----------|
| Syslog (high volume) | 7 days | High volume; Sentinel is primary after forwarding succeeds |
| Windows Event Logs (DC security) | 14 days | Medium volume; key for batch correlation across multiple events |
| Sysmon | 14 days | Medium volume; process/file/network chains need multi-event window |
| Netflow / IPFIX | 7 days | High volume; connection metadata only; lateral movement detection window |
| Forensic artifacts | 30 days | Low volume; raw artifacts may need local re-analysis before next cycle |
| Azure log pull (KQL results) | 3 days | Enrichment only; authoritative copy already lives in Sentinel |
| SIEMhunter internal (health / security) | 7 days | Mirrored to Sentinel; local copy is a convenience cache, not the record |

**Important:** the local retention window is also the **maximum replay window**. If Sentinel is unavailable for longer than the configured retention period for a source, events from that source will be purged locally before they can be forwarded. Those events are permanently lost. See Section 5.

---

## 3. ClickHouse TTL and Partition Management

### TTL configuration

The `security_events` table uses a table-level TTL that drives background deletion:

```sql
TTL TimeGenerated + INTERVAL {RETENTION_DAYS} DAY DELETE
```

Because different source types have different retention periods, each source type is stored in a separate table (or the TTL is set at the partition level for source-segregated partitions). Do not use a single global `{RETENTION_DAYS}` value across sources with different windows; use per-source table variables.

### Partitioning

The table is partitioned by `toYYYYMM(TimeGenerated)`. Monthly partitions serve two purposes:

- They enable efficient bulk purge via `DROP PARTITION` without expensive per-row mutations.
- They make the storage footprint auditable at a glance (each month is a discrete directory on disk).

### Background merges vs. manual OPTIMIZE

ClickHouse TTL deletion runs during background merge operations. **Do not run `OPTIMIZE TABLE security_events FINAL` automatically on a schedule.** On any table of meaningful size, `OPTIMIZE TABLE ... FINAL` forces a full merge of all parts — this is expensive in I/O and CPU and will degrade detection query performance during the merge. Rely on background merges to apply TTL deletions. The only acceptable use of `OPTIMIZE TABLE ... FINAL` is a deliberate, one-off operator action during a maintenance window when no detection runs are scheduled.

### Scheduled partition purge

Expired monthly partitions should be dropped by a scheduled maintenance task (not ad hoc):

```sql
ALTER TABLE security_events DROP PARTITION {YYYYMM};
```

The maintenance task must:

1. Identify partitions whose month-end date is older than the configured retention window for that source.
2. Confirm (via the forwarding ledger) whether all events in that partition were forwarded to Sentinel before dropping. If not, log a `PurgeBeforeForward` event (see Section 6).
3. Execute the `DROP PARTITION` statement.
4. Log the purge event to `SIEMHunterHealth_CL`.

### No per-row deletes

ClickHouse is append-only by design. Per-row `DELETE` mutations (`ALTER TABLE ... DELETE WHERE ...`) are expensive, block background merges, and are not appropriate for routine lifecycle management. Use TTL and partition drops exclusively for data removal.

---

## 4. Sentinel Retention

Sentinel retention is configured in the Azure Log Analytics workspace settings, not in SIEMhunter configuration. The values below are recommendations; the workspace owner must apply them in the Azure portal or via ARM/Bicep.

| Table | Recommended retention | Reason |
|-------|-----------------------|--------|
| `SIEMHunterHealth_CL` | 30 days | Operational noise; short-lived diagnostic relevance |
| `SIEMHunterSecurity_CL` | 90 days minimum | Feeds analytics rules; security dwell time baseline |
| `ASimAuthentication` | 90 days (workspace default) | Authentication events; dwell time and lateral movement |
| `ASimNetworkSession` | 90 days (workspace default) | Network flow data; C2 and exfil detection |
| Other ASIM tables | 90 days (workspace default) | Consistent with security event retention baseline |

**Extended retention** (beyond 90 days, up to 2 years) is available in Log Analytics at additional cost. For compliance or long-term hunting requirements, enable extended retention on `SIEMHunterSecurity_CL` and the relevant ASIM tables in the workspace settings. This is a workspace-owner decision; SIEMhunter has no control over it.

Sentinel is the only tier where retention settings carry compliance weight. ClickHouse local retention is never a substitute for Sentinel retention configuration.

---

## 5. Forwarding and Replay

### Normal operation

In normal operation, events are forwarded to Sentinel within one batch cycle (15–60 minutes) after ingest. The forwarding ledger records the batch ID, source, event count, and Sentinel API response for every batch. Reconciliation queries (see `07-sentinel-forwarding.md`) compare ledger entries against Sentinel to confirm delivery.

### Forward failure handling

When the Logs Ingestion API returns a retryable error (HTTP 429, 503, or network timeout):

- The failed batch is written to a local **retry queue** (append-only file on the local filesystem).
- The retry queue is consumed with exponential backoff (initial delay 30 seconds, doubling up to a configured maximum interval).
- The **maximum retry window equals the local retention period for that source**. If a batch has been in the retry queue longer than the source's `{RETENTION_DAYS}` and the partition is approaching expiry, the forwarder must emit a `PurgeBeforeForward` alert (see Section 6) before the partition is dropped.

### Replay scenario

If Sentinel was unavailable for more than one batch cycle, the local ClickHouse data provides a replay buffer. The operator can re-trigger forwarding for a time range by querying `security_events` for the affected window and submitting the results through the normal forwarding path.

Replay is bounded by local retention. If ClickHouse local retention for a source expires while Sentinel is still unavailable, those events are permanently lost and cannot be recovered. This is a deliberate design trade-off at lab scale — ClickHouse is not a durable archive and is not sized or operated as one.

**Replay is not guaranteed.** Operators who require stronger durability guarantees (e.g. for compliance) must:

- Reduce the local `{RETENTION_DAYS}` buffer to a longer window (with the associated storage cost), or
- Enable the optional Redpanda buffer between the collector and ClickHouse (which provides a durable, replay-capable queue at the cost of additional infrastructure), or
- Accept that the risk of event loss during extended Sentinel outages is appropriate for lab-scale use.

---

## 6. Purge Logging and Lifecycle Events

Every data removal action must be logged to `SIEMHunterHealth_CL`. Silent purges are not permitted.

### Standard purge log entry

Each partition drop must produce a log entry with at minimum:

| Field | Value |
|-------|-------|
| `TimeGenerated` | Timestamp of the purge operation |
| `EventType` | `"PartitionPurge"` |
| `SourceType` | Source name (e.g. `"Syslog"`, `"Sysmon"`) |
| `Partition` | The `YYYYMM` value dropped |
| `DateRangeStart` | First day of the dropped partition |
| `DateRangeEnd` | Last day of the dropped partition |
| `EventCountEstimate` | Row count from the partition before drop (approximate; ClickHouse part metadata) |
| `ForwardingConfirmed` | `true` / `false` — whether all events in the partition were confirmed forwarded |
| `Severity` | `"Informational"` if forwarding confirmed; `"Warning"` if not |

### Purge before forwarding confirmed

If a partition is dropped and the forwarding ledger does not confirm that all events in that partition reached Sentinel, the maintenance task must:

1. Log a `SIEMHunterHealth_CL` entry with `EventType = "PurgeBeforeForward"` and `Severity = "Warning"`.
2. Write an alert record to `SIEMHunterSecurity_CL` with the same fields, so that the event is visible in Sentinel even if the local health log is no longer queryable.

A `PurgeBeforeForward` event represents a potential gap in the security record. It does not indicate a breach, but it should be investigated: was Sentinel unavailable? Did the retry queue exhaust? Was the local partition TTL too short for the observed forwarding delay?

---

## 7. `detection_state` Table Lifecycle

The `detection_state` table supports stateful multi-event correlation rules (e.g. "three failed authentications from the same host within 10 minutes"). It has its own TTL mechanism separate from `security_events`.

- **TTL column:** `expiry` (DATETIME). Each row carries its own expiry timestamp, set by the detection engine when the correlation window opens.
- **TTL expression:** `TTL expiry DELETE`
- **Normal expiry:** a row that reaches its `expiry` timestamp without the correlation threshold being met is deleted by background TTL. This is expected and correct — the correlation window closed without a hit.
- **No manual purge needed.** The per-row `expiry` column means that partition-based bulk purge is not applicable to `detection_state`. Background TTL deletion is sufficient.
- **No forwarding.** `detection_state` rows are never forwarded to Sentinel. Only the detection *hits* (records written to `SIEMHunterSecurity_CL` when a rule fires) are forwarded. Correlation state is ephemeral by design.

---

## 8. ML Model Artifact Lifecycle

Machine learning model artifacts (trained weights, scalers, encoders) are versioned files on the local filesystem, not database records.

- **Storage path:** `models/v{version}/` under the SIEMhunter data directory.
- **Versioning:** each retrain produces a new version directory. The previous version is retained until the next retrain cycle succeeds and the new version passes validation. This gives one rollback opportunity if the new model performs poorly on live data.
- **Hash verification:** every model artifact has a corresponding `.sha256` file. The model loader verifies the hash at load time and refuses to load any artifact whose hash does not match. Stale, corrupted, or tampered artifacts are never loaded.
- **Old version pruning:** after a successful retrain and validation, the version two cycles back (i.e. not the previous version, but the one before it) may be removed. The current and one-previous versions are always retained.
- **Not in ClickHouse, not forwarded to Sentinel.** Model artifacts are local files only. They are not stored in the database and are not sent to Sentinel. Model performance metrics (accuracy scores, anomaly score distributions) may be written to `SIEMHunterHealth_CL` for monitoring purposes.

---

## 9. Sigma Rule Compiled Artifact Lifecycle

SIEMhunter compiles Sigma YAML rules to ClickHouse SQL at build/CI time. The two artifact categories have different lifecycle treatments.

### Source rules (authoritative)

- **Path:** `rules/local/*.yml`
- **Status:** version-controlled; the authoritative definition of every detection rule.
- **Lifecycle:** rules are added, modified, and retired via pull request. A retired rule's YAML is either deleted or marked `status: deprecated` before removal, depending on whether a historical reference is needed.

### Compiled SQL (generated artifact)

- **Path:** `rules/compiled/*.sql`
- **Status:** gitignored; generated artifact only.
- **Lifecycle:** regenerated on every CI run by the pySigma compilation step. The compiled SQL is never hand-edited. If a compiled file diverges from what the pipeline would produce from the corresponding YAML, the CI run fails. There is no retention concern for compiled SQL — it is disposable and reproducible.

### SigmaHQ snapshot (pinned submodule)

- **Path:** `rules/sigma/`
- **Status:** git submodule pinned to a known commit of the upstream SigmaHQ repository.
- **Lifecycle:** the submodule commit is bumped deliberately via a pull request. Automatic submodule updates are not enabled. Bumping the submodule triggers a full recompile and test run in CI before the bump is merged.

---

## 10. References

| Document | Relevance |
|----------|-----------|
| `04-normalization-and-schema.md` | ClickHouse table design, partition scheme, and field definitions |
| `07-sentinel-forwarding.md` | Forwarding SLA, retry queue design, and ledger reconciliation |
| `16-hardening-checklist.md` | Retention checklist items: workspace retention >= 90 days, partition purge logging, forwarding ledger verification |
