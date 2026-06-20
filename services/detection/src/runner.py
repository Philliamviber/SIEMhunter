"""
Sigma batch detection runner.

Purpose
-------
This module executes compiled Sigma rules against the siemhunter.security_events
table in ClickHouse and records the results in siemhunter.detection_hits.

The compiled rules arrive as CompiledRule objects from compiler.py. Each rule
was produced by pySigma from a Sigma YAML file using the clickhouse-asim-ocsf
pipeline. The SQL is a complete SELECT statement that returns matching event rows.

This module wraps each rule's SQL in a time-window predicate so the query
only examines events in the current detection batch window (e.g., the last
15 minutes). Without this wrapping, every detection run would re-examine the
entire security_events table, which grows with every ingest batch.

Anti-double-alerting design
-----------------------------
SIEMhunter does NOT create Sentinel incidents directly for Sigma hits.
Instead, detection hits are written to two places:
  1. siemhunter.detection_hits (local ClickHouse table)
  2. SIEMHunterSecurity_CL (Sentinel custom table, via the forwarder service)

A Sentinel scheduled analytics rule queries SIEMHunterSecurity_CL and creates
incidents based on those records. This two-stage design means:
  - SIEMhunter can detect without Sentinel being reachable (hits accumulate locally).
  - Sentinel owns incident triage, not SIEMhunter.
  - There is no risk of SIEMhunter and a Sentinel analytics rule both creating
    incidents for the same event (they operate on different data paths).

The exception is self-detection rules (SELF-001 through SELF-005): these DO
create Sentinel incidents directly (via the Incidents API) because they represent
SIEMhunter's own security posture, not customer telemetry.

ML advisory scoring
-------------------
After all rule executions, this module calls score_entities() from ml_scorer.py.
The ML scorer returns anomaly scores (0.0–1.0) for each entity (user or host)
that appeared in detection hits. These scores are attached to the hit record
but never change whether a hit is recorded — they are advisory only.
If ML models are not deployed, score_entities() returns an empty dict and
the anomaly_score field is 0.0 for all hits.

Spec: instructions/05-detection-and-anomaly.md §1, §5.
"""
from __future__ import annotations
import hashlib
import json
import uuid
from datetime import datetime, timezone

import structlog

from .compiler import CompiledRule
from .ml_scorer import score_entities

log = structlog.get_logger(__name__)

# Map from Sigma rule "level" field values to Sentinel incident severity strings.
# pySigma preserves the Sigma YAML "level" field in the CompiledRule.level attribute.
# The Sentinel Incidents API accepts: "Informational", "Low", "Medium", "High".
# "critical" maps to "High" because Sentinel has no Critical severity tier.
_SEVERITY_MAP = {
    "critical": "High",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "informational": "Informational",
}


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def _hit_id(rule_id: str, event_ids: list[str], batch_start: str) -> str:
    """Compute a deterministic detection hit ID.

    The hit ID is a SHA-256 hash of the rule ID, the sorted set of matching
    event record IDs, and the batch start time. Sorting the event IDs ensures
    the hash is the same regardless of the order in which ClickHouse returns rows.

    Determinism is important for two reasons:
    1. If the same batch is re-processed (e.g., after a detection service
       restart), the hit_id will be the same, allowing the forwarder to
       detect and skip duplicate forwarding.
    2. The hit_id becomes the Sentinel incident name for self-detection rules,
       providing idempotent incident creation (PUT with the same name is
       idempotent in the Incidents API).

    Args:
        rule_id: The Sigma rule ID (from the YAML "id" field).
        event_ids: The list of EventRecordID values for events that matched the rule.
        batch_start: The batch window start timestamp string.

    Returns:
        A 64-character hex SHA-256 digest.
    """
    content = f"{rule_id}:{','.join(sorted(event_ids))}:{batch_start}"
    return hashlib.sha256(content.encode()).hexdigest()


def run_detection_batch(
    client,
    rules: list[CompiledRule],
    batch_start: str,
    batch_end: str,
) -> list[dict]:
    """Execute all compiled Sigma rules against events in the current batch window.

    For each rule, this function:
      1. Wraps the compiled SQL in a time-window predicate so only events
         in [batch_start, batch_end] are examined.
      2. Executes the query against siemhunter.security_events.
      3. Collects entity context (SubjectUserName, HostName) for ML scoring.
      4. Builds a detection_hits row for each rule that matched at least one event.

    After all rules run, ML advisory scores are attached to the hit records.

    Time window injection
    ---------------------
    pySigma compiles Sigma rules to SQL like:
      SELECT * FROM security_events WHERE EventID = 4769 AND ServiceName LIKE '%$'

    This module wraps that SQL as a subquery and adds a time boundary:
      SELECT ... FROM (<pySigma_sql>) AS rule_matches
      WHERE TimeGenerated BETWEEN {batch_start} AND {batch_end}

    The time parameters are injected via ClickHouse's native parameterized
    query interface (curly-brace syntax), not string interpolation.
    This ensures that operator-configured batch_start/batch_end strings
    cannot be used to inject SQL.

    Entity feature cache
    --------------------
    The entity_feature_cache collects user and host identifiers from matching
    events. After all rules run, score_entities() is called once with all
    collected entities. The highest anomaly score across all entities is then
    attached to all hits for that batch (a conservative heuristic: if any
    entity in the batch is anomalous, all hits in the batch are flagged).

    In v0.1.0, entity features are placeholder values (a single 1.0 feature).
    The real feature engineering (login frequency, hours-of-day distribution,
    etc.) is specified in instructions/05-detection-and-anomaly.md §8 and
    will be implemented when ML baseline models are trained.

    Args:
        client: An authenticated clickhouse_connect Client.
        rules: List of compiled rules from compiler.compile_rules().
        batch_start: The start of the detection window (UTC string, DateTime64 format).
        batch_end: The end of the detection window (UTC string, DateTime64 format).

    Returns:
        A list of detection hit dicts ready for insertion into detection_hits.
        Empty list if no rules matched any events in the window.
        The caller (main.py) is responsible for inserting and forwarding.
    """
    hits: list[dict] = []
    # Accumulate entity context across all rules for a single ML scoring call.
    # Key format: "{entity_type}:{entity_key}", e.g., "user:jsmith", "host:dc01".
    entity_feature_cache: dict[str, dict] = {}

    for rule in rules:
        # Wrap the compiled rule SQL in a time-window subquery.
        # pySigma SQL: SELECT ... FROM security_events WHERE <conditions>
        # We add TimeGenerated BETWEEN to scope to the current batch window.
        # The {batch_start:DateTime64} syntax is ClickHouse parameterized query notation.
        windowed_sql = (
            f"SELECT EventRecordID, SubjectUserName, HostName, IpAddress, SrcIpAddr, "
            f"       DstIpAddr, EventID, TimeGenerated "
            f"FROM ({rule.sql}) AS rule_matches "
            f"WHERE TimeGenerated BETWEEN {{batch_start:DateTime64}} AND {{batch_end:DateTime64}}"
        )

        try:
            result = client.query(
                windowed_sql,
                parameters={"batch_start": batch_start, "batch_end": batch_end},
            )
            rows = result.result_rows
        except Exception as exc:
            log.error("rule_execution_error", rule_id=rule.rule_id, error=str(exc))
            continue

        if not rows:
            continue

        col_names = [col.name for col in result.column_names] if hasattr(result, 'column_names') else []
        event_record_ids = [str(row[0]) for row in rows if row]

        hit_id = _hit_id(rule.rule_id, event_record_ids, batch_start)

        # Collect entity features for ML scoring
        for row in rows:
            subject = str(row[1]) if len(row) > 1 else ""
            host = str(row[2]) if len(row) > 2 else ""
            if subject:
                key = f"user:{subject}"
                if key not in entity_feature_cache:
                    entity_feature_cache[key] = {
                        "entity_type": "user",
                        "entity_key": key,
                        "features": [1.0],   # placeholder; real features from §8 baselines
                    }

        hit = {
            "hit_id": hit_id,
            "rule_id": rule.rule_id,
            "rule_version": "1.0",
            "batch_start": batch_start,
            "batch_end": batch_end,
            "event_record_ids": json.dumps(event_record_ids),
            "hit_count": len(rows),
            "severity": _SEVERITY_MAP.get(rule.level, "Medium"),
            "mitre_tag": next(
                (t for t in rule.tags if t.startswith("attack.t")), ""
            ),
            "anomaly_score": 0.0,   # filled in after ML scoring below
            "created_at": _now_utc(),
            "forwarded_at": None,
        }
        hits.append(hit)
        log.info("detection_hit", rule_id=rule.rule_id, hit_count=len(rows),
                 severity=hit["severity"])

    # Attach ML advisory scores (never blocks or alters hits)
    if hits and entity_feature_cache:
        try:
            scores = score_entities(list(entity_feature_cache.values()))
            # Assign the max entity anomaly score to each hit as a heuristic
            max_score = max(scores.values()) if scores else 0.0
            for hit in hits:
                hit["anomaly_score"] = max_score
        except Exception as exc:
            log.warning("ml_scoring_skipped", error=str(exc))

    return hits


def insert_hits(client, hits: list[dict]) -> None:
    """Parameterized bulk insert of detection hits into ClickHouse."""
    if not hits:
        return
    client.insert(
        "siemhunter.detection_hits",
        hits,
        column_names=list(hits[0].keys()),
    )
    log.info("hits_inserted", count=len(hits))
