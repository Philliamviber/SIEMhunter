"""
Sigma batch detection runner.
Spec: instructions/05-detection-and-anomaly.md §1, §5.

Executes compiled Sigma SQL queries against security_events,
attaches ML advisory scores, and writes hits to detection_hits.

Anti-double-alerting: SIEMhunter never creates Sentinel incidents directly
for Sigma hits. All hits go through SIEMHunterSecurity_CL → Sentinel analytics rule.
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
    content = f"{rule_id}:{','.join(sorted(event_ids))}:{batch_start}"
    return hashlib.sha256(content.encode()).hexdigest()


def run_detection_batch(
    client,
    rules: list[CompiledRule],
    batch_start: str,
    batch_end: str,
) -> list[dict]:
    """Execute all compiled rules against the current batch window.

    Returns a list of detection hit records ready for insertion into detection_hits.
    The caller is responsible for inserting these into ClickHouse and forwarding
    them to the forwarder service.
    """
    hits: list[dict] = []
    entity_feature_cache: dict[str, dict] = {}    # for ML scoring

    for rule in rules:
        # Inject batch window into the SQL via a WHERE clause on TimeGenerated.
        # The compiled SQL already includes WHERE conditions from pySigma;
        # we AND in the batch window to scope the query.
        #
        # pySigma compiles to: SELECT ... FROM security_events WHERE <rule_conditions>
        # We wrap it to add the time window. Parameterized via ClickHouse native params.
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
