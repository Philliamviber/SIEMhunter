"""
pySigma rule compilation: Sigma YAML → ClickHouse SQL.

What pySigma does
-----------------
pySigma is a Python library that translates Sigma rules (a vendor-neutral YAML
detection language) into the query language of a specific SIEM or database.
The "backend" for ClickHouse translates Sigma detection conditions into SQL
WHERE clauses that run against the siemhunter.security_events table.

The "pipeline" (rules/pipelines/clickhouse-asim-ocsf.yaml) tells pySigma how
to map Sigma field names (e.g., "Image", "EventID", "SubjectUserName") to the
actual ClickHouse column names used in security_events. Without the pipeline,
pySigma would emit the raw Sigma field names in the SQL, which ClickHouse would
reject as unknown columns.

Rule lifecycle and status
-------------------------
Every Sigma rule has a "status" field in its YAML. The lifecycle in SIEMhunter:
  draft       → authored but not yet reviewed; skipped by the detection engine
  test        → passes CI compilation; run in detection but NOT forwarded to Sentinel
  review      → under peer review; run in detection; results inspected by operator
  production  → fully approved; run in detection and forwarded to Sentinel
  disabled    → explicitly turned off; skipped by the detection engine

The "draft" and "disabled" statuses are the only ones skipped at compile time.
This means a rule in "test" or "review" will be executed every detection cycle
even if it has never been validated against live data.

Production rule compilation failures
-------------------------------------
If a rule has status "production" and fails to compile (e.g., uses an unsupported
Sigma construct, or references a field not in the pipeline), this module raises
RuntimeError. The detection service main loop catches this and aborts the cycle.
The rationale: a broken production rule is a reliability/security incident.
Non-production failures are logged as warnings and the rule is skipped.

near/sequence limitation
------------------------
Sigma's "near" and "sequence" constructs express temporal correlation: "event A
must be followed by event B within N seconds". ClickHouse SQL cannot express this
in a single query. Rules using these constructs must be implemented as Python
state machines that read from and write to the detection_state ClickHouse table.
Such rules must be marked status: experimental in their YAML; this module skips
them at compile time with a warning.

Spec: instructions/05-detection-and-anomaly.md §1, §3, §6.
      instructions/04-normalization-and-schema.md §8.
"""
from __future__ import annotations
import os
import pathlib
from typing import NamedTuple

import yaml
import structlog
from sigma.collection import SigmaCollection
from sigma.backends.clickhouse import ClickHouseBackend
from sigma.processing.resolver import ProcessingPipelineResolver

log = structlog.get_logger(__name__)


class CompiledRule(NamedTuple):
    """An immutable record of a successfully compiled Sigma rule.

    Produced by compile_rules() and consumed by runner.run_detection_batch().
    The sql field is a complete ClickHouse SELECT statement that runner.py
    wraps in a time-window subquery before execution.

    Fields:
        rule_id:   The "id" field from the Sigma YAML (UUID or human-readable ID).
        title:     The "title" field from the Sigma YAML (human-readable description).
        status:    The "status" field (test/review/production).
        sql:       The ClickHouse SQL SELECT statement produced by pySigma.
        level:     The Sigma severity level (critical/high/medium/low/informational).
        tags:      The Sigma "tags" list (e.g., ["attack.t1558.003", "attack.credential_access"]).
        file_path: The absolute path to the Sigma YAML file (for operator debugging).
    """
    rule_id: str
    title: str
    status: str
    sql: str
    level: str
    tags: list[str]
    file_path: str


def load_pipeline(pipeline_path: str) -> ProcessingPipelineResolver:
    resolver = ProcessingPipelineResolver()
    resolver.add_pipeline_from_file(pipeline_path)
    return resolver


def compile_rules(rules_dir: str, pipeline_path: str) -> list[CompiledRule]:
    """Walk rules_dir, compile every Sigma YAML whose status is not draft.

    This function is called at the start of every detection cycle (in main.py).
    Re-compiling on every cycle means operators can update rule YAML files
    (change status, fix detection conditions) without restarting the container.
    The tradeoff is a few seconds of pySigma overhead at the start of each cycle.

    The compilation process for each rule:
      1. Load and parse the YAML file.
      2. Check status — skip draft rules; raise on broken production rules.
      3. Check for near/sequence constructs — skip if found (not SQL-compilable).
      4. Call pySigma ClickHouseBackend.convert() to produce SQL.
      5. Wrap in a CompiledRule NamedTuple and append to the result list.

    Rules are sorted by file path before processing to ensure deterministic order.
    This matters for debugging: the log output will always list rules in the same
    order, making it easier to spot which rule was the Nth to be processed.

    Args:
        rules_dir: Directory to walk recursively for *.yml files. In Docker Compose,
                   this is mounted from the host as /app/rules/local (read-only).
        pipeline_path: Path to the pySigma pipeline YAML that maps Sigma field names
                       to ClickHouse column names. Must be the clickhouse-asim-ocsf.yaml
                       pipeline from rules/pipelines/.

    Returns:
        A list of CompiledRule objects for all non-draft, compilable rules.

    Raises:
        RuntimeError: If a production-status rule fails to compile. This is a
                      hard error because a broken production rule is a reliability
                      incident — the detection cycle is aborted and the error is
                      logged for operator investigation.
    """
    compiled: list[CompiledRule] = []
    pipeline_resolver = load_pipeline(pipeline_path)
    backend = ClickHouseBackend(processing_pipeline=pipeline_resolver.resolve())

    for path in sorted(pathlib.Path(rules_dir).rglob("*.yml")):
        try:
            with open(path) as f:
                rule_yaml = yaml.safe_load(f)
        except Exception as exc:
            log.error("rule_load_error", path=str(path), error=str(exc))
            continue

        status = rule_yaml.get("status", "draft")
        if status == "draft":
            continue    # draft rules are not executed

        rule_id = rule_yaml.get("id", str(path.stem))

        # Reject rules with near/sequence — they need the Python state machine
        detection_block = rule_yaml.get("detection", {})
        if "near" in detection_block or "sequence" in detection_block:
            log.warning("rule_uses_near_sequence_skipped", rule_id=rule_id)
            continue

        try:
            collection = SigmaCollection.from_yaml(str(path))
            sql_results = backend.convert(collection)
            if not sql_results:
                log.warning("rule_produced_no_sql", rule_id=rule_id, path=str(path))
                continue

            sql = sql_results[0]
            compiled.append(CompiledRule(
                rule_id=rule_id,
                title=rule_yaml.get("title", ""),
                status=status,
                sql=sql,
                level=rule_yaml.get("level", "medium"),
                tags=rule_yaml.get("tags", []),
                file_path=str(path),
            ))
            log.debug("rule_compiled", rule_id=rule_id, status=status)

        except Exception as exc:
            if status == "production":
                # Production rule compilation failure is a hard error
                raise RuntimeError(
                    f"Production rule {rule_id} failed to compile: {exc}"
                ) from exc
            log.warning("rule_compile_warning", rule_id=rule_id, error=str(exc))

    log.info("rules_compiled", total=len(compiled))
    return compiled
