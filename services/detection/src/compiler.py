"""
pySigma compilation: Sigma YAML → ClickHouse SQL.
Spec: instructions/05-detection-and-anomaly.md §1, 04-normalization-and-schema.md §8.

Rules:
- Production-status rules must compile without warnings; warnings = CI failure.
- EventID values are UInt32 — never quoted strings.
- Rules using `near`/`sequence` must NOT be compiled here; they use the
  Python state machine in runner.py instead.
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
    """Walk rules_dir, compile every YAML with status in (test, review, production)."""
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
