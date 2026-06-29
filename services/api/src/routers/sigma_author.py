"""
POST /v1/sigma/compile  — compile Sigma YAML to ClickHouse SQL via pySigma
POST /v1/sigma/dryrun   — compile + SELECT-only dry-run against recent events

Security invariants
-------------------
compile:
  - Pure Python; zero DB interaction.

dryrun:
  - Read-only ClickHouse connection (readonly=1 session setting).
  - Single-SELECT guard before execution:
      • no semicolons
      • must start with SELECT
      • forbidden keywords: INSERT UPDATE DELETE DROP CREATE ALTER TRUNCATE
        RENAME ATTACH DETACH OPTIMIZE SYSTEM
  - Time window bounded to last N hours (default 24, max 168).
  - Hard row LIMIT (default 200).
  - Query timeout: 15 seconds.
  - No writes to rule_registry or any other table.

Authentication: Bearer token required.
"""
from __future__ import annotations
import os
import re
import time
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict

from ..auth import verify_token
from ..clickhouse_client import get_readonly_client

log = structlog.get_logger(__name__)
router = APIRouter()

_PIPELINE_PATH = os.environ.get(
    "SIGMA_PIPELINE_PATH",
    "/app/rules/pipelines/clickhouse-asim-ocsf.yaml",
)
_DRYRUN_ROW_LIMIT = int(os.environ.get("SIGMA_DRYRUN_LIMIT", "200"))
_DRYRUN_DEFAULT_WINDOW_HOURS = int(os.environ.get("SIGMA_DRYRUN_WINDOW_HOURS", "24"))
_DRYRUN_TIMEOUT_SECONDS = 15

# pySigma packages are optional at import time so the module remains importable
# in environments where pySigma is not installed (e.g. test runners). The
# endpoints raise HTTP 503 when _PYSIGMA_AVAILABLE is False.
try:
    from sigma.collection import SigmaCollection
    from sigma.backends.clickhouse import ClickHouseBackend
    from sigma.processing.resolver import ProcessingPipelineResolver
    _PYSIGMA_AVAILABLE = True
except ImportError:
    _PYSIGMA_AVAILABLE = False

# ── SELECT-only guard ─────────────────────────────────────────────────────────

_FORBIDDEN_KEYWORDS = re.compile(
    r"\b(INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE|RENAME|ATTACH|DETACH|OPTIMIZE|SYSTEM"
    r"|KILL|GRANT|REVOKE|EXCHANGE|MOVE|FREEZE|FETCH)\b",
    re.IGNORECASE,
)


def _assert_single_select(sql: str) -> None:
    """Raise HTTP 400 if sql is not a single, mutation-free SELECT statement.

    Checks (in order):
    1. No semicolons — prevents statement chaining.
    2. Must start with SELECT — no DDL/DML at the top level.
    3. No forbidden mutation keywords anywhere — blocks injection via subqueries or CTEs.
    """
    stripped = sql.strip()
    if ";" in stripped:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "Semicolons are not permitted in dry-run SQL",
                "code": "FORBIDDEN_STATEMENT",
            },
        )
    if not stripped.upper().startswith("SELECT"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "Only SELECT statements are permitted for dry-run",
                "code": "FORBIDDEN_STATEMENT",
            },
        )
    m = _FORBIDDEN_KEYWORDS.search(stripped)
    if m:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": f"Forbidden keyword in compiled SQL: {m.group()}",
                "code": "FORBIDDEN_STATEMENT",
            },
        )


# ── pySigma compilation ───────────────────────────────────────────────────────

def compile_sigma_to_sql(yaml_content: str) -> tuple[str, str, str]:
    """Compile Sigma YAML to ClickHouse SQL using the pySigma pipeline.

    Returns a tuple of (sql, title, rule_id).
    Raises RuntimeError if pySigma is not installed.
    Raises ValueError / pySigma exception on compilation failure.
    """
    if not _PYSIGMA_AVAILABLE:
        raise RuntimeError(
            "pySigma packages (pysigma, pysigma-backend-clickhouse) are not installed"
        )

    resolver = ProcessingPipelineResolver()
    resolver.add_pipeline_from_file(_PIPELINE_PATH)
    backend = ClickHouseBackend(processing_pipeline=resolver.resolve())

    collection = SigmaCollection.from_yaml(yaml_content)
    results = backend.convert(collection)
    if not results:
        raise ValueError("pySigma produced no SQL output for this rule")

    first_rule = next(iter(collection), None)
    title = str(first_rule.title) if first_rule and first_rule.title else ""
    rule_id = str(first_rule.id) if first_rule and first_rule.id else ""

    return results[0], title, rule_id


# ── Request / Response models ─────────────────────────────────────────────────

class SigmaCompileRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sigma_yaml: str


class SigmaCompileResponse(BaseModel):
    sql: str
    title: str
    rule_id: str


class SigmaDryRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sigma_yaml: str
    window_hours: int = _DRYRUN_DEFAULT_WINDOW_HOURS


class SigmaDryRunResponse(BaseModel):
    sql: str
    sample_rows: list[dict[str, Any]]
    sampled_count: int     # rows returned (capped at LIMIT); not a full-table count
    execution_time_ms: float


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/sigma/compile", response_model=SigmaCompileResponse)
async def compile_sigma(
    body: SigmaCompileRequest,
    _: None = Depends(verify_token),
) -> SigmaCompileResponse:
    """Compile Sigma YAML to ClickHouse SQL.

    Returns the compiled SQL plus the rule title and ID extracted from the YAML.
    Returns HTTP 422 with a plain-English error message on compile failure so the
    analyst can correct the YAML in the editor without leaving the page.
    """
    try:
        sql, title, rule_id = compile_sigma_to_sql(body.sigma_yaml)
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": str(exc), "code": "SIGMA_UNAVAILABLE"},
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": f"Sigma compile error: {exc}", "code": "SIGMA_COMPILE_ERROR"},
        )

    return SigmaCompileResponse(sql=sql, title=title, rule_id=rule_id)


@router.post("/sigma/dryrun", response_model=SigmaDryRunResponse)
async def dryrun_sigma(
    body: SigmaDryRunRequest,
    _: None = Depends(verify_token),
) -> SigmaDryRunResponse:
    """Compile Sigma YAML and dry-run the compiled SQL against recent events.

    Flow:
      1. Compile Sigma YAML → SQL (same as /sigma/compile).
      2. Assert single-SELECT: no semicolons, no mutation keywords.
      3. Wrap compiled SQL with a time-window predicate and hard row LIMIT.
      4. Execute on a read-only ClickHouse connection (readonly=1).
      5. Return sample rows and match count.

    No writes are performed. No rows are written to rule_registry.
    """
    # Step 1: compile Sigma → SQL
    try:
        compiled_sql, _, _ = compile_sigma_to_sql(body.sigma_yaml)
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": str(exc), "code": "SIGMA_UNAVAILABLE"},
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": f"Sigma compile error: {exc}", "code": "SIGMA_COMPILE_ERROR"},
        )

    # Step 2: guard — must be a single SELECT with no mutation keywords
    _assert_single_select(compiled_sql)

    # Step 3: wrap with time window + LIMIT (clamped 1h–7d)
    window_hours = max(1, min(body.window_hours, 168))
    bounded_sql = (
        f"SELECT * FROM ({compiled_sql}) AS sigma_dryrun "
        f"WHERE TimeGenerated >= now() - INTERVAL {window_hours} HOUR "
        f"LIMIT {_DRYRUN_ROW_LIMIT}"
    )

    # Step 4: execute on read-only connection
    t_start = time.monotonic()
    try:
        client = get_readonly_client()
        result = client.query(
            bounded_sql,
            settings={"max_execution_time": _DRYRUN_TIMEOUT_SECONDS},
        )
    except HTTPException:
        raise
    except Exception as exc:
        exc_str = str(exc)
        if "timeout" in exc_str.lower() or "exceeded" in exc_str.lower():
            raise HTTPException(
                status_code=408,
                detail={"error": "Dry-run query timed out", "code": "QUERY_TIMEOUT"},
            )
        log.error("sigma_dryrun_error", error=exc_str)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "ClickHouse dry-run failed", "code": "QUERY_ERROR"},
        )

    elapsed_ms = (time.monotonic() - t_start) * 1000.0
    column_names = result.column_names
    sample_rows = [dict(zip(column_names, row)) for row in result.result_rows]

    return SigmaDryRunResponse(
        sql=compiled_sql,
        sample_rows=sample_rows,
        sampled_count=len(sample_rows),
        execution_time_ms=round(elapsed_ms, 2),
    )
