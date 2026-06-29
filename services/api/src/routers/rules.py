"""
Rule lifecycle management endpoints.

  GET  /v1/rules              — list all rules (any authenticated analyst)
  GET  /v1/rules/{rule_id}    — get one rule  (any authenticated analyst)
  POST /v1/rules              — register a new rule in draft status  (admin/break-glass only)
  PUT  /v1/rules/{rule_id}/status — mutate rule lifecycle status    (admin/break-glass only)

Auth split (FR #10)
-------------------
Read operations (GET) accept either auth path via verify_token:
  - service token (automation / break-glass), OR
  - analyst session (cookie + CSRF).

Mutating operations (POST, PUT) require the admin / break-glass path ONLY:
  require_service_token raises 401/403 for analyst-session-only callers.
This ensures rule promotion and disable operations leave an audit trail in
the ServiceTokenUse record AND the RuleChangeAudit record.

Fail-closed audit sequence (mandatory for all mutations)
---------------------------------------------------------
1. Validate the requested state change.
2. Look up current rule state.
3. Build an audit record for SIEMHunterSecurity_CL (EventType: RuleChangeAudit).
4. Write the audit record to Sentinel — SYNCHRONOUS, 10 s timeout.
   If this write fails → return HTTP 503.  Do NOT apply the change.
5. Apply the rule status change to siemhunter.rule_registry in ClickHouse.
6. Update the Sigma YAML file on disk so the detection service hot-reload
   picks up the new status on the next batch cycle.
7. Return 200/201 with the updated rule state.

The invariant: Sentinel sees the audit record BEFORE ClickHouse is updated.
A missing RuleChangeAudit for an observed status change is evidence of a bypass.

Rule registry storage
---------------------
siemhunter.rule_registry uses ReplacingMergeTree(updated_at).  Each mutation is
an INSERT of a new row; ClickHouse deduplicates by rule_id, keeping the latest
updated_at after a background merge.  All SELECTs use FINAL.

Spec: instructions/06-api-control-plane.md §3.2, §4.
"""
from __future__ import annotations
import json
import os
import re
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict

from ..auth import verify_token
from ..auth_service_token import require_service_token
from ..clickhouse_client import get_client
from ..audit_client import send_security_event, send_health_event

log = structlog.get_logger(__name__)
router = APIRouter()

_VALID_STATUSES = frozenset({"draft", "test", "review", "production", "disabled"})

# Resolved once at module load; containers mount rules at this path.
_RULES_ROOT = Path(os.environ.get("RULES_DIR", "/app/rules")).resolve()

# Statuses that attract High severity in the audit record
_HIGH_SEVERITY_STATUSES = frozenset({"production", "disabled"})


# ── Pydantic models ──────────────────────────────────────────────────────────

class RuleRegister(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str
    rule_version: str = "0.0.1"
    file_path: str = ""
    reason: Optional[str] = None


class RuleStatusUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    new_status: str
    reason: Optional[str] = None


class RuleResponse(BaseModel):
    rule_id: str
    rule_version: str
    status: str
    file_path: str
    updated_at: str


# ── Helpers ──────────────────────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hostname() -> str:
    return socket.gethostname()


def _get_rule(client, rule_id: str) -> Optional[dict]:
    """Fetch the latest state of a rule from rule_registry (FINAL = latest merge)."""
    rows = client.query(
        """
        SELECT rule_id, rule_version, status, file_path, updated_at
        FROM siemhunter.rule_registry FINAL
        WHERE rule_id = {rule_id:String}
        LIMIT 1
        """,
        parameters={"rule_id": rule_id},
    ).result_rows
    if not rows:
        return None
    r = rows[0]
    return {
        "rule_id": str(r[0]),
        "rule_version": str(r[1]),
        "status": str(r[2]),
        "file_path": str(r[3]),
        "updated_at": str(r[4]),
    }


def _write_rule_status(
    client, rule_id: str, rule_version: str, new_status: str,
    file_path: str, actor: str,
) -> None:
    """Insert new status row into rule_registry. ReplacingMergeTree handles dedup."""
    now = datetime.now(timezone.utc)
    client.insert(
        "siemhunter.rule_registry",
        [[rule_id, rule_version, new_status, file_path, now, actor]],
        column_names=["rule_id", "rule_version", "status", "file_path",
                      "updated_at", "updated_by"],
    )


def _build_audit_record(
    rule_id: str, rule_version: str, file_path: str,
    old_status: Optional[str], new_status: str,
    reason: Optional[str], actor: str,
) -> dict:
    """Build the SIEMHunterSecurity_CL audit row."""
    is_high = new_status in _HIGH_SEVERITY_STATUSES or (old_status or "") in _HIGH_SEVERITY_STATUSES
    return {
        "TimeGenerated": _now_iso(),
        "RuleId": rule_id,
        "RuleVersion": rule_version,
        "EventType": "RuleChangeAudit",
        "Entity": file_path,
        "SourceEventIds": "[]",
        "Severity": "High" if is_high else "Informational",
        "Detail": json.dumps({
            "old_status": old_status,
            "new_status": new_status,
            "reason": reason or "",
            "actor": actor,
        }),
        "ATTACKTechnique": "",
    }


def _write_audit_failure_health(rule_id: str, new_status: str, error: str) -> None:
    """Log AuditWriteFailure to SIEMHunterHealth_CL (best-effort, swallow exceptions)."""
    try:
        send_health_event({
            "TimeGenerated": _now_iso(),
            "HostName": _hostname(),
            "EventType": "AuditWriteFailure",
            "Severity": "Error",
            "SourceId": "api",
            "EventCount": 1,
            "Detail": json.dumps({
                "rule_id": rule_id,
                "attempted_new_status": new_status,
                "sentinel_error": error[:500],
            }),
            "BatchId": "",
        })
    except Exception as exc:
        log.error("audit_failure_health_write_failed", error=str(exc))


def _validate_file_path(file_path: str) -> None:
    """Reject file_path values outside the configured rules root (path traversal guard).

    Callers hold the break-glass service token, but validating the path prevents
    accidental or malicious overwrites of files outside the rules directory.
    Empty paths are allowed (the rule may not have a YAML file yet).
    """
    if not file_path:
        return
    try:
        resolved = Path(file_path).resolve()
        resolved.relative_to(_RULES_ROOT)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error": f"file_path must be within the rules directory ({_RULES_ROOT})",
                "code": "INVALID_FILE_PATH",
            },
        )


def _update_yaml_status(file_path: str, new_status: str) -> None:
    """Update the `status:` line in the Sigma YAML file on disk.

    The detection service re-reads YAML files on every batch cycle. Updating
    the status field here is what makes a promotion or demotion visible to the
    hot-reload mechanism without restarting any container.

    Fail-soft: if the file does not exist or cannot be written, logs a warning
    and returns rather than raising — the ClickHouse registry is already updated
    at this point and the audit trail is intact.
    """
    if not file_path:
        return
    path = Path(file_path)
    if not path.exists():
        log.warning("rule_yaml_not_found_for_status_update", file_path=file_path)
        return
    try:
        content = path.read_text(encoding="utf-8")
        # Replace entire line tail after `status:` so quoted values and trailing
        # comments are handled correctly. `[ \t]*` avoids crossing line boundaries
        # (unlike `\s*`). `count=1` ensures only the first top-level `status:` line
        # (position 0 on its line) is touched; YAML block-scalar lines are always
        # indented so they cannot match `^status:` with re.MULTILINE.
        updated = re.sub(
            r"^(status:[ \t]*).*",
            rf"\g<1>{new_status}",
            content,
            count=1,
            flags=re.MULTILINE,
        )
        if updated != content:
            path.write_text(updated, encoding="utf-8")
            log.info("rule_yaml_status_updated", file_path=file_path, new_status=new_status)
    except Exception as exc:
        log.warning("rule_yaml_update_failed", file_path=file_path, error=str(exc))


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/rules")
async def list_rules(
    _: str = Depends(verify_token),
) -> list[RuleResponse]:
    """List all rules from rule_registry. Open to any authenticated analyst."""
    client = get_client()
    rows = client.query(
        """
        SELECT rule_id, rule_version, status, file_path, updated_at
        FROM siemhunter.rule_registry FINAL
        ORDER BY updated_at DESC
        """,
    ).result_rows
    return [
        RuleResponse(
            rule_id=str(r[0]),
            rule_version=str(r[1]),
            status=str(r[2]),
            file_path=str(r[3]),
            updated_at=str(r[4]),
        )
        for r in rows
    ]


@router.get("/rules/{rule_id}")
async def get_rule(
    rule_id: str,
    _: str = Depends(verify_token),
) -> RuleResponse:
    """Get one rule's status. Open to any authenticated analyst. Returns 404 if not found."""
    client = get_client()
    rule = _get_rule(client, rule_id)
    if rule is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": f"Rule not found: {rule_id}", "code": "RULE_NOT_FOUND"},
        )
    return RuleResponse(**rule)


@router.post("/rules", status_code=status.HTTP_201_CREATED)
async def register_rule(
    body: RuleRegister,
    request: Request,
    actor: str = Depends(require_service_token),
) -> RuleResponse:
    """Register a new Sigma rule in draft status. Admin / break-glass only.

    Fail-closed audit sequence: writes audit to Sentinel BEFORE updating ClickHouse.
    """
    rule_id = body.rule_id.strip()
    if not rule_id:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "rule_id must not be empty", "code": "INVALID_RULE_ID"},
        )

    _validate_file_path(body.file_path)

    client = get_client()

    existing = _get_rule(client, rule_id)
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": f"Rule already registered: {rule_id}", "code": "RULE_EXISTS"},
        )

    # ── Fail-closed audit: write BEFORE ClickHouse ────────────────────────────
    audit_record = _build_audit_record(
        rule_id=rule_id,
        rule_version=body.rule_version,
        file_path=body.file_path,
        old_status=None,
        new_status="draft",
        reason=body.reason,
        actor=actor,
    )
    try:
        send_security_event(audit_record)
    except Exception as exc:
        log.error("sentinel_audit_write_failed", rule_id=rule_id, new_status="draft", error=str(exc))
        _write_audit_failure_health(rule_id, "draft", str(exc))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "Audit write to Sentinel failed; rule registration rejected",
                "code": "AUDIT_WRITE_FAILED",
            },
        )

    # ── Apply registration in ClickHouse ──────────────────────────────────────
    try:
        _write_rule_status(client, rule_id, body.rule_version, "draft", body.file_path, actor)
    except Exception as exc:
        log.error("clickhouse_rule_insert_failed", rule_id=rule_id, error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "ClickHouse insert failed after successful Sentinel audit write",
                "code": "CLICKHOUSE_INSERT_FAILED",
            },
        )

    # Update YAML file if it exists so the detection service and registry stay in sync.
    _update_yaml_status(body.file_path, "draft")

    result = _get_rule(client, rule_id)
    if result is None:
        result = {
            "rule_id": rule_id, "rule_version": body.rule_version,
            "status": "draft", "file_path": body.file_path, "updated_at": _now_iso(),
        }
    log.info("rule_registered", rule_id=rule_id, actor=actor)
    return RuleResponse(**result)


@router.put("/rules/{rule_id}/status")
async def update_rule_status(
    rule_id: str,
    body: RuleStatusUpdate,
    request: Request,
    actor: str = Depends(require_service_token),
) -> RuleResponse:
    """Promote or demote a rule's lifecycle status. Admin / break-glass only.

    Fail-closed audit sequence (spec §4):
      1. Validate → 2. Build audit record → 3. Write to Sentinel (sync)
         If Sentinel write fails → 503, ClickHouse unchanged
      4. Apply change in ClickHouse
      5. Update YAML file on disk (detection hot-reload)
      6. Return 200
    """
    # ── Step 1: Validate ─────────────────────────────────────────────────────
    new_status = body.new_status.lower()
    if new_status not in _VALID_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error": f"Invalid status: {new_status!r}. "
                         f"Must be one of: {sorted(_VALID_STATUSES)}",
                "code": "INVALID_STATUS",
            },
        )

    client = get_client()
    rule = _get_rule(client, rule_id)
    if rule is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": f"Rule not found: {rule_id}", "code": "RULE_NOT_FOUND"},
        )

    # Idempotent: same status → no-op
    if rule["status"] == new_status:
        log.info("rule_status_noop", rule_id=rule_id, status=new_status)
        return RuleResponse(**rule)

    # ── Step 2: Construct audit record ───────────────────────────────────────
    audit_record = _build_audit_record(
        rule_id=rule["rule_id"],
        rule_version=rule["rule_version"],
        file_path=rule.get("file_path", ""),
        old_status=rule["status"],
        new_status=new_status,
        reason=body.reason,
        actor=actor,
    )

    # ── Step 3: Write audit record to Sentinel (MUST succeed before ClickHouse)
    try:
        send_security_event(audit_record)
    except Exception as exc:
        log.error("sentinel_audit_write_failed", rule_id=rule_id,
                  new_status=new_status, error=str(exc))
        _write_audit_failure_health(rule_id, new_status, str(exc))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "Audit write to Sentinel failed; rule change rejected",
                "code": "AUDIT_WRITE_FAILED",
            },
        )

    # ── Step 4: Apply rule change in ClickHouse ──────────────────────────────
    try:
        _write_rule_status(
            client,
            rule_id=rule["rule_id"],
            rule_version=rule["rule_version"],
            new_status=new_status,
            file_path=rule["file_path"],
            actor=actor,
        )
    except Exception as exc:
        log.error("clickhouse_rule_update_failed", rule_id=rule_id,
                  new_status=new_status, error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "ClickHouse update failed after successful Sentinel audit write",
                "code": "CLICKHOUSE_UPDATE_FAILED",
            },
        )

    # ── Step 5: Update YAML file on disk for detection hot-reload ────────────
    _update_yaml_status(rule["file_path"], new_status)

    # ── Step 6: Return updated state ─────────────────────────────────────────
    updated_rule = _get_rule(client, rule_id)
    if updated_rule is None:
        updated_rule = {**rule, "status": new_status}

    log.info("rule_status_updated", rule_id=rule_id,
             old_status=rule["status"], new_status=new_status, actor=actor)
    return RuleResponse(**updated_rule)
