"""
Rule lifecycle management endpoints: GET /v1/rules, PUT /v1/rules/{rule_id}/status.

These endpoints allow operators to promote, demote, or disable detection rules
without restarting any container. The detection service re-compiles rules from
disk on every cycle, so a status change takes effect within one detection interval.

Why rules need an audit trail
------------------------------
Disabling a detection rule is a high-value attacker action: if an adversary can
disable the rule that detects their lateral movement technique, they can operate
undetected. SIEMhunter therefore treats rule status changes as security-sensitive
events and enforces a fail-closed audit sequence.

The fail-closed audit sequence (mandatory for all mutation operations)
-----------------------------------------------------------------------
1. Validate the requested status change (must be a recognised status value).
2. Look up the current rule state from rule_registry.
3. Build an audit record for SIEMHunterSecurity_CL (EventType: RuleChangeAudit).
4. Write the audit record to Sentinel (SYNCHRONOUS call to the Logs Ingestion API).
   If this write fails → return HTTP 503. Do NOT apply the rule change.
5. Apply the rule status change to siemhunter.rule_registry in ClickHouse.
6. Return 200 with the updated rule state.

The invariant: Sentinel sees the audit record BEFORE ClickHouse is updated.
If step 4 fails and we returned 503 without making the ClickHouse change, the
operator can investigate why Sentinel is unreachable and retry. The rule was
never changed, so detection is still running. If ClickHouse fails AFTER a
successful Sentinel write (step 5 fails), the audit record is already committed
and the operator can reconcile by inspecting SIEMHunterSecurity_CL.

This is the SELF-003 (RuleDisableAudit) detection: any rule disable operation
that does NOT appear in SIEMHunterSecurity_CL is evidence of a bypass attempt.

Rule registry storage
---------------------
Rules are stored in siemhunter.rule_registry using ReplacingMergeTree(updated_at).
Each status change is an INSERT of a new row with the same rule_id but a newer
updated_at. ClickHouse's ReplacingMergeTree merges duplicate rule_id rows in the
background, keeping only the latest version. Queries use FINAL to get the merged
(latest) view rather than waiting for background merges.

Spec: instructions/06-api-control-plane.md §3.2, §4.
"""
from __future__ import annotations
import json
import socket
from datetime import datetime, timezone
from typing import Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict

from ..auth import verify_token
from ..clickhouse_client import get_client
from ..audit_client import send_security_event, send_health_event

log = structlog.get_logger(__name__)
router = APIRouter()

_VALID_STATUSES = frozenset({"draft", "test", "review", "production", "disabled"})

# Statuses that require High severity in the audit record
_HIGH_SEVERITY_STATUSES = frozenset({"production", "disabled"})


# ── Pydantic models ──────────────────────────────────────────────────────────

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


def _write_rule_status(client, rule_id: str, rule_version: str, new_status: str,
                       file_path: str) -> None:
    """Insert new status row into rule_registry. ReplacingMergeTree handles dedup."""
    now = datetime.now(timezone.utc)
    client.insert(
        "siemhunter.rule_registry",
        [[rule_id, rule_version, new_status, file_path, now, "API/bearer"]],
        column_names=["rule_id", "rule_version", "status", "file_path",
                      "updated_at", "updated_by"],
    )


def _build_audit_record(rule: dict, new_status: str, reason: Optional[str]) -> dict:
    """Build the SIEMHunterSecurity_CL audit row per spec §4 step 2."""
    old_status = rule["status"]
    is_high = new_status in _HIGH_SEVERITY_STATUSES or old_status in _HIGH_SEVERITY_STATUSES
    return {
        "TimeGenerated": _now_iso(),
        "RuleId": rule["rule_id"],
        "RuleVersion": rule["rule_version"],
        "EventType": "RuleChangeAudit",
        "Entity": rule.get("file_path", ""),
        "SourceEventIds": "[]",
        "Severity": "High" if is_high else "Informational",
        "Detail": json.dumps({
            "old_status": old_status,
            "new_status": new_status,
            "reason": reason or "",
            "actor": "API/bearer",
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


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/rules")
async def list_rules(
    _: None = Depends(verify_token),
) -> list[RuleResponse]:
    """List all rules from rule_registry."""
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
    _: None = Depends(verify_token),
) -> RuleResponse:
    """Get one rule's status. Returns 404 if not found."""
    client = get_client()
    rule = _get_rule(client, rule_id)
    if rule is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": f"Rule not found: {rule_id}", "code": "RULE_NOT_FOUND"},
        )
    return RuleResponse(**rule)


@router.put("/rules/{rule_id}/status")
async def update_rule_status(
    rule_id: str,
    body: RuleStatusUpdate,
    request: Request,
    _: None = Depends(verify_token),
) -> RuleResponse:
    """Promote or demote a rule's lifecycle status.

    Fail-closed audit sequence (spec §4):
      1. Validate → 2. Build audit record → 3. Write to Sentinel (sync, 10s timeout)
         If Sentinel write fails → 503, ClickHouse unchanged
      4. Apply change in ClickHouse → 5. Return 200
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

    # Idempotent: same status as current → no-op (spec §8)
    if rule["status"] == new_status:
        log.info("rule_status_noop", rule_id=rule_id, status=new_status)
        return RuleResponse(**rule)

    # ── Step 2: Construct audit record ───────────────────────────────────────
    audit_record = _build_audit_record(rule, new_status, body.reason)

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
        )
    except Exception as exc:
        # Audit already committed to Sentinel; ClickHouse write failed.
        # Return 500; operator must reconcile. Audit trail is intact.
        log.error("clickhouse_rule_update_failed", rule_id=rule_id,
                  new_status=new_status, error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "ClickHouse update failed after successful Sentinel audit write",
                "code": "CLICKHOUSE_UPDATE_FAILED",
            },
        )

    # ── Step 5: Return updated state ─────────────────────────────────────────
    updated_rule = _get_rule(client, rule_id)
    if updated_rule is None:
        # Fallback: return the expected state
        updated_rule = {**rule, "status": new_status}

    log.info("rule_status_updated", rule_id=rule_id,
             old_status=rule["status"], new_status=new_status)
    return RuleResponse(**updated_rule)
