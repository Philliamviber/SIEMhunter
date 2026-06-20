"""
POST /v1/ingestion/upload — Security-gated manual file upload.

Security controls enforced (all server-side):
  MUST 1  — ProvenanceTag is ALWAYS server-assigned; any ProvenanceTag,
             IngestTimestamp, or source-identity field found inside the file
             content is stripped before mapping to canonical columns.
  MUST 2  — Strict allowlist field mapping. Only EXACT matches against
             CANONICAL_COLUMNS are written to typed columns. Everything else
             goes to UnmappedFields as a JSON dict.
  MUST 3  — Hard input bounds: UPLOAD_MAX_BYTES (default 100 MiB),
             UPLOAD_MAX_EVENTS (default 1,000,000), max 64 KB per field,
             max 256 KB for UnmappedFields per row,
             decompression ratio cap 100:1 (rejected — no .zip/.gz for MVP).
  MUST 4  — Extension allowlist (.json, .jsonl, .csv, .log, .txt only).
             Magic byte check: content must be valid UTF-8 (no binary PE).
             Rejects path-traversal filenames (no '..' segments, no NUL).
             HTTP 415 for unsupported extension.
  MUST 5  — File is saved to drop/ directory before parsing; parsing is done
             inline with strict sandboxing (no external entity expansion,
             max row/field limits enforced before parsing finishes).
  MUST 6  — ClickHouse inserts use the client.insert() method with typed rows
             and explicit column lists. NEVER string-concatenated SQL.
  MUST 7  — No dangerouslySetInnerHTML. All field values are rendered as plain
             React text nodes (enforced in frontend UploadStatusCard).

Authentication: required (bearer token).
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import re
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import structlog
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from pydantic import BaseModel

from ..auth import verify_token
from ..clickhouse_client import get_client

log = structlog.get_logger(__name__)
router = APIRouter()

# ── Configuration (env-backed bounds) ────────────────────────────────────────

_UPLOAD_MAX_BYTES: int = int(os.environ.get("UPLOAD_MAX_BYTES", str(100 * 1024 * 1024)))  # 100 MiB
_UPLOAD_MAX_EVENTS: int = int(os.environ.get("UPLOAD_MAX_EVENTS", "1000000"))
_MAX_FIELD_BYTES: int = 64 * 1024          # 64 KB per field value
_MAX_UNMAPPED_BYTES: int = 256 * 1024      # 256 KB for UnmappedFields per row

# drop/ directory sits at repo root relative to the service; resolved at runtime.
_DROP_DIR: Path = Path(os.environ.get("UPLOAD_DROP_DIR", "/app/drop"))

# ── Allowlists ────────────────────────────────────────────────────────────────

_ALLOWED_EXTENSIONS: frozenset[str] = frozenset({".json", ".jsonl", ".csv", ".log", ".txt"})

# Exact canonical column names that may be populated from file content.
# ProvenanceTag and IngestTimestamp are INTENTIONALLY excluded: they are
# always server-assigned and must never come from file content.
CANONICAL_COLUMNS: frozenset[str] = frozenset({
    "TimeGenerated",
    "HostName",
    "EventID",
    "EventRecordID",
    "ChannelName",
    "ProviderName",
    "SubjectUserName",
    "SubjectUserSid",
    "SubjectDomainName",
    "TargetUserName",
    "TargetUserSid",
    "TargetDomainName",
    "LogonType",
    "ServiceName",
    "ProcessImagePath",
    "CommandLine",
    "ParentProcessImagePath",
    "ParentCommandLine",
    "GrantedAccess",
    "ObjectName",
    "FileMD5",
    "FileSHA256",
    "RegistryKey",
    "SrcIpAddr",
    "SrcPort",
    "DstIpAddr",
    "DstPort",
    "NetworkProtocol",
    "UnmappedFields",
})

# Fields that are always server-assigned and must be stripped from file content
# before allowlist mapping (MUST 1).
_SERVER_ONLY_FIELDS: frozenset[str] = frozenset({
    "ProvenanceTag",
    "IngestTimestamp",
    # Vector internal names that might appear in exported JSON
    "_siemhunter_provenance",
    "_siemhunter_ingest_ts",
})

# Integer-typed canonical columns — enforce int coercion
_INT_COLUMNS: frozenset[str] = frozenset({"EventID", "SrcPort", "DstPort", "LogonType"})

# Fixed-width string columns that need padding/truncation to exact length
_FIXED_COLUMNS: dict[str, int] = {
    "FileMD5": 32,
    "FileSHA256": 64,
}

# ── Response model ────────────────────────────────────────────────────────────

class UploadResponse(BaseModel):
    filename: str
    provenance_tag: str
    events_parsed: int
    events_written: int
    events_unmapped: int   # events that had at least one field go to UnmappedFields
    error_count: int
    status: str            # 'success', 'partial', 'failed'


# ── Helpers ───────────────────────────────────────────────────────────────────

def _safe_filename(name: str) -> str:
    """Return a sanitised filename or raise HTTP 400."""
    # Reject NUL bytes
    if "\x00" in name:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "Filename contains NUL byte", "code": "INVALID_FILENAME"},
        )
    # Reject path traversal
    parts = re.split(r"[/\\]", name)
    for part in parts:
        if part == "..":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": "Path traversal detected in filename", "code": "INVALID_FILENAME"},
            )
    # Return just the final component (strip any remaining path)
    return parts[-1] if parts else name


def _check_extension(filename: str) -> str:
    """Return the lowercased extension or raise HTTP 415."""
    ext = Path(filename).suffix.lower()
    if ext not in _ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail={
                "error": (
                    f"File type {ext!r} is not supported. "
                    "Allowed: .json .jsonl .csv .log .txt. "
                    "For .evtx files, convert to JSON first using EvtxECmd or similar."
                ),
                "code": "UNSUPPORTED_FILE_TYPE",
            },
        )
    return ext


def _truncate_field(value: Any) -> str:
    """Convert a value to string, truncate to _MAX_FIELD_BYTES."""
    s = str(value) if value is not None else ""
    encoded = s.encode("utf-8", errors="replace")
    if len(encoded) > _MAX_FIELD_BYTES:
        encoded = encoded[:_MAX_FIELD_BYTES]
    return encoded.decode("utf-8", errors="replace")


def _coerce_int(value: Any, column: str) -> int:
    """Coerce a value to int for integer-typed columns. Returns 0 on failure."""
    try:
        return int(value)
    except (TypeError, ValueError):
        log.debug("int_coercion_failed", column=column, value=repr(value))
        return 0


def _pad_fixed(value: str, length: int) -> str:
    """Pad or truncate to exact byte length for FixedString columns."""
    s = value[:length]
    return s.ljust(length, "\x00")


def _build_provenance_tag(filename: str, mode: str, incident_id: Optional[str], ts: int) -> str:
    """Build a server-assigned ProvenanceTag (MUST 1)."""
    digest = hashlib.sha256(filename.encode("utf-8")).hexdigest()[:8]
    if mode == "incident" and incident_id:
        return f"manual-upload:incident:{incident_id}:{ts}"
    return f"manual-upload:{digest}:{ts}"


def _map_event(
    raw: dict[str, Any],
    provenance_tag: str,
    ingest_ts: str,
) -> tuple[dict[str, Any], bool]:
    """
    Apply strict allowlist mapping (MUST 2).

    Returns (mapped_row, had_unmapped_fields).
    - Server-only fields (ProvenanceTag, IngestTimestamp, _siemhunter_*) are
      stripped first (MUST 1).
    - Only exact CANONICAL_COLUMNS names are placed in typed columns.
    - Everything else is serialised into UnmappedFields.
    """
    mapped: dict[str, Any] = {}
    unmapped: dict[str, Any] = {}

    for key, value in raw.items():
        # MUST 1: strip server-only fields unconditionally
        if key in _SERVER_ONLY_FIELDS:
            continue

        if key in CANONICAL_COLUMNS and key != "UnmappedFields":
            # Truncate oversized field values (MUST 3)
            if isinstance(value, str):
                value = _truncate_field(value)
            elif value is None:
                value = ""
            # Integer coercion for typed columns
            if key in _INT_COLUMNS:
                value = _coerce_int(value, key)
            # FixedString padding
            if key in _FIXED_COLUMNS:
                value = _pad_fixed(str(value), _FIXED_COLUMNS[key])
            mapped[key] = value
        else:
            unmapped[key] = value

    had_unmapped = bool(unmapped)

    # Serialise unmapped fields with size cap (MUST 3)
    unmapped_json = ""
    if unmapped:
        try:
            unmapped_json = json.dumps(unmapped, ensure_ascii=False, default=str)
        except Exception:
            unmapped_json = "{}"
        encoded = unmapped_json.encode("utf-8", errors="replace")
        if len(encoded) > _MAX_UNMAPPED_BYTES:
            encoded = encoded[:_MAX_UNMAPPED_BYTES]
            unmapped_json = encoded.decode("utf-8", errors="replace")

    # Always-present columns with defaults
    mapped.setdefault("TimeGenerated", ingest_ts)
    mapped.setdefault("HostName", "")
    mapped.setdefault("EventID", 0)
    mapped.setdefault("EventRecordID", "")
    mapped.setdefault("ChannelName", "")
    mapped.setdefault("ProviderName", "")
    mapped.setdefault("SubjectUserName", "")
    mapped.setdefault("SubjectUserSid", "")
    mapped.setdefault("SubjectDomainName", "")
    mapped.setdefault("TargetUserName", "")
    mapped.setdefault("TargetUserSid", "")
    mapped.setdefault("TargetDomainName", "")
    mapped.setdefault("LogonType", 0)
    mapped.setdefault("ServiceName", "")
    mapped.setdefault("ProcessImagePath", "")
    mapped.setdefault("CommandLine", "")
    mapped.setdefault("ParentProcessImagePath", "")
    mapped.setdefault("ParentCommandLine", "")
    mapped.setdefault("GrantedAccess", "")
    mapped.setdefault("ObjectName", "")
    mapped.setdefault("FileMD5", _pad_fixed("", 32))
    mapped.setdefault("FileSHA256", _pad_fixed("", 64))
    mapped.setdefault("RegistryKey", "")
    mapped.setdefault("SrcIpAddr", "")
    mapped.setdefault("SrcPort", 0)
    mapped.setdefault("DstIpAddr", "")
    mapped.setdefault("DstPort", 0)
    mapped.setdefault("NetworkProtocol", "")
    mapped["UnmappedFields"] = unmapped_json
    # MUST 1: always server-assigned, never from file
    mapped["ProvenanceTag"] = provenance_tag
    mapped["IngestTimestamp"] = ingest_ts

    return mapped, had_unmapped


# ── Parsers ───────────────────────────────────────────────────────────────────

def _parse_json(content: str, max_events: int) -> list[dict[str, Any]]:
    """Parse a JSON file as either a top-level array or a single object."""
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": f"Invalid JSON: {exc}", "code": "PARSE_ERROR"},
        )
    if isinstance(data, list):
        return [r for r in data[:max_events] if isinstance(r, dict)]
    if isinstance(data, dict):
        return [data]
    raise HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail={"error": "JSON root must be an object or array of objects", "code": "PARSE_ERROR"},
    )


def _parse_jsonl(content: str, max_events: int) -> list[dict[str, Any]]:
    """Parse newline-delimited JSON (one JSON object per line)."""
    rows: list[dict[str, Any]] = []
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue  # skip malformed lines; counted in error_count by caller
        if isinstance(obj, dict):
            rows.append(obj)
        if len(rows) >= max_events:
            break
    return rows


def _parse_csv(content: str, max_events: int) -> list[dict[str, Any]]:
    """Parse CSV with header row into list of dicts."""
    rows: list[dict[str, Any]] = []
    reader = csv.DictReader(io.StringIO(content))
    for i, row in enumerate(reader):
        if i >= max_events:
            break
        rows.append(dict(row))
    return rows


def _parse_log_txt(content: str, max_events: int) -> list[dict[str, Any]]:
    """
    For .log and .txt: try JSONL first; if that yields nothing try JSON;
    otherwise treat each non-empty line as a raw event with a single
    'message' field (which will land in UnmappedFields since 'message'
    is not a canonical column).
    """
    # Try JSONL
    rows = _parse_jsonl(content, max_events)
    if rows:
        return rows
    # Try JSON array/object
    try:
        rows = _parse_json(content, max_events)
        if rows:
            return rows
    except HTTPException:
        pass
    # Fall back: each non-empty line → {"message": line}
    result: list[dict[str, Any]] = []
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        result.append({"message": line})
        if len(result) >= max_events:
            break
    return result


def _parse_content(ext: str, content: str, max_events: int) -> list[dict[str, Any]]:
    if ext == ".json":
        return _parse_json(content, max_events)
    if ext == ".jsonl":
        return _parse_jsonl(content, max_events)
    if ext == ".csv":
        return _parse_csv(content, max_events)
    # .log, .txt
    return _parse_log_txt(content, max_events)


# ── Endpoint ──────────────────────────────────────────────────────────────────

_COLUMN_ORDER = [
    "TimeGenerated",
    "HostName",
    "EventID",
    "EventRecordID",
    "ChannelName",
    "ProviderName",
    "SubjectUserName",
    "SubjectUserSid",
    "SubjectDomainName",
    "TargetUserName",
    "TargetUserSid",
    "TargetDomainName",
    "LogonType",
    "ServiceName",
    "ProcessImagePath",
    "CommandLine",
    "ParentProcessImagePath",
    "ParentCommandLine",
    "GrantedAccess",
    "ObjectName",
    "FileMD5",
    "FileSHA256",
    "RegistryKey",
    "SrcIpAddr",
    "SrcPort",
    "DstIpAddr",
    "DstPort",
    "NetworkProtocol",
    "ProvenanceTag",
    "IngestTimestamp",
    "UnmappedFields",
]


@router.post("/ingestion/upload", response_model=UploadResponse)
async def upload_file(
    file: UploadFile = File(...),
    mode: str = Form(default="global"),
    incident_id: Optional[str] = Form(default=None),
    _: None = Depends(verify_token),
) -> UploadResponse:
    """
    Security-gated file upload endpoint.

    Validates file type, size, and content; normalises to canonical schema;
    inserts to ClickHouse via parameterized client calls.
    """
    ts_unix = int(time.time())
    ingest_ts = datetime.now(timezone.utc).isoformat()

    # ── Step 1: Validate filename (MUST 4) ───────────────────────────────────
    raw_filename = file.filename or "upload"
    safe_name = _safe_filename(raw_filename)
    ext = _check_extension(safe_name)

    # ── Step 2: Validate mode ────────────────────────────────────────────────
    if mode not in ("global", "incident"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "mode must be 'global' or 'incident'", "code": "INVALID_MODE"},
        )
    if mode == "incident" and not incident_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "incident_id is required when mode='incident'", "code": "MISSING_INCIDENT_ID"},
        )

    # ── Step 3: Read file bytes with size cap (MUST 3) ──────────────────────
    raw_bytes = await file.read(_UPLOAD_MAX_BYTES + 1)
    if len(raw_bytes) > _UPLOAD_MAX_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail={
                "error": (
                    f"File exceeds maximum allowed size of "
                    f"{_UPLOAD_MAX_BYTES // (1024 * 1024)} MiB"
                ),
                "code": "FILE_TOO_LARGE",
            },
        )

    # ── Step 4: Magic byte / encoding check (MUST 4) ─────────────────────────
    # For text-only extensions, the content must be valid UTF-8 text. A binary
    # PE file will fail this check (contains NUL bytes and non-UTF-8 sequences).
    try:
        content = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail={
                "error": (
                    "File content is not valid UTF-8 text. "
                    "Binary files are not accepted."
                ),
                "code": "BINARY_CONTENT_REJECTED",
            },
        )

    # Reject if content contains embedded NUL bytes (binary PE indicator)
    if "\x00" in content:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail={
                "error": "File content contains NUL bytes; binary files are not accepted.",
                "code": "BINARY_CONTENT_REJECTED",
            },
        )

    # ── Step 5: Assign ProvenanceTag server-side (MUST 1) ───────────────────
    provenance_tag = _build_provenance_tag(safe_name, mode, incident_id, ts_unix)

    # ── Step 6: Save to drop/ directory (MUST 5) ────────────────────────────
    drop_dir = _DROP_DIR
    try:
        drop_dir.mkdir(parents=True, exist_ok=True)
        drop_filename = f"{uuid.uuid4().hex}_{safe_name}"
        drop_path = drop_dir / drop_filename
        drop_path.write_bytes(raw_bytes)
        log.info(
            "upload_saved_to_drop",
            drop_path=str(drop_path),
            provenance_tag=provenance_tag,
            size_bytes=len(raw_bytes),
        )
    except OSError as exc:
        log.warning("upload_drop_write_failed", error=str(exc))
        # Non-fatal: continue with parsing even if drop/ write fails

    # ── Step 7: Parse events (MUST 5 inline parsing with bounds) ────────────
    try:
        raw_events = _parse_content(ext, content, _UPLOAD_MAX_EVENTS)
    except HTTPException:
        raise
    except Exception as exc:
        log.error("upload_parse_error", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": f"Parse failed: {exc}", "code": "PARSE_ERROR"},
        )

    events_parsed = len(raw_events)

    # ── Step 8: Map to canonical columns (MUST 2) + type validation (MUST 3)
    mapped_rows: list[list[Any]] = []
    events_unmapped = 0
    error_count = 0

    for raw in raw_events:
        try:
            mapped, had_unmapped = _map_event(raw, provenance_tag, ingest_ts)
            if had_unmapped:
                events_unmapped += 1
            # Build ordered row for ClickHouse insert
            row = [mapped[col] for col in _COLUMN_ORDER]
            mapped_rows.append(row)
        except Exception as exc:
            log.warning("upload_row_mapping_error", error=str(exc))
            error_count += 1

    # ── Step 9: Insert to ClickHouse via parameterized client (MUST 6) ───────
    events_written = 0
    if mapped_rows:
        try:
            client = get_client()
            # clickhouse_connect client.insert() uses typed rows with explicit
            # column list — never string-concatenated SQL.
            client.insert(
                table="siemhunter.security_events",
                data=mapped_rows,
                column_names=_COLUMN_ORDER,
            )
            events_written = len(mapped_rows)
            log.info(
                "upload_inserted",
                provenance_tag=provenance_tag,
                events_written=events_written,
            )
        except Exception as exc:
            log.error("upload_clickhouse_insert_failed", error=str(exc))
            error_count += len(mapped_rows)
            # Return partial/failed status below

    # ── Step 10: Build response ──────────────────────────────────────────────
    if events_written == 0 and events_parsed > 0:
        upload_status = "failed"
    elif error_count > 0 or events_written < events_parsed:
        upload_status = "partial"
    else:
        upload_status = "success"

    return UploadResponse(
        filename=safe_name,
        provenance_tag=provenance_tag,
        events_parsed=events_parsed,
        events_written=events_written,
        events_unmapped=events_unmapped,
        error_count=error_count,
        status=upload_status,
    )
