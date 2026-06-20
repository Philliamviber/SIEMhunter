"""
GET /v1/ai/summary — Claude AI narrative summary of pipeline health.

What is sent to Claude:
  Aggregated statistics bundle ONLY — counts, labels, numeric scores.
  NEVER row-level event content. NEVER CommandLine, HostName, UserName, IPs, etc.
  The bundle is numbers and labels only (see _build_stats_bundle).

Claude API:
  - Model: claude-opus-4-8
  - API key: read at call time from Docker secret /run/secrets/anthropic_api_key
  - SDK: official `anthropic` Python package (must be in requirements.txt)
  - If the secret is missing/empty → 503 AI_UNAVAILABLE (does NOT crash at import)
  - On any API failure → 503 AI_UNAVAILABLE (key never logged/leaked)

Caching:
  Module-level dict keyed on MAX(detection_hits.created_at).
  A new batch (newer max timestamp) invalidates the cache automatically.
  Cache is in-process only; resets on container restart.

Authentication: required (bearer token).
"""
from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from ..auth import verify_token
from ..clickhouse_client import get_client

log = structlog.get_logger(__name__)
router = APIRouter()

_ANTHROPIC_SECRET_PATH = "/run/secrets/anthropic_api_key"
_MODEL = "claude-opus-4-8"
_MAX_TOKENS = 1024
_DISCLAIMER = "ML scores are advisory only; not a replacement for analyst review"

_SYSTEM_PROMPT = (
    "You are a security operations analyst assistant. "
    "You will be given a JSON bundle of aggregated statistics from a local SIEM pipeline. "
    "The data contains only counts, percentages, severity labels, and rule names — "
    "no raw events, no user data, no hostnames, no IP addresses. "
    "Produce a concise security posture summary with:\n"
    "1. A narrative paragraph of 3–5 sentences describing the overall security posture.\n"
    "2. A list of 3–5 notable items that an analyst should pay attention to.\n"
    "Respond with a JSON object: "
    '{"narrative": "<string>", "notable_items": ["<string>", ...]}'
)


# ── In-memory cache ───────────────────────────────────────────────────────────

_cache: dict[str, "AISummaryResponse"] = {}   # keyed on batch marker ISO string


# ── Response models ───────────────────────────────────────────────────────────

class AISummaryResponse(BaseModel):
    narrative: str
    notable_items: list[str]
    disclaimer: str
    source_window: str      # human-readable description of the data window covered
    generated_at: str       # ISO-8601 UTC


# ── Helpers ───────────────────────────────────────────────────────────────────

def _read_api_key() -> str:
    """Read the Anthropic API key from the Docker secret. Raises on missing/empty."""
    try:
        val = Path(_ANTHROPIC_SECRET_PATH).read_text().strip()
    except OSError as exc:
        raise RuntimeError(f"Anthropic API key secret not found: {exc}") from exc
    if not val:
        raise RuntimeError("Anthropic API key secret is present but empty")
    return val


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _to_iso_safe(val) -> Optional[str]:
    if val is None:
        return None
    if isinstance(val, datetime):
        if val.tzinfo is None:
            val = val.replace(tzinfo=timezone.utc)
        return val.isoformat()
    return str(val)


def _build_stats_bundle(client) -> tuple[dict, str]:
    """
    Build an aggregated-stats-only bundle from local ClickHouse.
    Returns (bundle_dict, batch_marker_iso).
    NEVER includes row-level event content.
    """
    # ── Event counts by provenance (24h + 7d) ─────────────────────────────
    prov_24h_rows = client.query(
        """
        SELECT ProvenanceTag, count() AS cnt
        FROM siemhunter.security_events
        WHERE TimeGenerated >= now64(3) - INTERVAL 24 HOUR
        GROUP BY ProvenanceTag
        ORDER BY cnt DESC
        LIMIT 20
        """,
    ).result_rows
    events_24h_by_source = {str(r[0]): int(r[1]) for r in prov_24h_rows}

    prov_7d_rows = client.query(
        """
        SELECT ProvenanceTag, count() AS cnt
        FROM siemhunter.security_events
        WHERE TimeGenerated >= now64(3) - INTERVAL 7 DAY
        GROUP BY ProvenanceTag
        ORDER BY cnt DESC
        LIMIT 20
        """,
    ).result_rows
    events_7d_by_source = {str(r[0]): int(r[1]) for r in prov_7d_rows}

    # ── Top detection hits by severity + rule (24h) ────────────────────────
    hit_rows = client.query(
        """
        SELECT rule_id, severity, count() AS cnt, max(anomaly_score) AS max_score
        FROM siemhunter.detection_hits
        WHERE created_at >= now64(3) - INTERVAL 24 HOUR
        GROUP BY rule_id, severity
        ORDER BY cnt DESC
        LIMIT 20
        """,
    ).result_rows
    top_hits_24h = [
        {
            "rule_id": str(r[0]),
            "severity": str(r[1]),
            "hit_count": int(r[2]),
            "max_anomaly_score": round(float(r[3]), 4),
        }
        for r in hit_rows
    ]

    # ── Anomaly score percentiles (p95 + p99) over last 24h ───────────────
    score_rows = client.query(
        """
        SELECT
            quantile(0.95)(anomaly_score) AS p95,
            quantile(0.99)(anomaly_score) AS p99
        FROM siemhunter.detection_hits
        WHERE created_at >= now64(3) - INTERVAL 24 HOUR
          AND anomaly_score > 0
        """,
    ).result_rows
    if score_rows and score_rows[0][0] is not None:
        anomaly_p95 = round(float(score_rows[0][0]), 4)
        anomaly_p99 = round(float(score_rows[0][1]), 4)
    else:
        anomaly_p95 = None
        anomaly_p99 = None

    # ── Forward ledger local counts ────────────────────────────────────────
    ledger_rows = client.query(
        """
        SELECT stream_tag, sum(event_count) AS total
        FROM siemhunter.forward_ledger
        WHERE forwarded_at >= now64(3) - INTERVAL 24 HOUR
        GROUP BY stream_tag
        ORDER BY stream_tag
        """,
    ).result_rows
    forward_ledger_24h = {str(r[0]): int(r[1]) for r in ledger_rows}

    # ── Batch marker: MAX(created_at) from detection_hits ─────────────────
    max_rows = client.query(
        "SELECT MAX(created_at) FROM siemhunter.detection_hits",
    ).result_rows
    batch_marker_iso = _to_iso_safe(max_rows[0][0] if max_rows else None) or ""

    # ── Severity breakdown (24h) ───────────────────────────────────────────
    sev_rows = client.query(
        """
        SELECT severity, count() AS cnt
        FROM siemhunter.detection_hits
        WHERE created_at >= now64(3) - INTERVAL 24 HOUR
        GROUP BY severity
        ORDER BY cnt DESC
        """,
    ).result_rows
    severity_breakdown_24h = {str(r[0]): int(r[1]) for r in sev_rows}

    bundle = {
        "window": {
            "last_24h": "last 24 hours",
            "last_7d": "last 7 days",
            "batch_marker": batch_marker_iso,
        },
        "events": {
            "by_source_24h": events_24h_by_source,
            "by_source_7d": events_7d_by_source,
        },
        "detections": {
            "severity_breakdown_24h": severity_breakdown_24h,
            "top_hits_24h": top_hits_24h,
            "anomaly_score_p95": anomaly_p95,
            "anomaly_score_p99": anomaly_p99,
        },
        "forwarding": {
            "ledger_counts_24h": forward_ledger_24h,
            "sentinel_delta_note": (
                "Sentinel-side ledger reconciliation (SELF-005) is not locally "
                "available; see SIEMHunterHealth_CL for the delta."
            ),
        },
    }
    return bundle, batch_marker_iso


def _call_claude(api_key: str, bundle: dict) -> tuple[str, list[str]]:
    """
    Call the Anthropic Messages API with the aggregated bundle.
    Returns (narrative, notable_items).
    Raises RuntimeError on failure (caller maps to 503; key never logged).
    """
    try:
        import anthropic as _anthropic
    except ImportError:
        raise RuntimeError(
            "The 'anthropic' package is not installed. "
            "Add it to services/api/requirements.txt."
        )

    try:
        anth_client = _anthropic.Anthropic(api_key=api_key)
        message = anth_client.messages.create(
            model=_MODEL,
            max_tokens=_MAX_TOKENS,
            system=_SYSTEM_PROMPT,
            messages=[
                {
                    "role": "user",
                    "content": json.dumps(bundle, indent=2),
                }
            ],
        )
    except Exception as exc:
        # Log the error class and message but NEVER include the api_key
        log.error(
            "anthropic_api_call_failed",
            error_type=type(exc).__name__,
            error=str(exc)[:300],   # truncate; no key in str(exc) but be safe
        )
        raise RuntimeError("Anthropic API call failed") from exc

    # Parse the JSON response the model was instructed to produce
    raw_text = message.content[0].text if message.content else ""
    try:
        # Strip markdown fences if the model wrapped them
        text = raw_text.strip()
        if text.startswith("```"):
            lines = text.splitlines()
            text = "\n".join(
                line for line in lines
                if not line.startswith("```")
            ).strip()
        parsed = json.loads(text)
        narrative = str(parsed.get("narrative", ""))
        notable_items = [str(x) for x in parsed.get("notable_items", [])]
    except (json.JSONDecodeError, AttributeError, IndexError):
        # Fallback: use raw text as narrative, empty notable list
        log.warning("ai_summary_parse_fallback", raw_len=len(raw_text))
        narrative = raw_text
        notable_items = []

    return narrative, notable_items


# ── Endpoint ──────────────────────────────────────────────────────────────────

@router.get("/ai/summary", response_model=AISummaryResponse)
async def ai_summary(
    _: None = Depends(verify_token),
) -> AISummaryResponse:
    """
    Return a Claude-generated narrative summary of the current pipeline security posture.

    The request to Claude contains aggregated statistics only (counts, severity labels,
    rule IDs, numeric scores). Raw events are never sent.

    Result is cached per batch cycle (keyed on MAX detection_hits.created_at).
    """
    # ── Step 1: Read API key at call time (not at import) ──────────────────
    try:
        api_key = _read_api_key()
    except RuntimeError as exc:
        log.warning("ai_summary_key_unavailable", reason=str(exc))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "AI summary unavailable: Anthropic API key not configured",
                "code": "AI_UNAVAILABLE",
            },
        )

    # ── Step 2: Build stats bundle from ClickHouse ─────────────────────────
    try:
        client = get_client()
        bundle, batch_marker = _build_stats_bundle(client)
    except Exception as exc:
        log.error("ai_summary_bundle_build_failed", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "ClickHouse query failed", "code": "QUERY_ERROR"},
        )

    # ── Step 3: Check in-memory cache ─────────────────────────────────────
    if batch_marker and batch_marker in _cache:
        log.debug("ai_summary_cache_hit", batch_marker=batch_marker)
        return _cache[batch_marker]

    # ── Step 4: Call Claude ────────────────────────────────────────────────
    try:
        narrative, notable_items = _call_claude(api_key, bundle)
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "AI summary generation failed",
                "code": "AI_UNAVAILABLE",
            },
        )

    generated_at = _now_iso()
    source_window = (
        f"Last 24 hours (batch marker: {batch_marker})" if batch_marker
        else "Last 24 hours (no batch data yet)"
    )

    result = AISummaryResponse(
        narrative=narrative,
        notable_items=notable_items,
        disclaimer=_DISCLAIMER,
        source_window=source_window,
        generated_at=generated_at,
    )

    # ── Step 5: Store in cache, evict old entries ──────────────────────────
    if batch_marker:
        # Keep only the current batch; discard any stale entries
        _cache.clear()
        _cache[batch_marker] = result
        log.info("ai_summary_cached", batch_marker=batch_marker)

    return result
