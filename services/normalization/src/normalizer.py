"""
OCSF normalization layer.
Spec: instructions/04-normalization-and-schema.md

Rules:
- Every byte of ingest payload is treated as hostile input (NFR-05).
- All ClickHouse inserts use parameterized queries (NFR-05).
- ProvenanceTag and IngestTimestamp are collector-assigned and never overridden
  by event content.
- EventID is coerced to UInt32; non-numeric values become 0 with a logged warning.
"""
from __future__ import annotations
import hashlib
import json
import os
import re
import time
from datetime import datetime, timezone
from typing import Any

import structlog

from .schema import NormalizedEvent, CHANNEL_TO_OCSF_CLASS, EVENTID_CLASS_OVERRIDES

log = structlog.get_logger(__name__)

_RATE_LIMIT = int(os.environ.get("RATE_LIMIT_EVENTS_PER_MIN", "10000"))
_PARSE_TIMEOUT = float(os.environ.get("PARSE_TIMEOUT_SECONDS", "5"))

# Per-source event counters for rate limiting (reset every 60s)
_rate_counters: dict[str, int] = {}
_rate_window_start: float = time.monotonic()

# Allowed ObjectName patterns for DCSync detection (see windows-ad-003 filter note)
_DC_PATTERN = re.compile(r"DC=", re.IGNORECASE)


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def _coerce_event_id(raw: Any) -> int:
    """Coerce EventID to UInt32. Non-numeric values become 0 per spec §3."""
    try:
        val = int(raw)
        if 0 <= val <= 4294967295:
            return val
        log.warning("eventid_out_of_range", raw=raw)
        return 0
    except (TypeError, ValueError):
        log.warning("eventid_not_numeric", raw=raw)
        return 0


def _coerce_uint16(raw: Any) -> int:
    try:
        val = int(raw)
        return max(0, min(65535, val))
    except (TypeError, ValueError):
        return 0


def _coerce_uint8(raw: Any) -> int:
    try:
        val = int(raw)
        return max(0, min(255, val))
    except (TypeError, ValueError):
        return 0


def _stable_record_id(provenance_tag: str, raw_event: dict) -> str:
    """Deterministic EventRecordID per FR-18.

    Prefer the source's own record ID if present; otherwise derive from
    provenance + content hash so the ID survives normalization.
    """
    source_id = raw_event.get("EventRecordID") or raw_event.get("record_id") or ""
    if source_id:
        return f"{provenance_tag}:{source_id}"
    content = f"{provenance_tag}:{json.dumps(raw_event, sort_keys=True)}"
    return hashlib.sha256(content.encode()).hexdigest()


def _check_rate_limit(provenance_tag: str) -> bool:
    """Return True if this event should be accepted; False if rate-limited."""
    global _rate_window_start, _rate_counters
    now = time.monotonic()
    if now - _rate_window_start > 60:
        _rate_counters = {}
        _rate_window_start = now

    tag_prefix = provenance_tag.split(":")[0]
    _rate_counters[tag_prefix] = _rate_counters.get(tag_prefix, 0) + 1
    if _rate_counters[tag_prefix] > _RATE_LIMIT:
        log.warning("rate_limit_exceeded", provenance_tag=provenance_tag,
                    count=_rate_counters[tag_prefix], limit=_RATE_LIMIT)
        return False
    return True


def _extract_unmapped(raw: dict, mapped_keys: set[str]) -> str:
    unmapped = {k: v for k, v in raw.items() if k not in mapped_keys}
    if not unmapped:
        return ""
    try:
        return json.dumps(unmapped, default=str)
    except Exception:
        return "{}"


def normalize_windows_event(raw: dict, provenance_tag: str, ingest_ts: str) -> NormalizedEvent:
    """Normalize a Windows Event Log record to OCSF / security_events schema."""
    mapped = {
        "EventID", "EventRecordID", "Computer", "SubjectUserName", "SubjectUserSid",
        "SubjectDomainName", "TargetUserName", "TargetUserSid", "TargetDomainName",
        "LogonType", "ServiceName", "Image", "CommandLine", "ParentImage",
        "ParentCommandLine", "GrantedAccess", "TargetObject", "ObjectName",
        "TimeCreated", "Channel", "Provider", "IpAddress", "IpPort",
        "DestAddress", "DestPort", "Protocol", "Hashes",
    }

    event_id = _coerce_event_id(raw.get("EventID", raw.get("event_id", 0)))
    channel = raw.get("Channel", raw.get("channel", ""))

    # Resolve TimeGenerated from event timestamp or fall back to IngestTimestamp
    time_created = raw.get("TimeCreated", raw.get("time_created", ""))
    if not time_created:
        time_created = ingest_ts

    # Extract hash fields from Sysmon Hashes= string (format: MD5=...,SHA256=...)
    file_md5 = ""
    file_sha256 = ""
    hashes_raw = raw.get("Hashes", "")
    if hashes_raw:
        for part in str(hashes_raw).split(","):
            part = part.strip()
            if part.upper().startswith("MD5="):
                file_md5 = part[4:].lower()[:32]
            elif part.upper().startswith("SHA256="):
                file_sha256 = part[7:].lower()[:64]

    return NormalizedEvent(
        TimeGenerated=str(time_created),
        HostName=str(raw.get("Computer", raw.get("hostname", ""))),
        EventID=event_id,
        EventRecordID=_stable_record_id(provenance_tag, raw),
        ChannelName=channel,
        ProviderName=str(raw.get("Provider", "")),
        SubjectUserName=str(raw.get("SubjectUserName", "")),
        SubjectUserSid=str(raw.get("SubjectUserSid", "")),
        SubjectDomainName=str(raw.get("SubjectDomainName", "")),
        TargetUserName=str(raw.get("TargetUserName", "")),
        TargetUserSid=str(raw.get("TargetUserSid", "")),
        TargetDomainName=str(raw.get("TargetDomainName", "")),
        LogonType=_coerce_uint8(raw.get("LogonType", 0)),
        ServiceName=str(raw.get("ServiceName", "")),
        ProcessImagePath=str(raw.get("Image", "")),
        CommandLine=str(raw.get("CommandLine", "")),
        ParentProcessImagePath=str(raw.get("ParentImage", "")),
        ParentCommandLine=str(raw.get("ParentCommandLine", "")),
        GrantedAccess=str(raw.get("GrantedAccess", "")),
        ObjectName=str(raw.get("ObjectName", "")),
        FileMD5=file_md5,
        FileSHA256=file_sha256,
        RegistryKey=str(raw.get("TargetObject", "")),
        SrcIpAddr=str(raw.get("IpAddress", "")),
        SrcPort=_coerce_uint16(raw.get("IpPort", 0)),
        DstIpAddr=str(raw.get("DestAddress", "")),
        DstPort=_coerce_uint16(raw.get("DestPort", 0)),
        NetworkProtocol=str(raw.get("Protocol", "")).lower(),
        ProvenanceTag=provenance_tag,
        IngestTimestamp=ingest_ts,
        UnmappedFields=_extract_unmapped(raw, mapped),
    )


def normalize_syslog(raw: dict, provenance_tag: str, ingest_ts: str) -> NormalizedEvent:
    """Normalize a syslog event (RFC 3164/5424)."""
    # Syslog events map to OCSF Network Activity (4001) / ASimNetworkSession
    mapped = {"message", "hostname", "appname", "procid", "msgid", "timestamp",
              "facility", "severity", "src_ip", "dst_ip", "src_port", "dst_port", "proto"}

    src_ip = str(raw.get("host", raw.get("src_ip", "")))
    return NormalizedEvent(
        TimeGenerated=str(raw.get("timestamp", ingest_ts)),
        HostName=str(raw.get("hostname", "")),
        EventID=0,
        EventRecordID=_stable_record_id(provenance_tag, raw),
        ChannelName="Syslog",
        ProviderName=str(raw.get("appname", "")),
        SrcIpAddr=src_ip,
        SrcPort=_coerce_uint16(raw.get("src_port", 0)),
        DstIpAddr=str(raw.get("dst_ip", "")),
        DstPort=_coerce_uint16(raw.get("dst_port", 0)),
        NetworkProtocol="",
        CommandLine=str(raw.get("message", "")),
        ProvenanceTag=provenance_tag,
        IngestTimestamp=ingest_ts,
        UnmappedFields=_extract_unmapped(raw, mapped),
    )


def normalize_netflow(raw: dict, provenance_tag: str, ingest_ts: str) -> NormalizedEvent:
    """Normalize a Netflow/IPFIX record to OCSF Network Activity (4001)."""
    mapped = {"timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
              "proto", "bytes", "pkts", "duration"}

    proto_num = int(raw.get("proto", 0))
    proto_map = {6: "tcp", 17: "udp", 1: "icmp"}
    proto_name = proto_map.get(proto_num, str(proto_num))

    return NormalizedEvent(
        TimeGenerated=str(raw.get("timestamp", ingest_ts)),
        HostName=str(raw.get("exporter", "")),
        EventID=0,
        EventRecordID=_stable_record_id(provenance_tag, raw),
        ChannelName="Netflow",
        ProviderName="softflowd",
        SrcIpAddr=str(raw.get("src_ip", "")),
        SrcPort=_coerce_uint16(raw.get("src_port", 0)),
        DstIpAddr=str(raw.get("dst_ip", "")),
        DstPort=_coerce_uint16(raw.get("dst_port", 0)),
        NetworkProtocol=proto_name,
        ProvenanceTag=provenance_tag,
        IngestTimestamp=ingest_ts,
        UnmappedFields=_extract_unmapped(raw, mapped),
    )


def normalize_forensic(raw: dict, provenance_tag: str, ingest_ts: str) -> NormalizedEvent:
    """Normalize a forensic artifact record (Velociraptor/Volatility JSON)."""
    return NormalizedEvent(
        TimeGenerated=str(raw.get("timestamp", raw.get("TimeCreated", ingest_ts))),
        HostName=str(raw.get("hostname", raw.get("Computer", ""))),
        EventID=_coerce_event_id(raw.get("EventID", 0)),
        EventRecordID=_stable_record_id(provenance_tag, raw),
        ChannelName="ForensicArtifact",
        ProviderName=str(raw.get("tool", raw.get("Provider", ""))),
        CommandLine=str(raw.get("CommandLine", raw.get("cmdline", ""))),
        ProcessImagePath=str(raw.get("Image", raw.get("image_path", ""))),
        ProvenanceTag=provenance_tag,
        IngestTimestamp=ingest_ts,
        UnmappedFields=json.dumps({k: v for k, v in raw.items()
                                    if k not in {"timestamp", "TimeCreated", "hostname",
                                                 "Computer", "EventID", "tool", "Provider",
                                                 "CommandLine", "cmdline", "Image", "image_path"}},
                                   default=str) if raw else "",
    )


def dispatch(raw: dict, provenance_tag: str) -> NormalizedEvent | None:
    """Route a raw event to the correct normalizer and apply pre-checks.

    Returns None if the event should be dropped (rate limit, parse error).
    """
    ingest_ts = _now_utc()

    if not _check_rate_limit(provenance_tag):
        return None

    tag_prefix = provenance_tag.split(":")[0]
    try:
        if tag_prefix == "syslog":
            return normalize_syslog(raw, provenance_tag, ingest_ts)
        elif tag_prefix == "wef":
            return normalize_windows_event(raw, provenance_tag, ingest_ts)
        elif tag_prefix == "forensic":
            return normalize_forensic(raw, provenance_tag, ingest_ts)
        elif tag_prefix in ("netflow", "ipfix"):
            return normalize_netflow(raw, provenance_tag, ingest_ts)
        else:
            # Unknown provenance: attempt Windows event normalization as default
            return normalize_windows_event(raw, provenance_tag, ingest_ts)
    except Exception as exc:
        log.error("parse_error", provenance_tag=provenance_tag, error=str(exc))
        return None
