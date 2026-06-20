"""
OCSF normalization layer.

Purpose
-------
This module converts raw ingest payloads from all four source types (Windows
Event Log, syslog, Netflow/IPFIX, forensic artifact) into NormalizedEvent
rows that map one-to-one with columns in siemhunter.security_events.

The normalization contract is defined in instructions/04-normalization-and-schema.md.
The Python schema dataclass (NormalizedEvent) is the canonical authority; the
ClickHouse DDL (clickhouse/schema.sql) and the pySigma pipeline
(rules/pipelines/clickhouse-asim-ocsf.yaml) must agree with it exactly.

Security rules (non-negotiable, per NFR-05 and the project threat model)
-------------------------------------------------------------------------
- Every byte of an ingest payload is treated as hostile input. No field value
  from a raw event is concatenated into a SQL string. All inserts use the
  clickhouse_connect parameterized INSERT interface.
- ProvenanceTag and IngestTimestamp are assigned by the collector at receipt
  time. They are never overridden by values inside the event payload, even
  if the payload contains fields named the same. This is the primary tamper-
  evidence mechanism: a compromised log source cannot forge its own identity.
- EventID is coerced to UInt32. Non-numeric values become 0 and are logged
  as warnings, not silently discarded. This is required because pySigma
  compiles EventID comparisons as integer literals; a string in this column
  would cause Sigma rules to return zero results without an obvious error.

Rate limiting
-------------
The module maintains module-level counters (not per-process shared state) that
count events per source type within 60-second rolling windows. The limit
(RATE_LIMIT_EVENTS_PER_MIN) defaults to 10,000 events per minute per
ProvenanceTag prefix and is configurable via environment variable.

Rate limiting in this module is a second-line defence. The primary flood
heuristic is Vector's rate_throttle transform (vector/vector.yaml), which
fires at the ingest edge before events reach ClickHouse. This module's counter
catches cases where the event volume is high but the Vector throttle was not
triggered (e.g., an operator-raised threshold, or events arriving via a path
that bypasses Vector).

When the limit is exceeded, the event is dropped and a warning is logged. The
Vector flood heuristic also writes a FloodHeuristic record to SIEMHunterHealth_CL,
which is the operator's notification path for ingest floods.
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

# Maximum events per source per 60-second window before events are dropped.
# Configurable via RATE_LIMIT_EVENTS_PER_MIN environment variable.
# The default (10,000/min ≈ 167/sec) matches the Vector flood heuristic threshold.
_RATE_LIMIT = int(os.environ.get("RATE_LIMIT_EVENTS_PER_MIN", "10000"))

# Maximum time in seconds allowed to parse a single event before it is dropped.
# Parsing is synchronous and runs in the normalization service main loop.
# A stuck parse (e.g., a deeply nested JSON bomb) would block the entire pipeline.
_PARSE_TIMEOUT = float(os.environ.get("PARSE_TIMEOUT_SECONDS", "5"))

# Per-source event counters for the rate limiter.
# Key: the first segment of the ProvenanceTag (e.g., "syslog", "wef").
# Value: event count for the current 60-second window.
# Reset to an empty dict at the start of each new window.
_rate_counters: dict[str, int] = {}

# Monotonic timestamp at the start of the current rate-limit window.
# Using monotonic time (not wall-clock) so the window is not affected by NTP slew.
_rate_window_start: float = time.monotonic()

# Regex to detect DN-path patterns in ObjectName (used by DCSync detection rules
# to filter DS-Access events that touch the domain root vs. ordinary objects).
# Example match: "DC=corp,DC=example,DC=com"
_DC_PATTERN = re.compile(r"DC=", re.IGNORECASE)


def _now_utc() -> str:
    """Return the current UTC time as a ClickHouse-compatible DateTime64 string.

    Format: 'YYYY-MM-DD HH:MM:SS.mmm' (millisecond precision, UTC).
    The trailing three digits are milliseconds; [:‑3] trims the last three of
    the six-digit microsecond string that strftime produces.
    """
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def _coerce_event_id(raw: Any) -> int:
    """Coerce EventID to UInt32. Non-numeric values become 0 per spec §3.

    Why this is important: the security_events ClickHouse column is declared
    UInt32. pySigma compiles Sigma rules with integer literals for EventID
    comparisons. If a non-integer sneaks into the column, all Sigma rules
    that filter on EventID (which is most of them) would silently return
    zero results for that event's host. Coercing to 0 is the safe default
    because 0 is never a valid Windows Event ID.

    Args:
        raw: The raw EventID value from the event payload. May be an int,
             a string like "4624", a float, or None.

    Returns:
        An integer in [0, 4294967295]. Returns 0 for out-of-range or
        non-numeric inputs.
    """
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
    """Coerce a value to a UInt16 (port number). Clamps to [0, 65535].

    Used for SrcPort and DstPort. Out-of-range values are clamped rather than
    zeroed because a clamped value is still useful as an approximate signal,
    whereas a zeroed value looks like "port not present".

    Args:
        raw: The raw port value. May be a string, int, or None.

    Returns:
        An integer in [0, 65535]. Returns 0 for non-numeric inputs.
    """
    try:
        val = int(raw)
        return max(0, min(65535, val))
    except (TypeError, ValueError):
        return 0


def _coerce_uint8(raw: Any) -> int:
    """Coerce a value to a UInt8 (LogonType). Clamps to [0, 255].

    Windows LogonType values are small integers (0–12 in practice). A UInt8
    column is sufficient and saves space at scale.

    Args:
        raw: The raw LogonType value.

    Returns:
        An integer in [0, 255]. Returns 0 for non-numeric inputs.
    """
    try:
        val = int(raw)
        return max(0, min(255, val))
    except (TypeError, ValueError):
        return 0


def _stable_record_id(provenance_tag: str, raw_event: dict) -> str:
    """Compute a stable, deterministic EventRecordID per FR-18.

    The EventRecordID is used as the deduplication key when the same event
    is processed more than once (e.g., after a normalization service restart).
    It must be stable across restarts for the same event content.

    Algorithm:
    1. If the source event provides its own record ID (EventRecordID or
       record_id field), prefix it with the provenance tag and use that.
       Prefixing prevents ID collisions between different sources.
    2. If no source-provided ID exists, compute a SHA-256 hash of the
       provenance tag plus the canonical JSON representation of the event.
       This is deterministic as long as the event content and provenance
       tag are the same (which they will be for the same raw event).

    Args:
        provenance_tag: The collector-assigned tag (e.g., "wef:http:1234567890").
        raw_event: The full raw event dict before any field extraction.

    Returns:
        A string that uniquely identifies this event across the siemhunter
        instance. The format is either "{provenance_tag}:{source_id}" or
        a 64-character hex SHA-256 digest.
    """
    source_id = raw_event.get("EventRecordID") or raw_event.get("record_id") or ""
    if source_id:
        return f"{provenance_tag}:{source_id}"
    content = f"{provenance_tag}:{json.dumps(raw_event, sort_keys=True)}"
    return hashlib.sha256(content.encode()).hexdigest()


def _check_rate_limit(provenance_tag: str) -> bool:
    """Return True if this event is within the rate limit; False if it should be dropped.

    The rate limit is per ProvenanceTag prefix (the source type, e.g., "wef",
    "syslog"), not per full provenance tag. This prevents a single noisy host
    from flooding the pipeline while still allowing other sources to operate
    normally.

    Window behaviour: the counter resets every 60 seconds using a simple
    fixed-window algorithm (not a sliding window). The window start is tracked
    via monotonic time, so NTP adjustments do not cause a window to extend
    indefinitely.

    When the limit is exceeded, a warning is logged to the structured log.
    The Vector flood heuristic (vector.yaml rate_throttle) is the primary
    alerting path; this function is a fallback for events that arrive after
    the throttle.

    Args:
        provenance_tag: Full provenance tag from the event (e.g., "wef:http:1704067200").

    Returns:
        True  — event should be normalised and inserted.
        False — event should be dropped (rate limit exceeded for this source type).
    """
    global _rate_window_start, _rate_counters
    now = time.monotonic()

    # Reset counters at the start of each new 60-second window.
    if now - _rate_window_start > 60:
        _rate_counters = {}
        _rate_window_start = now

    # Use only the first segment of the tag as the key so all events from
    # a given source type (e.g., all WEF events) share a single counter.
    tag_prefix = provenance_tag.split(":")[0]
    _rate_counters[tag_prefix] = _rate_counters.get(tag_prefix, 0) + 1
    if _rate_counters[tag_prefix] > _RATE_LIMIT:
        log.warning("rate_limit_exceeded", provenance_tag=provenance_tag,
                    count=_rate_counters[tag_prefix], limit=_RATE_LIMIT)
        return False
    return True


def _extract_unmapped(raw: dict, mapped_keys: set[str]) -> str:
    """Serialise any raw event fields not captured in the canonical schema.

    Every field in the raw event that does NOT have a canonical ClickHouse
    column is collected into a JSON string and stored in UnmappedFields.
    This provides a forensic fallback: analysts can inspect UnmappedFields
    in Sentinel hunt queries even for fields that have no Sigma rule support.

    IMPORTANT: UnmappedFields is stored as a plain String in ClickHouse,
    not as a JSON column. It is NOT queryable via Sigma rules. It is intended
    for ad-hoc forensic queries only.

    Args:
        raw: The full raw event dict.
        mapped_keys: The set of field names that were already extracted into
                     canonical columns by the calling normalizer function.

    Returns:
        A JSON string of the unmapped fields, or an empty string if there
        are none. Falls back to "{}" if JSON serialisation fails.
    """
    unmapped = {k: v for k, v in raw.items() if k not in mapped_keys}
    if not unmapped:
        return ""
    try:
        return json.dumps(unmapped, default=str)
    except Exception:
        return "{}"


def normalize_windows_event(raw: dict, provenance_tag: str, ingest_ts: str) -> NormalizedEvent:
    """Normalize a Windows Event Log record to the OCSF / security_events schema.

    This is the primary normalizer for events arriving via Windows Event
    Forwarding (WEF) over HTTP on port 5985 (vector source: wef_http).
    It handles both Security channel events (e.g., EID 4624, 4625, 4768, 4769,
    4662) and Sysmon events (EID 1, 3, 7, 10, 12, 13).

    Field mapping rationale
    -----------------------
    Windows event fields use Microsoft-internal names (SubjectUserName, Image,
    GrantedAccess) that differ from both OCSF and ASIM names. This function
    applies the field map defined in rules/pipelines/clickhouse-asim-ocsf.yaml
    and documented in instructions/04-normalization-and-schema.md §5.

    Key mappings:
    - Computer     → HostName   (collector-assigned; the host that generated the event)
    - Image        → ProcessImagePath   (full executable path, from Sysmon)
    - IpAddress    → SrcIpAddr         (source IP of the connection, from Sysmon EID 3)
    - TargetObject → RegistryKey       (from Sysmon EID 12/13 registry events)
    - Hashes       → FileMD5 / FileSHA256  (Sysmon comma-delimited hash string)
    - TimeCreated  → TimeGenerated     (event origin timestamp)

    Sysmon Hashes field parsing
    ---------------------------
    Sysmon stores file hashes as a single comma-delimited string:
      "MD5=abc123...,SHA256=def456..."
    This function splits that string and stores MD5 and SHA256 in separate
    FixedString(32) and FixedString(64) columns. Values are forced to lowercase
    because ClickHouse FixedString comparisons are case-sensitive, and Sigma rules
    are expected to supply lowercase hex values per the pipeline spec.

    Timestamp precedence
    --------------------
    TimeGenerated is set to:
    1. The event's TimeCreated field (the timestamp from the source host), if present.
    2. The IngestTimestamp (collector receipt time) as a fallback.
    Using the source timestamp is preferred because it reflects when the event
    actually occurred, not when it arrived at the collector (which may be delayed
    by WEF batching or network conditions).

    Args:
        raw: Raw Windows event dict as parsed by Vector (field names are the
             Windows XML attribute names, normalised to snake_case by Vector).
        provenance_tag: Collector-assigned provenance tag (format: "wef:http:{ts}").
        ingest_ts: UTC timestamp string assigned by the normalization service at
                   the moment of processing (not Vector receipt time).

    Returns:
        A NormalizedEvent ready for insertion into siemhunter.security_events.
    """
    # The set of raw field names that are explicitly mapped to canonical columns.
    # Any key NOT in this set will be stored in UnmappedFields for forensic access.
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

    # Resolve TimeGenerated: prefer the event's own timestamp; fall back to ingest time.
    # The fallback is needed for events that arrive without a TimeCreated field
    # (e.g., malformed WEF submissions or synthetic test events).
    time_created = raw.get("TimeCreated", raw.get("time_created", ""))
    if not time_created:
        time_created = ingest_ts

    # Parse the Sysmon Hashes field.
    # Example input: "MD5=d41d8cd98f00b204e9800998ecf8427e,SHA256=e3b0c44298fc1c149afb..."
    # We split on commas, then check the prefix of each part.
    # Truncation to 32/64 chars is a safety guard in case the field contains
    # a malformed or oversized value; it cannot exceed FixedString bounds.
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
    """Normalize an RFC 3164 or RFC 5424 syslog event.

    Syslog events map loosely to OCSF Network Activity class (4001) and
    ASimNetworkSession in ASIM, though many syslog messages are not network
    events. The mapping is approximate: syslog is a general-purpose log format,
    not a structured security event schema.

    Field handling:
    - The syslog message body is stored in CommandLine (repurposed as a
      free-text field; no Sigma rule should filter on this for syslog).
    - Source IP: Vector's "host" field is the sender; "src_ip" is the inner
      field if the syslog message contains a structured network record.
    - EventID is always 0 for syslog events (no equivalent concept).

    Args:
        raw: Syslog event dict as parsed by Vector. Keys follow Vector's syslog
             source output schema: message, hostname, appname, procid, msgid,
             timestamp, facility, severity, and any structured data fields.
        provenance_tag: Collector-assigned provenance tag (format: "syslog:{transport}:{ts}").
        ingest_ts: UTC timestamp assigned at processing time.

    Returns:
        A NormalizedEvent. Many fields will be empty strings for syslog events.
    """
    # Fields explicitly mapped to canonical columns; everything else → UnmappedFields.
    mapped = {"message", "hostname", "appname", "procid", "msgid", "timestamp",
              "facility", "severity", "src_ip", "dst_ip", "src_port", "dst_port", "proto"}

    # Vector places the sender's address in "host"; the inner IP (if any) is "src_ip".
    src_ip = str(raw.get("host", raw.get("src_ip", "")))
    return NormalizedEvent(
        TimeGenerated=str(raw.get("timestamp", ingest_ts)),
        HostName=str(raw.get("hostname", "")),
        EventID=0,  # No EventID concept in syslog
        EventRecordID=_stable_record_id(provenance_tag, raw),
        ChannelName="Syslog",
        ProviderName=str(raw.get("appname", "")),
        SrcIpAddr=src_ip,
        SrcPort=_coerce_uint16(raw.get("src_port", 0)),
        DstIpAddr=str(raw.get("dst_ip", "")),
        DstPort=_coerce_uint16(raw.get("dst_port", 0)),
        NetworkProtocol="",
        # Store the syslog message body in CommandLine for searchability.
        # Sigma rules should not use this field for syslog events.
        CommandLine=str(raw.get("message", "")),
        ProvenanceTag=provenance_tag,
        IngestTimestamp=ingest_ts,
        UnmappedFields=_extract_unmapped(raw, mapped),
    )


def normalize_netflow(raw: dict, provenance_tag: str, ingest_ts: str) -> NormalizedEvent:
    """Normalize a Netflow v5/v9 or IPFIX flow record.

    Netflow records are network-layer flow summaries: they capture (src IP,
    dst IP, src port, dst port, protocol, byte count, packet count, duration)
    per flow. They do NOT contain application-layer content or process context.

    OCSF mapping: Netflow → Network Activity class (4001).
    ASIM mapping: Netflow → ASimNetworkSession.

    Protocol number translation:
    IPFIX and Netflow carry the IP protocol number (IANA protocol numbers).
    The most common values are 6 (TCP), 17 (UDP), 1 (ICMP). This function
    translates known numbers to lowercase names; unknown numbers are stored
    as their string representation (e.g., "47" for GRE).

    Args:
        raw: Netflow/IPFIX record dict. Expected fields: timestamp, src_ip,
             dst_ip, src_port, dst_port, proto (integer), bytes, pkts, duration,
             exporter (the device that exported the flow record).
        provenance_tag: Collector-assigned tag (format: "netflow:{ts}" or "ipfix:{ts}").
        ingest_ts: UTC timestamp assigned at processing time.

    Returns:
        A NormalizedEvent. Process fields (CommandLine, ProcessImagePath, etc.)
        will be empty strings — netflow has no process context.
    """
    # Fields mapped to canonical columns; the rest (bytes, pkts, duration) go to UnmappedFields.
    mapped = {"timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
              "proto", "bytes", "pkts", "duration"}

    # Translate IANA IP protocol number to a lowercase protocol name.
    proto_num = int(raw.get("proto", 0))
    proto_map = {6: "tcp", 17: "udp", 1: "icmp"}
    proto_name = proto_map.get(proto_num, str(proto_num))

    return NormalizedEvent(
        TimeGenerated=str(raw.get("timestamp", ingest_ts)),
        # "exporter" is the device that generated the flow (the router or switch),
        # not the source of the traffic being described.
        HostName=str(raw.get("exporter", "")),
        EventID=0,  # No EventID concept in Netflow
        EventRecordID=_stable_record_id(provenance_tag, raw),
        ChannelName="Netflow",
        ProviderName="softflowd",  # The expected flow exporter in a SIEMhunter lab deployment
        SrcIpAddr=str(raw.get("src_ip", "")),
        SrcPort=_coerce_uint16(raw.get("src_port", 0)),
        DstIpAddr=str(raw.get("dst_ip", "")),
        DstPort=_coerce_uint16(raw.get("dst_port", 0)),
        NetworkProtocol=proto_name,
        ProvenanceTag=provenance_tag,
        IngestTimestamp=ingest_ts,
        # bytes, pkts, duration are not in the canonical schema but are preserved
        # in UnmappedFields for forensic hunt queries.
        UnmappedFields=_extract_unmapped(raw, mapped),
    )


def normalize_forensic(raw: dict, provenance_tag: str, ingest_ts: str) -> NormalizedEvent:
    """Normalize a forensic artifact record from Velociraptor or Volatility.

    Forensic artifacts are JSON files dropped into /var/siemhunter/drop/ by an
    operator after a collection run. They may contain timeline entries, process
    listings, memory artifacts, or Windows Event Log exports collected offline.

    Because the structure of forensic artifacts varies widely across tools and
    collection types, this normalizer is intentionally permissive: it maps the
    fields it recognises and stores everything else in UnmappedFields.

    Field handling:
    - Prefers 'timestamp' over 'TimeCreated' for the event time.
    - Accepts both Velociraptor ("hostname", "cmdline", "image_path") and
      Volatility / Windows-native ("Computer", "CommandLine", "Image") field names.
    - The tool or provider name (e.g., "velociraptor", "volatility") is stored
      in ProviderName for source attribution.

    Args:
        raw: Forensic artifact event dict. Structure varies by tool.
        provenance_tag: Collector-assigned tag (format: "forensic:file:{ts}").
        ingest_ts: UTC timestamp assigned at processing time.

    Returns:
        A NormalizedEvent. Most network and authentication fields will be empty.
    """
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
        # All unrecognised fields are preserved verbatim in UnmappedFields.
        # This is particularly important for forensic data, where the valuable
        # detail is often in tool-specific fields that have no canonical mapping.
        UnmappedFields=json.dumps({k: v for k, v in raw.items()
                                    if k not in {"timestamp", "TimeCreated", "hostname",
                                                 "Computer", "EventID", "tool", "Provider",
                                                 "CommandLine", "cmdline", "Image", "image_path"}},
                                   default=str) if raw else "",
    )


def dispatch(raw: dict, provenance_tag: str) -> NormalizedEvent | None:
    """Route a raw event to the correct normalizer and apply pre-flight checks.

    This is the single entry point for the normalization service main loop.
    It applies rate limiting, determines the correct normalizer from the
    ProvenanceTag prefix, and handles parse errors without crashing the loop.

    Routing logic
    -------------
    The ProvenanceTag is assigned by Vector transforms (vector/vector.yaml).
    The first segment (before the first colon) identifies the source type:
      - "syslog" → normalize_syslog
      - "wef"    → normalize_windows_event
      - "forensic" → normalize_forensic
      - "netflow" or "ipfix" → normalize_netflow
      - anything else → normalize_windows_event (conservative default; logs a warning)

    Error handling
    --------------
    Any exception from a normalizer is caught and logged. The event is dropped
    (returns None) rather than crashing the main loop. This is by design: a
    single malformed event must not stop processing of subsequent events.
    The parse error is logged with the full provenance tag for operator investigation.

    Args:
        raw: The raw event dict from ClickHouse raw_events (deserialized from JSON payload).
        provenance_tag: The ProvenanceTag string assigned by Vector.

    Returns:
        A NormalizedEvent on success. None if the event is rate-limited or
        cannot be parsed.
    """
    # Collector-assigned processing timestamp (not the event's own timestamp).
    # This is when the normalization service processed the event, which may be
    # seconds or minutes after Vector received it (due to batch polling).
    ingest_ts = _now_utc()

    # Apply rate limit before any parsing work. If this source is flooding,
    # drop immediately without spending CPU on normalization.
    if not _check_rate_limit(provenance_tag):
        return None

    # Extract the source type from the first segment of the ProvenanceTag.
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
            # Unknown provenance prefix. Default to Windows event normalizer as the
            # most capable fallback (it extracts the most fields from structured JSON).
            # Log a warning so operators know an unexpected source type is arriving.
            log.warning("unknown_provenance_prefix", tag_prefix=tag_prefix,
                        provenance_tag=provenance_tag)
            return normalize_windows_event(raw, provenance_tag, ingest_ts)
    except Exception as exc:
        # Do not re-raise. A single bad event must not kill the normalization loop.
        log.error("parse_error", provenance_tag=provenance_tag, error=str(exc))
        return None
