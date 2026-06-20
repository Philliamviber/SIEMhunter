"""
Canonical field table — the Python expression of instructions/04-normalization-and-schema.md §5.

This module is the authoritative Python definition of the security_events schema.
It is the source of truth for three artefacts that must agree with it exactly:

  1. clickhouse/schema.sql — the DDL that creates the security_events table.
  2. rules/pipelines/clickhouse-asim-ocsf.yaml — the pySigma field map that
     tells pySigma how to translate Sigma field names to ClickHouse column names.
  3. services/normalization/src/normalizer.py — the code that populates fields.

Change protocol (see instructions/04-normalization-and-schema.md §8):
  1. Update this file and the companion doc first.
  2. Update clickhouse-asim-ocsf.yaml (field_mappings and type_hints sections).
  3. Apply a ClickHouse migration (ADD COLUMN or ALTER TABLE) for the new column.
  4. Update the Sentinel DCR column list if the field is forwarded to Sentinel.
  5. Update any Sigma rules that reference the old field name.
Never reorder steps 3-5 before steps 1-2 are reviewed — schema drift between
the Python model and the ClickHouse DDL will cause silent insert failures.

Column type rationale:
  - LowCardinality(String): Used for columns with a small, bounded set of values
    (< ~10,000 distinct values). LowCardinality applies dictionary encoding, which
    reduces storage and dramatically speeds up GROUP BY and WHERE = queries.
    Examples: HostName (bounded by the number of hosts), ChannelName, NetworkProtocol.
  - FixedString(N): For columns with a known, fixed-width value (MD5 and SHA256 hex
    strings). Slightly more efficient than String for exact-match queries.
  - UInt8/16/32: Right-sized integers to reduce storage. LogonType fits in UInt8
    (max value 12 in practice); ports fit in UInt16 (max 65535); EventID requires
    UInt32 (max 65535 but Windows reserves IDs up to 4294967295 in theory).
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any


@dataclass
class NormalizedEvent:
    """One row in siemhunter.security_events.

    Each field corresponds to exactly one column in the ClickHouse DDL.
    The ClickHouse column types are noted inline; the Python types are strings
    or ints because clickhouse_connect handles the actual type coercion.

    Fields are grouped by their ASIM schema category. This grouping mirrors the
    canonical field table in instructions/04-normalization-and-schema.md §5.

    To add a new field:
    1. Add it here with its default value.
    2. Add it to to_row() below.
    3. Add the column to clickhouse/schema.sql (ADD COLUMN migration).
    4. Add the mapping to rules/pipelines/clickhouse-asim-ocsf.yaml.
    5. Update normalizer.py to populate it from raw event data.
    """

    # ── Time and identity anchors (sort key columns) ──────────────────────────
    # These three columns form the ORDER BY key in ClickHouse. Queries that
    # filter on (TimeGenerated, HostName, EventID) are the most efficient.
    # TimeGenerated is the event origin time (from the source, not ingest time).
    TimeGenerated: str = ""           # ClickHouse: DateTime64(3,'UTC')
    HostName: str = ""                # ClickHouse: LowCardinality(String)
    EventID: int = 0                  # ClickHouse: UInt32 — MUST be integer, never string

    # ── Event metadata ────────────────────────────────────────────────────────
    # EventRecordID is the stable dedup key (FR-18). It is either the source's
    # own record ID (prefixed with ProvenanceTag) or a SHA-256 content hash.
    EventRecordID: str = ""           # ClickHouse: String
    ChannelName: str = ""             # ClickHouse: LowCardinality(String) — e.g., "Security"
    ProviderName: str = ""            # ClickHouse: LowCardinality(String) — e.g., "Microsoft-Windows-Security-Auditing"

    # ── Actor (subject) ───────────────────────────────────────────────────────
    # The "subject" is who initiated the action (the actor in ASIM terms).
    # In Windows Security events: the account performing the audited operation.
    SubjectUserName: str = ""         # ClickHouse: String
    SubjectUserSid: str = ""          # ClickHouse: String — SID in S-1-5-... format
    SubjectDomainName: str = ""       # ClickHouse: LowCardinality(String)

    # ── Target (user) ─────────────────────────────────────────────────────────
    # The "target" is the object of the operation (e.g., the account being logged into,
    # or the account whose password was changed).
    TargetUserName: str = ""          # ClickHouse: String
    TargetUserSid: str = ""           # ClickHouse: String
    TargetDomainName: str = ""        # ClickHouse: LowCardinality(String)

    # ── Authentication ────────────────────────────────────────────────────────
    # LogonType: Windows logon type integer. Common values:
    #   2  = Interactive (keyboard at the console)
    #   3  = Network (e.g., accessing a file share)
    #   10 = RemoteInteractive (RDP session)
    LogonType: int = 0                # ClickHouse: UInt8
    # ServiceName: service being authenticated to (e.g., "krbtgt" for Kerberos TGTs).
    # Also used for network service names in ASimNetworkSession context.
    ServiceName: str = ""             # ClickHouse: String

    # ── Process ───────────────────────────────────────────────────────────────
    # Populated from Sysmon EID 1 (process creation) and related events.
    ProcessImagePath: str = ""        # ClickHouse: String — full path, e.g., C:\Windows\System32\lsass.exe
    CommandLine: str = ""             # ClickHouse: String — full command with arguments
    ParentProcessImagePath: str = ""  # ClickHouse: String — spawning process path
    ParentCommandLine: str = ""       # ClickHouse: String
    # GrantedAccess: the access mask from Sysmon EID 10 (process access events).
    # This is the bitmask granted when one process opens a handle to another.
    # 0x1010 (LSASS read) is the signature of credential dumping tools.
    # No ASIM equivalent; this column is only used in local ClickHouse Sigma rules.
    GrantedAccess: str = ""           # ClickHouse: String — hex mask, e.g., "0x1010"

    # ── File ──────────────────────────────────────────────────────────────────
    ObjectName: str = ""              # ClickHouse: String — file or directory path
    # Hash fields: always lowercase hex. FixedString requires exactly N characters;
    # to_row() pads with spaces and truncates to enforce this.
    # Sigma rules must use lowercase hex values for hash comparisons.
    FileMD5: str = ""                 # ClickHouse: FixedString(32) — 32 lowercase hex chars
    FileSHA256: str = ""              # ClickHouse: FixedString(64) — 64 lowercase hex chars

    # ── Registry ──────────────────────────────────────────────────────────────
    # Populated from Sysmon EID 12/13 (registry create/set events).
    # Maps the Sigma field "TargetObject" (Windows registry key path).
    RegistryKey: str = ""             # ClickHouse: String — full registry path

    # ── Network ───────────────────────────────────────────────────────────────
    SrcIpAddr: str = ""               # ClickHouse: String — IPv4 or IPv6
    SrcPort: int = 0                  # ClickHouse: UInt16
    DstIpAddr: str = ""               # ClickHouse: String
    DstPort: int = 0                  # ClickHouse: UInt16
    # NetworkProtocol: lowercase protocol name, e.g., "tcp", "udp", "icmp".
    # Netflow records supply a protocol number that is translated in normalize_netflow().
    NetworkProtocol: str = ""         # ClickHouse: LowCardinality(String)

    # ── Pipeline fields (collector-assigned; immutable after assignment) ───────
    # These are set by the collector (Vector) and the normalization service.
    # They are NEVER derived from event content. An event cannot lie about its
    # own provenance tag or ingest time.
    ProvenanceTag: str = ""           # ClickHouse: LowCardinality(String) — e.g., "wef:http"
    IngestTimestamp: str = ""         # ClickHouse: DateTime64(3,'UTC') — collector receipt time

    # ── Catch-all for unmapped fields ─────────────────────────────────────────
    # Any raw event field not captured in the columns above is serialised to
    # JSON and stored here. This column is NOT queryable via Sigma rules.
    # It is available for ad-hoc forensic hunt queries in ClickHouse.
    UnmappedFields: str = ""          # ClickHouse: String (JSON blob)

    def to_row(self) -> dict[str, Any]:
        """Return a dict suitable for the clickhouse_connect parameterized INSERT interface.

        The dict keys must exactly match the column names in security_events.
        clickhouse_connect uses the column_names argument to INSERT to map
        dict keys to table columns.

        FixedString columns (FileMD5, FileSHA256) require exactly N characters.
        We pad with spaces and truncate to ensure the correct length. The
        normalizer stores lowercase hex (32 or 64 chars), so the padding is
        only ever applied to empty-string defaults.
        """
        return {
            "TimeGenerated": self.TimeGenerated,
            "HostName": self.HostName,
            "EventID": self.EventID,
            "EventRecordID": self.EventRecordID,
            "ChannelName": self.ChannelName,
            "ProviderName": self.ProviderName,
            "SubjectUserName": self.SubjectUserName,
            "SubjectUserSid": self.SubjectUserSid,
            "SubjectDomainName": self.SubjectDomainName,
            "TargetUserName": self.TargetUserName,
            "TargetUserSid": self.TargetUserSid,
            "TargetDomainName": self.TargetDomainName,
            "LogonType": self.LogonType,
            "ServiceName": self.ServiceName,
            "ProcessImagePath": self.ProcessImagePath,
            "CommandLine": self.CommandLine,
            "ParentProcessImagePath": self.ParentProcessImagePath,
            "ParentCommandLine": self.ParentCommandLine,
            "GrantedAccess": self.GrantedAccess,
            "ObjectName": self.ObjectName,
            # Pad to exact FixedString length; normalizer enforces lowercase hex already.
            "FileMD5": self.FileMD5.ljust(32)[:32],
            "FileSHA256": self.FileSHA256.ljust(64)[:64],
            "RegistryKey": self.RegistryKey,
            "SrcIpAddr": self.SrcIpAddr,
            "SrcPort": self.SrcPort,
            "DstIpAddr": self.DstIpAddr,
            "DstPort": self.DstPort,
            "NetworkProtocol": self.NetworkProtocol,
            "ProvenanceTag": self.ProvenanceTag,
            "IngestTimestamp": self.IngestTimestamp,
            "UnmappedFields": self.UnmappedFields,
        }


# ── OCSF class → ASIM table mapping ──────────────────────────────────────────
# Per instructions/04-normalization-and-schema.md §2.
# OCSF (Open Cybersecurity Schema Framework) defines integer event class IDs.
# ASIM (Advanced Security Information Model) defines named table schemas in Sentinel.
# This dict drives the Sentinel DCR routing: the forwarder uses the OCSF class
# to decide which ASIM table to upload a batch of events to.
#
# Not all OCSF classes have a direct ASIM equivalent; the mapping is approximate.
# When forwarding, the forwarder groups events by their OCSF class and sends
# each group to the corresponding Sentinel DCR stream.
OCSF_CLASS_TO_ASIM: dict[int, str] = {
    3002: "ASimAuthentication",
    4001: "ASimNetworkSession",
    4003: "ASimDns",
    1007: "ASimProcessEvent",
    1001: "ASimFileEvent",
    201001: "ASimRegistryEvent",
    3001: "ASimUserManagement",
    5003: "ASimScheduledTask",
}

# ── Windows channel → OCSF class heuristic ───────────────────────────────────
# Maps the Windows event log channel name to a default OCSF class ID.
# This is a heuristic: most Security channel events are authentication-related
# (OCSF 3002), but some (e.g., EID 4662 DS-Access) map to other classes.
# The EVENTID_CLASS_OVERRIDES dict below refines this for known exceptions.
CHANNEL_TO_OCSF_CLASS: dict[str, int] = {
    "Security": 3002,             # default to Authentication; normalizer refines per EventID
    "Microsoft-Windows-Sysmon/Operational": 1007,
    "System": 4001,
}

# ── EventID class overrides ───────────────────────────────────────────────────
# Overrides the channel-level default OCSF class for specific Windows Event IDs.
# Applied after CHANNEL_TO_OCSF_CLASS to refine the mapping for known events.
#
# Mapping rationale:
#   4662 — DS Object Access (Directory Services). Closest ASIM schema is
#          ASimRegistryEvent (201001) because ASIM has no DS-specific table.
#          The DCSync Sigma rule relies on filtering EID 4662 + ObjectName=~"DC=".
#   4624/4625 — Authentication success/failure → Authentication class (3002)
#   4768/4769 — Kerberos TGT/TGS requests → Authentication class (3002)
#   4720/4722/4728/4732/4756 — Account management operations → UserManagement (3001)
EVENTID_CLASS_OVERRIDES: dict[int, int] = {
    4662: 201001,   # Directory Service Access → RegistryEvent (closest available)
    4624: 3002,
    4625: 3002,
    4768: 3002,
    4769: 3002,
    4720: 3001,     # Account Management → UserManagement
    4722: 3001,
    4728: 3001,
    4732: 3001,
    4756: 3001,
}
