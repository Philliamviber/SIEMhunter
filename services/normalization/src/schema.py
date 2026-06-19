"""
Canonical field table — the Python expression of 04-normalization-and-schema.md §5.
Every field here maps to one ClickHouse column in security_events.
Changes to this file must be accompanied by a ClickHouse schema migration and
an update to rules/pipelines/clickhouse-asim-ocsf.yaml.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any


@dataclass
class NormalizedEvent:
    """One row in siemhunter.security_events."""

    # Time and identity anchors (sort key)
    TimeGenerated: str = ""           # DateTime64(3,'UTC') — ISO-8601 UTC string
    HostName: str = ""                # LowCardinality(String)
    EventID: int = 0                  # UInt32

    # Event metadata
    EventRecordID: str = ""           # String — stable dedup key per FR-18
    ChannelName: str = ""             # LowCardinality(String)
    ProviderName: str = ""            # LowCardinality(String)

    # Actor (subject)
    SubjectUserName: str = ""
    SubjectUserSid: str = ""
    SubjectDomainName: str = ""       # LowCardinality(String)

    # Target (user)
    TargetUserName: str = ""
    TargetUserSid: str = ""
    TargetDomainName: str = ""        # LowCardinality(String)

    # Authentication
    LogonType: int = 0                # UInt8
    ServiceName: str = ""

    # Process
    ProcessImagePath: str = ""
    CommandLine: str = ""
    ParentProcessImagePath: str = ""
    ParentCommandLine: str = ""
    GrantedAccess: str = ""           # Sysmon EID 10 only

    # File
    ObjectName: str = ""
    FileMD5: str = ""                 # FixedString(32) lowercase hex
    FileSHA256: str = ""              # FixedString(64) lowercase hex

    # Registry
    RegistryKey: str = ""

    # Network
    SrcIpAddr: str = ""
    SrcPort: int = 0                  # UInt16
    DstIpAddr: str = ""
    DstPort: int = 0                  # UInt16
    NetworkProtocol: str = ""         # LowCardinality(String) — lowercase: tcp/udp/icmp

    # Pipeline fields (collector-assigned; never from event content)
    ProvenanceTag: str = ""           # LowCardinality(String)
    IngestTimestamp: str = ""         # DateTime64(3,'UTC')

    # Catch-all for unmapped OCSF fields (not queryable in Sigma)
    UnmappedFields: str = ""

    def to_row(self) -> dict[str, Any]:
        """Return a dict suitable for ClickHouse parameterized INSERT."""
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


# OCSF event class → ASIM table mapping per 04-normalization-and-schema.md §2
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

# Windows channel → OCSF class heuristic
CHANNEL_TO_OCSF_CLASS: dict[str, int] = {
    "Security": 3002,             # default to Authentication; normalizer refines per EventID
    "Microsoft-Windows-Sysmon/Operational": 1007,
    "System": 4001,
}

# EventIDs that map to non-default OCSF classes within the Security channel
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
