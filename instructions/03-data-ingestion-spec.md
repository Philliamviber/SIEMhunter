# SIEMhunter — Data Ingestion Specification
**Document:** 03-data-ingestion-spec.md
**Version:** 0.1.0-draft
**Date:** 2026-06-18
**Status:** Authoritative — referenced by 04-normalization-and-schema.md and 05-detection-and-anomaly.md

---

## Summary

This document specifies every ingest path that SIEMhunter supports in v0.1.0. It covers the pipeline design, per-source configuration, the security controls enforced at the collector edge, the always-on flood heuristic that runs outside the batch schedule, and a sample raw event for each source showing exactly what arrives before the normalization stage defined in `04-normalization-and-schema.md`. All downstream documents that reference raw fields, provenance tags, or pre-normalization event shapes point here.

---

## 1. Ingestion pipeline overview

Raw telemetry from all sources flows through a single Vector process (a self-contained Rust binary) that runs as a non-root container. Vector handles native syslog listening on UDP 514, TCP 514, and TLS 6514 via its built-in `syslog` source; reads Windows Event Logs forwarded via Windows Event Forwarding (WEF) through its `windows_event_log` source or from EVTX-to-JSON exports via its `file` source; and receives IPFIX/NetFlow via its `socket` source fed by a softflowd or nfcapd collector. At the point of receipt, Vector assigns a `_siemhunter_provenance` tag (identifying the source type, source ID, and transport) and a `_siemhunter_ingest_ts` timestamp; neither field can be overridden by content within the event. After parsing and provenance tagging, Vector applies size and rate controls, then writes events directly to ClickHouse at lab scale. For higher-volume environments, Redpanda can be inserted between Vector and ClickHouse as a durable queue — the pipeline is architected to allow this without rewriting the application; Redpanda is not required for v0.1.0. Forensic artifact drops and the optional Azure KQL pull are handled as separate ingest paths that converge on the same ClickHouse store and normalization layer.

---

## 2. Per-source ingestion design

### 2.1 Syslog (RFC 3164 / RFC 5424)

#### Transport

| Protocol | Port | Notes |
|----------|------|-------|
| UDP | 514 | RFC 3164 (BSD syslog) and RFC 5424 |
| TCP | 514 | RFC 3164 and RFC 5424; no TLS |
| TCP + TLS | 6514 | RFC 5424 recommended; TLS listener certificate provisioned via Docker secret |

All three transports are independently configurable. Enable only what the environment requires. UDP provides no delivery guarantee and is acceptable only for low-criticality syslog sources or where TLS is not supported by the sender.

#### Vector source configuration

The `syslog` source is configured with three listeners: UDP on port 514, TCP on port 514, and TLS-wrapped TCP on port 6514. The source is set to `mode = "tcp"` or `"udp"` per listener, with a `max_length` setting enforcing the per-event size cap (default 65 536 bytes; see Section 4). The source automatically detects RFC 3164 vs. RFC 5424 framing. Each listener is labelled with a distinct source ID so the provenance tag can identify which transport delivered the event.

#### Transformation notes

Vector's built-in syslog parser extracts: `timestamp`, `hostname`, `appname`, `procid`, `msgid`, `severity`, `facility`, and `message`. For RFC 5424 messages, structured data elements (SD-ID key-value pairs) are also extracted and appended as top-level fields. The `hostname` field from the syslog header is **never used as an authentication identity** — it is stored as a data value only. The collector-assigned `_siemhunter_provenance` and `_siemhunter_ingest_ts` are appended after parsing.

#### Security controls specific to this source

- **ProvenanceTag** is assigned by Vector's pipeline, not derived from the syslog `HOSTNAME` field. An attacker who controls a sending host can put any value in `HOSTNAME`; that value is stored as `hostname` (untrusted data), not as the source identity.
- Per-event size cap: 64 KB default. Oversized events are dropped before parsing; the drop is counted in `SIEMHunterHealth_CL`.
- Rate limit: configurable events/second per source IP. Excess events are dropped; the excess triggers the flood heuristic described in Section 5.

#### Relevant event IDs / formats

Syslog carries no standard EventID field. The `msgid` field in RFC 5424 is application-defined. Windows hosts forwarding via syslog may populate `msgid` with the Windows EventID (e.g., `4769`). The normalization layer (doc 04) maps this to the canonical `EventID` field where present.

#### Sample event — RFC 5424 syslog before normalization

```json
{
  "hostname": "dc01.corp.local",
  "appname": "MICROSOFT-WINDOWS-SECURITY-AUDITING",
  "procid": "-",
  "msgid": "4769",
  "message": "A Kerberos service ticket was requested...",
  "timestamp": "2025-01-15T10:23:45.123Z",
  "severity": "notice",
  "facility": "security",
  "raw": "<134>1 2025-01-15T10:23:45.123Z dc01.corp.local MICROSOFT-WINDOWS-SECURITY-AUDITING - 4769 - ...",
  "_siemhunter_provenance": "syslog-tcp-6514",
  "_siemhunter_ingest_ts": "2025-01-15T10:23:45.456Z"
}
```

> **Field notes:** `_siemhunter_provenance` encodes the source type and transport (`syslog-tcp-6514`). `_siemhunter_ingest_ts` is the UTC arrival time at the Vector listener — this is the authoritative receipt timestamp for ordering and deduplication, not the syslog `timestamp` header, which is source-controlled.

---

### 2.2 Windows Event Logs — Domain Controller Security Log

#### Transport

Two delivery paths are supported:

| Path | Mechanism | Notes |
|------|-----------|-------|
| WEF → WEC → Vector | Windows Event Forwarding (WEF) pushes events from DCs to a Windows Event Collector (WEC). Vector reads from the WEC using the `windows_event_log` source. | Preferred for live monitoring. |
| EVTX → JSON → Vector | `wevtutil qe Security /f:XML` or `python-evtx` converts EVTX to JSON; output is dropped to a watched directory. Vector reads via the `file` source. | Used for offline or forensic ingestion of existing EVTX files. |

#### Vector source configuration

For the WEF path: the `windows_event_log` source subscribes to the `Security` channel on the WEC host using a configured subscription query. The source emits one JSON object per event record. For the EVTX-to-JSON path: the `file` source watches a drop directory; each file is parsed as newline-delimited JSON, then archived or deleted after processing.

#### Key EventIDs to capture

| EventID | Description | Audit policy requirement |
|---------|-------------|--------------------------|
| 4624 | Logon success | Audit Logon — Success |
| 4625 | Logon failure | Audit Logon — Failure |
| 4672 | Special privileges assigned to new logon | Audit Special Logon — Success |
| 4720 | User account created | Audit User Account Management — Success |
| 4728 | Member added to security-enabled global group | Audit Security Group Management — Success |
| 4732 | Member added to security-enabled local group | Audit Security Group Management — Success |
| 4756 | Member added to security-enabled universal group | Audit Security Group Management — Success |
| 4762 | Member removed from security-disabled universal group | Audit Security Group Management — Success |
| 4768 | Kerberos AS-REQ (TGT requested) | Audit Kerberos Authentication Service — Success/Failure |
| 4769 | Kerberos TGS-REQ (service ticket requested; Kerberoasting indicator) | Audit Kerberos Service Ticket Operations — Success/Failure |
| 4771 | Kerberos pre-authentication failure (AS-REP Roasting indicator) | Audit Kerberos Authentication Service — Failure |
| 4662 | Operation performed on AD object (DCSync indicator; filter on GUID for replication rights) | Audit Directory Service Access — Success; must have object SACL with `Replicating Directory Changes` GUID |

**DCSync audit policy note:** EID 4662 is only generated for the specific AD operation GUIDs associated with replication (`{1131f6aa-...}` DS-Replication-Get-Changes, `{1131f6ad-...}` DS-Replication-Get-Changes-All). A generic Object Access audit policy is insufficient; the DC object SACL must explicitly include these GUIDs. Without this configuration, DCSync (T1003.006) detection returns zero hits.

#### Transformation notes

Windows Event Log JSON (from WEF or wevtutil) wraps event data in a two-level structure: `System` (provider, EventID, channel, computer, time) and `EventData` (event-specific key-value pairs). The normalization layer (doc 04) flattens this into the canonical OCSF field set. Vector applies no structural transformation to this source — the raw Windows event shape is stored as-is with provenance fields appended.

#### Sample event — EID 4769 Kerberos TGS-REQ before normalization

```json
{
  "System": {
    "Provider": {
      "Name": "Microsoft-Windows-Security-Auditing",
      "Guid": "{54849625-5478-4994-a5ba-3e3b0328c30d}"
    },
    "EventID": 4769,
    "Version": 0,
    "Channel": "Security",
    "Computer": "dc01.corp.local",
    "TimeCreated": {
      "SystemTime": "2025-01-15T10:23:45.123456700Z"
    }
  },
  "EventData": {
    "TargetUserName": "svc_sql",
    "TargetDomainName": "CORP",
    "ServiceName": "MSSQLSvc/sqlserver.corp.local:1433",
    "ServiceSid": "S-1-5-21-...",
    "TicketOptions": "0x40810000",
    "TicketEncryptionType": "0x17",
    "IpAddress": "::ffff:192.168.1.50",
    "IpPort": "52341"
  },
  "_siemhunter_provenance": "wef-dc01",
  "_siemhunter_ingest_ts": "2025-01-15T10:23:45.789Z"
}
```

> **Detection relevance:** `TicketEncryptionType = 0x17` (RC4-HMAC) requested for a service account SPN is the Kerberoasting indicator (T1558.003). The normalization layer maps `EventData.TicketEncryptionType` to a canonical `TicketEncryptionType` field; Sigma rule `detect-kerberoasting` queries this canonical field, never the raw Windows path.

---

### 2.3 Windows Event Logs — Sysmon

#### Transport

Same two paths as 2.2: WEF → WEC → Vector `windows_event_log` source (subscribing to the `Microsoft-Windows-Sysmon/Operational` channel), or EVTX-to-JSON export dropped to the watched directory and read by the `file` source.

#### Key EventIDs to capture

| EventID | Description | Detection relevance |
|---------|-------------|---------------------|
| 1 | Process Create (includes command line, parent, hashes) | Malicious process execution; LOLBin detection |
| 3 | Network Connection | C2 beaconing; lateral movement; unexpected outbound |
| 7 | Image Loaded (DLL load with signer info) | DLL hijacking; unsigned DLL loaded into sensitive process |
| 8 | CreateRemoteThread | Lateral movement; process injection |
| 10 | ProcessAccess (LSASS access; GrantedAccess mask) | LSASS credential dumping (T1003.001) |
| 11 | File Created (full path) | Dropped payloads; web shells; suspicious artifact placement |
| 12 | Registry Object Added/Deleted | Persistence via registry key creation or removal |
| 13 | Registry Value Set | Persistence; defense evasion via registry value modification |
| 14 | Registry Key/Value Renamed | Persistence staging |
| 22 | DNS Query (process + queried name) | C2 domain resolution; DNS tunneling detection |

#### Sysmon configuration requirements

Sysmon must be deployed on endpoints using an explicit configuration file (e.g., a sysmon-modular or SwiftOnSecurity config) with the following specific settings:

- **EID 10 must be enabled** with a rule that logs `GrantedAccess` for accesses to `lsass.exe`. Without this, LSASS dump detection (T1003.001) returns zero hits regardless of what tooling the attacker uses.
- **EID 1 must include CommandLine hashing** (SHA256 at minimum) so that command-line values can be correlated against known-bad hash sets.
- **EID 3 must not be excluded wholesale** — many default configs exclude network events to reduce volume. SIEMhunter requires EID 3 for C2 and lateral movement detection.
- **EID 22 must be enabled**. DNS query logging is disabled by default in some Sysmon config templates.

If Sysmon is not deployed or these event types are not configured, the affected Sigma rules produce zero hits and log a warning identifying the missing telemetry (see `02-requirements.md` FR-02).

#### Transformation notes

Sysmon event structure mirrors the Windows Event Log format: `System` block plus `EventData` block. The normalization layer (doc 04) handles Sysmon-specific `EventData` fields (e.g., `SourceImage`, `TargetImage`, `GrantedAccess`, `CommandLine`) and maps them to OCSF process and network activity classes. Vector stores the raw shape with provenance fields appended.

#### Sample event — EID 10 ProcessAccess (LSASS) before normalization

```json
{
  "System": {
    "Provider": {
      "Name": "Microsoft-Windows-Sysmon",
      "Guid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"
    },
    "EventID": 10,
    "Channel": "Microsoft-Windows-Sysmon/Operational",
    "Computer": "workstation01.corp.local",
    "TimeCreated": {
      "SystemTime": "2025-01-15T10:25:01.234567Z"
    }
  },
  "EventData": {
    "SourceProcessGUID": "{4a3b...}",
    "SourceProcessId": "4512",
    "SourceImage": "C:\\Users\\jsmith\\Downloads\\mimikatz.exe",
    "TargetProcessGUID": "{0c2b...}",
    "TargetProcessId": "688",
    "TargetImage": "C:\\Windows\\system32\\lsass.exe",
    "GrantedAccess": "0x1010",
    "CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll+..."
  },
  "_siemhunter_provenance": "wef-workstation01",
  "_siemhunter_ingest_ts": "2025-01-15T10:25:01.500Z"
}
```

> **Detection relevance:** `TargetImage` ending in `lsass.exe` combined with `GrantedAccess` values including `0x10` (PROCESS_VM_READ) or `0x1010` (PROCESS_VM_READ + PROCESS_QUERY_LIMITED_INFORMATION) is the canonical LSASS credential-dump indicator (T1003.001). The normalization layer maps `EventData.GrantedAccess` to `ProcessAccessRights` in the OCSF Process Activity class.

---

### 2.4 Netflow / IPFIX

#### Transport and collector

Netflow provides connection metadata only — no payload content. SIEMhunter uses it for lateral movement detection, C2 beaconing patterns, and port-scanning detection.

| Collector | Output | Vector source |
|-----------|--------|---------------|
| softflowd | IPFIX (UDP) to a local listener | `socket` source, UDP, listening on the IPFIX export port |
| nfcapd | nfcapd binary files written to disk | `file` source watching the nfcapd output directory |

**softflowd** is the preferred path for home-lab use: it generates IPFIX from a live network interface without requiring dedicated network hardware.

#### Vector source configuration

For the socket path: the `socket` source is configured in UDP mode, listening on the IPFIX collector output port (default 4739 for IPFIX, or whatever softflowd is configured to export to). A per-packet size cap is enforced (default 9 000 bytes, matching jumbo-frame UDP MTU; packets exceeding this are dropped and logged to `SIEMHunterHealth_CL`). For the nfcapd file path: the `file` source watches the output directory; nfcapd files are processed in order and archived after ingestion.

#### Key fields

| Field | Description |
|-------|-------------|
| `src_ip` | Source IP address (attacker-controlled; treated as data, not identity) |
| `dst_ip` | Destination IP address |
| `src_port` | Source port |
| `dst_port` | Destination port |
| `protocol` | IP protocol number (6 = TCP, 17 = UDP, 1 = ICMP) |
| `bytes` | Total bytes in flow |
| `packets` | Total packets in flow |
| `start_time` | Flow start timestamp (UTC) |
| `end_time` | Flow end timestamp (UTC) |
| `flow_direction` | Ingress or egress relative to the monitored interface |
| `input_if` | Interface name on the collector host |

#### Transformation notes

IPFIX records received via UDP are parsed by Vector's codec layer (or by a pre-processing step if using softflowd's JSON export mode) into key-value fields. The normalization layer (doc 04) maps these to the OCSF Network Activity class. Netflow data has no hostname or username fields — enrichment (reverse DNS, asset lookup) is performed in the normalization stage, not at ingest.

#### Sample event — IPFIX/JSON before normalization

```json
{
  "src_ip": "192.168.1.50",
  "dst_ip": "10.0.0.200",
  "src_port": 52341,
  "dst_port": 445,
  "protocol": 6,
  "bytes": 123456,
  "packets": 89,
  "start_time": "2025-01-15T10:20:00.000Z",
  "end_time": "2025-01-15T10:21:30.000Z",
  "flow_direction": "egress",
  "input_if": "eth0",
  "_siemhunter_provenance": "netflow-softflowd",
  "_siemhunter_ingest_ts": "2025-01-15T10:22:00.123Z"
}
```

> **Detection relevance:** `dst_port = 445` (SMB) from an endpoint that is not a DC is a lateral movement indicator. Repeated short-duration flows to the same dst_ip at regular intervals indicate C2 beaconing. Both patterns are covered by Sigma rules querying the OCSF Network Activity table in ClickHouse.

---

### 2.5 Forensic / Blue-Team Artifacts (Structured JSON / Text)

#### Transport

Vector `file` source watches a designated drop directory. Files placed in the directory are processed once and then either archived to a completed subdirectory or deleted, depending on operator configuration. This is a batch path — files are not expected in real time.

#### Supported artifact types

| Tool | Export format | Notes |
|------|--------------|-------|
| Velociraptor | Newline-delimited JSON (one row per artifact result row) | Artifact name and hostname included as top-level fields |
| Volatility | Text output; must be pre-converted to JSON by the operator or a wrapper script | No standard JSON output in Volatility 2; Volatility 3 has JSON plugins |
| wevtutil / python-evtx | EVTX-to-JSON conversion; same structure as Section 2.2/2.3 | Processed identically to the live WEF path once in JSON form |
| Manual JSON drops | Any JSON file dropped to the directory | Schema is validated before normalization; unknown shapes are logged to SIEMHunterHealth_CL with a parse warning |

#### Security controls — CRITICAL for this source

This source is the highest-risk ingest path because artifact files may originate from attacker-controlled machines. A malicious actor who can place files in the drop directory (e.g., via a compromised endpoint running Velociraptor) can attempt parser exhaustion or decompression-bomb attacks.

- **Decompression-ratio cap:** Any compressed file (zip, gzip) that expands beyond the configured ratio (default 100:1) has decompression aborted immediately. The file is rejected and an event is written to `SIEMHunterHealth_CL` with `EventType = "DecompressionRatioCap"`. This is one of the five always-active self-detections (see `02-requirements.md` FR-09).
- **Per-file size cap:** Files exceeding the raw (pre-decompress) size limit are rejected before decompression begins.
- **Parse timeout:** Each file has a per-file parse timeout (default 30 seconds). If parsing exceeds the timeout, the file is abandoned, renamed with a `.timeout` suffix in the drop directory, and an event is written to `SIEMHunterHealth_CL` with `EventType = "ParseTimeout"`.
- **No execution:** Vector's `file` source reads file content only. No file in the drop directory is ever executed or deserialized using Python pickle.

#### Transformation notes

Velociraptor exports wrap the artifact data in an outer envelope (`artifact`, `hostname`, `collection_time`) with result rows nested under `row`. The normalization layer (doc 04) unwraps the envelope and maps `row` fields to the appropriate OCSF class based on the `artifact` name. Unknown artifact types are stored as raw JSON in an unclassified OCSF extension field for manual review.

#### Sample event — Velociraptor process listing before normalization

```json
{
  "artifact": "Windows.System.Pslist",
  "hostname": "workstation01.corp.local",
  "collection_time": "2025-01-15T10:00:00Z",
  "row": {
    "Pid": 4512,
    "Ppid": 2304,
    "Name": "mimikatz.exe",
    "Exe": "C:\\Users\\jsmith\\Downloads\\mimikatz.exe",
    "CommandLine": "mimikatz.exe \"sekurlsa::logonpasswords\" exit",
    "CreateTime": "2025-01-15T09:58:32Z",
    "Username": "CORP\\jsmith"
  },
  "_siemhunter_provenance": "velociraptor-drop",
  "_siemhunter_ingest_ts": "2025-01-15T10:00:05.000Z"
}
```

> **Detection relevance:** `Name = mimikatz.exe` and `CommandLine` containing `sekurlsa::logonpasswords` are direct credential-dumping indicators (T1003.001). The normalization layer maps `row.Exe` to `ProcessFilePath` and `row.CommandLine` to `ProcessCommandLine` in the OCSF Process Activity class, making this event queryable by the same Sigma rules that process live Sysmon EID 1 events.

---

### 2.6 Optional Azure Log Pull (KQL / Log Analytics API)

#### Nature of this source

This is a **pull** source, not a push source. SIEMhunter initiates outbound HTTPS requests to the Azure Monitor Logs Query API on the batch schedule. No inbound connection from Azure is involved. If this path is disabled or the workspace is unreachable, all other ingest paths continue operating normally.

#### Authentication

A separate `Log Analytics Reader` identity is used for the KQL pull — it is distinct from the push identity (`Monitoring Metrics Publisher` on the DCR). The two identities must never share a credential. See `15-adr-forwarder-credential.md` for the credential model and rotation procedure.

#### Use case

The primary use is pulling Entra ID SignInLogs and AuditLogs from the Sentinel workspace into the local ClickHouse store for cross-source correlation — for example, correlating a local Kerberoasting detection (EID 4769) with an Entra ID sign-in from the same account at the same time.

#### Pull cadence and overlap window

| Parameter | Default | Notes |
|-----------|---------|-------|
| Pull interval | Aligned to batch schedule (15–60 min) | Configurable |
| Lookback window | Batch interval + 5 minutes | The 5-minute overlap prevents gaps caused by clock skew or API latency |
| Max events per pull | Configurable (default 10 000 rows per query) | Prevents memory exhaustion from unexpectedly large result sets |

#### Rate limit handling

The Azure Log Analytics API enforces query rate limits. The pull client implements exponential back-off with jitter on HTTP 429 responses. Persistent failures after the retry budget is exhausted are logged to `SIEMHunterHealth_CL` with `EventType = "AzurePullRateLimitExceeded"` and the pull is skipped for the current cycle; the next cycle attempts a full lookback window.

#### Transformation notes

Pulled events arrive as JSON rows matching the Sentinel table schema (e.g., SignInLogs column names). These are treated as a distinct event class by the normalization layer (doc 04): the `TimeGenerated` column becomes the canonical `EventTime`, and Entra-specific fields map to the OCSF Identity Activity class. The `_siemhunter_provenance` tag identifies which Sentinel table the event was pulled from.

#### Sample event — SignInLogs entry after KQL pull, before local normalization

```json
{
  "TimeGenerated": "2025-01-15T10:23:00Z",
  "UserDisplayName": "Service Account - SIEMhunter Push",
  "AppDisplayName": "SIEMhunter Forwarder",
  "IPAddress": "203.0.113.42",
  "ResultType": 0,
  "AuthenticationRequirement": "singleFactorAuthentication",
  "ConditionalAccessStatus": "success",
  "_siemhunter_provenance": "azure-pull-signinlogs",
  "_siemhunter_ingest_ts": "2025-01-15T10:25:00.000Z"
}
```

> **Detection relevance:** `ResultType = 0` (success) for the SIEMhunter forwarder service account is baseline-normal. Anomalies — unexpected source IP, MFA downgrade, off-hours sign-in — are detected by the certificate-and-IP anomaly self-detection (FR-09 item 1) and by Sigma rules querying the OCSF Identity Activity table.

---

## 3. Source onboarding flow

New sources are registered and activated through the FastAPI control plane (see `02-requirements.md` FR-13). The sequence is:

1. **Register source** — POST to the control plane with the source name, source type (syslog / windows_event_log / netflow / file / azure_pull), and connection parameters (host, port, protocol, credentials if required). The control plane validates the parameters and rejects unknown source types.

2. **Vector pipeline config updated** — The control plane renders the Vector pipeline configuration from a Jinja2 template using the registered source parameters. The rendered config is validated against Vector's config schema before being applied. Vector is sent a reload signal (SIGHUP); it does not restart.

3. **ProvenanceTag assigned** — A `ProvenanceTag` is generated in the format `{source_type}-{source_id}` (e.g., `syslog-tcp-6514`, `wef-dc01`, `netflow-softflowd`). This tag is **immutable** once assigned. If a source is removed and re-added, a new source ID is allocated and a new provenance tag is issued — the old tag is never reused. This ensures historical events can always be traced to their original ingest path.

4. **Test event ingested** — A synthetic or real test event from the new source is ingested and stored in ClickHouse. The control plane validates the stored event's field set against the canonical field table in `04-normalization-and-schema.md`. Missing required fields fail validation and block the source from going live.

5. **Normalization mapping confirmed** — The operator confirms that the normalization mapping for the new source's event class is correct: raw fields resolve to the expected canonical OCSF fields, the ASIM mapping is populated, and the event is queryable by the relevant Sigma rules.

6. **Source goes live** — The control plane sets the source status to `active`. Events begin flowing to ClickHouse and into the detection batch cycle. An entry is written to `SIEMHunterHealth_CL` recording the source activation.

---

## 4. Security controls at the ingest edge

This section is the authoritative reference for ingest-edge controls. Hardening checklist items in `16-hardening-checklist.md` point here. The detection-engineer reading `05-detection-and-anomaly.md` should understand these controls to reason correctly about what telemetry the flood heuristic and decompression self-detections produce.

### 4.1 Hostile input principle

All source-supplied field values are treated as attacker-controlled data. This applies without exception to: `hostname`, `username`, `ip_address`, `appname`, `procid`, `msgid`, and every `EventData` field from Windows Event Logs. These values are:

- **Stored as data** in ClickHouse via parameterized INSERT statements — never via string-concatenated SQL.
- **Never used as authentication identity.** A syslog sender claiming `hostname = dc01.corp.local` is not authenticated as that host.
- **Never interpolated into SQL at query time.** Sigma rule metadata (rule name, tags, technique IDs) must never be interpolated as SQL table names, column names, or unparameterized string literals. The pySigma pipeline validates this at compile time.

### 4.2 Provenance tag

The provenance tag is the only trusted identity for an ingest stream. It is assigned by Vector's pipeline transform at the moment of receipt — it cannot be set, modified, or overridden by content within the event.

| Attribute | Value |
|-----------|-------|
| Field name | `_siemhunter_provenance` (at ingest) → `ProvenanceTag` (in ClickHouse) |
| Format | `{source_type}-{source_id}` |
| ClickHouse column type | `LowCardinality(String)` |
| Mutability | Immutable after assignment |
| Example values | `syslog-tcp-6514`, `wef-dc01`, `netflow-softflowd`, `velociraptor-drop`, `azure-pull-signinlogs` |

### 4.3 Per-event size cap

| Parameter | Default | Scope |
|-----------|---------|-------|
| Maximum event size | 64 KB (65 536 bytes) | Per event / per packet |
| On breach | Event dropped before parsing | — |
| Metric emitted | `SIEMHunterHealth_CL` row with `EventType = "EventSizeCap"`, source, size, timestamp | — |

The cap is applied **before parsing begins** — an oversized event never reaches the parser. This prevents parser-exhaustion attacks via pathologically large syslog messages or netflow packets.

### 4.4 Ingest rate limit

| Parameter | Default | Scope |
|-----------|---------|-------|
| Rate limit threshold | 1 000 events/minute | Per source IP |
| Measurement window | 60-second rolling window | — |
| On breach | Excess events dropped | — |
| Metric emitted | Triggers the flood heuristic in Section 5; also logs to `SIEMHunterHealth_CL` | — |

Rate limiting is enforced by a Vector pipeline condition before events are forwarded downstream.

### 4.5 Decompression-ratio cap

| Parameter | Default | Applicable sources |
|-----------|---------|-------------------|
| Maximum decompression ratio | 100:1 | Forensic artifact drops (Section 2.5); any compressed syslog or netflow input |
| On breach | Decompression aborted; file/event rejected | — |
| Metric emitted | `SIEMHunterHealth_CL` with `EventType = "DecompressionRatioCap"`, source, filename/event ID, timestamp | — |

This control is the primary defence against zip-bomb attacks delivered via attacker-controlled forensic artifact files. The ratio is checked continuously during decompression — it does not wait for the full file to expand.

### 4.6 Parse timeout

| Parameter | Default | Scope |
|-----------|---------|-------|
| Per-event parse timeout | 30 seconds | Syslog, Windows Event Log, netflow |
| Per-file parse timeout | 30 seconds | Forensic artifact drops |
| On breach | Event/file dropped or abandoned | — |
| Metric emitted | `SIEMHunterHealth_CL` with `EventType = "ParseTimeout"`, source, event/file identifier, timestamp | — |

A hanging parser consuming CPU for an unbounded duration is itself a DoS vector. The parse timeout caps the damage.

### 4.7 No identifier injection

Sigma rule metadata — including rule name, rule ID, MITRE ATT&CK technique tags, and author fields — must never be used as SQL table names, column names, or unparameterized string values in queries against ClickHouse. The pySigma pipeline validates this constraint at rule-compilation time: any rule whose compiled SQL output contains a non-parameterized interpolation of rule metadata fields is rejected with a compilation error and does not enter the production ruleset.

---

## 5. Always-on flood heuristic

This is NOT a batch detection. It runs continuously as a **Vector pipeline condition** and does not wait for the 15–60 minute batch cycle. It is one of the five self-detections that must be active before any third-party Sigma rules are enabled (see `02-requirements.md` FR-09).

| Parameter | Value |
|-----------|-------|
| Trigger condition | Events/second from a single source IP exceeds threshold for 60 continuous seconds |
| Default threshold | 1 000 events/minute (approximately 16.7 events/second sustained) |
| Threshold scope | Per source IP, per ingest path |
| On trigger | Emits event to `SIEMHunterHealth_CL` with `EventType = "IngestFlood"`, source IP, source ID, measured rate, and UTC timestamp |
| Threshold configuration | Per-source; overrides the global default |
| ClickHouse dependency | None — the heuristic runs entirely in Vector before events reach ClickHouse |

The flood heuristic provides sub-batch-cycle detection of log-flood attacks and collector misconfiguration without requiring a ClickHouse query. Because it runs in Vector before storage, it also catches floods that would otherwise fill the ClickHouse hot store before the next batch detection runs.

When the flood heuristic fires, the Sentinel forwarder picks up the `SIEMHunterHealth_CL` event at the next batch cycle and creates or updates a Sentinel incident, giving the operator an alert outside the SIEMhunter detection UI (which does not exist — Sentinel is the analyst surface).

---

## 6. References

| Document | Relationship |
|----------|-------------|
| `04-normalization-and-schema.md` | Canonical field table; every raw field documented here maps through that schema. The normalization mapping is confirmed at source onboarding (Section 3, step 5). |
| `05-detection-and-anomaly.md` | Per-detection telemetry prerequisites reference the source IDs and EventIDs defined in Section 2 of this document. |
| `12-data-retention-and-lifecycle.md` | Per-source retention tiers and ClickHouse TTL (Time To Live) settings for each ingest path. |
| `15-adr-forwarder-credential.md` | Credential model for the Azure KQL pull identity (Section 2.6) and the push identity. |
| `16-hardening-checklist.md` | Ingest-edge checklist items (size caps, rate limits, decompression-ratio cap, parse timeout, TLS config for syslog 6514) reference the defaults defined in Section 4 of this document. |
