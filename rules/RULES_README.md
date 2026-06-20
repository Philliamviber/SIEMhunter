# Detection Rules

This directory contains SIEMhunter's detection rules in Sigma YAML format, the
pySigma pipeline that compiles them to ClickHouse SQL, and test fixtures.

---

## Directory layout

```
rules/
├── RULES_README.md             — this file
├── pipelines/
│   └── clickhouse-asim-ocsf.yaml  — field name map: Sigma → ClickHouse columns
├── local/                      — rules executed by the detection service
│   ├── self_detection/         — rules that detect attacks on SIEMhunter itself
│   └── windows_ad/             — rules that detect Windows AD / Kerberos / LSASS TTPs
├── sigma/                      — (planned) pinned SigmaHQ community snapshot
├── compiled/                   — generated SQL (gitignored)
└── tests/                      — (planned) positive + negative test event fixtures
```

---

## What is Sigma?

Sigma is a vendor-neutral YAML format for writing detection rules. A Sigma rule
describes what to look for (field values, patterns) and which log source to search.
Tools like pySigma translate Sigma rules into the query language of a specific
platform (ClickHouse SQL in SIEMhunter's case).

The advantage of Sigma: you write the rule once in platform-neutral YAML and
compile it for ClickHouse, Splunk, Elastic, etc. SIEMhunter uses pySigma with
the `sigma-backend-clickhouse` backend.

---

## Rule schema

A minimal valid SIEMhunter Sigma rule:

```yaml
title: Kerberoasting — SPN Enumeration via TGS-REQ
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890   # UUID — must be unique across all rules
status: draft                               # lifecycle status (see below)
description: >
  Detects Kerberos TGS requests for service accounts using RC4 (Type 0x17) encryption.
  Attackers request service tickets for SPN-configured accounts to crack offline.
author: Your Name
date: 2026/06/19
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769                    # MUST be an integer, not a string
    ServiceName|endswith: '$'        # filter: service account names end with $
    TicketEncryptionType: '0x17'     # RC4 encryption — weak, preferred by attackers
  filter:
    TargetUserName|endswith: '$'     # exclude computer accounts
  condition: selection and not filter
falsepositives:
  - Legacy applications requiring RC4 encryption
  - Service accounts with intentionally weak cipher configuration
level: high
tags:
  - attack.t1558.003                 # MITRE ATT&CK: Kerberoasting
  - attack.credential_access
```

### Required fields

| Field | Type | Description |
|-------|------|-------------|
| `title` | string | Human-readable description of what the rule detects |
| `id` | UUID string | Globally unique identifier. Generate with `python3 -c "import uuid; print(uuid.uuid4())"` |
| `status` | string | Lifecycle status (see below) |
| `logsource` | object | Specifies which event source the rule applies to |
| `detection` | object | The detection conditions |
| `level` | string | Severity: `informational`, `low`, `medium`, `high`, `critical` |

### Optional but recommended fields

| Field | Description |
|-------|-------------|
| `description` | What the rule detects and why it matters |
| `author` | Who wrote the rule |
| `date` | When the rule was created (YYYY/MM/DD) |
| `tags` | MITRE ATT&CK technique IDs (e.g., `attack.t1558.003`) |
| `falsepositives` | Known benign conditions that trigger the rule |

---

## Rule lifecycle (status field)

Rules move through a defined lifecycle. The detection service behaviour differs
by status:

| Status | Compiled? | Executed? | Forwarded to Sentinel? | Notes |
|--------|-----------|-----------|------------------------|-------|
| `draft` | No | No | No | Work in progress; not executed |
| `test` | Yes | Yes | No | Running in detection; results reviewed locally |
| `review` | Yes | Yes | No | Peer review in progress; operator inspects results |
| `production` | Yes | Yes | Yes | Fully approved; hits forwarded to Sentinel |
| `disabled` | No | No | No | Explicitly turned off |

A broken production rule (fails to compile) aborts the entire detection cycle.
Always test rules in `draft` or `test` status before promoting to `production`.

### Promoting a rule via the API

```sh
TOKEN=$(cat secrets/api_auth_token.txt)

# Promote a rule from test to production
curl -s -X PUT http://localhost:8080/v1/rules/a1b2c3d4-e5f6-7890-abcd-ef1234567890/status \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"new_status": "production", "reason": "Verified against 2 weeks of live DC logs"}'
```

Every status change is audited to Sentinel (SIEMHunterSecurity_CL) before the
change is applied. This is the SELF-003 detection: any rule disable not reflected
in Sentinel's audit log is a tamper indicator.

---

## Field names: what you can use in detection conditions

Only fields listed in `pipelines/clickhouse-asim-ocsf.yaml` under `field_mappings`
are queryable in Sigma detection conditions. Using an unmapped field causes pySigma
to emit the raw field name in SQL, which ClickHouse will reject.

**Common fields:**

| Sigma field | ClickHouse column | Notes |
|-------------|------------------|-------|
| `EventID` | `EventID` | **Must be an integer**, not a quoted string |
| `Computer` | `HostName` | The host that generated the event |
| `SubjectUserName` | `SubjectUserName` | The actor (who initiated the action) |
| `TargetUserName` | `TargetUserName` | The target (who/what was acted upon) |
| `SubjectDomainName` | `SubjectDomainName` | Actor's domain |
| `Image` | `ProcessImagePath` | Full executable path (Sysmon EID 1, 10) |
| `CommandLine` | `CommandLine` | Full command with arguments |
| `ParentImage` | `ParentProcessImagePath` | Parent process path |
| `GrantedAccess` | `GrantedAccess` | Sysmon EID 10 access mask (hex string) |
| `IpAddress` | `SrcIpAddr` | Source IP (Sysmon EID 3, Windows auth events) |
| `DestAddress` | `DstIpAddr` | Destination IP |
| `IpPort` | `SrcPort` | Source port (UInt16) |
| `DestPort` | `DstPort` | Destination port (UInt16) |
| `ObjectName` | `ObjectName` | File or directory path |
| `TargetObject` | `RegistryKey` | Registry key path (Sysmon EID 12/13) |
| `Hashes.MD5` | `FileMD5` | MD5 hash (lowercase hex, 32 chars) |
| `Hashes.SHA256` | `FileSHA256` | SHA256 hash (lowercase hex, 64 chars) |
| `Channel` | `ChannelName` | Windows event log channel name |
| `ServiceName` | `ServiceName` | Kerberos service name or network service |
| `LogonType` | `LogonType` | Windows logon type integer (UInt8) |

---

## Authoring rules: common mistakes

### EventID as a string

**Wrong:**
```yaml
EventID: '4769'    # quoted string — produces zero results
```

**Correct:**
```yaml
EventID: 4769      # unquoted integer
```

Why: `security_events.EventID` is a ClickHouse `UInt32`. A string literal in a
`UInt32` comparison fails silently (zero results, no error). The pipeline's
`type_hints` section specifies `EventID: uint32` to help pySigma emit integer
literals, but this only works if the Sigma YAML has an unquoted integer.

### Using an unmapped field

**Wrong:**
```yaml
detection:
  selection:
    AccessMask: '0x1fffff'    # not in field_mappings
```

**Effect:** pySigma will emit `AccessMask = '0x1fffff'` in SQL. ClickHouse will
return an error: `Unknown column 'AccessMask'`.

**Fix:** Check `pipelines/clickhouse-asim-ocsf.yaml` for the correct Sigma field
name. For process access mask, use `GrantedAccess` (Sysmon EID 10 only).

### Hash field case sensitivity

ClickHouse `FixedString` comparisons are case-sensitive. Hash values stored in
`FileMD5` and `FileSHA256` are always lowercase hex. Sigma rules and test fixtures
must use lowercase hex or they will produce zero results.

**Wrong:**
```yaml
Hashes.SHA256: 'E3B0C44298FC1C149AFB...'   # uppercase — no match
```

**Correct:**
```yaml
Hashes.SHA256: 'e3b0c44298fc1c149afb...'   # lowercase
```

### Using `near` or `sequence`

These Sigma constructs require a Python state machine (not SQL). Rules using them
must be `status: experimental` and implemented separately. The compiler will skip
them with a warning — they will never execute as SQL-compiled rules.

### Regex with lookahead

ClickHouse uses the RE2 engine, which does not support lookahead or lookbehind.
A Sigma rule with `re:` containing `(?=...)` or `(?!...)` will compile but fail
at ClickHouse query time with a regex compilation error.

**Fix:** Rewrite as multiple AND conditions.

---

## self_detection/ vs windows_ad/ rule sets

### self_detection/

Rules that detect attacks against SIEMhunter's own infrastructure and components.
These fire incidents directly via the Incidents API (not just via SIEMHunterSecurity_CL).
They are the first five rules that must reach production status before any
`windows_ad/` rule is promoted.

| Rule ID | What it detects |
|---------|----------------|
| SELF-001 | CertAnomalyDetected — Sentinel auth from IP outside 30-day baseline |
| SELF-002 | IngestFloodDetected — Vector flood heuristic fired |
| SELF-003 | RuleDisableAudit — Sigma rule disabled/modified via API |
| SELF-004 | DecompressionCapTrip — Forensic artifact exceeded decompression ratio cap |
| SELF-005 | LedgerReconciliationDelta — Forwarded count ≠ Sentinel received count |

### windows_ad/

Rules that detect Active Directory and Windows credential-based TTPs. These write
hits to `SIEMHunterSecurity_CL` and rely on a Sentinel analytics rule to create
incidents — SIEMhunter does not create incidents for these directly.

Planned rules (v0.1.0 scope):
- Kerberoasting (EID 4769 + RC4 encryption)
- AS-REP Roasting (EID 4768 + no pre-authentication)
- DCSync (EID 4662 + DS-Replication-Get-Changes right)
- LSASS access (Sysmon EID 10 + GrantedAccess=0x1010)
- Lateral movement via PsExec/WMI (Sysmon EID 1 + parent/child process patterns)

---

## The pySigma pipeline

`pipelines/clickhouse-asim-ocsf.yaml` is the machine-readable contract between
Sigma field names and ClickHouse column names. It also:

- Defines `type_hints` so pySigma emits the right literal types (integer for EventID, etc.)
- Documents unsupported Sigma constructs (`translation_limits` section) with workarounds
- Defines `logsource_mappings` that inject ChannelName filters automatically

Do not edit this file without also updating `schema.py` (the Python dataclass),
`schema.sql` (the ClickHouse DDL), and any rules that reference changed field names.
Follow the change protocol in `instructions/04-normalization-and-schema.md §8`.
