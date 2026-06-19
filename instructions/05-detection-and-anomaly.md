# SIEMhunter — Detection and Anomaly Specification

**Document:** 05-detection-and-anomaly.md
**Version:** 0.1.0-draft
**Date:** 2026-06-19
**Status:** Active — all detection rules and pipeline logic must conform to this specification.
**Owner:** detection-engineer
**Audience:** detection-engineer, implementer, cloud-security-engineer, docs-maintainer

**Gate dependency:** This document must not be authored before `04-normalization-and-schema.md` is finalized. Every field name, ClickHouse column, and type referenced here derives from the canonical field table in `04` §5.

---

## 1. Detection Architecture Overview

SIEMhunter uses a three-tier detection model. The tiers are complementary, not redundant. Each has a distinct function, a distinct data path, and distinct alerting authority.

### Tier 1 — Rule-Based (Sigma, Primary)

Sigma rules compiled via pySigma to ClickHouse SQL. Runs on a configurable batch schedule (15–60 minutes depending on rule sensitivity and event volume). This tier is the primary incident generator. Detection hits write to `SIEMHunterSecurity_CL` in Sentinel; Sentinel analytics rules fire incidents from that table.

All rules targeting `security_events` are compiled against `rules/pipelines/clickhouse-asim-ocsf.yaml`. This pipeline file is the authoritative schema contract; see `04-normalization-and-schema.md` §8 for the change protocol.

### Tier 2 — ML / Statistical (Advisory)

Isolation Forest plus z-score baseline anomaly scoring. Runs per-entity (user, host, source IP). Output is an `AnomalyScore` field attached to events or detection records. This tier never creates an incident independently and never blocks a detection. Its sole function is to surface statistical outliers for analyst review. See §8 for the full ML specification.

### Tier 3 — Always-On Flood Heuristic (Real-Time, Vector)

The only real-time component in the architecture. A Vector pipeline condition evaluates events-per-second per `ProvenanceTag` continuously. If the rate exceeds the configured threshold for 60 consecutive seconds, Vector emits a synthetic `IngestFlood` event to `SIEMHunterHealth_CL`. The self-detection SELF-002 reads this table on the batch schedule and generates a Sentinel incident. See §7 for the full heuristic specification.

### Tier summary

| Tier | Mechanism | Schedule | Incident authority | Output table |
|------|-----------|----------|--------------------|-------------|
| 1 — Rule-based | Sigma → pySigma → ClickHouse SQL | Batch 15–60 min | Primary | SIEMHunterSecurity_CL |
| 2 — ML/Statistical | Isolation Forest + z-score | Batch (advisory only) | None (advisory) | AnomalyScore field on existing records |
| 3 — Flood heuristic | Vector pipeline condition | Continuous (real-time) | Via SELF-002 on batch | SIEMHunterHealth_CL |

### Self-detections (ship first)

SIEMhunter monitors its own security posture before it monitors anything else. Self-detections in `rules/local/self_detection/` are the first rules to reach production status. They do not depend on external telemetry being fully configured, with one explicit exception documented in §2.

---

## 2. Self-Detections (Ship First — `rules/local/self_detection/`)

These five detections cover SIEMhunter's own attack surface as defined in `14-threat-model.md`. They must reach production status before any Windows/AD or network detection rule is promoted.

### Self-detection table

| Rule ID | Rule Name | Description | Primary Source | ClickHouse Source | Status |
|---------|-----------|-------------|---------------|------------------|--------|
| SELF-001 | CertAnomalyDetected | Service principal (SP) authenticates to Sentinel from an IP not seen in the prior 30-day baseline | SignInLogs (Azure pull via Entra diagnostic settings → Sentinel) | External: Sentinel SignInLogs table (KQL pull) | production |
| SELF-002 | IngestFloodDetected | Vector flood heuristic fired (events/sec per ProvenanceTag exceeded threshold for 60 s) | SIEMHunterHealth_CL (Sentinel) | SIEMHunterHealth_CL where EventType = 'FloodHeuristic' | production |
| SELF-003 | RuleDisableAudit | A Sigma rule was disabled or its detection condition was modified via the FastAPI control plane | SIEMHunterSecurity_CL (Sentinel) | SIEMHunterSecurity_CL where EventType = 'RuleChangeAudit' | production |
| SELF-004 | DecompressionCapTrip | A forensic artifact exceeded the decompression ratio cap defined in `03-data-ingestion-spec.md` | SIEMHunterHealth_CL (Sentinel) | SIEMHunterHealth_CL where EventType = 'DecompressionCapTrip' | production |
| SELF-005 | LedgerReconciliationDelta | Forwarded event count (SIEMhunter ledger) does not match received count in Sentinel at end of batch cycle | SIEMHunterSecurity_CL (Sentinel) | SIEMHunterSecurity_CL where EventType = 'LedgerDelta' | production |

### SELF-001 prerequisite — Entra diagnostic settings (CRITICAL)

**SELF-001 requires that Entra ID AuditLogs and SignInLogs stream to the Sentinel Log Analytics workspace via Entra diagnostic settings.** If this streaming path is not configured, SELF-001 will return zero results on every batch cycle without producing an error. Zero results will be indistinguishable from "no anomalous authentication occurred," which is a silent blind spot, not a safe state.

**Verification before promotion to production:**

1. Confirm Entra diagnostic settings are configured: Azure Portal > Microsoft Entra ID > Monitoring > Diagnostic settings. At minimum, `SignInLogs` and `AuditLogs` must be routed to the Sentinel workspace.
2. Run the KQL query `SignInLogs | where AppDisplayName contains "SIEMhunter" | take 10` in Sentinel Log Analytics. If it returns results, the feed is active.
3. If the query returns no results, SELF-001 must be marked `status: draft` and must not be promoted to production. Set an alert in `SIEMHunterHealth_CL` that fires if the SignInLogs table has received no new rows for the SP's application in the prior 24 hours (indicates broken feed, not just no logins).

This prerequisite is the only external dependency among the five self-detections. SELF-002 through SELF-005 depend only on SIEMhunter's own internal tables and do not require external streaming configuration.

### SELF-001 detection logic (KQL, runs via Sentinel analytics rule)

```kql
// SELF-001: CertAnomalyDetected
// Detects the SIEMhunter service principal authenticating from an IP
// not seen in the 30-day baseline window.
// Prerequisite: Entra SignInLogs must stream to this workspace.
let baseline_days = 30d;
let sp_app_id = "<SIEMhunter_AppRegistration_ClientId>";  // operator-supplied
let known_ips =
    SignInLogs
    | where TimeGenerated > ago(baseline_days)
    | where AppId == sp_app_id
    | where ResultType == 0  // successful sign-ins only for baseline
    | summarize make_set(IPAddress);
SignInLogs
| where TimeGenerated > ago(1h)
| where AppId == sp_app_id
| where IPAddress !in (known_ips)
| project TimeGenerated, IPAddress, ResultType, Location, CorrelationId
| extend RuleId = "SELF-001", Severity = "High"
```

### SELF-002 — IngestFloodDetected (Sigma, batch)

```yaml
title: SIEMhunter Ingest Flood Detected
id: SELF-002
status: production
description: >
  Vector flood heuristic fired. Events per second per ProvenanceTag exceeded
  the configured threshold for 60 consecutive seconds. This may indicate a
  misconfigured log source, a log injection attempt, or a legitimate surge.
author: SIEMhunter detection-engineer
date: 2026-06-19
logsource:
  # Source is SIEMHunterHealth_CL in Sentinel; queried via KQL pull path.
  product: siemhunter
  service: health
detection:
  selection:
    EventType: FloodHeuristic
  condition: selection
fields:
  - TimeGenerated
  - HostName
  - Message
  - Count
  - Severity
falsepositives:
  - Legitimate burst from a verbose log source during a maintenance window.
  - Misconfigured syslog sender transmitting at unthrottled rate.
level: medium
tags:
  - SIEMhunterSelfDetection
```

### SELF-003 — RuleDisableAudit (Sigma, batch)

```yaml
title: SIEMhunter Rule Disabled or Modified
id: SELF-003
status: production
description: >
  A Sigma rule was disabled or its detection condition was modified via the
  FastAPI control plane. Required by FR-14 (rule-change audit). Any gap in
  the audit chain (missing RuleChangeAudit entries for a period) should itself
  be investigated.
author: SIEMhunter detection-engineer
date: 2026-06-19
logsource:
  product: siemhunter
  service: security
detection:
  selection:
    EventType: RuleChangeAudit
  condition: selection
fields:
  - TimeGenerated
  - RuleId
  - RuleVersion
  - Entity
  - Detail
  - Severity
falsepositives:
  - Authorized rule maintenance by the SIEMhunter operator (expected; investigate actor identity, not presence).
level: medium
tags:
  - SIEMhunterSelfDetection
```

### SELF-004 — DecompressionCapTrip (Sigma, batch)

```yaml
title: SIEMhunter Decompression Cap Exceeded
id: SELF-004
status: production
description: >
  A forensic artifact submitted for ingest exceeded the decompression ratio
  cap defined in 03-data-ingestion-spec.md. The artifact was rejected and
  the event was logged. This may indicate a zip bomb or a malformed archive.
author: SIEMhunter detection-engineer
date: 2026-06-19
logsource:
  product: siemhunter
  service: health
detection:
  selection:
    EventType: DecompressionCapTrip
  condition: selection
fields:
  - TimeGenerated
  - HostName
  - Message
  - Severity
falsepositives:
  - Legitimate large archive submitted by analyst (operator should pre-screen large artifacts).
level: high
tags:
  - SIEMhunterSelfDetection
```

### SELF-005 — LedgerReconciliationDelta (Sigma, batch)

```yaml
title: SIEMhunter Ledger Reconciliation Delta
id: SELF-005
status: production
description: >
  The forwarded event count recorded in the SIEMhunter batch ledger does not
  match the received event count visible in Sentinel at end of batch cycle.
  A nonzero delta indicates events were lost in transit, rejected by the DCR,
  or silently dropped by the Logs Ingestion API. Investigate the forwarder
  retry queue and DCR rejection logs.
author: SIEMhunter detection-engineer
date: 2026-06-19
logsource:
  product: siemhunter
  service: security
detection:
  selection:
    EventType: LedgerDelta
  condition: selection
fields:
  - TimeGenerated
  - RuleId
  - Detail
  - Severity
falsepositives:
  - Transient network interruption resolved within the retry window (delta self-clears on next cycle).
  - Sentinel ingestion lag for very recent events (wait one full cycle before escalating).
level: medium
tags:
  - SIEMhunterSelfDetection
```

---

## 3. Windows / Active Directory TTP Detection Set (v0.1.0)

These rules reside in `rules/local/windows_ad/`. All reference the `security_events` table via the `clickhouse-asim-ocsf.yaml` pipeline. Required EventIDs and audit policies are listed; if the audit policy is not active on the relevant system, the rule will produce zero results silently.

### Detection set table

| ATT&CK ID | Technique | Rule Name | Required EventID(s) | Required Audit Policy | Required Source |
|-----------|-----------|-----------|--------------------|-----------------------|----------------|
| T1558.003 | Kerberos Ticket Granting Service (Kerberoasting) | KerberoastingDetected | 4769 | Audit Kerberos Service Ticket Operations: Success — on every Domain Controller | Windows Security Event Log (DC) via WEF |
| T1558.004 | AS-REP Roasting | ASREPRoastingDetected | 4768 | Audit Kerberos Authentication Service: Success + Failure — on every DC | Windows Security Event Log (DC) via WEF |
| T1003.006 | DCSync (OS Credential Dumping) | DCSyncDetected | 4662 | Directory Service Access audit + SACL on domain NC object (see §4) | Windows Security Event Log (DC) via WEF |
| T1003.001 | LSASS Memory Dump | LsassAccessDetected | Sysmon EID 10 | Sysmon must be deployed with ProcessAccess config targeting lsass.exe | Sysmon via WEF |
| T1021.002 | SMB Lateral Movement | SMBLateralMovementDetected | 4624 (LogonType 3) + Netflow dst:445 | Audit Logon/Logoff: Success — on all member servers | Windows Security Event Log + Netflow |
| T1021.001 | RDP Lateral Movement | RDPLateralMovementDetected | 4624 (LogonType 10) + Netflow dst:3389 | Audit Logon/Logoff: Success — on all member servers | Windows Security Event Log + Netflow |

### T1558.003 — Kerberoasting

**ATT&CK technique:** T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting

**What this detects:** A Kerberos service ticket request (EID 4769) using RC4 encryption (ticket encryption type 0x17 or 0x18) for a non-machine account. Legitimate modern Kerberos requests use AES (0x12, 0x11). RC4 requests for non-machine accounts are strongly indicative of offline hash cracking preparation.

**Optimized for:** Precision (alerting mode). RC4 requests for non-machine accounts have very low legitimate prevalence in modern AD environments.

```yaml
title: Kerberoasting Activity Detected
id: windows-ad-001
status: production
description: >
  Detects Kerberos service ticket requests using RC4 encryption for non-machine
  accounts. This is the canonical indicator of Kerberoasting (T1558.003).
  Requires EID 4769 with TicketEncryptionType 0x17 or 0x18 and a ServiceName
  that does not end in '$' (machine accounts are excluded).
author: SIEMhunter detection-engineer
date: 2026-06-19
references:
  - https://attack.mitre.org/techniques/T1558/003/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    # TicketEncryptionType: 0x17 = RC4-HMAC, 0x18 = RC4-HMAC-EXP
    # These values arrive in the Windows event message body; the normalization
    # layer must extract them to a dedicated column. Until that column is added
    # to the canonical schema, filter on CommandLine or UnmappedFields is NOT
    # supported (UnmappedFields is not queryable in Sigma). Track as schema
    # addition requirement.
    # NOTE v0.1.0: Filter on TicketEncryptionType requires a schema addition.
    # Until then, this rule fires on all EID 4769 for non-machine accounts
    # with elevated FP rate. Mark status: test until schema addition is complete.
  filter_machine_accounts:
    # Exclude service tickets for machine accounts (name ending in '$')
    ServiceName|endswith: "$"
  condition: selection and not filter_machine_accounts
fields:
  - TimeGenerated
  - SubjectUserName
  - SubjectDomainName
  - ServiceName
  - TargetUserName
  - IpAddress
falsepositives:
  - Legacy applications that legitimately request RC4 tickets (uncomment TicketEncryptionType
    filter once schema column is added; this eliminates the legacy app FP class).
  - Pentest / red team activity (expected; tag the source IP).
level: high
tags:
  - attack.credential_access
  - attack.t1558.003
  - SIEMhunterDetected
```

**Schema gap note:** TicketEncryptionType is not in the v0.1.0 canonical field table. The normalization layer must extract this field from the EID 4769 event message and the detection-engineer must add it to `04-normalization-and-schema.md` §5 before this rule reaches full precision.

### T1558.004 — AS-REP Roasting

**ATT&CK technique:** T1558.004 — Steal or Forge Kerberos Tickets: AS-REP Roasting

**What this detects:** A Kerberos pre-authentication failure or AS-REQ for an account that has pre-authentication disabled (`DONT_REQ_PREAUTH` flag set). EID 4768 with a result code of 0x0 (success) for such accounts delivers the encrypted AS-REP hash, which can be cracked offline.

**Optimized for:** Precision (alerting mode). Accounts with pre-authentication disabled are a configuration finding in themselves; any AS-REQ for them warrants investigation.

```yaml
title: AS-REP Roasting Activity Detected
id: windows-ad-002
status: production
description: >
  Detects Kerberos AS-REQ events for accounts with pre-authentication disabled
  (EID 4768). The encrypted AS-REP hash returned to the requester can be cracked
  offline. Accounts with DONT_REQ_PREAUTH should be enumerated via §4 prerequisite
  verification and their count should be near zero in a hardened environment.
author: SIEMhunter detection-engineer
date: 2026-06-19
references:
  - https://attack.mitre.org/techniques/T1558/004/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4768
    # Pre-authentication type 0 means pre-auth is disabled for this account.
    # This value arrives in the event message body; requires schema addition
    # (same TicketEncryptionType gap as T1558.003). See schema gap note below.
  filter_machine_accounts:
    TargetUserName|endswith: "$"
  condition: selection and not filter_machine_accounts
fields:
  - TimeGenerated
  - TargetUserName
  - TargetDomainName
  - IpAddress
falsepositives:
  - Legacy applications using accounts with pre-authentication disabled (fix the
    configuration; do not tune the rule).
level: high
tags:
  - attack.credential_access
  - attack.t1558.004
  - SIEMhunterDetected
```

### T1003.006 — DCSync

**ATT&CK technique:** T1003.006 — OS Credential Dumping: DCSync

**What this detects:** A non-DC account requesting directory replication rights using the DS-Replication-Get-Changes and DS-Replication-Get-Changes-All extended rights (specific object GUIDs). EID 4662 is generated when these rights are exercised against the domain naming context object.

**Critical prerequisite:** A System Access Control List (SACL) must be configured on the domain naming context object to generate EID 4662. Without the SACL, no events are generated. See §4 (Detection Prerequisites) for verification steps.

**Optimized for:** Precision (alerting mode). Legitimate DC-to-DC replication generates 4662, which is why machine account exclusion is mandatory.

```yaml
title: DCSync Activity Detected
id: windows-ad-003
status: production
description: >
  Detects use of directory replication rights (DS-Replication-Get-Changes-All)
  by non-Domain-Controller accounts. This is the canonical indicator of DCSync
  credential dumping (T1003.006). Requires EID 4662 with directory replication
  property GUIDs and SACL configured on the domain NC object (see §4).
author: SIEMhunter detection-engineer
date: 2026-06-19
references:
  - https://attack.mitre.org/techniques/T1003/006/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4662
    ObjectName|contains:
      # Domain naming context distinguished name — operator must set this
      # to the actual domain DN, e.g. DC=corp,DC=example,DC=com
      # Wildcard placeholder; refine to exact DN before production deployment.
      - "DC="
    # Replication GUIDs (Properties field in event):
    # 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 = DS-Replication-Get-Changes
    # 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 = DS-Replication-Get-Changes-All
    # 89e95b76-444d-4c62-991a-0facbeda640c = DS-Replication-Get-Changes-In-Filtered-Set
    # NOTE: These GUIDs arrive in the Properties field of EID 4662.
    # The normalization layer must extract them; add to canonical schema as needed.
  filter_machine_accounts:
    SubjectUserName|endswith: "$"
  condition: selection and not filter_machine_accounts
fields:
  - TimeGenerated
  - SubjectUserName
  - SubjectDomainName
  - ObjectName
  - IpAddress
falsepositives:
  - Legitimate DirSync / Azure AD Connect accounts (exclude the specific account name; do not broaden the exclusion).
  - Backup / replication tools with legitimate replication rights (document and exclude by SubjectUserName).
level: critical
tags:
  - attack.credential_access
  - attack.t1003.006
  - SIEMhunterDetected
```

### T1003.001 — LSASS Memory Access

**ATT&CK technique:** T1003.001 — OS Credential Dumping: LSASS Memory

**What this detects:** Sysmon EID 10 (ProcessAccess) where the target process is `lsass.exe` and the `GrantedAccess` mask includes rights sufficient to read process memory. The specific access mask values that indicate credential dumping intent are: 0x1010, 0x1038, 0x143a, and 0x40.

**Optimized for:** Precision (alerting mode). These specific access masks are not used by legitimate Windows system components.

```yaml
title: LSASS Memory Access Detected
id: windows-ad-004
status: production
description: >
  Detects Sysmon ProcessAccess events targeting lsass.exe with access masks
  associated with credential dumping tools (Mimikatz, ProcDump, etc.).
  GrantedAccess values 0x1010, 0x1038, 0x143a, and 0x40 are strong indicators.
  Requires Sysmon deployed with a ProcessAccess rule targeting lsass.exe.
author: SIEMhunter detection-engineer
date: 2026-06-19
references:
  - https://attack.mitre.org/techniques/T1003/001/
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 10
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess|contains:
      - '0x1010'
      - '0x1038'
      - '0x143a'
      - '0x40'
  filter_legitimate:
    # Known legitimate callers of lsass; adjust to environment.
    Image|contains:
      - '\Windows\System32\werfault.exe'
      - '\Windows\System32\taskmgr.exe'
      - '\Windows\System32\svchost.exe'
  condition: selection and not filter_legitimate
fields:
  - TimeGenerated
  - HostName
  - Image
  - CommandLine
  - GrantedAccess
falsepositives:
  - Endpoint security agents that legitimately access LSASS memory for credential
    protection (add their process paths to filter_legitimate after verification).
  - Windows Error Reporting (werfault.exe) — filtered above.
level: critical
tags:
  - attack.credential_access
  - attack.t1003.001
  - SIEMhunterDetected
```

### T1021.002 — SMB Lateral Movement

**ATT&CK technique:** T1021.002 — Remote Services: SMB/Windows Admin Shares

**What this detects:** Network logon (EID 4624, LogonType 3) correlated with Netflow showing a destination port of 445 (SMB). DC-to-DC connections are excluded because legitimate replication traffic uses this pattern. This is a two-source correlation rule; it requires both Windows Security Event Log and Netflow data.

**Optimized for:** Recall (hunt mode). Network logon + SMB is legitimately common; this rule generates a list of lateral movement candidates for triage, not confirmed incidents.

```yaml
title: SMB Lateral Movement Candidate
id: windows-ad-005
status: production
description: >
  Detects network logon events (LogonType 3) correlated with Netflow showing
  SMB traffic (dst:445). Two-source correlation: requires both Windows Security
  Event Log (EID 4624) and Netflow records in security_events.
  Optimized for RECALL (hunt mode) — expect legitimate SMB activity in results;
  triage by entity and time clustering.
author: SIEMhunter detection-engineer
date: 2026-06-19
references:
  - https://attack.mitre.org/techniques/T1021/002/
logsource:
  product: windows
  service: security
detection:
  selection_logon:
    EventID: 4624
    LogonType: 3
  filter_dc_to_dc:
    # Exclude known DC-to-DC replication paths. Operator must populate
    # the DC IP list from the environment; placeholder CIDR below.
    IpAddress|cidr: '10.0.0.0/8'   # Replace with actual DC IP range or list
    TargetUserName|endswith: '$'
  condition: selection_logon and not filter_dc_to_dc
  # Netflow correlation for DstPort 445 is implemented as a Python
  # post-join step (two-table SQL join: security_events for EID 4624
  # + security_events for Netflow records with DstPort = 445,
  # matched on SrcIpAddr and time window). This cannot be expressed
  # as a single-table Sigma rule; see §6 (detection_state table) for
  # the correlation implementation pattern.
fields:
  - TimeGenerated
  - TargetUserName
  - TargetDomainName
  - IpAddress
  - LogonType
falsepositives:
  - Legitimate administrative access via network shares.
  - Backup agents using SMB.
  - Domain replication (filtered above, but filter requires accurate DC IP list).
level: medium
tags:
  - attack.lateral_movement
  - attack.t1021.002
  - SIEMhunterDetected
```

### T1021.001 — RDP Lateral Movement

**ATT&CK technique:** T1021.001 — Remote Services: Remote Desktop Protocol

**What this detects:** Remote Interactive logon (EID 4624, LogonType 10) correlated with Netflow showing destination port 3389 (RDP). Same two-source correlation pattern as T1021.002.

**Optimized for:** Precision (alerting mode). LogonType 10 with dst:3389 is a tighter signal than LogonType 3 with dst:445.

```yaml
title: RDP Lateral Movement Detected
id: windows-ad-006
status: production
description: >
  Detects Remote Interactive logon events (LogonType 10) correlated with Netflow
  showing RDP traffic (dst:3389). Two-source correlation; see SMB rule note.
  Optimized for PRECISION (alerting mode) — LogonType 10 is specific to RDP.
author: SIEMhunter detection-engineer
date: 2026-06-19
references:
  - https://attack.mitre.org/techniques/T1021/001/
logsource:
  product: windows
  service: security
detection:
  selection_logon:
    EventID: 4624
    LogonType: 10
  filter_console:
    # Exclude loopback / local console sessions
    IpAddress|contains:
      - '127.0.0.1'
      - '::1'
  condition: selection_logon and not filter_console
fields:
  - TimeGenerated
  - TargetUserName
  - TargetDomainName
  - IpAddress
  - LogonType
falsepositives:
  - Authorized remote administration (IT staff RDP to servers).
  - Helpdesk sessions (tune by SubjectUserName or source IP subnet).
level: high
tags:
  - attack.lateral_movement
  - attack.t1021.001
  - SIEMhunterDetected
```

---

## 4. Detection Prerequisites

If a prerequisite is not satisfied, the corresponding detection rule produces zero results on every batch cycle with no error. Verifying prerequisites before deploying rules is mandatory. The table below lists each prerequisite, which rule(s) it enables, how to verify it, and where to configure it.

| Prerequisite | Required By | How to Verify | Where to Configure |
|-------------|-------------|---------------|--------------------|
| DC Audit: Kerberos Service Ticket Operations (Success) | T1558.003 (EID 4769) | On a DC: `auditpol /get /subcategory:"Kerberos Service Ticket Operations"` — must show Success. Query ClickHouse: `SELECT count() FROM security_events WHERE EventID = 4769 AND ChannelName = 'Security'` — must return > 0 after a login event. | Group Policy Object (GPO): Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Account Logon > Audit Kerberos Service Ticket Operations. Apply to Domain Controllers OU. |
| DC Audit: Kerberos Authentication Service (Success + Failure) | T1558.004 (EID 4768) | On a DC: `auditpol /get /subcategory:"Kerberos Authentication Service"` — must show Success and Failure. Query ClickHouse for EID 4768 rows. | Same GPO path > Audit Kerberos Authentication Service. Apply to Domain Controllers OU. |
| DC Audit: Directory Service Access + SACL on domain NC | T1003.006 (EID 4662) | Step 1: `auditpol /get /subcategory:"Directory Service Access"` on DC — must show Success. Step 2: Check SACL on domain NC object: open ADSI Edit, right-click domain root object, Properties > Security > Advanced > Auditing. Must have entry for "Everyone" or "Authenticated Users" auditing the two replication GUIDs listed in §3. Step 3: Query ClickHouse for EID 4662 rows with DC= in ObjectName. | Audit policy: GPO > Audit Directory Service Access. SACL: ADSI Edit (adsiedit.msc) or `Set-Acl` PowerShell on domain NC object. Both must be configured; policy without SACL generates no events. |
| Sysmon deployed with ProcessAccess rule for lsass.exe | T1003.001 (Sysmon EID 10) | On target hosts: `Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5` — must succeed. Query ClickHouse for `EventID = 10 AND ChannelName = 'Microsoft-Windows-Sysmon/Operational'`. | Sysmon configuration XML must include a `<ProcessAccess>` rule with `<TargetImage condition="end with">lsass.exe</TargetImage>` and `onmatch="include"`. Deploy via GPO startup script or configuration management. Sysmon binary version >= 13.0 recommended. |
| WEF (Windows Event Forwarding) subscriptions active | All Windows EID rules | On the WEF collector: `wecutil es` — lists active subscriptions. Check ClickHouse for recent events from each expected source HostName. | Windows Event Collector service must be running on the collector host. Source-initiated or collector-initiated subscriptions in `wecutil` / Group Policy (Computer Configuration > Administrative Templates > Windows Components > Event Forwarding). Source computers need the WEF source policy applied. |
| Netflow records ingested for SMB/RDP correlation | T1021.002, T1021.001 | Query ClickHouse: `SELECT count() FROM security_events WHERE DstPort IN (445, 3389) AND TimeGenerated > now() - INTERVAL 1 HOUR`. Must return > 0 if network activity is expected. | Netflow/IPFIX export configured on network devices pointing to the SIEMhunter Vector ingest listener. Netflow records must be normalized to OCSF Network Activity class (OCSF 4001) by the normalization layer. |
| Entra diagnostic settings — SignInLogs + AuditLogs streaming to Sentinel | SELF-001 | In Sentinel workspace: `SignInLogs | take 5` must return results. If it returns an error ("table not found"), diagnostic settings are not configured. | Azure Portal > Microsoft Entra ID > Monitoring > Diagnostic settings. Create a setting targeting the Sentinel Log Analytics workspace. Check "SignInLogs" and "AuditLogs" at minimum. Allow up to 30 minutes for first events to appear after configuration. |
| SIEMHunterHealth_CL and SIEMHunterSecurity_CL tables exist in Sentinel | All self-detections | In Sentinel: `SIEMHunterHealth_CL | take 1` and `SIEMHunterSecurity_CL | take 1` — both must return results (or "no results" rather than "table not found"). | Create custom tables via DCR/DCE ingestion path. Table schemas defined in `04-normalization-and-schema.md` §7. DCR must be created before the SIEMhunter forwarder starts sending events. |

---

## 5. Local-vs-Sentinel Ownership (Anti-Double-Alerting)

Every detection hit must be owned by exactly one system — SIEMhunter or Sentinel — to prevent duplicate incidents. The table below is the authoritative ownership assignment for v0.1.0.

| Detection | Runs In | Incident Created By | Sentinel Analytics Rule Needed? | Tag Applied |
|-----------|---------|--------------------|---------------------------------|------------|
| SELF-001 (CertAnomalyDetected) | Sentinel (KQL analytics rule; pulls SignInLogs) | Sentinel analytics rule fires → Sentinel Incident | Yes — created from the KQL in §2 | SIEMhunterSelfDetection |
| SELF-002 (IngestFloodDetected) | SIEMhunter batch (queries SIEMHunterHealth_CL via forwarder pull) | SIEMhunter → writes record to SIEMHunterSecurity_CL → Sentinel analytics rule fires | Yes — simple query on SIEMHunterSecurity_CL where RuleId = 'SELF-002' | SIEMhunterSelfDetection |
| SELF-003 (RuleDisableAudit) | SIEMhunter batch (queries SIEMHunterSecurity_CL via forwarder pull) | SIEMhunter → writes record to SIEMHunterSecurity_CL → Sentinel analytics rule fires | Yes — simple query on SIEMHunterSecurity_CL where RuleId = 'SELF-003' | SIEMhunterSelfDetection |
| SELF-004 (DecompressionCapTrip) | SIEMhunter batch (queries SIEMHunterHealth_CL via forwarder pull) | SIEMhunter → writes record to SIEMHunterSecurity_CL → Sentinel analytics rule fires | Yes — simple query on SIEMHunterSecurity_CL where RuleId = 'SELF-004' | SIEMhunterSelfDetection |
| SELF-005 (LedgerReconciliationDelta) | SIEMhunter batch (computes delta at end of each batch cycle) | SIEMhunter → writes record to SIEMHunterSecurity_CL → Sentinel analytics rule fires | Yes — simple query on SIEMHunterSecurity_CL where RuleId = 'SELF-005' | SIEMhunterSelfDetection |
| All Windows/AD Sigma rules (windows-ad-001 through windows-ad-006) | SIEMhunter batch (ClickHouse SQL via pySigma) | SIEMhunter → forwards tagged event to SIEMHunterSecurity_CL → Sentinel analytics rule fires | Yes — single catch-all analytics rule on SIEMHunterSecurity_CL where EventType = 'DetectionHit' and Tag contains 'SIEMhunterDetected' | SIEMhunterDetected |
| ML / anomaly scoring | SIEMhunter batch (advisory) | None — advisory only; AnomalyScore field only | No — anomaly scores are never primary incident sources in v0.1.0 | SIEMhunterAnomaly |

**Anti-double-alerting enforcement:**

- SIEMhunter must never create a Sentinel incident directly via the Incidents API for Tier 1 (Sigma) or Tier 2 (ML) detections. All those hits flow through `SIEMHunterSecurity_CL` and are picked up by the Sentinel analytics rule.
- The single catch-all Sentinel analytics rule for `SIEMhunterDetected` events must deduplicate on `RuleId` + `EventRecordID` within its lookback window to prevent duplicate incidents from batch cycle overlap.
- SELF-001 is the sole exception to the `SIEMHunterSecurity_CL` path: it runs entirely within Sentinel as a KQL analytics rule and creates incidents directly. It must not also write to `SIEMHunterSecurity_CL` (that would create a second incident via the catch-all rule).

---

## 6. Stateful Correlation — `detection_state` Table in ClickHouse

Sigma `near` and `sequence` constructs, and any detection requiring multi-event temporal correlation across batch windows, are implemented via a Python state machine that reads from and writes to the `detection_state` table in ClickHouse. This table is not part of the canonical security event schema and is not queried by pySigma-compiled rules.

### Table definition

```sql
CREATE TABLE detection_state
(
    rule_id       String,
    entity_key    String,      -- entity being tracked (e.g., username, IP, hostname)
    window_start  DateTime64(3, 'UTC'),
    event_count   UInt32,
    payload       String,      -- JSON-serialized partial match state
    expiry        DateTime64(3, 'UTC')
)
ENGINE = MergeTree()
ORDER BY (rule_id, entity_key, window_start)
TTL expiry DELETE;
```

### Usage pattern

1. At each batch cycle, the Python correlation engine reads `security_events` for events matching the first condition of a multi-event rule (for example, "first SMB logon from this IP").
2. For each matching entity, it reads the current state record from `detection_state` for that `(rule_id, entity_key)`.
3. If the second condition is satisfied within the configured time window (for example, "second SMB logon from same IP to different host within 5 minutes"), the Python engine emits a detection hit to `SIEMHunterSecurity_CL`.
4. If the window expires without the second condition being satisfied, the TTL DELETE on `detection_state` removes the partial state automatically.

### Rules currently using detection_state (v0.1.0)

None. The v0.1.0 detection set does not include `near`/`sequence` rules. This table is defined here so that the schema is established before it is needed. Rules requiring stateful correlation are deferred to v0.2.

### Expiry and cleanup

The `TTL expiry DELETE` clause automatically removes partial state records whose window has expired. The Python correlation engine sets `expiry` to `window_start + INTERVAL <timespan>` when it creates a state record. There is no manual cleanup required.

---

## 7. Always-On Flood Heuristic

The flood heuristic is the only real-time detection component. It is implemented as a Vector Remap transform condition, not as a Sigma rule or a batch SQL query.

### Mechanism

Vector evaluates the following condition continuously as events flow through the ingest pipeline:

```toml
# Vector pipeline snippet (illustrative — exact syntax in 03-data-ingestion-spec.md)
[transforms.flood_heuristic]
type = "remap"
inputs = ["parsed_events"]
source = '''
  # Count events per ProvenanceTag in a 60-second sliding window.
  # If rate exceeds threshold, emit a synthetic flood event.
  # Threshold: operator-configured; default suggestion 10,000 events/sec per tag.
  if .rate_per_second > get_env_var!("FLOOD_THRESHOLD_EPS") {
    .event_type = "FloodHeuristic"
    .message = "Ingest rate exceeded threshold for ProvenanceTag " + .provenance_tag
    .severity = "Warning"
    .count = to_int(.rate_per_second) ?? 0
    emit .
  }
'''
```

When the condition fires, Vector writes a synthetic event to `SIEMHunterHealth_CL` in Sentinel with:
- `EventType`: `FloodHeuristic`
- `Message`: description of the source tag and rate
- `Count`: events per second at the time of firing
- `Severity`: `Warning` (escalates to `Error` if rate exceeds 5x threshold)

### Batch pickup (SELF-002)

SELF-002 reads `SIEMHunterHealth_CL` on the normal batch schedule (15–60 minutes) and queries for `EventType = 'FloodHeuristic'` rows since the last batch. If any exist, it writes a detection record to `SIEMHunterSecurity_CL`, which triggers a Sentinel incident.

### Why not real-time incidents for flood?

Ingest floods have a very high rate of transient false positives (verbose source bursts, maintenance windows). The 60-second sustained threshold plus the batch pickup cadence provides adequate response latency for a flood event while avoiding alert fatigue from transient spikes.

---

## 8. ML / Anomaly Scoring — Baseline-Only (v0.1.0)

### Model

- **Algorithm:** Isolation Forest (scikit-learn `IsolationForest`) for outlier detection; z-score normalization for per-feature deviation. Separate model per entity type (user, host, source IP).
- **Features:** Event count per time window, unique destination count, logon type distribution, off-hours ratio, new-source indicator.
- **Output:** `AnomalyScore` field (float, 0.0–1.0; higher = more anomalous). Attached to detection records, not to raw security events.

### Training

- Offline only. Training data: 7–14 days of historical `security_events` rows per entity type.
- Retrain cadence: manual, operator-initiated, and reviewed before deployment. No automated retraining in v0.1.0.
- Training must be performed on a workstation or analysis VM, not on the live SIEMhunter host. The model artifact (`.pkl` or equivalent) is transferred to the SIEMhunter host via the operator's deployment process.

### Advisory-only constraint

The ML tier never creates incidents independently and never gates or blocks a Tier 1 (Sigma) detection. Its only permitted outputs are:
1. Attach `AnomalyScore` to a `SIEMHunterSecurity_CL` record that was already created by a Tier 1 rule hit.
2. Write a low-severity informational record to `SIEMHunterSecurity_CL` for entities whose anomaly score exceeds the configured advisory threshold, tagged `SIEMhunterAnomaly`. These records do not trigger Sentinel incidents in v0.1.0.

### Model security

These controls are mandatory and non-negotiable per `14-threat-model.md` (Tampering threat, ML model artifact):

| Control | Requirement |
|---------|-------------|
| Hash verification | The SHA-256 hash of each model artifact must be stored in a separate operator-controlled file at deploy time. The Python detection engine must verify the hash before loading any model file. A hash mismatch must halt model loading and write a `Warning` record to `SIEMHunterHealth_CL`. |
| No pickle from untrusted paths | Model artifacts must be loaded only from the local trusted path declared in SIEMhunter configuration (`SIEMHUNTER_MODEL_PATH`). The Python engine must reject any model file path that is not under this directory prefix. |
| No network model loading | The detection engine must not retrieve model artifacts from any network location (HTTP, SMB share, S3). All model files must be present on the local filesystem at the time of loading. |
| No pickle from untrusted provenance | Model files transferred from external sources must be reviewed and re-hashed by the operator before being placed in `SIEMHUNTER_MODEL_PATH`. |

### Deferred to v0.2

- AI/LLM-based detection (requires HTTP proxy logs or LLM gateway logs; not available in v0.1.0 scope).
- Automated retraining pipeline.
- Per-entity model versioning and rollback.

---

## 9. Rule Lifecycle and Directory Structure

### Directory layout

```
rules/
  sigma/                  — Pinned SigmaHQ community rule snapshot (git submodule,
  |                         locked to a known commit hash). DO NOT modify files here.
  |                         Update only by advancing the submodule commit after review.
  local/
  |  self_detection/      — SELF-001 through SELF-005 (ship first)
  |  windows_ad/          — windows-ad-001 through windows-ad-006 (v0.1.0 TTP set)
  compiled/               — pySigma output (generated SQL). GITIGNORED.
  |                         Regenerated on every CI run; do not commit.
  pipelines/
  |  clickhouse-asim-ocsf.yaml   — Schema contract (this file's companion artifact)
  tests/
     <rule_id>/
        positive.json     — Sample event that MUST match the rule (true positive)
        negative.json     — Sample event that MUST NOT match the rule (true negative)
```

### Rule status lifecycle

```
draft → test → review → production
```

| Status | Meaning | CI behavior |
|--------|---------|-------------|
| draft | Being authored; may not compile cleanly | CI compiles but does not run tests; warnings allowed |
| test | Compiles cleanly; positive/negative test events written | CI compiles + runs tests; no warnings allowed |
| review | Tests pass; awaiting peer review | CI as above; blocks PR merge if tests fail |
| production | Reviewed and approved | CI blocks PR merge on any failure; included in ATT&CK Navigator layer generation |

### CI gate (enforced on every PR)

1. All `production`-status rules must compile against `rules/pipelines/clickhouse-asim-ocsf.yaml` with zero warnings.
2. All `production`-status rules must pass their positive and negative test events in `rules/tests/<rule_id>/`.
3. Any pySigma compilation warning for a `production` rule is a blocking CI failure.
4. ATT&CK Navigator layer (`rules/navigator-layer.json`) must be regenerated on every merge to main.

### Pinned SigmaHQ submodule policy

The `rules/sigma/` directory is a git submodule pointing to a specific commit of the SigmaHQ community rules repository. The pinned commit must be recorded in `.gitmodules` and in `00-orchestration-plan.md`. Updating the submodule requires:
1. Review of the SigmaHQ changelog between the old and new commit.
2. Re-compilation of any community rules used by SIEMhunter against the current pipeline.
3. Update to the pinned commit reference in `00-orchestration-plan.md`.

Community rules from `rules/sigma/` are never run directly against ClickHouse. They are copied to `rules/local/` (with attribution), adapted to the canonical field table, and given a local rule ID before compilation.

---

## 10. ATT&CK Coverage Matrix (v0.1.0)

### What is covered

| ATT&CK ID | Technique | Subtechnique | Coverage Status | Rule ID |
|-----------|-----------|-------------|----------------|---------|
| T1558 | Steal or Forge Kerberos Tickets | .003 Kerberoasting | Covered (precision gap: TicketEncryptionType schema addition pending) | windows-ad-001 |
| T1558 | Steal or Forge Kerberos Tickets | .004 AS-REP Roasting | Covered (same schema gap) | windows-ad-002 |
| T1003 | OS Credential Dumping | .006 DCSync | Covered (requires SACL prerequisite) | windows-ad-003 |
| T1003 | OS Credential Dumping | .001 LSASS Memory | Covered (requires Sysmon prerequisite) | windows-ad-004 |
| T1021 | Remote Services | .002 SMB/Windows Admin Shares | Covered (hunt-mode; Netflow correlation pending full implementation) | windows-ad-005 |
| T1021 | Remote Services | .001 Remote Desktop Protocol | Covered (alerting-mode) | windows-ad-006 |

### Self-detection coverage

| Threat | Self-detection | Coverage status |
|--------|---------------|----------------|
| SP certificate theft / unknown IP auth | SELF-001 | Covered (Entra prerequisite required) |
| Log injection / ingest flood (DoS to detection) | SELF-002 | Covered |
| Rule tampering / insider disabling detections | SELF-003 | Covered |
| Zip bomb / decompression exploit via forensic artifacts | SELF-004 | Covered |
| Event loss / forwarder tampering (silent gaps) | SELF-005 | Covered |

### Deferred to v0.2

| Category | ATT&CK IDs / Scope | Reason for deferral |
|----------|-------------------|---------------------|
| AI / LLM abuse | T1059.x (LLM-generated scripts), OWASP LLM Top 10 | Requires HTTP proxy or LLM gateway logs; not in v0.1.0 ingest scope |
| APT multi-stage campaigns | T1566 (phishing), T1190 (public-facing exploit), T1071 (C2) | Requires email gateway, web proxy, and C2 detection sources not yet ingested |
| Cloud-native detections | T1078.004 (cloud accounts), T1530 (data from cloud) | Requires Azure activity logs beyond Entra SignInLogs |
| NTLM relay / pass-the-hash | T1550.002 | Requires NTLM-specific audit events and netflow correlation not in v0.1.0 set |
| Scheduled task persistence | T1053.005 | Sysmon EID 12/13 required; ASIM table mapping ready but rules not authored |
| Registry persistence | T1547.001 | Sysmon registry events; schema ready (TargetObject/RegistryKey) but rules not authored |

### ATT&CK Navigator layer

The file `rules/navigator-layer.json` is auto-generated on every merge to main by the CI gate. It reflects only `production`-status rules. Do not edit this file manually.

---

## 11. pySigma Compile Limits (Cross-Reference to `04` §9)

This section summarizes the translation limits as actionable rules for the detection engineer. The authoritative technical explanation is in `04-normalization-and-schema.md` §9. The machine-readable version is in `rules/pipelines/clickhouse-asim-ocsf.yaml` under `translation_limits`.

| Sigma Construct | Status | Action Required |
|----------------|--------|----------------|
| `base64offset\|contains` | NOT SUPPORTED | Pre-decode in Python normalization layer; store in new column; write rule against decoded column |
| `re\|` with lookahead | NOT SUPPORTED | Rewrite as multiple positive AND conditions |
| `\|cidr` | Supported via `isIPAddressInRange()` | No action; pipeline handles automatically |
| `contains\|all` on Array(String) | Token semantics only | Use Python post-filter for substring matching inside arrays |
| `near` / `sequence` | NOT SUPPORTED in SQL | Implement via Python state machine + `detection_state` table (§6) |
| `timespan` | Requires manual SQL rewrite | Express as SQL sub-aggregation with explicit time-window GROUP BY |
| `EventID: '4769'` (quoted integer) | ERROR — use unquoted integer | Write `EventID: 4769` (no quotes) |
| Fields not in `field_mappings` | Silent zero-result error | Add field to `04` §5 first, then to pipeline, then write rule |

**Treat every pySigma compilation warning as a blocking error for production-status rules.** A warning that produces compilable SQL may still produce incorrect results (most commonly: zero results because a field was silently omitted). The CI gate enforces this; do not bypass it.

---

## 12. Cross-References

| Document | Relevant sections | Relationship to this document |
|----------|-------------------|------------------------------|
| `04-normalization-and-schema.md` | §5 (canonical field table), §8 (pipeline reference), §9 (translation limits) | Gate document for this spec. All field names derive from §5. This doc must not be authored before `04` is finalized. |
| `rules/pipelines/clickhouse-asim-ocsf.yaml` | Full file | Machine-readable schema contract. Every Sigma rule must compile against this file. Changes to either this doc or `04` must be reflected in the pipeline file simultaneously. |
| `07-sentinel-forwarding.md` | DCR/DCE configuration, custom table ingestion, ASIM table routing | Defines how detection hits in `SIEMHunterSecurity_CL` reach Sentinel and how Sentinel analytics rules fire from them. The anti-double-alerting model in §5 of this document depends on the forwarding architecture in `07`. |
| `14-threat-model.md` | §1 (assets), §2 (adversary model), Tampering threats | Justifies the five self-detections in §2 and the ML model security controls in §8. |
| `03-data-ingestion-spec.md` | Decompression cap, provenance tag assignment, Vector pipeline | Defines the ingest behavior that SELF-004 (DecompressionCapTrip) and SELF-002 (IngestFloodDetected) monitor. The flood heuristic in §7 is implemented in the Vector pipeline described in `03`. |
| `00-orchestration-plan.md` | Step 9 (detection-engineer work), pinned SigmaHQ commit | Defines the sequence of work that produces the files in this specification. The SigmaHQ submodule commit must be recorded in `00` and kept current. |
