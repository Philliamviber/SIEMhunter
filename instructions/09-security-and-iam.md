# 09 — SIEMhunter Security and Identity (IAM)

> **Document role:** Consolidated security and identity document for SIEMhunter v0.1.0.
> Draws from the security-architect design, the threat-modeler findings, and the
> cloud-security operational review. Single authoring owner: **iam-engineer**.
>
> This document is the operational authority for identity, secrets, certificate
> lifecycle, incident response, and container security posture. It extends and
> operationalizes the binding decisions made upstream in `15-adr-forwarder-credential.md`
> and `07-sentinel-forwarding.md`. No decision in this document supersedes those
> upstream ADRs; any conflict is a defect in this document.
>
> **Status:** Accepted — v0.1.0
> **Owner:** iam-engineer
> **Date:** 2026-06-19

---

## Table of Contents

1. [Threat Model Summary](#1-threat-model-summary)
2. [Secrets Handling](#2-secrets-handling)
3. [Analyst Access and Control Plane Auth](#3-analyst-access-and-control-plane-auth)
4. [Azure Identity and RBAC Model](#4-azure-identity-and-rbac-model)
5. [Certificate Lifecycle Runbook](#5-certificate-lifecycle-runbook)
6. [Incident Response Hooks](#6-incident-response-hooks)
7. [Container Security Summary](#7-container-security-summary)
8. [Supply Chain](#8-supply-chain)
9. [Outbound-Only Network Posture](#9-outbound-only-network-posture)
10. [References](#10-references)

---

## 1. Threat Model Summary

Full STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of
Service, Elevation of Privilege) analysis and the complete prioritized findings
table live in `14-threat-model.md`. The following three paragraphs summarize the
adversary classes and their primary attack paths. All finding numbers refer to
the table in `14-threat-model.md §6`.

**External log-feeder.** This adversary controls one or more log sources that
SIEMhunter ingests — a syslog emitter, a Windows Event Forwarding endpoint, or a
netflow producer. Their goal is to inject malicious events that either poison the
Sentinel investigation record (forged evidence) or exhaust the ingest pipeline to
blind the detection engine during the batch window. Primary attack paths: crafted
field injection exploiting the normalization parser (finding #2), batch-window
flood to suppress detection results (finding #4), and decompression-ratio attack
to crash or stall Vector (finding #7). These are the two highest-likelihood
findings in the model because they require only control of a log source, not
access to the Docker host.

**Host-landed attacker.** This adversary has obtained code execution on the Docker
host — through an unpatched OS vulnerability, compromised host credentials, or a
container escape. Their goal is to steal the forwarder private key and use it to
forge or tamper with events in Sentinel, or to pivot into the Azure environment.
Primary attack paths: reading the Docker secret from tmpfs (finding #1, rated
Critical impact), swapping an ML model artifact (finding #8), and exploiting the
FastAPI control plane via SSRF to reach the Azure Instance Metadata Service
(finding #9). Host compromise is the highest-impact adversary class; the Docker
host is the true crown jewel of the SIEMhunter deployment.

**Insider or compromised analyst.** This adversary holds valid FastAPI control
plane credentials — either a legitimate analyst acting maliciously or an attacker
who has compromised the analyst's workstation or API token. Their goal is to
disable detections, manipulate Sigma rules, or cover tracks before or during an
intrusion. Primary attack paths: disabling a Sigma rule via the control plane API
without leaving a trace (finding #5), adding an unauthorized credential to the
Entra app registration to create a parallel authentication path (finding #3,
T1098.001). The fail-closed rule-change audit to Sentinel is the primary control
against the detection-blind path; T1098.001 monitoring via Entra AuditLogs is the
primary control against credential-add.

---

## 2. Secrets Handling

### 2.1 Delivery method

All credentials are delivered exclusively via Docker Compose `secrets:` blocks.
There is no other permitted delivery method for any credential in SIEMhunter.

Docker secrets are mounted as tmpfs (in-memory) files inside the container at
`/run/secrets/{secret_name}`. They are never written to the container's writable
layer, never appear in `docker inspect` environment output, and are never visible
to sibling containers.

Secrets required at v0.1.0:

| Secret name | Contents | Consumed by service |
|-------------|----------|---------------------|
| `forwarder_cert_push` | PEM private key for the push app registration | `forwarder` |
| `forwarder_cert_pull` | PEM private key for the pull app registration (only if KQL pull enabled) | `forwarder` |
| `api_auth_token` | Static bearer token for FastAPI control plane auth | `api` |
| `clickhouse_password` | ClickHouse service account password (if auth enabled) | `clickhouse`, `normalization`, `detection` |

Minimum Compose structure:

```yaml
# TEMPLATE — do not commit real key material. Populate at deploy time.
secrets:
  forwarder_cert_push:
    file: ./secrets/forwarder_cert_push.pem   # host path; excluded by .gitignore

services:
  forwarder:
    secrets:
      - forwarder_cert_push
    # secret available inside container at /run/secrets/forwarder_cert_push
```

### 2.2 File permissions

| Item | Required permission | Notes |
|------|--------------------|----|
| Private key file on host | `chmod 400`, owned by service UID | Generated by the operator; never committed |
| Host `secrets/` directory | `chmod 700`, not world-readable | Parent directory of all key files on the host |
| Docker secret at runtime | `0400` inside container at `/run/secrets/` | Enforced by Docker secrets mechanism |

### 2.3 Prohibited patterns

The following patterns are strictly prohibited. Each creates a credential exposure
path that the Docker secrets mechanism specifically avoids.

- **`environment:` blocks for credentials.** Environment variables appear in plain
  text in `docker inspect {container}` output and in `/proc/{pid}/environ` on the
  host. Any secret placed in an environment variable is visible to any process
  that can run `docker inspect` or read from `/proc`. This prohibition is absolute
  and covers private keys, passwords, pre-shared tokens, and connection strings
  that contain passwords.
- **Bind-mounting the certificate directory.** A bind mount of the host secrets
  directory into the container exposes the entire directory to any process in
  the container. Docker secrets mount a single file per secret into tmpfs,
  providing both isolation and scope limitation.
- **Committing secrets to version control.** All private key files, `.env` files
  containing credentials, and any file under `secrets/` are listed in `.gitignore`.
  Both gitleaks and truffleHog run as CI gates on every push to enforce this.
  A credential committed to git history is not revoked by deletion — the history
  must be rewritten with `git filter-repo` and the credential rotated immediately.
- **Copying credentials into a container image at build time.** A `COPY` or `ADD`
  instruction that includes a key file bakes the credential into the image layer
  and into the image registry. Any party that can pull the image can extract the
  credential.
- **Passing credentials as Docker build arguments.** Build arguments are visible
  in the image layer metadata via `docker history`.

### 2.4 Startup validation (fail-closed)

At startup, every service that consumes a Docker secret MUST validate:

1. The expected file exists at `/run/secrets/{secret_name}`.
2. The file is non-empty (size > 0 bytes).
3. For certificate private keys: the file parses as a valid PEM private key.

If any check fails, the service MUST refuse to start and emit a structured error
log identifying which secret file failed validation. The service MUST NOT fall
back to reading from an environment variable, a bind-mounted path, a hardcoded
default, or any other source.

This fail-closed behavior applies equally to the Key Vault broker when it is
implemented in v0.2: if Key Vault is unreachable at startup, the forwarder
refuses to start. There is no fallback. A fallback path would itself become an
attack surface.

### 2.5 Key Vault — v0.2 feature

Azure Key Vault as a certificate broker is deferred to v0.2. When implemented,
the forwarder retrieves the private key from Key Vault at startup using a
separately scoped identity (`Key Vault Secrets User` on the specific secret
only). Key Vault provides HSM (Hardware Security Module) backing, automatic
expiry alerts, and a full access audit log. The fail-closed requirement at
startup (§2.4) applies without exception to the Key Vault path.

---

## 3. Analyst Access and Control Plane Auth

### 3.1 Control plane design

The FastAPI control plane is the only management interface for SIEMhunter v0.1.0.
There is no web UI. All administrative operations (rule enable/disable, health
check, manual detection trigger) are performed via CLI or direct API calls.

The control plane binds exclusively to `127.0.0.1` (loopback). The Compose
`ports` block publishes it as `127.0.0.1:8080:8080`. Publishing on `0.0.0.0`
is a misconfiguration that exposes the control plane to the host LAN.

### 3.2 Authentication

All requests to the FastAPI control plane require a bearer token:

```
Authorization: Bearer {token}
```

The token value is read from the Docker secret mounted at
`/run/secrets/api_auth_token`. It is never hardcoded in source code or in any
committed configuration file.

Token comparison uses `hmac.compare_digest` (Python standard library,
`hmac` module). This function performs a constant-time comparison that does not
short-circuit on the first mismatched byte, preventing timing side-channels that
could allow an attacker to enumerate valid token characters byte by byte.

```python
# TEMPLATE — illustrative pattern only.
import hmac, os

def verify_token(submitted: str) -> bool:
    expected = open("/run/secrets/api_auth_token").read().strip()
    return hmac.compare_digest(
        submitted.encode("utf-8"),
        expected.encode("utf-8")
    )
```

### 3.3 Auth failure logging

Every authentication failure is logged to `SIEMHunterSecurity_CL` with:

| Field | Value |
|-------|-------|
| `EventType` | `AuthFailure` |
| `Severity` | `Medium` (escalate to `High` after 5 failures in 60 seconds from the same IP) |
| `Entity` | Source IP address of the request |
| `TimeGenerated` | UTC timestamp of the failure |
| `Detail` | Human-readable context: endpoint path, HTTP method |

These entries form a brute-force signal. An analyst querying `SIEMHunterSecurity_CL`
for repeated `AuthFailure` entries from the same source IP can identify a
credential-stuffing or token-guessing attempt against the control plane.

### 3.4 Access scope for v0.1.0

SIEMhunter v0.1.0 supports a single analyst or small trusted team. All
authenticated callers share the same API token and have identical access to
all control plane operations. Multi-tenant RBAC (Role-Based Access Control) with
per-analyst permissions and per-rule ownership is deferred to v0.2.

The single-token model is appropriate for a home-lab or small-team deployment.
It is not appropriate for a deployment with more than one trust level among
operators (e.g., a tier-1 analyst who should not be able to disable rules). If
that requirement exists before v0.2, file a new ADR before deploying.

---

## 4. Azure Identity and RBAC Model

SIEMhunter uses two separate Entra (Microsoft Entra ID, formerly Azure Active
Directory) app registrations. They are never combined into a single identity.
Rationale: if the forwarder container is compromised, a single combined identity
gives the attacker both read and write access to Sentinel. Separation enforces
least privilege at the identity layer.

### 4.1 Push identity — forward events to Sentinel

This identity authenticates outbound calls from the forwarder service to the
Logs Ingestion API.

| Attribute | Value |
|-----------|-------|
| Suggested display name | `siemhunter-push-prod` (or `-lab`) |
| Credential type | Certificate (public key uploaded to app registration; private key stays on host) |
| Role | `Monitoring Metrics Publisher` |
| Scope | Exact DCR resource ID (see §4.3 for placeholder format) |
| Graph API permissions | None |
| Resource-group-level roles | None |
| Subscription-level roles | None |
| App registration owners | 0 service accounts; max 1 named human break-glass owner |

**What this identity can do:** Ingest log data to the specific DCR. Nothing else.
It cannot read the workspace, manage Azure resources, call the Incidents API, or
authenticate to any other Azure service.

**What it cannot do:** Read any table in the Log Analytics workspace. The
`Monitoring Metrics Publisher` role scoped to the DCR grants no read access.
The push identity is a one-way write pipe.

### 4.2 Pull identity — optional KQL enrichment

This identity authenticates outbound calls from the forwarder service to the
Log Analytics Query API, used for ledger reconciliation and local enrichment.

| Attribute | Value |
|-----------|-------|
| Suggested display name | `siemhunter-pull-prod` (or `-lab`) |
| Credential type | Certificate (same pattern as push identity) |
| Role | `Log Analytics Reader` |
| Scope | Log Analytics workspace resource ID (see §4.3 for placeholder format) |
| Graph API permissions | None |
| Resource-group-level roles | None |
| Subscription-level roles | None |
| App registration owners | 0 service accounts; max 1 named human break-glass owner |

**Provisioning condition:** This identity MUST NOT be provisioned if the KQL pull
feature is disabled in the SIEMhunter deployment configuration. An unused
identity with a valid certificate is an attack surface. Provision it only when
the feature is enabled.

**Scope warning:** `Log Analytics Reader` at workspace scope grants read access to
all tables in the workspace. Protect this identity's certificate with the same
rigor as the push identity's certificate.

### 4.3 Resource ID placeholder format

These placeholders are the binding hand-off contract from
`15-adr-forwarder-credential.md §4`. Both identities' RBAC scope assignments
MUST use exactly these formats. A mismatch between the RBAC scope and the
resource ID in the deployment config is a misconfiguration that blocks ingestion.

**Push identity scope — DCR resource ID:**

```
/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}/providers/Microsoft.Insights/dataCollectionRules/{DCR_NAME}
```

**Pull identity scope — workspace resource ID:**

```
/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}/providers/Microsoft.OperationalInsights/workspaces/{WORKSPACE_NAME}
```

| Placeholder | Description |
|-------------|-------------|
| `{SUBSCRIPTION_ID}` | Azure subscription GUID, e.g., `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` |
| `{RESOURCE_GROUP}` | Azure resource group name containing the target resource |
| `{DCR_NAME}` | Name of the Data Collection Rule resource |
| `{WORKSPACE_NAME}` | Log Analytics workspace name |

The DCR resource ID value must flow from IaC output to deployment config to RBAC
scope assignment without manual transcription. Use IaC variable references or
deployment pipeline variable passing to enforce the same value end-to-end.

### 4.4 App registration owner minimization and T1098.001 detection

MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) technique
T1098.001 covers the addition of credentials to an existing cloud identity. An
attacker who gains access to the Entra tenant can add a new certificate or secret
to either app registration, giving themselves a parallel authentication path that
bypasses all on-premise controls. This is finding #3 in the threat model and is
rated Critical impact.

**Owner minimization:**

| Setting | Value |
|---------|-------|
| Service account owners | 0 |
| Named human break-glass owners | Maximum 1 per app registration |
| Owner review cadence | Quarterly |

The break-glass owner's Entra account must be protected by phishing-resistant
MFA (Multi-Factor Authentication) or a FIDO2 (Fast IDentity Online 2) passkey.
The break-glass account is for emergency recovery only; it must not be used for
routine operations.

**T1098.001 detection — required before push identity is provisioned:**

The T1098.001 analytics rule MUST be active in Sentinel before the push identity
is provisioned. Provisioning the identity before the detection rule is active
creates a window of undetected exposure.

Detection logic: monitor `AuditLogs` in the Sentinel Log Analytics workspace for
entries where:

- `OperationName` = `"Update application – Certificates and secrets management"`
  or `OperationName` containing `"Add"` on `"appCredentials"`
- `TargetResources` includes the object ID of either the push or pull app
  registration

Any match generates an alert entry in `SIEMHunterSecurity_CL`:

| Field | Value |
|-------|-------|
| `EventType` | `CredentialAddDetected` |
| `Severity` | `Critical` |
| `ATTACKTechnique` | `T1098.001` |
| `Entity` | App registration object ID |
| `Detail` | Actor UPN, credential type added, timestamp |

**Entra AuditLogs prerequisite:** Entra AuditLogs must be streaming to the Sentinel
Log Analytics workspace via Entra diagnostic settings before this detection
produces any results. This is a hard prerequisite — without it, the query returns
zero results silently (finding #12 in the threat model).

Operator verification steps (run before enabling any self-detection that queries
Entra tables):

1. Navigate to Microsoft Entra ID → Diagnostic settings.
2. Confirm a diagnostic setting exists that targets the Sentinel Log Analytics workspace.
3. Confirm the setting includes both `AuditLogs` and `SignInLogs` categories.
4. Run a spot-check KQL query: confirm at least one event from each category
   has arrived in the workspace within the past 2 hours.

### 4.5 Conditional Access

Both workload identities (push and pull) MUST be covered by a Conditional Access
policy that restricts authentication to a named location corresponding to the
known egress IP of the SIEMhunter host.

**Requirements:**

- Entra ID P1 (Plan 1) license. Conditional Access for workload identities
  requires at minimum Entra P1. Verify the license before provisioning either
  identity.
- Create a named location in Entra ID → Security → Named locations containing
  only the static egress IP(s) of the SIEMhunter host.
- Assign a policy that blocks authentication from any IP not in the named
  location for both app registration service principals.

**Failure mode and correct behavior:** If the egress IP changes (for example,
ISP address reassignment), the forwarder fails to authenticate. This is
fail-closed and correct. Update the named location as part of the infrastructure
change process; the outage is an acceptable cost of the IP restriction control.
Authentication failure from an unexpected IP generates an Entra Conditional
Access log entry, which — if Entra diagnostic settings are streaming — appears
in the workspace and should trigger an analyst review.

**Operator action required:** Named-location creation, policy assignment, and
license verification cannot be automated in this document. The operator must
execute these steps in the Entra portal or via the Microsoft Graph API before
either workload identity is provisioned.

---

## 5. Certificate Lifecycle Runbook

TEMPLATE NOTE — The commands below are the authoritative operator runbook.
They assume a Linux host with `openssl` installed and Docker Compose V2.
The operator runs these commands themselves; no automation executes them.
Do not place the generated private key anywhere other than the `secrets/`
directory on the SIEMhunter host.

### 5.1 Initial provisioning

**Step 1 — Generate the certificate and private key on the SIEMhunter host.**

```bash
# Run on the SIEMhunter host in a directory that is not version-controlled.
# Replace 'siemhunter-forwarder' with the CN appropriate for push or pull.

openssl req \
  -x509 \
  -newkey rsa:4096 \
  -keyout forwarder.key \
  -out forwarder.crt \
  -days 365 \
  -nodes \
  -subj "/CN=siemhunter-forwarder"
```

Parameter notes:
- `rsa:4096` — 4096-bit RSA key. The minimum acceptable is 2048-bit; 4096-bit
  is preferred for a credential with write access to Sentinel.
- `-days 365` — maximum validity period. Do not request longer; Entra enforces
  its own maximum.
- `-nodes` — generates the private key without a passphrase. A passphrase would
  prevent unattended container startup; Docker secrets provide the equivalent
  protection by restricting file access to mode 0400.

**Step 2 — Set file permissions.**

```bash
chmod 400 forwarder.key
chmod 644 forwarder.crt

# Create the secrets directory if it does not exist.
mkdir -p ./secrets
chmod 700 ./secrets

# Move the private key to the secrets directory.
mv forwarder.key ./secrets/forwarder_cert_push.pem
```

**Step 3 — Upload the public certificate to the Entra app registration.**

The file uploaded to Entra is `forwarder.crt` (the public certificate). The
private key (`forwarder_cert_push.pem`) is never uploaded and never transmitted.

In the Entra portal:
1. Navigate to Microsoft Entra ID → App registrations → `siemhunter-push-prod`.
2. Select Certificates and secrets → Certificates tab.
3. Click Upload certificate.
4. Upload `forwarder.crt`.
5. Record the certificate thumbprint and expiry date displayed by Entra.

Alternatively, using the Azure CLI (az):

```bash
# Operator runs this. Replace {APP_OBJECT_ID} with the app registration object ID.
az ad app credential reset \
  --id {APP_OBJECT_ID} \
  --cert @forwarder.crt \
  --append
```

**Step 4 — Create the Docker secret.**

```bash
# Operator runs this on the Docker host.
docker secret create forwarder_cert_push ./secrets/forwarder_cert_push.pem
```

**Step 5 — Deploy the forwarder service with the secret mounted.**

Update `docker-compose.yml` to reference `forwarder_cert_push` in the
`forwarder` service secrets list, then deploy:

```bash
docker compose up -d --no-deps forwarder
```

**Step 6 — Verify and record.**

Confirm that the forwarder service is healthy and forwarding events successfully.
Check `SIEMHunterHealth_CL` for a `BatchSuccess` event within one batch cycle.

Record in the change log:
- Certificate thumbprint (from Entra portal or `openssl x509 -in forwarder.crt -fingerprint -noout`)
- Certificate expiry date
- Date of provisioning
- Operator who performed the provisioning

Set a calendar alert 90 days before the expiry date. Entra provides a built-in
notification: navigate to the app registration → Certificates and secrets →
confirm the expiry date is visible. Many teams set a separate calendar reminder
as a redundant alert.

Delete `forwarder.crt` from the working directory after upload. The public
certificate does not need to be retained on the host; it can be re-derived from
the private key if needed.

---

### 5.2 Certificate rotation (run 90 days before expiry)

The rotation procedure maintains an overlap period: the new certificate is
uploaded to Entra and verified before the old certificate is removed. This
prevents a gap in forwarding if the new certificate has an issue.

**Step 1 — Generate a new certificate and private key.**

```bash
# Use a different filename to avoid overwriting the active key.
openssl req \
  -x509 \
  -newkey rsa:4096 \
  -keyout forwarder_new.key \
  -out forwarder_new.crt \
  -days 365 \
  -nodes \
  -subj "/CN=siemhunter-forwarder"

chmod 400 forwarder_new.key
mv forwarder_new.key ./secrets/forwarder_cert_push_v2.pem
```

**Step 2 — Upload the new public certificate to Entra (ADD, do not replace).**

In the Entra portal, navigate to the app registration → Certificates and secrets
→ Certificates tab → Upload certificate. Upload `forwarder_new.crt`.

After upload, both the old and new certificates appear in the Certificates tab.
Entra will accept tokens signed by either certificate during the overlap period.
Do not remove the old certificate yet.

Using the Azure CLI:

```bash
# --append adds the new cert without removing the old one.
az ad app credential reset \
  --id {APP_OBJECT_ID} \
  --cert @forwarder_new.crt \
  --append
```

Record the new certificate thumbprint and expiry date.

**Step 3 — Create a new Docker secret.**

```bash
docker secret create forwarder_cert_push_v2 ./secrets/forwarder_cert_push_v2.pem
```

**Step 4 — Update Compose to use the new secret and redeploy.**

In `docker-compose.yml`, update the `forwarder` service to reference
`forwarder_cert_push_v2` instead of `forwarder_cert_push`. Update the forwarder
application config to reference the new secret path
`/run/secrets/forwarder_cert_push_v2`.

```bash
docker compose up -d --no-deps forwarder
```

**Step 5 — Verify forwarding succeeds with the new certificate.**

Wait for one full batch cycle. Query `SIEMHunterHealth_CL` for a `BatchSuccess`
event timestamped after the redeployment. Confirm the forwarder logs show
authentication using the new certificate thumbprint.

**Step 6 — Remove the old certificate from Entra.**

In the Entra portal: Certificates and secrets → Certificates tab → select the
old certificate by its thumbprint → Delete.

Using the Azure CLI:

```bash
# List credentials to find the key ID of the old certificate.
az ad app credential list --id {APP_OBJECT_ID} --cert

# Remove the old certificate by its key ID.
az ad app credential delete \
  --id {APP_OBJECT_ID} \
  --key-id {OLD_KEY_ID}
```

**Step 7 — Remove the old Docker secret.**

First confirm the forwarder is no longer using the old secret (step 5 must be
complete). Then:

```bash
docker secret rm forwarder_cert_push
```

Remove the old private key file from the host:

```bash
# Securely delete the old key file.
shred -u ./secrets/forwarder_cert_push.pem
```

**Step 8 — Log the rotation.**

Update the change log with:
- Old certificate thumbprint (now revoked)
- New certificate thumbprint
- New expiry date
- Date of rotation
- Operator who performed the rotation

Push an audit entry to `SIEMHunterSecurity_CL` with `EventType = "CertRotationAudit"`.
This confirms the rotation was intentional and provides a reference timestamp for
future ledger reconciliation queries.

---

### 5.3 Certificate expiry alert

Configure Entra certificate expiry notification:

1. Navigate to Entra ID → App registrations → `siemhunter-push-prod`.
2. Select Certificates and secrets.
3. The Certificates tab displays the expiry date for each uploaded certificate.
4. Set a personal calendar alert at 90 days before the expiry date — the
   rotation runbook (§5.2) must begin at this trigger, not later.

Entra does not natively send email alerts for app registration certificate expiry
by default. Consider scripting a monitoring check via the Microsoft Graph API
(`GET /applications/{id}/` and inspecting `keyCredentials[].endDateTime`) and
running it on a schedule to provide automated notification.

---

## 6. Incident Response Hooks

The following three runbooks correspond to the highest-priority security findings
from `14-threat-model.md`. Each runbook includes the trigger condition, immediate
containment actions, and the investigation steps required to close the incident.

Self-detection IDs (SELF-001 through SELF-005) are defined in
`07-sentinel-forwarding.md §3.3`.

---

### IR-001 — Certificate Theft

**Classification:** Severity Critical  
**Finding reference:** Finding #1 in `14-threat-model.md`  
**ATT&CK technique:** T1588.004 (Digital Certificates), T1553 (Subvert Trust Controls)

**Trigger:** SELF-001 fires (the push service principal authenticates from a
second IP address not matching the Conditional Access named location), OR a
manual report of Docker host compromise.

**Immediate actions:**

1. **Revoke the certificate from the Entra app registration immediately.**
   Navigate to Entra ID → App registrations → `siemhunter-push-prod` →
   Certificates and secrets → Certificates tab → select the compromised
   certificate by thumbprint → Delete.

   This action immediately invalidates all tokens issued using that certificate.
   The Logs Ingestion API will reject any subsequent call using a token derived
   from the revoked certificate. There is no grace period — revocation is
   immediate at the Entra token validation layer.

   Using the Azure CLI (if portal access is compromised):
   ```bash
   az ad app credential delete \
     --id {APP_OBJECT_ID} \
     --key-id {COMPROMISED_KEY_ID}
   ```

2. **Remove the Docker secret containing the compromised private key.**
   ```bash
   docker secret rm forwarder_cert_push
   ```
   This prevents the forwarder service from restarting with the compromised key
   after the cert is revoked. The forwarder will fail its startup secret
   validation (§2.4) and refuse to start.

3. **Investigate the Docker host for signs of compromise.**
   Scope the investigation to: what processes have accessed `/run/secrets/` since
   the last forwarder startup? Are there any unfamiliar processes, unexpected
   network connections, or modified files on the host filesystem? Check
   `/var/log/auth.log` (or equivalent) for unexpected logins.

4. **Issue a new certificate following the provisioning runbook (§5.1).**
   Do not reuse the compromised key material. Generate a fresh key pair. Upload
   the new public certificate to the app registration. Verify Conditional Access
   is still active and that the named-location policy is correctly configured
   before restarting the forwarder.

5. **Review `SIEMHunterSecurity_CL` and Sentinel AuditLogs for unauthorized writes.**
   Query `SIEMHunterSecurity_CL` for any `DetectionHit` or `RuleChangeAudit`
   entries that occurred after the estimated time of compromise. Cross-reference
   with the local forwarder logs to determine whether any of those entries
   originated from the SIEMhunter host or from the attacker's infrastructure.

6. **Check ledger reconciliation (SELF-005) for forged events.**
   If the attacker used the stolen certificate to write events to Sentinel from
   their own infrastructure, those events appear in the Sentinel tables but not
   in the local append-only ledger. A ledger delta for the compromise window is a
   high-confidence indicator of Sentinel forgery. Query the local ledger for the
   time window in question and compare against Sentinel table row counts.

7. **File a Sentinel incident for the certificate theft event.** Mark the
   SELF-001 incident as the primary incident. Link any `LedgerDelta` or
   `CredentialAddDetected` incidents as related. Preserve the local ledger file
   as forensic evidence before any cleanup operations.

---

### IR-002 — Ledger Gap (Potential Sentinel Forgery)

**Classification:** Severity High (escalate to Critical if forgery confirmed)  
**Finding reference:** Finding #6 in `14-threat-model.md`  
**ATT&CK technique:** T1565.001 (Stored Data Manipulation), if forgery confirmed

**Trigger:** SELF-005 fires — the forwarded event count does not match the
received event count in Sentinel for the same window and stream. Default
threshold: more than 5% delta or more than 50 events.

**Immediate actions:**

1. **Check `SIEMHunterHealth_CL` for forwarding errors in the same window.**
   Query for `EventType` in (`ForwardRetry`, `ForwardFail`, `PurgeBeforeForward`)
   with `TimeGenerated` in the ledger gap window and matching `BatchId`. A
   `ForwardFail` or `PurgeBeforeForward` entry is a legitimate explanation for a
   count discrepancy: Sentinel was temporarily unreachable or the retry queue
   was evicted. If this explains the gap, treat as a reliability incident, not a
   security incident, and monitor for recurrence.

2. **If no forwarding errors found, escalate.** A ledger gap with no forwarding
   errors means either: (a) the local ledger was tampered with, (b) Sentinel
   received events that SIEMhunter did not send (forgery), or (c) a bug in the
   ledger reconciliation logic. Treat as a potential security incident until (c)
   is ruled out.

3. **Query the local append-only ledger for the gap window.**
   Examine every ledger entry in the time window: `batch_id`, `event_count`,
   `http_status`, `confirmed`. Confirm that the sum of `event_count` for entries
   where `confirmed = true` matches what SIEMhunter believes it forwarded.

4. **Cross-reference with Sentinel table row counts for the same window.**
   Run the following KQL (Kusto Query Language) query in the Sentinel workspace,
   adjusting the time range and stream name:

   ```kql
   // TEMPLATE — adjust WindowStart and WindowEnd to the gap window.
   // Replace 'ASimAuthentication' with the actual stream table name.
   ASimAuthentication
   | where TimeGenerated between (datetime({WindowStart}) .. datetime({WindowEnd}))
   | count
   ```

   Compare the result against the ledger's confirmed `event_count` for the same
   stream and window. A row count in Sentinel that exceeds the ledger's confirmed
   count is a strong indicator of external writes to the DCR.

5. **Check the unexpected-DCR-writer Sentinel analytics rule for hits.**
   This rule (defined in `07-sentinel-forwarding.md §7`) alerts when the DCR
   receives writes from an IP that is not the known SIEMhunter egress IP. Any
   hit in the gap window confirms external writes to the DCR — a stolen
   certificate scenario.

6. **If forgery is confirmed:** Engage the full Sentinel incident response
   process. Preserve the local ledger file as forensic evidence before any
   cleanup. Cross-link with IR-001 if a certificate theft incident is open. The
   forged events in Sentinel cannot be deleted by standard means without a
   support case; document which events are suspected forgeries by their
   `EventOriginalUid` values so analysts can filter them from investigations.

---

### IR-003 — Rule Disable / Detection Blind Spot

**Classification:** Severity High  
**Finding reference:** Finding #5 in `14-threat-model.md`  
**ATT&CK technique:** T1562.001 (Disable or Modify Tools)

**Trigger:** SELF-003 fires (a Sigma rule was disabled or modified via the
FastAPI control plane, as recorded in the rule-change audit), OR a manual review
identifies an unexpected gap in detection coverage.

**Immediate actions:**

1. **Query `SIEMHunterSecurity_CL` for the `RuleDisableDetected` event.**
   Retrieve the full detail field: which rule ID was disabled, when, and from
   which source IP. The fail-closed audit (written to Sentinel before the
   ClickHouse update was applied) ensures this record exists even if the actor
   attempted to cover their tracks by subsequently modifying the local database.

   ```kql
   // TEMPLATE
   SIEMHunterSecurity_CL
   | where EventType == "RuleDisableDetected"
   | where TimeGenerated > ago(24h)
   | project TimeGenerated, RuleId, Entity, Detail, Severity
   | order by TimeGenerated desc
   ```

2. **Determine whether the disable was authorized.**
   Compare the source IP and timestamp against any known authorized maintenance
   windows or change records. If the source IP does not match the expected
   analyst workstation or if no change record exists, treat as unauthorized.

3. **If unauthorized: check whether the API token was compromised.**
   An unauthorized rule disable requires a valid API token. Rotate the
   `api_auth_token` Docker secret immediately:

   ```bash
   # Generate a new token (operator chooses method; example uses openssl).
   openssl rand -hex 32 > ./secrets/api_auth_token_new

   # Create a new Docker secret.
   docker secret create api_auth_token_v2 ./secrets/api_auth_token_new

   # Update docker-compose.yml to reference api_auth_token_v2.
   # Redeploy the api service.
   docker compose up -d --no-deps api
   ```

   Rotate the old secret after confirming the api service starts correctly:
   ```bash
   docker secret rm api_auth_token
   ```

4. **Re-enable the rule from version control.**
   The `rules/local/` directory in version control is the authoritative source
   for all Sigma rules. Re-enable the disabled rule via the FastAPI control plane:

   ```bash
   # TEMPLATE — replace {rule_id} with the actual Sigma rule UUID.
   curl -X PUT http://127.0.0.1:8080/v1/rules/{rule_id}/status \
     -H "Authorization: Bearer {api_auth_token}" \
     -H "Content-Type: application/json" \
     -d '{"status": "production"}'
   ```

   Verify the rule-change audit entry in `SIEMHunterSecurity_CL` confirms the
   re-enable was recorded in Sentinel before the ClickHouse update was applied.

5. **Review the blind-spot window manually.**
   Identify the time window during which the rule was disabled. Determine which
   ATT&CK technique the disabled rule was designed to detect (from the rule's
   `tags` field). Perform a manual hunt for that technique in the event data for
   the blind-spot window, using the ClickHouse data or any available Sentinel
   tables for the same time range.

   The fact that an attacker disabled a specific detection rule is itself a
   strong signal that the technique that rule detects was used during the
   blind-spot window. Prioritize hunting for that technique.

---

## 7. Container Security Summary

Full CIS (Center for Internet Security) Docker Benchmark control descriptions,
justifications, and YAML examples live in `08-deployment-hybrid.md §2`. The
following bullets summarize the mandatory controls that apply to all six services
in the SIEMhunter Compose stack.

- **`cap_drop: ALL` on every service.** Drops all Linux capabilities from the
  container. A compromised container cannot use any privileged kernel feature.
  No capability may be re-added without a superseding ADR and documented
  justification. At v0.1.0, no service requires any capability re-added.

- **`security_opt: no-new-privileges:true` on every service.** Prevents any
  process in the container from gaining additional privileges through `setuid`
  or `setgid` binaries. Primary defense against container breakout through
  privilege escalation.

- **`read_only: true` on every service where the application supports it.**
  Services requiring writable directories use named `tmpfs` mounts for those
  specific paths, not a writable container layer.

- **ClickHouse on `internal: true` network only, no published ports.** The
  internal network flag prevents container-to-host routing. ClickHouse is
  unreachable from the host LAN, the internet, and from the `forwarder` and
  `api` services. Only `normalization` and `detection` connect to it.

- **No Docker socket mounts.** No container may mount `/var/run/docker.sock`
  or the Windows equivalent. A mounted Docker socket gives the container full
  control of the Docker daemon, equivalent to root on the host (finding #13).

- **Non-root containers (service UID not equal to 0).** Every service runs as
  a non-root UID inside the container. Combined with `userns-remap` at the
  daemon level (recommended for v0.1.0, required for hardened deployments), a
  container UID 0 maps to an unprivileged host UID.

- **`forwarder` is the only service on the `egress` network.** All other
  services are blocked from direct outbound internet connections. The forwarder
  is the sole container that can reach the Sentinel DCE endpoint.

- **Control plane (`api`) binds to `127.0.0.1` only.** Published as
  `127.0.0.1:8080:8080`. Never published on `0.0.0.0`.

---

## 8. Supply Chain

### 8.1 Container image pinning

Every `image:` field in `docker-compose.yml` MUST be pinned by SHA-256 digest
in addition to the tag. Format:

```
image: name:tag@sha256:{64-character-hex-hash}
```

Docker image tags are mutable pointers. A registry operator or an attacker with
registry write access can silently replace the image behind a tag. A digest pins
the exact image layer tree; if the content changes, the digest changes and the
pull fails loudly. A CI gate rejects any Compose file containing a tag-only
image reference.

To retrieve the digest for an image:

```bash
docker pull name:tag
docker inspect --format='{{index .RepoDigests 0}}' name:tag
```

### 8.2 Sigma rules pinning

The SigmaHQ community ruleset is included as a git submodule pinned at a known,
reviewed commit SHA. Rules are not pulled from the upstream default branch at
runtime. Any update to the submodule pointer is a deliberate operator action
that goes through code review and the pySigma compilation gate in CI.

### 8.3 Python dependency lockfile

All Python services use either `pip-tools` (with a committed `requirements.txt`
generated from `requirements.in`) or Poetry (with a committed `poetry.lock`).
The lockfile pins every transitive dependency to an exact version and hash.
No service uses `pip install` without a lockfile or with `--no-index` workarounds
that bypass hash verification.

### 8.4 SBOM and vulnerability scanning

- A Software Bill of Materials (SBOM) is generated per release for each built
  image using `syft` or `docker sbom`. The SBOM is attached to the GitHub
  release as a build artifact.
- Both Trivy and Grype scan all images (base layer and application layer) on
  every release build and on any PR that modifies a `Dockerfile`.
- Critical and High severity CVEs (Common Vulnerabilities and Exposures) block
  the release. A documented exception in `16-hardening-checklist.md` is required
  to override a CVE block; the exception must include the CVE ID, reason the fix
  is not yet available, estimated fix date, and owner.

### 8.5 ML model artifact integrity

- No `pickle` deserialization from untrusted paths. The Python `pickle` module
  executes arbitrary code during deserialization; loading a pickled artifact from
  an attacker-controlled path is equivalent to remote code execution.
- Every ML model artifact is hash-verified on load. The expected hash is stored
  in a separate, version-controlled manifest file. If the on-disk hash does not
  match the manifest, the detection service emits a `ModelIntegrityFailure` alert
  and does not load the model (ML scoring falls back to advisory-off, not to an
  alternative model path).

---

## 9. Outbound-Only Network Posture

SIEMhunter initiates all connections outbound. It opens no inbound ports on
the forwarder path. There are no inbound listeners on the Sentinel-facing side,
no webhooks from Azure, and no agent-side server sockets accepting connections
from the cloud.

| Connection | Direction | Endpoint | Protocol |
|------------|-----------|----------|----------|
| Logs Ingestion API (events) | Outbound from forwarder | `https://{dce}.ingest.monitor.azure.com` | HTTPS / TLS |
| Entra token exchange | Outbound from forwarder | `https://login.microsoftonline.com` | HTTPS / TLS |
| Sentinel Incidents API | Outbound from forwarder | Sentinel ARM endpoint | HTTPS / TLS |
| KQL pull (optional) | Outbound from forwarder | `https://api.loganalytics.io` | HTTPS / TLS |
| Control plane | Internal only | `127.0.0.1:8080` | HTTP (localhost) |

**TLS verification:** Mandatory on all Sentinel API calls and all Entra token
exchange calls. TLS verification MUST NOT be disabled in any environment —
not in lab, not during development, not under any operational pressure. Any code
path that sets `verify=False` (Python `requests` / `httpx`) or equivalent is a
defect, not a configuration option.

**SSRF (Server-Side Request Forgery) block on the control plane:** The FastAPI
service blocks outbound connections from the control plane to:

| Blocked range | Reason |
|---------------|--------|
| `127.0.0.0/8` | Loopback — prevents SSRF loops to local services |
| `169.254.0.0/16` | Link-local — blocks Azure IMDS (Instance Metadata Service) at `169.254.169.254`; finding #9 |
| RFC 1918 private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) | Prevents lateral movement to internal network hosts |

Exceptions to the RFC 1918 block (explicitly allowlisted internal IPs, such as
the Docker internal network gateway) must be documented and reviewed. The default
posture is block; exceptions require explicit allowlist entries.

---

## 10. References

| Document | Relationship to this document |
|----------|-------------------------------|
| `15-adr-forwarder-credential.md` | Upstream binding ADR: credential design, two identity registrations, DCR resource ID placeholder format, Docker secrets delivery, cert rotation stub. This document implements and operationalizes that ADR. |
| `14-threat-model.md` | Full STRIDE analysis, adversary model, prioritized findings table, and attack trees. This document's threat summary (§1) and IR runbooks (§6) draw directly from that analysis. |
| `07-sentinel-forwarding.md` | Fail-closed rule-change audit, `SIEMHunterSecurity_CL` schema, `SIEMHunterHealth_CL` schema, self-detection IDs, and the Entra AuditLogs prerequisite. |
| `08-deployment-hybrid.md` | CIS Docker Benchmark controls, full Docker secrets Compose patterns, CI/CD gates, and container resource limits. §7 of this document is a summary cross-reference to §2 of that document. |
| `16-hardening-checklist.md` | Checklist form of all controls in this document, `08`, and `15`. Use during deployment review to verify every control has a pass/fail state. |
