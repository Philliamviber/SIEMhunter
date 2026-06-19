# ADR-15 — Forwarder Credential and Identity Design

> **Document role:** Architecture Decision Record (ADR). This is the binding identity design for the SIEMhunter Sentinel forwarder. It is a hand-off contract upstream of `07-sentinel-forwarding.md` and `09-security-and-iam.md`. Later agents MUST NOT deviate from the decisions recorded here without a superseding ADR.
>
> **Status:** Accepted — v0.1.0
> **Deciders:** iam-engineer, security-architect
> **Date:** 2026-06-18

---

## 1. Context

### 1.1 The problem

SIEMhunter runs inside Docker Compose on an on-premise host. It must:

1. **Push** normalized security events and detection alerts outbound to the Microsoft Sentinel (Security Information and Event Management) Logs Ingestion API, via a Data Collection Endpoint (DCE) and Data Collection Rule (DCR).
2. **Pull** Kusto Query Language (KQL) query results from the Log Analytics workspace for optional local enrichment (separate, read-only operation).

Both operations require authenticating to **Microsoft Entra ID** (formerly Azure Active Directory). This is the cloud identity boundary where on-prem credentials are exchanged for short-lived access tokens.

### 1.2 Why this is security-sensitive

The push identity carries **write access to Sentinel**. A compromised push credential can:

- Inject forged security events into the Sentinel workspace, polluting the investigation record.
- Suppress evidence by flooding or overwriting the log stream.
- Enable a confused-deputy attack: make Sentinel analytics fire on attacker-crafted data.

The pull identity carries **read access to a Log Analytics workspace**. A compromised pull credential can:

- Read security events, detection rules, or investigation history stored in Sentinel.
- Enumerate the environment to support lateral movement.

Neither identity is low-value. Both require least-privilege scoping, strong credential binding, and detection controls.

### 1.3 Options considered

**Option A — Client secret (rejected)**

A client secret is a randomly generated string stored in Entra and presented by the app during authentication. It is functionally equivalent to a password. Rejection rationale: client secrets are trivially stolen if they appear in environment variables, `.env` files, logs, or container inspect output — all realistic failure modes in a home-lab Docker deployment. Entra does not log which secret was used when multiple secrets exist, making forensics harder. Secrets also require the operator to manually track and rotate expiry, and the cadence commonly slips. The threat model for SIEMhunter (see `14-threat-model.md`) explicitly rates credential theft as a primary attack vector given the write access to Sentinel.

**Option B — App registration + certificate (chosen)**

The app authenticates using a public/private key pair. The app registration in Entra holds the public certificate (uploaded as a credential). The private key stays on the host and is never transmitted. An attacker who intercepts the TLS (Transport Layer Security) session or reads memory cannot recover the private key from the bearer token alone. Entra logs the certificate thumbprint on every token issuance, providing a per-credential audit trail. This is materially stronger than a shared secret for an on-premise workload. Selected as the v0.1.0 credential anchor.

**Option C — Managed identity (not available — noted for future reference)**

Managed identities are Entra identities issued to Azure-hosted compute resources (VMs, App Service, Container Instances, AKS pods). The platform handles credential issuance and rotation transparently. SIEMhunter runs on an on-premise Docker host, not on Azure compute. Managed identities are therefore not available. **Exception:** Azure Arc-connected machines can receive a managed identity. If the home-lab host is enrolled in Azure Arc in a future version, this option becomes viable and should supersede the certificate approach. Not in v0.1.0 scope.

**Option D — Federated credential / OpenID Connect (OIDC) (future option)**

Federated credentials allow an external identity provider (such as a GitHub Actions runner or a Kubernetes service account) to exchange a short-lived OIDC (OpenID Connect) token for an Entra access token, with no long-lived credential stored on the workload at all. This is the preferred pattern where available. It requires a trusted OIDC issuer reachable by Entra, which SIEMhunter's Docker Compose environment does not provide in v0.1.0. If a self-hosted OIDC issuer is introduced in v0.2+, this option should be re-evaluated before certificate rotation becomes operationally burdensome.

---

## 2. Decision

### 2.1 Two separate identities, separate registrations

SIEMhunter uses **two Entra app registrations** (or two service principals from one app registration, kept logically separate with distinct secret/cert sets). One identity covers the push path; one covers the pull path. They are never combined into a single credential. Rationale: if the forwarder container is compromised, a single combined identity gives the attacker both read and write access. Separation enforces least privilege at the identity layer.

---

### 2.2 Push identity — forward events to Sentinel

| Attribute | Value |
|-----------|-------|
| Display name (suggested) | `siemhunter-push-prod` (or `-lab`) |
| Role | `Monitoring Metrics Publisher` |
| Scope | DCR resource ID (see §4 for exact placeholder format) |
| Graph API permissions | None |
| RG-level roles | None |
| Subscription-level roles | None |

**Scope:** The role assignment MUST be scoped to the exact DCR resource ID, not to a resource group or subscription. The full Azure Resource Manager scope string takes the form documented in §4. Any broader scope is a misconfiguration and violates this ADR.

**What this identity can do:** Ingest log data to the specific DCR. Nothing else. It cannot read the workspace, manage Azure resources, call the Incidents API (which uses a separate, workspace-scoped permission model — see `07-sentinel-forwarding.md`), or authenticate to any other Azure service.

---

### 2.3 Pull identity — optional KQL enrichment

| Attribute | Value |
|-----------|-------|
| Display name (suggested) | `siemhunter-pull-prod` (or `-lab`) |
| Role | `Log Analytics Reader` |
| Scope | Log Analytics workspace resource ID |
| Graph API permissions | None |
| RG-level roles | None |
| Subscription-level roles | None |

**Scope:** The role assignment MUST be scoped to the specific Log Analytics workspace resource ID, not to a resource group or subscription.

**Provisioning condition:** If the KQL pull feature is not enabled in the SIEMhunter deployment configuration, this identity MUST NOT be provisioned. Do not create credentials that are unused. An unused identity with a valid certificate is still an attack surface.

---

### 2.4 Certificate handling

**Generation**

Certificates are generated on the host that will run SIEMhunter. The private key is generated locally and never transmitted to Azure, Entra, or any remote system. Only the public certificate (the `.pem` or `.cer` file without the private key) is uploaded to the Entra app registration.

Acceptable generation tools: `openssl req` (Linux/WSL/Git Bash) or `certutil` / `New-SelfSignedCertificate` (Windows PowerShell). The operator runs the generation command themselves — this ADR does not automate it. The full generation command examples live in `09-security-and-iam.md`.

Certificate parameters:
- Key type: RSA 2048-bit minimum; RSA 4096-bit or EC P-256 preferred.
- Validity period: maximum 1 year (365 days). Entra enforces its own maximum; do not request longer.
- Subject: `CN=siemhunter-push` (or `CN=siemhunter-pull`). The CN (Common Name) is for operator clarity only; Entra uses the thumbprint for matching.

**File permissions**

| Item | Permission |
|------|-----------|
| Private key file on host | `chmod 400`, owned by the UID (User Identifier) the Docker service runs as |
| Host certificate directory | `chmod 700`, not readable by other users |
| Docker secret (loaded at runtime) | tmpfs mount at `/run/secrets/forwarder_cert.pem`, mode `0400` inside the container |

**Docker secrets loading**

Certificates are loaded into the container via Docker's `secrets:` mechanism. This mounts the secret as a tmpfs (in-memory filesystem) file at `/run/secrets/`. The file is never written to the container's writable layer and never appears in `docker inspect` environment output.

The following patterns are prohibited:

- Bind-mounting the certificate directory into the container.
- Passing the certificate path or content via `environment:` blocks in `docker-compose.yml`.
- Including any certificate file or private key in version control.
- Copying the certificate into the container image at build time.

See `08-deployment-hybrid.md` for the Docker Compose `secrets:` block implementation.

---

### 2.5 Certificate rotation runbook (spec stub)

The full runbook, including the operator command sequences, lives in `09-security-and-iam.md`. This stub records the required steps in order so that `07` and `09` authors have the correct sequence as a dependency input.

1. Generate a new certificate/key pair offline on the host using the same parameters as the original.
2. Upload the new public certificate to the Entra app registration as an **additional** credential (do not remove the old one yet). This creates an overlap period where both certificates are valid.
3. Create a new Docker secret containing the new private key (`docker secret create siemhunter_cert_v2 ./new_cert.pem`).
4. Update the `docker-compose.yml` service definition to reference the new secret version and redeploy the forwarder service (`docker compose up -d --no-deps forwarder`).
5. Verify that the forwarder successfully authenticates and forwards events using the new certificate (check SIEMHunterSecurity_CL or forwarder logs).
6. Remove the old certificate from the Entra app registration.
7. Remove the old Docker secret.
8. Record the rotation in the change log and push an audit entry to the `SIEMHunterSecurity_CL` custom log table in Sentinel.

**Rotation schedule:** Rotate no later than 90 days before the certificate expiry date. Entra certificate expiry alerts (configured in Entra ID → App registrations → the specific app → Certificates and secrets) provide the earliest warning.

---

### 2.6 Entra audit monitoring — T1098.001 detection

MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) technique T1098.001 covers the addition of credentials to an existing cloud identity. An attacker who gains access to the Entra tenant can add a new certificate or secret to either app registration, giving themselves a parallel authentication path that bypasses all on-prem controls.

**Required configuration:**

- Entra AuditLogs MUST be streamed to the Sentinel Log Analytics workspace via Entra diagnostic settings. This is an operator prerequisite documented in `09-security-and-iam.md`.
- An analytics rule MUST alert when `AuditLogs` records an `operationType` of `"Add"` on `targetResources` that include `appCredentials` for either the push or pull app registration object ID.
- The alert should fire within one detection cycle (15–60 minutes) and create a Sentinel incident.

This detection is the primary control against unauthorized credential addition. It MUST be active before the push identity is provisioned. Do not provision the identity and defer the detection rule — that creates a window of undetected exposure.

---

### 2.7 Conditional Access

Both workload identities (push and pull) MUST be covered by a Conditional Access policy that restricts authentication to a named location corresponding to the known egress IP address of the on-premise host.

- **Requirement:** Entra ID P1 (Plan 1) license. Conditional Access for workload identities requires at minimum Entra ID P1; verify the license before provisioning.
- **Named location:** Create a named location in Entra ID → Security → Named locations containing only the static egress IP(s) of the home-lab host.
- **Policy:** Block authentication from any IP not in the named location for both app registration service principals.
- **Failure mode:** If the egress IP changes (e.g., ISP (Internet Service Provider) reassignment), the forwarder will fail to authenticate. This is fail-closed and correct. Update the named location as part of the infrastructure change process.

**Operator action required:** Named-location creation, policy assignment, and license verification cannot be automated here. The operator must execute these steps in the Entra portal or via the Microsoft Graph API. Steps are detailed in `09-security-and-iam.md`.

---

### 2.8 App registration ownership

| Setting | Value |
|---------|-------|
| Service account owners | 0 |
| Named human break-glass owners | Maximum 1 |
| Owner review cadence | Quarterly (part of the access review in `09-security-and-iam.md`) |

A break-glass owner exists only to recover from a scenario where the operator cannot authenticate via normal means. The break-glass owner's Entra account must itself be protected by a strong authentication policy (phishing-resistant MFA (Multi-Factor Authentication) or FIDO2 (Fast IDentity Online 2) passkey).

---

### 2.9 Key Vault — v0.2 feature, fail-closed

Azure Key Vault as a certificate broker is deferred to v0.2. When implemented:

- The forwarder retrieves the private key from Key Vault at startup using a separate, narrowly scoped identity (Key Vault Secrets User on the specific secret only).
- Key Vault provides Hardware Security Module (HSM) backing, automatic expiry alerts, and a full access audit log.
- **Fail-closed requirement:** If Key Vault is unreachable at startup, the forwarder MUST refuse to start. It MUST NOT fall back to reading a certificate from an environment variable, a bind-mounted file, or any other fallback path. The fallback itself would become an attack surface.

In v0.1.0, Docker secrets (tmpfs) are the sole credential anchor. The absence of Key Vault in v0.1.0 is an accepted risk documented in §3.

---

## 3. Consequences

### Positive

- **Credential theft is materially harder.** A certificate-based identity requires possession of the private key. A stolen bearer token, a credential-dump from memory, or a leaked `.env` file does not yield the private key. This is a meaningful security improvement over a client secret for an on-premise workload.
- **Blast radius is contained.** A compromised push identity can only ingest to the specific DCR. It cannot read the workspace, manage Azure resources, or escalate within the Entra tenant. A compromised pull identity can only read the specific workspace.
- **Separate identities limit lateral movement.** Compromising the forwarder container gives the attacker at most one of the two identities. The other remains unaffected.
- **Rotation is explicit and testable.** The runbook in §2.5 can be rehearsed in a lab without affecting the production Sentinel workspace (using a dev DCR/DCE pair). An untested rotation runbook is not a runbook.
- **Detection is coupled to the design.** The T1098.001 alert is a first-class deliverable of this ADR, not an afterthought. Monitoring is required before provisioning.

### Negative / Trade-offs

- **Certificate lifecycle adds operational overhead.** The operator must track expiry dates, generate new certificates, and execute the rotation runbook. Client secrets renew in place with less ceremony. For a home-lab operator this is real friction.
- **No managed identity means the cert is the only anchor.** There is no platform-managed rotation or automatic revocation. If the private key is exfiltrated and the theft is not detected before Conditional Access blocks the attacker, the cert can be used from the attacker's infrastructure until it expires or is manually revoked in Entra.
- **Conditional Access requires Entra P1.** This is a cost and licensing dependency. Without it, IP restriction for workload identities is not available, which removes a key compensating control.
- **On-prem deployment has no native Azure identity.** Azure Arc would unlock managed identity and eliminate the certificate lifecycle problem. Enrolling the home-lab host in Arc is out of scope for v0.1.0 but is the recommended long-term path.

### Risks and Mitigations

| Risk | Mitigation |
|------|-----------|
| Private key stolen from Docker host | Docker secrets (tmpfs, mode 0400); chmod 700 on host cert directory; Key Vault HSM backing in v0.2 |
| App-reg owner adds unauthorized credential | Minimize owners (max 1 break-glass); T1098.001 analytics rule fires within one detection cycle; Conditional Access blocks auth from unexpected IPs |
| Certificate expires unnoticed and forwarder stops | Entra certificate expiry alert; rotation runbook documented and rehearsed 90 days before expiry |
| Rotation runbook fails mid-execution, both certs removed prematurely | Overlap period (step 2 before step 6 in §2.5): old cert remains valid until new cert is verified working |
| Forwarder container compromised, token in memory | Short-lived tokens (default Entra access token TTL (Time-To-Live) is 60–75 minutes); private key not in memory after initial auth; Conditional Access IP restriction limits where stolen token can be replayed |
| Key Vault unreachable in v0.2 | Fail-closed: forwarder refuses to start rather than falling back to insecure credential source |

---

## 4. DCR Resource ID Placeholder — Hand-Off Contract

This section is the binding hand-off contract for `07-sentinel-forwarding.md` and `09-security-and-iam.md`. Both documents MUST reference this placeholder format exactly and MUST NOT introduce a different naming convention.

### 4.1 Push identity scope — DCR resource ID

```
DCR_RESOURCE_ID=/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}/providers/Microsoft.Insights/dataCollectionRules/{DCR_NAME}
```

Segment definitions:

| Segment | Description |
|---------|-------------|
| `{SUBSCRIPTION_ID}` | Azure subscription GUID (Globally Unique Identifier), e.g., `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` |
| `{RESOURCE_GROUP}` | Azure resource group name containing the DCR |
| `{DCR_NAME}` | Name of the Data Collection Rule resource |

### 4.2 Pull identity scope — workspace resource ID

```
WORKSPACE_RESOURCE_ID=/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}/providers/Microsoft.OperationalInsights/workspaces/{WORKSPACE_NAME}
```

Segment definitions:

| Segment | Description |
|---------|-------------|
| `{SUBSCRIPTION_ID}` | Same subscription GUID as above |
| `{RESOURCE_GROUP}` | Azure resource group name containing the Log Analytics workspace |
| `{WORKSPACE_NAME}` | Log Analytics workspace name |

### 4.3 Configuration delivery rules

These rules govern how the above values reach the running container. They are binding constraints for `08-deployment-hybrid.md`.

- Both values are set at deploy time. They are **not** hardcoded in application source code or in any file committed to version control.
- They are delivered via a **Docker config object** (`docker config create`) or an **external config file** (`config:` block in `docker-compose.yml`). They are **not** passed via Docker `environment:` blocks. Environment variables appear in `docker inspect` output and in process environment dumps; resource IDs must not leak through that path alongside a credential.
- The forwarder service reads the values from the mounted config file at startup and validates that both values are non-empty, well-formed ARM (Azure Resource Manager) resource ID strings before attempting to authenticate.
- `07-sentinel-forwarding.md` documents the DCE endpoint URL and DCR immutable ID (a separate runtime value), which are deployed alongside this resource ID.
- `09-security-and-iam.md` verifies that the RBAC (Role-Based Access Control) scope recorded in the role assignment matches the `DCR_RESOURCE_ID` value in the deployment config exactly. A mismatch is a misconfiguration and must block deployment.

---

## 5. References

| Document | Relationship |
|----------|-------------|
| `07-sentinel-forwarding.md` | Consumes the push identity and `DCR_RESOURCE_ID` placeholder from this ADR to configure the DCE/DCR data push. Must not define its own credential design. |
| `09-security-and-iam.md` | Full RBAC model, certificate generation commands, complete rotation runbook, access review cadence, and IR (Incident Response) hooks. Extends and operationalizes this ADR. |
| `08-deployment-hybrid.md` | Docker Compose `secrets:` block implementation, Docker config object delivery for resource IDs, and host directory permission setup. |
| `16-hardening-checklist.md` | Checklist line items: cert mode 0400, host dir chmod 700, no bind-mounts, no env-var credentials, T1098.001 rule active before provisioning, Conditional Access policy active before provisioning. |
| `14-threat-model.md` | STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) threat model that motivates the certificate-over-secret decision and scopes the blast-radius analysis. |
