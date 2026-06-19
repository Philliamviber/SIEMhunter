# 16 — SIEMhunter Hardening Checklist

> v0.1.0 hardening baseline — tick every box before declaring the build production-ready.

**How to use this file.** Work through each section in order before promoting the
deployment to production status. Every item is independently verifiable by an
operator or a build agent. Items marked **(CI gate)** must also pass in the
continuous integration pipeline on every pull request or release build. Items
marked **(live check)** require access to a running tenant or host and cannot be
verified statically. Items marked **(IaC)** must be enforced by Terraform or Bicep
before the first forwarder run.

Source documents: `08-deployment-hybrid.md` (container hardening, secrets,
CI gates), `09-security-and-iam.md` (RBAC, cert lifecycle, IR hooks),
`15-adr-forwarder-credential.md` (app registration, credential design,
Conditional Access), `07-sentinel-forwarding.md` (diagnostic prereqs, table
RBAC, DCE config, back-pressure), `03-data-ingestion-spec.md` (size caps, rate
limits, decompression, parse timeout), `04-normalization-and-schema.md`
(parameterized inserts, identifier injection prevention),
`05-detection-and-anomaly.md` (model artifact integrity, rule lifecycle CI gate),
`06-api-control-plane.md` (localhost-only API, fail-closed rule audit, SSRF),
`14-threat-model.md` (13 prioritized findings).

---

## Section 1 — Container Runtime (CIS Docker Benchmark)

Controls from `08-deployment-hybrid.md` §2. Each item applies to **every** service
in `docker-compose.yml` (`vector`, `clickhouse`, `normalization`, `detection`,
`forwarder`, `api`) unless the item names a specific service.

- [ ] All six services have `cap_drop: [ALL]` declared in Compose (08 §2.1)
- [ ] No service has a `cap_add:` entry; if any exception exists, a superseding ADR documents the specific capability by name and the reason a non-privileged alternative is not available (08 §2.1)
- [ ] All six services have `security_opt: [no-new-privileges:true]` (08 §2.2)
- [ ] No service sets `security_opt: seccomp=unconfined`; Docker's default seccomp profile is active on all containers (08 §2.3)
- [ ] On Linux hosts where AppArmor is enabled, Docker's default AppArmor profile (`docker-default`) is confirmed active on all containers (08 §2.3)
- [ ] `userns-remap: "default"` is configured in `/etc/docker/daemon.json` on the host; if this is a Windows Docker Desktop lab deployment, the gap is accepted and documented (08 §2.4)
- [ ] Every `image:` field in `docker-compose.yml` is pinned by SHA-256 digest in the format `name:tag@sha256:{64-hex-chars}`; no tag-only references exist **(CI gate — image-digest script, 08 §4.2)**
- [ ] Every service has `mem_limit` set (08 §2.6, baseline values in §2.6 table)
- [ ] Every service has `cpus` set (08 §2.6)
- [ ] Every service has `pids_limit` set (08 §2.6)
- [ ] Every service has `ulimits: nofile` set with both `soft` and `hard` values (08 §2.6)
- [ ] Every service has a `healthcheck` block with `test`, `interval`, `timeout`, `retries`, and `start_period` defined (08 §2.7)
- [ ] Every service uses `logging: driver: json-file` with `options: max-size` and `max-file` set (08 §2.8)
- [ ] Every service that supports it has `read_only: true`; any service requiring writable paths uses `tmpfs:` mounts for those specific paths instead of disabling read-only for the whole container (08 §2.11)
- [ ] No container mounts `/var/run/docker.sock` or the Windows named-pipe equivalent `//./pipe/docker_engine` — verified by grepping Compose for `docker.sock` **(CI gate — finding #13, 08 §2.10)**
- [ ] The `clickhouse` service is attached only to the `internal: true` Docker network; no `ports:` block is defined for `clickhouse` **(CI gate — 08 §2.9)**
- [ ] The `forwarder` service is the only container attached to the `egress` network; all other services are verified off that network (08 §1.2)

---

## Section 2 — Secrets Discipline

Controls from `08-deployment-hybrid.md` §3 and `15-adr-forwarder-credential.md` §2.4.

- [ ] No secret value appears in any `environment:` block in `docker-compose.yml`; all credentials use `secrets:` blocks that mount via tmpfs at `/run/secrets/` (08 §3.2)
- [ ] Every secret file inside the running container is mounted with mode `0400` (08 §3.1; 15 §2.4)
- [ ] The host directory holding certificate files is `chmod 700`, owned by the UID that runs the Docker daemon (or the remapped UID if `userns-remap` is enabled) (15 §2.4)
- [ ] The four required Docker secrets are defined: `forwarder_cert_push`, `forwarder_cert_pull` (if KQL pull is enabled), `api_auth_token`, and `clickhouse_password` (if ClickHouse auth is enabled) (08 §3.1, secrets table)
- [ ] At container startup each service verifies the secret file exists, is non-empty, and (for certificates) parses as a valid PEM private key; the service refuses to start if verification fails (08 §3.3)
- [ ] `.env` files in the repository contain no secret values — only non-sensitive Docker Compose variable substitutions such as `COMPOSE_PROJECT_NAME` (08 §3.5)
- [ ] `.env`, `*.pem`, `*.key`, `secrets/`, and `rules/compiled/` are listed in `.gitignore` (08 §3.5; go/no-go gate)
- [ ] **gitleaks** CI gate passes on every push with no secrets detected **(CI gate — 08 §4.1)**
- [ ] **truffleHog** CI gate passes on every push with no secrets detected **(CI gate — 08 §4.1)**
- [ ] Configuration values (DCE URI, DCR resource ID, workspace ID) are delivered via a Docker `config:` block or bind-mounted config file, not via `environment:` blocks (15 §4.3; 08 §3.4)
- [ ] The `./config/siemhunter.yaml.example` file with placeholder values is committed to the repository; `./config/siemhunter.yaml` (with real values) is in `.gitignore` (08 §3.4)
- [ ] Key Vault integration (planned for v0.2) is noted as fail-closed: when implemented, the forwarder must refuse to start if Key Vault is unreachable rather than falling back to any other credential source (15 §2.9)

---

## Section 3 — Forwarder Certificate and Azure Identity

Controls from `15-adr-forwarder-credential.md` §2 and `09-security-and-iam.md`.

- [ ] The push certificate/key pair was generated on the host; the private key was never transmitted to Azure, Entra, or any remote system — only the public certificate was uploaded to the Entra app registration (15 §2.4)
- [ ] Certificate key type is RSA 2048-bit minimum; RSA 4096-bit or EC P-256 preferred (15 §2.4)
- [ ] Certificate validity period is 365 days or fewer (15 §2.4)
- [ ] Cert rotation runbook (documented in `09-security-and-iam.md`) has been read and rehearsed at least once in a non-production DCR/DCE pair before the push identity goes live (15 §2.5)
- [ ] Entra certificate expiry alert is configured for both the push and pull (if enabled) app registrations at 90 days before expiry (15 §2.5, rotation schedule)
- [ ] The push app registration (`siemhunter-push-prod`) has zero service-account owners; maximum one named human break-glass owner **(live check — 15 §2.8)**
- [ ] The pull app registration (`siemhunter-pull-prod`, if KQL pull enabled) has zero service-account owners; maximum one named human break-glass owner **(live check — 15 §2.8)**
- [ ] The push identity role assignment is `Monitoring Metrics Publisher` scoped to the exact DCR resource ID — not to a resource group or subscription **(live check — 15 §2.2; IaC)**
- [ ] The pull identity role assignment is `Log Analytics Reader` scoped to the exact Log Analytics workspace resource ID — not to a resource group or subscription **(live check — 15 §2.3; IaC)**
- [ ] Neither the push nor the pull identity has any Microsoft Graph API permissions assigned **(live check — 15 §2.2, 2.3)**
- [ ] Neither the push nor the pull identity has any role assignment at the resource group level or subscription level **(live check — 15 §2.2, 2.3)**
- [ ] Entra Conditional Access named-location policy is active: authentication from both workload identities is restricted to the known static egress IP of the on-premise host; the Entra ID P1 license required for this feature is confirmed **(live check — 15 §2.7)**
- [ ] The pull identity is not provisioned if the KQL pull feature is disabled in the SIEMhunter deployment configuration (15 §2.3)
- [ ] T1098.001 detection is active: Entra AuditLogs are streaming to the Sentinel Log Analytics workspace via Entra diagnostic settings **before** either app registration is provisioned **(live check — 15 §2.6)**
- [ ] A KQL analytics rule is active in Sentinel that alerts on `AuditLogs` recording an `operationType` of `"Add"` on `appCredentials` for either the push or pull app registration object ID (15 §2.6)

---

## Section 4 — Ingest Edge Security

Controls from `03-data-ingestion-spec.md` §4 and `04-normalization-and-schema.md` §5.

- [ ] Per-event size cap is configured in the Vector pipeline for each registered source (default 64 KB / 65,536 bytes for syslog; 9,000 bytes for netflow); oversized events are dropped before parsing and counted in `SIEMHunterHealth_CL` (03 §4.3)
- [ ] Ingest rate limit is configured per source IP in the Vector pipeline (default 1,000 events/minute per source); excess events are dropped and the flood heuristic is triggered (03 §4.4)
- [ ] Decompression-ratio cap is configured for the forensic artifact drop source and for any compressed syslog or netflow input (default 100:1); decompression is aborted immediately when the cap is reached and an event is written to `SIEMHunterHealth_CL` with `EventType = "DecompressionRatioCap"` (03 §4.5)
- [ ] Parse timeout is configured per source (default 30 seconds per event or per file for forensic artifact drops); timed-out events/files are abandoned, renamed with a `.timeout` suffix, and logged to `SIEMHunterHealth_CL` with `EventType = "ParseTimeout"` (03 §4.6)
- [ ] All ClickHouse inserts performed by the normalization service use parameterized INSERT statements; no query uses string concatenation of any source-supplied log field value (03 §4.1; 04 §5)
- [ ] Sigma rule metadata (rule name, rule ID, tags, technique IDs, author) is never interpolated as a SQL table name, column name, or unparameterized string value in any ClickHouse query; pySigma compilation rejects any such interpolation **(CI gate — 03 §4.7)**
- [ ] `ProvenanceTag` is assigned by Vector's pipeline transform at receipt; it cannot be set, modified, or overridden by content within the inbound event (03 §4.2)
- [ ] The always-on flood heuristic is configured in the Vector pipeline and runs continuously without waiting for the batch schedule; it emits `EventType = "IngestFlood"` to `SIEMHunterHealth_CL` when sustained rate exceeds threshold (03 §5; 05 §7)

---

## Section 5 — Detection Pipeline

Controls from `05-detection-and-anomaly.md` §2, §8, §9 and `04-normalization-and-schema.md` §8.

- [ ] `rules/pipelines/clickhouse-asim-ocsf.yaml` exists and its `field_mappings` section matches the canonical field table in `04-normalization-and-schema.md` §5 (04 §8)
- [ ] All `production`-status rules compile against `rules/pipelines/clickhouse-asim-ocsf.yaml` with zero pySigma warnings **(CI gate — 05 §9, CI gate table)**
- [ ] All `production`-status rules have at least one positive-test event and at least one negative-test event in `rules/tests/<rule_id>/`; all tests pass via DuckDB **(CI gate — 08 §4.6)**
- [ ] The ATT&CK Navigator layer at `rules/navigator-layer.json` is regenerated on every merge to main **(CI gate — 05 §9)**
- [ ] The five self-detections (SELF-001 through SELF-005) are deployed and reach `production` status before any Windows/AD or network Sigma rule is promoted to `production` (05 §2, self-detection table)
- [ ] ML model artifact SHA-256 hashes are stored in a separate operator-controlled file; the detection engine verifies each hash before loading any model file; a hash mismatch halts model loading and writes a `Warning` to `SIEMHunterHealth_CL` (05 §8, model security table)
- [ ] No model file is loaded via Python `pickle` from any path that is not under the `SIEMHUNTER_MODEL_PATH` trusted local directory; the detection engine rejects any model path outside this prefix (05 §8, model security table)
- [ ] No model artifact is retrieved from any network location (HTTP, SMB share, S3) at runtime; all model files must be present on the local filesystem before the detection service starts (05 §8)
- [ ] The `detection_state` ClickHouse table exists with the schema defined in `05-detection-and-anomaly.md` §6; this table is required for any future stateful correlation rules (05 §6)
- [ ] The SigmaHQ community rules in `rules/sigma/` are pinned at a known git submodule commit; the commit hash is recorded in `00-orchestration-plan.md` **(CI gate — 05 §9, pinned submodule policy)**
- [ ] Community rules promoted from `rules/sigma/` to `rules/local/` are copied with attribution and assigned a local rule ID; no community rule is run directly from the submodule path (05 §9)

---

## Section 6 — API Control Plane

Controls from `06-api-control-plane.md` §2, §4, §5, §7, §8.

- [ ] The FastAPI service binds to `127.0.0.1` only; the `ports:` block in Compose publishes `127.0.0.1:8080:8080` — not `0.0.0.0:8080:8080` (06 §1; 08 §1.3)
- [ ] Every API endpoint requires a bearer token in the `Authorization: Bearer {token}` header; requests missing or presenting an incorrect token receive `401` (06 §2)
- [ ] The bearer token is stored as a Docker secret (`api_auth_token`) and injected at `/run/secrets/api_token`; it is not set in an environment variable or a config file (06 §2; 08 §3.1)
- [ ] Token comparison uses `hmac.compare_digest` (constant-time); naive string equality (`==`) is not used anywhere in the auth path (06 §2)
- [ ] On startup the FastAPI app verifies `/run/secrets/api_token` exists and is non-empty; if it is missing or empty, the service refuses to start (06 §8, startup validation)
- [ ] OpenAPI docs are disabled in production: `docs_url=None`, `redoc_url=None`, and `openapi_url=None` are all set in the `FastAPI()` constructor (06 §8)
- [ ] The fail-closed rule-change audit sequence is implemented for `PUT /v1/rules/{rule_id}/status` and `DELETE /v1/rules/{rule_id}`: the `RuleChangeAudit` record is written to `SIEMHunterSecurity_CL` via Sentinel **before** the ClickHouse rule-state update; the rule change is rejected with `503` if the Sentinel write fails (06 §4)
- [ ] If the Sentinel audit write fails, the error is logged to `SIEMHunterHealth_CL` with `EventType = "AuditWriteFailure"` and the rule state in ClickHouse is left unchanged (06 §4)
- [ ] SSRF protection blocks outbound HTTP from the API service to `127.0.0.0/8`, `169.254.0.0/16` (including `169.254.169.254` Azure IMDS), and RFC 1918 private ranges except the explicitly allowlisted ClickHouse internal IP and the Sentinel DCE endpoint (06 §5; finding #9)
- [ ] URL validation (SSRF check) is applied to all URL-valued fields in `POST /v1/sources` `connection_params` and in `PUT /v1/forwarder/config` `dce_uri` before the value is accepted (06 §5)
- [ ] No API endpoint returns the bearer token value, any certificate content, any private key, or any other Docker secret value; the `GET /v1/forwarder/config` endpoint redacts all secret-class fields (06 §3.3)
- [ ] All Pydantic request models are defined with `model_config = ConfigDict(extra="forbid")` so that unexpected JSON fields are rejected with `422` (06 §8)

---

## Section 7 — Sentinel Forwarding

Controls from `07-sentinel-forwarding.md` §2, §4, §5, §6, §8, §9.

- [ ] Entra AuditLogs are streaming to the Sentinel Log Analytics workspace via Entra diagnostic settings **(live check — 07 §4.1; finding #12)**
- [ ] Entra SignInLogs are streaming to the Sentinel Log Analytics workspace via Entra diagnostic settings; SELF-001 is marked `draft` until at least one sign-in from the SIEMhunter service principal is confirmed in the workspace **(live check — 07 §4.1; 05 §2 SELF-001 prereq)**
- [ ] Both streaming paths are verified by running KQL spot-checks in Sentinel within 2 hours of enabling diagnostic settings: `AuditLogs | take 5` and `SignInLogs | take 5` each return results rather than a "table not found" error (07 §4.1)
- [ ] Every DCR stream definition includes a `where` clause that drops events missing mandatory ASIM fields before they are written to the Log Analytics table **(IaC — 07 §2.2)**
- [ ] Every DCR stream definition includes a `project` clause that explicitly enumerates all expected ASIM columns and drops any unexpected fields server-side **(IaC — 07 §2.2)**
- [ ] The DCE URI is configuration-driven (injected from IaC output via a Docker config object); it is not hardcoded in application source code or in any file committed to version control (07 §2.1; 15 §4.3)
- [ ] The DCR resource ID is configuration-driven (injected from IaC output); it matches exactly the RBAC scope recorded in the push identity's `Monitoring Metrics Publisher` role assignment **(IaC — 07 §2.2; 15 §4.1)**
- [ ] TLS certificate verification is mandatory on all HTTPS calls to the Sentinel Logs Ingestion API and Incidents API; `verify=False` (or any equivalent) is absent from every code path including development and lab environments (07 §1)
- [ ] The forwarder respects `Retry-After` response headers on HTTP 429; if the header is absent, it defaults to a 60-second wait and applies exponential backoff on subsequent retries (07 §2.5)
- [ ] Failed forward batches that exceed the maximum retry budget are moved to the local on-disk retry queue; they are never silently discarded; `ForwardFail` is emitted to `SIEMHunterHealth_CL` (07 §2.5)
- [ ] The local append-only ledger is maintained per batch cycle recording `batch_id`, `event_count`, `http_status`, and `confirmed`; ledger entries are never deleted or overwritten (07 §2.4)
- [ ] SELF-005 ledger reconciliation runs once per batch cycle comparing the local confirmed event count against Sentinel's received count; a delta exceeding the threshold generates a `LedgerDelta` record in `SIEMHunterSecurity_CL` (07 §2.4; 05 §2 SELF-005)
- [ ] Table-level RBAC is configured in the Log Analytics workspace so that `SIEMHunterHealth_CL` and `SIEMHunterSecurity_CL` are readable only by the SOC analyst role and not by arbitrary workspace contributors **(live check — 07 §8; IaC)**
- [ ] The `SIEMHunterSecurity_CL` table retention policy is set to 90 days minimum, enforced via IaC and an Azure Policy assignment that rejects values below 90 days **(IaC — 07 §6; 07 §9)**
- [ ] The `SIEMHunterHealth_CL` table retention policy is set (suggested 30 days); the value is enforced via IaC **(IaC — 07 §5; 07 §9)**
- [ ] The Sentinel workspace-level retention is 90 days or more **(live check — 07 §9)**
- [ ] A single Sentinel analytics rule owns incident creation for all `SIEMhunterDetected` tagged events in `SIEMHunterSecurity_CL`; no duplicate analytics rule exists for the same event subset (07 §3.3 anti-double-alerting)

---

## Section 8 — Supply Chain

Controls from `08-deployment-hybrid.md` §4 and `09-security-and-iam.md`.

- [ ] All Python service dependencies are pinned with a lockfile (pip-tools `requirements.txt` generated by `pip-compile`, or Poetry `poetry.lock`); unpinned `requirements.txt` files are not used (08 §4 note; supply chain best practice)
- [ ] All base images in `docker-compose.yml` and all `Dockerfile` `FROM` lines are pinned by SHA-256 digest; confirmed by the image-digest CI gate **(CI gate — 08 §4.2)**
- [ ] A Software Bill of Materials (SBOM) is generated for each image on every release build using `syft` or `docker sbom` and attached to the GitHub release as a build artifact **(CI gate on release — 08 §4.3)**
- [ ] **Trivy** scan passes on all images with no unmitigated Critical or High severity CVEs; any exception is documented with CVE ID, reason, estimated fix date, and owner in this file **(CI gate on release and on any PR modifying a Dockerfile — 08 §4.4)**
- [ ] **Grype** scan passes on all images with no unmitigated Critical or High severity CVEs; exceptions documented as above **(CI gate on release and on any PR modifying a Dockerfile — 08 §4.4)**
- [ ] The SigmaHQ community rules submodule in `rules/sigma/` is pinned at a specific commit hash recorded in `.gitmodules` and in `00-orchestration-plan.md`; advancing the submodule requires changelog review and re-compilation of any consumed rules **(CI gate — 05 §9)**
- [ ] Sigma rule promotion from `draft` to `production` requires successful compilation and passing positive/negative test events; no untested rule reaches `production` status **(CI gate — 05 §9; 08 §4.5, 4.6)**
- [ ] Terraform provider versions are pinned in `.terraform.lock.hcl`; this file is committed to the repository; the `.terraform/` directory is in `.gitignore` (08 §6.4)
- [ ] Terraform state is stored in a private Azure Blob Storage container with public access disabled, firewall restricted to known IPs, and soft-delete enabled with 30-day retention; `.tfstate` files are in `.gitignore` (08 §6.1)

---

## Section 9 — Go/No-Go Gate (Pre-Build Code Phase)

All items in this section must be checked before the code-build phase begins. This
gate is a documentation and planning prerequisite, not a runtime control. An
unchecked item here means a decision has not been made, a dependency is unconfirmed,
or a document is missing — proceeding to code without resolving it guarantees a
rework cycle.

- [ ] All 17 numbered instruction documents (`00` through `16`) are present in `instructions/` and non-empty
- [ ] `advise.md` is present in the repository with the five red-team handoff objectives documented
- [ ] `README.md` is present at the repository root
- [ ] `.gitignore` is present and includes at minimum: `.env`, `*.pem`, `*.key`, `secrets/`, `rules/compiled/`, `.terraform/`, `*.tfstate`
- [ ] Cross-reference sweep (docs-maintainer step 20 in `00-orchestration-plan.md`) is complete; no dangling document references or broken internal links remain
- [ ] `10-acceptance-criteria.md` is present and has been reviewed and approved as the definition of done for v0.1.0
- [ ] The Azure Log Analytics workspace is identified; the DCR and DCE are planned and their resource ID placeholder format (from `15-adr-forwarder-credential.md` §4) is used consistently across all instruction documents that reference them
- [ ] The app registration plan is documented: display names for push and pull identities, tenant ID, and the RBAC scope strings are written into the deployment runbook or `09-security-and-iam.md`; the certificate generation command examples from `09` are verified to work in the operator's environment
- [ ] Entra ID P1 license is confirmed for the target tenant — required for Conditional Access for workload identities (15 §2.7); if the license is absent, Section 3 Conditional Access items cannot be completed and this gap is treated as a blocking risk
- [ ] DC audit policy requirements are documented per-detection in `05-detection-and-anomaly.md` §4 (prerequisites table); the operator has a plan to apply the required GPO settings before claiming any Windows/AD rule is active
- [ ] Sysmon deployment plan is confirmed for T1003.001 (LSASS memory access detection): the target hosts are identified, the Sysmon configuration XML includes a `ProcessAccess` rule targeting `lsass.exe`, and a deployment method (GPO startup script or configuration management) is chosen (03 §2.3; 05 §4)
- [ ] Entra diagnostic settings plan is documented for SELF-001: who will create the diagnostic setting, which workspace it targets, and how the spot-check KQL verification will be performed before SELF-001 is promoted to production (07 §4.1; 05 §2 SELF-001 prereq)
- [ ] Docker secrets strategy is confirmed for the on-premise deployment: the four required secrets are listed, their source files are generated on-host before first `docker compose up`, and the host directory permissions (`chmod 700`) are applied (08 §3.1)
- [ ] Supply-chain plan is confirmed: Python lockfile tool is chosen (pip-tools or Poetry), Trivy and Grype are available in the CI environment, syft is available for SBOM generation, and the SigmaHQ submodule is initialized at the pinned commit (08 §4)
- [ ] The `ad-redteamer` Phase 5 red-team exercise is explicitly held — it must not be invoked until the full system is built, all Section 1 through Section 8 items above are checked, and written authorization is obtained from the system owner; this gate is the authorization checkpoint and must not be bypassed (advise.md; threat model §2 adversary model)
