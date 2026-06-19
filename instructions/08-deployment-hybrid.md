# 08 — SIEMhunter Deployment: Hybrid Docker Compose

> **Status:** Authoritative deployment specification for v0.1.0
> **Audience:** Engineers deploying or reviewing SIEMhunter
> **Scope:** Docker Compose topology, CIS Docker Benchmark hardening, secrets
> handling, CI/CD gates, portability, and IaC state management.
> Companion documents: `09-security-and-iam.md` (RBAC, cert rotation),
> `15-adr-forwarder-credential.md` (credential design), `16-hardening-checklist.md`
> (per-requirement checklist).

---

## 1. Deployment topology

SIEMhunter runs as a six-service Docker Compose stack on a single host. Each
service has a defined, narrow responsibility. Services communicate by container
name inside Docker networks; no service depends on host-network routing.

### 1.1 Service summary

| Service | Image origin | Primary role | Network |
|---------|-------------|--------------|---------|
| `vector` | `ghcr.io/vectordotdev/vector` | Ingest edge: syslog, file watcher, WEF receiver | `ingest` + `internal` |
| `clickhouse` | `clickhouse/clickhouse-server` | Local columnar hot store | `internal` only |
| `normalization` | Built from `./services/normalization` | OCSF → ASIM schema normalizer | `internal` |
| `detection` | Built from `./services/detection` | Batch Sigma + ML detection; writes hits to ledger | `internal` |
| `forwarder` | Built from `./services/forwarder` | Logs Ingestion API + Incidents API push to Sentinel | `internal` + `egress` |
| `api` | Built from `./services/api` | FastAPI control plane; admin commands only | `localhost` binding |

### 1.2 Network topology

Three Docker networks are defined, each with a distinct trust level.

```
┌──────────────── ingest network ────────────────┐
│  vector  (receives syslog 5140 TCP/UDP,        │
│           forensic file drops, WEF)            │
└───────────────────────┬────────────────────────┘
                        │
┌──────────────── internal network (internal: true) ─────────────────────────┐
│  vector → clickhouse → normalization → detection → forwarder               │
│  api ──────────────────────────────────────────────────────────────         │
│  NO published ports; unreachable from host LAN or internet                 │
└───────────────────────────────────────────────────┬────────────────────────┘
                                                    │ forwarder only
                                              ┌─────┴──────────┐
                                              │  egress network │
                                              │  outbound HTTPS │
                                              │  to Sentinel    │
                                              └────────────────┘
```

**Key constraint:** ClickHouse is attached to `internal` only. It has no
published ports and no egress-capable interface. The `forwarder` is the only
service on the `egress` network — it is the sole container that can reach the
internet. All other services are blocked from direct outbound connections.

### 1.3 Service detail

#### `vector` — Ingest collector

Vector is the ingestion edge. It receives raw telemetry, attaches a provenance
tag (source identity, receipt timestamp, collector instance ID), and writes
parsed events to ClickHouse.

Listeners (container-internal ports — see section 7 for port mapping rationale):
- `5140/UDP` — syslog UDP (replaces privileged port 514 inside the container)
- `5140/TCP` — syslog TCP (replaces privileged port 514 inside the container)
- File watcher — reads forensic artifact drops from a host-bind-mounted drop
  directory (read-only bind mount; the container cannot write to the host path)
- Windows Event Forwarding (WEF) receiver — HTTP Event Collector compatible
  endpoint for WEC-forwarded Windows Event Log streams

#### `clickhouse` — Local hot store

ClickHouse is a columnar database that stores normalized events and serves as
the detection engine's query target. It is entirely internal: no host port is
published, and it is attached only to the `internal` network.

Only `normalization` and `detection` connect to ClickHouse. The `forwarder`
and `api` do not. The `vector` service writes directly to ClickHouse via the
ClickHouse HTTP interface on its internal network address.

ClickHouse data is persisted to a named Docker volume. The volume is NOT a
bind mount to a host path, so the container filesystem boundary is preserved.

#### `normalization` — Schema normalizer

A Python service that reads raw events written by Vector, applies the
OCSF-to-ASIM field mapping (documented in `04-normalization-and-schema.md`),
and writes normalized records back to the appropriate ClickHouse table. Runs
continuously (not on a cron schedule). Parameterized ClickHouse inserts are
required — no string-concatenated SQL.

#### `detection` — Batch Sigma + ML engine

A Python service that runs on a configurable schedule (default: every 15
minutes). It executes Sigma rules compiled to ClickHouse SQL (via pySigma)
against the normalized event tables, scores results with the advisory ML model,
and writes detection hits to:
1. A local append-only ledger table in ClickHouse.
2. The `forwarder` service queue for Sentinel push.

ML scoring is advisory only: a failed or slow ML inference does not block
Sigma detection results from being written or forwarded.

#### `forwarder` — Sentinel push client

A Python service that forwards two data streams to Microsoft Sentinel:
- **Normalized events** via the Logs Ingestion API (DCE/DCR path).
- **Detection hits as incidents** via the Sentinel Incidents API.

Authentication uses the app registration + certificate pattern defined in
`15-adr-forwarder-credential.md`. The certificate private key is loaded from a
Docker secret mounted at `/run/secrets/forwarder_cert_push.pem` (mode 0400).

The `forwarder` is the only service on the `egress` network. It respects
Sentinel-side rate limiting by honoring `Retry-After` headers and applying
exponential backoff. It verifies TLS on all outbound connections; TLS
verification may never be disabled in any environment.

#### `api` — FastAPI control plane

A FastAPI service that exposes an authenticated, localhost-only HTTP API for
administrative operations (rule enable/disable, forwarder health check, manual
detection trigger). It binds to `127.0.0.1` only; the Compose `ports` block
publishes it on `127.0.0.1:8080:8080` — never `0.0.0.0`.

SSRF protection is required: the API must block outbound requests to loopback,
link-local, and the Azure Instance Metadata Service address
(`169.254.169.254`). See threat model finding #9.

---

## 2. CIS Docker Benchmark hardening

The following controls apply to **every service** in the Compose file without
exception. The word "MUST" below means the control is a hard requirement for
v0.1.0 deployment; it is not optional and cannot be waived without a superseding
ADR with documented justification.

### 2.1 Drop all Linux capabilities (`cap_drop: ALL`)

Every service definition MUST include:

```yaml
cap_drop:
  - ALL
```

Linux capabilities are fine-grained privilege grants (e.g., `CAP_NET_BIND_SERVICE`
allows binding ports below 1024, `CAP_SYS_ADMIN` allows a wide range of
privileged operations). Dropping ALL capabilities means a container that is
compromised cannot use any privileged kernel feature, even if running as root
inside the container.

**No capability may be added back with `cap_add`** unless all of the following
conditions are met: (a) the specific capability is documented by name in this
file and in `16-hardening-checklist.md`, (b) a threat model entry explains why
the need cannot be met by a non-privileged alternative, and (c) a superseding
ADR is filed. At v0.1.0, no service requires any capability re-added.

Syslog port design and `cap_drop: ALL` are compatible: see section 7 for how
port 514 on the host maps to container-internal port 5140, eliminating the need
for `CAP_NET_BIND_SERVICE`.

### 2.2 Prevent privilege escalation (`security_opt: no-new-privileges:true`)

Every service definition MUST include:

```yaml
security_opt:
  - no-new-privileges:true
```

This kernel flag prevents any process inside the container from gaining
additional privileges through `setuid` or `setgid` binaries. Even if an
attacker exploits a vulnerability in the application, they cannot escalate to
root by executing a setuid binary. This is the primary defence against
container breakout through privilege escalation.

### 2.3 Default seccomp and AppArmor profiles

Docker applies a default seccomp (secure computing mode) profile to every
container automatically. This profile blocks approximately 44 dangerous system
calls (including `ptrace`, `kexec_load`, and `mount`). **Do NOT disable this
default by setting `security_opt: seccomp=unconfined`.** No service in
SIEMhunter requires an unconfined seccomp profile.

On Linux hosts where AppArmor is enabled, Docker's default AppArmor profile
(`docker-default`) is also applied automatically. Do not disable it. On hosts
where AppArmor is not available (some minimal Linux distributions, Windows
Docker Desktop), seccomp remains the active filter.

### 2.4 User namespace remapping (`userns-remap`)

`userns-remap` is a Docker daemon-level option (set in `/etc/docker/daemon.json`
on Linux hosts) that maps container UID 0 (root inside the container) to an
unprivileged UID on the host (e.g., UID 100000). Even if a process escapes the
container namespace, it runs as a low-privilege host UID with no meaningful
capabilities on the host filesystem.

- **Recommended for v0.1.0:** Enable `userns-remap` on all Linux hosts running
  SIEMhunter in a home-lab or production context.
- **Required for hardened deployments** (any deployment where the host stores
  other workloads or is accessible to other users).
- **Windows Docker Desktop:** `userns-remap` is not supported on Windows
  Desktop. Accept this gap for lab use; use a Linux host for any deployment
  beyond personal lab experimentation.

To enable, add to `/etc/docker/daemon.json`:

```json
{
  "userns-remap": "default"
}
```

Then restart the Docker daemon. The "default" value creates a `dockremap` user
and group automatically. Refer to Docker documentation for volume ownership
implications when enabling this on an existing deployment.

### 2.5 Pinned image digests

Every `image:` field in `docker-compose.yml` MUST be pinned by SHA-256 digest
in addition to the tag. The format is:

```
image: name:tag@sha256:{64-character-hex-hash}
```

Example (the hash below is illustrative — use the real digest from the registry):

```yaml
image: ghcr.io/vectordotdev/vector:0.36.1@sha256:abc123def456...
```

**Why tags alone are not sufficient:** A Docker image tag is a mutable pointer.
A registry operator or an attacker with registry write access can silently
replace the image behind a tag. A digest pins the exact image layer tree; if
the content changes the digest changes and the pull fails loudly. This is a
supply chain integrity control.

To retrieve the digest for an image:

```bash
docker pull name:tag
docker inspect --format='{{index .RepoDigests 0}}' name:tag
```

The CI image-digest verification gate (section 4) will reject any Compose file
that contains a tag-only reference.

### 2.6 Resource limits

Every service MUST declare resource limits. Unlimited resource allocation allows
a compromised or malfunctioning container to exhaust host resources, taking down
all other services (a denial-of-service through resource starvation).

Minimum required fields per service:

```yaml
mem_limit: {value}     # hard memory ceiling; container is OOM-killed if exceeded
cpus: {value}          # CPU share limit (fractional cores)
pids_limit: {value}    # maximum number of processes/threads inside the container
ulimits:
  nofile:
    soft: 1024
    hard: 4096
```

Baseline limits by service (tune based on observed usage; do not raise without
profiling):

| Service | `mem_limit` | `cpus` | `pids_limit` |
|---------|-------------|--------|--------------|
| `vector` | 512m | 1.0 | 256 |
| `clickhouse` | 2g | 2.0 | 512 |
| `normalization` | 512m | 0.5 | 128 |
| `detection` | 1g | 1.0 | 256 |
| `forwarder` | 256m | 0.5 | 128 |
| `api` | 256m | 0.5 | 128 |

These are starting-point values for lab-scale event volumes. Increase
`clickhouse` memory if query performance degrades under load. Do not increase
any limit without first profiling the service to confirm the need.

### 2.7 Healthchecks

Every service MUST declare a `healthcheck` block. Docker uses healthchecks to
determine whether a container is actually ready to serve traffic (not just
started). Orchestration (e.g., `depends_on: condition: service_healthy`) relies
on healthchecks to sequence startup correctly.

Minimum required fields:

```yaml
healthcheck:
  test: [...]           # command Docker runs to check health
  interval: 30s         # how often to run the check
  timeout: 10s          # how long before the check is considered failed
  retries: 3            # consecutive failures before marking unhealthy
  start_period: 15s     # grace period after container start before checks count
```

Check type by service:

| Service | Check type | Example test command |
|---------|-----------|----------------------|
| `vector` | HTTP GET to Vector's internal health endpoint | `["CMD", "curl", "-f", "http://localhost:8686/health"]` |
| `clickhouse` | TCP connect to ClickHouse HTTP port | `["CMD-SHELL", "clickhouse-client --query 'SELECT 1'"]` |
| `normalization` | Python health flag file or HTTP endpoint | `["CMD-SHELL", "python -c 'import sys; sys.exit(0)'"]` (stub; implement a real check) |
| `detection` | Check that the last-run timestamp is recent | `["CMD-SHELL", "test -f /tmp/detection_alive"]` |
| `forwarder` | HTTP GET to an internal readiness endpoint | `["CMD", "curl", "-f", "http://localhost:9000/health"]` |
| `api` | HTTP GET to the FastAPI `/healthz` route | `["CMD", "curl", "-f", "http://localhost:8080/healthz"]` |

Implement the actual health endpoint logic in each service. A container that
fails its healthcheck three consecutive times is marked `unhealthy`; review
the logs and root-cause before restarting.

### 2.8 Log rotation

Every service MUST configure the `json-file` Docker log driver with rotation
limits. Without rotation, container logs fill the host filesystem.

```yaml
logging:
  driver: json-file
  options:
    max-size: "10m"
    max-file: "5"
```

This retains up to 50 MB of logs per service (5 files × 10 MB) before the
oldest file is rotated out. For ClickHouse and Vector, which may produce higher
log volumes, consider reducing `max-size` to `5m` and `max-file` to `3` if
disk space is constrained, or forwarding container logs to Vector's own
pipeline for structured retention.

### 2.9 ClickHouse internal-only network

ClickHouse MUST be attached only to the `internal: true` Docker network. No
`ports:` block may be defined for the `clickhouse` service. The internal network
flag prevents container-to-host routing and prevents the Docker proxy from
forwarding connections from the host LAN.

```yaml
networks:
  internal:
    internal: true   # Docker sets up the network with no routing to the host
```

If a published ClickHouse port is ever added for debugging, remove it before
any commit. The CI image-digest gate (section 4) should also be extended to
check for accidental port publication on `clickhouse`. This mirrors the
architecture's Boundary 2 control described in `01-architecture-overview.md`.

### 2.10 No Docker socket mounts

No container in SIEMhunter may mount `/var/run/docker.sock` (or the Windows
named pipe equivalent `//./pipe/docker_engine`).

Mounting the Docker socket inside a container gives that container full control
of the Docker daemon, which is equivalent to root access on the host. This is
the container breakout vector documented as **finding #13** in
`14-threat-model.md`. Any Compose file containing a `docker.sock` volume mount
is a misconfiguration and must be caught by CI and code review before merge.

### 2.11 Read-only container filesystem

Every service MUST set `read_only: true` on its container filesystem where the
application supports it. This prevents an attacker who gains code execution
inside the container from writing persistent tooling, backdoors, or modified
binaries to the container layer.

```yaml
read_only: true
```

Services that require writable directories (temporary files, PID files, runtime
state) MUST declare `tmpfs` mounts for those specific paths instead of
disabling read-only mode for the whole container:

```yaml
tmpfs:
  - /tmp:mode=1777,size=64m
  - /run:mode=755,size=16m
```

The `tmpfs` mount is in-memory only. Data written to it does not persist across
container restarts. Services that need to persist data across restarts (e.g.,
ClickHouse) use named Docker volumes, not the container writable layer.

---

## 3. Secrets handling

This section defines how credentials reach the running containers. Any deviation
from these rules is a security defect, not a configuration preference.

### 3.1 Docker `secrets:` blocks — the only permitted credential delivery method

All credentials MUST be delivered via Docker Compose `secrets:` blocks. Docker
secrets are mounted as in-memory tmpfs files inside the container at
`/run/secrets/{secret_name}`. They are never written to the container's
writable layer, never appear in `docker inspect` environment output, and are
never visible to other containers.

Minimum Compose structure:

```yaml
secrets:
  forwarder_cert_push:
    file: ./secrets/forwarder_cert_push.pem   # host path; file is not committed to git

services:
  forwarder:
    secrets:
      - forwarder_cert_push
    # The secret is available at /run/secrets/forwarder_cert_push inside the container
```

The `secrets/` directory on the host MUST be mode `700`, owned by the user
running the Docker daemon (or the remapped UID if `userns-remap` is enabled).
Individual secret files MUST be mode `400`. See `15-adr-forwarder-credential.md`
section 2.4 for the full file permission table.

Secrets required at v0.1.0:

| Secret name | Contents | Consumed by |
|-------------|----------|-------------|
| `forwarder_cert_push` | PEM private key for the push app registration | `forwarder` |
| `forwarder_cert_pull` | PEM private key for the pull app registration (if KQL pull enabled) | `forwarder` |
| `api_auth_token` | Static bearer token for FastAPI admin authentication | `api` |
| `clickhouse_password` | ClickHouse service account password (if ClickHouse auth is enabled) | `clickhouse`, `normalization`, `detection` |

### 3.2 Environment variables — prohibited for secrets

The `environment:` block in `docker-compose.yml` MUST NOT contain any secret
value. This prohibition is absolute.

**Why:** Environment variables set via `docker-compose.yml` appear in plain text
in `docker inspect {container}` output, in `/proc/{pid}/environ` on the host,
and in container runtime dumps. Any process with the ability to run
`docker inspect` (including processes inside the container in some configurations)
can read them. A secret in an environment variable is effectively unprotected on
a multi-user or partially compromised host.

This prohibition covers all credential types: private keys, passwords,
pre-shared tokens, API keys, and connection strings containing passwords.

Non-secret configuration values (DCE URI, DCR resource ID, workspace ID, log
level, schedule interval) may be delivered via environment variables or via a
config file. See section 3.4.

### 3.3 Secret mount verification

At startup, each service that consumes a secret MUST verify:
1. The file exists at the expected `/run/secrets/` path.
2. The file is non-empty.
3. (For certificates) The file parses as a valid PEM private key.

If any verification fails, the service MUST refuse to start and emit a clear
error message identifying which secret is missing. The service MUST NOT
silently fall back to reading from an environment variable, a bind-mounted path,
or a default value.

This fail-closed requirement mirrors the Key Vault behaviour defined in
`15-adr-forwarder-credential.md` section 2.9.

### 3.4 Non-secret configuration

Configuration values that are not credentials (DCE URI, DCR resource ID,
workspace ID, schedule cadence, ingest rate limits) are delivered via a Docker
config object or a bind-mounted config file. Per `15-adr-forwarder-credential.md`
section 4.3, these values MUST NOT be passed via `environment:` blocks either,
because resource IDs alongside a certificate create a correlated leak.

Use a `config:` block in Compose:

```yaml
configs:
  siemhunter_config:
    file: ./config/siemhunter.yaml   # not a secret; committed to git with placeholder values

services:
  forwarder:
    configs:
      - source: siemhunter_config
        target: /etc/siemhunter/config.yaml
        mode: 0444
```

The config file in `./config/siemhunter.yaml` in the repository contains
**placeholder values only** (e.g., `DCE_URI: "REPLACE_AT_DEPLOY_TIME"`). The
operator populates real values at deploy time either by substituting the file
before deployment or by using environment variable interpolation in the config
YAML. Real values must not be committed.

### 3.5 `.env` files

A `.env` file at the repo root may be used for non-secret Docker Compose
variable substitution (e.g., `COMPOSE_PROJECT_NAME`, image tag overrides for
local development). It MUST be listed in `.gitignore`. It MUST NOT contain any
credential. If a `.env` file is used, its purpose and the list of variables it
is expected to contain must be documented in `README.md` with placeholder values.

### 3.6 Azure Key Vault — deferred to v0.2

Azure Key Vault as a certificate broker is out of scope for v0.1.0. When
implemented in v0.2, it MUST be fail-closed: if Key Vault is unreachable at
container startup, the service MUST refuse to start. It MUST NOT fall back to
reading from an environment variable, a bind-mounted file, or any other path.
A fallback would become an attack surface. See `15-adr-forwarder-credential.md`
section 2.9 for the full v0.2 design constraint.

---

## 4. CI/CD gates

The following checks run in the CI pipeline on every push and pull request.
They are gates: a failure blocks the PR from merging. None of these are
advisory-only. The implementation (GitHub Actions workflow files) is a separate
deliverable; this section defines what must run and what must block.

### 4.1 Secret scanning

Both **gitleaks** and **truffleHog** MUST run on every push.

- gitleaks scans git history and staged content for patterns matching known
  secret formats (API keys, private keys, connection strings, etc.).
- truffleHog performs additional entropy-based scanning that catches secrets
  without a known format.

Running both tools provides defence in depth: each has different detection
heuristics and different rule sets. A single false negative from one tool is
more likely to be caught by the other.

A detection by either tool blocks the PR. The PR author must investigate,
confirm whether the detection is a true positive or a false positive, and if
a true positive: rotate the exposed credential immediately (it is now in git
history, which is not fully erased by a rebase or force-push), then remove
the secret from all commits using `git filter-repo`, and re-push.

### 4.2 Image digest verification

A CI script MUST parse `docker-compose.yml` and verify that every `image:`
field matches the pattern `name:tag@sha256:[0-9a-f]{64}`. Any image reference
that uses a tag only (e.g., `vector:0.36.1`) fails the check.

This is the CI enforcement of the pinned-digest requirement in section 2.5.
The script should output the list of non-compliant image references so the PR
author knows exactly which lines to fix.

### 4.3 SBOM generation

On every release (not on every push — releases only), **syft** or
`docker sbom` generates a Software Bill of Materials (SBOM) for each built
image. The SBOM is attached to the GitHub release as a build artifact.

The SBOM records every OS package and language-level dependency in the image
layer tree. It is the primary input for supply chain auditing and for the
vulnerability scan in section 4.4.

### 4.4 Vulnerability scanning

Both **Trivy** and **Grype** scan all images (base layer and application
layer) on every release build and on any PR that modifies a `Dockerfile`.

- Trivy and Grype use different vulnerability databases (NVD, OSV, GitHub
  Advisory Database, vendor advisories). Running both reduces missed CVEs
  (Common Vulnerabilities and Exposures).
- **Critical or High severity CVEs block the release.** Medium and Low
  severity CVEs generate a report attached to the PR but do not block.
- If a Critical/High CVE cannot be fixed immediately (e.g., the fix is not
  yet available upstream), the blocker may be overridden by a documented
  exception in `16-hardening-checklist.md` with: the CVE ID, the reason the
  fix is not yet available, an estimated fix date, and an owner.

### 4.5 Sigma rule compilation

**pySigma** compiles all rules in `rules/local/` against the ClickHouse
backend on every PR that modifies any file under `rules/`. A compilation
failure (syntax error, unsupported field mapping, backend-incompatible
construct) blocks the PR.

This gate catches rule errors before they reach a running detection service,
where a bad rule would silently produce no results rather than failing loudly.
The compilation step should also run `--output-format` validation to confirm
the compiled SQL is syntactically valid ClickHouse SQL.

### 4.6 Sigma rule tests

**DuckDB** runs positive and negative sample event tests for each rule in
`rules/local/`. Each rule must have a corresponding test fixture file
containing at least one event that should trigger the rule (positive test)
and at least one event that should not trigger the rule (negative test).

A test failure (positive test does not fire, or negative test fires) blocks
the PR. This gate is the most important quality control for the detection
engine: it catches rules that are syntactically valid but logically broken.

DuckDB is used for local testing because it can execute ClickHouse-dialect SQL
without a running ClickHouse instance, making the CI check fast and
dependency-free.

---

## 5. Portability notes

### 5.1 Primary deployment: on-prem Docker Compose

The primary and fully supported deployment target is Docker Compose on a Linux
host. The Linux kernel's seccomp, namespace, cgroup, and capability controls
are fully available in this configuration, and all hardening controls in
section 2 apply without exception.

Minimum Linux host requirements: kernel 4.18+ (for full namespace support),
Docker Engine 24+, Docker Compose V2 (`docker compose`, not `docker-compose`).

### 5.2 Secondary deployment: Linux VM in Azure

The same `docker-compose.yml` file is intended to run on a Linux VM in Azure
without modification. The only difference at v0.2 is credential delivery: Docker
secrets are replaced by an Azure Key Vault broker. The Compose service
definitions, network topology, and hardening controls remain identical.

For Azure VM deployments, the VM's system-assigned managed identity (if the VM
is enrolled) or user-assigned managed identity provides the Key Vault access
credential, eliminating the on-prem certificate lifecycle problem.

### 5.3 Config-driven deployment values

No environment-specific value (DCE URI, DCR resource ID, workspace ID,
workspace name, subscription ID, resource group name) is hardcoded in
application source code or in any committed file with real values.

All such values are delivered at deploy time via the config file mechanism
described in section 3.4. The operator copies `./config/siemhunter.yaml.example`
to `./config/siemhunter.yaml`, fills in the real values, and this file is
excluded from git by `.gitignore`. The `.example` file with placeholders is
committed and serves as the authoritative template.

This means a single `docker-compose.yml` and a single set of image builds can
be deployed to any target (home-lab, lab Azure VM, production Azure VM) simply
by providing a different config file at deploy time.

### 5.4 Windows Docker Desktop (lab only)

Docker Desktop on Windows is supported for personal lab use and development
iteration. Limitations that apply to Windows Desktop deployments:

- `userns-remap` is not supported. Accept this gap; do not attempt to work
  around it.
- Linux kernel seccomp profiles apply inside the Linux VM that Docker Desktop
  uses; AppArmor does not (Windows does not use AppArmor).
- Host port `514` binding may require elevated permissions depending on the
  Windows configuration. Use the `5140:5140` mapping instead and configure
  log sources to send to port 5140 directly in lab environments where the
  host 514 mapping is not needed.
- Named Docker volumes are stored inside the Docker Desktop VM, not on the
  Windows host filesystem. This is acceptable for lab use; for any deployment
  where data persistence matters, use a Linux host.

**For any deployment beyond personal lab use, a Linux host is strongly
preferred.** The hardening controls in section 2 are fully enforceable only
on a Linux host.

---

## 6. IaC state management (Azure resources)

SIEMhunter's Azure resources (DCE, DCR, Log Analytics workspace, app
registrations) are provisioned using Terraform. This section defines how
Terraform state and identities are managed.

### 6.1 Terraform state storage

Terraform state files MUST be stored in a private Azure Blob Storage container.

Required storage account configuration:
- **Public access:** Disabled (no anonymous or public read access to any blob)
- **Firewall:** Restricted to the operator's known egress IP(s) and the CI
  runner IP range. No "Allow all networks" setting.
- **Soft delete:** Enabled with a minimum 30-day retention period. This allows
  recovery if a state file is accidentally deleted or overwritten.
- **Versioning:** Enabled on the storage container. Every Terraform plan that
  applies a change creates a new state version, making rollback possible.
- **Encryption:** Azure Storage encrypts at rest by default (AES-256); no
  additional configuration required. Customer-managed keys are optional for
  v0.1.0.

Terraform backend configuration (in `terraform/backend.tf`):

```hcl
terraform {
  backend "azurerm" {
    resource_group_name  = "{RESOURCE_GROUP}"      # replace at deploy time
    storage_account_name = "{STORAGE_ACCOUNT}"     # replace at deploy time
    container_name       = "siemhunter-tfstate"
    key                  = "siemhunter.tfstate"
  }
}
```

`.tfstate` files MUST be in `.gitignore`. They contain resource IDs,
connection strings, and potentially sensitive infrastructure details. A `.tfstate`
committed to a public repository is a reconnaissance gift to an attacker.

### 6.2 Deploy identity

The Terraform deploy identity is a service principal with the minimum RBAC
permissions required for the provisioning tasks:

| Role | Scope | Purpose |
|------|-------|---------|
| `Contributor` | Resource group | Create and manage DCE, DCR, storage account |
| `User Access Administrator` | DCR resource ID only | Assign `Monitoring Metrics Publisher` to the push service principal |

The `User Access Administrator` role is scoped to the DCR resource ID only,
not to the resource group or subscription. This is a two-step provisioning
pattern: a human with `Owner` on the resource group grants `User Access
Administrator` to the deploy service principal scoped to the DCR after the
DCR is created in step one.

This service principal is used only in CI and during initial provisioning. It
is not the forwarder's push or pull identity. Its credentials are stored in
the CI platform's secret store (GitHub Actions secrets or Azure DevOps Library),
never in the repository.

### 6.3 Azure Policy guard

An Azure Policy assignment MUST enforce that DCR stream definitions cannot be
modified outside of the Terraform apply pipeline. The policy:
- Audits (or denies, in hardened deployments) any modification to the DCR
  that does not originate from the known deploy identity.
- Ensures that the DCR schema matches the expected ASIM table definition.

This prevents an operator from manually editing the DCR in the portal in a
way that breaks the forwarder's schema expectations without a corresponding
PR and CI gate.

### 6.4 Terraform lock file

The `.terraform.lock.hcl` file (provider version lock file) MUST be committed
to git. It pins the exact provider versions used in the most recent
`terraform init`, ensuring that different operators and the CI runner use
identical provider binaries. Do not add `.terraform.lock.hcl` to `.gitignore`.

The `.terraform/` directory (local provider cache) MUST be in `.gitignore`;
it contains large provider binaries and is not part of the source-controlled
configuration.

---

## 7. Syslog port mapping and `cap_drop: ALL` compatibility

Linux restricts binding to ports below 1024 to processes with `CAP_NET_BIND_SERVICE`
or root privilege. Because section 2.1 requires `cap_drop: ALL` and forbids
re-adding any capability, no container can bind to port 514 (the standard
syslog UDP/TCP port) from inside the container.

The solution is a Docker port mapping that lets the host OS handle the
privileged port binding:

```yaml
services:
  vector:
    ports:
      - "514:5140/udp"    # host port 514 UDP → container port 5140 UDP
      - "514:5140/tcp"    # host port 514 TCP → container port 5140 TCP
```

How this works:
- The Docker daemon (which runs as root on the host) binds host port `514`.
- The host OS forwards connections arriving on `514` to the container's
  internal port `5140`.
- Inside the container, Vector binds to `5140`, which is above the privileged
  threshold. No capability is required.
- `CAP_NET_BIND_SERVICE` is NOT re-added. The container remains fully
  capability-dropped.

The Vector configuration file (`vector.yaml`) MUST specify the listener port
as `5140`, not `514`. The host-to-container port translation is transparent to
Vector.

For lab environments where the host port `514` mapping is not needed (e.g.,
log sources are configured to send directly to port `5140`), the `ports`
block can map `5140:5140` instead. In this case, the host does not bind port
`514` at all, which removes the need for the Docker daemon to have any
special host privilege for this port mapping.

**Windows Docker Desktop note:** Port `514` binding on the host may trigger a
Windows firewall prompt or require administrator confirmation. In lab use,
configure log sources to target port `5140` directly and use `5140:5140` in
the Compose file to avoid this.

---

## 8. References

| Document | Relationship to this file |
|----------|--------------------------|
| `09-security-and-iam.md` | RBAC details, analyst login, certificate generation commands, and full rotation runbook. Extends section 3 of this document. |
| `15-adr-forwarder-credential.md` | Binding credential design ADR. Section 3 of this document implements its requirements. |
| `16-hardening-checklist.md` | Per-requirement checklist that maps every control in section 2 to a verifiable pass/fail check. Use this document alongside `16` during deployment review. |
| `14-threat-model.md` | Threat model that motivates most of the hardening controls in section 2. Finding numbers referenced in this document (e.g., #13) refer to the finding table in `14`. |
| `01-architecture-overview.md` | Network topology overview and trust boundary definitions that this document implements in Compose config. |
| `04-normalization-and-schema.md` | OCSF → ASIM field mapping consumed by the `normalization` service. |
