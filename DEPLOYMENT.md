# Deployment Guide

> Audience: operators deploying SIEMhunter to a production or home-lab environment.
> For local development, see DEVELOPMENT.md. For the API reference, see API.md.

---

## Overview

SIEMhunter deploys as a Docker Compose stack on a single on-premise Linux host.
The stack is self-contained: no cloud-managed containers, no Kubernetes, no
external message bus required at lab scale.

Minimum host requirements:
- Linux (Ubuntu 22.04 LTS or equivalent) with Docker Engine 24.x
- 4 CPU cores
- 8 GB RAM (2 GB for ClickHouse, 1 GB for detection, remainder for OS + other services)
- 50+ GB disk (30 days × expected daily event volume × ~200 bytes/event average)
- Outbound HTTPS access to Azure endpoints (for the forwarder)

---

## Pre-deployment checklist

### Azure resources

Before starting the stack you need:

- [ ] **Log Analytics workspace** with Microsoft Sentinel enabled
- [ ] **Data Collection Endpoint (DCE)** in the same region as the workspace
- [ ] **Two Data Collection Rules (DCRs)** — one for `SIEMHunterHealth_CL`, one for `SIEMHunterSecurity_CL`
  - Each DCR must define the column schema matching the table the forwarder writes to
  - See `instructions/07-sentinel-forwarding.md §2.2` for the DCR column list
- [ ] **Two Azure app registrations** with X.509 certificates:
  - Push app registration: `Monitoring Metrics Publisher` role scoped to EACH DCR resource (not the resource group)
  - Pull app registration: `Log Analytics Reader` at workspace scope (only needed if SELF005_ENABLED=true)
  - See `instructions/15-adr-forwarder-credential.md` for naming convention and RBAC assignment steps

### Generating certificates for app registrations

```sh
# Generate a self-signed certificate for the push identity
openssl req -x509 -newkey rsa:2048 \
  -keyout push.key -out push.crt \
  -days 365 -nodes \
  -subj "/CN=siemhunter-push/O=SIEMhunter"

# Combine into a PEM file for the Docker secret
cat push.crt push.key > secrets/forwarder_cert_push.pem

# Upload push.crt to the Azure push app registration (not the private key)
```

Rotate certificates before they expire. Update both the secret file and the
Azure app registration, then restart the forwarder:

```sh
docker compose restart forwarder
```

### Host hardening

Before starting SIEMhunter on a production host:

- [ ] Apply OS security updates (`apt upgrade` or equivalent)
- [ ] Restrict SSH to key-based authentication only
- [ ] Disable password authentication in `/etc/ssh/sshd_config`
- [ ] Enable a host firewall; allow only inbound ports 5140, 5144, 5985 (telemetry) and 22 (SSH)
- [ ] Do NOT open port 8080 (the API) through the host firewall — it is localhost-only
- [ ] Enable Docker daemon log rotation
- [ ] Review `instructions/16-hardening-checklist.md` for the full checklist

---

## Secrets management

SIEMhunter uses Docker secrets: credential values are files on disk, mounted
inside containers at `/run/secrets/<name>` as tmpfs (memory-backed, not on disk).

Required secret files under `./secrets/`:

| File | Created by | Used by |
|------|------------|---------|
| `clickhouse_password.txt` | Operator | All Python services (normalization, detection, forwarder, api) |
| `api_auth_token.txt` | Operator | API service (bearer token for control plane auth) |
| `forwarder_cert_push.pem` | Operator | Forwarder, API (Sentinel push identity certificate) |
| `forwarder_cert_pull.pem` | Operator | Forwarder (Sentinel pull identity certificate; may be empty if KQL pull disabled) |

Creating secrets:

```sh
mkdir -p secrets

# ClickHouse password — minimum 32 random characters
python3 -c "import secrets; print(secrets.token_urlsafe(32))" > secrets/clickhouse_password.txt

# API token — 64 hex characters
python3 -c "import secrets; print(secrets.token_hex(32))" > secrets/api_auth_token.txt

# Set restrictive permissions
chmod 600 secrets/*.txt secrets/*.pem 2>/dev/null || true
```

**Important:** The `secrets/` directory is gitignored. Never commit secret files.
A gitleaks pre-commit hook (see `.gitignore`) prevents accidental secret commits.

### Optional: Docker Swarm secrets

For multi-host deployments, Docker Swarm provides cryptographically managed secrets:

```sh
echo "your-password" | docker secret create clickhouse_password -
# Update docker-compose.yml to use: external: true under each secret
```

For v0.1.0 (single host, lab scale), file-based secrets are sufficient.

---

## TLS certificates for syslog

If you require encrypted syslog (TLS port 5144), place the certificate and key
as Docker secrets:

```sh
# Generate a self-signed cert for the syslog TLS listener
openssl req -x509 -newkey rsa:2048 \
  -keyout syslog.key -out syslog.crt \
  -days 365 -nodes \
  -subj "/CN=siemhunter-syslog"

# Create the secrets
cp syslog.crt secrets/syslog_tls.crt
cp syslog.key secrets/syslog_tls.key
```

Add the secrets to `docker-compose.yml`:

```yaml
secrets:
  syslog_tls_crt:
    file: ./secrets/syslog_tls.crt
  syslog_tls_key:
    file: ./secrets/syslog_tls.key
```

And add them to the vector service's `secrets:` list. The paths in `vector/vector.yaml`
(`/run/secrets/syslog_tls.crt` and `/run/secrets/syslog_tls.key`) are already configured.

---

## Starting the stack

```sh
# First start: builds images and initialises the ClickHouse schema
docker compose up --build -d

# Follow startup logs
docker compose logs -f

# Verify all services are running
docker compose ps
```

Healthy state (all services `Up` and `(healthy)`):

```
NAME              STATUS          PORTS
siemhunter-vector          Up (healthy)    0.0.0.0:5140->5140/...
siemhunter-clickhouse      Up (healthy)
siemhunter-normalization   Up (healthy)
siemhunter-detection       Up (healthy)
siemhunter-forwarder       Up (healthy)
siemhunter-api             Up (healthy)    127.0.0.1:8080->8080/tcp
```

---

## Image pinning

Floating image tags (`vector:0.38.0`) can change if the registry is compromised
or a new image is pushed with the same tag. Pin to digest in production:

```sh
# Get the digest for the Vector image
docker inspect --format='{{index .RepoDigests 0}}' ghcr.io/vectordotdev/vector:0.38.0

# Update docker-compose.yml:
#   image: ghcr.io/vectordotdev/vector@sha256:<digest>
```

Do the same for the ClickHouse image.

---

## Adjusting data retention

The retention period for `security_events` is configured via `RETENTION_DAYS`
in `docker-compose.yml` under the `clickhouse` service environment block:

```yaml
environment:
  RETENTION_DAYS: "30"   # change to 60, 90, etc.
```

**Important:** `RETENTION_DAYS` is only applied during the schema initialisation
(first container start). To change retention on an existing deployment:

```sh
# Option 1: Update the TTL directly in ClickHouse
docker compose exec clickhouse clickhouse-client \
  --user siemhunter \
  --password "$(cat secrets/clickhouse_password.txt)" \
  --query "ALTER TABLE siemhunter.security_events MODIFY TTL TimeGenerated + INTERVAL 60 DAY DELETE"

# Option 2: Recreate the database (loses all data)
docker compose down -v
# Edit RETENTION_DAYS in docker-compose.yml
docker compose up --build -d
```

---

## Scaling considerations

SIEMhunter is designed for lab scale (single host, up to ~1 million events/day).

### Increasing event volume

For higher volumes:

1. **Increase ClickHouse memory**: Raise `mem_limit` for the clickhouse service. ClickHouse performance scales with available RAM.

2. **Adjust Vector buffer**: Raise the `target: /var/lib/vector` tmpfs size if Vector logs buffer overflow warnings.

3. **Increase detection parallelism**: The detection service runs rules sequentially. For large rule sets, consider splitting rules across two detection containers with different `RULES_DIR` values. Requires careful partition planning to avoid double-alerting.

4. **Add Redpanda (optional buffer)**: For bursty ingest patterns, add a Redpanda (Kafka-compatible) container between Vector and ClickHouse. Vector has a native Kafka sink; ClickHouse has a Kafka engine. See `instructions/01-architecture-overview.md §6` for the deferred-buffer design.

### Multiple hosts

SIEMhunter v0.1.0 is single-host. For multi-site deployments, run one complete
stack per site, each forwarding to the same Sentinel workspace. Detection rules
are duplicated across sites. This is simpler than a distributed setup and aligns
with the "close to the data" design principle.

---

## Updating SIEMhunter

```sh
# Pull latest code
git pull origin main

# Rebuild and restart (zero-downtime approach)
docker compose up --build -d normalization detection forwarder api

# Vector and ClickHouse can be updated separately
docker compose up --build -d vector
docker compose up -d clickhouse   # only if you changed the image version
```

After a ClickHouse schema migration (new column), run the ALTER TABLE before
restarting the normalization service:

```sh
docker compose exec clickhouse clickhouse-client \
  --user siemhunter \
  --password "$(cat secrets/clickhouse_password.txt)" \
  --query "ALTER TABLE siemhunter.security_events ADD COLUMN MyNewColumn String DEFAULT ''"
```

---

## Monitoring SIEMhunter itself

### Via the control plane API

```sh
TOKEN=$(cat secrets/api_auth_token.txt)
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8080/v1/status | python3 -m json.tool
```

### Via Sentinel (SIEMHunterHealth_CL)

Once the forwarder is operational, `SIEMHunterHealth_CL` in Sentinel receives
`BatchSuccess` and `BatchFail` events after each forward cycle. Use this KQL
to monitor pipeline health:

```kql
SIEMHunterHealth_CL
| where TimeGenerated > ago(1h)
| summarize count() by EventType, Severity
| order by count_ desc
```

### Alerting on SIEMhunter self-detections

The five SELF-00x rules (when promoted to production status) write incidents
to Sentinel directly. Create a Sentinel analytics rule on `SIEMHunterHealth_CL`
to alert on `BatchFail` events with a threshold (e.g., 3+ failures in 1 hour).

---

## Stopping the stack

```sh
# Graceful stop (containers receive SIGTERM and finish current batch)
docker compose stop

# Stop and remove containers (preserves volumes/data)
docker compose down

# Stop and remove containers AND volumes (DELETES ALL DATA)
docker compose down -v
```

All Python services handle SIGTERM gracefully: they finish the current batch
and exit cleanly. The alive files will not be updated after shutdown; Docker
health checks may report unhealthy briefly during graceful shutdown — this is normal.
