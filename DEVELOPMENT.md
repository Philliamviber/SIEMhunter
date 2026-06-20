# Development Guide

> Audience: engineers working on SIEMhunter locally — setting up the environment,
> running tests, adding detection rules, and debugging service failures.

---

## Prerequisites

| Tool | Minimum version | Purpose |
|------|----------------|---------|
| Docker Desktop (or Docker Engine + Compose plugin) | 24.x | Runs all services |
| Python | 3.12 | Running tests and linting locally |
| Git | any | Version control |
| `curl` | any | Testing the API |

On Windows, use Docker Desktop with WSL2. On Linux/macOS, Docker Engine is sufficient.

---

## Local setup

### 1. Clone the repository

```sh
git clone <repo-url> SIEMhunter
cd SIEMhunter
```

### 2. Create secrets

SIEMhunter reads all credentials from files under `secrets/`. These files are
gitignored. You must create them before starting the stack.

```sh
mkdir -p secrets

# ClickHouse password — used by all Python services
echo "changeme_dev_only" > secrets/clickhouse_password.txt

# API bearer token — used to authenticate against the control plane
python3 -c "import secrets; print(secrets.token_hex(32))" > secrets/api_auth_token.txt

# Sentinel certificates — needed by forwarder and API services.
# For local dev without Sentinel connectivity, create placeholder files:
touch secrets/forwarder_cert_push.pem
touch secrets/forwarder_cert_pull.pem
```

For real Sentinel connectivity, replace the placeholder PEM files with the
certificates from your Azure app registrations. See `instructions/15-adr-forwarder-credential.md`
for the app registration setup procedure.

### 3. Configure Sentinel endpoints

Copy the example config and fill in your Azure values:

```sh
cp config/siemhunter.yaml config/siemhunter.yaml.bak   # if you have local changes
```

Edit `config/siemhunter.yaml` and replace the placeholder values:

```yaml
sentinel:
  workspace_id: "your-actual-workspace-id"
  dce_uri: "https://your-dce-name.region.ingest.monitor.azure.com"
  tenant_id: "your-tenant-id"
  push_client_id: "your-push-app-registration-client-id"
  # ... dcr_ids etc.
```

For local development without Sentinel, you can leave placeholders — the forwarder
will log errors but the rest of the pipeline (ingest, normalization, detection) will
continue to function.

### 4. Start the stack

```sh
docker compose up --build
```

On first start, ClickHouse runs `clickhouse/init.sh`, which creates all tables.
This only happens when the `clickhouse_data` volume is empty.

To follow logs for a specific service:

```sh
docker compose logs -f normalization
docker compose logs -f detection
docker compose logs -f forwarder
```

### 5. Verify the pipeline is healthy

```sh
# Read the API token you created in step 2
TOKEN=$(cat secrets/api_auth_token.txt)

# Check the control plane is up (no auth needed)
curl http://localhost:8080/v1/health

# Check pipeline status (requires auth)
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/v1/status
```

A healthy response from `/v1/status` looks like:

```json
{
  "clickhouse": "ok",
  "normalization_alive": true,
  "detection_alive": true,
  "forwarder_alive": true,
  "pending_retry_queue": 0
}
```

### 6. Send a test event

Send a syslog event to trigger ingest:

```sh
echo "Aug 28 12:00:00 testhost sshd[1234]: Accepted password for user from 192.168.1.10 port 22" \
  | nc -u localhost 5140
```

After 2–5 seconds, verify it appeared in ClickHouse (via the query endpoint):

```sh
TOKEN=$(cat secrets/api_auth_token.txt)
curl -s -X POST http://localhost:8080/v1/query \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"sql": "SELECT TimeGenerated, HostName, ChannelName, ProvenanceTag FROM security_events ORDER BY IngestTimestamp DESC LIMIT 5"}'
```

---

## Running Python services locally (without Docker)

You can run individual Python services outside Docker for faster iteration, but
you still need ClickHouse running (e.g., via `docker compose up clickhouse`).

```sh
# Install dependencies for the normalization service
cd services/normalization
pip install -r requirements.txt

# Set required environment variables
export CLICKHOUSE_HOST=localhost
export CLICKHOUSE_PORT=8123
export CLICKHOUSE_DB=siemhunter
export CLICKHOUSE_USER=siemhunter
export LOG_LEVEL=debug

# The service reads the password from /run/secrets/clickhouse_password.
# On a developer machine, create a symlink or use a wrapper:
sudo mkdir -p /run/secrets
echo "changeme_dev_only" | sudo tee /run/secrets/clickhouse_password

# Run the service
python -m src.main
```

Repeat similarly for `services/detection` and `services/api`.

---

## Running tests

There are no automated tests yet (v0.1.0). The test structure is planned:

```
rules/tests/
  self_detection/
    SELF-001/
      positive.json   # event that should match the rule
      negative.json   # event that should NOT match the rule
  windows_ad/
    ...
```

When tests are added, run them via:

```sh
cd services/detection
python -m pytest tests/
```

The planned CI gate (from `instructions/10-acceptance-criteria.md`) requires:
- All production rules compile without warnings against the pipeline
- Every production rule has at least one positive and one negative test event
- Positive events trigger the rule; negative events do not

---

## Adding a new detection rule

Detection rules are Sigma YAML files. Place them in `rules/local/` under one of
the two subdirectories:

- `rules/local/self_detection/` — rules that detect attacks on SIEMhunter itself
- `rules/local/windows_ad/` — rules that detect Windows AD/Kerberos/LSASS TTPs

### Step 1: Write the Sigma YAML

Create `rules/local/windows_ad/my_new_rule.yml`:

```yaml
title: My New Detection Rule
id: 12345678-1234-1234-1234-123456789abc   # must be a valid UUID
status: draft                               # start as draft; promote after testing
description: >
  Detects something suspicious involving EventID 4769.
author: Your Name
date: 2026/06/19
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    ServiceName|endswith: '$'
    TicketEncryptionType: '0x17'
  condition: selection
falsepositives:
  - Legitimate Kerberos service ticket requests
level: high
tags:
  - attack.t1558.003
  - attack.credential_access
```

Key rules for Sigma YAML in SIEMhunter (from `rules/pipelines/clickhouse-asim-ocsf.yaml`):
- EventID must be an **unquoted integer**, not a string: `EventID: 4769` not `EventID: '4769'`
- Field names must be in the `field_mappings` section of the pipeline; unmapped fields produce zero results
- Do not use `re:` modifiers with lookahead/lookbehind (RE2 engine does not support them)
- Do not use `near:` or `sequence:` (requires Python state machine; not SQL-compilable)
- Hash values (`Hashes.MD5`, `Hashes.SHA256`) must be lowercase hex

### Step 2: Test compilation

With the detection service running, watch the logs for your new rule:

```sh
docker compose logs -f detection | grep "my_new_rule\|rule_id"
```

Or run the compiler directly:

```python
from services.detection.src.compiler import compile_rules
rules = compile_rules(
    rules_dir="rules/local",
    pipeline_path="rules/pipelines/clickhouse-asim-ocsf.yaml"
)
```

### Step 3: Promote the rule

Once you have verified the rule compiles and produces the expected results:

1. Change `status: draft` to `status: test` in the YAML.
2. The detection service will pick it up automatically on the next cycle.
3. Use the API to promote through the lifecycle:

```sh
TOKEN=$(cat secrets/api_auth_token.txt)

# First, register the rule in the rule_registry (insert via ClickHouse directly
# or wait for the detection service to pick it up and register it automatically)

# Promote to production:
curl -s -X PUT http://localhost:8080/v1/rules/12345678-1234-1234-1234-123456789abc/status \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"new_status": "production", "reason": "Tested and verified against sample data"}'
```

### Step 4: Write test events (planned)

Create `rules/tests/windows_ad/my_new_rule/positive.json` and `negative.json`
with event payloads that should and should not match the rule.

---

## Debugging service failures

### Normalization service not processing events

1. Check if raw_events has rows:
```sh
TOKEN=$(cat secrets/api_auth_token.txt)
curl -s -X POST http://localhost:8080/v1/query \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"sql": "SELECT count() FROM raw_events"}'
```

2. Check normalization logs:
```sh
docker compose logs normalization | grep -E "error|warning|rate_limit"
```

3. Check if the alive file is being touched:
```sh
docker compose exec normalization ls -la /tmp/normalization_alive
```

### Detection service not running

1. Check that rules exist and compile:
```sh
docker compose logs detection | grep -E "rule_compiled|rule_compile_warning|rules_compiled"
```

2. Check if security_events has data:
```sh
TOKEN=$(cat secrets/api_auth_token.txt)
curl -s -X POST http://localhost:8080/v1/query \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"sql": "SELECT count(), max(TimeGenerated) FROM security_events"}'
```

### Forwarder failing to reach Sentinel

1. Check for retry queue accumulation:
```sh
TOKEN=$(cat secrets/api_auth_token.txt)
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8080/v1/status | python3 -m json.tool
```

If `pending_retry_queue` is increasing, the forwarder cannot reach Sentinel.

2. Check forwarder logs:
```sh
docker compose logs forwarder | grep -E "error|429|sentinel"
```

Common causes and fixes are in `TROUBLESHOOTING.md`.

---

## Resetting the local environment

```sh
# Stop everything and remove volumes (deletes all local data)
docker compose down -v

# Remove built images to force a clean rebuild
docker compose down --rmi local

# Start fresh
docker compose up --build
```

---

## Useful ClickHouse queries

Connect directly to ClickHouse (skipping the API):

```sh
docker compose exec clickhouse clickhouse-client \
  --user siemhunter \
  --password "$(cat secrets/clickhouse_password.txt)" \
  --database siemhunter
```

Common queries:

```sql
-- How many events are in the store?
SELECT count() FROM security_events;

-- What are the most recent events?
SELECT TimeGenerated, HostName, EventID, ChannelName
FROM security_events
ORDER BY TimeGenerated DESC
LIMIT 10;

-- Are there any unforwarded detection hits?
SELECT rule_id, severity, created_at
FROM detection_hits
WHERE forwarded_at IS NULL
ORDER BY created_at DESC;

-- What is the current rule registry state?
SELECT rule_id, status, updated_at, updated_by
FROM rule_registry FINAL
ORDER BY updated_at DESC;

-- How much data is in raw_events (normalization backlog)?
SELECT count() FROM raw_events;
```
