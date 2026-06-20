# Troubleshooting

Common failures, their diagnostics, and fixes. Check `DEVELOPMENT.md` for
local setup issues. Check `DEPLOYMENT.md` for production-specific problems.

---

## Quick diagnostics checklist

Before diving into a specific failure, run through this checklist:

```sh
# 1. Are all containers running?
docker compose ps

# 2. What does the control plane status say?
TOKEN=$(cat secrets/api_auth_token.txt)
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8080/v1/status | python3 -m json.tool

# 3. Are there recent errors in any service?
docker compose logs --since 10m normalization | grep -i error
docker compose logs --since 10m detection | grep -i error
docker compose logs --since 10m forwarder | grep -i error
docker compose logs --since 10m vector | grep -i error

# 4. Is ClickHouse healthy?
docker compose exec clickhouse clickhouse-client \
  --user siemhunter \
  --password "$(cat secrets/clickhouse_password.txt)" \
  --query "SELECT count() FROM siemhunter.security_events"
```

---

## Ingest failures

### No events appearing in security_events

**Symptom:** `SELECT count() FROM security_events` returns 0 or is not growing.

**Diagnosis:**

```sh
# Step 1: Is Vector receiving events? Check its health endpoint.
curl http://localhost:8686/health

# Step 2: Are events reaching raw_events?
TOKEN=$(cat secrets/api_auth_token.txt)
curl -s -X POST http://localhost:8080/v1/query \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"sql": "SELECT count() FROM raw_events"}'

# Step 3: Are there Vector errors?
docker compose logs vector | grep -E "error|drop|failed"

# Step 4: Is the normalization service alive?
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8080/v1/status | python3 -m json.tool
# Look for "normalization_alive": false
```

**Possible causes and fixes:**

| Symptom | Cause | Fix |
|---------|-------|-----|
| `curl http://localhost:8686/health` fails | Vector container not running | `docker compose up vector` |
| `raw_events` count is 0 | No events reaching Vector | Check firewall rules; verify syslog sender is pointing to the right host/port |
| `raw_events` count is growing but `security_events` is not | Normalization service stuck | Check normalization logs for parse errors; restart with `docker compose restart normalization` |
| `normalization_alive: false` | Normalization crashed | `docker compose logs normalization` for the error; `docker compose restart normalization` |

### Flood heuristic firing unexpectedly

**Symptom:** `docker compose logs vector` shows throttle messages. Events are being dropped.

**Explanation:** The Vector `rate_throttle` transform drops events when a source
exceeds 10,000 events per 60-second window (~167 events/sec). This is intentional
— it protects ClickHouse. When this fires, a `FloodHeuristic` event is written to
`/tmp/health_events.jsonl` and forwarded to `SIEMHunterHealth_CL` in Sentinel.

**Diagnosis:**

```sh
# Check the current event rate by source
TOKEN=$(cat secrets/api_auth_token.txt)
curl -s -X POST http://localhost:8080/v1/query \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"sql": "SELECT ProvenanceTag, count() FROM security_events WHERE TimeGenerated >= now() - INTERVAL 1 MINUTE GROUP BY ProvenanceTag"}'
```

**Fix:** If the volume is legitimate, raise the threshold:

In `docker-compose.yml`, under the `vector` service, change:
```yaml
environment:
  FLOOD_THRESHOLD_EPS: "500"    # raise from 167 to 500 events/sec
```

Also raise the normalization service limit:
```yaml
environment:
  RATE_LIMIT_EVENTS_PER_MIN: "30000"   # raise from 10000
```

Apply: `docker compose up -d vector normalization`

---

## ClickHouse failures

### ClickHouse authentication failure

**Symptom:** Services log `clickhouse_password secret is present but empty` or
`Code: 516. DB::Exception: siemhunter: Authentication failed`.

**Diagnosis:**

```sh
# Is the secret file non-empty?
cat secrets/clickhouse_password.txt | wc -c

# Can clickhouse-client connect?
docker compose exec clickhouse clickhouse-client \
  --user siemhunter \
  --password "$(cat secrets/clickhouse_password.txt)" \
  --query "SELECT 1"
```

**Fix:**
1. Ensure `secrets/clickhouse_password.txt` is not empty and contains no trailing newlines:
   ```sh
   printf "your_password_here" > secrets/clickhouse_password.txt
   ```
2. Restart all services that read this secret:
   ```sh
   docker compose restart normalization detection forwarder api
   ```

### ClickHouse schema not initialised

**Symptom:** Services log `Table siemhunter.security_events doesn't exist`.

**Explanation:** The init script (`clickhouse/init.sh`) runs only on the first
start of the ClickHouse container (when the data volume is empty). If the volume
was created before the schema was applied, tables may be missing.

**Diagnosis:**

```sh
docker compose exec clickhouse clickhouse-client \
  --user siemhunter \
  --password "$(cat secrets/clickhouse_password.txt)" \
  --query "SHOW TABLES FROM siemhunter"
```

**Fix — Option 1 (non-destructive):** Run the init script manually:

```sh
# Substitute your actual RETENTION_DAYS value
docker compose exec clickhouse bash /docker-entrypoint-initdb.d/00_init.sh
```

**Fix — Option 2 (destructive — deletes all data):**

```sh
docker compose down -v       # removes the clickhouse_data volume
docker compose up clickhouse  # init script runs on fresh start
```

### ClickHouse running out of disk space

**Symptom:** Services log `DB::Exception: Not enough space` or ClickHouse becomes unresponsive.

**Diagnosis:**

```sh
# Check disk usage
df -h

# Check ClickHouse table sizes
docker compose exec clickhouse clickhouse-client \
  --user siemhunter \
  --password "$(cat secrets/clickhouse_password.txt)" \
  --query "SELECT table, formatReadableSize(sum(bytes)) AS size FROM system.parts WHERE database='siemhunter' GROUP BY table ORDER BY sum(bytes) DESC"
```

**Fix:**
1. Reduce `RETENTION_DAYS` in `docker-compose.yml` and run `docker compose up -d clickhouse`.
2. Force TTL deletion:
   ```sh
   docker compose exec clickhouse clickhouse-client \
     --user siemhunter \
     --password "$(cat secrets/clickhouse_password.txt)" \
     --query "OPTIMIZE TABLE siemhunter.security_events FINAL"
   ```
3. Long-term: add more disk, or archive old events before TTL.

---

## Detection failures

### No detection hits being generated

**Symptom:** `detection_hits` table is empty after several detection cycles.

**Diagnosis:**

```sh
# Are there events in security_events for detection to query?
TOKEN=$(cat secrets/api_auth_token.txt)
curl -s -X POST http://localhost:8080/v1/query \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"sql": "SELECT count(), min(TimeGenerated), max(TimeGenerated) FROM security_events"}'

# Are there compiled rules?
docker compose logs detection | grep "rules_compiled"
# Look for: rules_compiled total=N — if N=0, no rules are in the rules/local/ directory

# Is the detection service alive?
docker compose logs detection | tail -20
```

**Possible causes:**

| Cause | Diagnosis | Fix |
|-------|-----------|-----|
| No rules in `rules/local/` | `rules_compiled total=0` in logs | Add Sigma YAML files to `rules/local/self_detection/` or `rules/local/windows_ad/` |
| All rules are `draft` status | Check rule YAML `status:` fields | Change `status: draft` to `status: test` in at least one rule |
| Production rule compile error | Detection log: `rule_compilation_failed` | Fix the broken rule or change its status to `draft` |
| security_events empty | Count returns 0 | Fix ingest pipeline first |

### Detection cycle is too slow

**Symptom:** `detection_batch_complete elapsed_seconds=X` shows a very long time.

**Diagnosis:**

```sh
docker compose logs detection | grep "detection_batch_complete"
```

**Fix:** If a specific rule is slow, identify it by looking at individual rule execution times in the logs. Long-running rules are usually ones with no EventID filter (scanning the entire table). Always filter on EventID in Sigma rules — it is the primary sort key and makes queries dramatically faster.

---

## Sentinel forwarding failures

### Forwarder cannot authenticate to Sentinel

**Symptom:** Forwarder logs `Authentication failed` or `AADSTS` error codes.

**Cause:** The certificate in `secrets/forwarder_cert_push.pem` does not match
the one registered in the Azure app registration, or the app registration does not
have the `Monitoring Metrics Publisher` role on the DCR.

**Diagnosis:**

```sh
docker compose logs forwarder | grep -E "auth|credential|AADSTS"
```

**Fix:**
1. Verify the certificate thumbprint in Azure Portal → App Registrations → your push app → Certificates & secrets
2. Verify the `push_client_id` and `tenant_id` in `config/siemhunter.yaml` match the app registration
3. Verify the app registration has `Monitoring Metrics Publisher` on the specific DCR resource (not the resource group or subscription)
4. Regenerate the certificate and update both the secret file and the app registration:
   ```sh
   openssl req -x509 -newkey rsa:2048 -keyout push.key -out push.crt -days 365 -nodes
   cat push.crt push.key > secrets/forwarder_cert_push.pem
   ```
   Then upload `push.crt` to the Azure app registration.

### Forwarder retry queue growing

**Symptom:** `/v1/status` shows `pending_retry_queue` increasing.

**Explanation:** When the forwarder cannot reach the Sentinel Logs Ingestion API
after 5 attempts, it serialises the batch to `/app/retry_queue/*.json`. At the
start of each forward cycle, due retry entries are replayed.

**Diagnosis:**

```sh
# How many batches are queued?
docker compose exec forwarder ls /app/retry_queue/ | wc -l

# What do they contain?
docker compose exec forwarder cat /app/retry_queue/<batch-id>.json | python3 -m json.tool
```

**Fix:**
1. Identify and fix the root cause (Sentinel unreachable, authentication failure, etc.)
2. Once Sentinel is reachable, the forwarder will automatically replay queued batches
3. If the queue has grown very large and you want to discard it:
   ```sh
   docker compose exec forwarder rm /app/retry_queue/*.json
   ```
   This loses the queued events. Do this only if you accept the data loss.

### DCE URI validation failure

**Symptom:** Forwarder logs `DCE URI does not match expected pattern`.

**Cause:** The `dce_uri` in `config/siemhunter.yaml` is malformed or points to
a non-Microsoft endpoint.

**Expected format:** `https://<name>.<region>.ingest.monitor.azure.com`
**Example:** `https://siemhunter-dce.eastus.ingest.monitor.azure.com`

**Fix:** Correct the `dce_uri` in `config/siemhunter.yaml` and restart the forwarder:
```sh
docker compose restart forwarder
```

### Sentinel 429 (Too Many Requests)

**Symptom:** Forwarder logs `sentinel_429_backoff` with increasing retry intervals.

**Explanation:** The Logs Ingestion API has rate limits. The forwarder respects
`Retry-After` headers and backs off automatically. This is not a misconfiguration.

**Fix:** None needed immediately — the forwarder will retry. If 429s are frequent,
reduce the forward batch size:

In `docker-compose.yml`, under the `forwarder` service:
```yaml
environment:
  FORWARD_BATCH_SIZE: "50"   # reduce from default 200
```

---

## API failures

### API fails to start — api_token secret missing

**Symptom:** The API container exits immediately with `FATAL: Cannot read api_token`.

**Fix:** Create the secret file:
```sh
python3 -c "import secrets; print(secrets.token_hex(32))" > secrets/api_auth_token.txt
docker compose up -d api
```

### API returns 503 on rule status change

**Symptom:** `PUT /v1/rules/{rule_id}/status` returns HTTP 503 with `AUDIT_WRITE_FAILED`.

**Explanation:** The rule change was rejected because the audit record could not
be written to Sentinel. This is the expected fail-closed behaviour.

**Fix:**
1. Check if Sentinel (specifically the Logs Ingestion API) is reachable:
   ```sh
   curl -v https://your-dce.region.ingest.monitor.azure.com
   ```
2. Check the API logs for the specific error:
   ```sh
   docker compose logs api | grep "sentinel_audit_write_failed"
   ```
3. Once Sentinel is reachable, retry the rule status change.

---

## Self-detection alerts

### SELF-002 (IngestFloodDetected) firing unexpectedly

See the flood heuristic section under "Ingest failures" above.

### SELF-005 (LedgerReconciliationDelta) firing

**Symptom:** `SIEMHunterHealth_CL` in Sentinel has `LedgerDelta` events with a
large delta between `local_count` and `sentinel_count`.

**Explanation:** SELF-005 compares the forwarder's local count of forwarded events
with the count of events received by Sentinel (queried via KQL). A large delta means
events were forwarded but not received, or were received but not visible yet.

**Common false-positive causes:**
- Log Analytics ingestion delay (events can take 2–5 minutes to appear after ingestion)
- The KQL query window does not exactly match the forward batch window

**If the delta is persistent:**
1. Check the retry queue depth (events may be in the queue, not yet forwarded)
2. Check the Logs Ingestion API error logs in Sentinel
3. Enable SELF005_ENABLED=false temporarily to stop the noise while investigating:
   ```yaml
   environment:
     SELF005_ENABLED: "false"
   ```

---

## Container restart loop

**Symptom:** `docker compose ps` shows a service restarting repeatedly.

**Diagnosis:**

```sh
# Get the most recent exit reason
docker compose logs --tail 30 <service_name>
```

Common causes:
- Missing secret file (the service fails at startup)
- ClickHouse not ready yet (services depend on `clickhouse: condition: service_healthy`)
- Python import error (check for missing pip packages)

**Fix for "ClickHouse not healthy yet":**
```sh
# Wait for ClickHouse to be healthy before starting other services
docker compose up clickhouse
# Wait for "Status: healthy" in docker compose ps, then:
docker compose up
```
