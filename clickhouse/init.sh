#!/bin/bash
# SIEMhunter ClickHouse schema initialization script.
#
# When this script runs
# ----------------------
# The ClickHouse Docker image executes all scripts in /docker-entrypoint-initdb.d/
# in alphabetical order on the FIRST container start (when the data directory is
# empty). On subsequent starts (when data already exists), the script is skipped.
# This means re-running `docker compose up` will NOT re-run this script.
# To force re-initialization, delete the clickhouse_data Docker volume:
#   docker compose down -v
#   docker compose up
#
# What this script does
# ----------------------
# 1. Reads RETENTION_DAYS from the environment (default: 30).
# 2. Validates that RETENTION_DAYS is a positive integer.
# 3. Reads the ClickHouse password from the Docker secret file.
# 4. Substitutes {RETENTION_DAYS} in schema.sql with the actual value.
# 5. Pipes the resulting SQL to clickhouse-client to create all tables.
#
# The {RETENTION_DAYS} substitution is how the TTL clause in security_events
# is parameterized. A separate schema.sql is the source of truth; this script
# does not contain inline SQL.
#
# Environment variables consumed:
#   RETENTION_DAYS      — integer, days to retain security_events rows (default: 30)
#   CLICKHOUSE_USER     — ClickHouse username (default: siemhunter)
#
# Docker secrets consumed:
#   /run/secrets/clickhouse_password — ClickHouse user password
#
# Files consumed:
#   /docker-entrypoint-schema.sql — the schema.sql file mounted from the host
#
# Spec: instructions/08-deployment-hybrid.md §3.3, instructions/12-data-retention-and-lifecycle.md

set -euo pipefail

# Read RETENTION_DAYS from environment; default to 30 if not set.
DAYS="${RETENTION_DAYS:-30}"

# Validate: must be a positive integer.
# Passing 0 would create a TTL of 0 days, causing ClickHouse to delete all rows
# immediately after insertion — effectively breaking the entire pipeline.
if [ "${DAYS}" -lt 1 ] 2>/dev/null; then
    echo "ERROR: RETENTION_DAYS must be a positive integer (got: ${DAYS})" >&2
    exit 1
fi

# Read the database password from the Docker secret file.
# The secret file is mounted by Docker Compose at /run/secrets/clickhouse_password.
# Never use an environment variable for the password; secrets mount is the only
# approved method (instructions/09-security-and-iam.md §2).
PASSWORD="$(cat /run/secrets/clickhouse_password)"

# Substitute the {RETENTION_DAYS} placeholder in schema.sql.
# sed replaces every occurrence in the file. There is exactly one occurrence
# (in the security_events TTL clause). The other tables use hardcoded TTL values.
SQL="$(sed "s/{RETENTION_DAYS}/${DAYS}/g" /docker-entrypoint-schema.sql)"

echo "Initialising SIEMhunter schema (retention ${DAYS} days)..."

# Execute the SQL via clickhouse-client.
# --multiquery: allows multiple CREATE TABLE statements in one pipe.
# --user / --password: authenticate as the siemhunter user (created by the
# ClickHouse server via CLICKHOUSE_USER env in docker-compose.yml).
echo "${SQL}" | clickhouse-client \
    --user "${CLICKHOUSE_USER:-siemhunter}" \
    --password "${PASSWORD}" \
    --multiquery

echo "Schema initialised."
