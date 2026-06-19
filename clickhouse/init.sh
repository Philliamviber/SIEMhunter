#!/bin/bash
# Substitutes RETENTION_DAYS env var into schema.sql and runs it.
# Executed automatically by the ClickHouse Docker entrypoint on first start.
set -euo pipefail

DAYS="${RETENTION_DAYS:-30}"
if [ "${DAYS}" -lt 1 ] 2>/dev/null; then
    echo "ERROR: RETENTION_DAYS must be a positive integer (got: ${DAYS})" >&2
    exit 1
fi

PASSWORD="$(cat /run/secrets/clickhouse_password)"
SQL="$(sed "s/{RETENTION_DAYS}/${DAYS}/g" /docker-entrypoint-schema.sql)"

echo "Initialising SIEMhunter schema (retention ${DAYS} days)..."
echo "${SQL}" | clickhouse-client \
    --user "${CLICKHOUSE_USER:-siemhunter}" \
    --password "${PASSWORD}" \
    --multiquery

echo "Schema initialised."
