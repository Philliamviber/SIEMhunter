"""Shared ClickHouse client for the detection service (same pattern as normalization)."""
import os
import clickhouse_connect
import structlog

log = structlog.get_logger(__name__)


def get_client():
    host = os.environ["CLICKHOUSE_HOST"]
    port = int(os.environ.get("CLICKHOUSE_PORT", "8123"))
    database = os.environ["CLICKHOUSE_DB"]
    user = os.environ["CLICKHOUSE_USER"]

    try:
        with open("/run/secrets/clickhouse_password") as f:
            password = f.read().strip()
    except OSError as exc:
        raise RuntimeError(f"clickhouse_password secret missing: {exc}") from exc

    if not password:
        raise RuntimeError("clickhouse_password secret is empty")

    return clickhouse_connect.get_client(
        host=host, port=port, database=database,
        username=user, password=password,
        secure=False, compress=True,
        connect_timeout=10, send_receive_timeout=120,
    )
