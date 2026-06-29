"""
ClickHouse client for the API service.
Identical pattern to services/normalization/src/clickhouse_client.py.
All queries use parameterized statements — string concatenation is prohibited.
Spec: NFR-05, 04-normalization-and-schema.md §6.
"""
from __future__ import annotations
import os
import clickhouse_connect
from clickhouse_connect.driver.client import Client
import structlog

log = structlog.get_logger(__name__)


def _read_secret(path: str) -> str:
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError as exc:
        raise RuntimeError(f"Required secret missing at {path}: {exc}") from exc


def get_client() -> Client:
    """Return an authenticated ClickHouse client.

    Reads the password from the Docker secret at /run/secrets/clickhouse_password.
    Raises RuntimeError on startup if the secret is absent or empty (fail-closed).
    """
    host = os.environ["CLICKHOUSE_HOST"]
    port = int(os.environ.get("CLICKHOUSE_PORT", "8123"))
    database = os.environ["CLICKHOUSE_DB"]
    user = os.environ["CLICKHOUSE_USER"]
    password = _read_secret("/run/secrets/clickhouse_password")

    if not password:
        raise RuntimeError("clickhouse_password secret is present but empty")

    client = clickhouse_connect.get_client(
        host=host,
        port=port,
        database=database,
        username=user,
        password=password,
        secure=False,           # internal Docker network; no TLS needed
        compress=True,
        connect_timeout=10,
        send_receive_timeout=60,
    )
    log.info("clickhouse_connected", host=host, port=port, database=database)
    return client


def get_readonly_client() -> Client:
    """Return a read-only ClickHouse client (readonly=1 session setting).

    Used exclusively by the Sigma dry-run path. The readonly=1 setting prevents
    any INSERT/ALTER/DROP even if the query guard is somehow bypassed.
    """
    host = os.environ["CLICKHOUSE_HOST"]
    port = int(os.environ.get("CLICKHOUSE_PORT", "8123"))
    database = os.environ["CLICKHOUSE_DB"]
    user = os.environ["CLICKHOUSE_USER"]
    password = _read_secret("/run/secrets/clickhouse_password")

    if not password:
        raise RuntimeError("clickhouse_password secret is present but empty")

    client = clickhouse_connect.get_client(
        host=host,
        port=port,
        database=database,
        username=user,
        password=password,
        secure=False,
        compress=True,
        connect_timeout=10,
        send_receive_timeout=20,
        settings={"readonly": 1},
    )
    log.info("clickhouse_readonly_connected", host=host, port=port, database=database)
    return client
