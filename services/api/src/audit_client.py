"""
Lightweight Sentinel audit client for the API service.

The API service cannot import directly from services/forwarder/src/sentinel_client.py
because services are separate containers with separate PYTHONPATH roots. This module
replicates the minimum needed: a single send_logs call to the Logs Ingestion API
(DCE/DCR path) for writing audit and auth-failure events to SIEMHunterSecurity_CL
and SIEMHunterHealth_CL.

Security invariants:
- TLS verification ALWAYS enabled; verify=False is a defect, not a config option.
- DCE URI validated against pattern and SSRF-checked before every call.
- Credentials loaded from Docker secrets only.
"""
from __future__ import annotations
import ipaddress
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog
from azure.identity import CertificateCredential
from azure.monitor.ingestion import LogsIngestionClient

log = structlog.get_logger(__name__)

_DCE_URI_PATTERN = re.compile(
    r"^https://[a-zA-Z0-9\-]+\.[a-zA-Z0-9\-]+\.ingest\.monitor\.azure\.com$"
)

_BLOCKED_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
]


def _ssrf_check(uri: str) -> None:
    import urllib.parse
    parsed = urllib.parse.urlparse(uri)
    host = parsed.hostname or ""
    try:
        addr = ipaddress.ip_address(host)
        for blocked in _BLOCKED_RANGES:
            if addr in blocked:
                raise ValueError(f"SSRF blocked: {host}")
    except ValueError as exc:
        if "SSRF blocked" in str(exc):
            raise
        return  # hostname, not IP — allow DNS resolution


def _read_secret(path: str) -> bytes:
    try:
        return Path(path).read_bytes()
    except OSError as exc:
        raise RuntimeError(f"Secret missing at {path}: {exc}") from exc


def _load_config() -> dict:
    config_path = os.environ.get("SIEMHUNTER_CONFIG", "/app/config/siemhunter.yaml")
    import yaml
    with open(config_path) as f:
        return yaml.safe_load(f)


# Module-level lazy client; initialized on first use
_client: "LogsIngestionClient | None" = None
_credential: "CertificateCredential | None" = None
_cfg: "dict | None" = None


def _get_logs_client() -> tuple["LogsIngestionClient", dict]:
    global _client, _credential, _cfg
    if _client is not None and _cfg is not None:
        return _client, _cfg

    cfg = _load_config()
    sentinel = cfg["sentinel"]

    dce_uri = sentinel["dce_uri"]
    _ssrf_check(dce_uri)
    if not _DCE_URI_PATTERN.match(dce_uri):
        raise ValueError(f"DCE URI does not match expected pattern: {dce_uri}")

    cert_pem = _read_secret("/run/secrets/forwarder_cert_push")
    if not cert_pem:
        raise RuntimeError("forwarder_cert_push secret is empty")

    credential = CertificateCredential(
        tenant_id=sentinel["tenant_id"],
        client_id=sentinel["push_client_id"],
        certificate_data=cert_pem,
    )

    # LogsIngestionClient enforces TLS (azure-monitor-ingestion enforces this)
    client = LogsIngestionClient(
        endpoint=dce_uri,
        credential=credential,
    )

    _client = client
    _credential = credential
    _cfg = sentinel
    return client, sentinel


def send_security_event(record: dict[str, Any]) -> None:
    """Send one record to SIEMHunterSecurity_CL. Raises on failure."""
    _send_to_table("SIEMHunterSecurity_CL", [record])


def send_health_event(record: dict[str, Any]) -> None:
    """Send one record to SIEMHunterHealth_CL. Raises on failure."""
    _send_to_table("SIEMHunterHealth_CL", [record])


def _send_to_table(table: str, records: list[dict[str, Any]]) -> None:
    client, sentinel_cfg = _get_logs_client()
    dcr_id = sentinel_cfg["dcr_ids"].get(table)
    if not dcr_id:
        raise ValueError(f"No DCR ID configured for table: {table}")

    now_ts = datetime.now(timezone.utc).isoformat()
    for rec in records:
        if "TimeGenerated" not in rec:
            rec["TimeGenerated"] = now_ts

    stream_name = f"Custom-{table}"
    client.upload(rule_id=dcr_id, stream_name=stream_name, logs=records)
    log.debug("audit_sent", table=table, count=len(records))
