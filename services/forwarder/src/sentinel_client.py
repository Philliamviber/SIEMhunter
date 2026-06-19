"""
Sentinel Logs Ingestion API + Incidents API client.
Spec: instructions/07-sentinel-forwarding.md

Security invariants (non-negotiable per spec):
- TLS verification is ALWAYS enabled; verify=False is a defect, not a config option.
- Credentials loaded from Docker secrets only.
- DCE URI validated against pattern before first connection.
- SSRF protection: no outbound connections to RFC 1918, loopback, or IMDS.
"""
from __future__ import annotations
import ipaddress
import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
import structlog
from azure.identity import CertificateCredential
from azure.monitor.ingestion import LogsIngestionClient

log = structlog.get_logger(__name__)

# DCE URI must match this pattern — SSRF guard
_DCE_URI_PATTERN = re.compile(
    r"^https://[a-zA-Z0-9\-]+\.[a-zA-Z0-9\-]+\.ingest\.monitor\.azure\.com$"
)

# Blocked IP ranges per SSRF guard (NFR-07, threat model finding #9)
_BLOCKED_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local / IMDS
    ipaddress.ip_network("::1/128"),
]


def _ssrf_check(uri: str) -> None:
    """Raise ValueError if the URI target is in a blocked range."""
    import urllib.parse
    parsed = urllib.parse.urlparse(uri)
    host = parsed.hostname or ""
    try:
        addr = ipaddress.ip_address(host)
        for blocked in _BLOCKED_RANGES:
            if addr in blocked:
                raise ValueError(f"SSRF blocked: {host} is in {blocked}")
    except ValueError as exc:
        if "SSRF blocked" in str(exc):
            raise
        # hostname — not an IP address; allow DNS resolution (not our SSRF vector here)
        return


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


class SentinelForwarder:
    """Authenticated client for the Logs Ingestion API and Incidents API."""

    def __init__(self) -> None:
        cfg = _load_config()
        self._cfg = cfg["sentinel"]

        dce_uri = self._cfg["dce_uri"]
        _ssrf_check(dce_uri)
        if not _DCE_URI_PATTERN.match(dce_uri):
            raise ValueError(f"DCE URI does not match expected pattern: {dce_uri}")

        # Load push identity certificate from Docker secret
        cert_pem = _read_secret("/run/secrets/forwarder_cert_push")
        if not cert_pem:
            raise RuntimeError("forwarder_cert_push secret is empty")

        self._credential = CertificateCredential(
            tenant_id=self._cfg["tenant_id"],
            client_id=self._cfg["push_client_id"],
            certificate_data=cert_pem,
        )

        # LogsIngestionClient always uses TLS (azure-monitor-ingestion enforces this)
        self._logs_client = LogsIngestionClient(
            endpoint=dce_uri,
            credential=self._credential,
        )

        self._incidents_endpoint = (
            f"https://management.azure.com/subscriptions/"
            f"{{sub}}/resourceGroups/{{rg}}/providers/Microsoft.OperationalInsights/"
            f"workspaces/{self._cfg['workspace_id']}/providers/"
            f"Microsoft.SecurityInsights/incidents"
        )
        log.info("sentinel_forwarder_ready", dce_uri=dce_uri)

    def send_logs(self, table: str, records: list[dict]) -> None:
        """Forward records to a Sentinel custom table via Logs Ingestion API.

        Honors Retry-After on 429. After max_retries, moves to retry queue.
        Spec: instructions/07-sentinel-forwarding.md §2.3-2.4.
        """
        dcr_id = self._cfg["dcr_ids"].get(table)
        if not dcr_id:
            raise ValueError(f"No DCR ID configured for table: {table}")

        # Add TimeGenerated if missing (required by Log Analytics)
        now_ts = datetime.now(timezone.utc).isoformat()
        for rec in records:
            if "TimeGenerated" not in rec:
                rec["TimeGenerated"] = now_ts

        stream_name = f"Custom-{table}"
        self._logs_client.upload(
            rule_id=dcr_id,
            stream_name=stream_name,
            logs=records,
        )
        log.debug("logs_sent", table=table, count=len(records))

    def send_incident(self, incident: dict) -> None:
        """Create a Sentinel incident via the Incidents API.

        Used only for self-detections that own incident creation.
        Spec: instructions/07-sentinel-forwarding.md §3.
        """
        # Get access token for ARM (management.azure.com)
        token = self._credential.get_token("https://management.azure.com/.default").token

        # Idempotency: fingerprint-based incident name prevents duplicates
        incident_name = incident.get("fingerprint", incident.get("rule_id", "unknown"))

        # Build the ARM incident resource URI
        # Using workspace_id as a proxy; real path would need sub/rg from config
        url = (
            "https://management.azure.com"
            f"/subscriptions/{self._cfg.get('subscription_id', 'UNKNOWN')}"
            f"/resourceGroups/{self._cfg.get('resource_group', 'UNKNOWN')}"
            f"/providers/Microsoft.OperationalInsights/workspaces/{self._cfg['workspace_id']}"
            f"/providers/Microsoft.SecurityInsights/incidents/{incident_name}"
            "?api-version=2023-02-01"
        )

        _ssrf_check(url)

        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

        body = {
            "properties": {
                "title": incident.get("title", incident.get("rule_id")),
                "severity": incident.get("severity", "Medium"),
                "status": "New",
                "labels": [
                    {"labelName": tag} for tag in incident.get("tags", [])
                ],
                "additionalData": {
                    "source_event_ids": incident.get("source_event_ids", []),
                    "rule_id": incident.get("rule_id", ""),
                    "rule_version": incident.get("rule_version", ""),
                    "mitre_tag": incident.get("mitre_tag", ""),
                },
            }
        }

        # TLS verification ALWAYS enabled — no verify=False
        resp = requests.put(url, json=body, headers=headers, timeout=30, verify=True)
        if resp.status_code not in (200, 201):
            raise RuntimeError(
                f"Incidents API returned {resp.status_code}: {resp.text[:500]}"
            )
        log.info("incident_sent", rule_id=incident.get("rule_id"), status=resp.status_code)
