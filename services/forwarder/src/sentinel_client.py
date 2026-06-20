"""
Microsoft Sentinel API client: Logs Ingestion API + Incidents API.

How SIEMhunter pushes to Sentinel
----------------------------------
SIEMhunter uses two separate Sentinel API paths:

1. Logs Ingestion API (via Data Collection Endpoint / DCE + Data Collection Rule / DCR)
   Used for: normalized events (SIEMHunterSecurity_CL) and health events
   (SIEMHunterHealth_CL). This is the modern replacement for the legacy HTTP
   Data Collector API. Data flows: SIEMhunter → DCE → DCR → Log Analytics workspace.
   The DCR defines the table schema and the column mapping. A separate DCR resource
   exists for each ASIM table (configured in config/siemhunter.yaml under dcr_ids).

2. Incidents API (ARM management plane)
   Used for: self-detection incidents (SELF-001 through SELF-005).
   This is a REST PUT to the Azure Resource Manager (management.azure.com) endpoint.
   SIEMhunter only uses this for its own self-detections; general detection hits
   go via SIEMHunterSecurity_CL and are turned into incidents by a Sentinel
   analytics rule (to avoid double-alerting).

Authentication
--------------
Both APIs use the same app registration + certificate credential.
The CertificateCredential from azure-identity reads the certificate from a Docker
secret (/run/secrets/forwarder_cert_push) and uses MSAL to obtain access tokens.
No client secrets are used anywhere. See instructions/15-adr-forwarder-credential.md
for the full rationale and the app registration + RBAC assignment required.

Security invariants (non-negotiable per spec and threat model)
--------------------------------------------------------------
- TLS certificate verification is ALWAYS enabled. The requests library is never
  called with verify=False in any environment, including local testing. If TLS
  verification is needed against a private CA, the CA cert path must be passed
  as verify="/path/to/ca.crt", not as verify=False.
- Credentials are loaded exclusively from Docker secrets (files under /run/secrets/).
  They are never read from environment variables, command-line arguments, or config files.
- The DCE URI is validated against a strict regex pattern before the first connection
  to prevent operator misconfiguration from redirecting SIEMhunter logs to a
  non-Microsoft endpoint.
- SSRF protection: outbound connections to RFC 1918 ranges, loopback (127.x), and
  the Azure Instance Metadata Service (169.254.169.254) are blocked before DNS
  resolution. This prevents a compromised config file from redirecting traffic to
  an internal service.

Spec: instructions/07-sentinel-forwarding.md, instructions/15-adr-forwarder-credential.md
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

# DCE URI allowlist pattern (SSRF guard).
# The DCE URI provided in config/siemhunter.yaml must match this regex exactly.
# This prevents operator typos and deliberate misconfiguration from directing
# SIEMhunter's event output to a non-Microsoft endpoint.
# Expected format: https://<name>.<region>.ingest.monitor.azure.com
# Example:        https://siemhunter-dce.eastus.ingest.monitor.azure.com
_DCE_URI_PATTERN = re.compile(
    r"^https://[a-zA-Z0-9\-]+\.[a-zA-Z0-9\-]+\.ingest\.monitor\.azure\.com$"
)

# IP ranges that must never be targets of outbound connections.
# This list covers RFC 1918 private ranges, loopback, and the Azure IMDS endpoint.
# The IMDS endpoint (169.254.169.254) is particularly important: if an attacker can
# control the DCE URI or an ARM endpoint URL, this check prevents SIEMhunter from
# being used to exfiltrate the managed identity token from the host VM.
# Spec: NFR-07, instructions/14-threat-model.md finding #9.
_BLOCKED_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),       # RFC 1918 Class A private
    ipaddress.ip_network("172.16.0.0/12"),     # RFC 1918 Class B private
    ipaddress.ip_network("192.168.0.0/16"),    # RFC 1918 Class C private
    ipaddress.ip_network("127.0.0.0/8"),       # IPv4 loopback
    ipaddress.ip_network("169.254.0.0/16"),    # Link-local / Azure IMDS (169.254.169.254)
    ipaddress.ip_network("::1/128"),           # IPv6 loopback
]


def _ssrf_check(uri: str) -> None:
    """Raise ValueError if the URI resolves to a blocked (private/loopback/IMDS) IP range.

    This check is applied to the DCE URI at startup and to every Incidents API URL
    before making an outbound connection. It provides defence in depth against:
    - Operator misconfiguration (e.g., accidentally setting DCE URI to an internal service)
    - Config injection attacks (where an attacker modifies siemhunter.yaml to redirect
      SIEMhunter's output to an internal host)

    The check only blocks IP addresses, not hostnames. A hostname is allowed to proceed
    to DNS resolution because we cannot check the DNS-resolved IP here without creating
    a time-of-check/time-of-use (TOCTOU) race condition. The real SSRF protection for
    hostname targets is the DCE URI allowlist pattern (_DCE_URI_PATTERN), which requires
    the hostname to end in .ingest.monitor.azure.com.

    Args:
        uri: The full URI to check (e.g., "https://example.eastus.ingest.monitor.azure.com").

    Raises:
        ValueError: If the URI hostname is a literal IP address in a blocked range.
    """
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
    """Authenticated client for the Microsoft Sentinel Logs Ingestion API and Incidents API.

    Instantiate once at forwarder service startup. The credential and LogsIngestionClient
    are long-lived objects that handle token refresh automatically via azure-identity's
    token caching.

    Usage:
        forwarder = SentinelForwarder()          # reads config + secrets at construction
        forwarder.send_logs("SIEMHunterSecurity_CL", records)   # push events
        forwarder.send_incident(incident)                        # push self-detection incident
    """

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
        """Forward records to a Sentinel custom table via the Logs Ingestion API.

        The Logs Ingestion API sends data to a Log Analytics workspace via a
        Data Collection Endpoint (DCE) and Data Collection Rule (DCR). The DCR
        defines which table receives the data and how columns are mapped.

        The DCR ID is looked up from config/siemhunter.yaml (dcr_ids section).
        If no DCR ID is configured for the requested table, ValueError is raised.

        TimeGenerated handling: Log Analytics requires TimeGenerated to be present
        in each record and to be in ISO 8601 UTC format. If a record is missing
        this field, the current UTC time is injected. This is a fallback only —
        records should always have TimeGenerated set by the caller.

        The azure-monitor-ingestion SDK handles chunking (records over 1 MB are
        split automatically) and retries transient HTTP errors. The caller
        (forwarder/src/main.py _send_with_retry) handles 429 Retry-After backoff
        and on-disk queuing for persistent failures.

        Args:
            table: The Log Analytics custom table name (e.g., "SIEMHunterSecurity_CL").
            records: A list of dicts, each representing one log record to ingest.
                     Each dict must have a TimeGenerated key (ISO 8601 UTC string).

        Raises:
            ValueError: If no DCR ID is configured for the table.
            azure.core.exceptions.HttpResponseError: On Sentinel API errors.
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
        """Create or update a Sentinel incident via the ARM Incidents API.

        This method is used ONLY for the five self-detection rules (SELF-001
        through SELF-005). General Sigma detection hits do NOT use this path;
        they go to SIEMHunterSecurity_CL and are turned into incidents by a
        Sentinel analytics rule. See the anti-double-alerting design note in
        runner.py for the rationale.

        The ARM Incidents API uses HTTP PUT with the incident name in the URL path.
        The incident name is derived from the hit fingerprint (SHA-256 of the rule
        ID + sorted event IDs), which makes the PUT idempotent: if the same
        detection fires twice before Sentinel closes the incident, the second PUT
        updates the existing incident rather than creating a duplicate.

        The access token for management.azure.com is obtained fresh from the
        CertificateCredential on each call. azure-identity caches tokens internally
        and only requests a new one when the cached token is within 5 minutes of
        expiry, so this does not result in a token request on every incident.

        TLS verification: always enabled. See module docstring.

        Args:
            incident: A dict with keys: title, severity, rule_id, rule_version,
                      source_event_ids, mitre_tag, fingerprint, tags.

        Raises:
            RuntimeError: If the Incidents API returns a non-200/201 status code.
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
