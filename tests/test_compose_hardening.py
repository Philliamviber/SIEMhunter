"""
Static analysis of docker-compose.yml security hardening invariants.

These tests do not start Docker — they parse the YAML and assert that the
compose file meets the security requirements documented in
instructions/08-deployment-hybrid.md.

Why static analysis instead of runtime checks?
-----------------------------------------------
Many security properties (localhost-only binding, cap_drop, read_only) can be
verified from the compose YAML without running containers.  Catching regressions
here is faster and more reliable than a full integration test, and the tests
will run in any CI environment without Docker installed.
"""
from __future__ import annotations

import yaml
from pathlib import Path

COMPOSE_PATH = Path(__file__).parent.parent / "docker-compose.yml"


def load_compose() -> dict:
    with open(COMPOSE_PATH, encoding="utf-8") as f:
        return yaml.safe_load(f)


# ── Port binding security ─────────────────────────────────────────────────────

def test_no_wildcard_port_bindings():
    """No service should bind 0.0.0.0 (exposes the port to the host LAN).

    Services that need external reach (vector syslog receiver) may use bare
    port mappings like '5140:5140/udp', which Docker binds to 0.0.0.0 by
    default.  Control-plane ports (api: 8080, frontend: 8081) must always
    be explicitly restricted to 127.0.0.1.
    """
    compose = load_compose()
    for svc_name, svc in compose.get("services", {}).items():
        for port in svc.get("ports", []):
            port_str = str(port)
            assert "0.0.0.0" not in port_str, (
                f"{svc_name} has an explicit 0.0.0.0 port binding: {port!r}"
            )
            # Control-plane HTTP ports must never be exposed without host restriction
            assert not port_str.startswith("80:") and not port_str.startswith("8080:"), (
                f"{svc_name} may expose port 80/8080 without host-IP restriction: {port!r}"
            )


def test_frontend_port_is_localhost_only():
    """Frontend must bind only to 127.0.0.1 — never the host LAN."""
    compose = load_compose()
    frontend_ports = compose["services"]["frontend"]["ports"]
    assert any("127.0.0.1:8081" in str(p) for p in frontend_ports), (
        "frontend port must be bound to 127.0.0.1:8081, not 0.0.0.0"
    )


def test_api_port_is_localhost_only():
    """API must bind only to 127.0.0.1 — spec §1 non-negotiable invariant."""
    compose = load_compose()
    api_ports = compose["services"]["api"]["ports"]
    assert any("127.0.0.1:8080" in str(p) for p in api_ports), (
        "api port must be bound to 127.0.0.1:8080, not 0.0.0.0"
    )


# ── Secret handling ───────────────────────────────────────────────────────────

def test_no_secrets_in_environment():
    """Secret values must come from Docker secrets, not environment variables.

    Keys that contain 'password' are allowed only when the key also contains
    'FILE' (e.g. CLICKHOUSE_PASSWORD_FILE), which is the Docker-recommended
    pattern for pointing at a secrets file path rather than embedding the value.
    Token keys must not have inline values.
    """
    compose = load_compose()
    for svc_name, svc in compose.get("services", {}).items():
        env = svc.get("environment", {})
        items = env.items() if isinstance(env, dict) else []
        for key, val in items:
            lower_key = key.lower()
            # Password keys are OK if they reference a FILE (Docker secret path pattern)
            assert "password" not in lower_key or val is None or "FILE" in key, (
                f"{svc_name}.environment has a raw password key: {key!r} = {val!r}"
            )
            # Token keys must not have inline values
            assert "token" not in lower_key or val is None, (
                f"{svc_name}.environment has a raw token key: {key!r} = {val!r}"
            )


# ── Linux capabilities ────────────────────────────────────────────────────────

def test_all_services_cap_drop_all():
    """Every service must drop ALL Linux capabilities.

    Running with surplus capabilities (e.g. CAP_NET_RAW, CAP_SYS_PTRACE) gives
    a compromised container an attack surface against the host.  cap_drop: ALL
    is a mandatory baseline.
    """
    compose = load_compose()
    for svc_name, svc in compose.get("services", {}).items():
        cap_drop = svc.get("cap_drop", [])
        assert "ALL" in cap_drop, (
            f"{svc_name} is missing 'cap_drop: ALL'. "
            "All services must drop all Linux capabilities."
        )


def test_no_new_privileges():
    """Every service must set no-new-privileges:true.

    This prevents setuid/setgid binaries inside the container from escalating
    to capabilities beyond what the container was launched with.
    """
    compose = load_compose()
    for svc_name, svc in compose.get("services", {}).items():
        sec_opts = svc.get("security_opt", [])
        assert any("no-new-privileges:true" in str(o) for o in sec_opts), (
            f"{svc_name} is missing 'no-new-privileges:true' in security_opt"
        )


# ── Secrets configuration ─────────────────────────────────────────────────────

def test_api_has_anthropic_secret():
    """The api service must mount the anthropic_api_key secret.

    The AI summary endpoint uses the Anthropic API; the key must come from a
    Docker secret, not from an environment variable.
    """
    compose = load_compose()
    api_secrets = compose["services"]["api"].get("secrets", [])
    # Secrets list entries may be strings or dicts with 'source' key
    secret_names = [
        (s["source"] if isinstance(s, dict) else s) for s in api_secrets
    ]
    assert "anthropic_api_key" in secret_names, (
        "api service must mount the anthropic_api_key Docker secret"
    )


def test_api_has_auth_token_secret():
    """The api service must mount the api_auth_token secret."""
    compose = load_compose()
    api_secrets = compose["services"]["api"].get("secrets", [])
    secret_names = [
        (s["source"] if isinstance(s, dict) else s) for s in api_secrets
    ]
    assert "api_auth_token" in secret_names, (
        "api service must mount the api_auth_token Docker secret"
    )


# ── Network segmentation ──────────────────────────────────────────────────────

def test_api_on_egress_network():
    """API must be on the egress network (needed for Sentinel + Anthropic calls)."""
    compose = load_compose()
    api_networks = compose["services"]["api"].get("networks", [])
    assert "egress" in api_networks, (
        "api must be on the egress network for outbound API calls"
    )


def test_frontend_on_internal_network_only():
    """Frontend must NOT be on the egress network.

    The frontend serves only static assets and proxies to the api.  It has no
    reason to make outbound connections.  Placing it on the egress network would
    expand the blast radius if the nginx process were compromised.
    """
    compose = load_compose()
    frontend_networks = compose["services"]["frontend"].get("networks", [])
    assert "internal" in frontend_networks, (
        "frontend must be on the internal network"
    )
    assert "egress" not in frontend_networks, (
        "frontend must NOT be on the egress network"
    )


def test_clickhouse_not_on_egress_network():
    """ClickHouse must be on the internal network only — no outbound access."""
    compose = load_compose()
    ch_networks = compose["services"]["clickhouse"].get("networks", [])
    assert "egress" not in ch_networks, (
        "clickhouse must not be on the egress network"
    )


# ── Filesystem hardening ──────────────────────────────────────────────────────

def test_frontend_read_only():
    """Frontend container filesystem must be read-only."""
    compose = load_compose()
    assert compose["services"]["frontend"].get("read_only") is True, (
        "frontend service must set read_only: true"
    )


def test_normalization_read_only():
    """Normalization service must run with a read-only filesystem."""
    compose = load_compose()
    assert compose["services"]["normalization"].get("read_only") is True, (
        "normalization service must set read_only: true"
    )


def test_detection_read_only():
    """Detection service must run with a read-only filesystem."""
    compose = load_compose()
    assert compose["services"]["detection"].get("read_only") is True, (
        "detection service must set read_only: true"
    )


# ── Services are defined ──────────────────────────────────────────────────────

def test_expected_services_present():
    """All required services must be declared in the compose file."""
    compose = load_compose()
    services = set(compose.get("services", {}).keys())
    required = {"vector", "clickhouse", "normalization", "detection",
                "forwarder", "api", "frontend"}
    missing = required - services
    assert not missing, f"Missing services in docker-compose.yml: {missing}"


def test_top_level_secrets_declared():
    """Top-level secret references must be declared."""
    compose = load_compose()
    top_level_secrets = set(compose.get("secrets", {}).keys())
    required = {"api_auth_token", "anthropic_api_key",
                "clickhouse_password", "forwarder_cert_push", "forwarder_cert_pull"}
    missing = required - top_level_secrets
    assert not missing, (
        f"Missing top-level secret declarations in docker-compose.yml: {missing}"
    )
