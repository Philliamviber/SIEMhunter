"""
Invariant test: events.py must use ClickHouse native parameterization for all
user-supplied filter values.

Why this matters
----------------
String-interpolating user input into SQL (via %, .format(), or f-strings)
creates SQL injection vulnerabilities.  ClickHouse's native parameter syntax
{name:Type} combined with the parameters= dict argument provides safe,
server-side binding.

This test reads the router source to assert:
  1. User filter values appear as {name:Type} placeholders in the WHERE
     clause string, not as raw Python format arguments.
  2. The parameters= keyword is used when calling client.query().
  3. Specific per-field placeholders exist for every exposed filter.

Because we are testing a security invariant (injection prevention) rather
than implementation details, these assertions are deliberately source-level:
a developer who accidentally changes parameterization to f-string interpolation
will break this test, which is exactly the desired behavior.
"""
from __future__ import annotations

import re
from pathlib import Path

_EVENTS_PY = Path(__file__).parent.parent / "src" / "routers" / "events.py"


def _src() -> str:
    return _EVENTS_PY.read_text(encoding="utf-8")


def test_events_file_exists():
    assert _EVENTS_PY.exists(), f"Expected events.py at {_EVENTS_PY}"


def test_events_uses_parameters_keyword():
    """client.query() calls must pass user values via parameters=, not string concat."""
    src = _src()
    assert "parameters=params" in src or "parameters=params_page" in src, (
        "events.py must pass user filter values to client.query() via the "
        "parameters= dict argument to prevent SQL injection."
    )


def test_hostname_filter_is_parameterized():
    """HostName filter must use {hostname:String} placeholder."""
    src = _src()
    assert "{hostname:String}" in src, (
        "hostname filter must use ClickHouse parameterized placeholder "
        "{hostname:String}, not string interpolation."
    )


def test_event_id_filter_is_parameterized():
    """EventID filter must use {event_id:UInt32} placeholder."""
    src = _src()
    assert "{event_id:UInt32}" in src, (
        "event_id filter must use ClickHouse parameterized placeholder "
        "{event_id:UInt32}, not string interpolation."
    )


def test_src_ip_addr_filter_is_parameterized():
    """SrcIpAddr filter must use {src_ip_addr:String} placeholder."""
    src = _src()
    assert "{src_ip_addr:String}" in src, (
        "src_ip_addr filter must use ClickHouse parameterized placeholder "
        "{src_ip_addr:String}, not string interpolation."
    )


def test_provenance_tag_filter_is_parameterized():
    """ProvenanceTag filter must use {provenance_tag:String} placeholder."""
    src = _src()
    assert "{provenance_tag:String}" in src, (
        "provenance_tag filter must use ClickHouse parameterized placeholder "
        "{provenance_tag:String}, not string interpolation."
    )


def test_no_percent_format_in_where_building():
    """The where-clause building code must not use % string formatting."""
    src = _src()
    # Isolate the list_events function body (everything after the def line)
    fn_match = re.search(r"async def list_events\b.*", src, re.DOTALL)
    if fn_match:
        fn_body = src[fn_match.start():]
        # % used in a format string context (not inside a string literal
        # that represents SQL like %s or similar)
        # Heuristic: look for variable % variable or string % variable patterns
        py_format = re.findall(r'(?<!\{)(?<!\w)\w+\s*%\s*(?:\w+|\()', fn_body)
        assert not py_format, (
            f"events.py uses % string formatting in list_events: {py_format}"
        )


def test_no_dot_format_on_filter_variables():
    """Filter variable names must not appear inside .format() calls."""
    src = _src()
    filter_vars = ["hostname", "event_id", "src_ip_addr", "provenance_tag",
                   "subject_user_name"]
    format_calls = re.findall(r'\.format\([^)]*\)', src)
    for call in format_calls:
        for var in filter_vars:
            assert var not in call, (
                f"events.py uses .format() with filter variable '{var}': {call!r}"
            )


def test_pagination_also_parameterized():
    """Pagination limit/offset values must also go through parameters=."""
    src = _src()
    # Both _limit and _offset should appear as placeholders
    assert "{_limit:UInt32}" in src, (
        "LIMIT for pagination must use {_limit:UInt32} placeholder"
    )
    assert "{_offset:UInt32}" in src, (
        "OFFSET for pagination must use {_offset:UInt32} placeholder"
    )
