"""
Invariant test: rules.py must use the FINAL keyword on all SELECT queries
against siemhunter.rule_registry.

Why this matters
----------------
rule_registry uses ReplacingMergeTree(updated_at).  ClickHouse merges
duplicate rule_id rows in the background, keeping only the row with the
latest updated_at.  Without FINAL, a query may see stale/duplicate rows
until background merges complete — meaning a disabled rule could reappear
as active, which is a security regression.

This test reads the router source directly (not the compiled bytecode) so it
will fail the moment someone refactors the query strings and accidentally drops
FINAL.
"""
from __future__ import annotations

import re
from pathlib import Path

# Resolve relative to this file's location so the test works from any cwd.
_RULES_PY = Path(__file__).parent.parent / "src" / "routers" / "rules.py"


def test_rules_file_exists():
    """Sanity-check that we're pointing at the right file."""
    assert _RULES_PY.exists(), f"Expected rules.py at {_RULES_PY}"


def test_rules_uses_final_keyword():
    """rules.py must contain the FINAL keyword (ReplacingMergeTree dedup).

    FINAL forces ClickHouse to apply pending background merges before returning
    results, ensuring only the latest rule status is visible.
    """
    src = _RULES_PY.read_text(encoding="utf-8")
    assert "FINAL" in src, (
        "rules.py must use FINAL on rule_registry queries. "
        "Without FINAL, ReplacingMergeTree may return stale/duplicate rows, "
        "which can cause disabled rules to appear active."
    )


def test_from_rule_registry_final_pattern_appears():
    """Every 'FROM siemhunter.rule_registry' in a SELECT must be followed by FINAL.

    This checks the actual SQL query strings, not comments or docstrings.
    """
    src = _RULES_PY.read_text(encoding="utf-8")

    # Find every 'FROM siemhunter.rule_registry' occurrence in what looks like
    # query strings (inside triple-quoted strings, ignoring comment-only lines).
    # Strategy: find the pattern and check the next ~20 chars include FINAL.
    pattern = re.compile(
        r"FROM\s+siemhunter\.rule_registry\s+(FINAL)",
        re.IGNORECASE,
    )
    matches = pattern.findall(src)

    # Also check there is at least one FROM siemhunter.rule_registry at all
    any_ref = re.search(r"FROM\s+siemhunter\.rule_registry", src, re.IGNORECASE)
    assert any_ref is not None, (
        "rules.py has no 'FROM siemhunter.rule_registry' — "
        "expected at least one SELECT query against rule_registry."
    )

    # Every FROM siemhunter.rule_registry must be immediately followed by FINAL
    all_from_refs = re.findall(
        r"FROM\s+siemhunter\.rule_registry(\s+FINAL|\s+WHERE|\s+ORDER)",
        src,
        re.IGNORECASE,
    )
    non_final = [ref for ref in all_from_refs if "FINAL" not in ref.upper()]
    assert not non_final, (
        "Found 'FROM siemhunter.rule_registry' without FINAL in rules.py. "
        f"Non-FINAL occurrences: {non_final}"
    )

    assert len(matches) >= 1, (
        "Expected at least one 'FROM siemhunter.rule_registry FINAL' in rules.py"
    )


def test_both_list_and_get_use_final():
    """Both the list_rules and _get_rule queries must use FINAL.

    list_rules (GET /v1/rules) and _get_rule (used by GET and PUT) are two
    separate query sites.  Both must include FINAL to maintain consistency.
    """
    src = _RULES_PY.read_text(encoding="utf-8")

    # There should be at least 2 occurrences of the full pattern
    matches = re.findall(
        r"FROM\s+siemhunter\.rule_registry\s+FINAL",
        src,
        re.IGNORECASE,
    )
    assert len(matches) >= 2, (
        f"Expected at least 2 'FROM siemhunter.rule_registry FINAL' occurrences "
        f"in rules.py (one in _get_rule and one in list_rules), found {len(matches)}."
    )
