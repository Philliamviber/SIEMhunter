STATUS: GREEN
Branch: 4.0  SHA: fbcb083
Commit: feat(pr8): rule lifecycle — admin-gated promotion + fail-closed audit + SELF-006
New files: rules.py (updated), self_rule_status_mutation.yaml (SELF-006), test_rules_lifecycle.py
Suite: 263 passed, 0 failed (26 new tests; no regressions)
AC1 non-admin gate: PASS — analyst-session and no-auth callers receive 401/403 on mutations
AC2 audit-before-effect: PASS — send_security_event called before client.insert; actor propagated
AC3 fail-closed: PASS — Sentinel failure → 503, ClickHouse insert not called
AC4 SELF-006: PASS — fires on any RuleChangeAudit; 7 structural + simulated-event tests green
PR9 handoff: bump 4.0.0-dev → 4.0.0, finalize CHANGELOG, write gate-status doc; GATE I = SELF-006
