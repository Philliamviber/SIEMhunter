STATUS: GREEN
Branch: 4.0 — SHA: b75e0dd (post-review fix; initial impl 6efa96f)
New: sigma_author.py (POST /v1/sigma/compile + /v1/sigma/dryrun), SigmaAuthorPage.tsx, 19 backend + 12 frontend tests all green (237 + 373 total)
Gate satisfied: dual read-only enforcement (readonly=1 + SELECT-guard), no rule_registry writes, non-SELECT rejected by test
PR8 note: add pySigma to services/api/requirements.txt before first production use; compile_sigma_to_sql() in sigma_author.py is reusable for PR8 promotion flow
