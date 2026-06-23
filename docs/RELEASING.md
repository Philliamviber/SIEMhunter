# SIEMhunter Release Process

## Single source of truth: `3.0.0-dev`

The canonical version string lives in **three places** that must always agree:

| Surface | File | Field |
|---|---|---|
| Frontend npm package | `frontend/package.json` | `"version"` |
| FastAPI application | `services/api/src/main.py` | `version=` in `FastAPI(...)` |
| Docker image tag | `docker-compose.yml` | `image: siemhunter/frontend:<version>` |

When cutting a release, update all three to the same value (e.g. `3.0.0`) before tagging.

## Tagging

Annotated tags are cut at release time, pointing at the release commit:

```
git tag -a v3.0.0 <sha> -m "SIEMhunter v3.0.0 — UX Wave"
git push origin v3.0.0
```

Do **not** push tags prematurely. Tags are a post-merge, post-QA step.

## Historical tags

| Tag | Commit | Notes |
|---|---|---|
| `v1.0.0` | `86f9971` | Last backend-only commit before frontend scaffolding |
| `v2.0.0` | `b037da0` | Dashboard wave wrap-up (CHANGELOG + README rebuild) |
| `v3.0.0` | TBD | UX Wave — per-analyst auth, CI, UX fixes |
