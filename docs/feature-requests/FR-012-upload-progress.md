# FR #12 — Add upload progress, cancel, multi-file, and post-upload refresh to UploadZone

**Priority:** P2 · **Size:** M · **Labels:** ux, enhancement

## Problem / motivation
`UploadZone.tsx` shows only an indeterminate "Uploading…" spinner — no percentage, no byte
progress, no cancel — for files up to 100 MB. It handles one file at a time
(`dataTransfer.files?.[0]`), silently ignoring extra dropped files. After a successful
upload, `IngestionPage` shows the `UploadStatusCard` but does not invalidate the
ingestion-summary query, so the donut/volume charts and per-source cards stay stale until
the next 30s poll. There is also no toast confirmation — the result card can be below the
fold.

## Proposed solution
- Use a progress-capable upload (XHR / `fetch` with progress where available) to show a
  determinate progress bar and a Cancel button that aborts the request.
- Support selecting/dropping multiple files with a per-file status list — or explicitly
  state and enforce single-file with a clear message when >1 is dropped.
- On success, invalidate `['ingestion']` (and `['metrics']`) so charts refresh
  immediately; show a toast.

## Acceptance criteria
1. Given I upload a large file, when it is transferring, then I see a determinate progress
   indicator and a working Cancel that aborts the request.
2. Given I drop two files, when the drop completes, then either both are queued with
   individual statuses, or I get a clear message that only one file is processed.
3. Given an upload succeeds, when the result returns, then the ingestion charts/cards
   refresh without waiting for the poll, and a success toast appears.
4. Given an upload fails mid-transfer, when the error returns, then the partial state is
   cleared and a retry is offered.
