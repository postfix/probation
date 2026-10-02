# Research — OSV malicious-packages feed shape (Gate 2)

Verdict: ANSWERED (`sf-research`, 2026-09-27)

Question: How are OSV malicious-package advisories (`MAL-*` prefix) for npm and PyPI published and
fetched today (bulk export vs. HTTP query API), what is the bulk-export URL pattern/format/cursor
behavior, what is the HTTP API shape/batching/rate limits, and is there documented polling-cadence
guidance?

Decision this grounds: how the new Rust OSV poller (parallel to `src/tasks/blocklist_poller.rs`)
fetches OSV data and detects what changed for its periodic snapshot republish.

## Answer

1. `MAL-*` records are ordinary OSV records (`ecosystem` field = `npm` or `PyPI`), sourced from
   `ossf/malicious-packages` and ingested into the same OSV.dev store/bucket/API as CVE-style advisories
   — no separate "malicious packages ecosystem" endpoint; fetch the npm/PyPI ecosystem data and filter
   `id` starting with `MAL-`.
2. **Bulk export** (GCS, public, no auth): per-ecosystem zip at
   `https://storage.googleapis.com/osv-vulnerabilities/<ECOSYSTEM>/all.zip` (e.g. `npm/all.zip`,
   `PyPI/all.zip`), one JSON file per vulnerability. Full snapshot every time — no ETag/Last-Modified/
   generation-number diffing on the zip. A separate flat file
   `https://storage.googleapis.com/osv-vulnerabilities/modified_id.csv` (`<ISO modified timestamp>,
   <ecosystem_dir>/<id>`, reverse-chronological) is the documented incremental-change cursor: stream it,
   stop at a timestamp already seen, fetch only the changed per-ID JSON objects.
   Source: https://google.github.io/osv.dev/data/ (primary, "Data dumps")
3. **HTTP v1 API**, base `https://api.osv.dev`: `POST /v1/query` (single package-version/commit),
   `POST /v1/querybatch` (batched query across many packages/ecosystems, ID-only stubs), `GET
   /v1/vulns/{id}` (hydrate a full record). Response cap 32 MiB over HTTP/1.1, unlimited over HTTP/2.
   Documented rate limit: **none** ("Currently there are no limits on the API").
   Source: https://google.github.io/osv.dev/api/ (primary, API reference)
4. No primary-documented polling cadence or freshness SLA for the malicious-packages feed. Only a
   secondary, non-normative data point (OpenSSF blog, 2026-05-20): "most open source malicious packages
   end up getting classified by OSV.dev within the first 3 days" — offered as rationale for a
   `--min-release-age=3` heuristic, not an ingestion/poll-interval commitment.
   Source (secondary, not load-bearing alone): https://openssf.org/blog/2026/05/20/detecting-malicious-packages-using-the-osv-api/

## Recommendation

Mirror `blocklist_poller.rs`'s shape against the **bulk export**, not the query API: fetch
`npm/all.zip` and `PyPI/all.zip` (or `modified_id.csv` for incremental refresh) on a fixed interval.
There is no rate-limit pressure either way, but the zip gives a complete, validate-off-request-path
snapshot matching the poller's existing "fetch full snapshot, validate, republish" pattern.
`querybatch` is the right shape only if the design shifts to per-request/on-demand lookups instead of
a periodic full-snapshot poll. OSV documents no freshness SLA, so the poll interval is a product/ops
choice (config default), not something OSV constrains.

## Findings

- Bulk zip URL pattern & full-snapshot behavior — https://google.github.io/osv.dev/data/ — documented.
- `modified_id.csv` incremental change cursor — https://google.github.io/osv.dev/data/ — documented.
- v1 API endpoints, `querybatch` batching, 32 MiB/HTTP1.1 cap, "no limits" statement —
  https://google.github.io/osv.dev/api/ — documented.
- `MAL-*` records live inside standard per-ecosystem npm/PyPI data (confirmed via live record,
  `ecosystem="npm"`) — https://osv.dev/vulnerability/MAL-2024-10666 — observed.
- No primary-documented polling cadence/freshness SLA; only a secondary "~3 days" anecdote —
  https://openssf.org/blog/2026/05/20/detecting-malicious-packages-using-the-osv-api/ — claimed,
  secondary, non-normative.

Conflicts: none material — "no documented cadence" (primary) sits beside a non-normative "~3 days"
figure (secondary blog), surfaced but not treated as a spec.

Limitations: did not fetch the raw OpenAPI spec file or the `google/osv.dev` GitHub README directly;
the served docs pages (same primary maintainer source) were sufficient to answer all four questions.
