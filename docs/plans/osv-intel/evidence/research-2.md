# Research — OSV batch query API (Gate 2, re-steer)

Source: user-supplied, https://oneuptime.com/blog/post/2026-07-23-query-osv-api/view#query-one-package-version
and #batch-a-resolved-dependency-set, 2026-09-27. Cross-checked against the primary OSV API reference
already cited in `research-1.md` (https://google.github.io/osv.dev/api/) — consistent, no conflict.

## What this corrects in the Gate 2 design

The first Gate 2 pass (C6, superseded) chose a periodic bulk-zip poll over `POST /v1/querybatch`,
reasoning the bulk export better matched the existing poller's "fetch full snapshot, validate,
publish" shape. The user pointed out `/v1/querybatch` fits this feature directly: a batch of
package-version queries, not a whole-ecosystem snapshot, and OSV's query endpoints already scope
matches to the exact version queried — the firewall never needed the whole feed, only per-request
answers. See C6b.

## Batch request/response shape

Request, `POST https://api.osv.dev/v1/querybatch`:

```json
{
  "queries": [
    {"package": {"purl": "pkg:pypi/jinja2@3.1.4"}},
    {"package": {"ecosystem": "npm", "name": "lodash"}, "version": "4.17.20"},
    {"commit": "6879efc2c1596d11a6a6ad296f80063b558d5e0f"}
  ]
}
```

- Up to 1,000 queries per batch request (documented cap) — this service's own flush cap (C12) stays
  well under it.
- `results[i]` corresponds to `queries[i]` positionally, including when a query has no matches —
  array positions must be preserved, not zipped only over nonempty results.
- Each match in a batch response is compact: `{"id": "GHSA-example-id", "modified": "..."}` — no
  affected-range or severity detail. For this feature that is sufficient: any match whose `id` starts
  `MAL-` is a block (C4's unconditional-block policy), so no further filtering by range is needed —
  OSV already scoped the query to the exact version.
- Full vulnerability records are fetched separately via `GET /v1/vulns/{id}`, recommended to be
  cached by `(id, modified)` so an unchanged record is not re-downloaded. **Not needed for this
  feature** (C6b): the firewall only needs existence-of-a-MAL-match, which the compact batch result
  already carries; hydrating full records is for a different use case (reading severity/range/details),
  which this feature's block decision does not consult (C4).
- Production guidance from the source: URL-encode IDs, apply bounded concurrency and retries — not
  applicable here since this design never calls `/v1/vulns/{id}` at all.

## Consistency check against research-1.md

research-1.md (primary OSV API docs) already documented `POST /v1/querybatch` as batching "for given
package versions and commit hashes", `GET /v1/vulns/{id}` for hydration, a 32 MiB response cap over
HTTP/1.1, and no documented rate limit. This source adds the concrete request/response JSON shape and
the positional-correspondence and 1,000-query-cap details that were not in research-1.md's summary. No
conflict between the two sources.
