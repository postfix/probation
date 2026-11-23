# Code review, slice 30 (central OSV)
Verdict: FIX FIRST
Scope: dirty tree (slices 16, 28, 29, 30), slice-30 paths only: src/osv/{mod,batcher,matches}.rs, crates/probation-server/src/{osv,sync,service_policy,lib}.rs, crates/probation-policy/src/{osv_key,osv_wire}.rs, src/{lib,config}.rs, src/managed/report.rs, src/http/health.rs, call sites in src/{npm,pypi,artifacts}, tests/osv_*.rs, tests/common, tests/authorization_read_once.rs. Spec: 04-slices.md row 30, 03-program-design.md "Central OSV lookup", LS-F1/2/5/6/7/11/12/14/15, evidence/slice-30.md, evidence/tdd-slice-30.md (note: the file is under evidence/, not the plan root). No base/head; working tree vs HEAD.
Summary: the design is delivered and mostly sound. Three blockers: F1 (persist race can lose persisted matches), F2 (LS-F12 scope skip is not tested through any adapter path), F3 (LS-F7 alert and the file/stale counters are not observable on a managed `fwt_` endpoint; spec says they travel in the sync report). Lows F4-F7. The known p95-latency decision is excluded.

## Findings

F1 - medium - correctness/concurrency - unserialised `persist` and shared temp name can lose or corrupt persisted matches
Location: src/osv/mod.rs:322 (`persist`), src/osv/matches.rs:158 (`write_atomic` temp name), src/osv/batcher.rs:137 and :371 (flushes run concurrently and each calls `persist` via spawn_blocking)
Requirement: LS-F11 / C1031 (matches survive restart; atomic replace).
Failure: the batcher spawns every flush as its own task ("no cap on concurrent flushes", batcher.rs:130). Two flushes that each store a match both reach `persist`. Both write `.osv-matches.<pid>.tmp` (same path, `truncate(true)`), so they share one inode with independent offsets: interleaved bytes, then one `rename` succeeds and the other fails with ENOENT (counted as `osv_matches_file_degraded`). Separately, `dirty` is cleared at snapshot time, so an older snapshot renamed last replaces a newer file and nothing rewrites it until the next change. Result: a match missing from disk, or torn lines skipped on load, so a restart during a server outage stops refusing that package.
Evidence: code read (no test runs two persists concurrently; all osv_matches tests are single flush). Timing-dependent but the shared path and absent lock are unconditional; I did not reproduce.
Correction: serialise `persist` (a `Mutex<()>` held for snapshot+write, set `dirty` inside it) or use a unique temp name plus a lock. Closure: a test that stores matches from N concurrent flushes then loads the file and expects all N.
Blocking: yes (protection loss on a path the spec calls a safety net).

F2 - medium - tests - LS-F12 scope skip is never exercised through npm, PyPI or artifact paths
Location: src/npm/mod.rs:477/492, src/pypi/mod.rs:361/378, src/artifacts/mod.rs:239 (wiring present and correct on reading); tests: tests/osv_central_app.rs:324 (only the `App::osv_scope` accessor), src/osv/mod.rs:907 (only `evaluate_scoped`)
Requirement: row 30 "enforcer-side `osv_scope` decision"; LS-F12 test `osv_private_names_never_reach_server_or_upstream` (fake records zero hits). The test is absent (grep: no such name).
Failure: a call site that passes `OsvScope::Public` or calls `osv::evaluate` instead (as download.rs:394 legitimately does for standalone) would leave every test green while sending a Private registry's names to the shared server. Mutation witness not run (read-only), but no test touches `OsvScope::Private` outside those two.
Correction: add one test per adapter (npm metadata, PyPI, artifact GET) with a Private registry in the snapshot and a recording fake OSV server, asserting zero hits and an Allow; plus the Public control asserting one hit.
Blocking: yes (named spec test missing; IP/privacy control unguarded).

F3 - medium - requirement - LS-F7 degraded-ratio alert and the file/stale counters are invisible on a managed (`fwt_`) endpoint; the sync report carries none of them
Location: src/managed/report.rs:49 (comment says they "travel in the sync report"; they do not), src/http/health.rs:68 (only the shared-service readiness detail), plain_ready unchanged
Requirement: 03 "Persisted matches and stale window": `osv_matches_file_degraded` and `osv_stale_matches_expired` "travel in the existing sync report"; LS-F7/row 30 degraded-ratio alert (5 percent over 5 minutes).
Failure: managed endpoints are the main C1030 mode. When the matches file is corrupt, the stale window lapses, or the server answers degraded for every key (which the measured latency will cause), no operator surface shows it. Evidence open items 1 and 2 admit this.
Evidence: report.rs/health.rs read; `FirewallReport` carries only `Upstreams` reachability.
Correction: either add the counters to the sync report (additive field in crates/probation-policy/src/api.rs, server stores it; row 27 shows it) or record an explicit spec deviation approved by the user ("this removes the managed alert surface"). Fix the false doc comment either way.
Blocking: yes unless the coordinator records the deviation (touches the management wire, so the user's call).

F4 - low - robustness - a non-object result inside an `upstream_ok:true` answer counts as a confirmed no-match
Location: crates/probation-policy/src/osv_wire.rs:190-205
Failure: `[null]`, `[5]` or `["x"]` as a result yields `NoMatch`, which replaces a retained matched entry (OsvCache::put else-arm). LS-F2 says a no-match is `{}`. Needs a response that already carries a valid envelope (trusted server, so low).
Correction: require `Node::Obj`; anything else is `Degraded`. Add a case to osv_wire tests.
Blocking: no.

F5 - low - availability - OSV pre-auth throttle is keyed by raw socket peer, so endpoints behind one NAT or proxy share it
Location: crates/probation-server/src/osv.rs:355 (peer), :276 (`preauth_blocked`)
Failure: 10 failed credentials per minute from one peer address makes every valid caller behind that address get 429 for the minute (fail-open, so new-key protection lapses). /sync derives the caller address with `trusted_proxies`; this route does not. Plausible, deployment-dependent.
Correction: use the same address derivation as `firewall_identity`, or throttle only failures and exempt a valid credential's request.
Blocking: no.

F6 - low - tests - two spec-named tests are weaker than their names
Location: tests/osv_central_app.rs:253 (`standalone_still_queries_osv_dev_directly` only greps src/lib.rs for a string), tests/osv_central_app.rs:146 (`managed_endpoint_sends_no_request_to_osv_dev...` observes only the policy-server fake; no api.osv.dev recorder exists, the unreachable client is the only guard)
Failure: a rename or refactor breaks the first without behaviour change; the second cannot see an accidental direct call. Mitigated by `https_only`, the fixed Target and the structural test at :265, and by osv_enforcement for standalone behaviour.
Correction: keep, but add a behavioural standalone case and give the endpoint an `osv_client` that records hits on `api.osv.dev`.
Blocking: no.

F7 - low - behaviour - `record_would_block` now reads `cached` instead of `check`
Location: src/artifacts/mod.rs:299
Effect: no second lookup (good, and needed so a Private registry is never queried here), but in managed log-only mode a matched entry past its TTL (stale window) returns None and the "would have blocked" record is skipped. Diagnostic only; no verdict change. Note, not a regression of enforcement.
Blocking: no.

## Requirement coverage
| Requirement | Implementation/connection | Result |
|---|---|---|
| Managed endpoints make no api.osv.dev call (C1030, T9-8) | src/lib.rs:337-373: central arm whenever `osv_central_server()` is Some and no plain seam; `AppDeps::osv_client` ignored; `central_http_client` https_only, redirects off; `central_base` rejects http/userinfo/query/fragment; only `OsvClient::new` call is the standalone arm (structural test lib.rs; grep: api.osv.dev appears only in the fixed constant and test seams); no config key (`managed_config_has_no_direct_osv_key`) | MET |
| Per-result degraded and `upstream_ok` reached rule | osv_wire.rs `parse_central`; batcher.rs:312-325: reached = parsed && upstream_ok; degraded or `upstream_ok:false` no-match stores nothing and keeps stale match; matches in an `upstream_ok:false` answer honoured | MET (F4 aside) |
| Envelope required on client | `MissingEnvelopeMeta` for missing/invalid meta, version, `upstream_ok` type; duplicate keys rejected | MET |
| F11 matches file: format, CRC, clamp, bounds | matches.rs: header, per-line 512 B, crc over e|n|v|x, osv_key revalidation, `x.min(ceiling)`, expiry prune, 100000 entries, 16 MiB bounded read, later duplicate wins, torn tail skipped, 0600, temp+fsync+rename+dir fsync; tests 11 pass | MET for format/load; atomicity under concurrency NOT MET (F1) |
| F6 `osv_key` used by both sides | client `flush_central` filter (batcher.rs:296) and server `answer` (osv.rs ~line 430); loader too | MET (Go-path test not applicable, no Go family) |
| F12 scope skip wired | `app.osv_scope` + `evaluate_scoped` on npm, PyPI, artifact (standalone download.rs keeps unscoped `evaluate` by design); effective_scope matches LS-F12 rules | wired MET; end-to-end test NOT MET (F2) |
| F14 put-hook order | OsvCache::put: store, hook (mutex held), then `fetch_add(Release)`; mutation probe 3 recorded red | MET |
| Refusal separation (LS-F1) | `spawn_central`/`flush_central` take only `UpstreamHealth`; `osv_401_never_creates_or_clears_refusal`, `snapshot_refusal_not_cleared_by_osv_2xx` | MET |
| Rate budget, breaker, coalescing | per-credential bucket (600/min, burst 1000) charged per leader only, separate from sync; auth gate of 4; breaker on 429 capped 30 s plus jitter; leader fetch spawned independently of the request; 4xx split per key; size caps; matched LRU preferred | MET |
| Deadlines 300/500/400 | constants implemented as approved | MET against spec (latency decision is the coordinator's) |
| Cache/stale window semantic C1031 | matched exempt from LRU, cap 100000, stale ceiling, config 3600-604800 | MET |
| Sync-report counters, LS-F7 alert | see F3 | NOT MET (managed) |
| authorization_read_once additions | see below | MET |

## Conventions and simplifications
- authorization_read_once allowlist (tests/authorization_read_once.rs:56-59): both entries justified. The invariant guards the caller's package-manager Authorization header; the OSV batcher never sees it and attaches only the endpoint's own credential (batcher.rs `send_central`), origin-checked against the configured server origin, header marked sensitive. Entries are narrow (import in module scope, one `header(AUTHORIZATION,value)` in `fn send_central`, count 1); no existing entry changed. The test passes (4/4). Security review should still confirm as the evidence says.
- Test harness edits keep non-OSV managed tests meaningful: managed starts default to the plain unreachable seam (immediate fail-open, as the old `.resolve("api.osv.dev", port 0)` did); the production derivation is covered by osv_central_app via `osv_server_origin_override`. No assertion was weakened (`start_unready`, `managed_sync`, server tests/common: field additions only).
- `AppDeps::osv_base_url` and `osv_server_origin_override` are ordinary public fields, not cfg-gated, but there is no config or env path to them (main.rs sets both None); same stance as the existing `osv_base_url`. Fine.
- No functionality dropped found: standalone path, `osv::evaluate`, `OsvClient::new` unchanged; `check`-to-`cached` is F7.

## Uncertainties
- Open item 5 (`osv_stale_match_seconds` not in `LOCAL_ONLY_SETTINGS`, crates/probation-policy/src/lib.rs:24): assessment: acceptable as is. It is range-checked (3600..604800) after merge, rejected in standalone, and the equally protection-relevant `osv_mode` (can be `off`) and `osv_cache_ttl_seconds`/`osv_request_timeout_ms` are already pushable; the management server already controls policy. Making it local-only would be a cheap hardening (a pushed 3600 shrinks outage protection from 24 h to 1 h), but it would create the only OSV key a fleet owner cannot tune. User decision; I recommend leaving it pushable and documenting it in operations.md.
- Open item 1/2: see F3 (item 2, server counters via `OsvState::health()` only, is acceptable: the row asks only for "a health counter", but nothing exposes it either; low).
- Open item 3: Go charset test deferred to row 17-24 families: agree, not applicable.
- Open item 4: agree; direct mode sends what it sent before, central mode filters through `osv_key`. Risk: a legacy npm name with a character outside `[A-Za-z0-9._~-]` (a few historic packages) becomes degraded forever in managed mode, previously checked in direct mode. Plausible, rare; check against the npm corpus or widen the charset to what the adapter can emit.
- Open item 6 (E2E not run): acceptable for this row's command list; the row 33 gate must cover it.
- Server upstream call is cancelled at the 300 ms deadline (osv.rs `fetch`, `timeout_at`), so a slow-but-successful upstream answer is discarded and never reaches the cache; retries stay cold. Input for the pending latency decision: letting the leader finish into the cache past the deadline (followers still answer degraded) would let repeat lookups converge.
- A `Matches` page-token (osv.dev pagination for >1000 vulns) is ignored by the server's upstream parse; a MAL entry on page 2 would be missed. Theoretical.

## Verification and limits
Ran (all under `systemd-run --user --scope -q -p TasksMax=512 -p MemoryMax=16G -- timeout 900`, no /tmp targets, no mutation, tree not modified except this report):
- `cargo clippy --workspace --all-targets -- -D warnings`: exit 0, finished with no diagnostics (up to date build). The earlier E0624 (`cached` private) and non-exhaustive `SendError` match diagnostics are gone: `OsvClient::cached` is `pub` (osv/mod.rs), `SendError` has `Status`, `Oversize`, `Credential` arms and a total Display.
- `cargo test --features probation/test-support --test osv_matches_file --test osv_managed_endpoint --test osv_central_app --test osv_ecosystem_mapping --test authorization_read_once --test managed_release_wiring`: 11, 21, 11, 2, 4, 6 passed, 0 failed.
- Not rerun: probation-server tests (need Postgres), probation-policy osv_key/osv_wire, `cargo test --lib osv` (known hanging neighbours), e2e. Relied on evidence/slice-30.md for those; mutation-probe reds from tdd-slice-30.md are supplied evidence, not re-run. Test-first history: reds recorded for most cycles; osv_central_app and two later tests say "red not observed" (history unverified, not a defect).
- Unreviewed: docs edits, portal/row 27 views, tests/e2e, slice 16/28/29 changes except where they touch OSV. Spec file sizes were large; LS-F2/F5/F7 bounds table (line 264+) was read only through the code's constants.
- Unchanged during review: yes (read-only; git status unchanged apart from this report).
- Lenses with no finding: removed behaviour (none), security of credential attachment (origin check, https_only, no redirects, sensitive header), resource bounds on server (body cap before parse, read cap, batch cap, cache bounds).

## Next steps
1. Fix F1 (serialise persist, add a concurrent-flush test) and F2 (adapter-level Private-skip tests incl. zero fake hits).
2. Coordinator/user: decide F3 (add counters to the sync report vs recorded deviation), open item 5 (recommend pushable), and the pending latency decision (consider the leader-completes-into-cache option noted above).
3. Optionally fold in F4-F7, then re-review F1-F3.
