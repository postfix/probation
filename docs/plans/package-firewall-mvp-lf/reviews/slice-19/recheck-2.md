# Recheck 2, slice 19 (Go) fix round (recheck-1 items N1-N7)

Verdict: PASS (no blocking finding; six Low findings, L1-L6, none needs a fix before commit).
Procedure: /home/john/.claude/skills/lf-start/agents/code-review/AGENT.md, security lens applied to the same reads. Read-only; no source or test edited.
Subject: uncommitted tree on slice5-native-ci over 3e8d3e4. Inputs read: reviews/slice-19/recheck-1.md, evidence/slice-19.md (Recheck-1 round, decisions), evidence/tdd-slice-19.md (R1-R9 lines), src/http/readmit.rs, src/http/mod.rs (layer order), src/http/service_registry.rs, src/http/go_routes.rs, src/artifacts/stream.rs (into_response), src/managed/publication_gate.rs, src/managed/service_policy.rs (publish order), src/http/logging.rs (request context), src/go_modules/serve.rs (admit_rev, make_room), src/artifacts/download.rs, src/artifacts/mod.rs, src/http/limits.rs, src/store/mod.rs (carried_forward) and the tests named below.

Checks run (scope: systemd-run --user --scope TasksMax=512 MemoryMax=16G, timeout 900; CARGO_TARGET_DIR under .probation-scratch/target, nothing in /tmp): all pass.
- credential_bearing_reads `a_publication_between_authorisation_and_release_is_admitted_again_for_every_family`
- cargo_service_read `a_block_published_while_a_download_is_in_flight_wins`; go_service_read `a_block_published_while_a_go_file_is_in_flight_wins`, `a_long_list_is_not_dated_again_from_nothing_by_a_request_with_an_empty_table`
- go_modules `small_transfers_share_the_waiter_bound_and_read_only_their_own_cap`, `tiny_metadata_files_do_not_queue_behind_large_transfers`, the two revision tests
- persistence_projects `an_upsert_without_a_date_does_not_blank_a_recorded_go_publication`
- managed_mode go_ (6: includes `go_revision_queries_are_bounded_per_key_and_junk_cannot_block_another_key`, `go_block_published_while_the_request_is_in_flight_wins`, `go_request_released_across_a_policy_publication_is_admitted_again`)
- lib go_modules::serve (2). Not run: mutation probes (read-only), whole-lib run (known unrelated failures per evidence).

## Recheck-1 items

| Item | Status | Basis |
|---|---|---|
| N1 per-(registry,module,key) bound, bounded tables | FIXED, guarded, with L2/L3 | `admit_rev`: per-key window 32, per-module ceiling 256, both tables capped at 1024 windows (expired, then oldest dropped). Test uses two keys and 1,100 junk modules from one key. The ceiling itself is untested (evidence says so). |
| N2 re-admission | FIXED generically (see section A) | |
| N3 block mid-request | FIXED, guarded | three tests (key route Go, service Go, service Cargo) assert 403, not 503/200. |
| N4 publication carry-forward | FIXED, Go only, guarded | `carried_forward` carries stored `publication_micros` only when the upsert has None AND ecosystem is Go; the Npm case is pinned unchanged. See L5. |
| N5 small pool | FIXED, guarded, with L4 | waiter place taken from `max_download_waiters` after a failed try_acquire; the waiter is held through the bounded wait and released after; `.info` min(cfg,256 KiB), `.mod` min(cfg,16 MiB), applied in `transfer` and `fetch_request_scoped` alike. Test: 17 MiB `.mod` 502, 1 MiB 200, waiter bound refuses at once. |
| N6 | stated in docs/operations.md | no code change expected. |
| N7 list seeding | FIXED, guarded | 130 versions dated 64, 128, 130 over three request-scoped lists. |
| N8 | noted, left | |

## A. src/http/readmit.rs (all families)

Answers, each by reading and confirmed by the passing tests above:
- Replay a write: no. Anything other than GET or HEAD returns `next.run(request)` before any body is touched (readmit.rs:36). Only the marked 503 retries. GET routes that forward upstream (npm `any(action)`, Cargo `owners`) are reads; replay is a repeated read with the same caller credential. No test pins "a write is not replayed" (L1).
- Re-send sent bytes: no. The loop sees only a finished `Response` head; the refused one is an `ApiError` 503 body that is dropped; the permit, pin and request-scoped file of the refused artifact response are dropped when the iteration ends, before the next admission.
- Old-snapshot or pre-block response out: no. Every attempt rebuilds the request from the pristine `parts` (method, URI, version, headers, extensions cloned before the first run, so nothing accumulates) and runs the whole stack again. In `service_registry::respond` the generation is read before the snapshot, and `publish` swaps the snapshot before bumping the generation, so a retry cannot pair a new generation with an old snapshot; a mismatch can only refuse. The key route's receipts come from `principal()` under the gate read lock. A block published meanwhile wins (the three N3 tests).
- FIX-16-A / C1028: the gate code is untouched. `refusal()` is produced only by `respond_order`/`authorize_current_policy` failures (stream.rs:257, service_registry.rs:79-80) and the Go selected-route fingerprint recheck. Credential-bearing classification is recomputed per attempt from the same headers (`classify_read`); no cache is read or filled by the layer itself. The per-request `RequestContext` (logging.rs) is shared by attempts, so `request_scoped` stays set once set: only more conservative.
- Loop beyond 3: no; `attempt >= ATTEMPTS` returns the response, the one layer is the only retry (the Go-only loops were removed; grep finds no other).
- Credential across principals: no. The retry re-derives the principal from the same Authorization header; nothing authenticated is stored in extensions by the outer layers (bound_headers and logging::decide insert none; only ConnectInfo is cloned). A key revoked between attempts is refused on the next.

## Findings (all Low, none blocking)

L1 Low, test gap. src/http/readmit.rs:36 and tests/credential_bearing_reads.rs:799. No test makes a PUT/POST/DELETE hit a refused release and asserts one upstream effect, and the "bounded at 3" is only loosely pinned (100 publications give 503; a mutant with ATTEMPTS=50 still passes). Failure scenario: a later edit that widens the method match to all methods would replay a Cargo publish, yank or RubyGems push after a gate refusal and pass the suite. Fix: one test with a counting upstream, a PUT through the service route and one publication, asserting a single upstream write; and one with exactly 3 publications asserting the call count of the handler. Cost: two small tests. Not blocking.

L2 Low, availability. src/go_modules/serve.rs:583 (`MAX_REVS_PER_MODULE` 256). Keys are per key id, so an org with 8 or more read keys (or 8 colluding tenants in the standalone/managed route) sends 32 distinct tokens each for one module and the module ceiling makes every other key's `go get M@main` 429 for the minute. Smaller than the recheck-1 N1 (needs 8 keys, 256 req/min, the ceiling does not collapse to one request), but the evidence sentence "never blocks a module" is not true at the ceiling, and the ceiling is untested. Fix options: state it in evidence, or add a test with a lowered constant. Cost: documentation or a test seam.

L3 Low, bound strength. serve.rs:593-601 `make_room` + `admit_rev` run before any upstream call. One key sending about 1,024 junk module names a minute evicts the oldest windows, including its own window for module M, so its 32-token bound resets at the price of 1,024 requests that each cost an upstream 404 anyway. The bound therefore limits tokens per module, not upstream rev calls per key; only `max_active_requests` limits those. Not a regression (the same walk was possible before the bound). Mention in docs only.

L4 Low, resource accounting. src/http/limits.rs:107-113. Small waiters and large waiters draw from the same `download_waiters` pool. 64 small transfers held by slow upstream streams plus waiters can fill the pool, so a large `.zip` request that cannot get a place is refused at once (503) instead of waiting. The total concurrent transfers is `max_artifact_downloads + 64` (documented). Fail closed, availability only; consider a separate waiter count if zips are seen 503ing under tiny-file load.

L5 Low, plausible (not reproduced). src/store/mod.rs `carried_forward`: the carry applies only when the upsert has None. Two overlapping `record`s of one Go version with different upstream times can commit the older time last (each computed its max from what it had read), leaving stored publication earlier than the true max; the in-memory table keeps the max until restart or eviction, then the stored (earlier) date is the floor. Needs an upstream that answers two `.info` for one version with different times. Cost to close: take max(stored, upsert) for Go in the same statement. Optional.

L6 Low, operations. (1) `service.admit_request` (rate budget) and every upstream and OSV call run again on each re-admission, so a tenant near its rate limit can get 429 from a request that was already admitted once, and a request-scoped credential-bearing read re-downloads from upstream on every attempt (it never uses the store). (2) The gate generation is global, so any publication re-runs every in-flight read of every tenant, at most 3 times each; before the layer these were 503s. Bounded at 3x per request; no unbounded loop. Mention in docs/operations.md if desired.

## Requirement coverage

| Requirement | Status |
|---|---|
| Recheck-1 N1-N7 fixed and test-guarded | MET (N1 ceiling untested: L2; N4/N5 tests are written after code, probes R3, R5, R6 stand in, per evidence) |
| Re-admission never replays a write, never re-sends bytes, decides again under the new policy, at most 3 | MET, with test gap L1 |
| FIX-16-A and C1028 unchanged | MET (gate code and credential classification untouched; retried per attempt) |
| Slices 17/18 functionality | no regression seen in the listed suites; cargo, rubygems and shared-service suites were not rerun this round (the N2 test covers npm, PyPI, RubyGems, Cargo `config.json` and Go through the new layer) |

## Limits

Test-first: N1, N4, N5, N7 cycles are "red not observed as test-first red" with mutation probes R1-R9 (evidence/tdd-slice-19.md lines 104-112); that is an honest line, not blocking. Probes were not re-executed here. Unchanged-during-review: could not check by fingerprint; the working tree was the same HEAD and file set at start and end. The known whole-lib failures at HEAD are not attributed to this slice.
