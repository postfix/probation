# Slice 23 (Conan 2) fix round: recheck 4 (code review, security lens)
Verdict: FIX FIRST
Procedure: /home/john/.claude/skills/lf-start/agents/code-review/AGENT.md (read-only; no code edits).
Inputs read: reviews/slice-23/recheck-3.md (M1, M2, L1-L6), evidence/slice-23.md ("Recheck-3 round"), evidence/tdd-slice-23.md (named by the packet; only the evidence summary was relied on), src/conan/serve.rs (judging, verdicts, search slots, serve_search, serve_package_search, PackageDoc, list_units, resolve, reference_for_file, record), src/http/conan_routes.rs (`run`, `within`), tests/conan_judging.rs, tests/conan_service_read.rs:431, tests/managed_mode.rs (go publication tests as fixture model), Cargo.toml / Cargo.lock diff, src/artifacts/download.rs diff, docs/operations.md (search paragraph).
Snapshot: branch slice5-native-ci at 1e1418b plus the uncommitted slice.

## Status of recheck-3 findings
| ID | Status |
|---|---|
| M1 | Partly closed. Lanes and latency table are sound for a standalone firewall; two defects remain (R4-1, R4-2). |
| M2 | Closed: typed `PackageDoc` (ids plus `RawValue` info text), `Parent::Package` built per batch of 5,000, `kept` is indices only, answer written entry by entry. Sizes plausible (see below). |
| L1 | Closed (`kept` holds indices). |
| L2 | Open as a test gap only: code correct, test feasible (see below). |
| L3 | Closed in code and docs (a search writes no row; undated revisions get first-seen now and are not remembered). |
| L4 | Closed (`JUDGE_WAIT_MS`, `PEAK_BIG` private; `set_judge_wait_ms`, `peak_big`, `verdict_count`, `own_sizes` only under `test-support`). Note `PEAK_BIG.fetch_max` runs in the shipping `big_permit` (one atomic op; harmless). |
| L5 | Evidence format only; not re-judged. |
| L6 | Closed (ordered structures, no scan). |
| Slices 17-21 | No regression found: `download.rs` gained one MD5 update per chunk plus Conan arms (`is_conan_small`, `Call::Conan`, `verify_conan_manifest`); the Maven sidecar call now takes `.clone()` of the authorization, same behaviour. `md-5` was already in the root manifest and lock. |

## Findings

R4-1 - medium - correctness of the retry/convergence claim - verdict renewal is armed only by the 504 path, not by the client's own abort
Location: src/conan/serve.rs:1478-1487 (`unfinished` is set only inside the `timeout_at(deadline)` `Err` arm), :1264-1273 (`get_verdict` renews only when `retrying`), :1244-1246 (`JUDGE_WAIT_MS` 100 s), src/http/conan_routes.rs:57-58 (`within`, 120 s), versus evidence "N2" ("far inside the 60 s a Conan client waits", tests/conan_judging.rs:326).
Failure (CONFIRMED by reading the code path; the client timeout is the evidence's own figure, to be checked against the pinned Conan client): a Conan 2 client reads with a timeout of about 60 s. A search that needs more than 60 s is abandoned by the client at 60 s; hyper drops the handler future, so the deadline arm that sets `unfinished` is never reached (the server only answers 504 at 100 s, after the client has left). The next attempt reads its verdicts without renewing them, and a verdict lives 120 s from when it was made. Steady state is then at most 120 s x rate verdicts alive: 9,000 references need 75 per second (the original M1 criterion) whatever the retry. The tests use `reqwest` without a client timeout and a 3 s server deadline, so they exercise only the 504 branch, and `retry_sequence_at_200_ms_with_the_production_deadline` (an ignored measurement) the same. The claimed convergence "at any latency" holds only for a client that waits for the server's 504.
Correction: mark the registry unfinished when judging is left for ANY reason other than success (a drop guard around the judging loop that sets `unfinished` unless the search reached its end), and add a test that aborts the client request mid-search (drop the `reqwest` future) and shows the retry continues from the verdicts. Cost: one small guard type and one test.
Blocking: yes if the Conan client's real read timeout is below 100 s (the evidence says 60 s): the feature's core outcome on the public registry (a 9,000-reference search at 100-200 ms) then depends on a rate the table only reaches at 0-100 ms, standalone.

R4-2 - medium - evidence - the latency table was measured in the one mode where an owner share does not exist
Location: src/conan/serve.rs:1315-1330 (share `JUDGE_PLACES / 2` = 8 per (registry, owner), taken only when `owner` is `Some`); src/http/conan_routes.rs:73 (owner is `Some` for every service-mode and certificate-managed request, `None` for standalone); tests/conan_judging.rs:264-286 (`measure_cold` uses `TestServer::start_with_upstream_and_osv`, standalone).
Failure: in shared-service and certificate-managed mode a single honest caller judges with 8 lanes, not 16. Throughput is 8 / latency: 80 per second at 100 ms (9,000 references: 112 s, over one deadline), 40 per second at 200 ms (225 s, three attempts, and only if R4-1 is fixed). The documented table (docs/operations.md, evidence) states no mode, so it is read as applying to all.
Correction: run the measurement (and `a_search_too_large_for_one_attempt_converges...`) once in service mode with an owner, and state the mode in docs; or give one owner the registry's whole lanes when nobody else judges (a share that is a cap under contention only). Cost: one measurement variant, or a fair-share counter.
Blocking: no by itself (retry still converges when R4-1 is fixed); the numbers must state their mode.

R4-3 - medium - availability - an owner's judging share is per (registry, owner), so one owner can hold every process judging lane
Location: src/conan/serve.rs:1320-1332 (`owner_judging` key `(registry_id, owner)`), :220 (`judging_total` = half of `max_upstream_requests`, no owner dimension); `OWNER_SEARCHES_TOTAL` = 8 searches, 2 per registry.
Failure: one address (shared-service mode) or account that can use two registries (its own registry origins, or two selected registries) runs a search on each; each holds its 8 lanes of its registry, together all 16 process lanes. Other tenants' searches then wait up to `REFRESH_WAIT` (30 s) per verdict for a process lane and answer 504 (without arming renewal, see R4-1). A caller whose own registry's lists hang (an own origin it controls) holds the lanes for up to the 100 s deadline, repeatedly. Installs are untouched (judging takes half of `max_upstream_requests`, 16 remain; the test `judging_leaves_fetch_places_for_installs` shows it), so this is search-only denial across tenants, the same class as the accepted R-A (a few addresses each holding their half) but needing one caller.
Correction: add an owner-wide judging cap (key `owner` alone, for example 8 of the 16 process lanes), taken with the same timeout ordering; Cost: one more semaphore map entry per owner (the table already exists for `(registry, owner)`).
Blocking: no (search-only, bounded by deadline, installs unaffected); fix with R4-1.

## Answers to the specific questions
- Lanes starving installs: no. Judging lanes are 16 of 32 process upstream permits and take none of a registry's four fetch places (`fetch_list` with `judge=true`; `refresh_places` skipped). The 32-lane variant that starved an install is gone and is guarded by `judging_leaves_fetch_places_for_installs` (16 gated lists, an install answered at once). Per-registry judging lanes (16) are above the per-registry search slots only through `JUDGE_AHEAD`; no lane-order cycle (share, registry lane, process lane; no permit held while waiting for a share).
- Release on every exit: all permits (`_share`, `_place`, `_process`, `_decode`, search slots) are RAII locals of futures that are dropped on cancel, deadline, error and unwinding; `Flight::drop` removes the flight so waiters retry. No leak found.
- Latency table credibility: consistent with lanes / round trip (16 lanes: 160 per second theoretical at 100 ms, 137 measured; 80 at 200 ms, 74 measured; 320 at 50 ms, 242 measured). Credible for standalone (R4-2). The "retry converges" claim holds for a client that waits for the 504 (R4-1).
- Verdict renewal and staleness: bounded. A renewal needs `unfinished` for the registry (set only by a 504, 120 s long, re-armed only by another 504), only extends to `min(now + 120 s, born + 600 s)` and never shrinks, so no verdict outlives 10 minutes from its making whatever an attacker does; verdicts are keyed by registry, origin and the policy fingerprint, so a policy or fingerprint change never reuses an old verdict; credential-bearing reads have no key and keep nothing. A name or version block published after a verdict is re-applied to `kept` at the end of `serve_search` (FIX-16-A holds; `a_block_published_mid_search_wins`); `serve_package_search` blocks the recipe at its start and a digest block or pin is enforced at delivery. An OSV change or a hold that ends can show up to 10 minutes late in the listing only while searches keep failing; every file and list request is gated live (`refuse_unless_allowed`, the artifact pipeline), so a stale verdict never releases a file. A window nuance (low): the flag stays set up to 120 s after a 504 even when the next attempt finishes, so polling inside that window renews once more (bounded by the 10 minute cap; `polling_a_finished_search_does_not_keep_its_verdicts_alive` covers the no-504 case only).
- M2 memory: plausible. 500,000 references: result strings (about 25-30 MB), the dedup set (about 8 MB), the 8.9 MB body, 500,000 verdict entries (about 40 MB), plus a debug-build allocator; 207 MiB is of the right order. 100,000 ids at 81 MiB: 16.7 MB document plus about 100,000 `RawValue` boxes plus verdicts, plausible; 16 concurrent searches (the slot bound) would be about 1.3-3.3 GB, only the four-at-once case was measured (308 MiB).
- `serde_json` `raw_value`: one feature added to the root manifest only (Cargo.lock unchanged, correct: features are not locked, no new package). The feature adds the `RawValue` type and no behaviour change to `Value`; no `preserve_order` or `arbitrary_precision` interaction. The member crates keep their own plain `serde_json` and unify to the root's feature set only inside the root's build. No supply-chain concern. The `RawValue` is used only through `serde_json::from_slice`, which is the supported path.
- L2: the end-of-search fingerprint check (`fingerprint_of` before and after) is correct: it reads the current policy through `check_policy` and returns `PolicyUnavailable` (503) on any change; it covers certificate-managed layer changes and shared-service snapshots. In shared-service mode the re-admission layer fires first (the test sees a 200 with an empty list), so only certificate-managed mode reaches it, if at all (`legacy` is under the shared layer too, so the check may be dead code in practice there). A managed-mode test is feasible by combining `go_block_published_while_the_request_is_in_flight_wins` (tests/managed_mode.rs:1408, `FakeSyncServer::edit_layer`, `sync.applied`) with `FakeAnswer::GatedMetadata` on a list (tests/conan_service_read.rs:431): publish a stricter layer while a search judges, release, expect 403/503 or an empty list and no stale entry. Non-blocking; add it, or record the check as defence in depth.
- No row from a search, anchor written before serving: confirmed. A rowless entry (`rowless: true`) is put into the unit table only for dated revisions; `list_units` with `judge_only=false` ignores rowless entries and re-records (writes the anchor, `first_seen = now`); `resolve` may return a rowless entry for `reference_for_file`, which then (no row) runs `refuse_unless_allowed`, `within_row_bound` and commits the file's row (first-seen `known.first_seen.unwrap_or(now)`) before `serve_artifact_in`; the artifact pipeline itself never serves without a row. No path serves a revision before a row exists. Low note: an undated revision is judged as first-seen now on every search, so with a cooldown it never lists in a search until a list or file request writes its row (conservative; document it).
- Test seams: all four only under `test-support` (lines 230, 236, 860, 1248). No other public knob found.

## Requirement coverage
| Requirement | Connection | Status |
|---|---|---|
| M1 lanes bounded, no install starvation, released on every exit | `compute_verdict`, `judging_total`, RAII permits, `judging_leaves_fetch_places_for_installs` | MET |
| M1 per-owner limit | per (registry, owner) only | NOT MET at process scope (R4-3, non-blocking) |
| M1 latency table credible; retry converges | table consistent; 504-only renewal | MET for standalone and a patient client; NOT MET for a 60 s client (R4-1) and unmeasured in service mode (R4-2) |
| Verdict renewal rule safe (FIX-16-A, fingerprint, polling) | `get_verdict`, key with fingerprint, end-of-search block re-apply | MET |
| M2 typed package search, memory | `PackageDoc`, per-batch parents, indices | MET |
| `raw_value` dependency | Cargo.toml only, lock unchanged | MET |
| L2 end-of-search fingerprint test | none in managed mode | NOT MET (gap, feasible) |
| No row from search; anchor before serving | `list_units`, `resolve`, `reference_for_file` | MET |
| Seams under `test-support` | cfg gates | MET |
| Slices 17-21 | diffs read | MET (no regression found) |

## Verification and limits
- Run: `cargo test --locked -j 8 --test conan_judging` inside `systemd-run --user --scope -q -p TasksMax=512 -p MemoryMax=16G -- timeout 900`, target dir under /home/john/go/src/github.com/postfix/.probation-scratch/recheck4 13 passed, 0 failed, 4 ignored (measurements), 51 s.
- Not run: Postgres tests, E2E, the ignored measurements, any real Conan client (R4-1's 60 s timeout is the evidence's figure, not re-measured here).
- Unchanged during review: yes (no edits by this review). Scratch removed at the end.

## Next steps
Fix R4-1 (drop guard arms renewal on any non-success exit; abort test) and R4-3 (owner-wide judging cap); run the table once with an owner and state the mode (R4-2); add the managed-mode fingerprint test (L2). Then recheck R4-1 only.
