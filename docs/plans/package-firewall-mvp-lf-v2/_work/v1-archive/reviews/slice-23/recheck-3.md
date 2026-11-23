# Slice 23 (Conan 2) fix round: recheck 3 (code review, security lens)
Verdict: FIX FIRST
Procedure: /home/john/.claude/skills/lf-start/agents/code-review/AGENT.md (read-only; no code edits).
Inputs read: reviews/slice-23/recheck-2.md (N1-N7), evidence/slice-23.md ("Recheck-2 round", "Recheck-2 follow-up"), evidence/tdd-slice-23.md (lines 93-111; the file is under evidence/), src/conan/serve.rs (config, places, `fetch_list`, `list_units`, `record`, `resolve`, `reference_for_file`, judging, search), src/http/conan_routes.rs (`run`), src/http/spool.rs (`owner_of`, `owner_in`), tests/conan_judging.rs, tests/conan_service_read.rs (N4/N5 tests), diff of src/artifacts/download.rs, src/artifacts/mod.rs, src/http/limits.rs, src/http/mod.rs, Cargo.toml.
Snapshot: branch slice5-native-ci at 1e1418b plus the uncommitted slice (Cargo.toml and Cargo.lock unmodified).

## Status of recheck-2 findings
| ID | Status |
|---|---|
| N1 | Fixed. The permit is a local of `fetch_list` (:828) and of the decode blocks in `serve_search` / `serve_package_search`, dropped before any row, OSV decision or flight wait. The test is real: 4 searches over a 400 KB document (12,000 references, over 256 KiB) parked on a gated list, then a 15,000-entry list (over 256 KiB) must answer 200 in under 25 s (the earlier probe gave 504 after 30 s). Not capped at 100 rows in a way that matters now (the 100-row bound only affects `big_lists_are_decoded_a_few_at_a_time`, which no longer carries the N1 claim). |
| N2 | NOT closed: see M1. |
| N3 | Closed for `serve_search` only: see M2. |
| N4 | Closed as designed, with two residuals (see "N4 answers"). |
| N5 | Fixed (`own_count` derived from `own` in every `forget`; test asserts equality). |
| N6 | Fixed for fingerprint-changing policy (start and end compare in both searches) and for name/version blocks in `serve_search`. Test gap only (L2). |
| N7 | Fixed for searches (`drop(body)` after decode); a body can still wait up to 30 s for a permit (bounded by the 16 search slots). |
| Slices 17-21 | No regression found: the shared transfer path gained only an MD5 update per chunk and Conan arms (`is_conan_small`, `allows_archive_redirect`, `go_archive`); `limits.rs` is a comment; spool use is the shared `owner_of`; readmit untouched. md5 was already a dependency (Cargo.toml unchanged). |

## Findings

M1 - high - correctness of the convergence claim - the N2 measurement leaves the network out; with 2 fetch lanes a ConanCenter search cannot complete
Location: src/conan/serve.rs:54 (`JUDGE_FETCHES = 2`), :805-817 (the lane is held across the whole upstream fetch), :84 (`VERDICT_TTL` 120 s, not renewed), :1280 (`JUDGE_WAIT_MS` 100 s); evidence "N2 measured", tests/conan_judging.rs:267 (`nine_thousand_references_cold_measurement`).
Failure (arithmetic from the code; the latency is the assumption): the measured 565 verdicts/s used `FakeRegistry` (in-process, zero latency) with a local OSV server, so the table measures store, policy and OSV time only. A judged list is fetched in one of at most 2 fetch lanes per registry, each held for the full round trip to the remote. Throughput is therefore at most 2 / latency: 20/s at 100 ms, 40/s at 50 ms (a TLS round trip to a public host is rarely below 50 ms). 9,000 references need 75/s to finish inside one 120 s verdict life (the recheck-2 criterion), i.e. a list round trip of 26 ms or less. Below it, attempt 1 times out at 100 s with about 100 x rate verdicts, a retry reaches the unfinished references with the first verdicts about to expire, and every attempt answers 504: `conan search '*'` on the one public registry never succeeds. Recheck-2 N2 stated "if the measured rate is below 75 per second the feature does not work for ConanCenter and it becomes blocking"; the stored number is not a measurement of that rate.
Correction (any one, then measure): inject a per-list delay of 100 ms in the harness measurement and report the rate; and raise the lanes (for example 4 fetching, with installs still keeping a reserved place per registry), or start the verdict clock at the start of the search that makes it (so one search outlives a long judging), or renew a verdict a search reads. Cost: one constant or a TTL rule plus one delayed-fake measurement test.
Blocking: yes (core outcome of the feature on the public registry; the evidence's rate does not cover it).

M2 - medium - memory - `serve_package_search` still materialises everything N3 asked to avoid
Location: src/conan/serve.rs:1549-1560 (a full `serde_json::Value` of the document kept through judging, `ids`, and `parents: Vec<Parent>` for every id with a cloned recipe), versus the typed `Vec<String>` and 5,000-batch construction in `serve_search`.
Failure (structure CONFIRMED by reading; sizes estimated): the big-decode permit is dropped after the decode (N1 fix), so nothing now bounds how many of these trees live. A package-search document of up to 16 MiB with up to 500,000 package ids keeps its `Value` tree (about 5-10 times its size) plus 500,000 `Parent::Package` values each holding a cloned `Recipe` (about 200 B), roughly 150-300 MB per search for the whole judging time (up to 100 s). The slots allow 16 in the process and 8 per owner: about 2.4-4.8 GB. This is exactly the shape recheck-2 N3 warned about ("if N1 is fixed by releasing the permit early, 16 concurrent searches could hold about 5.6 GB"); the evidence's 317 MiB measurement and "1 GiB for four" bound are for `serve_search` only (and its all-unreadable case, see L1). Reaching it needs a recipe revision that passes policy on a registry whose package search the caller controls (an own registry origin in shared-service mode).
Correction: decode the package search typed (a map of id to a reduced info struct, or keys first and info on demand), build `Parent::Package` per batch from the ids (do not pre-clone the recipe for all of them), and add a cap or a measured test with 100,000 ids. Cost: moving the loop body into the batch and a small struct.
Blocking: yes (cross-tenant memory exhaustion from tenant-controlled input; the N3 closure the previous round required covers one of the two search routes).

## N4 answers (non-blocking residuals)
- Owner identity is `owner_of(...).key` only: in shared-service mode the client address (an unlisted proxy's X-Forwarded-For is ignored, a /64 is one owner), in certificate/managed mode the authenticated account. A junk `Authorization` is NOT part of `.key`, so one caller cannot mint owners by varying the header. Standalone has no owner (no tenants).
- Residual R-A (low-medium, searches only): two addresses (or accounts) each take 2 of a registry's 4 slots; 8 owners take the 16 process slots. An attacker with a few addresses can still 503 searches of a registry (or of all registries) while it holds them (up to 100 s per search). Installs are unaffected (own fetch places). Accepted if recorded; a small per-registry reserve for an owner with no search running would remove it. Behind an unlisted reverse proxy every caller is one owner (2 searches per registry for everybody; the code logs a warning for uploads only).
- Release on every exit: `SearchSlots::drop` decrements both owner counters and the semaphore permits drop with it; `search_slots` undoes its counters on each refusal before returning; the future is dropped on cancel/deadline, unwinding drops it on panic; locks are poison-tolerant. No leak path found.
- Judging share per owner (`JUDGE_PLACES / 2` = 4 of 8) is acquired before the registry place with a 30 s timeout: no cycle (no place is held while waiting for a share).

## Read-only judging: the new risk (answers)
1. A reference listed by search cannot be obtained without the live gate: a download goes `reference_for_file` (recipe gate with exempt false, `resolve`, `refuse_unless_allowed` when the row is new, then `serve_artifact_in` and the shared pipeline, which applies pins and digests). Verdicts are read only by `judge_one` for search; nothing else consults `verdicts` or `flights`.
2. A search verdict cannot release a held revision: it is a listing decision only; a Hold verdict hides, an Allow lists. The cell entries a search writes (`Known` from the remote's own time) are the same value the non-search path computes; the cooldown at download uses them through `refuse_unless_allowed` / the pipeline.
3. First-seen: a revision with no usable remote time is judged through `wanted` and `record`, which commits its row with `first_seen = now` even from a search (so "judging writes no row" is true only for revisions the remote dates; evidence and docs say "no row" without that qualifier: L3). A revision the remote dates is judged from its upstream time and gets its row at its first list or file request; it is never treated as old. Note the one difference: after a search, a later revision list read within the cell's life is served from the table and writes no anchor row (the `held` branch of `list_units`), so the "date only ever gets later" guard of the store starts at the first file request instead of the first list. This weakens only protection against a remote that later reports an EARLIER time; the depositor can back-date at upload anyway (documented residual U1). Low.
4. Pins are not read in a search (digest-blocked revisions can be listed); they are enforced at delivery. Low, listing only.

## Low / notes
L1 - the 317 MiB measurement used references that are all unreadable, so `kept` (a `Vec<(usize, Rref)>` of about 150-200 B each) stayed empty. A search of fast, readable references retains `kept` up to the number judged inside the deadline (a fast attacker-controlled registry could reach hundreds of thousands: tens of MB per search). Keep only the index (`at`) and re-parse on render. Non-blocking.
L2 - no test for the fingerprint re-check (503 `PolicyUnavailable`); mutation S5 covers only the blocklist re-apply. Add one test (managed or shared mode, publish a snapshot mid-search). Package search has no end-of-search name/version re-apply (the fingerprint check covers managed and shared). Non-blocking.
L3 - docs say judging "writes no row"; for undated revisions it does (and then costs the 63/s write path, unmeasured). An own registry that dates nothing makes each search write rows for every reference it names (rate-limited by the 100 s deadline and slots; row bound is per project, not per registry). State it in docs/operations.md. Non-blocking.
L4 - `JUDGE_WAIT_MS` and `PEAK_BIG` are `pub static` in the shipping library (not behind `test-support`). Harmless values, but they are a mutable process knob in the public API; gate with `#[cfg(feature = "test-support")]` accessors if cheap.
L5 - tdd lines for N1/N4/N5/N2/N6/N3 say "red -> green" without the copied failure line the procedure requires; N3 and N6 give none. Evidence-format only.
L6 - `note_upload` evicts by scanning all 65,536 entries per upload once a credential is over 4,096 (about 1 ms under the lock); many distinct accepted credentials can still evict others' entries from `own`. Unchanged low residual from recheck-2 N5.

## Requirement coverage
| Requirement | Connection | Status |
|---|---|---|
| N1 permit for the decode only, real test | fetch_list :828, serve_search, serve_package_search; test conan_judging.rs:220 | MET |
| N2 measured and credible; retry continues from stored verdicts | table in evidence; verdict TTL 120 s | NOT MET (M1: zero-latency fake; retry convergence needs 75/s) |
| N3 typed decode, batches of 5,000, memory bound | serve_search only | NOT MET for package search (M2); MET for serve_search |
| N4 per-owner shares, release on every exit | search_slots / SearchSlots::drop | MET (residual R-A) |
| N5 own/own_count consistent | note_upload forget | MET |
| N6 fingerprint start/end, block re-apply | serve_search, serve_package_search | MET (test gap L2) |
| N7 bodies | drop(body) | MET |
| Read-only judging cannot release or hide dates | list_units judge_only, reference_for_file | MET (note 3) |
| Slices 17-21 and Cargo/test features | diffs read; Cargo.toml unchanged; `test-support` is the pre-existing self dev-dependency | MET (no regression found) |

## Verification and limits
- Run: `cargo test --locked -j 8 --test conan_judging` inside `systemd-run --user --scope -q -p TasksMax=512 -p MemoryMax=16G -- timeout 900`, target dir in the scratch: 9 passed, 0 failed, 2 ignored (the measurements), 20.9 s. (The first, cold build hit the 900 s cap and was rerun; no test was affected.) Not run: Postgres tests, E2E, the ignored measurements (a zero-latency fake cannot answer M1; M2 sizes are estimated, not measured).
- Unchanged during review: yes for src/conan/serve.rs and tests/conan_judging.rs (read once; no edits by this review). Scratch under /home/john/go/src/github.com/postfix/.probation-scratch/recheck3, removed at the end.
- Lenses with no finding: security of the read-only judging path (above), per-credential flights (credentialed reads still share nothing), uploader exemption (hold only), spool/readmit (untouched).

## Next steps
Fix M1 (measure with injected per-list latency; raise lanes or move the verdict clock) and M2 (typed package search, per-batch parents, a measured 100,000-id test); consider L1 with M2. Then a recheck of M1 and M2 only. R-A and L2-L6 may follow in the same round or be recorded as accepted.
