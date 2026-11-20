# Slice 23 (Conan 2) fix round: recheck 2 (code review, security lens)
Verdict: FIX FIRST
Procedure: /home/john/.claude/skills/lf-start/agents/code-review/AGENT.md (read-only; one probe test in a scratch copy, deleted).
Inputs read: reviews/slice-23/recheck-1.md (R1-R8), evidence/slice-23.md ("Recheck-1 round"), evidence/tdd-slice-23.md ("Recheck-1 round"), src/conan/serve.rs (all), src/http/conan_routes.rs, src/http/credential_read.rs (cache_token), src/artifacts/download.rs (verify_conan_manifest, md5, small-file classes), tests/conan_judging.rs.
Snapshot: branch slice5-native-ci at 1e1418b plus the uncommitted slice. sha256 src/conan/serve.rs f4a34d48..., conan_routes.rs 766fa949..., download.rs 9bc56109... (equal to the evidence's restore hashes; unchanged during review).

## Recheck-1 status
| ID | Status |
|---|---|
| R1 | Fixed: `cooldown_only` (Decision::Hold only; Hold comes from the cooldown alone, `freeze_from` is the cooldown) used in `list_units` (serve.rs:883) and `refuse_unless_allowed` (:585); unit test green by reading. |
| R2 | Mostly fixed: no spawn, no background job, verdict flights with correct cancel/failure semantics (see "Checked, no defect"). Two new problems in the redesign: N1 (blocking) and N2, N3. |
| R3 | Fixed: the request uses its own results; eviction is expired first, then oldest tenth. TTL 120 s in code and docs. Residual: the stated "two minutes" is up to about 220 s (verdict clock starts when the flight ends, not when the list was read): low, noted only. |
| R4 | Fixed as decided (404/malformed list withheld and counted; other failures fail). Header is a `usize` through `HeaderValue::from`: no injection. Leak: the count only. |
| R5 | Partly: typed decode and the 4 permits exist, but the permit is held far too long (N1). |
| R6 | Fixed for the stated bound; one residual: N5 (low). |
| R7 | Fixed (sibling URL by popping the last segment, `conanmanifest.txt` pushed). |
| R8 | Shared-service search and mid-search block committed. Gap: the mid-search test covers a name block only (N6, low). |
| Slices 17-21 | No regression found: the shared transfer path only gained an MD5 update per chunk, `is_conan_small` / `allows_archive_redirect` arms for Ecosystem::Conan only, `Call::Conan`; spool use is the shared `owner_of`. Full earlier suites not rerun. |

## Findings

N1 - high - resource bound / availability (cross-tenant) - a big-decode permit is held for the whole judging, not the decode
Location: src/conan/serve.rs:1318 (`let _big = ...` in `serve_search`), :1378 (`serve_package_search`), :785-786 (`fetch_list` returns the permit; `list_units` :803 `_big` keeps it through row gates, DB commits and every OSV decision), :792-796 (`big_permit`, 30 s wait), constants :59-60.
Failure (CONFIRMED by a probe test in a scratch copy, then deleted): four searches whose search document is over 256 KiB (a 300 KiB document with one real reference; the attacker needs only a registry origin of its own, or any registry whose search result is that large) each take one of the four process-wide permits at :1318 and keep it until the search ends (up to 100 s, `JUDGE_WAIT_MS`). While their judging is slow (a tarpit list, or just a registry with many references), any other request that needs a big decode waits for a permit. Probe result: 4 such searches judging, then `GET /conan/v2/conans/big0/1.0/_/_/revisions` for a 15,000-entry list (over 256 KiB) answered **504 after 30.003 s**; the searches answered 200 after release. The same happens to the searches' own big lists (a search holds a permit and its makers need a second one: four concurrent big searches starve each other), and the judging place (:1218) is held while the maker waits for the permit. The same permit is also held through `record` in `list_units` (the test's own red line says 15,000 entries take about 15 s to record), so twelve big lists "decoded 4 at a time" take 45 s of permit time, longer than the 30 s wait: the committed test `big_lists_are_decoded_a_few_at_a_time` passes only because the harness bounds the project's rows to 100 (`max_references_per_project`), which removes the long hold it is meant to cover.
Scope: process-wide, no per-registry or per-owner share, so one hostile or just large registry (service mode: the registry id is the only credential on reads) takes every big decode away from all others for up to 100 s at a time and can repeat.
Correction: hold the permit only while decoding (drop it before `record`/decisions in `list_units`, and drop it in `serve_search`/`serve_package_search` as soon as `refs` is built); bound the retained entries separately (see N3). Add a test where 4 big-document searches are gated and a big list is still served. Cost: moving two guards plus one test; the memory bound of a decode stays what the permit gives.
Blocking: yes (cross-tenant denial reachable from tenant-controlled input; the redesign's own bound is the cause).

N2 - medium - correctness of the convergence claim - a large search never completes on the public registry
Location: src/conan/serve.rs:54 (`JUDGE_PLACES = 2`), :84 (`VERDICT_TTL` 120 s, not renewed), :1158 (100 s), :1286-1293.
Failure (arithmetic; the latency is the assumption): a verdict needs one list read plus several database round trips. The evidence's own largest real document (`search?q=*` on ConanCenter, 222 KB) holds roughly 9,000 references. With two lists judged at once the steady state keeps at most (2 / latency) x 120 s verdicts alive; to complete, one pass needs 9,000 / 120 s = 75 verdicts per second, that is 27 ms per reference end to end with two in flight. Any realistic round trip to a public host is above that, so every attempt answers 504 after 100 s, the earlier verdicts expire before the next attempt reaches them, and each attempt costs two judging places and four search slots (see N4). `conan search '*'` on the one public registry would then never succeed. The recheck-1 text "a search too large for one request converges within the time" holds only for searches that fit about 120 s of judging.
Correction: decide and record: either renew a verdict when a search reads it (not "never renewed"), or keep verdicts for the whole of one search plus a margin (for instance TTL measured from the start of the search that made it, longer for credential-free reads), or raise the places for credential-free judging; and measure the real rate with a registry of 10,000 references. Cost: a TTL or renewal rule; the freshness promise ("a hold that ends shows within two minutes") needs restating.
Blocking: no (needs a measurement and a recorded decision; if the measured rate is below 75 per second the feature does not work for ConanCenter and it becomes blocking).

N3 - medium - memory (plausible, bounded today only by N1) - one search retains about 350 MB at 500,000 entries
Location: src/conan/serve.rs:1319-1342.
Estimate: the `Value` tree (about 36 MB), `refs` (`String` + `Rref`, about 250 B each), `parents` (a second `Rref` per entry, about 200 B), `seen` (about 60 B), `kept`, the `json!` copy and the body: about 600-700 B per entry, 300-350 MB for 500,000 entries (the cap `MAX_ENTRIES`; a 16 MiB document holds that many short references). Today at most 4 big searches coexist (they hold the 4 permits, see N1), about 1.4 GB; small documents (under 256 KiB, about 18,000 entries) are negligible. If N1 is fixed by releasing the permit early, 16 concurrent searches could hold about 5.6 GB, because nothing else bounds `refs`/`parents`. Not measured: the 400,000-entry test measures one revision list, not a search.
Correction: when fixing N1, cap the references a search judges (say 20,000, the rest answered 413 or truncated with the withheld header), or stream parents rather than materialising `parents` next to `refs` (build `Parent` on demand from `refs`), and add a measured test with 100,000 entries. Cost: a cap constant and a test.
Blocking: no, but it must be closed together with N1 (a fix of N1 alone moves the memory risk).

N4 - medium - fairness - one caller can hold all of a registry's search slots, and a tenant-chosen registry set can hold all 16
Location: src/conan/serve.rs:1276-1277 (`try_acquire` of the process and registry slots), :56-57, :1218 (judging places per registry).
Failure: on a shared service a read needs no credential of its own (the registry id selects the registry), and no slot is owned by anyone: four concurrent searches by one caller on the public registry, or on a registry the caller depositor controls (origin of its own, slow lists up to the 100 s deadline), take all four registry slots, so every other caller's search of that registry answers 503; four registries of one owner take all 16 process slots and 503 every other registry's searches. Credentialed (junk `Authorization`) searches never share flights, so such a caller also keeps the registry's two judging places busy for 100 s, and the registry's credential-free searches then fail by the 30 s place wait (504). No per-owner or per-principal share exists (the spool already has `owner_of(app, principal, headers)`; searches do not use it). Not checked: whether the number of registries per owner is capped.
Correction: a share per owner (or per credential digest and per registry) of the slots, for instance 1 of the registry's 4 and 4 of the 16, and a separate judging place count for credentialed searches. Cost: a small table like `per_credential`.
Blocking: no (searches only; installs keep their own fetch places, and the probe-free reasoning shows `judging_leaves_fetch_places_for_installs` holds), but it should be fixed with N1 since both are tenant-reachable denials.

N5 - low - uploader memory: stale queue entries
Location: src/conan/serve.rs:270-301.
Failure: when `own` evicts its oldest tenth or expires entries, the per-credential queues in `own_by_credential` keep the evicted keys; `by.retain(!is_empty)` removes no stale queue. Each credential holds up to 4,096 keys (16 B) and up to 65,536 credentials are kept before `by.clear()`: a theoretical ceiling of 4.3 GB, practically unreachable (needs about 268 million 2xx PUTs) but there is no relation between the two tables. Many distinct credentials (a remote that accepts any `Authorization`) can also evict other depositors' entries from `own` (the per-credential bound does not protect against many credentials).
Correction: derive the queue from `own` (or drop queue keys that `own` no longer holds when evicting). Cost: small.
Blocking: no.

N6 - low - FIX-16-A coverage
Location: src/conan/serve.rs:1339-1341, tests/conan_judging.rs:164-182.
Failure: the final re-check re-applies only a name or version block (`blocked_outright`). A policy published mid-search that tightens the cooldown, adds an OSV rule or a digest block is not applied to the answer in standalone and certificate-managed mode (`legacy` has no fingerprint re-check; in shared-service mode `selected` :134-144 refuses a changed fingerprint, so FIX-16-A holds there). Impact: the listing may name a reference for up to the search's length (100 s) after a stricter policy; every download is gated live. The test covers the name block only.
Correction: compare `check_policy(...).0.policy.fingerprint` with the one the keys were made under at the end of `serve_search` and answer 503/retry when it changed (the same rule as `selected`); add a cooldown-change test. Cost: three lines.
Blocking: no.

N7 - low - body held while a permit is awaited
Location: src/conan/serve.rs:785 (`fetch_list` holds `body`, up to 16 MiB, while waiting up to 30 s for a big permit), :1318 (search document the same).
Failure: bodies waiting for a permit are not counted in any bound; with N1 the waiters pile up to the number of active requests. Fixed by N1 mostly; mention only.
Blocking: no.

## Checked, no defect (the points the packet asked about)
- Flight safety (`judge_one` :1237-1268): a verdict is sent only after a successful `compute_verdict` and after `put_verdict`; a failed or dropped maker drops `_flight` (removes the map entry) before `sender` (declared earlier, dropped later), so waiters get `Err` from `wait_for` and re-enter the loop as makers, never hang and never see a partial or failed verdict; a waiter that arrives between the two drops finds no entry and becomes the maker; a verdict already sent is returned even if the sender is gone (`wait_for` tests the current value first); no spin (the entry is always removed before the sender closes). Panic: `Flight::drop` uses the poison-tolerant `lock`; a panic in a maker only fails that request and the next waiter retries (a repeated panic is repeated per waiter, bounded by the search caps). A maker's error is not shared (each waiter retries, serially, within the 100 s deadline).
- Deadlock between the caps: search slots are `try_acquire` (never wait); judging place (30 s) is taken before fetch places and no fetch place is held while waiting for a judging place; fetch places are always credential, registry, global; the big permit is acquired after the fetch places are released; `row_gate` holders wait on nothing that needs a place. The only wait cycle left is N1 (bounded by 30 s timeouts, so a stall, not a deadlock).
- C1028: a credentialed read has `cache_token` None, so `key` is None, `judge_one` calls `compute_verdict` directly: no flight, no verdict, no raw list, a fresh `Cell` (`cell_for` :183); `shared_raw`/`remember_raw` also check the token. Rows (identity, first seen, pins) are still committed as for any read: unchanged from before.
- Cross-tenant sharing of verdicts: key = registry id, origin, policy fingerprint, parent key; credential-free only; the uploader exemption is applied only when `credentialed`, so a shared verdict never carries it. A waiter's verdict is the maker's, computed for the same registry, origin and fingerprint.
- Uploader exemption: Hold only, per credential digest, registry and unit key, bounded 4,096 per credential and 65,536 in all; downloads (`exempt` false) unchanged; no cross-credential effect.
- `x-probation-withheld`: a decimal count only, set only when more than zero; carries no name or URL.
- FIX-16-A in shared-service mode: `selected` re-checks the principal's fingerprint, origin, trust, CIDRs, archive origin and read authorization after the answer (a changed policy is a refusal).
- Verdict table memory: 600,000 entries at about 70 B (about 45 MB); eviction sorts 600,000 keys under the lock only when full (about 100 ms stall, then 60,000 free inserts).

## Requirement coverage (recheck-1 promises)
| Requirement | Connection | Status |
|---|---|---|
| R1 hold-only exemption | serve.rs:305, 585, 883 | MET |
| R2 no job, bounded, deduplicated, cancel-safe | judge_one, judge_parents | MET for bounds on searches and flights; NOT MET for the cross-tenant bound (N1, N4) |
| R3 verdict table and TTL | put_verdict, VERDICT_TTL | MET |
| R4 withheld header | serve.rs:1226-1230, 1340; conan_routes.rs:34-36 | MET |
| R5 typed decode, 4 decodes | read_revisions, big_permit | NOT MET in effect (permit held too long, N1) |
| R6 bounded uploads | note_upload | MET (N5 low) |
| R7 manifest sibling | download.rs:783-787 | MET |
| R8 tests | tests/conan_judging.rs, conan_service_read.rs:364 | MET with gaps (N1 test hides the hold, N6) |

## Verification and limits
- Run: one probe test (tests/probe_conan.rs, a copy of the conan_judging harness) in a scratch copy under /home/john/go/src/github.com/postfix/.probation-scratch/recheck2, inside `systemd-run --user --scope -q -p TasksMax=512 -p MemoryMax=16G -- timeout 900 cargo test --test probe_conan`: 1 passed, printing `PROBE install big list: status 504 after 30.003s` (N1). Scratch removed (`podman unshare rm -rf`; the copy had picked up root-mapped files of an old repo `.scratch`).
- Not rerun: the full conan suites, Postgres tests, E2E (the evidence reports them green; this round did not change them), memory of a 500,000-entry search (estimated, N3).
- Evidence: tdd lines exist for every changed behavior (recheck-1 round; two "red not observed" are stated, not blocking). The red line of the big-list test records the 15 s per 15,000 entries and the harness change that hides it (N1).
- Reviewed: src/conan/serve.rs, src/http/conan_routes.rs, src/http/credential_read.rs, src/artifacts/download.rs (diff), tests/conan_judging.rs. Not reviewed: coords.rs again, docs, E2E scripts.

## Next steps
Fix N1 (permit scope) with N3 (entry cap or no double materialisation) and N4 (per-owner share), add the three tests (4 big-document searches gated while a big list is served; a 100,000-entry search measured; one caller cannot take all slots); decide N2 after measuring; N5-N7 with the same round. Then a recheck of N1-N4 only.
