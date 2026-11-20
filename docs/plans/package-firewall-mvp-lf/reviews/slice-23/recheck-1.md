# Slice 23 (Conan 2) fix round: recheck 1 (code review, security lens)
Verdict: FIX FIRST
Procedure: /home/john/.claude/skills/lf-start/agents/code-review/AGENT.md (read-only; scratch probe in a deleted copy).
Inputs read: reviews/slice-23/code-review.md, reviews/slice-23/security-review.md, evidence/slice-23.md ("Fix round"), evidence/tdd-slice-23.md ("Fix round"; note: the tdd file is under evidence/, there is no top-level tdd-slice-23.md), src/conan/serve.rs, src/http/conan_routes.rs, src/artifacts/download.rs (verify_conan_manifest), crates/probation-policy/src/names.rs, src/policy/blocklist.rs, crates/probation-server/tests/ecosystem_tags.rs, the tests named below.
Snapshot: branch slice5-native-ci at 1e1418b plus the uncommitted slice (84 changed/untracked paths).

Checks run (inside `systemd-run --user --scope -p TasksMax=512 -p MemoryMax=16G`, own target dir under .probation-scratch, deleted):
- `cargo test --test conan_registry --test conan_service_read --test conan_service_write`: 36 + 11 + 8 passed, peak RSS of the whole run 614 MB (includes the 400,000-entry list).
- Probe (scratch copy, deleted): a search in shared-service mode, credential-free twice and credentialed once, answers 200 with the right list (the job path works there; no committed test covers it, see R9).
- Not run: Postgres test (ecosystem_tags, needs the compose database), real Conan client tests (no `conan` binary here; native tests skip), E2E.

## Finding status

| ID | Status |
|---|---|
| C23-1 / F2 | Fixed in behavior (700 refs, 600 package ids, unreadable list = error, tests green). New resource and robustness problems: R2, R3, R4, R5. |
| F1 | Fixed (batches of 1,000, unit table never cleared, 400k test green). Residual: R5 (parse memory times 16). |
| F2 places | Fixed, no deadlock found: acquisition order is always credential, registry, global; no caller holds a place while taking another set (probe, fetch_list, serve_files, search, auth each take and release one). Test `one_credential_cannot_hold_all_...` green. Residual: R6. |
| C23-2 | Fixed (`files_of_one_revision_cost_one_list_per_freshness_window` green). |
| C23-3 | Fixed for the stated cooldown case; rule is not exactly the stated rule: R1. |
| C23-4 | Fixed (test green). |
| C23-5 / F3 | Decision acceptable (see "Policy identity"). |
| C23-6 | Fixed (dead state removed). |
| F4 | Fixed; allow-list not verifiable against a real client here: U-1. |
| F5 / F6 | Fixed (tests green). |
| F7 | Fixed with one gap: R8. |
| U1 / U2 | Fixed (tests green; `EARLIEST` applies to lists and `Last-Modified`; lower-case name in policy, blocklist and rows). |
| Hardening (firewall key on PUT) | Fixed: `a_firewall_key_is_refused_as_an_upload_credential` green; the refusal happens before admission, spool and any upstream call. |
| C23-7 / C23-8 | Fixed. `swift` is a tag no family will use; the DB test drops the ecosystem CHECK only inside `Db::fresh()`, which creates its own uniquely named database (tests/common/mod.rs:95-120), so no shared state is touched. Not executed here (needs Postgres). |
| Slices 17-21, shared spool | No regression found in the diff areas read (upload spool use in forward_write is the shared one, `owner_of`); the Conan tests and the shared download path compile and pass. Full suites of earlier slices were not rerun. |

## Findings

R1 — medium — security (documented rule not implemented) — the uploader's list exemption skips OSV
Location: src/conan/serve.rs:817-819 (`list_units`), contrast :538 (`refuse_unless_allowed`).
Rule: evidence/slice-23.md C23-3: "exempt from the COOLDOWN, not from a block or an OSV verdict".
Failure: in `list_units`, `if credentialed && !blocked && uploaded_by_caller(...) { return Decision::Allow; }` returns before `evaluate_scoped` runs. `blocked` is only a name or version block (`blocked_outright`). A revision whose name/version OSV flags (or any other non-cooldown denial) is therefore listed and returned as `latest` to its uploader, while `refuse_unless_allowed` (file list, recipe gate, binary search) refuses the same unit for OSV. The two code paths disagree, and the revision list is the one that feeds `latest` and `keep`. Impact is bounded (own credential, own upload, downloads stay gated), so it is a promise and consistency defect, not a leak to others.
Test gap: `the_depositors_own_lists_...` covers the cooldown only; no test with an OSV hit or a digest block.
Correction: evaluate normally and apply the exemption only when the decision is not one of BlockedPackage, BlockedVersion, BlockedByOsv, BlockedDigest (one shared helper used by both sites); add an OSV-flagged-upload test. Cost: one OSV evaluation per exempt unit (already done for everyone else).
Blocking: no (bounded to the uploader; fix with R2 round).

R2 — high — resource bound (judging jobs) — the background job has no bound, no real dedup, no cancellation
Location: src/conan/serve.rs:1128-1190 (`judge_parents`), :1092 (`judge_all`), :1112 (`put_verdict`).
Failure scenarios (CONFIRMED by source; not load-tested):
1. Dedup key is `digest(all missing verdict keys)` (:1146). Any change in the missing set gives a new job: another pattern (`q=a*`, `q=*`), a retry after the first 504 (by then the earlier verdicts, TTL 20 s, are partly expired, so the set differs), or a different tenant. Each spawns its own full `tokio::spawn` that re-reads every list. A client that gets 504 and retries every few seconds starts one more full job per retry; all of them share the registry's four places, so each runs slower and none finishes inside the 20 s verdict life: positive feedback, no ceiling.
2. Each job owns `work: Vec<(usize, Parent)>` plus a clone of all keys (up to 500,000 entries, tens of MB), alive until the job ends. Nothing caps concurrent jobs per registry, per tenant or per process, and nothing cancels a job when its requests are gone or the registry/policy changed. With a tenant-chosen registry origin (private registries are tenant data), a tenant can fill process memory and keep its registry's places saturated for hours (500,000 lists at 4 in flight).
3. Fairness: the job takes places as a credential-free caller, so the per-credential share (2 of 4) does not apply; interactive installs of the same registry queue FIFO behind up to 12 waiting job fetches, and a place wait over `REFRESH_WAIT` (30 s) makes them fail with 504.
Correction (smallest adequate): one job per (registry, origin, policy fingerprint) rather than per missing-set (later requests join or wait for it and read verdicts), a cap on jobs in flight (process and per registry; over it answer 503 with Retry-After), give the job a deadline and drop it when no request has waited for it for a while, and judge with at most the registry's place count in flight. Cost: a small job registry and a join path.
Blocking: yes (unbounded memory and place use reachable by a tenant; same class as the Medium F1/F2 resource findings that blocked this slice).

R3 — medium — correctness under pressure — a finished job's answer is read back from the shared table and can be lost
Location: src/conan/serve.rs:1112-1121, :1175-1185.
Failure: the waiting request reads its verdicts from `verdicts` after the job ends. `put_verdict` calls `verdicts.clear()` when the table is full of unexpired entries. Two concurrent large searches (different registries or policies, 300,000+ entries each; the table holds 600,000 for the whole process) clear each other's verdicts; the finished job's request then finds `None` and answers 502 although its work was done, and the retry re-reads everything. Also `VERDICT_TTL` is 20 s in code (:62) while evidence/slice-23.md C23-1 and the spec text say 120 s ("a held reference ages in within two minutes"); the user-visible convergence the evidence describes (a retry finds the verdicts) holds for 20 s, not two minutes.
Correction: hand the job's verdicts to its waiters through the `watch` channel (or an `Arc` result) instead of re-reading the shared table; evict oldest instead of `clear()`; make evidence and code agree on the TTL. Cost: small.
Blocking: no with R2's fix; plausible only for very large concurrent searches.

R4 — medium — availability/parity — one unreadable list fails every search of the registry
Location: src/conan/serve.rs:1092-1110 (`try_for_each` stops at the first error), :1186-1189.
Failure: a reference named by `search` whose revision list is a 404 (deleted between the two calls), invalid (`read_revisions` strict), or times out for a place wait makes the whole job fail; every later search that includes that reference fails with 502/504 until the remote changes. On a registry that accepts uploads, a depositor who writes a malformed list directly to the remote (the firewall cannot stop that) takes `q=*` away from everyone. Leaving the unreadable reference out of the result is fail-closed and cheaper than failing the search; the evidence states "no 200 is ever shorter than the truth", which is the product choice, but it turns one bad entry into a registry-wide outage. Needs a decision recorded with its consequence, or per-reference isolation (omit and log, plus a response header or warning count).
Blocking: no (documented decision; recommend revisiting).

R5 — medium (plausible) — memory of 16 parallel list parses is outside the fetch places
Location: src/conan/serve.rs:1092 (`buffer_unordered(JUDGE_PARALLEL = 16)`), :714-733 (`fetch_list` releases the place before `read_revisions` and `list_units` decode and judge).
Failure: a list may be up to 16 MiB; `read_revisions` builds a full `serde_json::Value` then `Vec<Rev>` (several times the body size), and `list_units` adds `known` and decisions. 16 such lists decode concurrently per job, per search, regardless of the four places. With a tenant-controlled origin this is a multiple-GB transient per search, more with R2. The 400k test measures one list only (whole run peak 614 MB).
Correction: bound concurrent decode with a process semaphore (or hold the place through decode), and parse lists without the intermediate `Value`. Counted with R2 for blocking purposes.

R6 — low — uploader memory (own table) policy
Location: src/conan/serve.rs:249-262.
Failure: when 65,536 unexpired entries exist, `own.clear()` forgets everyone's exemption; any depositor with write access can PUT 65,536 distinct revisions (each 2xx notes the unit, a package file notes two) and make every other depositor meet 403 on its upload existence checks until its next upload; there is no per-credential bound. Restart and multi-instance behavior: memory only; a second instance behind a balancer does not see the upload, and a restart forgets it, so an upload through instance A followed by an existence check on B or after a restart gets the 403 hold. Restart is documented, multi-instance is not.
Correction: evict oldest, cap per credential digest, and document the multi-instance limit (or note the sticky-routing requirement).
Blocking: no.

R7 — low — F7 gap
Location: src/artifacts/download.rs:784-786.
Failure: the manifest path is built with `url.path().strip_suffix(file)`; the URL path is percent-encoded while `file` is the raw name, so a file whose name needs encoding (a space, now a legal name by C23-4) never matches and the manifest check is skipped silently. Fail-open only for corruption detection (the manifest is no trust anchor). A manifest answered 403 is also no check (by design).
Correction: compare against the encoded form or build the manifest URL from the unit's own coordinates. Test: a spaced file with a wrong MD5 in the manifest.
Blocking: no.

R8 — low — test and doc gaps
- No committed test runs a search in shared-service mode, the mode the product sells (the probe above shows it works). The background job runs without the request task-local, so `cache_token` is None there; correct today, but untested (src/conan/serve.rs:1128, src/http/credential_read.rs:40).
- Nothing tests a policy publication landing mid-job. Reasoned: the verdict key includes the principal's policy fingerprint and the job judges with the same principal's policy; `selected` (conan_routes.rs:132) re-checks fingerprint before answering, so FIX-16-A holds for the service path. Standalone (no principal) reads the live policy, but the key then belongs to the old fingerprint and nobody reads it afterwards. OSV changes show within 20 s for lists; file downloads are gated live.
- Stale anchor dates: lists use stored dates only when the remote does not say later (`list_units` :757-769); correct.

## Judgments requested

(a) Uploader exemption. Credential identity: SHA-256 (first 16 bytes) of the whole Authorization value, combined with registry id and unit key; only digests are stored, never the secret. It does not reach other principals (another credential string misses the key), other registries (id in key), shared caches (credentialed reads use a fresh cell and the raw/verdict tables are credential-free only), file downloads (`exempt` false at :1010 and :1018, gate unchanged), the `latest` others see (decisions are per request), or other revisions (unit key includes name, version, user, channel, rrev, pkgid, prev). A forged 2xx is not possible from the client side: the status is the remote's own answer to the forwarded PUT and is only noted when it is 2xx. A remote that accepts anonymous PUTs gives any junk credential a 2xx, but that credential then only unlocks lists for units it just wrote to. A shared bot credential is exempt for all of its users, which equals its upstream identity. The rule is the minimal safe one after R1 is fixed (exempt only cooldown denials); a package PUT also exempts its recipe revision, which is needed for the client's own list check and matches the writer's rights. A safer variant would also bind the memory to the firewall principal, which costs a field and gains little.

(f) Policy identity for exceptions: acceptable as the narrowest rule the shared model allows (block names package and version for every user/channel, fail closed; an exception releases the version for all users/channels of that registry). The documented consequence for open-upload remotes is stated; the model field for a scoped exception is correctly listed as a spec change. No objection.

(e) F4 allow-list vs a real client: could not verify here (no `conan`). Entries keep `settings`, `options`, `requires`, `recipe_hash`, `content` and drop a whole key if any nested string contains `://`; Conan 2 `info` may carry additional members (for example `python_requires`) and an option value that is a URL drops that whole key. Only `conan list`/search display is affected, not installs. Needs a check against a real `conan list pkg/ver:*` output; U-1.

U-1 (uncertainty): what the real client prints for binary search members beyond the five kept; deciding check is the native test on a machine with Conan 2.
U-2 (uncertainty): the Postgres test and the E2E publishing scenario were not run in this recheck.

## Verification and limits
Reviewed paths: src/conan/serve.rs (all), src/conan/coords.rs (name/limits), src/http/conan_routes.rs, src/artifacts/download.rs (manifest check), crates/probation-policy/src/names.rs, src/policy/blocklist.rs (diff), the tests listed above. Unchanged during review: yes (read-only; the probe lived in a deleted copy under .probation-scratch, which now holds no recheck23 files).

## Next steps
Fix R2 (and R5 with it) and R1; add the tests named in R1, R2 (second distinct search or retry must not start a second job; jobs in flight are capped) and R7; decide R3/R4 and correct the 120 s claim. Then a further recheck of R1, R2, R5 only.
