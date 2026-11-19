# Code review: slice 17 (RubyGems)

Verdict: FIX FIRST
Scope: uncommitted working tree on branch slice5-native-ci, base/HEAD e3226bf (53 changed or untracked paths). Requirements: 04-slices.md row 17, 03-program-design.md (LS-F13, LS-F7, LS-F12, LS-F6, LS-F3, C1027, C1028, lines 313/329/333/363), evidence/slice-17.md, tdd-slice-17.md, rubygems-corpus.md. Read-only review; no source modified.
Summary: Blocking: F1 (tuple index does not judge age/OSV; in shared-service mode it judges no gem at all), F2 (E2E-rubygems not built, a named row verification), F3 (LS-F7 trailing-bytes rule not enforced for zlib quick gemspecs). Non-blocking: F4-F10. Uncertainties U1-U4.

Subject fingerprints (sha256 prefix): src/rubygems/serve.rs 13f83c8c, marshal.rs f095f255, inflate.rs c8e560e4, info.rs 1abf39fd, src/http/rubygems_routes.rs 81bcd000. Git status unchanged at start and end of review (53 entries).

## Findings

F1 — high — spec/correctness — Legacy tuple indexes list young and OSV-flagged versions; in shared-service mode no gem is age-judged at all
Location: src/rubygems/serve.rs:461-503 (`serve_index`), src/store/mod.rs:1108 (`persist_metadata`), src/rubygems/serve.rs:207-212
Requirement: 03 line 333 "Global indexes may contain missing-date candidates: only committed first-seen or matching authoritative publication data can grant age eligibility; no cache-age/build-time substitute. Batch persistence by actual project"; line 313 "Filter compact/full/quick metadata consistently"; line 363 "eligible older choice where the client supports a range".
Failure: (a) For any gem without a stored compact index, `serve_index` judges the tuple with `PublicationTime::Upstream(0)` (epoch), i.e. a substitute date that grants age eligibility to every unindexed version, and it never queries OSV for them. (b) Worse, in shared-service mode (`app.service_policy().is_some()`) `refresh` commits with `commit_request_references_in` (`persist_metadata: false`), so `load_project` (serve.rs:467) returns None for every gem, `judged` stays empty, and every tuple of every gem is judged by blocks only. Result: `gem install foo` resolves from `latest_specs.4.8.gz`, picks the young latest version, and its quick gemspec then answers 404 (serve.rs:379-381), so the install fails instead of falling back to the eligible older version. This is the sold (PAAS) path.
Evidence: code trace as above. The only test of the index (`specs_index_is_filtered_by_blocks_and_by_what_the_instance_has_indexed`) runs in standalone mode with the compact index warmed first; `native_gem_install_resolves_only_what_the_firewall_lists` warms `/info/demo` before installing (tests/rubygems_native.rs:131-133), which hides the gap. No test runs `specs.4.8.gz` through `/registry/rubygems/{id}/` or `/rubygems/` in service mode. The implementer reported (a) as "known gap 1"; (b) is not reported and is wider.
Correction: Implement the batch first-seen store for tuples (spec literal: per-project batched persistence, tuple eligible only after committed first-seen plus cooldown), or a dated bulk source that is authoritative; persist first-seen for index tuples in service mode (references are persisted even when payload is not, so the first-seen path exists). Remove the `Upstream(0)` substitute. Closure: a service-mode test where `latest_specs` offers a young latest of a never-indexed gem and `gem install` (native) installs the older eligible version without a prior `/info` call.
Blocking: yes (core client outcome of a required family; the spec text forbids the substitute).

F2 — high — missing deliverable — E2E-rubygems not built
Location: tests/e2e/ (no RubyGems scenario, fake or client image); row 17 verification `node tests/e2e/harness/run.mjs --only E2E-rubygems`
Requirement: 04-slices.md row 17 Verification and Environment columns; 03 line 363 (native allowed/blocked/pin/cold-warm-restart lanes).
Failure: a named acceptance command does not exist; the containerised native lane, restart behaviour and origin traces are unproved. Host-level native tests (`rubygems_native.rs`) are good evidence but do not replace it (the implementer says so).
Evidence: `ls tests/e2e/scenarios`; evidence/slice-17.md gap 2.
Correction: build the scenario (RubyGems fake, Ruby/Bundler client image) in its own capped run. Closure: the row command passes.
Blocking: yes (row verification command).

F3 — medium — spec/security — zlib trailing bytes are not refused (quick gemspec)
Location: src/rubygems/inflate.rs:30-43
Requirement: LS-F7 (03 line 278) "trailing bytes after the last member are refused".
Failure: `flate2::read::ZlibDecoder::new(&[u8])` wraps the slice in a 32 KiB BufReader, so `reader.get_ref().is_empty()` is true after the first fill and garbage after the zlib stream is accepted; `serve_quick_gemspec` then serves the ORIGINAL bytes, trailing data included, to the client.
Evidence: reproduced in a scratch crate on disk (flate2 1.1.10): `ZlibEncoder` output plus 16 trailing bytes, decoded to end: `remaining_in_inner=0` (the bytes were swallowed into the BufReader). The gzip branch uses `bufread::MultiGzDecoder` over the slice and is exact (tested at rubygems_marshal.rs:454). No test appends bytes to a zlib stream; `gzip_ratio_and_size_cap_refuse_bomb` only checks a 5-byte malformed zlib.
Correction: use `flate2::bufread::ZlibDecoder::new(input)` (exact slice accounting) or compare `total_in()` with `input.len()`; add a zlib trailing-bytes assertion. Closure: that test fails before the change, passes after.
Blocking: yes (explicit LS-F7 rule on a trust boundary; the fix is a few lines).

F4 — medium — parity — Fully refused RubyGems listing writes no managed decision
Location: src/rubygems/serve.rs:233-265 (no `managed.record_decision`); compare src/pypi/mod.rs:127,139.
Requirement: parity with delivered families (project rule: full parity). Not a literal row-17 sentence.
Failure: in managed mode an `/info/{gem}` whose lines are all refused leaves no activity record, unlike npm/PyPI. Gem file refusals are recorded through the generic artifact path (src/artifacts/mod.rs:306).
Correction: record the verdict when every entry is refused, as PyPI's `refused_listing`. Closure: a managed-mode test asserting one decision record.
Blocking: no (reported by the implementer; needs scheduling, not a decision).

F5 — medium — parity — RubyGems missing from portal forms and client-setup surfaces
Location: crates/probation-server/templates/policy.html:72,114 (block and exception ecosystem `<select>` list only npm and pypi); policy.html:28 ("applies to both npm and PyPI"); templates/keys.html:23 and src/portal/certificates.rs:502-611 (only npm/pypi client setup); docs/api.md:443, docs/management-server.md:225, docs/operations.md:754, docs/portal-guide.md:693 (list of upstream-URL keys omits `rubygems_upstream_url`); tests/managed_sync.rs:575 (http-origin rejection tested for npm/pypi only).
Requirement: row 17 "portal mappings"; project rule full parity.
Failure: the server accepts `rubygems` (portal/policy.rs `ecosystem()` text, registries.rs), but an operator cannot choose RubyGems when adding a block or exception in the UI (import file only); key and certificate bundles give no RubyGems client configuration.
Correction: add the option and the stale wording; add gem-source snippets if the row 17 owner agrees they belong to this row (otherwise record against the later client-config slice).
Blocking: no for the options and docs; the setup snippets are UNKNOWN as to owner row.

F6 — medium — operations — Tuple index is re-fetched, re-inflated, re-filtered per request, and judges every known gem sequentially
Location: src/rubygems/serve.rs:462-485
Failure: each request fetches up to 6.4 MB, inflates 26 MB, parses 7.4M nodes (measured 0.93 s, 283 MB peak RSS, rubygems-corpus.md) and, before that, loads every known project from the database one by one and runs `evaluate_scoped` (which may call OSV) for every entry of every known gem, with no result cache and no bound on concurrent index requests beyond the generic admission permit. Ten concurrent `gem` clients is about 3 GB.
Evidence: code read and the recorded corpus numbers; not load-tested.
Correction: cache the filtered output per (registry, file, policy fingerprint, upstream validators) with a short TTL; bound index requests with a semaphore. Closure: a test that two requests cause one upstream fetch and one filter pass.
Blocking: no (PLAUSIBLE impact; needs a workload number).

F7 — low — test quality — C1028 info-cache assertion is vacuous in service mode
Location: tests/credential_bearing_reads.rs:~300-330
Failure: `current_project` never caches in service mode (serve.rs:89-91), so `projects.get(&key).is_none()` holds for every carrier even if the credential classification were broken; the "control" asserts nothing positive for the info path. The gem-file part has a real positive control (`content` store grows for an allow-listed read), and the pure classification test guards the allow-list. The doc comment of `credential_bearing_read_never_enters_shared_caches_rubygems` names the wrong file (rubygems_registry.rs, the test is in rubygems_native.rs).
Correction: add a standalone-mode variant where the project cache is populated for an allow-listed read and empty for a credential-bearing one.
Blocking: no.

F8 — low — test portability — Native tests hard-fail without Ruby and a fixed Bundler path
Location: tests/rubygems_native.rs:124 (`/usr/lib/ruby/gems/3.3.0/gems/bundler-2.5.22/exe/bundle`), `.expect("ruby 3.x ...")` here and in tests/rubygems_registry.rs:233,268.
Failure: `cargo test --workspace` fails on any host without that exact Ruby/Bundler layout; no skip or feature gate. Passed here (Ruby 3.3 present).
Correction: resolve Bundler via `ruby -S bundle` or gate on an env var / `which ruby`, with a loud skip.
Blocking: no.

F9 — low — correctness — `Gem::Version` equality differs from Ruby in two edge cases
Location: crates/probation-policy/src/names.rs:82-125
Failure: all `-` should become `.pre.` (Ruby `gsub`), the code replaces only the first; segment letters are lowercased, Ruby compares case-sensitively (`1.0.RC1` is not equal to `1.0.rc1` in Ruby). Only affects operator-written block versions with such spellings; real index versions contain neither.
Correction: mirror Ruby exactly, add two cases. Blocking: no.

F10 — low — spec fidelity — `names` is passed through unvalidated; `versions` third column is upstream's MD5 of the unfiltered info
Location: src/rubygems/serve.rs:313-350
Failure: `names` accepts any 200 body (an HTML portal page would be served as text/plain); `versions` lists withheld versions and an info checksum that never matches the filtered info, so Bundler re-downloads info every run (the implementer documents this; 03 line 313 says "preserve checksum relationships"). Second-run and `bundle update` flows with a populated Bundler cache are not covered by the native test.
Correction: validate `names` (`---` header, one valid name per line); decide with the user whether `versions` should be re-rendered consistently. Blocking: no.

## Requirement coverage

| Requirement and source | Implementation / connection | Expected -> observed | Check and limits | Status |
|---|---|---|---|---|
| R1 RubyGems variant, tag, `ALL`, OSV arm `Some("RubyGems")` (row 17, 03:160-171) | policy lib.rs, osv/batcher.rs, blocklist, policy/mod.rs, logging, report, origins, config | present in every exhaustive match; npm/pypi tags unchanged | osv_ecosystem_mapping 3 passed (run here); policy crate tests | MET |
| R2 LS-F6 key charset | osv_key.rs, names.rs | charset and case kept | osv_key tests (run, passed) | MET |
| R3 migration 0014 nine tags, in place, old rows reopen | 0014_ten_ecosystems.sql | four constraints widened | ecosystem_tags requires Postgres; not run here (implementer: 3 passed on Postgres 16) | UNKNOWN (SQL read, correct) |
| R4 server unknown tag refuses, no Npm fallback | policy.rs `ecosystem_of`, StoreError::UnknownEcosystem, all match sites | explicit 503/unavailable | implementer Postgres run + mutation Y1; not re-run | UNKNOWN (code read, correct) |
| R5 old enforcer LS-F3 mixed version | service_policy_cache tests | known denies kept, unknown registry refused | `service_policy_cache` 5 passed (run here), uses `maven2` tags; no old binary | MET at test level, binary claim UNKNOWN |
| R6 compact index: filter by age per version+platform, blocks, OSV; lines byte-identical | serve_info, info.rs | as specified | rubygems_registry 12, rubygems_info 4 passed (run) | MET |
| R7 gem file identity gate, index-backed unambiguous name, ambiguity refuses | reference_for_file, deliver | as specified | gem_file_* tests | MET |
| R8 LS-F13 A tuple filter typed, re-rendered, bounds, budget | marshal.rs | as specified; Ruby loads output | rubygems_marshal 20 passed (run), real-corpus measurement recorded | MET (codec) |
| R9 LS-F13 B quick gemspec validate, nested stream, original bytes served, real fixture byte-identical | marshal.rs, serve_quick_gemspec | as specified | tests run; hostile and nested cases present; all 17 named tests exist | MET |
| R10 Use "pinned marshal-rs" (03:333) | hand-written codec | deviation, disclosed, no new dependency | needs the user's yes (implementer states so) | UNKNOWN (user decision) |
| R11 LS-F7 inflate caps 128 MiB / 4 MiB, ratio 100:1, trailing refused, largest fixture recorded | inflate.rs, rubygems-corpus.md | caps and ratio met; trailing bytes refused for gzip only | F3 | NOT MET (zlib trailing) |
| R12 tuple indexes: only first-seen/authoritative dates grant eligibility | serve_index | substitute epoch date; no judgement in service mode | F1 | NOT MET |
| R13 F12 `osv_skipped_for_private_registry_in_rubygems`, `osv_public_mirror_with_explicit_scope_is_queried` | src/osv/mod.rs tests | present, pass | `cargo test --lib osv_` not re-run (known hangs in full lib); implementer: 14 passed | MET (by implementer evidence, tests read) |
| R14 C1028 family case through row 28 seam | credential_read.rs RUBYGEMS rules, service_registry.rs | classification and gem store covered | F7 (info-cache part vacuous) | MET with weak part |
| R15 compressed fixtures recorded, caps set | rubygems-corpus.md | numbers recorded, caps kept (5x headroom) | measurement is an `--ignored` test, not re-run | MET (evidence read) |
| R16 E2E-rubygems | absent | row command missing | F2 | NOT MET |
| R17 wiring: routes, listener table, config, origins, logging, docs/sample | http/mod.rs, rubygems_routes.rs, listener_admission rows, origin_guard, config.sample.toml, operations.md | present; listener 16 passed, origin_guard 6 passed (run) | F5 for UI/docs remainders | MET with F5 |
| R18 npm/PyPI preserved | only arms and one strengthened portal assertion text | no behaviour removed | 4 additional prior-slice test binaries run, all passed (origin_guard, shared_service, service_policy_cache, managed_delivery_authority) | MET |

## Implementer-reported gaps, judged

| Gap | Spec requirement? | Judgement |
|---|---|---|
| 1 Legacy tuple index lists unseen gem's young latest, quick gemspec 404 | Yes (03:333, :363) | Blocking, and wider than reported (F1b) |
| 2 E2E-rubygems not built | Yes (row 17 verification) | Blocking (F2) |
| 3-4 Old enforcer/server binary not built | Partly: the row asks to "prove" them; the test-level witnesses with unknown tags exist | Acceptable if the coordinator accepts the current-binary witness; otherwise a prior-release build is needed (UNKNOWN) |
| 5a No `record_decision` for fully refused listing | Not literal; parity | F4, non-blocking |
| 5b No RubyGems field in sync report | Not in the row text; additive management-API change | Non-blocking, needs the user's yes (outage of the RubyGems upstream is invisible to the fleet, `let _ = rubygems.close_period()`) |
| 5c Managed-certificate mode untested | Row lists generic dispatch; `admit` is shared with the tested standalone path | Non-blocking; add one test (U2) |
| 6a `gem push`/`yank` not forwarded | Not in row 17 or LS-F13 ("No RubyGems function is dropped" concerns index/quick); the shared service routes are read-only | Not a requirement of this row; confirm with the user that push/yank is out of the PAAS scope |
| 6b No Range / Repr-Digest | Not in spec | Performance only; see F10 |

## Conventions and simplifications
- Mutation claims: probes P1-P8, M1-M5, X1-X4, Y1 are plausible and consistent with the code; P9 "equivalent mutant" is correct (`length()` bounds `n*per_item` by remaining bytes; Vec grows by push). Not re-run (costly, and none contradicts the code). X4 first survived and the test was strengthened, which is the right response.
- TDD history: most of the codec, serve and route tests have "red not observed"; honestly recorded. Marked UNKNOWN if test-first is an acceptance condition.
- `OriginKind::NpmMetadata` slot reuse for a selected RubyGems origin (serve.rs:43, download.rs:572) mirrors PyPI and is commented; acceptable but a naming debt.
- `Marshal::V::Hash`, `Int` etc. carry `#[allow(dead_code)]`; small speculative surface.

## Uncertainties
U1 — Real upstream transport behaviour: no test sends `specs.4.8.gz` or `.gemspec.rz` through the real HTTP transport (fakes only; E2E missing). If the transport auto-decodes a `Content-Encoding: gzip` on a `.gz` file or applies `max_metadata_bytes` after decoding, the inflater input differs from the curl-downloaded corpus. Check: one live fetch through the real transport (owner: slice 17 implementer, with F2).
U2 — Managed-certificate mode: `admit` is shared, but no test; check by one rubygems_registry-style test with a verified peer.
U3 — Compact-index parse robustness over real `info/` files: only 24 real lines are fixtures; one malformed-looking real line makes the whole gem answer 502 (`parse_info` is all-or-nothing). Check: parse a sample of real info files (rails, rack, nokogiri, a prerelease-heavy gem) like the Marshal corpus run.
U4 — Bundler second run and `bundle update` with a populated cache (Range, If-None-Match, the third `versions` column) is unverified.

## Verification and limits
Commands run (all under `systemd-run --user --scope -q -p TasksMax=512 -p MemoryMax=16G -- timeout`, cargo -j 8, builds in the repo target dir on disk):
- `cargo test --test rubygems_registry --test rubygems_marshal --test rubygems_info --test osv_ecosystem_mapping --test credential_bearing_reads --test listener_admission`: 12 + 20 (1 ignored) + 4 + 3 + 8 + 16 passed.
- `cargo test -p probation-policy --test osv_key`: 6 passed. `--test origin_guard --test shared_service --test service_policy_cache --test managed_delivery_authority`: 28 + 29 + 5 + one more binary all passed (4 result lines, none failed).
- Scratch crate under /home/john/go/src/github.com/postfix/.probation-scratch/zlibprobe (removed) to confirm F3.
Not run: rubygems_native (requires the local Ruby, evidence says passed), `cargo test -p probation-server` (needs Postgres), full `cargo test --lib` (known hangs), clippy, the `--ignored` corpus measurement, E2E.
Supplied evidence relied on: slice-17.md, tdd-slice-17.md, rubygems-corpus.md (read, consistent with the code).
Reviewed paths: src/rubygems/*, src/http/rubygems_routes.rs, src/http/{mod,registry_read,service_registry,credential_read,logging}.rs, src/artifacts/{mod,download}.rs, src/upstream/origins.rs, src/config.rs, src/osv/{batcher,mod}.rs, src/policy/*, src/managed/report.rs, crates/probation-policy/src/{lib,names,osv_key}.rs, crates/probation-server/src/{policy,service_policy,sync,fleet}.rs and portal/*.rs, migration 0014, templates (grep), the new and touched tests, 03/04 spec rows.
Unchanged during review: yes (git status entry count 53 before and after; no source edited).
Lenses with no finding: Marshal reader memory/depth/link safety (read in full, no defect found; `long()` has no overflow path), path/URL injection through gem and file names (segments validated and pushed encoded), credential carriers, route table.

## Next steps
1. Fix F1 (decision: first-seen store for tuples, persisted also in service mode) and add the service-mode native/indexed test without a warming `/info` call.
2. Fix F3 with a zlib trailing-bytes test.
3. Build E2E-rubygems (F2) and run it in its own capped scope; settle U1 with it.
4. Schedule F4, F5, F6, F7, F8, F9, F10; ask the user about marshal-rs vs the hand-written codec, the sync-report RubyGems field, and push/yank scope.
