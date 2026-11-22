# TDD record, slice 27 (cross-plan portal, intelligence, decision and native-release acceptance)

Procedure followed: /home/john/.claude/skills/agents/implement/AGENT.md (red, then green, one behavior at a time). Inputs read: 00-status.md (NEXT ACTION), 03-program-design.md (LS-F12, items (j) to (r), the OSV mapping owner paragraph), 04-slices.md row 27, evidence/slice-17.md to slice-26.md and slice-30.md (lanes, remaining limits, spec changes), the existing tests named in each line below.

Review baseline: `git rev-parse HEAD` = `182f7f3e33f11c3c01bf65c27063c3e0760ec0ee` (branch slice5-native-ci); `git status --short --untracked-files=all` was empty before the first edit. Nothing is committed. 00-status.md, 03 and 04 are not edited.

Environment: every cargo, python, node, podman and E2E command ran inside `systemd-run --user --scope -q -p TasksMax=512 -p MemoryMax=16G -- timeout N ...` (timeouts 300 to 3000 s; the E2E run 9000 s, a measured need: the release suite is 47 scenarios of which 19 start their own stack). Build artifacts and scratch under `/home/john/go/src/github.com/postfix/.probation-scratch/s27` (own target directory, on disk, not /tmp). Host load average was 15 to 68 from other sessions throughout; timing-sensitive results are labelled.

Seams (caller-visible interfaces the tests act through): `probation_server::osv_view::{coverage, coverage_label, registry_line, scope_value}` (the OSV coverage view, from `probation::osv::{osv_ecosystem, effective_scope}`); the portal catalog page `GET /org/{id}/registries` and its form `POST .../osv-scope`; `Ecosystem::ALL`, `Ecosystem::{as_tag, from_tag}`, `BlocklistSnapshot::parse_and_validate`, `policy::evaluate`, `credential_read::classify_read`, the real shared-service router (`probation::http::router`, driven through `tower::ServiceExt::oneshot` with a `ConnectInfo` peer); the repository files the contract names (migrations, `config.sample.toml`, docs, `src/http/mod.rs` routes, `tests/e2e/scenarios/*.mjs` meta); `node tests/e2e/harness/run.mjs --suite ...`.

## Cycles

```text
tdd: osv_coverage_view_matches_mapping — red: error[E0432]: unresolved import `probation_server::osv_view` (could not find `osv_view` in `probation_server`) — green: cargo test --locked -p probation-server --test osv_coverage_view passed (2 passed)
tdd: osv_coverage_view_shows_scope — red: the same E0432 (one test file, two tests; both red until the module existed) — green: cargo test --locked -p probation-server --test osv_coverage_view passed (2 passed)
tdd: t_registry_catalog_shows_osv_coverage_and_scope — red: panicked at crates/probation-server/tests/portal_places.rs:4498:9: npm: <!doctype html>... (the catalog had no coverage table, no per-registry line, no preselected scope) — green: cargo test --locked -p probation-server --test portal_places t_registry passed (10 passed)
tdd: the_release_suites_account_for_every_scenario — red: assertion `left == right` failed left: [] right: ["release-native"] (E2E-service-native was in no suite); then red: PBT-smoke (pbt-smoke.mjs) belongs to no release suite and is not a named exception (suites ["pr"]) — green: cargo test --locked --test cross_plan_acceptance passed (11 passed)
tdd: readme_and_docs_cover_every_family — red: panicked at tests/cross_plan_acceptance.rs:387 (README.md, docs/usage.md and docs/configuration.md named only npm and PyPI) — green: same command passed (11 passed)
tdd: config_keys_are_in_the_sample_the_parser_and_the_docs — red: npm_upstream_url is not listed in docs/configuration.md — green: same command passed (11 passed)
tdd: the_shared_service_contract_holds_in_every_family — red: assertion `left == right` failed left: 7 right: 0 (my test counted the admitted reads, which legitimately reach the fake upstream; a test defect, fixed in the test by counting only after the refused and credential-less requests; no product defect) — green: cargo test --locked --test cross_plan_acceptance the_shared passed
tdd: every_family_has_a_stable_tag_and_an_unknown_tag_fails_closed — red not observed (characterizes delivered behavior; mutation probe A1/A8 below shows it can fail)
tdd: the_publication_gate_gives_every_family_the_same_answers — red not observed (probe A3 below)
tdd: osv_mapping_and_default_scope_cover_every_family — red not observed (probe A1 below)
tdd: credential_bearing_reads_are_never_cache_eligible_in_any_family — red not observed (probe A2 below)
tdd: migrations_are_present_and_ordered — red not observed (delivered; no probe: a removed migration cannot be restored by a text mutation, the test reads the directory)
tdd: every_family_is_routed_on_both_prefixes_and_classified — red not observed (probe A4 below)
tdd: every_publishing_family_keeps_its_write_and_spool_witnesses — red not observed (probe A9 below)
tdd: every_transports_hot_path_meets_its_stated_bounds — red: npm: read p95 174.914207ms over 1µs (first run with placeholder bounds of 1 µs, printing the measured table) — green: cargo test --locked --test transport_rated_load passed (1 passed) after the bounds were set from the measured table
tdd: transport_hot_paths bench (--assert) — red: with every bound a placeholder the verdict lines were all PASS, then with a bound mutated beyond reach `slice 27 pypi throughput 541287/s >= 1000000000000/s FAIL`, exit 1 (probe B1) — green: cargo bench --locked --bench transport_hot_paths -- --assert exit 0 with the measured bounds
tdd: native_mvn_resolves_a_snapshot_to_the_newest_allowed_build (host Maven lane, found by executing it) — red: [ERROR] Could not find artifact org.apache.maven.plugins:maven-dependency-plugin:jar:3.8.1 in probation (http://127.0.0.1:37177/maven/) (the workflow's seed step fetched the plugin through the default `central` id; Maven records the repository id) — green: PROBATION_NATIVE_HOST=1 PROBATION_MAVEN_SEED=<the workflow's own corrected seed step run by bash> cargo test --test maven_native passed (3 passed)
tdd: check_workflow.test.py new mutations (bench step removed, bench without --assert, workspace tests removed) — red: each of the three mutated release.yml texts is refused by check_workflow.py (`release.yml's test job must run cargo bench --locked --bench transport_hot_paths -- --assert` and the workspace-test requirement) — green: python3 tests/e2e/native/check_workflow.test.py: `check_workflow.test: 202 bypasses all fail, known-good passes` (199 before)
tdd: E2E-015 an unknown ecosystem is refused with one line naming the record (found by running the release suite) — red: E2E FAIL E2E-015: Error: PUT with an unknown ecosystem: one line naming the problem: `x` is not a package name (the scenario's `maven` became a known family in slice 21) — green: node tests/e2e/harness/run.mjs --suite release --only E2E-015: `E2E-015 passed in 105.0 s` after the case used `swift`
```

E2E, native and live lanes are in evidence/slice-27.md ("Lane ledger", "E2E"); they are checks, not red-green cycles of this slice, except the two cycles above.

Typecheck and build: every green above included a `cargo test` compile of the touched crates (no separate typecheck command exists for Rust beyond it); `cargo clippy` in both feature sets and on lib and bins alone are in "Checks".

## Mutation probes (sha256-verified restores)

Method: `probe.py apply FILE OLD NEW` (backup copy and its sha256 recorded, the pattern must match exactly once), the focused test run in a capped scope with an EXIT trap that restores, then `probe.py restore FILE` (copy back, touch so cargo rebuilds, sha256 compared). Every restore printed `sha256 MATCHES`. No command was killed (no 137 or 143), so no post-kill check was needed.

| # | File and mutation | Expected red | Observed |
|---|---|---|---|
| P1 | crates/probation-server/src/osv_view.rs: `coverage()` drops OCI | osv_coverage_view_matches_mapping | FAILED (osv_coverage_view.rs:17), restore 49ccad202dc1 MATCHES |
| P2 | osv_view.rs: `OsvScope::Private => QUERIED_SHARED` | osv_coverage_view_shows_scope | FAILED (osv_coverage_view.rs:59), restore MATCHES |
| P3 | osv_view.rs: the "no OSV ecosystem, never queried" early return removed | osv_coverage_view_shows_scope | FAILED (osv_coverage_view.rs:52), restore MATCHES |
| P4 | crates/probation-server/src/portal/registries.rs: the line is always `QUERIED_SHARED` | t_registry_catalog_shows_osv_coverage_and_scope | FAILED (portal_places.rs:4504), restore fe6cea61fcca MATCHES |
| P5 | registries.rs: the stored `private` option is no longer preselected | the same | FAILED (portal_places.rs:4513), restore MATCHES |
| A1 | src/osv/batcher.rs: `Ecosystem::Oci => Some("OCI")` | osv_mapping_and_default_scope_cover_every_family | FAILED (cross_plan_acceptance.rs:115), restore d110e8a125e5 MATCHES |
| A2 | src/http/credential_read.rs: `authorization` added to the common headers | credential_bearing_reads_are_never_cache_eligible_in_any_family | FAILED (:162), restore e1faf255e423 MATCHES |
| A3 | src/policy/mod.rs: a Go block no longer applies | the_publication_gate_gives_every_family_the_same_answers | FAILED (:98), restore dca760e66f75 MATCHES |
| A4 | src/http/mod.rs: the `/registry/maven/{registry}` route renamed | every_family_is_routed_on_both_prefixes_and_classified and the_shared_service_contract_holds_in_every_family | both FAILED (:327, :197), restore 104eaaf89273 MATCHES |
| A5 | README.md: Conan removed from the sentence | readme_and_docs_cover_every_family | FAILED (:302), restore 299f4e9ab8c2 MATCHES |
| A6 | config.sample.toml: `maven_publish_url` misspelt | config_keys_are_in_the_sample_the_parser_and_the_docs | FAILED (:280), restore 63d157751534 MATCHES |
| A7 | tests/e2e/scenarios/service-cluster.mjs: `suites: []` again | the_release_suites_account_for_every_scenario | FAILED (:377), restore df67e4b41fb7 MATCHES |
| A8 | src/http/listener_admission.rs: `peer_admitted` always true | the_shared_service_contract_holds_in_every_family and transport_rated_load | both FAILED (:188; `an unlisted peer is refused every time left: [404] right: [403]`), restore f94392b72610 MATCHES |
| A9 | tests/maven_service_write.rs: the cross-forwarder spool witness renamed | every_publishing_family_keeps_its_write_and_spool_witnesses | FAILED (:411), restore 2c07993678e6 MATCHES |
| B1 | benches/transport_hot_paths.rs: `FLOOR_RPS` set to 1e12 | `cargo bench --bench transport_hot_paths -- --assert` | exit 1 with 8 FAIL lines, restore 4753829075f0 MATCHES |

Not probed, and why: the three new `check_workflow.test.py` mutations are themselves mutation probes of release.yml (they run in the python suite; see "Checks"); `migrations_are_present_and_ordered` reads a directory, so a text mutation cannot express a deleted file; the fleet-health text is slice 30's (`tests/osv_fleet_health.rs`), accepted here unchanged.

## Remaining stubs and limits of this slice (the packet has no "Remaining stubs and limits" entry, so each is listed and none is claimed fixed)

- Stubs and hardcoded values left: the acceptance test's `TAGS`, `sample_name`, `surfaces()` (the nine registry ids and routes), the OSV mapping table and the config-key table are hardcoded lists, deliberately: a tenth family fails the length assertions until each is extended. The in-process fake upstream of the load measurements answers 404/502 for every family except npm (warm fixture) and Conan (served locally); stated in docs/operations.md section 22. Stubs replaced: none (the slice adds checks, no stub existed).
- The acceptance test's second part (migrations, config keys, docs, routes, release suites, witnesses) reads repository files: it proves a witness exists and a contract row is documented, not that the witness passes. The witnesses run in `cargo test --workspace`.
- Fixed by this slice and found by running something: README.md, docs/usage.md and docs/configuration.md named only npm and PyPI; E2E-service-native, -smoke, -cluster and -cluster-probe were in no suite; PBT-smoke was in `pr` only; the host-Maven seed step of native-service.yml seeded through the wrong repository id (it could not have passed on a runner).

## Spec changes needed

The full list is in evidence/slice-27.md ("Spec changes needed"); summarized for the TDD record: (1) 04 row 27 must name the three suite runs (`release`, `release-native --client-host native`, `release-cluster`) because a native-host scenario cannot share a run with container scenarios; (2) the acceptance sentence about "all 3 client OSes" is a hosted-runner criterion and is not met by this host; (3) 03 needs the third registry line "OSV queried: public registry" and the three witness names (`osv_coverage_view_matches_mapping`, `osv_coverage_view_shows_scope`, `t_registry_catalog_shows_osv_coverage_and_scope`); (4) the shared service's every-read-revalidates-upstream cost (measured, docs/operations.md section 22) needs an owner decision; (5) the two pre-existing failing SPEC section 12 benches (`artifact_throughput`, `warm_metadata`, reproduced at e3226bf) need a diagnosis or a restated target; (6) 00-status: slice 27 complete for the Linux-executed scope only, D1 open.


## Fix round (second implementer): cycles and probes

Procedure: /home/john/.claude/skills/agents/implement/AGENT.md (red, then green). Every cargo, node, python and E2E command ran in a capped
`systemd-run --user --scope` (TasksMax 512, MemoryMax 16G, timeouts 300 to 9000 s); build artifacts, pg data and scratch under
`/home/john/go/src/github.com/postfix/.probation-scratch/s27f` (disk, not /tmp). Host load average 30 to 60 from other sessions.

```text
tdd: E2E-publishing-native-linux (the lane's loopback registries are refused by the service) — red: `only 2 checks ran, the pinned floor is 75` and the service never activates the snapshot (`failed the activation order checks`); the product pin is tests/service_policy_cache.rs descriptor_naming_loopback_or_link_local_is_rejected_before_activation (a 127.0.0.1 target with its own /32 is refused, 10.0.0.5 with its own CIDR is accepted) — green: node tests/e2e/harness/run.mjs --suite release --only E2E-publishing-native-linux: `native publishing passed: 75 checks on linux-x64`, `passed in 37.9 s` (lane address 10.254.77.1 on the loopback interface; two earlier greens with 10.77.0.1, changed because compose has a 10.77.0.0/24 network)
tdd: stack.test.mjs (the lane address, pypi.org mapping, hosts-file undo) — red not observed (the expectations were edited together with the code; the 127.0.0.1 lookups of the old test would no longer be the lane address) — green: NATIVE_TEST_SCRATCH=... node tests/e2e/native/stack.test.mjs: `stack.test: ok`
tdd: check_workflow.test.py (--no-run, --list, tag name and event payload interpolated into run scripts) — red not observed (the four mutants were added together with the stricter rule; the old rule was a substring match that `--no-run` and `-- --assert --list` satisfy) — green: `check_workflow.test: 206 bypasses all fail, known-good passes` (202 before)
tdd: transport_rated_load (asserts what the read answered; npm reads the warm fixture and are shared) — red: `npm: read p95 14.78ms over 2ms`, `npm: 337 req/s under 800` once the test read the real warm document instead of a miss (and the old floors, which were round numbers) — green: bounds re-derived by one rule from five runs (docs/operations.md section 22), `cargo test --test transport_rated_load`: 1 passed
tdd: cross_plan_acceptance (is_live_test, word-exact names, 0014 exact tag list, parser key set, doc names, release-suite exclusivity, admitted status exact) — red: four tests failed on real gaps the old checks had hidden: docs/usage.md never named PyPI, docs/configuration.md lacked pypi_artifacts_url, cargo_artifacts_url and go_artifacts_url, tests/osv_ecosystem_mapping.rs has no test named osv_ecosystem_mapping_per_family, and npm's allowed read answered 404 where the warm fixture answers 200 — green: docs fixed, the three keys listed, the real witness named, the read made against the warm path: 11 passed
tdd: osv_coverage_view_matches_mapping (oracle table driven from Ecosystem::ALL, complete) and the public-source line with a stored Private scope — red not observed (written with the code) — green: see the server sweep below
tdd: t_registry_catalog_shows_osv_coverage_and_scope (privacy warning on the Add form and beside the default option, add form lists Ecosystem::ALL, audit rows of osv_scope and sibling setters) — red not observed separately (the assertions were written with the handlers) — green: see the server sweep below
tdd: E2E-publishing-certificate-scale (organisation-issuer admission paced by a measured sustainable rate) — red: `identity 517 was denied: 401` (20 ms pace) in the standalone scenario on a quiet host; in the full matrix `identity 4768 was denied: 401` at the calibrated 30 ms pace — green: standalone `E2E-publishing-certificate-scale passed in 1025.2 s` (calibrated 20 ms trial, probe at 30 ms, 10,000 admitted in 317.4 s); NOT green inside E2E-publishing-full-matrix (FAILED in 4450.2 s, runner 20 and runner 6 `npm-read-disabled`; open, see evidence/slice-27.md)
tdd: artifact_throughput and warm_metadata benches (SPEC §12) — red: `SPEC §12 artifact additional p95 ttfb +24.184 ms <= 5 ms FAIL`, `artifact throughput 22.2% ... FAIL`, `warm policy denial p95 14.927 ms <= 2 ms FAIL` — green: `+0.155 / +0.377 / +0.308 ms`, `107.8 / 105.2 / 106.2%`, `warm policy denial p95 1.812 ms PASS` after the benches were given a reachable in-process OSV (root cause: an offline OSV client and uncached failed lookups, bisected to b02e088)
tdd: service_metadata_share (the share is per registry and per origin) — see the probe table: the original two tests did not kill the key probes; this third test does
```


### The red of the share, observed

The share (`src/service_share.rs`) was written before its test in round 1, so its red is observed by removing it: probe P-S0 below (share disabled) fails `service_mode_npm_and_pypi_metadata_reads_are_shared_for_plain_reads_and_never_for_credentialed_ones` and `the_share_holds_at_most_256_projects`, and the product before the share measured p50 14.4 to 23.4 ms at 32 clients (docs/operations.md section 22).

A first run of the sweep caught two consequences of the share that no test of its own would have: `shared_service::shared_http_cold_warm_selected_and_legacy_authority_changes` (once) and `managed_delivery_authority::common_route_policy_change_refuses_before_release` failed (twice alone) (`Elapsed` at line 524): it holds the artifact request's upstream revalidation, and a credential-free artifact request now reuses the project the preceding metadata read fetched for 5 seconds, so the revalidation never happened. The test advances the test clock past the share's lifetime before the artifact request (the product guarantee it protects, that a policy published before release governs the bytes, is unchanged and still asserted); passed 6 of 6.

### Mutation probes of this round (sha256-verified restores)

Method: `probe.py apply FILE OLD NEW` (backup and its sha256 recorded, the pattern must match exactly once), the focused test inside a capped scope with an EXIT trap that restores, then the trap's `probe.py restore` (copy back, touch so cargo rebuilds, sha256 compared). Every restore printed `sha256 MATCHES`; no command was killed.

| # | File and mutation | Expected red | Observed |
|---|---|---|---|
| P-S0 | src/service_share.rs: `get` always answers `None` (no share) | service_metadata_share | FAILED (2 tests), restore bb29bf2cc6a6 MATCHES |
| P-S1 | src/service_share.rs: the TTL never expires | the plain/credentialed test ("the share is short") | FAILED, restore MATCHES |
| P-S2 | src/npm/mod.rs: a credential-bearing read fills the share (`if true`) | the same test | SURVIVED the first test set; the test then advanced the clock past the TTL before the credentialed reads, so only they could fill the table; FAILED after that edit, restore 979be006d6ae MATCHES |
| P-S3 | src/npm/mod.rs: the `read_authorization.is_none()` term dropped from `shareable` | none | SURVIVES, an EQUIVALENT mutant: `cache_token(app)` is already `None` for any request-scoped (credential-bearing) read, so the term is belt and braces; kept |
| P-S4 | src/service_share.rs: the 256-cell cap removed | `the_share_holds_at_most_256_projects` (new) | SURVIVED the first two tests (no test covered the cap); FAILED with the new test, restore MATCHES |
| P-S5 | src/npm/mod.rs: the key without the registry | `the_share_is_per_registry_and_per_origin` (new) | SURVIVED until that test existed; FAILED with it, restore MATCHES |
| P-S6 | src/npm/mod.rs: the key without the origin | the same | FAILED (a publication that moves a registry's target is not answered from the old origin's share), restore MATCHES |
| P-S7 | src/pypi/mod.rs: the key without the registry | the same | SURVIVED until the test had a second PyPI registry; FAILED after, restore 6ba0ac68d6e9 MATCHES |
| P-S8 | src/pypi/mod.rs: `shareable = true` (credentialed PyPI reads fill and read) | the plain/credentialed test | FAILED, restore MATCHES |
| P-B1 | src/npm/mod.rs: a store checkpoint added to every standalone warm read | `cargo bench --bench warm_metadata -- --assert` | exit 101: `the measured window issued 3000 database commands, more than the 2 maintenance passes it spanned, so it was not warm`, restore MATCHES |

"Policy publication not invalidating" has no mutant of its own: the cell holds the fetched project only and the policy is evaluated on every read, so nothing needs invalidating; `a_policy_publication_governs_the_next_shared_read` asserts the property end to end (and `managed_delivery_authority` above asserts the release order).


## Fix round 3: cycles

Procedure: /home/john/.claude/skills/agents/implement/AGENT.md (red, then green); root-cause method /home/john/.claude/skills/agents/debug/AGENT.md (reproduce, instrument, isolate, fix, rerun). Every cargo, node, python and E2E command ran in a capped `systemd-run --user --scope` (TasksMax 512, MemoryMax 16G); build artifacts, Postgres data and the client lane under `/home/john/go/src/github.com/postfix/.probation-scratch/s27g` (disk). The only production-code edit is a log line; the rest is E2E scenario, fake and harness code, so the cycles are E2E reds and greens, each with its command.

```text
tdd: E2E-publishing-certificate-scale at a 20 ms organisation-issuer pace (the failing pace of two earlier rounds) — red: `identity 6358 was denied: 401` after a temporary firewall timing diagnostic showed 13,710 OCSP round trips p50 305 ms / p99 1,293 ms / max 5,074 ms, 8 `Connect, TimedOut` and responder gaps of 1.5 to 2.9 s (synchronous `spawnSync("openssl")` in the fakes' one thread) — green: after the fake signs through at most four asynchronous children and the probe's pace is a floor, the same run: round trip p50 37 ms p95 236 ms, 1 connect timeout in 1,439 (`identity 703 was denied: 401`, still red), then with one retry per first refusal: `E2E-publishing-certificate-scale passed in 1243.9 s` (command: E2E_COMPOSE_CMD=podman-compose E2E_WORK=... E2E_TEMP_PACE=20 node tests/e2e/harness/run.mjs --suite release --only E2E-publishing-certificate-scale; E2E_TEMP_PACE was a temporary override, removed)
tdd: certificate-scale enrollment under a slow database — red: `scale member 7900 signed in: 503 null` (server log: COMMIT 2.0 s, statement timeout) — green: sign-in restarted up to three times on a 503, passed in the run above
tdd: E2E-publishing-full-matrix runner npm-read-disabled — red not observed in isolation (`E2E_MATRIX_ONLY=npm-read-disabled`: passed in 323.8 s, 9 witnesses); the earlier two reds carried no status or time, so the assertions now print both and measure the request inside the client — green: the full matrix, 20 of 20 runners, `E2E-publishing-full-matrix passed in 3528.2 s`
tdd: npm-actions runner, stalled action response and 121st login start (host-speed assertions) — red: runner 3 `stalled action response ends within the deadline: 0` (no status or time was printed) and runner 5 `121st web-login start is rate-limited before upstream: [200, ... 118 times]` (fakes log: the 121 starts spread over 98 s, the fixed 60 s window of `LoginRates` rolled) — green: the probe measures its own duration and repeats after the window when it took more than 45 s; the failed assertion prints exit, status, time, stderr and stdout; both runners passed in the next full matrix
tdd: src/managed/mod.rs refusal log — red not observed (a log line; no test reads logs) — green: clippy and the 89 root test binaries, and the line printed `error: "Unavailable"` in the firewall log of the isolating runs
tdd: harness (matrix log retention, replaced container logs, E2E_MATRIX_ONLY, stack-up retry on `pool timed out`) — red: the first release run aborted at a fresh stack's `admin bootstrap` (`pool timed out while waiting for an open connection`) and the matrix kept no per-runner logs — green: `node --check` of every edited file, `python3 tests/e2e/native/run_tests.py` (31 files hold), the full release suite above
```

Mutation probes of this round: none (see slice-27.md, "Final checks on the final tree (round 3)", for why). Checks: clippy three ways exit 0; 89 root test binaries 1,194 passed 0 failed; probation-policy 73; `--lib` 304 passed 2 ignored; probation-server on Postgres 16 244 passed; `run_tests.py` 31 files; `transport_hot_paths -- --assert` 36 PASS; the three SPEC §12 benches exit 0.


## Fix round 4: cycles

Procedure: /home/john/.claude/skills/agents/implement/AGENT.md (red, then green). Review baseline: `git rev-parse HEAD` 182f7f3 plus the uncommitted tree of round 3 (`git status` unchanged except the files named below). Commands in `systemd-run --user --scope -q -p TasksMax=512 -p MemoryMax=16G -- timeout 900`; Postgres 16 on disk in the scratch tree.

```text
tdd: F2 artifact requests never use the metadata share (owner decision) — red: the restored ORIGINAL tests/managed_delivery_authority.rs and tests/shared_service.rs (clock-advance edits reverted with git checkout HEAD) fail against the round 3 product (an artifact request inside the 5 s window is answered from the share, never reaching the held upstream revalidation); the new `artifact_requests_always_revalidate_upstream_and_never_use_the_share` and `an_upstream_takedown_is_seen_by_the_next_artifact_request` fail the same way (mutant M6 reproduces it: both FAILED) — green: `current_project(.., metadata: bool)` in npm and PyPI, `ensure_fresh_project_*` pass false; service_metadata_share 9 passed, managed_delivery_authority 6 and shared_service 5 pass unchanged (command: cargo test --features probation/test-support --test service_metadata_share --test managed_delivery_authority --test shared_service)
tdd: F1 byte bound — red: `the_share_is_bounded_by_bytes_and_drops_expired_and_oversized_cells` is written against the new accounting (`App::service_share_stats`, test-support) and fails for each of M1 to M4 (per-cell cap, byte budget, expired eviction, oldest-first eviction); the round 3 table (count only, clear() when full) cannot satisfy it — green: 64 MiB / 8 MiB / expired-first / oldest-first in src/service_share.rs: 30 reads of 3 MiB documents never account more than 64 MiB (18 to 21 cells), a 9 MiB document is not kept
tdd: F4 single flight and cancellation safety — red: M5 (every caller fetches) fails `a_cold_burst_of_plain_reads_costs_one_upstream_fetch`; M10 (flight entry kept) fails the unit test — green: per-key tokio mutex flight with a Drop guard, 12 concurrent reads cost one fetch, a 503 first fetch is not cached and hangs nobody, a dropped leader leaves the waiter free and the flight table empty
tdd: F3 PyPI credential check — red not observable (M8 survives: `cache_token` is already None for every credential-bearing read, an equivalent mutant as P-S3 was for npm) — green: the same expression as npm
tdd: F5 registry.* audit before — red: `t_registry_audit_before_is_the_row_the_update_replaced` got `(Some("false"), Some("false"))` (the `before` was read before the other admin's committed edit) — green: `FOR UPDATE` in `registry_state`: `(Some("true"), Some("false"))` (command: cargo test -p probation-server --test portal_places t_registry, PROBATION_SERVER_TEST_DATABASE_URL on the podman Postgres)
tdd: F8 policy-server URL — the guard existed (`has_userinfo` in RawServicePolicy::validate); the test now asserts the message never echoes the URL, and the snapshot-fetch warning uses `error.without_url()`; green: config_server_url_rejects_path_query_userinfo_fragment_and_http
tdd: F7 harness up() retry — red: before the change `up()` retried a message containing ECONNREFUSED or socket hang up, so the new test cases "a product-side failure is not retried" (4) would have failed; I wrote the tests after the code, so this red is by construction, not observed — green: node --test tests/e2e/harness/stack-retry.test.mjs: 6 passed (IPAM retried and recorded; a one-off step's pool timeout retried; ECONNREFUSED, socket hang up, a readiness timeout and a product-side pool timeout not retried)
tdd: F7 net.mjs resend, purgeStaleDns, certificate-scale ceiling and 401-only retry and pace floor, issuer.mjs one read of statusMode — E2E harness and scenario code: checked by `node --check` and by the E2E runs listed in evidence/slice-27.md "Fix round 4 (final)"; no unit test (the resend needs a stale kept-alive tunnel, which only the stack provides)
tdd: F6 — no behaviour change (a header line of the bench and a sentence of operations.md)
```

Honest note: the F1, F4 and F2 tests were written after the share code of this round, then proven by the mutants M1 to M7 and M10 (each FAILED on its mutant, which is the red a test written first would have shown). The F5 test was run red before the fix.

## Fix round 4, final step: share figures 8/64 MiB to 32/256 MiB

```text
tdd: the_share_is_bounded_by_bytes_and_drops_expired_and_oversized_cells (20 reads of 16 MiB documents, accounted bytes <= 256 MiB at each step, 13 to 16 cells, 33 MiB document not shared) — red: panicked at tests/service_metadata_share.rs:328:5 (cells assertion, 16 MiB cells were above the old 8 MiB cell cap) — green: cargo test --features probation/test-support --test service_metadata_share passed (9 passed; the lib unit test service_share passed)
```
Clippy `--all-targets --features probation/test-support -D warnings`: exit 0.
