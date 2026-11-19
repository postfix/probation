# Code review: slice 18 (Cargo sparse index, verified crate downloads, Cargo OSV mapping)

Verdict: CLEAN (no confirmed blocker; three medium items need a user decision or a test before SHIP, listed below)
Subject revision: uncommitted working tree on slice5-native-ci, HEAD 707ff3d (73 status entries at start and end). Fingerprints (sha256 prefix): src/cargo_registry/serve.rs a39fd057, index.rs 155d513c, src/http/cargo_routes.rs 8012188f, tests/cargo_registry.rs 331f0f3d.
Scope: 04-slices.md row 18; 03-program-design.md (Cargo family row, LS-F6/F7/F12/F4, C1028, mapping table line 256); evidence/slice-18.md, tdd-slice-18.md; checklist = reviews/slice-17/*.md. The Cargo write path (publish/yank/owner, tests/cargo_service_write.rs) is out of scope per the coordinator.

## Findings (all non-blocking)

F1 - medium - test gap - The selected-registry READ path with a real `target_url` is never exercised
Location: src/cargo_registry/serve.rs `origins_for` (Some branch), `own_origin` Cargo arm in src/artifacts/download.rs:579, `/registry/cargo/{id}/` index and download routes.
Requirement: row 18 "router; origin descriptors"; LS-F12 private-registry semantics; evidence "dl origin rule" claim for a selected registry.
Failure: every service-mode Cargo test uses `target_url: None` (tests/cargo_native.rs:132) or only requests `/registry/cargo/7/config.json` (credential_bearing_reads.rs). grep finds no test or E2E that fetches an index file or a crate through `/registry/cargo/{id}/` with a selected origin. A regression in the NpmMetadata-slot reuse, the path-prefix admission, the cached-config key (registry_id, origin) or the recheck would pass every Cargo test.
Evidence: grep for `registry/cargo` and `target_url: Some` over tests/ and crates/*/tests (only the other agent's cargo_service_write.rs). Code read: the path looks correct (url_for on the selected set, admit against the same set, authorization attached only when the archive origin equals the selected one).
Correction: one test with a selected registry `target_url: Some("https://reg.invalid/api/cargo/repo/index/")`: config, index filter, download, plus a `dl` outside the prefix refused. This also pins claim 3 of "decisions".
Blocking: no (mechanism read as correct; coverage only).

F2 - medium - parity (decision needed) - A selected registry whose `dl` is on another host or outside the index URL's path is refused with 502
Location: serve.rs `origins_for` (archives = same selected origin), `reference_of`; evidence decision 3.
Failure: any private or public mirror whose archives are not under the index URL (Artifactory `api/cargo/{repo}/index` vs `.../crates`, a mirror of crates.io whose dl is static.crates.io, Kellnr-style layouts) makes every index and download 502. Confirmed by reading `OriginSet::admit` (host and path_is_under). The same shape exists for npm/RubyGems, so this is not a regression, but the user's 2026-11-09 ruling (full parity, no backlog, never ask to defer) means decision 3 should be built, not left as an operator workaround.
Correction: add an optional archive-origin field to the registry descriptor (wire change) or admit the dl origin the operator configured (`cargo_artifacts_url` when the selected target is the public index host). Closure: a service-mode test with index and dl on different hosts.
Blocking: no for this review (not a literal row-18 sentence); needs a user yes for the descriptor wire change.

F3 - medium - parity (decision needed) - Cargo is unusable for a managed-certificate organisation
Location: crates/probation-server/src/portal/certificates.rs `render_cargo`; evidence decision 2.
Failure: npm, pip and gem are configured by the certificate script; Cargo only prints a note. Whether such an organisation can fall back to a key depends on whether the portal still issues keys in certificate mode (not checked here). Cargo has no client-certificate setting (claim plausible), so the fix is a design item (key fallback documented per org, or a local TLS-terminating helper in slice 25), not code in this row.
Blocking: no; record as an owned item against the native-lifecycle slice rather than an "accepted reduction".

F4 - low - E2E looser than comment - E2E-cargo header says "the firewall's decision log names them" but the assert is `dated.length > 0` (any decision since start)
Location: tests/e2e/scenarios/e2e-cargo.mjs (end of scenario). Activity row for the folded name IS asserted (`activityRow`), so refusals are covered there; the decision-log claim is not. Correction: assert a decision naming one of the refused crates, or reword the comment.

F5 - low - hostile-registry bound only in standalone - The 4-spelling cap and the `payload_name` check are skipped in service mode (`current_project` returns `refresh` before the cap), and `refresh` still pushes into `spellings`. A hostile private registry answering many `-`/`_` spellings creates one reference set per spelling in service mode. Impact is limited to the tenant's own registry and the map self-clears at 4096 entries. Also the service-mode "undated version waits on committed first-seen" case has no test (the standalone one does, and the commit path is shared).

F6 - low - efficiency - Every download parses the full index file (up to 20,000 lines) three times (reference_for_download, ensure_fresh_project_in, plus reference_of per line in serve_index three times per entry), and in service mode a download costs two upstream index fetches plus config.json (no caching there by design). Same shape as other families; no workload number, so advisory.

F7 - low - evidence accuracy and docs - (a) tdd-slice-18 P8 calls the `payload_name` filter an "equivalent mutant" "not counted". It is not equivalent: without it a cached row of another spelling would make `parse_entries` return OtherCrate and a 502, which `at_most_four_spellings_of_one_crate_are_committed_per_registry` (second-round 200 on variants[0]) kills (reasoned, mutation not re-run). (b) SPEC.md and CHANGELOG.md still list only older upstream-URL keys (evidence item 7). (c) 03's family-table cell still says "created_at"; the code reads `pubtime` and `created_at` (later wins), evidence flags it. (d) keys.html: the trailing sentence "uv and Poetry use the same index URL" now sits after the Cargo block.

## Requirement coverage

| Requirement and source | Implementation / connection | Expected -> observed | Check and limits | Status |
|---|---|---|---|---|
| Variant, tag, ALL, OSV arm `Some("crates.io")`, name charset, SemVer sans build (row 18, 03:169, :256) | policy lib, batcher.rs:39, canonical_name, osv_key | as table | osv_ecosystem_mapping 4 passed (run); policy tests not re-run | MET |
| Sparse layout 1/2/3/ab-cd, nothing else reaches upstream | index.rs `name_of_path`, cargo_routes | uppercase and bad prefixes 404 before upstream | cargo_registry 21 passed (run); asserts upstream call count | MET |
| Filter candidates by age/block/OSV, keep line bytes (checksum, features, yanked) | serve_index, render_index | kept lines equal upstream text | real fixture test uses an independent date parser; native cargo 6 passed (run, real cargo 1.96) | MET |
| Dates: no cache-age substitute; first-seen for undated | publication_of | Upstream(later of pubtime/created_at) else FirstSeen else Unknown | tests for later-of-two, future, undated; persisted first-seen path shared with other families | MET (service-mode undated untested, F5) |
| Verify archive SHA-256 == index cksum before delivery | `Entry::expected` -> shared artifact pipeline | mismatch 502, no bytes | test + real cargo verifies | MET |
| Aliases and exact refused pins | canonical keys, exact file name; pin test via real cargo | young exact pin fails; archive 403 | cargo_native, E2E (recorded green, not re-run) | MET |
| dl/api rewritten, auth-required, Cargo login_url challenge | serve_config, cargo_routes `challenge` | as specified | tests, managed_mode cargo tests (not re-run), E2E recorded | MET |
| Identity: path vs file name vs policy key (slice-17 class) | lower path, exact spelling in file, canonical for policy/OSV | consistent; OSV key folded, live-checked 2026-11-19 (evidence) | Inflector and Mark tests, E2E Cg_Mixed | MET |
| C1028 family case via row 28 seam; LS-F4 path-embedded forms and allow-list | credential_read CARGO rules, service_registry, tests | config cache and archive store not filled by credential reads; positive controls present | credential_bearing_reads 16 passed (run) | MET |
| F12 cases `osv_skipped_for_private_registry_in_cargo`, `..._public_mirror_with_explicit_scope_is_queried` | src/osv/mod.rs:1007,1026 | present | not re-run (known lib hangs); evidence 16 passed | MET (evidence) |
| LS-F7 largest real input recorded, cap set | evidence section, INDEX_FLOOR_CAP 16 MiB | 1.48 MB measured, cap 43x | large-doc test passes | MET |
| Wiring: routes, listener table, origins, config.sample, docs, portal selects, keys page, certificate script, report | grep + diffs | present for Cargo in policy.html, registries.rs, keys.html, docs x4, fleet.rs | listener_admission 16 passed (run); server crate needs Postgres, not run | MET (F7 b-d residue) |
| E2E-cargo | tests/e2e/scenarios/e2e-cargo.mjs | scenario covers freeze, config, OSV, mixed case, block | not run here (Docker, disk 97%); evidence records green | UNKNOWN (evidence only) |
| Full parity vs earlier families | npm/PyPI/RubyGems arms only added | no removal | prior-family binaries not re-run beyond listener table | MET; F2/F3 are Cargo-internal gaps |

## Slice-17 defect-class checklist

- Fake dates / substitute dates: none; unparseable counts as absent (holds longer), future denied.
- Fan-out before policy: OSV is called only after the blind decision allows (`evaluate_scoped`).
- Unbounded caches/crawls: config cache cleared at 64 cells, spellings at 4096 and 4 per crate (standalone), index cap and entry cap present; service-mode spelling gap = F5.
- Case/identity mismatches: handled and tested (see coverage).
- Credential reads and shared caches: config cache gated by `cache_token`, project/absent caches gated, tests have positive controls.
- Weak assertions: none found that miss a defect; F4 is the one loose E2E assert.
- Missing wiring: portal selects, keys page, docs, certificate script all done; SPEC/CHANGELOG residue (F7).
- Tests that pass without the fix: mutation list P1-P21 is consistent with the code; P8 mislabelled (F7a); P16/P17 equivalent claims plausible.

## Verification and limits
Run (capped scope, CARGO_TARGET_DIR on disk under .probation-scratch, -j 8): `cargo test --test cargo_registry --test cargo_native --test osv_ecosystem_mapping --test credential_bearing_reads --test listener_admission` -> 21, 6 (real cargo), 4, 16, 16 passed, 0 failed. Not run: E2E-cargo (containers, disk 97% full), probation-server tests (Postgres), `cargo test --lib osv_`, clippy, mutation probes. Evidence relied on: slice-18.md, tdd-slice-18.md. Unchanged during review: yes (no source edited; only this file added).
Reviewed: src/cargo_registry/*, src/http/cargo_routes.rs, diffs of credential_read, service_registry, registry_read, artifacts/{mod,download}.rs, upstream/origins.rs (admit), store commit paths, portal/template/doc greps, tests/cargo_registry.rs (read in full), cargo_native/credential/managed_mode (relevant parts), E2E scenario.

## Next steps
1. Add the F1 selected-registry test (and the service-mode undated case from F5) before SHIP.
2. Get user decisions for F2 (descriptor field) and F3 (certificate-mode Cargo) under the no-backlog ruling; do not leave them as "decisions" in the evidence.
3. Tighten F4, fix doc residue F7.
