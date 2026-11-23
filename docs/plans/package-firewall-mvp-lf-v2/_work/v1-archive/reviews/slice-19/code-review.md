# Code review, slice 19 (Go module proxy protection, Go OSV mapping)

Verdict: FIX FIRST
Subject: uncommitted tree on slice5-native-ci, HEAD 3e8d3e4 (76 changed/untracked paths at start and end; unchanged during review).
Reviewer procedure: /home/john/.claude/skills/lf-start/agents/code-review/AGENT.md. Read-only; no source or test edited.

Requirement sources read: 04-slices.md row 19; 03-program-design.md (family table row Go line 315, LS-F6 Go row 259, OSV table line 172, item 7 of the open list); 01-product.md C1006/C1007 (as cited by the slice); evidence/slice-19.md, evidence/tdd-slice-19.md; reviews/slice-17 and slice-18 were named by the packet as the defect-class checklist only (not re-read in detail).
Fingerprints (sha256 prefix): serve.rs bc97e8f8, escape.rs 192c66d9, sumdb.rs 8889d33c, go_routes.rs c39add04, reqwest_transport.rs 5db782c8, origins.rs 259a299c, tests/go_modules.rs 54f181e9, tests/go_service_read.rs f5ee9e5b, e2e-go.mjs 06a52fb9.

## Summary

The core is sound: strict one-spelling `!`-escape with exact round trip, rebuilt URLs and file names, decoded case-sensitive policy key, no fake dates, fan-out bounded before the first call, undated and re-dated handling fail closed, credential-bearing reads use throwaway tables, the archive bucket is a fixed second origin admitted only for artifact transfers from the proxy, sumdb gets no credential. The two Go test binaries I ran pass (22 + 7). Blocking items: G19-1 (a test whose name and the evidence claim a pin refusal that nothing asserts; TOFU pinning of `.info`/`.mod`/`.zip` has no witness and no mutation probe), G19-2 (revision queries such as `go get mod@main` / `@<commit>` answer 404, undocumented and untested; needs a decision or a built path). G19-3 is a design weakness of the date source that the user should see before ship. The cold-stack 503 is not explained; candidate causes are listed with the one check that decides it (U-1).

## Findings

G19-1 — medium — test — the "zip pin" test asserts the opposite of its name; `.info`/`.mod`/`.zip` TOFU refusal is unwitnessed
Location: tests/go_modules.rs:328-339 (`a_zip_whose_bytes_change_after_the_first_download_is_refused`); tdd-slice-19.md has no probe on the pin.
Requirement/rule: slice 19 row (TOFU pin, SPEC §9), decision (2) in evidence ("a later different `.info` is refused 502"); checklist class "weak/vacuous assertions, tests that pass without the fix".
Failure or cost: the test changes the upstream zip after the first download, then asserts the second GET returns the ORIGINAL bytes. That is served from the verified store without contacting upstream, so the test passes with the pin deleted. Nothing exercises a re-download against a pinned digest for any of the three kinds, and no probe P1..P33 removes the pin. Decision (2) (pin `.info`/`.mod`, 502 on change) is therefore stated but unproved.
Evidence: read of the test; `h.registry.answer(...)` changes only the fake, the second request is a store hit (cache status Hit). Test passes in my run (22 passed).
Correction: after the first download evict the content mapping (the technique P27 already uses for reference rows) or assert the stored pins via `list_project_pins_in` for all three references, then assert a changed upstream body gives 502 for `.zip`, `.mod` and `.info`; rename the test to what it proves. Cost: a few lines, one probe run.
Blocking: yes (cheap, same class as slice 17/18 findings).

G19-2 — medium — behaviour/docs — revision queries (`@v/{branch|commit}.info`, `go get mod@main`, `mod@abc1234`) are 404 with no test or doc line
Location: src/http/go_routes.rs:40-47 and src/go_modules/escape.rs `version_of` / `valid_version` (only `v` + full SemVer is a version).
Requirement/rule: 03 family table "preserve ... Go checksum verification", row text "Go module discovery and mod/info/zip protection"; docs/operations.md says the firewall "serves exactly the module proxy protocol".
Failure or cost: the real go command resolves a branch, tag-less commit or short hash by `GET {module}/@v/{rev}.info` (proxyRepo.Stat) and expects the canonical version (usually a pseudo-version) in the JSON. Here `main.info` fails `version_of`, so `go get example.com/m@main` and `go install tool@<hash>` get 404 and, with the single protected GOPROXY, no fallback. No test names it, evidence does not list it under "Not done", docs do not say it. It is fail closed, so not a security hole, but it is silent loss of a client workflow, and by the program's rule that every capability is either built or recorded as a user decision it must not be left implicit.
Evidence: parse() path trace; grep of evidence, docs/operations.md and tests for branch/revision/@main finds nothing.
Correction: either (a) forward a revision `.info` whose element passes a bounded charset, require the answer's `Version` to be a canonical version (or pseudo-version), judge that version by its own `Time` through the same gate and serve it (cost: one more route shape, the answer's Version is not the requested name so the reference/filename check needs the canonical name; `.mod`/`.zip` then use the canonical version), or (b) record the refusal in evidence "Not done", docs/operations.md and add a test pinning 404 with zero upstream calls, and get the user's explicit yes. Closure check: a native-go test `go get example.com/m@<branch>` (success with held-version rules, or the documented failure).
Blocking: yes unless the user chooses (b) explicitly.

G19-3 — medium — design — `.info` `Time` is the VCS commit time, which the publisher controls; the cooldown is bypassable by back-dating
Location: src/go_modules/serve.rs `parse_info` and `Known::publication` (Dated::Upstream is trusted as the publication time).
Requirement/rule: 03 line 315 ("Matching info.Time or first-seen") chose this; 01-product age-delay promise.
Failure or cost: on proxy.golang.org `Time` is the commit time of the tagged revision, not the time the proxy or the firewall first saw the version. A malicious publisher tags a new commit authored with an old `GIT_COMMITTER_DATE`; `.info` says 2019, the firewall computes age years, the 7-day freeze never applies and the version is listed and served at once. The same holds for pseudo-versions (their embedded timestamp is also the commit time). npm/PyPI/RubyGems/Cargo publish times are server-set; Go's is not, so the core protection is weaker for this family and nothing in evidence/docs says so.
Evidence: protocol semantics (evidence itself says "the fixed public proxy writes it for every version"); no code path compares `Time` with first-seen for a version that APPEARS in a list the firewall had already seen.
Correction (needs the user): at minimum state the limit in evidence and docs/operations.md. A cheap strengthening that avoids holding the whole back catalogue at first sight: when a version first appears in a list of a module this firewall already recorded earlier (module known, version new), floor its date at that first-seen time (`max(Time, first_seen)`); cold-start versions keep `Time`. Cost: one more branch in `record`, a test, and a policy decision about the first-sight window.
Blocking: no for this slice if accepted and documented by the user; it must be an explicit decision, not an omission.

G19-4 — low — security hygiene — the key page and docs tell users to set `GOFLAGS=-mod=mod`
Location: crates/probation-server/templates/keys.html (Go block), docs/operations.md "Go clients" (line ~1572).
Failure or cost: nothing in the firewall or E2E-go needs it (E2E sets only GOPROXY/GOSUMDB). `-mod=mod` lets any `go build` rewrite go.mod/go.sum silently, removing Go's default `-mod=readonly` guard, in the environment of every developer who copies the lines. A firewall page should not weaken a client default.
Correction: remove the line (or explain a concrete need). Cost: none. Blocking: no.

G19-5 — low — design consistency — archive origin read from the live snapshot, config key cannot hold a prefix, redirect not limited to zip
Location: src/artifacts/download.rs `go_archive_origin` (reads `app.service_policy().snapshot()` at transfer time; the Cargo path uses `principal.registry_archive_origin`); src/config.rs `upstream_origin` (path must be `/`), src/upstream/origins.rs `admits_archive_redirect`.
Failure or cost: (a) the download leader's archive origin comes from the current snapshot while the request was admitted under its principal's; a snapshot flip mid-request can differ (the handler's recheck makes the request 503 in the selected route, so it fails closed). (b) an operator override of `go_artifacts_url` cannot carry a path prefix, so it admits the whole host, while docs say "origin and path prefix". (c) the artifact client admits the redirect for `.info` and `.mod` as well as `.zip` (docs/evidence say zip).
Correction: pass the principal's value like Cargo; document (b) and (c). Blocking: no.

G19-6 — low — identity — `+incompatible` is part of the policy version
Location: crates/probation-policy/src/names.rs (`CanonicalVersion::Go` keeps build metadata); serve.rs `policy_version`.
Failure or cost: the proxy serves a non-modular major tag only as `v2.0.0+incompatible`; an operator block or exception typed `2.0.0` (the spelling most advisories use) does not match it, while OSV matches both (canary). Fail-open only for hand-written blocks of those modules.
Correction: document in the portal block form/operations doc that Go blocks for non-modular majors need `+incompatible`, or match a block without build metadata against both. Blocking: no.

## Uncertainties

U-1 — the one cold-stack 503 on `.info` (E2E-go first run). PLAUSIBLE causes, none establishable from the kept evidence (no log, and `go` prints the body of a non-200 as `server response:`, which was not kept):
- `ApiError::CapacityExhausted` (503): `open_or_download` maps a failed `open_verified` and any content `Capacity` error to 503 (src/artifacts/mod.rs:424-431, 508-511). The host had a release image build and the Postgres suite running with 91% disk; a content-store reserve/free-space check failing on the first transfer of a cold store is the most consistent environmental cause (not Go specific).
- `ApiError::Overloaded` from `store critical` queue `Busy` (src/store/mod.rs:704) in `record`/`get_reference`, or `Limits::download_permit` waiter timeout; Go adds writes on every freshness miss (`resolve` -> `record` -> `commit_request_references_in`, plus up to 64 sequential `get_reference` per list) and three downloads per version, so it is more exposed under load than the other families.
- `ApiError::LookupBusy`/`NotReady`/`StorageUnusable` at `admit` (src/http/mod.rs:210-243) during cold key-table load while `go` issues parallel requests.
- A first-seen/persist race is NOT supported: `record` is a single upsert, `resolve` has no check-then-insert, and the 24-client back-to-back test passes (re-run here).
Deciding check: make the E2E harness keep the `go` stderr/body and the firewall decision line (error_code is distinct: CAPACITY_EXHAUSTED, OVERLOADED, LOOKUP_BUSY, NOT_READY, STORAGE_UNUSABLE, POLICY_UNAVAILABLE) for any non-200, then rerun the cold stack once under the same load. Owner: slice author. Not a Go-logic defect on current evidence.

U-2 — `.info`/`.mod` pinned by TOFU digest (decision 2). A legitimate upstream change of the same version's bytes (Athens re-dating an undated module, an `Origin` field change, a mirror switch) is a permanent 502 for that file once its stored copy is evicted, because the pin is permanent. While the copy is stored the old bytes are served. Frequency on proxy.golang.org is believed near zero (immutable proxy contract); on Athens/Artifactory unknown. Deciding input: user choice already listed as decision 2 (pin zips only vs all three); add G19-1 coverage so the behaviour is at least tested. Fail closed, so acceptable if the user keeps it.

U-3 — credentialed-read persistence: `record` stores `publication_micros` learned through a credential-bearing private read in the registry-scoped reference row (registry id in the key, so tenant-scoped). Same pattern as slices 17/18; I did not find a cross-tenant path.

## Requirement coverage

| Requirement and source | Implementation/connection | Expected -> observed | Check and limits | Status |
|---|---|---|---|---|
| list, @latest, .info/.mod/.zip routes (row 19) | go_routes.rs, serve.rs, router in http/mod.rs, shared-service rewrite | all five shapes routed, read-only | go_modules 22 + go_service_read 7 pass; go_native not rerun | MET (revision `.info` excluded, G19-2) |
| `!` escape strict, round trip | escape.rs `escape`/`unescape`, parse() | one spelling per module/version, other spelling 404 before upstream | read of code + P1-P3 kills; real go mixed-case test | MET |
| gate mod/info before zip, all three together | `reference_for_version` -> `locally_blocked` -> `resolve` -> `serve_artifact_in` | held version's three files 403, `.mod`/`.zip` not fetched | tests + E2E-go assert | MET |
| 64-.info cap, undated withheld, no fake date | judged_list `take(LIST_INFO_CAP)`, `Dated::Undated`, first-seen | cap decided before first call; next request dates rest | exact-64 test, undated test | MET |
| TOFU pin of the three files | shared artifact pipeline, `expected: []` | different later body refused | no test proves it (G19-1) | UNKNOWN |
| Time source | `parse_info` | read, never invented | works as spec'd; weak source (G19-3) | MET to spec; risk open |
| 302 to bucket as fixed second origin | origins.rs `admits_archive_redirect`, transport `archives` flag | artifact transfer from proxy only, not list/info (metadata client), credential not forwarded | origin_guard tests + P28-P32 + live test (opt-in, not rerun) | MET |
| sumdb forwarding | sumdb.rs | public registry only, no credential, db name = host, grammar-checked | tests + E2E 3 requests no auth | MET |
| archive_origin for Go (migration 0017) | service_policy.rs, registries.rs, download.rs | Go with target may declare one | server suite per evidence; migration read: drops by definition, re-adds check | MET (G19-5 notes) |
| GOPROXY write refusal | service_registry.rs, go_routes `reads_only` | non-GET/HEAD 405/404, nothing upstream | tests + E2E | MET |
| `+incompatible` / `v` for OSV and policy | `policy_version`, `CanonicalVersion::Go`, osv_key | OSV gets `1.0.0+incompatible` | go_names tests, canary recorded | MET (G19-6) |
| OSV mapping `Go`, F12 cases | batcher.rs, osv/mod.rs tests | per-family case references `Ecosystem::Go` | osv_ecosystem_mapping, lib tests per evidence | MET |
| C1028 family case | credential_read.rs GO rules, `cell_for` throwaway table | no shared table read or written | tests per evidence; go_service_read passes here | MET |
| wiring: portal registries/policy/keys, cert script, fleet keys, SPEC, CHANGELOG, docs, sample config | diffs read | every list that names Cargo also names Go (grep of src/crates/docs/tests: only install.md/backlog.md unrelated) | G19-4 on keys page text | MET |
| E2E-go | e2e-go.mjs | comments match asserts; write verbs accept 404 or 405 (loose by design) | not rerun (needs the stack) | MET (not rerun) |
| cold-stack 503 explained | none | no cause | U-1 | UNKNOWN |

## Conventions and simplifications

- escape.rs is clean and small; `valid_module_path` requiring a dotted first element is sound and documented (decision 3).
- `Known.checked`/TTL, bounded `MAX_DOCS`/`MAX_DOC_VERSIONS` tables are bounded; eviction `retain(strong_count > 1)` is correct for idle cells.
- Mutation probes: P1-P3, P5, P7-P12, P14, P16, P18-P25, P27-P33 each name a killing test and are credible. Probes do NOT cover the pin (G19-1), `locally_blocked` precision (P4/P33 changed the reason, accepted), or the sumdb db-name branch beyond P14. The "written after the code, red not observed" admission for go_modules.rs/go_native.rs is honest; apart from G19-1 the probes do cover the behaviours tested.
- P26 (membership `version_ok`) survived as an equivalent mutant; accepted.

## Verification and limits

Run by me (capped scope, existing CARGO_TARGET_DIR under .probation-scratch): `cargo test -j 8 --test go_modules --test go_service_read` -> 22 passed, 7 passed. Not rerun: go_native (needs go 1.26), E2E stack, server suite (Postgres), live witness, clippy; relied on tdd-slice-19.md "Verification" for those (commands, identity not independently re-matched).
Reviewed paths: src/go_modules/*, src/http/go_routes.rs, diffs of src/upstream/{origins,reqwest_transport,mod}.rs, src/artifacts/{mod,download}.rs, src/http/{mod,logging,credential_read,registry_read,service_registry}.rs, src/config.rs, src/osv/batcher.rs, src/managed/report.rs, crates/probation-policy/src/{names,osv_key}.rs, crates/probation-server (migration 0017, service_policy, portal registries/policy/certificates, templates), tests/go_modules.rs (key tests), tests/go_service_read.rs (names), e2e-go.mjs, SPEC/CHANGELOG/docs diffs. Not read line by line: tests/go_native.rs, tests/credential_bearing_reads.rs Go cases, fake go.mjs, the server crate tests.
Lenses with no finding: removed behavior (only additions), callers/wrappers, efficiency (list cost O(versions) per request is acceptable at measured sizes), cleanup/lifetimes (no new lock held across the store except `list_gate`, intentionally).
Unchanged during review: yes (git status 76 paths before and after, HEAD 3e8d3e4).

## Next steps

1. Fix G19-1 (assert the pin for all three kinds with an eviction or pin-table check; add a probe that removes the pin).
2. Decide G19-2: build revision `.info`, or record the refusal in evidence/docs with a 404-pinning test and the user's "this removes X" yes.
3. Put G19-3 and decision (2)/U-2 in front of the user; at least document the commit-time limit.
4. Drop `GOFLAGS=-mod=mod` (G19-4); optionally G19-5/G19-6 doc and consistency fixes.
5. Make E2E keep the non-200 body and decision line, rerun the cold stack once to close U-1.
A re-review by a new reviewer after 1-2 should be bounded to G19-1, G19-2 and the touched tests.
