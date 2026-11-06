# Active Slice 3 TDD

The original certificate-era TDD record is preserved byte-for-byte in [tdd-slice-3-certificate-history.md](tdd-slice-3-certificate-history.md). Recovery is bound to the captured clean pre-task status and Git blob in `.scratch/slice3/baseline/tdd-history-recovery.json`.

Approved seams: local selected-registry HTTP/npm operations and durable action-lease store operations, from the active Slice 3 witness in `04-slices.md` and the active local-client contracts in `03-program-design.md`. Existing certificate-era action coverage remains historical.

Baseline: `.scratch/slice3/baseline/`; test/build temporary files use disk-backed `.scratch/slice3/tmp`. Initial E2E sandbox/runtime startup failures are infrastructure failures, not behavioral RED evidence.

tdd: local-service npm publish — red: npm error 405 Method Not Allowed - PUT https://fw-standalone.e2e.test/registry/npm/2/service-publish-a5c276c1 - METHOD_NOT_ALLOWED — green: node tests/e2e/harness/run.mjs --only E2E-publishing-npm-actions passed

Cycle 1: `.scratch/slice3/red-actions-lowcpu2.log`, `.scratch/slice3/green-publish.log`; GREEN 1 passed, 0 failed, 0 notrun. Compiler: `.scratch/slice3/check-publish.log` (`cargo check --workspace`, PASS). This first scenario covers publish only; subsequent cycles strengthen the same acceptance scenario.

tdd: write_preflight_commits_a_service_scoped_reference — red: write preflight must advertise a durable service reference; left: 404, right: 200 — green: cargo test --test service_unpublish passed

Cycle 2: `.scratch/slice3/red-service-unpublish2.log`, `.scratch/slice3/green-service-preflight.log`, `.scratch/slice3/check-preflight.log`; 1 passed, 0 failed. The earlier attempt used a reqwest JSON convenience method absent from the pinned features and failed compilation; that attempt is not behavioral RED.

tdd: service_removal_verifies_revision_and_consumes_once_before_send — red: wrong revision: revision; left: 405, right: 404 — green: cargo test --test service_unpublish passed

Cycle 3: `.scratch/slice3/red-service-removal.log`, `.scratch/slice3/green-service-removal3.log`, `.scratch/slice3/check-removal.log`; 2 passed, 0 failed. The matrix exercises accepted response revision, authenticated GET fallback, unavailable/inconsistent GET, malformed/invalid revision, upstream denial, unchanged version, durable marker failure, wrong revision, concurrent consume and replay. Intermediate GREEN attempts corrected two test expectations using existing error/store contracts: partial writes are HTTP 503, and the deliberately disappeared-lease corruption fixture poisons store health, so later DELETEs also refuse 503 with zero I/O. Product behavior was unchanged for both corrections.

tdd: scoped_action_routes_decode_once_and_preserve_selected_identity — red: scoped write preflight: @scope%2fexample; left: 404, right: 200 — green: cargo test --offline --test service_unpublish --test shared_service passed

Review regression: `.scratch/slice3/red-scoped-action.log`, `.scratch/slice3/green-scoped-focused.log`; 3 service-unpublish and 4 shared-service tests passed. `PackageName::parse_route` expects already decoded router components; the new middleware had passed raw escaped URI text. The shared URI-package guard now decodes once with strict UTF-8 using the already locked percent-encoding 2.3.2 implementation, then delegates existing package validation. Original routing bytes are preserved. Positive lower/uppercase escaped scope separators and escaped `@` match the exact selected upstream name; malformed, double-escaped, traversal, extra-separator, backslash and invalid-UTF-8 cases make zero upstream calls.

The production-quota fixture is additional acceptance evidence over unchanged quota logic; no RED was observed and no TDD cycle is claimed for that fixture. Its dedicated PASS and later ignore annotation are recorded in `slice-3-engineering.md`.

tdd: production_service_registry_global_quota_plus_one_preserves_every_row — red not observed

tdd: sealed_foreign_reference_with_valid_marker_refuses_before_send — red not observed

The foreign-reference case is adversarial acceptance characterization of an existing guard, not a claimed behavioral TDD cycle. `.scratch/slice3/foreign-reference-focused2.log` passes all 4 service-unpublish tests. It seeds a correctly service-sealed, identity-bound foreign destination and valid marker despite a legacy bearer-forwarding scope, then observes explicit destination refusal, zero transport calls and an unconsumed marker. Its first attempt failed fixture key-path setup before behavior; correcting the fixture to use the configured data directory required no product edit.
