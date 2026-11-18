# Code review
Verdict: FIX FIRST
Scope: slice 28 (partial delivery) in the dirty tree on slice5-native-ci vs 04-slices.md row 28, 03-program-design.md LS-F1/F3/F4/F7/F8/F9/F10/F12/F15/F16, evidence/slice-28.md and tdd-slice-28.md. Read-only; no base/head, working tree only.
Summary: Wiring is real and the tests are mostly meaningful. One confirmed D5 gap (R28-1, wildcard-bound listener) and one open decision (R28-2, loopback Host exemption) block row closure. R28-3 to R28-8 are non-blocking. Row 28 stays open for the items the evidence lists as not delivered, plus two it does not list (see Coverage).

## Findings

R28-1 - medium - security - own-listener denial misses a wildcard-bound listener and hostname targets
Location: src/http/service_connector.rs:117-146 (`check_target`), :62-70 (`denies` ignores `listener`); wired from src/managed/service_policy.rs:623 and src/main.rs:192.
Requirement/rule: row 28 closure "descriptor naming loopback, link-local or its own listener rejected before activation" (D5); LS-F9.
Failure: the listener check compares the target IP with `listener.ip()` for equality. A deployment binding `0.0.0.0:P` or `[::]:P` (the normal non-loopback bind) never matches `https://<host-ip>:P`. A hostname that resolves to the host's own non-loopback address passes at activation, and the connect-time `Denylist::denies` has no port and no listener, so it passes there too. Either descriptor can dial the enforcer's own listener.
Evidence: code reading. tests/service_connector.rs:90 and tests/service_policy_cache.rs:703 only use a specific bind address (203.0.113.5:8080). No wildcard-bind case exists.
Correction: when `listener.ip().is_unspecified()`, treat any local interface address, and loopback, with the listener port as own-listener. Add a connect-time check of the resolved address plus port against the listener for hostnames (the resolver has port 0, so check at the connector). Add wildcard-bind and hostname cases.
Blocking: yes (closes D5).

R28-2 - medium - security - Host check exempts loopback peers (known open decision)
Location: src/http/service_registry.rs:35-37.
Requirement/rule: 03 LS-F10 and the "Configuration, data and platform contract" paragraph say to validate Host against public_url with no loopback exemption.
Failure: the machine default is a loopback listener, so the exemption disables the Host check exactly where DNS rebinding (a browser reaching 127.0.0.1 with `Host: attacker.test`) applies. The check is real for CIDR peers, which cannot spoof the TCP peer, so only the exemption is weak.
Evidence: tests/listener_admission.rs `listener_host_checked_at_the_http_boundary` only covers the 10.1.2.3 peer. The evidence file flags this as a deviation.
Correction (recommendation for the user decision): keep the check for every peer. For loopback peers also accept the loopback literals and `localhost` with the listener's own port, in addition to public_url. Local clients that send `127.0.0.1:port` then keep working, rebinding hosts are refused, and 03 needs one sentence added. A bare exemption leaves rebinding open.
Blocking: pending the user decision.

R28-3 - low - efficiency/doc - SHA-1 recomputed by re-reading the whole temp file on the async worker
Location: src/artifacts/download.rs, `fetch_request_scoped` (the `sha1` block after `temp.into_file()`).
Failure: the comment says SHA-1 is computed "only in that case" (advertised), but the code always does it. Every credential-bearing artifact is read a second time, synchronously, on a tokio worker. `TempFile::write` (src/http/credential_temp.rs, `write`) also uses blocking `write_all` per chunk. Large wheels and tarballs stall a worker.
Correction: update SHA-1 in the streaming loop as the normal path does, and drop the re-read. Move writes to `spawn_blocking` or `tokio::fs`.
Blocking: no.

R28-4 - low - tests - route inventory test never checks the R/W/X class
Location: tests/listener_admission.rs, `ROUTE_TABLE` and `route_inventory_equals_classified_table`.
Failure: the third column (class) is dead data. The test parses `package_router` source text and compares only paths and verbs. A route reclassified, or a W route that loses its credential check, passes. The row names this test as the closure for the R/W/X table. `upstream_write_without_credential_is_refused` covers only 3 of the W rows.
Correction: drive every W row through `from_peer` and assert 401 with no upstream call. Drop the class column or assert it behaviourally.
Blocking: no (coverage gap).

R28-5 - low - behaviour change not recorded in the plan; 401 branch untested
Location: src/artifacts/mod.rs:469-480 (`service_download_error`), src/http/error.rs:212.
Failure: "upstream 401/403 on an artifact maps to 401/403 in service mode" is consistent with the metadata mappings (src/npm/mod.rs:764, src/pypi/mod.rs:613, src/http/token_packument.rs:86, registry_routes.rs:527), so the direction is right. Three gaps remain. Neither 03 nor 04 mentions it, so it needs one line in 03. The 403 reuses `ApiError::Blocked` (code BLOCKED), which a client cannot tell from a policy block. The 401 body says "a valid API key is required", which reads as a Probation key rather than the registry credential. The tests assert only the 403 (FakeRegistry), never the 401 on an artifact.
Correction: add the 03 sentence, add a 401-on-artifact case, and consider a distinct code or reason string.
Blocking: no. No parity loss: a previously 502 response now reports the real cause.

R28-6 - low - tests - detection test duplicates the production allow-list
Location: tests/credential_bearing_reads.rs:15-18 defines its own `NPM` rules; production uses `FamilyReadRules::NPM`. src/http/service_registry.rs:53 always passes `extra_pseudo_headers: &[]`.
Failure: drift between the test copy and the production const goes unnoticed. The pseudo-header branch is unreachable on the real path (axum is built with http1 only), so the "pseudo-header" requirement is met only at library level.
Correction: use `FamilyReadRules::NPM` in the test. Note the HTTP/1-only assumption in 03.
Blocking: no.

R28-7 - low - robustness - unknown-ecosystem degraded state is lost on restart
Location: src/managed/service_policy.rs `load` (floor and snapshot restore, about :140-170); `unavailable` and `skipped` are reset to empty.
Failure: the persisted snapshot already has the unknown registries and rules removed, so after a restart `/health/ready` shows no degraded registry and a zero skipped counter until the next successful poll. Requests still refuse (404), so enforcement is unaffected. Plausible, low.
Correction: persist the two values in the envelope as additive optional fields, or accept and document it.
Blocking: no.

R28-8 - low - credential_temp sweep skips directories with no lock file
Location: src/http/credential_temp.rs, `sweep`.
Failure: a crash between `create_dir` and creating the `lock` file leaves a directory the sweep never removes (`open(lock)` fails, then `continue`).
Correction: remove an empty or lock-less directory older than the process start. Low.
Blocking: no.

## Requirement coverage
| Requirement | Connection | Result | Status |
|---|---|---|---|
| LS-F1 only snapshot 401/403 is a refusal | `sync_once` (service_policy.rs:~281) matches 401/403 only; a 404 falls through as a structural error. OSV side is row 30. | `snapshot_404_is_not_an_authority_refusal` | MET (snapshot side) |
| LS-F8 monotonic floor, digest, reset command | `ActiveRevision` in the envelope; `activation_order` is called from `sync_once`; `ResetRevisionFloor` is wired in main.rs; the digest is a canonical re-serialisation | cycle 1/2 tests re-run green (26/26) | MET. Operator docs for the command not found (R28-9 below) |
| LS-F3 unknown ecosystem degrades only itself | `classify_snapshot`, readiness JSON, health counter | `activation_unknown_ecosystem_*`, `readiness_reports_*` green | MET, with R28-7 |
| LS-F7 bounds | `validate` (256 registries, 64 CIDRs, 10k rules per layer, depth 16, strings 2048) | at-limit and over-limit test | MET. The 100k total bound has no test (unreachable, disclosed) |
| LS-F9 / D5 denylist at activation, connect and redirect | `check_target`; `GuardedResolver::with_denylist`; `ReqwestTransport::with_denylist` set in main.rs only in service mode | service_connector 15/15 green | NOT MET for own listener on a wildcard bind (R28-1) |
| LS-F10 peer admission, Host, CIDR floor | `respond` uses `peer_admitted` and `host_admitted`; the floor is in config | listener_admission 11/11 green | MET for non-loopback peers. Loopback exemption deviates (R28-2) |
| LS-F4 / C1028 credential-bearing reads | `classify_read` sets a log flag; `open_or_download` branches to `fetch_request_scoped` (no content store, no single-flight, temp file); the `absent` cache write is skipped in service mode | credential_bearing_reads 2/2: A is not served to no-credential or B, unknown header forces its own request, the shared store stays empty | MET (npm and PyPI artifacts). The metadata claim ("already request-scoped") is from the evidence, not independently traced |
| LS-F16 temp files | `CredentialTemp::open` in `App`, unlinked temp files, lock-file sweep, gauge in readiness | credential_temp 10/10 | MET, with R28-3 and R28-8 |
| LS-F15 config | `RawServicePolicy::validate` | tests in service_policy_cache | MET |
| LS-F12 server side | migration 0015; `set_osv_scope`; portal route and form; wire field | server tests only reported in the evidence (not re-run, needs Postgres) | MET per evidence (UNKNOWN by my run) |
| Row: FIX-16-A cases extended to the common route in tests/managed_delivery_authority.rs | the file is unchanged in the tree; shared_service.rs covers some `/npm/` paths | not listed under "Still not delivered" | UNKNOWN |
| Row: documented operator reset command | the command exists; no doc found outside plans | | UNKNOWN |
| Row: osv_scope migration "rollback/refuse" test | only additive and reopen-old-rows is tested | | UNKNOWN |
| Row: E2E scenarios, record_refusal typed API (row 30), TCP-level listener (row 26) | disclosed as not delivered; E2E is another agent's work | | NOT MET (known) |

R28-9 (documentation, low): `reset-revision-floor` has no operator doc outside the plans; add it to the operator or runbook docs the row calls "documented".

## Checks on the questions asked
- Wiring: every new module is reachable from a real request or startup path. Evidence: service_registry.rs:31/53, artifacts/mod.rs:360, lib.rs:343, service_policy.rs:302/623, main.rs:192, crates/probation-server/src/service_policy.rs:58/80. No dead module found. `plain_ready` keeps a now-unreachable service_policy branch (cosmetic).
- Tests are not vacuous: the red-first claims are plausible. Stubs were compiled first and the reds are assertion failures with line numbers. The two mutation probes (policy.rs `insert_change`, portal handler) are the strongest evidence. The cases marked "red not observed" are disclosed. LS rows requiring "each named LS test observed red first" are therefore unmet for: `config_service_key_rejects_control_non_ascii_and_overlong`, `forged_x_forwarded_for_*`, `listener_host_checked_at_the_http_boundary`, `snapshot_order_*`, `connector_refuses_rebinding_between_resolutions`, and the accept-path guards. These need red witnesses or an explicit waiver.
- Edited existing test `shared_http_cold_warm_selected_and_legacy_authority_changes` (tests/shared_service.rs:~470): legitimate. LS-F8 now rejects an equal-revision, different-digest snapshot, which a real server never sends. The bump applies only to the `deny` change and the assertions are unchanged. The `rate` change stays at an equal revision, which is consistent with `activation_equal_revision_rate_change_is_accepted` (rate is outside the digest). No coverage is lost; managed-mode `same_revision_authority_payload_invalidates_prepared_response` is untouched.
- Parity: no output field, option or capability dropped. Intentional tightenings are all plan decisions: 404 no longer a refusal, key trimmed once, `server_url` must be an origin, CIDR floor, 256-registry bound. The 256 bound makes an org with more than 256 registries stall on its last snapshot; confirm the portal create path enforces it.

## Verification and limits
Run (each under `systemd-run --user --scope -q -p TasksMax=512 -p MemoryMax=16G -- timeout 900 cargo test -j 8 --features test-support`, repo target/ on disk): `--test service_policy_cache` 26/26, `service_connector` 15/15, `listener_admission` 11/11, `credential_bearing_reads` 2/2, `credential_temp` 10/10, `shared_service` 5/5. Not run: probation-server tests (need Postgres), clippy, E2E, the full `--lib`. I rely on the evidence file for those. Nothing was modified in the tree; the only file written is this report. Mutation probes were not repeated.
Not independently traced: metadata request-scoping for credential-bearing reads; portal session behaviour.

## Next steps
1. Fix R28-1 and add wildcard-bind and hostname cases.
2. Decide R28-2 (recommendation above) and amend 03 accordingly.
3. Add the missing 03 sentence and a 401 artifact test (R28-5); strengthen the route inventory test (R28-4).
4. Resolve the UNKNOWN row items (common-route cases, operator doc, migration refuse test) or list them under "Still not delivered".
5. Provide red witnesses or a waiver for the "red not observed" LS tests before row 28 closes.
