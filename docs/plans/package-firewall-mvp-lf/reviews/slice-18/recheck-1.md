# Recheck 1: slice 18 (Cargo) follow-up round

Verdict: CLEAN (no open security property; no blocker; five low or info items, none required before SHIP)
Subject revision: uncommitted working tree on slice5-native-ci, HEAD 707ff3d. Procedures: /home/john/.claude/skills/lf-start/agents/code-review/AGENT.md and security-review/AGENT.md. Inputs read: reviews/slice-18/code-review.md and security-review.md (prior), evidence/slice-18.md ("Follow-up round"). tdd-slice-18.md does not exist under that name in the plan directory (not read). Source read in full: src/http/cargo_routes.rs, src/cargo_registry/serve.rs (origins_for, upstream_config, current_project), diffs of src/artifacts/{mod,download}.rs, src/managed/service_policy.rs, src/upstream/origins.rs, src/http/service_registry.rs, crates/probation-policy/src/api.rs, migration 0016, crates/probation-server/src/{service_policy.rs,portal/registries.rs}, upstream/reqwest_transport.rs `send_action`/`selected_within`, registry_read.rs `service_principal`.
Not re-run: probation-server tests (need Postgres; read only), E2E (containers, disk 97%), mutation probes.

## Prior findings

| ID | Status | Evidence |
|---|---|---|
| F1 selected-registry reads | CLOSED, guarded | tests/cargo_service_read.rs `selected_registry_reads_index_and_downloads_under_its_own_prefix` (index, config, download via /registry/cargo/7/, unqualified root) and `..._dl_outside_its_prefix_is_refused_with_502` (3 spellings, asserts nothing fetched). Would fail if the Some branch, admit or prefix check regressed. |
| F2 / F3 (decisions) | F2 built (archive_origin, below); F3 certificate mode is key-auth by decision, documented | not re-opened |
| F4 decision-log assert | CLOSED, guarded | e2e-cargo.mjs:143-146 now requires a decision for the held and the blocked crate with package, version, status 403 (E2E not re-run) |
| F5 service-mode cap and undated | CLOSED, guarded | `service_mode_commits_at_most_four_spellings_of_a_crate` (5th spelling 404 and zero upstream calls; code: cap runs before the service early return) and `service_mode_undated_version_waits_on_first_seen` (clock 0/6/8 days). Both pass. |
| F6 / L3 cost | CLOSED, guarded | 5 s share; test counts index fetches (1 for four plain reads, 2 after 10 s, +3 for credentialed reads that neither read nor fill) |
| F7 docs, P8 | CLOSED | SPEC.md and CHANGELOG.md name cargo_upstream_url, cargo_artifacts_url and the Cargo clients; keys.html: "uv and Poetry..." (line 24) precedes the Cargo block (line 29). P8 label withdrawn per evidence (not re-run). |
| L1 spelling cap ceiling | ACCEPTED (ledger), unchanged | process-local, ponytail comment present |
| L2 login_url challenge | CLOSED, guarded | `challenge()` now maps `Unauthenticated` and `UpstreamUnauthenticated` on the selected handlers (id parsed from the path) ; test `service_mode_upstream_401_carries_the_cargo_login_challenge` asserts both /cargo/ and /registry/cargo/7/ carry `Cargo login_url=".../registry/cargo/7/"` and a 403 carries none. Fails without the fix. |

## Security properties (new boundary code)

| Property | Result | Evidence |
|---|---|---|
| W1 caller's token goes only to the registry's own origin, never the service key | closed | `forward_api`: `credential` is the caller's Authorization header only; `send_action` authorization = that value; the service snapshot carries `registry_read_authorization: None` and `service_principal` replaces it with the caller's header, so there is no service-held registry secret to leak. Test asserts the registry saw only the caller token and never the `prb_` key. |
| W2 401 before any lookup / permit | closed | writes return 401 before `admit_cargo`; test asserts zero upstream calls for five shapes |
| W3 name and version validated before upstream | closed | `valid_crate_name` on segment 3 (percent-decoded by Path, so `a%2Fb` is refused), `semver::Version::parse` plus MAX_VERSION on yank/unyank; test: `a.b`, `1.0`, `owners/x` give 404 |
| W4 hostile config.json cannot steer the API root | closed | `own_api_root` requires same scheme, host and port as the registry origin (or https crates.io:443 for index.crates.io), no userinfo, query, fragment. Userinfo trick (`https://reg@evil`) parses to host evil and is refused; trailing-dot or IDN variants differ and are refused (fail closed). Then `send_action` builds an OriginSet from the root and `admitted` re-checks the URL under it; the denylist and connect-peer check apply. Test: config naming evil.invalid gives 502 and no write. |
| W5 redirects | closed | `send_action` uses `redirect::Policy::none()` and `refused_redirect`; a 3xx is an error, never followed |
| W6 header and query allow-lists | closed | upstream request carries only Accept (fixed), Authorization, Content-Type (<=256), Content-Length; query only on search, keys q, per_page, page, sort, category, keyword, letter, <=1024 bytes (test: `evil=1` dropped); other queries are 404 in `classify_selected_registry` |
| W7 credential-bearing reads never cached | closed | `record_request_scoped` before any fetch when a credential is present; config.json is fetched uncached (`fetch_metadata` with no validators); responses carry no cache state; `authorization_read_once` reviewed-site entry for `fn forward_api` count 1 matches the single `get(header::AUTHORIZATION)`; the test passes (4 passed) |
| W8 size cap | closed with note N1 | Content-Length over cap gives 413, streamed total counted; test 500 bytes gives 413 |
| A1 archive_origin wire and old enforcer | closed | `#[serde(default, skip_serializing_if)]`; archive_origin_wire test; an old enforcer drops the field and keeps requiring archives under the target (fails closed) |
| A2 migration and column | closed | nullable, CHECK only a cargo registry with a target, length <= 2048; ecosystem_tags test inserts two violating rows and asserts rejection |
| A3 activation validation | closed | `validate`: <=2048, Cargo only, target present, parse, `check_target` (denylist incl. mapped IPv6), `selected_npm_with_private` (https, no query), plus `check_hostnames` resolution for the archive host; any failure rejects the whole snapshot. service_policy_cache test: ten shapes (http, userinfo, query, fragment, loopback, metadata IP, mapped loopback, npm, no target, garbage) all rejected; ordinary one accepted (30 passed) |
| A4 portal route | closed | POST /org/{org}/registries/{id}/archive-origin: `signed_in_post` (CSRF), `org_place`, `admin_on`, shape rules, UPDATE scoped by org_id, ecosystem cargo, target present, live row. Test (read, not run, needs Postgres): set, clear, five refused shapes, npm refused, foreign org admin refused |
| A5 credential to archive origin | closed | `serve_artifact_in`: archive authorization only when `origin.origin() == archive.origin()`, else None; download uses the archive as selected origin (denylist and private CIDRs of the registry apply). Stale reference rows (archive changed or cleared) fall back to the target origin, which does not admit them: fail closed. |
| A6 SSRF via archive_origin | closed | admin-controlled but bounded: https only, denylist at activation and at connect time (GuardedResolver with the service denylist), private ranges only inside the registry's approved CIDRs, redirects same-origin policy. Same trust level as `target_url`. |
| S1 5 s shared index | closed | `shareable = cache_token(app).is_some()` gates both read and fill (false for credential-bearing and for no request context); credential-free reads fetch with no read authorization (principal's is None), so the shared project holds public data only; key (registry id, origin, lower-case crate) includes the exact spelling; spelling cap runs before it; policy is evaluated per request on top of the project, so staleness is at most 5 s of upstream data, not of policy; map cleared at 256. Test covers fill, expiry, credentialed bypass without fill. |

## New findings

N1 low, availability (parity with RubyGems/PyPI upload): `forward_api` fetches config.json from the registry (with whatever Authorization the caller sent, even a junk one) before the Content-Length 413 check and before reading the body, and no read timeout exists on the request body (no TimeoutLayer anywhere in src). Scenario: a client on the service's network sends `PUT .../crates/new` with `Authorization: x` and `Content-Length: 10 GiB` (or dribbles a body): one upstream config fetch per request, and a permit plus tempfile held while the body trickles. Bounded by the admission permits; no confidentiality impact. Correction (optional): check Content-Length before the config fetch; a body read timeout is a family-wide item.

N2 low, functional: the portal registry list (SELECT in portal/registries.rs:131) does not show the stored archive origin, and the field is rendered for every ecosystem (a non-Cargo submit is answered not found). An admin cannot see or audit the current value, only overwrite or clear it. Correction: show it on Cargo rows. Test gap: the portal test only asserts the label "Archive origin".

N3 low, hardening: `selected_download_inner` recheck compares fingerprint, origin, trust, CIDRs and read authorization but not `registry_archive_origin`; a snapshot that clears or changes it between admission and delivery does not fail an in-flight download. Impact is one download already admitted under the earlier snapshot. Same for `forward_api` (does not compare the credential-bearing state, which is per request anyway).

N4 info, hardening: `own_api_root` pins scheme, host and port only, not a path prefix, so the caller's token can go to any path on the registry's host that the registry's own config.json names. This is the registry's own host (the operator selected it); only on a multi-tenant host (for example static hosting) could one tenant's config.json steer another tenant's token to a path of the same host, and no third-party host is reachable. Accept; document if a shared-host registry is ever supported.

N5 info, test coverage: the write-forwarding tests use a fake transport, so redirect refusal (W5) and the connect-peer check for the action path are proven by code reading and by the transport's shared `refused_redirect`, not by a Cargo test. Add one real-transport test with a 307 from the API host if wanted.

## Verification
Run, capped scope, CARGO_TARGET_DIR on disk under .probation-scratch, -j 8: `cargo test --test cargo_service_read --test cargo_service_write --test authorization_read_once --test listener_admission --test service_policy_cache` gave 8, 3, 4, 16, 30 passed, 0 failed (exit 0). Not run: probation-server tests (Postgres), E2E, clippy, mutation probes. Source and tests unchanged by this review; only this file was added.
Not examined: Cargo write behaviour of real crates.io (E2E only, recorded), certificate-managed mode (no API routes by design; E2E pins 404, not re-run).

## Next steps
None blocking. Optional before SHIP: N1 (Content-Length check before the config fetch), N2 (show archive origin in the portal). Record N3-N5 in the ledger.
