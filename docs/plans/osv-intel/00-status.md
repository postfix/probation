# Status: OSV vulnerability intelligence

- Gate 1 — Product: APPROVED 2026-09-27
- Gate 2 — Architecture: APPROVED 2026-09-29
- Gate 3 — Program Design: APPROVED 2026-09-29
- Gate 4 — Slice plan: APPROVED 2026-09-29

## Factory settings

- presentation: auto

## Loop signal

{"generation":19,"boundary":null,"reopened":false,"history":[]}

## Slices

- [x] Slice 1 — tracer bullet: wire `osv::OsvClient`/`osv::evaluate`/batcher end to end through `artifacts::serve_artifact`, plus config keys and the five deferred invariant specs
  - proof: cargo test --lib -- osv:: policy:: config:: && cargo test --test config_validation -> 33 passed, 0 failed; 25 passed, 0 failed; reviews: qa=VERIFIED, code-review=SHIP, security=CLEAR
- [x] Slice 2 — extend `osv::evaluate` to npm/PyPI resolve and the artifact download path
  - proof: cargo test --lib -- npm:: pypi:: artifacts::download && cargo test --test decision_log_delivery -> 36 passed, 0 failed; 31 passed, 0 failed; reviews: qa=VERIFIED, code-review=SHIP, adversarial=PASS
- [x] Slice 3 — e2e coverage proving OSV-only (non-blocklist) malicious matches refuse a real `npm install`, wiring a `wiremock` stand-in for `api.osv.dev` through `TestServer::start_with_upstream_and_osv`
  - proof: cargo test --test e2e_npm -- --ignored osv -> ok. 2 passed; 0 failed; reviews: qa=VERIFIED, code-review=SHIP
- [x] Slice 4 — operator-configurable `osv_mode` (enforce/diagnostic/off), defaulting to today's enforce-always behavior
  - proof: cargo test --lib -- osv:: config:: http::logging:: && cargo test --test config_validation && cargo test --test decision_log_delivery -> 25 passed, 0 failed; 26 passed, 0 failed; 32 passed, 0 failed; reviews: qa=VERIFIED, code-review=SHIP, security=CLEAR

## Notes for a fresh session

Gate 2 reopened 2026-09-27: user challenged C6 (bulk zip export) post-approval, pointing to OSV's
per-package-version /v1/query API as simpler. Re-steering to switch the OSV fetch shape from a
periodic full-snapshot bulk-zip poll to a live per-request /v1/query call; C7/C9/C10/C11 (persistence,
decompression caps, circuit breaker, spawn_blocking isolation) are being re-evaluated since most of
that complexity existed specifically to guard the bulk-zip path. Resolved in Gate 3: the final shape
is `POST /v1/querybatch` (batched, not the single-item `/v1/query`), reusing D2's shared
`osv::evaluate` wrapper so every production call site pays one coalesced batch round trip instead of
a per-call HTTP request; see `03-program-design.md` D1-D4 and `## Threat model`.

Gate 4 approved 2026-09-28: `04-slices.md` splits the design into Slice 1 (core module + one wired call site,
including the five invariants Gate 3 deferred "to slice 1: source absent") and Slice 2 (the
remaining three call sites). Both slices are complete and verified.

Gate 4 reopened 2026-09-29: adding Slice 3, e2e coverage proving OSV-only (non-blocklist)
malicious matches refuse a real `npm install`, wiring a `wiremock` stand-in for `api.osv.dev`
through `TestServer::start_with_upstream_and_osv`. No architecture or design decision changes;
Gates 1-3 and Slices 1-2 stand. Completed and approved 2026-09-29; the plan reached "complete" once.

Gate 2 reopened 2026-09-29 (second re-steer): user asked whether OSV blocking can be switched on/off
in config, and whether a diagnostic mode exists that only logs malicious matches without refusing —
neither exists today. Adding an operator-configured enforcement mode (enforce/diagnostic/off) as new
config keys, changing `policy::evaluate`'s `osv_matched` tier to consult it. This is a security-control
behavior change, so Gate 2 and Gate 3 both re-run threat modeling. Gate 1's product problem (block
malicious packages by default) is unchanged; Slices 1-3 stand — their code is not invalidated, the new
mode is additive and defaults to today's enforce-always behavior.

Gate 2 approved 2026-09-29 (osv_mode: enforce/diagnostic/off, C16-C18b; sf-threat-model MODELED via
evidence/threat-model-3.md; sf-red-team FIX FIRST closed by C17c's dedicated OSV_DIAGNOSTIC_REASON
constant). Gate 3 reopened 2026-09-29 to pin concrete Rust types (D5-D8): `OsvMode` enum and
`OsvClient.mode` field, `config.rs`'s validated string following the `public_url`/`osv_cache_ttl_seconds`
idioms, and `http::logging`'s `RequestContext.osv_diagnostic_match`/`record_osv_diagnostic_match`/
`OSV_DIAGNOSTIC_REASON` seam. Approved 2026-09-29 after 4 REVISE rounds (7 findings, F1-F7, all closed
by `sf-gate-qa`, verified against live source each round). Gate 4 reopened 2026-09-29 to add Slice 4
implementing D5-D8. No further design decisions remain open.