# Status: OSV vulnerability intelligence

- Gate 1 — Product: APPROVED 2026-11-02
- Gate 2 — Architecture: in progress
- Gate 3 — Program Design: pending
- Gate 4 — Slice plan: pending

## Factory settings

- presentation: auto

## Loop signal

{"generation":23,"boundary":{"kind":"gate","number":2},"reopened":false,"history":[{"from":"hand","reason":"rework","to":"hand"},{"from":"hand","reason":"complete","to":"hand"},{"from":"hand","reason":"complete","to":"hand"},{"from":"hand","reason":"complete","to":"hand"},{"from":"hand","reason":"complete","to":"hand"},{"from":"hand","reason":"start","to":"qa"},{"from":"qa","reason":"rework","to":"hand"},{"from":"hand","reason":"start","to":"qa"},{"from":"qa","reason":"complete","to":"hand"},{"from":"hand","reason":"rework","to":"hand"},{"from":"hand","reason":"start","to":"qa"}]}

## Gate 1 progress

- [x] Create 00-status.md
  Result: Existing status and historical delivery evidence retained; new scope is reviewed before revised design and implementation.
- [x] Select the plan with router resume
  Result: Six affected plans resumed without checkpoints. Package Firewall MVP is the lead release scope; dependent products retain their feature ownership and baseline requirements.
- [x] Create the product clarification inventory
  Result: C1006/C1008/C1009 select local enforcement/direct upstream traffic, API-key policy connection and explicit standalone TOML. C1013/C1027 select nine package/container families, omit CPAN and prioritize RubyGems; C1015 keeps registry credentials configured in package managers; C1016 selects Linux/macOS/Windows clients; C1017 selects a Linux-only policy server. Technical deferrals C1003/C1018 are imported into 02-architecture.md.
- [x] Resolve user decisions
  Result: Q2, Q3, Q5, Q6 and Q7 plus server/CI follow-ups are recorded. No open product inventory rows remain. Exact APIs, per-format/platform contracts, migration and CI/daemon topology remain combined-design obligations, not implementation discretion. Management C19/C20 outage/propagation and C30 device-control limits are retained explicitly in the lead scope.
- [x] Gather ecosystem and authentication evidence
  Result: Lead evidence includes pinned Nora/Dozor reuse, public ecosystem inventory, current auth/policy seams, platform baseline and research-native-ci.md; management-server/evidence/research-ecosystem-auth.md retains the former native-certificate survey. CI report ANSWERED for ordinary native jobs and Linux container restrictions, with non-Linux Docker execution unproved. No new-source/runtime proof is claimed. Legacy OSV/log-delivery inventory formatting is repaired with unchanged selected policies and explicit original-ID aliases.
- [x] Review UI mockups with the user
  Result: No new desktop GUI or account/membership interaction is introduced. Reuse existing approved API-key, policy, registry and account surfaces; selected family names/credential ownership/platforms are recorded user answers. Revised setup text, obsolete certificate-control retirement and exact changed screen content are reviewed in combined design before implementation; no historical certificate mockup is treated as a preview of new behavior.
- [x] Complete 01-product.md
  Result: Lead scope has the approved nine-family matrix, deployment/credential model, measurable artifact acceptance, native CI requirements, exclusions, retained policy/security limits, cross-plan ownership and domain/flow diagrams. Dependent product amendments make those choices authoritative over obsolete certificate/format proposals and retain their own prior outcomes.
- [x] Obtain QA READY
  Result: Fresh nine-family/RubyGems-critical Scope QA READY; verified docs/plans/osv-intel/gate-1-qa.md with no blocking findings. Shared-service journey, policy, node admission and package-manager credentials are included.
- [x] Present and record user approval
  Result: User approved the nine-family/RubyGems-critical scope on 2026-11-02; gate-qa approve --gate 1 returned APPROVED. Bound presentation: docs/plans/osv-intel/show-me-gate1-rubygems-nine.md. Required delivery-authority correction remains design/implementation work; no runtime proof is inferred.

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

Current scope after C1027 is approved 2026-11-02: nine families (npm, PyPI, Maven, Go modules, Cargo, NuGet, RubyGems, Conan, Docker/OCI). RubyGems is critical and first added after the shared-service foundation; CPAN is omitted. Q8-Q11 and package-manager credential ownership remain settled. Gate 1 approval and progress are recorded; earlier pending-scope/ten-family notes below are historical. Combined design remains unapproved. Lead FIX-16-A in package-firewall-mvp/02-architecture.md, 03-program-design.md and 04-slices.md assigns the discovered managed-authority release gap to Slice 16 before new adapters; evidence/artifact-flow-correctness.md records source facts and required tests, not an implemented fix.

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
## Nora ecosystem expansion — 2026-11-02

The user requests all ecosystems supported by Nora, borrowing Nora/Dozor code where practical, across Package Firewall MVP, management server/portal, OSV intelligence, decision logging and rated load. The user also requires checking package-manager and registry support for the existing SSL authentication and whether architecture must change. Scope Gate 1 is reopened; design Gates 2–4 await the revised scope. Earlier completed slice proofs remain historical evidence for their original npm/PyPI behavior, not evidence of expanded ecosystem or authentication coverage. No historical slice completion is invalidated by this additive request. The pending legacy completion presentation has not been accepted or acknowledged.

Next: obtain fresh Scope QA READY, present the recorded ten-family/three-client-OS/Linux-server scope and record approval. Exact interfaces, native CI topology, Docker coverage and migrations are deferred to combined design under C1003/C1018.

## Selected local-client direction — 2026-11-02

C1006 resolves Q2 with a locally installed client and API-key authentication to the policy server, replacing the earlier certificate bridge proposal. C1008 explicitly retains TOML-configured standalone backend operation without the policy server. The completed publishing-proxy plan was reopened because it owns the superseded mandatory certificate contract; its prior five slice acceptances are historical and need fresh delivery against the new design. No product code was changed. Q3 / C1009 is resolved: local enforcement and direct registry downloads. C1013 / Q5 now selects the actual target formats after public-source research.

## Public-source review — 2026-11-02

Saved evidence/research-public-ecosystems.md under package-firewall-mvp: APT has Debian public archives, RPM has public distribution repositories, Terraform has a public registry and executable provider plugins. Sixteen Nora families have public sources; generic Raw storage has no defined ecosystem upstream. Proposed first target is thirteen developer dependency/container families, deferring APT/RPM and Hugging Face and omitting Raw; C1013 / Q5 remains unanswered. No format exclusion is approved solely by this status note. Q3 local enforcement is recorded in every affected product inventory.

## Selected package/container release — 2026-11-02

Q5/C1013 is resolved: npm, PyPI, Maven, Go modules, Cargo, NuGet, CPAN, RubyGems, Conan and Docker/OCI only. Earlier thirteen/sixteen/seventeen-family proposals are historical, not pending alternatives. Q6/C1015 is resolved: users and CI jobs own local registry credentials; policy API keys never become registry credentials and the policy server does not distribute shared organisation read secrets. Q7/C1016 is resolved for Linux/macOS/Windows clients; C1017 makes the policy server Linux-only; C1018 carries native GitHub Actions requirements into design. Preserve historical source/proofs; no product code was changed.

## Scope ready for independent review — 2026-11-02

All product choices in C1006/C1008/C1009/C1013/C1015/C1016/C1017 are recorded. C1003/C1018 defer technical implementation to combined design. The user requires native Windows/macOS GitHub Actions tests; Linux client/server checks and unproved non-Linux Docker integration are explicit. All six router inventories have no findings after legacy formatting normalization. Scope QA, presentation and approval remain required; no code or workflow is changed by these documents.
