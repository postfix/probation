# Status: Rated load guard

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
  Result: Fresh nine-family/RubyGems-critical Scope QA READY; verified docs/plans/rated-load-guard/gate-1-qa.md with no blocking findings. Shared-service journey, policy, node admission and package-manager credentials are included.
- [x] Present and record user approval
  Result: User approved the nine-family/RubyGems-critical scope on 2026-11-02; gate-qa approve --gate 1 returned APPROVED. Bound presentation: docs/plans/rated-load-guard/show-me-gate1-rubygems-nine.md. Required delivery-authority correction remains design/implementation work; no runtime proof is inferred.

## Slices

- [x] Slice 1 — tracer bullet: operator-sized delivery queues, with a bad budget refused at load
  - proof: cargo check --all-targets && cargo test --lib --test config_validation --test decision_log_delivery -> check exit 0; test result: ok for all three binaries — 85 / 25 / 18 passed, 0 failed, including rl1-rl6 and the amended tp7; reviews: code-review=SHIP, security=FIX FIRST-resolved (all findings applied; round detail in evidence/slice-1.md)
- [x] Slice 2 — every record's method bounded, so BYTES_PER_RECORD is a real ceiling
  - proof: cargo check --all-targets; cargo test --lib --test decision_log_delivery -> exit 0; ok. 87 passed (lib), ok. 20 passed (integration) incl. rl16b rl22 rl24 rl24b; reviews: code-review=SHIP, security=CLEAR, adversarial=PASS
- [x] Slice 3 — all eight loss sites account through SinkCounters::lose, plus a monotonic total
  - proof: cargo check --all-targets; cargo test --lib --test decision_log_delivery -> check exit 0; lib ok 94 passed, decision_log_delivery ok 21 passed incl. rl7, rl8, rl9, tp19; E0616 negative control re-witnessed; reviews: code-review=SHIP, adversarial=PASS, qa=VERIFIED
- [x] Slice 4 — the closed-loop load driver and the cargo test floor that fails on a collapse
  - proof: cargo test --test delivery_rated_load -> test result: ok. 3 passed (rl17, rl18, rl19) in ~6 s; F=1500 B=122_880_000; reviews: code-review=SHIP, qa=VERIFIED, adversarial=PASS
- [x] Slice 5 — GET /health/delivery reports shedding for 60 s while /health/ready stays green
  - proof: cargo check --all-targets; cargo test --lib --test decision_log_delivery -> ok: 94 lib + 27 integration passed incl. rl12 rl13 rl14 rl15 rl16c rl25; reviews: qa=VERIFIED, code-review=SHIP, security=CLEAR, adversarial=PASS
- [x] Slice 6 — the SIEM sink holds its batch while the collector is unreachable, bounded and cancellable
  - proof: cargo check --all-targets; cargo test --test decision_log_delivery -> check exit 0; ok. 31 passed incl. rl10 rl10b rl23 rl23b tp7 tp9 tp11a tp15 tp15b; reviews: code-review=SHIP, security=CLEAR, adversarial=PASS, qa=VERIFIED
- [x] Slice 7 — the bench, the published numbers, and the final default budget literal
  - proof: cargo check --all-targets; cargo bench --bench delivery_rated_load; cargo test --no-fail-fast -> corrected mid-slice (C39 supersedes this session's first answer C98, see 04-slices.md): DEFAULT_QUEUE_MAX_BYTES=1,875 MiB from the 200 req/s reference load, not from measured N; check exit 0; bench: calibrated+confirmed loss-free at full 600s, N=59,288 (published for reference only), exit 0; test: every target ok, 0 failed; reviews: code-review=SHIP, qa=VERIFIED (both re-run against the corrected diff)

## Notes for a fresh session

Current scope after C1027 is approved 2026-11-02: nine families (npm, PyPI, Maven, Go modules, Cargo, NuGet, RubyGems, Conan, Docker/OCI). RubyGems is critical and first added after the shared-service foundation; CPAN is omitted. Q8-Q11 and package-manager credential ownership remain settled. Gate 1 approval and progress are recorded; earlier pending-scope/ten-family notes below are historical. Combined design remains unapproved. Lead FIX-16-A in package-firewall-mvp/02-architecture.md, 03-program-design.md and 04-slices.md assigns the discovered managed-authority release gap to Slice 16 before new adapters; evidence/artifact-flow-correctness.md records source facts and required tests, not an implemented fix.

- Requested by the user on 2026-09-23, straight after the decision-log-delivery feature shipped
  on branch `package-firewall-mvp` (PR #1, commits `d27dc9f` and `734d22d`).
- WHY THIS PLAN EXISTS. `01-product.md` of decision-log-delivery promises: "no decision record
  is lost while the firewall is serving at its rated load, and any record that is dropped is
  counted and reported rather than discarded quietly." The second half shipped and is witnessed
  (`tp7`, `tp15b`). The first half never had a witness, because **"rated load" has no number
  anywhere in the firewall**. The user accepted that gap on 2026-09-23 as decision-log-delivery
  C52, on the condition it returns as its own plan. This is that plan.
- WHAT ALREADY EXISTS and must not be reinvented: both sinks are bounded queues that drop rather
  than block (`src/delivery/`), every drop is counted and surfaced as `dropped_file` /
  `dropped_siem` on the summary record, and `tests/decision_log_delivery.rs` holds the delivery
  integration suite with `TestServer`, `TestClock` and a `wiremock` collector. The MVP's own
  limits already name concurrency ceilings in `config.sample.toml`: `max_active_requests = 1024`,
  `max_upstream_requests = 32`, `max_artifact_downloads = 8`.
- THE OPEN PRODUCT QUESTION, which is what Gate 1 has to settle: "rated load" can mean a
  requests-per-second figure the operator is promised, a queue-depth headroom claim, or a
  documented measurement an operator can re-run on their own hardware. These lead to very
  different features, and the choice is the user's.

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
