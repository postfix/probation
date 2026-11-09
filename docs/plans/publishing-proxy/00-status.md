# Status: Transparent package publishing

- Gate 1 — Product: APPROVED 2026-11-02
- Gate 2 — Architecture: APPROVED 2026-11-02
- Gate 3 — Program Design: APPROVED 2026-11-03
- Gate 4 — Slice plan: APPROVED 2026-11-03

## Factory settings

- presentation: auto

## Loop signal

{"generation":52,"boundary":{"kind":"slice","number":5},"reopened":false,"history":[{"from":"hand","reason":"start","to":"engineering"},{"from":"engineering","reason":"complete","to":"code-review"},{"from":"engineering","reason":"complete","to":"security"},{"from":"engineering","reason":"complete","to":"qa"},{"from":"engineering","reason":"rework","to":"code-review"},{"from":"engineering","reason":"rework","to":"security"},{"from":"engineering","reason":"rework","to":"qa"},{"from":"engineering","reason":"rework","to":"code-review"},{"from":"engineering","reason":"rework","to":"security"},{"from":"engineering","reason":"rework","to":"qa"},{"from":"engineering","reason":"rework","to":"qa"},{"from":"engineering","reason":"complete","to":"code-review"},{"from":"engineering","reason":"complete","to":"security"},{"from":"engineering","reason":"complete","to":"qa"}],"presentedSlice":4}

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
  Result: Fresh nine-family/RubyGems-critical Scope QA READY; verified docs/plans/publishing-proxy/gate-1-qa.md with no blocking findings. Shared-service journey, policy, node admission and package-manager credentials are included.
- [x] Present and record user approval
  Result: User approved the nine-family/RubyGems-critical scope on 2026-11-02; gate-qa approve --gate 1 returned APPROVED. Bound presentation: docs/plans/publishing-proxy/show-me-gate1-rubygems-nine.md. Required delivery-authority correction remains design/implementation work; no runtime proof is inferred.

## Gate 2 progress

- [x] Check whether existing architecture and evidence can be reused
  Result: The approved 01-product.md amendment supersedes certificate-based package admission and shared package-data behavior. Reuse the lead package-firewall-mvp architecture for shared-service policy and direct upstream fetches; this plan retains npm/PyPI operations, registry selection, publishing and upstream authorization.
- [x] Create or update the architecture and carry deferred questions
  Result: Active local-service design is recorded in 02-architecture.md. It carries C1003/C1018 into the combined design and imports C1019-C1024 without reopening settled choices.
- [x] Gather repository evidence
  Result: evidence/local-client-repository-map.md maps npm/PyPI TLS client admission separately from upstream registry authorization. SMTC coverage is partial; it describes the delivered baseline and makes no claim that the replacement path exists.
- [x] Save findings and resolve architecture decisions
  Result: C1019-C1024 are reused: one common service policy, no package-request login, local/approved-node access and upstream registry credentials remain separate. D42 records the proposed service-scoped lease because this path has no member identity; D41 safety remains.
- [x] Complete 02-architecture.md
  Result: Active boundaries, selected registry paths, managed policy API-key authentication in the HTTP Authorization header, separate package-manager credentials for selected-upstream authorization, failure behavior, D42 service-scoped reference proposal and C1018 verification obligations are recorded. Certificate-era architecture is explicitly historical.
- [x] Record architecture assumptions and review triggers
  Result: 02-architecture.md records local/approved-node access, no per-user identity, no managed-to-standalone fallback, C19/C20 outage behavior and fresh threat/Red Team review triggers. Prior certificate reviews are historical.
- [x] Complete architecture section of the combined design
  Result: Active molecule-flow.json covers managed/standalone policy source, selected npm/PyPI requests, local/upstream denial, current-policy release, request-local token-packument, and service-scoped unpublish. router molecule-check PASS.
- [x] Carry contracts and obligations into program design
  Result: Active molecule-contracts.json binds six modeled operations with seven source obligations. Existing action, token-packument and audit controls PASS; four planned service-source obligations are absent and assigned to future slices. molecule-check PASS; evidence/source-contract-rebind.md records fresh run-Z0bKeh and the exact-value/runtime limits. Gate QA preparation must classify future sources as PENDING.

## Gate 3 progress

- [x] Create or update the design from its template
  Result: 03-program-design.md records the active local-service caller flow: the firewall identifies/authenticates to the policy server with its API key in the HTTP Authorization header; package-manager credentials separately authorize requests to the selected registry. It also records managed/standalone policy, npm/PyPI contracts and the historical certificate baseline.
- [x] Gather design evidence
  Result: evidence/local-client-repository-map.md separates existing npm/PyPI TLS admission from upstream credential forwarding; lead evidence supplies shared-service source contracts. SMTC map completeness limits are recorded.
- [x] Record effects on callers, dependencies, and planned checks
  Result: Active caller-owner table and the lead Slice 16/25 dependencies are documented in 03-program-design.md and 04-slices.md. Existing npm/PyPI actions remain owned here; service foundation is lead-owned.
- [x] Define interfaces, behavior, invariants, and test cases
  Result: 03-program-design.md defines the local service response and service-scoped unpublish seams, exact package-manager credential role, upstream allow/deny, token-packument/audit rules and caller scenarios; runtime proofs are assigned to active slices.
- [x] Validate analyzer specs or assign their authoring to slices
  Result: Existing action, token-packument and audit source controls PASS at evidence/source-contract-rebind.md run-Z0bKeh. Four service-route/unpublish controls target absent future Slice 1/3 sources; narrow call-order specs exist and do not claim value binding or atomicity.
- [x] Define security coverage and resolve required planning reviews
  Result: Active security coverage distinguishes the policy API key in the HTTP Authorization header from package-manager credentials sent to the selected registry. Fresh evidence/threat-model-local-service.md returned MODELED and evidence/red-team-local-service.md returned SOUND after closing response-handoff and service-scoped marker findings. Future source/runtime proofs remain assigned to slices.
- [x] Complete contracts and flows for the combined design
  Result: Active six-flow molecule-flow.json and seven source obligations are linked to active slices; molecule-check PASS. Fresh run-Z0bKeh confirms the three existing source controls PASS; four obligations remain on absent future route/unpublish modules assigned to later slices, as recorded in evidence/source-contract-rebind.md.
- [x] Carry guarantees and checks into delivery slices
  Result: 04-slices.md assigns current-policy/read, safe-audit/token-packument, npm publishing/unpublish, PyPI upload and native release witnesses to Slices 1–5, with the lead Slice 16/25 dependencies and security reviews explicit.

## Gate 4 progress

- [x] Write the slice plan
  Result: 04-slices.md now assigns local-service reads, npm audits/token-packuments, npm publishing/unpublish, PyPI publishing, and native release acceptance to active Slices 1–5. The earlier certificate-based delivery record is historical.
- [x] Define slice behavior and dependencies
  Result: Active Slices 1–5 depend on lead package-firewall-mvp Slices 16/25 where they consume the shared service/current-authority and native lifecycle, and preserve this plan’s npm/PyPI ownership.
- [x] Define checks
  Result: 04-slices.md names allow/deny, credential separation, selected-upstream, safe audit, token-packument isolation, D41/D42 service-scoped marker/destination and native GitHub Actions witnesses. These are future executable witnesses, not current test results.
- [x] Validate prerequisites
  Result: Reuse lead Slice 16 shared-service and Slice 25 native lifecycle prerequisites, plus its Linux/macOS/Windows client and Linux policy-server requirements. Runtime and non-Linux Docker evidence remain future acceptance, not current proof.
- [x] Complete required combined design reviews
  Result: evidence/threat-model-selected-origin-only.md returned MODELED and evidence/red-team-selected-origin-only-final.md returned SOUND against the current design. They cover the policy API key/header split, selected-registry-only credentials, extra-origin refusal, all three DELETE routes, marker/GET fallback, uncertain partial-write recovery, and service-scoped quotas. Runtime/source guarantees remain pending.
- [x] Obtain QA READY
  Result: Fresh combined Design QA READY sealed and independently verified on 2026-11-03; gate-4-qa.md reviews current verification bindings and implemented Slice 1 evidence. Source checks PASS for existing obligations; only three absent Slice 3 obligations remain PENDING. Bound presentation show-me-design.md was subsequently approved by the user on 2026-11-03.
- [x] Present and record user approval
  Result: User approved the refreshed combined design on 2026-11-03. gate-qa approve --gate design returned APPROVED against docs/plans/publishing-proxy/show-me-design.md and current READY gate-4-qa.md. Original 2026-11-02 approval is retained as history; caller behavior and scope are unchanged. Slice 1 implementation and independent verification are complete; record completion using evidence/slice-1.md.

## Slices

- [x] Slice 1 — Local npm/PyPI reads through the shared service
  - proof: cargo test --workspace; cargo check --workspace; node tests/e2e/harness/run.mjs --only E2E-service-policy --skip-build; router molecule-check and molecule-verify --slice 1 -> Workspace 782 passed/0 failed/21 ignored; compiler PASS; current-image npm/pip E2E 1 passed/0 failed/0 skipped; both models PASS; publishing 3 due plus 3 existing checks PASS, 3 future Slice 3 checks PENDING; imported foundation 54 checks PASS; evidence/slice-1.md and evidence/slice-1-verification.md bind the verified 30-file subject d2e8313f9c0e50283ce86820a895407208912a3dd9de518c29d100b6fe993a80; reviews: code=SHIP, security=CLEAR, adversarial=PASS, qa=VERIFIED
- [x] Slice 2 — Safe npm audit and token-packument behavior
  - proof: node tests/e2e/harness/run.mjs --only E2E-publishing-npm-read; cargo test --workspace; cargo check --workspace; installed router molecule-check and molecule-verify --slice 2 -> E2E 1 passed/0 failed/0 skipped; workspace 782 passed/0 failed/21 ignored; compiler/model PASS; installed source 6 PASS and 6 unsafe controls, zero UNKNOWN, 3 future Slice3 PENDING; tooling fullsuite PASS, drift 299/0; evidence/slice-2.md and slice-2-verification.md VERIFIED; reviews: code=SHIP, security=CLEAR, adversarial=PASS, qa=VERIFIED
- [x] Slice 3 — npm publishing and service-scoped version unpublish
  - proof: node tests/e2e/harness/run.mjs --only E2E-publishing-npm-actions; cargo test --workspace; cargo check --workspace; installed router molecule-check and molecule-verify --slice 3 with reviewed receiver receipt -> Workspace 786 passed/0 failed/22 ignored; native npm actions 1/0/0; actual production quotas PASS separately; fresh compiler and 8 HTTP tests PASS; model and installed 9 source obligations plus 9 unsafe controls PASS; Factory full tests and drift 299/0; unchanged 15-file subject; evidence/slice-3-verification.md VERIFIED; historical RED and tooling limits retained; reviews: code=SHIP, security=CLEAR, adversarial=PASS, qa=VERIFIED
- [x] Slice 4 — PyPI publishing and uv workflows
  - proof: node tests/e2e/harness/run.mjs --only E2E-publishing-full-matrix -> PASS 1 passed/0 failed/0 not run in 2846.9 s; workspace 792/0/22; molecule-check PASS; molecule-verify 9/9 PASS; python-service large-upload probe PASS; evidence/slice-4.md; reviews: code=SHIP, security=CLEAR, adversarial=PASS, qa=VERIFIED
- [ ] Slice 5 — Native package-client release acceptance

## Notes for a fresh session

User requested a handoff during active Slice 4. Work is paused; all spawned agents and their owned processes are terminal. No Slice 4 completion is claimed. Read `/tmp/probation-slice4-handoff-2026-11-03.md` first for exact implementation, frozen files, partial checks, blockers and next steps. The approved active Slice 4 row in `04-slices.md` requires the full publishing matrix; its latest run failed. Preserve earlier approved slices and guarantees. First resume action: reconcile the active `evidence/tdd-slice-4.md` line with the certificate-era HEAD history it accidentally replaced, preserving both; then update `evidence/slice-4-engineering.md` with terminal results. The full matrix has two real 503 failures plus witness-accounting gaps; the workspace suite stopped on a missing test executable and needs an isolated-target retry. Do not mark a failed or interrupted check PASS. The temporary handoff document is the user-requested handoff artifact; no formal Factory clear-safe checkpoint was created.

Previous resume note (historical; superseded above):

The user answered `next` after the completed Slice 3 presentation. `acknowledge-slice-presentation --slice 3` succeeded; router resume selects approved active Slice 4, PyPI publishing and uv workflows, with checkpoint null and no findings. Slice 4 Engineering is dispatched as `sf-implement` and owns only its assigned PyPI code/tests/evidence. Do not reopen Gate decisions or alter Slice 3 product guarantees. The approved Slice 4 row/direct witness is returned by router resume. Review code, security, adversarial and implementation after direct checks, then present the completed slice before any Slice 5 work.

Previous resume note (historical; superseded above):

Slice 3 is COMPLETE and independently VERIFIED. The guarded completion command exited 0; resume selects presentation boundary 3 with done [1,2,3] and no findings. Present the completed slice through sf-show-me and sf-display, then wait for the user's continuation decision before Slice 4. Approved scope/design, models/specs and the frozen 15-file product subject remain unchanged. Final evidence: evidence/slice-3.md and evidence/slice-3-verification.md (SHA-256 6de0a0680d3eb04fcbcec3659e75e58043d6d10ca0f22d9bcc3fda07def2f26d). Code SHIP, security CLEAR and adversarial PASS stand. Workspace 786/0/22, native npm 1/0/0, separately passed actual quota, fresh eight HTTP tests and workspace compilation all pass. Missing historical RED remains a process limitation, with current sensitivity demonstrated.

Both verifier repairs are installed. Immutable Factory release 2ae901dc66af5637abceac7201f74c2511ebfe98c9fd76a9250fe661d0f4673c passed full standard installer and drift 299/0. Installed model and nine source/nine unsafe controls pass, archive run-xKUiUa; fresh named specialist four ordering pairs PASS. Exact receiver receipt evidence/slice-3-rust-receiver-scopes.json must be supplied per-command through SF_RUST_RECEIVER_SCOPES_FILE for future source verification or completion checks. Use pinned Node 24.19.0 and installed matched SMTC fbde1a/2d149b pair, no candidate overrides. Final deployment receipt is .scratch/slice3-repair/tooling/factory-deployment-receipt.json SHA c282876264dc536fb11b5619cc98a1a6ecd55181162366e690bd44ab6c88e075.

Preserve limits: standard emergency provider evaluation matrix skipped; broader SMTC failures recorded (36 reproduced on baseline,five passed in isolation on both versions); historical RED and LSP compile leg unavailable; optional duplicate aggregate interrupted without a verdict. Two failed pre-promotion installer attempts and their bounded diagnoses remain recorded; final 106-file toolsubject passed independent lexical and mechanical pin reviews. No approved guarantee or assertion weakened. No Slice 4 authorization follows from the checks.

Previous resume note (historical; superseded above):

Scope and combined design remain approved. Router resume selects active Slice 3; its checkbox remains unchecked.

Slice 3 implementation and runtime validation are complete on the 15-file subject in `.scratch/slice3/current-subject.json` (SHA-256 a85bfdde9de40508ce3c512087d59461037b0710b125f2382359832d66e201b9). Final workspace 786 passed/0 failed/22 ignored; scoped native npm actions 1/0/0; earlier action/read pair 2/0/0; compiler PASS; actual production quota witness PASS separately. Fresh scoped code correction review SHIP and adversarial recheck PASS. Exact current evidence and open blockers are in `evidence/slice-3.md` and `evidence/slice-3-engineering.md`; certificate-era evidence is archived separately.

Acceptance remains blocked: selected Factory release source attribution is UNKNOWN; repaired-release comparison has six obligations/controls PASS and three UNKNOWN (two receiver-call attribution failures plus classifier CFG failure). Direct independent verdicts for three unpublish ordered specs PASS Structural, but do not resolve the complete contract check or two qualified-operation summary expectations. Security remains UNKNOWN and final implementation verification is not yet authorized as complete. Missing historical RED for quota characterization is recorded honestly as a process-evidence gap. Preserve approved models/specs; resolve checker/binding and review blockers before completing or presenting Slice 3. Do not start Slice 4.

## Source contract evidence

Required for this plan.

## Local-client and policy-source re-steer — 2026-11-02

User selects a locally installed client and API-key authentication to the policy server, while retaining a backend that works without the policy server from TOML configuration. This replaces the target mandatory package-client certificate model; existing implemented certificate behavior is historical until changed through approved delivery. Gate 1 and dependent design are reopened. All five slice acceptances require fresh delivery/checks under the revised identity path; prior proofs are preserved in evidence/resteer-local-client-baseline.md and evidence/slice-1.md through slice-5.md. Registry selection, package/tenant isolation, upstream-authorized publishing, secret confinement and safe audit outcomes remain requirements. Certificate-specific setup, issuance, enterprise issuer/status and revocation expectations must be reconciled explicitly in revised scope/design. No product code is changed by this status.

Next: obtain fresh Scope QA READY, present the recorded ten-family/three-client-OS/Linux-server scope and record approval. Exact interfaces, native CI topology, Docker coverage and migrations are deferred to combined design under C1003/C1018.

## Public-source review — 2026-11-02

Saved evidence/research-public-ecosystems.md under package-firewall-mvp: APT has Debian public archives, RPM has public distribution repositories, Terraform has a public registry and executable provider plugins. Sixteen Nora families have public sources; generic Raw storage has no defined ecosystem upstream. Proposed first target is thirteen developer dependency/container families, deferring APT/RPM and Hugging Face and omitting Raw; C1013 / Q5 remains unanswered. No format exclusion is approved solely by this status note. Q3 local enforcement is recorded in every affected product inventory.

## Selected package/container release — 2026-11-02

Q5/C1013 is resolved: npm, PyPI, Maven, Go modules, Cargo, NuGet, CPAN, RubyGems, Conan and Docker/OCI only. Earlier thirteen/sixteen/seventeen-family proposals are historical, not pending alternatives. Q6/C1015 is resolved: users and CI jobs own local registry credentials; policy API keys never become registry credentials and the policy server does not distribute shared organisation read secrets. Q7/C1016 is resolved for Linux/macOS/Windows clients; C1017 makes the policy server Linux-only; C1018 carries native GitHub Actions requirements into design. Preserve historical source/proofs; no product code was changed.

## Scope ready for independent review — 2026-11-02

All product choices in C1006/C1008/C1009/C1013/C1015/C1016/C1017 are recorded. C1003/C1018 defer technical implementation to combined design. The user requires native Windows/macOS GitHub Actions tests; Linux client/server checks and unproved non-Linux Docker integration are explicit. All six router inventories have no findings after legacy formatting normalization. Scope QA, presentation and approval remain required; no code or workflow is changed by these documents.

## Workflow history

### Prior Slice 2 completion notes

Current scope and combined design are approved 2026-11-02. The recorded design approval covers Gates 2–4; its review is gate-4-qa.md (READY).

Use router resume position for the current step. Check the current prerequisites and implementation obligations in 04-slices.md before delivery; this note asserts no new slice or prerequisite is complete.

Current decisions remain in the approved Gate documents. Earlier workflow and approval requests are preserved as explicitly classified history.


Slice 2 implementation and required reviews are complete; evidence/slice-2.md and evidence/slice-2-verification.md record current proof. E2E 1/0/0, workspace 782/0/21 ignored, compiler/model PASS, installed source 6 PASS plus six unsafe controls and zero UNKNOWN; only three absent future Slice 3 checks PENDING. Code SHIP, adversarial PASS, bounded security CLEAR, independent verification VERIFIED. Repaired Factory release 7e8fca647076e63b75952e8850dc78c21a23861bafb9ac4ce8e6a9fdbc51cb83 installed with fullsuite PASS and 299 entries/zero drift. Approved project model/spec bytes and frozen product subject are unchanged. Use router position for completion/presentation; do not begin Slice 3 before presentation acknowledgment.

### Narrative before combined-design approval recorded 2026-11-02

The following exact prior text is retained for traceability. Its earlier workflow and approval requests were superseded by the current reviewed and approved design; it is not a current instruction to reopen that approval. This classification does not claim any pending implementation obligation has passed.

### Prior Gate 2 record

Rework: Preserve the approved product promise; design a safe reference for npm version-unpublish after the token packument version is removed, rebind exact source controls, then repeat combined design QA and approval. Prior results above are historical.
Rework status: superseded; Gates: 2; Resolution: Combined design approved 2026-11-02, recorded in Gate 4 progress. Current 02-architecture.md, 03-program-design.md, 04-slices.md and READY gate-4-qa.md replace this earlier workflow instruction; current slice implementation obligations remain due.

### Prior Gate 2 record

Rework: Reconcile architecture Flow 3 login credential wording with approved N06 legacy Basic login, then repeat combined design reviews and approval. The product outcome is unchanged.
Rework status: superseded; Gates: 2; Resolution: Combined design approved 2026-11-02, recorded in Gate 4 progress. Current 02-architecture.md, 03-program-design.md, 04-slices.md and READY gate-4-qa.md replace this earlier workflow instruction; current slice implementation obligations remain due.

### Prior Gate 3 record

Rework: Preserve the approved product promise; design a safe reference for npm version-unpublish after the token packument version is removed, rebind exact source controls, then repeat combined design QA and approval. Prior results above are historical.
Rework status: superseded; Gates: 3; Resolution: Combined design approved 2026-11-02, recorded in Gate 4 progress. Current 02-architecture.md, 03-program-design.md, 04-slices.md and READY gate-4-qa.md replace this earlier workflow instruction; current slice implementation obligations remain due.

### Prior Gate 3 record

Rework: Slice 4 production checks pass, but eight approved unsafe mutation controls cannot apply their illustrative exact source statements. Rebind those controls to the meaningful frozen source shape without changing D40/D41 guarantees; rerun combined design QA and approval. Slice 3 proof remains valid.
Rework status: superseded; Gates: 3; Resolution: Combined design approved 2026-11-02, recorded in Gate 4 progress. Current 02-architecture.md, 03-program-design.md, 04-slices.md and READY gate-4-qa.md replace this earlier workflow instruction; current slice implementation obligations remain due.

### Prior Gate 3 record

Rework: Fresh Slice 4 security review found the direct canonical tarball DELETE route can bypass the accepted-removal marker. Add that entry point to security coverage and require local refusal before outbound I/O. Independent adversarial review found a leased retained version can submit a changed ordinary upstream URL; specify exact leased URL preservation without rejecting valid unleased upstream URLs. Recheck the design and obtain combined approval before implementation resumes.
Rework status: superseded; Gates: 3; Resolution: Combined design approved 2026-11-02, recorded in Gate 4 progress. Current 02-architecture.md, 03-program-design.md, 04-slices.md and READY gate-4-qa.md replace this earlier workflow instruction; current slice implementation obligations remain due.

### Prior Gate 3 record

Rework result: The direct canonical DELETE and leased-URL design is explicit in 03-program-design.md, 04-slices.md and molecule-flow.json. Fresh threat review MODELED and Red Team SOUND are in evidence/threat-model-direct-delete.md and evidence/red-team-direct-delete.md. Router molecule-check PASS and molecule-verify --slice 4 PASS for existing structural obligations at run-ArzeXw; the two new exact-value/route controls remain Slice 4 runtime and security-review work.

### Prior Gate 4 record

Rework: Preserve the approved product promise; design a safe reference for npm version-unpublish after the token packument version is removed, rebind exact source controls, then repeat combined design QA and approval. Prior results above are historical.
Rework status: superseded; Gates: 4; Resolution: Combined design approved 2026-11-02, recorded in Gate 4 progress. Current 02-architecture.md, 03-program-design.md, 04-slices.md and READY gate-4-qa.md replace this earlier workflow instruction; current slice implementation obligations remain due.

### Prior Gate 4 record

Rework: The same eight Slice 4 control strings need exact source rebinding; existing planned outcomes and Slice 3 completion are preserved.
Rework status: superseded; Gates: 4; Resolution: Combined design approved 2026-11-02, recorded in Gate 4 progress. Current 02-architecture.md, 03-program-design.md, 04-slices.md and READY gate-4-qa.md replace this earlier workflow instruction; current slice implementation obligations remain due.

### Prior Gate 4 record

Rework: Extend the Slice 4 witness to reject direct canonical tarball DELETE before upstream and changed tarball URLs for leased retained versions. Prior Slice 4 source and client results predate these controls.
Rework status: superseded; Gates: 4; Resolution: Combined design approved 2026-11-02, recorded in Gate 4 progress. Current 02-architecture.md, 03-program-design.md, 04-slices.md and READY gate-4-qa.md replace this earlier workflow instruction; current slice implementation obligations remain due.

### Prior Gate 4 record

Rework result: Slice 4 now requires changed leased-URL refusal with valid unleased URL compatibility and direct canonical tarball DELETE refusal with zero outbound calls. Threat review MODELED and Red Team SOUND; finite model PASS, existing structural controls PASS. Combined QA and user approval remain due.

### Prior Gate 4 record

Rework: Fresh Slice 4 security review found the upstream-authorized whole-package revision DELETE is a separate public route absent from the Threat model inventory. Add its authorization boundary and a direct allow/deny witness, repeat design reviews and combined approval, then finish Slice 4. No marker bypass was established.
Rework status: superseded; Gates: 4; Resolution: Combined design approved 2026-11-02, recorded in Gate 4 progress. Current 02-architecture.md, 03-program-design.md, 04-slices.md and READY gate-4-qa.md replace this earlier workflow instruction; current slice implementation obligations remain due.

### Prior notes for a fresh session

Current scope after C1027 is approved 2026-11-02: nine families (npm, PyPI, Maven, Go modules, Cargo, NuGet, RubyGems, Conan, Docker/OCI). RubyGems is critical and first added after the shared-service foundation; CPAN is omitted. Q8-Q11 and package-manager credential ownership remain settled. Gate 1 approval and progress are recorded; earlier pending-scope/ten-family notes below are historical. Combined design remains unapproved. Lead FIX-16-A in package-firewall-mvp/02-architecture.md, 03-program-design.md and 04-slices.md assigns the discovered managed-authority release gap to Slice 16 before new adapters; evidence/artifact-flow-correctness.md records source facts and required tests, not an implemented fix.

Reopened Gate 1 on 2026-10-27 after the user chose a distinct selected-registry URL and reduced, policy-safe audit advisories and requested investigation of proxy fallback. Pinned npm 11 sends only names and versions to bulk audit while quick audit needs a full dependency tree, so a general proxy translation cannot faithfully recover the missing input. C38 is resolved: Probation only proxies the selected registry; npm 11 reports an upstream bulk failure, and direct quick clients retain guarded access. No advisory server or fabricated fallback is added. Slices 1–2 passed historically but their selected-URL witnesses must rerun under the new path. Slice 3's nonempty audit control remains red until revised design approval and implementation. See `evidence/slice-3.md`.
On 2026-10-28, Slice 4 QA found that version unpublish fails for an otherwise capable selected upstream with a noncanonical tarball URL. Preserve Gate 1; reopen Gate 2 and the combined design for a safe URL reference, then reverify affected Slice 3 and Slice 4. The exact source controls for package policy and action origin also need rebinding to current signatures. See `evidence/slice-4.md` and `evidence/research-8-nora.md`.

On 2026-10-28, Slice 4 code and pinned npm action E2E passed the canonical, noncanonical and approved extra-origin restart paths, but all eight new defect controls were UNKNOWN because exact `from` text in molecule-contracts.json predates implementation. Reopen Gate 3 for control rebinding only; preserve the approved D40/D41 behavior. See evidence/slice-4.md and contract-evidence run-cfTjHy.

On 2026-10-30, all five slices are complete and the Slice 5 presentation was accepted. The final pinned client matrix passed 19/19 runners and 123/123 row-mode cases, including 10,000 distinct certificate-backed admissions per provider. The private-PyPI upload approval-withdrawal regression passed; cargo check, finite model and 21/21 source controls passed. Fresh code, security, adversarial and implementation reviews returned SHIP, CLEAR, PASS and VERIFIED. Post-completion verification on the corrected source passed the full Rust workspace suite (762 passed, 0 failed, 21 ignored) and a fresh containerized OpenSSL issuer transition (1 passed, 0 failed). The portal still requires each actual organization issuer to prove a fresh good-to-revoked transition before activation. See `evidence/slice-5.md` and `show-me-slice-5.md`.

### Recovery note before deriving position only from the router

Current scope and combined design are approved 2026-11-02. The recorded design approval covers Gates 2–4; its current review is gate-4-qa.md (READY). No new approval is pending for this recorded design.

Resume position: Slice 1 — Local npm/PyPI reads through the shared service. Before implementation, verify the prerequisites declared in 04-slices.md, including the lead package-firewall-mvp Slice 16 shared-service and FIX-16-A delivery. This status does not assert those prerequisites or any new slice are complete.

Current decisions and obligations are in 01-product.md, 02-architecture.md, 03-program-design.md and 04-slices.md. Earlier rework instructions and notes below are preserved as explicit workflow history; their old approval requests are superseded by the recorded design approval. Runtime/source checks still assigned to the current slices remain required.

Binding recovery 2026-11-03: Slice 1 is implemented and independently VERIFIED, with workspace782/0/21 and current-image E2E1/0/0. Completion recording refused because the presentation identity and approved verification descriptors changed. Reopen Gates3–4 for a fresh combined binding review; preserve scope/architecture approvals and all runtime evidence. See evidence/approval-binding-recovery.md and evidence/slice-1.md.
