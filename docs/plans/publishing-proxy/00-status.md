# Status: Transparent package publishing

- Gate 1 — Product: APPROVED 2026-10-27
- Gate 2 — Architecture: APPROVED 2026-10-29
- Gate 3 — Program Design: APPROVED 2026-10-29
- Gate 4 — Slice plan: APPROVED 2026-10-29

## Factory settings

- presentation: auto

## Loop signal

{"generation":35,"boundary":null,"reopened":false,"history":[],"presentedSlice":5}

## Gate 1 progress

- [x] Create 00-status.md
  Result: docs/plans/publishing-proxy/00-status.md was created from the Gate 1 template.
- [x] Select the plan with router resume
  Result: router resume selected docs/plans/publishing-proxy with no findings.
- [x] Create the product clarification inventory
  Result: 01-product.md contains the Gate 1 clarification inventory.
- [x] Resolve user decisions
  Result: 01-product.md C36-C38 record the distinct selected URL, reduced audit advisories and transparent proxy behavior clarified by the user on 2026-10-27.
- [x] Review UI mockups with the user
  Result: The registry-admin screens were previously approved; corrected certificate settings and separate Users screens were approved on 2026-10-26, and all linked states were included in the Gate 1 presentation approved on 2026-10-26.
- [x] Complete 01-product.md
  Result: 01-product.md C36-C38, Problem, Success metric and Non-goals plus client-operation-matrix.md N04 capture the revised URL and audit outcomes; C34-C35 remain.
- [x] Obtain QA READY
  Result: Fresh gate-1-qa.md sealed READY with no findings for C36-C38 and N04; router gate-qa verify --gate 1 returned READY on 2026-10-27.
- [x] Present and record user approval
  Result: The revised show-me-gate-1.html was bound to READY scope QA, presented, approved by the user on 2026-10-27, and router gate-qa approve --gate 1 recorded APPROVED.

## Gate 2 progress

- [ ] Check whether existing architecture and evidence can be reused
  Result: Approved 01-product.md and screens remain current; the host/password architecture was superseded and replaced after C29-C31.
- [ ] Create or update the architecture and carry deferred questions
  Result: 02-architecture.md carries C24/C29-C31 and resolves the certificate identity, revocation freshness and TLS seam in D34-D37.
- [ ] Gather repository evidence
  Result: evidence/repository-structure.md maps TLS listener, key admission, membership/group policy and portal gaps; evidence/research-4.md establishes revocation freshness limits.
- [ ] Save findings and resolve architecture decisions
  Result: One organization registry URL, URI SAN membership UUID, current certificate/member/status checks and same-organization registry join are documented in 02-architecture.md.
- [x] Complete 02-architecture.md
  Result: Flow 3 now explicitly distinguishes tokenless web-login start/poll, credentialed N06 legacy Basic login and token-required later writes; D38-D39 and the token-packument exception remain.
- [ ] Record architecture assumptions and review triggers
  Result: 02-architecture.md Constraints/External state issuer status and availability prerequisites; current threat model and Red Team were invalidated for fresh review.
- [ ] Complete architecture section of the combined design
  Result: molecule-flow.json adds token-packument-hidden success, upstream-denied and unavailable routes; router molecule-check reports PASS.
- [ ] Carry contracts and obligations into program design
  Result: molecule-contracts.json now binds seven implemented Slice 1 source checks and five absent later-slice checks; evidence/source-contract-rebind.md records PASS/PENDING and the exact-value runtime/source-review limits.

Rework: Preserve the approved product promise; design a safe reference for npm version-unpublish after the token packument version is removed, rebind exact source controls, then repeat combined design QA and approval. Prior results above are historical.

Rework: Reconcile architecture Flow 3 login credential wording with approved N06 legacy Basic login, then repeat combined design reviews and approval. The product outcome is unchanged.

## Gate 3 progress

- [ ] Create or update the design from its template
  Result: 03-program-design.md now describes TLS peer evidence, certificate admission, one URL, signed-in setup, guarded reads and upstream-authorized actions.
- [ ] Gather design evidence
  Result: evidence/repository-structure.md, client-certificate-support.md, research-4.md and client-operation-matrix.md v5 ground current source and client/provider constraints.
- [ ] Record effects on callers, dependencies, and planned checks
  Result: 03-program-design.md Files, Call stack and Test plan link TLS, portal, management, storage, package routes, clients and observable failures.
- [ ] Define interfaces, behavior, invariants, and test cases
  Result: 03-program-design.md specifies distinct route classification, safe bulk/quick advisory rendering, finite audit work, numeric legacy and nonempty/invalid audit controls, and X09-X11 outcomes in all certificate modes.
- [x] Validate analyzer specs or assign their authoring to slices
  Result: evidence/source-contract-rebind-slice4.md records eight exact Slice 4 mutation-statement rebinds on frozen source; model and all due production/unsafe controls PASS. Approved analyzer specs and guarantees are unchanged.
- [x] Define security coverage and resolve required planning reviews
  Result: 03-program-design.md inventories all N05-N23 routes including whole-package revision DELETE; fresh evidence/threat-model-npm-route-final.md returned MODELED and evidence/red-team-npm-route-final.md returned SOUND.
- [x] Complete contracts and flows for the combined design
  Result: Router molecule-check PASS; molecule-verify --slice 4 PASS on all current obligations and mutations after exact control rebind, evidence run-7uzC0X. Structural proof limits and remaining runtime witnesses are recorded in evidence/source-contract-rebind-slice4.md.
- [x] Carry guarantees and checks into delivery slices
  Result: 04-slices.md assigns the seven corrected Slice 1 structural checks and exact member, self-service and route witnesses; Slice 3 owns the absent token-packument source, and all later guarantees retain direct witnesses.

Rework: Preserve the approved product promise; design a safe reference for npm version-unpublish after the token packument version is removed, rebind exact source controls, then repeat combined design QA and approval. Prior results above are historical.

Rework: Slice 4 production checks pass, but eight approved unsafe mutation controls cannot apply their illustrative exact source statements. Rebind those controls to the meaningful frozen source shape without changing D40/D41 guarantees; rerun combined design QA and approval. Slice 3 proof remains valid.

Rework: Fresh Slice 4 security review found the direct canonical tarball DELETE route can bypass the accepted-removal marker. Add that entry point to security coverage and require local refusal before outbound I/O. Independent adversarial review found a leased retained version can submit a changed ordinary upstream URL; specify exact leased URL preservation without rejecting valid unleased upstream URLs. Recheck the design and obtain combined approval before implementation resumes.

Rework result: The direct canonical DELETE and leased-URL design is explicit in 03-program-design.md, 04-slices.md and molecule-flow.json. Fresh threat review MODELED and Red Team SOUND are in evidence/threat-model-direct-delete.md and evidence/red-team-direct-delete.md. Router molecule-check PASS and molecule-verify --slice 4 PASS for existing structural obligations at run-ArzeXw; the two new exact-value/route controls remain Slice 4 runtime and security-review work.

## Gate 4 progress

- [x] Write the slice plan
  Result: 04-slices.md assigns selected-URL setup, safe audit and numeric-legacy checks to Slice 3; D40/D41 approved extra-destination, marker and pinned npm witnesses to Slice 4; Python and full matrix to Slice 5.
- [x] Define slice behavior and dependencies
  Result: Slices 1-5 deliver Probation setup/npm install, enterprise status and registry isolation, full npm reads, npm actions, and Python/uv/full matrix.
- [x] Define checks
  Result: Slice 3 requires numeric legacy paths, nonempty safe advisories, malformed/over-limit refusals, real npm 11 detection and upstream bulk-error transparency; Slice 5 asserts all X09-X11 certificate-mode outcomes.
- [x] Validate prerequisites
  Result: Router check has no witness-tool findings; disposable pinned-client one-URL/TLS/credential probes now precede Slice 1 code, and real issuer integration remains required before activation.
- [x] Complete required combined design reviews
  Result: Fresh evidence/threat-model-npm-route-final.md MODELED and evidence/red-team-npm-route-final.md SOUND cover N05-N23, N06 Basic login, whole-package DELETE and all version-deletion routes; model PASS and current source controls PASS at run-prCSoM.
- [x] Obtain QA READY
  Result: Fresh gate-4-qa.md sealed and verified READY on the corrected 02-04 design, with no findings; sixteen model flows and all twenty-one current source obligations/unsafe controls PASS. Exact whole-package DELETE route behavior remains Slice 4 runtime work.
- [x] Present and record user approval
  Result: The corrected whole-package DELETE design was presented in show-me-design-npm-routes.html and approved by the user on 2026-10-29; router gate-qa approve --gate design returned APPROVED.

Rework: Preserve the approved product promise; design a safe reference for npm version-unpublish after the token packument version is removed, rebind exact source controls, then repeat combined design QA and approval. Prior results above are historical.

Rework: The same eight Slice 4 control strings need exact source rebinding; existing planned outcomes and Slice 3 completion are preserved.

Rework: Extend the Slice 4 witness to reject direct canonical tarball DELETE before upstream and changed tarball URLs for leased retained versions. Prior Slice 4 source and client results predate these controls.

Rework result: Slice 4 now requires changed leased-URL refusal with valid unleased URL compatibility and direct canonical tarball DELETE refusal with zero outbound calls. Threat review MODELED and Red Team SOUND; finite model PASS, existing structural controls PASS. Combined QA and user approval remain due.

Rework: Fresh Slice 4 security review found the upstream-authorized whole-package revision DELETE is a separate public route absent from the Threat model inventory. Add its authorization boundary and a direct allow/deny witness, repeat design reviews and combined approval, then finish Slice 4. No marker bypass was established.

## Slices

- [x] Slice 1 — Probation certificate setup and npm install
  - proof: test -f tests/e2e/scenarios/publishing-certificate-npm.mjs && TMPDIR="$PWD/.scratch/tmp" node tests/e2e/harness/run.mjs --only E2E-publishing-certificate-npm -> 1 passed, 0 failed, 0 not run; cargo check PASS; model PASS; seven due source controls PASS; reviews: code-review=SHIP, security=CLEAR, adversarial=PASS, qa=VERIFIED
- [x] Slice 2 — enterprise certificates and registry isolation
  - proof: test -f tests/e2e/scenarios/publishing-enterprise-registry.mjs && TMPDIR="$PWD/.scratch/tmp" node tests/e2e/harness/run.mjs --only E2E-publishing-enterprise-registry -> 1 passed, 0 failed, 0 not run; cargo check PASS; model PASS; nine due source controls PASS; reviews: code-review=SHIP, security=CLEAR, adversarial=PASS, qa=VERIFIED
- [x] Slice 3 — complete guarded npm reads
  - proof: test -f tests/e2e/scenarios/publishing-npm-read.mjs && TMPDIR="$PWD/.scratch/tmp" node tests/e2e/harness/run.mjs --only E2E-publishing-npm-read -> 1 passed, 0 failed, 0 not run; cargo check PASS; model PASS; 13 due source controls PASS; reviews: qa=VERIFIED, code-review=SHIP, security=CLEAR, adversarial=PASS
  - rework: token packument artifact links and reads need fresh source and runtime proof after the design revision; historical proof remains in evidence/slice-3.md.
- [x] Slice 4 — npm publishing and administration
  - proof: TMPDIR="$PWD/.scratch/tmp" node tests/e2e/harness/run.mjs --only E2E-publishing-npm-actions -> 1 passed, 0 failed, 0 not run; final source model and 21 source controls PASS; full Rust workspace 760 passed, 0 failed, 21 ignored; reviews: qa=VERIFIED, code-review=SHIP, security=CLEAR, adversarial=PASS
- [x] Slice 5 — Python and uv workflows
  - proof: test -f tests/e2e/scenarios/publishing-full-matrix.mjs && node tests/e2e/harness/run.mjs --only E2E-publishing-full-matrix -> 19/19 runners passed; 123/123 row-mode cases observed; JUnit 1 passed, 0 failed, 0 skipped; focused private-CIDR withdrawal regression passed; cargo check PASS; finite model PASS; 21/21 source controls PASS; reviews: qa=VERIFIED, code-review=SHIP, security=CLEAR, adversarial=PASS

## Notes for a fresh session

Reopened Gate 1 on 2026-10-27 after the user chose a distinct selected-registry URL and reduced, policy-safe audit advisories and requested investigation of proxy fallback. Pinned npm 11 sends only names and versions to bulk audit while quick audit needs a full dependency tree, so a general proxy translation cannot faithfully recover the missing input. C38 is resolved: Probation only proxies the selected registry; npm 11 reports an upstream bulk failure, and direct quick clients retain guarded access. No advisory server or fabricated fallback is added. Slices 1–2 passed historically but their selected-URL witnesses must rerun under the new path. Slice 3's nonempty audit control remains red until revised design approval and implementation. See `evidence/slice-3.md`.
On 2026-10-28, Slice 4 QA found that version unpublish fails for an otherwise capable selected upstream with a noncanonical tarball URL. Preserve Gate 1; reopen Gate 2 and the combined design for a safe URL reference, then reverify affected Slice 3 and Slice 4. The exact source controls for package policy and action origin also need rebinding to current signatures. See `evidence/slice-4.md` and `evidence/research-8-nora.md`.

On 2026-10-28, Slice 4 code and pinned npm action E2E passed the canonical, noncanonical and approved extra-origin restart paths, but all eight new defect controls were UNKNOWN because exact `from` text in molecule-contracts.json predates implementation. Reopen Gate 3 for control rebinding only; preserve the approved D40/D41 behavior. See evidence/slice-4.md and contract-evidence run-cfTjHy.

On 2026-10-30, all five slices are complete and the Slice 5 presentation was accepted. The final pinned client matrix passed 19/19 runners and 123/123 row-mode cases, including 10,000 distinct certificate-backed admissions per provider. The private-PyPI upload approval-withdrawal regression passed; cargo check, finite model and 21/21 source controls passed. Fresh code, security, adversarial and implementation reviews returned SHIP, CLEAR, PASS and VERIFIED. Post-completion verification on the corrected source passed the full Rust workspace suite (762 passed, 0 failed, 21 ignored) and a fresh containerized OpenSSL issuer transition (1 passed, 0 failed). The portal still requires each actual organization issuer to prove a fresh good-to-revoked transition before activation. See `evidence/slice-5.md` and `show-me-slice-5.md`.

## Source contract evidence

Required for this plan.
