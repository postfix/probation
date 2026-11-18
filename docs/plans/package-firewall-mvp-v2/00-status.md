SUPERSEDED by ../package-firewall-mvp-lf

# Status: Package Firewall MVP (version 2 successor)

- Gate 1 — Product: in progress
- Gate 2 — Architecture: pending
- Gate 3 — Program Design: pending
- Gate 4 — Slice plan: pending

## Factory settings

- presentation: auto

## Loop signal

{"generation":1,"boundary":{"kind":"gate","number":1},"reopened":false,"history":[{"from":"hand","reason":"start","to":"qa"},{"from":"qa","reason":"retry","to":"qa"},{"from":"qa","reason":"rework","to":"hand"},{"from":"hand","reason":"start","to":"qa"},{"from":"qa","reason":"rework","to":"hand"},{"from":"hand","reason":"start","to":"qa"}]}

## Gate 1 progress

- [ ] Create 00-status.md
- [ ] Select the plan with router resume
- [ ] Create the product clarification inventory
- [ ] Resolve user decisions
- [ ] Review UI mockups with the user
- [ ] Complete 01-product.md
- [x] Obtain QA READY
  Result: READY, verified; report docs/plans/package-firewall-mvp-v2/gate-1-qa.md
- [ ] Present and record user approval

## Gate 2 progress

- [ ] Check whether existing architecture and evidence can be reused
- [ ] Create or update the architecture and carry deferred questions
- [ ] Gather repository evidence
- [ ] Save findings and resolve architecture decisions
- [ ] Complete 02-architecture.md
- [ ] Record architecture assumptions and review triggers
- [ ] Complete architecture section of the combined design
- [ ] Carry contracts and obligations into program design

## Gate 3 progress

- [ ] Create or update the design from its template
- [ ] Gather design evidence
- [ ] Record effects on callers, dependencies, and planned checks
- [ ] Define interfaces, behavior, invariants, and test cases
- [ ] Validate analyzer specs or assign their authoring to slices
- [ ] Define security coverage and resolve required planning reviews
- [ ] Complete contracts and flows for the combined design
- [ ] Carry guarantees and checks into delivery slices

## Gate 4 progress

- [ ] Write the slice plan
- [ ] Define slice behavior and dependencies
- [ ] Define checks
- [ ] Validate prerequisites
- [ ] Complete required combined design reviews
- [ ] Obtain QA READY
- [ ] Present and record user approval

## Slices

- [ ] Slice 16 — fix-16-a: deliver-known-binding, deliver-cold-binding
- [ ] Slice 17 — rubygems: deliver-known-binding, deliver-cold-binding
- [ ] Slice 18 — cargo: deliver-known-binding, deliver-cold-binding
- [ ] Slice 19 — go: deliver-known-binding, deliver-cold-binding
- [ ] Slice 20 — nuget: deliver-known-binding, deliver-cold-binding
- [ ] Slice 21 — maven: deliver-known-binding, deliver-cold-binding
- [ ] Slice 23 — conan: deliver-known-binding, deliver-cold-binding
- [ ] Slice 24 — oci: deliver-known-binding, deliver-cold-binding
- [ ] Slice 25 — native-lifecycle: deliver-known-binding, deliver-cold-binding
- [ ] Slice 26 — cluster: deliver-known-binding, deliver-cold-binding
- [ ] Slice 27 — acceptance: deliver-known-binding, deliver-cold-binding
- [ ] Slice 28 — service-policy: deliver-known-binding, deliver-cold-binding
- [ ] Slice 29 — spike-native-cluster: deliver-known-binding, deliver-cold-binding

## Notes for a fresh session

New v2 plan; scope and design await approval.
