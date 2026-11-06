# Design QA
## Verdict
READY

## Overall assessment
The combined design is ready for presentation. The prior finding DQA-F2 is resolved: every active invariant disposition line begins with an allowed prefix. The credential boundary remains explicit: the service API key is sent only in the HTTP Authorization header for the policy snapshot request, and package-manager credentials go only to the selected registry. Fresh molecule checks pass, and all existing source obligations and their controls pass.

## Questions and findings
None.

## What was checked
- **Approved scope and decisions:** Read approved `01-product.md` with proposed `02-architecture.md`, `03-program-design.md`, and `04-slices.md`. The selected nine-family scope, local/approved-node access model, managed and standalone modes, no fallback, and service-level policy are consistent. No unresolved user-owned planning choice remains.
- **Architecture, interfaces, and caller effects:** Reviewed active ownership across this plan and `package-firewall-mvp`, package operation flows, registry selection, failure behavior, and effects on current npm/PyPI callers. Repository evidence identifies the delivered certificate path as historical and partial, links its caller map, and distinguishes it from absent future service modules.
- **Contracts, flows, and required outcomes:** Fresh `molecule-check` returned PASS. The model represents policy acquisition, selected-registry reads/actions, token-packument, safe audit, and three distinct DELETE paths, including local refusal, upstream allow/deny, revision verification, marker commit, and guarded consumption. The threat model and independent Red Team review are current for the captured design subjects and cover all three DELETE routes.
- **Security coverage and credential policy:** The security table maps credential separation, local policy and upstream authority, token-private metadata, audit disclosure, route confusion, reference/marker safety, listener scope, and stale response release to selected checks and slice witnesses. The API key remains confined to the policy snapshot HTTP Authorization header; package-manager credentials remain confined to the selected registry. Extra-origin tarball destinations are refused before URL advertisement or outbound I/O.
- **Molecule source and controls:** Preparation returned PENDING for six obligations because their planned Slice 1 and Slice 3 source files are absent. The three obligations with existing source passed, and each unsafe control triggered its expected finding. Inspected the current action, token-packument, and audit-filter symbols through SMTC. These structural checks establish only their encoded call-order properties.
- **Delivery order and witnesses:** Slices 1–5 depend on lead Slice 16 and Slice 25 where required, then assign local read/audit, npm actions and unpublish, PyPI publishing, and native release acceptance. Caller scenarios state expected success and refusal outcomes, credential destinations, direct witnesses, relevant dependencies, and future source/runtime work. Exact value binding, durable marker semantics, concurrency, quotas, platform behavior, and runtime credential traces remain explicit delivery checks.
- **Disposition format:** Every nonempty active line under `## Invariants & spec dispositions` begins with `deferred to slice <N>:`, `existing check:`, or `UNKNOWN:`; this resolves DQA-F2.
- **Design and testability:** Applied `sf-codebase-design` to caller contracts, state ownership, seams, and cross-request marker lifetime. Applied `sf-tdd` to caller-level witnesses and defect-distinguishing outcomes. Read the full molecule model references and agent-writing instructions required by the review protocol.

## Limitations
Six declared source obligations remain PENDING because their future source files are absent. Structural checks and the finite model do not establish runtime credential routing, exact-value binding, marker durability/atomicity, concurrency, quotas, listener exposure, or native platform behavior; the plan assigns these to named slices. No product tests were run.

## Next steps
Present the combined design for user approval. Implementation remains gated on that approval and the stated slice prerequisites.
