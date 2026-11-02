# Final npm route red-team review

Review kind: red-team
Verdict: SOUND
Review: independent
Subject: slices `04-slices.md`=5b60c59c31059267f067053d1ba850c3ebfd52fafa0c19bad6712431cd211bde; upstream `01-product.md`=31b1037c3697b949ddb223fff9432eb7eeb875ea4043d787b8d0291257d76658, `02-architecture.md`=cefc11d374a80df8667ff8976deac0028523415a255db268e715e915366f10bd, `03-program-design.md`=412a522eca618b9a717b90f90cb1d84157ea8632fef7cf5e9a177f7422fd2121
Bottom line: The corrected design covers the complete N05–N23 route review denominator, separates web and Basic legacy login, and requires distinct witnesses for all three DELETE paths. The plan has no remaining design blocker; exact dispatch and authorization remain Slice 4 implementation checks.
Findings: none.
Checked clean: Coverage—N05–N23 and the selected mutation inventory map to Slice 4 and the full-matrix rerun; Dependencies—Slice 3 classifier and canonical packument read precede actions, with pinned request-shape probes before product edits; Risk order—N11 canonical/noncanonical/extra-origin probes and the denied shared-read credential happen before implementation; Foundations—certificate admission, selected registry, developer credential modes, lease, marker, quota and refusal rules precede their consumers; Verifiability—Slice 4 specifies real-client traces, upstream allow/deny, zero-outbound refusals, source review and a defect control; Sizing—Slice 4 is a coherent npm action increment with a direct E2E witness; Hard bar—one selected URL, upstream-only write authorization, no credential leak, and group-filtered artifact bytes each have explicit checks; Security—the supplied model's T1–T8 boundaries and verification properties are represented in the design and Slice 4 witnesses.
Threat model: MODELED (supplied `evidence/threat-model-npm-route-final.md`, b9d880d2815005a5473af90d426bc6fca19880ee16a9c252d20637d770e0d5e0).

Deciding evidence (Structural and Manual tier):

1. `evidence/client-operation-matrix.md` (abd351ca829e6033ff375247617be712c8d64f0db65ac062e46a0aee76071cbc) defines N05–N23, including N17 logout, N19 profile, N21 star, N23 trust, and N06 Basic legacy login; its required-row rule rejects skipped endpoints or traces.
2. `evidence/npm-write-route-inventory.md` (48214c7f73871d872a5b2eeff664a82397ff87db3437f7d5f906064e650b6652) enumerates whole-package revision DELETE, direct canonical tarball DELETE, and member-bound reference DELETE as separate public routes.
3. `02-architecture.md` Flow 3–4 and D40–D41 bind action credentials to the selected upstream, restrict tokenless bootstrap, and require current approval plus an accepted-removal marker for reference DELETE. `03-program-design.md` behavior 4 makes direct canonical tarball DELETE a local refusal.
4. `04-slices.md` Slice 4 requires upstream-allowed and upstream-denied whole-package DELETE, zero-outbound direct canonical tarball refusal, one-use reference DELETE with exact revision and destination, and route-by-route N05–N23 source review. `03-program-design.md` Security coverage names the same three paths separately.
5. The supplied threat model covers certificate admission, route confusion, Basic login, upstream authority, whole-package deletion, marker and destination integrity, disclosure, and resource bounds. The molecule contract for `publisher-auth-before-send` explicitly leaves route specificity and upstream denial to runtime controls.

Omitted evidence items: 0.
Limitations: This is a design review. No client command, exact route dispatch, credential byte flow, marker atomicity, or upstream authorization was executed here. Molecule models and structural source controls cannot prove those values; the planned Slice 4 source and runtime witnesses must do so. This review did not audit proposed source.

SMTC receipt: `file read` for the architecture, product, program design, slices, matrix, inventory, threat model, and relevant molecule contract/flow ranges; `file grep` for headings and molecule route/credential controls; `file find` for molecule paths. All legs ran with `--root /home/john/go/src/github.com/postfix/probation --format json --max-tokens 2048 --session-id sf-npm-routes-red-team-2026-10-28`; outer and inner status `ok`, no refusal, no code-function analysis applicable. Broad reads/searches were truncated; narrowed reads supplied the deciding passages. Fidelity: selected document text (Manual), plan/model structure (Structural). No ref over 4,096 estimated tokens was opened.
