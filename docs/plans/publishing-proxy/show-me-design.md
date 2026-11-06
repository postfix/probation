## What problem do we have?

Shared-service npm/PyPI reads: implemented, VERIFIED. Prerequisite—service API, cached policy and access checks—done. Slice 1 recording awaits approval.

## How will we solve it?

Behavior/signatures stay unchanged: one policy → shared service → selected registry; separate credentials, no fallback.

Corrected descriptors (18 labels; three specs):
```diff
- activate
+ ServicePolicy.activate
+ evidence: full
```
Exact activation identity and fuller diagnostics; guards/controls unchanged. The saved presentation also changed after approval.

[sf-start](/home/john/.local/share/software-factory/releases/f1f0153cb1e4866d71fd95a69aee0d468b4d75096c451526f2e7da2d26e45f26/skills-codex/sf-start/SKILL.md) requires: “Changes to approved model, source-obligation sidecar or analyzer specs require reopening the affected design”. This applies to corrected descriptors; previous approval cannot transfer.

[Unchanged security/contracts](/home/john/go/src/github.com/postfix/probation/docs/plans/publishing-proxy/03-program-design.md#security-coverage) retain credential confinement, private metadata, safe audit and guarded unpublish. [Order](/home/john/go/src/github.com/postfix/probation/docs/plans/publishing-proxy/04-slices.md): reads → audit/token metadata → npm actions/unpublish → PyPI publishing → native acceptance.

## How will we confirm it is solved?

| Check | Observed result |
|---|---|
| Workspace tests | 782 passed, 0 failed, 21 ignored |
| Compiler | PASS |
| Real npm/pip E2E | 1/1 passed |
| Code/security/adversarial | Passed |
| Implementation / Design QA | VERIFIED / READY |
| Source ordering | 6 PASS; 3 future PENDING |

Recommendation: Approve: behavior is unchanged.

Context: Gates 1–2 approved; 3–4 reopened.

CPU: Yes—our builds contributed earlier; they are finished. They were capped at two cores/low priority. Other identified busy processes belong to another project; total attribution remains unknown.

Sources: [QA](/home/john/go/src/github.com/postfix/probation/docs/plans/publishing-proxy/gate-4-qa.md), [verification](/home/john/go/src/github.com/postfix/probation/docs/plans/publishing-proxy/evidence/slice-1-verification.md), [binding correction](/home/john/go/src/github.com/postfix/probation/docs/plans/publishing-proxy/evidence/approval-binding-recovery.md).

Limits: audit/publishing/native-OS checks and three Slice 3 obligations remain; foundation only.

Approve the design, or what should change?
