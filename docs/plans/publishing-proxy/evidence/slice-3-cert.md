# Slice 3 bounded spec verdicts — 2026-11-03

Verdict: PASS for each of the three named current-source structural properties; each matching unsafe control is FAIL as expected.
Evidence tier: Structural.

All three unchanged, file-backed ordered specs complete with zero scoped findings against current source and one grounded finding against their retained unsafe controls.

| Spec | Current source | Unsafe control | Bounded claim |
|---|---|---|---|
| service-removal-marker-after-put | PASS | FAIL, expected commit_service_removal_marker at service_unpublish.rs:25 | Resolver call dominates marker commit in record_successful_service_removal |
| service-unpublish-reference-before-send | PASS | FAIL, expected app.transport.send_action at service_unpublish.rs:103 | Reference-check call dominates send in consume_service_marker_then_send |
| service-unpublish-marker-before-delete | PASS | FAIL, expected app.transport.send_action at service_unpublish.rs:103 | Marker-consumption call dominates send in consume_service_marker_then_send |

## Evidence

1. Removal pair: safe 1 operation, 1 guard, 0/1 unguarded; unsafe 1 operation, 0 guards, 1/1 unguarded and one retained finding.
2. Reference pair: safe 10 operations, 1 guard, 9/10 unguarded before caller scope filtering, zero retained findings; unsafe 1 operation, 0 guards, one retained finding at the expected send.
3. Marker pair: safe 10 operations, 1 guard, 9/10 unguarded before caller scope filtering, zero retained findings; unsafe 1 operation, 0 guards, one retained finding at the expected send.
4. SHA-256 binding below matches before and after the deciding runs and the prior authoring report. No source, control, spec or model was edited by this agent.
5. The two send-order unsafe findings preserve exact summary `Operation 'app.transport.send_action' lacks required guard`; the approved model's `Operation 'send_action' lacks required guard` expectation remains unresolved.

Omitted deciding items: 0.

## Binding

Safe root: `/home/john/go/src/github.com/postfix/probation`.
Unsafe roots: `/home/john/go/src/github.com/postfix/probation/.scratch/slice3-specs/<spec-name>/unsafe`.
The bound unsafe files are the earlier approved one-guard-call mutations documented in slice-3-specs.md; hash equality preserves that exact subject.

Before/after SHA-256 (unchanged):

```text
0c49a83b5d1e54edef99a5da501bf246156acb0f2c70907325a0cfac59143301  /home/john/go/src/github.com/postfix/probation/src/http/service_unpublish.rs
2359ca96180dccb09bfaaa57003d25115eeb2f6b9cf348a4df5e3795115b3181  /home/john/go/src/github.com/postfix/probation/.scratch/slice3-specs/service-removal-marker-after-put/unsafe/src/http/service_unpublish.rs
ff8e089c785e0d273e3d853a9e5a86e437391de844a6ddeee4ce3e9955467e9d  /home/john/go/src/github.com/postfix/probation/.scratch/slice3-specs/service-unpublish-reference-before-send/unsafe/src/http/service_unpublish.rs
c268996232b5fc82d04943b5e3a7b2c990e03df78bfd54ca4a943f48b281a136  /home/john/go/src/github.com/postfix/probation/.scratch/slice3-specs/service-unpublish-marker-before-delete/unsafe/src/http/service_unpublish.rs
9b10f579ee58592213bf5e4a84983d480851c3f1065ffbf156d7dc23e96ba3c1  /home/john/go/src/github.com/postfix/probation/docs/plans/publishing-proxy/specs/service-removal-marker-after-put.yaml
cbb99d749b5576acbadf5b54786d4cd552dd45410064e12107c93b6ecca5dabd  /home/john/go/src/github.com/postfix/probation/docs/plans/publishing-proxy/specs/service-unpublish-reference-before-send.yaml
2951b7e029318e172cbd86f9b695aa27bfc5e75e9c862714f06c1886c8881a56  /home/john/go/src/github.com/postfix/probation/docs/plans/publishing-proxy/specs/service-unpublish-marker-before-delete.yaml
```

## Limits

The registry inventory lists 28 historical analyzers and does not register these three planned files. The parent explicitly supplied absolute path TARGETs; each exact file was resolved with SMTC file read and passed unchanged via --spec-file. No registry persistence or name substitution occurred.

These are cfg_dominance structural verdicts. The runner emits neither an explicit fidelity field nor a functions-analyzed count; available completeness evidence is nonzero operation/guard discovery and completed, non-vacuous dominance/filter traces. All six runs return outer ok=true, complete inline results, empty refs/diagnostics and no truncation. Unsafe findings report structural confidence. No compiler or exported certificate evidence is claimed.

Classifier remains separately UNKNOWN from the supplied doctor result: CFG cannot resolve its operation block. This run does not recheck service_registry.rs, which another agent is changing. Neither this classifier gap nor the two summary expectation mismatches is normalized away or upgraded by these PASS verdicts. Complete contract certification remains UNKNOWN.

No runtime proof is supplied for exact values, upstream authorization, persistence/recovery, quota, atomic one-winner consumption, replay, restart, SSRF/credentials or DELETE behavior. Unsafe controls are structural source copies, intentionally not executable Rust builds.

## SMTC receipt

Session: sf-slice3-cert-2026-11-03. Local argv contain no secrets; no redaction required.

### Inventory and target resolution

```text
smtc spec list --root /home/john/go/src/github.com/postfix/probation --format json --max-tokens 2048 --session-id sf-slice3-cert-2026-11-03
```

Status: run; outer ok=true; inner 28 specs; no refs, diagnostics or truncation; fidelity/functions analyzed not emitted (inventory). Request req-25513-1793722126507-0. First project operation, prior to source reads; inventory alone is not proof.

Exact planned spec targets were resolved by the following run legs (outer ok=true; inner full contents, 10/8/8 lines; no refs/truncation/diagnostics; fidelity/functions analyzed not emitted, text-only resolution):

```text
smtc file read --root /home/john/go/src/github.com/postfix/probation --path docs/plans/publishing-proxy/specs/service-removal-marker-after-put.yaml --format json --max-tokens 2048 --session-id sf-slice3-cert-2026-11-03
smtc file read --root /home/john/go/src/github.com/postfix/probation --path docs/plans/publishing-proxy/specs/service-unpublish-reference-before-send.yaml --format json --max-tokens 2048 --session-id sf-slice3-cert-2026-11-03
smtc file read --root /home/john/go/src/github.com/postfix/probation --path docs/plans/publishing-proxy/specs/service-unpublish-marker-before-delete.yaml --format json --max-tokens 2048 --session-id sf-slice3-cert-2026-11-03
```

Supporting authoring report read: status run, outer ok=true; full-file response truncated into ref-95 (3182 estimated tokens), not opened. Narrowed reads of lines 1–42, 43–64 and 85–120 returned complete inline contents without refs/truncation/diagnostics. These are Manual context only, not the verdict source. Exact base argv: `smtc file read --root /home/john/go/src/github.com/postfix/probation --path docs/plans/publishing-proxy/evidence/slice-3-specs.md --format json --max-tokens 2048 --session-id sf-slice3-cert-2026-11-03`; narrowed legs add respectively `--start-line 1 --end-line 42`, `--start-line 43 --end-line 64`, and `--start-line 85 --end-line 120`.

Report destination check: `smtc file find --root /home/john/go/src/github.com/postfix/probation --pattern 'docs/plans/publishing-proxy/evidence/slice-3-cert.md' --max-results 20 --format json --max-tokens 2048 --session-id sf-slice3-cert-2026-11-03`; run, outer ok=true, zero matches, no refs/truncation/diagnostics, fidelity/functions not applicable.

### service-removal-marker-after-put — safe

```text
smtc spec run --root /home/john/go/src/github.com/postfix/probation --spec-file /home/john/go/src/github.com/postfix/probation/docs/plans/publishing-proxy/specs/service-removal-marker-after-put.yaml --format json --max-tokens 2048 --session-id sf-slice3-cert-2026-11-03
```

Status: run; exit 0; outer ok=true; inner completed, 0 findings; request req-31614-1793722175709-0; generation 71. Trace: 1 operation sites found; 1 guard sites found; 0/1 operations unguarded; 0 findings before filter, 0 after. Explicit fidelity/functions-analyzed fields: not emitted. Findings confidence: not applicable (no findings); no VacuousObligation, refs, truncation or diagnostics. Interpretation: PASS for named structural property.

### service-removal-marker-after-put — unsafe

```text
smtc spec run --root /home/john/go/src/github.com/postfix/probation/.scratch/slice3-specs/service-removal-marker-after-put/unsafe --spec-file /home/john/go/src/github.com/postfix/probation/docs/plans/publishing-proxy/specs/service-removal-marker-after-put.yaml --format json --max-tokens 2048 --session-id sf-slice3-cert-2026-11-03
```

Status: run; exit 0; outer ok=true; inner completed, 1 findings; request req-31606-1793722175655-0; generation 0. Trace: 1 operation sites found; 0 guard sites found; 1/1 operations unguarded; 1 findings before filter, 1 after. Explicit fidelity/functions-analyzed fields: not emitted. Findings confidence: structural; no VacuousObligation, refs, truncation or diagnostics. Interpretation: FAIL at expected unsafe-control site; positive control fires.

### service-unpublish-reference-before-send — safe

```text
smtc spec run --root /home/john/go/src/github.com/postfix/probation --spec-file /home/john/go/src/github.com/postfix/probation/docs/plans/publishing-proxy/specs/service-unpublish-reference-before-send.yaml --format json --max-tokens 2048 --session-id sf-slice3-cert-2026-11-03
```

Status: run; exit 0; outer ok=true; inner completed, 0 findings; request req-31610-1793722175668-0; generation 71. Trace: 10 operation sites found; 1 guard sites found; 9/10 operations unguarded; 9 findings before filter, 0 after. Explicit fidelity/functions-analyzed fields: not emitted. Findings confidence: not applicable (no findings); no VacuousObligation, refs, truncation or diagnostics. Interpretation: PASS for named structural property.

### service-unpublish-reference-before-send — unsafe

```text
smtc spec run --root /home/john/go/src/github.com/postfix/probation/.scratch/slice3-specs/service-unpublish-reference-before-send/unsafe --spec-file /home/john/go/src/github.com/postfix/probation/docs/plans/publishing-proxy/specs/service-unpublish-reference-before-send.yaml --format json --max-tokens 2048 --session-id sf-slice3-cert-2026-11-03
```

Status: run; exit 0; outer ok=true; inner completed, 1 findings; request req-31604-1793722175618-0; generation 0. Trace: 1 operation sites found; 0 guard sites found; 1/1 operations unguarded; 1 findings before filter, 1 after. Explicit fidelity/functions-analyzed fields: not emitted. Findings confidence: structural; no VacuousObligation, refs, truncation or diagnostics. Interpretation: FAIL at expected unsafe-control site; positive control fires.

### service-unpublish-marker-before-delete — safe

```text
smtc spec run --root /home/john/go/src/github.com/postfix/probation --spec-file /home/john/go/src/github.com/postfix/probation/docs/plans/publishing-proxy/specs/service-unpublish-marker-before-delete.yaml --format json --max-tokens 2048 --session-id sf-slice3-cert-2026-11-03
```

Status: run; exit 0; outer ok=true; inner completed, 0 findings; request req-31603-1793722175608-0; generation 71. Trace: 10 operation sites found; 1 guard sites found; 9/10 operations unguarded; 9 findings before filter, 0 after. Explicit fidelity/functions-analyzed fields: not emitted. Findings confidence: not applicable (no findings); no VacuousObligation, refs, truncation or diagnostics. Interpretation: PASS for named structural property.

### service-unpublish-marker-before-delete — unsafe

```text
smtc spec run --root /home/john/go/src/github.com/postfix/probation/.scratch/slice3-specs/service-unpublish-marker-before-delete/unsafe --spec-file /home/john/go/src/github.com/postfix/probation/docs/plans/publishing-proxy/specs/service-unpublish-marker-before-delete.yaml --format json --max-tokens 2048 --session-id sf-slice3-cert-2026-11-03
```

Status: run; exit 0; outer ok=true; inner completed, 1 findings; request req-31605-1793722175646-0; generation 0. Trace: 1 operation sites found; 0 guard sites found; 1/1 operations unguarded; 1 findings before filter, 1 after. Explicit fidelity/functions-analyzed fields: not emitted. Findings confidence: structural; no VacuousObligation, refs, truncation or diagnostics. Interpretation: FAIL at expected unsafe-control site; positive control fires.

Skipped: compiler/certificate export and heavy workspace/E2E/quota checks. Risk: these bounded structural PASS verdicts do not close the classifier or exact model-summary blockers.

