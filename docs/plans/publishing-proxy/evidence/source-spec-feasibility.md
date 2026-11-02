# Publishing proxy source-spec feasibility (2026-10-25)

**Verdict: UNKNOWN.** No analyzer has been validated for the four planned Rust operations. The required production sources do not exist yet, and the installed SMTC Rust backend cannot establish that the context value validated for a host and registry is the exact context used for an outbound operation. An earlier capability probe and independent doctor check found that `ordered_obligation.relation.same_argument` supports TypeScript and JavaScript only; see [the Rust same-value evidence](smtc-rust-same-value.md).

The existing analyzer registry has 16 specs and none owns `resolve_context`, `serve_package_read`, `forward_registry_action`, or `revoke_host`. I added tiny Rust safe and wrong-value fixtures in `../specs/controls/` for a future capability check. No proposed spec has been installed in `.smtc/analyzers/` or declared in `molecule-contracts.json` because the controls have not passed.

| Planned operation | Source claim requiring proof | Defect control in `../specs/controls/wrong-value/src/lib.rs` | Current analyzer feasibility |
|---|---|---|---|
| `resolve_context` | The active host and registry resolved in the same organization become the returned immutable context. | Validate `(host, registry)` but construct the context with `other_registry`. | Call dominance could detect an omitted or late validation. It would not prove the validated registry is returned. Same-value support is unavailable for Rust. |
| `serve_package_read` | The same selected context governs policy, upstream selection, cache identity, and response links. | Check policy for `context` but send the read with `other_context`. | Call dominance would miss this wrong-value defect. Independent runtime regression and source review are required. |
| `forward_registry_action` | Caller Authorization goes only to the selected context's upstream; shared download credentials cannot enter this path. | Validate `context` but send the action with `other_context`. | Call dominance would miss this wrong-value defect. Credential provenance and redirect behavior also need runtime checks. |
| `revoke_host` | Revoking a host invalidates its next lookup, with no stale accepted result. | Mark `host` revoked but invalidate `other_host` in the cache. | Call dominance would miss this wrong-value defect. A post-revocation lookup test and fail-closed outage test are required. |

The ordered-obligation candidate for `resolve_context` used `validate_host_and_registry` as guard, `build_context` as operation, `must_dominate: true`, `evidence: full`, and `where: "caller_function == 'resolve_context'"`. Both safe and wrong-value fixture runs failed **before analysis** with `daemon_unavailable`: the process could not connect to `/home/john/.cache/smtc/daemon/daemon.sock` (`Operation not permitted`). The main agent's `sf-smtc-doctor health` check then reported a healthy daemon, but one exact retry of the safe fixture returned the same socket permission error. This is an invocation-context blocker, not a source finding. The exact retried argv is shown below; the initial wrong-value run used the same `--spec` with `--root` ending in `/wrong-value`. Even if both runs become executable, a wrong-value fixture that produces zero findings rejects this candidate for the exact-value claim.

```text
smtc spec run --root /home/john/go/src/github.com/postfix/probation/docs/plans/publishing-proxy/specs/controls/safe --spec 'name: resolve-context-same-registry
kind: ordered_obligation
severity: high
evidence: full
guard: {calls: {name: [validate_host_and_registry]}}
operation: {calls: {name: [build_context]}}
relation: {must_dominate: true}
where: "caller_function == '\''resolve_context'\''"' --format json --max-tokens 2048 --session-id sf-source-specs-2026-10-25
```

No weaker call-order claim should replace the selected exact-context requirement in the source contract. A typed, immutable request context can make value substitution harder to write, but only focused tests and review currently check that it is actually used. `molecule-verify` must remain PENDING while source is absent and UNKNOWN if it reaches a slice without a valid analyzer and controls.

## SMTC receipt

- `spec list --root /home/john/go/src/github.com/postfix/probation --format json --max-tokens 2048 --session-id sf-source-specs-2026-10-25`: **run**, outer `ok: true`, 16 specs, complete inline result, no overlap. Structural inventory.
- `file read` on `01-product.md`, `02-architecture.md`, `molecule-flow.json`, and `evidence/smtc-rust-same-value.md`, each with the same root, JSON format, 2048-token bound and session: **run**, outer `ok: true`; long files were narrowed to line ranges, complete ranges used. Manual contract evidence.
- `spec run` on safe and wrong-value fixture roots with the candidate above, and one safe-root retry after the doctor's healthy verdict: **refused by host**, outer `ok: false`, `daemon_unavailable`, no functions analyzed or findings, no ref. No inference about analyzer behavior is drawn from these failures.
- Native fallback after the supplied healthy-doctor verdict and repeated EPERM: `rg -n 'Verdict|wrong-value|doctor|SMTC receipt' docs/plans/publishing-proxy/evidence/source-spec-feasibility.md` confirmed the saved evidence text. This is reduced evidence; no post-edit SMTC verification was possible.

Tier: Manual for contract mapping; no structural or decision-grade source proof. Limitations: absent production Rust, unavailable `spec run`, and confirmed unsupported Rust same-argument relation.
