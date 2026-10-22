# Existing analyzers against the managed reference shapes

Date: 2026-10-21. Method: a synthetic snapshot of the repository with every `controls/reference/**/*.rs.txt` copied to its source path. On that snapshot I ran `smtc spec run --spec-file <spec> --root <root> --detail full --no-refs` with SMTC (`/home/john/.local/bin/smtc`).

| Spec | Root | Findings |
|---|---|---|
| client-data-reaches-delivery-sink | src/managed | 0 |
| consumer-identity-extension-read | src/managed | 0 |
| outbound-timeout-guard | src/managed | 0 (the `send` in `request_changes` sits beside `tokio::time::timeout`) |
| enqueue-timeout-guard | src/managed | 0 |
| outbound-timeout-guard, enqueue-timeout-guard | src/policy/effective.rs | 1 info record each, "obligation vacuous" (no `send` there), not a breach |

Same snapshot: `router molecule-verify --plan-root docs/plans/management-server` returned PASS, 12 of 12 contracts, with every control detected.

The baseline runs keep their documented roots and pass conditions in each spec's header. New code is checked with its own roots (src/managed, src/tasks/policy_sync.rs, crates/probation-server), and the pass condition is zero breach findings.
