# Local-client design grounding — 2026-11-02

Reviewer: sf-repo-view (`design_grounding`). Verdict: PARTIAL. Subject commit: `8d9f5e35b6d92898f6c9c33b852df5a9b04e8d59`; SMTC generation 55, dirty_build true. Structural orientation and selected source text, not a clean-commit or runtime certificate.

## Deciding findings

1. Lifecycle is unselected. `src/main.rs:29` supplies `serve --config PATH`; `src/config.rs:25` supplies a configurable listener. Existing `evidence/local-client-policy-modes.md` explicitly leaves per-user service, machine daemon and command wrapper open. C1003/C1016 defer lifecycle and C1018 defers Docker/runner topology. Q8/C1019 must be answered before selecting ownership and supervision.
2. Reuse enforcement, design scoped client policy retrieval. `src/lib.rs:200,324,355` selects principal/standalone policy and optional managed startup. `src/managed/client.rs:45–93` uses a FirewallToken for fleet lookup/layer/certificate calls, with redirects/environment proxies disabled. A local user API key needs a separate scope/authority contract; fleet tokens are not that contract. Shared resolution is in `crates/probation-policy/src/lib.rs`.
3. Credential custody changes. `src/managed/mod.rs:50–76` supplies principal policy, registry origin and optional shared read authorization. C1006/C1009/C1015 replace certificate-only admission and shared backend secrets on the new path. Client-owned credentials must stay bound to the selected upstream; the policy key must never enter registry requests.
4. Only npm and PyPI are present in the inspected protocol surface. `src/http/mod.rs:49–116`, `crates/probation-policy/src/lib.rs:56–59` and `src/policy/mod.rs:18–22` supply two-ecosystem routes/types. Maven, Go, Cargo, NuGet, CPAN, RubyGems, Conan and OCI require new contracts and runtime checks. Docker daemon-to-listener connectivity was not checked; no demonstrated Docker topology blocker is claimed.
5. Windows requires source work. Unconditional Unix imports occur in `src/main.rs:14`, `src/http/unpublish_reference.rs:5`, `src/delivery/mod.rs:19`, `src/delivery/file.rs:8`. The store lock uses fs4; its flock commentary does not prove it Unix-only. Existing rust.yml tests Ubuntu; release.yml builds Linux/macOS, with no Windows. Compilation is not native runtime acceptance.

## Remaining decisions

Service lifecycle/ownership; listener access and native-tool setup; enrollment/key scope/rotation/revocation; deliberate mode transitions; local credential storage/forwarding; supported client/version/OS matrix; Docker engine placement and reachability. These findings select none of them.

## SMTC receipt and limits

Root: `/home/john/go/src/github.com/postfix/probation`. Session: `sf-design-grounding-2026-11-02`. Question commands used that absolute root, JSON output and a 2048-token maximum (map: 1024). Run legs: map, inspect file/imports, architecture/cycles, file find/read/grep, entry-points and one bounded ref. Outer/inner status OK except absent `docs/codebase-overview.md`; no unsupported-language or operation refusal. Fidelity: structural orientation plus selected text; file reads have functions analyzed n/a. Broad discoveries were truncated and narrowed for deciding claims; large references were left unopened. The entry-point analysis had 2,053 unresolved dispatch sites and analyzed_clean false, so it is incomplete. The mixed production/test cycle is not a proven runtime defect. No native source fallback was used.

Representative exact reads (same root/session for each):

```text
smtc file read --root /home/john/go/src/github.com/postfix/probation --path src/managed/client.rs --start-line 45 --end-line 93 --format json --max-tokens 2048 --session-id sf-design-grounding-2026-11-02
smtc file read --root /home/john/go/src/github.com/postfix/probation --path src/http/mod.rs --start-line 49 --end-line 116 --format json --max-tokens 2048 --session-id sf-design-grounding-2026-11-02
```

No source edits, builds, tests, external research or Docker connectivity checks. Risk: treating the existing proxy, fleet sync or release builds as proof of the new installed-client contract.
