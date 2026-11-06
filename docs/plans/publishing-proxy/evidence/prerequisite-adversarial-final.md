# Independent adversarial recheck — 2026-11-03

Verdict: **PASS**, Manual, bounded test-design review. All four prior effectiveness gaps closed; no remaining concrete gap found in this scope. No product/test changes or runtime executions by this reviewer.

Subject: base `8d9f5e35b6d92898f6c9c33b852df5a9b04e8d59`; all30 final path/hash pairs matched before/after, manifest SHA-256 `4551649c2a115004aacd7048c9ef8d9d53da97b2d2b820357ae7f19f3d94a9ed`. No mode changes, renames or drift.

1. API foreign organization/registry exists before the tested snapshot, whose assertions exclude that exact registry. The exclusion is nonvacuous.
2. E2E tests explicit standalone's local denial and central-package allowance before conversion. Managed mode reverses those outcomes; native clients fetch the locally denied package. Server outage and firewall restart retain both central allow and central deny. This distinguishes remembered managed authority from standalone fallback.
3. Shared-service handoff runs2ecosystems ×2cache states ×5actions using actual service principals and verified prepared responses. A separate worker publishes before conversion for deny/refusal or after accepted conversion. Tests require refusal without artifact payload, preserve exact accepted bytes, and refuse a later HTTP request. Existing selected/legacy HTTP races and inspected route/artifact/stream wiring connect the common principal to the final gate.
4. Credential spies record metadata/artifact kind, URL and Authorization. Tests positively observe selected npm/PyPI metadata auth and selected npm artifact auth, reject forbidden npm extra-origin transfer, require a real PyPI files-origin open and require all such opens to omit credentials. Verified response-body assertions prevent vacuous empty-trace success. Policy snapshot mock requires the service key's Authorization separately.

The reviewer inspected focused RED/GREEN and acceptance evidence as supplied, without claiming to have executed it. Historical TDD limitations remain recorded. Final full-suite/current-image E2E are separate pending acceptance receipts, not evidence of ineffective assertions.

SMTC session `sf-prerequisite-adversarial-final-2026-11-03` used successful bounded file reads/grep of deciding tests and connected route/cache/gate code. Broad document outputs were narrowed; no negative search or truncated read was treated as proof. No compiler certificate or formal concurrency proof is claimed. Later publishing, native-platform/broader ecosystem acceptance and broad security auditing were outside this bounded recheck. Omitted findings:0.
