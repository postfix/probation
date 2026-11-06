# Local-client source contract rebind — 2026-11-02

The certificate-era model and sidecar are preserved as `molecule-flow-certificate-baseline.json` and `molecule-contracts-certificate-baseline.json`. The active files now describe the approved shared local service, separate policy-server and registry credentials, npm/PyPI operation boundaries, and service-scoped unpublish.

`router molecule-check --plan-root docs/plans/publishing-proxy` returned PASS after the active model was revised.

`router molecule-verify --plan-root docs/plans/publishing-proxy` returned UNKNOWN on run `run-xz0DVA` because four planned source obligations point to source files that do not yet exist:

- `src/http/service_registry.rs` — selected-route dispatch and current-policy response release, assigned to Slice 1 and lead `package-firewall-mvp` Slice 16.
- `src/http/service_unpublish.rs` — service-scoped reference and marker-before-delete checks, assigned to Slice 3.

Three existing source obligations passed with their unsafe controls:

- `src/http/registry_action.rs::forward_registry_action` — upstream publisher authorization before action send.
- `src/http/token_packument.rs::serve_token_packument` — canonical token-packument guard before selected upstream send.
- `src/http/audit_filter.rs::filter_audit_response` — visible advisory filter before response rendering.

The complete verifier reports absent future sources as `SOURCE_MISSING` in full-plan mode. Gate QA preparation must classify them from the explicit slice assignment; only then may they be carried as future PENDING work. The specs for the planned service route and unpublish module are narrow call-order checks. Exact credential/header destination, selected-value binding, request-local cache behavior, atomic marker consumption, replay refusal and runtime platform behavior require the caller tests and independent review in `03-program-design.md` and `04-slices.md`.

No product tests or implementation were run. The SMTC commands use the local daemon; the initial sandboxed attempt was blocked by daemon IPC and the successful verification used the authorized local runner with `XDG_STATE_HOME` under repository `.scratch`.

Fresh verification — 2026-11-02: `router molecule-verify --plan-root docs/plans/publishing-proxy` returned UNKNOWN on run `run-Z0bKeh`. The three existing source obligations and their unsafe controls passed. The only remaining UNKNOWNs are the four declared future-source obligations: two in `src/http/service_registry.rs` (Slice 1, lead-owned) and two in `src/http/service_unpublish.rs` (Slice 3). Earlier run `run-mmnH55` could not connect to the SMTC daemon and was superseded by authorized local-daemon checks; `run-7WYQor` confirmed the same four missing future sources. The active design now specifies final authorization/handoff ordering with policy publication and durable service-scoped, revision-bound one-use unpublish markers; finite-model PASS does not prove those runtime/concurrency properties.
