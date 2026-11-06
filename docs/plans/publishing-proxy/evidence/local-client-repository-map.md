# Local-client re-steer: npm/PyPI identity and upstream credentials

Read-only SMTC investigation on 2026-11-02. This evidence distinguishes existing firewall client admission from upstream registry authorization; it does not claim the revised local-client path is implemented.

## Existing npm path

- `src/http/registry_read.rs::admit_for` requires transport-provided `VerifiedPeer` evidence and calls `managed.admit_certificate` for the selected registry/ecosystem. The matching recheck repeats certificate admission after upstream I/O.
- Selected npm handlers in `src/http/registry_routes.rs` use that admission path. `src/npm/mod.rs::serve_registry` passes the configured principal's `registry_read_authorization` into metadata resolution; artifact metadata uses the same separate value.
- `src/upstream/reqwest_transport.rs::fetch_metadata` and `open_artifact` apply the read authorization to the outbound upstream request. Redirect handling consumes credential state separately from `VerifiedPeer`.
- npm actions pass the inbound package-manager headers from `registry_routes::forward_action` to `registry_action::forward_registry_action`. The latter validates action-specific Basic/Bearer authorization and places the accepted credential in the upstream `ActionRequest`; TLS certificate admission is performed separately by the route.

## Existing PyPI path

- Selected project, index, artifact and upload handlers in `src/http/pypi_routes.rs` accept `VerifiedPeer` and call the shared certificate admission/recheck path in `src/http/registry_read.rs`.
- PyPI reads pass the principal's separately configured `registry_read_authorization` to upstream resolution in `src/pypi/mod.rs`.
- `pypi_routes::selected_upload` separately reads package-manager Basic/Bearer authorization and passes it on the upstream action request after firewall admission.

## Active design implications

The approved C1006/C1008/C1009/C1015 scope supersedes certificate identity and firewall-held shared read credentials for the new local-client path. Package requests use the locally enforced policy and selected registry. The service API key authorizes policy retrieval only. Registry credentials remain in package-manager configuration and authorize the selected upstream; they are not firewall-client identity, policy-server credentials, or a signal to relax local package policy. Preserve the existing publishing operation and upstream authorization contract. Do not invent a public/private mode or make the firewall configure user registry credentials.

## Limits

This is a focused route map, not a complete call graph. SMTC `analyze entry-points` covered only 5 of 23 entry points and reported unresolved dispatch sites; the broad map was truncated. No tests were run, and this source describes the delivered certificate-based baseline, not the replacement implementation.
