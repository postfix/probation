# Socket-style credential split: design re-steer under review

User steering on 2026-10-25: use shared passwords like Socket to avoid making the registry host itself a secret, while allowing publishing through Probation. This revisits Gate 2 C11/C12/C14; Gate 1 C2 (one exact configured URL) may also change if separate client routes are selected. No design approval or implementation has occurred.

[Socket's configuration reference](https://docs.socket.dev/docs/socket-firewall-enterprise-registry-mode-configuration-reference) documents two distinct paths: a shared client-auth gate that verifies a bearer or Basic value and strips it before upstream I/O, and a route with `forward_client_auth` that accepts a well-formed bearer and forwards it to the upstream. The latter does not verify the shared gate and does not accept pip Basic credentials. This is a per-route choice, not two credentials in one `Authorization` header. The [npm 11 source evidence](research-1.md) shows npm selects one registry-scoped Authorization value per request.

Proposed adaptation, pending the user's answer:

| Surface | Context and credential | Result |
|---|---|---|
| Stable user/group virtual host | Public selector, with revocation and ownership validation; no access granted by host possession alone | Host may be written to committed lockfiles without exposing a secret. |
| `/r/<registry-id>/install/...` | Shared, revocable password or bearer token specific to the context; stored in user-local npm/pip/uv configuration, never a project file | Policy-filtered metadata and package bytes. The shared upstream read connection is used only after local authentication. |
| `/r/<registry-id>/publish/...` | Developer's own upstream token, forwarded only to the selected registry | Login, publish, package administration and necessary metadata preflights; no package-file GET. Upstream permissions govern writes. |

The publish path must reject package-file GET/HEAD before upstream I/O, including alternate tarball paths, and must not use the shared read credential. npm metadata served there must keep tarball references under the publish path for revision-aware DELETE, but a GET to such a reference must fail. Real npm client probes must establish that publish/deprecate/unpublish still work with this rule. The install path's metadata and file links stay under the install path. Neither route may silently fall back to the other or to direct upstream.

This changes the user-visible workflow: `npm install` points to the install URL; `npm login --registry=<publish-url>` and `npm publish` use the publish URL, potentially through a committed `publishConfig.registry` with only a nonsecret URL. Twine already has a separate `--repository-url`; pip and uv use the install URL. The user's earlier C2 required one exact URL without switching. The user has been asked whether separate URLs are acceptable. Do not treat this proposed design as approved until that answer is recorded.

Safety proof obligations: a public host plus arbitrary upstream bearer must not grant package bytes, select another organization's registry, or enter the shared-read path; install requires the context password on every metadata and artifact request, including after redirects and restarts. A browser login step is separately observed. The fixed matrix must add install-versus-publish route isolation, real npm lockfile/uv.lock scans for **secrets** (the stable hostname may appear), credential rotation and group membership changes. A publisher token cannot be assumed to prove Probation user/group membership; it only proves upstream permissions.
