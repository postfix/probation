# Repository structure for transparent package publishing

Read-only SMTC map at Git `acf18d6f695a6bd37dc5a7c6817922cc3a52b7a6`.

- `src/http/mod.rs:45-89` registers GET npm metadata, PyPI Simple and GET/HEAD artifact routes. Other paths return 404; unsupported methods return 405. `src/http/npm_routes.rs:35-76`, `src/http/pypi_routes.rs:38-87` and `src/http/artifact_routes.rs:130-172` admit requests, then call the respective package or artifact serving path.
- `src/http/mod.rs:107-140` calls `Managed::authenticate`. `src/managed/mod.rs:281-304,975-1001` treats the HTTP Authorization value exclusively as a Probation key (Bearer token or Basic password), hashes it, then uses the local cache and management lookup for policy, network and rate checks. `crates/probation-server/src/sync.rs:390-401,700-765` owns the key-to-place lookup.
- `src/npm/mod.rs:55-150` and `src/pypi/mod.rs:73-150` obtain policy, use memory cache keyed by ecosystem, package name, representation and policy fingerprint (`src/store/cache.rs:34-110`), then resolve or refresh metadata. Refresh builds URLs through `OriginSet::url_for` and fetches with validators and a size cap (`src/npm/mod.rs:575-620`, `src/pypi/mod.rs:485-529`, `src/upstream/mod.rs:1-70`).
- `src/config.rs:100-108` has process-wide upstream URLs. `src/upstream/origins.rs:79-109` selects those or fixed npm/PyPI defaults. The observed request path has no per-project upstream selection.

Evidence tier: SMTC structural orientation plus targeted source reads. SMTC map and architecture analysis succeeded; broad entry-point output had unresolved dispatch sites and the map summary was truncated. Targeted file evidence supports the paths above, but the map alone does not establish behavior of proposed writes or forwarding.

## Management, persistence and sync addendum

- `crates/probation-server/src/portal/mod.rs:197-235,295-300` routes key, policy, organization and global fleet settings administration. The route table has no registry administration path. `portal/organisation.rs:159-183` and `tenancy.rs:97-145,295,491` handle scoped organization and admin roles.
- `crates/probation-server/migrations/0001_init.sql:23-37,128-188` stores organizations, policy layers and hashed keys with place identifiers. Targeted search of the six migrations found no registry, upstream or project table. The existing `accounts::SecretBox::seal/open` (`accounts.rs:928-964`) protects SSO secrets; hashed project keys are not recoverable upstream connection credentials.
- Global upstream settings are handled by `portal/fleet.rs:157-186` and the process-wide settings noted above. There is no observed per-organization registry configuration or project-to-registry selection.
- Server `sync.rs:54-107,362-368,578-654` and `crates/probation-policy/src/api.rs:93-110,280-294` sync key, layer, place, limits, network ranges and global settings. `KeyLookup` carries place context but no registry selection. `src/managed/sync.rs:177-199` applies the current invalidations and settings.

This addendum uses targeted SMTC file reads and grep, with the same structural tier. Absence claims are bounded to the scanned route table, six migrations and current sync payload; they are not a repository-wide absence proof.

## TLS and proxy identity addendum

- `src/config.rs:90-96,570-583` accepts a server certificate/key pair. `src/lib.rs:365-426` starts a Rustls server from them, or a plain HTTP listener. The observed listener does not configure client-certificate verification or attach peer certificate identity to requests.
- `src/config.rs:124-143,792-830` configures management trusted-proxy CIDRs. `src/managed/lock.rs:98-131` uses `X-Forwarded-For` only from a trusted immediate peer to establish client IP for network controls; it does not identify a user or project. `src/managed/mod.rs:281-305` still requires a Probation key in Authorization.
- Targeted search across 78 daemon source files found no client-certificate verifier or verified-identity proxy header in the request path. Consequently neither client-certificate identity nor proxy-asserted principal is a current authentication mechanism.

Evidence tier: SMTC structural orientation and targeted source reads. The negative claim is limited to the configured listener/authentication path and the 78 scanned daemon files.

## Virtual-host and URL addendum

- The public router is path-only (`src/http/mod.rs:45-91`). Targeted SMTC search of 78 daemon source files found no inbound Host, authority, or forwarded-host reader in the registry request path. `Managed::authenticate` returns a `Principal` with place, key, policy, account, organization and chain, but no project or host identity (`src/managed/mod.rs:45-65,281-304`).
- `Config.public_url` is one HTTPS base URL (`src/config.rs:26,422-450`). npm tarball and PyPI file rendering build absolute URLs from that base (`src/npm/mod.rs:756-818`, `src/npm/render.rs:115-163`, `src/pypi/mod.rs:697-716`). The PyPI project index uses relative project paths (`src/pypi/render.rs:118-133`). Artifact serving authenticates a key and resolves the reference without Host (`src/http/artifact_routes.rs:25-75,130-172`).
- Existing rendered-cache keys include project, representation and policy fingerprint, but not host (`src/store/cache.rs:70-80`). Portal setup snippets use one configured firewall URL for display (`crates/probation-server/src/portal/keys.rs:25-39,96-113`).

Current code cannot select a user/group place or registry by virtual host, and absolute artifact links would leave that host. This is based on targeted SMTC source reads and the bounded 78-file search; no proposed-host runtime check has run.

## Registry identity, cache and artifact addendum

- Metadata and rendered responses use `ProjectKey(ecosystem,name)` and `RenderKey(project,representation,policy fingerprint)` (`src/npm/mod.rs:55-106`, `src/pypi/mod.rs:73-118`, `src/store/cache.rs:33-82`). The stored project primary key is `(ecosystem,name)` (`src/store/schema.rs:66-90`). Origin selection is one configured origin per ecosystem (`src/upstream/origins.rs:33-49,79-111`). A registry identifier is needed in persisted and in-flight project identity, cache keys, and artifact membership to keep same-name packages from different selected registries separate.
- npm rendering rewrites eligible `dist.tarball` links but otherwise preserves upstream metadata fields (`src/npm/render.rs:50-70,119-165`). Other retained URL fields could expose direct upstream links; this is a structural risk, not an observed client connection. PyPI synthesizes its Simple file links under the configured public URL (`src/pypi/mod.rs:692-745`, `src/pypi/render.rs:59-117`).
- Artifact references include upstream URL and digest material (`src/artifacts/reference.rs:21-66`), but a reference ID is a lookup key, not authorization. Artifact serving validates ecosystem, filename, policy, current project membership and verified bytes (`src/artifacts/mod.rs:65-201`); download admission limits URLs to configured ecosystem origins (`src/artifacts/download.rs:435-455`). Selected registry identity and virtual host must feed those checks.

This addendum is structural SMTC evidence and selected source text. The source provider reported a dirty snapshot, so the Git commit alone does not bind these exact bytes; no runtime client or cache collision test has run.

## Key lifecycle and host-label fit

- `crates/probation-server/src/keys.rs:16-90,113-139` generates `prb_` plus 32 random mixed-case alphanumeric characters, about 190.5 bits of case-sensitive entropy. User keys bind to user/personal places and service keys include organization/group places. The underscore and mixed case prevent using that exact plaintext as a conventional case-insensitive DNS host label.
- `crates/probation-server/migrations/0001_init.sql:172-188` stores SHA-256 key hashes, kind, place and `revoked_at`, not plaintext. `crates/probation-server/src/keys.rs:307-348` revokes a scoped key and records `ChangeKind::Key`; `crates/probation-server/src/sync.rs:585-635` and `src/managed/sync.rs:177-194` invalidate cached keys.
- `crates/probation-server/src/sync.rs:389-400,700-765` looks up user/service key hashes for the firewall. Current `src/http/mod.rs:107-140` and `src/managed/mod.rs:281-304` require that key in HTTP Authorization. A distinct DNS-safe host capability can reuse the hash, place and revocation pattern, but needs its own kind and host lookup. The current managed cache may use a stale known key during management outage (`src/managed/mod.rs:330-365`), so the proposed host lookup cannot inherit that fallback if revocation is to apply on the next lookup.

Evidence tier: targeted SMTC declaration inspection and source trace. No DNS runtime or revocation propagation test has run.

## Certificate identity and current membership addendum

- `src/lib.rs:365-426` loads only a server certificate/key, then serves HTTPS or plain HTTP. The observed listener has no verified client-certificate identity attached to package requests. `src/http/mod.rs:107-140` admits requests through `Managed::authenticate`, which requires a Probation key in Authorization. `X-Forwarded-For` in `src/managed/lock.rs:98-131` supplies only a client IP from a trusted proxy; it is not certificate evidence. Package admission needs a transport-originated verified certificate extension before the HTTP route; package paths must require it even if browser portal paths permit a connection without one.
- `crates/probation-server/src/tenancy.rs:603` loads active session memberships, excluding deleted logins and limiting SSO to its organization. `sync.rs:701-824` checks a key owner's standing and obtains the current membership group for a user place, producing the platform → organization → group → user place chain. `sync.rs:403` and `policy.rs:303` load the layers for that chain; `src/managed/mod.rs:517` compiles the policy. Certificate identity can resolve to a current membership beside this management lookup and then reuse the layer path. The current key-based `Principal` cannot be used unchanged.
- The inspected `portal/mod.rs` route table has no certificate provider, CA trust, self-service enrollment, or targeted certificate revocation routes. An in-process TLS seam avoids trusting client-provided identity headers. A separate TLS terminator would require an authenticated proxy-to-firewall assertion and strict header stripping, which is not in the current source.

SMTC-backed structural orientation and targeted source reads; no runtime certificate or membership witness has run. Broad entry-point analysis left unresolved dispatch sites, so the exact new adapter remains a design and implementation obligation.
