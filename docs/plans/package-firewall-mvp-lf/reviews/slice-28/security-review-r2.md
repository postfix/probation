# Security review (re-review r2)
Verdict: CLEAR (bounded; two low hardening items and one low disclosure, none blocking)
Subject and scope: probation working tree on slice5-native-ci, HEAD 6c4b7fc30ab1ccda2ed61e0f8224a0c5d0ab9693 plus the dirty tree, 2026-11-18. Bounded static recheck of the claims affected by the fixes: S28-1..S28-6 and the new surface (UPSTREAM_* error mapping, reset-revision-floor marker, /health bypass, E2E changes). Read-only; nothing built or run. Test results in evidence/slice-28.md and tdd-slice-28.md cycles 17-21 are supplied, not re-run. File fingerprints not recorded; subject identified by HEAD plus dirty tree.
Summary: all six prior findings closed (S28-4 stays an accepted informational trade-off). New: S28-7 low (unauthenticated /health/ready body), S28-8 low (own-listener port taken from config, not the bound socket), S28-9 low/informational (floor-reset marker trust = data-dir write). No property open. One correction to the first review's reasoning is recorded under S28-1.

## Status of prior findings
| ID | Status | Basis |
|---|---|---|
| S28-1 | closed | See below. |
| S28-2 | closed (residuals S28-8 and hairpin note) | See below. |
| S28-3 | closed | See below. |
| S28-4 | accepted, informational | No default cap by user decision; `credential_temp_max_*` optional, bounded per request by `max_artifact_bytes`. |
| S28-5a | closed | Host check now runs for every peer. |
| S28-5b | closed | `selected_upload` checks the Authorization form before `admit_pypi` (src/http/pypi_routes.rs:337-341). |
| S28-6 | closed | https-only `server_url`, no redirects. |

### S28-1 closed
- `GatedCache` (src/store/cache.rs:236-262) wraps `projects`, `rendered` and `absent`; the inner `ShardedCache` field is private, and `insert` / `insert_if_current` need `&CacheToken`. Grep of every `.insert(` / `.insert_if_current(` on those caches finds exactly 8 sites (npm/mod.rs:177,303,758; pypi/mod.rs:145,288,607 and their `absent` twins). All take a token from `cache_token(app)`, which is `None` for a request-scoped read in service mode (src/http/credential_read.rs:40-47). `CacheToken(())` is minted only in credential_read.rs (`classify_read`, `cache_token`) and in `for_test_support` behind `feature = "test-support"`. That feature is enabled only through dev-dependencies (Cargo.toml:116, crates/probation-server/Cargo.toml:52), so a plain `cargo build --release` does not carry it.
- The only ungated shared cache is `references` (artifacts/mod.rs:335): a DB row cache, not derived from a caller credential.
- Correction to the r1 reasoning: in shared-service mode the caller's `Authorization` header IS forwarded upstream on metadata and artifact reads (registry_read.rs:122-125 sets `registry_read_authorization`; reqwest_transport.rs:279 sends it). What keeps it out of shared state is not the absence of forwarding. Metadata: `current_project` returns `refresh(..)` before any cache read or insert in service mode, with no coalescing (npm/mod.rs:246-249, pypi/mod.rs:232-234), and the commit uses `commit_request_references_in` with `persist_metadata: false` (store/mod.rs:424-431), so the credentialed payload is not stored. The `projects` cache is therefore never filled in service mode, and the warm path in npm/mod.rs:121-125 and pypi/mod.rs:111-112 needs a `projects` hit, so it cannot serve. Artifacts: `open_or_download` sends any credentialed or request-scoped read to `fetch_request_scoped` (artifacts/mod.rs:360-373) and never to the shared content store. The `absent` mark is skipped entirely in service mode. The type seam is a second, structural layer.
- Residual, not a finding: `classify_read` is called for GET/HEAD only (service_registry.rs:46); non-GET routes insert into no cache. `extra_pseudo_headers` is always `&[]` at the call site (service_registry.rs:53), which is correct for hyper (other pseudo-headers are rejected before this point) and was noted by the author as library-level only. Reference rows (name, version, filename, upstream_url) written by `commit_request_references_in` are shared across principals of a registry, but they are reachable only by 32-byte reference id and every artifact request re-proves membership upstream with the caller's credential (artifacts/mod.rs:134, 207). Not examined further.

### S28-2 closed
- `Denylist::denies_endpoint(ip, port)` = built-in/control-plane ranges on any port, or own listener on its port (service_connector.rs:77-103). A wildcard listener owns loopback and every address of this host, detected by binding a UDP socket (`is_local_address`; fails closed when `ip_nonlocal_bind` makes every bind succeed, and only on the listener port). Mapped, compatible, NAT64, 6to4 and ISATAP spellings are unwrapped to a fixpoint of 8 and fail closed on exhaustion.
- Activation: `check_target` rejects an IP literal that is denied or is the own listener with the URL's port (service_connector.rs:155-160). `check_hostnames` resolves each descriptor hostname with the target port and refuses any denied answer (managed/service_policy.rs:567-577). An unresolvable name is not an activation error but is refused at connect.
- Connect: `GuardedResolver` is built with the selected origin's port and checks every answer with `denies_endpoint` before any private-CIDR exemption (resolver.rs:72-78, reqwest_transport.rs:155). `check_connected_peer` re-checks the actual peer address and port (origins.rs:205-207, reqwest_transport.rs:367-373). Every selected origin set carries the denylist (reqwest_transport.rs:121-124) for metadata, artifacts, `send_action` and redirect hops (hops must stay on the same origin; the proxy is off). Rebinding (A record changes between activation and connect) is covered because the connect-time resolver repeats the check on its single resolution; redirect-to-self is covered because every hop dials through the same resolver and peer check.
- Residuals: (a) A hostname that resolves to an address not local to this host but routed back to the listener (Kubernetes Service VIP, load balancer, NodePort hairpin) cannot be detected by address comparison. Not exploitable beyond the D1 deployment boundary; stated as an assumption. (b) The peer check runs after the request is sent, so it is a second layer, not the first; the resolver check is the gate.

### S28-3 closed
credential_temp.rs:92-102: a symlinked or non-directory parent is refused; an existing parent must be owned by the data-dir owner and is chmod 0700 (`private`); the process directory is created then chmod 0700; files are `tempfile_in` (unlinked, 0600). `sweep` (credential_temp.rs:120-143) skips non-directories, opens only a lock that `symlink_metadata` says is a regular file, and removes lock-less directories only after 60 s. `remove_dir_all` does not follow swapped symlinks. The one race (check then chmod) needs write access to the data directory, which is the trust boundary.

### S28-5a closed (Host variants)
`host_admitted` (service_registry.rs:252-261) runs for every peer, loopback included (service_registry.rs:35-37), with `Host` from the public URL or `127.0.0.1` / `[::1]` / `localhost` on the actual bound port (`app.bound`; local names are disabled until the bind has set it). Checked variants: exactly one Host header required (none or several refused); the value is re-parsed with `url`, so case, IDN to punycode, one trailing dot, decimal/hex/short IPv4 spellings and default-port elision normalise before comparison; userinfo, path, query, fragment, backslash, zone ids (`%25eth0`) and non-UTF-8 are refused; a different explicit port is refused; an HTTP/2 `:authority` and an HTTP/1 absolute-form target must each also match; `X-Forwarded-*` and `Forwarded` are never read. DNS rebinding (Host: attacker name reaching loopback) is refused. Residual (not a bypass): a cross-site no-cors request from a browser to `http://localhost:PORT` carries an accepted Host; reads of public data are possible but every write and private read needs the caller's own Authorization, which cross-site simple requests cannot set.

### S28-6 closed
config.rs:805-810: `server_url` must be https, with host, without userinfo, query, fragment or path; no insecure override or `danger_accept_invalid_*` exists in the tree (grep). The policy client uses rustls defaults, `no_proxy`, `redirect::Policy::none()` (managed/service_policy.rs:193-195), 10 s timeout, 1 MiB streaming cap. Equal-revision replay of an older registry set (digest excludes registries, `api.rs:101-104`) therefore needs TLS compromise of the policy server, i.e. the policy server itself, which is out of this review's threat model. Lower revision and equal revision with changed digest are rejected structurally (`ActiveRevision::admits`).

## New findings

### S28-7 Low, confirmed: unauthenticated `/health/ready` body in shared-service mode
Location: src/http/service_registry.rs:30-32 (the `/health/` prefix returns before peer, Host and policy checks), src/http/health.rs:45-61.
Any network peer able to reach the listener (and a rebinding page against loopback, since Host is not checked either) reads `degraded_registries` (registry ids), `policy_active`, `gate_poisoned`, rule-skip count and `credential_temp_bytes`. The last is a live gauge of in-flight credential-bearing downloads, a coarse activity side channel. Impact is bounded; no secret.
Smallest correction: return the detailed body only to admitted peers or on a separate operator route; keep a status-only response for `/health/*`. Check: a peer outside `allowed_peer_cidrs` gets the code without the JSON fields; a probe from an admitted peer still gets them.

### S28-8 Low, plausible: own-listener port comes from configuration, not the bound socket
Location: src/main.rs:192-195, src/lib.rs:344 (`with_listener(deps.config.listen)`), src/config.rs:455-458 (port 0 accepted).
If an operator configures an ephemeral port (`listen: ...:0`), the denylist holds port 0 and the own-listener rule never matches the real port. The Host check already uses `app.bound`. Unlikely in production (a fixed port is needed for `public_url`); the shared-service validation does not require it.
Smallest correction: reject port 0 when `service_policy` is set, or refresh the denylist from `app.bound` after the bind. Check: a config with port 0 and `[service_policy]` fails validation.

### S28-9 Informational: `revision-floor-reset` marker is trusted on data-dir write access
Location: src/managed/service_policy.rs:89, 210-236, 274-277; src/main.rs:95-117.
Who can write it: the operator command (needs the config and key file and rewrites only the envelope bound to that key hash) or any principal with write access to `data_dir`. No network or HTTP route creates it. A data-dir writer can also plant or replace the saved snapshot and the REFUSED marker, so the marker adds no new capability. Note: if the marker is a directory or unremovable, `clear_marker` errors and the in-memory floor is cleared on every poll (`floor = None` precedes the removal), so a data-dir writer can hold the floor off; this is again inside the data-dir boundary. The operator identity in the warning log is an environment hint (`operator_identity`), not an authenticated one, as documented.
No change required; keep the data directory 0700 and owned by the service user (deployment note).

## UPSTREAM_AUTHENTICATION_REQUIRED / UPSTREAM_DENIED
Closed. `service_download_error` maps only `UpstreamError::Status(401|403)` in service mode (artifacts/mod.rs:471-479); the messages are static strings (error.rs:206-207) with no upstream body, header, URL or status text. The 401 carries no `WWW-Authenticate`, so no scheme or realm from upstream is relayed. The status code is an oracle about the caller's own credential only. `PayloadTooLarge` / `Overloaded` / `CapacityExhausted` mappings for temp errors reveal only local capacity.

## E2E fixture and compose changes
Closed. `git status` shows no change under tests/e2e or docker-compose.test.yml; evidence/tdd-slice-28.md records that the two scenarios already existed and no E2E file was edited. The recorded E2E run (images rebuilt from the fixed tree, 2 passed) is supplied evidence, not re-run. The `shared_service` fixture edits are test-only struct-literal and revision updates. Not examined: the existing compose stack's own configuration (unchanged).

## Security properties
| Property | Boundary/owning code | Status | Evidence | Limits |
|---|---|---|---|---|
| Credential-bearing reads never enter shared caches | credential_read.rs, store/cache.rs, npm and pypi mod.rs, artifacts/mod.rs:360 | closed | type seam plus service-mode early return plus non-persisting commit; artifact path request-scoped | S28-1 correction noted |
| Own listener never dialled | service_connector.rs, resolver.rs, origins.rs, reqwest_transport.rs, service_policy.rs | closed | activation, resolve and peer checks with port; wildcard and hostnames covered | S28-8, hairpin assumption |
| Host/peer admission incl. loopback, rebinding | listener_admission.rs, service_registry.rs | closed | variants enumerated above | S28-7 (/health exempt) |
| Temp-file perms, symlinks, sweep | credential_temp.rs | closed | as above | S28-4 availability trade-off |
| Snapshot origin and replay | config.rs:805, service_policy.rs | closed | https, no redirect, digest/floor rules | S28-9 |
| Upstream error mapping | artifacts/mod.rs:471, error.rs | closed | static messages | none |
| E2E/compose | tests/e2e, docker-compose.test.yml | closed | unchanged | |

## Verification and limits
Commands run: git status/diff --stat, grep and file reads only; nothing executed or built (no scope needed). Supplied, not re-run: all test and E2E results in evidence/slice-28.md and tdd-slice-28.md. HEAD 6c4b7fc unchanged at start; the tree is dirty and shared, so unchanged-during-review cannot be confirmed beyond the files read in one pass.
Not examined: TLS termination and cluster-level hairpin routing (row 26), central OSV client (row 30), path-embedded credential forms per family, portal and server routes beyond the earlier osv_scope setter.
Non-security: the evidence file's "Behaviour changes" still says loopback peers are exempt from the Host check; the later cycle 19 reversed it, so the evidence text is stale (documentation only).

## Next steps
1. No blocking item. Optional: S28-7 (restrict `/health/ready` detail), S28-8 (reject listen port 0 under `[service_policy]`).
2. Keep the data directory private to the service user (S28-3, S28-9); state the hairpin assumption in the deployment doc.
