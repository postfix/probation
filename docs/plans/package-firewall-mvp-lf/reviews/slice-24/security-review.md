# Security review
Verdict: FIX FIRST
Subject and scope: uncommitted slice 24 (OCI registry) on branch slice5-native-ci at aa774dc plus working tree. Bounded review: src/oci/{coords,serve}.rs, src/http/oci_routes.rs, the OCI branches of src/http/service_registry.rs, src/http/registry_read.rs, src/artifacts/download.rs, src/upstream/{reqwest_transport,origins}.rs (redirect and origin handling only), migration 0022, config keys oci_upstream_url / oci_artifacts_url (existence only), evidence/slice-24.md. Procedure: /home/john/.claude/skills/lf-start/agents/security-review/AGENT.md. Static review only (no build, no test run). Prior slice 18-23 review reports were not read; the prior finding classes were taken from the task brief and checked against the code (table below).
Summary: open S24-F1 (high), S24-F2 (medium), S24-F3 (medium), S24-F4 (low), S24-F5 (low), S24-F6 (low hardening). Unknown: U-1 (spool/owner behaviour on the new write route), U-2 (row growth across repository names).

Fingerprints (sha256 prefix): src/oci/serve.rs 4200e7d2842a0436, src/oci/coords.rs e367550dd642139d, src/http/oci_routes.rs d9a7b50ee0f8751e. HEAD aa774dc.

## Findings

### S24-F1 high, confirmed (source trace): the token endpoint hands a stored registry credential, or tokens minted from it with client-chosen scopes, to every certificate holder
Location: src/oci/serve.rs:1090-1121 (`serve_token`), 182-184 (`caller`), 1107-1113 (the no-token-service arm); src/http/oci_routes.rs:~203 (route), run() `Parsed::Token` arm; src/managed/mod.rs:239,320 (`registry_read_authorization: read_authorization`).
Prerequisites: certificate-managed mode; a registry descriptor with a stored read credential (`CertificateAdmission::Granted.read_authorization`); attacker holds a valid client certificate for that registry (any developer of the account, no API key, no registry login). In service mode the field is the caller's own header (registry_read.rs service_principal), so this does not apply there.
Path: `GET /registry/oci/{id}/v2/token?scope=repository:x/y:pull,push,delete` -> `admit_oci` -> certificate principal with `registry_read_authorization = stored credential` -> `serve_token` takes `basic = caller(principal)` (the STORED Basic credential, not anything the client sent).
 - Registry with a Bearer token service: `fetch_token(realm, scopes, Some(stored basic))`. `scope_ok` allows `push`, `delete`, `*` for any repository name, up to 8 scopes. The minted token is returned in the body (`token`, `access_token`). The client can use it straight at the registry (bypassing every cooldown, block and digest check of the firewall) or present it to the firewall write route, which forwards it (the write route's own-credential rule is satisfied by the minted token).
 - Registry with Basic only (or open): the `_` arm returns `{"token": <base64 user:password of the stored credential>}`. This is the stored credential itself.
Ineffective defense: the "caller's own credential" model of the token endpoint is applied to a credential the caller never held. Realm confinement is irrelevant, the credential leaves in the response body.
Impact: disclosure of a shared registry credential (confidentiality of the registry account, including write rights if the stored account has them), and a policy bypass for reads.
Smallest correction: in `serve_token` use only a credential the client itself sent (add a separate field, or read the request header there) and never `registry_read_authorization`; for a principal with a stored credential answer with a firewall-local dummy token (the firewall adds the stored credential itself) and drop non-pull scopes. Cost: one extra parameter; the key-route echo for the legacy route is unchanged.
Closure checks: (unauthorized) certificate-only client with a stored Basic read credential calls `/v2/token`: body contains neither the credential nor a registry token; (legitimate) a service-mode client with its own Basic still gets a token from the registry realm; podman pull through a cert-managed registry with stored credential still works without calling the endpoint (ping answers 200 because `caller` is Some).

### S24-F2 medium, confirmed: fetch places are keyed by the presented Authorization text, a value the client chooses (recurrence of the "credential alone is not an identity" class closed for the spool in slice 23)
Location: src/oci/serve.rs:218-244 (`places`), 200-205 constants, tests named in evidence (`one_credential_cannot_hold_all_of_a_registrys_fetch_places`: "16 callers with different tokens peak at 8").
Attacker: any client address admitted by `allowed_peer_cidrs` in service mode (one client). Anonymous callers have no per-credential share at all (`credential = None`), so one anonymous client can take all 8 registry places; a client that rotates `Authorization: Bearer <random>` gets a fresh 2-place share per value and also reaches 8. Places are held for the whole upstream exchange (up to the 120 s deadline; large lists up to 16 MiB; blob HEAD), waits are 30 s then 504. Eight concurrent connections from one address keep the registry's 8 places (and half the process's upstream places, max 32, shared with `global`) busy; every other client of that registry queues and times out. Same effect on the Hub anonymous rate: every anonymous request is a shared-IP pull.
Defense missing: spool::owner_of (src/http/spool.rs:31-37) explicitly says "only REAL identities, never a credential alone" (client address /64). The OCI place table does not use it. `service.admit_request` is a service-wide budget, not per client.
Correction: key the per-owner share by `spool::owner_of`-style identity (peer /64 or account), keep the credential as the second count; give the anonymous case the same share. Cost: pass headers into `places`.
Closure checks: 16 callers from one address with distinct credentials peak at 2; a second address still gets a place; anonymous x16 peaks at 2.

### S24-F3 medium, plausible: blocks and cooldown are repository-scoped, so a blocked digest is re-hostable (cross-repository mount) and sha256/sha512 spellings are separate identities
Location: src/oci/serve.rs:544-551 (`blocked_outright`: Candidate{name, version=digest text}), 553-566, 795-835 (`judge`), src/oci/coords.rs:23-33 (sha512 accepted), src/http/oci_routes.rs:~415 (mount query forwarded).
Scenario: an operator blocks malicious image digest `sha256:X` in repository `library/foo`. Anyone who can push to a registry (Docker Hub: anyone) pushes the same bytes to `evil/foo` (a `mount=`/`from=` upload makes this one request) and pulls `evil/foo@sha256:X`: the block names (library/foo, X), so it does not match; the digest is only held for one cooldown from first sight, then served. The same applies to the same manifest pushed by sha512 reference to registries that store both spellings (distribution 3.x): `Candidate.version` is `sha512:...`, which never equals a `sha256:` block.
Evidence limit: whether policy blocks accept a name wildcard or a name-less digest rule was not checked; OSV does not apply to OCI (mapping None), so blocks and cooldown are the only protection.
Correction: for a manifest always also compute sha256 of the bytes and run the block check on the sha256 identity (and for a blob check the pipeline's computed sha256 against blocks after download); offer a name-independent digest block. Cost: one more hash of at most 8 MiB; policy-schema change if no wildcard exists.
Closure check: a block of (library/foo, sha256:X) refuses `evil/foo@sha256:X` after mount; `..@sha512:Y` of the same bytes is refused.

### S24-F4 low, confirmed: any Authorization value turns a manifest HEAD into a cooldown-exempt answer
Location: src/oci/serve.rs:787 (`exempt = head && caller(principal).is_some()`), src/http/service_registry.rs service_principal (any `Bearer `/`Basic ` string is taken).
Path: a client sends `HEAD manifests/latest` with `Authorization: Bearer junk` to a registry that ignores or does not check authentication (open registry, or one whose anonymous GET succeeds). The registry answers 200, the decision is Hold only by cooldown, so it is waved through: the client learns the digest, size and media type of a young, not yet released manifest. No bytes are delivered and the following GET is judged normally, so this is information only (digest of the tag now). Slice 23 exemption residual class; no release.
Correction: none required for release safety; optionally exempt only when the registry's answer proved the credential (a 200 from a registry whose `/v2/` challenged), or document it.

### S24-F5 low, confirmed: the manifest and list responses are not marked nosniff and carry the registry's Content-Type
Location: src/http/oci_routes.rs:139-150 (`manifest_response`), 125-137; src/oci/serve.rs:749-751 (`media_type_ok` accepts any `type/subtype` token, and falls back to the body's own `mediaType`).
Scenario: a configured private registry (or a registry that echoes a pusher-chosen content type) serves a JSON object as `text/html`; the firewall serves it as `text/html` on its own origin, so a string inside the JSON executes as script in the firewall's origin (the shared portal origin). Docker Hub constrains the type to manifest types, so the default registry is not affected; only a configured registry with lax content typing.
Correction: add `X-Content-Type-Options: nosniff` and restrict the served Content-Type to the manifest/index media-type families (else `application/json`); Cost: small.

### S24-F6 low hardening (all confirmed, none exploitable alone)
1. src/http/oci_routes.rs:271-290 `selected`: the `Prefix` and the 401 challenge realm are built from the unvalidated `{registry}` path segment before `registry_id()` runs for the write branch (credential check comes first). `Url::set_path` normalizes and encodes, so the realm stays on the firewall host, but a decoded `%2F`/`..` lets a caller steer the realm path. Validate the segment first.
2. Token responses (oci_routes.rs plain(), key echo at ~L238, serve.rs serve_token) carry no `Cache-Control: no-store`; the legacy key route returns the API key in the body.
3. oci_routes.rs:411 `let _ = reference;`: a manifest PUT is checked against the repository block but not the tag/digest (comment says it is); blob uploads and DELETEs skip `locally_blocked` entirely.
4. Caches that evict with `clear()` (tokens serve.rs:420-424, manifests 765-770, exists, registered, realms): one client sending 256 distinct valid repository names (an anonymous token is minted for any name) flushes everyone's token cache and forces extra token fetches. Evict oldest instead.
5. Non-security defects found: `GET` of an upload session is routed to `read()` (write = not GET/HEAD) and answers 405, so the documented GET arm in `write_segments` is unreachable; `challenge_header` with `principal=None` probes the process default registry rather than the selected one for the 401 of an unauthenticated read.

## Prior finding classes (checked against this code)
| Class | Result |
|---|---|
| Redirect/credential drop (slice 19 F2) | closed. `fetch_oci` uses `Policy::none` (reqwest_transport.rs:130-156 with `follow_redirects=false`); blob pipeline `open_artifact` (reqwest_transport.rs:424-458) uses a manual loop, `authorization.take()` sends the credential on the first request only, hops admitted by `admit` or `admits_archive_redirect`; OCI blob redirects only to `oci_artifacts_url`, Hub's two storage hosts when the default registry host is exactly registry-1.docker.io (origins.rs:332-338), or a selected registry's declared archive origin. Hub hosts are not admitted for a selected registry. |
| Write response relay allow-list | closed. status allow-list, Location same-origin and `/v2/` prefixed and rewritten, Range/UUID/digest filtered by shape, body 64 KiB, type json or text/plain + nosniff (oci_routes.rs:430-475). |
| Hard atomic row bound / orphan rows | closed per repository (row gate held from bound check to commit, serve.rs:605-640, 795-830, 860-880); open question U-2 across repository names. |
| Spool owner/seat/byte share, trickle floors | unknown (U-1): write route uses `spool::owner_of` and `spool::spool` (oci_routes.rs:392-401), same shared code as slice 21/23, not re-audited. Writes do not take `places` (direct `fetch_oci`), so upstream upload concurrency is bounded only by `active_permit` and spool budget. |
| Share cells, fairness, per-owner caps on shared lanes | open (S24-F2). |
| C1028 | closed for caches: memo/exists/tokens used only when `caller(principal).is_none()` and `cache_token` allows (serve.rs:719, 881-890); anonymous token shared only among anonymous callers; stored-credential principals are request-scoped. Open for the token endpoint (S24-F1). |
| FIX-16-A mid-request block | closed by design: `read()` rechecks policy fingerprint and origin fields after the work (oci_routes.rs:311-325), the legacy route re-reads the key; not executed. |
| Path canonicalisation | closed. coords.rs parses once, strict grammar; `url_for` refuses `.`/`..` (origins.rs:464-470) so session id `..` is 404; names lower case; digest lower-case hex fixed length; query keys per route once. Decoded `%2F` yields the same canonical identity. |
| Strict bounded decoding / amplification | closed for documents (typed serde, entry and byte caps: manifests 8 MiB, lists 16 MiB, 20,000 children, token 64 KiB). Remaining amplification: anonymous blob HEAD runs a full cold download after cooldown (same as other families). |
| Uploader / back-dating U1 | closed: dates are first-seen only; a child takes the allowed parent's first-seen (immutable by digest, no depositor-chosen time read); S24-F4 is information only. |

## Security properties
| Property | Boundary/owning code | closed / open / unknown | Evidence and actual result | Limits or finding |
|---|---|---|---|---|
| Token realm confinement, no credential to attacker realm | serve.rs:260-300 `parse_challenge`, `realm_allowed`, `fetch_token` | closed | realm must be the registry's own origin (scheme, host, port) or the fixed table pair over https with no port, no userinfo/fragment; query rebuilt from firewall-built service/scopes; `admitted()` re-checks path prefix; redirects not followed | table maps only the process's/selected registry host; `eu.gcr.io` style hosts simply fail |
| Scope injection | serve.rs:1078-1088 `scope_ok`, `serve_token` | closed for injection, open for escalation by stored credential | scopes grammar-checked, max 8, `service` taken from the registry challenge | S24-F1 |
| Token caching across principals | serve.rs:414-428, 440-446 | closed | anonymous cache keyed (origin, scope), used only without credential; no per-principal token cached | cache flush S24-F6.4 |
| Token leakage in logs/headers | reqwest_transport.rs fetch_oci (`set_sensitive`), serve.rs warn! sites | closed (static) | only realm URL and repository name logged | log sink not exercised |
| Stored credential confidentiality | serve.rs:1090-1121 | open | S24-F1 | |
| Blob redirect host allow-list / SSRF | origins.rs:332-359, download.rs:518, reqwest_transport.rs:424-458 | closed | see class table; peer address re-checked (`check_connected_peer`) | not executed |
| Digest verification of served bytes | serve.rs:722-760, download.rs verify_advertised | closed | manifest bytes hashed in the requested algorithm and compared with the asked digest and with a same-algorithm Docker-Content-Digest; tag uses sha256; layer verified in full before first byte | sha512 blocks S24-F3 |
| Algorithm confusion / case / truncation | coords.rs:19-33 | closed for parsing | only lowercase sha256/sha512 of exact length | identity equivalence S24-F3 |
| Index/child/blob gating, orphan digests | serve.rs:795-890 | closed | children registered only after Allow, dated as parent; unnamed blob/manifest gets own first-seen; exists check per caller | blocks scoped per repository (S24-F3) |
| Mount as bypass | oci_routes.rs write path | open (S24-F3) | | |
| Tags/catalog/referrers rewriting, Link/Location | serve.rs:978-1020, 1180-1190 | closed | Link only same origin, same list, paging keys only; Location same origin under `/v2/`; HeaderValue rejects CR/LF | |
| Repository name canonicalisation | coords.rs, probation_policy valid_oci_name | closed | | |
| Upload sessions, id guessing, Content-Range | oci_routes.rs:380-405 | closed at the firewall (registry owns session authority, caller's own credential, same-origin Location) | | spool/budget U-1 |
| Manifest PUT/DELETE with caller credentials only | oci_routes.rs:358-372 | closed | firewall key (`prb_`) refused 403; credential sent only to `fetch_oci` against the registry origin | S24-F6.3 |
| Certificate-managed legacy route re-auth | oci_routes.rs:219-245 | closed (static) | policy fingerprint re-read without a second rate charge | |
| Ping "open" when a credential is presented | serve.rs:1128-1136 | closed | the 200 reveals nothing; anonymous caller gets the registry's own challenge; private data always needs the registry's authorization | |
| Memory/latency of verify-in-full, DoS by huge layers | download.rs fetch paths | unknown | caps and download permits are the shared pipeline's; OCI adds blobs up to 5 GiB per digest chosen by the caller after one cooldown | U-2, not measured |
| Resource fairness (places) | serve.rs:218-244 | open | S24-F2 | |
| Row growth across repositories | store/ rows | unknown (U-2) | per-repository cap exists; no global cap seen; an attacker can create rows for any number of real public repositories | same as other families, not re-verified |

## Verification and limits
- Commands run: git status/rev-parse, sha256sum of the three files, source reads via camlstruct. No build, no tests, no containers started (read-only scope; nothing to clean up). The scratch directory was not used.
- Evidence file slice-24.md was read as claims only; its test names were not run.
- Not examined: src/http/spool.rs internals, src/artifacts serve_artifact_in beyond the OCI branches, portal and server crates (templates, fleet), the E2E fixtures, config validation of `upstream_origin_with` (userinfo/query rejection assumed), dependency advisories (no new dependency was introduced by the files read).
- Unchanged during review: yes for the three primary files (fingerprints recorded before and checked at the end of reading).

## Next steps
1. Fix S24-F1 first (separate the client-sent credential from the stored one in `serve_token`; add a cert-mode regression test that the response never contains the stored credential and no scope above pull is minted).
2. Fix S24-F2 (owner-keyed place shares incl. anonymous) and decide S24-F3 (name-independent / sha256-canonical digest block).
3. Apply S24-F4/F5/F6 hardening; answer U-1 and U-2 with a test that runs the OCI write route through the spool owner scan and a global project/row bound check.
4. Re-review S24-F1..F3 after the fix with an executed witness.
