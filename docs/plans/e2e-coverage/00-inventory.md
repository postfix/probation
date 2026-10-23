# End-to-end coverage inventory

Date: 2026-10-23. Commit: 2a6d065 (branch `management-server`).

Source: eight read-only reviews of the code and tests. Nothing was built or run. All counts below were made by hand from those reviews, so they are close but not exact (about ±2 per area).

What the coverage levels mean in this document:

| Level | Meaning |
|---|---|
| **E** (e2e) | Runs against the deployed stack: real images, Postgres, server, firewalls. Today this is only one script: `tests/e2e/signup_to_install.sh` with `tests/e2e/drive.mjs`. It runs in `release.yml` only, never on a PR. |
| **I** (integration) | Runs in-process against real Postgres and/or an in-process firewall (`App::start`) with a fake upstream. `tests/e2e_npm.rs` and `tests/e2e_pip.rs` run the real npm and pip clients, but against an in-process firewall and a fake registry on loopback, so they count as I. |
| **U** (unit) | A `#[test]` inside `src/`. |
| **NONE** | No test of any kind. |

---

## 1. Summary

### 1.1 Counts per area

| Area | Operations | Cases | E | I | U | NONE |
|---|---:|---:|---:|---:|---:|---:|
| A1 Firewall proxying (npm, PyPI, cache, upstream, health, config) | 24 | 184 | 4 | 131 | 9 | 40 |
| A2 Policy decisions (blocklist, freeze, OSV, layers, exceptions, logs) | 24 | 150 | 3 | 93 | 22 | 32 |
| A3 Firewall managed mode (keys, sync, lock, activity, settings push) | 16 | 161 | 4 | 104 | 15 | 38 |
| A4 Management server core (sync API, keys, edits, tenancy, CLI) | 17 | 170 | 11 | 86 | 3 | 70 |
| A5 Accounts and sign-in | 16 | 192 | 10 | 95 | 1 | 86 |
| A6 Portal places (orgs, groups, members, keys page, policy page) | 20 | 181 | 5 | 111 | 1 | 64 |
| A7 Global admin, fleet, automation, retention | 30 | 172 | 4 | 106 | 1 | 61 |
| A8 Operations and deployment | 26 | 150 | 13 | 63 | 5 | 69 |
| **Total** | **173** | **1360** | **54 (4%)** | **789 (58%)** | **57 (4%)** | **460 (34%)** |

How to read this:

- Integration coverage is strong and careful. Most race conditions are made deterministic with row locks or fake clocks.
- The 54 "E" cases all come from **one** script. That script is npm only, happy path only, managed mode only, and does not run on PRs.
- One case in three has **no test at all**. Most of these are negative or edge cases.

### 1.2 Biggest risks

1. **PyPI never runs through the deployed stack.** No pip, uv or poetry run against a managed firewall. No test touches real `pypi.org` or `files.pythonhosted.org`. The shared OSV fake ignores the ecosystem field, so a wrong spelling of `PyPI` would pass every test. A malicious PyPI release could be served while every check is green.
2. **Removing a block, and exceptions, are not tested where they matter.** `remove_block` and `remove_exception` have no test anywhere. Exceptions are only unit-tested in the firewall. If an unblock never reaches the fleet, builds stay broken. If an exception lifts too much, blocked code installs.
3. **Operations paths run only in-process or not at all.** Nothing tests these on real images: settings push with exit 75 and a supervisor restart, a restore with real `pg_dump`/`pg_restore`, an upgrade with mixed versions, a server or Postgres outage, a container restart on a populated volume.
4. **Standalone mode (the MVP's main mode) is never run as an image.** Blocklist file watching on bind mounts, volume permissions for the non-root user and the log directory are all untested.
5. **The documented client matrix is untested.** `docs/operations.md` §7 says pnpm, yarn 1 and berry, bun, corepack, uv, poetry and pipx work. No test runs any of them.
6. **Proxy topologies are untested, and two of them break the product.** An `X-Forwarded-For` entry with a port gives 403 to every request. A portal behind a proxy not listed in `trusted_proxies` puts all users on one IP, so one attacker can lock out sign-in for everyone.
7. **The release gate depends on live services** (registry.npmjs.org, api.osv.dev, api.pwnedpasswords.com, and the state of the `commander` package). An outside change can block a release, and a broken release can pass if the live data happens to be friendly.

### 1.3 Suspect defects found while reading

These are not only test gaps. Each needs a decision (see §5, D9) before a test can assert the right behaviour.

| # | Finding | Where |
|---|---|---|
| F1 | `X-Forwarded-For` entries with a port, brackets, `unknown`, or only a `Forwarded` header are refused, so every request behind such a load balancer gets 403 | `src/managed/lock.rs:131` |
| F2 | A plain SIGTERM loses activity queued since the last sync. Only the restart-for-settings path makes a last call | `src/tasks/policy_sync.rs:51` |
| F3 | An unknown enum variant from a newer server counts as "unreachable", so the firewall serves stale policy forever while looking healthy | `src/managed/client.rs`, `src/managed/sync.rs` |
| F4 | After a restart, the snapshot makes the firewall ready before the first sync, so keys revoked while it was down are served until that sync | `src/managed/cache.rs` |
| F5 | The "retired" flag is not persisted across a restart | `src/managed/sync.rs` |
| F6 | `managed-cache.json` is unversioned JSON. An upgrade that changes it loses both snapshots; during a server outage every key then gets 401 | `src/managed/cache.rs` |
| F7 | `verify_email` does not end the login's earlier sessions. An attacker who signed up with the victim's address keeps a session that becomes valid once the victim clicks the confirm link | `crates/probation-server/src/accounts.rs` |
| F8 | `probation-server` has no SIGTERM handler and no graceful shutdown. As PID 1 it ignores SIGTERM and is killed after the grace period | `crates/probation-server/src/lib.rs`, `main.rs` |
| F9 | The server has no health endpoint, and neither compose file has a server healthcheck | – |
| F10 | `admit_any` admits an artifact URL on any of the three origins, so an npm tarball URL on the PyPI files host is fetched | `src/upstream` |
| F11 | The automation API answers 401 (looks like a revoked token) on a database outage, not 503 | `Tenancy::automation` |
| F12 | With no SMTP configured, unsent outbox rows keep live confirm and reset links in plain text | `accounts::deliver_outbox` |
| F13 | `revoke-key` docs say "Revokes any key", but the code only revokes user and service keys | `docs/management-server.md`, `keys.rs` |
| F14 | npm Accept negotiation uses `contains()`, so `install-v1;q=0` still gets the abbreviated form | `npm_routes::negotiate` |
| F15 | `release.yml` creates the GitHub release before `cargo publish`; the version 0.2.2 is already on crates.io; the real-client tests and the coverage gate do not run in `release.yml` | `.github/workflows/release.yml` |
| F16 | A firewall registered after a backup gets 401 after the restore and stops serving; a firewall retired after the backup comes back to life. Not documented | `docs/operations.md` §13 |
| F17 | The invitee who has no login opens `/invite`, is sent to `/signin`, and the link is lost | portal `/invite` |

---

## 2. Gap matrix per area

Each cell shows the best coverage level of that kind of case, then the main missing cases. **NONE** means no case of that kind has any test. "–" means the review listed no case of that kind.

### A1 Firewall proxying

| Operation | Positive | Negative | Edge |
|---|---|---|---|
| npm full packument | E (is-number only), I | I | I. Gap: real large packuments (typescript, @types/node) and render time |
| npm abbreviated (install-v1) | I | – | I. Gap: mixed Accept with q-values (yarn, pnpm, bun); `install-v1;q=0` (F14) |
| npm scoped packages | I | I | **NONE**: scoped exact version with three segments; real client installing a scoped tree |
| npm exact version and tag | I | I | E (status flip on policy edit). Gap: versions with build metadata or a `v` prefix |
| npm dist-tags | I | I | I. Gap: `npm install pkg` when `latest` is omitted; `npm dist-tag ls` endpoint |
| npm ping and unsupported endpoints | I | I | **NONE**: npm with audit on (the default); `npm publish` and `npm login` refused |
| npm tarball by reference | I | I | I. Gap: artifact of hundreds of MB through the real transport timeouts |
| npm tarball at lockfile path | I (real npm ci) | I (real npm ci) | I. Gap: yarn 1 with and without the sed rewrite; pnpm-lock; yarn berry |
| Integrity verification | U, I | I | U, I. Gap: PyPI wheel whose bytes contradict its sha256 |
| PyPI simple page | I (real pip) | I | I. Gap: real pip with requires-python, yanked, `--require-hashes`; real pypi.org shapes |
| PyPI name normalisation | I | U only | I. Gap: relative redirect behind a TLS proxy; non-ASCII name |
| PyPI known-project index | I | I | **NONE**: index after restart; many projects |
| PyPI file filtering | I | I (real pip) | I, U. Gap: build-isolation fetch of setuptools and wheel |
| PyPI file download | I | I. Gap: advertised sha256 mismatch | **NONE**: real files.pythonhosted.org over TLS |
| Metadata cache and revalidation | I | I | I, U. Gap: real registry ETag and 304 behaviour |
| Content store, eviction, crash safety | I | I | I, U. Gap: container restart on a volume; upgrade of a real data_dir from the previous release |
| Upstream errors, timeouts, redirects | I | I | U, I. Gap: real 5 s connect, 30 s metadata, 30 s idle and 15 min artifact timeouts; slow upstream body |
| Origin guard | I | I | I. Gap: cross-ecosystem artifact URL (F10) |
| Configurable upstream origins | I. Gap: `pypi_upstream_url` and `pypi_artifacts_url` never used end to end | I | I. Gap: a real mirror whose files sit on another host |
| Capacity, overload, slow clients | I | I | I. Gap: health probes while `max_active_requests` is exhausted; CI fan-out 503 storms |
| Health endpoints | I | I | E (ready over TLS), I. Gap: standalone image ready with the sample blocklist |
| Config, startup, TLS, signals | I | I | I. Gap: image never started standalone; TLS cert mismatch, expiry, rotation |
| Policy applied to listings | U, I | I (real npm) | I. Gap: real pip or uv on an OSV-flagged PyPI version |
| Real client matrix | E (npm only), I | **NONE** for pnpm, yarn 1 and berry, bun, corepack, uv, poetry. pip in managed mode: I only | **NONE**: pip over HTTPS with the firewall's certificate |

### A2 Policy decisions

| Operation | Positive | Negative | Edge |
|---|---|---|---|
| Load blocklist at startup | I, U | I | I, U. Gap: standalone image with a mounted file |
| Hot reload and atomic swap | I. Gap: an unblock reappears in warm npm and PyPI listings | I | I. Gap: producer writes on a bind mount or overlayfs in a container |
| Expiry and readiness | I | I | I. Gap: wall clock stepped across `expires_at` |
| npm package, version, hash blocks | I, E (by fetch only) | I. Gap: real npm against the deployed image | I |
| PyPI package, version, hash blocks | I, U | I. Gap: direct artifact URL of a blocked or digest-blocked file; advertised sha256 block; any PyPI decision in the deployed image | **NONE**: block added while a wheel downloads |
| Release-age freeze | U, I | I. Gap: a fresh release held by the deployed image, then released by a portal change | U, I |
| Publication-time trust rules | – | U, I | I |
| npm dist-tag rewriting | I | I | I |
| OSV lookup | I, U | **NONE**: PyPI ecosystem spelling; non-MAL advisories must not block | E (implicit, no match asserted). Gap: OSV recheck between listing and download; `next_page_token` |
| OSV outage (fail open) | I | – | U, I. Gap: slow-but-up OSV silently failing open |
| OSV modes off / log-only / enforce | U, I | – | I. Gap: log-only on the artifact path (`record_would_block`) |
| Decision order | U | – | **NONE**: version that is both held and OSV-flagged |
| Effective policy and layers | U, I | U | U. Gap: group and user layers enforced by a firewall; newer layer encoding on an older firewall |
| Edit a policy layer | I, E. Gap: `remove_block`, `remove_exception` and their propagation | I | I |
| Exceptions at decision time | U. Gap: an exception makes a package installable through a firewall | U, I | **NONE**: PEP 440 spelling; exception on artifact and lockfile paths |
| Per-key policy in managed mode | I | I | I. Gap: two orgs on one deployed firewall with real npm |
| Blocklist import, export, automation push | I. Gap: a CI push enforced by a deployed firewall | I | – |
| Decision log line and activity | I. Gap: org admin sees the blocked install on the portal | I | I |
| Decision log file sink | I | I | I. Gap: file on a container volume |
| SIEM delivery | I | I | I. Gap: real TLS collector from the image |
| Delivery health | I | – | I |
| Refusal responses (HTTP) | I | I | **NONE**: 403 body and Retry-After on PyPI artifact and npm lockfile paths |
| What the client user sees | I (npm "403", pip "No matching distribution") | **NONE**: an actionable message; yarn, pnpm, uv, poetry | **NONE**: client retries on 503 and on 403 HELD |
| check-blocklist CLI | I | I | – |

### A3 Firewall managed mode

| Operation | Positive | Negative | Edge |
|---|---|---|---|
| Authenticate by API key | E (npm Bearer), I, U. Gap: real pip, uv, poetry, pnpm, yarn | I. Gap: non-ASCII header bytes; 401 without `WWW-Authenticate` (pip prompt or hang in CI) | I, U. Gap: 1024 vs 1025 byte boundary; `public_url` alias so clients do not send credentials to artifact URLs |
| Serve under the key's own policy | I, E | I | I |
| Key lookup and key cache | I (with real server burst) | I. Gap: oversized, malformed or 3xx answer; unknown variant from a newer server (F3) | U, I. Gap: `key_cache_max_entries` under load; NTP jump |
| Lookup budget (LOOKUP_BUSY) | I | I | I. Gap: default 5/s with many CI runners behind one NAT; real clients retrying 503 |
| Network lock | I | I | I, U. Gap: direct IPv6 and dual-stack clients; docker gateway as peer |
| Trusted proxies and XFF | I | I, U | U. Gap: XFF with port, brackets, `unknown`, or `Forwarded` (F1); real load balancer |
| Per-account rate limit | I | I | I. Gap: npm and pip behaviour on 429; Retry-After |
| Readiness before first sync | E, I | I | **NONE**: TLS failure at first sync; storage unhealthy after ready |
| Sync round | E (revocation p99), I | I. Gap: oversized, malformed or unknown-variant `changes` answer | I. Gap: panicking round; `management.url` with a path prefix; report fields from a real firewall |
| Reset (cursor behind, lower revision) | I | I | **NONE**: fleet-wide lookup burst after a reset with real clients |
| Server unreachable: serve stale | I | I | I, U. Gap: snapshot write failure; revoked-key window after restart (F4); multi-day outage |
| Activity queue and shipping | I. Gap: row visible on the portal Activity page | I | U, I. Gap: rows lost on SIGTERM or crash (F2); more than 1000 accounts with drops |
| Settings push and overlay | I | I | I. Gap: real exit 75 and supervisor; crash between overlay and state; UTF-8 truncation; `managed-settings.failed.toml`; change of `sync_interval_seconds` |
| Retired firewall, token refused | I | I | **NONE**: restart of a retired firewall (F5); token rotation |
| Key canary | I | I | I. Gap: shipped image's stdout under real traffic |
| `[management]` config | U, I | U | – |

### A4 Management server core

| Operation | Positive | Negative | Edge |
|---|---|---|---|
| Sync lookup | I, E | I. Gap: malformed body gives 422 | I. Gap: refill storm after a reset against the 200/s token rate; lookup racing a revocation |
| Sync layers | I, E | I. Gap: more than 1000 places gives 413; malformed gives 422 | **NONE**: exactly 1000 places; very large layer vs 8 MiB and 1 s; missing layer row |
| Sync changes | I, E | I. Gap: malformed gives 422; undecodable subject gives 503 | I. Gap: `i64::MAX + 1` boundary |
| Report and activity intake | I. Gap: rows on the portal Activity page | I. Gap: kind filter; `last_apply_error` over 2 KiB; bad `eligible_at` fails the whole batch; stray `client_ip` | I. Gap: same event id from two firewalls; report committed but delta fails; long or unicode strings |
| Firewall token authentication | I, E (sources 0.0.0.0/0 only) | I. Gap: non-IP XFF; lowercase `bearer`; source refusal in the deployed stack | **NONE**: IPv6 and mapped peers; rate per process with replicas; empty source list |
| Key create | U, I, E | I. Gap: key on the platform place; suspended org | I. Gap: concurrent creates at the limit; audit failure rollback; long or unicode name |
| Key revoke (portal and CLI) | I, E. Gap: CLI in the image | I. Gap: double revoke; CLI unknown id; CLI on a firewall or automation token id (F13) | **NONE**: concurrent revokes; CLI with server stopped; id above `i64::MAX`; operator audit row |
| Policy edit path | I, E | I, U | I. Gap: parent switch changed during a child save; thousands of blocks vs 1 s timeout; missing layer |
| Tenancy authorization | I | I. Gap: id probing through the deployed portal | I. Gap: store error fails closed |
| Audit append-only and prune | I | I. Gap: TRUNCATE | I. Gap: the hourly job runs; grants after a real `pg_restore` |
| change_log order and prune | I | I. Gap: retention 0 refused | **NONE**: nothing to prune; scheduling; two replicas |
| `admin after-restore` | I | **NONE**: DB URL unset; firewall registered after the backup; retired firewall revived (F16) | **NONE**: real `pg_dump`/`pg_restore`; run while serving; deployed drill |
| `admin bootstrap` | I, E. Gap: the printed bootstrap key is never used | I. Gap: BadEmail; EmailTaken (address squat); missing source, CIDR, DB or config | I. Gap: two bootstraps at once; link expiry; unicode org |
| `admin reset-link` | I | I. Gap: non-admin or deleted admin; no `[portal]` | **NONE**: audit row; TOTP still asked |
| `migrate` | I, E | I. Gap: migrate URL unset; owner without CREATEROLE | I. Gap: re-run is a no-op; upgrade of a populated DB; older binary on a newer schema |
| `serve` and config load | U, E | **NONE**: unknown key, retention 0, bad SECRET_KEY, provider secret, DB unreachable | **NONE**: restart during syncs |
| Firewall registration | I, E | I | **NONE**: empty sources; duplicate name |

### A5 Accounts and sign-in

| Operation | Positive | Negative | Edge |
|---|---|---|---|
| Sign up (org, personal) | E (org), I | I. Gap: HIBP 5xx, TLS or refused; invalid email; org name rules on `/signup` | I. Gap: password over 1024 bytes; NFC vs NFD; email casing; IDN; concurrent sign-ups; org name taken before confirm |
| Email confirm, resend, outbox | E (link read by SQL), I | I. Gap: 24 h expiry; resend for unknown or confirmed address; resend caps | **NONE**: real SMTP; the 30 s outbox loop in the binary; retry backoff; payload cleared; two servers; other browser; earlier sessions not ended (F7) |
| Password sign-in and sign-out | E, I | I. Gap: OAuth-only login with a password; cookie replayed after sign-out; login past 30 days | U, E. Gap: `/signin` while signed in; email casing |
| Throttles and mail caps | – | I | I. Gap: password throttle lifts after 15 min; spoofed XFF; proxy not trusted (one IP for all); failure-row purge |
| Authenticator step at sign-in | E, I | I. Gap: `/totp` with nothing pending | **NONE**: +30 s skew; spaces and casing in codes; same code from two browsers; wrong SECRET_KEY |
| Turn authenticator on or off | E, I | I. Gap: global or group admin turning it off; wrong code at enable | I. Gap: QR SVG under the CSP; setup while already on |
| Change password | I | I. Gap: leaked new password; login without a password; SSO session | I |
| Password reset and set-password links | I, E (bootstrap link) | I. Gap: bad new password at confirm; deleted or OAuth-only login | **NONE**: reset of an unconfirmed method; link after unlink; real SMTP |
| OAuth (Google, GitHub, Microsoft) | I. Gap: GitHub creating a new login | I. Gap: Google iss, aud, exp; alg none or HS256; JWKS or token failures; GitHub errors; user cancels; unknown provider | I, U. Gap: identity of a login past 30 days; real IdP over TLS; cookie on the cross-site return |
| Org SSO | I | I. Gap: shared issuer without tenant; unknown org id; suspended or deleted org | I. Gap: trailing slash in issuer; real OIDC provider |
| Link and unlink methods | I. Gap: Microsoft | I. Gap: unknown SSO org; callback after sign-out | I. Gap: re-link duplicate; two sessions unlink both methods; admin drops their password |
| Sessions, CSRF, headers | I | I | **NONE**: 12 h and 1 h expiry; purge; security headers; survive restart; Secure cookie over http |
| Delete, restore, new login | I | I. Gap: wrong confirm text; restore on day 31 | **NONE**: other sessions ended; SSO scope after restore; race with purge |
| Personal account and org from Account page | I | I. Gap: name length; restore after 30 days | I |
| Daily 30-day purge job | I | – | **NONE**: exact boundary; one failing erase; session and failure purge; job runs in the binary; two replicas |
| Secrets at rest | I | I | I. Gap: hash is Argon2id; bad or rotated SECRET_KEY; plain-text links in unsent outbox (F12) |

### A6 Portal places

| Operation | Positive | Negative | Edge |
|---|---|---|---|
| Create organisation | E, I | I | I. Gap: unicode case folding and NFC; two creates with one name; HTML escaping on `/org`, `/keys`, `/policy`, `/audit`, `/activity` |
| Place switcher | I | I | I. Gap: selected org deleted or suspended; two tabs |
| Move member to another group | I | I | **NONE**: moving a group admin out; race with group delete; no-op move |
| Change a member's role | I | I. Gap: forged role on the role route; group admin changing a role | **NONE**: promoted without TOTP during a session |
| Remove a member | I | I. Gap: group admin or member posting a removal | I. Gap: removal during an in-flight install; member who is also global admin |
| Invitations: create, cancel | I | I. Gap: invalid email; group admin role without a group; accepting a cancelled link | **NONE**: link through real SMTP; group deleted before accept |
| Invitations: open, accept | I | I. Gap: accepting when already a member | I. Gap: time boundaries; deleted or suspended org; invitee without a login (F17) |
| Leave requests | I | I. Gap: sole admin approves own leave; member approving | I. Gap: asking twice |
| Groups: create, rename, delete | I | I. Gap: empty or 101-char name; group admin renames or deletes | **NONE**: duplicate names; pending invitations into a deleted group; HTML or unicode names |
| Admin second factor (C24) | E, I | I. Gap: hold-back in the deployed stack | I. Gap: org admin who signs in with GitHub or Microsoft |
| TOTP reset by org admin | I | I. Gap: login that is also in another org | **NONE**: end of the 30-day window; re-enrol after reset; race with promotion |
| Company SSO settings | I | I. Gap: http issuer; shared issuer without tenant; duplicate issuer and client | I |
| Keys page and setup snippets | I, E (npm only) | I. Gap: personal 5-key limit; org override at creation; name validation | I, U. Gap: concurrent create at the limit; FIREWALL placeholder; path prefix; real pip, uv, poetry, yarn, pnpm with the snippets |
| Service keys | I | I. Gap: group admin creating one | I. Gap: service key used by CI through a deployed firewall |
| Policy page | I, E. Gap: role redirects; `remove_block`, `remove_exception`; allowed `add_exception`; OSV off | I. Gap: non-numeric or unknown values; bad remove index | I. Gap: partly applying exception label; freeze on a real client; PyPI name normalisation; large forms |
| Activity page | I | I | I. Gap: rows from a real firewall upload; personal account view; 500-row cap; group history follows membership |
| Audit page | I | I | **NONE**: personal account view; 500-row cap |
| IP ranges (org side) | I | I | I. Gap: IPv6, 0.0.0.0/0, overlaps; real client addresses |
| Organisation delete and restore | I | I. Gap: member or group admin deleting | I. Gap: exact boundary; sign-in while deleted; daily purge in the binary |
| CSRF, isolation, suspension, a11y | – | I | **NONE**: axe walk not in CI; DB outage gives 503; restart mid-session; mixed versions |

### A7 Global admin, fleet, automation, retention

| Operation | Positive | Negative | Edge |
|---|---|---|---|
| Reach `/admin` and `/fleet` | E, I | I | I. Gap: removed admin's open session; thousands of orgs with no pagination |
| Act inside an org as global admin | I | – | I |
| Suspend an organisation | I. Gap: confirm page (axe only) | I | **NONE**: suspend twice; automation token 401; service keys on two firewalls |
| Re-activate an organisation | I | – | – |
| Personal account suspend, activate | I | I | **NONE**: banner for the owner; deleted account |
| Personal account: revoke all keys | I | – | **NONE**: propagation measured; zero keys |
| Personal account: reset TOTP | I | – | **NONE**: owner re-enrols |
| Personal account: delete, restore, purge | I | **NONE**: restore after 30 days | I |
| Add a global admin | I, E (bootstrap) | I. Gap: invalid email | I. Gap: expired link; already admin; links of a deleted login; real SMTP |
| Remove a global admin | I | I | I |
| Default limits | I | I. Gap: rate 0, negative, overflow, unknown kind | **NONE**: default change reaches cached keys; max_keys below the current count |
| Org limit override | I, E (indirect) | I | **NONE**: suspended or deleted org |
| Set retention | I | I | **NONE**: 7 and 36500 boundaries; non-numeric input |
| Activity and audit prune job | I | – | I. Gap: per-org activity retention; the hourly job runs; millions of rows |
| change_log prune job | I | – | I |
| Range approve, refuse, delete | I | I. Gap: blank refusal reason; range already decided | I. Gap: overlap with another org; IPv6; concurrent approvals; real load-balancer address |
| Edit the platform policy | I | – | – |
| Platform automation token | I | I. Gap: revoked token gives 401; name validation | – |
| Org automation token | I. Gap: org admin revokes own token | I | **NONE**: token created during demotion |
| Automation blocklist API | I | I. Gap: no or wrong auth scheme; malformed JSON, schema, ecosystem, digest, non-UTF-8 | **NONE**: concurrent push 409; empty PUT; DB outage gives 401 (F11); default reason changes fingerprint; unicode; 8 MiB layers cap; proxy 1 MB body limit |
| Blocklist import and export in the portal | I. Gap: platform import and export | I. Gap: bad file; conflict message | **NONE**: large textarea vs form limit; download header |
| Fleet page health | I | – | I. Gap: npm and PyPI unreachable states; Retired row; real reports; stopped container |
| Register a firewall | I, E | I. Gap: blank or long name; no sources; bad CIDR | **NONE**: host bits; separators; IPv6; duplicate name |
| Firewall token and source ranges | I | I | I. Gap: restrictive range behind the real sync proxy |
| Push settings | I | I. Gap: non-https upstream; empty selection; duplicate or retired id | I. Gap: two operators push at once |
| Rollout progression | I (fake check-ins) | I | I, U. Gap: retired firewall's step skipped; real firewall with supervisor |
| Rollout timeout | I | – | I. Gap: state moves only when `/fleet` is read |
| Resume and skip | I. Gap: `rollout.resume` and `rollout.skip` audit rows | I. Gap: resume or skip of a running or done rollout | **NONE**: two operators at once |
| Retire a firewall | I | I. Gap: retire twice | **NONE**: retire while its step is sent releases the next |
| Daily purge of admin data | I | – | **NONE**: purge scheduled in the served process |

### A8 Operations and deployment

| Operation | Positive | Negative | Edge |
|---|---|---|---|
| Build the firewall image | E. Gap: standalone run with shipped config and blocklist | **NONE**: `--locked` mismatch | **NONE**: bind mount owned by another uid; podman; volume kept across restart |
| Build the server image | E | – | **NONE**: images are never published |
| Server start | E, I | U. Gap: unknown key; retention 0; SECRET_KEY; provider and SMTP secrets; DB unset or unreachable | **NONE**: start before Postgres; SIGTERM ignored (F8) |
| `migrate` | E, I. Gap: re-run; upgrade of a populated DB | **NONE**: URL unset; no CREATEROLE; edited migration checksum | I |
| `admin bootstrap` | E, I | I. Gap: BadEmail; EmailTaken; bad source or config | I. Gap: two at once |
| First sign-in through the link | E | I | **NONE**: self-service `/reset` cancels the link; https portal with Secure cookie |
| `admin reset-link` | I | I. Gap: non-admin; deleted admin; no `[portal]` | **NONE**: audit row; TOTP kept |
| `admin revoke-key` | I | I (library only) | **NONE**: run while the server is stopped |
| Restore and `after-restore` | I | **NONE**: operator forgets `after-restore` | **NONE**: real `pg_dump`/`pg_restore`; other SECRET_KEY; clock stepped back; run while serving; sequence exhaustion |
| Managed config and first sync | E, I | I. Gap: sync proxy certificate not trusted | I, E |
| TLS and reverse proxies | E, I | I | **NONE**: firewall behind a TLS proxy with `public_url` (the deploy example); certificate renewal |
| Settings push, exit 75, restart | I. Gap: binary exits 75; supervisor restarts it | I | I. Gap: no restart policy; systemd StartLimitBurst; mixed versions |
| Stop and restart a firewall | I | I | I. Gap: managed SIGTERM loses activity (F2); real `docker stop` and `systemctl stop` |
| Server or Postgres outage | I | **NONE**: slow Postgres vs the 1 s timeouts; portal during a DB outage | I. Gap: snapshot unreadable after upgrade (F6) |
| Disk full | I | I | **NONE**: snapshot and overlay writes on a full disk; Postgres volume full |
| Firewall upgrade and rollback | U | U | U. Gap: real previous image on a volume; standalone to managed |
| Server upgrade and mixed versions | U, I | I | **NONE**: unknown fields ignored; real rolling upgrade |
| Standalone backup of `state/` | I | I | I |
| Decision log and outputs | I | I | I. Gap: log directory in the container |
| Server prune job | I | **NONE**: a failure is logged and the loop continues | **NONE**: two replicas; first tick at start |
| Health checks | I | **NONE**: the server has no health endpoint (F9) | – |
| Release workflow gates | E | **NONE**: real-client tests and coverage not run in release; version already on crates.io (F15) | **NONE**: dependency on live npm, OSV, HIBP; logs on failure |
| Crate publishing | **NONE** | **NONE**: name squat and checksum not checked | **NONE**: index timeout; packaged contents |
| Clock issues | I | **NONE**: Postgres clock stepped back before `after-restore` | **NONE**: TOTP skew; host clock offset vs cooldown |
| Real clients through the deployed stack | E (npm), I | I (standalone only). Gap: 401 as npm and pip show it | **NONE**: yarn, pnpm, poetry, uv; `NODE_EXTRA_CA_CERTS` |
| Local installers | **NONE** | – | **NONE**: re-run overwrites config |

---

## 3. Real-life scenario catalogue

All scenarios run against the deployed stack: real images, Postgres, the server, at least two firewalls, real npm and pip clients (and the other clients where named), and Playwright Chromium for the portal. The 74 scenarios from the reviews were merged into 39 journeys.

Fixture codes:

| Code | Fixture |
|---|---|
| NPM | Fake npm registry (answers as `registry.npmjs.org`) |
| PYPI | Fake PyPI (answers as `pypi.org` and `files.pythonhosted.org`) |
| OSV | Fake OSV (answers as `api.osv.dev`) |
| HIBP | Fake leaked-password range API |
| SMTP | Mail catcher with an HTTP API (mailpit) |
| OIDC | Fake OIDC IdP (plus a real one, dex or Keycloak, in nightly) |
| TLS | TLS reverse proxy (nginx) in front of firewall and portal, with XFF variants |
| CLOCK | Clock control (relative timestamps, SQL back-dating, libfaketime only where needed) |
| DBR | Database dump and restore (`pg_dump`/`pg_restore`) |
| NET | Network faults (disconnect, hang, throttle) |
| SUP | Real supervisor: compose restart policy, and systemd in a container |
| PREV | Images of the previous release |
| LIVE | Real public registries (canary only) |

Priority: **P0** must exist before the next release. **P1** next. **P2** later.

### P0

#### E2E-001 Python clients in managed mode (pip, uv, poetry)
- **Steps:** Sign up, create a key, copy the pip.conf line from the keys page. Run `pip install`, `uv pip install` (uv.toml) and `poetry add` (source plus http-basic), each with a clean cache, for a wheel and an sdist project. Block a version with a non-canonical spelling (`Foo_Bar==1.0`): pip and uv fall back; `pip install foo-bar==1.0.0` fails. Install a `--require-hashes` file and a `poetry.lock` that name the blocked file's artifact URL: 403. Add an org exact-version exception: the install works. Revoke the key: each client fails fast with 401 in a non-TTY shell (no prompt, no hang). The Activity page shows the rows.
- **Proves:** Python users can install through the product as shipped, and refusals hold on every PyPI route.
- **Closes:** no PyPI client in managed mode; PyPI artifact-route refusals; PEP 503/440 in managed blocks and exceptions; Basic auth on rewritten artifact URLs; 401 without `WWW-Authenticate`.
- **Fixtures:** PYPI, TLS.

#### E2E-002 npm block, refuse and unblock on two firewalls
- **Steps:** Org admin (with TOTP) adds a package block and a version block on the portal. After one interval, real `npm install` falls back to an older version; `npm ci` with the blocked pin fails with 403 and the lockfile is unchanged. Check npm's stderr for the code and reason. The Activity page shows rule and layer, never the key. Admin uses `remove_block`. After one interval the same installs work on both firewalls, from a warm cache.
- **Proves:** a block reaches the fleet, real npm shows it, and an unblock comes back.
- **Closes:** `remove_block` and unblock propagation; refusal seen by real npm (today checked with fetch); activity page fed by a real firewall.
- **Fixtures:** NPM.

#### E2E-003 OSV enforcement, log-only and outage
- **Steps:** Fake OSV flags an npm version and a PyPI version with `MAL-*`, and another version with a GHSA advisory only. The fake rejects any query whose ecosystem is not exactly `npm` or `PyPI`. Enforce: npm and pip refuse the MAL versions and install the GHSA one. Flag a version between listing and download: the download is refused. An org with `allow_osv_off` switches to log-only: installs work and Activity shows `would_block` (also on the artifact path). Make the fake slow, then stop it: installs still work (fail open), the fleet page shows OSV unreachable, warnings are logged.
- **Proves:** malware advisories block for both ecosystems; outages fail open in a visible way.
- **Closes:** PyPI ecosystem spelling; non-MAL advisories; post-download recheck; `record_would_block`; slow OSV.
- **Fixtures:** OSV, NPM, PYPI.

#### E2E-004 Offboarding and key revocation
- **Steps:** Three members install with warm caches on both firewalls. Org admin removes one, approves another's leave, and revokes a key on `/keys`. The operator runs `admin revoke-key` in the server container. A personal-only user deletes their login. All those keys get 401 on both firewalls within one interval, including a key created during the removal. Restore the deleted login: 200 again. "Start a new login": the old key stays 401. `revoke-key` with a firewall token id is refused, matching the docs.
- **Proves:** people who leave lose access everywhere, fast.
- **Closes:** removal, leave and delete on real images; CLI in the image; F13.
- **Fixtures:** NPM, PYPI.

#### E2E-005 Operator's first deployment in the documented topology
- **Steps:** Use `deploy/docker-compose.yml` as the shape. Build images, start Postgres, `migrate` as owner, create the app role, `admin bootstrap` with the firewall's real address as `--firewall-source`. Firewall on plain HTTP behind a TLS proxy with `public_url` https; portal on an https `base_url`; the proxy in both `trusted_proxies`. Open the set-password link in the browser, set up TOTP, reach `/admin`, register firewall-2. Install with npm and pip using the printed bootstrap key. Start a third firewall with the same token from an unlisted address: 403 FIREWALL_SOURCE_REFUSED.
- **Proves:** the documented deployment works as written.
- **Closes:** T31 never exercised; bootstrap key never used; `public_url` and proxy mismatch; Secure cookie on https; the deploy example.
- **Fixtures:** NPM, PYPI, TLS.

#### E2E-006 Standalone firewall image with a producer blocklist
- **Steps:** Run the firewall image without `[management]`, with a bind-mounted `blocklist.json`, a log file and a fake SIEM collector over TLS (`PROBATION_SIEM_AUTH` from env). npm and pip install. The producer atomically replaces the file to add a block: within `blocklist_poll_seconds` the install falls back. Replace with a malformed file: last good stays, ready stays 200. Remove the block: the version reappears in warm listings. Replace with an expired file: `/health/ready` 503, every request 503 including warm hits. Restart the container: the persisted snapshot is used. Check the NDJSON file (mode 0600, rollover) and the SIEM batches.
- **Proves:** the MVP mode works as a shipped image.
- **Closes:** standalone never run as an image; rename semantics on bind mounts; volume and log-directory permissions; unblock in warm listings.
- **Fixtures:** NPM, PYPI, TLS (collector).

#### E2E-007 Settings push with exit 75 and a real supervisor
- **Steps:** Push `max_active_requests = 64` to both firewalls on `/fleet` while installs run. firewall-1 drains, delivers queued activity, exits 75, docker (`restart: unless-stopped`) restarts it on the overlay, it reports the revision, then firewall-2 gets the push. Push a value that fails at start: rollback, `failed_revision` on the page, rollout halts, no crash loop. Skip works, Resume is not offered; audit has `rollout.skip`. Retire a firewall whose step is sent: the next is released. Repeat once under systemd with `deploy/probation.service`.
- **Proves:** a fleet-wide config change cannot take the fleet down.
- **Closes:** exit 75 never tested; overlay ownership; retired step skipped; resume and skip audit rows.
- **Fixtures:** NPM, SUP.

#### E2E-008 Management server and Postgres outage during installs
- **Steps:** With install loops running: stop the server, then the sync proxy, then make TCP hang. Known keys keep installing (stale), a new key gets 401, `/health/ready` stays 200. Restart firewall-1 during the outage: ready from its snapshot. Stop Postgres: sync answers 5xx within the 1 s timeouts, portal shows an error page, nothing half-written. Bring all back: recovery without restarts, queued activity arrives. `docker stop server` exits promptly (F8). Revoke a key while firewall-1 is stopped, start it: measure how long the revoked key works (F4).
- **Proves:** a server outage does not become a fleet outage or a security hole.
- **Closes:** real TCP timeouts; snapshot on the image volume; revoked-key window; server shutdown; portal during DB outage.
- **Fixtures:** NPM, NET.

#### E2E-009 Backup and restore drill
- **Steps:** `pg_dump` the running DB. Then revoke key K, register firewall-3, retire firewall-2, add a block, push settings. Stop the server, `pg_restore` with the documented flags, run `admin after-restore`, then `admin revoke-key K` with the server stopped. Start it. Both firewalls reset once. K gets 401. Check firewall-3 and firewall-2 against the decided behaviour (F16). The app role still cannot UPDATE or DELETE `audit_log`; `prune_audit` works; sequences work. TOTP sign-in works with the same SECRET_KEY and fails clearly with another. A run that skips `after-restore` shows the skipped revocation (as a documented failure). Clients see LOOKUP_BUSY during the refill, never 401.
- **Proves:** the documented restore keeps revocations and permissions.
- **Closes:** TEMPLATE copy is the only restore test today; grants and ownership after `pg_restore`; F16.
- **Fixtures:** DBR, NPM.

#### E2E-010 Rolling upgrade with mixed versions
- **Steps:** Run the previous release's images and fill them: orgs, keys, layers, activity, a rollout, firewall data_dir, `managed-cache.json`, overlay. Run the new `migrate`, swap the server image while old firewalls sync. Upgrade one firewall on its volume. Check sync, reports, activity, pushes and propagation both ways. Stop the server and restart the upgraded firewall (snapshot must load). Roll one firewall back: clean refusal.
- **Proves:** an upgrade window is not an outage.
- **Closes:** migrations on real data; schema 4→5 on a real volume; F3 and F6; wire compatibility.
- **Fixtures:** PREV, NPM, PYPI.

#### E2E-011 Release-age freeze holds and releases
- **Steps:** The fake registry publishes a version one hour old (times are relative to start, so no clock control). Platform freeze 7 days, org may shorten. `npm install pkg` gets the previous version; `npm install pkg@new` fails 403 HELD with `eligible_at` and Retry-After; pip the same. The org sets 0 hours: within one interval the exact install works. With the switch off, the org save is refused and names the switch.
- **Closes:** freeze in the deployed image; HELD as real clients show it; projection expiry on policy change.
- **Fixtures:** NPM, PYPI.

#### E2E-012 Lockfile replay across every documented client
- **Steps:** With fresh caches, install from lockfiles made against the public registries: `npm ci`, `pnpm install --frozen-lockfile`, yarn 1 (after the documented sed rewrite, and once without it), yarn berry, `bun install`, `uv sync`, `poetry install`, `pip --require-hashes`. Then block one pinned version and repeat: each fails loudly and leaves the lockfile unchanged. The yarn run without the rewrite must not silently bypass the firewall.
- **Proves:** the client claims in `docs/operations.md` §7.
- **Closes:** every non-npm, non-pip client; token scoping per registry URL; lockfile bypass.
- **Fixtures:** NPM, PYPI.

#### E2E-013 Layered policy with groups, users and exceptions
- **Steps:** Platform block and 7-day freeze with exceptions allowed. Org A has group Frontend (group block) and Mia in it; org B has nothing. Bob (group admin, password only) blocks package X. Mia's `npm install X` gets 403; Max (no group) installs X; org B's key on the same firewall is unaffected by A. Org A adds an exception lifting the platform block but not the group block. A whole-package exception on a digest-blocked version: still refused; an exact-version one: allowed; PyPI exception with `1.0` vs `1.0.0`. Member edits their own user layer. Switch off: "not in effect" shown and enforced. Stale-revision save: conflict page. `remove_exception` restores the refusal.
- **Proves:** policy applies to exactly the right people.
- **Closes:** group and user chains on a running firewall; exceptions on a running firewall; `remove_exception`; cross-tenant cache.
- **Fixtures:** NPM, PYPI.

#### E2E-014 Upstream registry outage and recovery
- **Steps:** Warm cache, then make the fake registries refuse, hang, answer 5xx and 429, and stall mid-body. Clients get 502 or 504 within the real limits (5 s connect, 30 s metadata), never a CI hang. Warm artifacts stay served while metadata is fresh. Past the TTL and the age ceiling (configured short) refusals grow, not all at once. Restore: recovery without restart. The fleet page shows npm or PyPI unreachable.
- **Closes:** real ReqwestTransport timeouts; slow upstream; managed report in the UI.
- **Fixtures:** NPM, PYPI, NET.

#### E2E-015 Incident response through the automation API
- **Steps:** Global admin creates a platform automation token. A curl call (as CI) POSTs a blocklist with a package and a sha512 entry through the TLS proxy. Within one interval npm and pip installs of it fail for an org key and a personal key on both firewalls. GET export shows it. PUT without it lifts it. A body over the cap gets 413, a malformed body 422, nothing written. Stop Postgres: the API answers per the F11 decision.
- **Closes:** automation path on real images; proxy body limit vs 1 MiB; F11.
- **Fixtures:** NPM, PYPI, TLS.

#### E2E-016 Network lock and trusted proxies behind a real load balancer
- **Steps:** nginx in front of firewall-1 with `trusted_proxies` set. Org admin registers the office range; it has no effect while waiting; operator approves. A Globex key from inside the range gets 403 with the address only; the Acme key gets 200. Delete the range: lifted within one interval. Variants: XFF with `ip:port` and bracketed IPv6 (F1); `trusted_proxies` unset; docker bridge gateway as peer; IPv6 client. On the portal side: 100 failed sign-ins from one client must not lock out another client.
- **Closes:** every XFF case runs only on loopback today; F1; shared-IP lockout.
- **Fixtures:** TLS, NPM.

#### E2E-017 Self-service sign-up to install, in a real browser with real mail
- **Steps:** In Chromium: sign up as an organisation, read the mail from the catcher, confirm, sign in, turn on TOTP (QR SVG loads under the CSP), sign out, sign in with a code and with a backup code, create a key, use `.npmrc` and pip.conf lines. Repeat as a personal account. Fake HIBP refuses a leaked password; HIBP down shows "try again".
- **Closes:** SmtpMailer and the outbox loop in the binary; personal-account key path; Secure, HttpOnly, SameSite cookies over real redirects; CSP.
- **Fixtures:** SMTP, HIBP, NPM, PYPI, TLS.

#### E2E-018 Invite to install (new hire)
- **Steps:** Org admin invites bob@ by email. Bob has no login: he opens the link signed out (F17), signs up, confirms, signs in, accepts. His key is in Acme. npm install works on both firewalls. A cancelled link and a reused link are refused.
- **Closes:** invitee without a login; link built from `base_url`; key landing in the right place.
- **Fixtures:** SMTP, NPM.

#### E2E-019 Password reset and account takeover defences
- **Steps:** User signed in with TOTP in browser A, with a key. In browser B: forgot password, link from the mail, leaked password refused, good one accepted. A is signed out; B still gets the TOTP step; the key still installs; a reused link gives 410. Takeover check: an attacker signs up `victim@` with their own password and keeps the session; the victim confirms; the attacker's session must not be signed in (F7). The victim reclaims a squatted unconfirmed address by reset.
- **Closes:** session ending on reset; F7; unconfirmed-method reset.
- **Fixtures:** SMTP, HIBP.

#### E2E-020 OAuth and company SSO with an OIDC provider
- **Steps:** Configure a fake OIDC IdP as a provider and as Acme's SSO issuer. In Chromium: `/o/acme`, sign in, become a member, create a key, install. Link and unlink a provider. Negative tokens from the fake: wrong iss and aud, expired, alg none, rotated JWKS, user cancels. Org admin removes the member: SSO does not re-add them; a new invitation does; an approved leave followed by SSO re-adds them (C130). SSO off: password set by reset mail. Nightly: same happy path against dex or Keycloak.
- **Closes:** every IdP path is covered only by FakeNet today; cookie on the cross-site return; C128 and C130 on real images.
- **Fixtures:** OIDC, SMTP, TLS, NPM.

### P1

#### E2E-021 Suspend and re-activate tenants during CI
- **Steps:** An org with a member key, a service key and an automation token runs installs. Operator suspends it: all three get 401 on both firewalls, members see the banner. Re-activate: recovery, including keys first seen while suspended. Same for a personal account, plus revoke-all, TOTP reset, delete and restore.
- **Closes:** suspension of automation and service keys; revoke-all propagation.
- **Fixtures:** NPM.

#### E2E-022 Organisation delete, restore and the purge job
- **Steps:** Delete an org with the typed name: 401 on both firewalls. Second admin restores: 200 again. Back-date rows by SQL past 30 days, restart the server (first tick runs at start): org, keys and login rows are erased, the address frees, approved ranges lift. Run two server replicas at once.
- **Closes:** purge job in the running binary.
- **Fixtures:** CLOCK, NPM.

#### E2E-023 Cold-cache CI fan-out and lookup budget
- **Steps:** Cold firewall, default limits. 50 parallel `npm ci` and `pip install` jobs, each with a new key, from one address. All must finish; none sees 401. Then a 1000-package lockfile with `max_artifact_downloads = 8`. Health probes keep answering. Repeat right after `admin after-restore`.
- **Closes:** real clients retrying LOOKUP_BUSY and 503; health under load.
- **Fixtures:** NPM, PYPI (large synthetic tree).

#### E2E-024 Firewall stop, crash and disk full
- **Steps:** `docker stop` during a large download and a SIEM backlog: drain and summary. Check activity since the last sync (F2). `kill -9` mid-download, restart: WAL recovery, `tmp/` empty. Fill the volume: ready 503, no policy relaxation, snapshot write fails safely. Free space: recovery within 30 s.
- **Closes:** F2; snapshot and overlay writes on a full disk; container crash recovery.
- **Fixtures:** NPM, NET.

#### E2E-025 Retire and replace a firewall
- **Steps:** Retire firewall-2: keys 401, ready 503. Restart its container: it must stay refusing (F5). Register a new firewall, swap the token file, restart: it serves.
- **Closes:** F5; token rotation path.
- **Fixtures:** NPM.

#### E2E-026 Rate and key limits on real installs
- **Steps:** Org rate 30/min; npm install of more than 30 packages; check npm's behaviour on 429 and Retry-After; another org unaffected. Change the default: cached keys follow it. Lower `max_keys` below the count: new keys refused, old keys work. Personal 5-key limit; org override enforced at creation.
- **Closes:** client behaviour on 429; default change propagation; limit enforcement at creation.
- **Fixtures:** NPM.

#### E2E-027 Large artifacts and slow networks
- **Steps:** The fake serves a 500 MB artifact through a throttled link. Check the 30 s idle and 15 min total limits, `max_artifact_bytes`, and that the client does not time out while the firewall verifies before the first byte.
- **Fixtures:** NPM, PYPI, NET.

#### E2E-028 Configured upstream mirror
- **Steps:** Point `npm_upstream_url`, `pypi_upstream_url` and `pypi_artifacts_url` at a fake mirror on another hostname. Install. A mirror whose file URLs sit on a third host is refused with a clear log line. A pushed bad origin is rolled back.
- **Closes:** PyPI origin settings never used end to end.
- **Fixtures:** NPM, PYPI.

#### E2E-029 Cross-tenant isolation through the deployed portal
- **Steps:** Acme admin swaps Globex ids into every id route: same 404 as an unknown id. Globex blocks never affect Acme installs. One login with a personal account and two orgs creates a key in each place; each key follows its own place's policy. Admin actions appear in `/audit` with actor and flag.
- **Fixtures:** NPM.

#### E2E-030 Global admin rotation
- **Steps:** Admin A invites B by email; B accepts and turns on TOTP; B removes A. A's open session loses `/admin` on the next click; A's platform token gets 401; A's open invitation links stop working. B cannot remove itself as the last admin.
- **Fixtures:** SMTP.

#### E2E-031 Live public registries canary
- **Steps:** Nightly, non-blocking. Through the deployed stack with real egress: `npm install` of a scoped transitive tree (`express`, `@babel/core`) with audit on; large packuments (`typescript`, `@types/node`); `pip install requests numpy` and one sdist-only project; real api.osv.dev; real 304 revalidation.
- **Closes:** real document shapes and sizes; real CDN validators; files.pythonhosted.org.
- **Fixtures:** LIVE.

#### E2E-032 Release pipeline integrity
- **Steps:** Tag with a version already on crates.io, or different from Cargo.toml: no GitHub release is created. Real-client tests and the coverage gate run in `release.yml`. The `probation-policy` owner and checksum check runs before publish. The e2e gate uses the fakes.
- **Closes:** F15.
- **Fixtures:** none (CI only).

### P2

#### E2E-033 Refusal UX across clients
- **Steps:** For npm 10, 11, 12, yarn 1, pnpm, pip, uv and poetry, trigger HELD, BLOCKED (producer), BLOCKED (OSV), POLICY_UNAVAILABLE, LOOKUP_BUSY, 401 and 429. Record what each prints and whether it retries; assert the code or reason is visible where the client allows it.
- **Fixtures:** NPM, PYPI, OSV.

#### E2E-034 Retention, prune jobs and fleet health on a long-running server
- **Steps:** Back-date activity, audit and change_log rows; set retention 7/30; after the job, old rows are gone and new ones kept. A firewall offline past the retention resets on return. Stop firewall-2: after three intervals `/fleet` shows missed check-ins.
- **Fixtures:** CLOCK, NPM.

#### E2E-035 Clock drift across the stack
- **Steps:** Firewall containers run a few minutes ahead and behind (libfaketime). Check cooldown and `eligible_at`, activity times, TOTP sign-in, fleet health. Step the Postgres clock back before `after-restore`.
- **Fixtures:** CLOCK.

#### E2E-036 Operator bootstrap and recovery negatives
- **Steps:** Second bootstrap refused. Someone signs up with the operator's address before bootstrap (EmailTaken). Bad email; missing source. Expired link, then `reset-link`; `reset-link` for a non-admin refused; audit row written.
- **Fixtures:** none.

#### E2E-037 Sign-in throttles at scale with production Argon2
- **Steps:** 50 parallel sign-ins and sign-ups from distinct addresses through the proxy, plus a credential-stuffing burst from one address. Measure p99, Argon2 queueing and pool use. Lockout lifts after 15 minutes.
- **Fixtures:** TLS, CLOCK.

#### E2E-038 Unicode and casing in a real browser
- **Steps:** Sign up with `' Ana@Example.ORG '`, sign in as `ana@example.org`. IDN address. Password with combining characters typed as NFC and NFD. Org name with emoji and repeated spaces, found through `/o/<name>`. HTML in org, group and key names on every page.
- **Fixtures:** SMTP.

#### E2E-039 Large blocklist migration through the portal
- **Steps:** Paste a standalone `blocklist.json` with thousands of records (unicode reasons, sha256 and sha512) into the org import, export it, re-import: nothing changes, including fingerprint and reasons. Blocked packages fail to install.
- **Fixtures:** NPM, PYPI.

---

## 4. Test infrastructure

### 4.1 Fixtures

**One fake-upstream service** (a small Node server; Node is already used by `drive.mjs`) plays npm, PyPI, OSV, HIBP and the GitHub API:

- Serves real, installable tiny packages: npm tarballs and wheels and sdists built at start from templates, so npm, pnpm, yarn, bun, pip, uv and poetry can really install them. Reuse the shapes in `tests/fixtures/npm/` and `tests/fixtures/pypi/`.
- Publish times are **relative to start** ("1 hour ago", "400 days ago"), so freezes are deterministic without clock control.
- A control endpoint per scenario: flag a version in OSV, add a version, make a host hang, answer 5xx or 429, stall the body, throttle, serve wrong bytes, drop validators.
- The OSV fake rejects a query whose ecosystem is not exactly `npm` or `PyPI`.
- It records every request, so tests can assert what the firewall asked for.

**The origin guard problem.** The production image refuses upstreams on private, loopback and special-purpose addresses (`src/upstream/resolver.rs::is_public`), and the OSV URL is fixed. A fake on a normal docker network is refused. Without changing the binary, put the fakes on an `internal: true` docker network whose subnet is ordinary public unicast (not RFC 1918, not 100.64/10, not 198.18/15, not documentation ranges). Then give them the real hostnames as network aliases, and issue their certificates from the e2e CA that the compose file already puts in `SSL_CERT_DIR`. The image under test is then byte-for-byte the shipped image. See D1.

**Other fixtures:**

| Fixture | Choice |
|---|---|
| SMTP | mailpit; tests read mail through its HTTP API, never from SQL |
| OIDC | The fake service serves discovery, JWKS and tokens, including bad tokens for negative cases. Nightly also runs dex (lighter than Keycloak) for one real-IdP happy path |
| TLS proxy | nginx with config variants: plain XFF, XFF with port, bracketed IPv6, no XFF, `Forwarded` only, 1 MB body limit |
| Browser | Playwright Chromium. It is already a dependency of `crates/probation-server/tests/a11y` |
| Clients | One "clients" image with pinned versions: npm 10, 11, 12; pnpm; yarn 1 and berry; bun; pip current and previous; uv; poetry. The e2e CA is trusted. |
| Clock | Avoided where possible: relative publish times, short configured TTLs and intervals, SQL back-dating plus a restart for 30-day jobs. libfaketime only for E2E-035. TOTP codes are computed from the secret. |
| DB restore | `pg_dump`/`pg_restore` inside the Postgres container, run by a script that follows `docs/operations.md` §13 exactly |
| Network faults | `docker network disconnect`, `docker pause`, and the fake's hang and throttle modes. No `tc` (needs NET_ADMIN) unless the fake cannot do it |
| Supervisor | compose `restart: unless-stopped` on PRs and nightly; a systemd container only nightly |
| Previous release | Build images from the previous tag once and cache them (see D7) |

### 4.2 Keeping tests deterministic and offline

- No live network in the PR and nightly suites. Only E2E-031 uses real registries, and it does not block.
- Pinned versions of every client and every image.
- Wait for conditions with a deadline (for example "until 401, at most 2 intervals"), never fixed sleeps. Use a short `sync_interval_seconds` (2 to 5 s).
- One stack per suite run; each scenario makes its own org, keys and package names, so scenarios can share a stack and run in any order.
- Scenarios that break the stack (outages, restore, upgrade, disk full) get their own stack.
- On failure, dump the logs of every container, the fake's request log and the mail catcher's inbox. Keep the Playwright trace.
- No automatic retries. A flaky test is a bug to fix by reading the code, as the project rules say.
- Disk: build caches and volumes go on disk next to the project, never under `/tmp` (tmpfs on dev machines).

### 4.3 Run time estimate

| Item | Estimate |
|---|---|
| Image build, cold | 10 to 15 min (cached: 2 to 4 min) |
| Stack start | 1 to 2 min |
| A shared-stack scenario | 1 to 4 min |
| A scenario with its own stack | 3 to 8 min |
| PR suite (below) | about 15 to 20 min wall time |
| Nightly, all P0 and P1, 3 stacks in parallel | about 60 to 90 min |
| Release extra (upgrade from previous tag, live canary) | about 20 to 30 min more |

### 4.4 Suite split

| Suite | When | Scenarios | Blocks |
|---|---|---|---|
| **PR** (fast) | every PR | E2E-001, 002, 003, 004, 011, 013, 017 on one stack, plus today's in-process real-client tests (`e2e_npm`, `e2e_pip`) | merge |
| **Nightly** (full) | every night on `main` | all P0 and P1 except 031 and 032; P2 weekly | opens an issue |
| **Canary** | nightly | E2E-031 (live registries) | alerts only |
| **Release** | on tag | the nightly set must be green for the tagged commit; plus E2E-010 from the previous tag and E2E-032 | release |

Code layout: keep `tests/e2e/`. One file per scenario (`node:test`), shared helpers taken out of `drive.mjs`, one base compose file plus overlays (`standalone`, `lb`, `idp`, `prev`). Tag each file with its suite and priority so CI can select.

---

## 5. Open decisions

| # | Decision | Options | Recommendation |
|---|---|---|---|
| D1 | Real public registries or local fakes? | (a) real npm, PyPI, OSV, HIBP; (b) fakes on a public-range internal docker network with real hostnames; (c) a test-only build switch that relaxes the origin guard | **(b)** for PR, nightly and release, so the shipped image is the one tested and runs are offline and repeatable. Keep (a) only as the nightly canary E2E-031. Avoid (c): it tests a different binary. First check that the chosen subnet passes `is_public` and does not shadow any host the stack needs. |
| D2 | Which clients? | Everything in the docs, or a smaller set | PR: current npm and current pip. Nightly: npm 10, 11, 12, pnpm, yarn 1, yarn berry, pip previous, uv, poetry, bun. Drop corepack and pipx from `docs/operations.md` §7 unless you want to test them. |
| D3 | Browser automation tool | Playwright, Puppeteer, Node fetch | **Playwright Chromium.** Already a dependency (a11y), handles cookies, CSP and cross-site redirects. Keep fetch for API-only steps. |
| D4 | CI time budget | | PR suite at most 20 min; nightly at most 90 min; release at most 2 h. |
| D5 | Where the suite runs | GitHub-hosted runners, self-hosted runners | GitHub-hosted runners (docker compose) for PR, nightly and release. Self-hosted only if E2E-023 and E2E-027 need more CPU, disk or bandwidth than hosted runners give. |
| D6 | Does the e2e gate block a release when a live service is down? | | No. The release gate uses fakes (D1); the live canary alerts. |
| D7 | Publish the images? | Publish to a registry, or build from the tag each time | Publish both images on release (no workflow does today). The upgrade test (E2E-010) then pulls the previous release instead of building it. |
| D8 | Real IdP in CI? | fake only, dex, Keycloak | Fake for every negative case; dex nightly for one happy path. Keycloak only if a customer uses it. |
| D9 | Intended behaviour for the suspect defects F1 to F17 | Write the test to the current behaviour, or to the correct behaviour | Write each test to the **correct** behaviour and let it fail until the product is fixed. Rule on each: F1 accept `ip:port` and brackets; F2 last changes call on every SIGTERM; F3 tolerate unknown variants or report version skew loudly; F4 not ready for keys until the first sync, or accept the window and document it; F5 persist "retired"; F6 version the snapshot; F7 end other sessions on confirm; F8 graceful shutdown; F9 add `/health/ready` to the server; F10 tie artifact origin to ecosystem; F11 answer 503; F12 do not keep links in clear text, or document it; F13 fix the docs; F14 honour q=0; F15 check before creating the release; F16 document it, or keep registrations through `after-restore`; F17 keep the invitation link through sign-in and sign-up. |
| D10 | Run the 30-day and 15-minute timers for real? | Wait, libfaketime, or SQL back-dating | SQL back-dating plus a restart for 30-day jobs; the 15-minute throttle lift only in the weekly P2 run (real wait or libfaketime). |
| D11 | Keep the axe accessibility walk manual? | | Move it into the nightly suite; it already uses Playwright. |
