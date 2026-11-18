# Security review (re-check r4)
Verdict: FIX FIRST (two small items, both availability or fail-open degradation only; everything else closed or accepted Low)
Subject and scope: slice 30 at HEAD 97f3200 (tree clean). Bounded recheck of the round-3 fixes: failed-tag memory, per-tag lookup limit, blocked-source window cap, rescue slot and permits, per-organisation tenant collapse with per-tenant floor, poisoned-mutex guard, SEC-1 comment. Read directly: crates/probation-server/src/osv.rs (all), sync.rs (OsvCaller, osv_caller, firewall_identity, source_of, source_address), service_policy.rs live_service_key_id, accounts.rs (sign_up, add_org), keys.rs at_limit, migrations/0001_init.sql limits, evidence/slice-30.md and tdd-slice-30.md (round 3).
Fingerprints (sha256 prefix): osv.rs 6b0f1221, sync.rs b37799cc. Unchanged during review: yes. Nothing was run (static read only); the tests named in the evidence were taken as supplied.

Summary: open: R4-1 (SourceRefused poisons the shared failed-tag and known_good memory), R4-2 (the tenant floor is outside the global budget, and organisations are unbounded per login, so tenant identity is attacker-mintable). Accepted Low residuals: R4-3 (IPv6 source granularity), R4-4 (valid credentials can still use the gate), R4-5 (rescue permits can be held), R4-6 (rescue entry has no drop guard). Closed: NEW-1 (as designed, see below), SEC-2 stampede, drop guard, SEC-1 comment.

## Status per prior finding
| ID | Status | One line |
|---|---|---|
| NEW-1 | closed for revoked credentials and bad-token floods; two residuals R4-1, R4-3 | pop on failure, 10 s failed tag, per-tag limit, window cap |
| SEC-2 | closed (stampede gone); residual R4-5 Low accepted | one rescue per key, 2 reserved permits |
| SEC-5 | closed for collapse to organisation; open R4-2 (Low/Medium) | floor and org minting |
| Drop guard | closed | real poisoned-table test now exists (osv.rs tests module) |
| SEC-1 comment | closed | wording only; PyPI limit research is a decision item, not code |

## Findings

### R4-1 open, Low, confirmed in source: a SourceRefused failure poisons the credential for its legitimate source
Location: osv.rs `querybatch`, the `Err(SyncError::Unauthenticated | SyncError::SourceRefused)` arm (known_good.pop, failed_tags.put); sync.rs `firewall_identity` (SourceRefused returned after the token is found valid).
Path: attacker holds a firewall token (leaked or stolen) but is outside its `allowed_source_cidrs` -> sends one request every 10 s -> `firewall_identity` returns SourceRefused -> the tag (hash of the bearer only, no source) is put in `failed_tags` and removed from `known_good` -> the real firewall, from its allowed address, is answered 401 without a lookup for up to 10 s, and again after each refresh. The legitimate firewall has no OSV verdicts for as long as the attacker keeps sending (fail-open: allowed with a degraded warning, so availability and protection loss of one control, not a block).
Why it matters: the source CIDR binding is the control that makes a stolen firewall token useless. Here it becomes a lever for locking the owner out of OSV. `/sync` is unaffected (own path). It also feeds `preauth_failed` for the legitimate source on every 401-without-lookup, so a retrying real firewall can reach the 10-failure block.
Not abusable without the exact bearer: the tag is computed server-side from what the caller sends, so someone without the credential cannot poison a victim's tag; and a service key has no source binding, so only fwt_ tokens are affected. The dripping of a stranger's request into a victim's tag needs a 2^64 preimage match (impractical, same as r3).
Smallest correction: record `failed_tags` and pop `known_good` only for `Unauthenticated`, not `SourceRefused` (SourceRefused still counts `preauth_failed`). Or key both by (tag, source).
Closure checks: a valid firewall token refused from a foreign address 50 times does not make a request from the allowed address return 401; a revoked token still costs one lookup then 401s without lookup for 10 s (existing test).

### R4-2 open, Low/Medium (conditional), confirmed in source: the per-tenant floor is outside the global budget and tenants are cheap to mint
Location: osv.rs `charge` (the floor branch after the global check; `floors` take does not touch `global`); accounts.rs `add_org` (accounts.rs ~1794, portal route POST /account/org) with no per-login count; keys.rs `at_limit` (50 service keys per org by default, migrations/0001_init.sql limits; personal accounts: service keys not counted by `at_limit`, but all of a personal account is one tenant); sync.rs `osv_caller` tenant mapping.
Collapse works as designed: org, group and user service keys map to `(1, org)` (service_policy.rs `live_service_key_id` resolves group and membership to org_id); firewall token is `(10, firewall id)`; personal and platform are their own codes. So many keys in one organisation share one share (25%) and one floor. Firewall tokens: registered in fleet.rs:71 by the operator path (not re-traced here; the r3 and sync.rs comment say global admin only), so not mintable by a tenant.
What does not hold: (1) one confirmed login can create unlimited organisations (`add_org` has no count or rate limit; each is a new tenant with its own service keys), so the "4 places take everything" gaming of r3 SEC-5 is reproducible with 4 organisations instead of 4 groups; the 25% cap per tenant is a per-identity cap, not per-attacker. (2) The floor (burst 30, 60 per minute per tenant) is paid out of nothing: floor draws do not reduce the global bucket and have no total cap, so N minted tenants add N x 60 keys per minute of upstream load beyond the 12,000 per minute global budget, and each fresh tenant starts with its 30-key floor burst. Backstops: the upstream 429 breaker (30 to 60 s of degradation for everyone), mail-capped sign-up (accounts.rs `mail_allowed`, per address), and fail-open (victims degrade, never blocked).
Impact: availability and fail-open degradation of OSV for other tenants; upstream abuse. Bounded by sign-up cost (one confirmed e-mail address per login, then unlimited orgs per login), so Low if sign-up is closed or invitation-only, Medium on open self-service sign-up.
Smallest correction (pick one, decision for the spec author): (a) make floor draws also take from a shared floor pool (for example 10% of the global rate) so the sum of all floors is capped; (b) cap organisations per login (and per time) in `add_org`; (c) accept and document that tenant fairness protects only against honest tenants. (a) is the one that closes the unbounded-upstream part; (b) closes the identity-minting part.
Closure check: 200 freshly created organisations each sending at its floor do not raise total upstream keys above the global rate; a legitimate fifth tenant still gets its floor.

### R4-3 accepted Low: source throttle is per /128 and per 10,000 LRU entries
Location: osv.rs `preauth_blocked`/`preauth_failed`, sync.rs `source_address` (no prefix aggregation).
A client with an IPv6 /64, or any botnet, uses a fresh source per 10 failures, so the throttle never blocks it, and 10,000 sources evict the table. Bad tokens then reach the 4-permit gate at the rate the network allows: others see 429 after the 1 s wait, 4 DB connections used. Failed-tag memory does not help (random bearers). Effect: OSV degraded (fail-open), pool use capped at 4. Same weakness exists on `/sync`. Optional hardening: aggregate IPv6 to /64 in `source_of`, or a global pre-auth lookup rate.

### R4-4 accepted Low: valid credentials can still use the gate
Per-tag limit is 100/s with burst 500 per credential before the gate; the gate has 4 permits. An authenticated tenant with k service keys (up to 50 per org, more with more orgs) can send k x 100 lookups per second and hold the gate; others get 429 and degrade. Needs a valid account; same minting cost as R4-2. Hardening: per-tenant pre-gate lookup limit (tenant is known only after the lookup, so key it by source plus tag, or cap total lookups per second server-wide).

### R4-5 accepted Low: rescue permits can be held, and the rescue slot is fail-open
Location: osv.rs `rescue_for`, `call_upstream_with(&rescue_permits)`.
Rescue calls use only their own 2 permits (they do not compete with the 8 main permits, and the main permits no longer starve them). An attacker can hold both only by getting two distinct keys into rescue at once for long calls, which needs followers behind slow leaders (the upstream must be slower than 750 ms for those keys; the attacker cannot make it so except by picking keys with many pages, up to 10 sequential pages, 10 s timeout) and each is charged to the attacker's own budget, tenant share and the global budget (`charge` in `rescue_for`). While both are held, other rescues queue until their deadline and degrade: the answer is "no OSV verdict, allowed" (the same fail-open as any upstream trouble, C3/C14), plus the shared leader still completes into the cache, so a retry converges. A queued rescue task keeps waiting on the permit up to 10 s after its follower is gone (wasted work bounded by the budget). Acceptable as fail-open; recommend only a note in the spec. Stampede check: the rescue starter is charged once; every other follower joins it (one upstream call per key), so the r3 stampede is closed.

### R4-6 accepted Low (hardening): the rescue slot has no drop guard
`rescue_for` removes the key from `rescue` only after the call ends. A panic in that task (only the `expect` on a poisoned cache mutex can do it) leaves a dead receiver in the table; later followers of that key get `Failed` immediately until restart (leaders and cache hits are unaffected). `inflight` and `rescue` locks use `PoisonError::into_inner`, but `cache`, `buckets` and the other maps use `expect`, so a poisoned cache already breaks every request. Hardening: reuse `InflightGuard` for `rescue`.

## Answers to the specific questions
- Failed-tag memory (10 s) lockout of a legitimate credential: not from outside (the tag needs the exact bearer string; service keys have a strict 36-character format, and an altered bearer simply fails and is counted against the sender). It IS abusable by whoever holds the bearer but is outside its source CIDR: R4-1. The memory is refreshed only by a real lookup (after expiry), so it does not extend itself; a revoked credential gets one lookup per 10 s.
- Hiding revoked -> re-enabled: a credential that was failing is answered 401 for at most 10 s after re-enabling (then one lookup succeeds, `failed_tags.pop`, `known_good.put`). Revocation is never hidden: every request that is not inside the 10 s window does the full database check; known_good is only a block exemption, not an auth skip. Closed.
- Per-tag lookup limit before the gate: 100/s burst 500 per bearer hash, charged for every tagged request. Closed for one credential and for revoked ones; does not bound many credentials or random bearers (R4-3, R4-4).
- Blocked-source window cap: window never exceeds 2 x limit (20 entries), blocked requests are not recorded; the block ends 60 s after the last recorded failure. Closed. Note: a failing legitimate client that keeps sending a recently failed tag adds entries until the cap, then the block expires 60 s after the last add; documented.
- Rescue slot per key + 2 rescue permits: R4-5. Exhaustion needs slow upstream plus budget; result is the accepted fail-open degrade.
- Tenant collapse and floor: R4-2.
- Poisoned-mutex guard: closed; the test poisons the table for real and checks cleanup; residual R4-6.

## Security properties
| Property | Boundary/owning code | Status | Evidence | Limit or finding |
|---|---|---|---|---|
| Revoked credential cannot flood or hide | osv.rs querybatch | closed | pop + failed tag + per-tag limit | none |
| Failed-tag memory not abusable | osv.rs querybatch | open (Low) | SourceRefused path | R4-1 |
| Auth gate not floodable by unknown sources | osv.rs + sync.rs source_of | closed per IPv4 source; accepted Low | window cap, 10 per minute | R4-3 |
| Auth gate and valid credentials | osv.rs per-tag limit | accepted Low | 100/s per tag | R4-4 |
| Body, parse, envelope | osv.rs | closed (unchanged since r3) | | |
| Follower fallback bounded and shared | osv.rs settle, rescue_for | closed | one rescue per key, charged | R4-5, R4-6 accepted |
| Fair share across tenants | osv.rs charge, sync.rs tenant | open (Low/Medium, conditional) | floor outside global; unlimited orgs | R4-2 |
| In-flight cleanup incl. poisoned mutex | InflightGuard | closed | test present | R4-6 for rescue |
| Key function / PyPI | osv_key.rs | closed npm; PyPI limit unverified, allowed fail-open | decision item | unchanged |

## Verification and limits
No command run; no database or live calls. Not examined: whether firewall registration (fleet.rs:71) is reachable only by operators (comment says so, not re-traced), sign-up availability in the deployed configuration (R4-2 severity depends on it), real PyPI limits, hyper connection limits, dependency advisories, `trusted_proxies` deployment. Non-security note: the evidence says the floor test and share test exist (osv_every_tenant_keeps_a_floor..., osv_share_is_per_organisation...); they were not re-run here.

## Next steps
Before the slice closes: (1) R4-1: stop recording SourceRefused in failed_tags and known_good (one condition). (2) R4-2: decide between a shared floor pool, an organisation-per-login cap, or a recorded acceptance; the plan should state which. Accept R4-3 to R4-6 as Low residual with a note in the evidence (R4-6 is a three-line hardening if wanted). Then a recheck of R4-1 and R4-2 only.
