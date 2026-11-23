# Security review (re-check r3)
Verdict: FIX FIRST
Subject and scope: slice 30 code at HEAD ff1c232 (working tree changes are docs only). Bounded recheck of the r2 round-2 fixes: SEC-1, SEC-2, SEC-5, NEW-1, NEW-2, drop guard, body cap versus batch cap, fleet-health OSV text. Static read only; nothing was run, and the test results in evidence/slice-30.md and evidence/tdd-slice-30.md were taken as supplied.
Fingerprints (sha256 prefix): osv.rs 051f95df, sync.rs 14875447, osv_key.rs 1d819f01, fleet.rs b1dc9d48. Unchanged during review: yes (rechecked at the end).
Summary: open: NEW-1 (partly closed; the exemption reopens the gate flood for any once-valid credential, and a block is sticky and shared), SEC-2 (residual: stampede and permit starvation), SEC-5 (residual: 4 places). Closed: NEW-2, SEC-1 (npm), drop guard, body-cap contract, fleet-health text. Unknown: SEC-1 PyPI. None of the open items is above Low/Medium and all are availability or fail-open degradation only.

## Status per prior finding
| ID | Status | One line |
|---|---|---|
| SEC-1 | closed for npm; PyPI residual unknown (Low) | counted and visible, allowed |
| SEC-2 | partly closed; residual Low/Medium | slow-chunk victim is fixed; follower stampede and permit starvation remain |
| SEC-5 | partly closed; residual Low | one place capped at 25%; 4 places still take everything |
| NEW-1 | open, Low/Medium (confirmed in source) | the "authenticated before" memory is never invalidated and the check is not per source |
| NEW-2 | closed (hardening note) | body read has no permit and a 2 s limit |
| Drop guard | closed | `InflightGuard`, osv.rs:~860 |
| Body cap vs batch cap | closed | 413 for the whole envelope |
| Fleet-health OSV text | closed | literals plus u64 only, and askama autoescape |

## Findings

### NEW-1 (re-check) open, Low/Medium, confirmed in source: the "authenticated before" memory reopens the gate flood
Location: osv.rs:~373-395 (`bearer_tag`, `known`, block check), osv.rs:~397-413 (`known_good.put` on success only), osv.rs:~418 (`admit_request` runs after the lookup).
How it is remembered: `bearer_tag` is the first 8 bytes of SHA-256 of the whole bearer string. The tag is computed on the server from what the client sends, so an attacker cannot "present a hash". To spoof the exemption the attacker needs a bearer string whose 64-bit tag is in the table. With a 10,000-entry LRU that is about 2^50 SHA-256 evaluations for a targeted preimage. This is expensive but not out of reach for a funded attacker, and a success only buys the bypass below. Nobody can obtain a victim's tag from outside (it is never sent or returned). I count the collision route as impractical for this threat model.
The real hole:
1. `known_good` is global, not per source, and an entry is only ever added (`put` on success) or LRU-evicted. A failed authentication does not remove it. A revoked, deleted, or retired credential keeps its tag until 10,000 other credentials displace it.
2. For a known tag the blocked-source check is skipped and the request goes through the 4-permit auth gate and a database lookup. Revoked credential: the lookup returns 401 and calls `preauth_failed`, but the cost is already paid. The holder of any once-valid credential (a departed employee, a retired firewall) can send as many requests as the connection layer lets through. They are not cheaply rejected, and every other caller sees 429 after the 1 s gate wait. This is exactly the NEW-1 flood.
3. A still-valid credential gets the same effect, because `admit_request` (100/s) is charged after the lookup (osv.rs:~418). Any tenant with one service key can occupy the gate with valid lookups. The per-credential limit only caps the answered requests, not the lookups.
4. The block is sticky and shared. A blocked source's cheap rejection also calls `preauth_failed` (osv.rs:~385), which pushes onto the window it is rejecting from. A legitimate client that retries every few seconds therefore never leaves the block (it needs 60 s of silence). A client whose credential has not authenticated since the process started (a new firewall, or any firewall after a restart, since `known_good` is memory only) is locked out for the duration. If the server sits behind a proxy and `trusted_proxies` is missing or wrong, every client shares the proxy's source address, so one attacker's 10 bad tokens a minute block every first-time credential in the fleet.
5. Memory: the window per source grows by one `Instant` per request, including blocked ones. It is pruned only past 60 s, so a flood at R requests per second holds about 60 x R entries per source (3M entries, about 48 MB, at 50k/s). Bounded, but it is an amplification of attacker rate into server memory.
Smallest correction: (a) on `Unauthenticated` or `SourceRefused`, `known_good.pop(&tag)` so a revoked credential stops being exempt on its first failure; (b) charge a cheap pre-lookup limit keyed by tag (or by source) before the gate, so a valid credential cannot hold the gate; (c) do not extend the window from blocked requests (or cap its length at 2 x the limit), so a block ends 60 s after the last real failure; (d) bound the window length.
Closure checks: a revoked credential sent 1000 times: after the first 401 the rest are rejected without a lookup (the gate stays free for another credential); one valid credential at 1000 requests per second does not push another credential to 429; a blocked source whose client retries once every 5 s for 2 minutes recovers once it presents a good credential.

### SEC-2 (re-check) residual, Low/Medium, confirmed in source: the follower self-call can stampede, and permits can still be starved
Location: osv.rs:~558-600 (`settle`: `half`, self-call, `charge`), osv.rs:~705 (`call_upstream` permit).
Charge and attribution: the self-call is charged to the follower's own credential (own bucket, tenant share, global) at the moment it fires (`self.charge(caller, self.now())`, not when it joins the leader). So it cannot make an attacker's work free: each self-call spends one key of the follower's budget, and the global 12,000 per minute caps the total. If the budget is refused, the follower waits to the deadline and degrades. That bounds amplification to the same budget as ordinary misses, but not to one upstream call per key.
Stampede: `inflight` is bypassed, so for a hot key behind a leader that has not answered in 750 ms, every concurrent follower (one per request, up to N) sends its own single-key call. Upstream slowness above 750 ms is exactly when this multiplies load, and the shared 429 breaker (30 to 60 s of degradation for everyone) is the failure it can trigger. The healthy case (control test) still gives one call.
Permit starvation: all calls (leaders and self-calls) share 8 permits (`upstream_concurrency`). A chunk holds a permit for all its keys and pages in sequence (up to 10 s). Slow chunks from 8 concurrent leaders (for example 3 or 4 credentials, each with a chunk of multi-page packages, if the upstream is slow for them) hold all 8 permits. A victim's self-call then waits for a permit until its own deadline and degrades. The fix removed the dependency on one chunk, not on the permit pool.
Sequential self-calls: `settle` fires the fallback key by key inside one request. After the first one, `half` is already past, so a request of 200 followers burns 200 `charge`s and runs the calls one at a time. Those after the deadline are dropped by `timeout_at` having been paid for. That is self-harm to the credential, not an attack on others.
Smallest correction: one rescue slot per key (a second small in-flight table, so a single follower per key fires the self-call and the others wait on it), and a reserved permit or two for self-calls. Closure check: 50 concurrent followers behind one 5 s leader give at most 2 upstream calls for that key.

### SEC-5 (re-check) residual, Low, confirmed mechanism, reachability not verified: 25% share and 20% reserve can still be gamed with 4 places
Location: osv.rs:~478-520 (`charge`), sync.rs:199-209 (`tenant` is `(place_kind code, place id)`).
What holds: one place cannot take more than 25% of the burst (750) or of the refill (50 per second), and its credentials still have their own 600 per minute. The reserve (600 of 3,000) is only available to a place whose own bucket is at least 90% full after the take.
What does not: (1) the global refill is 200 per second, so 4 places each running at 50 per second (5 credentials each) take it all. The "light user" test is true for any place that consumes at or below its share rate, because its own bucket stays near full. The reserve therefore does not protect a victim from steady users, only from a burst. (2) A new place starts with a full bucket, so the first 75 tokens of each fresh place are "light" and draw on the reserve; 8 fresh places empty a 600-token reserve. (3) Tenants are places: org, group, user, personal. Several groups or users under one organisation count as separate tenants, so one organisation creating 4 groups with service keys gets the whole budget. Whether places and service keys can be created cheaply is not verified here (sign-up is e-mail confirmed and mail-capped, accounts.rs:419). Victims whose requests find the global bucket empty degrade fail-open (never a block).
Smallest correction: key the share on the organisation, or the root of the place tree, not the place; give every authenticated place a small guaranteed floor that is not shared (a per-tenant reserved slice); alert when the global bucket sits near zero.
Closure check: 4 places each sending at their share cannot reduce a fifth tenant's accepted rate below its floor.

### SEC-1 (re-check) closed for npm; PyPI over 1024 bytes: residual risk stated precisely
Behaviour (osv_key.rs:11-55, osv.rs:`answer`): a PyPI name or version over 1024 bytes makes `osv_key` fail; the client never sends it and counts `osv_keys_refused`; the server (same function) turns an arriving one into `Slot::Degraded`. The decision is therefore "no OSV verdict, degraded, allowed" (fail-open per C3 and C14). It is visible in `keys_refused`, in the readiness detail, and now in the fleet health text. It is not blocked and not alerted per package.
Residual risk, exactly: it needs three conditions together: PyPI accepts a project name or version over 1024 bytes (unverified: the PyPI limits were not confirmed; the normalized-name check here allows only `a-z0-9-` and the version allows printable ASCII); the package's only malware signal is an OSV `MAL-` entry; and no other control (age or cooldown, allow-list, scanner) stops it. If these hold, a publisher can pick a key that skips OSV for the firewall's new-install decision. Impact: loss of one control for that package, not a bypass of the other controls. Severity Low, state unknown. To close: confirm PyPI's limits (PEP 508 and the Warehouse upload validation), or allow a policy hold of a refused key (the evidence records this as a decision for the spec author). The osv_key.rs comment ("PyPI has no practical cap") is an unverified claim.

### NEW-2 closed (hardening note)
Location: osv.rs:~419-436.
The body is read after authentication and after `admit_request`, with `tokio::time::timeout(2 s, to_bytes(body, cap))` and no permit; the parse permit covers only `parse_request` and is `try_acquire` (429 if full). A dripping body therefore holds one socket for at most 2 s and takes no one else's turn. Unauthenticated callers cannot reach the body read at all. Bound on concurrent held sockets: there is no OSV-specific or server-wide connection cap (`axum::serve` at lib.rs:167 with no timeout or concurrency layer; grep found none). The realistic bound is 100 requests per second per credential (burst 500) times 2 s, so about 200 to 700 sockets per credential, multiplied by the number of credentials. That is a socket, not a processing, resource; the file-descriptor limit and hyper's own header read timeout (pre-existing, same for `/sync`) were not examined. Hardening: a request-per-source cap before the body read, or a proxy limit. Smaller notes: a client read error and an over-cap body are both mapped to 413 (osv.rs:~430); a slow legitimate client on a 0.55 MB batch needs about 275 KB/s to meet 2 s.

### Drop guard closed
`InflightGuard` (osv.rs:~860-872) is created at the top of `fetch` and removes every key of the chunk from `inflight` on any exit, including a panic and a cancelled task (`unwrap`-free: `if let Ok` on the lock, so a poisoned mutex does not panic inside Drop). Residual: with a poisoned `inflight` mutex the guard does nothing, and every `expect("the in-flight table")` panics; that needs a prior panic while holding it. The evidence says the guard has no test (no panic seam); static inspection only.

### Body cap versus 1000-key cap: closed (contract confirmed)
`to_bytes(body, 1 MiB)` runs before `parse_request`, and `parsed.len() > batch_max` (1000) is checked after the parse, both returning 413 for the whole envelope, with no upstream call (osv.rs:~419-445). A maximum client batch (256 keys at 1024 + 1024 bytes) is about 0.55 MB and fits. 1000 maximum-size keys (about 2.1 MB) get 413 for the whole request. So the byte cap binds first for large keys, and a client that sends more than about 480 maximum-size keys loses the whole batch (degraded for all on the client side). No security effect; the spec text should say the byte cap is binding (as the evidence notes).

### Fleet-health OSV text closed
fleet.rs:550-566 (`healthy_text`) builds the string only from fixed literals and one `u64` (`keys_refused`), and `OsvReport` is a typed struct (one bool and eight `u64`, api.rs:322-334) re-serialised by `record_report`, so no firewall-supplied string reaches the text. The template prints `{{ firewall.health }}` through askama (templates/fleet.html:29), which escapes `.html` templates by default (the escape mode was not changed; grep found no `escape =` override). A firewall can only lie about its own counters to its own tenant's view. One minor point: a lying firewall can show "Healthy; OSV warning" noise; no injection path.

## Security properties
| Property | Boundary/owning code | Status | Evidence | Limit or finding |
|---|---|---|---|---|
| Auth gate not floodable | osv.rs:~373-413 | open | exemption never revoked; request bucket after lookup; sticky block | NEW-1 |
| Body read bound | osv.rs:~419-436 | closed | no permit, 2 s | no connection cap anywhere (not examined further) |
| Parse concurrency | osv.rs:~437 | closed | try_acquire around parse only | |
| Fair share of the shared budget | osv.rs `charge` | open (Low) | 25% per place, reserve for light places | SEC-5: 4 places, fresh places |
| Follower fallback charged and bounded | osv.rs `settle` | closed for amplification beyond the budget | charged to credential, tenant, global | stampede and permits: SEC-2 residual |
| In-flight cleanup on failure | `InflightGuard` | closed (untested) | Drop impl | poisoned mutex |
| Key function / PyPI length | osv_key.rs | closed npm, unknown PyPI | | SEC-1 |
| Envelope caps | osv.rs:~419-445 | closed | 413 whole envelope | |
| Report text to portal HTML | fleet.rs:550, fleet.html:29 | closed | literals + u64, autoescape | |

## Verification and limits
No command run; no live or database calls. Read: crates/probation-server/src/osv.rs (all 903 lines of the relevant parts), sync.rs (`osv_caller`, `firewall_identity`, Tenant), fleet.rs `healthy_text`, osv_key.rs, api.rs `OsvReport`, accounts.rs sign-up, fleet.html line 29, evidence/slice-30.md and tdd-slice-30.md (round 2). The tests named in the evidence were not re-run. The mutation reds are as supplied.
Not examined: PyPI and npm real limits, whether org or group admins can create places and service keys cheaply, hyper/axum default header-read and connection limits, `trusted_proxies` deployment, OS file-descriptor limits, dependency advisories.
New surfaces absent from the earlier threat model: the in-memory `known_good` set and the self-call fallback.

## Next steps
1. NEW-1: pop the tag on failure; add a pre-lookup per-tag or per-source rate limit; stop blocked requests from extending the window and cap its length.
2. SEC-2: one rescue slot per key and a reserved permit for self-calls.
3. SEC-5: share per organisation (or root place) plus a per-tenant floor; alert on an empty global bucket.
4. SEC-1 PyPI: confirm the limits or decide the hold; add a test for the drop guard if a panic seam is acceptable.
5. Recheck with the closure checks above.
