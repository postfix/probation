# Security review (final narrow recheck r5)
Verdict: CLEAR for slice 30 security, with the accepted residuals R4-3, R4-4, R4-5 and the new Low note R5-1 (pool is contested; fail-open only).
Subject and scope: bounded read-only recheck of R4-1, R4-2, R4-6 at HEAD c4a8b01 (tree clean). Read directly: crates/probation-server/src/osv.rs (querybatch 540-621, charge 443-506, settle 766-826, rescue_for 831-858, RescueGuard 1021-1030, unit test 1063-1080), tests/osv_lookup_api.rs (1181-1261), sync.rs call sites of SourceRefused (grep), evidence/slice-30.md lines 83-87. osv.rs sha256 prefix ee8889da. Unchanged during review: yes. Nothing was built or run (static read); named tests taken as supplied by the evidence.

## Status
| ID | Status | Evidence |
|---|---|---|
| R4-1 | closed | osv.rs:606-613: the pop of known_good and the put into failed_tags happen only when the error is `Unauthenticated` (pattern `(Some(tag), SyncError::Unauthenticated)`). `SourceRefused` only calls `preauth_failed(source)` (the attacker's address) and returns 401. Only producer of SourceRefused is sync.rs:282; only consumer outside the enum/mapping (sync.rs:366, 405) is this arm. No other call site pops or tags. Test osv_out_of_cidr_holder_cannot_lock_out_the_real_firewall (tests:1217) asserts 5 foreign refusals, then the real source gets 200 and does a real lookup. Residual noted: a foreign holder still pays one DB lookup per request up to the 100/s per-tag limit (R4-4 class, accepted). |
| R4-2 | closed (with R5-1) | osv.rs:484-506: a floor draw succeeds only if the tenant floor bucket AND the shared floor pool (floor_pool_percent, default 10, of global burst and global refill, osv.rs:493-497; pool_burst at least 1) both have a token. If the pool is empty the floor token is refunded (501) and the key/tenant tokens are given back (504), so no budget leaks. Floor draws do not reduce `global`, so total upstream keys are at most global rate plus 10% of it, regardless of how many tenants are minted. Real tenant: while the pool has tokens its own floor (30 burst, 60/min) holds, and the global-exhaustion path is the only one that reaches the floor, so there is no double charge. Per-organisation share check (460-471) runs before global and floor and is refunded on failure (give_back(false) before floors; give_back(true) after), consistent. Lock order floors then floor_pool, nowhere reversed; `drop(pool)` before touching `bucket` is correct. Tests: tests:1183 (floor kept, pool set to 200% to isolate) and tests:1232 (30 minted tenants draw at most 12 beyond the budget, at least 5 still get floor). |
| R4-6 | closed | rescue_for 843-856: `RescueGuard` is created first in the spawned task, so on panic or cancel it removes the slot (lock uses into_inner, poison-safe) and the captured `tx` drops, so followers' `rescue_rx.wait_for` returns Err and maps to `Answer::Failed` (settle 802-805). `answer()` 735-744 then retries every non-leader Failed key once (`!led`, deadline not passed): `register` makes it a leader or joins the live in-flight call, and `settle` re-enters `rescue_for` with a now-free slot, so followers ask for themselves. Unit test rescue_guard_frees_the_slot_when_the_task_panics (osv.rs:1065) asserts slot removed and receiver released. |
| R4-3, R4-4, R4-5 | accepted Low, recorded | evidence/slice-30.md:87 lists R4-3 (per /128 and 10,000-entry LRU, now only 401 versus 429), R4-4 (valid credential up to 100/s burst 500, multiplied by keys), R4-5 (2 rescue permits can be held, fail-open degrade). All three are availability or fail-open degradation only, with no data exposure or auth bypass. |

## New finding
R5-1, Low, confirmed in source, osv.rs:497 (the pool take). The shared floor pool is first come, first served. With the global budget at its reserve, tenants beyond roughly 20 active at the full floor rate (pool 1,200/min against 60/min per floor at defaults), or minted tenants that drain the 1,200 burst, can leave a real tenant's floor empty. This is the intended trade (a bound on upstream beats an unconditional floor) and the effect is fail-open (verdict degraded, allowed), so it needs no code change. Optional: say in the spec that the floor is "guaranteed while the pool lasts" (the evidence at line 83 already says so) and that minting organisations remains an operator-level concern (add_org has no per-login cap, not in scope of these three items).

## Security properties
| Property | Status | Note |
|---|---|---|
| Failed-tag memory not abusable by an out-of-CIDR holder | closed | R4-1 |
| Total upstream draw bounded regardless of tenant count | closed | R4-2 |
| Real tenant floor under global exhaustion and share | closed while the pool lasts | R5-1 Low |
| Rescue slot cannot be left dead; followers re-ask | closed | R4-6 |
| Source throttle, valid credential gate use, rescue permits | accepted Low | R4-3, R4-4, R4-5 |

## Verification and limits
No commands run. Not examined (unchanged from r4): deployment wiring of trusted_proxies, sign-up availability (severity of org minting), real PyPI limits, dependency advisories, fleet.rs firewall registration reach. Non-security: none new.

## Next steps
Slice 30 may close security-wise. Keep R4-3, R4-4, R4-5 and R5-1 as accepted Low residuals in the evidence (R5-1 is a one-line addition to the R4-2 note).
