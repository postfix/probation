# TDD — slice 4 (probation-server on Postgres)

Seams: the `probation-server` library interfaces the slice plan names (`Tenancy::authorized_place`, `authorize`, `PolicyStore::{parent_policy, save_edit}`, `keys::{create, revoke}`, `fleet::register`, `sync::record_change`), the `probation-server` binary, the sync API over HTTP, and Postgres privileges as the app role. Postgres from `docker-compose.test.yml` (port 55432), one fresh database per test.

Red evidence: the implementation of each module was written before its test file, so a red against absent code was not observed. Each test's red was instead observed against a named mutant of the current source (applied, the single test run, the source restored), which is the evidence that the test can fail on the behavior it names. Green: the single test file run on the restored source.

## policy_edit.rs

tdd: T-edit-parent-chain — red (mutant: `parent_policy` resolves the whole chain, place included): `panicked at crates/probation-server/tests/policy_edit.rs:60:77` (the parent is no longer `resolve` of the ancestors) — green: `cargo test -p probation-server --test policy_edit` passed (8 passed)
tdd: T-edit-atomic — red (mutant: `insert_audit` swallows its error): `panicked at crates/probation-server/tests/policy_edit.rs:143:5` (the save succeeded) — green: `cargo test -p probation-server --test policy_edit` passed
tdd: T-edit-conflict — red (mutant: compare-and-set on `revision >= expected`): `panicked at crates/probation-server/tests/policy_edit.rs:176:18` (exactly one save must win) — green: `cargo test -p probation-server --test policy_edit` passed
tdd: T-edit-audited-global-admin — red (mutant: `actor_is_global_admin` bound `false`): `panicked at crates/probation-server/tests/policy_edit.rs:206:5` (flagged global admin) — green: `cargo test -p probation-server --test policy_edit` passed
tdd: T-changelog-commit-order — red (mutant: the revision taken from the clock, not the locked counter row): `panicked at crates/probation-server/tests/policy_edit.rs:245:5` (the second writer waits for the first) — green: `cargo test -p probation-server --test policy_edit` passed
tdd: T-audit-append-only — red (mutant: migration without `REVOKE UPDATE, DELETE, TRUNCATE ON audit_log`): `panicked at crates/probation-server/tests/policy_edit.rs:301:65` (`UPDATE audit_log` succeeded as the app role) — green: `cargo test -p probation-server --test policy_edit` passed
tdd: T-audit-coverage-keys-policy — red (mutant: `keys::create` commits before its audit row): `assertion left == right failed; left: [("key.revoke", …), ("layer.edit", …), ("firewall.register", …)]` (no `key.create` row) — green: `cargo test -p probation-server --test policy_edit` passed
tdd: T-revoke-atomic — red (mutant: `revoke` commits `revoked_at` and `change_log(key)` before the audit insert): `panicked at crates/probation-server/tests/policy_edit.rs:402:5` (the key stays live) — green: `cargo test -p probation-server --test policy_edit` passed

## tenancy.rs

tdd: T-authz-matrix — red (mutant: a group admin is admin of every group of the organisation): `panicked at crates/probation-server/tests/tenancy.rs:86:13: login 3 on PlaceRef { kind: Group, id: 2 }; left: Edit right: Read`; second mutant (suspension ignored, C78): `tenancy.rs:92:9: suspended Acme, login 2; left: Edit right: Read`. A first mutant (`GroupAdmin` may edit user layers) survived: no group admin holds a role on another member's user place, so it was equivalent — green: `cargo test -p probation-server --test tenancy` passed (3 passed)
tdd: T-tenant-isolation — red (first run, test fault: one actor reused across places answered `Denied` instead of `NotFound`; fixed in the test) `panicked at crates/probation-server/tests/tenancy.rs:143:9`; red (mutant: SSO scope ignored): `panicked at crates/probation-server/tests/tenancy.rs:168:5: left: None right: Some(NotFound)` — green: `cargo test -p probation-server --test tenancy` passed
tdd: T-grant-bootstrap — red (mutant: refusal only once two global admins exist): `panicked at crates/probation-server/tests/tenancy.rs:216:5: probation-server: bootstrap: … duplicate key value violates unique constraint "orgs_name"` (the second run is not refused as a bootstrap) — green: `cargo test -p probation-server --test tenancy` passed

## sync_api.rs (lookup and layers; the `changes` parts follow api.rs)

tdd: T-sync-api-contract (lookup and layers through the firewall's own `SyncClient`) — red (mutant: the answer's revision read one below the snapshot's): `panicked at crates/probation-server/tests/sync_api.rs:72:5: left: Known { …, revision: 2 } right: Known { …, revision: 3 }` — green: `cargo test -p probation-server --test sync_api` passed (4 passed so far)
tdd: T-firewall-token-required (lookup and layers) — red (mutant: retired firewalls not excluded): `panicked at crates/probation-server/tests/sync_api.rs:143:13: api/v1/sync/lookup with Some("fwt_…"); left: 200 right: 401` — green: `cargo test -p probation-server --test sync_api` passed
tdd: T-credential-kind — red (mutant: lookup without the key-kind filter): `panicked at crates/probation-server/tests/sync_api.rs:183:9: assertion failed: matches!(sync.lookup(KeyHash::of(token)).await.unwrap(), KeyLookup::Unknown` — green: `cargo test -p probation-server --test sync_api` passed
tdd: T-firewall-token-source — red (mutant: `X-Forwarded-For` believed from any peer): `panicked at crates/probation-server/tests/sync_api.rs:225:9: [("x-forwarded-for", "192.0.2.7")]: 200 OK`; second mutant (rate 201 a second): `sync_api.rs:267:5: left: 200 right: 429` — green: `cargo test -p probation-server --test sync_api` passed

## propagation.rs (written before slice 3's sync loop; green after the slice-3 merge)

After the merge, `ManagementConfig` gained `token_file`; the harness sets a placeholder path.

tdd: T-revoke-end-to-end — red (slice-2 firewall, no sync loop and no `changes` route): `panicked at crates/probation-server/tests/common/mod.rs:423:13: the firewall never became ready` — green (after the slice-3 merge, 207c7a9): `cargo test -p probation-server --test propagation -- --nocapture` passed (3 passed)
tdd: T-lookup-burst — red (same tree): `panicked at crates/probation-server/tests/common/mod.rs:423:13: the firewall never became ready`; then, after the merge, a test fault: `propagation.rs:223:9: key 40 answered 200 after 2.49384338s` (60 reqwest clients built inside the timed window loading TLS roots; built before the clock now) — green: `cargo test -p probation-server --test propagation -- --nocapture` passed
tdd: M-propagation — red (same tree): `panicked at crates/probation-server/tests/common/mod.rs:423:13: the firewall never became ready`; then, after the merge, a test fault: `propagation.rs:276:13: left: 503 right: 200` (the warm-up sent 50 new keys faster than the firewall's lookup budget; it now waits out `Retry-After`) — green: `cargo test -p probation-server --test propagation -- --nocapture` passed, `propagation edits p99 <= interval (4.958 s, interval 10 s)`, `propagation revocations p99 <= interval (5.041 s, interval 10 s)`

## sync_api.rs, `changes` (test first, after api.rs arrived)

Written before `sync::changes` existed; red is the run against the tree without the route.

tdd: T-sync-api-contract (`changes` deltas, the `ranges` table, the `pruned_through` reset and the prune job added to the test) — red: `panicked at crates/probation-server/tests/sync_api.rs:68:5: left: 404 right: 200` — green: `cargo test -p probation-server --test sync_api` passed (6 passed)
tdd: T-firewall-token-required (`changes` added to the routes) — red: `panicked at crates/probation-server/tests/sync_api.rs:328:13: api/v1/sync/changes with None; left: 404 right: 401` — green: `cargo test -p probation-server --test sync_api` passed
tdd: T-body-limits — red: `panicked at crates/probation-server/tests/sync_api.rs:527:9: 1 001 events; left: 404 right: 413` — green: `cargo test -p probation-server --test sync_api` passed
tdd: T-activity-place-from-key — red: `panicked at crates/probation-server/tests/sync_api.rs:582:9: left: 404 right: 200` — green: `cargo test -p probation-server --test sync_api` passed

## Rework

Review findings R1–R3. The witness counts stay 6/8/3: each new case extends the test whose promise it belongs to (R1 and R2 in T-authz-matrix, R3 in T-sync-api-contract).

tdd: T-authz-matrix, R1 case (a permit for one place never saves another) — red (written first, before the fix): `panicked at crates/probation-server/tests/tenancy.rs:195:5: a permit for PlaceRef { kind: User, id: 4 } saved PlaceRef { kind: Org, id: 1 }: Ok(4)` — green: `cargo test -p probation-server --test tenancy` passed (3 passed)
tdd: T-authz-matrix, R2 keys/fleet table (member, group admin, org admin, global admin × org, group, own user, other user; create and revoke; non-global `fleet::register`) — the checks already existed, so red is each check removed: `keys::create` check removed → `tenancy.rs:55:5: login 3 on PlaceRef { kind: Org, id: 1 }: create and revoke disagree; left: true right: false`; `keys::revoke` check removed → `tenancy.rs:55:5: … create and revoke disagree; left: false right: true`; `fleet::register` global-admin check removed → `tenancy.rs:174:27: fleet::register by login 2: None`; `may_manage_keys` admitting members → `tenancy.rs:154:13: keys: login 3 on PlaceRef { kind: Org, id: 1 }; left: true right: false` — green: `cargo test -p probation-server --test tenancy` passed
tdd: T-sync-api-contract, R3 case (a cursor above the log after a restore) — red (written first, before the fix): `panicked at crates/probation-server/tests/sync_api.rs:313:5: ChangesResponse { revision: 4, …, reset: true, … }` (the reset answered below the cursor 104) — green: `cargo test -p probation-server --test sync_api` passed (6 passed)

## Rework 2

Re-check findings N1–N3. Counts unchanged (6/8/3): N1 and N2 extend T-sync-api-contract, N3 extends T-authz-matrix's R1 case. `insert_audit` keeps its `_permit` parameter: the control strings pin the call text `insert_audit(&mut tx, actor, &permit, &checked)`.

tdd: T-sync-api-contract, N1 case (three firewalls from the lost history, cursors head+100, head+50, head+100) — red (written first): `panicked at crates/probation-server/tests/sync_api.rs:322:9: cursor 54: ChangesResponse { revision: 104, …, reset: false, … }` — green: `cargo test -p probation-server --test sync_api` passed (6 passed); mutant (raise `value` without `pruned_through`) killed: `sync_api.rs:322:9: cursor 104: ChangesResponse { revision: 105, …, reset: false }`
tdd: T-sync-api-contract, N2 case (a cursor at `MAX_CURSOR`, a change past it, then the handed-out cursor; `u64::MAX` refused) — red (written first, with N1 fixed): `panicked at crates/probation-server/tests/sync_api.rs:68:5: left: 422 right: 200` — green: `cargo test -p probation-server --test sync_api` passed; mutant M8 (the bigint check removed) killed: `sync_api.rs:354:5: left: 200 right: 422`; mutant (raise bound `$1 <= MAX_CURSOR` removed) killed by the added `i64::MAX - 1` case: `sync_api.rs:348:5: ChangesResponse { revision: 9223372036854775807, … }`
tdd: T-authz-matrix, N3 case (m2 saves m1's own layer with m1's permit) — red (written first): `panicked at crates/probation-server/tests/tenancy.rs:215:5: m2 saved with m1's permit: Ok(5)` — green: `cargo test -p probation-server --test tenancy` passed (3 passed); mutant (actor check removed) killed with the same line

## Rework 3 (S4-11, after slice 3's review fixes were merged, 505ab8c)

tdd: T-activity-place-from-key, S4-11 case (an event's `at`: 10 minutes ago kept, 1 hour ahead stored as now, missing stored as now, "yesterday" stored as now, 200 days ago clamped to the 90-day retention) — red (written first; `event()` gained `at: None`): `panicked at crates/probation-server/tests/sync_api.rs:763:5: (event, at the firewall's time, at now, at the retention bound); left: [("event-4", false, true, false), …, ("event-8", false, true, false)] right: [("event-4", true, false, false), …, ("event-8", false, false, true)]` — green: `cargo test -p probation-server --test sync_api` passed (6 passed)

## Rework 4 (C126: a `changes` call never moves the revision; F7; dedupe; S4-11 override)

C126 replaces S4-12 and the R3/N1 counter raise; `MAX_CURSOR` is removed and only a cursor that cannot be a bigint answers 422. Counts unchanged (6/8/3).

tdd: T-sync-api-contract, C126 case (three firewalls with cursors revision+100, revision+50, revision+100 and one at i64::MAX−1: each answered exactly the reset at the server's current revision; `change_counter (value, pruned_through)` unchanged; a fourth firewall at the revision is not reset and then sees exactly the next change) — red (written first): `panicked at crates/probation-server/tests/sync_api.rs:331:9: cursor 104; left: ChangesResponse { revision: 105, …, reset: true } right: ChangesResponse { revision: 4, …, reset: true }` — green: `cargo test -p probation-server --test sync_api` passed (6 passed)
tdd: T-sync-api-contract, a subject repeated in one delta is named once (push_new now dedupes with a HashSet) — added after the change, so red is the mutant that pushes every repeat: `sync_api.rs:365:5: left: { revision: 7, changed_layers: [Org 1, Org 1] } right: { revision: 7, changed_layers: [Org 1] }` — green: sync_api passed
tdd: T-activity-place-from-key, S4-11 organisation override (Globex keeps activity 30 days; an event 200 days old is stored 30 days ago) — passed when first run (the clamp already read the override), so red is the mutant that drops the organisation's override: `sync_api.rs:800:5: left: […, ("event-9", false, false, true, false)] right: […, ("event-9", false, false, false, true)]` — green: sync_api passed
tdd: T-grant-bootstrap, F7 (the bootstrap audit row names the host operator: no login, global-admin flag set) — red (written first): `panicked at crates/probation-server/tests/tenancy.rs:371:5: left: (Some(1), true, "admin.bootstrap") right: (None, true, "admin.bootstrap")` — green: `cargo test -p probation-server --test tenancy` passed (3 passed)

Test fix: T-firewall-token-source failed once with `sync_api.rs:549:5: the burst fits in one second` at load average 41. The cause is the wall-clock precondition: 201 sequential requests on a loaded host can take more than a second, and that proves nothing either way. A burst that does not fit is now waited out and sent again, up to five times; the rate assertions run only on a burst that fitted.
