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

tdd: T-revoke-end-to-end — red (slice-2 firewall, no sync loop and no `changes` route): `panicked at crates/probation-server/tests/common/mod.rs:423:13: the firewall never became ready` — green: pending the slice-3 merge
tdd: T-lookup-burst — red (same tree): `panicked at crates/probation-server/tests/common/mod.rs:423:13: the firewall never became ready` — green: pending the slice-3 merge
tdd: M-propagation — red (same tree): `panicked at crates/probation-server/tests/common/mod.rs:423:13: the firewall never became ready` — green: pending the slice-3 merge

## sync_api.rs, `changes` (test first, after api.rs arrived)

Written before `sync::changes` existed; red is the run against the tree without the route.

tdd: T-sync-api-contract (`changes` deltas, the `ranges` table, the `pruned_through` reset and the prune job added to the test) — red: `panicked at crates/probation-server/tests/sync_api.rs:68:5: left: 404 right: 200` — green: `cargo test -p probation-server --test sync_api` passed (6 passed)
tdd: T-firewall-token-required (`changes` added to the routes) — red: `panicked at crates/probation-server/tests/sync_api.rs:328:13: api/v1/sync/changes with None; left: 404 right: 401` — green: `cargo test -p probation-server --test sync_api` passed
tdd: T-body-limits — red: `panicked at crates/probation-server/tests/sync_api.rs:527:9: 1 001 events; left: 404 right: 413` — green: `cargo test -p probation-server --test sync_api` passed
tdd: T-activity-place-from-key — red: `panicked at crates/probation-server/tests/sync_api.rs:582:9: left: 404 right: 200` — green: `cargo test -p probation-server --test sync_api` passed
