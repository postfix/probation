# Slice 4 evidence — probation-server on Postgres, sync API, bootstrap CLI, atomic audited edits

Built in parallel with slice 3, in worktree ../probation-slice4 (branch `management-server-slice4`, from 6ac2e36), by the user's choice on 2026-10-22. `crates/probation-policy/src/api.rs` is owned by slice 3; slice 4 builds against a copy of it and is merged after slice 3.

## Decisions and deviations
| ID | Status | Item | Decision |
|---|---|---|---|
| S4-1 | accepted, slice 8 docs | The server listens on plain HTTP; TLS is terminated by a proxy in front (`[server] trusted_proxies`). Firewalls accept only https (C34). | Document for operators in slice 8. |
| S4-2 | accepted | `Actor::Operator` for `probation-server admin`: acts as a global admin; its audit rows have no login. | — |
| S4-3 | accepted | Schema choices: the user place id is `memberships.id`; a global admin is a memberships row with a NULL org; layer, block and exception rows have ids; `change_log.subject` is jsonb; `activity.rule` is NOT NULL. | — |
| S4-4 | for review | The audit `before` value reaches `insert_audit` through a transaction-local setting, because the control strings fix `insert_audit`'s arguments. | Reviewers judge. |
| S4-5 | accepted | A store error in `authorized_place` maps to NotFound (fails closed, logged). | — |
| S4-6 | accepted | Bootstrap writes exactly one audit row (T-grant-bootstrap); keys and fleet write their own rows. | — |
| S4-7 | accepted | `keys::create`/`revoke` already check the role. | — |
| S4-8 | accepted | CI starts Postgres through the compose file (it needs max_connections=500). | — |
| S4-9 | scope | The root `Cargo.toml` gets one `exclude` entry, `docker-compose.test.yml`, to keep it out of the published `probation` package (C117). | Approved. |
| S4-10 | process | The first tests were written after the code; their reds come from named mutants. | Accepted because it is recorded; the remaining tests are written test-first. |
| S4-11 | fixing (review confirmed): slice 3 adds optional `ActivityEvent.at`; the server stores it clamped to [now − retention, now] and falls back to now() | Activity `at` is the server's receive time, because `ActivityEvent` (api.rs) carries no timestamp, so a row can be up to one sync interval late. | Reviewers judge against the activity-log requirements (C-rows on activity, T-activity-*). Adding a field would change slice 3's wire type. |
| S4-12 | for review | A `since` above the server's revision (for example after a database restore) answers with a reset. That is not in the design text; the effect is conservative. | — |
| S4-13 | for review | The `changes` entry caps (1 000 events, 1 000 `activity_dropped`, a 2 KiB `last_apply_error`) are checked after a parse that the 2 MiB byte cap bounds, and before any write (T24). | — |

## Branch history
- e19ee19: slice 4 WIP committed in the worktree (sync_api 6, policy_edit 8, tenancy 3, doctest 1; propagation red until slice 3 is merged).
- 207c7a9: `management-server` (slice 3, af70628, pre-review) merged into `management-server-slice4`. Clean; api.rs identical on both sides.
- Final slice-4 commit (pre-review) on `management-server-slice4`: propagation green (edits p99 5.080 s, revocations p99 5.014 s at a 10 s interval); molecule-verify --slice 4 PASS (12/12 obligations); 44 workspace suites ok. Fixes after the merge were test-only (propagation.rs, and the `token_file` placeholder in the harness).
- Packaging note: a stale local copy of `probation-policy 0.2.2` (~/.cargo/registry/src/… and target/) made `cargo package` verification fail with E0432. It is host-local only, since CI uses a fresh CARGO_HOME. The implementer deleted that cached copy. Re-packaging locally after changing probation-policy without bumping its version needs a fresh target or cache.

## Review backlog (minor or refuted; not fixed in slice 4)
| Finding | Where | Title |
|---|---|---|
| code-review F4 | crates/probation-server/tests/sync_api.rs:488 | T-firewall-token-source fails under load because 201 sequential HTTP+DB requests must finish within one wall-clock second |
| code-review F5 | crates/probation-server/src/sync.rs:307 | Sync handlers read up to 2 MiB of body, and query Postgres for the token, before the firewall token is checked or rate-limited |
| code-review F6 | crates/probation-server/tests/tenancy.rs:178 | T-tenant-isolation's 'an SSO session sees only Acme' check only tests Globex; a mutant admitting places with no org survives |
| code-review F7 | src/../crates/probation-server/src/lib.rs:181 | The bootstrap audit row says the newly created admin did the bootstrap, and lists the row in Acme's org log |
| code-review F8 | crates/probation-server/src/tenancy.rs:140 | Actor is a public enum with public fields, so any caller can create an authorizing actor without a session |
| security F3 | crates/probation-server/src/tenancy.rs:355 | A deleted login keeps its personal place and the Owner role on it |
| security F4 | crates/probation-server/src/sync.rs:307 | Sync handlers read the full 2 MiB body before the firewall token is checked |
| security F2 (refuted by skeptics) | — | Actor (including Operator) can be built by any caller, so authorize, keys and fleet trust a made-up identity |
| adversarial F3 | crates/probation-server/src/tenancy.rs:129 | Automation actor is authorized for any field of its layer, and its audit row does not name the token |
| adversarial F4 | crates/probation-server/src/sync.rs:515 | changes builds the delta in quadratic time; since=0 over a large log can outlast the firewall's 2 s request timeout |
| adversarial F5 | crates/probation-server/src/tenancy.rs:242 | A soft-deleted login keeps Owner on its personal account (edit and key management) |
