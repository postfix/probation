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
| S4-11 | for review | Activity `at` is the server's receive time, because `ActivityEvent` (api.rs) carries no timestamp, so a row can be up to one sync interval late. | Reviewers judge against the activity-log requirements (C-rows on activity, T-activity-*). Adding a field would change slice 3's wire type. |
| S4-12 | for review | A `since` above the server's revision (for example after a database restore) answers with a reset. That is not in the design text; the effect is conservative. | — |
| S4-13 | for review | The `changes` entry caps (1 000 events, 1 000 `activity_dropped`, a 2 KiB `last_apply_error`) are checked after a parse that the 2 MiB byte cap bounds, and before any write (T24). | — |
