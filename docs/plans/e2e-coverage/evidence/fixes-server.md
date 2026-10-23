# Server defect fixes: red and green

Branch `fix-server-defects`, from `management-server` ce42bc9. Each defect is from
`00-inventory.md` §1.3. Each test was run red before its fix and green after it.

## F1: `X-Forwarded-For` entries with a port or brackets

- Tests: `sync::tests::forwarded_entries_with_ports_and_brackets` and
  `portal::tests::forwarded_entries_with_ports_and_brackets` (crates/probation-server, lib).
- Red: `cargo test -p probation-server --lib forwarded`, 2 failed:
  `sync.rs: assertion left == right failed: 192.0.2.7:4711; left: None, right: Some(192.0.2.7)`
  and `portal/mod.rs: left: None, right: Some(192.0.2.7)`.
- Fix: `sync::forwarded_ip` accepts a bare address, `ip:port`, `[v6]` and `[v6]:port`;
  `sync::source_address` and `portal::client_ip` parse each entry through it. Anything
  else, `unknown` included, still refuses.
- Green: same command, 3 passed (the two above and `sync::tests::forwarded_ip_forms`).

## F8: `serve` stops cleanly on SIGTERM

- Test: `sigterm_stops_serve_with_success` (crates/probation-server/tests/serve.rs). It runs
  the built binary with the portal and SMTP set, so the prune, outbox and purge jobs all
  run, sends SIGTERM once it listens, and wants exit code 0 within 5 s.
- Red: `cargo test -p probation-server --test serve`: `panicked at tests/serve.rs:67:5:
  signal: 15 (SIGTERM)`; the process died by the signal.
- Fix: `serve` installs SIGTERM and SIGINT handlers and serves with
  `with_graceful_shutdown`, so requests in flight finish. The prune, outbox and purge jobs
  run under one helper, `every`, that stops between runs when a watch channel turns; `serve`
  waits for them before it returns. `Portal::launch` is gone: `serve` starts the portal's
  jobs itself (`accounts::spawn_jobs` returns their handles).
- Green: same command, `sigterm_stops_serve_with_success ... ok`; the log shows
  `stopping: finishing the requests in flight`.

## F9: health endpoints

- Test: `health_live_and_ready` (tests/serve.rs). Over the router `serve` uses:
  `/health/live` and `/health/ready` answer 200; after `db.app.close()`, live still 200 and
  ready 503.
- Red: `cargo test -p probation-server --test serve`: `panicked at tests/serve.rs:86:5:
  left: 404, right: 200` (no such route).
- Fix: `build_router` merges a `health` router: `/health/live` always 200;
  `/health/ready` runs `SELECT 1` on the pool under a 2 s timeout, 200 or 503. It is merged
  next to the sync and automation APIs, so the portal's session, CSRF and confirm layers
  never wrap it, and it reads no session and no network lock.
- Container health check: the image (debian bookworm-slim) has neither curl nor wget, so
  the binary got `probation-server health [--url]` (default
  `http://127.0.0.1:8080/health/ready`), exit 0 on 2xx, 1 otherwise. Its test,
  `health_command_follows_ready`, was written with the command, so it has no separate red
  beyond "unrecognized subcommand". `deploy/docker-compose.yml` and
  `docker-compose.e2e.yml` run it as the server's `healthcheck`.
- Green: same command, `health_live_and_ready ... ok`, `health_command_follows_ready ... ok`.
- Docs: operations.md §16 describes both endpoints and the command (limitation 9, "no
  health endpoint", removed); management-server.md §7 and api.md §3 list `health`.

## F13: `admin revoke-key` is not "any key" (docs)

`keys::revoke_where` updates only `kind IN ('user', 'service')`. Reworded:
management-server.md §7 (was "Revokes any key"), api.md §3 (`--key-id`), operations.md
server commands and restore step 4, and the `admin::revoke_key` doc comment. Each now
says automation (`aut_`) and firewall (`fwt_`) tokens are revoked on the portal or by
retiring the firewall. Docs only, no test.

## F16: firewalls registered or retired after a backup (docs)

operations.md, "Backing up and restoring the management server": step 4 lists firewall
registrations among the post-backup changes; step 5 says a firewall registered after the
backup gets 401 and must be registered again, and one retired after it is live again and
must be retired again. Docs only, no test.

## F11: the automation API answers 503, not 401, on a database outage

- Test: `automation_api_answers_503_when_the_database_is_down` (tests/admin_fleet.rs). It
  serves the API over a pool, closes the pool, calls `GET /api/v1/blocklist/org-1` with an
  `aut_` token and wants 503; then `Tenancy::automation` on the closed pool wants `Err`.
- Red: `cargo test -p probation-server --test admin_fleet automation_api_answers_503`:
  `panicked at tests/admin_fleet.rs:3242:5: left: 401, right: 503`.
- Fix: `Tenancy::automation` returns `Result<Option<(Actor, Authorized<Place>)>,
  sqlx::Error>`: `Ok(None)` for no live token or a suspended place (401, unchanged), `Err`
  for a store error. `policy::token_layer` maps `Err` through `store_failure` to 503. The
  one other caller (`t_automation_scope`) unwraps. api.md's status table no longer says a
  database failure answers 401.
- Green: `cargo test -p probation-server --test admin_fleet automation`: 5 passed (the new
  test and the four existing automation tests).

## F12: unsent outbox rows keep links in plain text

- Test: `outbox_body_sealed_at_rest` (tests/accounts.rs). A sign-up queues the confirm
  mail; the whole raw row (`row_to_json(email_outbox)`) must contain neither `token=` nor
  the base URL. `deliver_outbox` under another key sends nothing and the row waits; under
  the portal's key the mail carries a link that confirms the address.
- Red: `cargo test -p probation-server --test accounts outbox_body_sealed`: `panicked at
  tests/accounts.rs:645:5: {"id":1,...,"payload":{"body": "Open this link to confirm your
  email address for Probation:\n\nhttps://portal.test/verify-email?token=Q5wE...`.
- Fix: `accounts::enqueue` inserts the row, then stores
  `{"subject", "sealed_body"}` where `sealed_body` is base64url of
  `SecretBox::seal(outbox_aad(id), body)`, `outbox_aad(id) = "outbox:<id>"`, in the same
  transaction. `deliver_outbox` opens it; a body that does not open counts as a failed
  attempt (retried with backoff, never sent empty); a row queued before this change
  (plain `body`) is still sent. The `SecretBox` reaches `enqueue` through `sign_up`,
  `resend_verification`, `request_reset`, `tenancy::invite`, `invite_global_admin`
  (callers pass `portal.secrets`) and `spawn_jobs`. Tests share `common::SECRET_KEY`.
- E2E: `tests/e2e/drive.mjs` reads the newest row's id and `sealed_body` by SQL as before
  and opens it with `E2E_SECRET_KEY` (already exported by `signup_to_install.sh`) in
  Node's AES-256-GCM: a 15-line `lastMail` helper, no new service. Checked against a body
  sealed by the Rust `SecretBox`: it opens under its own row id and fails under another.
  The E2E stack itself was not run here.
- Green: same command, `outbox_body_sealed_at_rest ... ok`; `--test accounts` 30 passed.
- Docs: management-server.md (`[portal.smtp]` unset) and operations.md (backups) say
  waiting mail is sealed under `PROBATION_SERVER_SECRET_KEY`.

## Checks (2026-10-23)

- `cargo test -j 16 --workspace --no-fail-fast -- --test-threads=16` (Postgres on 55437):
  exit 0; 49 test binaries, 716 passed, 0 failed, 21 ignored. After it, two small edits
  in the server crate (the stop signal uses `send_replace`, and `outbox_aad` became
  private); `cargo test -p probation-server` afterwards: 12 binaries, 129 passed, 0 failed.
- `cargo clippy --workspace --all-targets -- -D warnings`: clean (`tenancy::invite` has
  `#[allow(clippy::too_many_arguments)]` for its eighth argument, the `SecretBox`).
  `cargo fmt --all --check`: clean.
- `router molecule-verify --plan-root docs/plans/management-server`: PASS, 12 checks,
  0 findings.
- SMTC analyzers at `--root crates/probation-server`: client-data-reaches-delivery-sink 0,
  consumer-identity-extension-read 0, enqueue-timeout-guard 0, outbound-timeout-guard 0.
  The first run found 1 each: `stop.send(true)` on the watch channel in `serve` matched
  the `send` operation; it is now `send_replace(true)`.
- C123 query (`smtc callers --name get|get_all --callsites-matching '*AUTHORIZATION'
  --argument-index 0|1` at the absolute `src` and `crates/probation-policy/src`): one
  site over the eight runs, `src/managed/mod.rs:276` `get(AUTHORIZATION)`.
