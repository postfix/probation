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

## Review round on 7a86ad0

### F8 (major): the drain had no deadline

- Tests (tests/serve.rs, now over a small `Server` helper):
  `stalled_request_holds_shutdown_for_the_drain_only` opens a connection that announces a
  1000-byte body and sends 10 bytes, then sends SIGTERM, and wants exit 0 within 25 s.
  `second_sigterm_ends_the_drain` does the same, checks that the process is still
  draining 1 s later, then sends a second SIGTERM and wants exit 0 within 3 s.
- Red: `cargo test -p probation-server --test serve`: `serve still runs 25s later` and
  `serve still runs 3s later`.
- Fix: the first signal turns the stop channel, which both starts the graceful shutdown
  and stops the jobs. `serve` then races "the server drained and the jobs ended" against
  "`DRAIN` (20 s) passed or a second SIGTERM/SIGINT came", logs `stopping now: requests or
  jobs still running are dropped` if the second wins, and returns `Ok`.
- Green: 5 passed; the deadline case logs the warning 20.0 s after the signal, the
  second-signal case 1 s after it.
- Header-read and request timeouts: not added. `axum::serve` 0.8 builds its hyper
  connection with no timer and exposes no builder, so hyper's `header_read_timeout`
  cannot be set without replacing `axum::serve` with a hyper-util accept loop. A tower
  timeout layer would need `tower`'s `timeout` feature plus a `HandleErrorLayer`, and would
  not cover header reads. The drain deadline bounds shutdown either way.
- `deploy/docker-compose.yml` gives the server `stop_grace_period: 30s`, above the drain;
  operations.md §16 and api.md §3 describe the 20 s drain and the second signal.

### Minor: jobs could run after stop, and an outbox run ignored stop

- Test: `outbox_run_stops_between_mails` (tests/accounts.rs): three sign-ups queue three
  mails, `spawn_jobs` runs with a relay that turns the stop channel as it takes its first
  mail, the jobs must end within 10 s with 1 mail sent and 2 rows unsent.
- Red: `cargo test -p probation-server --test accounts outbox`: `left: 3, right: 1`.
- Fix: `every` selects `biased` with the stop branch first and runs the job after the
  select, so no run starts once stop has turned. `deliver_outbox` takes the stop receiver
  and checks it before each mail. The test fixtures pass a receiver that never turns.
- Green: same command, 3 passed.

### Minor (F12): mail queued before sealing; mixed versions

- Test: `outbox_sends_a_row_queued_before_sealing` (tests/accounts.rs): a row with a plain
  `payload.body` is sent with its subject and body. It passed when first run: the
  fallback was already in 7a86ad0, so this test only adds coverage and has no red.
- Docs: management-server.md now says a body is sealed when it is queued, and mail queued
  by an older server stays in plain text until sent; operations.md's backup note says
  "sealed bodies of unsent mail". The server upgrade steps say to stop every instance,
  and never to run an old and a new server on one database (an old one sends a sealed
  mail with an empty body and marks it sent). No compatibility code.

### Checks (review round)

- `cargo test -j 16 --workspace --no-fail-fast -- --test-threads=16`: the first run had 1
  failure outside this change, `tests/content_store.rs`
  `an_open_during_eviction_is_refused_and_a_second_eviction_stands_aside` ("a second pass
  over the same key stands aside"). Nothing under `src/` or that test changed on this
  branch. It passed 5 of 5 runs alone. The test relies on the first `evict` yielding
  inside the removal before the second is polled, so it is timing dependent. The rerun of
  the whole suite: exit 0, 49 binaries, 720 passed, 0 failed, 21 ignored.
- clippy `-D warnings` and `fmt --check`: clean.
- `router molecule-verify`: PASS, 12 checks, 0 findings.
- The 4 SMTC analyzers at `crates/probation-server`: 0 findings each.
- C123 query: one site, `src/managed/mod.rs:276` `get(AUTHORIZATION)`.

## Round 3: defects from the P0 e2e run

### F7: a session opened before the address was confirmed survived the confirmation

- Test: `confirming_an_address_ends_the_logins_sessions` (tests/accounts.rs). A squatter
  signs up with the victim's address and signs in; the owner opens the confirm link in
  another browser; the squatter's `GET /account` must redirect to `/signin`, and the
  login must have no session left.
- Red: `cargo test -p probation-server --test accounts confirming_an_address`:
  `left: (200, None), right: (303, Some("/signin"))`.
- Fix (chosen: end all, the safest minimal option): `accounts::verify_email` calls
  `end_sessions(login, keep: None)` in its transaction, so every session of the login
  ends, signed in or pending at its TOTP or deleted-login step, the confirmer's included.
  The confirmation page always continues to `/signin`, so whoever confirms signs in
  with the password.
- Green: same command, ok; `--test accounts`, `portal_places`, `admin_fleet` and `tenancy`
  all pass.
- Not fixed here: a squatter who chose the password can still sign in again after the
  owner confirms, until the owner resets it. Closing that needs a design change, such as
  asking for the password on the confirm page.

### F17: an invitation was lost across sign-up and sign-in

- Test: `invitation_survives_sign_up_and_sign_in` (tests/portal_places.rs; its test
  `Browser` now keeps cookies by name). A signed-out invitee opens the link, is sent to
  `/signin`, signs up, confirms, signs in, and `GET /account` must redirect to the
  invitation, which it accepts; the next `/account` is 200. Planted values
  (`https://evil.example/`, `//evil.example`, `/admin`, `x&next=/admin`) give 200 and go
  nowhere, and a link with no usable token sets no cookie.
- Red: `cargo test -p probation-server --test portal_places invitation_survives`:
  `left: (200, None), right: (303, Some("/invite?token=…"))`.
- Fix (chosen over a `next` parameter): `/invite` opened signed out sets a
  `probation_invite` cookie (Secure, HttpOnly, SameSite=Lax, one day) that holds only the
  token, and only when it is URL-safe base64 of at most 64 characters. Every sign-in path
  (password, TOTP, the deleted-login choice, Google/GitHub/Microsoft, company SSO, and
  sign-up then confirmation) ends on `GET /account`, which sends the browser to
  `/invite?token=<token>` and clears the cookie. The destination is built by the server
  from a validated token, so it cannot become an open redirect. A value that is not a
  token is cleared and ignored. A `next` parameter would have to be carried through every
  one of those flows and through the confirmation mail.
- Green: same command, ok.

### ND-2: a wrong `PROBATION_SERVER_SECRET_KEY` failed silently

- Test: `serve_refuses_a_secret_key_that_does_not_match` (tests/serve.rs). A TOTP secret
  sealed under key `[8; 32]`; `serve` with key `07…` must exit 1, with the stderr naming
  the mismatch; after the row is sealed again under the key used, `serve` starts and
  stops on SIGTERM with 0.
- Red: `cargo test -p probation-server --test serve serve_refuses`: `serve stops at once:
  Elapsed(())`; serve ran with the wrong key. That first version of the test waited on
  the process's output and hung until it was killed; the test now polls and kills
  the process at 20 s.
- Fix: `accounts::secret_key_matches` opens one TOTP secret and one SSO client secret,
  when there are any. `serve` with `[portal]` runs it first and, on a mismatch, logs and
  returns `PROBATION_SERVER_SECRET_KEY does not match the one these secrets were sealed
  with (a database restored with another key?); serve refused` (exit 1). Decision:
  refuse, as recommended, because otherwise every TOTP sign-in and SSO sign-in fails
  silently. A database error during the check only warns, so a slow database does not
  stop the start. `second_factor` logs an error when the TOTP secret does not open,
  instead of folding it into "wrong code" (log only, no test).
- Green: same command, ok (serve.rs: 6 passed).
- Docs: operations.md (backups: back up the key together with every database backup;
  serve refuses another key; a troubleshooting row for the new message),
  management-server.md (the key's row). portal-guide.md §1.2 and §1.8 now describe F7
  and F17.

### Checks (round 3)

- `cargo test -j 16 --workspace --no-fail-fast -- --test-threads=16`: exit 0, 49
  binaries, 723 passed, 0 failed, 21 ignored.
- clippy `-D warnings` and `fmt --check`: clean.
- `router molecule-verify`: PASS, 12 checks, 0 findings.
- The 4 SMTC analyzers at `crates/probation-server`: 0 findings each.
- C123 query: one site, `src/managed/mod.rs:276` `get(AUTHORIZATION)`.

## Round 4: F7 closed by the user's decision

User decision (relayed by the team lead, 2026-10-24): confirming an address sets a new
password. The confirmation link opens a page where the user chooses a password, so only
who reads the mailbox ends up knowing it; a link opened by a mail scanner does nothing.

- Tests (tests/accounts.rs):
  - `confirming_an_address_ends_the_logins_sessions`, extended: after the owner
    confirms with a new password, the squatter's sign-up password is refused and the
    owner's works.
  - `confirming_takes_a_posted_password_once`: a GET of the link from another browser
    shows the form and leaves the method unconfirmed with no personal account. A post
    with a wrong CSRF token, with two passwords that differ, and with a short password
    each confirms nothing. The real post confirms and creates the personal account
    (C6). The used link then answers 410, opened or posted. The new password signs in.
- Red: `cargo test -p probation-server --test accounts confirming`, 2 failed. The
  extended test fails in `Page::csrf` with "a form with a CSRF token", because the GET
  confirmed at once and showed no form. The new test fails at its first check: the page
  had no `action="/verify-email"` form.
- Fix:
  - `GET /verify-email?token=…` only checks that the token is live
    (`accounts::verify_token_live`) and renders the password form; 410 for a dead link.
  - New `POST /verify-email` (`signin::confirm_email`) checks the session's CSRF token,
    the token, that the two passwords match, and `check_new_password` (C42: length and
    the leaked-password range API). Then `accounts::verify_email(pool, token, new_hash)`
    does all of it in one transaction: it uses up the token, sets `verified_at` and
    replaces `password_hash`, ends every session of the login (signed in, or pending
    TOTP or the deleted-login choice), and creates the organisation or personal account
    the sign-up asked for (C5/C6, unchanged).
  - `/verify-email` was already exempt from the confirm-first redirect, so a signed-out
    browser, or the squatter's unconfirmed one, can post it. The route table's CSRF walk
    (T-portal-csrf) covers the new POST.
- C41 check: an unconfirmed login cannot set up TOTP. `confirm_first` redirects every
  route except `/verify-email*`, `/signout` and `/static/*` to `/verify-email`, and
  `t_portal_unverified_blocked` walks the whole route table, `/account/totp/setup`
  included, for a signed-in unconfirmed login. So a squatter has no authenticator to
  leave behind.
- OAuth and SSO logins: unchanged. Only email-and-password sign-ups get a verify token
  (`send_verify`); Google, GitHub, Microsoft and company SSO methods are created
  confirmed.
- Test callers that confirmed by GET now go through a `confirm(browser, link, password)`
  helper in tests/accounts.rs and tests/portal_places.rs. `tests/e2e/drive.mjs` submits
  the link's form with the user's password (3 lines).
- Green: `--test accounts` 34 passed, `portal_places` 37, `admin_fleet` 30, `tenancy` 4.
- Docs: portal-guide.md §1.1 and §1.2.

### Checks (round 4)

- `cargo test -j 16 --workspace --no-fail-fast -- --test-threads=16`: exit 0, 49
  binaries, 724 passed, 0 failed, 21 ignored.
- clippy `-D warnings` and `fmt --check`: clean.
- `router molecule-verify`: PASS, 12 checks, 0 findings.
- The 4 SMTC analyzers at `crates/probation-server`: 0 findings each. The spec paths
  are given as absolute paths; a relative path made the daemon fail to read the spec.
- C123 query: one site, `src/managed/mod.rs:276` `get(AUTHORIZATION)`.
