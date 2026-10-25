# Firewall defect fixes: F1, F2, F3, F6, F10, F14

Source: `00-inventory.md` §1.3. Branch `fix-firewall-defects`, based on `management-server` at ce42bc9. Each fix was test-first: the test below was run against the unfixed code (red), then the fix was applied and the same test run again (green).

## F1: `X-Forwarded-For` entry with a port

- Test: `src/managed/lock.rs` `a_listed_proxy_names_the_rightmost_untrusted_entry` (new asserts). Accepted: `203.0.113.9:1234`, `[2001:db8::1]`, `[2001:db8::1]:443`, `[::ffff:192.0.2.7]:80` (canonicalised to IPv4). Refused (`None`, so `403`): `unknown`, `_hidden`, `[192.0.2.7]`, `192.0.2.7:`, `[2001:db8::1`.
- Red: `assertion left == right failed: 203.0.113.9:1234, left: None, right: Some(203.0.113.9)`.
- Fix: `forwarded_ip(entry)`, which tries a bare `IpAddr`, then `SocketAddr` (`ip:port`, `[v6]:port`), then `[v6]`, and canonicalises the result. Every other entry still refuses the request (C113 fail-closed). `Forwarded` (RFC 7239) is not read. The server side (`crates/probation-server`) is not touched here.
- Green: `test managed::lock::tests::a_listed_proxy_names_the_rightmost_untrusted_entry ... ok`.

## F2: activity lost on SIGTERM

- Test: `tests/managed_sync.rs` `t_activity_flushed_on_stop`. Sync interval 3600 s, so only the start-up round runs. The test queues one event (`KeyId(77)`), checks that no restart is pending, calls `shutdown`, and asserts that the fake server received the event.
- Red: `the queued event went out before the stop: []`.
- Fix: `src/tasks/policy_sync.rs` `run` always waits for `drain` after the loop and sends one last `changes` call. It skips the call when the batch has no events, no dropped counts and no restart is pending. A failed delivery logs the warning `the activity queued before the stop could not be delivered`. The call is bounded by `request_timeout_seconds` (`KeySync::request_changes` deadline).
- Green: `test t_activity_flushed_on_stop ... ok`.

## F3: an undecodable server answer treated as an outage

- Test: `tests/managed_sync.rs` `t_sync_unreadable_answer`. The fake server answers `200` with `changed_layers: [{"kind":"Galaxy",...}]`, an unknown `LayerKind` variant (new fake hook `FakeSyncServer::answer_changes_raw`). The test asserts that `/health/ready` is `503`, that the next report's `last_apply_error` says `could not be read` and names `(v<CARGO_PKG_VERSION>)`, and that readiness returns to `200` once the answers can be read again.
- Red: `assertion left == right failed: reported on readiness, left: 200, right: 503`.
- Fix: `src/managed/sync.rs` replaces the private `Failed` and public `Unreachable` with `pub enum SyncFailure { Unreachable, Unreadable }`. Only a 2xx body that fails to deserialize is `Unreadable`. `sync_once` handles `Unreadable` this way:
  - logs at error level `the management server's answer could not be read; this firewall (v<version>) may be older than the server; serving from the cache`;
  - re-queues the batch (events carry `event_id`, so a re-send is stored once);
  - calls `note_unreachable(Some(..))`.

  `/health/ready` therefore turns `503`, and the error reaches the fleet page through `last_apply_error`. A transport failure behaves as before.
- Green: `test t_sync_unreadable_answer ... ok`.

## F6: no compatibility guard on `managed-cache.json`

- Fixture: `tests/fixtures/managed/managed-cache.json`. It was written by the unchanged ce42bc9 `write_snapshot` from a throwaway generator test, which was removed afterwards. It holds one key (with rate limit override, org and a 2-place chain), two layers (one stale, with a block and an exception), one network-lock range, and cursor 42.
- Version field: added. `Snapshot.version: u32` has `#[serde(default)]`, so a file without it reads as version 0. Current writes use `SNAPSHOT_VERSION = 1`, and a file whose version is newer than that is not read (warning, then the previous file is tried). An older binary ignores the unknown field, because `Snapshot` has no `deny_unknown_fields`. The existing format still loads.
- Tests (`src/managed/cache.rs`):
  - `a_snapshot_from_before_versioning_still_loads` loads the golden file through `read_snapshot` and checks every part plus the restored stale marker.
  - `a_snapshot_from_a_newer_format_is_not_read`.
- Red (before the fix): the two tests do not compile (`E0560 struct Snapshot has no field named version`, `E0609 no field version`, `E0425 cannot find value SNAPSHOT_VERSION`).
- Red (the guard itself, by mutation after the fix): renaming `SavedKey.hash` to `key_hash` makes `a_snapshot_from_before_versioning_still_loads` fail at `read_snapshot(..).expect("the golden snapshot loads")`. The mutation was reverted.
- Green: both tests `... ok`, and `a_snapshot_survives_a_truncated_current_file ... ok`.

## F10: artifact host not tied to its ecosystem

- Test: `tests/npm_upstream_paths.rs` `a_tarball_on_another_ecosystems_host_is_refused_unfetched`. The npm packument's `dist.tarball` points at `https://files.invalid/...`, the fake PyPI files origin. The test asserts that the response is not `200` and that no registry call went to `files.invalid`.
- Red: `assertion left != right failed, left: 200, right: 200`. The tarball was fetched from the PyPI files host and served.
- Fix: `src/artifacts/download.rs` `transfer` calls `own_origin` before `open_artifact`. The URL must pass `OriginSet::admit` against one of the artifact's own ecosystem's origins: npm uses `NpmMetadata`; PyPI uses `PypiArtifacts` or `PypiMetadata`. Any other URL fails with the existing upstream refusal, `UpstreamError::RejectedUrl` carrying the `admit_any` reason, or `ForeignOrigin` when that URL belongs to another ecosystem. The transport is never called.
- First attempt and its regression: the first version classified the URL with `admit_any` (that is, `kind_of`). That returns only the first of several origins configured to the same URL, so `tests/key_canary.rs` `t_key_canary`, where one wiremock socket stands for all three origins, got `502` for a PyPI wheel. Admitting the URL against each of the artifact's own origins fixed this, and `key_canary` passes again.
- Green: `test a_tarball_on_another_ecosystems_host_is_refused_unfetched ... ok`.

## F14: npm `Accept` negotiation

- Test: `src/http/npm_routes.rs` `only_an_acceptable_entry_selects_the_abbreviated_form`, which includes `application/vnd.npm.install-v1+json;q=0, application/json` → full document.
- Red: the substring match failed the case-insensitive case first (`Application/VND.npm.Install-v1+JSON;q=0.5` got the full document). The `q=0` case would also fail, because `contains` matched it.
- Fix: `names_abbreviated(entry)` splits each comma-separated entry. It returns true only when the media type equals `application/vnd.npm.install-v1+json` (case-insensitive) and q > 0. A missing or unparseable q counts as 1.
- Green: `test http::npm_routes::tests::only_an_acceptable_entry_selects_the_abbreviated_form ... ok`.

## Docs

- `SPEC.md` §4: `ip:port`/`[v6]` forms, and `Forwarded` is not read.
- `SPEC.md` §10 managed paragraph: flush on every graceful stop, and an unreadable answer gives `503` plus a report.
- `SPEC.md` §11: the `/health/ready` row, and artifact origins are tied to their ecosystem.
- `docs/operations.md`: section 2 (stopping), outbound filtering, `trusted_proxies`, the managed-mode alert lines (two new rows), and the `/health/ready` row.

## Checks (2026-10-23)

- `cargo test -j 16 --workspace --no-fail-fast -- --test-threads=16`: Postgres on 127.0.0.1:55432 was not reachable (connection refused). Every `probation-server` test failed at its `PgPool::connect` (`crates/probation-server/tests/common/mod.rs:106`, "Postgres is up"). The one other failure in that run was `key_canary`, which is the F10 regression described above, now fixed. The workspace run was therefore replaced by `cargo test -j 16 -p probation -p probation-policy --no-fail-fast -- --test-threads=16`: 593 passed, 0 failed, 21 ignored.
- `cargo clippy -j 16 --workspace --all-targets --all-features -- -D warnings`: clean. `cargo fmt --all -- --check`: clean.
- `router molecule-verify --plan-root docs/plans/management-server`: PASS, 12/12. `fetch_changes` keeps the line `Err(_) => return Err(Unreachable),` that the `unreachable-keeps-cache` controls mutate.
- SMTC analyzers, each at its documented root:
  - `client-data-reaches-delivery-sink` @ `src`: 0 findings (pass).
  - `consumer-identity-extension-read` @ `src`: 1 finding, `src/http/logging.rs:217` (pass).
  - `enqueue-timeout-guard` @ `src/osv/mod.rs`: 0 findings (pass).
  - `outbound-timeout-guard` @ `src/osv/batcher.rs`: 10 findings at 234, 329, 370, 413, 439, 483, 484, 509, 510, 549, and 179 absent (pass; `batcher.rs` untouched).
- C123 (`smtc callers --name get|get_all --callsites-matching '*AUTHORIZATION' --argument-index 0|1` over `src` and `crates/probation-policy/src`): one site in total, `src/managed/mod.rs:276` `headers.get(AUTHORIZATION)`.

# E2E follow-ups (on top of f311d6e)

## E1: cold `npm install` gets `503 OVERLOADED` past 8 concurrent downloads (not changed; decision needed)

- Root cause: `src/artifacts/download.rs` `transfer` takes `app.limits.download_permit()`. That call is `try_acquire_owned` on a semaphore of `max_artifact_downloads` permits (`src/http/limits.rs:71`), and when no permit is free it returns `DownloadError::Overloaded`, which becomes `503 OVERLOADED` with no `Retry-After`. The default is 8 (`SPEC.md` §4, `config.sample.toml`, `docs/operations.md`). npm 11's default `maxsockets` is 15 (`npm config get maxsockets`), so one cold install of a tree with more than 8 uncached tarballs exceeds the global cap on its own. npm retries a 503 only twice, after about 10 s and then up to 60 s (`fetch-retries=2`, `fetch-retry-mintimeout=10000`, `fetch-retry-maxtimeout=60000`), and a retry can collide again. yarn 1 defaults to `network-concurrency` 8.
- This is approved behaviour, not a bug:
  - `docs/plans/package-firewall-mvp/02-architecture.md` item 6 says overload is "refused, never queued without limit".
  - `04-slices.md` slice 8 says "Overload is refused with `503`, never queued", and its witness test is `overload_is_refused_not_queued`.
  - `03-program-design.md` describes `src/http/limits.rs` as "overload is refused, never queued".
  - The default of 8 is in SPEC §4.
  - `SPEC.md` §10 itself allows "semaphores and bounded queues; reject overload instead of allowing unbounded waiters".
- No code was changed. The options are in the report to the team lead.

## E2: yarn 1 gets an authentication error with the keys page's `.npmrc` lines

- Root cause: yarn 1.22.22 `NpmRegistry.request` (`lib/cli.js`, line 31739 in the corepack copy) attaches `Authorization` only when `this.token || isToRegistry && (alwaysAuth || this.isScopedPackage(packageIdent))`. For an unscoped package without `always-auth`, it sends no key at all, and the managed firewall answers 401. The `//host/npm/:_authToken` line is read (`getAuthByRegistry`), but it is never consulted for that request. yarn 1's npm config comes only from `.npmrc` files and `npm_config_*` environment variables, so `.yarnrc` cannot carry the setting.
- Probe: the real yarn 1.22.22 ran against a local stub that logs whether `Authorization` is present. The scratch dir was on disk next to the project and was deleted afterwards.
  - With the keys page lines, `yarn add left-pad` sent `GET /npm/left-pad auth=no`.
  - With `//host/npm/:always-auth=true` added, the same command sent `GET /npm/left-pad auth=yes`.
- Why not in the firewall: a request that carries no key cannot be authenticated, and serving it would break managed-mode authentication. yarn 1 does not retry with credentials after a 401. The fix therefore belongs in the snippet.
- Why a separate line instead of a change to the npm block: npm 11 warns on `always-auth` in either form ("Unknown project config "always-auth" … will stop working in the next major version of npm"), and npm does not need it. The npm block stays unchanged, which also keeps the e2e driver's `<pre>registry=` extraction intact. The keys page gets a "Using yarn 1? Also add to `.npmrc`" block with `//{{ host }}/npm/:always-auth=true`.
- Server code changed for this fix: `crates/probation-server/templates/keys.html`.
- Test: `crates/probation-server/tests/portal_places.rs` `t_portal_keys_create_once` now asserts `//fw.acme.test:8443/npm/:always-auth=true`.
  - Red: `the yarn 1 line: <!doctype html>…` (panicked at `portal_places.rs:730`).
  - Green: `test t_portal_keys_create_once ... ok`.
- Docs: `docs/portal-guide.md` (setup lines) and `docs/operations.md` (the yarn 1 row of the client table).
- Checks for this commit:
  - Workspace tests ran against a private Postgres (`PROBATION_SERVER_TEST_DATABASE_URL`): 713 passed, 1 failed, 21 ignored.
  - The one failure was `admin_fleet::t_sync_ranges`: "purged: 200 OK within one interval, still 403 Forbidden". It asserts a firewall sees a range purge within one 2 s interval, measured by wall clock. It passed 3/3 alone and in its whole binary (29/29), and it touches no file this commit changed. The failure is that 2 s wall-clock bound being missed under the full parallel run, so it is reported here and was not changed.
  - fmt and clippy `-D warnings`: clean.

# Review round on f311d6e

## R1: F3 completion (lookup and layers)

- Root cause: `src/managed/client.rs` `call` mapped a `200` body that fails to decode to `CallError::Unreachable`, for both `lookup` and `layers`. `Managed::after_answer` cleared `sync_error`, then called `fetch_layers`, and skipped `rebuild` without a word when that failed. So a newer server's layer (a new `Block` variant, say) was never applied, the old layer kept serving, the firewall looked healthy, and nothing was reported.
- Fix:
  - `CallError::Unreadable` covers a 2xx that does not decode.
  - `Managed::failed` maps it to `note_unreadable()` plus `note_server_down()`, then `Failed::Unreachable`. A key never seen gets `401`, an expired entry is served stale, and a stale layer stays in use (C19).
  - `Managed::note_unreadable` is shared with the `changes` path. It logs at error level with the firewall version and stores the text in a new `version_skew` field.
  - `after_answer` clears `version_skew` before its `layers` call, and that call sets the field again when the answer is unreadable. A readable `changes` answer therefore clears it, but a layers failure in the same round does not get wiped.
- Tests (`tests/managed_sync.rs`, using the new fake hook `FakeSyncServer::answer_raw(route, body)`):
  - `t_sync_unreadable_layers`: unknown `Block` variant `Quarantine` after a block edit of Acme's layer.
    - Red: `layers: FirewallReport { … last_apply_error: None, … }`.
    - Green: the error is reported with `failed_revision` 0. Readiness stays 200, `left-pad` is still 200 under the stale layer, it is `403 BLOCKED` once the layer is readable, and the error clears.
  - `t_sync_unreadable_lookup`: unknown `KeyLookup` status `quarantined`.
    - Red: `lookup: FirewallReport { … last_apply_error: None, … }`.
    - Green: the never-seen key gets 401, the error is reported, readiness stays 200, and the key is 200 once lookups are readable.

## R2: an unreadable answer keeps the firewall ready (user decision 2026-10-23)

- The `changes` path no longer calls `note_unreachable(Some(..))`, which had set `sync_error` and so failed readiness. It now calls `note_unreadable()` and `note_unreachable(None)` and re-queues the batch. `healthy()` reads `sync_error` only, and `report()` reads `version_skew` as well.
- `t_sync_unreadable_answer` was rewritten.
  - Red against f311d6e: `still ready, left: 503, right: 200`.
  - Green: readiness stays 200, the key is still served, the skew error is reported, and it clears after readable answers.
- Docs:
  - `SPEC.md` §10 and the §11 `/health/ready` row.
  - `docs/operations.md`: the alert table row ("Alert on this line"), the `/health/ready` row, and a new item under "Mixed versions" in section 5.

## R3: F2 final flush ignored `Ok(Synced::BatchRejected)`

- Fix: `!matches!(result, Ok(Synced::Applied))` logs the warning, and a `BatchRejected` result also goes to `count_rejected(batch)`. The count is held only in memory, so after the process exits it is not observable.
- Test: `t_activity_flush_refused_on_stop` queues 7 events, makes the server answer `413`, then stops the firewall.
  - Red: `lines_containing_all(["could not be delivered", "events=7"])` was 0, expected 1.
  - Green: ok.

## R4: a version-skew error never halts a settings rollout

- The server's S7-14 rule (`crates/probation-server/src/fleet.rs` `settle`) fails a step when `failed_revision` is absent or equals the rollout id. Rollout ids are `GENERATED ALWAYS AS IDENTITY` and so are ≥ 1.
- `report()` resolves the error in this order: a real apply or sync error, with its own `failed_revision`, as before; otherwise the version-skew text with `failed_revision: Some(0)`. Revision 0 is the no-push revision, which no rollout has, so the step is never failed for it and the fleet page still shows the text.
- No server change was needed. `assert_skew_reported` asserts `failed_revision == Some(0)` in all three F3 tests.

## Checks for this round

- `cargo test -j 16 --workspace --no-fail-fast -- --test-threads=16`, with `PROBATION_SERVER_TEST_DATABASE_URL` set to a private podman Postgres on 127.0.0.1:55438: 717 passed, 0 failed, 21 ignored.
- `cargo clippy -j 16 --workspace --all-targets --all-features -- -D warnings`: clean. `cargo fmt --all -- --check`: clean.
- `router molecule-verify --plan-root docs/plans/management-server`: PASS 12/12.
- SMTC analyzers:
  - client-data @ `src`: 0.
  - consumer-identity @ `src`: 1, at `src/http/logging.rs:217`.
  - enqueue @ `src/osv/mod.rs`: 0.
  - outbound @ `src/osv/batcher.rs`: 10, at 234, 329, 370, 413, 439, 483, 484, 509, 510, 549.
  - All four hold.
- C123: one site, `src/managed/mod.rs:281` `headers.get(AUTHORIZATION)`. It is the same call; it moved 5 lines because of the new `version_skew` field.
