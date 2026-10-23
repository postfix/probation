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
