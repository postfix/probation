# Windows port: `probation` binary and `probation-server` crate

Goal: compile for `x86_64-pc-windows-*` with Unix behaviour unchanged. Nothing was run on real Windows.

| Change | File | Check |
|---|---|---|
| Shutdown signals: Unix keeps SIGINT/SIGTERM; Windows listens for Ctrl+C, Ctrl+Break, console close, shutdown (`tokio::signal::windows`) | `src/main.rs` (`ShutdownSignals`) | windows-gnu check; Linux `serve_signals` test (3 passed) |
| Same for the server; `StopRequests` replaces the two `Signal`s in `serve` | `crates/probation-server/src/lib.rs` | windows-gnu check; `probation-server --lib` (12 passed) |
| Service-key `0o077` check runs under `cfg(unix)` only. On Windows only `is_file` is checked | `src/config.rs` | windows-gnu check; `config_validation` (32 passed) |
| `owner_only(&mut std::fs::OpenOptions)`: `0o600` on Unix, no-op elsewhere. Used by the log-file probe, the file sink (via `tokio::fs::OpenOptions::from`) and the npm unpublish key | `src/delivery/mod.rs`, `src/delivery/file.rs`, `src/http/unpublish_reference.rs` | windows-gnu check; `decision_log_delivery` (36 passed); lib `config`/`delivery`/`unpublish` filter (18 passed) |
| "File readable by others" warning (`warn_if_shared`, `warned`) is `cfg(unix)` | `src/delivery/file.rs` | same |
| SIGXFSZ/`prlimit` torn-write test and its child are `cfg(unix)` | `src/delivery/file.rs` | `a_failed_write_leaves_no_torn_fragment` still passes on Linux |

## Windows ACL gap (not faked)

Windows has no mode bits. The service-key file check and the decision-log "shared file" warning do nothing there, and new files (decision log, `npm-unpublish.key`) inherit the parent directory's ACL. The operator must restrict the ACL of the service key file, the data directory and the log directory to the service account. A real ACL check is future work.

## Not changed

`crates/probation-server/tests/admin_fleet.rs` `data_dir = "/tmp"` is a TOML string that the server must refuse; it never touches the filesystem, so it needs no tempdir.

## Compile check

`cargo check --target x86_64-pc-windows-gnu -p probation -p probation-server` passes for `--lib --bins`, for `--profile test --lib --bins` (unit tests) and for `probation-server --tests`. `x86_64-pc-windows-gnu` std was added with `rustup target add`; the MSVC target is not installed and was not used. Build scripts needed `windres` (turso_sdk_kit), supplied by a symlink to `x86_64-w64-mingw32-windres` on PATH.

## Still unverified / remaining blockers

- MSVC linking, runtime behaviour and the console-event handlers were not run on Windows.

## Integration tests gated for Windows

`cargo check --tests --target x86_64-pc-windows-gnu -p probation` now passes with no warnings. Only attributes and `cfg` blocks were added; no assertion changed on Unix (`git diff --numstat` shows 0 deleted lines; `service_policy_cache.rs` is untracked, and its one block was re-indented inside `#[cfg(unix)]`). Linux, after: content_store 12, decision_log_delivery 36, managed_sync 41, persistence_content 5, serve_signals 3, service_policy_cache 6, storage_health 10, all passed. Before-counts were measured only for decision_log_delivery (36) and serve_signals (3); the rest are unchanged by construction, since `cfg(unix)` is true on Linux.

Excluded on Windows (`#[cfg(unix)]`):

| File | Test | Why |
|---|---|---|
| serve_signals | `a_sigterm_during_startup_is_caught`, `a_sigint_once_listening_shuts_down_gracefully` | send POSIX signals with `kill`; `ExitStatusExt::signal` |
| content_store | `every_publication_outcome_leaves_tmp_empty`, `the_probe_fails_while_objects_refuses_writes`, `a_write_the_disk_refuses_fails_the_publication`, `an_unreadable_object_at_the_path_is_replaced`, `an_eviction_the_filesystem_refuses_keeps_the_file` | chmod to inject faults; `/dev/full` symlink |
| persistence_content | `file_sync_order_holds`, `disk_full_is_a_503_not_a_policy_relaxation`, and the helper for the directory-sync fault | chmod fault injection; `/dev/null` symlink |
| service_policy_cache | `refusal_remains_closed_when_storage_fails_during_the_request` | makes the data dir read-only with `0o555` |
| decision_log_delivery | `tp17_log_file_mode_is_0600`, `a_non_utf8_credential_refuses_to_start` | mode bits; `OsStrExt::from_bytes` (non-UTF-8 env value) |

Partly gated (rest runs on Windows):
- `service_policy_cache::explicit_service_policy_config_accepts_private_key_and_refuses_unsafe_binding`: the chmod and the "shared-readable key refused" assertion are Unix-only (no ACL check on Windows, see above).
- `managed_sync::t_settings_push_allowlist`: the symlink case `link.ndjson` is Unix-only.
- `storage_health` needed no change (already `cfg(target_os = "linux")`).
