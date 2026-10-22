# Research: Cargo workspace packaging and publishing on Cargo 1.96

Source: sf-research, 2026-10-21. Verdict: ANSWERED. Decision served: C117 (how `probation-policy` and `probation` are published).

## Answers
1. **`cargo package --workspace`** has existed as a flag since Cargo 1.56. Since 1.90 (PR #15636), packaging and verifying crates that depend on each other is stable. In 1.96, Cargo packages the crates in dependency order and verifies each one against a temporary local registry that overlays crates.io. So `probation` verify-builds against the locally packaged `probation-policy`, which does not need to be on crates.io yet.
   - Source: Cargo CHANGELOG, "Cargo 1.90 (2025-09-18)".
   - Source: rust-1.96.0 `src/cargo/ops/cargo_package/mod.rs` (`needs_local_reg`, TmpRegistry "overlay our new packages on the upstream registry", "Packages need to be created in dependency order").
2. **`cargo publish --workspace`** is stable since 1.90. In 1.96 the publish loop uploads only crates whose dependencies are already confirmed in the index. It then polls the index, with `publish.timeout` defaulting to 60 s, before it unblocks the dependents. A timeout stops the command with "unable to publish ... due to a timeout". Publishing is not atomic.
   - Source: CHANGELOG 1.90, "Stabilize multi-package publishing".
   - Source: rust-1.96.0 `src/cargo/ops/registry/publish.rs` (`take_ready`, `wait_for_any_publish_confirmation`, `mark_confirmed`).
3. **`publish = false` members:**
   - `cargo publish --workspace` skips them (PR #15525).
   - `cargo package --workspace` still packages and verifies them, but leaves them out of the overlay. `--exclude probation-server` avoids this.
   - Source: rust-1.96.0 `publish.rs` (partition on `publish() == Some(vec![])`).
   - Source: rust-1.96.0 `cargo_package/mod.rs` ("This allows packaging unpublishable packages").
4. **Sequential alternative:** `cargo publish -p probation-policy`, then `cargo publish -p probation`. `cargo publish` has blocked until the package appears in the index since 1.66 (CHANGELOG 1.66). `publish.timeout` is still unstable (`-Zpublish-timeout`), so on stable the wait stays at 60 s.

## Caveats
- Cargo 1.97 fixed a "false deadlock" internal error in workspace publish that was a regression in 1.96 (CHANGELOG 1.97, #17094; issue #17028, a 25-crate workspace).
  - The researcher read the 1.96 loop. The error needs two or more packages waiting for confirmation at once, and a single chain (`probation-policy` -> `probation`) never has more than one waiting. This is a reading of the code, not a maintainer statement.
- If the 60 s index wait times out after `probation-policy` is uploaded, finish with `cargo publish -p probation`. Do not run `--workspace` again: a user on #15636 reports that a repeated `--workspace` run aborts on a crate that already exists.

## Use in the plan
The release job runs `cargo package --workspace --exclude probation-server --locked`, then `cargo publish --workspace --locked --no-verify`, and documents the timeout recovery in docs/operations.md.
- Slice 1 checks `cargo package --workspace --locked`; `probation-server` does not exist yet.
- From slice 4, the check uses `--exclude probation-server`.
