# TDD record, slice 25 (machine-wide native lifecycle and native package-tool execution on three OSes)

Procedure: /home/john/.claude/skills/lf-start/agents/implement/AGENT.md (red, then green, one behavior at a time). Inputs read: 00-status.md, 03-program-design.md ("Configuration, data and platform contract", "Exact native test baseline and runner topology", "Native acceptance and check ownership"), 04-slices.md row 25, evidence/spike-native-cluster.md and reviews/slice-29, evidence/slice-28.md, evidence/research-native-supervision.md, evidence/design-deployment-contract.md, evidence/slice-24.md (pattern only). 00-status, 03 and 04 are NOT edited.

Baseline: starting commit `208f8cde8ac9eee76390b99aab26ed7b50b4b048` on branch `slice5-native-ci`, working tree clean (`git status --short --untracked-files=all` empty). Nothing is committed.

Owned paths (the write allowlist, from the row): src/main.rs (+ src/lifecycle.rs, src/lib.rs one line, src/osv/matches.rs: the Unix-sensitive source), Cargo.toml/Cargo.lock (the pinned `windows-service` for Windows builds), deploy/probation.service, scripts/install-service.sh, scripts/install-service.ps1, scripts/install-local.sh (non-destructive repair), tests/e2e/native/ (the native harness helper), tests/e2e/scenarios/service-native.mjs, tests/e2e/README.md, .github/workflows/native-service.yml and release.yml (release packaging), docs/operations.md, CHANGELOG.md, tests/{lifecycle_plan,native_lifecycle,service_scripts,install_local}.rs, tests/oci_native.rs (the Docker Engine mode the row names). Two further files were touched with the reason recorded: src/http/service_connector.rs (a clippy `needless_update` that fails `cargo clippy --lib --bins -D warnings` with no features; one `#[allow]` and a comment) and tests/e2e/native/check_workflow.py + check_workflow.test.py (the release gate must now include the native-service lanes; mutations that quote release.yml text were updated to the new text, one rule and two mutations were added).

Seams: (1) the `probation` binary as a process (`serve`, `check-config`, signals, exit codes, the data-directory lock); (2) `scripts/install-service.sh` and `.ps1` as commands against a staging root (`--root`); (3) `probation::lifecycle::exit_plan`; (4) the host's own service manager through `native/service-lifecycle.mjs`; (5) the pinned Docker Engine daemon through `tests/oci_native.rs`.

## Cycles

tdd: osv::matches::write_atomic compiles on Windows — red: `error[E0433]: cannot find unix in os --> src/osv/matches.rs:157:18` (`cargo check --locked --target x86_64-pc-windows-gnu --bin probation`, a second error: no method `mode`) — green: the same command `Finished dev profile` (uses `delivery::owner_only` and `config::sync_directory`, so the owner-only mode on Unix and the documented no-op directory sync on Windows are kept, not cfg-gated away)

tdd: lifecycle_plan (3 tests: stop, settings restart exit 75 without `Stopped`, failure) — red: `error[E0432]: unresolved import probation::lifecycle ... could not find lifecycle in probation` — green: `cargo test --locked --test lifecycle_plan` 3 passed

tdd: windows service host (`probation service --config`, `windows-service` 0.8.1, src/main.rs `windows_service_host`) — red not observed (a Windows service cannot be run on this Linux host); verified by `cargo check` and `cargo clippy -D warnings --target x86_64-pc-windows-gnu --lib --bins`, both clean. NOT a behavioral pass: see Lanes.

tdd: serve refactor (`serve(config, stop, ready) -> StopOutcome`, `finish`) — red not observed (behavior-preserving); `cargo test --locked --test serve_signals` 3 passed after the change, and `native_lifecycle` 5 passed.

tdd: native_lifecycle (5 tests on the real binary: SIGTERM exit 0, second owner refused with the first still serving, SIGKILL then restart on the same state, 0700 data dir and nothing group/other accessible under umask 0077, non-loopback address refused) — red not observed (they pin behavior that already existed: `store::lock`, the signal handlers, the loopback default); they bite, shown by mutations M1, M2, M9 below.

tdd: service_scripts (12 tests: files and modes, the generated unit is deploy/probation.service, nothing existing replaced, second owner refused, upgrade changes binary and definition only, upgrade without install or config refused, uninstall keeps config and data, foreign binary kept, custom data dir, user scope, supervision contract, launchd plist keys parsed with python plistlib, systemd-analyze verify) — red not observed as a separate run (script and test were written in one pass); they bite, shown by M3, M4, M5. Real defect found by them later: an edit left a bare `X ||` in `do_upgrade` (it executed /usr/lib/xorg/Xorg.wrap), two upgrade tests went red, fixed to `default_binary` + the original `[ -f ... ] || die`.

tdd: install_local (2 tests: first run keeps credentials, comments and unrelated settings and sets only registry/audit/index-url; second run replaces no config, blocklist, key or certificate) — red: `Unknown argument: --no-service` (the same tests against `git show HEAD:scripts/install-local.sh`; 2 failed) — green: `cargo test --locked --test install_local` 2 passed. The behavioral reds are M6.

tdd: service-lifecycle.test.mjs (41 assertions: command lines per OS, parsers, install-service.ps1 contract) — red not observed; bites by M7a, M7b.

tdd: oci_native Docker mode (`PROBATION_OCI_ENGINE=docker`) fails on this host's front end — red: `assertion left == right failed: the pinned Docker Engine is 29.9.2; this daemon is 5.4.2` (4 failed; `docker` here is podman 5.4.2) — green: against a real Docker Engine 29.9.2 daemon `4 passed`, including `DOCKER ENGINE WITNESS: version 29.9.2, api 1.56, platform Docker Engine - Community, os/arch linux/amd64`.

tdd: oci_native Docker mode is repeatable on a long-lived daemon — red: `the storage host never saw a credential: []` (a second run of the same lane on the same daemon: the daemon already held the layers, so no blob was fetched and the test proved nothing about the storage host) — green: each lane removes only the references it pulled (`DockerForget`); after one `docker image prune -a -f` of this private daemon, two consecutive `PROBATION_OCI_ENGINE=docker cargo test --locked --test oci_native -- --nocapture --test-threads=1` runs: `4 passed` each

tdd: E2E-service-native — red: `E2E FAIL E2E-service-native: ReferenceError: exit75 is not defined` (a half-applied refactor; run from the stack's first start) and, before the harness existed, `config.toml: invalid public_url: must use the https scheme` (the installer's first config had `http://`; the product requires https even for a plain-HTTP listener, so the installer now writes `https://localhost:<port>` and takes `--public-url`, `--tls-cert/--tls-key`) and `the stand-in's status is 75: 0` (read before the stand-in ran: the baseline of `NRestarts` is now taken first) — green: see the final run in slice-25.md.

tdd: release gate (check_workflow.py rule "release, publish and images transitively need native-service", mutations "release no longer gated by the native service lanes" and "native-service job removed") — red: `BYPASS (checker passed): release no longer gated by the native service lanes (slice 25)` (the first mutation removed `native-service` from `build` only while `build-windows` still carried it: the mutation was too weak; it now removes both) — green: `check_workflow.test: 162 bypasses all fail, known-good passes`.

## Mutation probes (each: backup with sha256, one edit, narrow test, restore in a SEPARATE command, sha256 verified)

| # | File | Mutation | Test | Result |
|---|---|---|---|---|
| M1 | src/store/lock.rs (orig sha256 31210a704007708f4c1a60bfed9ee8e9b8c6acbefa72de3077a393c1df343ef2; mutated b134f16105b25576948398bfbfca725209af56ff492037c33a72b35b0a8413fe) | the lock never refuses | native_lifecycle a_second_instance | RED: `the second instance on a held data directory was not refused: it was still running after 30 s`; restored, sha256 equal |
| M2 | src/main.rs (orig 25c648f70533135fa6a8a667230603c3f59a3d9791de6743c7db1122be7cce91; mutated 099f47c9811a194aad6a2c48203ad4f72770a37d8e35c5342ef1a98bc5c694d4) | exit code always 0 | native_lifecycle a_second_instance | RED: `left: Some(0) right: Some(1)`; restored, equal |
| M9 | src/main.rs (mutated 27eefadcf4845024115c80b8c9cdb7e45b4beb2a4eea77664e728eb09a30596d) | SIGTERM never resolves | native_lifecycle a_sigterm | RED: `the process did not exit within 40s`; restored, equal |
| M2b | src/lifecycle.rs (orig 2a29b5282eaec7fda922a1a04baca6db5f636564ede8a1609ac9f960126e3b1e; mutated 498c8c9ae6945f5d625bf25db92111fb9bdad564a38c566d44498299b3f7686d) | settings restart reported as Stopped | lifecycle_plan | RED: `left: ExitPlan { code: 75, report_stopped: true }`; restored, equal |
| M3 | deploy/probation.service (orig f41b953d02b0c2515c6cd492d04f8283b825e4e50377a396a6bc35f89254a9c4; mutated 332660bc80fda4ff1401b43d06f7f0c17bf72ecb7a0b5887b8ce0d3bd1307ba5) | `Restart=always` | service_scripts | RED in the_unit_carries_the_supervision_contract and a_user_scope_unit (two more failures in that run were the unrelated `X ||` defect above, found right after and fixed); restored, equal |
| M4 | scripts/install-service.sh (orig 11be77beff6d02744f48eb76f8bc61e8ec012fd1d23296fccfc386e23269dea5; mutated 4a38f182a3751456a31e992a75a44bc8450e8aaaf6e6375e9dad88f816b755c0) | an install overwrites config.toml | service_scripts | RED: an_install_never_replaces_existing_config_blocklist_tls_material_or_data; restored, equal |
| M5 | scripts/install-service.sh (mutated eb14870bc9f248e1e53f1f1a2a5a8ffbbbae95064d4b724c03575c25cf0c7ee4) | uninstall removes config | service_scripts | RED: an_uninstall_removes_what_install_recorded_and_keeps_config_and_data; restored, equal |
| M6 | scripts/install-local.sh (orig 168a536d89519dde4c72dfe012a951f3ea26daaaab2ced4738d7546f03fbf670; mutated 859b13c2ba989cb34d12cba71fff4233e4a5a2b600758b9a61d19813763ce364) | config.toml guard removed | install_local | RED: a_second_run_over_an_existing_install...; restored, equal |
| M7a | scripts/install-service.ps1 (orig 54a32a1c9f38da7fd067b95ff8c022ca06c348915470374edf7a2501b1f81c6d; mutated 770e7195b898cffd06e3b032717705a298a0c4d294fd5f73e74f1892f11b59fc) | restart delay 500 ms | service-lifecycle.test.mjs | RED: `install-service.ps1 has restart/5000/restart/5000/restart/60000`; restored, equal |
| M7b | tests/e2e/native/service-lifecycle.mjs (orig 6c649f1c3407902deb511cd1b065a0d6faef1399a655e2c0dfe4b3857ebedb63; mutated b305c13820c14a6f8dcddb14c3c5e8daabd700f4c3d449cf2e16e5f22bc38c9f) | macOS stop is `launchctl kill` instead of an unload | service-lifecycle.test.mjs | RED: deepEqual; restored, equal |

Process lessons recorded: (a) the first M1 run had no deadline on the second instance, so with the lock gone the test hung until the 600 s cap and the task was stopped; the test now kills the second instance after 30 s and fails by name. No process was left behind (`pgrep` empty). (b) The first restore used `shutil.copy2`, which keeps the old mtime, so cargo kept the mutated build and a later green run was really still mutated; found when a good run failed, fixed by `touch` and a restore with a fresh mtime. Every result above is from after that fix (M1 was run again).

## Fix round cycles (after the code and security reviews)

tdd: lifecycle_plan an_unclean_shutdown_after_an_operator_stop_is_still_reported_stopped — red: `error[E0425]: cannot find function after_shutdown in module probation::lifecycle` — green: `cargo test --test lifecycle_plan` 4 passed

tdd: service_log (3 tests: size bound with newest event kept, an event over the bound cut, reopen appends) — red: `unresolved import probation::service_log`; then a REAL red from the first version of the test: `the newest event is in the live file: 199}` (writeln! issues two writes and a rotation fell between them: the tracing formatter issues one write per event, the test now does too) — green: `service_log` 3 passed

tdd: key_acl (5 tests on the SDDL parser) — red: `unresolved import probation::key_acl` — green: 5 passed; the Windows DACL reader is `cfg(windows)`: `cargo check` and `cargo clippy -D warnings --target x86_64-pc-windows-gnu --lib --bins` clean (not run on Windows)

tdd: service_scripts the_system_unit_is_sandboxed_and_its_exposure_is_bounded — red not observed (the unit was edited first); `systemd-analyze security --offline` reported `exposure level 1.2`; the user-scope lane then gave a real red: `status=218/CAPABILITIES ... Failed to drop capabilities: Operation not permitted` for `CapabilityBoundingSet=` in a user unit, fixed by dropping the capability directives from the user variant and asserting it (`the_user_scope_unit_keeps_the_directives_a_user_manager_can_apply`)

tdd: service_scripts containment and arguments (a_forged_install_record..., files_that_were_already_there..., unsafe_arguments..., a_certificate_the_system_unit_cannot_see..., an_existing_config_keeps_its_mode..., the_launchd_log_files_sit_in_a_root_owned_directory..., the_release_attestation..., the_release_package_has_one_layout...) — red: the first run of the rewritten script failed 10 existing tests with `--listen: '127.0.0.1:8080' has a character outside the URL alphabet` (a bash bracket-expression slip in `safe_text`), fixed; the new tests are red not observed as separate runs; they bite, shown by the mutation table below

tdd: service_scripts an_upgrade_to_a_binary_that_validates_but_does_not_start_is_rolled_back (REAL `systemd --user`, stand-in binary that accepts check-config and exits 1) — red not observed before the fix existed; mutation Mp2 below shows it red when the rollback restores nothing — green: the previous binary is back byte for byte and the service is `active`

tdd: install_local an_existing_credential_file_is_never_widened_by_the_rewrite — red not observed (new behavior written with the test); 0600 npmrc stays 0600, 0640 pip.conf stays 0640, a new one is 0644

tdd: conan_native host mode (`PROBATION_NATIVE_HOST=1`) — red: `PROBATION_NATIVE_HOST=1 but conan does not run: No such file or directory` (no conan on the host: the lane fails loudly, never skips); then a real red: the host run hung until the 900 s cap because the recorder started with `&` in the script kept the output pipe open (in the podman image the container's exit killed it) — fixed with `trap 'kill $(jobs -p)' EXIT` — green: `PROBATION_NATIVE_HOST=1 cargo test --test conan_native` with conan 2.21.0 from a venv: `3 passed`. maven host mode: no mvn here, same loud failure, not executed

tdd: check_workflow native-service.yml rules and 9 mutations — red: `FAIL native-service.yml is not plain YAML: mapping values are not allowed here` (my own step name contained `: `, caught by the strict loader), then `FAIL ... pipes a command without pipefail ... [Environment]::OSVersion | Format-List` (a PowerShell step; the rule now exempts powershell/pwsh), then `BYPASS (checker passed): publish job no longer needs native (C6)` (the new attest job's `needs` text hid the old mutation's anchor: reworded) — green: `check_workflow.test: 171 bypasses all fail, known-good passes`

### Mutation probes of the fix round (sha256 of the original; restore in a separate command, verified)

| # | File | Mutation | Result |
|---|---|---|---|
| Mp1 | scripts/install-service.sh (8df7d0042b9938a89d44d96990b9a32d23d39e080eaeed0216a08906f0b696bb) | uninstall removes any path the record names | RED: a_forged_install_record... |
| Mp2 | scripts/install-service.sh (same original) | rollback restores nothing | RED: an_upgrade_to_a_binary_that_validates_but_does_not_start_is_rolled_back (6.5 s, real systemd --user) |
| Mp3 | src/lifecycle.rs (1278e08a91d2ea24461ec39c53e1c07c7bef8a7f2e5b41ac92703a56e0b196c4) | an unclean operator stop becomes a failure | RED: an_unclean_shutdown_after_an_operator_stop... |
| Mp4 | src/key_acl.rs (9112bd3a977862019554e2962b2ea2c62b1c2126bc06c67cc2174bd2a2408c8c) | Users accepted | RED: 2 of 5 tests |
| Mp5 | src/service_log.rs (5e2fbf4ef1eeaf7ecffa66c5b55d86ec5bd393496898d231d19313ba6fb04e55) | never rotates | RED: the_log_stays_within_its_bound... |

## Checks (final tree)

See evidence/slice-25.md, "Final checks", for every command and result.

## Recheck-1 cycles

tdd: key_acl private_violations / service_sid (4 new tests) — red: `unresolved imports probation::key_acl::{private_violations, service_sid}`; then a real red: `a_null_dacl_is_not_private` on `PNO_ACCESS_CONTROL: []` (the NULL-DACL check looked for the marker at the start of the flags only) — green: 9 passed; mutation (marker never matched) red
tdd: service_scripts release provenance (3 tests: refusal without gh/cosign/bundle, the pins, launchd health) — red: `a_release_package_without_...` first failed with `the release attestation ... does not verify`: this host has a real `/usr/bin/gh` on PATH (the test now builds a PATH without gh); mutations red: `--signer-workflow` removed, release marker ignored, launchd health made vacuous
tdd: service_scripts low ports / --bin-dir (2 tests) — red not observed (written with the change) — green: 29 passed
tdd: install_local abort restores ownership — red: my first assertion expected the LAST chown to hand back to root, but the trap's last call is the data directory to the service account (assertion corrected to check both); mutation (trap removed) red — green: 4 passed
tdd: check_workflow rules (static triplet, release builds carry the feature, id-token only on release/attest) — red: `FAIL openssl-setup.mjs must use the x64-windows-static-md vcpkg triplet only` against the file's own comment mentioning the plain triplet (comment reworded) — green: `check_workflow.test: 175 bypasses all fail`
tdd: service-lifecycle.test.mjs ps1 contract (SIDs, DACL reset, verification order, pins) — red not observed — green: ok (62 assertions)

Mutation probes (sha256 of the original; restored in a separate command, verified): install-service.sh a6b73f745960365b8e2f80397507385538c7f580b89513fa0b4c6893741763b3 (remove `--signer-workflow`: RED; release marker ignored: RED; launchd health vacuous: RED; one first attempt, `|| true; echo`, was an equivalent mutant because cosign refused anyway, and was replaced by the marker mutation); key_acl.rs 246cb9a8e3723c6f4152eb5eec404b435a3f38a304eb1fcf8606828bfc67e6c8 (NULL DACL marker: RED); install-local.sh 47b62340a4ca245aba0f92c347c1b80fd69f4a331d598464a5f95f82ab0d14b7 (no trap: RED).

## Recheck-2 cycles

tdd: key_acl allowed_for / service_name (2 tests) — red: `unresolved imports` of the two functions — green: 11 passed
tdd: service_scripts dev-package flag, path spellings, low port on upgrade, bundle naming — red: the first run of the spelling test failed with `--binary: ... has a '..' component` (the argument check refuses `..` before the provenance check; that spelling was dropped from the list), and `the_pins_given_to_gh_and_cosign...` red on `^https://github\.com//\.github/...` (the repository was empty: a nested-quote slip in the escaping, rewritten with a variable), then red on the symlink spelling (`canon_file` did not follow the link) — green: 33 passed
tdd: check_workflow bundle naming and draft rules — red: `BYPASS (checker passed): the bundle is named another way` (the mutation replaced only the first of two `--bundle` occurrences) — green after replacing all
tdd: service-lifecycle.test.mjs — red: `a pre-existing directory is judged with everything under it` (my needle spanned a comment line break) — green: 69 assertions
