# Slice 25 security review (uncommitted tree on 208f8cd, branch slice5-native-ci)

Method: static read of every file in scope plus one staging run of `install-service.sh uninstall --root` in an on-disk scratch dir (deleted). AGENT.md at `lf-start/agents/security-review/` does not exist on this host; the review followed the brief. Not executed: any installer against a real /etc, /usr or user unit; macOS, Windows and CI behaviour (read only). Action SHAs of the three new third-party actions (setup-go, setup-dotnet, setup-ruby) were checked against the GitHub API and match their tag comments.

## Verdicts on the brief's questions (no finding)
- Second owner: `store::lock` is `flock`/LockFileEx on `<data_dir>/lock`, `try_lock`, released by the kernel on SIGKILL. No stale lock, no state corruption. A second *service name* aimed at the same data dir is refused at runtime and then restart-loops (see S25-L3).
- Secrets in argv/logs: none. Config path only on the command line; config holds `token_file` path, not the token.
- CI triggers: `native-service.yml` is `workflow_call`/`workflow_dispatch` only, `contents: read`, no `secrets:` passed, `persist-credentials: false`, every action pinned by SHA. No `pull_request_target`. Release gating is sound: `build` needs `native-service` and `build-windows`; `release` needs `build`; `publish`/`images` need `release`.
- Docker lane: unix socket only, no TCP listener, archive verified by pinned sha256 before extraction, `mktemp -d` trap safe. The daemon is rootful (not rootless) and the socket is `chmod 666` on a disposable GitHub-hosted runner: acceptable there, would be root-equivalent for every local user on any other host (S25-I1).
- `osv/matches.rs`: atomic temp+rename kept; see S25-L5 for the permission-equivalence gap.
- Unquoted Windows service path: it is quoted (`install-service.ps1:103`). Account is the virtual account `NT SERVICE\Probation`, no password: good.

## Findings

### S25-H1 HIGH: Windows ProgramData pre-creation / junction hijack, then admin-run icacls and uninstall act on attacker-controlled paths
- `scripts/install-service.ps1:177` (`New-Item -Force` of ConfigDir/DataDir/LogDir under `C:\ProgramData\Probation`), `:72` (keeps an existing config.toml), `:56-64,186` (ACLs applied only after the service is registered), `:213-221` (uninstall deletes whatever the manifest lists).
- `C:\ProgramData` lets ordinary users create subfolders. Scenario: a non-admin user creates `C:\ProgramData\Probation\config\config.toml` (they own the parent) before the admin installs. The installer prints "Keeping the existing config.toml"; the service then runs the attacker's policy (upstreams, blocklist path, TLS, management URL). `icacls /inheritance:r` hardens only `config`; the attacker owns the parent `Probation` folder and can rename `config`/`data` away and drop in their own after install, so the swap survives. Variant: pre-create `data` as a junction to a protected directory: admin `icacls <junction> /inheritance:r /grant:r ...` rewrites the ACL of the target. Chain: a forged `.service-install-Probation` in the swapped config dir makes the next admin `uninstall` run `Remove-Item -LiteralPath <any path> -Force` as Administrator.
- Fix: create `C:\ProgramData\Probation` (the root) with the restricted ACL first (SYSTEM/Administrators full, service read) and set ACLs before writing any file; refuse if any of the three dirs or the root already exists with an owner other than Administrators/SYSTEM, or is a reparse point; in uninstall, accept only the exact paths the script computes (BinPath, its `.prev`, the manifest), never a free path read from the file.

### S25-M1 MEDIUM: macOS LaunchDaemon writes logs as root into a directory the unprivileged service owns (symlink attack)
- `install-service.sh:362-363` (LOG_DIR owned `_probation`, 750), `:180-181` (launchd opens `StandardOutPath`/`StandardErrorPath` as root), `:379-381` (newsyslog, runs as root, rotates `LOG_DIR/*.log`).
- A compromised `_probation` process replaces `probation.stdout.log` with a symlink (or hardlink) to a root-owned file. At the next launchd (re)start root opens/creates that target for append; newsyslog renames and chowns it to `_probation:_probation`. Arbitrary root-side file create/append, or ownership transfer of a chosen file to the service account.
- Fix: stdout/stderr and newsyslog files in a root-owned directory (launchd opens them as root, the service needs no write access there); keep only `decisions.ndjson` (written by the service itself, self-rotating) in the service-owned directory.

### S25-M2 MEDIUM: Windows release zip ships libcrypto DLL but the installer never installs it; the fallback is a PATH/DLL-planting vector
- `release.yml` build-windows (`cp "$RUNNER_TEMP"/openssl-shim/libcrypto-3*.dll`), `install-service.ps1:89-100` copies only `probation.exe` to `Program Files\Probation`. CI hides it because `openssl-setup.mjs` adds the shim dir to PATH (`native-service.yml` service-windows).
- Installed service cannot find the DLL (fails to start) unless an operator "fixes" it by putting an OpenSSL directory on the machine PATH; any PATH directory writable by Users then plants `libcrypto-3-x64.dll` and runs code as `NT SERVICE\Probation` (holds the data dir and token). The shipped DLL is also whatever OpenSSL the runner image carried: unpinned, unhashed.
- Fix: copy the DLL next to the exe in BinDir (admin-only ACL), record it in the manifest, pin and hash-check the OpenSSL version used for the release, or link OpenSSL statically/vendored.

### S25-M3 MEDIUM: macOS release binary dynamically links Homebrew libcrypto at an absolute, user-writable path (library hijack)
- `release.yml` build (macOS targets: `openssl-setup.mjs apply`, `-L native=$(brew --prefix openssl@3)/lib`), `src/managed/enterprise_certificate.rs:227` `#[link(name = "crypto")]`.
- The binary records `/opt/homebrew/opt/openssl@3/...` (or `/usr/local/...` on Intel), directories owned by the installing admin user, not root. Any process running as an admin user can swap that dylib and gets code execution as `_probation` at the next daemon start (state, token). It also fails to start when the user lacks that exact Homebrew formula. `brew install openssl@3` in CI is unpinned.
- Fix: static/vendored OpenSSL (or aws-lc symbols already in the tree) for the release; otherwise bundle the dylib beside the binary with `@loader_path`, root-owned, pinned and hashed.

### S25-M4 MEDIUM: `install-local.sh` makes machine-wide npm/pip config world-readable (credentials preserved but exposed) and leaves state user-owned on abort
- `install-local.sh:256` (`install -m 644 ... "$NPMRC"`), `:297` (`install -m 644 ... "$PIP_CONF"`): an existing root-0600 npmrc with `_authToken`, or a pip.conf with `index-url=https://user:pass@...`, is rewritten byte-for-byte but at mode 0644. The brief's "credentials preserved, not made world-readable" is not met.
- `install-local.sh:154` chowns existing `$ETC_DIR` and `$DATA_DIR` recursively to the login user, final chown back only at `:347-352`; the script is `set -euo pipefail` with no `trap`. Any failure in between (check-config at the "Validating" step, npm/pip step) leaves config, blocklist, TLS key and the cache/state of an already running service owned by the login user, so code as that user (a postinstall script, the threat the script's own comment names) can rewrite policy or replace cached tarballs. The re-run-keeps-existing change (`:171-175`, `:215-243`) makes this path common.
- `:402-424` unconditionally overwrites `/etc/systemd/system/probation.service`, replacing a hardened unit from `install-service.sh` with one that has only `NoNewPrivileges` and `UMask`.
- Fix: preserve mode (`stat -c %a` of the existing file, `install -m "$mode"`), and never widen; `trap` to restore ownership on exit or chown only files the script creates; refuse to overwrite a unit recorded in an `install-service` manifest.

### S25-M5 MEDIUM: uninstall trusts free paths in the manifest, no containment under owned locations
- `install-service.sh:415-421`: `rm -f "$(at "$path")" "$(at "$path").prev"` for every `file:` line; `at()` only prefixes `--root`, so `/../..` components are not rejected (staging run printed `Removed /../../../victim/file2`; root containment is by inspection, not demonstrated). With `--config-dir` in a location another user can write, or a hostile package, `sudo install-service.sh uninstall` deletes arbitrary files as root. Default `/etc/probation` is root:750, so exposure needs an operator-chosen directory; same pattern as H1 on Windows (`:213-221`).
- Also `record` runs even for files the script did not create: a pre-existing identical `/usr/local/bin/probation` (`:256,262`), `/etc/systemd/journald@NS.conf` (`:373-374`, overwritten with `>`) and `/etc/newsyslog.d/NAME.conf` (`:381`) are recorded, then deleted on uninstall.
- Fix: in uninstall, compare each path to the exact set the script computes and refuse anything with `..` or not absolute; record only files created by this run; create with `set -o noclobber`/`install` after an existence check.

### S25-M6 MEDIUM (defense in depth): systemd unit hardening is partial
- `deploy/probation.service:9-34` has User, UMask=0077, StateDirectoryMode=0700, NoNewPrivileges, ProtectSystem=strict, ProtectHome, PrivateTmp. Missing: `CapabilityBoundingSet=` (empty; loopback port > 1024 needs none), `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, `ProtectKernelTunables/Modules/ControlGroups/Clock/Hostname`, `PrivateDevices`, `LockPersonality`, `RestrictSUIDSGID`, `RestrictNamespaces`, `SystemCallFilter=@system-service`, `ProtectProc=invisible`, `RemoveIPC`. The service parses untrusted registry responses, so an RCE currently has every capability the User has plus raw sockets of the user.
- User scope (`install-service.sh:137`) strips ProtectSystem/ProtectHome/PrivateTmp too; at least the capability and kernel-protection directives work in a user manager.
- ReadWritePaths for a non-default data dir (`:141-144`) is correct but ProtectHome=yes makes any dir under /home unusable: functional only.

### S25-L1 LOW: restart loop is effectively unbounded on Linux
- `deploy/probation.service:19-20`: `Restart=on-failure`, `RestartSec=2`, no `StartLimitIntervalSec/Burst`. Defaults (10 s / 5) are borderline at 2 s spacing and are often disabled by distro settings. A bad config (`ExecStartPre` fails), a held lock or a policy server that keeps pushing settings restarts the process every ~2 s plus startup, forever, with log and CPU amplification. exit 75 and a crash are indistinguishable to systemd. Fix: set `StartLimitIntervalSec=60`, `StartLimitBurst=10` (or `RestartSteps/RestartMaxDelaySec`); `exit 75` could use `RestartForceExitStatus`/`SuccessExitStatus` handling so only real failures count. macOS (ThrottleInterval 5) and Windows (5 s, 5 s, 60 s repeating) are bounded in effect; Windows applies the 60 s delay to the third and later settings pushes within 24 h (availability, fail-closed).

### S25-L2 LOW: Windows install leaves a LocalSystem service on partial failure
- `install-service.ps1:104-110,185-186`: `New-Service` creates the service as LocalSystem, Automatic; if `sc config obj=`, `sidtype` or `Set-Acls` fails, the script throws and the service stays registered, as LocalSystem if `obj=` failed, with weak ACLs on config until the next boot starts it. Fix: register with `-StartupType Disabled`, switch the account, set ACLs, then set Automatic; delete the service in a catch.

### S25-L3 LOW: installer input and name collision hygiene
- `--service-user` is unvalidated (`:63`) and goes into `chown`, `useradd`, dscl and a plist; paths with `&`, `\`, `%` or XML metacharacters are substituted unescaped into the unit (awk `gsub` replacement, `-v` backslash processing) and the plist (`:150-185`); `--public-url`, `--listen` and `--tls-*` go into TOML via awk with no quote check (`:233-243`); PS `-Listen` is used in a regex replacement (`install-service.ps1:75-81`). Only operator-supplied, so no privilege crossing unless a wrapper forwards untrusted values; validate with `case` patterns.
- `--root /` becomes ROOT="" and runs as an unstaged install (`:67`).
- No refusal when two names share one `--data-dir`: the second restart-loops on the lock (L1).
- Existing `config.toml` is `chown root:svc; chmod 640` on every install (`:366`) even though "never replaces/touches" is advertised; widening 600 to 640 for the service group.
- Non-loopback `--listen` without TLS is accepted silently (`:226-233`).
- `default_binary` falls back to `command -v probation` and installs whatever PATH names as root-owned `/usr/local/bin/probation` (`:342-345`); macOS `sudo` keeps the user's PATH. A binary supplied without a hash or signature check: release `.sha256` files are same-origin (no signature, attestation or cosign), and the installer never verifies them.

### S25-L4 LOW: Windows package-tool edits follow attacker-controlled files
- `install-service.ps1:130-165` (`-ConfigureTools`): `Set-Content` into `ProgramData\pip\pip.ini` and npm's global config, both in locations where Users can pre-create the file; admin writes through hardlinks/symlinks (arbitrary overwrite with partly controlled text), rewrite is not atomic, PS 5.1 `Set-Content` default encoding corrupts non-ASCII credential URLs, and `npm` is resolved through the elevated shell's PATH. Credential lines survive (good) but not their file permissions on a fresh write.
- `install-local.sh:288-289` drops a user's own `cert =` line from pip `[global]` when the instance cert is trusted (data loss, not exposure).

### S25-L5 LOW: `osv/matches.rs` `write_atomic`
- `delivery::owner_only` is a no-op on non-Unix (`src/delivery/mod.rs:515-516`): on Windows the file is exactly as private as the directory ACL. `install-service.ps1` restricts the data dir, but a hand-run service with `data_dir` under a world-readable path leaves the matches file readable by Users (names of matched packages). Doc comment claims equivalence; it is conditional. `OpenOptions::create(true)` instead of `create_new(true)` on the temp name follows a pre-planted symlink on Unix if the directory is not private (pre-existing). `sync_directory` no-op on Windows loses the directory fsync (durability only).

### S25-I1 INFO
- `docker-engine.sh:37`: rootful dockerd on a hosted runner with `chmod 666 /var/run/docker.sock`, and the sha256 was recorded from the first download (trust on first use, vendor publishes none). Do not reuse the script on a non-ephemeral host.
- `release.yml` Package steps interpolate `${{ github.ref_name }}` into shell (existing in `build`, copied into `build-windows`); only a tag pusher can inject, and that person can already release. Set it through `env:` instead.
- `setup-go` caches by default in the release gate; a cache written by a `workflow_dispatch` run on the default branch is readable by tag runs. Gate-only, not the shipped artifact (the artifact is built in `build`).
- The tested binary (`target/debug` in `native-service`) is not the shipped one (`--release`); the gate proves the lifecycle, not the artifact.
- `native-service.yml` Linux step runs the repo's harness and `npm ci` output as root via `sudo -E`; acceptable on a disposable runner.
