# Running Probation

The operator handbook for both programs:

- `probation`, the firewall. It sits in front of npm and PyPI.
- `probation-server`, the management server. It holds API keys, organisations and
  their policy, and serves the self-service portal. You need it only for managed
  mode.

Start with the short [Overview](../README.md), [Install](install.md),
[Usage](usage.md), and [Troubleshooting](troubleshooting.md) guides. This file
keeps the detailed settings, limits, backup, restore, and release procedures.
How to set up the management server is in
[management-server.md](management-server.md); what the portal does for its users is in
[portal-guide.md](portal-guide.md).

Every claim here was checked against the code or measured on a real run. Section 12
lists every known gap in one place.

Every release after 0.2.2 is under the Elastic License 2.0 (`Elastic-2.0`).
Releases 0.1.0 to 0.2.2 stay under Apache-2.0. See [LICENSE](../LICENSE).

---

## 1. What this service is

One firewall process, one data folder. It withholds two kinds of release:

- anything published less than `cooldown_seconds` ago (default in the sample: 24
  hours)
- anything on a blocklist, or in the OSV vulnerability database (section 4)

It runs in one of two modes:

- **Standalone** (no `[management]` section): one set of rules for every client,
  from one local blocklist file.
- **Managed** (with `[management]`): every request carries an API key, and the
  firewall serves it under that key's policy. It fetches keys and policy from
  `probation-server` and caches them. The local blocklist file is ignored.

`npm` and `pip` still resolve dependencies themselves. The firewall only narrows
what they can resolve against, and verifies every file it hands back.

"Allowed through" means it passed these checks. It does not mean the package is
safe.

### What runs where

| Piece | Talks to | Notes |
| --- | --- | --- |
| `probation` (firewall) | npm, PyPI, `api.osv.dev`; in managed mode also the server | One data folder (`data_dir`). |
| `probation-server` | Postgres; with `[portal]` also your SMTP host, the sign-in providers and `leaked_password_url` | Sync API (`/api/v1/sync/…`), automation API (`/api/v1/blocklist/{layer}`), and the portal when `[portal]` is set. Keeps nothing on disk. Plain HTTP only. |
| Postgres 16 | — | Everything the server knows. Postgres 16 is the version tested. |
| Your TLS reverse proxy | the server, the firewalls | Required in front of the server. Required in front of firewalls for per-client rate limits (section 6). |

## 2. Installing and running

### Installing the firewall

Any one of:

- the archive for your platform from the GitHub release, checked against its
  `.sha256`
- `cargo install probation --locked`, which puts it in `~/.cargo/bin`
- `cargo build --release --locked` in a checkout of the release tag
- `scripts/build-install.sh [--engine docker|podman] [--prefix DIR]`: builds in a
  container and installs the binary (default `/usr/local/bin`), for a machine with
  no Rust toolchain
- the container image: `docker build -t probation .`

Building from source needs Rust 1.96.0, `cmake`, a C compiler and `perl`, because
one crypto library compiles from C. Running needs the system's CA certificates
(`ca-certificates`): with an empty trust store, every connection to npm and PyPI
fails. The `Dockerfile` handles both.

For a local machine, `scripts/install-local.sh` writes a config, a blocklist and
a TLS certificate, and points npm and pip at the result (section 6).

### Installing the management server

It is not on crates.io and not in the release archives. Build it from the
repository root:

```sh
docker build -f crates/probation-server/Dockerfile -t probation-server .
# or
cargo build --release --locked -p probation-server
```

The image runs `probation-server serve --config /etc/probation-server/config.toml`
as the non-root user `probation`. Mount your settings file there.

### Resetting the shared-service revision floor

A firewall in `[service_policy]` mode refuses a policy snapshot whose revision is older than
the one it holds (or equal with a different policy), and keeps its last good policy with
`/health/ready` showing it degraded. After you restore the policy server from a backup, roll
it back or fail over to an older replica, the server's revisions are lower than the floor the
firewall remembers. Clear only that floor:

```sh
probation reset-revision-floor --config /etc/probation/config.toml
```

- Run it as the user that owns `data_dir` (or root). It edits the saved envelope directly, so it works with the
  firewall stopped; with the firewall running it also leaves a `revision-floor-reset` marker the
  firewall consumes at the start of its next poll. The marker is harmless when no firewall runs.
- It never clears a refusal (a 401/403 on the snapshot route) and has no network trigger. The next valid
  snapshot sets the new floor.
- It logs one audit line with the previous floor and the invoking user (`SUDO_USER`, `USER`, `LOGNAME` or `USERNAME`, plus
  the process uid on Linux). That identity comes from the host's environment; it is an audit hint, not authentication.

### Check before you start

```sh
probation check-config /etc/probation/config.toml
probation check-blocklist /etc/probation/blocklist.json
```

Both stop at the first problem, report it, and write nothing. Run them in your
deploy pipeline before a restart: a restart onto a broken config is an outage.

- Run `check-config` with the same environment and user as `serve`. With
  `siem_url` set, it also refuses a `PROBATION_SIEM_AUTH` that `serve` would
  refuse. In managed mode it reads the token file, so that file must be readable.
- `check-config` reads only `config.toml`. It does not read the settings a push
  wrote to `<data_dir>/managed-settings.toml` (section 13).
- `check-blocklist` checks against the default size limit (128 MiB), not your
  `max_blocklist_bytes`.

The server has no check command. It checks its settings file when it starts and
refuses unknown keys.

### Firewall with Docker

```sh
docker build -t probation .
docker run --rm probation check-config /etc/probation/config.toml
docker run -d --name probation --restart unless-stopped \
  -p 127.0.0.1:8080:8080 \
  -v /srv/probation:/var/lib/probation \
  -v /etc/probation:/etc/probation:ro \
  probation serve --config /etc/probation/config.toml
```

The image ships with the sample config and sample blocklist. The build changes
one thing: it listens on `0.0.0.0:8080` instead of localhost, so the published
port is reachable. A `config.toml` you mount must do the same. Publish that port
only to your reverse proxy (section 6), never to a network.

The image runs as the user `firewall`. The data folder you mount must be writable
by it, and a token file readable by it. Find its uid with
`docker run --rm --entrypoint id probation firewall`.

The sample blocklist has a far-off expiry so the container starts. Replace it with
your real blocklist before relying on this.

### Firewall under systemd

`deploy/probation.service` is an example unit. It runs `check-config` before
every start, runs `serve` as the user `probation`, and sets:

- `Restart=on-failure` and `RestartSec=2`. A managed firewall needs this (below).
- `TimeoutStopSec=45`, longer than the 30-second drain (below).
- `StateDirectory=probation` (for `data_dir = "/var/lib/probation"`) and
  `LogsDirectory=probation` (for a `log_file_path` under `/var/log/probation/`).
- `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `NoNewPrivileges=yes`.

`scripts/install-local.sh` installs its own unit and gives the service its own
journal namespace: read it with `journalctl --namespace=probation -u probation`.

### Native service: Linux, macOS, Windows

A release package holds the binary, `config.sample.toml`, `blocklist.sample.json`, `deploy/` and the installer for its
OS (`install-service.sh` on Linux and macOS, `install-service.ps1` on Windows). Run it from the unpacked directory:

```
sudo ./install-service.sh install            # Linux (systemd) or macOS (LaunchDaemon)
sudo ./install-service.sh upgrade --binary ./probation
sudo ./install-service.sh uninstall
.\install-service.ps1 install                # Windows, from an elevated PowerShell
```

`--scope user` installs a service for the login that runs it (`systemd --user`, a LaunchAgent), for a developer machine.
Every flag is in `install-service.sh --help`.

What the installer guarantees:

- **First install creates only what is absent.** `config.toml` and `blocklist.json` come from the samples only when there
  is no file, with a loopback listener (`127.0.0.1:8080`, never widened by the installer). TLS material is never generated or
  replaced (`install-local.sh` makes a certificate; `--tls-cert/--tls-key` name an existing one). Package-manager settings
  (npm, pip: registry URLs and credential entries) are edited only by `install-local.sh` and `install-service.ps1
  -ConfigureTools`, and only the `registry`, `audit` and `index-url` lines they own; every other line stays as it was.
- **Upgrade changes the binary and the service definition and nothing else.** It checks that the new binary accepts the
  existing configuration, stops the service, keeps the old binary as `probation.prev`, installs the new one, validates it
  again (restoring the old one if that fails) and starts the service on the same data directory. It never writes a sample
  over a missing config.
- **Uninstall stops and disables the service and removes only what install recorded** (the definition, the installed binary,
  the journald or newsyslog file). Configuration, blocklist, TLS files and data stay; delete them yourself.
- **A second owner is refused.** An install over a service of that name the installer did not create is refused, and a second
  `probation serve` on a held data directory exits 1 naming the lock without touching anything. The first keeps serving.
- **Permissions.** System scope: the config directory is `root:<service account>` mode 0750 (the service reads its policy and
  cannot change it), the data directory is the service account's alone at 0700, and the service runs with umask 0077. Windows:
  the service runs as the virtual account `NT SERVICE\Probation` (no password stored); ACLs give it read and execute on the
  configuration and modify only on data and logs; nobody else is granted anything.
- **Supervision.** Linux: `Restart=on-failure`, `RestartSec=2`, `TimeoutStopSec=45`. macOS: `KeepAlive` with
  `SuccessfulExit` false (a failure and exit 75 restart; a stop, which exits 0, does not), `ThrottleInterval` 5, `ExitTimeOut`
  45; stdout goes to a file `newsyslog` rotates. Windows: the service reports `Running` once the listener is up; Stop,
  Pre-shutdown (45 s) and Shutdown take the same graceful path as `SIGTERM`; exit 75 and any fatal error end the process
  without reporting `Stopped`, which the service control manager treats as a failure and answers with a restart after 5 s
  (then 5 s, then 60 s, reset after a day). Under the service control manager stdout goes nowhere: use `log_file_path`
  (the installer sets it) for the decision log.
- **Upgrade is undone on any failure.** The new binary must accept the existing config (checked from a copy in the bin directory,
  not the package directory), then, after the swap, the service must start and stay up for five seconds; if the copy, the
  validation or the start fails the previous binary and definition (`.prev`) are put back and the previous service is started
  again, on Linux and Windows. An upgrade re-applies the service definition (failure actions, stop allowance) as well.
- **Uninstall and installer arguments are contained.** Only paths the installer itself computes can be removed, and only when the
  install record names them and this install created them (an identical program, journald or newsyslog file that was already
  there is never recorded as ours); a record naming anything else, or a `..` or relative path, is refused and nothing outside is
  deleted. Names, users and paths are limited to a plain alphabet (no spaces, quotes, `&`, `\\`), `--root /` needs `--no-staging`,
  and a system install refuses a certificate, key or directory under `/home`, `/root` or `/run/user` (`ProtectHome=yes` hides them).
- **Windows directories are the installer's.** `C:\ProgramData` lets any user create folders, so the installer creates the
  `Probation` directories itself with a protected ACL (SYSTEM and Administrators, then the service account) before writing
  anything, and uses an existing directory or `config.toml` only if Administrators or SYSTEM own it and no component is a junction
  or other reparse point. The service is registered Disabled as `NT SERVICE\Probation`, becomes Automatic only after its ACLs are
  verified, and a failed install removes what it created. The release zip carries no OpenSSL DLL (it is linked into `probation.exe`); the exe is verified against
  `SHA256SUMS`, a package that carries a library is refused, and `check-config` runs with a clean PATH. A failure before the log sink
  exists leaves `service-failure.txt` (at most 4 KiB, replaced by the next failure) in the log directory and ends the service
  with exit code 78 (invalid configuration), 70 (cannot start) or 73 (log unavailable). The operational log is
  `<log dir>\probation.log` (50 MiB, three backups); a key file whose DACL grants anyone but SYSTEM, Administrators and the
  service account is refused like a group-readable key file on Unix. Retry: the service control manager restarts a failure
  after 5 s, 5 s, then 60 s (reset after a day), without end; a stop by an operator is reported `Stopped` even when the shutdown
  was unclean, so it is not restarted. Recovery for a process that dies before reporting `Running` is not documented by
  Microsoft and is expected to take the same path.
- **Retry limits differ per OS.** systemd gives up after ten starts in a minute (`StartLimitBurst=10`, `StartLimitIntervalSec=60`;
  then `systemctl reset-failed`); launchd retries every 5 s without end (`ThrottleInterval`), and so does the Windows service
  manager at its 5 s, 5 s, 60 s steps. A bad config therefore stops on Linux and keeps retrying, with a diagnostic in the log,
  on macOS and Windows.
- **The Linux unit is sandboxed** (`systemd-analyze security` exposure 1.2): no capabilities, no raw sockets (only AF_INET,
  AF_INET6, AF_UNIX), a system-call filter (`@system-service`, no `@privileged` or `@resources`), no kernel, clock, hostname or
  cgroup access, no namespaces, no W+X memory, `ProtectProc=invisible`. A user-scope unit keeps the directives a user manager can
  apply (system-call filter, address families, W^X, personality).
- **Low ports.** The unit keeps no capability, so a port below 1024 cannot be bound. `--listen` with such a port on a Linux system
  service installs a drop-in (`probation.service.d/10-low-port.conf`) that grants exactly `CAP_NET_BIND_SERVICE`; a user service and a
  macOS daemon cannot be given that right, and the installer refuses a low port there (use 1024 or more behind a TLS proxy).
- **Release provenance.** Each release has a GitHub build-provenance attestation for the archives and the binaries (beside the
  same-origin `.sha256` files). A release package carries a `RELEASE-PACKAGE` marker; for it the installers REQUIRE `gh attestation verify` (pinned to this
  repository and `.github/workflows/release.yml`) and the cosign bundle below, and refuse when `gh`, `cosign` or the bundle is
  missing or does not verify, unless `--allow-unverified` / `-NoVerify` is given (a loud warning). A binary named with `--binary`, or a
  package without the marker, is checked softly when the tools are there. The Windows installer also requires `SHA256SUMS` and checks
  it before copying anything. Every binary also has a keyless cosign signature, the release asset
  `probation-<version>-<target>.sigstore.json`: with `cosign` installed, `install-service.sh` verifies it (save it beside the binary as
  `probation.sigstore.json`, or `--cosign-bundle FILE`) against this repository's release workflow and refuses a bundle that does not
  verify; without cosign or a bundle it says so. `install-service.ps1` does not run cosign.
- **The listener stays on loopback.** Reaching it from another machine needs the deliberate TLS plus `allowed_peer_cidrs`
  setup of the shared service (section 6); the installer does not open it.

### Running the management server

`deploy/docker-compose.yml` runs the server and one managed firewall side by side.
The server reads its secrets from the environment (section 15), from `server.env`
in that example. Publish its port only to your TLS proxy.

Start each new server version only after `probation-server migrate`
([management-server.md](management-server.md#4-migrations-and-database-roles) §4).

### A managed firewall needs a restart policy

A global admin can push settings to a firewall from the fleet page. The firewall
has no live reload: it checks the pushed settings, writes them to
`<data_dir>/managed-settings.toml` (never to your `config.toml`), drains, and
exits with code **75**. Its supervisor must start it again. Use `restart:
unless-stopped` in compose, `--restart unless-stopped` with `docker run`, or
`Restart=on-failure` under systemd. Without one, the firewall stays stopped after
a push.

### Stopping the firewall

`SIGINT` (Ctrl-C) and `SIGTERM` (`docker stop`, `systemctl stop`, plain `kill`)
both shut it down cleanly: queued log records are delivered and a summary is
printed. A managed firewall also sends the activity queued since its last sync in
one last call to the server, waiting at most `request_timeout_seconds`. What it
cannot send, for example while the server is down, is kept in
`<data_dir>/managed-activity.json` and sent after the next start. A signal that arrives while the service is still starting is acted on as
soon as startup finishes. An abrupt stop is still safe. Nothing gets corrupted.

Requests already in progress get 30 seconds to finish; after that their
connections are closed and shutdown continues. Give the service manager more than
that before it kills the process, so the log drain still runs: with systemd,
`TimeoutStopSec=45`; with Docker, `docker stop -t 45` or `stop_grace_period: 45s`
(the default is 10 seconds).

### Health checks

Point the liveness probe at `GET /health/live` and the readiness probe at
`GET /health/ready`. Section 16 says what each one means.

## 3. Disk space and memory

### `cache_max_bytes` does not cap everything

The name sounds like a total disk limit. It is not.

The data folder has these parts:

```text
<data_dir>/content/     the downloaded files
<data_dir>/state/       the database (firewall.db, firewall.db-wal)
<data_dir>/lock         the lock file
<data_dir>/managed-*    managed mode only (section 13)
```

`cache_max_bytes` limits only `content/`. When it fills, the least recently used
files are evicted.

**`state/` has no size limit.** Nothing caps it and nothing warns you when it
grows. Give the disk real headroom beyond `cache_max_bytes` and watch free space
yourself.

`state/` holds a row for every project ever looked at, a row for every file ever
checked (with its hash and first-seen time), a row per cached file, and the
current blocklist. The first-seen records are permanent: they are what stops a
restart from resetting the cooldown clock. So `state/` only grows. Deleting rows
does not shrink the file, and nothing prunes it.

> **Known gap:** no low-disk warning. If the disk fills, writes fail, the
> service reports "not ready", and requests get `503`. It never relaxes its rules
> to save space.

"Not ready" covers both halves of the data folder: a failed write to the database
or to `content/` turns `/health/ready` to `503`. Successful reads do not turn it
back; only a successful write does. While it is not ready, the background
maintenance pass (every 30 seconds) tries one small write to each, so readiness
returns on its own within about 30 seconds of space being freed — it does not
wait for traffic, which a load balancer would no longer send.

A cached file found with the wrong size is deleted and downloaded again on the
next request. A file already sitting where a download is about to be stored is
kept only if its SHA-256 matches; anything else there is replaced.

Keep room for one blocklist update: a 100,000-entry blocklist is about 9.6 MB,
and the old and new copies exist together briefly.

### Memory

`memory_cache_max_bytes` budgets parsed metadata and cached responses only. It is
**not** a limit on the process. In testing with a 100,000-entry blocklist under
load, the process used **357 to 374 MB** of RAM. Size your memory limit from that
number, and add the log queues (section 8). A managed firewall also holds up to
`key_cache_max_entries` keys and their policies.

## 3a. `metadata_max_age_seconds`: a safety setting with a cost

`metadata_ttl_seconds` sets how often a package is re-checked with upstream. But
a cheap "nothing changed" answer from upstream can renew that clock forever. So
there is a harder limit: `metadata_max_age_seconds` (default: 1 day). Once a
package's data is that old, the next request must fully re-fetch it, however many
cheap re-checks happened.

**The cost:** if that forced re-fetch fails, the request is refused, even though
a slightly stale local copy exists. So an outage on the path between this service
and npm/PyPI that lasts longer than this limit makes already-cached packages
start failing. Projects expire at slightly different moments (up to a tenth
early) so the failures spread out, but they still happen.

Your two choices:

- **Raise it.** Longer survival through an upstream outage, but a longer window
  in which a misbehaving upstream can feed you stale data. It cannot be lower than
  `metadata_ttl_seconds`. The service refuses to start if it is.
- **Set it to `0`.** No limit. An upstream that always says "nothing changed" can
  then freeze your view of a package forever. Do this deliberately and write down
  why.

There is no "serve it stale" option.

This limit never affects blocklist enforcement: a blocked package stays blocked.
It never affects downloaded files either. They are identified by content hash and
cannot go stale.

## 4. The blocklist and OSV

### Standalone: the blocklist file

The firewall reads one local JSON file. It does not fetch feeds or merge lists.
Your own tooling must produce that file and replace it atomically. Only trusted
people or systems may write it. You own what is in it; the service only enforces
it.

How reloading works:

1. Every `blocklist_poll_seconds`, it checks the file for changes.
2. The whole new file is validated before use, if it is under
   `max_blocklist_bytes`.
3. Every update needs a strictly higher revision number. A roll-back is rejected.
   Same revision with the same content is a no-op. Same revision with different
   content is rejected.
4. The file's "generated at" and "expires at" window must include now.
5. An accepted update is saved to the database before it takes effect.

A broken replacement keeps the last good blocklist in force and logs an error. A
file larger than `max_blocklist_bytes` is refused the same way, and is read no
further than that limit. An empty but valid blocklist is accepted (only the
cooldown then protects you). A missing file is never treated as empty. A reload
check that fails unexpectedly (a bug) is logged at error, and the next interval
checks again; it never stops reloading.

**If the blocklist expires, the service fails closed:** package lookups and
downloads return `503`, even for cached files. The service stays "alive" but
reports "not ready". Set the expiry far enough ahead to cover a producer outage,
and alert on it.

Every new file is a full replacement, including removals. To un-block something,
your producer must stop listing it.

### Managed: policy layers

A managed firewall ignores the blocklist file. Each key's policy is built from
layers (platform, organisation, group, user, or platform and personal account),
edited on the portal. A tool can also replace or add to one layer's blocks over
the automation API, `GET`/`PUT`/`POST /api/v1/blocklist/{layer}`, with a token
made on the organisation page or on `/admin`. Both take and give the same JSON
format as the blocklist file; its `revision`, `generated_at` and `expires_at` are
ignored on import. Limits are in section 18.

### What a block stops

A block applies to every request checked after the new blocklist or policy loads,
including files downloaded and verified earlier. New CI runs, fresh installs, and
cache misses are all refused.

It does **not** remove a copy already on someone's machine. Cleaning up an
installed bad package is a job for endpoint security.

### OSV vulnerability checks

[OSV](https://osv.dev) (Open Source Vulnerabilities) is a free, open database of
known vulnerabilities in open-source packages, run by Google and fed by npm, PyPI,
GitHub, and others. The firewall checks every package against it as a second net
beside your own blocklist.

**How the two combine:** whichever one blocks, it is blocked. OSV is only asked
about a package your own blocklist would allow, so OSV can add blocks but never
undo one.

**OSV problems never block anything.** If the check is slow, times out, the queue
is full, or the answer cannot be parsed, the service treats it as "no match" and
continues with its normal checks. A "no match" answer is cached for 30 seconds so
a struggling OSV endpoint is not hammered. A match is cached for
`osv_cache_ttl_seconds` (default 300, 5 minutes). The cache holds at most 65,536
answers; past that the least recently used is dropped and asked again.

`osv_mode` controls what a match does:

- `enforce` (default): blocks, the same as a blocklist match.
- `diagnostic`: checks, caches, and logs a match, but lets the request through.
  Use it to see what OSV would block before turning enforcement on. The only
  signal is the `reason` text in the decision log, so alert on that.
- `off`: no check and no calls to OSV.

Changing `osv_mode` needs a restart (or, in managed mode, a settings push).

**Network:** the endpoint is fixed at `https://api.osv.dev/v1/querybatch`. If you
restrict outbound traffic (section 6), allow `api.osv.dev` too. Otherwise every
OSV check times out and fails open, and packages are served without it.

`osv_request_timeout_ms` (default 2000) bounds one batch of OSV lookups before it
fails open. All versions of a package are checked together, up to 256 per batch,
so a package the service has not seen recently costs about one OSV round trip,
not one per version.

**Managed and shared-service mode: the policy server answers OSV.** An endpoint with
`[management]` or `[service_policy]` never calls `api.osv.dev`. It sends the same
osv.dev-shaped batch to `<server URL>/osv/v1/querybatch` with the credential it
already uses for that server (the firewall token, or the organisation service key),
and the policy server makes the one upstream call and keeps the shared answer cache.
There is no key that points an endpoint at `api.osv.dev` in these modes, and an
unreachable server never selects it: the lookup fails open, as above.

- A managed endpoint keeps every matched (malicious) answer for `osv_stale_match_seconds`
  (default 86400, from 3600 to 604800) after its normal TTL while the server cannot be
  asked, and writes matched entries to `<data_dir>/osv-matches` (owner-only, replaced
  atomically) so a restart during an outage still refuses them. An outage longer than
  that window ends protection for those entries; a package never asked about before the
  outage is unchecked until the server answers.
- `osv_request_timeout_ms` must be at least 1600 in these modes (the server answers at a
  1500 ms deadline; a slow upstream answer still lands in the server's cache, so a retry
  converges).
- **Upgrade the policy server first, then the endpoints.** An endpoint that finds no
  Probation envelope in the answer treats OSV as unreached (known matches kept) until
  the server is upgraded.
- Server setting `[server] osv_key_rate_per_minute` (default 600, burst 1000) is the
  cache-missing keys one credential may ask for per minute. Cache hits are never charged
  as keys, but every request counts against a per-credential request rate (100 a second,
  burst 500), and all credentials together share one key budget (12000 a minute) so the
  single api.osv.dev connection cannot be exhausted by many tenants at once. Upstream
  429 answers open a breaker for at most 60 s; breaker openings are counted.
- The OSV route throttles sources that fail to authenticate: 10 failures a minute from one source
  turn that source away without a lookup, except for credentials that authenticated before, and the
  block ends 60 s after the last failure. Behind a proxy that is not in `[server] trusted_proxies`
  every client shares the proxy's address, so list the proxy there. The shared key budget is
  divided per organisation (25% each), and every organisation keeps a small floor of its own.
- Names and versions are asked about up to 1024 bytes each; a key refused beyond that is
  never sent and is counted in `osv_keys_refused` (sync report and readiness detail).
- A registry's `osv_scope` (portal registry page) decides whether its package names are
  sent: `Public` (the default, including custom registries) or `Private` (never sent).
- The same counters travel in every managed endpoint's sync report (`osv`). `/health/ready` on a shared-service endpoint reports `osv_degraded_warning` when more
  than 5% of the last five minutes' OSV results were degraded. Readiness itself does not
  change. Check the server's upstream health, then raise `osv_key_rate_per_minute` or
  pre-warm the cache.

## 5. Backup, restore and upgrades

### The firewall: what to back up

Three things, separately:

1. The config file (and, in managed mode, the token file).
2. In standalone mode, the current blocklist file. In managed mode,
   `<data_dir>/managed-settings.toml` and `managed-settings.state`, which hold
   the pushed settings.
3. **The whole `state/` folder**, with the service stopped, including
   `firewall.db-wal`.

Downloaded files in `content/` are re-downloaded and re-verified on demand.
`state/` holds what cannot be rebuilt: every first-seen time, every pinned file
hash, and the current blocklist revision. Lose it and every cooldown timer
resets. `managed-cache.json` is refilled from the server.

### How to back it up

**Stop the service first.** It holds an exclusive lock on the data folder while
it runs, and copying the database live can catch it mid-write. There is no
backup-while-running option.

```sh
docker stop -t 45 probation    # shuts down cleanly
tar -C /srv/probation -czf state-$(date -u +%Y%m%dT%H%M%SZ).tgz state/
docker start probation
```

Keep `firewall.db-wal`. It holds committed data not yet merged into the main
file. Deleting it loses real data.

### How to restore it

1. Stop the service.
2. Restore the whole `state/` folder as one unit, database and WAL together.
3. In standalone mode, put a **current, unexpired** blocklist in place. A
   restored blocklist that has since expired leaves the service "not ready"
   until you update it.
4. Start the service and wait for `/health/ready` to return `200`.
5. Treat all cached metadata as stale. Each package is re-checked with upstream
   on its next request.

### If the firewall's database will not open

If the database cannot be opened, for any reason, the process **still starts**,
but:

- `/health/live` says `200`
- `/health/ready` says `503`
- every package request is refused
- nothing on disk is touched, deleted, or recreated

Silently recreating a broken database would lose every pinned hash and timer
while looking healthy. A refusal with the data intact can still be fixed.

One case to know: if `firewall.db` is empty or missing but `firewall.db-wal` has
data, the service refuses to open it. Back up `state/` before doing anything
else. The WAL file is your real data.

If another process holds the lock on the data folder, `serve` reports that and
exits.

### Backing up and restoring the management server

Back up Postgres the way you back up any Postgres database (`pg_dump`, or your
provider's snapshots). The server keeps nothing else, except its settings file
and its environment. Back up `PROBATION_SERVER_SECRET_KEY` together with every
database backup, but store it apart from them: without it the authenticator
secrets, SSO client secrets and sealed bodies of unsent mail in the backup cannot
be read. A restored database needs the key it was sealed with; `serve` refuses to
start with another one.

To restore:

1. Stop `probation-server`.
2. Restore the database.
3. Run `probation-server admin after-restore` (with
   `PROBATION_SERVER_DATABASE_URL` set as for `serve`). It prints the counter
   before and after.
4. Before starting the server, list the security changes made after the backup
   was taken, from your own records (tickets, chat) or from the audit log of any
   newer copy of the database: key revocations, member removals, suspensions,
   policy blocks, firewall registrations, firewall retirements and settings
   pushes. The restored database does not have them.
   Re-apply the user and service key revocations now with
   `probation-server admin revoke-key --key-id N`, which needs no running server.
   It does not revoke automation (`aut_`) tokens or firewall (`fwt_`) tokens.
5. Start `probation-server` and re-apply the rest on the portal before you open
   it to everyone else: automation token revocations included. Until each one is
   back, firewalls enforce the restored database's version of it. Two firewall
   changes need their own step:
   - **A firewall registered after the backup** is not in the restored database:
     its token gets `401` on every sync. Register it again on the fleet page and
     install the new token on it.
   - **A firewall retired after the backup** is live again in the restored
     database: its token syncs again. Retire it again on the fleet page.

Why step 3: every change the server makes gets the next revision number, and each
firewall remembers the last revision it applied. A restored database counts from
an older number, so the changes made after the restore reuse numbers a firewall
has already seen, and that firewall would skip them, including revocations.
`admin after-restore` raises the revision counter, in one transaction with an
audit log row, to the database clock in microseconds since 1970 plus one (or one
past its current value, if that is higher), and marks everything up to there as
pruned. At its next sync every firewall drops its cached keys and policies and
refills them from the restored database, so every firewall matches the restored
database (which is why step 4 matters); expect one burst of key lookups as caches
refill. The command also moves the settings rollouts' ids a million past the
highest one, so a firewall still reporting a push the restore lost never
completes a new one. Running it again is harmless: the counter only moves up.

It relies on two things:

- **The clock never steps backwards.** The command reads the clock of the
  Postgres server (`clock_timestamp()`) inside its transaction. If that clock has
  gone backwards since the backup was taken, whether by a restore of the host, a
  VM snapshot or an NTP step, the new counter can land on a number a firewall has
  already seen, by up to the size of the step. If you know the clock stepped
  back, wait at least that long before running the command.
- **Fewer than one change per microsecond.** The counter then never runs ahead of
  the clock, so each run lands above every number issued before it.

The same holds for a backup restored twice, a backup taken right after an earlier
`after-restore`, and a backup that predates one.

### Upgrading the firewall

Stop the service, replace the binary, start it again. On its first start a new
release upgrades the database in place when it knows how. v0.1.0's schema
(version 4) becomes version 5, with every pinned hash, first-seen time and the
blocklist revision kept. 0.2.0 and later all use version 5, so they need no
database change. A database from any other version is refused and left untouched,
as described above under "If the firewall's database will not open".

An upgraded database does not open in the older release. Keep the old binary and
a backup of `state/` until you are sure you will not roll back.

1. **Back up** the config, the blocklist, and the whole `state/` folder, with the
   service stopped (above). Keep a copy of the old binary too.
2. **Get the new binary** (section 2).
3. **Install it where the service runs it from**, for example
   `sudo install -m 755 probation /usr/local/bin/probation`. With Docker, build
   the new image and start a new container on the same data folder.
4. **Check the config** with the new binary:
   `probation check-config /etc/probation/config.toml`.
5. **Start the service** and wait for `/health/ready` to return `200`. The log
   says `upgrading the database schema`, with `from` and `to`, on the first start
   only.

To roll back: stop the service, put the old binary back, restore the `state/`
backup from step 1, and start it.

**If you installed v0.1.0 with `scripts/install-local.sh`:** that version ran the
service as your login user. To move to the dedicated `probation` account (section
6), do steps 1–3 above, then re-run `sudo scripts/install-local.sh --start` with
the same options you used before (`--etc-dir`, `--data-dir`, `--host`, …).
Without `--start` it installs the service but leaves it stopped. Two things to
know first:

- It **replaces `config.toml` and `blocklist.json`** with the samples. Copy yours
  back afterwards (as root, since the folder then belongs to root) and restart
  the service.
- Under `sudo` it runs whatever `probation` it finds first, normally
  `/usr/local/bin/probation`. That is why step 3 has to come first: otherwise the
  service keeps running the old release.

Then check it:

```sh
ps -o user= -C probation                 # probation
curl --cacert /etc/probation/tls/localhost.pem https://localhost:8443/health/ready
sudo journalctl --namespace=probation -u probation | grep 'upgrading the database schema'
```

The `--cacert` is needed only with the self-signed certificate; with `mkcert`
drop it.

### Upgrading the management server

1. Back up the database.
2. Stop the server: every instance of it, if you run more than one.
3. Run `probation-server migrate` with the new binary.
4. Start the new server.

Never run an old and a new server on one database at once. For example, a server
built before outbox mail was sealed sends a sealed mail with an empty body and marks
it sent, so its link is lost. Stop every old instance before you start a new one.

Firewalls keep serving from their cache while the server is stopped (section 13),
so a server upgrade needs no firewall downtime. Only keys a firewall has never
seen are refused (`401`) until the server is back.

### Mixed versions

- Managed mode is new in the first release after 0.2.2. Firewalls 0.2.2 and older
  refuse a `[management]` section as an unknown key; they can only run
  standalone.
- Upgrade managed firewalls one at a time, after the server. The fleet page shows
  the version each firewall reports.
- A firewall older than the server may get answers it cannot read. It keeps
  serving its cache and stays ready, so a load balancer does not take it out.
  However, policy edits the new server makes stop reaching it. It logs
  `the management server's answer could not be read; this firewall (v…) may be
  older than the server` at error level, and the fleet page shows the same text.
  Alert on that line, and upgrade the firewalls soon after the server.
- The sync API is versioned in its path (`/api/v1/`). The report field
  `failed_revision` is optional both ways, so firewalls and servers built before
  and after it was added read each other's reports.

## 6. TLS, reverse proxies and outbound traffic

### The firewall terminates TLS itself

`serve` terminates TLS when both `tls_cert_path` and `tls_key_path` are set. Set
both or neither. No proxy or sidecar is needed for HTTPS.

Set `public_url` to the URL clients use to reach you. Download links are built
from it, so a wrong value breaks downloads. **`public_url` must be `https`**,
with no localhost exception. (`siem_url` in section 8 does allow plain `http` on
localhost.)

For a local end-to-end setup, which generates a cert, writes a real
`/etc/probation/config.toml` and blocklist, creates the data directory, validates
both, and points this machine's npm and pip config at the result:

```sh
scripts/install-local.sh
```

It uses `sudo` only where `/etc/probation` or `/var/lib/probation` need it. Pass
`--start` to also start `probation serve`.

When it needs `sudo`, the service runs as a dedicated `probation` system account.
`/etc/probation` (config, blocklist, TLS key) is owned by root and only readable
by that account, and `/var/lib/probation` belongs to it alone. Neither the
service nor your login user can change policy or the verified cache, so a
package's install script running as you cannot either. Your blocklist producer
must write `/etc/probation/blocklist.json` as root. When the directories are ones
you can create yourself (`--etc-dir`/`--data-dir` under your home), it is a
personal install and everything runs as you.

**Upgrading from an earlier install:** it gave both directories to your login
user. Section 5, "Upgrading the firewall", has the steps to get the separation above.

The script picks the best certificate tool available:

- [`mkcert`](https://github.com/FiloSottile/mkcert), if installed. This adds a
  local certificate authority to the machine's trust store once, so `pip` and
  `curl` on that machine trust every cert it issues with no flags. A mkcert cert
  is not valid on any other machine, which is what you want for local testing.
- Otherwise a self-signed `openssl` cert, which clients would refuse. The script
  adds a `cert=` line pointing at it to the pip config for you. Force this with
  `--self-signed`.

Either way, Node does not read the machine's trust store, so npm, bun and
corepack need the authority named separately. The script copies it to
`/etc/probation/tls/ca.pem` and points `NODE_EXTRA_CA_CERTS` at it, which adds it
to the authorities Node trusts. It does not use npm's `cafile=`: that *replaces*
Node's list, so npm could then reach nothing else over TLS, such as a scoped
private registry. An install that wrote `cafile=` into npm's machine-wide config
has it removed on the next run; remove it from `~/.npmrc` yourself.

- A system install writes `NODE_EXTRA_CA_CERTS` to `/etc/environment`, which
  login sessions read from the next login. Shells already open need
  `export NODE_EXTRA_CA_CERTS=/etc/probation/tls/ca.pem`. A personal install
  prints that line for your own shell profile instead.
- Node trusts only one such file. If `/etc/environment` already names another (a
  corporate proxy's CA, say), the script leaves it and prints how to combine the
  two.
- systemd services and CI runners do not read `/etc/environment`. One that runs
  npm needs `Environment=NODE_EXTRA_CA_CERTS=/etc/probation/tls/ca.pem` in its
  unit.
- A `NODE_EXTRA_CA_CERTS` you set yourself, in `~/.profile` for instance,
  overrides this one.

Run `scripts/install-local.sh --help` for every flag.

Let's Encrypt does not work for `localhost`: it needs a public domain it can
reach. For a real domain, get a certificate however you already do and point
`tls_cert_path` and `tls_key_path` at it. Renewal is yours: the service reads
both files once at startup, so restart after a renewed certificate is in place.

### The management server needs TLS in front of it

`probation-server` listens on plain HTTP only. Terminate TLS on a reverse proxy
and publish the server's port only to that proxy. Firewalls refuse a management
`url` that is not `https`, even on loopback, because their token and every key
hash travel it.

### A reverse proxy is still required for per-client rate limiting

In standalone mode the firewall has no logins or accounts, so it cannot limit one
client's rate.

The risk: a client requests a file and downloads it very slowly, holding one of a
small number of download slots. Enough such clients use every slot, and nobody
else can download.

`max_active_requests` and `max_artifact_downloads` are global totals shared by
everyone. **Set per-client connection and rate limits on your reverse proxy** so
no one client can hold more than a fair share.

A cold download that finds every slot taken waits up to `download_wait_seconds`
(default 5) for one, with at most `max_download_waiters` (default 64) waiting.
That is enough for npm's default of 15 connections against the default 8 slots.
Past either bound it gets `503 OVERLOADED` with `Retry-After: 5`, and npm and pip
retry. **Alert on a steady rate of `503 OVERLOADED`** in the decision log. It
means downloads keep waiting longer than the wait allows, so raise
`max_artifact_downloads` if upstream and disk can take it.

### Outbound filtering

For npm and PyPI traffic, the firewall refuses on its own: cross-site redirects,
URLs with embedded credentials, unusual ports, non-HTTPS upstreams, and DNS
answers pointing at local or private addresses. An artifact is fetched only from
its own ecosystem's hosts: npm tarballs from the npm upstream, PyPI files from
the PyPI files or index upstream. An npm document that names the PyPI files host
for a tarball is refused, and that host is never asked. It cannot detect a custom NAT64
range specific to your network. The standard one is covered. **None of this
covers OSV traffic**: the OSV client is a plain HTTP client that only talks to
one fixed Google-run URL.

To close the NAT64 gap at the network level, restrict the firewall's outbound
connections to the hosts it needs:

- `registry.npmjs.org`, `pypi.org` and `files.pythonhosted.org`, or the hosts in
  `npm_upstream_url`, `pypi_upstream_url`, `pypi_artifacts_url`, `rubygems_upstream_url`, `cargo_upstream_url`, `cargo_artifacts_url`, `go_upstream_url`, `go_sumdb_url`, `go_artifacts_url`, `nuget_upstream_url`, `nuget_search_url`, `nuget_publish_url`, `maven_upstream_url` and `maven_publish_url` if you set them
- `api.osv.dev`, unless `osv_mode = "off"`
- in managed mode, the server's address from `[management] url`

The server needs outbound access to Postgres, your SMTP host, the sign-in
providers you configured, each organisation's own SSO provider, and
`leaked_password_url`.

### Firewalls reach the server directly, never through an egress proxy

The firewall's sync client ignores `HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY` and
`NO_PROXY`, so an environment variable cannot redirect the token and key hashes
somewhere else. A site that can reach the management server only through an
egress proxy cannot run managed today; allow the firewall's address through to
the server.

## 7. What this service does not protect against

Its package safety checks run when a client downloads through it. Selected
registry publishing uses separate access checks and the upstream registry's
permissions. The download checks cannot help with:

- **Already-installed packages.** A later block does not remove them from
  `node_modules` or similar.
- **Client-side caches.** A file already cached by the client is not re-checked.
  (npm does not currently cache files from this service, because of a
  cache-control header it sends. That is npm's behavior today, not a control to
  rely on.)
- **Anything not fetched through this service:** other registries, Git or URL
  dependencies, local files, anything an install script downloads itself.
- **Lockfiles that pin a direct upstream URL**, except npm's (see "Clients"
  below). Check your lockfiles when you roll this out.
- **Code that runs during install.** It checks package files, not what an
  installer script does.

Point your clients here with:

```ini
# .npmrc
registry=https://packages.example.org/npm/
audit=false
```

```ini
# pip.conf
[global]
index-url = https://packages.example.org/pypi/simple/
```

These lines use the legacy download paths. The legacy npm path has no audit route,
so its client setting turns audit off. Selected npm registries have separate paths
and guarded audit routes; see [Usage](usage.md#use-a-selected-npm-or-pypi-registry).
In managed mode each client also sends its API key. The portal's keys page shows
the exact lines to paste.

That is cooperative. To *enforce* it, block direct access to the public
registries at the network level too.

### Clients

Each package tool decides for itself where it downloads from. Most npm tools read
`.npmrc`. Most Python tools do not read `pip.conf`. A tool that is not pointed
here downloads straight from the public registry, and nothing tells you so.

| Tool | Covered by the config above? | To point it here |
| --- | --- | --- |
| npm, npx | Yes | Nothing more. |
| pnpm | Yes, it reads `.npmrc` | Nothing more. |
| bun | Only from `~/.npmrc` or a project's `.npmrc`, not the machine-wide npmrc the installer writes | Put the same `registry=` line in `~/.npmrc`. |
| yarn 1 | New installs only | Rewrite each existing `yarn.lock` once (below). In managed mode, also add `//<host>/npm/:always-auth=true` to `.npmrc`: without it yarn 1 sends the key only for scoped packages. |
| pip, pipx | Yes | Nothing more. |
| uv | No | `uv.toml`, plus a certificate from `mkcert` (below). |
| Poetry | No | Once per project (below). |
| corepack | No | Set `COREPACK_NPM_REGISTRY` (below). |
| conda packages | No, and cannot be | conda channels are not supported. |

**npm lockfiles work as they are.** A `package-lock.json` made against the public
registry names `https://registry.npmjs.org/...` in every `resolved` URL. npm
rewrites only the host of those URLs to the configured registry, so it asks this
service for upstream's own tarball path, which it serves under the same policy as
every other download.

**yarn 1 lockfiles need one rewrite.** yarn 1 downloads exactly the `resolved`
URLs in `yarn.lock` and has no setting to change their host. Point them here once
per project, and commit the result:

```sh
sed -i 's#https://registry.yarnpkg.com/#https://packages.example.org/npm/#g' yarn.lock
```

A teammate without access to this service cannot install from that lockfile.

**uv** reads its own config, not `pip.conf`. Machine-wide, in `/etc/uv/uv.toml`
(per user: `~/.config/uv/uv.toml`):

```toml
[[index]]
url = "https://packages.example.org/pypi/simple/"
default = true
```

uv also refuses the self-signed certificate `scripts/install-local.sh` falls back
to without `mkcert`, even with `SSL_CERT_FILE` pointing at it. Use a certificate
from a real CA, or install `mkcert` and re-run the installer.

**Poetry** has no machine-wide setting. In each project:

```sh
poetry source add --priority=primary probation https://packages.example.org/pypi/simple/
```

With the self-signed certificate, also run
`poetry config certificates.probation.cert /etc/probation/tls/localhost.pem`.

**corepack** downloads yarn and pnpm themselves from `registry.npmjs.org`. Set
`COREPACK_NPM_REGISTRY=https://packages.example.org/npm` in the environment. It
trusts this service's certificate through the same `NODE_EXTRA_CA_CERTS` the
installer sets for npm.

## 8. Logs

### The firewall's decision log

Structured JSON on stdout, one line per decision, including routes that match
nothing (404/405):

```json
{"level":"INFO","fields":{"message":"request decided","request_id":"req-0000000000000003",
 "method":"\"GET\"","ecosystem":"npm","package":"\"left-pad\"","version":"","status":200,
 "result":"ALLOWED","reason":"the request was served","blocklist_revision":42,
 "cache":"miss","duration_micros":415780,"bytes":23563}}
```

Every decision can be explained from `result`, `reason`, and
`blocklist_revision` together. `blocklist_revision` is the revision the request
was judged against. `result` is `REFUSED` for a 4xx/5xx the router or HTTP layer
produced without a policy decision (a malformed path, an unsatisfiable range),
and those count as errors in the periodic summary. The `request_id` matches the
one a client sees in its error message. Credentials are never logged and never
forwarded upstream.

In managed mode a record also carries `place`: the server's id of the place the
request's key belongs to. Never the key or its hash.

`RUST_LOG` (default `info`) controls verbosity for everything except the decision
line, which cannot be silenced. There is no metrics endpoint. Counters are
printed to stdout periodically.

### Also writing logs to a file

By default logs go only to stdout, which your container runtime or systemd keeps.
Set `log_file_path` to also keep a file. Nothing is written to disk until you do.

| Setting | Default | What it does |
| --- | --- | --- |
| `log_file_path` | off | File every decision is appended to, one JSON object per line. |
| `log_file_max_bytes` | 100 MiB | Size at which the file rolls over to a `.1` backup. |
| `log_queue_max_bytes` | 1875 MiB | Memory that may queue while disk writes fall behind. See "The rated load" below. |

One process per `log_file_path`. There is no locking, so two writers corrupt the
file. Let this process rotate the file itself with `log_file_max_bytes`. An
external `logrotate` renaming or truncating it causes silent data loss.

One backup generation (`.1`) is kept. For longer history, ship logs to your own
log system.

`log_file_max_bytes` is a hard ceiling. If the rollover rename fails (a single
bind-mounted file, a directory the service cannot write to, or a directory
sitting at the `.1` path), the file is not extended: new records are dropped and
counted, with one warning, until a rename succeeds. A record too large to fit in
an empty file is dropped and counted too.

Dropped records are always counted. If writing cannot keep up, losses appear in
the periodic summary as `dropped_file` and `dropped_siem`. The summary has its
own room in each queue, so the record that reports a loss is not lost to the same
full queue. A slow log destination never slows or fails a request. The record is
dropped, not the request.

What the file promises: every record is written whole or not at all (a write that
fails partway, such as on a full disk, is cut back off), and each record is
handed to the kernel as soon as it is written, so it survives the process
crashing or being killed. It is not `fsync`ed. A host crash or power loss can
lose the records of the last few seconds that the kernel had not yet written out.
Syncing every record would cap the rate at the disk's sync rate, far below the
rated load, and the queue would then drop records instead.

### Sending logs to a SIEM or log collector

Set `siem_url` to turn this on.

| Setting | Default | What it does |
| --- | --- | --- |
| `siem_url` | off | Where records are POSTed. Must be `https` unless it is localhost. |
| `siem_auth_header` | `Authorization` | Which header carries the credential. |
| `siem_queue_max_bytes` | 1875 MiB | Memory that may queue while the collector is unreachable. |

The credential never goes in the config file. Set the `PROBATION_SIEM_AUTH`
environment variable. It is never logged or written anywhere, and the process
refuses to start if it is not a legal HTTP header value. With it unset, delivery
is unauthenticated.

Records are sent in batches of 256 records or every 2 seconds, whichever comes
first. Redirects from the collector are never followed, so a compromised
collector cannot send your credential elsewhere.

Retries: a connection error, a `5xx`, or a `429` is retried with a short backoff
(100 ms, 500 ms, then every 2 seconds) for as long as the service runs. The batch
is held, and records queue behind it until the queue budget is full. Any other
error, such as a bad credential, is not retried, and that batch is dropped. Lost
records are counted in `dropped_siem`.

Delivery is **at least once**. A collector that stores a batch but answers after
the 3-second request timeout gets the same batch again on the retry, so
deduplicate on `request_id` if duplicates matter to you. Only a timed-out or
failed attempt is retried; a batch the collector acknowledged is never sent
again.

The service logs only the scheme, host and port of `siem_url`, never its path or
query, so a token placed in the URL stays out of the console.

**One limit:** when a collector rejects a batch, the *whole batch* of up to 256
records is dropped, not one record. The file from `log_file_path` does not have
this problem: one bad record never costs its neighbours, and each record is
written at most once (see what the file promises, above).

### Shipping to a SIEM over syslog

`siem_url` is HTTP only. There is no syslog support in `probation` itself: a
mature shipper already does TLS, framing, and retries correctly. If your
collector takes HTTP (Splunk HEC, Elastic, Datadog, and most others), use
`siem_url` and skip this section.

If you need syslog, point `rsyslog`'s `imfile` input at the file from
`log_file_path` and let `omfwd` deliver it. The file is the better source: it is
complete (see the batch limit above) and plain appended text.

```
# /etc/rsyslog.d/probation.conf
module(load="imfile")
input(type="imfile"
      File="/var/log/probation/decisions.ndjson"
      Tag="probation:"
      Severity="info"
      Facility="local0"
      ruleset="probation_to_siem")

ruleset(name="probation_to_siem") {
  action(type="omfwd" target="siem.example.org" port="6514" protocol="tcp")
}
```

This exact pipeline was verified against a real `rsyslogd`: each appended line
arrived at a TCP listener as RFC 3164 syslog (`<134>` is `local0.info`) with the
JSON payload intact, so field-based queries on the collector keep working.

For TLS to the collector (port 6514, not 514), add `StreamDriver="gtls"` and the
matching cert settings to the `omfwd` action. See rsyslog's own `omfwd` TLS
documentation.

The shipper reads a file this service appends to and rotates itself. Keep
`logrotate` away from it, and leave `decisions.ndjson.1` in place until the
shipper has finished reading it after a rotation.

Other shippers (Vector, Fluentd) work the same way in principle: tail
`decisions.ndjson` and forward with that tool's syslog output. They were not
verified here. Check that tool's own docs.

### Recording who is asking

`log_consumer_identification` (off by default) adds the requester's IP address to
every log line. Read this before turning it on:

- It records only the raw IP of the TCP connection, nothing the client sends, so
  it cannot be spoofed.
- Behind one proxy or load balancer, every record shows that proxy's address, not
  the developer or build machine. `trusted_proxies` does not change this.
- Turning it off later erases nothing already logged, in your files, your SIEM,
  or your console logs.
- It requires `log_file_path` or `siem_url`. Without one, the service refuses to
  start with it on.
- A log file this service creates gets owner-only permissions (`0600`). A file
  that already exists keeps its permissions. Fix those yourself. With this on, a
  `log_file_path` that cannot be opened stops the start.
- If the log destination is broken (SIEM unreachable, disk full, file deleted),
  the service keeps running and counts dropped records. Watch `dropped_file` and
  `dropped_siem`.
- `check-config` checks that the setting is valid, not that the destination
  works.

### The rated load: how much this can handle

On a 16-core/32-thread reference machine, the logging pipeline sustained about
**59,000 decisions per second with zero records lost**. That is the logging
ceiling, not overall throughput. Real traffic is limited mainly by how fast npm
and PyPI respond, and by `max_upstream_requests` (32 in the sample).

The default queue budgets (`log_queue_max_bytes` and `siem_queue_max_bytes`,
1875 MiB each) are not sized for that rate: surviving a 5-minute outage at
59,000/s would need about 543 GB per destination. They are sized to survive a
5-minute outage at a realistic **200 requests/second**.

If your traffic is above 200 req/s, work out your own outage window:

> outage tolerance (seconds) = queue size in bytes ÷ 32,768 ÷ your
> requests/second

Each queue is separate. `log_queue_max_bytes`, `siem_queue_max_bytes`, and
`memory_cache_max_bytes` (section 3) do not share memory. Budget for all three.

**The decision log cannot be turned off.** No `RUST_LOG` value silences it, so
there is always an audit trail of every decision.

### Managed-mode lines to alert on

| Level | Message | Meaning |
| --- | --- | --- |
| warn | `the management server could not be reached; serving from the cache` | The server is down, or refused this firewall's address. |
| error | `the management server refused this firewall's token` | A key lookup got `401`: the firewall was retired or its token is not valid (section 13). A sync that finds this logs nothing; `/health/ready` turns `503`. |
| error | `the management server refused an empty sync; treating it as unreachable` | The server rejects every sync. `/health/ready` is `503`. |
| error | `the management server's answer could not be read; this firewall (v…) may be older than the server; serving from the cache` | The server answered a sync, key lookup or layers call in a form this firewall cannot decode, most likely because the server was upgraded past it. The firewall stays ready and serves its cache, including the old version of any layer it could not read, so policy edits stop reaching it. The fleet page shows the error. **Alert on this line**, because `/health/ready` stays `200`. Upgrade the firewall. |
| warn | `the activity queued before the stop could not be delivered; it is saved for the next start` | The last call on a stop failed. The rows are in `managed-activity.json` and go out after the next start. |
| error | `the undelivered activity could not be saved; it is lost` | The stop could not write `managed-activity.json`. Check the data directory's disk space and permissions. |
| error | `a settings push was refused` | The push failed its checks; it is reported on the fleet page. |
| error | `the pushed settings fail at start; restoring the previous ones` | A push broke the start and was rolled back. |

### The management server's logs

Plain text on stderr, one line per event, at the level `RUST_LOG` sets (default
`info`). The server writes no request log. What people do on the portal goes to
the audit log in the database. On `/audit`, each person sees the entries their
role allows. What firewalls decided for each account is on
the Activity page. Both are pruned by their retention (section 17).

## 9. Error responses from the firewall

| What happened | Status code |
| --- | --- |
| Held by cooldown, or blocked | `403` (with a reason, and `Retry-After` for cooldowns) |
| Managed: the client address is inside the approved address ranges of an organisation the key does not belong to | `403 NETWORK_NOT_ALLOWED` |
| Managed: no key, or a key the firewall does not accept | `401 AUTHENTICATION_REQUIRED` |
| Managed: the account's request rate is used up | `429 TOO_MANY_REQUESTS` |
| Unknown or removed package | `404` |
| Bad request | `400` |
| Unsupported route or method | `404`, `405`, `406` |
| Blocklist missing or expired, out of capacity, storage broken | `503` |
| Busy: `max_active_requests` in use, or no download slot freed within `download_wait_seconds` (`Retry-After: 5`) | `503 OVERLOADED` |
| Managed: lookup budget used up, or the server is busy (`Retry-After: 1`) | `503 LOOKUP_BUSY` |
| Managed: no cache and no sync yet | `503 NOT_READY` |
| Upstream failure or bad data | `502` |
| Upstream timed out | `504` |

Every response, success or error, tells clients not to cache it.

Two of these need a person, not a client retry:

- **`502 INTEGRITY_MISMATCH`**: a file's contents changed since this service
  first saw it. That is an upstream security incident or a bug in how this
  service identifies files. Investigate.
- **A `503` from storage**: writes are failing. The service will not loosen its
  rules to work around it. Fix storage.

## 10. Performance numbers

Measured with `cargo bench` on a 32-core / 124 GB RAM machine, local SSD, no
TLS, against an in-process fake registry.

| Scenario | Target | Measured |
| --- | --- | --- |
| Warm metadata responses | ≥1,000/s, p95 ≤5ms | 120,000–144,000/s, p95 0.09–0.12ms — met |
| Warm policy denial | p95 ≤2ms | p95 1.19–1.31ms — met |
| Extra delay vs. plain file server, small project | p95 ≤5ms | +0.12–0.16ms — met |
| Same, medium project | p95 ≤5ms | +0.11–0.16ms — met |
| Same, large project | p95 ≤5ms | +0.09–0.15ms — met |
| Download throughput vs. plain file server | ≥85% | 109–113% — met |
| Blocklist update takes effect under load | within 2 poll intervals (10s) | 5.0s — met |

All targets are met with margin across projects of 100 to 5,000 package
versions. Memory under load with a 100,000-entry blocklist: 357 to 374 MB
resident.

The raw numbers, the method, and why the throughput ratio reads above 100% (a
quirk in how the baseline streams, not evidence this service speeds downloads
up) are in the git history of this file.

## 11. Tested against real clients

Verified with real `npm` and `pip` installs against an in-process fake registry,
never the public internet:

- npm 10.9.9, 11.16.0, and 12.0.2
- pip 25.0.1 and 26.2.1

All versions behave the same. Confirmed: installs succeed and fall back to older
eligible versions; `npm ci` fails cleanly on a blocked lockfile entry without
changing the lockfile; already-installed packages stay installed after a later
block; pip installs work from wheels and source distributions.

npm 12 is stricter about which download URLs it trusts. This service's URL layout
already satisfies that (artifacts live under `/npm/artifacts/...` and
`/pypi/artifacts/...`), so no `.npmrc` change is needed. If an old
`allow-remote=all` line is in an `.npmrc` from an earlier setup, remove it. It
weakens npm's own supply-chain protection for every dependency.

Old download URLs under the previous `/artifacts/...` path no longer work.
Clients get a fresh URL from current metadata.

## 12. Known gaps in this release

1. **No low-disk-space warning.** (Section 3.) Monitor disk space yourself.
2. **The firewall's `state/` database only grows.** (Section 3.) No automatic
   cleanup.
3. **Removed upstream packages can still appear in listings** for up to
   `metadata_ttl_seconds` (5 minutes in the sample). Downloads are judged
   correctly and immediately.
4. **A newly blocked file hash can briefly still appear in a listing** in the
   same window, under rare concurrent access. Direct downloads are blocked
   immediately regardless.
5. **No backup while running** for the firewall. Stop it first.
6. **If upstream is down when metadata needs a full refresh, the request fails**
   rather than serving a last-known-good copy. Deliberate. See section 3a.
7. **Only schema version 4 is upgraded in place.** A firewall database from any
   other older version is refused. See section 5.
8. **A standalone firewall has no admin API.** Everything is config files,
   signals, and logs. Managed mode moves policy to the server.
9. **No live reload.** Every config change and every settings push restarts the
    firewall.
10. **Managed firewalls cannot sync through an egress proxy.** (Section 6.)

## 13. Managed mode

### How it behaves

- Every package request needs an API key. A key the firewall has not seen is
  looked up on the server once, then cached for `key_cache_ttl_seconds`.
- Every `sync_interval_seconds` the firewall asks the server what changed: edited
  policy, revoked keys, suspended accounts, network-lock ranges, settings pushes.
  So a change reaches every firewall within one interval.
- Each sync also carries the firewall's report (version, settings revision, last
  error, whether npm, PyPI and OSV were reachable) and its activity records. The
  fleet page and the portal's Activity page show them.
- The local blocklist file is not read. Policy is edited on the portal, or
  through the automation API.

### First run of the management server

The steps (schema and database roles, `admin bootstrap`, the set-password link,
`admin reset-link`, starting the server) are in
[management-server.md](management-server.md#4-migrations-and-database-roles) §4
and §5.

On each firewall, start from `config.sample.toml` and uncomment its
`[management]` section. Set `url` to the server's `https` address, and put the
token in the file `token_file` names (readable by the firewall's user, never in
`config.toml`). In a container, also set `listen = "0.0.0.0:8080"`. Run
`check-config`, then start it with a restart policy (section 2). Register more
firewalls on the fleet page; each gets its own token, shown once.

### Server commands

`serve`, `migrate` and the `admin` commands (`bootstrap`, `reset-link`,
`revoke-key`, `after-restore`), with every flag and what each prints, are in
[api.md](api.md#3-commands) §3. The `admin` commands are for the operator of the
server's host: they need `PROBATION_SERVER_DATABASE_URL`, and no API route
reaches them. `admin revoke-key` revokes a user or service key only, not an
automation (`aut_`) token or a firewall (`fwt_`) token: revoke an automation token
on the portal, and retire a firewall on the fleet page.

### `trusted_proxies`: who the client is

A managed firewall uses the client's address twice: for the network lock (an
address inside an organisation's approved ranges may use only that
organisation's keys; any other key from there gets `403`, which names the address
it saw) and for the per-client lookup allowance
(`client_lookup_allowance_per_second`, default 5 lookups a second for keys the
firewall has no entry for, inside `lookup_budget_per_second`).

Put the addresses of your reverse proxies in `[management] trusted_proxies`. From
those peers only, the client is the rightmost `X-Forwarded-For` entry that is not
itself a listed proxy. From any other peer the header is ignored. An entry may
be a bare address, `ip:port`, `[v6]` or `[v6]:port`; any other entry, such as
`unknown`, refuses the request with `403`. The RFC 7239 `Forwarded` header is
not read, and PROXY protocol is not supported. Log lines always keep the TCP
peer.

**Behind a proxy that is not listed, every client is the proxy.** All of them
share one network-lock address, so if the proxy's address is inside an
organisation's range, every key of anyone else is refused, and they share one
lookup allowance, so one client sending made-up keys slows new
keys down for everyone. Direct connections need nothing.

The server has the same rule on its own side: `[server] trusted_proxies` decides
whose `X-Forwarded-For` is read for a firewall token's source check and for
sign-in throttling. Since a TLS proxy always sits in front of the server, **list
that proxy there**. Otherwise every firewall appears to come from the proxy's
address, and each firewall's allowed source ranges (`--firewall-source`, or the
register form on the fleet page) would have to name the proxy instead of the
firewall. These ranges are set when the firewall is registered and cannot be
changed later.

### When the server is down

A firewall keeps serving every key and policy it has cached, past their TTL,
until the server answers again; it does not wait on a dead server. A key it has
never seen gets `401` until then. Its cache is written to
`<data_dir>/managed-cache.json` after every sync the server answers, so a restart
during an outage keeps serving too.

If the server answers `401` to the firewall's token (the firewall was retired on
the fleet page, or the token in `token_file` is wrong), the firewall stops serving:
every request gets `401`, and `/health/ready` answers `503`. A retired firewall
cannot come back: register it again on the fleet page, put the new token in
`token_file`, and restart it.

### Settings pushes

A push goes to one firewall at a time. The firewall checks the pushed settings
the way start-up does, writes them to `<data_dir>/managed-settings.toml`, keeps
the previous ones in `managed-settings.prev.toml`, and exits with code 75 (section
2). If the new settings fail at start, the firewall swaps the previous ones back
(or moves a first push aside to `managed-settings.failed.toml`), starts on them,
and reports the error on the fleet page. A bad push never loops, and a refused
push is never applied again. The fleet page counts a push as applied only once the
firewall reports it after its restart, so a firewall with no restart policy that
never comes back stays "sent" and holds up the rollout.

Files a managed firewall keeps in `data_dir`, beside `state/`, `content/` and
`lock`: `managed-cache.json`, `managed-settings.toml`, `managed-settings.prev.toml`,
`managed-settings.state`, and sometimes `managed-settings.failed.toml` and
`managed-activity.json`. The last one holds the activity a stop could not send to
the server. The next start sends it and deletes the file.

## 14. Firewall configuration reference

One TOML file, passed with `--config`. Every change needs a restart. Blocklist
changes do not. A key the release does not know is refused, so a typo stops the
start instead of being ignored. `config.sample.toml` has every key with comments.

### Required keys

These have no default. The values shown are the ones in `config.sample.toml`.

| Key | Sample value | Rules |
| --- | --- | --- |
| `listen` | `"127.0.0.1:8080"` | Address and port. |
| `public_url` | `"https://packages.example.org"` | The URL clients use. Download links are built from it. `https` only, no localhost exception, no user or password, no query or fragment, no path. |
| `data_dir` | `"/var/lib/probation"` | Absolute path. |
| `blocklist_file` | `"/etc/probation/blocklist.json"` | Absolute path. May be left out in managed mode, where it is ignored. |
| `cooldown_seconds` | `86400` (24 h) | `0` turns the age rule off; blocks still apply. At most `315360000` (ten years). |
| `metadata_ttl_seconds` | `300` | How often a package is re-checked with upstream. |
| `blocklist_poll_seconds` | `5` | Not zero. May be left out in managed mode. |
| `cache_max_bytes` | `107374182400` (100 GiB) | Limits `content/` only (section 3). |
| `memory_cache_max_bytes` | `268435456` (256 MiB) | A cache budget, not a process limit. |
| `max_artifact_bytes` | `5368709120` (5 GiB) | Not above `cache_max_bytes`. |
| `max_metadata_bytes` | `67108864` (64 MiB) | After decompression. |
| `max_blocklist_bytes` | `134217728` (128 MiB) | A larger file is refused. |
| `max_upstream_requests` | `32` | Global, shared by all clients. |
| `max_artifact_downloads` | `8` | Global, shared by all clients. |
| `download_wait_seconds` | `5` | How long a cold download waits for a free `max_artifact_downloads` slot before `503 OVERLOADED`. At most 60; `0` refuses at once. |
| `max_download_waiters` | `64` | How many requests may wait for a slot at once; the next one is refused at once. `0` means none waits. Keep it near 8 × `max_artifact_downloads`. |
| `max_active_requests` | `1024` | Global, shared by all clients. |

Every size and count above must not be zero.

### Optional keys

| Key | Default | Rules |
| --- | --- | --- |
| `metadata_max_age_seconds` | `86400` (1 day) | `0` means no limit. Otherwise not below `metadata_ttl_seconds`. Section 3a. |
| `max_references_per_project` | `20000` | Files one project may list. Not zero. |
| `log_file_path` | off | Section 8. |
| `log_file_max_bytes` | 100 MiB | Refused without `log_file_path`. |
| `log_queue_max_bytes` | 1875 MiB | From 32 KiB to 4 GiB. Refused without `log_file_path`. |
| `siem_url` | off | `https` unless the host is loopback or `localhost`. No user or password. |
| `siem_auth_header` | `Authorization` | Refused without `siem_url`. |
| `siem_queue_max_bytes` | 1875 MiB | From 32 KiB to 4 GiB. Refused without `siem_url`. |
| `log_consumer_identification` | `false` | Refused unless `log_file_path` or `siem_url` is set. |
| `osv_mode` | `enforce` | `enforce`, `diagnostic` or `off`. |
| `osv_cache_ttl_seconds` | `300` | Not zero. |
| `osv_request_timeout_ms` | `2000` | Not zero; at least 1600 with `[management]` or `[service_policy]`. |
| `osv_stale_match_seconds` | `86400` | 3600 to 604800; only with `[management]` or `[service_policy]`. |
| `tls_cert_path`, `tls_key_path` | off | Both or neither. Section 6. |
| `npm_upstream_url` | `https://registry.npmjs.org` | `https`, no user, query, path or private address. |
| `pypi_upstream_url` | `https://pypi.org` | Same rules. |
| `pypi_artifacts_url` | `https://files.pythonhosted.org` | Same rules. |
| `rubygems_upstream_url` | `https://rubygems.org` | Same rules. One origin serves the compact index, tuple indexes, quick gemspecs and gems. Point a Bundler `source` or `gem --source` at `/rubygems/` of this firewall. |
| `cargo_upstream_url` | `https://index.crates.io` | Same rules. The Cargo sparse index (`config.json` and the per-crate files). |
| `cargo_artifacts_url` | `https://static.crates.io` | Same rules. The one origin the `dl` of the registry's `config.json` may name; a `dl` anywhere else, or outside the registry's own path, is refused. Set both Cargo URLs for a mirror. |
| `go_upstream_url` | `https://proxy.golang.org` | Same rules. The one Go module proxy: `@v/list`, `@latest`, `.info`, `.mod` and `.zip` (the proxy serves its own zips; a zip served from another origin is refused). |
| `go_artifacts_url` | `https://storage.googleapis.com/proxy-golang-org-prod` | Same rules, except that it may carry a path prefix (a bucket's name; whole segments, no dot or encoded segment). The one origin a zip redirect of the module host may land on: proxy.golang.org answers a large module's `.zip` with a 302 to this signed bucket (measured 18.6 MB for k8s.io/kubernetes v1.30.0; small zips are direct). Only a `.zip` transfer follows it, never a list, an `.info` or a `.mod`, and the registry credential is not sent there. A selected registry has no such origin unless it declares an archive origin on its registry page (below); a redirect away from it is refused (502). |
| `go_sumdb_url` | `https://sum.golang.org` | Same rules. The one checksum database the `/go/sumdb/{host}/` route forwards to (its host is the database name). |
| `nuget_upstream_url` | `https://api.nuget.org` | Same rules. The origin of the service index, flat container, registration, vulnerability and signature documents; a resource of the registry's service index on any other origin is not used. |
| `nuget_search_url` | `https://azuresearch-usnc.nuget.org` | Same rules. The origin of the search and autocomplete services. |
| `nuget_publish_url` | `https://www.nuget.org` | Same rules. The origin of the publish endpoints the shared service forwards to. |
| `maven_upstream_url` | `https://repo.maven.apache.org/maven2` | Same rules, except that it is an origin AND the path prefix of the repository tree (Central's is `maven2`; a mirror's is whatever it publishes, whole segments, no dot or encoded segment). The one public Maven repository: `maven-metadata.xml`, the files of every version, their checksums and signatures, the archetype catalog. Artifacts are read from it only; a selected registry has its own `target_url` instead. |
| `maven_publish_url` | none | Same rules as `maven_upstream_url`. Where the shared service forwards `mvn deploy` for the PUBLIC registry (one with no `target_url`). There is no default, because Maven Central has no deploy endpoint of its own: with the key absent a deploy to the public registry is a 404. A registry with a `target_url` is deployed to at that URL. |
| `conan_upstream_url` | `https://center2.conan.io` | Same rules, except that it is an origin AND the optional path prefix of the remote's `v2` tree (ConanCenter has none; an Artifactory remote is `https://host/artifactory/api/conan/{repo}`; whole segments, no dot or encoded segment). The one public Conan remote: revision lists, file lists, searches and the files of every revision. A selected registry has its own `target_url` instead. |
| `oci_upstream_url` | `https://registry-1.docker.io` | Same rules as `conan_upstream_url` (an origin and the optional path prefix of a registry's `v2` tree). The default OCI registry the plain `/v2/` root serves (a shared service's selected registries name their own). |
| `oci_artifacts_url` | `https://production.cloudfront.docker.com` | An https origin. The one storage host a blob download on the default registry may be redirected to (a signed URL); the caller's credential is never sent there. A selected registry declares its own as its archive origin. |
| `oci_token_url` | none | An https origin. The token service of the DEFAULT registry when its challenge names a host other than the registry's own (a GitLab registry's realm is `https://gitlab.example/jwt/auth`); a realm on any other host is never asked. A registry of a shared service or a certificate-managed firewall declares its own `token_origin` on the registry page, and a certificate admission carries it. |
| `oci_foreign_layer_hosts` | `["mcr.microsoft.com", "*.data.mcr.microsoft.com", "go.microsoft.com", "download.microsoft.com"]` | A list of up to 64 lower-case hosts (`host.example`, or `*.` and a domain for every host below it). The hosts a layer's own download `urls` (a Windows foreign layer) may name: https on the default port, no user name, never an address. A manifest that names any other host is refused (403); a layer's URL on the list is fetched by this firewall with no credential and verified against its digest. An empty list allows no foreign layer. |
| `conan_publish_url` | none | Same rules as `conan_upstream_url`. Where the shared service forwards `conan upload` for the PUBLIC registry (one with no `target_url`). There is no default, because ConanCenter takes no uploads: with the key absent an upload to the public registry is a 404. A registry with a `target_url` is uploaded to at that URL. |
| `sync_interval_seconds` | `60` | Managed mode only. From 1 to 86400. How long a change on the server may take to reach this firewall. |

The environment variable `PROBATION_SIEM_AUTH` holds the SIEM credential (section
8). `RUST_LOG` (default `info`) sets log verbosity.

### `[management]`

Present means managed mode. A broken section stops the start; the firewall never
falls back to standalone. None of these keys can be pushed from the portal.

| Key | Default | Rules |
| --- | --- | --- |
| `url` | required | The server's address. `https` only, loopback included. No user, query or fragment. |
| `token_file` | required | A file holding only the firewall token. Visible ASCII, no spaces. |
| `key_cache_ttl_seconds` | `300` | How long a cached key and its policy are served without a sync confirming them. From 1 to 86400. |
| `key_cache_max_entries` | `100000` | Not zero. |
| `lookup_budget_per_second` | `50` | Lookups a second for keys the firewall has no entry for. |
| `client_lookup_allowance_per_second` | `5` | One client address's share of that budget. |
| `sync_margin_seconds` | `5`, or half of `sync_interval_seconds` if that is smaller | Each sync starts this much before the interval ends. At most half the interval. |
| `request_timeout_seconds` | `2`, or `sync_margin_seconds` if that is smaller | One call to the server. Not above `sync_margin_seconds`. |
| `trusted_proxies` | `[]` | Address ranges such as `"10.0.0.0/8"`. Section 13. |

### What a settings push may change

A push may set any key above except these, which stay as `config.toml` says:
`management`, `listen`, `data_dir`, `tls_cert_path`, `tls_key_path`, `public_url`,
`siem_url`, `siem_auth_header`. A pushed `log_file_path` or `blocklist_file` must
be a file of its own under `data_dir`, not a symlink, and not one of the
firewall's own files. The token file can never be pushed over.

## 15. Server configuration reference

The server's settings file (`[server]`, `[portal]` and its sub-sections) and its
environment variables are in
[management-server.md](management-server.md#3-the-servers-settings-file) §3. The
database connection has a 1-second statement timeout and a 1-second wait for a
free connection (§4 there).

## 16. Health and monitoring

### The firewall

| Endpoint | What it tells you |
| --- | --- |
| `GET /health/live` | The process is up. Still `200` with an expired blocklist or broken storage. |
| `GET /health/ready` | Standalone: the blocklist is valid **and** storage works. Managed: storage works, a cache was loaded or a sync applied, the firewall is not retired, and the server does not refuse its syncs. `503` otherwise. An answer the firewall cannot read does not make it `503`; alert on its log line instead (section 8). Never checks upstream npm/PyPI. |
| `GET /health/delivery` | **For alerts only, never a health probe.** `503` if a log record was lost in the last 60 seconds. |

Point the liveness probe at `/health/live` and the readiness probe at
`/health/ready`. They differ on purpose: a service with an expired blocklist is
working and should not be restarted. It should leave rotation until the blocklist
is fixed.

While storage is broken, package and download requests also answer `503
STORAGE_UNUSABLE`, even ones that could be served from memory.

A managed firewall whose server is only unreachable stays ready: it keeps serving
from its cache.

`/health/delivery` is unauthenticated and reflects a 60-second window, so polling
less often than that can miss a loss. Poll it more often than every 60 seconds,
and never let it decide whether the service stays in rotation.

There is no metrics endpoint. Watch the periodic summary on stdout (`requests`,
`errors`, `dropped_file`, `dropped_siem`), free disk space, and the alert lines
in section 8.

### The management server

| Endpoint | What it tells you |
| --- | --- |
| `GET /health/live` | The process answers. Always `200`. |
| `GET /health/ready` | Postgres answers `SELECT 1` within 2 seconds: `200`, otherwise `503`. |

Both are unauthenticated and outside the portal's sessions, CSRF and the network
lock. The image has no curl: its health check is `probation-server health`, which
exits `0` when `http://127.0.0.1:8080/health/ready` answers `200` (`--url` for
another address). Both compose files use it.

`SIGTERM` or `SIGINT` stops the server cleanly: it stops taking connections, starts
no new background job run, gives requests in flight and a run in progress up to 20
seconds to finish (the outbox stops between mails), and exits `0`. A second signal
ends the wait at once. Give the container a stop grace period above 20 seconds.

The fleet page shows each firewall's health from its reports:

| Shown | Meaning |
| --- | --- |
| `Healthy` | Checked in recently, and reached npm, PyPI and OSV. |
| `Unhealthy: missed 3 check-ins` | No report for three of its sync periods. |
| `Unhealthy: cannot reach …` | Every call to the named upstream (npm, PyPI or OSV) failed in its last period. |
| `Waiting for its first check-in` | Registered, never synced. |
| `Retired` | Retired on the fleet page; it serves nothing. |

The last settings-push error is shown there too.

## 17. Retention and prune jobs

**The firewall** prunes nothing in `state/` (section 3). It rolls its own log
file (section 8). A managed firewall drops cached keys no request used for a
TTL, after each sync.

**The server** runs its prune jobs inside `serve`: once at start, then every
hour. A failed run logs a warning and is tried again the next hour.

| What | Kept for | Set where |
| --- | --- | --- |
| `change_log` (what firewalls sync from) | `change_log_retention_days`, default 7 | Server settings file. A firewall that was offline longer resets its cache when it comes back and refills it from the server: expect one burst of key lookups. |
| Activity (the Activity page) | 90 days by default | `/admin`, Retention, by a global admin. 7 to 36500 days. |
| Audit log (`/audit`) | 365 days by default | Same place, same range. |

Changing the retention is written to the audit log.

## 18. Limits and caps

### Firewall

| Limit | Value |
| --- | --- |
| `cooldown_seconds` | At most 315360000 (ten years). |
| `sync_interval_seconds`, `key_cache_ttl_seconds` | At most 86400 (one day). |
| `log_queue_max_bytes`, `siem_queue_max_bytes` | From 32 KiB (one record) to 4 GiB. |
| One answer from the management server | At most 8 MiB. |
| Requests, downloads, upstream calls, sizes | The `max_*` keys (section 14). All global, never per client. |
| Waiting for a download slot | `download_wait_seconds` (at most 60) and `max_download_waiters`. Nothing else waits. |

### Management server

| Limit | Value |
| --- | --- |
| Blocks in one policy layer | 5,000. An edit or import past it is refused. |
| Records in one imported blocklist file | 5,000. |
| A block's reason | 256 bytes. |
| Automation API body (`/api/v1/blocklist/{layer}`) | 1 MiB. A larger body gets `413` before it is read. |
| Sync API request body | 2 MiB. |
| Activity and audit retention | 7 to 36500 days. |
| New organisation | 6000 requests a minute, 20 keys per member, 50 service keys, until a global admin changes it on `/admin`. |
| New personal account | 1200 requests a minute, 5 keys. |

## 19. Troubleshooting

| Symptom | Likely cause | What to do |
| --- | --- | --- |
| `check-config` says `unknown key` or `missing key` | A typo, or a key this release does not know. | Fix the named key. Compare with `config.sample.toml`. |
| ``invalid `management.token_file`: cannot be read`` | Wrong path or permissions. | Make the file readable by the user that runs the firewall (`firewall` in the image). |
| Standalone `/health/ready` is `503` | Blocklist missing, invalid or expired, or storage failing. | `probation check-blocklist <file>`; read the log; check free disk space. |
| Managed `/health/ready` is `503` right after the first start | No sync has worked yet and there is no saved cache. | Check `[management] url`, the network path, and the server log. |
| Managed firewall answers `401` to every key | The server refused its token: firewall retired, or the token in `token_file` is wrong. | Check `token_file`. For a retired firewall, register it again on the fleet page, write the new token to `token_file`, restart. |
| Firewall logs `could not be reached` while the server is up | The server refuses the firewall's address (`403` with the header `x-probation-error: FIREWALL_SOURCE_REFUSED`). | Check the server's `[server] trusted_proxies` (section 13). A firewall's allowed source ranges cannot be changed: if they are wrong, register it again with the right ones and retire the old entry. |
| Many `503 LOOKUP_BUSY`, or `403 NETWORK_NOT_ALLOWED` for every key outside one organisation | All clients look like one address. | List the reverse proxy in `[management] trusted_proxies` (section 13). |
| Firewall stays stopped after a settings push | No restart policy. | Add one (section 2) and start it. |
| A push shows an error on the fleet page | The pushed settings failed their checks or the start. | The firewall runs on its previous settings. Fix the push and send it again. |
| Server stops at start: `PROBATION_SERVER_SECRET_KEY is not set`, or `must be 64 hex characters (32 bytes)` | `[portal]` is set and the key is missing or wrong. | Set the key you used before. A new key makes stored authenticator and SSO secrets unreadable. |
| Server stops at start: `PROBATION_SERVER_SECRET_KEY does not match the one these secrets were sealed with` | The key does not open a stored authenticator or SSO secret: usually a database restored from a backup taken under another key. | Set the key the database was sealed with (the one backed up with it). |
| Server stops at start: `PROBATION_SERVER_<PROVIDER>_CLIENT_SECRET is not set` | A provider section with no secret. | Set the secret, or remove the section. |
| `bootstrap refused: a global admin exists already; nothing changed` | Bootstrap ran before. | Use `admin reset-link` for a lost link. |
| `no live global admin signs in as …` from `reset-link` | That address is not a global admin's email sign-in. | Check the address. |
| Nobody receives mail | No `[portal.smtp]`, or the SMTP host refuses. | Add `[portal.smtp]`. Mail waits in the `email_outbox` table. |
| `502 INTEGRITY_MISMATCH` | A file changed upstream after it was first seen. | Investigate as a security incident (section 9). |

## 20. Release and crate-name recovery

The release workflow (`.github/workflows/release.yml`) runs on a pushed `v*.*.*`
tag. Nothing is released unless the tests, the e2e release suite
(`tests/e2e/README.md`) and CodeQL pass. It then builds the firewall archives,
creates the GitHub release, publishes the two images the e2e suite tested to
`ghcr.io/postfix/probation` and `ghcr.io/postfix/probation-server` (tagged with the
version and the commit), and publishes to crates.io from the `crates-io`
environment, which should have required reviewers. `probation-server` is never published to crates.io.

The publish step publishes `probation-policy` and then `probation`, which depends
on it at the same version. If the `probation` step fails after
`probation-policy X.Y.Z` reached crates.io, do not re-run the whole publish.
Finish with `cargo publish -p probation --locked` from the tagged commit, but
only after these two checks pass:

```sh
# 1. The crate name still belongs to this project.
cargo owner --list probation-policy

# 2. The published probation-policy X.Y.Z is the one this commit builds.
cargo package -p probation-policy --locked
sha256sum target/package/probation-policy-X.Y.Z.crate
curl -s https://index.crates.io/pr/ob/probation-policy \
  | jq -r 'select(.vers == "X.Y.Z") | .cksum'
```

The owners must be the project's own, and the two checksums must be equal. If
either check fails, publish nothing: someone else controls what `probation` would
depend on.

### RubyGems clients

Point `gem` and Bundler at `/rubygems/` of the firewall (or `/registry/rubygems/{id}/` of a selected registry): `gem install NAME --clear-sources --source https://firewall.example/rubygems/`, or `source "https://firewall.example/rubygems/"` in the Gemfile. Bundler uses the compact index and sees only eligible versions of each gem. The legacy `specs.4.8.gz` indexes `gem` reads are filtered with the registry's own publication dates (rubygems.org's `timeframe_versions` API, at most 42 days back); a registry without that API lists no gem it has not indexed, and Bundler is unaffected. Through the shared service `gem push` and `gem yank` are forwarded only with the caller's own API key to the selected registry's own origin. Bundler may re-download an info file on each run: upstream's `versions` checksum is the MD5 of the unfiltered file.

### Cargo clients

A registry whose archives are not under the path of its index URL (Artifactory keeps `api/cargo/{repo}/index` and `api/cargo/{repo}/crates` apart) declares an **archive origin** on the registry page of the portal (a Cargo registry with a target only): an https URL, origin and path prefix, without credentials, query or fragment, checked like a target (the enforcer's address denylist applies). Its archives (the `dl` of the registry's `config.json`) are then fetched from that origin and only from it; the registry's read credential is sent there only when it is the registry's own origin. Without one, an archive outside the target's own prefix is refused (502). The descriptor field is `archive_origin`, additive and optional.

Point Cargo's source at `/cargo/` of the firewall (or `/registry/cargo/{id}/` of a selected registry):

```toml
# ~/.cargo/config.toml
[source.crates-io]
replace-with = "probation"
[source.probation]
registry = "sparse+https://firewall.example/cargo/"
[registries.probation]
index = "sparse+https://firewall.example/cargo/"
credential-provider = "cargo:token"
```

The `[registries.probation]` entry names the source to Cargo for credentials (without it Cargo answers "no token found") and `credential-provider` is needed because the firewall asks for authentication (Cargo refuses an authenticated registry that has no provider).

Cargo reads the index file of each crate it resolves and sees only eligible versions: a version published inside the cooldown, a blocked version or one OSV flags is left out of the file, and every other line (checksum, features, yank flag, `rust_version`) is upstream's text. The firewall serves its own `config.json`, whose `dl` and `api` name the firewall, and a crate archive is delivered only when its SHA-256 equals the `cksum` of the same index line. A yanked version stays listed and downloadable, as it does upstream (lockfiles name it). The publication time is the `pubtime` field crates.io writes (or `created_at`, whichever is later); a line without either waits on the time this firewall first saw it.

Names: policy, blocklist and OSV key a crate by its lower-case name with `_` folded to `-` (crates.io treats them as one name); the archive file name keeps the registry's spelling (`Inflector-0.11.4.crate`), so the download URL needs the crate name exactly as the index line spells it, which Cargo does.

Authentication: a managed firewall on the key route (`/cargo/`) sets `auth-required` and answers `401` with a `Cargo login_url` challenge, so Cargo sends its token with every read. Cargo sends the token as written, so store it with the word `Bearer` (`token = "Bearer prb_..."` in `credentials.toml`). Cargo authenticates with an API key on the key route (product decisions C1006 and C1007: Cargo and Go sign in through the installed client and the key route, not a client certificate), so the certificate script configures npm, pip and RubyGems only and points Cargo at the Keys page. Through the shared service the registry API is forwarded as class W: `cargo publish` (`PUT /api/v1/crates/new`), `cargo yank` and `--undo` (`DELETE`/`PUT /api/v1/crates/{name}/{version}/yank|unyank`) and `cargo owner --add/--remove` (`PUT`/`DELETE .../owners`) go to the registry's own API root with the caller's own token (Cargo sends it bare in `Authorization`) and never the service key; a write without a token is refused locally with 401 before any upstream call, a body over `max_artifact_bytes` (doubled) is 413, and the registry's own answer (200, 401, 403) is the caller's. The API root is the `api` the registry's `config.json` names, and it must be the registry's own origin (or `https://crates.io` for the `index.crates.io` source); any other host is refused with 502 and nothing is sent. The owner list (`GET .../owners`) and `cargo search` (`GET /api/v1/crates?q=...`, only the query keys `q`, `per_page`, `page`, `sort`, `category`, `keyword` and `letter` are passed on) are forwarded as reads with whatever credential the caller sent and are never cached. A standalone or managed firewall has no such routes and answers 404; the rewritten `config.json` still advertises `api` so those commands reach the shared service where it is the registry. In shared-service mode an index and its `config.json` are shared between credential-free reads for 5 seconds (one upstream fetch for a burst, or for the two lookups of one download); a request that carries a credential never reads or fills that share.

The firewall fetches `config.json` of the registry once a minute at most and never reads or fills that cache for a request that carries a credential.

### Go clients

Set `GOPROXY` to the firewall's `/go/` (or `/registry/go/{id}/` of a selected registry) and nothing else:

```sh
export GOPROXY=https://key:prb_...@firewall.example/go/    # one URL: no ",direct", no "|" fallback
```

`GOPROXY` must name only the firewall. In a list such as `...,direct` the client falls back to the origin whenever the
first entry answers 404 or 410, and with `|` it falls back on any error, so a version the firewall does not list can
still be fetched from another source. The firewall answers a refused version with 403 (which `go` does not treat as a
fallback trigger with a comma), but only the single URL keeps every path protected. The firewall serves exactly the module
proxy protocol: `GET {module}/@v/list`, `{module}/@latest` and `{module}/@v/{version}.info|.mod|.zip` (HEAD and ranges
on the files), with the module path and the version case-encoded (`!` before a capital letter) exactly as `go` writes
them; any other spelling of the same module is a 404 and asks upstream nothing.

What is applied. The publication time of a version is the `Time` of its own `.info` (the proxy protocol has no other
source); a version whose `.info` has no `Time` (or the zero time) waits on the time this firewall first saw it, and a
`Time` that does not parse refuses the version (502). The three files of a version are judged together: `.info`, `.mod`
and `.zip` of a version held by the cooldown, a block or OSV (ecosystem `Go`, the module path as `go` writes it, the
version without its `v`; `2.0.0` and `2.0.0+incompatible` are one version for a block) are all refused (403), and a held version's `.mod` and `.zip` are never
fetched. `@v/list` shows only the versions that pass, in the proxy's order. Pseudo-versions are not listed by the proxy, so
each is judged by its own `.info`. `@latest` is the proxy's own answer when it passes, else the highest release (with no
release, the highest prerelease) that the filtered list still offers, else 404. A zip is delivered exactly as the proxy sent
it (nothing is repacked or unpacked, so no inflate cap applies); the first verified download pins its digest and a later,
different body is refused.

Re-admission. A policy publication (any sync that changed anything, a new shared-service snapshot) between a request's authorisation and its release refuses the finished response (SPEC §9). For every GET and HEAD of every family, in every mode, the shared layer around the routes admits the request again from the start under the new policy, at most three times: a block or a stricter rule published meanwhile wins (nothing admitted under the old policy is served), a change that keeps landing is reported as 503. Writes are never replayed. Cost: each admission repeats the rate-budget check, the upstream calls and the OSV lookups of the request, so a tenant near its rate limit can see a 429 from a request that was already admitted once, a request that bypasses the store (a credential-bearing read) downloads again from upstream on each admission, and a download that was already stored is decided again. The publication generation is global, so one publication re-runs every in-flight read of every tenant, each at most three times (before the layer these were 503s).

Bounds. A burst of lists of one module makes one fan-out: a request that finds one running does not wait for it (it answers at once with what is dated). `.info` and `.mod` transfers have their own 64 places in addition to the `max_artifact_downloads` of the large transfers, have their own `max_download_waiters` waiter places (slow tiny files never take the places of zip requests), and are read to 256 KiB (`.info`) and 16 MiB (`.mod`) at most. One list request makes at most 64 `.info` calls (eight at a time, newest versions first, none for a version a block
already refuses); a version still undated after that is withheld until a later request has dated it, so the list of a module
this firewall has not seen completes over a few requests. A list of more than a third of `max_references_per_project`
versions, a `.info` over 256 KiB and a list over `max(max_metadata_bytes, 16 MiB)` are refused. Revision queries (`go get mod@main`) are bounded before any upstream call, per minute: 32 distinct tokens per key and module, 64 per organisation and module (so one organisation's many keys cannot use up the module's 256-token ceiling for everyone else), 256 per module, and 64 distinct modules per key (a key that floods module names stops at that bound; it does not reset its own windows). Past a bound the answer is 429. Dates are remembered in
memory per module for `metadata_ttl_seconds` (5 s through the shared service); a version the proxy no longer has is 404
even when its zip is stored.

The checksum database. `go` asks the proxy for `sumdb/{name}/supported` before it contacts the database itself; the
firewall answers that and forwards `latest`, `lookup/{module}@{version}` and `tile/...` to `go_sumdb_url` only (the database
name must be that host), so `GOSUMDB` works unchanged through the firewall. These reads carry hashes, never module content;
they are not cached, never carry the caller's credential and are answered on the public registry only (a registry with a
`target_url` of its own has no checksum route: keep its modules out of the public database with `GOPRIVATE` or `GONOSUMDB`).

Redirected zips. proxy.golang.org answers a zip of about 10 MB or more with a 302 to its signed storage bucket (`go_artifacts_url`); only a `.zip` transfer follows it, never a list, an `.info` or a `.mod`, and the registry credential is not sent there. A private proxy in redirect mode (Athens or Artifactory with cloud storage) does the same to its own storage: such a registry declares an **archive origin** on the registry page of the portal (a Go registry with a target only; an https URL, origin and path prefix, without credentials, query or fragment, checked like a target: the enforcer's address denylist applies). A redirect of that registry's zip may then land there and nowhere else; without one a redirect away from the registry is refused (502). The descriptor field is `archive_origin` (the same optional field Cargo registries use); an older enforcer ignores it and so keeps refusing the redirect.

Revision queries. `go get mod@main`, `mod@v1` and `mod@<commit>` ask `GET {module}/@v/{rev}.info`; the firewall passes a bounded token (`[A-Za-z0-9._+-]`, at most 128 bytes, lower case on the wire, never starting with `.` or `-` and never holding `..`) to the proxy, at most 32 distinct tokens per key per module per minute and 256 per module across all keys (429 beyond; one key's junk never blocks another key, and the counting tables are bounded: a flood evicts old windows, it never blocks), and judges the version the proxy resolves it to (a pseudo-version or a tag) by that version's own time, block and OSV: a name for a held or blocked version is held or blocked, and the answer is that version's `.info`. Its `.mod` and `.zip` then take the ordinary path.

Dates and back-dating. A version's time is the proxy's `Time`, which for a VCS-backed module is the commit time the publisher chose. The firewall therefore dates a version no earlier than its own first sight for any version that appears after the first list it saw for that module (a later list, or a pseudo-version asked for afterwards): it is held for one cooldown from that day whatever `Time` says. What stays trusted: every version of a module's first list (and any version asked for before the module's first list was ever served), whose `Time` is used as sent. The limit is the very first list: a back-dated version already present when this firewall first lists a module has its upstream date. A pseudo-version of a module whose list the firewall already saw is held one cooldown from the first request for it, even for an old commit. Plainly: a CI that pins an old pseudo-version of a module whose list this firewall has since seen (a `go get -u` or `go list -m -u` through it is enough) can get 403 for that version for one cooldown, although go.sum pins it, and the same request made before that list was seen is served; an exception entry for the version is the way through.

Authentication. A managed firewall on the key route (`/go/`) takes the key as HTTP Basic (the userinfo of the `GOPROXY` URL,
or a `.netrc` entry). `go` has no client-certificate setting for a module proxy (product decisions C1006 and C1007), so the
certificate script writes no Go configuration and points at the Keys page. Through the shared service a selected registry's
own credential is the caller's `Authorization` (Basic or Bearer); such a request is request-scoped (nothing of it is cached or
shared, and its zip is held in a request-owned file). Go has no write protocol: a module is published by pushing to its
repository, never to a proxy, so every non-read request is refused and nothing is forwarded.

### NuGet clients

Point the client at the firewall's service index and at nothing else:

```sh
dotnet nuget add source https://firewall.example/nuget/v3/index.json --name probation \
  --username key --password prb_... --store-password-in-clear-text
dotnet nuget disable source nuget.org      # one protected source: a second source would offer what this one refuses
```

(`/registry/nuget/{id}/v3/index.json` of a selected registry; in `nuget.config`, a `<clear />` and one `<add>`.) The key is
the password of HTTP Basic. The firewall serves the NuGet v3 protocol: `GET v3/index.json` (the service index), the flat
container (`v3-flatcontainer/{id}/index.json` and `{id}/{version}/{id}.{version}.nupkg`, `{id}.nuspec`, `readme`, `icon`; HEAD
and ranges on the files), registration (`v3/registration/{id}/index.json` and `{id}/{version}.json`), `v3/query` and
`v3/autocomplete`, `v3/vulnerabilities/...` and `v3/repository-signatures/...`. The id is the one lower-case spelling and the
version the one normalised lower-case spelling (`1.0.0.0` is `1.0.0`; `1.0.0-Beta` is `1.0.0-beta`), as every URL of the
protocol spells them; any other spelling is a 404 and asks upstream nothing.

The service index. The firewall reads the registry's own service index (cached 60 s per registry) and serves a rewritten
one: every resource it can protect points at a route here, and it says nothing else. A resource the registry names on an
origin that is not configured is not used: for the public registry the three origins `nuget_upstream_url` (the index, flat
container, registration, vulnerability and signature documents; default `https://api.nuget.org`), `nuget_search_url`
(`https://azuresearch-usnc.nuget.org`) and `nuget_publish_url` (`https://www.nuget.org`); for a registry of your own
(its `target_url` is its service index, `.../v3/index.json`, or the directory holding it) every resource must lie on the
registry's own origin, any path. A registry whose flat container is elsewhere cannot be served (502); a search or publish
service elsewhere is simply not offered. Not advertised, because there is nothing to protect or serve: the legacy gallery,
package staging, the catalog, and the web-page URI templates (report abuse, package details, owner details). Registration is
served as one SemVer 2 view for every `RegistrationsBaseUrl` type (the registry's semver1-only view is not offered separately).
`RepositorySignatures` is advertised only when the firewall's public URL is https (the NuGet client refuses it over http, NU1301; over
http package signatures are verified by the client alone). `VulnerabilityInfo` is advertised over http too, so a development setup
with `allowInsecureConnections` keeps `NuGetAudit`; audit data over plain http is unauthenticated for an on-path attacker, which is
an operator's choice of public URL (use https for anything beyond a development machine).

What is applied. A version's publication time is the `published` of its registration leaf. The unlisted sentinel
(1900-01-01), an absent value and one that does not parse are "no date": the version waits on the time this firewall first saw
it (held for a whole cooldown) and is never dated from a cache or a build time; a version the flat container lists and
registration does not yet name is held the same way. The four files of a version (`.nupkg`, `.nuspec`, `readme`, `icon`) are
judged together: held by the cooldown, a block or OSV (ecosystem `NuGet`, the lower-cased id, the normalised version without
build metadata; `1.0.0` and `1.0.0.0` are one version for a block) all four are refused (403) and a held version's files are
never fetched. The flat container's `index.json` lists only the versions that pass, in the registry's order. Registration is
rendered page by page (a page the registry inlined stays inline; one it links is read only under that registry's own directory of its
registration base and is served by this firewall's page route), the leaves that pass, `count`, `lower` and `upper` recomputed, `@id`, `packageContent`, `registration`,
a registry-own `iconUrl` and `readmeUrl` (the flat container's readme route here), a dependency's `registration` link and every other URL of the registry's own origin (a catalog entry
and its fragments) pointed at this firewall (a catalog URL becomes `v3/catalog/...`, a route that is not served, so no link in a
document leads a client around the firewall; a licence or project page on another host is the packager's own and stays); a leaf of a
held version is 403. A file is delivered exactly as the registry sent it (nothing is repacked or opened, so no inflate cap applies; the NuGet
client verifies the package's own signature); the first verified download pins its digest and a later, different body is
refused. Search (`v3/query`) and autocomplete (`v3/autocomplete`) keep only the protocol's own query keys (`q`, `id`, `skip`,
`take`, `prerelease`, `semVerLevel`, `packageType`, `supportedFramework`), pass `take` on exactly (whatever its size: the registry
applies its own ceiling, 1,000 on nuget.org, and a clamp would silently skip the results between what the client asked for and
what it got; `totalHits` is the registry's and counts versions this firewall withholds) and show a package only with its allowed
versions: each result costs a registration and flat container read, every returned result (up to 1,000) is judged two at a time
(so a large `take` leaves the registry's other refresh places to other reads) under the request's 60 s deadline (a request that runs out of it is a 504; a result whose project cannot be read fails the search, a package the registry does not have is not shown, nothing is dropped silently), and a blocked id is refused before
the registry is asked about it. The registration index keeps a page the registry inlined inline and links a page the registry only
linked to this firewall's own route (`v3/registration/{id}/page/{lower}/{upper}.json`, the registry page's bounds), so no response
holds every leaf of a project with thousands of versions. The vulnerability database (`NuGetAudit`, `dotnet list package
--vulnerable`) and the repository signature index are read through the firewall: only the files and certificates the
registry's current index names are served, from that index's own origin.

Bounds. Documents (and each registration page) are read to `max(max_metadata_bytes, 16 MiB)` (the largest registration measured is far
below it); a registration page is read, its facts taken and its bytes dropped, so a project's registration is not held whole.
Every version of a project (up to 200,000, a registration of up to 4,096 pages) is kept, judged and listed; only the newest
`max_references_per_project / 4` versions have their four reference rows made at refresh, and any other version has its rows made
when a file of it is first asked for and the policy does not refuse it (an exact pin of version 1.0.0 of a nightly feed restores); such rows are bounded per project at four times `max_references_per_project` beyond the newest versions' own, and one more old version past that is a 503; a service index of more
than 512 resources, a vulnerability index of more than 16 entries and a signature index of more than 64 certificates are refused, a `.nuspec`, readme or icon is read to 16 MiB and takes one of the 64 small-transfer places
(not a place of the large ones). Work that reaches the registry is bounded across requests: a
service index is cached per registry (60 s, 64 at most); one request at a time refreshes one project (the others wait for it and use
what it stored), at most 16 project refreshes run at once in the process and one registry holds at most 4 of them (a wait over 30 s is a 504, so a slow registry of one organisation cannot starve another's reads), every document request has a
60 s deadline, the registration documents of an id are shared for 5 s (8 ids, 16 MiB each), a vulnerability or signature document
for 30 s (16 documents of at most 8 MiB; the vulnerability file is read to 32 MiB) and, in the shared service, one fetched project
for 5 s per registry and id (256 at most); a read that carries the caller's credential reads and fills nothing shared, and every
certificate is served only when its bytes hash to the SHA-256 fingerprint the registry's index names.

Uploads. Every publish forwarder (npm publish, PyPI upload, `gem push`, `cargo publish`, `dotnet nuget push`) spools the body to
an unnamed file before forwarding so the policy can be rechecked first. That spool is bounded in one place (src/http/spool.rs): at
most 8 uploads at once, at most 4 of them one owner's (the ninth, or an owner's fifth, is a 503, not a queue; the owner is defined in "Who a spool share belongs to" below), all of them together within one byte budget (four times `max_artifact_bytes`, at
least 64 MiB: one owner's half is then the largest upload any forwarder accepts, an artifact plus its envelope), taken as the bytes arrive and not as a declared length (a declaration that
never delivers holds a place and nothing else; an upload that finds the budget taken waits up to 30 s for the others to finish instead of being refused), a body that stalls for 15 s (60 s for its first chunk) or does not arrive within 15 minutes is refused, a write
with no credential is 401 before anything is read, an empty body (unlist, relist) takes no place, and a declared or received length
over the cap is 413 before a place is held for it. The credential's value is not validated here (the registry does that), so a
junk key can occupy the places for at most a minute of silence and never more than the budget.

Resource path prefix. A registry of your own may declare a path prefix (the portal's registry page; migration 0019, optional,
whole segments such as `/org-a/_packaging`): every resource its service index names, and every document its vulnerability and signature indexes name, must then lie under it, so a feed host that
serves many tenants by path cannot be steered to another tenant's path with your credential. Absent, the whole host is admitted
(Azure Artifacts, Artifactory, GitHub Packages and BaGet name resources beside, not below, the index); set it when your layout
allows. Publish-date residual: the cooldown trusts a version's `published`; nuget.org assigns it, but a self-hosted feed that takes it from the publisher can be back-dated (the same accepted residual as Go's first list: no code defends it, an exception entry or a block is the way through).

Redirects. api.nuget.org answers a package directly. A registry of your own that redirects a `.nupkg` to its storage (GitHub
Packages, Azure Artifacts, Artifactory with cloud storage) needs an archive origin on its descriptor (the portal's registry
page; migration 0018): only a `.nupkg` transfer follows a redirect, and only to that origin; the registry credential is not
sent there. Without one a redirect away is refused (502).

Authentication. A managed firewall on the key route takes the key as HTTP Basic (the source's username and password). NuGet
signs in with credentials or an API key, never a client certificate (product decisions C1006 and C1007), so the certificate
script writes no NuGet configuration and points at the Keys page. Through the shared service the registry's own credential is
the caller's `Authorization` (Basic or Bearer), forwarded to the registry's own origin only; a request that carries one is
request-scoped. The client sends `X-NuGet-Client-Version` and `X-NuGet-Session-Id` on every read (measured with .NET SDK
8.0.416); they carry no credential and are on the read allow-list.

Writes. Only the shared service forwards them (class W), on the selected-registry route: `dotnet nuget push` (`PUT
api/v2/package`, a multipart body), the symbol package (`PUT api/v2/symbolpackage`), `dotnet nuget delete` (unlist, `DELETE
api/v2/package/{id}/{version}`) and relist (`POST` of the same URL). The caller's own `X-NuGet-ApiKey` and `Authorization` go to the
endpoint the registry's service index names (the registry's own origin; for the public registry `nuget_publish_url`), never the
service key; a write with neither is refused locally with 401 before any lookup, a body over twice `max_artifact_bytes` with 413
(the spool above bounds the rest), and the registry's answer comes back as plain text or JSON with `X-Content-Type-Options: nosniff`
(a status that is no publish answer is a 502). A standalone or managed firewall has no write route: any non-read verb on `/nuget/`
is 405 and reaches nothing.

### Maven and Gradle clients

Point Maven at the firewall as the one mirror of every repository, with the key as the password of the matching server
(`~/.m2/settings.xml`):

```xml
<settings>
  <mirrors><mirror><id>probation</id><mirrorOf>*</mirrorOf><url>https://firewall.example/maven/</url></mirror></mirrors>
  <servers><server><id>probation</id><username>key</username><password>prb_...</password></server></servers>
</settings>
```

(`/registry/maven/{id}/` of a selected registry.) Gradle: `maven { url = uri("https://firewall.example/maven/"); credentials { username = "key"; password = "prb_..." } }` as the only repository, in
the project and in `pluginManagement`. One mirror with `mirrorOf *` is the one protected source: a second repository would offer what this
one refuses. Maven refuses an `http` mirror unless it is declared (it is, by this mirror); use https beyond a development machine.

What is served. The repository layout under `/maven/`: `{group as directories}/{artifact}/maven-metadata.xml`,
`{group}/{artifact}/{version}/maven-metadata.xml` of a `-SNAPSHOT` version, `{group}/maven-metadata.xml` of a plugin group,
`{group}/{artifact}/{version}/{artifact}-{version}[-{classifier}].{ext}` (POM, JAR, sources, javadoc, `.module`, distributions)
and every `.md5`, `.sha1`, `.sha256`, `.sha512` and `.asc` of them, and `archetype-catalog.xml`; `HEAD` and ranges on the files.
A coordinate, version and file name have one spelling (group directories carry no dot; the file name is the artifact id and the version
the directory names); anything else is a 404 and asks the repository nothing. The identity is `groupId:artifactId` as the layout spells it
and case is identity (`Foo` and `foo` are two artifacts, as on every repository). Directory listings and files that are no part of the layout
are not served.

What is applied. A version's publication time is the `Last-Modified` of its POM (the repository's own, set when the file was uploaded or
synced); a version whose POM has none, or none that parses, waits on the time this firewall first saw it (held for a whole cooldown), and no
directory listing time, cache age or build time is ever used. The metadata lists only the versions that pass (the
age, a block, OSV on `groupId:artifactId` and the version directory verbatim, a pinned digest), in the repository's order; `latest` and
`release` name the newest allowed (the element goes when none is left); everything else the document says is passed on byte for byte. Its
`.md5`, `.sha1`, `.sha256` and `.sha512` are the checksums of what was served, and its `.asc` is the repository's own only when nothing was
removed (a signature of other bytes would not verify, so it is a 404 then). The dating of a long listing is bounded per request (2,048 POMs
newest first, 16 at a time, committed as they are read; the largest artifact measured on Central has 1,956 versions): a version still undated is withheld, and the next request settles more.
Every file of a version is refused (403, with the hold's deadline when it is a hold) when the version is, and a refused version's files are
never fetched; a file the repository does not have makes no reference and is a 404. A snapshot build (`1.0-20260101.120000-3`) is its own unit:
it is aged by its own POM, the version-level metadata keeps the builds that pass and points at the newest of them (403 with the hold when
there is none), and a block or an exception written for `1.0-SNAPSHOT` applies to every build. The artifact-level listing names a snapshot directory
unless a block names it. A POM may name repositories of its own (`<repositories>`); `mirrorOf *` sends every one of them through this firewall, so that mirror is what makes it the one source (Gradle ignores a POM's repositories unless told otherwise). A plugin group's metadata lists no plugin whose package a block names; the archetype catalog lists no archetype whose
package or version a block names and carries no `<repository>` URL of its own. The documents are read by a strict scanner (no document type or entity declaration, no processing
instruction, no entity other than the five predefined and numeric references, nesting at most 24 deep, at most 16 MiB for a metadata document and
128 MiB for the archetype catalog, which is 18.6 MB on Maven Central): anything else is a 502, never expanded or fetched.

What is shared. Credential-free reads share a fetched metadata document for 5 s, the dates of an artifact's versions in a bounded table (128
artifacts), and one refresh at a time per artifact; a read that carries the caller's own credential reads and fills none of it (the committed
reference identity, first-seen times and pins are the only memory that outlives a request). Refreshes are bounded process-wide (16) and per
registry (4), the archetype catalog is read one at a time, and a project may hold at most five times `max_references_per_project` reference rows.
A POM, checksum, signature or `.module` is a small file (up to 16 MiB, its own pool of places) and never queues behind a large download.

Through the shared service. A registry with a `target_url` is read at that URL (its repository root, path included) with the caller's own
`Authorization` (Basic or Bearer; a bare key is not accepted); its `401` carries the `Basic` challenge Maven needs; a repository that redirects
a download to storage declares that origin on its registry page (an archive origin: only a large file's transfer follows it, never a
POM or checksum, and the credential is not sent there). `mvn deploy` (and `deploy:deploy-file`) is forwarded: a `PUT` of each file, checksum,
signature and metadata document, and a `DELETE`, to the registry's own origin (for the public registry, `maven_publish_url`, and a 404 when it is not
set) with the caller's own `Authorization` and never a credential of this service. Maven sends no credential until it is challenged: a write
with none is answered `401` with `WWW-Authenticate: Basic` before anything is read or asked, a body over twice `max_artifact_bytes` is `413`,
a path that is no layout path is `404`, and the registry's answer is relayed only with a status a deploy endpoint gives (otherwise 502), as
plain text that no browser sniffs. Every upload shares the one bounded spool of the other forwarders. A standalone or certificate-managed firewall has
no deploy route (405). The certificate script writes no Maven configuration (the JVM's trust store is a system matter and `mvn` signs in
with the key) and points at the Keys page.

Maven, fix round of review 21 (what changed in the paragraphs above).
- Rows: the per-project row bound (five times `max_references_per_project`) is hard: a unit's POM anchor is also refused with a 503 past it (nothing is committed first), and a listing is dated only up to the room the bound leaves.
- A version listed with no POM at all (a bare jar on a private repository) is not cut for ever: it is held for one cooldown from the time this firewall first listed it and then served (its files are confirmed to exist when one is asked for).
- Documents: a comment may hold an ampersand; a document that declares `ISO-8859-1` is read as such (served as the repository wrote it when nothing is removed, as UTF-8 with the declaration changed when something is); any other non-UTF-8 document is a 502. A document that could be read two ways is a 502 and is never filtered and passed on: a repeated `latest`, `release`, `lastUpdated`, `snapshot`, `versions` or `plugins`, a `version`, `latest`, `release` or build with markup inside, `plugins` beside `versions`, or a prefixed element name.
- `DELETE` of a whole artifact or version directory (`.../lib/1.0/`, as Nexus and Artifactory take it) is forwarded to the registry's own directory URL; `PUT` still names a file.
- Files: a file's own `Last-Modified` counts as well as its POM's: a classifier or module file added later to an old version waits its own cooldown (the probe reads headers only, never the body). A Gradle `.module` file that names a location by absolute URL (`files[].url`, `available-at.url`) is refused (403) because the client would be sent outside this repository; relative URLs, the normal form, are served. The first download of a file is compared with the `.sha1` the repository publishes next to it (when it publishes one) before its digests are pinned; a mismatch is a 502 and nothing is stored or pinned.
- The archetype catalog waits for one slot BEFORE it takes a refresh place (a queue of catalog requests holds nothing another document needs) and credential-free reads share the fetched copy for 5 s; a read that carries the caller's credential fetches its own and keeps none.
- Uploads: the spool places of every forwarder (npm, PyPI, RubyGems, Cargo, NuGet, Maven) are counted per credential PRESENTED (a hash of `Authorization`, `X-NuGet-ApiKey` and the like together with the service key), at most four per credential of the eight, an upload that stalls is cut after 15 s (it was 60 s), and after 20 s a body must average at least 1 KiB/s: a trickle can no longer hold a place for the whole 15-minute deadline, and one caller's open uploads do not use up another's places. A caller can still present many distinct credentials; the eight places and the byte budget bound that, and the rate floor ends it in seconds.
- Hosted registries that let a depositor choose the stored modification time (some Artifactory and GitHub Packages style feeds, imports, checksum deploys) can back-date a POM and skip the cooldown for that unit: the same accepted residual as Go's first list and NuGet's `published`. A block or an exception entry is the way through; the operator decides which hosted registries to register.
- A snapshot whose newest build is held, on a repository that lists only the newest build per extension in its metadata, resolves to a 403 with the hold until the build is old enough (an older build is still downloadable by its exact name): that is the cooldown applied to the newest build, stated here so it is not mistaken for a defect.

Maven, recheck of review 21 (changes to the paragraphs above).
- Uploads: the first chunk of a body may take up to 60 s to arrive; once it has started a stall of 15 s cuts it. A body must average 16 KiB/s after a 20 s grace; a body with no declared length may take 5 minutes at most, a declared one 20 s plus twice its length at that rate (never more than 15 minutes). Who a place is counted against is described in the recheck-2 paragraph below (it replaces the earlier per-service-key counting).
- A checksum file the registry does not have may be answered 403 as well as 404 (a bucket that does not list absent keys): that is "no sidecar", not a failed download; a sidecar that is there and disagrees still blocks the pin.
- The row bound and the rows a listing makes are counted and committed under one gate per project, so simultaneous first requests cannot pass the bound together.
- A catalog read that carries the caller's credential takes its own registry's slot (and one of four process-wide private ones), never the slot the public registry's reads wait for.
- `python3 tests/e2e/native/run_tests.py` defaults its scratch directory to `<repository parent>/.<repository>-scratch/native` on disk (several tests assert on the host's file systems and /tmp is RAM here); `NATIVE_TEST_SCRATCH` overrides it.

Maven, recheck-2 of review 21: who a spool share belongs to (one rule for all six forwarders: npm, PyPI, RubyGems, Cargo, NuGet, Maven).
- A place and the bytes of an upload are counted against REAL identities only, never an unvalidated credential alone. Certificate-managed firewall: the caller's ACCOUNT (the firewall has authenticated it; every principal there carries key id 0, so the key id counts nothing). Shared-service mode: the CLIENT ADDRESS, because the firewall cannot tell a valid credential from junk (the registry decides): the peer address of the connection, or, when the peer is listed in `[service_policy] trusted_proxies` (address ranges, default none), the rightmost `X-Forwarded-For` entry that is not itself a listed proxy (the same reading as `[management] trusted_proxies`; an entry that is not an address counts as the proxy's own address). `X-Forwarded-For` from any other peer is never read, so a forged header buys no share. The credential presented (`Authorization`, `X-NuGet-ApiKey`, cookies and the like) is the second, separately capped count in every mode.
- No owner (account, address or credential) holds more than half of the places (4 of 8) or half of the byte budget. A byte is reserved as it arrives (never the declared length), so a burst followed by a trickle cannot hold the whole budget; an upload past its owner's half waits up to 30 s for its own bytes to come back, then is a 503. One account (or address) at its share never keeps another's deploy out; the other 4 places stay reachable.
- Trickles: the rate clock starts at the FIRST chunk (the 20 s grace and the 16 KiB/s average are measured from it, so a small first chunk that takes up to the 60 s first-chunk wait is accepted), and the rate is also held over each 20 s window, so a body that bursts early and then trickles is cut within about one window and 15 s rather than after its credit (minutes) or the 15-minute deadline. An owner BELOW the floor therefore holds a seat for roughly 35 s at most; a body AT the floor still holds its seat for its deadline (5 minutes undeclared, up to 15 minutes declared). The time an upload spends waiting for its own bytes is not counted against its rate.
- Limits. Callers behind one NAT or an unlisted proxy share one address and so one share; an IPv6 client is counted by its /64 (one machine holds a whole /64), and an IPv4-mapped address as IPv4. The share rule stops ONE identity, not a caller that controls several: two source addresses with different credentials, each sending a body at the floor rate, can hold all 8 places and the whole byte budget for 5 to 15 minutes, and repeat, so publishes (never reads) are 503 meanwhile. The firewall cannot do better in shared-service mode, where the credential is validated only by the registry; put the listener behind the allowed peers (`allowed_peer_cidrs`) and the proxy's own limits. Behind a reverse proxy list it in `[service_policy] trusted_proxies`, or every caller counts as the proxy's address (one share for the whole deployment); the firewall logs one warning when an unlisted peer sends `X-Forwarded-For`.
- One owner's uploads larger than a quarter of the budget take turns (a second waits up to 30 s for the first), so two big uploads of one account do not hold each other's bytes; one body of the full accepted size (artifact plus envelope, up to twice `max_artifact_bytes`) always fits one owner's half.

### OCI clients

Docker, Podman, containerd, CRI-O, skopeo, crane and Helm (any client of the OCI distribution API, `/v2/...`). Every manifest, index and blob is judged
before a byte reaches the client; nothing of a registry is relayed that the firewall has not read strictly and rebuilt (a tag list, the catalog and a
referrers index are rebuilt from the entries that are well formed; every `Link` is rewritten into the firewall's own namespace or dropped).

Client set-up (the firewall is `fw.example`, served over TLS the client trusts):

```
# Docker / Podman, by name:   docker login fw.example -u key -p <API key>   (a certificate-managed firewall)  then  docker pull fw.example/library/alpine
# Docker daemon, as a mirror: /etc/docker/daemon.json  {"registry-mirrors": ["https://fw.example"]}
# Podman, as a mirror:        /etc/containers/registries.conf.d/probation.conf
#                               [[registry]]
#                               prefix = "docker.io"
#                               location = "docker.io"
#                               [[registry.mirror]]
#                               location = "fw.example"
# containerd (a node), original names kept:  /etc/containerd/certs.d/docker.io/hosts.toml
#                               server = "https://fw.example"
#                               capabilities = ["pull", "resolve"]
```

A mirror that is not the only route is no protection (the client falls back to the origin when the mirror refuses): the cluster guide pins nodes to the service
(slice 26). The tests exercise podman (a native lane, `tests/oci_native.rs`), skopeo (`E2E-oci`, `E2E-publishing-oci-service`) and containerd
(`E2E-service-cluster-probe`).

Routes. A standalone or certificate-managed firewall serves `GET|HEAD /v2/...` for its default registry (`oci_upstream_url`, Docker Hub unless
changed). A shared service serves the same `/v2/...` when its snapshot names exactly one OCI registry, and `/registry/oci/{registry}/v2/...` for each
selected registry; containerd and the Docker daemon send `?ns=<registry>` to a mirror, which is read for its shape and nothing else (the route has
chosen the registry). Class W (a shared service only): blob uploads (`POST`, `PATCH`, `PUT`, `GET` of a session, `DELETE`), a manifest `PUT` and the
`DELETE`s are forwarded with the caller's own credential to the registry's own origin; a write with no credential is answered `401` with the challenge
before anything is read or asked, a firewall key is refused as a registry credential (403), and every `Location` that comes back is rewritten into the
firewall's namespace (one that leaves the registry's origin or path prefix is a 502, never passed on). A blob is spooled through the shared upload
spool (owner = the client address /64 and credential in a shared service) up to `max_artifact_bytes` (what can be pulled back); a larger layer is a 413 before the registry is asked. A layer with no declared length (docker, skopeo and containerd stream it chunked) may take what its size needs at the shared rate floor of 16 KiB/s, at most two hours (a 5 GiB layer needs about 0.7 MiB/s on average); a declared length has the shared rule. One owner pushes as many layers at once as its half of the spool budget holds at the largest layer size (two by default); the others WAIT their turn, they are never cut in the middle of their stream. Only a request whose body can be a layer takes a place of that lane (a `PATCH`, or a `PUT` or `POST` that declares more than 1 MiB or no length and has a body): the empty `POST` that starts an upload, the finishing `PUT` and a manifest `PUT` never wait behind a layer, so a push of several multi-GiB layers keeps its small requests prompt. A client that goes away during a first pull of a layer stops the transfer when no other request shares it (a request that shares it keeps it). A request that waits holds no active-request place (it takes one when its turn comes); at most six requests of one owner wait, the rest are a 503 at once, and a wait ends in a 503 after ten minutes, in both cases before any byte of the body is read (docker retries a layer upload). Worst case for an owner that declares no length: a layer that streams is held for up to two hours, so one owner holds at most two of the lane's places for that long (the lane's size) and, with every other owner and every other family's uploads, at most eight places of the spool in total. A standalone or certificate-managed firewall has no write route (405, before anything is read).

Login. The registry's own token flow, unchanged for the client: `GET /v2/` is answered `401` with `WWW-Authenticate: Bearer realm=<this firewall>/v2/token`
when the registry wants a login (a registry that takes Basic directly gets a Basic challenge), the client asks `/v2/token` with its own credential, and
sends the token it gets. A firewall on the API-key route answers that request itself with the API key as the token (`docker login <host> -u any -p <key>`); a certificate-managed firewall answers it with its own pull-only token (`probation-pull-<expiry>.<HMAC>`: keyed by a secret that exists only in this process, bound to the certificate holder's place, the registry and five minutes, so it is not a constant; it authorises nothing, because admission is by the client certificate, so a presented token is checked for its SHAPE only and one minted by another instance or by an earlier process of this one is accepted: behind a balancer a client's requests may reach any instance and a restart does not turn tokens into failures; a malformed one is sent the challenge again), which is never a registry token and never the registry's stored credential (the firewall adds that itself, server-side), whatever scopes are asked (push, delete and `*` are not granted; a repository the policy blocks is left out); admission itself is by the client certificate, so a request that presents no token is admitted by it too; a shared service asks the registry's token realm with the credential the CALLER sent (its own Basic, never anything stored) and relays the token. The token realm is the registry's own origin, the token origin its descriptor declares (`token_origin`, an https origin set on the registry page, for a GitLab-style registry whose realm is another host; a certificate admission carries it, and the default registry of a standalone, key-managed or certificate firewall without a descriptor names it with `oci_token_url`), or
the one host the registry is known by (`registry-1.docker.io` -> `auth.docker.io`, `ghcr.io`, `quay.io`, `gcr.io`, `public.ecr.aws`); any other realm is
never asked and no credential goes to it. A caller's Bearer token goes to the registry's origin only. The ping mirrors the registry (a client that is told "open" never signs in, so a push would meet a 401 it does not act on): a registry that wants tokens is answered `401` even for
an anonymous pull, and the client's own token request (anonymous, or with its credential) is relayed. A request that carries no credential at all (a client that skips the flow, or a
standalone firewall, whose ping is always `200`) is served with the firewall's own anonymous token (shared by every anonymous caller of the registry for the scope, four minutes
at most), so a public image needs no login. A TLS-terminating proxy in front must not limit or buffer a push (`client_max_body_size 0; proxy_request_buffering off;` for nginx).

Identity and dates. Policy sees the repository (`library/alpine`, lower case) as the name and the manifest digest as the version; a block may also name a
tag (it then applies to every request that names it). A registry's v2 API carries no publication time, and a config's `created` or an annotation is the
depositor's word: it releases nothing. The age of a digest is the time this firewall FIRST SAW it (committed in the store), so an image already on the
registry waits one cooldown from first sight (the safe direction: a depositor cannot back-date a release; the residual is the same as Go's first list
and NuGet's `published`: an attacker-controlled registry only ever makes its own images wait). A child (an index's manifest, a config, a layer) takes the
date of the manifest that named it once that manifest is allowed; a blob nobody named is judged as a direct request with its own first-seen time. A tag is only
a name: every request for one asks the registry for its manifest and judges the digest it names now (a moved tag is a new digest with its own age).
The manifest's bytes are hashed and must be the digest asked for (and the registry's `Docker-Content-Digest`); a layer is hashed in full against its digest
before the first body byte is delivered (the verified artifact pipeline: `max_artifact_bytes` is the bound, 5 GiB by default), in one pass over the bytes, with the two digests the firewall keys on (sha256 for policy, sha512 for its content store; the SHA-1 and MD5 digests of Maven's and Conan's sidecars are not computed for an image). The response headers of a first pull of a sha256 layer go out as soon as the policy has allowed it (`200`, the registry's `Content-Length`, `Docker-Content-Digest`), and the body follows the verified file: a layer that is not its digest is an aborted connection, never a complete answer, and no byte of it is released. Time to the first body byte is therefore the download plus one hash; a reverse proxy in front with a read timeout shorter than that (nginx `proxy_read_timeout` is 60 s by default) cuts the first pull of a multi-GiB layer once the headers are out and the body has not started: raise it (`proxy_read_timeout 3600s;`) on the firewall's server block. A second pull is served from the verified bytes at once. Measured first-byte latencies are in `docs/plans/package-firewall-mvp-lf/evidence/slice-24.md`. Range, HEAD and resumed pulls work
on verified bytes. A client's HEAD of a manifest is the registry's HEAD (Docker Hub counts a manifest GET as a pull and a HEAD as none): the digest it names is judged, no byte is read, and the answer is remembered for 30 seconds for a caller with no credential. In a shared service, a HEAD with the caller's own credential to a registry that asked for one is an existence check (a push asks before it uploads) and is not held by the cooldown (a block still refuses it); to a registry that asked for none, and on a key route, it is held like a GET. A blob or manifest named by sha256 or sha512 is served: its bytes are verified in the algorithm the client asked with, and are judged and pinned under their sha256, which the firewall computes in the same pass (so a block by digest holds for either spelling; a sha512 layer is judged when its bytes have arrived, because a manifest does not state their sha256; once the pair is known, a manifest that names it by sha512 is refused at manifest time too). A digest a policy blocks under ANY repository is blocked in every repository (a read, a mount, an upload that finishes with it, a delete); what a policy blocks is not pushed either. A manifest is served under a manifest media type or `application/json` (never the registry's `text/html`) with `X-Content-Type-Options: nosniff`. The referrers tag-schema fallback (`sha256-<hex>`, an index of descriptors with no config or layer) is not held by the cooldown, and a registry's paged referrers list is followed (same origin, same list, at most 64 pages) and answered whole. A manifest whose layer names download URLs of its own (a Windows foreign layer) is accepted when every URL is https on the default port, has no user name and is on `oci_foreign_layer_hosts`; any other URL refuses the manifest (403). Every digest the manifest names, a foreign layer's included (a client that fetches it elsewhere never makes a blob request of its own), is checked against the blocks when the manifest is judged, and each is pinned under the manifest's cooldown. The firewall also serves the foreign layer at the registry blob route `/v2/<repository>/blobs/<digest>`: it fetches the first listed URL with no credential, follows redirects only to hosts on the list, verifies the digest and serves the verified bytes. What stays outside the firewall: a client that fetches a layer's `urls` itself takes those bytes from the listed host around the firewall's verification, because the manifest cannot be rewritten (its digest is its identity). The hosts are a short list the operator controls; a layer's digest in the manifest still names what the client verifies.

Redirects. A blob download is answered by the registry with a redirect to a signed storage URL: the firewall follows it to the storage origin only
(`oci_artifacts_url`, or the selected registry's archive origin) with the credential dropped at the first hop, and serves the verified bytes itself; a client is
never redirected, so no storage URL reaches it.

Bounds. A manifest or index is read to 8 MiB (twice what the distribution spec says a registry must accept; the largest real ones measured on Docker Hub on 2026-11-20 are an 11 KB index of 18 platforms and a 2.3 KB manifest), a tag list, the catalog and a referrers index to `max(max_metadata_bytes, 16 MiB)` (the largest real one: the 4,127 tags of `library/python`, 85 KB, in one page)
with at most 500,000 entries, a manifest names at most 20,000 digests, a token answer 64 KiB. A repository holds at most five times
`max_references_per_project` reference rows (a hard bound held atomically from the count to the commit: past it a manifest is a 503 and its children
commit nothing; its own row is the one thing that does). Fetches hold a place of the registry (8), of the process (half of `max_upstream_requests`, at most 32), of the caller's OWNER (at most 4 of the registry's and half of the process's: the account on a key route, the client address /64 in a shared service, the peer for a standalone firewall; anonymous callers have an owner too) and of the caller's credential (2 of them, a second count: a client can present any number of junk credentials, so they multiply nothing); an anonymous token is kept per owner (at most 32) and the table drops its oldest entry, never everyone's; a registry holds at most five times `max_references_per_project` repositories (a new one is a 503, a repository that has rows is still served); the process tables (anonymous tokens 256, realms 64, manifests 256 for 60 s, existence checks 4,096 for 30 s,
row gates 1,024, registered manifests 4,096) are bounded and never grow with the number of repositories. Credential-bearing reads (almost every request of an
authenticated client) are request-scoped: they read and fill nothing shared (no memo, no stored blob), and a blob fetched under a credential is never served
without it; anonymous reads stay cache-eligible.

Docker Hub counts an anonymous pull against the firewall's own address (a `GET` of a manifest counts, a `HEAD` does not); a busy deployment logs in (the caller's own
credential goes to the registry through the token flow and is counted for that account) or sets `oci_upstream_url` to a registry of its own.

Not done, limits and decisions: only `sha256` and `sha512` digests are verified (a registry's other algorithms are a 404); the catalog is a feature few
registries serve; a layer larger than `max_artifact_bytes` cannot be pushed through the firewall or pulled (the same bound);
OSV does not apply to images (OSV has no image ecosystem: the family is not OSV-covered); conditional requests are answered with the full document;
a mirror of Docker Hub with a different token host must be reached through the registry's own origin.

### Conan clients

Conan 2 only (the client's `v2` REST API; nothing of the Conan 1 tree is routed, so no `download_urls` or `upload_urls` indirection can lead
a client around the firewall). Point the client at the firewall as its only remote and sign in with the API key:

```
conan remote remove conancenter
conan remote add probation https://firewall.example/conan
conan remote login probation key -p prb_...
```

(`/registry/conan/{id}` of a selected registry.) A certificate-managed firewall answers the login with the key itself, which the client
then sends as its Bearer token; through the shared service the login is the registry's own (the client's credential goes to the
registry's `v2/users/authenticate` and its token comes back), and every later read and upload carries the client's own token. A second
remote would offer what this one refuses: remove ConanCenter.

What is served. `v1/ping` and `v2/ping` (the one capability advertised is `revisions`), `v2/users/authenticate` and `check_credentials`,
`v2/conans/search?q=` (`q` and `ignorecase` are the only query keys), and below `v2/conans/{name}/{version}/{user}/{channel}` (`_/_` for
none): `latest` and `revisions` of the recipe, `revisions/{rrev}/files` and `files/{file}`, `revisions/{rrev}/search` (the binaries of a
recipe revision), and `revisions/{rrev}/packages/{pkgid}/{latest,revisions}` and `.../revisions/{prev}/files[/{file}]`. A name, version,
user, channel, revision, package id and file name have one spelling (a name or version is `[A-Za-z0-9_][A-Za-z0-9_+.-]*`, user and channel
both or neither); anything else is a 404 and asks the remote nothing. The identity policy sees is the package name (case is identity) and
the recipe version verbatim; the user, channel and revisions are what the firewall dates.

What is applied. The thing that has a publication time is a revision: a recipe revision (`rrev`) or a package revision (`prev`) of one
package id of one recipe revision. The time is the `time` of the remote's own `revisions` document (`2024-12-11T16:57:24.862+0000`), committed on
the revision's `conanmanifest.txt` row and only ever later; a revision with no usable time waits on the time this firewall first saw it. A new
binary of an old recipe is its own revision with its own age, and no recipe date ever ages a binary (nor a binary a recipe). The revision
lists show only the revisions that pass (age, block, OSV on the package name under `ConanCenter`, a pinned digest), `latest` is the newest of
them (403 with the hold's deadline when there is none), the search lists a reference only while a revision of it passes and a binary search a
package id only while a package revision of it passes. EVERY result is judged (up to the document's own bound of 500,000 entries), in batches of 5,000 references (a search holds its result strings and one batch, not a tree of the document; a binary search is decoded the same way, each id's info kept as the text the remote wrote and reduced only when it is listed). A verdict needs one read of the reference's revision list and the policy decision. A search writes no row for it, whether the remote dates the revisions or not (an undated revision is judged as a row made now would be: first seen now); the rows, and the date the store only ever moves later, are made by the first list or file request for the revision, which is also gated live, so nothing is released without its rows. Work is shared per verdict: any request that needs the same verdict (same registry, origin, policy, reference) waits for the one that is making it. A verdict lives 120 s from when it was made. After a search of a registry ended unfinished (the client gave up, which a Conan client does after about 60 s, or the 504 at 100 s, or any error), the retries of the next two minutes renew the verdicts they read (at most 10 minutes from when each was made), so a search too large for one attempt continues from what the attempts before it made and converges over a few retries at any latency; a search that finishes clears the mark and renews nothing, so an OSV change or a hold that ends shows within two minutes (a policy change shows at once: the policy is part of the verdict's key). Judging has lanes of its own: a registry judges 16 lists at once and the process judges at most half of `max_upstream_requests` (16 at the default), so a search never takes a fetch place or an upstream slot an install needs. Measured against a local registry fake with the real store, policy and OSV client, 9,000 references (the size of `search?q=*` on ConanCenter), cold: 1,098 verdicts per second and 8.2 s at 0 ms of network per document, 242 per second and 37 s at 50 ms, 137 per second and 66 s at 100 ms; at 200 ms 74 per second, so the first attempt ends at 100 s with a 504 (7,368 verdicts made) and the retry finishes in 22 s (two attempts, 122 s in all). At most 4 searches judge at once per registry and 16 in all (more is a 503); one owner (the account in certificate mode; the client address /64 in shared-service mode, as for an upload spool) holds at most 2 per registry, 8 in all, and 12 of the 16 judging lanes across all the registries it reads (so one owner on two registries cannot take every lane). The latency table above is for a standalone firewall, which has no owner: 16 lanes. Through the shared service and in certificate-managed mode a caller judges with 12 lanes (120 lists per second at 100 ms, 60 at 200 ms): a 9,000-reference search is one attempt of 77 s at 100 ms and two attempts at 200 ms (the first ends at 100 s with a 504, the second finishes after 53 s more), measured through the shared service (evidence/slice-23.md "Recheck-4 round"). A search whose reference has an undated revision lists it once a list or file request has written its row and the cooldown since has passed (the first such request writes the row; until then the search holds it as one first seen now). In certificate-managed mode a search answer is checked against the key's policy again when it is finished: a layer published meanwhile admits the request again under it. A big document (over 256 KiB) is decoded under one of 4 process-wide permits that is held only for the decode. The memory of a search, measured (debug build, resident growth): a 500,000-reference document with 20,000 readable references 207 MiB for one search and 308 MiB for four at once; a package search of 100,000 ids 81 MiB and of 360,000 ids (the most a 16 MiB document holds) 161 MiB. A reference whose list is gone or unreadable is withheld and counted in the response header `x-probation-withheld`; any other failure (the remote down, a timeout) fails the search with 502 or 504, never a shorter 200. A policy published while a search runs refuses its answer (503, retry). The uploads a credential made through the firewall are remembered in memory, per process (at most 4,096 per credential): a restart forgets them and a second instance behind a balancer does not see them, so an uploader needs sticky routing to keep its existence checks clear of the cooldown. and a file list names the files the policy allows and nothing else of the remote's document (no location of the remote
reaches a client). Every file of a revision is refused (403) when the revision is, and a refused revision's files are never fetched; a file the
remote does not have makes no reference and is a 404.

What is shared. Credential-free reads share a fetched list for 5 s and the dates of a package's revisions in a bounded table (128 packages); a read
that carries the caller's own token reads and fills none of it. Fetches are bounded process-wide (16) and per registry (4), a document is read to
`max(max_metadata_bytes, 16 MiB)` (the largest real ones: 222 KB for `search?q=*` on ConanCenter, 32 KB for the binaries of boost), a project may
hold at most five times `max_references_per_project` reference rows, and the archives (`conan_export.tgz`, `conan_sources.tgz`,
`conan_package.tgz`) are the large transfers while every other file is small and has its own pool of places.

Through the shared service. A registry with a `target_url` is read at that URL (the remote root, path included) with the caller's own
`Authorization`; a remote that redirects an archive to storage declares that origin on its registry page (an archive origin: only an
archive's transfer follows it). `conan upload` is forwarded: a `PUT` of each file of a recipe or package revision and a `DELETE` (also of a
recipe, revision, packages or package directory) to the registry's own origin (for the public registry `conan_publish_url`, a 404 when it is
not set) with the caller's own `Authorization` and never a credential of this service; a write with none is answered `401` with
`WWW-Authenticate: Bearer`, a body over twice `max_artifact_bytes` is `413`, a path that is no layout path is `404`, and the registry's answer is
relayed only with a status an upload endpoint gives (otherwise 502), as `text/plain`. Uploads share the spool of every forwarder (who a spool
share belongs to, above). The client's `X-Checksum-Sha1` header is not forwarded (the registry computes it).

Not done: the Conan 1 API; `checksum_deploy` and `complex_search` capabilities (not advertised); the client's own cache and package signatures.
