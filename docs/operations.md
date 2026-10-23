# Running Probation

The operator handbook for both programs:

- `probation`, the firewall. It sits in front of npm and PyPI.
- `probation-server`, the management server. It holds API keys, organisations and
  their policy, and serves the self-service portal. You need it only for managed
  mode.

How to install, configure, run, watch, back up, restore and upgrade them, and what
to do when something breaks. How to set up the management server is in
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
one last call to the server, waiting at most `request_timeout_seconds`. A signal that arrives while the service is still starting is acted on as
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

`osv_request_timeout_ms` (default 500) bounds one batch of OSV lookups before it
fails open. All versions of a package are checked together, up to 256 per batch,
so a package the service has not seen recently costs about one OSV round trip,
not one per version.

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
and its environment. Keep `PROBATION_SERVER_SECRET_KEY` with the backups, but
apart from them: without it the authenticator secrets and SSO client secrets in
the backup cannot be read.

To restore:

1. Stop `probation-server`.
2. Restore the database.
3. Run `probation-server admin after-restore` (with
   `PROBATION_SERVER_DATABASE_URL` set as for `serve`). It prints the counter
   before and after.
4. Before starting the server, list the security changes made after the backup
   was taken, from your own records (tickets, chat) or from the audit log of any
   newer copy of the database: key revocations, member removals, suspensions,
   policy blocks, firewall retirements and settings pushes. The restored database does not have them.
   Re-apply the key revocations now with
   `probation-server admin revoke-key --key-id N`, which needs no running server.
5. Start `probation-server` and re-apply the rest on the portal before you open
   it to everyone else. Until each one is back, firewalls enforce the restored
   database's version of it.

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
2. Stop the server.
3. Run `probation-server migrate` with the new binary.
4. Start the new server.

Firewalls keep serving from their cache while the server is stopped (section 13),
so a server upgrade needs no firewall downtime. Only keys a firewall has never
seen are refused (`401`) until the server is back.

### Mixed versions

- Managed mode is new in the first release after 0.2.2. Firewalls 0.2.2 and older
  refuse a `[management]` section as an unknown key; they can only run
  standalone.
- Upgrade managed firewalls one at a time, after the server. The fleet page shows
  the version each firewall reports.
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
  `npm_upstream_url`, `pypi_upstream_url` and `pypi_artifacts_url` if you set them
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

It only checks packages as they are *downloaded*. It cannot help with:

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
| yarn 1 | New installs only | Rewrite each existing `yarn.lock` once (below). |
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
| error | `the management server's answer could not be read; this firewall (v…) may be older than the server; serving from the cache` | The server answered in a form this firewall cannot decode, most likely because the server was upgraded first. `/health/ready` is `503` and the fleet page shows the error. Upgrade the firewall. |
| warn | `the activity queued before the stop could not be delivered` | The last call on a stop failed; those activity rows are lost. |
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
9. **No health endpoint on the management server.** (Section 16.)
10. **No live reload.** Every config change and every settings push restarts the
    firewall.
11. **Managed firewalls cannot sync through an egress proxy.** (Section 6.)

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
reaches them. `admin revoke-key` revokes a user or service key, not a firewall
token: retire a firewall on the fleet page.

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
push is never applied again.

Files a managed firewall keeps in `data_dir`, beside `state/`, `content/` and
`lock`: `managed-cache.json`, `managed-settings.toml`, `managed-settings.prev.toml`,
`managed-settings.state`, and sometimes `managed-settings.failed.toml`.

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
| `osv_request_timeout_ms` | `500` | Not zero. |
| `tls_cert_path`, `tls_key_path` | off | Both or neither. Section 6. |
| `npm_upstream_url` | `https://registry.npmjs.org` | `https`, no user, query, path or private address. |
| `pypi_upstream_url` | `https://pypi.org` | Same rules. |
| `pypi_artifacts_url` | `https://files.pythonhosted.org` | Same rules. |
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
| `GET /health/ready` | Standalone: the blocklist is valid **and** storage works. Managed: storage works, a cache was loaded or a sync applied, the firewall is not retired, the server does not refuse its syncs, and its last answer could be read. `503` otherwise. Never checks upstream npm/PyPI. |
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

The server has no health endpoint. Watch the process, its log, and Postgres.

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
| Server stops at start: `PROBATION_SERVER_<PROVIDER>_CLIENT_SECRET is not set` | A provider section with no secret. | Set the secret, or remove the section. |
| `bootstrap refused: a global admin exists already; nothing changed` | Bootstrap ran before. | Use `admin reset-link` for a lost link. |
| `no live global admin signs in as …` from `reset-link` | That address is not a global admin's email sign-in. | Check the address. |
| Nobody receives mail | No `[portal.smtp]`, or the SMTP host refuses. | Add `[portal.smtp]`. Mail waits in the `email_outbox` table. |
| `502 INTEGRITY_MISMATCH` | A file changed upstream after it was first seen. | Investigate as a security incident (section 9). |

## 20. Release and crate-name recovery

The release workflow (`.github/workflows/release.yml`) runs on a pushed `v*.*.*`
tag. Nothing is released unless the tests, `tests/e2e/signup_to_install.sh` and
CodeQL pass. It then builds the firewall archives, creates the GitHub release,
and publishes to crates.io from the `crates-io` environment, which should have
required reviewers. `probation-server` is never published to crates.io.

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
