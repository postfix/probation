# Running Probation

How to start it, what it protects against, what it does not, where it can run
out of room, and how to back it up and restore it.

Every claim here was checked against the code or measured on a real run.
Section 12 lists every known gap in one place.

---

## 1. What this service is

One process, one data folder, one set of rules for every client. It sits in
front of npm and PyPI and withholds two kinds of release:

- anything published less than `cooldown_seconds` ago (default: 24 hours)
- anything on your blocklist, or in the OSV vulnerability database (section 4)

`npm` and `pip` still resolve dependencies themselves. This service only
narrows what they can resolve against, and verifies every file it hands back.

"Allowed through" means it passed these checks. It does not mean the package
is safe.

## 2. Starting it

### With Docker

```sh
docker build -t probation:mvp .
docker run --rm probation:mvp check-config /etc/probation/config.toml
docker run -d --name probation \
  -p 127.0.0.1:8080:8080 \
  -v /srv/probation:/var/lib/probation \
  -v /etc/probation:/etc/probation:ro \
  probation:mvp serve --config /etc/probation/config.toml
```

The image ships with the sample config and sample blocklist. The build changes
one thing: it listens on `0.0.0.0:8080` instead of localhost, so the published
port is reachable. Publish that port only to your reverse proxy (section 6),
never to a network.

The sample blocklist has a far-off expiry so the container starts. Replace it
with your real blocklist before relying on this.

Building the image needs `cmake`, a C compiler, and `perl`, because one crypto
library compiles from C. Running it needs `ca-certificates`: with an empty
trust store, every connection to npm and PyPI fails. The `Dockerfile` handles
both.

### Running the binary directly

```sh
cargo build --release --locked
./target/release/probation check-config  /etc/probation/config.toml
./target/release/probation check-blocklist /etc/probation/blocklist.json
./target/release/probation serve --config /etc/probation/config.toml
```

Both `check-*` commands stop at the first problem, report it, and write
nothing. Run them in your deploy pipeline before restarting. A restart onto a
broken config is an outage. Run `check-config` with the same environment as
`serve`: with `siem_url` set it also refuses a `PROBATION_SIEM_AUTH` that
`serve` would refuse.

### Stopping it

`SIGINT` (Ctrl-C) and `SIGTERM` (`docker stop`, `systemctl stop`, plain `kill`)
both shut it down cleanly: queued log records are delivered and a summary is
printed. A signal that arrives while the service is still starting is acted on
as soon as startup finishes. An abrupt stop is still safe. Nothing gets
corrupted.

Requests already in progress get 30 seconds to finish; after that their
connections are closed and shutdown continues. Give the service manager more
than that before it kills the process, so the log drain still runs: with
systemd, `TimeoutStopSec=45`; with Docker, `docker stop -t 45` (the default is
10 seconds).

### Health checks

| Endpoint | What it tells you |
| --- | --- |
| `GET /health/live` | The process is up. Still `200` with an expired blocklist or broken storage. |
| `GET /health/ready` | The blocklist is valid **and** storage works. `503` if either is broken. Does not check upstream npm/PyPI. While storage is broken, package and download requests also answer `503 STORAGE_UNUSABLE`, even ones that could be served from memory. |
| `GET /health/delivery` | **For alerts only, never a health probe.** `503` if a log record was lost in the last 60 seconds. See "The rated load" in section 8. |

Point the liveness probe at `/health/live` and the readiness probe at
`/health/ready`. They differ on purpose: a service with an expired blocklist
is working and should not be restarted. It should leave rotation until the
blocklist is fixed.

## 3. Disk space: `cache_max_bytes` does not cap everything

The name sounds like a total disk limit. It is not.

The data folder has two parts:

```text
<data_dir>/content/     the downloaded files
<data_dir>/state/       the database (firewall.db, firewall.db-wal) and lock file
```

`cache_max_bytes` limits only `content/`. When it fills, the least recently
used files are evicted.

**`state/` has no size limit.** Nothing caps it and nothing warns you when it
grows. Give the disk real headroom beyond `cache_max_bytes` and watch free
space yourself.

`state/` holds a row for every project ever looked at, a row for every file
ever checked (with its hash and first-seen time), a row per cached file, and
the current blocklist. The first-seen records are permanent: they are what
stops a restart from resetting the cooldown clock. So `state/` only grows.
Deleting rows does not shrink the file, and nothing prunes it.

> **Known gap:** no low-disk warning. If the disk fills, writes fail, the
> service reports "not ready", and requests get `503`. It never relaxes its
> rules to save space.

"Not ready" covers both halves of the data folder: a failed write to the
database or to `content/` turns `/health/ready` to `503`. Successful reads do
not turn it back; only a successful write does. While it is not ready, the
background maintenance pass (every 30 seconds) tries one small write to each,
so readiness returns on its own within about 30 seconds of space being freed —
it does not wait for traffic, which a load balancer would no longer send.

A cached file found with the wrong size is deleted and downloaded again on the
next request. A file already sitting where a download is about to be stored is
kept only if its SHA-256 matches; anything else there is replaced.

Keep room for one blocklist update: a 100,000-entry blocklist is about 9.6 MB,
and the old and new copies exist together briefly.

Memory: `memory_cache_max_bytes` budgets parsed metadata and cached responses
only. It is **not** a limit on the process. In testing with a 100,000-entry
blocklist under load, the process used **357 to 374 MB** of RAM. Size your
memory limit from that number.

## 3a. `metadata_max_age_seconds`: a safety setting with a cost

`metadata_ttl_seconds` sets how often a package is re-checked with upstream.
But a cheap "nothing changed" answer from upstream can renew that clock
forever. So there is a harder limit: `metadata_max_age_seconds` (default: 1
day). Once a package's data is that old, the next request must fully re-fetch
it, however many cheap re-checks happened.

**The cost:** if that forced re-fetch fails, the request is refused, even
though a slightly stale local copy exists. So an outage on the path between
this service and npm/PyPI that lasts longer than this limit makes
already-cached packages start failing. Projects expire at slightly different
moments so the failures spread out, but they still happen.

Your two choices:

- **Raise it.** Longer survival through an upstream outage, but a longer window
  in which a misbehaving upstream can feed you stale data. It cannot be lower
  than `metadata_ttl_seconds`. The service refuses to start if it is.
- **Set it to `0`.** No limit. An upstream that always says "nothing changed"
  can then freeze your view of a package forever. Do this deliberately and
  write down why.

There is no "serve it stale" option.

This limit never affects blocklist enforcement: a blocked package stays
blocked. It never affects downloaded files either. They are identified by
content hash and cannot go stale.

> **Upgrading:** this release bumped the database schema version to 5 (it
> indexes the cached-file mapping, so evicting files stays fast on a large
> cache). A database made by an older build, including v0.1.0's version 4,
> **will not open**. The service refuses it rather than guess at a migration.

## 4. The blocklist

This service reads one local JSON file. It does not fetch feeds or merge
lists. Your own tooling must produce that file and replace it atomically. Only
trusted people or systems may write it. You own what is in it; the service
only enforces it.

How reloading works:

1. Every `blocklist_poll_seconds`, it checks the file for changes.
2. The whole new file is validated before use, if it is under
   `max_blocklist_bytes`.
3. Every update needs a strictly higher revision number. A roll-back is
   rejected. Same revision with the same content is a no-op. Same revision with
   different content is rejected.
4. The file's "generated at" and "expires at" window must include now.
5. An accepted update is saved to the database before it takes effect.

A broken replacement keeps the last good blocklist in force and logs an error.
A file larger than `max_blocklist_bytes` is refused the same way, and is read
no further than that limit. An empty but valid blocklist is accepted (only the
cooldown then protects you). A missing file is never treated as empty. A
reload check that fails unexpectedly (a bug) is logged at error, and the next
interval checks again; it never stops reloading.

**If the blocklist expires, the service fails closed:** package lookups and
downloads return `503`, even for cached files. The service stays "alive" but
reports "not ready". Set the expiry far enough ahead to cover a producer
outage, and alert on it.

Every new file is a full replacement, including removals. To un-block
something, your producer must stop listing it.

### What a block stops

A block applies to every request checked after the new blocklist loads,
including files downloaded and verified earlier. New CI runs, fresh installs,
and cache misses are all refused.

It does **not** remove a copy already on someone's machine. Cleaning up an
installed bad package is a job for endpoint security.

### OSV vulnerability checks

[OSV](https://osv.dev) (Open Source Vulnerabilities) is a free, open database
of known vulnerabilities in open-source packages, run by Google and fed by npm,
PyPI, GitHub, and others. This service checks every package against it as a
second net beside your own blocklist.

**How the two combine:** whichever one blocks, it is blocked. OSV is only asked
about a package your own blocklist would allow, so OSV can add blocks but
never undo one.

**OSV problems never block anything.** If the check is slow, times out, the
queue is full, or the answer cannot be parsed, the service treats it as "no
match" and continues with its normal checks. A "no match" answer is cached for
30 seconds so a struggling OSV endpoint is not hammered. A match is cached for
`osv_cache_ttl_seconds` (default 300, 5 minutes). The cache holds at most 65,536
answers; past that the least recently used is dropped and asked again.

`osv_mode` controls what a match does:

- `enforce` (default): blocks, the same as a blocklist match.
- `diagnostic`: checks, caches, and logs a match, but lets the request
  through. Use it to see what OSV would block before turning enforcement on.
  The only signal is the `reason` text in the decision log, so alert on that.
- `off`: no check and no calls to OSV.

Changing `osv_mode` needs a restart, like every config key.

**Network:** the endpoint is fixed at `https://api.osv.dev/v1/querybatch`. If
you restrict outbound traffic (section 6), allow `api.osv.dev` too. Otherwise
every OSV check times out and fails open, and packages are served without it.

`osv_request_timeout_ms` (default 500) bounds one batch of OSV lookups before
it fails open. All versions of a package are checked together, up to 256 per
batch, so a package the service has not seen recently costs about one OSV round
trip, not one per version.

## 5. Backup and restore

### What to back up

Three things, separately:

1. The config file.
2. The current blocklist file.
3. **The whole `state/` folder**, with the service stopped, including
   `firewall.db-wal`.

Downloaded files in `content/` are re-downloaded and re-verified on demand.
`state/` holds what cannot be rebuilt: every first-seen time, every pinned
file hash, and the current blocklist revision. Lose it and every cooldown
timer resets.

### How to back it up

**Stop the service first.** It holds an exclusive lock on the data folder
while it runs, and copying the database live can catch it mid-write. There is
no backup-while-running option.

```sh
docker stop probation    # shuts down cleanly
tar -C /srv/probation -czf state-$(date -u +%Y%m%dT%H%M%SZ).tgz state/
docker start probation
```

Keep `firewall.db-wal`. It holds committed data not yet merged into the main
file. Deleting it loses real data.

### How to restore

1. Stop the service.
2. Restore the whole `state/` folder as one unit, database and WAL together.
3. Put a **current, unexpired** blocklist in place. A restored blocklist that
   has since expired leaves the service "not ready" until you update it.
4. Start the service and wait for `/health/ready` to return `200`.
5. Treat all cached metadata as stale. Each package is re-checked with
   upstream on its next request.

### If recovery fails

If the database cannot be opened, for any reason, the process **still
starts**, but:

- `/health/live` says `200`
- `/health/ready` says `503`
- every package request is refused
- nothing on disk is touched, deleted, or recreated

Silently recreating a broken database would lose every pinned hash and timer
while looking healthy. A refusal with the data intact can still be fixed.

One case to know: if `firewall.db` is empty or missing but `firewall.db-wal`
has data, the service refuses to open it. Back up `state/` before doing
anything else. The WAL file is your real data.

If another process holds the lock on the data folder, `serve` reports that
and exits.

## 6. TLS, and the one job a reverse proxy still has

### TLS is built in

`serve` terminates TLS itself when both `tls_cert_path` and `tls_key_path`
are set. Set both or neither. No proxy or sidecar is needed for HTTPS.

Set `public_url` to the URL clients use to reach you. Download links are built
from it, so a wrong value breaks downloads. **`public_url` must be `https`**,
with no localhost exception. (`siem_url` in section 8 does allow plain `http`
on localhost.)

For a local end-to-end setup, which generates a cert, writes a real
`/etc/probation/config.toml` and blocklist, creates the data directory,
validates both, and points this machine's npm and pip config at the result:

```sh
scripts/install-local.sh
```

It uses `sudo` only where `/etc/probation` or `/var/lib/probation` need it.
Pass `--start` to also start `probation serve`. It picks the best certificate
tool available:

- [`mkcert`](https://github.com/FiloSottile/mkcert), if installed. This adds a
  local certificate authority to the machine's trust store once, so every cert
  it issues is trusted by `npm`, `pip`, and `curl` on that machine with no
  flags. A mkcert cert is not valid on any other machine, which is what you
  want for local testing.
- Otherwise a self-signed `openssl` cert, which clients would refuse. The
  script adds the `cafile=` and `cert=` lines pointing at it to the npm and
  pip config for you. Force this with `--self-signed`.

Run `scripts/install-local.sh --help` for every flag.

Let's Encrypt does not work for `localhost`: it needs a public domain it can
reach. For a real domain, get a certificate however you already do and point
`tls_cert_path` and `tls_key_path` at it. Renewal is yours: the service reads
both files once at startup, so restart after a renewed certificate is in
place.

### A reverse proxy is still required for per-client rate limiting

This service has no logins or accounts, so it cannot limit one client's rate.

The risk: a client requests a file and downloads it very slowly, holding one
of a small number of download slots. Enough such clients use every slot, and
nobody else can download.

`max_active_requests` and `max_artifact_downloads` are global totals shared by
everyone. **Set per-client connection and rate limits on your reverse proxy**
so no one client can hold more than a fair share.

### Outbound filtering

For npm and PyPI traffic, this service refuses on its own: cross-site
redirects, URLs with embedded credentials, unusual ports, non-HTTPS upstreams,
and DNS answers pointing at local or private addresses. It cannot detect a
custom NAT64 range specific to your network. The standard one is covered.
**None of this covers OSV traffic**: the OSV client is a plain HTTP client
that only talks to one fixed Google-run URL.

To close the NAT64 gap at the network level, restrict outbound connections to
the four hosts it needs: `registry.npmjs.org`, `pypi.org`,
`files.pythonhosted.org`, and `api.osv.dev`. With `osv_mode = "off"` the last
one is never contacted.

## 7. What this service does not protect against

It only checks packages as they are *downloaded*. It cannot help with:

- **Already-installed packages.** A later block does not remove them from
  `node_modules` or similar.
- **Client-side caches.** A file already cached by the client is not
  re-checked. (npm does not currently cache files from this service, because
  of a cache-control header it sends. That is npm's behavior today, not a
  control to rely on.)
- **Anything not fetched through this service:** other registries, Git or URL
  dependencies, local files, anything an install script downloads itself.
- **Lockfiles that pin a direct upstream URL.** Pointing npm or pip here does
  not rewrite those. Check your lockfiles when you roll this out.
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

That is cooperative. To *enforce* it, block direct access to the public
registries at the network level too.

## 8. Logs

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
was judged against. `result` is `REFUSED` for a 4xx/5xx the router or HTTP
layer produced without a policy decision (a malformed path, an unsatisfiable
range), and those count as errors in the periodic summary. The `request_id` matches the one a client sees
in its error message. Credentials are never logged and never forwarded
upstream.

`RUST_LOG` (default `info`) controls verbosity for everything except the
decision line, which cannot be silenced. There is no metrics endpoint.
Counters are printed to stdout periodically.

### Also writing logs to a file

By default logs go only to stdout, which your container runtime or systemd
keeps. Set `log_file_path` to also keep a file. Nothing is written to disk
until you do.

| Setting | Default | What it does |
| --- | --- | --- |
| `log_file_path` | off | File every decision is appended to, one JSON object per line. |
| `log_file_max_bytes` | 100 MiB | Size at which the file rolls over to a `.1` backup. |
| `log_queue_max_bytes` | 1875 MiB | Memory that may queue while disk writes fall behind. See "The rated load" below. |

One process per `log_file_path`. There is no locking, so two writers corrupt
the file. Let this process rotate the file itself with `log_file_max_bytes`.
An external `logrotate` renaming or truncating it causes silent data loss.

One backup generation (`.1`) is kept. For longer history, ship logs to your
own log system.

`log_file_max_bytes` is a hard ceiling. If the rollover rename fails (a
single bind-mounted file, a directory the service cannot write to, or a
directory sitting at the `.1` path), the file is not extended: new records are
dropped and counted, with one warning, until a rename succeeds. A record too
large to fit in an empty file is dropped and counted too.

Dropped records are always counted. If writing cannot keep up, losses appear
in the periodic summary as `dropped_file` and `dropped_siem`. The summary has
its own room in each queue, so the record that reports a loss is not lost to
the same full queue. A slow log destination never slows or fails a request.
The record is dropped, not the request.

What the file promises: every record is written whole or not at all (a write
that fails partway, such as on a full disk, is cut back off), and each record
is handed to the kernel as soon as it is written, so it survives the process
crashing or being killed. It is not `fsync`ed. A host crash or power loss can
lose the records of the last few seconds that the kernel had not yet written
out. Syncing every record would cap the rate at the disk's sync rate, far
below the rated load, and the queue would then drop records instead.

### Sending logs to a SIEM or log collector

Set `siem_url` to turn this on.

| Setting | Default | What it does |
| --- | --- | --- |
| `siem_url` | off | Where records are POSTed. Must be `https` unless it is localhost. |
| `siem_auth_header` | `Authorization` | Which header carries the credential. |
| `siem_queue_max_bytes` | 1875 MiB | Memory that may queue while the collector is unreachable. |

The credential never goes in the config file. Set the `PROBATION_SIEM_AUTH`
environment variable. It is never logged or written anywhere, and the process
refuses to start if it is not a legal HTTP header value.

Records are sent in batches of 256 records or every 2 seconds, whichever
comes first. Redirects from the collector are never followed, so a compromised
collector cannot send your credential elsewhere.

Retries: a connection error, a `5xx`, or a `429` is retried with a short
backoff (100 ms, 500 ms, then every 2 seconds) for as long as the service
runs. The batch is held, and records queue behind it until the queue budget
is full. Any other error, such as a bad credential, is not retried, and that
batch is dropped. Lost records are counted in `dropped_siem`.

Delivery is **at least once**. A collector that stores a batch but answers
after the 3-second request timeout gets the same batch again on the retry, so
deduplicate on `request_id` if duplicates matter to you. Only a timed-out or
failed attempt is retried; a batch the collector acknowledged is never sent
again.

The service logs only the scheme, host and port of `siem_url`, never its path
or query, so a token placed in the URL stays out of the console.

**One limit:** when a collector rejects a batch, the *whole batch* of up to
256 records is dropped, not one record. The file from `log_file_path` does not
have this problem: one bad record never costs its neighbours, and each record
is written at most once (see what the file promises, above).

### Shipping to a SIEM over syslog

`siem_url` is HTTP only. There is no syslog support in `probation` itself: a
mature shipper already does TLS, framing, and retries correctly. If your
collector takes HTTP (Splunk HEC, Elastic, Datadog, and most others), use
`siem_url` and skip this section.

If you need syslog, point `rsyslog`'s `imfile` input at the file from
`log_file_path` and let `omfwd` deliver it. The file is the better source: it
is complete (see the batch limit above) and plain appended text.

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

This exact pipeline was verified against a real `rsyslogd`: each appended
line arrived at a TCP listener as RFC 3164 syslog (`<134>` is `local0.info`)
with the JSON payload intact, so field-based queries on the collector keep
working.

For TLS to the collector (port 6514, not 514), add `StreamDriver="gtls"` and
the matching cert settings to the `omfwd` action. See rsyslog's own `omfwd`
TLS documentation.

The shipper reads a file this service appends to and rotates itself. Keep
`logrotate` away from it, and leave `decisions.ndjson.1` in place until the
shipper has finished reading it after a rotation.

Other shippers (Vector, Fluentd) work the same way in principle: tail
`decisions.ndjson` and forward with that tool's syslog output. They were not
verified here. Check that tool's own docs.

### Recording who is asking

`log_consumer_identification` (off by default) adds the requester's IP
address to every log line. Read this before turning it on:

- It records only the raw IP of the TCP connection, nothing the client sends,
  so it cannot be spoofed.
- Behind one proxy or load balancer, every record shows that proxy's address,
  not the developer or build machine.
- Turning it off later erases nothing already logged, in your files, your
  SIEM, or your console logs.
- It requires `log_file_path` or `siem_url`. Without one, the service refuses
  to start with it on.
- A log file this service creates gets owner-only permissions (`0600`). A
  file that already exists keeps its permissions. Fix those yourself.
- If the log destination is broken (SIEM unreachable, disk full, file
  deleted), the service keeps running and counts dropped records. Watch
  `dropped_file` and `dropped_siem`.
- `check-config` checks that the setting is valid, not that the destination
  works.

### The rated load: how much this can handle

On a 16-core/32-thread reference machine, the logging pipeline sustained about
**59,000 decisions per second with zero records lost**. That is the logging
ceiling, not overall throughput. Real traffic is limited mainly by how fast
npm and PyPI respond, and by `max_upstream_requests` (default 32).

The default queue budgets (`log_queue_max_bytes` and `siem_queue_max_bytes`,
1875 MiB each) are not sized for that rate: surviving a 5-minute outage at
59,000/s would need about 543 GB per destination. They are sized to survive a
5-minute outage at a realistic **200 requests/second**.

If your traffic is above 200 req/s, work out your own outage window:

> outage tolerance (seconds) = queue size in bytes ÷ 32,768 ÷ your
> requests/second

Each queue is separate. `log_queue_max_bytes`, `siem_queue_max_bytes`, and
`memory_cache_max_bytes` (section 3) do not share memory. Budget for all
three.

**`GET /health/delivery` is for alerting, never for load-balancer checks.** It
is unauthenticated and reflects a 60-second window, so polling less often
than that can miss a loss. Poll it more often than every 60 seconds, and never
let it decide whether the service stays in rotation.

**The decision log cannot be turned off.** No `RUST_LOG` value silences it, so
there is always an audit trail of every decision.

## 9. Error responses

| What happened | Status code |
| --- | --- |
| Held by cooldown, or blocked | `403` (with a reason, and `Retry-After` for cooldowns) |
| Unknown or removed package | `404` |
| Bad request | `400` |
| Unsupported route or method | `404`, `405`, `406` |
| Blocklist missing or expired, out of capacity, storage broken | `503` |
| Upstream failure or bad data | `502` |
| Upstream timed out | `504` |

Every response, success or error, tells clients not to cache it.

Two of these need a person, not a client retry:

- **`502 INTEGRITY_MISMATCH`**: a file's contents changed since this service
  first saw it. That is an upstream security incident or a bug in how this
  service identifies files. Investigate.
- **A `503` from storage**: writes are failing. The service will not loosen
  its rules to work around it. Fix storage.

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

Verified with real `npm` and `pip` installs against an in-process fake
registry, never the public internet:

- npm 10.9.9, 11.16.0, and 12.0.2
- pip 25.0.1 and 26.2.1

All versions behave the same. Confirmed: installs succeed and fall back to
older eligible versions; `npm ci` fails cleanly on a blocked lockfile entry
without changing the lockfile; already-installed packages stay installed after
a later block; pip installs work from wheels and source distributions.

**If you are upgrading from an older version of this service:** npm 12 is
stricter about which download URLs it trusts. This service's URL layout
already satisfies that (artifacts live under `/npm/artifacts/...` and
`/pypi/artifacts/...`), so no `.npmrc` change is needed. If an old
`allow-remote=all` line is in an `.npmrc` from an earlier setup, remove it.
It weakens npm's own supply-chain protection for every dependency.

Old download URLs under the previous `/artifacts/...` path no longer work.
Clients get a fresh URL from current metadata.

Git dependencies, URL dependencies, and alternate registries are still not
covered. They need whatever client-side overrides they always needed.

## 12. Known gaps in this release

1. **No low-disk-space warning.** (Section 3.) Monitor disk space yourself.
2. **The `state/` database only grows.** (Section 3.) No automatic cleanup.
3. **Removed upstream packages can still appear in listings** for up to
   `metadata_ttl_seconds` (default 5 minutes). Downloads are judged correctly
   and immediately.
4. **A newly blocked file hash can briefly still appear in a listing** in the
   same window, under rare concurrent access. Direct downloads are blocked
   immediately regardless.
5. **No backup while running.** Stop the service first.
6. **If upstream is down when metadata needs a full refresh, the request
   fails** rather than serving a last-known-good copy. Deliberate. See
   section 3a.
7. **A database from an older version will not open.** No automatic
   migration. See section 3a.
8. **No admin API.** Everything is config files, signals, and logs.
9. **Compiler warnings are not errors anywhere in this repo.** Run
   `cargo clippy --all-targets -- -D warnings` yourself and wire it into CI.
   Plain `cargo build` lets real bugs through as warnings.
10. **One test is flaky in release builds only**
    (`artifacts_concurrency::blocklist_commit_is_not_delayed_by_a_large_project_refresh`).
    Its timing margin is tuned for debug builds. The behavior it tests is
    fine.
