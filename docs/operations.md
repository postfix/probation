# Operating Probation

This is the operator's document: how to run the service, what it protects, what it
does **not** protect, where its capacity limits actually are, and how to back it up
and restore it.

Every claim here was checked against the code in this repository or against a
measured run. Where something is not implemented, or is implemented more narrowly
than it sounds, it says so and marks the gap rather than leaving it to be discovered
in an incident. Section [12](#12-known-gaps) is the list of those.

---

## 1. What the service is

One process, one local data directory, one policy for every consumer. It proxies
public npm and PyPI metadata and artifacts, and it withholds two classes of release:

- anything younger than `cooldown_seconds` (default 24 hours), and
- anything the blocklist names, by package, by package/version, or by artifact digest.

Package managers do the dependency resolution. The firewall only decides what is
available to resolve against, and verifies every artifact before delivering it.

Eligibility is not a safety claim. An eligible package has passed the configured
checks; that is all it means.

## 2. Running it

### From the container image

```sh
docker build -t probation:mvp .
docker run --rm probation:mvp check-config /etc/probation/config.toml
docker run -d --name probation \
  -p 127.0.0.1:8080:8080 \
  -v /srv/probation:/var/lib/probation \
  -v /etc/probation:/etc/probation:ro \
  probation:mvp serve --config /etc/probation/config.toml
```

The image ships `config.sample.toml` at `/etc/probation/config.toml` and
`blocklist.sample.json` at `/etc/probation/blocklist.json`, with one edit made
at build time: `listen` becomes `0.0.0.0:8080`, because SPEC §3's loopback default
would make the published port unreachable from outside the container's own network
namespace. Publish that port only to the reverse proxy (section 6), not to a network.

The shipped sample blocklist is a *sample*. It carries a distant `expires_at` so the
image starts ready out of the box; mount your producer's real snapshot over that path
before the service is used for anything.

The build stage needs `cmake`, a C compiler and `perl`: reqwest's default rustls
crypto provider is `aws-lc-rs`, which builds `aws-lc-sys` from C. The runtime stage
needs `ca-certificates`: certificate roots come from `rustls-platform-verifier`, which
reads the system trust store, so an **empty trust store is a total upstream outage**
rather than a degraded mode — every metadata fetch and every artifact download fails.
Both are in the `Dockerfile` with that reasoning beside them.

### From the binary

```sh
cargo build --release --locked
./target/release/probation check-config  /etc/probation/config.toml
./target/release/probation check-blocklist /etc/probation/blocklist.json
./target/release/probation serve --config /etc/probation/config.toml
```

Both validation commands exit non-zero on the first problem, name it, and write
nothing. Run them in your deployment pipeline before restarting the service:
configuration changes require a restart, and a restart onto an invalid configuration
is an outage.

### Health endpoints

| Endpoint | Meaning |
| --- | --- |
| `GET /health/live` | The process is answering. Stays `200` through an expired blocklist and through unusable storage. |
| `GET /health/ready` | A valid blocklist is in force **and** storage is usable. `503` otherwise. No upstream is probed. |
| `GET /health/delivery` | **Alerting only — never wire this into a probe.** `503` while a decision record was lost to either sink in the last 60 s, `200` otherwise; `/health/ready` is unaffected either way. See section 8, "The rated load". |

Point your orchestrator's liveness probe at the first and its readiness probe at the
second. They are deliberately different questions: a service with an expired blocklist
is running correctly and must not be restarted; it must be taken out of rotation until
its producer catches up.

## 3. Capacity — and what `cache_max_bytes` does not cover

This is the finding SPEC §15 records as **OPS-01**, and it is the one most likely to
cause an incident, because the name `cache_max_bytes` reads like a total storage
bound and is not one.

The data directory has two halves:

```text
<data_dir>/content/     artifact bytes and in-flight temporary downloads
<data_dir>/state/       firewall.db, firewall.db-wal, the lock file
```

`cache_max_bytes` bounds **`content/` only**. It is the ceiling on bytes held by
verified artifact files plus the reservations of downloads currently in flight, and
the maintenance pass evicts down to it in approximate least-recently-used order.

`state/` is **outside that budget entirely**. Nothing in this service caps the size of
the database or its write-ahead log, and nothing warns when either grows. Provision
the filesystem with headroom beyond `cache_max_bytes` and monitor free space yourself.

What lives in `state/`, and therefore what grows:

- one row per project snapshot, holding the upstream payload;
- one row per artifact reference, holding its expected and computed digests, its
  publication or first-seen time, and its content key;
- one row per cached content object;
- the last accepted blocklist snapshot, in full.

Artifact reference rows and first-seen times are **identity records, not cache**. They
are what makes a restart not reset the cooldown clock and what makes a permanently
pinned digest permanent. Eviction removes content rows and files; it does not remove
pins. `state/` therefore grows monotonically with the number of distinct artifact
references this instance has ever seen. Deleting rows does not shrink the database
file, and there is no automatic pruning. Treat state growth as an operational capacity
limit to plan for.

> **Gap.** There is no startup free-space check and no low-space alarm. `fs4` is used
> for the exclusive data-directory lock only; the `available_space` headroom check
> named in the program design is not implemented. Monitor free space with your own
> tooling. If the filesystem fills, storage writes fail, readiness goes false and
> package requests answer `503` — the service never relaxes policy to free space, and
> it never deletes the write-ahead log to make room.

Reserve enough headroom for a blocklist commit and a checkpoint at all times. A
100,000-entry snapshot is about 9.6 MB of JSON, and both the previous and the new one
exist during the commit.

Memory: `memory_cache_max_bytes` is a budget for parsed metadata, hot reference
records and rendered responses. It is **not** total process memory, and it excludes
the blocklist itself and in-flight buffers. Measured resident set size with a
100,000-entry snapshot in force under sustained metadata load: **357–374 MiB** across
five runs (section 10). Size the process's memory limit from the top of that range,
not from `memory_cache_max_bytes`.

## 3a. The metadata maximum age — and the outage it can turn into a refusal

This is the finding the program design records as **TM-15-2**. It was *accepted*
rather than designed away, and **operations owns it**. Read it beside OPS-01 above:
both are cases where a default that looks like a safety setting has an operational
cost you have to decide about yourself.

`metadata_ttl_seconds` bounds how often this firewall **checks** upstream. It does
not bound how old a stored copy may become, because every upstream `304` renews the
validation time. `metadata_max_age_seconds` (default **86400**, one day) is the
separate bound on a copy's real age, measured from its last **full** fetch — an
instant no `304` ever advances. Once a snapshot reaches its ceiling the next request
refetches it in full with no validators at all, so upstream cannot answer `304`.

**The cost, stated plainly.** An over-age snapshot is **never served**. If that full
fetch fails — a transport error, a timeout, an unreachable registry — the request is
**refused** (`502`/`504`), not answered from the stored copy. So an actor who can
disrupt only the network path between this firewall and the real upstream, without
touching this process at all, can take warm projects offline by sustaining that
disruption past one ceiling. Before this control existed, warm reads survived an
upstream outage indefinitely. They no longer do.

Each project's ceiling is its configured value less a deterministic offset of up to a
tenth, derived from the project's own name, so projects fetched together — a bulk
seed, a restore from backup — lapse gradually instead of all at once. That spreads
the failure; it does not remove it. The offset only ever shortens, so
`metadata_max_age_seconds` remains a true maximum.

**Your two levers, and nothing else:**

- **Raise `metadata_max_age_seconds`.** A longer ceiling means a longer upstream
  outage is survivable on warm reads, and a longer window in which an unchanging or
  dishonest upstream can hold this firewall's view of a project fixed. It may not be
  set below `metadata_ttl_seconds`; the service refuses to start if it is.
- **Set `metadata_max_age_seconds = 0`.** This disables the ceiling entirely.
  **It reinstates exactly the unbounded-staleness exposure the ceiling exists to
  close:** an upstream that answers `304` forever will hold this firewall's cached
  view of a project fixed forever, and nothing here will ever notice. Choose it
  deliberately, and record why.

There is no third setting, no soft mode and no "serve stale on outage" switch. The
fail-closed behaviour is the specification's existing rule against serving expired
metadata during an upstream outage, reached by a second route.

The ceiling has **no effect on blocklist enforcement**, which invalidates rendered
responses on its own revision and never depends on upstream contact. A blocked
package stays blocked whether or not its snapshot is over-age. It also does not apply
to cached artifact bytes, which are content-addressed and cannot go stale.

> **Schema note.** Recording the last full fetch added a column to `projects` and
> moved `SCHEMA_VERSION` from 3 to 4. A database written by an older build is
> **refused, not migrated**: the service reports the version it found and leaves the
> file exactly as it is. This is acceptable only on the condition that nothing has
> shipped. The repository can show that no deployed database exists *in it*; it
> cannot show that none exists in the world. If you are holding a database written by
> an earlier build of this service, this release will not open it, and there is no
> migration step to run — treat that as a blocker and raise it before upgrading.

## 4. The blocklist

The service consumes one local JSON file. It does not fetch feeds, merge vendor data
or deduplicate anything: an external producer does all of that and atomically replaces
the file. The file must be writable only by trusted operators or that producer.

The blocklist is supplied by the operator. Whoever runs this firewall is accountable
for what is in `blocklist_file` and for where it came from; this service enforces that
file and makes no judgement about its contents.

The reload rules, all enforced:

1. The file is polled every `blocklist_poll_seconds`. A change is detected by device,
   inode, modification time and length, with a 60-second backstop re-read for a
   producer that rewrites in place instead of renaming.
2. The whole candidate is validated off the request path, within `max_blocklist_bytes`.
3. A changed snapshot must carry a **strictly increasing** revision. Rollback is
   refused. Identical revision and identical content is a no-op; identical revision
   with changed content is refused.
4. `generated_at <= now < expires_at` and `generated_at < expires_at`.
5. The accepted snapshot is committed to the database **before** it is published in
   memory.

A malformed replacement keeps the last valid snapshot in force and logs an error. An
empty but valid snapshot is accepted and means only cooldown protection is active — it
is never silently substituted for a missing one.

**At expiry the service fails closed.** Both new resolutions and artifact downloads
answer `503`, including requests that would have been cache hits. Liveness stays
healthy; readiness goes false. Your producer's publishing cadence and the snapshot's
`expires_at` window together decide how long an outage in the producer takes to become
an outage in installs. Choose the window deliberately and alarm on it.

Revocation is **not retroactive** — see below for exactly what a block does and does
not reach. A new full snapshot replaces the previous one including removals, so block
withdrawal is the operator's: still-active detections must appear in every snapshot
published.

### What a block reaches, and what it does not

A block takes effect for every request whose final policy check happens after the new
snapshot is published. That includes requests for artifacts this instance has already
downloaded, verified and cached, and previously issued artifact URLs: they are refused
from that moment on. So a block stops further fetches — CI runs, container builds,
fresh checkouts and cache misses all hit the refusal. The permanently pinned digests
SPEC §9 keeps across eviction are identity records, not permission; they are an input
to the block check and make a digest block *more* effective, not less.

What it does not reach is a copy already on a machine. Bytes already sent stay sent, a
response already authorised runs to completion, and anything already installed or
already held in a client's own cache keeps working. That is the boundary of a registry
proxy, not a defect in this one — removing an installed package is endpoint
remediation, and whatever handles that in your environment is what handles it here.

### OSV enforcement mode

`osv_mode` decides what an OSV match does, independent of the operator's own
blocklist: `enforce` (default) denies the request, `diagnostic` checks and logs a
match but never denies, and `off` skips the OSV check entirely. Changing it requires
a restart, like every other configuration key. `diagnostic` mode has no counter or
metric distinct from ordinary allowed traffic — the NDJSON `reason` field is the only
signal a would-be-blocked match happened, so an operator watching for it should
grep/alert on that exact string rather than expect a dedicated metric.

## 5. Backup, restore, and recovery failure

### What to back up

Three things, independently:

1. The configuration file.
2. The producer's current blocklist snapshot.
3. **The stopped service's complete `state/` directory**, including `firewall.db-wal`.

Artifact bytes under `content/` are replaceable — they are refetched and reverified
against the retained digest pins. Policy and identity records are not replaceable:
lose `state/` and you lose every first-seen time, every permanently pinned digest and
the last accepted blocklist revision. The cooldown clock restarts for every reference
whose age was known only from a first-seen value.

### How to back up

**Stop the service first.** The service holds an exclusive lock on the data directory
for its whole lifetime, and a copy taken while it is running can catch the database
and its write-ahead log in inconsistent states. There is no online-backup command in
this release.

```sh
docker stop probation    # the image sets STOPSIGNAL SIGINT, so this is graceful
tar -C /srv/probation -czf state-$(date -u +%Y%m%dT%H%M%SZ).tgz state/
docker start probation
```

Never delete `firewall.db-wal` as part of cleaning up temporary artifact files. It is
not a temporary file; it is the half of the database that has not been checkpointed
yet, and removing it discards committed state.

### How to restore

1. Stop the service.
2. Restore the whole `state/` directory together — the database and its write-ahead
   log are one unit.
3. Put a **current** blocklist in place before starting. A restored snapshot that has
   since expired leaves readiness false, which is correct: the service refuses to
   serve packages under a policy it cannot vouch for.
4. Start the service and wait for `/health/ready` to answer `200`.
5. Treat all cached metadata freshness as expired. It revalidates against upstream on
   the next request after its TTL, and the TTL of restored data cannot be trusted.

### When recovery fails

If the database cannot be opened, is not in the mode this build requires, or carries a
different schema version, the process **starts anyway** and:

- answers `/health/live` with `200`;
- answers `/health/ready` with `503`;
- refuses every package request;
- leaves the bytes on disk exactly as they were.

It never recreates the database and never truncates it. That is deliberate: silently
recreating would lose first-seen times, digest pins and the blocklist revision, and
would do so while looking healthy. A refused start with the data intact is a restore
you can still perform; a recreated database is not.

One specific refusal worth recognising: a zero-length or absent `firewall.db` beside a
**populated** `firewall.db-wal` is refused rather than opened, because opening would
overwrite the log and destroy a still-recoverable revision. If you see that, the log is
your data — take a copy of `state/` before doing anything else.

A data directory whose lock is already held by another process is a different failure:
`serve` reports it and exits. There is nothing to diagnose from inside a second
instance.

## 6. The reverse proxy in front of this service

The deployment model puts a reverse proxy between clients and this service. Three
responsibilities live there and nowhere else in this system.

### TLS termination

This binary speaks plain HTTP and its default listener is loopback. Terminate TLS at
the proxy, and set `public_url` to the URL clients actually reach — the artifact URLs
in every rendered document are built from it, so a wrong value produces metadata whose
download links do not resolve. `public_url` must be `https`, with no path, query or
fragment.

### Per-client rate limiting — required, and this service cannot do it

This is threat **TM-3**, accepted for the MVP and transferred to you.

The attack: a client requests a legitimate artifact and then consumes bytes slowly,
just fast enough to stay under the 30-second write-idle timeout, holding one of
`max_artifact_downloads` permits for up to the full 15-minute response lifetime.
Repeating that occupies every download permit and artifact delivery stops for
everyone.

The bounds this service does have are **global, not per client**:
`max_active_requests` caps concurrent requests, `max_artifact_downloads` caps
concurrent upstream transfers, and the two SPEC §9 deadlines bound how long any one
response can hold a permit. None of them is per-actor, and this binary has no client
identity to be per-actor about: no authentication, no accounts, one shared policy
(SPEC §3).

**Configure per-client connection and request-rate limiting at the proxy**, additive
to the global semaphores here. Size it so that concurrently occupied download permits
attributable to any one client stay below `max_artifact_downloads`.

### Egress filtering

The outbound boundary in this service refuses cross-origin redirects, URL credentials,
unexpected ports, non-HTTPS schemes, and DNS answers that resolve to loopback, private
or link-local addresses. One case it structurally cannot refuse: a **network-specific
NAT64 prefix** (RFC 6052 permits any operator prefix from /32 to /96) is
indistinguishable from an ordinary global address in a DNS answer. The well-known
`64:ff9b::/96` prefix is refused; an operator-chosen one cannot be.

Mitigate at the network: restrict this service's egress to the three upstream origins
it is allowed to reach (`registry.npmjs.org`, `pypi.org`, `files.pythonhosted.org`),
and pin connect-time addresses if your environment supports it.

## 7. What this service does not enforce

The proxy enforces on delivery. Everything below is outside that boundary, and none of
it is a defect:

- **Already-installed packages.** A block that arrives after an install does not remove
  anything from `node_modules` or a site-packages directory. Verified by
  `tests/e2e_npm.rs::an_already_installed_package_is_outside_the_enforcement_boundary`.
- **Client-side caches.** SPEC §2 places these outside the boundary. Measured
  behaviour for npm is narrower than that in one specific way: because every response
  carries `Cache-Control: no-store` and npm honours it, npm does **not** retain
  firewall-served tarballs in its own content cache, so a block still bites on a warm
  cache. That is an observation about npm's current behaviour, not a control — do not
  build a policy on it. pip's cache was not exercised (the e2e tests run with
  `--no-cache-dir`, which is what SPEC §13 asks for enforcement tests).
- **Anything not fetched through this index.** Alternate indexes, Git and URL
  dependencies, local wheels, vendored directories, and downloads an installer script
  makes for itself.
- **Existing lockfiles that pin upstream URLs directly.** Changing one registry setting
  does not rewrite them. Audit lockfiles during deployment.
- **Code that runs during installation.** The cooldown applies to wheels, source
  distributions and build dependencies fetched through the configured index. It does
  not inspect what an installer executes.

Cooperative client configuration:

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

Cooperative is the operative word. Enforced use requires network policy that prevents
direct public-registry downloads.

## 8. Logs

Structured JSON on stdout. One decision line per request, including router-level `404`
and `405` responses that reach no handler:

```json
{"level":"INFO","fields":{"message":"request decided","request_id":"req-0000000000000003",
 "method":"\"GET\"","ecosystem":"npm","package":"\"left-pad\"","version":"","status":200,
 "result":"ALLOWED","reason":"the request was served","blocklist_revision":42,
 "cache":"miss","duration_micros":415780,"bytes":23563}}
```

Every exclusion is explainable from `result`, `reason` and `blocklist_revision`
together with the snapshot that revision names. The `request_id` in the log is the
same one in the error body a client received. Credentials are never logged, and a
client's authorization headers, cookies and proxy credentials are never forwarded
upstream.

Set the level with `RUST_LOG`; the default is `info`. There is no metrics service in
this release — counters and timing summaries are emitted to stdout periodically. The
decision log itself is pinned and not silenceable by `RUST_LOG` — see "The rated load"
below.

### Delivering decisions to a file

stdout is kept by the host rather than by this process: under systemd it lands in the
journal, and under a container runtime in a node-level log file, with whatever
retention the host gives them. Two optional configuration keys append every decision
to a file this process owns as well, as one JSON object per line (NDJSON). Both are absent by default: with
no `log_file_path` this process opens no file, starts no delivery task, and writes
exactly the stdout line it writes today.

| Key | Default | Meaning |
| --- | --- | --- |
| `log_file_path` | absent — delivery is off | The file decisions are appended to. |
| `log_file_max_bytes` | `104857600` (100 MiB) | The size at which the live file is rolled over. Refused without `log_file_path`, and refused as zero. |
| `log_queue_max_bytes` | `1966080000` (1,875 MiB) — see "The rated load" below | The in-memory budget for records queued while the file cannot keep up. Refused without `log_file_path`, refused as zero, and refused above `4294967296` (4 GiB). |

Each line carries the same fields as the stdout decision line — twelve, or thirteen
with `consumer` when `log_consumer_identification` is on — plus an
`"event"` field naming which record it is — `request_decided` for a decision,
`request_summary` for the periodic counter summary. The summary lines also carry
`dropped_file` and `dropped_siem`: the number of records that could not be delivered
in that window. A record is never discarded silently; if delivery cannot keep up, the
loss is counted and reported. Delivery never slows or fails a request — a record that
cannot be handed over is dropped, and the request is answered regardless.

Every record in the file and at the SIEM collector carries a `timestamp` as its first
field: UTC RFC 3339 with exactly six fractional digits and a `Z` suffix, for example
`2026-09-21T14:13:20.000000Z`. It is the time the record was built — for a decision,
when the response was ready; for a summary, when its window was closed. A collector's
own receipt time can lag behind it by the two-second batch window plus any retries, so
sort and correlate on `timestamp`, not on arrival. The stdout decision line has no
`timestamp` field, because the console formatter already stamps every line it writes.

**Disk use is bounded at twice `log_file_max_bytes`.** When the live file reaches the
cap it is renamed to `<log_file_path>.1`, replacing any previous `.1`, and a fresh
file is started. **One generation is kept and no more**; an operator who needs longer
history ships the records to their own log system rather than accumulating them here.

Two obligations come with the key, and neither is enforced by this process:

- **Exactly one process may write `log_file_path`.** There is no interprocess lock.
  Two instances pointed at the same file interleave and lose records.
- **Do not hand the file to an external `logrotate`, or anything else that renames or
  truncates it.** This process does its own rollover and keeps an open handle; a
  rotator moving the file out from under it sends later records to the rotated copy
  until the next write error reopens the path, which is silent data loss dressed up
  as working rotation. Set `log_file_max_bytes` instead.

### Delivering decisions to a SIEM collector

Two further optional keys ship the same records to an HTTP collector. Both are absent
by default: with no `siem_url` this process builds no HTTP client, starts no delivery
task and connects nowhere.

| Key | Default | Meaning |
| --- | --- | --- |
| `siem_url` | absent — delivery is off | The collector records are `POST`ed to. Must use `https` unless the host is a loopback address or `localhost`; anything else is refused at startup. |
| `siem_auth_header` | `Authorization` | The header the credential is sent under. Refused without `siem_url`, and refused if it is not a valid HTTP header name. |
| `siem_queue_max_bytes` | `1966080000` (1,875 MiB) — see "The rated load" below | The in-memory budget for records held while the collector is unreachable, on top of the one in-flight batch the retry loop always holds. Refused without `siem_url`, refused as zero, and refused above `4294967296` (4 GiB). Two sinks are two queues: a deployment with both configured pays both. |

**The credential is never written in the configuration file.** It is read once at
startup from the environment variable `PROBATION_SIEM_AUTH`, kept only as a
redacted-in-`Debug` header value, and never stored on the configuration or written to
any log line — only the header *name* appears in the startup line. With the variable
unset, delivery is unauthenticated. With it set to something that is not a legal HTTP
header value, the process refuses to start and says so without echoing the value.

Records are batched at **256 records or two seconds**, whichever comes first, and sent
as one `POST` of newline-delimited JSON with `Content-Type: application/x-ndjson` —
the same objects the file sink writes. **Redirects are never followed**: a `3xx` from
the collector sends the batch nowhere, by design, so a compromised collector cannot
point this process, credential attached, at a host nobody configured.

A transport error, a `5xx` or a `429` is retried three times, at 100 ms, 500 ms and
2 s. Any other non-2xx answer is not retried: a stale credential or a rejected payload
fails identically on every attempt. Each attempt is bounded at three seconds, and at
shutdown the drain is bounded at five, so a collector that goes silent cannot hold up
a restart.

Every record that could not be delivered is counted and reported in the
`dropped_siem` field of the `request_summary` record, alongside `dropped_file` — in
the log file, in the collector's own feed, and on stdout. Records lost during the
final drain are reported once on stdout as the process exits, because by then the
sinks themselves have stopped.

**Known limitation: a rejected batch is lost whole.** When the collector refuses a
batch, all of its records are dropped and counted — up to 256 at a time — rather than
the one record it objected to. A record shape the collector keeps rejecting therefore
repeats that loss on every batch containing it. This is a deliberate choice: isolating
the offending record means either a burst of up to 256 individual `POST`s at a
collector that is already failing, or a bisection ladder, and both make a bad moment
worse. **An operator who needs completeness configures `log_file_path`**, which has no
equivalent failure mode.

### Recording who asked

One further optional key adds the peer IP of the asking connection to every delivered
record, as a `consumer` field. It is off by default, and with it off no record carries
the field at all — neither in the log file, nor at the collector, nor on stdout.

| Key | Default | Meaning |
| --- | --- | --- |
| `log_consumer_identification` | `false` — nothing is recorded | Adds `consumer`, the peer IP of the connection, to every decision record and to the stdout decision line. Refused at startup unless `log_file_path` or `siem_url` is set. That checks only that a destination is configured, not that records arrive there — see below. |

**This records who is installing packages. Read the facts below before turning it
on.**

- **What is recorded is the peer IP of the accepted TCP connection, and nothing the
  caller supplies.** Not `X-Forwarded-For`, not `User-Agent`, not any other header — a
  caller cannot choose, spoof or blank what appears here. The port is never recorded.
- **Every delivered record pairs that peer IP with the time of the request.** The
  record's `timestamp` says when the address asked, to the microsecond, in the log
  file and at the collector alike.
- **Behind a proxy, NAT or load balancer it identifies that hop, not the machine that
  ran the install.** If everything reaches this process through one ingress, every
  record carries that ingress's address and the field tells you nothing about the
  developer or the build agent behind it.
- **The addresses also appear on the stdout decision line**, and stdout is kept on
  disk by the host under systemd (the journal) or a container runtime (a node-level
  log file, often shipped off the node by a cluster agent). Its permissions and
  retention belong to the host, not to this process.
- **Turning it off erases nothing already written.** Addresses already recorded stay
  in four places: `log_file_path`, its `.1` rollover, the collector, and the host's
  console log. There is no purge path; removing them from all four is the operator's
  job, on the operator's own retention schedule.
- **The log file is created readable by its owner alone (`0600`).** That applies only
  when this process creates it: a file that already exists keeps its mode, and if it is
  accessible to the group or to other users the process logs one warning naming the
  path and mode, and carries on. It does not change the mode of a file it did not
  create — tighten it yourself with `chmod 600` before turning this on, since a
  deployment that ran earlier releases will already have a file created `0644`.
- **With it on, an unopenable `log_file_path` stops startup.** The file is opened once
  at startup; a missing directory or a path the service user cannot write refuses to
  start, rather than collecting addresses with nowhere durable to put them. With it
  off, the same failure logs one error naming `log_file_path` and the process keeps
  serving, counting every record it cannot write as dropped.
- **With it on, the process can still collect addresses that reach no destination.**
  A deployment with only `siem_url` is never checked at startup: a collector that
  does not resolve, or one that refuses every batch (a permanent `403`, say), leaves
  the process recording addresses and counting every record as dropped. The file sink
  can fall into the same state after startup, when its volume is unmounted or full or
  the file is deleted. Neither state can be detected at startup; the signal is the
  per-sink drop count, `dropped_file` and `dropped_siem`, in the periodic
  `request_summary` record and on the stdout `request summary` line. Watch for them
  staying above zero.
- **`check_config` validates keys, not destinations.** It writes nothing, so it cannot
  open the log file, and it can report a configuration as valid that then fails at
  boot because `log_file_path` cannot be opened.

### The rated load, and what a default deployment survives

**The rated figure.** Measured on the reference machine — AMD Ryzen 9 7950X3D
(16 cores / 32 threads), 124 GiB RAM, Linux 7.1.8, `rustc` 1.96.0, release profile —
`cargo bench --bench delivery_rated_load` drives the delivery pipeline through the file
sink for ten minutes and finds the highest rate it sustains with **zero records
dropped**: **N = 59,288 decided requests per second.** Below this figure this release
loses no decision record to the delivery pipeline; nothing here says anything about the
rest of the request path. This figure is **published for reference, as this machine's
ceiling — it is not what the default queue budget below is sized against**, because no
honest budget could cover an outage at it (see below). `cargo bench` (with no `--bench`
flag) does not run this target — it takes ten minutes and is invoked by name (see
`README.md`).

**`BYTES_PER_RECORD` — a ceiling, not a mean.** Every queue is sized in bytes, not
records, from `BYTES_PER_RECORD = 32,768`: `3 x FIELD_CEILING_BYTES` (10,242 — 256
characters, 4 bytes per UTF-8 code point, 10 bytes for the worst-case `Debug` escape,
2 quotes — for `package`, `version` and `method`) plus a 64-byte timestamp, a 64-byte
request id, a 512-byte reason and the 256 bytes `size_of::<Decision>()` allows, rounded
up to the next power of two: `30,726 + 64 + 64 + 512 + 256 = 31,622 <= 32,768`. A
record's real heap footprint is bounded by this figure by construction (`rl16b`,
`rl22`); it is never averaged down by smaller records, so `budget / BYTES_PER_RECORD`
is always a safe lower bound on how many records a budget holds.

**Why the default is sized from a stated reference load, not from `N`.** The formula
that would size a default budget to survive a five-minute collector outage **at the
rated (measured) load**, `ceil(5 min x N x BYTES_PER_RECORD)`, computes to roughly
**543 GiB per sink** (555,825 MiB) at the measured `N` — about 136 times past
`MAX_QUEUE_MAX_BYTES` (4 GiB, the largest budget either key accepts). No operator would
set that, and raising the ceiling to fit it would mean accepting far more resident
memory risk for a number nobody could use. `N` is a synthetic ceiling in the first
place: the bench drives `/health/live` in a closed loop with no upstream registry round
trip in the path, so it measures what the delivery pipeline alone can sustain, not what
real package-manager traffic produces — a real deployment's request rate is bottlenecked
far below `N` by actual npm/PyPI upstream latency and by `max_upstream_requests`
(default 32 concurrent).

So **the default is derived from a stated 200 requests/second reference load** instead:
`ceil(5 min x 200 x BYTES_PER_RECORD) = 1,875 MiB` per sink. At that reference load the
default buys the full five minutes:

> outage tolerance = budget / BYTES_PER_RECORD / rate = 60,000 records / 200/s = **300
> seconds (5 minutes)**.

At the measured `N` the same default buys far less — about **1 second** — which is
stated here so the gap is never a surprise:

> at the rated (measured) figure: 60,000 records / 59,288/s ≈ **1.0
> seconds**.

Compute your own deployment's tolerance from the same formula, using your own observed
decided-requests-per-second rather than either published number:

> your tolerance (seconds) = your `*_queue_max_bytes` / 32,768 / your observed
> requests/second.

**The budget is additive, not a cap on total memory.** `log_queue_max_bytes` and
`siem_queue_max_bytes` each bound one sink's own queue, on top of
`memory_cache_max_bytes` (section 3) and everything else this process holds — they do
not share a pool with it or with each other. The SIEM sink additionally holds one
serialized batch outside its queue budget for as long as the collector is unreachable
(up to 256 records) — the batch the retry loop is currently attempting to deliver.

**Upgrade note.** Before this feature, an unreachable SIEM collector cost records after
roughly seven seconds, once the fixed three-attempt backoff ladder (100 ms, 500 ms,
2 s) gave up on a batch. **Starting with this release, a deployment that sets neither
new key loses nothing until its 1,875 MiB default queue is full** — records are held
and retried for as long as the collector stays down, up to that budget, and only
records past it are dropped and counted. An operator who was relying on the old
~7-second failure window to bound memory during an outage should read the tolerance
formula above and, if 1,875 MiB is more than their host can spare, set
`siem_queue_max_bytes` explicitly to a smaller budget — or raise it, up to the 4 GiB
`MAX_QUEUE_MAX_BYTES` ceiling, for a deployment whose real traffic runs above the
200 req/s reference load.

**`GET /health/delivery` is an alerting signal, never a probe target.** It answers
`503` while a decision record was lost in the last 60 seconds and `200` otherwise
(section 2, "Health endpoints"); `/health/ready` never reflects this state, on purpose,
so a firewall that is shedding decision records is never pulled out of a load
balancer's rotation for it. **Do not wire it into a liveness, readiness or load-balancer
health check** — it is unauthenticated, and a caller who can trigger a loss and then
poll it can otherwise use it to confirm things about the deployment they should not be
able to. Poll it only at an interval **strictly shorter than 60 seconds**: the quiet
window is measured from the first probe that observes a loss, not from the loss itself,
so a gap of 60 seconds or more between probes can read `200` immediately after a real
loss.

**stdout's decision trail, restated.** stdout carries every decided request — including
router-level `404` and `405` responses — **except**: the console writer itself
discarding a write (a dead pipe reader, or `ENOSPC` on a redirected stdout); a handler
that panics before `tracing::info!` runs; the host's log transport truncating the
stream under volume it cannot keep up with (the decision trail shares stdout with this
process's other diagnostic lines, and applies no volume control of its own); or a
**span- or field-qualified** `RUST_LOG` directive that out-specifies the pin below.
None of these four has a demonstrated trigger in this release; they are named so an
operator investigating a missing decision line knows where to look.

**The decision log's level is pinned.** No level or target directive set through
`RUST_LOG` can silence `probation::http::logging` — `RUST_LOG=warn`,
`RUST_LOG=hyper=debug` and an empty `RUST_LOG` all still print every decision line,
because this process appends its own `info` directive for that target after parsing
whatever the operator sets. The one exception is the fourth item above: a directive
that names a **span or field** on that same target still out-specifies the pin. Use
`RUST_LOG` freely to control every other target's verbosity.

## 9. Failure responses

| What happened | Status |
| --- | --- |
| Version or artifact held by the cooldown, or blocked | `403` with `reason`, and for a hold `eligible_at` and a numeric `Retry-After` |
| Unknown package or reference, or removed upstream | `404` |
| Invalid input | `400` |
| Unsupported route, method or representation | `404`, `405`, `406` |
| Blocklist missing or expired, local capacity exhausted, overloaded, storage unusable | `503` |
| Upstream failure, invalid upstream metadata, integrity mismatch | `502` |
| Upstream timeout | `504` |

Every response, including every error, carries `Cache-Control: no-store`. The service
never produces a downstream `304` and never forwards upstream validators to a client.

Two of these deserve an operator's attention rather than a client's:

- **`502 INTEGRITY_MISMATCH`** means the bytes behind a reference changed. The first
  verified download of a reference pins its computed SHA-256 and SHA-512 permanently,
  including when policy later blocks them, and eviction does not clear those pins. A
  mismatch discards the new bytes and keeps the original pins. Investigate it; it is
  either an upstream integrity incident or a reference identity error.
- **`503` from storage** means writes are failing. Readiness is already false. The
  service will not relax policy to recover, so this needs a human.

## 10. Benchmark results against the SPEC §12 targets

Run with `cargo bench`. Three benches, in `benches/`, each printing the quantity SPEC
§12 states rather than a mean with a confidence interval.

They use no benchmarking framework — each is a `harness = false` `main` that samples,
sorts and reports percentiles itself, and the `criterion` dev-dependency the program
design had named for this job was dropped because it reports means with confidence
intervals and no percentiles, which is not what SPEC §12's targets are stated in.

**Measurement environment.** AMD Ryzen 9 7950X3D, 32 logical cores, 124 GiB RAM, Linux
7.1.8, release build, local NVMe, plain HTTP over loopback without TLS, upstream
served by an in-process fake registry. Payload 8 MiB in 64 KiB chunks on both sides of
the artifact comparison. Blocklist fixture 100,000 entries / 9.6 MB.

**Every figure in the Measured column is a range across five consecutive `cargo bench`
runs**, on 2026-09-20, not a single reading. These quantities vary between runs by
more than their own precision, so a single point figure would be a more confident
number than the instrument can support. Read the range, not its midpoint.

The host was not quiescent: unrelated desktop applications held one-minute load
average between 1.67 and 8.38 across the five runs, and swap was exhausted throughout.
The artifact ratios moved by less than four points over that whole range, which is
itself the evidence that the comparison is drift-cancelling — see below.

The **Pre-change** column is the same benches run on 2026-09-19 against a build that
predates the advertised-reference-set cache described below, kept here so the change
is checkable rather than asserted.

| SPEC §12 scenario | Target | Measured, range over 5 runs | | Pre-change, 2026-09-19 |
| --- | --- | --- | --- | --- |
| Warm metadata, 100-version project | ≥ 1,000 responses/s, p95 ≤ 5 ms | **120,178–144,006 responses/s** at concurrency 32; **p95 0.085–0.119 ms** | MET | 151,865 responses/s; p95 0.115 ms — MET |
| Warm policy denial | p95 ≤ 2 ms | **p95 1.187–1.307 ms** | MET | p95 1.153 ms — MET |
| Verified warm artifact, additional TTFB vs an unfiltered local-file server — 100-version project | p95 ≤ 5 ms | **+0.123 to +0.163 ms** | MET | +0.675 ms — MET |
| … same, 1,000-version project (511 KB document) | p95 ≤ 5 ms | **+0.114 to +0.158 ms** | MET | +6.232 ms — **BREACH** |
| … same, 5,000-version project (2.6 MB document) | p95 ≤ 5 ms | **+0.094 to +0.153 ms** | MET | +37.903 ms — **BREACH** |
| Verified artifact throughput vs that baseline — 100 versions | ≥ 85 % | **110–112 %** | MET | 99.9 % — MET |
| … 1,000 versions | ≥ 85 % | **109–111 %** | MET | 44.9 % — **BREACH** |
| … 5,000 versions | ≥ 85 % | **109–113 %** | MET | 11.1 % — **BREACH** |
| Concurrent cold requests for one reference | exactly one upstream transfer | asserted by `tests/artifacts_concurrency.rs::concurrent_cold_requests_cause_exactly_one_upstream_transfer`, not by a bench | MET | same test — MET |
| Valid blocklist replacement, 100,000 entries, under load | active within two polling intervals (10 s at the sample's 5 s interval) | **4.96–5.03 s**, while 16 workers served 644,000–667,000 metadata responses | MET | 4.97 s / 697,200 responses — MET |

Each artifact row is 1,000 paired samples per shape per run, so 15,000 downloads of
8 MiB per side behind the three artifact TTFB rows. The 2026-09-19 pre-change figures
are single runs of 150 unpaired samples, which is part of why they are a historical
baseline and not an acceptance. No verdict in the table changed across runs.

### Why the throughput ratios sit at about 110 %, and how to read them

A proxy cannot sustainably outrun the unfiltered file server it proxies, so a ratio
above 100 % is a fact about the instrument, not about this service. It is worth
understanding rather than ignoring, because the same number was unusable two days ago
and is now reproducible to within four points.

**Two asymmetries were found and fixed.**

- *Connection warmup.* The firewall side ran ten unmeasured requests before sampling
  while the baseline went straight into its samples, so the baseline's first samples
  paid a cold-connection cost the firewall's did not. Both sides now run the same
  warmup through one shared `warm_up` helper.
- *Separate measurement blocks.* The two sides were measured one after the other, so
  any change in machine load between them landed entirely in the ratio. On a busy host
  that produced 56–252 % on identical code — a measurement of the host. The bench now
  **interleaves** them, one baseline request then one firewall request inside a single
  loop (`measure_paired`), so shared drift cancels sample for sample. Sample count also
  went from 150 to 1,000 per side per shape.

The effect is the point: across five runs whose one-minute load average ranged from
1.67 to 8.38, every one of the fifteen shape-runs landed between 108.9 % and 112.7 %.
The old spread was not this host being noisy; it was the instrument charging drift to
the firewall.

**One asymmetry remains, and it is what the residual ~10 % is.** The firewall streams
an artifact from a dedicated task feeding a one-chunk channel (`src/artifacts/stream.rs`,
`file_body`), so it reads chunk *n+1* while the client is still consuming chunk *n*.
The bench's baseline server reads the next chunk only when its response stream is
polled, strictly serially. Same 64 KiB chunk size, same payload, different pipelining.
It shows up in the tails too: the baseline's total p95 sits near 47 ms against the
firewall's 5.4 ms. Now that the noise is gone, this bias is visible for what it is — a
steady offset of roughly ten points, not a fluctuation. Correcting it means giving the
baseline server the same read-ahead; that is not done here.

**So read the ratio rows as "≥ 85 % is cleared with about 25 points of margin, of
which roughly 10 are known instrument bias"** — not as evidence the firewall is faster
than serving a file. The additional-TTFB rows carry no such offset, are positive in
every one of the fifteen shape-runs, and sit at 2–3 % of the 5 ms budget; they are the
stronger evidence for SPEC §12's warm-artifact requirement.

Also recorded, because SPEC §10 asks for it: **resident set size 357–374 MiB** with
the 100,000-entry snapshot in force under sustained load, against a
`memory_cache_max_bytes` of 256 MiB. The two are different quantities; see section 3.
Startup with a 100,000-entry snapshot already on disk — validate, commit, publish, and
open the database — took **53–65 ms**. A run outside this set took 260 ms, so size a
startup probe's patience well above the high end rather than from the median.

### The warm-artifact cost, and why it no longer scales with project size

The extra time a warm artifact request costs used to scale with the size of the
**project document**, not with the size of the artifact. It no longer does:

| Versions in the project | Document size | Additional vs baseline, 3 runs | Additional, pre-change |
| --- | --- | --- | --- |
| 100 | 51 KB | +0.123 to +0.163 ms | +0.606 ms |
| 1,000 | 511 KB | +0.114 to +0.158 ms | +6.761 ms |
| 5,000 | 2.6 MB | +0.094 to +0.153 ms | +35.655 ms |

The pre-change column was close to linear in version count — roughly 7 µs per version
— which is the signature of per-request, per-version work rather than of anything to
do with the bytes being served. Every artifact request revalidates that the reference
is still advertised by a current project snapshot (SPEC §9 requires this, and it
closes a real hole — without it, withdrawn bytes stay downloadable by anyone who can
compute the reference id), and that revalidation used to re-parse the stored project
document and recompute a reference id for every version, on every request, including a
fully warm one.

This release caches the advertised reference-id set per project snapshot, so the
revalidation is a set membership test against work done once when the snapshot was
stored. The check itself is unchanged — the same question is asked and the same
answers are given — so nothing about what is served or refused has moved; only the
per-request cost has. The measured curve is now flat across a 50× range of document
size, which is what that change predicts.

**Consequence for an operator today:** the 5 ms warm-artifact target and the 85 %
throughput target hold at every project size measured, up to 5,000 versions / 2.6 MB
of metadata. Larger projects than that were not measured; the mechanism gives no
reason to expect a cliff, but that is an inference and not a measurement.

## 11. Verified client behaviour

Run with `cargo test --test e2e_npm -- --ignored` and
`cargo test --test e2e_pip -- --ignored`. These drive the real `npm` and `pip`
binaries against a listening instance. Nothing in them reaches a public registry: the
firewall's upstream is an in-process fake, and the clients talk to loopback.

Two client versions each, as SPEC §13 requires — the previous npm major and pip minor
alongside the current ones — plus npm 12, the current upstream stable major:

| | Current upstream stable | On `PATH` here | Previous |
| --- | --- | --- | --- |
| npm | **12.0.2** (on Node **v24.19.0**) | 11.16.0 | **10.9.9** |
| pip | **26.2.1** | 25.1.1 (the interpreter's) | **25.0.1** |

Every version in bold is pinned by version in the test files and installed out of tree,
at `~/.local/share/probation-e2e-clients` or wherever
`PROBATION_E2E_CLIENTS` points:

```sh
ROOT=~/.local/share/probation-e2e-clients
npm install --prefix $ROOT/npm-12.0.2  npm@12.0.2
npm install --prefix $ROOT/npm-10.9.9  npm@10.9.9
python3 -m pip install --target $ROOT/pip-26.2.1 pip==26.2.1
python3 -m pip install --target $ROOT/pip-25.0.1 pip==25.0.1
```

npm 12 declares its supported engines as `^22.22.2 || ^24.15.0 || >=26.0.0`, so its leg
runs under a Node it supports rather than whatever is on `PATH`. It is looked for at
`~/.nvm/versions/node/v24.19.0/bin`, or at `PROBATION_E2E_NODE_BIN`:

```sh
nvm install v24.19.0
```

A test whose client is missing fails naming that command; it never skips quietly.

| Behaviour | Client | Test |
| --- | --- | --- |
| An install succeeds on npm 12's defaults, with no `--allow-remote` and no `.npmrc` | npm **12.0.2** | `npm_12_installs_without_allow_remote` |
| An install falls back to an older eligible release, with the requirement unedited | npm 11.16.0 **and 10.9.9** | `an_install_falls_back_to_an_older_eligible_release`, `…_on_the_previous_npm_major` |
| `npm ci` fails on a blocked pin with a `403`, and the lockfile is byte-identical afterwards | npm 11.16.0 **and 10.9.9** | `npm_ci_fails_on_a_blocked_pin_without_rewriting_it`, `…_on_the_previous_npm_major` |
| `npm ci` succeeds on an allowed lockfile and does not rewrite it | npm 11.16.0 | `npm_ci_succeeds_on_an_allowed_lockfile` |
| An already-installed package stays installed after a block | npm 11.16.0 | `an_already_installed_package_is_outside_the_enforcement_boundary` |
| Install from a wheel, falling back past a held release | pip **26.2.1 and 25.0.1** | `pip_installs_from_a_wheel_falling_back_to_an_older_eligible_release`, `…_on_the_previous_pip_minor` |
| Install from a source distribution | pip **26.2.1 and 25.0.1** | `pip_installs_from_an_sdist`, `…_on_the_previous_pip_minor` |
| Resolution fails when nothing eligible remains | pip **26.2.1 and 25.0.1** | `pip_fails_when_nothing_eligible_remains`, `…_on_the_previous_pip_minor` |
| An exact pin on a held release is refused, never substituted | pip **26.2.1** | `an_exact_pin_on_a_held_release_is_refused_not_substituted` |

No behaviour differed between npm 10.9.9, 11.16.0 and 12.0.2, or between pip 25.0.1 and
26.2.1.

### npm 12 installs with no client configuration, and why the artifact paths look the way they do

**Set nothing.** npm 12 installs through this firewall on its own defaults. If you are
carrying an `allow-remote=all` line in an `.npmrc` from an earlier release of this
service, delete it: it disables an npm supply-chain control for **every** tarball
dependency in that project, not only for the ones this proxy serves, which defeats the
point of running a package firewall at all.

This is why artifacts live at `/npm/artifacts/{reference_id}/{filename}` and
`/pypi/artifacts/{reference_id}/{filename}` rather than under a single `/artifacts/`
root. npm 12 changed the default of `allow-remote` from `all` to `none`, and exempts
only tarballs whose URL shares **both the origin and the path prefix** of the
configured registry. An earlier release of this service served metadata under `/npm/`
and artifacts under `/artifacts/`, so every rewritten `dist.tarball` matched the origin,
failed the prefix, and was refused:

```text
npm error code EALLOWREMOTE
npm error Fetching packages of type "remote" have been disabled
npm error Refusing to fetch "fixture-widget@http://…/artifacts/…/fixture-widget-1.0.0.tgz"
```

Serving each ecosystem's artifacts under that ecosystem's own prefix satisfies the
check. `npm_12_installs_without_allow_remote` is the standing witness: it drives npm
12.0.2 on Node v24.19.0 with no `--allow-remote` flag, no `.npmrc`, and a fresh cache.

Two consequences worth knowing:

* **Nothing migrated.** A reference id is a hash of the artifact reference — ecosystem,
  name, version, filename, upstream URL and expected digests — and never of the public
  path. Moving the route rotated no id, invalidated no stored record, and moved no
  digest pin or first-seen time. Old bookmarked URLs under `/artifacts/…` are simply
  `404`; clients rediscover the current URL from metadata, which is where they get it
  from in the first place.
* **The ecosystem in the URL is checked.** A reference id is derived from public
  metadata and is not an authorization token, so an npm reference asked for at
  `/pypi/artifacts/…` is refused with `404` rather than served under the wrong
  ecosystem. Policy never read the path — it reads the stored record — so this changes
  no allow or deny decision; it keeps the decision log honest.

> **Still outside the boundary.** SPEC §11 places Git, URL and alternate-index
> dependencies outside registry-proxy coverage. A project that has any of those still
> needs an `allow-remote` override for them, whatever this service does. What is
> restored here is `allow-remote=none` compatibility for trees whose tarballs are all
> resolved through this firewall — and no more than that.

## 12. Known gaps

Everything in this list is true of this release. None of it is hypothetical.

1. **No free-space check or alarm.** Section 3. Monitor the filesystem yourself.
2. **`serve` waits on SIGINT and installs no SIGTERM handler.** Inside the container
   this is worked around rather than fixed: the image sets `STOPSIGNAL SIGINT`, so
   `docker stop` shuts down gracefully (measured: exit 0 in under 0.1 s, with the
   `shutting down` line in the log). **Outside the container the gap is live** — a
   plain `kill` on the process sends SIGTERM, which has its default disposition and
   terminates it immediately without a graceful shutdown. Send `SIGINT` instead
   (`kill -INT`, or Ctrl-C), and configure any systemd unit with
   `KillSignal=SIGINT`. An ungraceful stop is survivable in any case — startup
   recovers the write-ahead log and removes incomplete temporary downloads, and a
   cache mapping whose file turns out to be missing or the wrong size is discarded
   when it is next read; both paths are tested — but it should not be the normal
   path.
3. **State grows monotonically.** Section 3. No pruning, and deleting rows does not
   shrink the file.
4. **Metadata removal is visible only after the metadata TTL** (`metadata_ttl_seconds`,
   default 300 s). A version withdrawn upstream can still appear in a listing for up to
   that long. Artifact delivery is judged on the reference row, which is not subject to
   this lag.
5. **A computed-digest block can stay visible in a listing for up to one metadata
   TTL** under a concurrent reader, for a known and accepted race. The artifact
   endpoint refuses it immediately regardless; only the listing lags.
6. **No online backup.** Stop the service to take a consistent copy of `state/`.
7. **Expired metadata is not served during an upstream outage.** If upstream is
   unreachable after the TTL expires, the affected project answers `502`/`504` rather
   than serving a stale document. This is deliberate. `metadata_max_age_seconds`
   (section 3a) extends that refusal to a project whose stored copy has passed its age
   ceiling, even though its TTL is being renewed by upstream `304`s.
8. **A database written by an earlier build is refused, not migrated.** Section 3a's
   schema note. There is no migration step.
9. **No administrative API.** Everything is configuration files, signals and logs.
10. **Nothing in this repository enforces `-D warnings`.** If you build or patch this
    service yourself, read this one. There is no `.cargo/config.toml`, no CI workflow
    and no `#![deny(warnings)]` anywhere in the tree, so plain `cargo build` and plain
    `cargo clippy` both exit 0 on code that emits warnings. Several of the guards in
    this service degrade *quietly* rather than loudly when they are edited wrongly —
    swapping a compare-and-set cache insert for an unconditional one, for example,
    compiles clean and only leaves an unused-variable warning behind. Build with
    `cargo clippy --all-targets -- -D warnings`, as `README.md` says and as every
    check recorded here did, and put that form in whatever CI you run this through.
    The flag is the only thing that turns that class of regression into an error.
11. **The test suite has never been green under `--release`.** `cargo test` passes
    completely (276 passed, 0 failed, 15 ignored). `cargo test --release
    --no-fail-fast` gives 275 passed, 1 failed: `artifacts_concurrency::`
    `blocklist_commit_is_not_delayed_by_a_large_project_refresh`. The test asserts at
    `tests/artifacts_concurrency.rs:991` that a large maintenance backlog finishes at
    least 500 ms *after* a concurrent blocklist commit, which is how it demonstrates
    that maintenance never delays a commit. Optimized code drains the backlog in
    roughly 160–200 ms, so the margin cannot be met — observed 362 ms commit against
    696 ms drain, a 333 ms gap, and 198 ms against 369 ms on another run. The
    behaviour under test is fine in both profiles; the *threshold* is calibrated to
    debug-build timing. Expect this failure, do not treat it as a regression, and do
    not read it as maintenance blocking commits. Note also that `cargo test
    --release` stops at the first failing target, so it reports nothing about the
    twenty targets after this one — use `--no-fail-fast` if you want the whole
    picture. Fixing it means re-deriving the margin from the profile, sizing the
    backlog to the build, or making the test profile-independent; none of those is in
    this release.
