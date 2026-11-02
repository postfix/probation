# Repository grounding: management-server (managed mode)

Source: sf-repo-view, 2026-10-20. Verdict: ORIENTED (structural tier).
Repository root: `/home/john/go/src/github.com/postfix/probation`, branch `main` at `23e8822`.
Paths are repository-relative and line numbers are one-based against the current bytes.
Anything marked **(inferred)** is a reading of the code, not something the code states.

This refreshes and replaces the two earlier briefings for this design:
`docs/plans/rated-load-guard/evidence/repository-structure.md` was written against the old
`osprey` / `package_firewall` naming, and `docs/plans/osv-intel/evidence/repository-structure.md`
predates the OSV slice landing. Their module map still holds, but their line numbers are stale.
For example, `delivery::Decision` was at `:54` and is now at `src/delivery/mod.rs:161`. The crate is
now `probation` (`Cargo.toml:2`).

---

## 1. Request entry points and where a per-request credential could be read

**Router**: `http::router` is at `src/http/mod.rs:42-92`. Routes are registered explicitly and have no
catch-all.

| Route | Handler | Gets `HeaderMap`? |
|---|---|---|
| `GET /npm/{package}` | `npm_routes::package`, `src/http/npm_routes.rs:35` → `npm::serve`, `src/npm/mod.rs:53` | yes (`:37`, used for `Accept`) |
| `GET /npm/{package}/{version_or_tag}` | `npm_routes::package_version`, `src/http/npm_routes.rs:54` → `npm::serve` | yes (`:56`) |
| `GET /npm/-/ping` | `npm_routes::ping`, `src/http/npm_routes.rs:25` | no (no policy, no storage) |
| `GET /pypi/simple/` | `pypi_routes::index`, `src/http/pypi_routes.rs:41` → `pypi::index`, `src/pypi/mod.rs:138` | yes |
| `GET /pypi/simple/{project}/` | `pypi_routes::project`, `src/http/pypi_routes.rs:52` → `pypi::serve`, `src/pypi/mod.rs:70` | yes (`:54`) |
| `GET /pypi/simple/{project}` | `pypi_routes::project_without_slash`, `src/http/pypi_routes.rs:72` | no (local 301 only) |
| `GET\|HEAD /npm/artifacts/{ref}/{file}` | `artifact_routes::serve_npm`, `src/http/artifact_routes.rs:24` | yes (`:27`, used for `Range`) |
| `GET\|HEAD /pypi/artifacts/{ref}/{file}` | `artifact_routes::serve_pypi`, `src/http/artifact_routes.rs:41` | yes (`:44`) |
| `GET\|HEAD /npm/{pkg}/-/{file}` and `/npm/@{scope}/{pkg}/-/{file}` | `serve_npm_upstream` `:76` and `serve_npm_upstream_scoped` `:87` | yes |
| `GET /npm/-/{*rest}` | `serve_npm_namespace`, `src/http/artifact_routes.rs:111` | yes |
| `/health/{live,ready,delivery}` | `src/http/health.rs` (`ready` at `:30`) | no |

All artifact routes converge on `artifact_routes::deliver` (`src/http/artifact_routes.rs:140`), which
calls `artifacts::serve_artifact` (`src/artifacts/mod.rs:61`).

**Common choke points**:
- `http::admit` (`src/http/mod.rs:102-112`) is called by every package and artifact handler. It
  handles the permit and storage health but takes no request input. Today it is the one shared
  per-request gate.
- `http::logging::decide` (`src/http/logging.rs:181`) is the outermost middleware
  (`src/http/mod.rs:87-90`). It is the only place that sees the whole `Request`. It sets up a
  task-local `CONTEXT` (`src/http/logging.rs:56-60`, scoped at `:209`), which carries the request id,
  cache status, ecosystem, OSV diagnostic flag and blocklist revision (`RequestContext`,
  `src/http/logging.rs:100-114`).

**Existing auth**: none. No inbound credential, API key, or `Authorization` read exists anywhere in
`src/`. The only `AUTHORIZATION` reference is the default header name for the outbound SIEM
credential (`src/config.rs:368`). Client `Authorization`/`Cookie` headers are never forwarded
upstream (`src/upstream/reqwest_transport.rs:13`). Artifact reference ids are explicitly
"not an authorization token" (`src/artifacts/reference.rs:30`, `src/artifacts/mod.rs:84`).

**Landmines for adding a key read**:
- `.smtc/analyzers/client-data-reaches-delivery-sink.yaml` is a repository-wide structural check. It
  fails on any `headers`/`body`/`from_request*` call whose receiver text matches
  `request|req|parts`. If a middleware reads the key with `request.headers()`, this check fires
  **(inferred from the spec text)**. Reading it from the `HeaderMap` extractor, as the handlers
  already do, would not match. Either way the spec's rule is "nothing a client sends reaches a log
  line" (`src/http/logging.rs:14-18`), so putting a key, user or org in the decision record means
  amending this rule on purpose, not slipping past it.
- `.smtc/analyzers/consumer-identity-extension-read.yaml` passes only at exactly one
  `request.extensions()` read, the `ConnectInfo` read at `src/http/logging.rs:191-200`. Passing a
  resolved identity to handlers through request extensions would change that count **(inferred)**.
- The metadata entry points take `&App`, not `Arc<App>`, so they cannot spawn work
  (`src/npm/mod.rs:463-483`). The artifact transfer runs in a detached `tokio::spawn` task
  (`src/artifacts/download.rs:165-188`), where the task-local `CONTEXT` is not set
  **(inferred: tokio task-locals do not cross `spawn`)**. That means a per-request identity has to be
  passed explicitly into anything the transfer task decides.

## 2. `policy::evaluate`, its callers, and where per-request policy values come from today

`policy::evaluate` (`src/policy/mod.rs`, the fn following the doc block at `:94-104`) is pure, with no
I/O, clock or config (`:1-4`). Its signature is
`(snapshot: Option<&BlocklistSnapshot>, now_utc_micros, cooldown_seconds: u64, candidate: &Candidate, osv_matched: bool) -> Decision`.
The check order is fixed: Unavailable → BlockedPackage → BlockedVersion → BlockedByOsv →
BlockedDigest → timestamp denies → Hold → Allow. This order is pinned by
`check_order_is_unavailable_deny_hold_allow`. `Candidate` and `Decision` live in the same file.

Production code calls `policy::evaluate` **only** from `osv::evaluate` (`src/osv/mod.rs:256-289`;
calls at `:263` and `:282`). `osv::evaluate` has four production callers:

| Caller | Location | snapshot from | cooldown from | OSV mode from |
|---|---|---|---|---|
| npm listing (`npm::resolve`) | `src/npm/mod.rs:345` | `app.blocklist()` read once in `serve` `:62` | `app.config.cooldown_seconds` `:349` | `app.osv` (mode fixed at construction) |
| PyPI listing (`pypi::resolve`) | `src/pypi/mod.rs:313` | `app.blocklist()` in `serve` `:79` | `app.config.cooldown_seconds` `:317` | `app.osv` |
| artifact first and final checks (`artifacts::evaluate`) | `src/artifacts/mod.rs:189-208`, called at `:99` and `:132` | `app.blocklist()` at `:71` and again at `:130` | `app.config.cooldown_seconds` | `app.osv` |
| post-download recheck (`artifacts::download::transfer`) | `src/artifacts/download.rs:339` | `app.blocklist()` at `:337` | `app.config.cooldown_seconds` | `app.osv` |

**Today every policy input is global.** These are the one `ArcSwapOption<BlocklistSnapshot>` on
`App` (`src/lib.rs:89`), `Config::cooldown_seconds` (`src/config.rs:29`), and `Config::osv_mode`,
which is baked into the single `OsvClient` (`src/lib.rs:105`, `src/osv/mod.rs:144`). Nothing is per
request. There is no "exception" (allow-list) or "freeze" concept anywhere in `policy`. The only
outcomes are deny, hold or allow, and OSV can only ever add a deny (`src/policy/mod.rs:128-136`).

Other places that read the global snapshot (only `is_valid_at`, no deny decision):
`npm::reference_for_file` (`src/npm/mod.rs:273`), `pypi::index` (`src/pypi/mod.rs:140`),
`http::admit` (`src/http/mod.rs:106`), `/health/ready` (`src/http/health.rs:36`).

## 3. Blocklist snapshot: load, poll, swap

- **Type**: `BlocklistSnapshot` (`src/policy/blocklist.rs:34-48`) is immutable. Its fields are
  `revision`, `generated_at_micros`, `expires_at_micros`, `raw: Arc<[u8]>`, and per-ecosystem
  `packages`/`versions` tables plus `digests`. `parse_and_validate` (`:72`) is all-or-nothing.
  `is_valid_at` (`:219`), `blocks_package` (`:223`), `blocks_version` (`:227`), `blocks_digest`
  (`:252`). `check_replacement` (`:301`) rejects a rollback, or changed content at the same revision.
- **Publication point**: `App.policy: ArcSwapOption<BlocklistSnapshot>` (`src/lib.rs:89`,
  initialised empty at `:233`). The reader is `App::blocklist()` (`src/lib.rs:115-121`, using
  `load_full`), which also records the revision in the request context. The writer is
  `App::publish_blocklist()` (`src/lib.rs:125-127`, using `store`). `blocklist_revision()` is at
  `:129`. A comment at `src/lib.rs:84-88` says Gate 3 intended a `PolicyHandle` type in
  `policy/blocklist.rs` that never got lifted out.
- **Startup**: `restore_blocklist` (`src/lib.rs:358-388`) re-validates the persisted row from
  `store.load_blocklist()`. Then one synchronous `blocklist_poller::poll_once`
  (`src/lib.rs:247-248`) runs before the listener binds.
- **Poll loop**: `tasks::blocklist_poller::run` (`src/tasks/blocklist_poller.rs:36`) sleeps
  `blocklist_poll_seconds`, then runs `poll_once` (`:114`) inside `catch_unwind`. Each pass does
  these steps in order:
  1. file identity check (dev, inode, mtime, len), plus a 60 s backstop (`:33`)
  2. capped read
  3. byte-identical short-circuit
  4. `parse_and_validate` on `spawn_blocking` (`:180`)
  5. `check_replacement` (`:190`)
  6. `store.commit_blocklist` (`:205`)
  7. **only then** `app.publish_blocklist` (`:222`)
  This is the commit-then-publish invariant. A failed commit leaves the old snapshot in force.
- **Persistence**: there is one blocklist row (`blocklist` table, `CHECK (id = 1)`,
  `src/store/schema.rs` DDL). The store methods are `commit_blocklist`/`load_blocklist`
  (`src/store/mod.rs:422`, `:429`). The schema has room for exactly **one** global snapshot. A
  per-user or per-org layered policy needs new storage or an in-memory map **(inferred)**.
- **Expiry is fail-closed**: an expired or missing snapshot means `PolicyUnavailable` (503) on every
  package route (`src/npm/mod.rs:62-65`, `src/pypi/mod.rs:79-82`, `src/artifacts/mod.rs:71-74`), and
  `/health/ready` goes unhealthy.

## 4. OSV client and `osv_mode`

- `OsvMode {Enforce, Diagnostic, Off}` is at `src/osv/mod.rs:66-74`. Its doc says it is "set once at
  construction and never mutated — there is no reload/hot-swap path" (`:63-64`).
- `OsvClient` (`src/osv/mod.rs:134-145`) holds `tx`, a shared `Arc<OsvCache>`, `request_timeout`, and
  `mode`. It is built in `App::start` through `OsvClient::new`/`spawn_with` (`src/lib.rs:205-220`,
  passing `deps.config.osv_mode`). The batcher task (`osv::batcher::run`, `src/osv/batcher.rs:74`)
  is pushed into the drain-token task set (`src/lib.rs:221`).
- `OsvCache` (`src/osv/mod.rs:85-93`) is keyed by `(Ecosystem, name, version)` and holds only the
  matched/unmatched **fact**, not the mode. It can therefore be shared across users unchanged
  **(inferred)**.
- The mode is applied only in `osv::evaluate` (`src/osv/mod.rs:256-289`):
  - `Off` returns the blind decision without asking (`:267-269`).
  - `Diagnostic` asks, calls `record_osv_diagnostic_match` (`:275-280`), and returns the blind
    decision.
  - `Enforce` re-runs `policy::evaluate` with the match (`:282`).
- **Where a per-request mode would enter**: `osv::evaluate` reads `osv.mode` from the client
  (`:267`, `:275`). A per-request mode means adding a `mode` parameter to `osv::evaluate`, or taking
  it from a policy object, at all four call sites in item 2 **(inferred)**. The client and its cache
  can stay single.
- The diagnostic flag is a task-local (`src/http/logging.rs:171-173`). It is lost in the detached
  download task, and it is never set on a warm rendered-cache hit, because that path never calls
  `evaluate` **(inferred)**.

## 5. Config loading, validation and live reload

- `Config` (`src/config.rs:24-89`) is a plain `Clone + Debug` struct. `RawConfig` uses
  `#[serde(deny_unknown_fields)]` (`src/config.rs:129-162`, attribute at `:128`).
  - `Config::from_toml_str` (`:215`) runs in three stages: TOML parse, `check_keys` (`:501`) against
    `REQUIRED_KEYS` (`:178`) and `OPTIONAL_KEYS` (`:197`), then `RawConfig::validate` (`:234`).
  - `Config::load` (`:224`) reads the file.
  - `osv_mode` is parsed at `:464-475`.
  - A new key must be added to both `RawConfig` and one of the key lists.
    `tests/config_validation.rs` enforces the list by deleting each sample key in turn
    (`src/config.rs:172-177`).
- **`check-config`**: `main::check_config` (`src/main.rs:87-110`) runs `Config::load`, then
  `probation::check_delivery` (`src/lib.rs:338-350`, which builds and drops the delivery sinks). The
  CLI subcommands are `serve`, `check-config`, and `check-blocklist` (`enum Command`, `src/main.rs:29-53`).
- **Live reload: none.**
  - `main::serve` loads the config once (`src/main.rs:147`) and moves it into `AppDeps` and then
    into `App.config` (`src/lib.rs:75`). `App.config` is a plain field, not an `ArcSwap`.
  - Signals are only SIGINT and SIGTERM, both for shutdown (`ShutdownSignals`, `src/main.rs:190-208`). There is no
    SIGHUP handler.
  - Startup-only values are baked into constructed objects and would not follow a config swap
    **(inferred)**:
    - `Limits::new` uses the `max_*` settings (`src/lib.rs:191`).
    - `MemoryCaches::new` uses `memory_cache_max_bytes` (`:174`).
    - `ContentStore::new` uses `cache_max_bytes` (`:189`).
    - The OSV client uses TTL, timeout and mode (`:201-220`).
    - The listener and TLS use `listen`, `tls_*` (bind at `:268`, TLS config just above it).
    - Delivery sinks use `log_*`, `siem_*` (`:200`).
    - The upstream limiter uses `max_upstream_requests` (`:226-229`).
  - Values read straight from `app.config` on every use would pick up a swapped `Arc<Config>` if
    `App.config` became one **(inferred)**: `cooldown_seconds`, `metadata_ttl_seconds`,
    `metadata_max_age_seconds`, `max_references_per_project`, `max_metadata_bytes`,
    `blocklist_poll_seconds` (read once per loop entry, `src/tasks/blocklist_poller.rs:37`), and
    `log_consumer_identification` (read per request at `src/http/logging.rs:191`, but the server's
    connect-info choice is fixed at bind, `src/lib.rs:290`).
  - The only live-swapped state in the process is the blocklist `ArcSwapOption` (item 3).

## 6. Response caches that assume one policy for all clients

`MemoryCaches` (`src/store/cache.rs:209`) holds four caches. Only one bakes in the policy:

- **`rendered: ShardedCache<RenderKey, RenderedResponse>` assumes one policy for everyone.**
  - `RenderKey` is `{project: ProjectKey, representation}` (`src/store/cache.rs:69-72`) and has no
    identity or policy component.
  - `RenderedResponse` (`:77-89`) stores the **already filtered** body, meaning blocked, held and
    OSV-denied versions are removed and dist-tags re-pointed (`src/npm/mod.rs:356-373`).
  - `is_reusable` (`src/store/cache.rs:93-107`) checks project generation, **`blocklist_revision`**,
    digest generation and the deadlines. The global blocklist revision is the only policy input it
    knows. Cooldown, OSV mode and OSV answers are not in the key.
  - The warm path returns it before any `evaluate` (npm `src/npm/mod.rs:78-96`, insert `:103-117`;
    PyPI `src/pypi/mod.rs:92-109`, insert `:116-130`).
  - The deadline includes the next held version's release time and the global blocklist expiry
    (`src/npm/mod.rs:390-396`). Both are policy-dependent.
  - Under per-user policy this cache would serve user A's filtered listing to user B. It must be
    keyed by an effective-policy identity (for example org plus policy revision), or bypassed in
    managed mode **(inferred)**.
- `projects: ShardedCache<ProjectKey, CachedProject>` (`:212`) holds the raw upstream snapshot,
  first-seen times, pins and advertised references. It is policy-independent and safe to share
  **(inferred)**.
- `references` (`:219`) and `absent` (`:221`) are policy-independent **(inferred)**.
- The OSV `OsvCache` is a fact cache, so it is safe (item 4).
- **Single-flight on artifact transfer**: `DownloadCoordinator.transfers` is keyed by `ReferenceId`
  (`src/artifacts/download.rs:122-126`). The leader's spawned task runs the post-download policy
  check (`:337-361`), and its `DownloadError::Refused(decision)` is handed to **every** waiter
  (`:180-186`). So one user's deny would refuse a concurrent download for another user. On a deny it
  also calls `bump_digest_generation` (`:358`, `:410`), which invalidates the rendered listing for
  all users **(inferred)**. The metadata refresh single-flight (`src/npm/mod.rs:488-515`) carries
  only the raw `CachedProject` and is policy-independent.
- `pypi::index` (`src/pypi/mod.rs:138-162`) lists every project this instance has ever fetched, with
  no filtering. It is shared across all clients today **(inferred: an org-visibility question for
  managed mode)**.
- Every response carries `Cache-Control: no-store` (`no_store`, `src/http/mod.rs:142`), so downstream HTTP
  caches are not a factor.

## 7. Decision log and delivery records

- `delivery::Record` (`src/delivery/mod.rs:148-153`) is `RequestDecided(Decision)` or
  `RequestSummary(Summary)`.
- `delivery::Decision` (`src/delivery/mod.rs:161-180`) has these fields: `timestamp`, `request_id`,
  `method`, `ecosystem`, `package`, `version`, `status`, `result`, `reason`, `blocklist_revision`,
  `cache`, `duration_micros`, `bytes`, plus the optional `consumer: Option<IpAddr>` (`:179`, only
  with `log_consumer_identification`).
- **Built in one place**: `http::logging::build_decision` (`src/http/logging.rs:317-348`), called
  from `decide` (`:262-278`). It is emitted to stdout through `tracing::info!` (`:280-297`) and then
  `app.delivery.offer(Record::RequestDecided(..))` (`:299`). `Sinks` is at
  `src/delivery/mod.rs:288`, `offer` at `:316`, and `build` at `:412`.
- **Where key, user or org would go**:
  1. Add fields to `RequestContext` (`src/http/logging.rs:100-114`). Whatever resolves the key would
     set them, the same way `record_blocklist_revision` (`:155`) and `record_ecosystem` (`:143`) do.
  2. Add them to `delivery::Decision`.
  3. Pass them through `build_decision`.
  **(inferred: this follows the existing `consumer` pattern.)**
- **Compile-time size budget**:
  - `BYTES_PER_RECORD` (`src/delivery/mod.rs:61`) is derived field by field (`:49-60`).
  - `const _: () = assert!(...)` (`:68-70`) checks that sum.
  - `assert!(size_of::<Decision>() <= 256)` (`:85`) caps the struct; today it is 240 bytes, so 16
    bytes are spare.
  - New `String` fields must be bounded (as `loggable` does) and `BYTES_PER_RECORD` re-derived by
    hand (`:72-84`). This is the same landmine `docs/backlog.md` B4 names.
  - The analyzer spec in item 1 is the other guard.
- `blocklist_revision` in the record is the revision of the single global snapshot
  (`src/http/logging.rs:246-273`). With layered per-user policy, "which policy decided" needs a new
  field or a changed meaning **(inferred)**.

## 8. Background tasks framework

- `tasks::spawn(app: Arc<App>, shutdown: CancellationToken, watcher, delivery: Vec<JoinHandle<()>>) -> Tasks`
  is at `src/tasks/mod.rs:29-46`. It `tokio::spawn`s `blocklist_poller::run` and `maintenance::run`
  (`src/tasks/maintenance.rs:28`), then adopts the delivery and OSV handles. `Tasks::join`
  (`:58-64`) awaits them all.
- There are **two tokens** (`drain` at `src/lib.rs:199`, `shutdown` at `:275`):
  - `shutdown` stops the loops.
  - `drain` is cancelled later, so the delivery sinks and the OSV batcher outlive in-flight requests.
- Shutdown order is in `Running::shutdown_within` (`src/lib.rs:439-462`): cancel `shutdown` (`:440`)
  → join the server → cancel `drain` (`:452`) → `tasks.join()` (`:454`).
- The loop shape to copy is `blocklist_poller::run`: a `select!` on `shutdown.cancelled()` against
  `sleep(interval)`, the pass wrapped in `catch_unwind`, and a retry flag
  (`src/tasks/blocklist_poller.rs:36-66`). A policy-sync task would be a third entry in the
  `tasks::spawn` vector. It would keep commit-then-publish if it persists a cached policy
  **(inferred)**.
- The pattern for an outbound HTTP client inside a task is `delivery/siem.rs` (`run` at `:47`) and
  `osv/batcher.rs` (`:74`). Both use an injected `reqwest::Client` (OSV through
  `AppDeps.osv_client`/`osv_base_url`, `src/lib.rs:63`, `:70`).

## 9. Storage and workspace layout

- **Single crate, not a workspace.** `Cargo.toml` defines `[lib] name = "probation"`
  (`:16-18`), one `[[bin]] probation` (`:20-22`), four `harness = false` benches (`:29-46`), and one
  feature, `test-support` (`:54`). Edition 2024, rust-version 1.96.0.
- **Database**: Turso (`turso = "0.7.2"`, `Cargo.toml`; `TURSO_CRATE_VERSION`,
  `src/store/schema.rs:31`).
  - It is one local file, `<data_dir>/state/firewall.db` (`src/store/startup.rs:30-31`), opened by
    `open_and_recover` (`:43`), in WAL mode with synchronous FULL.
  - Schema version 5 (`src/store/schema.rs:26`) has these tables: `schema_meta`, `blocklist` (single
    row), `projects`, `artifact_references`, `content`.
  - A version mismatch is refused, except for the 4→5 in-place upgrade (`src/store/schema.rs:151`).
  - Adding tables means bumping `SCHEMA_VERSION` and handling the upgrade from 5 **(inferred from
    the doc at `:23-25`)**.
- **Store actor**: one task and one connection.
  - `store::spawn` (`src/store/mod.rs:628`) has two bounded queues (critical and maintenance,
    `QUEUE_DEPTH = 64`, `:44`, channels at `:633-634`).
  - `StoreHandle` (`:194`) is the only way in.
  - The SQL text lives as constants at `:46-133`.
- **Other files**:
  - Verified artifact bytes go in `ContentStore` under `data_dir` (`src/lib.rs:189`).
  - The blocklist JSON file is at the `blocklist_file` path (polled).
  - The TOML config file is read once.
  - TLS cert and key PEMs, when set.
  - The NDJSON decision log is written when `log_file_path` is set.

---

## Evidence and limitations

- Structural core:
  - `smtc map` returned 89 files (ranked, truncated to the top 14).
  - `smtc analyze architecture` found 10 hotspots, all `in_cycle: true`. The top ones are
    `probation`, `probation::store::cache`, `probation::delivery`, `probation::store`,
    `probation::artifacts::download`, `probation::http::limits` and `probation::osv`.
  - `smtc inspect file src/lib.rs` returned 36 declarations.
  - Every result reported `dirty_build: true`.
- Caller enumeration for `osv::evaluate`/`policy::evaluate` is **text search** (`smtc file grep`),
  not a call graph. `smtc review slice --function osv::evaluate` answered "function not found in call
  graph". The callers in item 2 are therefore a manual-tier inventory, complete for direct textual
  calls in `src/`.
- File content comes from `smtc file read`, with line anchors from `smtc file grep` (one-based). Line
  ranges taken from read offsets are accurate to within the stated span.
