# Repository grounding — Gate 2, rated-load-guard

Source: sf-repo-view, 2026-09-23. Verdict: ORIENTED.

Repository root: `/home/john/go/src/github.com/postfix/osprey`. Branch `package-firewall-mvp`
at `734d22d`. Every claim below names the file, and every declaration or constant names
the line. Paths are repository-relative.

---

## 1. Repository shape

**Crate layout** — `Cargo.toml`:

- `[lib] name = "package_firewall", path = "src/lib.rs"` (`Cargo.toml:10-12`)
- `[[bin]] name = "package-firewall", path = "src/main.rs"` (`Cargo.toml:14-16`)
- edition 2024, rust-version 1.96.0 (`Cargo.toml:4-5`); `rust-toolchain.toml` pins the toolchain.
- One feature: `test-support` (`Cargo.toml:41`), default-off, gating test-only setters.

**Module tree** (declared `src/lib.rs:7-20`) and ownership, each from the module's own header doc:

| Module | Owns |
|---|---|
| `artifacts` (`mod.rs`, `content.rs`, `download.rs`, `reference.rs`, `stream.rs`) | Verified artifact delivery; on-disk content cache; the cold fetch/verify path; downstream streaming |
| `clock` (`src/clock.rs:1`) | The injected time source (`Clock` trait) |
| `concurrency` (`mod.rs`, `single_flight.rs`) | One piece of upstream work per key |
| `config` (`src/config.rs:1`) | SPEC §4 configuration file; all rejection rules |
| `delivery` (`mod.rs`, `file.rs`, `siem.rs`) — **`pub(crate)`** (`src/lib.rs:13`) | Where a decision record goes once it exists |
| `http` (`mod.rs`, `artifact_routes.rs`, `error.rs`, `health.rs`, `limits.rs`, `logging.rs`, `npm_routes.rs`, `pypi_routes.rs`) | Router, layer stack, SPEC §11 failure table, the bounds, per-request identity and the decision line |
| `npm` / `pypi` | Per-ecosystem metadata end to end: fetch or reuse a snapshot, judge, render |
| `policy` (`mod.rs`, `blocklist.rs`, `digest.rs`) | The pure rule block of SPEC §5 (no I/O, no clock) and the blocklist snapshot |
| `store` (`mod.rs`, `cache.rs`, `lock.rs`, `rows.rs`, `schema.rs`, `startup.rs`) | One task, one connection, every SQL statement; bounded memory caches; the data-dir lock |
| `tasks` (`mod.rs`, `blocklist_poller.rs`, `maintenance.rs`) | The background loops |
| `upstream` (`mod.rs`, `origins.rs`, `reqwest_transport.rs`, `resolver.rs`) | The one outbound seam, the three fixed origins, DNS admission |

**Entrypoint and request-to-record flow** (module::function names only):

- `main::main` (`src/main.rs:55`) → clap `Command::Serve` → `main::serve` (`src/main.rs:122`) →
  `Config::load` → `App::start` (`src/lib.rs:127`).
- `App::start` calls `delivery::build` (`src/lib.rs:161`) with a **drain token distinct from the
  shutdown token** (`src/lib.rs:158-161`), then `http::router` inside the `axum::serve` task
  (`src/lib.rs:207`).
- `http::router` (`src/http/mod.rs:39`) installs `http::logging::decide` as the **outermost**
  layer (`src/http/mod.rs:70-73`), so router-generated `404`/`405` also get a decision line.
- `http::logging::decide` (`src/http/logging.rs:150`) runs the inner handler, builds a
  `delivery::Decision` (`src/http/logging.rs:207`), emits the stdout line via `tracing::info!`
  (`src/http/logging.rs:224`), then `app.delivery.offer(Record::RequestDecided(decision))`
  (`src/http/logging.rs:243`), then `http::logging::summarise` (`src/http/logging.rs:245`).
- `summarise` (`src/http/logging.rs:357`) → `close_window` (`src/http/logging.rs:415`) →
  `emit` (`src/http/logging.rs:440`) → `Sinks::offer(Record::RequestSummary(..))`
  (`src/http/logging.rs:451`).
- Shutdown: `Running::shutdown` (`src/lib.rs:310`) joins the server, calls
  `http::logging::flush_summary` (`src/lib.rs:321`), cancels `drain` (`src/lib.rs:322`), joins
  tasks, then `http::logging::flush_drop_tail` (`src/lib.rs:326`).
- The shutdown signal is `SIGINT` or `SIGTERM`, via `main::wait_for_shutdown_signal`
  (`src/main.rs:172-178`).

---

## 2. `src/delivery/`

Three files: `src/delivery/mod.rs` (334 lines), `src/delivery/file.rs` (268),
`src/delivery/siem.rs` (215). Everything is `pub(crate)` or `pub(super)` — `src/lib.rs:11-13`
states the feature adds no public Rust surface.

**The decision-record type** — `delivery::Record`, `src/delivery/mod.rs:43`, an enum tagged by
the serde key `event` (`src/delivery/mod.rs:42`):

- `Record::RequestDecided(Decision)` — `Decision` at `src/delivery/mod.rs:54`, 13 fields plus the
  optional `consumer` (`src/delivery/mod.rs:55-72`): `timestamp`, `request_id`, `method`,
  `ecosystem`, `package`, `version`, `status`, `result`, `reason`, `blocklist_revision`, `cache`,
  `duration_micros`, `bytes`, `consumer` (`Option<IpAddr>`, `skip_serializing_if` at
  `src/delivery/mod.rs:71`).
- `Record::RequestSummary(Summary)` — `Summary` at `src/delivery/mod.rs:79`, fields `timestamp`,
  `requests`, `errors`, `bytes`, `mean_duration_micros`, `window_micros`, `dropped_file`,
  `dropped_siem` (`src/delivery/mod.rs:80-87`).

**Public surface of `src/delivery/mod.rs`:**

```rust
pub(crate) fn rfc3339(utc_micros: i64) -> String                                    // :93
pub(crate) struct Drops { pub file: u64, pub siem: u64 }                            // :100
pub(crate) struct Sinks { file: Option<Sink>, siem: Option<Sink> }                  // :122
impl Sinks {
    pub(crate) fn offer(&self, record: Record)                                      // :133
    pub(crate) fn drops(&self) -> Drops                                             // :150
    pub(crate) fn is_empty(&self) -> bool                                           // :171 (test-support caller only)
}
pub(crate) fn build(config: &Config, drain: CancellationToken)
    -> Result<(Sinks, Vec<JoinHandle<()>>), StartupError>                           // :203
fn probe(path: &Path, consumer_identification: bool) -> Result<(), StartupError>    // :293
fn siem_auth(name: &HeaderName) -> Result<Option<(HeaderName, HeaderValue)>, StartupError> // :320
```

Private: `struct Sink { tx: mpsc::Sender<Record>, drops: Arc<AtomicU64> }`
(`src/delivery/mod.rs:107`) with `fn push(&self, record: Record)` (`src/delivery/mod.rs:113`).

**`src/delivery/file.rs`:**

```rust
pub(super) async fn run(
    path: PathBuf, max_bytes: NonZeroU64, rx: mpsc::Receiver<Record>,
    drain: CancellationToken, drops: Arc<AtomicU64>,
)                                                                                   // :31
async fn drain(writer: &mut Writer, rx: &mut mpsc::Receiver<Record>,
               drops: &AtomicU64, deadline: Duration)                               // :62
struct Writer { path, max_bytes, file: Option<File>, written: u64, warned: bool }   // :80
impl Writer {
    fn new(path: PathBuf, max_bytes: NonZeroU64) -> Writer                          // :93
    async fn append(&mut self, record: Record, drops: &AtomicU64)                   // :103
    async fn open(&mut self, drops: &AtomicU64) -> bool                             // :151
    fn warn_if_shared(&mut self, mode: u32)                                         // :190
    async fn roll_over(&mut self)                                                   // :205
}
```

One `#[cfg(test)]` unit test in the file: `tp19_file_drain_deadline_counts_cut_off_records`
(`src/delivery/file.rs:228`).

**`src/delivery/siem.rs`:**

```rust
pub(super) async fn run(
    client: Client, url: Url, auth: Option<(HeaderName, HeaderValue)>,
    rx: mpsc::Receiver<Record>, drain: CancellationToken, drops: Arc<AtomicU64>,
)                                                                                   // :45
async fn send(client: &Client, url: &Url, auth: Option<&(HeaderName, HeaderValue)>,
              batch: &mut Vec<Record>, drops: &AtomicU64)                           // :113
struct Unsent<'a> { count: u64, drops: &'a AtomicU64 }                              // :197
impl Unsent<'_> { fn delivered(&mut self) }                                         // :204
impl Drop for Unsent<'_>                                                            // :209
```

**Queue construction and bound.** `const QUEUE_CAPACITY: usize = 4096;` at
**`src/delivery/mod.rs:37`**. Used twice, once per sink: `mpsc::channel(QUEUE_CAPACITY)` at
`src/delivery/mod.rs:214` (file) and `src/delivery/mod.rs:250` (SIEM). Both are
`tokio::sync::mpsc` bounded channels. The capacity is a compile-time constant; **no
configuration key reaches it.**

**Enqueue-when-full.** `Sink::push`, `src/delivery/mod.rs:113-118`:

```rust
fn push(&self, record: Record) {
    if self.tx.try_send(record).is_err() {
        self.drops.fetch_add(1, Ordering::Relaxed);
    }
}
```

`try_send` never awaits, so full *and* closed both fall into the same counted branch.
`Sinks::offer` (`src/delivery/mod.rs:133`) is non-`async`, returns `()`, takes no lock and does
no I/O — the module header (`src/delivery/mod.rs:7-9`) states this shape is deliberate so that
delivery cannot slow or fail a request without changing a signature. `offer` clones the record
only when both sinks are enabled (`src/delivery/mod.rs:134-142`).

**Where drop counters are incremented:**

| Site | Reason |
|---|---|
| `src/delivery/mod.rs:115` | queue full or closed at `offer` time |
| `src/delivery/file.rs:75` | file drain deadline cut off `rx.len() + 1` records |
| `src/delivery/file.rs:105` | record would not serialize |
| `src/delivery/file.rs:142` | write/flush error |
| `src/delivery/file.rs:181` | file could not be opened |
| `src/delivery/siem.rs:97` | SIEM drain deadline cut off `batch.len() + rx.len()` |
| `src/delivery/siem.rs:212` | `Unsent::drop` — a batch that left `batch` and was never delivered; the **whole batch** is counted, up to 256 records (rationale `src/delivery/siem.rs:107-112`) |

**Where they are read.** Only `Sinks::drops()` (`src/delivery/mod.rs:150`), which is
**read-and-reset** via `swap(0, Ordering::Relaxed)` (`src/delivery/mod.rs:155`, `:159`). Two
callers:

- `http::logging::close_window` (`src/http/logging.rs:421`), inside the `COUNTERS` mutex critical
  section so one window's counts cannot be split across two.
- `http::logging::flush_drop_tail` (`src/http/logging.rs:400`), after the sinks have joined —
  that last line reaches the console only, as a `tracing::warn!`
  (`src/http/logging.rs:402-407`).

The doc at `src/delivery/mod.rs:148-149` warns that a second concurrent caller would silently
steal a window's counts.

**Other constants in the module:**

| Constant | Value | Line |
|---|---|---|
| `QUEUE_CAPACITY` | `4096` | `src/delivery/mod.rs:37` |
| `SIEM_AUTH_ENV` | `"OSPREY_SIEM_AUTH"` | `src/delivery/mod.rs:179` |
| `SIEM_AUTH_REJECTED` | fixed `&'static str` | `src/delivery/mod.rs:184` |
| `SIEM_REQUEST_TIMEOUT` | 3 s | `src/delivery/mod.rs:191` |
| `SIEM_CONNECT_TIMEOUT` | 1 s | `src/delivery/mod.rs:192` |
| `LOG_FILE_REJECTED` | fixed `&'static str` | `src/delivery/mod.rs:280` |
| `DRAIN_DEADLINE` (file) | 5 s | `src/delivery/file.rs:24` |
| `BATCH_RECORDS` | `256` | `src/delivery/siem.rs:24` |
| `BATCH_INTERVAL` | 2 s | `src/delivery/siem.rs:27` |
| `BACKOFF` | `[100 ms, 500 ms, 2 s]` (retry count is its length: three) | `src/delivery/siem.rs:30` |
| `DRAIN_DEADLINE` (SIEM) | 5 s | `src/delivery/siem.rs:38` |

`build` (`src/delivery/mod.rs:203`) opens no file, constructs no HTTP client and spawns nothing
when neither `log_file_path` nor `siem_url` is set (`src/delivery/mod.rs:196-198`,
`:209-263`). The SIEM client disables redirects (`src/delivery/mod.rs:237`), sets both timeouts
(`:239-240`) and ignores proxy environment variables (`:243`).

---

## 3. Configuration surface

**One file defines the config structs:** `src/config.rs`. Two structs — the validated `Config`
(`src/config.rs:22`) and the as-written `RawConfig` (`src/config.rs:84`, with
`#[serde(deny_unknown_fields)]` at `src/config.rs:83`). There is **no `Default` impl** on either.

**Complete key list:**

| Key | `RawConfig` line | `Config` type (line) | Default / rule |
|---|---|---|---|
| `listen` | `:85` | `SocketAddr` (`:23`) | required |
| `public_url` | `:86` | `Url` (`:24`) | required; https, no path/query/fragment (`:183-200`) |
| `data_dir` | `:87` | `PathBuf` (`:25`) | required; absolute (`:202`) |
| `blocklist_file` | `:88` | `PathBuf` (`:26`) | required; absolute (`:205`) |
| `cooldown_seconds` | `:89` | `u64` (`:27`) | required; zero is meaningful |
| `metadata_ttl_seconds` | `:90` | `u64` (`:28`) | required; zero is meaningful |
| `metadata_max_age_seconds` | `:92` | `u64` (`:36`) | `86_400` via serde default fn (`:91`, `:116-118`, const `:74`); must not be below `metadata_ttl_seconds` unless 0 (`:216-226`) |
| `blocklist_poll_seconds` | `:93` | `NonZeroU64` (`:37`) | required, non-zero |
| `cache_max_bytes` | `:94` | `NonZeroU64` (`:38`) | required, non-zero |
| `memory_cache_max_bytes` | `:95` | `NonZeroU64` (`:39`) | required, non-zero |
| `max_artifact_bytes` | `:96` | `NonZeroU64` (`:40`) | required; must not exceed `cache_max_bytes` (`:230`) |
| `max_metadata_bytes` | `:97` | `NonZeroU64` (`:41`) | required, non-zero |
| `max_blocklist_bytes` | `:98` | `NonZeroU64` (`:42`) | required, non-zero |
| `max_upstream_requests` | `:99` | `NonZeroU32` (`:43`) | required, non-zero |
| `max_artifact_downloads` | `:100` | `NonZeroU32` (`:44`) | required, non-zero |
| `max_active_requests` | `:101` | `NonZeroU32` (`:45`) | required, non-zero |
| `max_references_per_project` | `:103` | `NonZeroU32` (`:46`) | `20_000` via serde default fn (`:102`, `:112-114`, const `:69`) |
| `log_file_path` | `:104` | `Option<PathBuf>` (`:49`) | `None` — absent means off |
| `log_file_max_bytes` | `:105` | `NonZeroU64` (`:52`) | 100 MiB const `DEFAULT_LOG_FILE_MAX_BYTES` (`:78`), applied `:245-250`; refused without `log_file_path` (`:239-244`) |
| `siem_url` | `:106` | `Option<Url>` (`:55`) | `None`; https unless loopback (`:266-271`) |
| `siem_auth_header` | `:107` | `HeaderName` (`:59`) | `header::AUTHORIZATION` (`:283`); refused without `siem_url` (`:254-259`) |
| `log_consumer_identification` | `:109` | `bool` (`:63`) | `false` via `#[serde(default)]` (`:108`); refused without a sink (`:290-300`) |

**How defaults are expressed.** Three mechanisms, no `Default` impl:

1. `#[serde(default = "fn")]` on `RawConfig` for `metadata_max_age_seconds` and
   `max_references_per_project` (`src/config.rs:91`, `:102`), each returning a module-level
   `const` (`src/config.rs:69`, `:74`).
2. `#[serde(default)]` for the `bool` (`src/config.rs:108`).
3. Applied inside `RawConfig::validate` for `Option`-shaped raws: `log_file_max_bytes` →
   `DEFAULT_LOG_FILE_MAX_BYTES` (`src/config.rs:249`), `siem_auth_header` →
   `header::AUTHORIZATION` (`src/config.rs:283`).

Conversion helpers: `nonzero_u64` (`src/config.rs:376`), `nonzero_u32` (`src/config.rs:380`),
`invalid` (`src/config.rs:372`). Error type `ConfigError` (`src/config.rs:385`) with variants
`Read`, `Syntax`, `UnknownKey`, `MissingKey`, `Invalid`.

**How `config.sample.toml` relates to the struct.** Three linkages, all enforced:

- `REQUIRED_KEYS` (`src/config.rs:126-142`, 15 entries) and `OPTIONAL_KEYS`
  (`src/config.rs:145-153`, 7 entries) are a second, hand-maintained copy of the key set,
  checked by `check_keys` (`src/config.rs:357`) *before* serde runs, so a missing key and an
  unknown key report as themselves rather than as "invalid TOML". The doc at
  `src/config.rs:123-125` states `tests/config_validation.rs` deletes each key of the shipped
  sample in turn, so the list cannot silently drift from `RawConfig`.
- `src/http/limits.rs:111` loads `config.sample.toml` directly in a unit test.
- `tests/common/mod.rs:36` `sample_config()` is the base configuration for the whole integration
  suite. The sample is load-bearing, not documentation.

**Sample values** (`config.sample.toml`):

| Key | Value | Line |
|---|---|---|
| `listen` | `"127.0.0.1:8080"` | `:5` |
| `cooldown_seconds` | `86400` | `:15` |
| `metadata_ttl_seconds` | `300` | `:16` |
| `metadata_max_age_seconds` | `86400` | `:24` |
| `blocklist_poll_seconds` | `5` | `:25` |
| `cache_max_bytes` | `107374182400` (100 GiB, incl. temporary downloads) | `:27` |
| `memory_cache_max_bytes` | `268435456` (256 MiB) | `:28` |
| `max_artifact_bytes` | `5368709120` (5 GiB) | `:29` |
| `max_metadata_bytes` | `67108864` (64 MiB) | `:30` |
| `max_blocklist_bytes` | `134217728` (128 MiB) | `:31` |
| `max_upstream_requests` | `32` | `:32` |
| `max_artifact_downloads` | `8` | `:33` |
| `max_active_requests` | `1024` | `:34` |
| `max_references_per_project` | `20000` | `:35` |

All five delivery keys are present in the sample but **commented out**:
`log_file_path` (`config.sample.toml:44`), `log_file_max_bytes` (`:48`), `siem_url` (`:54`),
`siem_auth_header` (`:59`), `log_consumer_identification` (`:74`).

**Naming conventions.**

- **Memory/byte budgets** end in `_bytes` and are `NonZeroU64`: `cache_max_bytes`,
  `memory_cache_max_bytes`, `max_artifact_bytes`, `max_metadata_bytes`, `max_blocklist_bytes`,
  `log_file_max_bytes`.
- **Count / concurrency keys** are `max_<thing>` with no suffix and are `NonZeroU32`:
  `max_upstream_requests`, `max_artifact_downloads`, `max_active_requests`,
  `max_references_per_project`.
- **Durations** end in `_seconds`, `u64` where zero is meaningful and `NonZeroU64` where it is
  not (rationale `src/config.rs:16-20`).
- **Delivery keys** carry a `log_*` or `siem_*` prefix.

A new count-shaped key for a load guard would therefore be `max_*` + `NonZeroU32`; a new
rate-shaped key has no precedent in this file — nothing existing is expressed per unit time
other than the `*_seconds` intervals.

---

## 4. Health / HTTP surface

**Every route**, all registered in `http::router` (`src/http/mod.rs:39-75`), explicitly with no
catch-all:

| Route | Methods | Handler | Line |
|---|---|---|---|
| `/health/live` | GET | `health::live` | `src/http/mod.rs:41` |
| `/health/ready` | GET | `health::ready` | `src/http/mod.rs:42` |
| `/npm/-/ping` | GET | `npm_routes::ping` | `src/http/mod.rs:43` |
| `/npm/-` | GET | `unsupported_npm_api` → 404 | `src/http/mod.rs:44` |
| `/npm/-/{*rest}` | GET | `unsupported_npm_api` → 404 | `src/http/mod.rs:45` |
| `/npm/{package}` | GET | `npm_routes::package` | `src/http/mod.rs:46` |
| `/npm/{package}/{version_or_tag}` | GET | `npm_routes::package_version` | `src/http/mod.rs:47-50` |
| `/pypi/simple/` | GET | `pypi_routes::index` | `src/http/mod.rs:51` |
| `/pypi/simple/{project}/` | GET | `pypi_routes::project` | `src/http/mod.rs:52` |
| `/pypi/simple/{project}` | GET | `pypi_routes::project_without_slash` | `src/http/mod.rs:53-56` |
| `/npm/artifacts/{reference_id}/{filename}` | GET, HEAD | `artifact_routes::serve_npm` | `src/http/mod.rs:57-60` |
| `/pypi/artifacts/{reference_id}/{filename}` | GET, HEAD | `artifact_routes::serve_pypi` | `src/http/mod.rs:61-64` |
| fallback (any other path) | any | `unknown_route` → 404 | `src/http/mod.rs:65` |
| method-not-allowed fallback | — | `unsupported_method` → 405 | `src/http/mod.rs:66` |

Layer stack, inner to outer: `middleware::map_response(no_store)` (`src/http/mod.rs:67`, adds
`Cache-Control: no-store` to every response including errors, `src/http/mod.rs:94-99`), then
`middleware::from_fn_with_state(.., logging::decide)` as the outermost layer
(`src/http/mod.rs:70-73`).

**Which module registers them:** `src/http/mod.rs`, function `router`
(`src/http/mod.rs:39`), called once from `App::start` (`src/lib.rs:207`).

**What the health routes return today** — `src/http/health.rs`, 39 lines total:

- `pub async fn live() -> StatusCode` (`src/http/health.rs:12`) — returns `StatusCode::OK`
  unconditionally (`src/http/health.rs:13`). **Bare status code; no response body type.**
- `pub async fn ready(State(app): State<Arc<App>>) -> StatusCode` (`src/http/health.rs:30`) —
  `503` when `!app.store().is_healthy()` (`src/http/health.rs:32-34`), else `200` when a
  blocklist snapshot exists and `snapshot.is_valid_at(now)` (`src/http/health.rs:36`), else `503`
  (`src/http/health.rs:37`). **Bare status code; no response body type.**

Both still receive `Cache-Control: no-store` from the `no_store` layer
(`src/http/mod.rs:94`). Readiness reads the clock via `app.clock.now_utc_micros()`
(`src/http/health.rs:31`) rather than a poller.

**Metrics / counter surface: none exists.**

- No metrics crate: searched `Cargo.lock` for `metrics`, `prometheus`, `opentelemetry`, `statsd`
  — zero matches.
- No `/metrics` route: searched all of `src/`, `tests/`, `benches/` for `"/metrics"`,
  `prometheus`, `opentelemetry`, `metrics::`, `metric_` — zero matches.
- The only occurrence of the word "metrics" anywhere in `src/` is a SPEC quote in a doc comment
  at `src/http/logging.rs:334`: *"Emit counts and timing summaries periodically to stdout; no
  separate metrics service is required for the MVP."*

**What exists instead** — the periodic summary in `src/http/logging.rs`:

- `static SUMMARY_MILLIS: AtomicU64 = AtomicU64::new(60_000)` (`src/http/logging.rs:54`) — the
  window, 60 s.
- `struct Counters { requests, errors, bytes, micros, opened }` (`src/http/logging.rs:339`)
  behind `static COUNTERS: LazyLock<Mutex<Counters>>` (`src/http/logging.rs:347`) — a single
  process-global mutex, poison-recovering (`src/http/logging.rs:363`, `:385`).
- The window is closed **by the request that notices it has run out**
  (`src/http/logging.rs:336-338`, `:369-377`) — there is no background timer task to start,
  stop or leak. A window with no request in it is never written.
- `close_window` (`src/http/logging.rs:415`) is the one place a summary reads the time, and
  resets all five counters (`src/http/logging.rs:432-436`).
- `#[cfg(feature = "test-support")] pub fn set_summary_window(window: Duration)`
  (`src/http/logging.rs:461`) is the only way to shorten the window; rationale at
  `src/http/logging.rs:454-459`.
- Per-request identity: `request_id()` (`src/http/logging.rs:118`), `record_cache`
  (`src/http/logging.rs:126`), `record_ecosystem` (`src/http/logging.rs:136`), backed by a
  `tokio::task_local!` `CONTEXT` (`src/http/logging.rs:56-60`).
- Log-injection bounds: `MAX_LOGGED_TARGET = 256` (`src/http/logging.rs:51`) and `loggable`
  (`src/http/logging.rs:322`); three `#[cfg(test)]` unit tests at
  `src/http/logging.rs:469`, `:480`, `:488`.

**Existing bounds most relevant to a load guard** — `src/http/limits.rs` (139 lines):

```rust
pub const WRITE_IDLE: Duration = Duration::from_secs(30);            // :21
pub const RESPONSE_LIFETIME: Duration = Duration::from_secs(15 * 60);// :24
pub struct Limits { downloads, active, active_permits, write_idle_millis, lifetime_millis } // :26
impl Limits {
    pub fn new(config: &Config) -> Limits                            // :35
    pub fn active_permit(&self) -> Option<OwnedSemaphorePermit>      // :53  try_acquire_owned; None = 503, never a wait
    pub fn active_available(&self) -> usize                          // :59
    pub fn max_active(&self) -> usize                                // :63
    pub fn download_permit(&self) -> Option<OwnedSemaphorePermit>    // :71
    pub fn download_available(&self) -> usize                        // :75
    pub fn write_idle(&self) -> Duration                             // :79
    pub fn response_lifetime(&self) -> Duration                      // :83
    #[cfg(feature = "test-support")]
    pub fn set_response_timeouts(&self, write_idle: Duration, lifetime: Duration) // :98
}
```

`Limits` is constructed once in `App::start` (`src/lib.rs:156`) and held on `App`
(`src/lib.rs:79`). Both semaphores are sized from config: `max_artifact_downloads`
(`src/http/limits.rs:38`) and `max_active_requests` (`src/http/limits.rs:36`, `:39`). The module
header (`src/http/limits.rs:1-9`) states the governing SPEC §10 rule: "Use semaphores and
bounded queues; reject overload instead of allowing unbounded waiters or tasks." Two
`#[cfg(test)]` unit tests at `src/http/limits.rs:117` and `:126`.

---

## 5. Test and benchmark harness

**`tests/`** — 19 integration-test binaries plus one shared helper module:

| File | Lines |
|---|---|
| `tests/artifacts_concurrency.rs` | 1008 |
| `tests/artifacts_verification.rs` | 614 |
| `tests/blocklist_reload.rs` | 479 |
| `tests/blocklist_revocation.rs` | 629 |
| `tests/blocklist_snapshot.rs` | 242 |
| `tests/config_validation.rs` | 797 |
| `tests/decision_log_delivery.rs` | 1299 |
| `tests/e2e_npm.rs` | 844 |
| `tests/e2e_pip.rs` | 605 |
| `tests/http_contract.rs` | 1156 |
| `tests/npm_metadata.rs` | 2572 |
| `tests/origin_guard.rs` | 1044 |
| `tests/persistence_content.rs` | 327 |
| `tests/persistence_projects.rs` | 590 |
| `tests/persistence_recovery.rs` | 377 |
| `tests/pypi_metadata.rs` | 2597 |
| `tests/slice11_adversarial_singleflight.rs` | 746 |
| `tests/tracer.rs` | 69 |
| `tests/warm_artifact_budget.rs` | 265 |
| **total** | **16260** |

`tests/common/mod.rs` (~1296 lines) is the shared harness, pulled in by each binary with
`mod common;`; because it lives in a subdirectory Cargo does not build it as its own test
target. Its declarations include:

| Item | Line |
|---|---|
| `pub fn sample_config() -> Config` | `tests/common/mod.rs:36` |
| `pub struct TestClock` | `tests/common/mod.rs:49` (impl `:59`, `impl Clock` `:101`) |
| `pub fn parse_rfc3339(text: &str) -> i64` | `tests/common/mod.rs:116` |
| `pub struct TestServer` | `tests/common/mod.rs:124` |
| `TestServer::start()` | `tests/common/mod.rs:135` |
| `TestServer::start_with(config, clock)` | `tests/common/mod.rs:146` |
| `TestServer::start_with_upstream(config, clock, transport, origins)` | `tests/common/mod.rs:153` |
| `TestServer::start_in(data_dir, config, clock)` | `tests/common/mod.rs:172` |
| `pub fn downstream_client()` | `tests/common/mod.rs:365` |
| `pub async fn wait_until(..)` | `tests/common/mod.rs:377` |
| `pub struct SlowReader` | `tests/common/mod.rs:395` |
| `pub enum FakeAnswer` | `tests/common/mod.rs:483` |
| `pub struct Gate` | `tests/common/mod.rs:549` |
| `pub struct FakeRegistry` (impl `Transport` `:662`) | `tests/common/mod.rs:584` |
| `pub fn fake_origins()` / `fake_upstream()` | `tests/common/mod.rs:833` / `:841` |
| `pub struct WiremockUpstream` | `tests/common/mod.rs:900` |
| `pub fn config_with_open_blocklist(dir: &Path)` | `tests/common/mod.rs:931` |
| `pub mod logs` (stdout capture) | `tests/common/mod.rs:989` |
| `pub fn publish_blocklist(..)` | `tests/common/mod.rs:1116` |
| `pub struct TriggerClock` (impl `Clock` `:1179`) | `tests/common/mod.rs:1134` |

`TestServer::start_with_upstream` is documented as the only seam a test has into the
application — "Nothing else reaches `App::start`" (`tests/common/mod.rs:151-152`), and the
default upstream is a `FakeRegistry` that knows nothing, so a test that says nothing about
upstream reaches no socket at all (`tests/common/mod.rs:143-145`).

Fixtures live under `tests/fixtures/{artifacts,blocklist,config,npm,pypi}` — notably
`tests/fixtures/config/zero_max_active_requests.toml`,
`zero_max_artifact_downloads.toml`, `zero_max_upstream_requests.toml`,
`zero_cache_max_bytes.toml`, `zero_memory_cache_max_bytes.toml`, one per non-zero rule.
18 `#[ignore]` attributes across `tests/*.rs` (the e2e cases).

**`benches/` exists** — three files, each its own `harness = false` `main`, not Criterion:

| File | `main` | Measures |
|---|---|---|
| `benches/warm_metadata.rs` | `:37` | SPEC §12 rows 1-2: warm metadata throughput/latency, warm policy denial latency |
| `benches/artifact_throughput.rs` | `:70` | SPEC §12 rows 3-4: warm-artifact TTFB and throughput vs. an unfiltered local-file baseline |
| `benches/blocklist_swap.rs` | `:42` | SPEC §12 last row: replacement active within two polling intervals at 100,000 entries |

**`Cargo.toml` declarations:**

- `[[bench]]` × 3 — `warm_metadata` (`Cargo.toml:23-25`), `artifact_throughput`
  (`Cargo.toml:27-29`), `blocklist_swap` (`Cargo.toml:31-33`), each `harness = false`. The
  rationale at `Cargo.toml:18-22` states SPEC §12's targets are p95 latencies, throughput ratios
  and a deadline, none of which is a mean with a confidence interval.
- **No `[[test]]` section at all** — every `tests/*.rs` is auto-discovered.
- `[dev-dependencies]` (`Cargo.toml:76-87`) — exactly two entries:
  - `package-firewall = { path = ".", features = ["test-support"] }` (`Cargo.toml:86`) — the
    crate depending on itself, so Cargo feature unification turns `test-support` on for the test
    and bench binaries without a flag on any command.
  - `wiremock = "0.6.5"` (`Cargo.toml:87`).
  - `Cargo.toml:77-82` records that **criterion was deliberately dropped**: it reports means with
    confidence intervals and no percentiles, so it cannot express the targets it was named for.
- No `#[bench]` attribute anywhere in the tree; the nightly bench harness is unused.

**How tests are run.** There is **no CI**: no `.github/` directory, no `justfile`, no
`Makefile`, no `.cargo/config.toml`. `docs/operations.md:862-869` states this explicitly ("There
is no `.cargo/config.toml`, no CI workflow and no `#![deny(warnings)]` anywhere in the tree") and
instructs that whatever CI is later added must use the `-D warnings` form, because several guards
in this service degrade quietly rather than loudly when edited wrongly.

**The exact command CI uses: not determined — no CI configuration exists in the repository.**
What blocked it: there is no `.github/`, no `justfile`, no `Makefile` and no
`.cargo/config.toml` to read, and `docs/operations.md:862` confirms the absence is intentional
rather than an oversight.

The canonical commands are `README.md:71-75`:

```sh
cargo clippy --all-targets -- -D warnings
cargo test                                  # offline; no test reaches a public network
cargo test --test e2e_npm -- --ignored      # drives the real npm client
cargo test --test e2e_pip -- --ignored      # drives the real pip client
cargo bench                                 # the SPEC §12 measurements
```

`docs/operations.md:871-887` records the current baseline: `cargo test` is 276 passed / 0 failed
/ 15 ignored. `cargo test --release --no-fail-fast` gives 275 passed / 1 failed —
`artifacts_concurrency::blocklist_commit_is_not_delayed_by_a_large_project_refresh`, whose 500 ms
margin asserted at `tests/artifacts_concurrency.rs:991` is calibrated to debug-build timing and
cannot be met by optimized code. That failure is expected and is not a regression.

Build prerequisites beyond the pinned toolchain: `cmake`, a C compiler and `perl`
(`README.md:77-79`); the e2e tests additionally need `npm`, and `python3` with `pip`,
`setuptools` and `build` (`README.md:80-82`).

**Stale-doc warning.** `docs/codebase-overview.md:21` asserts "No build or test commands exist
because no manifest or automation exists (verified: no Cargo.toml/Makefile/CI config found)".
That file predates the MVP commit and is wrong about `Cargo.toml`. Do not ground the Gate 2
document on it.

---

## Asserted-fact audit

The Gate 2 packet describes these as nine asserted facts; it lists **eight** bullets. All eight
are audited below, none dropped. Fact 2 and fact 7 carry qualifications; fact 4 is corrected.

**1. `src/delivery/` holds two decision-record sinks (a file sink and a SIEM sink), both bounded
queues that drop rather than block.**
**CONFIRMED `src/delivery/mod.rs:13-14`** (`mod file;` / `mod siem;`). Bounded queues at
`src/delivery/mod.rs:214` and `src/delivery/mod.rs:250` (`mpsc::channel(QUEUE_CAPACITY)`).
Drop-not-block at `src/delivery/mod.rs:113-118` — `try_send`, and any `Err` increments the drop
counter. `Sinks::offer` is non-`async` and returns `()` (`src/delivery/mod.rs:133`).

**2. Every drop is counted and surfaced as the fields `dropped_file` and `dropped_siem` on a
summary record.**
**CONFIRMED `src/delivery/mod.rs:86-87`** (field declarations), populated at
`src/http/logging.rs:429-430` from `Sinks::drops()` (`src/delivery/mod.rs:150`).
**Qualification:** drops that occur *during the drain*, after the final summary has been read,
never reach a `Summary` record — by then the sinks have returned. They are surfaced only as a
`tracing::warn!` console line by `flush_drop_tail` (`src/http/logging.rs:399-408`), stated
deliberately at `src/http/logging.rs:392-398`.

**3. A fixed default queue capacity of 4096 records per sink is defined at approximately
`src/delivery/mod.rs:37`.**
**CONFIRMED `src/delivery/mod.rs:37`** — exactly that line: `const QUEUE_CAPACITY: usize = 4096;`.
Applied per sink at `src/delivery/mod.rs:214` and `:250`. It is a compile-time constant and no
configuration key reaches it.

**4. `tests/decision_log_delivery.rs` is the delivery integration suite and contains helpers
named `TestServer`, `TestClock`, and a `wiremock`-based collector.**
**CORRECTED.** It *is* the delivery integration suite (`tests/decision_log_delivery.rs:1-11`,
1,299 lines, cases TP-1 … TP-20). But `TestServer` and `TestClock` are **not defined in that
file** — they are defined in `tests/common/mod.rs:124` and `tests/common/mod.rs:49` and merely
imported at `tests/decision_log_delivery.rs:23`. The wiremock collector is not a named helper
either: `wiremock::MockServer::start()` is called inline at `tests/decision_log_delivery.rs:622`,
`:808`, `:837`, `:843`, `:908`. The helpers actually **defined in** that file are
`one_batch()` (`tests/decision_log_delivery.rs:807`), `wedged_collector()`
(`tests/decision_log_delivery.rs:1097`) and `silent_collector()`
(`tests/decision_log_delivery.rs:1115`) — the latter two are **raw-TCP** collectors, not
wiremock — plus `drain_tail_dropped_siem()` (`:1074`), `SIEM_AUTH_LOCK` / `AuthEnv`
(`:1142-1144`), `decided()` (`:1195`), `delivered()` (`:1182`), `decided_records()` (`:1175`),
`levelled()` (`:1210`), and `mod stdout` (`:1230`). It also defines
`const DECISION_FIELDS: [&str; 12]` (`:36`) and `const OVERFLOW_REQUESTS: usize = 5_000`
(`:690`), the latter sized explicitly to overflow the 4096-record queue.

**5. `config.sample.toml` declares `max_active_requests = 1024`, `max_upstream_requests = 32`,
`max_artifact_downloads = 8`.**
**CONFIRMED** — `config.sample.toml:34`, `config.sample.toml:32`, `config.sample.toml:33`
respectively.

**6. `src/http/health.rs` serves `/health/ready`, which returns a bare status code with no
response body.**
**CONFIRMED `src/http/health.rs:30`** — `pub async fn ready(State(app): State<Arc<App>>) ->
StatusCode`, returning `SERVICE_UNAVAILABLE` (`:33`, `:37`) or `OK` (`:36`). Registered at
`src/http/mod.rs:42`. Its sibling `live` is the same shape (`src/http/health.rs:12-14`,
registered `src/http/mod.rs:41`). Note: the `no_store` layer (`src/http/mod.rs:94`) still
attaches `Cache-Control: no-store` to both responses.

**7. Configuration keys exist with the names `cache_max_bytes` and `memory_cache_max_bytes`,
expressed as memory budgets.**
**CONFIRMED as to existence `src/config.rs:38` and `src/config.rs:39`** (both `NonZeroU64`; raw
fields `src/config.rs:94-95`). **CORRECTED as to "memory":** `cache_max_bytes` is a **disk**
budget, not a memory budget — `config.sample.toml:27` annotates it "100 GiB, including temporary
downloads", and it is passed to `ContentStore::new` (`src/lib.rs:151-154`), the on-disk content
cache. Only `memory_cache_max_bytes` is a memory budget (`config.sample.toml:28`: "256 MiB cache
budget, not total process RSS"), passed to `MemoryCaches::new` (`src/lib.rs:134-136`).

**8. Configuration keys exist with the `log_*` and `siem_*` prefixes.**
**CONFIRMED** — `log_file_path` (`src/config.rs:49`), `log_file_max_bytes` (`src/config.rs:52`),
`log_consumer_identification` (`src/config.rs:63`), `siem_url` (`src/config.rs:55`),
`siem_auth_header` (`src/config.rs:59`). All five are listed in `OPTIONAL_KEYS`
(`src/config.rs:145-153`). The SIEM *credential* is deliberately **not** a configuration key: it
is the environment variable `OSPREY_SIEM_AUTH` (`src/delivery/mod.rs:179`), kept off `Config`
because `Config` derives `Debug` (`src/config.rs:21`; rationale `src/delivery/mod.rs:176-178`).

---

## SMTC receipt

| Leg | Status | Result |
|---|---|---|
| `smtc map --root <root> --output-format ranked_list --token-budget 256 --max-tokens 1024 --format json --session-id sf-gate2-grounding-2026-09-23` | run | ok:true — 70 ranked files, 14 returned, `truncated: true`, no refs. Required core satisfied; `src/delivery/mod.rs` ranked 10th, `src/delivery/file.rs` 11th. |
| `smtc inspect file --root <root> --path <root>/src/delivery/mod.rs --limit 5 --format json --max-tokens 2048 --session-id <session>` | run | ok:true — 5 top-level declarations + 15 imports, no truncation. Gave `QUEUE_CAPACITY` (zero-based line 36 = one-based 37), the `Record` enum, the `Decision` struct and the `file`/`siem` submodules. |
| `smtc analyze architecture --root <root> --format json --max-tokens 2048 --session-id <session>` | run | ok:true — 10 of 306 modules, `files_scanned: 70`, no violations. `package_firewall::delivery` hotspot 0.573, fan_in 26 / fan_out 32, 24 public entry points. |
| `smtc analyze entry-points --root <root> --limit 5 --format json --max-tokens 2048 --session-id <session>` | run | ok:true — 4 of 4, coverage 1.0, `verified_clean: false`, 427 unresolved dispatch sites, 20 test files excluded at discovery. `src/main.rs:55` plus the three `benches/*.rs` mains. parse_health: 70 files, 0 error nodes, 0 dropped statements. |
| `smtc inspect imports` | irrelevant | Not a dependency-boundary question. |
| `smtc deps reverse` | irrelevant | No single `module_id` scope was given. |
| `smtc analyze cycles` | irrelevant | Architecture leg reported no violation; no health check was requested. |

**Tier:** structural (SMTC `map`, `analyze architecture`, `analyze entry-points`, `inspect file`),
supplemented by manual file reads for the per-line declaration and constant claims.

**Limitations:** the architecture leg reports `in_cycle: true` for all ten top modules, which for
a Rust crate reflects intra-crate module reference cycles rather than a build-level cycle; it was
not investigated further. The exact CI command is not determined because no CI configuration
exists.
