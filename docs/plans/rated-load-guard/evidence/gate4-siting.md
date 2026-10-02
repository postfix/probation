# Gate 4 siting evidence — where each check lands and what command runs it

Four read-only `sf-repo-view` dispatches, 2026-09-24, all verdict ORIENTED, all tier structural
(SMTC file/symbol evidence; no compile or test execution was run). They answer the question Gate 3
left open: `03-program-design.md` `## Test plan` names 24 checks and the seam each observes, but
does not say which file holds each one or which command runs it. Gate 4 cannot write a witness
cell without that.

Each dispatch's stated limitations are carried at the end of its section rather than dropped.

---

## §1 Configuration checks — `rl2`, `rl3`, `rl4`, `rl5`

Scope: `src/config.rs`, `tests/config_validation.rs`.

**There is no `#[cfg(test)]` module in `src/config.rs`.** The file is 426 lines, read in full, and
ends at `impl std::error::Error for ConfigError` (`:416-426`). So a configuration check has no
in-file site and must be an integration test.

Reachable surface, both `pub`, in `impl Config` (`:155-172`):

- `pub fn from_toml_str(text: &str) -> Result<Config, ConfigError>` — `src/config.rs:156`, body
  156-163: `toml::from_str` → `check_keys(&table)?` (`:160`) → `RawConfig` deserialize →
  `raw.validate()`.
- `pub fn load(path: &Path) -> Result<Config, ConfigError>` — `:165`, body 165-171, delegating to
  `from_toml_str` at `:170`.

`RawConfig::validate` is **private** (`:175`, body 175-341) and not directly testable.

`ConfigError` is `:384-400`; the `Invalid` variant is:

```rust
    Invalid {                       // config.rs:396
        key: &'static str,          // config.rs:397
        reason: String,             // config.rs:398
    },                              // config.rs:399
```

`Display` is `:402-414`, the `Invalid` arm printing ``invalid `{key}`: {reason}`` at `:411`.

**The existing rejection idiom**, which `rl2`–`rl4` copy. A local helper appends raw TOML to the
shipped sample:

```rust
fn sample_with(lines: &[&str]) -> String {          // config_validation.rs:579-586
    let mut text = fs::read_to_string("config.sample.toml").expect("the sample is readable");
```

and the assertion pair, verbatim from the `log_file_max_bytes` precedent:

```rust
    let err = Config::from_toml_str(&sample_with(&["log_file_max_bytes = 1048576"]))   // :592
        .expect_err("a size without a path is refused");                               // :593
```

```rust
        matches!(                                   // :595
            &err,                                   // :596
            ConfigError::Invalid {                  // :597
                key: "log_file_max_bytes",          // :598
                ..                                  // :599
            }                                       // :600
        ),                                          // :601
        "the refusal names the key an operator can fix, got `{err}`"   // :602
```

(`assert!(` opens at `:594`; the paired reason check is `err.to_string().contains("log_file_path")`
at `:605`.) `common::sample_config()` is imported at `:18` and used for the default half of a key's
test at `:567` and `:643`; the rejection assertions themselves use `sample_with` /
`sample_with_ceiling`, not `sample_config`.

**Anchors in `src/config.rs`** for the six edits slice 1 makes:

| Item | Lines |
|---|---|
| `REQUIRED_KEYS` | 126-142 (15 entries) |
| `OPTIONAL_KEYS` | 145-153 (7 entries) |
| `check_keys` | 357-370 |
| `invalid(key, reason)` | 372-374 (siblings `nonzero_u64` 376-378, `nonzero_u32` 380-382) |
| `Ok(Config { … })` literal | 302-340 (`log_file_max_bytes` shorthand at 336) |
| `log_file_max_bytes` on `RawConfig` | 105 (`Option<u64>`, private, beside `log_file_path` at 104) |
| `log_file_max_bytes` on `Config` | 52 (`pub … NonZeroU64`, doc 50-51) |
| "refused without its sink" arm | 239-244 |
| default-application arm | 245-250 (`None => DEFAULT_LOG_FILE_MAX_BYTES,` at 249) |
| `DEFAULT_LOG_FILE_MAX_BYTES` | 78 |

Note the zero check at `:247` is written inline as `"must be greater than zero"` rather than routed
through `nonzero_u64`'s `"must not be zero"` (`:376-378`), because the value is an `Option<u64>`
that is defaulted, not a plain `u64`.

**Three facts that constrain how the new keys land**, reported by the dispatch as things that would
make a new optional `NonZeroU64` key unlandable as assumed:

1. **The key must be declared twice or every test fails at parse.** `check_keys` (`:357-370`)
   rejects anything outside `REQUIRED_KEYS`/`OPTIONAL_KEYS` as `UnknownKey` (`:361`), *and*
   `RawConfig` carries `#[serde(deny_unknown_fields)]` (`:83`). A key missing from either yields
   `UnknownKey`/`Syntax`, never the `Invalid` the tests match.
2. **A live key in `config.sample.toml` breaks two existing tests.** `config_validation.rs:171` is
   `assert_eq!(keys.len(), 17, "the sample carries every documented key");` — a hard-coded count —
   and the deletion sweep at `:183-190` requires any key whose removal still yields `Ok` to appear
   in `const WITH_DEFAULTS` (`:174`), which lists only `max_references_per_project` and
   `metadata_max_age_seconds`. **This is the evidence for C71**: the two new keys stay commented
   out, which is also what makes `rl5` true.
3. **A `NonZeroU64` on `Config` cannot be left absent**, since the `Ok(Config { … })` literal
   (`:302-340`) must be given a value — so the key needs a `DEFAULT_*` constant in the 66-78 block,
   mirroring `:249`. A test asserting "absent means off" is not expressible for a `NonZeroU64`
   field. Gate 3 chose a defaulted `NonZeroU64` (C23, C36), so this is consistent, not a conflict.

`tests/config_validation.rs` reads `config.sample.toml` six times — `Config::load` at `:129`, the
built binary at `:236` and `:245`, and `fs::read_to_string` at `:161`, `:310`, `:493`, `:580` — all
by bare relative path, so all assume cargo's crate-root working directory.

Limitations: `smtc inspect file` on `tests/config_validation.rs` returned a 4,241-token ref above
the 4,096 bound and was not opened; the declaration inventory was recovered by bounded `file read`
instead. `sample_with` appends to the *end* of the sample text, which is safe only while the sample
is a flat key/value document with no `[table]` header — `config.sample.toml` was outside this
dispatch's scope and was not read, so that is flagged rather than confirmed.

---

## §2 Build and test layout — every witness command in this plan

Scope: `Cargo.toml`, `tests/`, `tests/common/mod.rs`, `benches/`.

**19 integration targets** directly under `tests/`, so `cargo test --test <name>` resolves for each:
`artifacts_concurrency`, `artifacts_verification`, `blocklist_reload`, `blocklist_revocation`,
`blocklist_snapshot`, `config_validation`, `decision_log_delivery`, `e2e_npm`, `e2e_pip`,
`http_contract`, `npm_metadata`, `origin_guard`, `persistence_content`, `persistence_projects`,
`persistence_recovery`, `pypi_metadata`, `slice11_adversarial_singleflight`, `tracer`,
`warm_artifact_budget`. `tests/common/mod.rs` is a module, not a target.

**Three benches**, each `harness = false` with its own `main` — `Cargo.toml:18-33`:

```toml
[[bench]]
name = "warm_metadata"
harness = false

[[bench]]
name = "artifact_throughput"
harness = false

[[bench]]
name = "blocklist_swap"
harness = false
```

Every `[[bench]]` name has a matching file under `benches/`; none is unregistered.

**`test-support` needs no flag on any witness command.** `Cargo.toml:41` declares `test-support = []`
inside `[features]` (`:35-41`) with no `default = [...]` key anywhere, so it is off for
`cargo build`; the self dev-dependency turns it on for test and bench binaries through feature
unification — `Cargo.toml:76-87`:

```toml
[dev-dependencies]
package-firewall = { path = ".", features = ["test-support"] }
wiremock = "0.6.5"
```

(The block's comment records why `criterion` is absent: it "reports means with confidence intervals
and no percentiles — it cannot express the targets it was named for." This is the C19/C49
precedent.) Exactly two dev-dependencies today; `proptest` would be the third, which is C49's stated
cost.

**The bench/test shared-harness include**, identical in all three benches —
`benches/artifact_throughput.rs:25` is `#[path = "../tests/common/mod.rs"]` with `mod common;` at
`:26`; the same pair at `benches/warm_metadata.rs:15-16` and `benches/blocklist_swap.rs:19-20`.
This is the mechanism C42 relies on.

**The documented command shapes**, `README.md:70-75`:

```sh
cargo clippy --all-targets -- -D warnings
cargo test                                  # offline; no test reaches a public network
cargo test --test e2e_npm -- --ignored      # drives the real npm client
cargo test --test e2e_pip -- --ignored      # drives the real pip client
cargo bench                                 # the SPEC §12 measurements
```

`README.md:78-80` notes the build needs `cmake`, a C compiler and `perl`; the e2e targets
additionally need `npm` and `python3`, neither of which any check in this plan uses.

**`tests/common/mod.rs` has no load driver and no pacer today.** A name search for
`pub (async )?fn` matching `load|pace|rate|rps|burst|concurren|drive|parallel|spawn|flood` returned
14 repo-wide hits and zero in that file. Its only `tokio::time::sleep` uses are condition-waits —
`:347` in `wait_for_status` (25 ms poll) and `:385` in `wait_until`, whose doc at `:375-376` says
"This is a wait for something to *become* true, never a wait to create timing". The only
concurrency primitive is `Gate` (`:549-551`), a two-`Semaphore` rendezvous. So `drive_rated_load`
is genuinely new code in slice 6, not an adaptation.

Existing public harness surface slice 6 builds on: `sample_config() -> Config` (`:36`, loading
`config.sample.toml` by relative path and overriding only `listen` to port 0), `TestClock` (`:49`,
with `at` `:60`, `at_rfc3339` `:71`, `set_rfc3339` `:75`, `rewind_wall_clock_seconds` per doc
`:44-47`), `TestServer` (`:124`, with `start` `:134`, `start_with`, `wait_for_status` `:340`,
`shutdown` `:352`), `downstream_client()` (`:365`), `wait_until()` (`:377`), `Gate` (`:549`),
`WiremockUpstream` (`:900`). The file depends on `wiremock` (`:901`, `:909`), so a bench pulling in
the harness links it too — available, since it is a dev-dependency.

Limitations: two `inspect file` legs on `tests/common/mod.rs` (900+ lines) hit the token ceiling and
were substituted with targeted reads, so the negative in the paragraph above rests on a name-pattern
search plus targeted reads, not an exhaustive symbol dump — a pacing helper named outside that
pattern and using no `sleep`/`interval`/`Semaphore` would have been missed.

---

## §3 In-crate `#[cfg(test)]` modules, and the `logging.rs` anchors

Scope: `src/http/logging.rs`, `src/delivery/mod.rs`, `src/delivery/file.rs`,
`src/delivery/siem.rs`, `src/lib.rs`. All five read in full.

| File | `#[cfg(test)]` module | Range | Tests |
|---|---|---|---|
| `src/http/logging.rs` | **yes** | 465-499 (`mod tests` 466, closing brace = last line) | `a_hostile_route_component_cannot_forge_a_log_line` (469-478), `an_unrecognised_target_contributes_nothing` (480-486), `a_long_component_is_bounded` (488-498) |
| `src/delivery/mod.rs` | **does not exist** | — | — |
| `src/delivery/file.rs` | **yes** | 222-268 | one: `tp19_file_drain_deadline_counts_cut_off_records` (227-267) |
| `src/delivery/siem.rs` | **does not exist** | — | — |
| `src/lib.rs` | **does not exist** | — | — |

This is the evidence for C72: `rl22` and `rl16b` are **added cases** in the module that already
exists at `logging.rs:465-499`, reaching the private helpers through its `use super::*;`, while
`rl6` needs a **new** module in `src/delivery/mod.rs`.

**Visibility**, which decides what a `tests/`-resident check could never do: `Decision` is
`pub(crate) struct Decision` at `src/delivery/mod.rs:54` (declaration with derive 53-73, all fields
`pub`), and `src/lib.rs:13` is `pub(crate) mod delivery;` with a doc at `:11-12` reading
"Crate-internal: this feature adds no public Rust surface." `loggable` (`logging.rs:322-326`),
`MAX_LOGGED_TARGET` (`:51`) and `Target::of` (`:268-317`) are all private to the `logging` module.

**`logging.rs` anchors, and the two-line drift C78 records.** The inline literal is
`let decision = Decision {` at `:207`, fields 208-221, `};` at `:222` — exactly as Gate 3 says. The
`tracing::info!` block is `:224-239`, and `app.delivery.offer(Record::RequestDecided(decision));` is
at **`:241`**, not `:243`. `decide` itself is `:150-253`. The ordering claim holds at the real
lines.

**`delivery/mod.rs` anchors** for slice 1 and slice 3: `struct Sink` at 107-110, **private, no
visibility modifier**, with `drops: Arc<AtomicU64>` at `:109`; `impl Sink { fn push }` 112-118 with
`self.drops.fetch_add(1, Ordering::Relaxed);` at `:115`; both `mpsc::channel(QUEUE_CAPACITY)` calls
at `:214` (file sink, `drops` created `:215`, `Sink { tx, drops }` `:223`) and `:250` (SIEM,
`:251`, `:260`) inside `pub(crate) fn build` (203-276) — and no third `mpsc::channel(` in the file;
`const QUEUE_CAPACITY: usize = 4096;` at `:37`; `pub(crate) fn drops(&self) -> Drops` 150-161 with
`swap(0, …)` at `:155` and `:159`; `pub(crate) struct Drops` 99-103.

**The two existing `#[cfg(feature = "test-support")]` items in `src/lib.rs`**, which the new
accessor copies:

```
    #[cfg(feature = "test-support")]
    pub fn delivery_is_empty(&self) -> bool {      // src/lib.rs:114-117, on impl App
        self.delivery.is_empty()
    }
```

```
    #[cfg(feature = "test-support")]
    pub fn background_task_count(&self) -> usize {  // src/lib.rs:300-303, on impl Running
        self.tasks.count()
    }
```

Elsewhere in the crate the same gate appears at `src/http/logging.rs:460` (`set_summary_window`,
body 461-463), `src/http/limits.rs:97` and `src/tasks/mod.rs:51`.

**`tp19` and its three C64 edits**, confirmed at the lines Gate 3 names. Range 227-267 inside the
module at 222-268 (preamble `use super::*;` `:224`, `use crate::delivery::Summary;` `:225`). It
builds a plain stack counter and passes it by reference into the private `drain`:

```
248:        let mut writer = Writer::new(path.clone(), NonZeroU64::MAX);
249:        let drops = AtomicU64::new(0);
250:
251:        drain(&mut writer, &mut rx, &drops, Duration::ZERO).await;
```

and reads it once after the drain at `:260`, `let dropped = drops.load(Ordering::Relaxed);`. Its
channel is local — `mpsc::channel(QUEUED as usize)` at `:234` with `QUEUED: u64 = 10_000` at `:233`
— so it bypasses `QUEUE_CAPACITY` and `Sink` entirely and is unaffected by slice 1.

**`cargo test --lib` is the command for anything in these modules.** `Cargo.toml:10-12` declares
`[lib] name = "package_firewall", path = "src/lib.rs"` with no `test = false`; `src/lib.rs:14` has
`pub mod http;` and `src/http/mod.rs:7` has `pub mod logging;`, so `logging` compiles into the lib
test binary. The precedent is already recorded: `docs/plans/decision-log-delivery/04-slices.md:65`
runs `tp19` as `cargo test --lib` precisely because `cargo test --test <name>` never compiles unit
tests. This grounds C73.

Limitations: a repo-wide `^#\[cfg\(test\)\]` grep hit the 20-match cap, so absence in
`delivery/mod.rs`, `delivery/siem.rs` and `lib.rs` was established by reading every line of each
file rather than by the grep. No `cargo` invocation was made, so the `cargo test --lib` claim rests
on the manifest, the module graph and the recorded precedent, not on an executed run.

---

## §4 The delivery suite's own idioms — overflow, and what "stdout" means there

Scope: `tests/decision_log_delivery.rs`, 1299 lines.

**`tp7_drop_is_counted_and_read_back_from_file`**, `:693`, body 693-740 — the overflow shape `rl1`
copies and the test C41 amends. Its configuration (`:698-702`) points the SIEM sink at a collector
that never answers:

```rust
    let mut config = sample_config();
    config.log_file_path = Some(path.clone());
    config.siem_url = Some(wedged_collector().await);

    let server = TestServer::start_with(config, Arc::new(SystemClock)).await;
```

`OVERFLOW_REQUESTS` is declared next to it with the doc comment C41 names (`:688-690`):

```rust
/// Enough requests to fill the SIEM sink's 4096-record queue and overflow it while the
/// collector holds the sink's one in-flight batch hostage.
const OVERFLOW_REQUESTS: usize = 5_000;
```

The load is sequential awaited HTTP (`:707-711`):

```rust
    let first = server.get(PACKAGE).await.status();
    let mut last = first;
    for _ in 1..OVERFLOW_REQUESTS {
        last = server.get(PACKAGE).await.status();
    }
```

and the assertion C41 says would stop testing overflow is `:727-733`, read out of the **delivered
file**, not the console:

```rust
    assert!(
        summaries
            .iter()
            .any(|summary| summary["dropped_siem"].as_u64() > Some(0)),
        "the records the wedged collector cost are counted against its own sink, and \
         the count is readable out of the file the operator keeps: {summaries:?}"
    );
```

Its records come from `delivered(&path)` filtered to `event == "request_summary"` (`:719-722`); the
paired `dropped_file == 0` check is `:734-739`.

**"stdout" in this file is a captured `tracing` JSON stream, never the real file descriptor.** This
is the evidence for C74. Two flavours exist:

(a) **Binary-wide, INFO level**, in the private `mod stdout` (`:1228-1299`), installed once —
`:1264-1278`:

```rust
    pub fn capture() -> Lines {
        static CAPTURED: OnceLock<Lines> = OnceLock::new();
        CAPTURED
            .get_or_init(|| {
                let lines = Lines::default();
                let subscriber = tracing_subscriber::fmt()
                    .json()
                    .with_writer(lines.clone())
                    .with_max_level(tracing::Level::INFO)
                    .finish();
                let _ = tracing::subscriber::set_global_default(subscriber);
                lines
            })
            .clone()
    }
```

`Lines` is `Arc<Mutex<Vec<u8>>>` (`:1237`) implementing `io::Write` (`:1239-1251`) and
`MakeWriter` (`:1253-1259`), with readers `Lines::text()` (`:1282`) and
`Lines::decision_line(request_id)` (`:1287-1297`). Call sites: `:61` (tp1), `:344` (tp4), `:569`
(tp13), `:903` (tp11a). The module doc calls it "The process's own structured stdout, captured as
the operator's log collector would see it" (`:1228-1229`).

(b) **Per-test thread-local, WARN level**, via `set_default` into a fresh `stdout::Lines` — `:444`
(tp16), `:531` (tp17), and `tp15b` at `:1047-1054`:

```rust
    let captured = stdout::Lines::default();
    let console = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .json()
            .with_writer(captured.clone())
            .with_max_level(tracing::Level::WARN)
            .finish(),
    );
```

read back after dropping the guard (`:1062-1069`). `tp15b`'s own comment at `:1044` records why it
is thread-local rather than the binary-wide capture.

**The level distinction decides `rl24`'s mechanism**: a decision line is INFO, so `rl24` uses the
global `stdout::capture()` plus `Lines::decision_line(request_id)`, not the WARN-level thread-local
form. The dispatch's closing answer states that `rl24` is landable using only mechanisms already in
this file — `wedged_collector()` plus the `OVERFLOW_REQUESTS` loop to force the loss, the global
INFO capture to read the record back, and `delivered(&path)` summaries to corroborate the drop, as
`tp7` does.

The file's shared reading helpers, available to every new row: `decided_records(path)` (`:1175-1180`),
`delivered(path)` (`:1182-1191`), `decided(server, path)` (`:1195-1197`), `request_id_of`
(`:1199-1207`), `levelled(text, level)` (`:1210-1214`), `rollover_of` (`:1216-1220`), `size_of`
(`:1222-1226`). `AuthEnv` / `SIEM_AUTH_LOCK` (`:1142-1166`) serialize the process-global
`OSPREY_SIEM_AUTH`. Preamble consts are `DECISION_FIELDS` (`:35-48`, the twelve SPEC §11 keys
`tp13` compares) and `PACKAGE` (`:52`). `TestClock` is imported at `:22-25`.

---

## §5 Collectors, and the hang guard `rl23` copies

Same scope as §4. Three collector mechanisms exist, and the plan's SIEM rows divide between them:

- **`wedged_collector()`** — `:1097-1109`, a raw `tokio::net::TcpListener` that accepts connections
  and holds the streams unread. Used by `tp7` (`:700`) and `tp15` (`:1006`). This is the
  unreachable-collector state C31's hold is written for, so `rl10`, `rl23` and `rl23b` drive it.
- **`silent_collector()`** — `:1115-1134`, reads the request and never answers. Used by `tp15b`
  (`:1036`).
- **`wiremock::MockServer`** — for a collector that *answers*, which is what `rl10b` needs. The
  file's one wrapper is `one_batch()` (`:805-828`, "One server run against a collector that accepts
  everything, returning what that collector was sent"), `:808-815`:

```rust
async fn one_batch() -> Vec<wiremock::Request> {
    let collector = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&collector)
        .await;

    let mut config = sample_config();
    config.siem_url = Some(Url::parse(&collector.uri()).expect("the collector's URL"));
```

  returning `collector.received_requests().await…` (`:824-827`). `tp9` inlines the same shape twice
  (`:837-841`, `:843-849`). There is no generic `start_collector()` helper.

**`tp15_shutdown_bounded_against_wedged_collector`** — `:1003`, body 1003-1026. Its guard, which
C59 requires `rl23` to copy and which `:1016-1018` states verbatim:

```rust
    tokio::time::timeout(Duration::from_secs(20), server.shutdown())
        .await
        .expect("HANG: shutdown did not return against a collector that never answers");
```

followed by `assert!(elapsed < Duration::from_secs(10), …)` at `:1021-1025`. This is the suite's
only hang-to-failure converter, which is why C41 forbids weakening it.

**`tp9_redirect_is_not_followed`** — `:835`, body 835-893: two wiremock servers, 302 → elsewhere,
assertions that the collector received requests (`:865-872`) and `elsewhere` did not (`:873-880`),
then `dropped_siem > 0` over `delivered(&path)` summaries (`:882-892`). It waits with a bare
`tokio::time::sleep(Duration::from_millis(2_500))` at `:862` and carries **no** timeout guard —
which is what C41 means by calling it untouched-but-exposed, and why slice 5's witness runs it.

Limitations: `smtc inspect file --limit 60` on this file returned a 6,124-token ref above the bound
and was not opened; declaration spans were recovered by targeted `file read` plus anchored
`file grep` instead. `file grep` is repo-wide, so file scoping was done by reading the returned
paths.
