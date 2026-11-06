# Program Design: Decision log delivery

Repository evidence for every "existing" claim below: `evidence/repository-structure.md` and the
verbatim declarations returned by an isolated read-only `sf-repo-view` dispatch against Git base
`0f50cec6d526773abec4b4897f64afc10992a8ae`. Every declaration quoted as *existing* was read from
that tree; everything else is labelled **proposed**. For the C49 revision, the construction and
call sites of `Decision`, `Summary`, `summarise`, `flush_summary` and `close_window` come from
`evidence/impact-c49.md`. The seven sites it names are the complete edit surface, including the
test-only `Summary` literal at `src/delivery/file.rs:236`, which must gain `timestamp`.

## Clarifications and decisions

| ID | Class | Status | Owning Gate | Target Gate | Question or disposition | Selected value or policy | Decision source |
|---|---|---|---|---|---|---|---|
| C13 | current-Gate decision | resolved | 3 | none | Where do per-sink drop counts live? Gate 2 said they ride on the existing `Counters` mutex at `src/http/logging.rs:284`. But drops happen in two places: the request path (queue full) and the sink task (write error, batch dropped after retries), and the sink task is async. | Each sink owns an `Arc<AtomicU64>`, incremented by whichever side drops, read and reset by `summarise()` at window close. **This refines the mechanism Gate 2 named while keeping the constraint Gate 2 set** — nothing new on the request path beyond arithmetic — and it avoids a sink task reaching for a synchronous `std::sync::Mutex` that the request path holds on every request. Consequence: `struct Counters` at `src/http/logging.rs:276-282` is **unchanged**, so the change surface is smaller than Gate 2 estimated, not larger. | `## Modules and interfaces`, `delivery::Sinks` |
| C14 | current-Gate decision | resolved | 3 | none | Is the decision record built even when no sink is enabled? Building it costs a few small allocations per request on the default path, which the product promises is unchanged. | Yes — always built, rendered to stdout from the record, then offered to a sink set that is empty by default and returns immediately. The alternative is two rendering paths for one line, which is how the twelve stdout fields and the delivered fields drift apart. Stated cost, measured against the confirmed types: exactly two new allocations per request — a clone of `context.id` and a `String` for the method — on a path that already allocates a bounded `String` for the target (`src/http/logging.rs:261`) and an `Arc<RequestContext>` (`src/http/logging.rs:139`). Everything else is moved or is `&'static str`. Allocation is not observable behaviour; a changed field set would be. | `## Modules and interfaces`, `delivery::Record`; `## Least confident decisions` 1 |
| C15 | current-Gate decision | resolved | 3 | none | The peer address must be read from `Request`, but `decide` consumes the request at `next.run(request)` (`src/http/logging.rs:144-146`). | The `ConnectInfo<SocketAddr>` extension is read from `request.extensions()` **before** `next.run(request)`, in the same block that already calls `Target::of` on the URI, and only the `IpAddr` is kept. Reading it afterwards is not possible, and this is the kind of ordering fact that costs an implementation round trip if the design leaves it implicit. | `## Modules and interfaces`, `http::logging::decide`; `## Call stack` |
| C16 | current-Gate decision | resolved | 3 | none | The file sink writes from inside a Tokio task. Gate 2's Fit row named `std::fs`, which blocks the runtime thread it is on. | `tokio::fs` with `tokio::io::AsyncWriteExt`. The `fs` feature is already enabled on `tokio 1.53.1` (`Cargo.toml`), so this is not a new dependency and not a new feature flag — it is the same code shape without a blocking call on an async worker. | `## Modules and interfaces`, `delivery::file::run` |
| C17 | implementation verification | resolved | 3 | none | `axum` is declared as a bare `axum = "0.8.9"` (`Cargo.toml:46`), with no feature list. `ConnectInfo` / `into_make_service_with_connect_info` are core axum APIs under its default features, but that was inferred from the version line rather than witnessed. | Policy is already selected: consumer identification uses `ConnectInfo<SocketAddr>`, enabled on the server only when the opt-in is on. The later check is the consumer-identification slice's own `cargo clippy --all-targets -- -D warnings`, which fails at compile time if the API is not available under the declared features. No design alternative is held open. | `## Test plan`, check `TP-12` |
| C19 | current-Gate decision | resolved | 3 | none | Gate 2's five-second drain deadline assumes a sink task can be stopped. Nothing in the design bounded an in-flight `POST`, and `reqwest`'s async `ClientBuilder::timeout` **defaults to no timeout** (confirmed against current reqwest documentation: "Default is no timeout"). A collector that accepts the connection and never answers would hang `tasks.join()` forever. | Two independent bounds, because one is not enough: the client is built with `.timeout(Duration::from_secs(3))` and `.connect_timeout(Duration::from_secs(1))`, and each sink's drain loop is wrapped in `tokio::time::timeout(Duration::from_secs(5), ..)` so the deadline holds regardless of what is stuck inside. The drain deadline is then enforced by the caller rather than trusted to the callee. | `## Modules and interfaces`, `delivery::build`, `file::run`, `siem::run`; check `TP-15` |
| C20 | current-Gate decision | resolved | 3 | none | `flush_summary` reads and resets the drop counters *before* the drain begins, so every record dropped during the drain window — an I/O error, a batch abandoned at the deadline — increments a counter nobody ever reads. That is a silent hole in Gate 1's "every dropped record is counted and reported". | After `tasks.join()` returns and before `drop(self.app)`, `flush_drop_tail` reads the counters one last time and, when either is non-zero, emits one `tracing::warn!`. The sinks are finished by then, so this last line reaches the console only — which is stated as a residual rather than hidden, and is the same residual Gate 2 C12 already recorded for a SIEM-only operator whose SIEM is down. | `## Modules and interfaces`, `http::logging::flush_drop_tail`; `## Least confident decisions` 7 |
| C21 | current-Gate decision | resolved | 3 | none | A non-retryable `4xx` drops the whole batch. One record a collector rejects therefore costs up to 255 good records beside it, and a record *shape* that keeps recurring repeats that loss indefinitely. | **Accepted, owner: product**, rather than mitigated. Splitting a rejected batch to isolate the bad record costs either a burst of up to 256 individual `POST`s against a collector that is already failing, or a bisection ladder — both of which make a broken-collector situation worse at exactly the wrong moment. An operator who needs completeness configures the file sink, which has no equivalent failure mode; that is already the product's stated answer for anyone needing a guarantee. Stated plainly in the operator documentation and in `## Least confident decisions` 5 so it can be overruled. | `## Threat model` T-BATCH-POISON; `## Least confident decisions` 5 |
| C18 | current-Gate decision | resolved | 3 | none | Where do sink task handles live, given `tasks::spawn` owns `Tasks.handles` but the queue receivers must never escape the delivery module? | `delivery::build` spawns its own tasks and returns their `JoinHandle`s; `tasks::spawn` gains a fourth parameter that pushes them into `Tasks.handles`. The receivers stay inside `delivery`, and the existing drain at `src/lib.rs:264` already awaits everything in `Tasks`, so no new hook point is added — which is what Gate 2's Fit row for `src/tasks/mod.rs` required. | `## Modules and interfaces`, `delivery::build`, `tasks::spawn` |
| C27 | user clarification | resolved | 3 | none | The decision log file is created `0o666 & ~umask` — 0644 under a normal umask — and slice 3 changes its contents to personal data, readable by every local user and process. Fix in code, or transfer the restriction to operator documentation? | `.mode(0o600)` on every create-capable open: in `Writer::open` (`src/delivery/file.rs`) through `tokio::fs::OpenOptions`'s own inherent `.mode` on Unix, and in the startup probe in `build` (C36) through `std::fs::OpenOptions` with `std::os::unix::fs::OpenOptionsExt`. It applies only on creation, so an operator who pre-creates the file keeps their own mode. Documentation-only was rejected because the unsafe state is the default and silent: an operator who follows every word of the privacy section still gets a world-readable file of peer IPs, with nothing in the process's behaviour to signal it. Unix-only, no `cfg` guard — this product targets Linux. **Amended by C37:** the pre-created-file carve-out is not the whole policy; a group- or world-accessible file produces one warning. | user answer, Gate 3 grilling round 1; `sf-security-review` slice 3, F1 |
| C28 | user clarification | resolved | 3 | none | `delivery::build`'s approved Effects say it "opens the log file for append and reads its current length into the byte tally", but the implementation defers the open to `Writer::open` on the first record. An unopenable path therefore starts cleanly and drops every record while still collecting peer IPs on every request — the exact state the `log_consumer_identification` rejection exists to refuse. Restore the contract, and is the failure fatal? | Restore the startup-time open inside `build`, take the length into the byte tally there, and map a failure to `StartupError::Delivery` — fatal at startup. This is a deviation from an already-approved contract, not a new design choice; the contract licenses the fix. Accepted cost, stated rather than hidden: an operator whose log directory is created later by an init system or a mount now fails to boot instead of recovering when the directory appears. **Superseded in two parts:** the byte-tally clause is struck by C36 (the startup action is a probe that reads no length), and "fatal at startup" is narrowed by C39 to apply only while `log_consumer_identification` is on. | user answer, Gate 3 grilling round 1; `sf-security-review` slice 3, F2 |
| C29 | user clarification | resolved | 3 | none | `request.extensions()` is an inbound-request accessor that the retained spec's call-name list cannot see, so `TP-14`'s product-root zero proves less than this document claimed, and the spec's own prose — "fails the moment an inbound-request accessor call site exists anywhere in this repository, full stop" — is now false. Add `extensions` to the existing spec, author a second spec, or accept the residual knowingly? | A second retained spec, `.smtc/analyzers/consumer-identity-extension-read.yaml`, over `extensions` with the same <code>request&#124;req&#124;parts</code> receiver idiom, whose pass condition is **exactly one finding, at `src/http/logging.rs`** rather than zero. Adding `extensions` to the existing spec was rejected: it would fire on slice 3's own approved read and destroy that spec's zero-findings pass condition. The exception therefore lives in the pass condition rather than requiring an engine suppression feature this SMTC build is not confirmed to have. A count moving off 1 is as loud a signal as a zero becoming 1. The sibling spec's false prose claim is corrected either way. | user answer, Gate 3 grilling round 1; `sf-security-review` slice 3, F3; ADR candidate |
| C30 | user clarification | resolved | 3 | none | C27's and C28's fixes land in `src/delivery/file.rs` and `src/delivery/mod.rs`, both slice 1 files outside slice 3's approved file list. Reopen slice 3 with an expanded file list, or close slice 3 as it stands and add a slice 4? | Reopen slice 3 and expand its file list. Slice 3 is what turns that file's contents into personal data and what turns "a configured but non-functional destination" into a privacy state — caused here, fixed here. Closing slice 3 first would record a proof line for a feature whose own security surface is under a `FIX FIRST` verdict. | user answer, Gate 3 grilling round 1 |
| C35 | current-Gate decision | resolved | 3 | none | Red Team finding 1: `consumer` is rendered to stdout as well as to the record (Gate 2 C9), and this plan asserts in three places that stdout "is not durable". Under systemd that stdout is journald's persistent journal; under Docker/Kubernetes a node-level file shipped by a cluster agent. Peer IPs therefore reach a durable destination the model never inventoried, whether or not the C11 rejection fires. | Add `T-CONSOLE-JOURNAL-DESTINATION`; amend `T-PEER-IP-RETENTION` to four destinations; the operator documentation's purge bullet names the console alongside the file, its `.1` rollover and the collector; and the `log_consumer_identification` reason string at `src/config.rs:295` stops claiming the rejection gives addresses "a destination" — what it actually buys is a *second, operator-chosen* one. No technical control over the journal: its permissions and retention belong to the host, not this process. | `sf-red-team`, Gate 3 reopening, finding 1 |
| C36 | current-Gate decision | resolved | 3 | none | Red Team finding 2: C28's restored Effects clause said `build` reads the file's length "into the byte tally", but there is no tally in `build` — it is `Writer.written` inside `file::run`, whose signature this design leaves unchanged. The slice instructed both that and "keep `Writer::open`'s existing length-restoring behaviour", which is unsatisfiable. `TP-16` exercises only the failure path, so an implementation that opens, discards the handle and lets `Writer::open` re-read the length would pass — the original defect's exact shape, restated. | Strike the tally clause. The startup action is a **probe**: `std::fs::OpenOptions::new().create(true).append(true).mode(0o600)`, handle dropped immediately, whose only jobs are failing startup and creating the file at `0o600`. `Writer::open` keeps its length-restoring behaviour untouched, which `tp2b` depends on. The probe is `std::fs`, not `tokio::fs`: C16 binds the sink *task*, which must not block an async worker, and `build` is synchronous and runs before any runtime work. Every verb in the revised clause is observable by `TP-16` or `TP-17`. | `sf-red-team`, Gate 3 reopening, finding 2 |
| C37 | current-Gate decision | resolved | 3 | none | Red Team finding 4: `.mode()` applies only on creation, so every deployment already running slices 1–2 has a `0644` file that will have peer IPs appended to it at `0644`. C27 presented this as a feature ("an operator who pre-creates the file keeps their own mode") and answered it with one documentation sentence — the option C27 rejected by name for an identically default-and-silent state. The same carve-out lets a local user pre-create or symlink the target under a world-writable directory. | After any open, `file::run` emits one `tracing::warn!` when `mode & 0o077 != 0`, naming the path and the mode. It does not re-chmod a file it did not create and does not refuse to run — `0640` with a group may be deliberate. `TP-17` gains a pre-created-`0644` case, because its existing cases only exercise files the process created and structurally cannot see this. | `sf-red-team`, Gate 3 reopening, finding 4 |
| C38 | current-Gate decision | resolved | 3 | none | Red Team finding 5: `TP-18` has a fourth hole no conjunct can close — delete the approved read and add a different inbound-extension read in the same file, and the count, filename and `.ok` are all unchanged, while the engine's finding output cannot distinguish the two. | Cover it behaviourally rather than structurally: `TP-4` sends `X-Forwarded-For: 203.0.113.9` and a `Forwarded:` header and still asserts `consumer == 127.0.0.2`, testing the property instead of the call site's shape. This also gives the operator-facing promise its first witness — **no test in this repository has ever sent a forwarding header**. Separately, `extensions_mut` joins the spec's name list, verified free (still exactly one finding), and field access (`parts.extensions`) is recorded as invisible to both specs, since `structural_pattern` is a call-site inventory by construction. | `sf-red-team`, Gate 3 reopening, finding 5 |
| C39 | user clarification | resolved | 3 | none | Red Team finding 6: C28 as first recorded makes an unopenable `log_file_path` fatal for every operator, but its justification is privacy — peer IPs collected with nowhere durable to go — which applies only when `log_consumer_identification` is on. For a package firewall, whose unavailability blocks CI, container builds and fresh checkouts, fatality with the opt-in off turns a logging typo into an outage with no privacy benefit. | Fatal **only when `log_consumer_identification` is on**. With the opt-in off, the startup probe's failure emits one `tracing::error!` naming the key and the reason, and the process continues serving; the file sink then behaves as it did before this revision (drops counted, `Writer::open` retried per record). This narrows C28 and supersedes its "fatal at startup" wording. **Divergence from approved Gate 2, named:** Gate 2's Failures bullet said an unopenable log file leaves the firewall serving with no condition, and Gate 2 C11 rested on the console being "non-durable" (refuted by C35). Both were brought into agreement under the backtracking rule as Gate 2 C41, and Gate 2 is re-approved before this Gate. | user answer, Gate 3 grilling round 2; `sf-red-team` Gate 3 reopening, finding 6 |
| C40 | user clarification | resolved | 3 | none | `check_config` (`src/main.rs:80-96`) calls only `Config::load` and is pinned by `the_check_commands_write_nothing` to write nothing, so it cannot run the startup probe, which may create the file. It will therefore report a valid configuration that then fails at boot when the opt-in is on. | Accepted as a stated residual. The operator documentation says plainly that `check_config` validates keys, not destinations. A read-only probe would not close the gap either — a path that opens at check time can be unwritable at boot — and relaxing the no-write contract costs more than it buys. | user answer, Gate 3 grilling round 2 |
| C31 | implementation verification | resolved | 3 | none | `TP-4`'s assertion derives its expected `consumer` from the server's bind address, which on loopback is the same `127.0.0.1` the client connects from — so wiring `decide` to the local socket address, or to a hardcoded `IpAddr::LOCALHOST`, would still pass. The no-port half of the assertion is real; the peer half is not. | Bind the test client to a distinct loopback source for the opt-in-on run — `reqwest::ClientBuilder::local_address(IpAddr::from([127, 0, 0, 2]))` — and expect `127.0.0.2`. The expectation then differs both from the server's bind address and from any constant a wrong wiring would produce. | `sf-code-review` slice 3, finding 1 |
| C42 | user clarification | resolved | 3 | none | Slice 2's review found that `file::run` counts nothing when its five-second drain deadline cuts it off: the queued records and the one in hand disappear from every count. That breaks the `docs/operations.md` promise that "a record is never discarded silently". The SIEM sink had the same bug, fixed in slice 2 with its `Unsent` guard. Fix it, accept and document it, or defer it to a later slice? | Fix it in slice 3, which already edits `src/delivery/file.rs`. On a cut-off, a private `drain` adds `rx.len() + 1` to `drops`. It may count one written record too many and never counts one too few (`### src/delivery/file.rs`, Drain). Witness: `TP-19`. | user answer, 2026-09-22 |
| C43 | user clarification | resolved | 3 | none | Slice 2's review found that the SIEM client obeys `HTTP_PROXY`/`HTTPS_PROXY`, while the upstream registry client sets `.no_proxy()` (`src/upstream/reqwest_transport.rs:101`). Security judged that this crosses no new trust boundary. Match upstream, or keep obeying the proxy variables and document the difference? | Match upstream: `delivery::build` adds `.no_proxy()` to the SIEM client builder. There is no execution witness, because a proxy test would have to set process-wide environment variables and rely on reqwest's loopback-proxy rules. The change is one builder call beside the three `TP-9`/`TP-15` already cover, so code review checks it against the upstream line (`## Invariants & spec dispositions`). | user answer, 2026-09-22 |
| C46 | current-Gate decision | resolved | 3 | none | Slice 3 Engineering found the approved `TP-19` cannot fail. It assumed `timeout(Duration::ZERO)` fires on its first poll, but tokio's timer fires only at the next millisecond tick. Three records are written in about 200µs, so the pre-fix code wrote 3, dropped 0, and passed 300 of 300 runs. With 10,000 records the cut-off lands after about 8 writes (about 600µs): pre-fix 8 written + 0 dropped, post-fix 10 + 9,991 = 10,001. What form must `TP-19` take? | Queue **10,000** records and keep `Duration::ZERO`. Assert two things. (1) Lines written < 10,000, so a cut-off actually happened. If a machine ever drains all 10,000 inside one tick, the test fails with a message saying it is inconclusive, rather than passing vacuously. (2) Lines + `drops` is 10,000 or 10,001, the stated one-high residual. Pre-fix, `drops` stays 0 while lines < 10,000, so (2) fails. Rejected: tokio paused time, because its auto-advance around `spawn_blocking` file I/O is itself timing-sensitive; and an injected-writer seam, because that adds an abstraction only a test would use. | `sf-debugging` evidence from slice 3 Engineering, 2026-09-22 |
| C49 | current-Gate decision | resolved | 3 | none | Gate 2 C48 (imported, approved 2026-09-22): every record offered to a sink carries a UTC RFC 3339 `timestamp`, read from the injected clock when the record is built, and left out of the stdout render. Gate 2 left the formatter, the field's type and how `summarise` and `flush_summary` reach the clock to this Gate. | **Type:** `timestamp: String`, the first field of both `Decision` and `Summary`, so it serialises right after the `event` tag. **Formatter:** `jiff` (already a dependency, `Cargo.toml:52`, the crate `SystemClock` itself uses at `src/clock.rs:22`). One new `pub(crate) fn rfc3339(utc_micros: i64) -> String` in `src/delivery/mod.rs` returns exactly <code>jiff::Timestamp::from_microsecond(utc_micros).map(&#124;t&#124; format!(&quot;{t:.6}&quot;)).unwrap_or_else(&#124;_&#124; utc_micros.to_string())</code>. The output always has six fractional digits and a `Z` suffix, e.g. `2026-09-21T14:13:20.000000Z`. Plain `Display` would trim trailing zeros (`…:20Z`, `…:20.1234Z`). A fixed width sorts as text and is simpler for a collector to parse. Evidence: `evidence/research-jiff-format.md`. `from_microsecond` fails only outside years -9999..9999, which the production clock cannot reach. On that error the decimal microsecond count is used instead, the same fallback `check_blocklist` uses at `src/main.rs:109-111`. **Plumbing:** `summarise` and `flush_summary` each gain a final `clock: &dyn Clock` parameter, borrowed from the `Arc<dyn Clock>` Gate 2 C48 names. `decide` passes `app.clock.as_ref()`, and `Running::shutdown` passes `self.app.clock.as_ref()`. Both forward it unread to the private `close_window`, which also gains `clock: &dyn Clock`. That makes `close_window` the **only** place a summary reads the time, and both the periodic and the shutdown summary go through it. So `TP-20`, which drives the shutdown path, exercises the one read the periodic path uses too. **Stdout:** the two `tracing::info!` calls list their fields by name, so they leave `timestamp` out by not naming it; `TP-13`'s key set is unchanged. Witness: `TP-20`. | `## Modules and interfaces`, `delivery::rfc3339`, `decide`, `summarise`, `flush_summary`; `02-architecture.md` C48 |

## Files

- `src/delivery/mod.rs` — **new.** The record type and the sink set, plus `rfc3339`, the one place a record's `timestamp` gets its text form (C49). It lives beside the other top-level modules listed at `src/lib.rs:7-17` because "a record leaves this process" is not owned by any of them; `http::logging` owns "a line reaches stdout".
- `src/delivery/file.rs` — **new.** The file sink task. Separate file because its failure mode (I/O error, size cap, rollover) shares nothing with the SIEM sink's (HTTP status, retry, batch). Its create path sets mode `0o600` (C27): this file holds peer IP addresses once consumer identification is on, and the default umask would otherwise publish them to every local user.
- `src/delivery/siem.rs` — **new.** The HTTP sink task, including the one place the credential is read and the one place redirects are disabled.
- `src/http/logging.rs` — **changed.** Builds the record, renders it to stdout exactly as today, offers it to the sinks, and gains a one-shot summary flush for the drain.
- `src/config.rs` — **changed.** Five optional keys plus the cross-key and URL-scheme rejections.
- `src/lib.rs` — **changed.** Builds the sink set, holds it on `App`, creates the drain token, orders the drain, and enables connect-info when the opt-in is on.
- `src/tasks/mod.rs` — **changed.** One parameter, so delivery's handles join the existing handle set.
- `config.sample.toml` — **changed.** Five commented-out keys with the privacy note.
- `docs/operations.md` — **changed.** The operator-facing section Gate 2's Fit row specified. After C49 it also covers the `timestamp` field on file and SIEM records, its format, and the fact that the console line omits it (Gate 2 C48).
- `tests/decision_log_delivery.rs` — **new.** The delivery integration checks named in the test plan, including `TP-20` (C49).
- `tests/config_validation.rs` — **changed.** The five keys' validation checks, in the file that already owns configuration rejection tests.
- `.smtc/analyzers/client-data-reaches-delivery-sink.yaml` — **retained, prose corrected.** Its matching keys are unchanged and its pass condition stays zero findings; only its false coverage claim and its "what it does not catch" paragraph are corrected (C29).
- `.smtc/analyzers/consumer-identity-extension-read.yaml` — **new.** The second retained spec, guarding the `request.extensions()` route the sibling spec cannot see. Pass condition: exactly one finding, at `src/http/logging.rs` (C29).

**Change surface, measured rather than assumed.** An isolated read-only impact dispatch against
the same Git base established that every struct this design widens has exactly one literal
construction site, so the new fields are source-compatible everywhere else: `App` is built once,
at `src/lib.rs:140`, although 241 functions transitively hold an `Arc<App>`; `Config` is built
once, at `src/config.rs:201`, inside `RawConfig::validate` itself — every test helper that
appears to build one in fact calls `Config::load` and then mutates fields; `RawConfig` is
deserialize-only and never constructed by literal; `tasks::spawn` has exactly one caller,
`src/lib.rs:167`; and `decide` has **zero** static callers, because it is registered as a
function pointer at `src/http/mod.rs:70-73` and invoked by Axum at runtime.

The one compatibility risk that analysis surfaced is not a Rust caller at all: every integration
test that sends a request passes through `decide`, and `assert_decided`
(`tests/http_contract.rs:1148-1156`) asserts on the decision log line itself. **That existing
assertion is weaker than it looks** — it checks three substrings (the `"request decided"`
message, the request id, and one `status=N`) and says nothing about `method`, `package`,
`version`, `result`, `reason`, `blocklist_revision`, `duration_micros` or `bytes`, and no other
test in the closure checks those names either. So the drift C14 and Gate 2 C9 rest on ruling out
— a field silently renamed or dropped when emission moves to record-then-render — would pass
every check in the repository today. `TP-13` below therefore adds an assertion over the complete
field set rather than leaning on the existing one.

## Modules and interfaces

No new programming entry point and no new HTTP route. The supported entry point is unchanged:
the operator's configuration file, read by the existing `Config::load` (`src/config.rs:129`).

### `src/delivery` — proposed module

Purpose: the one place that knows a decision record exists as a value and where copies of it go.

Provides: build the enabled sinks from configuration; hand the request path an offer that never
blocks and never fails the caller; report per-sink drop counts; own the record type that stdout,
the file and the SIEM all render from.

Owns: `Record`, `Decision`, `Summary`, `Sinks`, `Drops`; the bounded queues (capacity 4096, the
value Gate 2 approved); the per-sink drop counters; the spawned sink tasks.

Callers and visibility: `Sinks`, `Record`, `Decision`, `Summary`, `Drops` and `build` are
`pub(crate)`; `src/http/logging.rs` and `src/lib.rs` are the only callers. Nothing here is part
of the crate's public API, because Gate 2 settled that this feature adds no public Rust surface.
`file` and `siem` are private submodules; their `run` functions are `pub(super)`.

Public types and values (proposed):

```rust
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub(crate) enum Record {
    RequestDecided(Decision),
    RequestSummary(Summary),
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct Decision {
    pub timestamp: String, // C49
    pub request_id: String,
    pub method: String,
    pub ecosystem: &'static str,
    pub package: String,
    pub version: String,
    pub status: u16,
    pub result: &'static str,
    pub reason: String,
    pub blocklist_revision: u64,
    pub cache: &'static str,
    pub duration_micros: u64,
    pub bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consumer: Option<IpAddr>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct Summary {
    pub timestamp: String, // C49
    pub requests: u64,
    pub errors: u64,
    pub bytes: u64,
    pub mean_duration_micros: u64,
    pub window_micros: u64,
    pub dropped_file: u64,
    pub dropped_siem: u64,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Drops {
    pub file: u64,
    pub siem: u64,
}

pub(crate) struct Sinks { /* private: Option<Sink> per destination */ }
```

Every field type above is the owned form of a value that already exists at
`src/http/logging.rs:172-186`, confirmed against the tree: `ecosystem` is `&'static str`
(`struct Target`, `src/http/logging.rs:198-202`), `result` is `&'static str`
(`ApiError::error_code`, `src/http/error.rs:113`, and the literal `"ALLOWED"`), `cache` is
`&'static str` (`CacheStatus::as_str`, `src/http/logging.rs:58`), and `reason` is already a
`String` (`ApiError::reason`, `src/http/error.rs:136`). So sending a record across a channel
costs exactly two new allocations per request: a clone of `context.id` and a `String` for the
method. `reason`, `package` and `version` are moved out of values the existing code already owns;
the three `&'static str` fields copy for free. `package` and `version` are `Option<String>` on
`Target` and become the empty string here, which is exactly what
`target.package.as_deref().unwrap_or("")` already renders to stdout.

Units and valid states: `duration_micros`, `window_micros` and `mean_duration_micros` are
microseconds; `bytes` is response body bytes as the existing code already computes it
(`src/http/logging.rs:151-157`); `status` is the HTTP status code as `u16`; `consumer` is
`Some` only while consumer identification is on, and carries the connection's peer `IpAddr`
with no port (Gate 2 C7); `package` and `version` are the already-bounded strings produced by
`loggable` (`src/http/logging.rs:259`), empty string where the existing code logs empty string.
`Decision` field names and order are exactly the twelve names emitted at
`src/http/logging.rs:172-186`, plus `consumer` last, so that one NDJSON line and one stdout line
carry the same field set (Gate 2 C9). The one exception is `timestamp`, first in both
`Decision` and `Summary`. It is on every delivered record and never on the stdout line, whose
formatter already stamps it (Gate 2 C48, C49). It holds the time the record was built, in UTC
RFC 3339 with exactly six fractional digits and a `Z` suffix, e.g.
`2026-09-21T14:13:20.000000Z`, produced by `rfc3339` below.

#### `rfc3339` — proposed

Declaration: `pub(crate) fn rfc3339(utc_micros: i64) -> String`

Accepts: UTC microseconds since the Unix epoch, the unit `Clock::now_utc_micros` returns
(`src/clock.rs:11-12`).

Returns: exactly
`jiff::Timestamp::from_microsecond(utc_micros).map(|t| format!("{t:.6}")).unwrap_or_else(|_| utc_micros.to_string())`.
`from_microsecond` fails only outside years -9999..9999, and then the result is the decimal
count, the same fallback as `src/main.rs:109-111` (`evidence/research-jiff-format.md`).

Rejects: nothing. Effects: none.

Callers: `decide` and `close_window` in `src/http/logging.rs`; no others.

Checks: `TP-20`.

#### `build` — proposed

Declaration:

```rust
pub(crate) fn build(
    config: &Config,
    drain: CancellationToken,
) -> Result<(Sinks, Vec<JoinHandle<()>>), StartupError>
```

Accepts: the validated `Config` (`src/config.rs:21`) after `RawConfig::validate` has already
rejected every combination C11 names, and the drain token created by the caller.

Returns: the sink set to hold on `App`, and one `JoinHandle` per enabled sink. With neither
`log_file_path` nor `siem_url` set, returns an empty `Sinks` and an empty handle vector — no
file is opened, no HTTP client is constructed, nothing is spawned.

Rejects: the SIEM client cannot be constructed, `OSPREY_SIEM_AUTH` is set to a value that is
not a legal HTTP header value, **or `log_file_path` cannot be opened for append while
`log_consumer_identification` is on** → `StartupError::Delivery` (**proposed** variant on the
existing `StartupError`), so the process fails at startup rather than after it begins serving.
With the opt-in off, the same probe failure is not a rejection: `build` emits one
`tracing::error!` naming the key and the reason and continues (C39). `check_config` cannot see
either case, because it is pinned to writing nothing and the probe may create the file (C40).

**The file-open rejection is load-bearing and was missed once already (C28).** Deferring the
open to the first record makes an unopenable path — a typo, a directory that does not exist, a
directory the service user cannot write — indistinguishable from working delivery: the process
starts, serves, collects a peer IP on every request when the opt-in is on, drops every record,
and reports the loss only through a drop counter and a `tracing::warn!`. That is precisely the
state the `log_consumer_identification` rejection in `RawConfig::validate` exists to refuse, and
a key-presence check cannot reach it, because the key is present and merely wrong. Accepted cost
of making it fatal, which applies only with the opt-in on (C39): an operator whose log directory
is created later by an init system or a mount now fails to boot rather than recovering when the
directory appears.
**That error carries the variable's name and a fixed reason, never the value.** This is stated as
a contract rather than left to implementation taste because the obvious naive rendering —
`format!("invalid header value: {value}")` — prints the credential straight into
`check_config`'s `path: err` output (`src/main.rs:80-96`) and into the startup log. Marking the
`HeaderValue` sensitive does not help here: there is no `HeaderValue` on the rejection path,
only the rejected string. `TP-11` tests this exact path.

Effects: **probes** the log file at startup, inside `build`, before `App` is constructed —
`std::fs::OpenOptions::new().create(true).append(true).mode(0o600)`, with the handle dropped
immediately. The probe has exactly two jobs: fail startup when the path cannot be opened (C28),
and create the file at `0o600` when it does not yet exist (C27). **It does not read the length
and does not touch a byte tally.** An earlier draft of this clause said it did, and that was
unsatisfiable: there is no tally in `build` — the tally is `Writer.written`, created inside
`file::run`, whose signature this design leaves unchanged — so neither a handle nor a length has
anywhere to go. `Writer::open` keeps its existing length-restoring behaviour untouched, which is
what slice 1's `tp2b` regression witness depends on. The probe being a `std::fs` call rather than
`tokio::fs` does not contradict C16: C16 binds the sink *task*, which must not block an async
worker, and `build` is a synchronous function running before any runtime work begins.

**This clause is the one that already failed once, so its wording is deliberate.** The original
contract said `build` "opens the log file for append and reads its current length into the byte
tally" and the implementation simply did not, for two shipped slices, with no check that could
see the difference. Restating an Effects sentence is not a fix. What makes this one different is
that every verb in it is observable: `TP-16` witnesses the failure path, and `TP-17` case (d)
witnesses creation — it asserts the file exists at `0o600` after `App::start` returns and before
any request is sent or shutdown begins. That case matters because `Writer::open` also creates the
file lazily on the first record, also at `0o600`, so any case that sends a request first would pass
even if the probe created nothing.

Also constructs the `reqwest::Client` with
`redirect::Policy::none()` (Gate 2 C4) **and with `.timeout(Duration::from_secs(3))` plus
`.connect_timeout(Duration::from_secs(1))`**, because reqwest's async client has no default
timeout at all and an untimed `POST` to a collector that accepts the connection and then goes
silent would outlive any drain deadline (C19), **and with `.no_proxy()`**, so the SIEM client
ignores `HTTP_PROXY`/`HTTPS_PROXY` exactly as the upstream registry client at
`src/upstream/reqwest_transport.rs:95-105` does and both clients leave the host by the same
route (C43); reads `OSPREY_SIEM_AUTH` once, wraps it in a
`HeaderValue` marked sensitive via `HeaderValue::set_sensitive(true)` so it is redacted in any
`Debug` rendering, and never stores it in `Config`. That last point is load-bearing rather than
stylistic: `pub struct Config` derives `Clone, Debug` (`src/config.rs:20-21`), so any
`tracing::debug!("{config:?}")` anywhere in the process would print every field it holds. The
credential therefore exists only as a sensitive `HeaderValue` inside the SIEM sink, and `Config`
holds nothing but the header *name*. `build` also emits one `tracing::info!` line stating
which sinks are enabled and whether the SIEM sink is authenticated (Gate 2 C6).

Caller obligations: called once, from `App::start`, before `App` is constructed. The `drain`
token must be the one cancelled **after** the HTTP server join, never the existing `shutdown`
token (Gate 2 C10).

Uses: `tokio::sync::mpsc::channel` bounded at 4096 — the same bounded-channel-plus-spawned-task
shape `store::spawn` already uses at `src/store/mod.rs:590-612`, where sender halves are kept on
a handle struct and receiver halves move into the spawned task.

Caller example (proposed, in `App::start`, whose parameter is
`AppDeps { config, clock, transport, origins }` at `src/lib.rs:44-49`):

```rust
let drain = CancellationToken::new();
let (delivery, delivery_tasks) = delivery::build(&deps.config, drain.clone())?;
```

Checks: `TP-3`, `TP-8`, `TP-11`, `TP-16`, `TP-17`.

#### `Sinks::offer` — proposed

Declaration:

```rust
impl Sinks {
    pub(crate) fn offer(&self, record: Record)
}
```

Accepts: one record by value. Clones only for the second sink when both are enabled, so the
common single-sink case moves rather than clones (Gate 2 C8 named one clone per request as the
cost of independent sinks; this pays it only when both are on).

Returns: nothing. There is no error for the caller to handle — that is the point of the
interface, and it is what makes Gate 1's "delivery never slows a request" enforceable at the
type level rather than by review.

Rejects: nothing.

Effects: one `try_send` per enabled sink. A full or closed queue increments that sink's drop
counter and returns. No `await`, no I/O, no lock, no allocation beyond the clone above.

Caller obligations: none. Safe to call with no sinks enabled, in which case it returns
immediately.

Caller example (proposed, in `decide`):

```rust
app.delivery.offer(Record::RequestDecided(decision));
```

Checks: `TP-1`, `TP-7`.

#### `Sinks::drops` — proposed

Declaration:

```rust
impl Sinks {
    pub(crate) fn drops(&self) -> Drops
}
```

Returns: the drops accumulated since the previous call, per sink. Read-and-reset
(`AtomicU64::swap(0, Ordering::Relaxed)`), so the counts are per summary window exactly as
`requests` and `errors` already are (`src/http/logging.rs:317-321`).

Caller obligations: called only from the summary path, which already serialises itself under the
existing `COUNTERS` mutex; a second caller would silently steal a window's counts.

Checks: `TP-7`.

#### `Sinks::is_empty` — proposed

Declaration:

```rust
impl Sinks {
    pub(crate) fn is_empty(&self) -> bool
}
```

Returns: true when no sink is enabled. Used by the default-path test to assert that configuring
nothing spawns nothing.

Checks: `TP-3`.

### `src/delivery/file.rs` — proposed

Purpose: append records to one operator-named file with a hard size ceiling, owning the open
handle and the byte tally.

#### `file::run` — proposed

Declaration:

```rust
pub(super) async fn run(
    path: PathBuf,
    max_bytes: NonZeroU64,
    rx: mpsc::Receiver<Record>,
    drain: CancellationToken,
    drops: Arc<AtomicU64>,
)
```

This is the same shape as the two existing background loops — `blocklist_poller::run(app,
shutdown, watcher)` (`src/tasks/blocklist_poller.rs:35`) and `maintenance::run(app, shutdown)`
(`src/tasks/maintenance.rs:28`) — an `async fn` taking its inputs and a cancellation token,
spawned by the caller.

Accepts: a path the operator named; the size cap; the receiving half of the bounded queue; the
drain token; the shared drop counter.

Returns: nothing; returns when the drain completes.

Effects, per record: serialise to JSON with `serde_json::to_string`, push `'\n'`, append with
`tokio::fs` + `AsyncWriteExt::write_all`, add the byte count to the tally. When the tally would
exceed `max_bytes`, rename the file to `<path>.1` — replacing any previous `.1`, built by
pushing the literal `.1` onto the path's `OsString` so a non-UTF-8 path still works — then open
a fresh file and reset the tally. Disk use is therefore bounded at twice `max_bytes`.

**Every open that may create the file sets mode `0o600`** (C27). The API differs by call site:
the startup probe in `build` is `std::fs::OpenOptions`, where `.mode` comes from
`std::os::unix::fs::OpenOptionsExt`; `Writer::open` uses `tokio::fs::OpenOptions`, which has its
own inherent `.mode` on Unix and does not implement that trait. This covers the startup probe in `build`, the fresh
file opened after a rollover, and the reopen after an I/O error — a mode applied at only one of
the three would leave a world-readable generation behind at the first rollover. The `.1`
generation inherits its mode from the file it was renamed from. Unix-only and deliberately not
`cfg`-guarded: this product targets Linux.

**`.mode` applies only on creation, and that carve-out has to be covered rather than admired.**
An earlier draft presented "an operator who pre-creates the file keeps their own mode" as a
feature. It is also the gap: every deployment already running slices 1–2 has a `0644` file, and
turning the opt-in on appends peer IPs to it at `0644` with nothing said. Answering that with one
sentence of documentation is precisely the option C27 rejected by name, for an identically
default-and-silent state. The same carve-out lets a local user pre-create — or symlink — the
target under a world-writable directory before the service starts.

So after any open, `file::run` checks the resulting mode and emits **one** `tracing::warn!` when
`mode & 0o077 != 0`, naming the path and the mode. It does not change the mode of a file it did
not create and does not refuse to run: an operator may have chosen `0640` with a group on
purpose. The warning is what turns a silent state into a visible one, which is the whole of what
C27 asked for. `TP-17` gains a pre-created-`0644` case, because the existing case only ever
exercises files the process created itself and therefore cannot see this at all.

Failure: any I/O error increments `drops` by one and is retried on the next record by reopening;
the task never exits on an I/O error and never propagates one to the request path.

Caller obligations: exactly one process may write this path. There is no interprocess lock, so a
second instance pointed at the same file, or an external `logrotate` renaming it away, interleaves
or loses records — this belongs in the operator documentation, per Gate 2's constraint.

Drain: `tokio::select!` over `rx.recv()` and `drain.cancelled()`. Once the drain token fires, the
remaining drain work runs **inside `tokio::time::timeout(Duration::from_secs(5), ..)`**, so the
deadline is imposed by the caller and holds even if a write is stuck (C19); the task writes what
it drained within the deadline and returns. It never waits for the senders to close: `drop(self.app)` happens at `src/lib.rs:265`,
after `tasks.join()` at `:264`, so waiting on sender closure would deadlock (Gate 2 C10).

**What the deadline cuts off is counted** (C42). The drain loop moves into a private
`async fn drain(writer: &mut Writer, rx: &mut mpsc::Receiver<Record>, drops: &AtomicU64, deadline: Duration)`,
which `run` calls with `DRAIN_DEADLINE`. When `tokio::time::timeout` returns `Err`, `drain` adds
`rx.len() as u64 + 1` to `drops`: the records never taken off the queue, plus the one in hand.
There is always exactly one in hand at a cut-off, because `try_recv` never waits, so the drain
future can only be pending inside `append`. Stated residual: when the cut lands after that record's
`write_all` finished, it is both written and counted, so the count can be one too high and is never
too low. `flush_drop_tail` runs after `tasks.join()`, so it reports these drops. The `deadline`
parameter exists only so `TP-19` can pass `Duration::ZERO`. A zero deadline does **not** fire on the first poll: tokio's timer fires at the next millisecond tick, so the cut-off lands after however many records fit in that tick. That is why `TP-19` queues far more records than one tick can drain (C46).

Checks: `TP-1`, `TP-2`, `TP-10`, `TP-17`, `TP-19`.

### `src/delivery/siem.rs` — proposed

Purpose: ship records to an HTTP collector without ever touching the request path.

#### `siem::run` — proposed

Declaration:

```rust
pub(super) async fn run(
    client: reqwest::Client,
    url: Url,
    auth: Option<(HeaderName, HeaderValue)>,
    rx: mpsc::Receiver<Record>,
    drain: CancellationToken,
    drops: Arc<AtomicU64>,
)
```

Accepts: a client already built with `redirect::Policy::none()` and `.no_proxy()`; the validated URL; the optional
header name and sensitive-marked value; the queue, drain token and drop counter. The credential
is passed in rather than read here, so `build` owns the single point at which the environment is
read and the single point at which a bad value fails startup.

Effects: accumulates records until it holds 256 or two seconds have passed, then `POST`s them as
newline-delimited JSON with `Content-Type: application/x-ndjson` and the auth header when one was
configured.

Failure and retry: a transport error, a `5xx`, or a `429` is retried three times with
100 ms / 500 ms / 2 s backoff. Any other `4xx` — including a `3xx` that is not followed, since
redirects are disabled — is dropped and counted immediately, because a stale credential or a
rejected payload fails identically on every attempt and retrying only widens the window in which
the queue fills and sheds records. After the retries the batch is dropped and `drops` is
increased by the number of records in it.

**The whole batch goes, not the offending record.** One record a collector rejects therefore
costs up to 255 good records beside it, and a record shape that keeps recurring — an oversized
field, or a collector that answers a generic `400` to what is really throttling, which Splunk
HEC and Elastic bulk endpoints are both known to do — repeats that loss on every batch that
contains it. This is **accepted, not mitigated** (C21): isolating the bad record means either up
to 256 individual `POST`s at a collector that is already failing, or a bisection ladder, and both
make a bad moment worse. The file sink has no equivalent failure mode and is the product's
answer for an operator who needs completeness.

Caller obligations: none beyond `build`'s. While a retry is in flight the queue keeps filling and
may drop; that is the approved Gate 1 policy, not an accident.

Drain: identical to the file sink's, and wrapped in the same
`tokio::time::timeout(Duration::from_secs(5), ..)` — drain the queue, send the final partial
batch, return. The retry ladder is abandoned when that deadline expires: with a three-second
per-attempt client timeout, one batch's worst case is roughly four attempts plus 2.6 s of
backoff, which is longer than the drain window by design. Whatever the deadline cuts short is
dropped and counted like any other drop, which is the approved Gate 1 policy.

Checks: `TP-8`, `TP-9`, `TP-11`.

### `src/http/logging.rs` — existing module, changed

Purpose (unchanged): emit exactly one decision line per request, and a periodic counter summary.

Owns (unchanged): the decision fields, the `Target::of` / `loggable` bounding at
`src/http/logging.rs:198-263`, and `static COUNTERS` at `:284`. `struct Counters` at `:276-282`
is **unchanged** (C13).

#### `decide` — existing, changed body, unchanged signature

Declaration (existing, `src/http/logging.rs:134`):

```rust
pub async fn decide(State(app): State<Arc<App>>, request: Request, next: Next) -> Response
```

Changed behaviour, in order:

1. Before `next.run(request)` at `:144-146`, and in the same block that already calls
   `Target::of` at `:136`, read the peer address — `request.extensions().get::<ConnectInfo<SocketAddr>>()`
   — and keep `Some(addr.ip())` only when `app.config.log_consumer_identification` is true, else
   `None`. This must happen here: `next.run(request)` consumes the request (C15).
2. After the response returns, build a `Decision` from exactly the values the existing
   `tracing::info!` at `:172-186` already renders, plus `consumer`, plus
   `timestamp: delivery::rfc3339(app.clock.now_utc_micros())`. The clock is read here, after
   `next.run(request)` has returned, so the time is when the decision was complete (Gate 2 C48).
3. Render that same `tracing::info!` from the record's fields, with the identical message
   `"request decided"` and identical field names, so an operator who configures nothing sees no
   change (Gate 2 C9). `timestamp` is not named in that call, so it does not appear (C49).
4. `app.delivery.offer(Record::RequestDecided(decision))`.
5. `summarise(elapsed, bytes, error.is_some(), &app.delivery, app.clock.as_ref())`.

Caller obligations: unchanged. Registration at `src/http/mod.rs:70-73` is unchanged.

Checks: `TP-1`, `TP-4`, `TP-6`, `TP-13`, `TP-14`, `TP-18`, `TP-20`.

#### `summarise` — existing, changed signature

Declaration (existing, `src/http/logging.rs:294`): `fn summarise(elapsed: Duration, bytes: u64, was_error: bool)`

Proposed: `fn summarise(elapsed: Duration, bytes: u64, was_error: bool, sinks: &Sinks)`,
shipped in slice 2 at `src/http/logging.rs:349`. **C49 adds a final parameter:**
`fn summarise(elapsed: Duration, bytes: u64, was_error: bool, sinks: &Sinks, clock: &dyn Clock)`.

Changed behaviour: when the window has elapsed, it reads `sinks.drops()` inside the same critical
section it already holds at `:300`, renders the existing `"request summary"` line with two added
fields `dropped_file` and `dropped_siem`, and offers a `Record::RequestSummary` to the sinks, so
drop counts land wherever decision records land (Gate 2 C12). It passes `clock` unread to the
private `close_window`
(`fn close_window(counters: &mut Counters, open_for: Duration, sinks: &Sinks, clock: &dyn Clock) -> Summary`),
which sets `timestamp: rfc3339(clock.now_utc_micros())` on the `Summary` it builds. That line is
the only summary clock read, shared with `flush_summary`. The summary line on
stdout (`emit`) does not name `timestamp` (C49).

Visibility: private, one caller (`decide` at `:188`).

Checks: `TP-7`, `TP-20`.

#### `flush_summary` — proposed

Declaration:

```rust
pub(crate) fn flush_summary(sinks: &Sinks, clock: &dyn Clock) // `clock` added by C49
```

Accepts: the sink set and the application clock. It stamps the final summary from `clock`
through `close_window`, exactly as `summarise` does (C49). Closes the current summary window regardless of how much of it has
elapsed, emits the summary line, offers the summary record, and resets the counters.

Effects: exactly one summary record enters each enabled queue.

Caller obligations: called once, from `Running::shutdown`, **after** the HTTP server join at
`src/lib.rs:257` — so no further records can be produced — and **before** the drain token is
cancelled, so the record is already queued when the sinks begin draining (Gate 2 C12).

Checks: `TP-10`, `TP-20`.

#### `flush_drop_tail` — proposed

Declaration:

```rust
pub(crate) fn flush_drop_tail(sinks: &Sinks)
```

Accepts: the sink set, after every sink task has returned.

Effects: reads `sinks.drops()` one final time and, when either count is non-zero, emits a single
`tracing::warn!` carrying `dropped_file` and `dropped_siem`. Emits nothing when both are zero, so
a clean shutdown stays quiet.

Why it exists: `flush_summary` reads and resets the counters *before* the drain starts, so every
record dropped during the drain window — a write error, a batch abandoned at the five-second
deadline — would otherwise increment a counter nobody ever reads again, silently breaking Gate 1's
promise that a dropped record is always counted and reported (C20).

Caller obligations: called from `Running::shutdown` after `self.tasks.join().await` and before
`drop(self.app)` — the only window in which every sink has finished *and* `App` still exists.

Stated residual: by this point the sinks are gone, so this last line reaches the console only. An
operator running the SIEM sink alone, with the SIEM down, learns of these final drops from stdout
or not at all — the same residual Gate 2 C12 already recorded, now also true of the tail.

Checks: `TP-15`.

### `src/config.rs` — existing module, changed

Five optional keys, each absent-means-off. All five names go into `OPTIONAL_KEYS`
(`src/config.rs:117`), because `#[serde(deny_unknown_fields)]` at `:61` plus `check_keys()` at
`:240` reject any key missing from that list.

Public types (proposed additions to `pub struct Config`, `src/config.rs:21-46`):

```rust
pub log_file_path: Option<PathBuf>,
pub log_file_max_bytes: NonZeroU64,      // effective value; defaulted at validate
pub siem_url: Option<Url>,
pub siem_auth_header: HeaderName,        // effective value; defaulted at validate
pub log_consumer_identification: bool,
```

Proposed additions to `struct RawConfig` (`src/config.rs:60-82`) — the wire shape, where absent
must be representable:

```rust
log_file_path: Option<PathBuf>,
log_file_max_bytes: Option<u64>,
siem_url: Option<String>,
siem_auth_header: Option<String>,
#[serde(default)]
log_consumer_identification: bool,
```

Units and valid states: `log_file_max_bytes` is bytes, defaulting to `100 * 1024 * 1024` when
`log_file_path` is set, and rejected as zero by the existing `nonzero_u64` helper used at
`:192-199`; `siem_auth_header` defaults to `Authorization` when `siem_url` is set;
`log_consumer_identification` defaults to false, which is the product's off-by-default promise.

#### `RawConfig::validate` — existing, changed

Declaration (existing, `src/config.rs:139`): `fn validate(self) -> Result<Config, ConfigError>`

Added rejections, all `ConfigError::Invalid { key, reason }` (`src/config.rs:279-282`), rendered
as ``invalid `<key>`: <reason>`` by the `Display` arm at `:294`, in the same idiom as the
`max_artifact_bytes` vs `cache_max_bytes` rule at `:192-199`:

| Condition | `key` | `reason` |
|---|---|---|
| `log_consumer_identification` true with neither `log_file_path` nor `siem_url` set | `log_consumer_identification` | `requires log_file_path or siem_url, so recorded peer addresses reach a durable destination the operator chose` |
| `log_file_max_bytes` set without `log_file_path` | `log_file_max_bytes` | `has no effect without log_file_path` |
| `siem_auth_header` set without `siem_url` | `siem_auth_header` | `has no effect without siem_url` |
| `siem_url` does not parse as a URL | `siem_url` | `must be a valid URL` |
| `siem_url` scheme is not `https`, and its host is not a loopback address or `localhost` | `siem_url` | `must use https unless the host is loopback` |
| `siem_auth_header` is not a legal HTTP header name | `siem_auth_header` | `must be a valid HTTP header name` |
| `log_file_max_bytes` is zero | `log_file_max_bytes` | `must be greater than zero` |

The first is the one that matters: without it, an operator who turns on consumer identification
but configures no destination starts collecting peer IPs whose only home is the console — which is
durable wherever this firewall actually runs, but is not a destination the operator chose (Gate 2
C11, as corrected by Gate 2 C41 and Gate 3 C35). Its reason string is exactly the one in the
table above, and `TP-5` asserts it in full, not only the key.

Checks: `TP-5`, `TP-6`.

### `src/lib.rs` — existing module, changed

`pub struct App` (`src/lib.rs:52-77`) gains one field:

```rust
pub(crate) delivery: delivery::Sinks,
```

`struct Running` (`:231-240`) gains one field:

```rust
drain: CancellationToken,
```

`App::start` (`:109`) — proposed order, all before the existing `App` struct literal at `:140-150`:
create `drain`, call `delivery::build(&config, drain.clone())?`, move the `Sinks` into the `App`
literal, and pass the returned handles to `tasks::spawn`.

`axum::serve` at `:170-177` — proposed conditional, because
`into_make_service_with_connect_info::<SocketAddr>()` changes the service type, so each branch
must own its complete `axum::serve(..).with_graceful_shutdown(..).await` expression rather than
assigning to one variable:

```rust
let router = http::router(app);
if consumer_identification {
    axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(async move { signal.cancelled().await })
        .await
} else {
    axum::serve(listener, router)
        .with_graceful_shutdown(async move { signal.cancelled().await })
        .await
}
```

`Running::shutdown` (`:255-271`) — proposed order, two statements added between the existing
server join and the existing `tasks.join()`:

```rust
self.shutdown.cancel();                               // existing :256
let served = match self.server.await { .. };          // existing :257-260
http::logging::flush_summary(&self.app.delivery, self.app.clock.as_ref()); // proposed; clock per C49
self.drain.cancel();                                  // proposed
self.tasks.join().await;                              // existing :264
http::logging::flush_drop_tail(&self.app.delivery);   // proposed
drop(self.app);                                       // existing :265
```

This is the whole of Gate 2 C10: the drain begins only after in-flight requests have finished,
however long they took, and the existing drain order is otherwise untouched.

Checks: `TP-3`, `TP-4`, `TP-10`.

### `src/tasks/mod.rs` — existing module, changed

Declaration (existing, `src/tasks/mod.rs:26-30`):

```rust
pub fn spawn(app: Arc<App>, shutdown: CancellationToken, watcher: blocklist_poller::Watcher) -> Tasks
```

Proposed:

```rust
pub fn spawn(
    app: Arc<App>,
    shutdown: CancellationToken,
    watcher: blocklist_poller::Watcher,
    delivery: Vec<JoinHandle<()>>,
) -> Tasks
```

Changed behaviour: the existing `vec![..]` at `:31-38` is extended with `delivery`, so
`Tasks.handles` holds every sink handle and the existing `Tasks::join` at `:46` already awaits
them. The two existing spawns keep the `shutdown` token; the sink tasks were spawned by
`delivery::build` with the **drain** token and are only adopted here.

Visibility: `pub`, one caller (`src/lib.rs:167`).

Checks: `TP-10`.

## Call stack

| Caller -> operation | Value/state passed | Why accepted | Result/failure handling |
|---|---|---|---|
| `main` -> `Config::load` (`src/config.rs:129`) | operator TOML | — | Startup fails with `ConfigError::Invalid` naming the key; `check_config` prints `path: err` and exits FAILURE (`src/main.rs:80-96`) |
| `App::start` -> `delivery::build` | validated `Config`, fresh `drain` token | `RawConfig::validate` has already rejected every combination C11 names, so `build` never sees a meaningless pairing | `StartupError::Delivery` propagates out of `start`; nothing is spawned and nothing serves |
| `App::start` -> `tasks::spawn` | `Arc<App>`, `shutdown`, watcher, delivery handles | Handles come from `build`, which spawned the tasks with the drain token | `Tasks` holds every handle; existing `Tasks::join` drains them |
| axum router -> `logging::decide` (`src/http/mod.rs:70-73`) | `State<Arc<App>>`, `Request` | Registration unchanged | Unchanged response path |
| `decide` -> `request.extensions().get::<ConnectInfo<SocketAddr>>()` | the request, before `next.run` | The extension exists only when the server was built with connect-info, which happens only when the opt-in is on | `None` when absent or when the opt-in is off — the record simply carries no `consumer` field |
| `decide` -> `Sinks::offer` | `Record::RequestDecided` by value | `Sinks` is always present on `App`, empty by default | Returns immediately; a full or closed queue counts one drop |
| `decide` -> `summarise` | elapsed, bytes, was_error, `&Sinks`, `app.clock.as_ref()` (C49) | Called on every request exactly as today (`:188`) | On window close: reads `drops()`, renders the summary, offers `Record::RequestSummary` |
| `Running::shutdown` -> `flush_summary` | `&Sinks`, `self.app.clock.as_ref()` (C49), after the server join at `:257` | No further records can be produced once the server has joined | One summary record enters each queue |
| `Running::shutdown` -> `drain.cancel()` | the drain token | Every producer has finished | Each sink drains to empty or five seconds, then returns |
| `Running::shutdown` -> `flush_drop_tail` | `&Sinks`, after `tasks.join()` and before `drop(self.app)` | Every sink task has returned, so the counters are final, and `App` still exists | One `tracing::warn!` when either count is non-zero; silence when both are zero |
| `decide` -> `app.clock.now_utc_micros()` -> `delivery::rfc3339` | the injected `Arc<dyn Clock>` on `App` | Read after `next.run(request)` returns, so the stamp is the time the decision completed (Gate 2 C48) | Infallible; out of jiff's range falls back to the decimal microsecond count (C49) |
| `summarise` / `flush_summary` -> `close_window` -> `clock.now_utc_micros()` -> `delivery::rfc3339` | the `&dyn Clock` their callers passed, forwarded unread | Callers pass `app.clock.as_ref()`: `decide` for `summarise`, `Running::shutdown` for `flush_summary`. `close_window` is the only summary clock read | The `Summary` carries `timestamp`; the stdout summary line does not |
| sink task -> `drops.fetch_add` | count of records it could not deliver | The counter is an atomic shared with the request path | Next summary window reports it |

## Test plan

| API promise | Caller and input/state | Expected observable result | Planned check and evidence kind |
|---|---|---|---|
| `file::run` appends one NDJSON line per decision | Running app with `log_file_path` set; one package request driven through the real HTTP surface | File holds one JSON object per line whose twelve fields equal the stdout line's | `TP-1`; execution |
| File never exceeds twice the cap | `log_file_max_bytes` set small; enough requests to cross it | `<path>.1` exists; live file is smaller than the cap; both together bounded by twice it | `TP-2`; execution |
| Default configuration opens nothing and connects nowhere | App started from `config.sample.toml` with all five keys absent | `Sinks::is_empty()` is true; no file at any log path; no task spawned for delivery | `TP-3`; execution |
| Consumer identification is off by default, records **the peer's** IP when on, and ignores what the caller claims about itself | Two app runs, opt-in off then on, one request each. The opt-in-on run's client binds a distinct loopback source address via `reqwest::ClientBuilder::local_address(IpAddr::from([127, 0, 0, 2]))` (C31) **and sends `X-Forwarded-For: 203.0.113.9` and a `Forwarded:` header** | Off: no `consumer` field in the record. On: `consumer` equals `127.0.0.2` — the client's own source address — with no port, and neither forwarding header's value appears anywhere in the record or the stdout line. The distinct source is what makes the first half a check: expecting `127.0.0.1` would also pass against a `decide` wired to the server's bind address or to a hardcoded `IpAddr::LOCALHOST`. The forwarding headers are what make the second half a check at all — `docs/operations.md` promises an operator that what is recorded is the peer of the accepted connection and nothing the caller supplies, and **no test in this repository has ever sent a forwarding header**, so that promise was entirely untested (C31, Red Team finding 5) | `TP-4`; execution |
| The three C11 combinations are rejected by name | `Config::from_toml_str` with each combination | `ConfigError::Invalid { key }` naming `log_consumer_identification`, `log_file_max_bytes`, `siem_auth_header` respectively. For `log_consumer_identification` (`TP-5c`) the `reason` is asserted in full as well, equal to `requires log_file_path or siem_url, so recorded peer addresses reach a durable destination the operator chose` — the old string claimed the rejection gives addresses "a destination" when the console already is one, and asserting only the key could not catch that claim returning (C35) | `TP-5`; execution |
| `siem_url` scheme rule | Four URLs: `https://…`, `http://127.0.0.1…`, `http://localhost…`, `http://collector.example…` | First three accepted; the fourth rejected as `ConfigError::Invalid { key: "siem_url" }` | `TP-6`; execution |
| A drop is counted and **surfaced durably**, and the request still succeeds | Both sinks enabled; queue driven full against a collector that never responds | Request returns its normal status; the summary record **read back out of the file sink's NDJSON output** — not merely from captured stdout — carries `dropped_siem` greater than zero while `dropped_file` stays zero. Reading it from the file is the point: Gate 2 C12's claim is that drop counts reach the durable destinations, and a stdout-only assertion would pass even if that were false | `TP-7`; execution |
| SIEM batch shape and optional credential | A `wiremock::MockServer` collector; one run with `OSPREY_SIEM_AUTH` set, one without | Body is newline-delimited JSON, `Content-Type: application/x-ndjson`; header present with the exact value when set, absent when unset | `TP-8`; execution |
| Redirects are not followed | One `wiremock::MockServer` answers `302` pointing at a second one | The second server receives nothing; the batch is counted as dropped | `TP-9`; execution |
| Records from a slow in-flight request survive shutdown | Request still in flight when `shutdown()` is called | Its record is in the file after `shutdown()` returns | `TP-10`; execution |
| The credential never reaches a record, a log line or an error — **runtime path** | `OSPREY_SIEM_AUTH` set to a known sentinel; a forced SIEM failure | Neither the log file nor captured stdout contains the sentinel | `TP-11a`; execution |
| The credential never reaches an error — **startup rejection path** | `OSPREY_SIEM_AUTH` set to a sentinel that fails `HeaderValue::from_str`, e.g. one containing a newline | Startup fails; the `StartupError::Delivery` text and `check_config`'s printed `path: err` name the variable and the reason, and contain no part of the sentinel. This is the path a naive `format!("invalid header value: {value}")` leaks through, and the sensitive-`HeaderValue` control does not cover it | `TP-11b`; execution |
| Every changed file typechecks and lints clean | `cargo clippy --all-targets -- -D warnings` | Zero warnings; this is also what settles C17 | `TP-12`; typecheck |
| Shutdown is bounded even when a sink is wedged, and the final drops are reported | `siem_url` points at a listener that accepts the connection and never responds; records queued; `shutdown()` called | `shutdown()` returns within roughly the five-second drain deadline rather than hanging, and when records were lost in that window a final `tracing::warn!` carries the tail counts. Without the client timeout and the caller-imposed deadline this test hangs, which is exactly what makes it a witness | `TP-15`; execution |
| No inbound-request accessor exists anywhere in the crate, so no client-supplied value can reach a delivered record | `smtc spec run` with `.smtc/analyzers/client-data-reaches-delivery-sink.yaml`, run against the repository and against an unsafe control | Product root: zero findings. Control: the check fires at the `request.headers()` call site. Non-vacuity is proved by a third run — the same call names with the `receiver_type` filter removed, which must match a non-zero number of call sites in the product root; a zero there would mean the search itself is dead | `TP-14`; retained analyzer spec |
| An unopenable `log_file_path` fails startup when peer IPs would be collected, and only then | Two cases, both with `log_file_path` inside a directory that does not exist. (a) `log_consumer_identification` on; (b) the opt-in off | (a) `App::start` returns `StartupError::Delivery`; nothing serves; the text names the configuration key and the reason and contains no peer address. Fails today: the app starts cleanly and collects peer IPs while dropping every record. (b) `App::start` succeeds, a request is served normally, and exactly one `tracing::error!` names the key. Case (b) is what stops the narrowing from silently regressing to fatal-for-everyone (C28, C39) | `TP-16`; execution |
| The decision log file is not readable by other local users, and a pre-existing permissive file is not silently inherited | Four cases. (a) Running app with `log_file_path` set, one request; (b) the same after a forced rollover; (c) a file pre-created `0o644` before the app starts, one request; (d) `App::start` returns, and **no request is sent and shutdown has not begun** | (d): the file exists at mode `0o600`. This is the only case that witnesses the startup probe's create verb — `Writer::open` also creates the file lazily at `0o600` on the first record, so cases (a)–(c) would pass even if the probe created nothing (C36). (a) and (b): `std::fs::metadata(..).permissions().mode() & 0o777` equals `0o600` for the live file and for the `.1` generation. Fails today: the file is created `0o666 & ~umask`. (c) the mode is left at `0o644` — the process does not re-chmod a file it did not create — and exactly one `tracing::warn!` names the path and the mode. Case (c) is the one that matters for every deployment already running slices 1–2, and the first two cases structurally cannot see it, because they only exercise files the process created itself (C27) | `TP-17`; execution |
| The `request.extensions()` route stays guarded, with exactly one approved reader | `smtc spec run` with `.smtc/analyzers/consumer-identity-extension-read.yaml` against the repository, its result asserted by `jq -e` because the engine has no expected-count field | The run exits 0 against a three-part assertion: `.ok == true`, exactly one finding, and that finding's file ending in `/src/http/logging.rs`. All three are needed — `.ok` catches a refused run reported as an empty finding list, the count catches a second read appearing, and the filename catches deleting the approved read and adding an inbound-extension read in a *different* file, which leaves the count at 1. The path test is `endswith`, not equality, because the engine returns an absolute path that varies with the checkout location. **No line number is asserted**: the spec has no line predicate, so a line drift is stale prose, and asserting a line would invent a maintenance trap that does not exist. The name list covers `extensions` and `extensions_mut`; adding the latter was verified free, still exactly one finding (C29) | `TP-18`; retained analyzer spec |
| Records cut off by the file drain deadline are counted, not lost silently | A unit test inside `src/delivery/file.rs` (`#[cfg(test)]`, because `drain` is private): 10,000 records queued on a fresh channel with capacity for all of them, a `Writer` on a temporary path, `drain(.., Duration::ZERO)` awaited (C46) | (1) Lines in the file < 10,000, asserted first with the message `inconclusive: no cut-off happened`. The zero deadline fires at tokio's next millisecond tick, and about 8 records fit in that tick here. (2) Lines + `drops` is 10,000 or 10,001, the one-high residual. Before the fix, `drops` stays 0 while lines < 10,000, so (2) fails. Measured pre-fix: 8 written, 0 dropped | `TP-19`; execution |
| Every delivered record states when it was made, from the injected clock, in fixed-width UTC RFC 3339; stdout gains no field (Gate 2 C48, C49) | `TestServer::start_with(config, clock.shared())` with `clock = TestClock::at_rfc3339("2026-09-21T14:13:20.120000Z")`, `log_file_path` set, and `siem_url` pointing at a `wiremock::MockServer` answering `200`. Send one request to `PACKAGE`, then `clock.advance_seconds(60)`, then `shutdown()` | The file's `request_decided` record has `timestamp == "2026-09-21T14:13:20.120000Z"`. Its **last** `request_summary` record, the one `flush_summary` built at shutdown, has `timestamp == "2026-09-21T14:14:20.120000Z"`. The `request_decided` record in the collector's received body has the same timestamp as the file's. The advance proves the summary reads the clock when it is built and does not copy the decision's time. `.120000` proves the width is fixed, because plain `Display` would print `.12Z`. Reading the injected clock rather than `SystemClock` is what makes an exact string possible. The stdout side is `TP-13`, unchanged: its key set still has no `timestamp`. Fails today: neither record has a `timestamp` key | `TP-20`; execution |
| The stdout decision line does not drift | A new assertion that parses the emitted JSON decision line and compares its **complete key set**, not selected substrings | Exactly the twelve field names emitted today while the opt-in is off, thirteen with `consumer` when it is on — no key renamed, added or missing, and the message still `"request decided"`. The existing `assert_decided` stays green as a weaker regression guard, but it checks only three substrings and cannot catch a renamed `method`, `bytes` or `blocklist_revision` on its own, which is why this check is new rather than inherited | `TP-13`; execution |

`TP-14` needs an unsafe control that the check demonstrably fires on, kept outside the product
root — otherwise the product run's zero is indistinguishable from the check being broken. The
fixtures that validated the spec were deleted after validation, so the slice that runs `TP-14`
materialises its control into a temporary directory as part of the witness command rather than
committing a deliberately-unsafe Rust file into this repository. Gate 4 supplies that command.

`TP-8` and `TP-9` need a local HTTP collector. `wiremock` is already a dev-dependency
(`Cargo.toml:87`) and `tests/common/mod.rs:900-923` uses `wiremock::MockServer` to stand up a
fake registry. That helper itself is bound to `Transport`/`OriginSet` and is the wrong shape
here, so the SIEM checks call `wiremock::MockServer::start()` directly — reuse of the crate the
repository already depends on, not a new one.

`TP-18` adds one tool the earlier checks do not use, `jq`, because `smtc spec run` reports a
finding count and has no expected-count field, so the pass condition of exactly one has to be
asserted by the runner rather than by the engine. It resolves at `/usr/bin/jq`, and the assertion
command was executed against the current tree and exited 0 before this document was written.

**How the operator-documentation changes are checked.** They are prose with no executable
witness. Slice 3's row enumerates them as items (a)–(e) under `docs/operations.md`, including the
stale "stdout is not durable" sentence (`docs/operations.md:432`) and the four-destination purge
bullet (`:518` onward). `sf-verification` checks each enumerated item against the file as part of
the slice's completion, and `sf-security-review` checks that the privacy statements match what
the code does. This is weaker than an executable check and is stated as such.

Commands come from what the repository actually uses (`README.md:23`, `README.md:71-75`): debug
`cargo test` and `cargo clippy --all-targets -- -D warnings`. Gate 2 recorded that
`cargo test --release` is self-reported as never green and that there is no CI, so no witness
depends on either. Gate 4 assigns these checks to slices and supplies exact commands.

## Invariants & spec dispositions

- **"Nothing a client sends reaches a log line"** (`src/http/logging.rs:14`) — load-bearing, repeated, and put at direct risk by this feature, which for the first time takes a per-connection value into the record and ships it off the machine. Disposition: **spec authored and kept**, at `.smtc/analyzers/client-data-reaches-delivery-sink.yaml`. `sf-spec-authoring` found no existing analyzer in the repository (`.smtc/analyzers/` did not exist) and judged the candidate neither one-off nor low-risk.

  **Corrected after slice 1, which is the first run that could mean anything.** The spec was originally authored as a `taint_query` over header/body-reading sources reaching `Sinks::offer`, and this document previously claimed it discriminates. That claim was false, and only synthetic fixtures had ever tested it. Its first run against the real repository returned a finding on clean code, because the source globs are bare names with no directionality and matched the opposite of client input: `response.headers()` on **our own outbound response** (`src/http/logging.rs:153,157`, read to compute the `bytes` field), `response.headers()` in the **upstream registry client** (`src/upstream/reqwest_transport.rs:214,234,236`), and `into_bytes()` on markup this process rendered (`src/pypi/render.rs:94,134`).

  The repair established a capability limit worth recording: in this SMTC build every discrimination lever for `taint_query` is a no-op — `receiver_type`, `package`, `scope.files` and `sanitizers` — confirmed against the engine source and empirically, by passing a filter value engineered to match nothing and getting an unchanged finding. Backward taint is function-granular, so `decide()` is marked tainted merely for containing both a `body()` call and a path to `offer`. Forward taint returns a clean zero but has a **proven false negative on the exact breach shape this spec exists to catch** — a header bound to a named local, used, then moved into an enum-wrapped `offer` call, which is literally what `Decision` / `Record::RequestDecided` does here. No `taint_query` configuration satisfies both "zero on clean code" and "fires on the realistic breach".

  The kept spec is therefore a **`structural_pattern` forbidden-call inventory, not a reachability proof**: it fires if a call named `headers`, `body`, `into_body`, `to_bytes` or `from_request*` appears anywhere in the crate with a receiver matching `request|req|parts`. It never traces the value, so the dataflow shape that defeated forward taint is irrelevant to it. `structural_pattern`'s `receiver_type` filter is real code, unlike `taint_query`'s — verified to return `request.headers()` and `response.headers()` separately on a two-call fixture before being trusted. What it gives up: it does not prove the call reaches `offer`, so an unrelated inbound read elsewhere in the crate would also trip it. That over-banning bias is deliberate and correct for a guard on an invariant this repository has held since it was written.

  **Corrected again after slice 3's security review, which found the inventory incomplete (C29).** This document and the spec's own prose both claimed the check "fails the moment an inbound-request accessor call site exists anywhere in this repository, full stop." That was false. `extensions` is not in the call-name list, and slice 3 added `request.extensions().get::<ConnectInfo<SocketAddr>>()` at `src/http/logging.rs` — an inbound-request accessor feeding straight into the delivered record. Slice 3's own Gate 4 note that "slice 3 added no inbound accessor" was therefore wrong: it added one the spec could not see.

  The unguarded breach shape is concrete rather than theoretical. The request extension map is the standard place a tower/axum layer deposits a header-derived value, so an `axum-client-ip`-style layer — or one `request.extensions().insert(..)` in middleware parsing `X-Forwarded-For` — read back with exactly the shape slice 3 legitimised would put caller-controlled, caller-**spoofable** data into every record shipped to the collector, with the guard silent. `X-Forwarded-For` and `User-Agent` were rejected at Gate 2 C7 and must stay rejected. No current exploit exists: `request.extensions()` is read exactly once in all of `src/`, and only for `ConnectInfo<SocketAddr>`.

  Disposition: a **second retained spec**, `.smtc/analyzers/consumer-identity-extension-read.yaml`, whose pass condition is **exactly one finding, at `src/http/logging.rs`** rather than zero (`TP-18`). Authored and validated by an isolated `sf-spec-authoring` dispatch: `structural_pattern`, `calls.name: ["extensions", "extensions_mut"]` (`extensions_mut` added by C38), `receiver_type: ["request|req|parts"]`. Product root returns exactly one finding, at `src/http/logging.rs`; an unsafe fixture holding a second inbound-extension read — a header-derived `ClientIp` read back into a `Decision`, which is the breach shape — returns two, so the count demonstrably moves. The receiver filter is live rather than matching nothing: removing it returns two findings in the product root, the approved `request.extensions()` plus the outbound `response.extensions()` the filter is there to exclude. The sibling spec's matching keys were not touched and its product-root run returns the identical `0 finding(s)`, `matched: 0, filtered: 0` before and after the prose correction. Adding `extensions` to the sibling spec was rejected — it would fire on the one approved read and destroy that spec's zero-findings pass condition, and this SMTC build is not confirmed to offer any suppression or allowlist key. Putting the exception in the pass condition costs no engine feature and keeps both signals unambiguous: the sibling stays at 0, this one stays at 1, and either number moving is the alarm.

  **`TP-18` has a fourth hole its assertion cannot close, and no conjunct will close it.**
  Same-file substitution: delete the approved read and add a different inbound-extension read
  inside `src/http/logging.rs`. The count stays 1, the filename still matches, `.ok` is still
  true, and the engine's output for a finding — file, line, severity, and a summary reading
  `'request.extensions'` — cannot distinguish the approved read from a substituted one. Neither
  `TP-13`'s key-set assertion nor `TP-4` would necessarily catch it either. What covers this is
  not the spec: it is `TP-4` sending `X-Forwarded-For` and `Forwarded` and still asserting
  `127.0.0.2`, which tests the property directly rather than the call site's shape. That is why
  the forwarding-header case was added to `TP-4` rather than a fourth conjunct to `TP-18`.

  **Field access is invisible to both specs.** They match method *calls*. A future edit reading
  `parts.extensions` as a struct field rather than calling `.extensions()` trips neither. This is
  recorded rather than fixed: `structural_pattern` is a call-site inventory by construction.

  **What neither spec proves, stated because the previous claim was too strong.** These are tripwires for two shapes — the direct inbound accessor read, and the extension-map read — not proofs of the invariant. And the invariant was already an approximation before slice 3 touched it: `package` and `version` have always been derived from the client-supplied request-target path, bounded by `loggable` but client-supplied all the same. "Nothing a client sends reaches a log line" has always meant "no client-supplied *header, body or connection* value reaches one". That is still worth guarding — it is the property whose reversal is a privacy decision — and it should not be described as more.

  **That precise statement has to live where a maintainer will meet it.** It is written here, in a gate document no maintainer opens, while `src/http/logging.rs:14` still states the flat and now-inaccurate version: "Nothing a client sends reaches a log line." Slice 3 carries the corrected sentence into that module doc, naming the narrower guarded property and the two specs that guard it. The file is already in the slice's list, so this costs nothing and is the only place the correction actually reaches its audience.
- **Delivery never blocks the request path** — enforced by the type system rather than a spec: `Sinks::offer` is a non-`async` function that takes no lock and performs no I/O, so a blocking call cannot be added to the request path without changing a signature that this document fixes. No spec authored: the compiler already owns it.
- **Sink tasks watch the drain token, never the `shutdown` token** — one-off, enforced by `delivery::build`'s signature, which accepts exactly one token and is called exactly once. No spec authored.
- **The credential never reaches a record, a log line or an error** — covered by `TP-11` plus `HeaderValue::set_sensitive(true)`, which redacts it in `Debug`. No spec authored: one call site, one env read, and an execution check that fails loudly.
- **The SIEM client ignores proxy environment variables, like the upstream client** (C43). This is one-off: a single builder call. `sf-code-review` checks it against `src/upstream/reqwest_transport.rs:101`. No spec authored.
- **Every time reading goes through the injected `Clock`** (`src/clock.rs:8-9`). C49 reads it at exactly two sites: `decide` for decision records, and `close_window` for every summary, periodic and final. `TP-20` fails if either site reads `SystemClock` or `jiff::Timestamp::now()`, because the expected strings come from a `TestClock`. One residual has no execution witness. `summarise` could forward some other `&dyn Clock`, such as `&SystemClock`, in place of the one it receives. The periodic window runs on a real `Instant` with a 60 s default, and its only setter, `set_summary_window`, is process-global. Code review checks that `summarise` forwards its own parameter. No spec authored: the rule is not new, an execution check covers both read sites, and the residual is one argument.
- **Configuration keys are registered in three places** — an existing check owns it: `#[serde(deny_unknown_fields)]` at `src/config.rs:61` and `check_keys()` at `:240` reject an unregistered key at load time, and `TP-5`/`TP-6` exercise the path. No spec authored.

## Threat model

Produced by the `sf-threat-model` lens inside an isolated `sf-red-team` review of this design,
against Git base `0f50cec6d526773abec4b4897f64afc10992a8ae`. It models the **plan**; implemented
source gets an independent Security review once the code exists. Four of its findings changed
this document — C19, C20, C21 and the split of `TP-11` — and the table below reflects the design
as it now stands, not as it was reviewed. Reassessed after the Gate QA revision round:
strengthening `TP-13` and correcting one type name changed no decision, interface, dependency or
risk, so no further Red Team round was triggered. The 2026-09-22 reopening (C42, C43) also
triggered none. C42 closes an already-modelled threat, T-DROP-BLACKOUT, with a counting rule whose
mechanism is checked against tokio 1.53.1's own source: `Receiver::len`, and `Timeout::poll`
polling the inner future before the delay. C43 removes an egress path and adds none. The later 2026-09-22 reopening (C46) changes only the form of `TP-19`, a test, and triggered none: it adds no behaviour, trust boundary or decision with material uncertainty, and its mechanism is measured evidence rather than a claim. The 2026-09-22 revision for Gate 2 C48 (C49) also triggered none. It adds one field whose value comes from the process's own clock, so it adds no entry point, trust boundary, destination or input. The one thing it touches is the content of A2. Once consumer identification is on, a delivered record now pairs a peer IP with the time of the request. That was the point of Gate 1's P-WHEN promise, and it is already covered by T-PEER-IP-RETENTION's accept (Gate 1 C1), whose operator documentation this revision extends. The existing file and SIEM destinations already held records in delivery order, which gives an approximate time anyway.

**Scope.** The proposed delivery path: record construction in `decide`, the sink set, both sink
tasks, the configuration surface, and the shutdown drain.

**Entry points.** The peer TCP connection (`ConnectInfo<SocketAddr>`), sole source of `consumer` ·
the operator's configuration file, five new keys · the environment variable `OSPREY_SIEM_AUTH` ·
the SIEM collector's HTTP responses, which are externally controlled once `siem_url` is set and
are consumed as retry/drop control input.

**Trust boundaries.** B1 network peer → process · B2 process → local filesystem · B3 process →
operator's collector over HTTPS with a credential attached · B4 process environment → in-memory
`HeaderValue` · B5 collector response → the firewall's own control flow.

**Assets.** A1 decision records · A2 peer IP addresses, privacy-sensitive when the opt-in is on ·
A3 the `OSPREY_SIEM_AUTH` credential · A4 request-path latency and shutdown promptness ·
A5 drop-count accountability · A6 bounded local disk use.

| ID | Property | Concrete mechanism | Asset | Planned location | Severity | Mitigation | Verification property | Design evidence | Tier |
|---|---|---|---|---|---|---|---|---|---|
| T-SHUTDOWN-HANG | Availability | reqwest's async client has no default timeout; an in-flight `POST` to a collector that accepts the connection and never answers outlives the drain deadline and hangs `tasks.join()` indefinitely | A4 | `delivery::build`, `siem::run` | Blocker, now mitigated | Client `.timeout(3s)` and `.connect_timeout(1s)`, plus each drain loop wrapped in `tokio::time::timeout(5s, ..)` so the deadline is imposed by the caller (C19) | `shutdown()` returns within roughly five seconds against a listener that never responds | `delivery::build` Effects; `file::run` / `siem::run` Drain; `TP-15` | design-fixed, grounded |
| T-DROP-BLACKOUT | Accountability | `flush_summary` reads and resets the drop counters before the drain starts; anything dropped during the drain window increments a counter nobody reads again | A5 | `Running::shutdown`, `flush_summary` | Blocker, now mitigated with a stated residual | `flush_drop_tail` after `tasks.join()` emits the final counts (C20). Records a sink's own drain deadline cuts off are counted before the task returns: the SIEM sink through its `Unsent` guard (slice 2), the file sink through `drain` (C42, `TP-19`). Residual: the sinks are gone by then, so that line reaches the console only | A record dropped strictly after `flush_summary` is still reported before the process exits | `flush_drop_tail`; `TP-15`; `01-product.md` C2 | design-fixed, grounded |
| T-BATCH-POISON | Integrity | One record a collector rejects with a non-429 `4xx` drops the whole 256-record batch; a recurring record shape repeats that loss on every batch containing it | A1 | `siem::run` failure and retry | Major | **Accepted, owner: product** (C21). Isolation costs up to 256 `POST`s at an already-failing collector, or a bisection ladder. The loss is counted, and the file sink is the answer for operators needing completeness | Drop counts reflect the full batch size, so the loss is visible even though it is not prevented | `siem::run`; `## Least confident decisions` 5 | accepted, plausible-not-witnessed |
| T-CRED-STARTUP-LEAK | Confidentiality | `OSPREY_SIEM_AUTH` failing `HeaderValue` validation raises an error on a path where no sensitive `HeaderValue` exists — only the rejected string. A naive `format!("invalid header value: {value}")` prints it into `check_config` output and the startup log | A3 | `delivery::build` Rejects; `src/main.rs:80-96` | Major, now mitigated | The error contract fixes the text to the variable name and a fixed reason, never the value | Startup output for an invalid credential contains no part of it | `delivery::build` Rejects; `TP-11b` | design-fixed, grounded |
| T-CRED-RUNTIME-LEAK | Confidentiality | The credential surfacing through a reqwest error or `Debug` path during a failing `POST` | A3 | `siem::run` | Minor | `HeaderValue::set_sensitive(true)`; no request or response body is ever logged | No sentinel credential appears in the log file or stdout after a forced failure | `siem::run`; `TP-11a` | witnessed-by-check |
| T-CRED-CONFIG-DEBUG | Confidentiality | `Config` derives `Debug` (`src/config.rs:20-21`), so any `{config:?}` anywhere prints every field it holds | A3 | `src/config.rs` | Minor | The credential is never placed on `Config`; only the header *name* is | No configuration field holds a credential value | `delivery::build` Effects | design-fixed, grounded |
| T-REDIRECT-EGRESS | Confidentiality, integrity | A compromised or malicious collector redirects delivery traffic, credential attached, to an unvalidated host | A1, A3 | `siem::run` | Informational, mitigated | `redirect::Policy::none()` (Gate 2 C4) closes the channel outright | A `302` from the collector reaches no second host and the batch is counted as dropped | `02-architecture.md` C4; `TP-9` | witnessed-by-check |
| T-PEER-IP-RETENTION | Privacy | Peer IPs written to the file, its `.1` rollover, the SIEM **and the console/journal** have no purge path; turning the opt-in off erases nothing already recorded | A2 | both sinks **and the console destination**, indefinitely | Informational, accepted | **Accepted, owner: product** (Gate 1 C1). No technical control; transferred to operator documentation | The operator documentation states what is recorded, what it costs behind a proxy, that nothing is purged, **and names all four places an address can persist** — the omission of the fourth is what T-CONSOLE-JOURNAL-DESTINATION corrects | `02-architecture.md` Constraints; `01-product.md` C1 | accepted, grounded; destination list corrected at the Gate 3 reopening |
| T-CONSOLE-JOURNAL-DESTINATION | Privacy | `consumer` is rendered into the stdout decision line (`src/http/logging.rs:229`) as well as into the record — an approved Gate 2 C9 decision. This plan states in three places that stdout "is not durable" (`docs/operations.md:432`, Gate 2 C11, and T-SILENT-DESTINATIONLESS-COLLECTION's own mechanism text) and treats it as a non-destination. That premise is false in the deployments a package firewall actually runs in: `src/main.rs:58-63` writes JSON to stdout, which under systemd is journald's persistent journal — readable by `systemd-journal`, commonly `adm` by ACL — and under Docker or Kubernetes is a node-level file shipped by a cluster log agent. Peer IPs therefore reach a durable, third-party-readable destination that nobody modelled, permissioned or documented, **whether or not the C11 rejection fires** | A2 | `http::logging::decide`, `src/main.rs` subscriber, and every operator deployment | Major, partly accepted | The plan hardens one destination to `0o600` while this one streams continuously; no technical control is proposed for the journal, because its permissions and retention belong to the host, not this process. Mitigation is honesty: the operator documentation names the console as a fourth place addresses persist, the purge guidance covers it, and the C11 reason string stops claiming the rejection gives addresses "a destination" when they already have one | The operator documentation's purge bullet names four destinations, not three, and the `log_consumer_identification` rejection reason claims only what it delivers — a second, operator-chosen destination | `## Threat model` A2; `docs/operations.md` purge bullet; `src/config.rs` C11 reason string | found by Red Team at the Gate 3 reopening, **by refuting this document's own explanation of the first three misses** |
| T-INVARIANT-FIRST-BREACH | Integrity | `consumer` is the first per-connection value ever admitted to a decision record, and the first record content to leave the machine — so a later edit adding a header-derived field would now export it, not merely print it | A1 | `http::logging::decide`, `delivery::Decision` | Informational, tracked | The retained analyzer spec `.smtc/analyzers/client-data-reaches-delivery-sink.yaml`, which fires on a `headers` / `body` / `into_body` / `to_bytes` / `from_request*` call site and stays silent on the outbound-response, upstream-client and URI-derived reads this crate actually performs. **It does not cover `extensions`** — see T-EXTENSION-ROUTE, which owns that gap | Product root returns zero findings, with the receiver-filter-removed run matching a non-zero number of call sites to prove the search is live | `## Invariants & spec dispositions`; `TP-14` | spec-backed, verified non-vacuously at slice 1; coverage claim corrected at slice 3 |
| T-EXTENSION-ROUTE | Integrity, privacy | The request extension map is the idiomatic place a tower/axum layer deposits a header-derived value. An `axum-client-ip`-style layer, or one `request.extensions().insert(..)` in middleware parsing `X-Forwarded-For`, read back with exactly the shape slice 3 legitimised, puts caller-controlled and caller-**spoofable** data into every record shipped to the collector. The sibling spec's call-name list has no `extensions`, so the guard stays silent — and slice 3 made this route idiomatic in this file | A1, A2 | `http::logging::decide` | Major, mitigated | A second retained spec, `.smtc/analyzers/consumer-identity-extension-read.yaml`, with a pass condition of exactly one finding at `src/http/logging.rs` (C29). No current exploit: `request.extensions()` is read once in all of `src/`, only for `ConnectInfo<SocketAddr>` | The product root returns exactly one finding and a fixture with a second inbound-extension read returns two or more, proving the count moves | `## Invariants & spec dispositions`; `TP-18` | found by post-implementation Security at slice 3; **absent from the pre-implementation model** |
| T-LOGFILE-WORLD-READABLE | Confidentiality, privacy | The decision log is created `0o666 & ~umask` — 0644 under a normal umask — and the `.1` rollover inherits it. With the opt-in on, every unprivileged local user and every other process on the host can read a complete record of which IP asked for which package, when. The pre-implementation model named B2 as a trust boundary and A2 as an asset but modelled no threat across them | A1, A2 | `delivery::file.rs` `Writer::open`, and the startup open in `build` | Medium, mitigated | `.mode(0o600)` on every open that may create the file (C27). Documentation-only was rejected: the unsafe state is the default and silent. A file that already exists — every deployment running slices 1–2, or a target a local user pre-created or symlinked — keeps its mode, and `file::run` emits one `tracing::warn!` when `mode & 0o077 != 0` (C37) | A file produced by a running app, and its `.1` generation, both report mode `0o600`; the probe alone creates the file at `0o600` before any request; a pre-created `0o644` file keeps its mode and produces exactly one warning | `file::run` Effects; `TP-17` cases (a)–(d) | found by post-implementation Security at slice 3; **absent from the pre-implementation model** |
| T-SILENT-DESTINATIONLESS-COLLECTION | Privacy, accountability | The `log_consumer_identification` rejection checks that a sink **key** is present, not that a destination exists. With `log_file_path` pointing into a directory that does not exist or is not writable by the service user, the process starts cleanly, collects a peer IP on every request, and drops every record — data acquired for no stated purpose, which is the exact state that rejection exists to refuse. A path typo is the realistic trigger. (The earlier mechanism text here said the addresses reach "the console the product calls non-durable"; that premise is false — see T-CONSOLE-JOURNAL-DESTINATION) | A2, A5 | `RawConfig::validate`, `delivery::build` | Low severity, high likelihood; **mitigated for the file sink only** | The startup probe in `build` closes the file-sink case (C28). A key-presence check structurally cannot reach it, because the key is present and merely wrong. **Three residuals are not closed and are not claimed to be:** a SIEM-only deployment passes C11 and `build` never contacts the collector, so an unresolvable host or a permanently-`403`ing collector reproduces the identical state indefinitely; the file sink can enter it *after* startup when the volume is unmounted, fills, or the file is deleted; and neither is detectable at startup by construction | With `log_consumer_identification` on, an app configured with an unopenable `log_file_path` fails at startup rather than serving; with it off, the app serves and logs one error (C39). The three residual states remain reachable and are named in the operator documentation and in `## Least confident decisions` 9 | `delivery::build` Rejects; `TP-16` | found by post-implementation Security at slice 3; **absent from the pre-implementation model**; coverage claim narrowed by `sf-red-team` at the Gate 3 reopening, finding 3 (the claim "mitigated" was true of the file sink only) |
| T-CLONE-COST | Availability | `Sinks::offer` clones the record's owned fields once when both sinks are enabled | A4 | `Sinks::offer` | Informational, accepted | **Accepted, owner: engineering** (Gate 2 C8), the priced cost of independent pipelines. Synchronous, no I/O, no lock | The request path holds no `await` and no new lock | `02-architecture.md` C8 | accepted, grounded |

**Four entries were added after implementation, and the model was wrong to omit them.** Slice 3's
independent Security review returned `FIX FIRST` and produced T-EXTENSION-ROUTE,
T-LOGFILE-WORLD-READABLE and T-SILENT-DESTINATIONLESS-COLLECTION. The Red Team review of *this
revision* then produced a fourth, T-CONSOLE-JOURNAL-DESTINATION, by attacking the explanation
offered for the first three.

**The first explanation given here was wrong, and replacing it matters more than the four rows.**
This paragraph previously claimed the misses shared a shape — that each concerned the
*consequences* of a value existing, while the model was organised around the value's *path
through the design*. T-CONSOLE-JOURNAL-DESTINATION refutes that directly: stdout is squarely on
the value's path, step 3 of `decide`'s changed behaviour and an approved Gate 2 C9 decision, and
the model still did not inventory it as a destination for A2.

The actual shape is narrower and worse. **The asset inventory enumerated only the destinations
this feature adds** — the file sink and the SIEM sink — and silently scoped out the destination
that already existed, because it was already there. That is not a lens problem, it is a
scope-of-inventory problem, and it predicts a different class of miss than the comfortable story
did: it predicts one anywhere this feature changes the *contents* of something pre-existing
without the model re-inventorying that thing. `consumer` on the stdout line is exactly that, and
the model treated the line as unchanged infrastructure rather than as a destination whose payload
had grown.

Recorded here rather than only in the slice's proof line because the model is what a later slice
reads, and because a reader who inherits the first explanation will reproduce the mistake. Gates 3
and 4 were reopened for these (C30).

**Limitations.** Nothing in the original model was executed: none of this code existed at the
base commit, so every entry except the four above is derived from the design text cross-checked
against `evidence/repository-structure.md`. The four post-implementation entries are Structural
rather than reproduced: the Security review was read-only, so it configured no unwritable path
and stat-ed no file it had produced. SMTC's taint engine returned Stub/Lossy output on this
workspace and contributed nothing to them; they rest on a complete caller set plus an exhaustive
`src/` accessor search.
T-BATCH-POISON's realism rests on general collector behaviour (Splunk HEC and Elastic bulk
answering a generic `400` to throttling conditions), not on a named collector tested here.
reqwest's no-default-timeout behaviour, which T-SHUTDOWN-HANG turns on, was confirmed against
current reqwest documentation rather than assumed. Every entry assumes the design is implemented
literally; the post-implementation Security review is what checks that assumption against source.

## Least confident decisions

1. **Always building the `Decision` record, even with no sink enabled** (C14). It costs two small allocations per request on the default path to keep one rendering path. The alternative — build the record only when a sink exists, and keep today's direct `tracing::info!` otherwise — is faster for operators who configure nothing, which is most of them, at the price of two code paths that must stay field-identical forever.
2. **The conditional `axum::serve` branch** for connect-info. Gate 2 chose "enabled only when the opt-in is on". Always enabling `ConnectInfo` and gating only the recording would be one code path instead of two, and the peer address never leaves the process unless the opt-in is on. This is worth overruling now if the duplicated `serve` expression looks worse than an always-present extension.
3. **Drop counters as atomics rather than fields on `Counters`** (C13). It shrinks the change and keeps a sync mutex out of the async sink tasks, but it does refine a mechanism Gate 2 wrote down, and it means drop counts are not reset by the same statement that resets the other counters.
4. **No `BufWriter` on the file sink** — one `write_all` per record, so one syscall per request at steady state. Simple and immediately durable for a tailing operator; the queue already absorbs the latency. If throughput ever matters this is the first thing to batch.
5. **Non-retryable `4xx` drops the whole 256-record batch, and this is accepted rather than fixed** (C21). One rejected record costs up to 255 good ones, and a recurring record shape repeats that loss on every batch containing it — realistic against collectors that answer a generic `400` to throttling. Isolating the bad record costs a burst of up to 256 `POST`s at an already-failing collector, or a bisection ladder. If you would rather pay that cost than lose batches, this is the decision to overrule.
6. **One rollover generation only** (`<path>.1`). An operator who wants history configures their SIEM, which is the product's actual answer to retention.
7. **The final drop tail reaches the console only** (C20). `flush_drop_tail` reports what was lost during the drain, but by then the sinks have returned, so those last counts cannot be delivered durably. A SIEM-only operator whose SIEM is down learns of them from stdout or not at all. The alternative — keeping a sink alive specifically to carry its own failure report — buys a guarantee that a wedged sink still cannot honour.
8. **A pass condition of exactly one finding** (C29). `TP-18` passes at 1, not 0, because the one approved `request.extensions()` read is the thing being excepted. It is the cheapest exception mechanism available — it needs no engine feature — but it carries two costs a reviewer should weigh. It is positional in a way a zero is not: an innocent refactor that splits `decide`, or that moves the read into a helper, changes the count or the file and fails the check for a reason that is not a breach. And **the engine does not enforce it** — `smtc spec run` reports a count and has no expected-count field, so nothing but the witness command and the spec's own prose knows that 1 is the pass and 0 would be just as wrong as 2. A reader who treats a finding as a failure by reflex will "fix" this spec by silencing it. The alternative is amending the sibling spec's prose to name the gap and accepting the residual with no automated guard at all. If the false alarms outnumber the value, this is the decision to overrule.
9. **Making an unopenable log path fatal at startup, but only with the opt-in on** (C28, C39). It converts silent collection-without-destination into a loud failure, and limits that to the one configuration where a privacy harm exists. Residual costs: a deployment whose log directory appears after the service does — an init system, a late mount, a container volume — crash-loops when the opt-in is on; `check_config` reports such a configuration as valid (C40); and the probe covers only the file sink at startup. A SIEM-only deployment with an unreachable or permanently-rejecting collector, and a file sink whose volume disappears after startup, both reach the same collect-and-drop state and are detectable only through the drop counters.
10. **`0o600` with no `cfg(unix)` guard** (C27). One line, correct on the platform this product targets, and it makes the crate fail to compile anywhere non-Unix. That is an acceptable trade only while Linux is the only target; a `cfg` guard is the fix if that ever stops being true, and it is cheap to add later.
11. **Three seconds per SIEM attempt, five seconds of drain** (C19). Both numbers are chosen, not derived. A collector that habitually takes four seconds to answer will see every attempt time out and every batch dropped, and the symptom will look like a rejecting collector rather than a slow one.
12. **The timestamp is a pre-rendered `String`, not a `jiff::Timestamp`** (C49). Serialising a `jiff::Timestamp` directly would need jiff's `serde` feature, which `Cargo.toml:52` does not enable, and plain `Display` would trim the fraction. A `String` costs one allocation per record, fixes the width, and keeps the serialised form written down in one function. The out-of-range fallback emits digits instead of a date, the same trade `src/main.rs:109-111` makes. It is unreachable with the production clock.
