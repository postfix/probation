# Threat model — Gate 2, rated-load-guard

Source: sf-threat-model, 2026-09-23. Verdict: MODELED.

## Verdict: MODELED

Every in-scope boundary is accounted for; every retained threat carries a concrete mitigation and a verification property. One material design defect is recorded (T1) — it is a defect in the plan, not a gap in my knowledge of it, and it has a named fix.

---

## Scope

Exactly the five surfaces named: the `/health/delivery` route, the two budget keys, the byte→record conversion, the shedding state, and the `test-support` load-driver seam. No source analysis of proposed code — none exists. Evidence is the approved Gate 1/Gate 2 packet plus the cited repository lines, which I read directly at `/home/john/go/src/github.com/postfix/osprey/src/delivery/mod.rs`, `/src/delivery/file.rs`, `/src/delivery/siem.rs`, `/src/http/health.rs`, `/src/http/mod.rs`, `/src/http/logging.rs`, `/src/http/error.rs`, `/src/config.rs`, `/Cargo.toml`.

## Entry points

| Entry point | Actor | Authentication |
|---|---|---|
| `GET /health/delivery` (new, `src/http/mod.rs:42` neighbourhood) | any network peer that can reach `listen` | none |
| every other route, via `logging::decide` → `Sinks::offer` (`src/http/logging.rs:243`) | any network peer | none — this is the write path into the queues |
| `log_queue_max_bytes` / `siem_queue_max_bytes` in the TOML file (`Config::load`, `src/main.rs:122`) | operator with write access to the config file | filesystem |
| the `test-support` load driver | a `tests/` or `benches/` binary in this repo | Cargo feature |

## Trust boundaries

1. **Network peer → process state.** A request both *writes* the shedding state (by filling a queue) and *reads* it (via the new route). This is the only boundary this feature adds in both directions, and it is the same unauthenticated actor on both sides.
2. **Operator config → host memory.** A `NonZeroU64` the operator writes becomes an unbounded-above record capacity.
3. **`delivery` internals → bench/test binaries.** `mod delivery` is `pub(crate)` (`src/lib.rs:13`); a `benches/*.rs` target is an external consumer, so the driver must cross the crate's public boundary under a feature flag.
4. **Hot path → observer.** `Sink::push` (`src/delivery/mod.rs:113-118`) is non-`async`, lock-free, on every request; the health handler is on a different task. New shared mutable state crosses that.

## Assets

- **The audit trail** (file and SIEM decision records) — the asset the whole program exists to keep. Its *completeness* and the *truthfulness of the alarm that reports incompleteness* are distinct assets; T1 is about the second.
- **Package-serving availability for the fleet** — C7/C8 rank this above the audit trail.
- **Host memory** on the firewall.
- **The SIEM credential** — untouched by this feature (`OSPREY_SIEM_AUTH`, `src/delivery/mod.rs:179`); confirmed out of reach.

---

## Threats (8 shown, 1 omitted)

### T1 — the shedding signal is blind to the drop sites that have no backpressure
- **Property:** audit-trail integrity monitoring / noninterference between "loss" and "alarm"
- **Mechanism:** the Flow step 4 of the architecture marks the shedding state in `Sink::push` only. Four of the seven drop sites are *downstream of the queue*, in the sink task, and they discard records while the receiver keeps draining at full speed — so the queue never fills and `push` never drops. Concretely: a decision log file that cannot be opened (`src/delivery/file.rs:175-183`; wrong ownership after a rotation, full filesystem, SELinux denial) makes `append` return early for every record; a SIEM collector that answers `401`/`403`/`400` after a credential rotation is **not retryable** (`src/delivery/siem.rs:164`, `:175-177`), so `send` returns after one attempt and `Unsent::drop` counts the whole batch (`src/delivery/siem.rs:209-213`) — a *fast* failure, not a backpressuring one. In both cases 100% of the audit trail is being destroyed while `/health/delivery` returns `200`.
- **Asset:** the audit trail, and the operator's belief that it is intact
- **Location:** `src/delivery/mod.rs:113-118` (where the plan puts the mark) vs. `src/delivery/file.rs:105`, `:142`, `:181`, `src/delivery/siem.rs:97`, `:212`
- **Severity:** **High.** It inverts the product promise exactly when it matters: the operator alerts on non-`200`, sees green, and learns months later that the records for the incident window never existed. The queue-full case the plan does cover is the *least* silent one — it is already visible as `dropped_file`/`dropped_siem` on the summary record.
- **Mitigation:** mark the shedding state at **every** site that increments a drop counter, not at `push` alone. The plumbing already exists: `drops: Arc<AtomicU64>` is cloned into both sink tasks (`src/delivery/mod.rs:221`, `:258`), so the shed marker travels the same way — the lazy shape is to replace that `Arc<AtomicU64>` with an `Arc<Drops>`-style two-field struct (count + shed marker) and leave every call site's shape unchanged.
- **Verification property:** *no `fetch_add` on a drop counter exists that does not also set the shedding state* — a grep-checkable structural invariant over `src/delivery/`. Behavioural witness: with a `log_file_path` pointing at an unwritable location, `/health/delivery` returns `503` after the first served request.
- **Tier:** structural

### T2 — `Decision.method` is unbounded, so `BYTES_PER_RECORD` is not an upper bound
- **Property:** attacker-controlled complexity / memory bound
- **Mechanism:** C15 makes the budget a real memory bound only if `BYTES_PER_RECORD` is a ceiling on a record's true footprint. `package` and `version` are bounded — `loggable` truncates to `MAX_LOGGED_TARGET = 256` chars (`src/http/logging.rs:322-326`, `:51`) — and `reason` is always one of the constants in `src/http/error.rs:136-172`. But `method: method.to_string()` (`src/http/logging.rs:210`) is copied verbatim with no bound, and `logging::decide` is the **outermost** layer (`src/http/mod.rs:70-73`), so it runs before routing: a request with a multi-kilobyte HTTP extension-method token still produces a `Decision`, gets a `405`, and is offered to the sinks. Its ceiling is whatever hyper's request-line buffer allows — nothing in this repository. An attacker who sends such requests at a rate that keeps the queues full makes resident memory `capacity × real_record_size`, an arbitrary multiple of the budget the operator was promised.
- **Asset:** host memory; and the honesty of the published tolerance figure (C6/C10)
- **Location:** `BYTES_PER_RECORD` at `src/delivery/mod.rs` (new, near `:37`); the unbounded field at `src/http/logging.rs:210`
- **Severity:** **Medium.** The exposure is pre-existing (4096 fixed records have the same property today) — what is new is that the feature *publishes a byte budget as a bound*. Turning an undocumented exposure into a documented, false guarantee is the harm.
- **Mitigation:** either (a) bound `method` the way route components are bounded — reuse `loggable`/`MAX_LOGGED_TARGET` rather than adding a second truncation idiom — or (b) state in `docs/operations.md` that the budget bounds a record *count* derived from a typical record and is not a hard memory ceiling. (a) is the smaller change and keeps C6's promise true.
- **Verification property:** *the serialized size of any `Decision` this process can construct is ≤ `BYTES_PER_RECORD`* — derivable statically once every `String` field has a stated bound. Witness: a request with an oversized method token yields a record no larger than the constant.
- **Tier:** decision (Gate 3 must choose (a) or (b) before the constant is measured; measuring a *mean* silently picks neither)

### T3 — `/health/delivery` is an unauthenticated confirmation oracle for audit-trail evasion
- **Property:** information disclosure enabling repudiation
- **Mechanism:** an unauthenticated client floods a cheap route to fill the queues — the cheapest request in the service is a health request, which touches no upstream, no store and no artifact and still produces exactly one decision record, because the logging layer is outermost and `Target::of` gives `/health/*` the ecosystem `"health"` (`src/http/logging.rs:272-279`). It then polls `/health/delivery` until it reads `503`, which confirms the sinks are discarding, and issues the package fetch it wants absent from the audit trail. Without the endpoint the attacker is guessing; with it, the evasion is confirmed rather than hoped for.
- **Asset:** the audit trail's answer to "which machines took this package before it was blocked"
- **Location:** the new handler in `src/http/health.rs`; route at `src/http/mod.rs:42`
- **Severity:** **Medium**, not high, because of a real existing mitigation: the decision line is emitted to stdout by `tracing::info!` at `src/http/logging.rs:224` **before** `offer` at `:243`, so a record dropped by the sinks is still on stdout. The evasion succeeds only against an operator whose durable trail is the file/SIEM sink and who does not capture stdout.
- **Mitigation (partly existing):** already mitigated in shape by C9 — bare status code, no body, no per-sink detail — and by `no_store` (`src/http/mod.rs:94`). The residual mitigation is documentary: `docs/operations.md` must state that stdout remains the complete trail and that a `503` here means the durable sinks, not the record stream, are lossy.
- **Verification property:** *a record dropped by a sink is still present on stdout* — i.e. no change may move `offer` above the `tracing::info!` call, and `/health/delivery` discloses no per-sink or per-count detail beyond the status code.
- **Tier:** manual (the flood half is pre-existing and unchanged; the confirmation half is what this feature adds)

### T4 — a `/health/` route that an operator wires into a load balancer inverts C8
- **Property:** availability / privilege crossing by misconfiguration
- **Mechanism:** the route lives under the `/health/` prefix beside the two routes that *are* probe targets. An operator who adds it to their LB pool check — a plausible mistake, because the prefix is the convention their tooling matches on — hands any client that can drive delivery drops a lever to pull every firewall instance out of the serving pool. That is precisely the outcome C8 rejected ("a wedged collector must never throttle package traffic"), reached by configuration rather than by code.
- **Asset:** package-serving availability for the fleet — the asset C7/C8 rank first
- **Location:** the route registration at `src/http/mod.rs:42`; the countermeasure belongs in `docs/operations.md` and `README.md`
- **Severity:** **Medium.** Requires an operator error, but the consequence is a fleet-wide serving outage driven by an unauthenticated party.
- **Mitigation:** the operator documentation must say, at the point it introduces the route, that `/health/delivery` is an **alerting** signal and must never be a load-balancer or Kubernetes readiness/liveness probe target; `/health/ready` is the probe. C9 already chose the name for this reason — the documentation has to finish the job the name starts.
- **Verification property:** *no serving decision anywhere in the process reads the shedding state* — the state has exactly one reader, the new handler; `ready` (`src/http/health.rs:30-39`) is unchanged and does not consult it.
- **Tier:** structural

### T5 — a budget below one record produces `mpsc::channel(0)`, which panics at startup
- **Property:** availability / arithmetic edge case at a trust boundary
- **Mechanism:** C15's conversion is integer division, so any `log_queue_max_bytes` between 1 and `BYTES_PER_RECORD - 1` yields a capacity of `0`. `tokio::sync::mpsc::channel(0)` panics ("mpsc bounded channel requires buffer > 0"), inside `delivery::build` (`src/delivery/mod.rs:203`), on the startup path from `App::start` (`src/lib.rs:161`). The architecture promises this is rejected as `Invalid` at configuration load (`src/config.rs:385`) — but `src/config.rs` does not know `BYTES_PER_RECORD` today, and the conversion lives in `delivery`. If the two ever disagree, or if the guard lands only in `delivery`, a one-character config typo is a panic rather than the actionable rejection every other bad value gets (`src/config.rs:239-250` is the pattern).
- **Asset:** startup availability; the operator's ability to act on a configuration error
- **Location:** the validation in `src/config.rs` (`RawConfig::validate`) vs. the division at `src/delivery/mod.rs:203-214`, `:250`
- **Severity:** **Medium** — it is a crash on a path an operator reaches by mistake, and a panic is the one failure mode this config module is written to avoid.
- **Mitigation:** the minimum-budget rule must be expressed against the same constant the division uses — export `BYTES_PER_RECORD` to `config` rather than duplicating the number, exactly as `max_artifact_bytes ≤ cache_max_bytes` (`src/config.rs:230-235`) cross-checks two keys against each other. The same conversion must use `usize::try_from` rather than `as usize`, or a 32-bit build truncates a large budget into a small or zero capacity (this is the omitted threat, folded here).
- **Verification property:** *no configuration accepted by `Config::load` can produce a channel capacity of `0`* — and `delivery::build` performs no capacity arithmetic that `config` has not already validated.
- **Tier:** structural

### T6 — the shedding write must not add a lock or a clock read to `Sink::push`
- **Property:** noninterference — delivery must not slow or fail a request
- **Mechanism:** the open Gate 3 question (architecture line 128, "how long `/health/delivery` stays `503` after the last drop") pushes toward a time-based clear rule, and the obvious implementation records a timestamp *in `push`*. That puts a clock read — or worse, a `Mutex`, by analogy with the existing `COUNTERS` mutex at `src/http/logging.rs:347` — on a path that is documented as non-`async`, lock-free and infallible (`src/delivery/mod.rs:7-9`, `:128-132`), and that runs on every request at up to `max_active_requests = 1024` concurrency. The contention would arrive exactly during the overload the state exists to report, i.e. the feature would degrade serving latency under the one condition it was built for.
- **Asset:** request latency / the C7 promise that delivery never slows package serving
- **Location:** `src/delivery/mod.rs:113-118`
- **Severity:** **Medium** (a self-inflicted latency amplifier under load; not remotely exploitable beyond driving the load)
- **Mitigation:** the state is a relaxed atomic beside `drops`, mirroring `src/delivery/mod.rs:115` — the lazy correct shape is a monotonically increasing drop epoch written on the drop path and a *last-seen epoch plus timestamp* held by the reader, so the clock read happens in the health handler (which already reads the clock, `src/http/health.rs:31`) and never in `push`.
- **Verification property:** *`Sink::push` acquires no lock, performs no allocation, no syscall and no clock read* — its body remains a `try_send` plus relaxed atomic writes, and it stays non-`async` returning `()`.
- **Tier:** decision (Gate 3 owns the clear rule; this constrains which clear rules are admissible)

### T7 — the load driver becomes public API under `test-support`, and it can forge audit records
- **Property:** capability / ambient authority
- **Mechanism:** C17 requires a `benches/*.rs` target to reach the driver, and a bench is an **external** consumer of `package_firewall`. So unlike `set_summary_window` (`src/http/logging.rs:461`) and `set_response_timeouts` (`src/http/limits.rs:98`) — which are setters on already-public types — the driver must be a `pub` item that *constructs `Sinks` and offers arbitrary `Record`s*. Under `test-support`, the crate's public surface would therefore include record forgery into a decision-record pipeline. Secondly, whatever the driver needs from `Sink`/`Sinks` (field access, a constructor) must not be widened outside the `cfg`, or the loosening is permanent and unconditional.
- **Asset:** the audit trail's authenticity; the crate's public surface
- **Location:** the new driver module in `src/delivery/`; the feature at `Cargo.toml:41`, the self dev-dependency at `Cargo.toml:86`
- **Severity:** **Low**, because two existing controls hold: the feature is default-off (`Cargo.toml:41`), and `publish = false` (`Cargo.toml:8`) means no external consumer exists that could enable it. Edition 2024's feature resolver keeps dev-dependency features out of a plain `cargo build` of the binary, which is why the two existing setters are already safe by the same argument.
- **Mitigation (largely existing):** `#[cfg(feature = "test-support")]` on the driver *and* on every visibility widening it requires; no `src/main.rs` or non-`cfg` path may reference it. Prefer exposing one narrow entry (offer N records at rate R, return the tally) over exposing `Sinks`'s internals.
- **Verification property:** *a default `cargo build --release` contains no symbol from the driver, and every item whose visibility the driver requires is inside a `#[cfg(feature = "test-support")]` block.* Mechanically checkable with `nm`/`cargo build` plus a grep that no `pub(crate)`→`pub` change in `src/delivery/mod.rs` sits outside a `cfg`.
- **Tier:** structural

### T8 — neither budget key has an upper bound
- **Property:** resource exhaustion via operator-authored input
- **Mechanism:** `NonZeroU64` with no ceiling. A budget of `u64::MAX` yields a capacity around 10^16 records. `tokio`'s mpsc does not preallocate its buffer, so `build` succeeds and the process starts normally — the failure is deferred: under a sustained collector outage the queue grows until the OOM killer takes the firewall, and *then* package serving stops. The attacker-facing shape is a slow-burn: any client can drive queue growth, but only up to the capacity the operator configured. The interaction with `max_active_requests = 1024` (`config.sample.toml:34`) is worth stating precisely: that ceiling bounds *concurrency*, not queue occupancy, so it caps the rate at which records are produced but places no bound at all on how many accumulate behind a stalled sink.
- **Asset:** host memory, and transitively package-serving availability
- **Location:** `RawConfig::validate`, `src/config.rs`
- **Severity:** **Low** — the config file is an operator asset; an attacker who can write it already owns the host. It is listed because the repository's own precedent is to cross-check budgets (`src/config.rs:230-235`), and because the delayed failure mode (starts fine, dies in an incident) is the worst shape a bad value can have.
- **Mitigation:** Gate 3 decides whether to add a sanity ceiling. The cheaper alternative is documentary: `config.sample.toml` states the default and the `docs/operations.md` line states that this memory is *in addition to* `memory_cache_max_bytes`, since the sample already annotates that key "not total process RSS" (`config.sample.toml:28`).
- **Verification property:** *the documented default and any configured budget are additive to the stated process memory envelope, and the envelope is published* — or, if a ceiling is chosen, no accepted value exceeds it.
- **Tier:** decision

**Omitted: 1** — the `u64 → usize` truncating conversion on a 32-bit target, folded into T5's verification property because it is the same arithmetic site and the same fix (`try_from`, not `as`).

## Items I judge to carry no real threat

- **Memory-ordering staleness of the shedding state.** A relaxed write in `push` and a relaxed read in the handler can be microseconds stale. For a signal an operator polls on a scrape interval, that is unobservable, and the existing drop counters already use `Ordering::Relaxed` for the same reason (`src/delivery/mod.rs:115`). No mitigation needed.
- **Disclosure of whether delivery is configured at all.** With no sink, `Sinks` is empty (`src/delivery/mod.rs:141`), nothing is ever pushed, nothing is ever dropped, and the route returns `200` — the same answer a healthy configured deployment gives. The endpoint does not distinguish "logging off" from "logging fine", so it leaks nothing about the operator's delivery configuration.
- **The SIEM credential.** `OSPREY_SIEM_AUTH` is read once in `build` and never placed on `Config`, which derives `Debug` (`src/delivery/mod.rs:176-179`). Nothing in this feature adds a path that could print it: the new keys are byte counts and the new route has no body.
- **`Cache-Control` on the new route.** Already handled — the `no_store` layer covers every response including the health routes (`src/http/mod.rs:94-99`), so no stale `200` can be served from an intermediary while the firewall is shedding.
- **The `cargo test` floor test as an attack surface.** It runs in a debug test binary against a locally constructed `Sinks`; it reaches no socket and no configured sink. Nothing to model.

## Decisions Gate 3 must settle (named, not assumed)

1. **Where the shedding state is marked** — `push` only, or every drop site (T1). This is the decision that determines whether the alarm is truthful.
2. **How `/health/delivery` clears** — already on the architecture's open list (line 128). T6 constrains it: whatever rule is chosen must keep the clock out of `Sink::push`.
3. **Whether `BYTES_PER_RECORD` is an upper bound or a typical value** (T2) — and if an upper bound, whether `method` gets a `loggable`-style bound.
4. **Where the minimum-budget rule lives** and how `config` learns the constant (T5).
5. **Whether the budget keys get a ceiling** (T8).

## Limitations

- Proposed code does not exist; every threat is against the design plus the existing lines it names. Tier is `structural` where the invariant is mechanically checkable once code exists, `decision` where Gate 3 must choose first.
- I did not determine the exact ceiling hyper places on an HTTP request-line method token (T2). The finding does not depend on the number — it depends on the ceiling not being stated anywhere in this repository, which I did verify: the layer stack is `no_store` plus `logging::decide` only (`src/http/mod.rs:67-73`), with no request-size limit layer.
- No accepted or transferred risk is recorded here; every retained threat carries a mitigation. T8 is the closest to acceptance and is flagged as a Gate 3 decision rather than accepted on anyone's behalf.

---

TRIGGER-CHECK: Yes. Two changes here are security controls in their own right and must be modelled again in depth at Gate 3: the shedding signal is an *audit-trail-loss detection control* (T1 shows the planned placement makes it report green during total loss), and `BYTES_PER_RECORD` is a *memory-bound control* whose correctness depends on a field bound that does not currently exist (T2). The new unauthenticated route (T3, T4) is a third, lesser trigger.

RED-TEAM-INPUT: The plan marks the shedding state only in `Sink::push`, but the drop sites that destroy records *without* filling the queue — an unopenable log file (`src/delivery/file.rs:181`) and a collector that refuses a batch non-retryably (`src/delivery/siem.rs:164`, `:212`) — drain at full speed, so the alarm reads `200` while 100% of the audit trail is discarded; challenge whether this design can detect total silent loss at all. Second, `BYTES_PER_RECORD` is only a memory bound if every record field is bounded, and `Decision.method` (`src/http/logging.rs:210`) is copied verbatim from an attacker-controlled request line by the outermost layer with no truncation — challenge whether the published byte budget is a guarantee or a guess. Third, the same unauthenticated party can both cause shedding (cheap health-route floods produce one decision record each) and confirm it on `/health/delivery`, so challenge whether that confirmation oracle is acceptable given that stdout (`src/http/logging.rs:224`) is the only thing that keeps the dropped record.
