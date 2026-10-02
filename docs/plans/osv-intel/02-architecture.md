# Architecture: OSV vulnerability intelligence

## Clarifications and decisions

| ID | Class | Status | Owning Gate | Target Gate | Question or disposition | Selected value or policy | Decision source |
|---|---|---|---|---|---|---|---|
| C5 | current-Gate decision | resolved | 1 | 2 | Implementation language/shape is pre-decided: hardcoded Rust, no provider abstraction. Gate 2 designs the concrete module/fetch shape under this constraint. | A small `osv` module (injected HTTP client, batching, cache) plus one new background task; `policy::evaluate` takes one extra, OSV-specific boolean parameter. No `Provider` trait, no registry of sources. | architect decision, this Gate, grounded in `evidence/repository-structure.md` conventions (pure-core/impure-shell, injected seams) and SPEC.md:59's ban on a plugin framework |
| C6 | current-Gate decision | resolved | 2 | none | Fetch shape: OSV bulk zip export vs. `/v1/querybatch` HTTP API. | Superseded by C6b — reopened after Gate 2 approval when the user pointed out the query API fits this feature better than a bulk-snapshot poll. | user re-steer, 2026-09-27 |
| C9 | current-Gate decision | resolved | 2 | none | (Bulk-zip design, superseded) Decompressed-size/entry-count ceilings on the in-memory unzip. | Void — there is no zip to unzip under C6b's live-query design; nothing decompresses, so no decompression-bomb surface exists to cap. | superseded by C6b, 2026-09-27 |
| C10 | current-Gate decision | resolved | 2 | none | (Bulk-zip design, superseded) Snapshot-sanity circuit breaker against a poisoned bulk export. | Void — there is no snapshot to poison under C6b; blast radius from a bad OSV answer is now one (ecosystem, name, version) cache entry for one TTL window (`evidence/threat-model-2.md`'s T1), not a whole-ecosystem swap, so the circuit-breaker mechanism this decision specified no longer applies. | superseded by C6b, 2026-09-27 |
| C11 | current-Gate decision | resolved | 2 | none | (Bulk-zip design, superseded) `spawn_blocking` isolation for unzip/JSON-parse CPU work. | Void — under C6b there is no bulk unzip/parse; each batch response is small and parsed inline like any other JSON HTTP response, no CPU-isolation concern distinct from the rest of the request path. | superseded by C6b, 2026-09-27 |
| C6b | current-Gate decision | resolved | 2 | none | Fetch shape, revised: live per-package `/v1/querybatch` calls instead of a periodic bulk-snapshot poll. | `POST https://api.osv.dev/v1/querybatch`, one `{"package": {"ecosystem", "name"}, "version"}` query per (ecosystem, name, version) that needs checking. OSV's query endpoints already scope matches to the exact queried version, so a returned match is sufficient to decide — no `/v1/vulns/{id}` hydration of the full vulnerability record is needed for this feature: C4 (Gate 1) already says any `MAL-*` match blocks unconditionally, with no severity/range detail to read. This also means the pure `osv::OsvSnapshot`/`blocks_version` matcher from the original design is unneeded — OSV performs the version-range matching, this service does not. | `sf-research`, `evidence/research-1.md` (endpoint, batch shape, no documented rate limit); user-supplied primary source, https://oneuptime.com/blog/post/2026-07-23-query-osv-api/ (batch request/response shape, `results[i]` positional correspondence) |
| C7 | current-Gate decision | resolved | 2 | none | Does the OSV check need `store` persistence to survive a restart, the way the blocklist snapshot does? | No. There is no snapshot to persist any more (C6b) — only a short-TTL in-memory cache of recent query results (C13). On restart the cache is empty and every lookup is a cache miss, which behaves exactly like C3's already-accepted "OSV data absent" case: no block from OSV until an answer arrives, never a fail-closed `Unavailable`. No new `store` table. | architect decision, following directly from C3 and C6b |
| C8 | current-Gate decision | resolved | 2 | none | How does the decision log distinguish "producer's snapshot caught this" from "OSV alone caught this", which the product's success metric (01-product.md) requires? | One new `DenyReason` variant, `BlockedByOsv` (a single variant, not two — C6b's per-version query means there is no separate "whole package" vs. "this version" distinction to carry the way the producer blocklist has). `DenyReason` is `Copy` and already flows into the existing `&'static str` `reason` field (`src/delivery/mod.rs`'s `FIELD_CEILING_BYTES`/`BYTES_PER_RECORD`) via `ApiError::reason()` (`src/http/error.rs:136-168`, including each call site's `deny_reason()` arms) — no new field, no `BYTES_PER_RECORD` change (longest current reason string is 66 bytes; new strings stay well under the 512-byte ceiling). | architect decision, grounded in `evidence/repository-structure.md`'s B4/`BYTES_PER_RECORD` landmine, `src/http/error.rs:136-168`, `src/artifacts/mod.rs:320-327`, `src/npm/mod.rs:749-756` |
| C12 | current-Gate decision | resolved | 2 | none | The user asked for batching, not one `/v1/query` call per request ("we use batch ... if there is queue"): how do concurrent requests for different packages share one `/v1/querybatch` call instead of issuing one HTTP call each? | Reuse `delivery/siem.rs`'s existing batch-and-send shape exactly, rather than inventing a new pattern: an `mpsc::Receiver<(OsvKey, oneshot::Sender<OsvResult>)>` of **fixed, bounded capacity** (C12a), a `Vec` batch, a `tokio::select!` over `rx.recv()` and `tokio::time::sleep_until(deadline)`, flushing on a record-count cap (mirrors `BATCH_RECORDS`) or a short interval (mirrors `BATCH_INTERVAL`), whichever comes first. One `/v1/querybatch` call ships the whole batch (OSV's own cap is 1,000 queries/request; this service's flush cap stays well under that); each `results[i]` is matched back to `queries[i]` by position only after a length-equality check (C12b), and each waiting request gets its answer over its own `oneshot` channel. Unlike `siem.rs`'s send (which the batcher task awaits inline, and which is allowed to hold the loop since delivery is best-effort and has its own drain deadline), the batcher's outbound `POST /v1/querybatch` is wrapped in `tokio::time::timeout` no looser than C14's per-waiter bound (C12c) — so one slow or hung OSV connection cannot stall the task past that bound, and it always returns to draining `rx` for the next flush. Route handlers that need an OSV answer send into the channel (bounded by the same enqueue-timeout, C12a) and await their `oneshot`, bounded by C14's timeout. | architect decision, directly reusing `src/delivery/siem.rs`'s existing batch-and-send convention (mpsc + count/interval flush), grounded in user's supplied OSV batch-API reference; C12a-c close `sf-threat-model` G1/G2/G3 (`docs/plans/osv-intel/evidence/threat-model-2.md`) |
| C12a | current-Gate decision | resolved | 2 | none | Closes G2: what bounds the batcher's channel, and what happens when it is full? | The `mpsc` channel has a fixed capacity (a Gate 3 config or constant value, sized against the flush cap). A `send` onto a full channel is itself bounded by a short enqueue-timeout; on timeout the route handler treats that key as OSV-unreachable and takes the same fail-open + short-negative-TTL path as C14 — never an indefinite blocking send on the request path. | architect decision, closing `sf-threat-model` G2 |
| C12b | current-Gate decision | resolved | 2 | none | Closes G3: what stops a `results[i]`/`queries[i]` length mismatch from panicking (index past bounds) or silently truncating (a real match paired away and cached clean)? | Before any positional pairing, the batcher checks `results.len() == queries.len()`. A mismatch is classified as a whole-batch failure and takes C14's fail-open + short-negative-TTL path for every key in that flush — never a partial or truncated pairing, and never an unchecked index. | architect decision, closing `sf-threat-model` G3 |
| C12c | current-Gate decision | resolved | 2 | none | Closes G1: does the batcher task's own outbound call block it from draining the channel? | No — the batcher's `POST /v1/querybatch` call is wrapped in `tokio::time::timeout`, not awaited unbounded the way `siem.rs`'s best-effort delivery is. A timeout on the outbound call takes the whole-batch fail-open path (same as C12b's mismatch case) and the task returns to `rx.recv()` immediately, so one hung OSV connection cannot back up every subsequently-enqueued key behind it. | architect decision, closing `sf-threat-model` G1 |
| C13 | current-Gate decision | resolved | 2 | none | Does every request pay a live OSV round trip, including repeat requests for the same hot package/version? | No — a short-TTL in-memory cache (`HashMap`/`DashMap`-shaped, keyed by `(Ecosystem, name, version)` → `OsvResult` with an expiry) sits in front of the batcher; a cache hit answers immediately with no network call, a cache miss enqueues into the batcher (C12) and caches the result on reply. This bounds external call volume under load, which matters because `docs/plans/rated-load-guard/` is actively hardening this same request-serving path's throughput/latency. Populated straight from the compact batch match (`{"id", "modified"}` — no hydration needed, C6b), so a cache entry is cheap: an `Option<&'static-ish id string>` or boolean plus an expiry instant. Exact TTL is a Gate 3 config value. | user decision, this Gate (recommended: short-TTL cache, given `rated-load-guard`'s in-flight latency focus) |
| C14 | current-Gate decision | resolved | 2 | none | What happens to a request's OSV check on a batch failure, an OSV outage, or a timeout waiting on the `oneshot`? | Fail-open, per C3: a batch send failure, a non-2xx response, or a timeout past a short bound (a few hundred ms, aligned with existing upstream client timeout conventions) answers every waiter in that flush with "no OSV match" rather than blocking the request or producing `Decision::Unavailable`. Counted (mirrors `SinkCounters`), not silently dropped. A short negative-TTL cache entry (shorter than C13's normal TTL) is written on failure too, so a struggling OSV endpoint is not hammered by every subsequent request for the same package during an outage. | architect decision, following directly from C3 |
| C15 | current-Gate decision | resolved | 2 | none | Does `policy::evaluate` (pure, no I/O) perform the OSV check itself, or does the impure shell resolve it first? | The impure shell resolves it first, same as it already resolves the blocklist snapshot before calling `evaluate`. To avoid paying an OSV round trip for a request the producer's snapshot would deny anyway, the route handler calls `evaluate(..., osv_matched: false)` first; if that decision is anything other than `Allow`, it is used as-is (no OSV call was needed to reach it). Only when the OSV-blind decision would be `Allow` does the handler resolve the OSV answer (cache or batcher, C12/C13) and call `evaluate` again with the real value. `evaluate` stays pure and is cheap enough to call twice. | architect decision, preserving the existing pure-core/impure-shell split while avoiding an unnecessary external call on the already-denied path |
| C16 | current-Gate decision | resolved | 2 | none | Q1: should OSV enforcement be operator-configurable, and what states/default? | Three states, `enforce`/`diagnostic`/`off`; default `enforce`. `enforce` is today's only behavior (an OSV match denies). `diagnostic` runs the same OSV check but never denies on its result — it only records that OSV would have matched. `off` skips the OSV check entirely (no network call, no cache lookup). Default `enforce` keeps every existing deployment, and Slices 1-3's tests, behaved exactly as today. | user answer, Gate 2 grilling Q1 |
| C17 | current-Gate decision | resolved | 2 | none | Q2: what does a `diagnostic`-mode log entry carry — same fields as today, or a new field (e.g. the matched OSV advisory ID)? | Same fields, no new field. The impure shell (not `policy::evaluate`, which stays pure and unaware of mode) decides what `osv_matched` value to pass based on config: `enforce` passes the real value; `diagnostic` always passes `false` (so `evaluate` never denies); `off` skips the OSV check and touches no logging. See C17b for the diagnostic-match logging mechanism (revised after `sf-threat-model` G1). | user answer, Gate 2 grilling Q2 |
| C17b | current-Gate decision | resolved | 2 | none | `sf-threat-model` G1: C17's original claim — set `Decision.reason` directly while `result` stays `"allow"` — is unbuildable. `decide()` (`src/http/logging.rs:189-193`) derives `result`/`reason` as one pair from `response.extensions().get::<ApiError>()`: `Some` gives both the error code and its reason, `None` always gives `("ALLOWED", "the request was served")`. There is no route-handler-to-middleware channel that can override only `reason` on a response carrying no `ApiError`, and inserting an `ApiError` to carry a reason would also flip `result` away from `"ALLOWED"`, breaking the "`result` stays `allow`" promise. What is the real mechanism? | Reuse the existing task-local `RequestContext` seam (`src/http/logging.rs:100-106`), the same one `record_cache`/the `ecosystem: AtomicU8` field already use to let a handler tell `decide()` something the URL path alone doesn't know, without touching `ApiError` or response extensions. Add `osv_diagnostic_match: AtomicBool` to `RequestContext` and a `record_osv_diagnostic_match()` function mirroring `record_cache()`'s shape; the route handler calls it when `osv_mode` is `diagnostic` and the real OSV check matched. `decide()`'s `None` (no-`ApiError`) branch reads it: `("ALLOWED", "the request was served")` normally, or, when set, `("ALLOWED", <diagnostic reason>)` — `result` never changes, only `reason` on the allow path, and only via a channel `decide()` already reads independently of `ApiError`. | architect decision, resolving `sf-threat-model` G1 (`docs/plans/osv-intel/evidence/threat-model-3.md`), grounded in `src/http/logging.rs:100-106,126,173-174,189-193` |
| C17c | current-Gate decision | resolved | 2 | none | `sf-red-team` finding 1: C17b's "`BlockedByOsv`'s existing reason string" does not exist as one reusable value. `artifacts::deny_reason(BlockedByOsv)` and `npm::deny_reason(BlockedByOsv)` are two different, private, per-module strings (`src/artifacts/mod.rs:324-336`, `src/npm/mod.rs:749-761`), and PyPI has no `DenyReason` mapping in the repo at all yet. `decide()` lives in a third module and cannot call either private function, and a diagnostic match isn't scoped to artifacts-vs-npm the way a deny is — there is no principled way to pick between the two. What is `<diagnostic reason>`? | A fourth, new `pub(crate)` constant, owned by `http::logging` itself (not derived from any `deny_reason` call site): `const OSV_DIAGNOSTIC_REASON: &str = "the request would be blocked by a known OSV malicious-package advisory (diagnostic mode: not enforced)"`. `decide()`'s no-`ApiError` branch uses it directly when `record_osv_diagnostic_match()` was called; the three ecosystem-specific `deny_reason` functions are untouched, no visibility change, no cross-module call, no refactor of the (already pre-existing, out-of-scope) artifacts/npm string divergence. This is also the string T2 says operators grep/alert on, so it names both what happened and that it was not enforced. | architect decision, resolving `sf-red-team` finding 1, grounded in `src/artifacts/mod.rs:324-336`, `src/npm/mod.rs:749-761` (two divergent private strings, no PyPI equivalent yet) |
| C18b | current-Gate decision | resolved | 2 | none | `sf-threat-model` T1: does an unrecognized `osv_mode` config value hard-fail startup, or silently fall back to a weaker mode? | Hard-fail, matching every other validated key in `config.rs` (`public_url` scheme, `siem_auth_header`, `log_file_max_bytes`, etc. — zero precedent for silent fallback on any validated key). An unrecognized `osv_mode` value refuses startup; it never silently maps to `off` or `diagnostic`. A `tests/config_validation.rs` case asserts this. | architect decision, resolving `sf-threat-model` T1, grounded in `src/config.rs:213-339`'s existing validation convention |
| C18 | current-Gate decision | resolved | 2 | none | Where does the mode live in config, and does `off` still pay a cache/network cost? | New key `osv_mode: enforce/diagnostic/off` (string, validated, default `enforce`) in `config.rs`, alongside `osv_cache_ttl_seconds`/`osv_request_timeout_ms`. `off` short-circuits before C15's OSV-blind-first step even runs — no `osv::OsvClient::check` call, no cache lookup, no batcher enqueue; `diagnostic` and `enforce` both still perform the check exactly as C15 describes (only what `evaluate` is told, and what the log records, differs). | architect decision, following directly from C15 and C16 |

## Program behavior

Purpose: block a request for a malicious npm/PyPI package the moment OSV's `MAL-*` malicious-package
advisory data lists it, without waiting on the operator's own producer to catch up (01-product.md).

Capabilities: an OSV-listed package/version is denied even when absent from the producer's blocklist
snapshot -> request denied, decision logged with a reason distinguishing the OSV match; a package
neither source blocks -> unaffected by this feature, existing cooldown/hold/allow behavior unchanged;
a repeat request for a package/version already checked recently -> answered from the cache (C13), no
extra OSV round trip. Operator-configurable enforcement (C16): `osv_mode: enforce` is the above;
`diagnostic` runs the identical check but always allows, logging the match in the existing `reason`
field instead of denying (C17); `off` skips the OSV check entirely, no network call or cache lookup
(C18).

Failures: OSV is unreachable, errors, or a check times out -> firewall keeps serving on the producer's
snapshot alone (C3/C14), no `Unavailable` result is produced by OSV's absence; a malformed or
unexpected batch response -> that batch's waiters fail open the same way (C14), logged and counted,
never a crash or a hang past the timeout bound.

Programming entry point: none — an added await in the existing request path plus one new background
batching task.

## Fit

| Module/package | Purpose | Provided functionality | Owns | Used by / uses | Existing or proposed |
|---|---|---|---|---|---|
| `osv` (`src/osv/mod.rs`) | The OSV query client and cache: everything needed to answer "does OSV block (ecosystem, name, version)?" | `OsvClient::check(ecosystem, name, version) -> OsvResult`, backed by the cache (C13) and the batcher (C12). No pure snapshot/matcher type — OSV's own API already does version matching (C6b). | The in-memory result cache and the batcher's `mpsc` sender handle. | Called by every route that decides a request today, at the point C15 describes. | New |
| `osv::batcher` (`src/osv/batcher.rs`) | Coalesces concurrent OSV lookups into `/v1/querybatch` calls. | Background task mirroring `delivery/siem.rs`'s batch-and-send loop (`mpsc::Receiver` of fixed capacity, count-cap or interval flush, `oneshot` reply per queued item), with two departures from that mirror: the outbound call is `tokio::time::timeout`-wrapped rather than awaited unbounded (C12c), and pairing `results[i]` to `queries[i]` is gated by a length check (C12b). | Its own flush cadence, in-flight batch, and bounded channel (C12a). | Spawned once from `tasks::spawn` on the same `CancellationToken`; fed by `osv::OsvClient::check`. | New |
| `policy::evaluate` (`src/policy/mod.rs`) | Composes the OSV result into the existing fixed decision order (SPEC §5). | Adds an `osv_matched: bool` parameter; when `true`, denies at the same tier as the existing producer package/version checks and before the digest check; `false` contributes no block (never `Unavailable`). | The fixed decision order (`Unavailable -> Deny(package) -> Deny(version) -> Deny(digest) -> Deny(timestamp) -> Hold -> Allow`), now with one OSV check interleaved at the same tier as the producer's. | Called twice per request when the OSV-blind result would be `Allow` (C15), once otherwise. | Change |
| `DenyReason` (`src/policy/mod.rs`) | Names why a request was denied. | Adds `BlockedByOsv`. | The enum `Copy` and exhaustive; every match site the compiler flags must be updated. | `src/artifacts/mod.rs:320`, `src/npm/mod.rs:749` (and any `pypi` equivalent) map the new variant to a `&'static str` for the decision-log `reason` field. | Change |
| `App` (`src/lib.rs`) | Shared process state. | Adds the `osv::OsvClient` (cache + batcher sender) as a field, constructed once. | Nothing atomically-swapped this time — the cache is its own interior-mutable structure, not a published-snapshot type. | Read by every request path that calls `policy::evaluate`'s OSV step. | Change |
| `AppDeps` (`src/lib.rs`) | Injectable construction seam. | Adds an injected OSV HTTP client so tests never touch the real OSV endpoint, following the repo's actual constructor-injection convention: `AppDeps.transport: Arc<dyn Transport>` (`src/lib.rs:47-51`), not `siem.rs`'s internally-constructed `reqwest::Client` (`src/delivery/mod.rs:388-399`, tested via `wiremock`, not injection). Exact trait shape vs. a plain injected `reqwest::Client` field is a Gate 3 detail. | The one point production wiring (`main.rs`) supplies a real client; tests supply a fake, mirroring `Transport`. | `osv::batcher`. | Change |
| `config` (`src/config.rs`) | Config parsing/validation. | Adds `osv_cache_ttl_seconds: NonZeroU64`, an OSV request-timeout key, and `osv_mode: enforce/diagnostic/off` (default `enforce`, C16/C18) to `REQUIRED_KEYS`/`OPTIONAL_KEYS`, `RawConfig`, `Config`, and validation; a fixture line in `tests/config_validation.rs`. | The cache TTL, per-check timeout (C13, C14), and enforcement mode (C16). | `osv::OsvClient` reads the TTL/timeout; the route handler reads `osv_mode` (C18). | Change |
| `http::logging` (`src/http/logging.rs`) | Renders the per-request decision line (SPEC §11). | Adds `record_osv_diagnostic_match()` and the `OSV_DIAGNOSTIC_REASON` constant so a `diagnostic`-mode OSV match can override only the allow-path `reason`, never `result` (C17b/C17c). | The new `osv_diagnostic_match: AtomicBool` field on the existing task-local `RequestContext`, alongside its existing `cache`/`ecosystem` fields. | Called by the route handler under `osv_mode: diagnostic` (C17b); `decide()`'s no-`ApiError` branch reads it. | Change |

## Endpoints

none — no new HTTP surface; the feature changes only the internal decision path and background tasks.

## Data

No new `store`/database table (C7). New in-process state only:
- `osv`'s result cache — `(Ecosystem, name, version) -> (OsvResult, expiry)`, short TTL (C13), empty on
  every restart, no durability requirement.
- The batcher's in-flight batch — transient, held only between flushes (C12).

## Flow

1. A route handler reaches the point where it already calls `policy::evaluate` with the producer's
   blocklist snapshot. It first calls `evaluate(..., osv_matched: false)`.
2. If that result is not `Allow`, it is used as the final decision — the producer's snapshot, a digest
   match, or a timestamp rule already decided this request, and no OSV call is made (C15).
3. If that result is `Allow` and `osv_mode` is `off` (C16/C18), this `Allow` is the final decision —
   no OSV call is made at all.
4. If that result is `Allow` and `osv_mode` is `enforce` or `diagnostic`, the handler asks
   `osv::OsvClient::check(ecosystem, name, version)`:
   - Cache hit (C13): returns immediately, no network call.
   - Cache miss: enqueues `(key, oneshot::Sender)` into `osv::batcher`'s channel and awaits the
     `oneshot`, bounded by a short timeout (C14).
5. `osv::batcher::run` (mirrors `delivery/siem.rs`'s loop) accumulates queued keys until its
   record-count cap or its flush interval fires, then sends one `POST /v1/querybatch` with one query
   per distinct key in the batch, wrapped in a `tokio::time::timeout` (C12c) — so the task always
   returns to draining `rx` for the next flush even if this call hangs.
6. On a successful, on-time response whose `results.len() == queries.len()` (C12b), each `results[i]`
   is matched back to `queries[i]` by position; a returned match with `id` starting `MAL-` is an OSV
   block for that key. Every waiter for that key gets its answer over its `oneshot`; the cache is
   populated with each key's result and a normal-length TTL.
7. On a failed/erroring/malformed/timed-out/length-mismatched response, or a channel-enqueue timeout
   (C12a), every waiter affected is answered "no match" (fail open, C14), and a short negative-TTL
   cache entry is written per key to avoid re-hammering OSV.
8. Back in the route handler: under `enforce`, `evaluate` is called again with the real `osv_matched`
   value and that result is the final decision (C8). Under `diagnostic`, `evaluate` is always called
   with `osv_matched: false` (never denies on OSV); if the real check matched, the handler calls
   `record_osv_diagnostic_match()` (C17b) so `decide()`'s no-`ApiError` branch logs the dedicated
   `OSV_DIAGNOSTIC_REASON` constant (C17c) while `result` stays `"ALLOWED"` — no new delivery field,
   no `ApiError` inserted on an allowed request, and no dependency on either ecosystem's private
   deny-path strings.

## Constraints

- No provider abstraction, no `Provider` trait, no registry of sources (C5, backlog B2, SPEC.md:59)
  — exactly two hardcoded sources: the producer's blocklist and OSV.
- OSV absence/staleness/timeout must never produce `Decision::Unavailable` or otherwise block a
  request that the producer's snapshot alone would allow (C3, C14).
- `Decision`'s heap-footprint ceiling (`BYTES_PER_RECORD`, `src/delivery/mod.rs`) must not be
  invalidated: this feature adds one `DenyReason` variant (cheap, `Copy`, already-sized `reason`
  field), never a new `String`/`Vec` field on `Decision` itself.
- `docs/plans/rated-load-guard/` is a separate, in-flight plan actively changing `src/delivery/*` and
  `src/http/{health,logging,mod}.rs`; slice work here must check that plan's current state before
  editing those files to avoid silent conflict. It is also the direct reason C13's cache exists.
- SPEC §5's fixed decision order is preserved; OSV's check is interleaved at the existing
  package/version tier, not appended after digest/timestamp checks, and the pinned ordering test
  (`check_order_is_unavailable_deny_hold_allow`, `src/policy/mod.rs`) is extended, not replaced.
- `osv_mode` gates only what `evaluate` is told and what the log records (C16/C17/C18) — it never
  changes `policy::evaluate` itself, which stays pure and mode-unaware; the impure shell is the only
  place `osv_mode` is read. Default `enforce`, so an operator who never sets it keeps today's behavior.
- The OSV merge stays OR-only (C1): nothing OSV returns, times out, or fails on may un-block what the
  producer's snapshot blocks, and no OSV failure path (C14) may deny a request the producer's snapshot
  alone would allow.
- OSV's own batch cap is 1,000 queries/request (`evidence/research-2.md`); this service's flush cap
  (C12) stays well under it.

## Threat model

Reopened: the trust boundary changed shape after Gate 2's first approval (bulk zip -> live query,
C6b), so the prior model (`evidence/threat-model-1.md`, first pass UNKNOWN then MODELED against the
bulk-zip design) no longer describes the design. A fresh pass against the batch-query design
(`evidence/threat-model-2.md`) returned UNKNOWN with three gaps in the batcher's mechanism: G1 (the
outbound OSV call could stall the batcher task indefinitely if awaited unbounded, backing up every
subsequently-enqueued key), G2 (the channel's capacity and full-channel behavior were unstated), and
G3 (a `results[i]`/`queries[i]` length mismatch had no stated guard — an unchecked index panics, and a
silent truncation would cache a real match as clean). All three are closed above by C12a (bounded
channel + enqueue-timeout fail-open), C12b (length-equality check before pairing, mismatch takes the
whole-batch fail-open path), and C12c (`tokio::time::timeout`-wrapped outbound call). T1 (a
wholesale-erroneous OSV match) and T5 (oversized response body) were confirmed non-gaps, already
covered by C4's Gate-1 trust policy and OSV's own documented response cap respectively. A second
`sf-threat-model` pass against the revised text (C12a/b/c in place) returned **MODELED**: every
retained threat has a concrete, buildable mitigation, and the non-regression check confirmed C1
(OR-only merge), C3 (never fail-closed), C5 (no provider abstraction), and C15 (OSV-blind-first
ordering) all still hold. Full detail: `docs/plans/osv-intel/evidence/threat-model-2.md`.

Reopened again 2026-09-29 (second re-steer): the trust boundary changed shape once more with the
addition of the operator-configurable `osv_mode` (C16-C18) — a config-driven change to what the
security control does. A fresh `sf-threat-model` pass (`evidence/threat-model-3.md`) returned
UNKNOWN with a blocking structural gap, G1: C17's original claim (set `Decision.reason` directly
while `result` stays `"allow"`) is unbuildable against `decide()`'s actual `result`/`reason`
derivation (`src/http/logging.rs:189-193`), which ties both to `ApiError`-extension
presence/absence. Closed by C17b, reusing the existing task-local `RequestContext` seam
(`record_cache`'s pattern) instead. Also raised T1 (an unrecognized `osv_mode` value's failure
mode was unstated), closed by C18b (hard-fail, matching every other validated config key), and
T2 (`diagnostic` mode has no distinct metric), accepted and documented as an operational
limitation, not a code change. A second pass against the revised C17b/C18b text returned
**MODELED**: every retained threat has a concrete mitigation or is a confirmed non-gap, and the
non-regression check confirmed C1/C3/C15 and pass 2's closures all still hold. Full detail:
`docs/plans/osv-intel/evidence/threat-model-3.md`.

`sf-red-team` (mandatory this reopen: a security-control behavior change) returned **FIX FIRST**
against the MODELED result above: C17b's fix text named "`BlockedByOsv`'s existing reason string"
as the value `decide()` would log, but no such single string exists — `artifacts::deny_reason` and
`npm::deny_reason` are two different private per-module strings, and PyPI has none yet. Closed by
C17c: a new, dedicated `pub(crate)` constant owned by `http::logging` itself, independent of every
ecosystem's deny-path strings. Red Team's other checks (coverage, dependencies, risk order, sizing,
hard bar, security) came back clean; this was the only blocker.

## External

- OSV query API: `api.osv.dev` (`POST /v1/querybatch`) — env vars: none required; no credential to
  configure. Documented rate limit: none (`evidence/research-1.md`).
- No SIEM/webhook change.

## Repository evidence

- `docs/plans/osv-intel/evidence/repository-structure.md` — `sf-repo-onboarding`, module ownership,
  existing poller/delivery/config conventions, invariants (commit-then-publish, pure-core/impure-shell,
  decision order), landmines (`BYTES_PER_RECORD`, `rated-load-guard` in flight, no-provider-abstraction).
- `docs/plans/osv-intel/evidence/research-1.md` — `sf-research`, OSV bulk-export and `/v1/querybatch`
  API shape, no documented rate limit, no documented polling-cadence SLA.
- `docs/plans/osv-intel/evidence/research-2.md` — the user-supplied OSV batch-API reference
  (https://oneuptime.com/blog/post/2026-07-23-query-osv-api/): batch request/response shape,
  `results[i]`/`queries[i]` positional correspondence, the 1,000-query batch cap, and the
  `/v1/vulns/{id}` hydration-by-`modified` pattern (noted as not needed for this feature, C6b).
- `docs/plans/osv-intel/evidence/threat-model-1.md` — the superseded bulk-zip trust boundary's model
  (T1-T7), kept for history; no longer describes the current design.
- `docs/plans/osv-intel/evidence/threat-model-2.md` — the batch-query design's model: first pass
  UNKNOWN (G1/G2/G3), closed by C12a/C12b/C12c above; T1/T5 confirmed non-gaps.
- `docs/plans/osv-intel/evidence/threat-model-3.md` — the `osv_mode` config-switch model: first pass
  UNKNOWN (G1 blocking, T1 decision, T2 accepted), closed by C17b/C18b above; second pass MODELED.
- Direct reads grounding C8: `src/delivery/mod.rs:44-110` (`BYTES_PER_RECORD` derivation),
  `src/http/error.rs:136-168` (`ApiError::reason()`, every `&'static str` that reaches the decision
  log), `src/artifacts/mod.rs:320-327`, `src/npm/mod.rs:749-756` (`deny_reason` match sites).
- Direct reads grounding C12's reuse: `src/delivery/siem.rs:44-104` (the exact batch-and-send
  `mpsc`/`tokio::select!`/count-or-interval-flush shape being mirrored).
- Direct reads grounding the Fit table: `src/policy/mod.rs:1-140` (`evaluate`, `Decision`,
  `DenyReason`), `src/tasks/mod.rs:1-40`, `src/lib.rs:47-80` (`AppDeps`/`App`, the `Transport`
  constructor-injection convention the OSV client follows), `src/delivery/mod.rs:388-399` (contrast:
  `siem.rs`'s client is built internally, not injected via `AppDeps`), `src/config.rs`
  (`blocklist_poll_seconds` naming convention for the new config keys).

sf-red-team: triggered for this reopening — `osv_mode` is a security-control behavior change. First
pass returned FIX FIRST (C17b's reason-string claim did not hold up against the actual, divergent
per-ecosystem `deny_reason` strings); closed by C17c above. Coverage, dependencies, risk order,
sizing, hard-bar, and security checks all came back clean otherwise. The original Gate 2 content
(C1-C15) was not re-triggered — its own `sf-red-team: not triggered` finding above stands unchanged.
