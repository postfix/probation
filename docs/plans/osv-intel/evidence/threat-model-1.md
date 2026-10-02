# Threat model — OSV feed ingestion (Gate 2)

`sf-threat-model`, 2026-09-27. Scope: ingestion of OSV's malicious-packages bulk export (npm/all.zip,
PyPI/all.zip, GCS, public, no auth) from fetch through unzip, JSON parse, `osv::OsvSnapshot`
construction, `ArcSwapOption` publish, to `policy::evaluate` read (02-architecture.md Flow §1-5 and Fit
table, first draft).

First verdict: UNKNOWN — two blocking gaps (below), each closed in the architecture by C9/C10/C11.

Re-review verdict (`sf-threat-model`, 2026-09-27, against the revised architecture with C9/C10/C11 in
place): **MODELED**. T1/T2 confirmed closed by C9's decompressed-size/entry-count ceilings (concrete
abort-and-keep-previous mechanism; only the numeric thresholds are deferred to Gate 3, not the
mechanism). T4/T7 confirmed closed by C10's snapshot-sanity circuit breaker, including an explicit,
named first-snapshot-since-restart behavior (trust-on-first-use, bounded by C9's caps — a stated
accepted residual, not a silent gap). T6 confirmed closed by C11's `spawn_blocking` isolation. T3/T5
reconfirmed still mitigated and untouched by C9/C10/C11. Non-regression check passed for C1 (OR-only
merge), C3 (no fail-closed on OSV absence), C5 (no provider abstraction revived), and C7 (no `store`
persistence added).

## Trust boundaries

Internet (public GCS, TLS-only, no auth, no documented content-integrity signature) →
`tasks::osv_poller` (impure shell) → `osv::OsvSnapshot` (pure parse boundary, no I/O) → published
snapshot → every concurrent request thread calling `policy::evaluate` (shared-read boundary via
`ArcSwapOption`).

## Assets

1. Availability of legitimate npm/PyPI installs (false-positive blast radius, unconditional per C4).
2. Process memory/CPU shared between the poller and request-serving.
3. Integrity of the block/allow decision (false-negative risk).
4. Decision-log `reason` field (low sensitivity, already bounded, not affected by this feature).

## Threats

- **T1 — decompression bomb** (High, GAP → closed by C9): small compressed zip inflates to unbounded
  memory during in-memory unzip; the download-size cap (C6) does not bound decompressed size.
- **T2 — entry-count bomb** (Medium-High, GAP → closed by C9): unbounded small JSON entries exhaust
  CPU/allocations during per-record parsing.
- **T3 — malformed/adversarial JSON** (mitigated by design): per-record tolerance (Program behavior's
  Failures line) means one malformed record cannot prevent the rest from being indexed or crash the
  poller. Residual: adversarial-depth JSON (stack-overflow class) not explicitly bounded; low severity
  given a fixed-struct (not open-ended `Value`) parse target. Not blocking.
- **T4 — poisoned/corrupted feed content → false-positive DoS** (High, GAP → closed by C10): no
  content-integrity signature, only transport TLS; C4's unconditional block means a bogus `MAL-*`
  record lands in production with no graduated response.
- **T5 — feed suppression/tampering → false negative** (mitigated by design): the additive OR-only
  merge (C1) means compromising OSV can only reduce OSV's own contribution, never un-block what the
  producer's snapshot already flags — identical in effect to an ordinary OSV outage, which C3 already
  accepts. Holds by construction as long as the merge stays OR-only with no override path; must survive
  Gate 3/implementation unchanged.
- **T6 — noisy-neighbor resource exhaustion** (Medium, GAP → closed by C11): unzip/parse CPU work for
  two full-ecosystem archives every poll, if run on the request-serving executor, could delay in-flight
  requests.
- **T7 — no persistence (C7) × restart during a poisoned-fetch window** (Low standalone, folds into
  C10): the first snapshot since restart has no prior baseline to diff against even once a
  circuit-breaker exists; C10 states this explicitly — trust-on-first-use, bounded by C9's caps rather
  than by a content check.
- No SSRF: the fetch URL is fixed and hardcoded, never derived from request input. No credible threat.
- No deserialization-code-execution threat: standard JSON parsing, not a tag-executing format.

## Resolution

C9 (`docs/plans/osv-intel/02-architecture.md`) closes T1/T2 with hard decompressed-size and
entry-count ceilings. C10 closes T4/T7 with a snapshot-sanity circuit breaker plus an explicit
first-snapshot-since-restart behavior. C11 closes T6 by running the unzip/parse CPU work via
`tokio::task::spawn_blocking`, off the request-serving executor. None of the three revives a
provider abstraction or a `store` persistence step — each is an additive cap/check inside
`tasks::osv_poller`, consistent with C5/C7.
