# Threat model pass 3 — `osv_mode` config-driven enforcement switch

Reopened 2026-09-29: user asked whether OSV blocking can be switched on/off and whether a
diagnostic (log-only) mode exists. Neither did. This pass models the new `osv_mode:
enforce | diagnostic | off` config surface (C16-C18).

## Scope
The `osv_mode` config surface and its effect on request handling: can it silently weaken
enforcement below what an operator intends; does `diagnostic` mode's non-denial interact badly
with anything downstream that assumes a match always denies; is `off`/`diagnostic` reachable
without explicit operator configuration.

## Entry points / actors
Operator (config file, `osv_mode` key); route handler (impure shell, C15/C18);
`policy::evaluate` (pure, mode-unaware); OSV external API; decision-log consumers
(file/SIEM sinks, `src/http/logging.rs`'s `decide()`).

## Trust boundaries
Operator config -> impure shell mode selection; impure shell -> pure `evaluate` (only a bool
crosses, mode itself never crosses); OSV response -> cache/log; decision record -> external
sinks.

## Assets
Enforcement integrity (a malicious package must be denied under `enforce`); decision-log
fidelity (operators/alerting must be able to trust what `result`/`reason` say); config integrity
(no silent weakening of intended enforcement level).

## First pass: UNKNOWN

**G1 (blocking, structural).** C17's original mechanism — set `Decision.reason` directly while
`result` stays `"allow"` — is unbuildable. `decide()` (`src/http/logging.rs:189-193`) derives
`result`/`reason` as one pair from `response.extensions().get::<ApiError>()`: `Some` gives both
the error code and its reason, `None` always gives `("ALLOWED", "the request was served")`. There
is no route-handler-to-middleware channel that overrides only `reason` on a response carrying no
`ApiError`, and inserting an `ApiError` to carry a reason would also flip `result` away from
`"ALLOWED"`. Verification property: "a `diagnostic`-mode OSV match can set `Decision.reason` while
`Decision.result` remains `\"allow\"`, for a route that inserts no `ApiError`."

**T1 (decision).** C18 said `osv_mode` is "string, validated" without stating the failure mode
for an unrecognized value: hard-fail startup, or silent fallback to a weaker mode?

**T2 (accepted, Low-Medium).** `diagnostic`-mode matches have no counter/metric distinct from
ordinary `Allow` traffic — only the NDJSON `reason` string on an otherwise-`Allow` record carries
the signal (once G1 is fixed). No existing alerting surface in this codebase assumes
match-always-denies (`src/delivery/counters.rs` only tracks sink loss), so nothing regresses;
this is a forward-looking operational limitation, not a break. Owner: user (C16/C17 answers).
Documented, not code-mitigated.

**T3 (non-regression, confirmed).** OR-only merge (C1) preserved: `policy::evaluate` unchanged in
shape (`src/policy/mod.rs:107-135`), mode only changes what the shell passes in.

**T4 (non-regression, pre-existing).** Under `enforce`, a fail-open OSV outage (C14) is
behaviorally indistinguishable from `off` for the outage's duration. Already accepted in
`threat-model-2.md` (C3/C14); not introduced by this change, not reachable via config alone.

**T5 (confirmed non-gap).** Cache (C13) stores the raw OSV answer keyed by
`(ecosystem, name, version)`, independent of mode; mode is read only at the point the
cached/batched result is consumed, never written into the cached value. No cross-mode poisoning.

**Unintended reachability (closed, contingent on T1).** Default is `enforce` (C16), an explicit
key is required to weaken it, no reload/hot-swap path exists for `osv_mode`. Adequately closed
once T1's validation policy is explicit.

**Decision-log heap ceiling (confirmed non-gap).** `BYTES_PER_RECORD` unaffected — the fix reuses
an existing `&'static str` reason already sized under C8; no new `String`/`Vec` field.

## Resolution
- G1: closed by C17b — reuse the existing task-local `RequestContext` seam
  (`src/http/logging.rs:100-106`), the same one `record_cache`/`ecosystem: AtomicU8` already use.
  Add `osv_diagnostic_match: AtomicBool` and `record_osv_diagnostic_match()`; `decide()`'s
  no-`ApiError` branch reads it and substitutes `BlockedByOsv`'s reason string while `result`
  stays `"ALLOWED"`.
- T1: closed by C18b — an unrecognized `osv_mode` value hard-fails startup, matching every other
  validated key in `config.rs` (zero precedent for silent fallback). A `tests/config_validation.rs`
  case asserts this.
- T2: accepted and documented as an operational note (no code change) — Gate 3/`docs/operations.md`
  records that `diagnostic` mode is monitor-only with no distinct metric.

## Second pass: MODELED

Every retained threat (T1-T5) now has a concrete, buildable mitigation or a confirmed non-gap;
G1's structural gap is closed by C17b's task-local seam, grounded directly in code the middleware
already reads. The non-regression check confirmed C1 (OR-only merge), C3 (never fail-closed),
C15 (OSV-blind-first ordering), and threat-model-2.md's prior findings (G1/G2/G3 closures, T1/T5
non-gaps) all still hold under `osv_mode`.
