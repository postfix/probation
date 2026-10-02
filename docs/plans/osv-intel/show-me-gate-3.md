## What problem do we have?

Gate 2 reopened because the user asked whether OSV blocking can be switched on/off in config, and
whether a diagnostic mode exists that only logs malicious matches without refusing them — neither
existed. `osv_mode: enforce/diagnostic/off` was added as new config keys. Gate 3 reopened in turn:
its original program design (D1-D4) pinned `osv::evaluate`'s two-phase dance and config shape, but
never pinned the concrete Rust types and call shapes that make the new mode operator-configurable.
Without that pinning, an implementer would have to invent where `OsvMode` lives and how 4 existing
production call sites become mode-aware without each hand-rolling its own branch.

## How will we solve it?

D5-D8 pin exactly that, reusing D2's existing `osv::evaluate` wrapper so the mode branch lives in
one place, not four.

```rust
// src/osv/mod.rs
pub enum OsvMode { Enforce, Diagnostic, Off }   // Copy, Clone, PartialEq, Eq, Debug

pub struct OsvClient {
    tx: mpsc::Sender<OsvRequest>,
    cache: OsvCache,
    mode: OsvMode,                               // D5: set once at construction, never mutated
}

// existing, Slice 1; changed, D5 — both gain a `mode: OsvMode` parameter
pub fn new(client: reqwest::Client, cache_ttl: Duration, request_timeout: Duration,
           mode: OsvMode, shutdown: CancellationToken) -> (OsvClient, JoinHandle<()>);
pub(crate) fn spawn_with(client: reqwest::Client, url: Url, cache_ttl: Duration,
           request_timeout: Duration, mode: OsvMode, shutdown: CancellationToken)
           -> (OsvClient, JoinHandle<()>);

// proposed; osv::evaluate's own signature is unchanged from D2 — the mode branch is internal
pub async fn evaluate(osv: &OsvClient, snapshot: Option<&BlocklistSnapshot>,
           now_utc_micros: i64, cooldown_seconds: u64, candidate: &Candidate<'_>) -> Decision;
```

`osv::evaluate` branches once, inside itself, on `osv.mode`:
- `Off` — returns the OSV-blind `policy::evaluate` result unchanged; `OsvClient::check` is never called.
- `Enforce` — D2's existing two-phase dance, unchanged.
- `Diagnostic` — the same two-phase dance runs (so the cache and batcher still see every request),
  but the second `policy::evaluate` call always passes `osv_matched: false` (never denies); if the
  real check answered `true`, calls `record_osv_diagnostic_match()` first.

```rust
// src/config.rs — D6, following public_url's string-then-validate idiom
osv_mode: match self.osv_mode {
    Some(value) => match value.to_lowercase().as_str() {
        "enforce" => osv::OsvMode::Enforce,
        "diagnostic" => osv::OsvMode::Diagnostic,
        "off" => osv::OsvMode::Off,
        _ => return Err(invalid("osv_mode", format!("must be one of enforce, diagnostic, off, got {value:?}"))),
    },
    None => osv::OsvMode::Enforce,   // default, hard-fail on unrecognized value, no serde default attribute
}
```

```rust
// src/http/logging.rs — D7, mirroring record_cache's exact shape
// RequestContext gains: osv_diagnostic_match: AtomicBool
pub fn record_osv_diagnostic_match();  // no-op outside a request, same tolerance as record_cache
pub(crate) const OSV_DIAGNOSTIC_REASON: &str =
    "the request would be blocked by a known OSV malicious-package advisory (diagnostic mode: not enforced)";
// decide()'s no-ApiError branch: if osv_diagnostic_match is set, reason = OSV_DIAGNOSTIC_REASON; result stays "ALLOWED"
```

D8 confirms this is a pure pinning: no new entry point, trust boundary, or asset beyond Gate 2's
`threat-model-3.md` (MODELED) and Gate 2's Red Team pass (FIX FIRST, closed by C17c) — `sf-threat-model`
and `sf-red-team` are not re-dispatched.

## How will we confirm it is solved?

| Behavior | Test | Guards |
|---|---|---|
| `off` mode never calls `OsvClient::check`, decision matches OSV-blind result | `evaluate_off_mode_never_calls_check` (real client via `spawn_with` against a `counting_server` asserting zero requests) | core |
| `enforce` mode denies on a real OSV match, unchanged from today | `evaluate_enforce_mode_denies_on_match` | core |
| `diagnostic` mode allows even on a real OSV match | `evaluate_diagnostic_mode_allows_on_match` | boundary |
| `diagnostic` mode with no match also allows | `evaluate_diagnostic_mode_allows_without_match` | boundary |
| `record_osv_diagnostic_match` sets only `reason`, never `result` | `record_osv_diagnostic_match_sets_the_reason_without_changing_result` (integration/e2e, delivered decision-log record) | core |
| `record_osv_diagnostic_match` outside a request is a no-op | `record_osv_diagnostic_match_outside_a_request_is_a_no_op` | error |
| `osv_mode` rejects an unrecognized value with a named reason | `every_invalid_config_fixture_is_refused_with_its_reason` (3rd new row) | error |
| `osv_mode` defaults to `enforce` when absent | `osv_mode_defaults_to_enforce_when_absent` | boundary |
| Security: no new entry point/trust boundary/asset introduced by D5-D7 | D8 non-regression check against `threat-model-3.md` (MODELED) and Gate 2's Red Team FIX FIRST closure | security |

All rows are planned checks at this Gate; `sf-tdd` implements them one at a time. Gate QA
(`gate-3-qa.md`) independently verified the design against live source across 4 REVISE rounds (7
findings: F1-F7, all closed) and returned READY.

Recommendation: approve. The reopen adds no new architectural risk — D5-D8 are grounded, mechanical
pinnings of Gate 2's already-threat-modeled and already-red-teamed `osv_mode` design, verified
against current repository source (not just the document's own claims), with zero open findings.
Limits: `osv_mode` has no hot-reload path (least-confident-decision 4) — changing it requires a
process restart, consistent with every other config value in this codebase; worth confirming
operators are comfortable with that before shipping a diagnostic-mode rollout under a live incident.
Status: Gate 3 reopened only to pin D5-D8; Slices 1-3 already built and verified stand unchanged
(the new mode is additive and defaults to today's enforce-always behavior). Gate 2's re-steer and
this Gate's QA round history are recorded in the plan's status notes.
Sources: docs/plans/osv-intel/03-program-design.md (D5-D8, Files, Modules and interfaces, Call
stack, Test plan, Threat model, Least confident decisions); docs/plans/osv-intel/gate-3-qa.md
(READY, F1-F7).
Approve Gate 3, or what should change?
