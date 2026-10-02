# Repository grounding — OSV vulnerability intelligence (Gate 2)

Source: `sf-repo-onboarding` briefing, 2026-09-27. Read-only; not written to `docs/codebase-overview.md`
(that file is stale — dated 2026-09-17, describes a repo with "no source code" — but refreshing it is
out of this plan's scope).

Tooling note: `smtc orient --with-repo-map --with-health` ran but `analysis_freshness.status: not_built`
(`dirty_build: true`) — module-health numbers are informational only; all code-path claims below are
grounded by direct `Read` of the source, which is authoritative regardless.

## Purpose

Osprey (binary `package-firewall`, crate `package_firewall`) is a self-hosted registry proxy for public
npm and PyPI packages (`SPEC.md:1-16`). It hides releases younger than a configurable cooldown (default
24h) and hides/refuses known-malicious packages and artifacts, while npm/pip retain dependency
resolution. This feature adds OSV's `MAL-*` malicious-package advisory feed as a second, additive block
source alongside the existing operator-fed blocklist snapshot (block if either source blocks; neither
can un-block what the other flags — `01-product.md` C1).

## Start here

- `src/lib.rs` — the injectable `App`/`AppDeps`/`Running` seam; `App::start` is the single constructor,
  every background loop, sink, and route is wired from here.
- `src/main.rs` — CLI (`serve`, `check-config`, `check-blocklist`); builds production `AppDeps`, maps
  errors to exit codes.
- `SPEC.md` — the current, exhaustively detailed implementation spec (§5 eligibility rules, §8 blocklist
  interface, §9 artifact flow) — ground truth for existing behavior.
- `docs/backlog.md` — B1 (OSV feature, accepted) and B2 (provider abstraction, **declined**) govern this
  feature's scope.
- `docs/plans/osv-intel/01-product.md` — Gate 1: resolved C1-C5 (merge semantics, digest-independence,
  fail-open on OSV outage, malicious-only scope, hardcoded-Rust-no-abstraction).

## Shape (module ownership/consumers)

| Module | Responsibility |
| --- | --- |
| `config` (`src/config.rs`, 504 lines) | Parses/validates TOML → `Config`. `RawConfig` (serde, `deny_unknown_fields`) → `validate()` → `Config`. Single source of truth; `serve` and `check-config` both go through `Config::load`. New keys need entries in `REQUIRED_KEYS`/`OPTIONAL_KEYS` plus a fixture line in `tests/config_validation.rs`. |
| `policy` (`src/policy/{mod,blocklist,digest}.rs`) | Pure decision logic, no I/O, no clock reads inside `evaluate()`. `evaluate()` turns a `Candidate` + `BlocklistSnapshot` + `now` into a `Decision` (`Unavailable`/`Deny`/`Hold`/`Allow`). `blocklist.rs` owns `BlocklistSnapshot` (immutable, parsed/validated once) and `check_replacement` (revision/rollback rules). |
| `tasks` (`src/tasks/{mod,blocklist_poller,maintenance}.rs`) | Background loops, all `tokio::spawn`ed from `tasks::spawn`, sharing one `CancellationToken` for graceful shutdown. `blocklist_poller.rs` is the only existing pattern for polling external state into policy. |
| `delivery` (`src/delivery/{mod,file,siem,counters}.rs`) | Where a decision record goes after being made: optional NDJSON file sink and/or SIEM HTTP `POST` sink, both non-blocking (`Sinks::offer` is sync, drops-and-counts on backpressure), spawned only if configured. `siem.rs` is the only existing pattern for an outbound HTTP client inside a background task (batching, backoff, drain deadline). `pub(crate)` only — no public Rust surface. |
| `http` (`src/http/{mod,health,logging,error,limits,npm_routes,pypi_routes,artifact_routes}.rs`) | Axum router, explicit routes only, health endpoints, request-scoped decision logging middleware, bounded concurrency (`limits.rs`). |
| `upstream` (`src/upstream/{mod,origins,resolver,reqwest_transport}.rs`) | The only existing pattern for a registry HTTP client: injectable `Transport` trait, two `reqwest::Client`s (metadata vs. artifact, different timeouts), fixed-origin allowlist (`origins.rs`), private/loopback-address rejection (`resolver.rs`), size-capped streaming reads. |
| `store`, `artifacts`, `npm`, `pypi`, `concurrency`, `clock` | Turso persistence, artifact download/verify/cache, ecosystem-specific metadata, single-flight coalescing, injectable clock. `store` is where `commit_blocklist`/`load_blocklist` live (used by the poller) — template for persisting an OSV snapshot/cursor if needed. |

Consumers: `lib.rs` re-exports all top-level modules as `pub` except `delivery` (`pub(crate)`).
`main.rs` only imports `config`, `policy::blocklist`, `clock`, `upstream`, and `App`/`AppDeps` — never
`delivery`, `tasks`, or `policy::mod` directly; wiring happens inside `App::start`.

## Build and test

```
cargo build / cargo test
cargo bench --bench delivery_rated_load
```

`tests/` has real integration tests (`config_validation.rs`, `blocklist_reload.rs`,
`blocklist_revocation.rs`, `blocklist_snapshot.rs`, `decision_log_delivery.rs`, `e2e_npm.rs`,
`e2e_pip.rs`, `http_contract.rs`, etc.) against `tests/common/mod.rs` (`TestClock`, `TestServer`,
`sample_config`) and `CARGO_BIN_EXE_package-firewall`. `tests/config_validation.rs` drives config
validation two ways (library `Config::load` and `check-config` binary) off one shared fixture table
(`INVALID_CONFIGS`) — the established convention for new config-key validation.

## Conventions

- **Pure-core/impure-shell**: `policy::evaluate` and `BlocklistSnapshot` are pure; the poller
  (`tasks/blocklist_poller.rs`) does all I/O and clock reads, hands validated data to the pure core. Any
  OSV decision rule should follow this split.
- **Commit-then-publish**: every state-changing background loop persists via `store` *before*
  publishing the new in-memory snapshot via `ArcSwapOption` (`App::publish_blocklist`) — a failed
  persist leaves the old snapshot in force. Hard invariant.
- **Injected seams for testability**: `Transport`, `Clock`, `OriginSet` are constructor-injected via
  `AppDeps`; tests never touch the real network. Any OSV HTTP client should be injected the same way.
- **`&'static str` for anything that could reach a printed error** (e.g. `StartupError::Delivery`) so no
  secret/interpolated value leaks into it.
- Extensive doc comments citing `SPEC.md` section numbers as rationale — SPEC is living, authoritative
  design documentation.

## Invariants

- **SPEC §5 decision order is fixed**: `Unavailable → Deny(package) → Deny(version) → Deny(digest) →
  Deny(timestamp) → Hold → Allow`, enforced by `policy::evaluate`'s literal code order, pinned by
  `check_order_is_unavailable_deny_hold_allow` (`src/policy/mod.rs`). A second block source (OSV) must
  compose into this ordering without disturbing it — C1's "block if either source blocks" is an AND/OR
  extension, not a reordering.
- **Commit before publish**: `tasks/blocklist_poller.rs::poll_once` calls `commit_blocklist(...)` and
  only calls `publish_blocklist(...)` on success; a persistence failure leaves the previous snapshot in
  force and retries. Same pattern must hold for any new source of block data.
- **A rejected/expired snapshot never becomes an empty blocklist**: the last accepted, still-valid
  snapshot stays in force; `/health/ready` goes unhealthy at expiry while `/health/live` stays healthy
  (`src/http/health.rs`).
- **Revision monotonicity + no-silent-partial-apply**: `BlocklistSnapshot::parse_and_validate` is
  all-or-nothing; `check_replacement` rejects rollback and same-revision content changes.
- **No new public Rust surface for delivery/background features**: `delivery` is `pub(crate)`; an OSV
  poller module would plausibly follow `tasks::blocklist_poller`'s visibility posture.
- **C3 (resolved, Gate 1)**: an OSV-fetch outage must **not** fail-closed the firewall — contrasts with
  the existing blocklist's fail-closed-on-expiry behavior. Gate 2 needs an explicit design for "OSV data
  absent/stale" that is NOT modeled on `BlocklistSnapshot::is_valid_at`'s expiry-driven unavailability.

## Hotspots and landmines

- `docs/backlog.md` B4: adding a caller-identity field to `Decision` (`src/delivery/mod.rs`) would break
  the `BYTES_PER_RECORD` derivation (a compile-time `const _: () = assert!(...)` ceiling on the struct's
  heap footprint, derived field-by-field in a comment) — same risk applies if OSV data changes the shape
  of a decision record (e.g. a "matched-by: producer/OSV/both" reason field). Read
  `src/delivery/mod.rs:44-110` before touching `Decision`.
- `docs/plans/rated-load-guard/` is an in-flight, separate plan actively fixing `BYTES_PER_RECORD` and
  load-shedding behavior around `delivery`; touching that module for OSV without checking that plan's
  current state risks silent conflict (git status shows `src/delivery/*`, `src/http/{health,logging,mod}.rs`,
  `benches/delivery_rated_load.rs` all modified/added, consistent with that plan being mid-flight).
- `SPEC.md:59` bans "a dependency solver or generic plugin framework" — `docs/backlog.md` B2 argues this
  doesn't bar hardcoded-OSV-in-Rust, and the user separately declined any provider abstraction. Gate 2
  must not reintroduce a provider trait/interface for "future intelligence sources" (C5, B2).
- The blocklist poller's change detection (`FileIdentity` — device/inode/mtime) is file-specific; an OSV
  poller talking to an HTTP API needs a different "did anything change" signal (cursor/ETag/last-modified
  or polling window), not a reusable piece of this code — only its overall shape (capped read → validate
  off-request-path → commit → publish, with a `Retry::Later` vs `Retry::NotUntilItChanges` distinction).

## Unknowns (Gate 2 must resolve or defer)

- Where OSV's per-advisory identity (package name + version range, no digests per C2) should be
  persisted/cached, and whether that needs a new `store` table analogous to the blocklist's.
- Whether the OSV poller should be a second loop in `tasks::` or a new top-level module (both equally
  consistent with current module boundaries).
- What OSV API surface/pagination/rate-limit shape is being targeted (batch `MAL-*` export vs.
  per-package query) — external-API research, not visible from the repo.

## Evidence freshness

- `smtc orient --root <root> --with-repo-map --with-health --format json --max-tokens 4096
  --session-id sf-repo-onboarding-2026-09-27`: ok, structural, but `analysis_freshness.status: not_built`,
  `dirty_build: true` — limitation, not a clean verdict.
- Manual, full or near-full reads (2026-09-27) of: `SPEC.md`, `docs/backlog.md`,
  `docs/plans/osv-intel/01-product.md`, `docs/plans/osv-intel/gate-1-qa.md`, `src/config.rs`,
  `src/policy/mod.rs`, `src/policy/blocklist.rs`, `src/tasks/blocklist_poller.rs`, `src/delivery/mod.rs`,
  `src/lib.rs`, `src/main.rs`, `src/http/mod.rs`, `src/http/health.rs`, `src/tasks/mod.rs`,
  `src/upstream/mod.rs`, `src/delivery/siem.rs` (partial), `src/upstream/reqwest_transport.rs` (partial),
  `tests/config_validation.rs` (partial).
