# Status: Rated load guard

- Gate 1 — Product: APPROVED 2026-09-23
- Gate 2 — Architecture: APPROVED 2026-09-26
- Gate 3 — Program Design: APPROVED 2026-09-27
- Gate 4 — Slice plan: APPROVED 2026-09-27

## Factory settings

- presentation: auto

## Loop signal

{"generation":19,"boundary":null,"reopened":false,"history":[]}

## Slices

- [x] Slice 1 — tracer bullet: operator-sized delivery queues, with a bad budget refused at load
  - proof: cargo check --all-targets && cargo test --lib --test config_validation --test decision_log_delivery -> check exit 0; test result: ok for all three binaries — 85 / 25 / 18 passed, 0 failed, including rl1-rl6 and the amended tp7; reviews: code-review=SHIP, security=FIX FIRST-resolved (all findings applied; round detail in evidence/slice-1.md)
- [x] Slice 2 — every record's method bounded, so BYTES_PER_RECORD is a real ceiling
  - proof: cargo check --all-targets; cargo test --lib --test decision_log_delivery -> exit 0; ok. 87 passed (lib), ok. 20 passed (integration) incl. rl16b rl22 rl24 rl24b; reviews: code-review=SHIP, security=CLEAR, adversarial=PASS
- [x] Slice 3 — all eight loss sites account through SinkCounters::lose, plus a monotonic total
  - proof: cargo check --all-targets; cargo test --lib --test decision_log_delivery -> check exit 0; lib ok 94 passed, decision_log_delivery ok 21 passed incl. rl7, rl8, rl9, tp19; E0616 negative control re-witnessed; reviews: code-review=SHIP, adversarial=PASS, qa=VERIFIED
- [x] Slice 4 — the closed-loop load driver and the cargo test floor that fails on a collapse
  - proof: cargo test --test delivery_rated_load -> test result: ok. 3 passed (rl17, rl18, rl19) in ~6 s; F=1500 B=122_880_000; reviews: code-review=SHIP, qa=VERIFIED, adversarial=PASS
- [x] Slice 5 — GET /health/delivery reports shedding for 60 s while /health/ready stays green
  - proof: cargo check --all-targets; cargo test --lib --test decision_log_delivery -> ok: 94 lib + 27 integration passed incl. rl12 rl13 rl14 rl15 rl16c rl25; reviews: qa=VERIFIED, code-review=SHIP, security=CLEAR, adversarial=PASS
- [x] Slice 6 — the SIEM sink holds its batch while the collector is unreachable, bounded and cancellable
  - proof: cargo check --all-targets; cargo test --test decision_log_delivery -> check exit 0; ok. 31 passed incl. rl10 rl10b rl23 rl23b tp7 tp9 tp11a tp15 tp15b; reviews: code-review=SHIP, security=CLEAR, adversarial=PASS, qa=VERIFIED
- [x] Slice 7 — the bench, the published numbers, and the final default budget literal
  - proof: cargo check --all-targets; cargo bench --bench delivery_rated_load; cargo test --no-fail-fast -> corrected mid-slice (C39 supersedes this session's first answer C98, see 04-slices.md): DEFAULT_QUEUE_MAX_BYTES=1,875 MiB from the 200 req/s reference load, not from measured N; check exit 0; bench: calibrated+confirmed loss-free at full 600s, N=59,288 (published for reference only), exit 0; test: every target ok, 0 failed; reviews: code-review=SHIP, qa=VERIFIED (both re-run against the corrected diff)

## Notes for a fresh session

- Requested by the user on 2026-09-23, straight after the decision-log-delivery feature shipped
  on branch `package-firewall-mvp` (PR #1, commits `d27dc9f` and `734d22d`).
- WHY THIS PLAN EXISTS. `01-product.md` of decision-log-delivery promises: "no decision record
  is lost while the firewall is serving at its rated load, and any record that is dropped is
  counted and reported rather than discarded quietly." The second half shipped and is witnessed
  (`tp7`, `tp15b`). The first half never had a witness, because **"rated load" has no number
  anywhere in the firewall**. The user accepted that gap on 2026-09-23 as decision-log-delivery
  C52, on the condition it returns as its own plan. This is that plan.
- WHAT ALREADY EXISTS and must not be reinvented: both sinks are bounded queues that drop rather
  than block (`src/delivery/`), every drop is counted and surfaced as `dropped_file` /
  `dropped_siem` on the summary record, and `tests/decision_log_delivery.rs` holds the delivery
  integration suite with `TestServer`, `TestClock` and a `wiremock` collector. The MVP's own
  limits already name concurrency ceilings in `config.sample.toml`: `max_active_requests = 1024`,
  `max_upstream_requests = 32`, `max_artifact_downloads = 8`.
- THE OPEN PRODUCT QUESTION, which is what Gate 1 has to settle: "rated load" can mean a
  requests-per-second figure the operator is promised, a queue-depth headroom claim, or a
  documented measurement an operator can re-run on their own hardware. These lead to very
  different features, and the choice is the user's.
