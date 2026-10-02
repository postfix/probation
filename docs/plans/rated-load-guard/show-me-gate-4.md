## What problem do we have?
Today a SIEM sink gives up on a down collector after about 7 seconds of retries and its queue is a fixed 4096 records, so a maintenance window costs records with no published figure for what an operator can survive. Gate 3 fixed every signature; Gate 4 orders the build so each slice has a witness that fails today. Slice 1 is done (`evidence/slice-1.md`); this approval covers the revised slices 2-7.
## How will we solve it?
Build order, seven slices (2-7 are the ones you approve):

| # | Outcome | APIs used or changed | Witness | Temporary limit |
|---|---|---|---|---|
| 1 (done) | `siem_queue_max_bytes` / `log_queue_max_bytes` size the queue as `budget / BYTES_PER_RECORD` | `capacity_for`, `Config`, `delivery::build` | `rl1`-`rl6`, amended `tp7` | provisional 64 MiB default |
| 2 | `method` bounded by `loggable`; decision line still precedes `offer`; `RUST_LOG` cannot silence the decision log | `build_decision`, `decide` unchanged, one line in `src/main.rs` | `rl16b`, `rl22`, `rl24`, `rl24b`; red today: only `rl24b` | none |
| 3 | all eight loss sites go through `SinkCounters::lose`; compiler refuses any other write | `SinkCounters`, `Sinks::drops`, `App::delivery_lost_total` (test-support) | `rl7`-`rl9`, `tp19`; `E0616` negative control (C82); `rl11` structural | none |
| 4 | `cargo test` fails if delivery collapses; driver measures the debug rate that fixes `F` | `drive_rated_load`, `RatedLoadResult` | `rl17`-`rl19` within `D + 30 s` | none |
| 5 | `GET /health/delivery`: `503` for 60 s after a loss, else `200`; `/health/ready` stays `200` | `Sinks::is_shedding`, `health::delivery` | `rl12`-`rl15`, `rl16c`, `rl25`; `rl16` structural | none |
| 6 | SIEM holds its batch during an outage; shutdown still returns; no hot-spin | `send` gains `drain: &CancellationToken` | `rl10`, `rl10b`, `rl23`, `rl23b`; `tp7`/`tp9`/`tp11a`/`tp15`/`tp15b` unedited | none |
| 7 | rated figure, outage tolerance, floor and `BYTES_PER_RECORD` derivation published | bench `delivery_rated_load` (`bench = false`, run by name) | `rl20`, `rl21`; eight docs items read by hand | removes 64 MiB and `rl5` literal |

Files that differ from slice 1 (diff of what each later slice adds):
```diff
+ 2: src/main.rs (one directive), docs/operations.md (:414-419 sample)
+ 3: src/delivery/counters.rs, src/lib.rs
+ 4: tests/common/mod.rs, tests/delivery_rated_load.rs
+ 5: src/http/health.rs, src/http/mod.rs
+ 6: src/delivery/siem.rs
+ 7: benches/delivery_rated_load.rs, Cargo.toml, tests/config_validation.rs, README.md
```
Slice 2 pin (C87), `rl24b` runs the built binary and sends SIGTERM with `kill -TERM <pid>` via `std::process::Command`, no new dependency (C94):
```diff
  EnvFilter (src/main.rs:58-63)
+ .add_directive("package_firewall::http::logging=info".parse().expect("static directive"))
```
Order rationale: measurement moved to 4 because it does not depend on the SIEM hold (C81); `rl24` sits in slice 2, the only slice that can break it (C74); `rl23b` uses a prompt-503 timestamping collector and asserts intervals `>= 2 s` after the first three (C79); line anchors are HEAD `734d22d` unless a row says otherwise (C95).
## How will we confirm it is solved?
- Slice 2: `RUST_LOG=hyper=debug` -> decision line on stdout after SIGTERM -> `rl24b` (planned; today 0 bytes of stdout, reproduced 2026-09-25). `rl16b`/`rl22` red seeds are recorded in `evidence/tdd-slice-2.md`; `rl24b` is not written yet.
- Slice 3: raw `counters.window.fetch_add` in `src/delivery/file.rs` -> `E0616` captured then reverted -> `cargo check --all-targets` (planned).
- Slice 4: driver offers, delivers, drops -> `(offered + 1) - delivered == dropped` -> `cargo test --test delivery_rated_load` (planned).
- Slices 5-7: rows above; each runs `cargo check --all-targets` then its `cargo test` / `cargo bench --bench delivery_rated_load` command (planned).
Recommendation: approve. The order puts the High memory bound (`rl22`, G3-T3) second and the measurement risk fourth; `sf-gate-qa` returned READY and the red-team findings are resolved in C78-C82.
Limits: `rl11` and `rl16` are structural with no executable witness (C52); `rl24b` needs `kill(1)` on the host (C94); slice 7 documents eight items verified by a reviewer, not a command; nothing in Gate 4 was executed by QA. Slice 1 evidence flags `BYTES_PER_RECORD` at 32 KiB against the ~1 KiB Gate 4 assumed: the 64 MiB default holds about 2048 records (~10 s at 200 rps, below today's ~20 s) and C13's five-minute rule exceeds the 4 GiB ceiling above ~437 rps. That is a Gate 3 (C44) question, not settled here, and slice 7's literal is to be questioned if outside 60-250 MiB (C76).
Status: Gate 4 QA READY (`gate-4-qa.md`, round 7); Gate 3 reopen decisions C87, C90, C93 carried; slice 1 complete.
Sources: `04-slices.md` (C70-C82, C86, C94, C95), `gate-4-qa.md`, `evidence/red-team-gate4.md`, `evidence/tdd-slice-2.md`, `evidence/reproduction-2026-09-25.md`, `evidence/slice-1.md`
Approve Gate 4, or what should change?
