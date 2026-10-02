# Red team — Gate 4 slice plan

`sf-red-team`, 2026-09-24, verdict **NEEDS REVISION**. Review kind: red-team, independent,
read-only. Tier **structural** throughout: every source claim derives from SMTC (`file read`,
`file grep`, `file find`, `inspect file`, `search symbol`); nothing was executed, so "fails today"
is asserted from source rather than observed, and C73's `cargo test --lib` feature-unification
claim is unverified by running.

Subject hashes at review time: `04-slices.md`
`cafcc0e6b08dc66c0bd30a1df025ed4ced9a1b5c5a54bdd0356e4e6f2059bc47`, against the three approved
gates and `evidence/gate4-siting.md`
`98a74593458a29f1b09a1fc06a693a4fe1fe5e9a53246860b20abab1e672c82a`. Threat model supplied as
`evidence/threat-model-gate3.md` (MODELED, 8 retained threats); no fresh model was dispatched
because Gate 4 introduces no new seam, entry point, asset or trust boundary — it sequences
surfaces Gate 3 already modelled.

## Findings and dispositions

Six findings, ordered blockers first. All six are resolved in the current revision.

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | **Blocker** | `rl23b` cannot fail and has no observable. `wedged_collector()` (`tests/decision_log_delivery.rs:1097-1109`) pushes each accepted `TcpStream` into a local `Vec`, never reads it and records no time — so "POSTs observed at the collector" is unobservable there. Worse, `SIEM_REQUEST_TIMEOUT` is 3 s (`src/delivery/mod.rs:191`), so against a collector that accepts and goes silent, `request.send().await` (`src/delivery/siem.rs:149`) burns 3 s before the `Err` arm (`:166-172`) reaches the backoff sleep at `:181`: the inter-attempt interval is `>= 3 s` **with no sleep at all**, so the row passes against the bare `loop { send }` hot-spin C46 and G3-T5 exist to reject. The `tp7` device C41 records, one layer down. | **Fixed — C79.** `rl23b` drives a new prompt-`503` collector that reads the request, answers immediately and timestamps each arrival, modelled on `silent_collector()` (`:1115-1134`). With no timeout contribution the observed interval is the backoff sleep alone: `>= 2 s` against the C46 implementation, near zero against the forbidden one. `wiremock` was considered and rejected — `received_requests()` carries no arrival timestamps. |
| 2 | **Blocker** | `rl5` and the floor test's `B` name `pub(crate)` constants from `tests/`. `src/lib.rs:13` is `pub(crate) mod delivery;`, so an external test crate can name neither `DEFAULT_QUEUE_MAX_BYTES` nor `BYTES_PER_RECORD`; the bench's `#[path]` include does not change that. Widening either contradicts Gate 3 ("the crate's only new gated item") and Gate 2 ("adds no public Rust API"). Neither can move in-crate the way C61 moved `rl6`. As written, slices 1 and 4 do not compile. | **Fixed — C80.** Both state their number as a literal with the derivation in a comment. `rl5`'s literal tracks the default, so `tests/config_validation.rs` is added to slice 7's exact files and updated in the same change that sets the final constant. `B` does **not** track anything: `BYTES_PER_RECORD` is derived, not measured, and final from slice 1. |
| 3 | Major | C78 misreported the tree. `file grep 'app\.delivery\.offer'` returns exactly one source hit, `src/http/logging.rs:243` — Gate 3's citation, not the draft's `:241`. Slice 3 also cited `mod file;` / `mod siem;` at `:12-13` where Gate 3 says `:13-14`. A gate whose stated policy is to record drift rather than silently correct it had become a source of drift. | **Fixed — C78 rewritten as a withdrawal.** Gate 3's `:243`, `:13-14` and `:207-222` are authoritative and cited unchanged. The view that reported otherwise flagged a zero-based/one-based conversion hazard in its own limitations; the red team verified its conversion against a 1-based read. |
| 4 | Major | (a) `rl24` was sited in slice 3, where it cannot fail: `tracing::info!` already precedes `offer` in the shipped tree and slice 3 touches neither. The only slice that can break the ordering is slice 2, whose witness observed nothing of it. (b) Slice 3 claimed `cargo check --all-targets` exiting 0 "is itself the witness" for the C45 compile-time half — but that command exits 0 before and after, so it distinguishes nothing. | **Fixed — C74 amended and C82 added.** `rl24` moves to slice 2 as the regression guard for the `build_decision` extraction. The compile-time half is evidenced by a negative control: one raw `fetch_add` outside `counters`, the `E0616` captured into `evidence/slice-3.md`, then reverted. |
| 5 | Major | Both Gate-4-owned sequencing rows gave a false reason for a right decision. (a) C77 said an under-sized `BYTES_PER_RECORD` "merely makes the queue shorter" — inverted: capacity is `budget / BYTES_PER_RECORD`, so understating the record makes the queue hold **more** bytes than the budget, which is exactly G3-T3's High asset. (b) C76 claimed the provisional 64 MiB is "large enough that no existing test's premise changes", while slice 1's own `Changes` amends `tp7` because a large default removes its overflow premise. | **Fixed — both rewritten.** C77 states the real exposure (resident bytes above the published budget, unbounded while `method` is) and keeps the conclusion. C76 states that 64 MiB does remove `tp7`'s premise, which C41 already requires amending, and that no other test's premise changes. C76 also now records the ~60–250 MiB band C13's formula implies at the rated rate, so a slice-7 literal far outside it is questioned rather than adopted. |
| 6 | Major | Slice 6's dependency on the SIEM hold was false — the driver configures the file sink only (C48, C54) — and the false edge parked the plan's largest measurement risk at position 6 of 7. An unusable debug rate invalidates C60, C67 and slice 7. | **Fixed — C81.** The measurement slice moves to position 4, immediately after the loss-site discipline it genuinely needs. The shedding signal and the hold become 5 and 6; nothing that now precedes them depends on them. |

## Smaller defects, all fixed in place

- `rewind_wall_clock_seconds` cited at `tests/common/mod.rs:44-47`, which is the `TestClock` doc
  comment; the method is at `:86-91`. `TestClock` cited as `:49-75`; the struct is `:49-57` and
  `:75` is the first line of `set_rfc3339`. Corrected in slice 5's `Uses`.
- C73 cited `README.md:72` for the `cargo test --test <target>` shape; `:72` is bare `cargo test`
  and the shape is at `:73-74`. `:75` is bare `cargo bench`, and the repository documents no
  `--bench <name>` form at all — which is what C86 asks the user about.
- Slice 5's `Uses` (now slice 6) listed `src/delivery/siem.rs:145-147` among "the non-retryable
  rejection arms"; that block is credential attachment, and the rejection arms are `:164` and
  `:175-177`. Both are now named for what they are.
- Slice 1's witness said "the three new `config_validation` cases" where its Acceptance lists four.
- `rl25`'s `Cache-Control: no-store` limb is entailed by the router-wide `map_response(no_store)`
  applied at `src/http/mod.rs:67` (function at `:94`), so it can only fail by breaking every
  existing route. The **empty body** limb is the discriminating one, and the row now says so.
- `rl21` was claimed twice, "in part" by slice 3 and in full by slice 7. Slice 3 no longer claims
  it.
- Slice 4's driver reads `App::delivery_lost_total` after `Running::shutdown`, which does
  `drop(self.app)` (`src/lib.rs:327`). It works only because the driver clones the handle through
  `pub fn app(&self) -> Arc<App>` (`tests/common/mod.rs:238`) **before** shutting down. Getting it
  wrong reads zero, so it is now stated in `Uses`.

## Completeness against Gate 3

The `## Test plan` table (`03-program-design.md:894-922`) holds **29** rows, not 24: `rl1`–`rl25`
plus `rl10b`, `rl16b`, `rl16c`, `rl23b`. Every one is assigned to exactly one slice, with its Gate 3
evidence kind preserved — `rl6`, `rl16b` and `rl22` stay property with `proptest` and committed
`proptest-regressions/`; `rl11` and `rl16` stay structural and say so in both the Gate 3 row and the
slice cell; every other row stays execution. Slice 7 *adds* a manual limb for the six documentary
deliverables, which Gate 3 carried as `## Files` rows with no check — an addition, not a downgrade.
After the revision the assignment is: slice 1 `rl1`–`rl6`; slice 2 `rl16b`, `rl22`, `rl24`; slice 3
`rl7`, `rl8`, `rl9`, `rl11`; slice 4 `rl17`, `rl18`, `rl19`; slice 5 `rl12`–`rl16`, `rl16c`, `rl25`;
slice 6 `rl10`, `rl10b`, `rl23`, `rl23b`; slice 7 `rl20`, `rl21`.

## Checked clean

**Coverage** — every Gate 3 requirement traces to a slice and a falsifiable check, modulo findings
1, 2 and 4; no unjustified scope. **Sizing** — seven slices, each a coherent increment; slice 1 is
the largest but its parts share one compile unit and cannot be split without a half-typed `Config`.
**Hard bar** — G3-T3, the High memory-bound control, is attacked second by a falsifying property
rather than an assertion, and the published-numbers half is correctly last. **Siting** — C70, C71,
C72, C74 and C75 were re-derived independently and land byte-exact, including `src/config.rs`
ending at `:426` with no `#[cfg(test)]`, `RawConfig::validate` private at `:175`, `OPTIONAL_KEYS`
`:145-153`, `sample_with` `:579-586`, the `log_file_max_bytes` precedent `:592-605`,
`keys.len(), 17` at `:171`, `WITH_DEFAULTS` at `:174`, `#[cfg(test)] mod tests` at
`src/http/logging.rs:465-499`, `tp19` at `src/delivery/file.rs:227-267`, `mod stdout` with
`capture()` at `:1264` installing a binary-wide INFO subscriber and `decision_line` at `:1287-1297`,
and `tp15`'s guard quoted verbatim at `:1016-1018`. **Slice 6's whole `siem.rs` citation set** and
**slice 1's whole `delivery` citation set** land exactly. **Build order beyond finding 6** — every
other `Dependencies` cell is satisfied by the shipped tree or a named earlier slice.

**Threat coverage applied:** G3-T3 (High) carried by `rl22`, early and falsifiable — clean. G3-T4
(High) carried by `rl23` with `tp15`'s verbatim 20 s guard — clean. G3-T5 (Medium) — finding 1,
fixed by C79. G3-T6 (Medium) — finding 4(a), fixed by C74. G3-T1, G3-T2, G3-T7 and G3-T8 map to
their slices with their structural, compile-time and accepted tiers intact, G3-T2's now resting on
C82's negative control rather than on a green build.

**Also checked and clean within finding 5:** C76's deferral of the literal does not contradict
approved C13 — `02-architecture.md:10` says the literal "and the tolerance it yields … are produced
by the slice that measures the constant" — and at the ~200 rps `01-product.md:18` implies, the final
default lands near 60–250 MiB, comfortably inside C36's 4 GiB ceiling, so the slice-7 recomputation
cannot collide with it.

## Limitations

`01-product.md` and `02-architecture.md` were read only through targeted decision-row lookups (C13
in both, plus C26, C30, C34, C37, C38 by pattern), not end to end, so "contradicts an approved Gate
1–2 decision" is checked for the decisions the slice plan cites and for C13 specifically, not
exhaustively. Gate 3's own reconciliations (C55 against `## External`, C58 against C34) were taken
as approved and not reopened. `evidence/gate4-siting.md` was hashed and its cited claims re-derived
against the tree, but its four underlying views were not re-run. One SMTC leg degraded: a
repository-wide `cfg(test)` grep returned a ref at 4,817 estimated tokens, above the 4,096 bound,
and was not opened; `search symbol` plus targeted reads were substituted, which is why C70's "no
`#[cfg(test)]` module at all" rests on the file's tail (`:405-426`) rather than an exhaustive sweep.

## Questions routed to the user

One of the review's three questions is the user's and is carried as an open clarification row,
**C86**: `rl20` adds ten minutes to bare `cargo bench`, which `README.md:75` documents as a
canonical contributor command. The other two were decided by the main agent and recorded: slice
ordering (C81, finding 6 — the technical dependency was absent, so the measurement slice moved
earlier) and whether slice 1 records the expected default-budget band (C76 — it does).
