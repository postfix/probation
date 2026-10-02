# Gate 1 QA

## Verdict

READY

## Questions and findings

None blocking. This is a fresh independent review of the revised `01-product.md`; the four
author revisions and two user-owned questions from the previous review are resolved in the
current bytes:

- **Q1 (outage tolerance vs unchanged defaults) — resolved.** C12 records the user's answer:
  raise the default modestly to a stated memory budget and publish whatever tolerance it yields
  in the unit it comes out as. The Success metric no longer promises minutes ("published in
  whatever unit M actually comes out as — seconds or minutes, not rounded up to the friendlier
  one") and states today's baseline honestly (4096 records per sink ≈ 20 s at 200 records per
  second; 4096/200 = 20.5, and `const QUEUE_CAPACITY: usize = 4096` at `src/delivery/mod.rs:37`
  is used at both `mpsc::channel` sites, so "per sink" is accurate).
- **Q2 (what the default budget is expressed in) — resolved.** C12: "The unset default becomes a
  memory budget expressed the same way as the new key (C6), so the default and the key mean one
  thing rather than two units." C13 defers only its value, with a product constraint.
- **R1 (blank deferral values) — resolved.** C5 and C9 now carry both a "Not selected at Gate 1
  … Product requires only that …" policy and a decision source ("Deferred to Gate 2, Gate 1
  grilling Q4" / "Q8").
- **R2 (unselected CI floor value) — resolved.** New C11 defers the floor's fraction/value to
  Gate 2 with its product constraint: published beside the rated figure, low enough not to fail
  on ordinary CI noise, and a collapse fails the run (C3).
- **R3 (overstated non-goal) — resolved.** The bullet is rescoped to "Changing serving
  behaviour" and names the two additive unconfigured changes (larger default budget per C12, the
  shedding signal per C8).
- **R4 (false `/health/ready` body premise) — resolved and verified against source.** C9 now
  reads "a response body added to an existing health route — noting that `/health/ready` returns
  a bare status code with no body today (`src/http/health.rs`)". Confirmed: `pub async fn
  ready(State(app): State<Arc<App>>) -> StatusCode` returns `StatusCode` only, no body type.

Two non-blocking notes for the author, neither changing the verdict and neither requiring a user
answer:

- **N1 — C4's policy column still reads literally as "the default keeps today's behaviour
  exactly".** C12 resolves this in band, by name, and delimits what does not change (serving
  behaviour, the drop-and-count rule, every other shipped default), so the inventory contains a
  documented supersession rather than a hidden contradiction. A parenthetical back-pointer in C4
  ("superseded in part by C12") would remove the last chance of Gate 2 reading C4 alone.
- **N2 — the Announcement is silent on the default itself growing.** Nothing in it is false, and
  C13 makes the number unavailable to quote yet; the sentence "how long a default deployment can
  survive a collector outage" carries the operator-visible effect. A clause saying the default
  now holds more would match C12 more closely.

## Checked dimensions

- **Subject completeness, readable regular paths, freshness** — pass. Every `01-product.md`
  template heading is present (Clarifications and decisions, Problem, Success metric, Non-goals,
  Announcement, Screens) plus the required last line. All tracked evidence read as regular files
  through the helper; the deciding source facts were read through SMTC after tracking.
- **Clarification inventory (IDs, class, status, owner, target, disposition, policy, source)** —
  pass. Thirteen stable plan-local IDs, C1–C13, none missing and none reused; every row is class
  `user clarification`, owner Gate 1; no row is `open`; every resolved row names a selected value
  and an exact decision source (`user answer, Gate 1 grilling Q<n>`); three rows carry the `ADR
  candidate` mark (C3, C8, C12). Ordering only: C10 sits after C13 because C11–C13 were appended;
  cosmetic, IDs are stable.
- **Deferrals carry a product constraint Gate 2 can act on** — pass, all four. C5 (key
  name/placement/per-sink split): raisable by configuration, expressed as memory, unset keeps the
  shipped default. C9 (shedding signal's shape and name): visible and alertable without reading
  log records, `/health/ready` keeps its meaning and stays green. C11 (CI floor value): published
  beside the rated figure, survives ordinary CI noise, fails on collapse. C13 (default budget
  value and per-sink vs shared): materially longer than today's ~20 s at the rated load, memory
  cost bounded and stated per sink, resulting tolerance published. Each targets Gate 2 under the
  ID Gate 2 must import and resolve.
- **Gate 1 technical choices deferred, not decided** — pass. The four deferrals are exactly the
  technical/measurement-dependent choices; no product outcome is parked in them. No
  implementation-verification row conceals an unselected value (there are none).
- **Incoming deferrals retain their IDs** — not applicable in the strict sense: new plan, no
  approved upstream Gate. The originating promise is closed here as traceability only and matches
  what this plan scopes: `decision-log-delivery/01-product.md:38` ("no decision record is lost
  while the firewall is serving at its rated load…"), C52 in that plan's `04-slices.md` (accepted
  as a stated limitation on condition it returns as its own plan), and `evidence/slice-4.md`.
- **Clear user problem in product language** — pass. The Problem is the operator's: cannot size a
  deployment, cannot predict a collector outage, no lever to pull. Technical citations are
  confined to question columns and deferral scoping, where they ground the user's answer
  (`src/delivery/mod.rs:37` in C12) or prevent Gate 2 inheriting a false premise
  (`src/http/health.rs` in C9); `/health/ready`, `cache_max_bytes`/`memory_cache_max_bytes` and
  the `log_*`/`siem_*` family are existing operator-facing surfaces, all of which exist as cited
  (`config.sample.toml` lines 37–74, `log_file_max_bytes` being the byte-shaped precedent C6
  leans on).
- **Success metric: falsifiable, with a measurement method** — pass. Headline: zero decision
  records lost at N records per second sustained ten minutes on named reference hardware.
  Derived: outage tolerance M, in the unit it comes out as, from N and the default budget.
  Measured by: the benchmark reports records offered, delivered, dropped and the achieved rate;
  success is zero drops at N and a drop count matching the deficit exactly past it. N and M being
  unmeasured is correct — producing them is the feature — and the unit and default they rest on
  are now settled (C12), which is what previously blocked. A low measured N would still be an
  honest published figure, consistent with C1 and the "making the firewall faster" non-goal.
- **Non-goals consistent with the decisions and with the upstream promise** — pass. Faster
  firewall (out), removing loss entirely (out, C7), slowing/failing requests to protect records
  (out, C7 — and the shipped non-blocking offer agrees), taking the firewall out of service when
  shedding (out, C8), load-testing the whole firewall (out, C2), changing serving behaviour (out,
  with the two additive unconfigured changes named — C12, C8). No bullet now overstates.
- **Announcement matches the decisions after the default changed** — pass, see N2. Published
  rated figure on reference hardware and shipped re-runnable benchmark (C1), outage tolerance for
  a default deployment (C10, C12), larger memory budget for delivery (C4, C6), dedicated shed
  signal while packages keep serving and readiness stays green (C7, C8). The CI floor (C3) is
  internal and rightly absent. Nothing announced is contradicted by a row.
- **Screens** — pass. "No UI." is correct for a benchmark, a configuration key and a health
  signal; no mockups are owed.
- **Red Team** — pass. Red Team never runs at Gate 1; the document's last line is exactly
  `sf-red-team: not triggered — Gate 1 has no plan to challenge`. This review is fresh,
  independent, and in isolated context.
- **Gate 2, 3 and 4 stage dimensions** — not applicable.

## Limitations

- `00-status.md` could not be tracked: the helper refuses it as machine state. It was read
  untracked and treated as bookkeeping (workflow position and origin notes only); no finding or
  dimension result rests on it, and no decision was taken from it.
- No research artifact exists in the plan folder and none is owed: the Gate asserts no external
  fact. N, M, the CI floor and the default budget are numbers this feature will measure.
- `config.sample.toml` was read for the existence and shape of the `log_*` / `siem_*` and
  `*_max_bytes` key families only; the deciding queue facts come from `src/delivery/mod.rs`,
  read through SMTC.
- The previous `gate-1-qa.md` was read to re-check its findings against the current bytes; it was
  treated as a prior review artifact, never as decision evidence.

## SMTC receipt

- **file read `src/http/health.rs`** — `smtc file read --root <root> --path src/http/health.rs
  --format json --max-tokens 2048 --session-id <session>` — run; ok true, no inner refusal, 39
  lines, not clamped, no refs, no diagnostics. Interpretation: `ready` returns `StatusCode` with
  no body, confirming C9's corrected premise (R4 resolved).
- **file read `src/delivery/mod.rs` lines 20–60** — `smtc file read --root <root> --path
  src/delivery/mod.rs --start-line 20 --end-line 60 --format json --max-tokens 2048 --session-id
  <session>` — run; ok true, 41 lines, not clamped, no refs. Interpretation: `const
  QUEUE_CAPACITY: usize = 4096;` is at line 37, confirming C12's and the Success metric's
  baseline citation.
- **file grep `QUEUE_CAPACITY`** — `smtc file grep --root <root> --pattern 'QUEUE_CAPACITY'
  --max-results 20 --format json --max-tokens 2048 --session-id <session>` — run; ok true, 6
  matches across 218 files, `truncated: false`, `max_results_hit: false`. Interpretation: two
  `mpsc::channel(QUEUE_CAPACITY)` sites (lines 214, 250), so the 4096 bound is per sink as the
  Gate states.
- **file grep `cache_max_bytes|memory_cache_max_bytes`** — `smtc file grep --root <root>
  --pattern '(cache_max_bytes|memory_cache_max_bytes)' --max-results 20 --format json
  --max-tokens 2048 --session-id <session>` — run; ok true, `max_results_hit: true`,
  `truncated: true` (fixture configs dominate). Interpretation: both memory-shaped keys exist,
  which is all C6's analogy needs; truncation does not bear on the verdict.
- **Native `grep` on `config.sample.toml` and the upstream plan documents** — used for
  path-scoped location of the `log_*` / `siem_*` family and the upstream promise/C52 text,
  because the available `file grep` recipe has no path scope and returns repository-wide
  matches. Reduced evidence: line location only; no deciding fact rests on it alone.
