## What problem do we have?

An operator was told the firewall does not lose decision records while it is serving at its
rated load. Nobody ever said what the rated load is: no figure in the documentation, none in
the configuration, and no test that ever ran one.

Two things follow, and the operator feels both. They cannot size a deployment — they do not
know whether 200 requests a second is comfortable or already shedding records. And when their
collector goes down for maintenance, they cannot tell whether the firewall holds the records
until it returns or starts dropping them after a few seconds. Today the firewall holds a fixed
amount and the operator cannot change it.

## How will we solve it?

Published numbers, a benchmark anybody can re-run, and one knob. What an operator can do
afterwards:

- Read the operator documentation -> gets the rated figure: zero decision records lost at N
  records per second, sustained for ten minutes, on named reference hardware. The firewall
  emits exactly one record per request, so it reads as requests per second (C1, C2).
- Read on -> gets the outage tolerance: at the rated load, a default deployment survives a
  collector outage of M without losing a record, published in whatever unit M comes out as —
  seconds or minutes, not rounded up to the friendlier one (C10, C12).
- Run the benchmark on their own hardware -> gets their own figure by the same method, instead
  of every operator discovering the same number alone (C1).
- Give record delivery a larger memory budget -> buys headroom instead of losing records. The
  budget is an amount of memory, the same shape as the existing cache byte budgets, not a
  record count whose cost varies with package-name length (C4, C6).
- Set nothing -> exactly today's serving behaviour: same responses, same latency, same
  drop-and-count rule. The default queue capacity does grow, to a stated memory budget
  materially longer than today's fixed 4096 records per sink, which is about 20 seconds at 200
  records per second (C12).
- Watch the shedding signal -> sees and can alert on "records are being shed" without reading
  log records. Readiness keeps its current meaning and stays green, so an overloaded firewall
  is never pulled out of the serving pool because of log loss (C7, C8).
- Overload anyway -> packages keep serving; a request is never slowed or failed to protect a
  record, and every drop stays counted and reported (C7).

Screens: no UI. The operator's surfaces are the documentation, the configuration and the
health signal.

## How will we confirm it is solved?

Planned, not observed — producing these numbers is the feature.

| Scenario | Expected result | Check |
|---|---|---|
| N records per second sustained ten minutes on reference hardware | Zero records lost | The benchmark this feature adds reports records offered, delivered, dropped and the achieved rate; success is zero drops |
| Rate pushed past N | Drop count matches the deficit exactly | The same benchmark run |
| Collector down at the rated load, default budget | Survives an outage of M without losing a record | M derived from N and the default budget, published in the operator documentation (C6, C10) |
| Every automated run | A collapse of the delivery pipeline fails the run; ordinary CI noise does not | A deliberately low floor asserted automatically, published beside the rated figure as a second number (C3) |

Recommendation: approve. The one contradiction the review found is settled — "minutes of outage
tolerance at the default" could not stand beside "defaults unchanged" when today's default is
4096 records per sink, about 20 seconds at 200 requests a second. You chose to raise the default
to a stated memory budget and publish the real number rather than the friendlier one. What is
still unselected are values and names this feature's own measurements produce.

Limits:

- Four technical choices are deferred to Gate 2, each with a product constraint: the
  configuration key's name, placement and whether one key covers both sinks (C5); the shape and
  name of the shedding signal (C9); the CI floor's value (C11); the default memory budget's
  value and whether it is per sink or shared (C13).
- N, M, the floor and the default budget are unmeasured today. That is correct — measuring them
  is the feature — but no number in this Gate is proven yet, and a low measured N would still be
  the honest published figure.
- Record loss is not removed: sustained overload always outruns a bounded queue. The feature
  makes the ceiling known and adjustable, not infinite.
- The figure covers the decision-record delivery pipeline only, not upstream registry fetches or
  artifact downloads. Making the firewall faster is a different plan.
- Three rows are ADR candidates: C3 (gate on a low floor), C8 (readiness stays green, shedding
  gets its own signal), C12 (raise the default to a stated memory budget).

sf-gate-qa returned READY with no blocking findings, after one earlier QUESTIONS round. It left
two non-blocking notes for the author, neither needing your answer: C4's policy column still
reads literally as "the default keeps today's behaviour exactly" (C12 supersedes it in band, by
name), and the Announcement is silent on the default itself growing (C13 makes that number
unquotable for now).

Sources: `docs/plans/rated-load-guard/01-product.md` (C1-C13, Problem, Success metric,
Non-goals, Announcement, Screens); `gate-1-qa.md` (READY); `00-status.md`;
`docs/plans/decision-log-delivery/01-product.md` (the promise this plan closes) and its
`evidence/slice-4.md` (C52, the accepted gap that sent it here).

Approve Gate 1, or what should change?
