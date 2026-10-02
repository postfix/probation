# Product: Rated load guard

## Clarifications and decisions

| ID | Class | Status | Owning Gate | Target Gate | Question or disposition | Selected value or policy | Decision source |
|---|---|---|---|---|---|---|---|
| C1 | user clarification | resolved | 1 | none | What does "rated load" mean to an operator: a throughput number the firewall promises, headroom the operator can observe, or a measurement they re-run on their own hardware? | A measured ceiling. The project publishes a rated-load figure on named reference hardware, and a repeatable benchmark in the repository proves no decision record is lost below it. Rejected: reporting queue headroom only (promises the operator nothing), and a documented procedure each operator runs themselves (makes every operator discover the same number). | user answer, Gate 1 grilling Q1 |
| C2 | user clarification | resolved | 1 | none | Does the rated-load figure describe the whole firewall serving requests, or the decision-record delivery pipeline? | The delivery pipeline: decision records per second offered to the sinks, with none lost. It measures the promise itself instead of a stubbed upstream registry's speed, and because the firewall emits exactly one decision record per request, an operator reads the figure as requests per second. | user answer, Gate 1 grilling Q2 |
| C3 | user clarification | resolved | 1 | none | What does the benchmark do when the measured ceiling is below the published figure — fail a run that gates merges, or report a number a human reads? | Gate on a deliberately low floor. The published figure comes from a quiet reference machine; the automated check asserts only a fraction of it, so a real collapse fails the run while ordinary CI noise does not. The floor is a second published number, separate from the rated figure. Rejected: gating on the full figure (fails on other people's builds), and reporting only (a regression sits unnoticed). | user answer, Gate 1 grilling Q3, ADR candidate |
| C4 | user clarification | resolved | 1 | none | Does this feature change how the firewall behaves under load, or only measure and publish what it already does? | Both. The feature measures and publishes the rated figure and the CI floor, **and** gives the operator a configuration key for delivery queue capacity, so an operator running above the rated load can trade memory for headroom instead of losing records. The default keeps today's behaviour exactly, so an operator who sets nothing sees no change. | user answer, Gate 1 grilling Q4 |
| C5 | user clarification | deferred | 1 | Gate 2 | The name of the queue-capacity configuration key, where it sits among the existing `log_*` / `siem_*` keys, and whether one key covers both sinks or each sink gets its own. | Not selected at Gate 1: a naming and placement choice, not a product outcome. Product requires only that an operator can raise delivery queue capacity by configuration, that the key is expressed as memory (C6), and that leaving it unset keeps the shipped default behaviour (C4). | Deferred to Gate 2, Gate 1 grilling Q4 |
| C6 | user clarification | resolved | 1 | none | What does the operator write in that key: a number of records, or an amount of memory? | An amount of memory, the same shape as the existing `cache_max_bytes` / `memory_cache_max_bytes` keys. It bounds the resource that actually hurts a host, rather than a count whose memory cost varies with package-name length. The operator documentation must therefore state how many seconds of collector downtime a budget buys at the rated load, since the operator cannot derive it from the budget alone. | user answer, Gate 1 grilling Q6 |
| C7 | user clarification | resolved | 1 | none | When the queue reaches its budget, what does the firewall do? | Keep dropping and counting, exactly as today — package serving is never slowed or failed — and additionally make the shedding state visible on a health signal, so an operator sees it without reading logs. Rejected: making the request wait for queue space, which reverses the approved promise that delivery never slows a request and would let a wedged collector throttle package traffic. | user answer, Gate 1 grilling Q7 |
| C8 | user clarification | resolved | 1 | none | Which health signal carries "records are being shed", given that a failing readiness probe removes the firewall from service? | A separate signal. `/health/ready` keeps its current meaning and stays green while records are shed, so an overloaded firewall is never pulled out of the serving pool because of log loss. The shedding state is reported on its own surface for an operator to alert on. Rejected: failing readiness (stops package traffic to protect log records, which inverts the priority), and logs plus counters only (the user chose visibility in C7). | user answer, Gate 1 grilling Q8, ADR candidate |
| C9 | user clarification | deferred | 1 | Gate 2 | The shape of that separate signal and what it is called. The options are a new endpoint, a counter or metrics surface, or a response body added to an existing health route — noting that `/health/ready` returns a bare status code with no body today (`src/http/health.rs`), so "a field on the readiness body" would mean introducing one. | Not selected at Gate 1: an interface choice. Product requires only that an operator can see and alert on "records are being shed" without reading log records, and that `/health/ready` keeps its current meaning and stays green while shedding (C8). | Deferred to Gate 2, Gate 1 grilling Q8 |
| C11 | user clarification | deferred | 1 | Gate 2 | The CI floor's value: what fraction of the rated figure it asserts, and whether it is expressed as a fraction or as its own absolute number. | Not selected at Gate 1: it depends on the measured spread between the reference machine and the CI runner, which this feature produces. Product requires only that the floor is published beside the rated figure, that it is low enough not to fail on ordinary CI noise, and that a collapse of the delivery pipeline fails the run (C3). | Deferred to Gate 2, Gate 1 grilling Q3 |
| C12 | user clarification | resolved | 1 | none | The Success metric promised outage tolerance in minutes at the default, but today's default is a fixed 4096 records per sink (`src/delivery/mod.rs:37`), which at the Problem section's own 200 requests per second is about 20 seconds. Publish the real number at the unchanged default, or raise the default? | Raise it modestly to a stated default memory budget, and publish whatever tolerance that budget actually yields, in the unit it comes out as. The unset default becomes a memory budget expressed the same way as the new key (C6), so the default and the key mean one thing rather than two units. This supersedes the literal reading of C4: the default queue capacity does change. What does not change is serving behaviour, the drop-and-count rule, and every other shipped default. | user answer, Gate 1 grilling Q11, ADR candidate |
| C13 | user clarification | deferred | 1 | Gate 2 | The default memory budget's value, and whether it is one budget per sink or one shared. | Not selected at Gate 1: it trades host memory against tolerance and needs the measured record size this feature produces. Product requires that it be materially longer than today's roughly 20 seconds at the rated load, that its memory cost be bounded and stated per sink, and that the operator documentation publish the tolerance it yields (C6, C10). | Deferred to Gate 2, Gate 1 grilling Q11 |
| C10 | user clarification | resolved | 1 | none | Which number decides whether this feature succeeded? | Both numbers, with throughput as the headline: the rated figure (zero records lost at N records per second, sustained), and the outage tolerance derived from it and the default budget (at the rated load, a default deployment survives a collector outage of M minutes without losing a record). The promise being closed is about loss at rated load, so the figure leads; the operator sizing a budget needs the minutes. | user answer, Gate 1 grilling Q10 |

## Problem

An operator was told the firewall does not lose decision records while it is serving at its
rated load. Nobody ever said what the rated load is. There is no figure in the documentation,
none in the configuration, and no test that ever ran one. So an operator who depends on those
records — for an audit trail, or to find which machines took a package before it was blocked —
has no way to know whether their traffic is inside the promise or outside it, and no lever to
pull if it is outside.

Two things follow from that. First, the operator cannot size a deployment: they do not know
whether 200 requests a second is comfortable or already shedding records. Second, when their
collector goes down for maintenance, they cannot tell whether the firewall will hold the
records until it returns or start dropping them after a few seconds. Today the firewall holds a
fixed amount and the operator cannot change it.

This feature answers both questions with published numbers, proves them with a benchmark
anybody can re-run, and gives the operator a knob to buy more headroom when their traffic
exceeds what the default holds.

## Success metric

**Headline: the rated figure.** Zero decision records lost at N records per second, sustained
for ten minutes, on named reference hardware. N is what this feature measures and publishes;
because the firewall emits exactly one decision record per request, an operator reads it as
requests per second (C2, C10).

**Derived: outage tolerance.** At the rated load, a default deployment survives a collector
outage of M without losing a record, published in whatever unit M actually comes out as —
seconds or minutes, not rounded up to the friendlier one. M follows from N and the default
memory budget, and it is the number an operator uses to size that budget (C6, C10, C12).
Today's fixed 4096 records per sink yields roughly 20 seconds at 200 records per second; the
default becomes a stated memory budget that is materially longer than that (C12, C13).

Both numbers are published in the operator documentation. A third, deliberately lower number —
the CI floor — is asserted automatically on every run, so a collapse fails the build while
ordinary CI noise does not (C3).

Measured by: the repeatable benchmark this feature adds, reporting records offered, records
delivered, records dropped, and the achieved rate. Success is zero drops at N, and a drop count
that matches the deficit exactly whenever the rate is pushed past it.

## Non-goals

- **Making the firewall faster.** This measures and documents what it already does, and adds a
  capacity knob. Performance work is a different plan.
- **Removing record loss entirely.** Sustained overload will always outrun a bounded queue.
  Loss stays counted and reported (C7); the feature makes the ceiling known and adjustable.
- **Slowing or failing package requests to protect records.** Explicitly rejected at C7: a
  wedged collector must never throttle package traffic.
- **Taking the firewall out of service when it sheds records.** Readiness keeps its current
  meaning and stays green (C8).
- **Load-testing the whole firewall.** The figure covers the delivery pipeline, not upstream
  registry fetches or artifact downloads (C2).
- **Changing serving behaviour.** An operator who sets nothing sees exactly today's serving
  behaviour: the same responses, the same latency, the same drop-and-count rule (C4, C7). Two
  things do change without configuration, both additive: the default queue capacity becomes a
  stated memory budget larger than today's fixed 4096 records (C12), and the shedding signal
  reports state while changing no decision the firewall makes (C8).

## Announcement — the blog post before the feature

The package firewall has always promised not to lose decision records while it is serving at
its rated load. Starting with this release, we say what the rated load actually is: a measured
figure on reference hardware, published alongside how long a default deployment can survive a
collector outage before records start dropping. The benchmark that produces the number ships in
the repository, so you can run it on your own hardware and get your own figure.

If your traffic runs above what the default holds, you can now give record delivery a larger
memory budget and buy the headroom you need. If records are ever shed anyway, the firewall says
so on a dedicated signal you can alert on — while continuing to serve packages normally, and
while staying in your load balancer's pool. Losing log records is a problem; it is never a
reason to stop serving packages.

## Screens

No UI.

sf-red-team: not triggered — Gate 1 has no plan to challenge.
