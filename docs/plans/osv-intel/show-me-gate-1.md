## What problem do we have?
Today the firewall only blocks a malicious package once the operator's own producer has found it,
hashed it, and pushed it into the snapshot this service polls. A package published to npm or PyPI
as malware — a typosquat, a backdoored release, a compromised maintainer account — is invisible to
the firewall until that producer independently catches up, which can be hours or days. The
operator wants the firewall to also know about malicious packages the moment a public feed (OSV's
malicious-packages data) lists them, without waiting on their own producer.

## How will we solve it?
`user action -> outcome`
- A request for a package OSV lists as malicious -> blocked, even if the producer's own snapshot never flagged it (Problem, Announcement).
- A request for a package either source blocks -> blocked; neither source can un-block what the other flags (C1: merge, additively).
- OSV matches by package name + version range only, no digest -> the block still applies; OSV has no hashes to check (C2).
- OSV feed is unreachable -> firewall keeps serving on the producer's snapshot alone; an OSV outage does not fail-closed the firewall (C3).
- A package has a real CVE but no malicious-package (`MAL-*`) advisory -> not blocked by this feature; no severity threshold, scope is malicious-package advisories only (C4).
- Operator's existing block configuration -> unchanged; OSV is a second, independent source feeding the same block decision (Announcement).

Non-goals: blocking on general CVE-style vulnerability advisories (settled C4/C5); a pluggable/swappable
intelligence-provider system (backlog B2, declined 2026-09-25 — OSV is hardcoded, no provider abstraction,
deferred to Gate 2 for the concrete module/fetch shape, C5); any severity triage or scoring.

No UI — Screens: No UI.

## How will we confirm it is solved?
| Scenario | Expected result | Check |
|---|---|---|
| A package is on OSV's malicious-packages feed but not yet in the producer's snapshot | Request for that package is blocked | Planned: decision log records the block with an OSV-sourced reason |
| A package is blocked by the producer's snapshot but absent from OSV | Request for that package is still blocked | Planned: decision log shows the producer-sourced reason unchanged |
| OSV is unreachable | Firewall keeps serving on the producer's snapshot alone, not fail-closed | Planned: outage does not add blocks or take the firewall down (C3) |
| A package has a CVE but no `MAL-*` advisory | Request is not blocked by this feature | Planned: out of scope per C4/C5 |
| Success metric, first week after launch | Count of malicious-package requests blocked that were *not* in the producer's snapshot at request time is greater than zero | Planned: measured from the existing decision log's per-request reason field |

Recommendation: Approve. The Gate document resolves all four user clarifications (C1-C4) and records the
pre-decided implementation constraint (C5) with no open questions; scope, non-goals, and the announcement
are consistent and stated in product language.
Limits: Implementation language/shape (Rust, no provider abstraction) is fixed by C5/backlog B2 but the
concrete module and fetch design wait for Gate 2. No UI exists to preview since this feature has no screens.
Gate QA report: docs/plans/osv-intel/gate-1-qa.md — READY.
Sources: docs/plans/osv-intel/01-product.md (Clarifications C1-C5, Problem, Success metric, Non-goals,
Announcement, Screens); docs/plans/osv-intel/gate-1-qa.md (READY).
Approve Gate 1, or what should change?
