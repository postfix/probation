# Product: OSV vulnerability intelligence
## Clarifications and decisions
| ID | Class | Status | Owning Gate | Target Gate | Question or disposition | Selected value or policy | Decision source |
|---|---|---|---|---|---|---|---|
| C1 | user clarification | resolved | 1 | none | Does OSV data replace the producer's blocklist snapshot, or merge with it? | Merge, additively: a package is blocked if either source blocks it; neither source can un-block what the other flags. | user answer, Gate 1 grilling Q1 |
| C2 | user clarification | resolved | 1 | none | Which is authoritative when a version matches an OSV advisory but its digest is unlisted? | OSV blocks by package name + version range, digest-independent — OSV has no hashes, only package/version identity, so digest matching does not apply to it. | user answer, Gate 1 grilling Q2 |
| C3 | user clarification | resolved | 1 | none | What happens when OSV is unreachable? | Keep serving on the producer's snapshot alone; an OSV outage does not fail-closed the firewall. | user answer, Gate 1 grilling Q3 |
| C4 | user clarification | resolved | 1 | none | Severity threshold, or block on any advisory regardless of severity? Confirmed scope: malicious-package advisories only, not general CVE vulnerabilities. | No severity threshold. Scope is malicious-package advisories only (OSV's `MAL-*` malicious-packages data) — a package with a real CVE but no malicious-package advisory is not blocked by this feature. | user answer, Gate 1 grilling Q4/Q5 |
| C5 | current-Gate decision | deferred | 1 | 2 | Implementation language/shape is pre-decided: hardcoded Rust, no provider abstraction (backlog B2, declined 2026-09-25). Gate 2 designs the concrete module/fetch shape under this constraint. | Rust, no provider abstraction | user decision, backlog.md B2, 2026-09-25 |
## Problem
Today the firewall only blocks a malicious package once the operator's own producer has found it,
hashed it, and pushed it into the snapshot this service polls. A package that gets published to
npm or PyPI as malware — a typosquat, a backdoored release, a compromised maintainer account — is
invisible to the firewall until that producer independently catches up, which can be hours or
days. The operator wants the firewall to also know about malicious packages the moment a
public feed (OSV's malicious-packages data) lists them, without waiting on their own producer.
## Success metric
Number of malicious-package requests blocked per week that were *not* in the producer's snapshot
at request time (i.e., OSV alone caught it) — measured from the existing decision log's per-request
reason field. Target: greater than zero within the first week after launch, demonstrating the
producer's snapshot alone was insufficient and OSV closed a real gap.
## Non-goals
- Blocking on general CVE-style vulnerability advisories (a package with an exploitable bug but no
  malicious-packages advisory) — settled C4/C5, out of scope for this feature.
- A pluggable/swappable intelligence-provider system (backlog B2, declined 2026-09-25) — OSV is the
  only source, hardcoded.
- Any severity triage or scoring — every OSV malicious-package advisory blocks, unconditionally.
## Announcement — the blog post before the feature
The package firewall now checks every request against OSV's malicious-packages feed, in addition
to your own producer's snapshot. A typosquat or a supply-chain-compromised release listed by OSV is
blocked the moment the firewall's next OSV poll picks it up — you no longer wait on your own
pipeline to notice and hash it first. Nothing changes about how you configure blocks today: this is
a second, independent source feeding the same block decision, and if either source says block, the
firewall blocks.
## Screens
No UI.

sf-red-team: not triggered — Gate 1 has no plan to challenge
