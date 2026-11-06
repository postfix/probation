# Independent implementation verification — Slice 1

Review kind: qa. Verdict: **VERIFIED**. All selected requirements have current supporting evidence; no blocking finding remains. Scope is publishing Slice1 plus its explicitly imported shared-service/FIX-16-A prerequisite, not the broader lead release.

Subject: base `8d9f5e35b6d92898f6c9c33b852df5a9b04e8d59`; all30 supplied path hashes checked individually before review and before return. Final manifest SHA-256 `d2e8313f9c0e50283ce86820a895407208912a3dd9de518c29d100b6fe993a80`. Only the E2E scenario changed after round4; its current hash is `d3b3c9662b2eec1c7d85ea41ec582d87985012951fef53b37252d6dd43d9e9f5`;29other hashes match.

## Verified requirements

- Live service-key scope and protected configuration: actual snapshot loading derives organization/group from the live key; live API test excludes a foreign registry that exists before the response. Unsafe key files/server/listener bindings refuse.
- Matching remembered authority, durable refusal and no fallback: six cache/config tests cover refusal-time storage failure, restart, malformed snapshots and rotation. Final E2E distinguishes conflicting standalone/central policy and retains central allow/deny through outage/firewall recreation; recovery, key revocation and restart refusal all execute successfully.
- Selected/legacy reads, credentials and private cache isolation: four shared-service tests and real npm/pip E2E pass. Spies positively observe selected-origin credentials and real credential-free PyPI files-host traffic. Wrong-registry and denied/anonymous warm-cache controls reject. Inspected npm/PyPI branches bypass shared metadata reuse.
- Current authority and exact artifact handoff: real-service20-case matrix covers2ecosystems/cold-warm/GET-HEAD-range/refusal/accepted streams; five managed-authority tests pass. Actual wiring binds registry/ecosystem/filename, carries the authority generation and holds the publication read guard through response conversion.
- Integration and source obligations: workspace782passed/0failed/21ignored; compiler PASS; E2E1passed/0failed/0skipped. Both models PASS. Fresh publishing checks3duePASS plus3existing later-sourcePASS,3absent Slice3PENDING. Imported prerequisite54PASS across three common seams; expected unsafe controls detected. No nine-adapter implementation claim.

## Independent observations

The verifier inspected actual router admission, service principal construction, policy persistence, registry selection and final artifact conversion. Active architecture/program/slice documents match implementation; historical certificate material and later plans were not counted as delivered work. Retained code SHIP and bounded Security CLEAR are consistent with inspected behavior. The scenario-only fixture change preserves all assertions/timeouts and has fresh independent adversarial PASS.

Verifier ran both molecule model/source checks anew, retaining `.keep` archives `run-ipvdCi` and `run-ORDI3r`, and ran final Node syntax check. It independently inspected these runner logs:

| Log | SHA-256 |
|---|---|
| Final workspace | `a7d4a01a18c8ac6b5beff981ba9ff64d386585a171f1e82a106ca6b1e936aa26` |
| Final compiler | `7e564aedd61f03231b679e1fd251ec5c9e6e3c6da8cccd3c2f8d64f512ac13a2` |
| Final E2E | `b4d9617dd42dd8167dcdf4902dc5ea27ee66e10d6567658d4220d1334d1ddcfe` |

JUnit confirms one successful unskipped scenario in50.236seconds. The earlier E2E failure remains recorded: a bounded probe proved container address collision, not product failure. Corrected scenario requires actual paused state, preserves firewall restart and policy assertions, and unpauses in finally. Running→paused→running retains both addresses. Exact current product images were reused without product changes.

## Evidence limits

SMTC session `sf-publishing-slice1-verification-2026-11-03` used successful bounded direct source reads/grep and resolved gate/release symbol inspection. Broad results were narrowed. Caller resolution for live service scope was ambiguous across product/control fixtures, so no graph conclusion was drawn; current source and live API witnesses establish the connection. Freshness was full250files/notstale before the later JS fixture edit; afterward no stale semantic inference about changed JS was used. Rust source hashes stayed unchanged. Router verification retried with repository-backed state and authorized local IPC after default-state EROFS; no property was weakened.

Runtime results establish observed cases; source checks establish encoded ordering, not exhaustive concurrency or universal security. Global formal taint/guard analysis remains unproved.21ignored workspace cases are not executed acceptance. Historical missing chronological RED for extra acceptance controls remains an acknowledged process deviation. Later audit, publishing/unpublish, broader ecosystems and native macOS/Windows acceptance remain outside this slice.

The verifier wrote no status/approval file. This document retains its returned VERIFIED report for the coordinator's completion step.
