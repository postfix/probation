# Prerequisite review round 1 — 2026-11-03

Subject: base `8d9f5e35b6d92898f6c9c33b852df5a9b04e8d59`; the 30 file hashes in `.scratch/prerequisite-review/subject.json`, manifest SHA-256 `bb9e0b9aea790ec21ed6d8d03f09ae7946cef72ea849d8495e1e71202b82983d`. Both independent reviewers checked this frozen subject. Subsequent fixes invalidate dependent receipts and require fresh checks/reviews.

## Security: FIX FIRST

The independent security reviewer found two source-established defects, classified MINOR / Manual because runtime reproductions were not yet available. This evidence ceiling does not imply low potential impact.

1. `ServicePolicy.refuse` clears RAM before creating the refusal marker. If marker creation fails while absent, old primary/backup snapshots can authorize after storage recovery and restart during a server outage. The existing directory-at-marker test already has a marker, so does not cover this failure. Required regression: valid snapshot, absent-marker write failure, explicit 401/403, RAM closed, storage recovery, unavailable server, restart still closed.
2. `Managed.authenticate` checks `fresh()` before taking the publication lock, then obtains `stale()` under the lock and stamps the new generation. A concurrent place invalidation can retain an old Live principal and attach the new generation. Final generation comparison then accepts stale authority. Required regression: pause between freshness check and capture, invalidate/suspend/reparent place, resume and require revalidation/refusal; preserve explicitly permitted remembered-layer outage behavior.

The reviewer manually inspected service-key scope, downstream credential isolation, service route/network/write refusal, and private-egress approval boundaries without finding additional defects in those connected paths. Global entry-point/sink inventories were incomplete, validation/missing-guard analyzers Stub, and exact IFDS taint failed on unrelated test-source qualification. No formal taint or global security clearance is claimed. Unchanged portal/TLS/SQL/dependency internals were not independently audited.

## Code review probes received

The code reviewer independently confirmed the refusal error path and proposed a raw scoped npm legacy tarball routing regression. Final report: `prerequisite-code-review-round-1.md`, FIX FIRST. Both reviewers returned terminal results before source edits resumed. The unrelated-key generation observation is nonblocking: the approved contract explicitly permits refusal after a changed generation. It must not motivate a weaker publication guard or an unsolicited redesign.

Additional positive/acceptance controls were added after initial fixes; their missing chronological RED is recorded honestly in `tdd-prerequisite-slice-16.md`. Later baseline/mutation tests cannot retroactively establish test-first history.

Coordinator disposition of the procedural finding: retain the useful acceptance controls and report the missed historical test-first step as a process deviation. No historical claim is repaired by a later test. New defect fixes still require real before-fix failures and after-fix passes; independent review must assess whether current controls detect the prohibited behavior. This disposition does not waive product requirements, failing checks, runtime witnesses or either security defect, and does not claim strict per-test TDD compliance. The developer instruction permits resolving routine process exceptions without inventing a new user approval gate.

## End-to-end witness on this subject

Actual working-tree server and firewall images were rebuilt, with no skip-build/prebuilt substitution. `node tests/e2e/harness/run.mjs --only E2E-service-policy` exited 0: 1 passed, 0 failed, 0 not run; scenario 91.778 seconds after 529-second build/setup. All 30 subject hashes matched at completion. The harness cleaned its own project containers; a filtered container inventory was empty.

Log: `.scratch/prerequisite-checks/e2e-service-policy-current.log`. JUnit: `.scratch/service-policy-e2e-current/out/junit.xml`. Disk-backed work directory: `.scratch/service-policy-e2e-current`; project `probation-e2e-s16-current`, network `11.223.17`, bridge port `18130`. This PASS does not resolve the review findings or certify later source changes.
