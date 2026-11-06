# Prerequisite adversarial test review — 2026-11-03

Independent verdict: UNKNOWN, Manual. This was a bounded test-design review during correction of the known defects, not immutable final acceptance. Initial 30-file subject matched `.scratch/prerequisite-review/subject.json`; final 27 matched, with `src/managed/mod.rs`, `tests/service_policy_cache.rs`, and `tests/shared_service.rs` changing during the review. No source or tests were edited by the reviewer; no builds were run.

Four test-effectiveness gaps derive from publishing Slice 1's approved witness. No additional production vulnerability was established.

1. The service snapshot test creates the foreign organization/registry after fetching the response used for its exclusion assertion. Create both organizations before the fetch, or fetch again after fixture creation.
2. The E2E converts the nominal standalone container into managed service-policy mode before package requests. Its allowed-package 200 during outage cannot distinguish remembered authority from permissive standalone fallback. Use conflicting central/local policy: managed denial persists through outage/restart, while explicit standalone allows that package; an empty managed cache remains closed.
3. Existing shared HTTP races pause metadata preparation; final prepared-response controls use legacy managed principals; generic gate tests order a writer after authorization. Compose the shared-service caller witness at final handoff: publication before authorization gives no payload; publication after accepted handoff preserves the exact stream, but subsequent requests refuse. Include cold/warm npm/PyPI and HEAD/range denial parity.
4. The credential spy records metadata credentials without destinations and does not observe artifact opens. Extend it to observe destination and credential for metadata and artifacts, including npm/PyPI selected and extra artifact origins. Developer credentials may reach only selected registry; the service key only policy snapshot authorization.

Existing controls already substantially cover API wrong/missing/revoked keys and suspended scope; snapshot binding/rotation/malformed data; cold/warm reads and deny/refusal/rate updates; request-local metadata, private warm-content isolation and unsupported writes; native npm/pip and revoked-key restart. Extend these controls rather than introduce a parallel framework. The three known code/security defects are already assigned. Unrelated-generation conservative refusal is allowed by the approved contract. Missing historical RED is the separately recorded process deviation.

SMTC session `sf-prerequisite-adversarial-2026-11-03`: bounded file read/grep operations succeeded; deciding source reads were complete. Broad document outputs were narrowed rather than treated as complete, and no search negative was interpreted as proof. Git base and all source hashes were checked at entry/exit. No formal proof, fresh runtime PASS, or final acceptance is implied.

All four gaps were sent to the sole implementation agent for correction and targeted checks before fresh independent review.
