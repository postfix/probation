# Slice 1 — shared-service npm/PyPI reads

The certificate-era Slice1 evidence formerly at this path is preserved byte-for-byte in `slice-1-certificate-history.md` (SHA-256 `bef51d38c06f969e26497fb39316c801321fa6dd3ed4ba41afaadcbae9072227`). This document records the approved local-service re-steer.

Status: required runtime/source checks and specialist reviews passed; independent implementation verification VERIFIED. Ready for the router completion step.

## Scope and authority

The user approved the publishing design on2026-11-02. `resume-approval-scope.md` records the recovered approval and its explicit import of the lead-owned shared-service foundation/FIX-16-A. This delivery implements and verifies that bounded prerequisite plus publishing Slice1's credential/registry assertions. It does not approve the lead's broader nine-family draft or claim those adapters/native deployments are delivered. The lead's own status remains distinct.

Caller outcome: npm and pip use one managed service policy without a package-request Probation login; selected registry and package-manager credentials retain their separate upstream authority. Explicit standalone mode remains separate. Managed refusal persists across restart; allowed remembered policy survives a normal outage without switching modes. Final artifact handoff applies current authority to exact verified bytes, while already accepted streams can finish.

Current subject: base `8d9f5e35b6d92898f6c9c33b852df5a9b04e8d59`; `slice-1-subject.json` records30 source/test hashes, manifest SHA-256 `d2e8313f9c0e50283ce86820a895407208912a3dd9de518c29d100b6fe993a80`. All product bytes equal independently reviewed round2; afterward only two reviewed Authorization inventory entries and the E2E outage fixture changed. Scanner logic and negative controls are unchanged. The scenario-only correction does not invalidate the final Rust suite/compiler or encoded source obligations.

## Required outcomes and evidence

| Outcome | Deciding controls |
|---|---|
| Service key selects only its live organization/group and registry descriptors | Live HTTP/Postgres API tests, with foreign organization created before response; wrong-kind/revoked/suspended scope controls |
| Validated policy persists with exact server/key/mode/registry binding | Cache binding, malformed snapshot, rotation and backup controls; durable checking intent precedes requests; actual storage-failure-during401 regression |
| Explicit standalone and remembered managed outage remain distinct | Expanded E2E uses conflicting standalone and central policy, then central denial through outage/restart; existing unchanged C19 controls retained |
| Credentials authorize only their selected registry and cannot reuse another caller's metadata | npm/PyPI request-local metadata; two-token/anonymous warm-content denial; disk/memory/restart controls; destination spies record metadata and artifacts, including absent PyPI files-host credential |
| Selected/legacy reads retain exact registry, package and artifact identity | Shared HTTP selected/legacy cold/warm matrix, raw scoped npm GET/HEAD, wrong registry/refusal, unsupported-write zero-I/O |
| Current authority governs final bytes | Real-service prepared-response20-case npm/PyPI cold/warm GET/HEAD/range matrix with cross-thread publication before/after handoff, accepted stream completion and subsequent denial; managed regression matrix and deterministic admission-generation race |

`prerequisite-slice-16.md` and `tdd-prerequisite-slice-16.md` retain engineering detail and exact commands/logs. Four review-discovered defects have real behavioral RED then GREEN: refusal recovery after unwritable storage, stale principal/new generation, scoped npm alias routing, and extra-origin artifact credential forwarding.

Additional positive/acceptance controls were added after initial code. Their missing chronological RED is an acknowledged process deviation (`prerequisite-review-round-1.md`), not a fabricated test-first claim. Current effectiveness is independently reviewed; later checks do not rewrite history.

## Checks

- Focused four defect regressions: PASS. Shared real-service final-handoff20-case acceptance: PASS within1 test. Unchanged C19 controls: PASS. API nonvacuity correction: PASS.
- Final Authorization inventory: `cargo test --test authorization_read_once`,4passed/0failed/0ignored, `.scratch/prerequisite-checks/review-inventory-green-4.log`.
- Final `cargo test --workspace`: PASS, exit0,782passed/0failed/21ignored across53summaries; `.scratch/prerequisite-checks/workspace-review-final-4.log`. Ignored19real-client tests,1resource-limit child and1timing measurement remain explicit; current native npm/pip E2E is checked separately. Earlier round2 attempt stopped223passed/3inventory failures/1ignored; it is historical, not the final result.
- Final `cargo check --workspace`: PASS, `.scratch/prerequisite-checks/workspace-review-final-check-4.log`.
- Final E2E: round5 PASS, exit0,1passed/0failed/0notrun; JUnit1test/0failures/0skipped,50.236seconds after15-second setup. Logs `.scratch/prerequisite-checks/e2e-service-policy-round5.log`, `round-5-server-states.log`, `round-5-manifest-before.json`, `round-5-manifest-after.json`; JUnit `.scratch/service-policy-e2e-round5/out/junit.xml`. Actual running→paused→running retained11.223.20.12 and10.77.0.5; exact image IDs and all30hashes matched before/after; own project containers were cleaned.
- The preceding rebuilt-image attempt FAILED after setup159seconds/runtime101.4seconds at server recovery (`Expected HTTP/, RTSP/ or ICE/`), before final revocation/restart assertions. Log `.scratch/prerequisite-checks/e2e-service-policy-final.log`. A separate current-image probe proved a fixture address collision: stopping server released its fixed.12; recreated dynamic firewall acquired.12; recreated server remained CREATED/noIP; gateway's fixed HTTP upstream reached the firewall's TLS listener. Five lifecycle snapshots in `.scratch/service-policy-recovery-probe/out` and `review-recovery-probe.log` establish this cause. Own stacks were cleaned; product hashes unchanged. Scenario now pauses/asserts paused/unpauses server in finally, preserving its address while retaining all policy-outage/restart/recovery/revocation assertions and timeouts. Node syntax and fresh narrow `outage-fixture-review.md` both PASS.
- Replacement command: `node tests/e2e/harness/run.mjs --only E2E-service-policy --skip-build`. Reuse is limited to the exact images already rebuilt from unchanged product: firewall `38e5ff3a9d140209d8324485543ad80170924a93b109dc28d9e802ae9ea5c685`, server `fe7f9258137f8309e7db8cfa4d7c8f7dd4ba349cf4cc2671359d29be90f77ad1`; `.scratch/prerequisite-checks/recovery-image-context.json` records image/config bindings. This is not substitution of archived/pre-implementation images. Earlier round1 E2E1/0 remains historical.
- Both molecule models PASS. Publishing:3checks due at Slice1 and3additional existing-source checks PASS with unsafe controls;3absent Slice3 checks legitimately PENDING; archive `run-O1FiQp`. Lead prerequisite Slice16:54checks PASS with unsafe controls; archive `run-obTWSc`. Independent verification clarified this bySlice distinction;6PASS is not6due-at-Slice1.
- All8 unique applicable specs independently rerun:0production findings and1expected finding per unsafe control.60pair grouping/120archive bindings verified. Retained reports: `slice-1-source-report.json`, `slice-1-source-hashes.json`; detailed immutable source/control archives under `.scratch/state/software-factory/contract-evidence/repo-cc718bf594b6832a/`, both protected with `.keep`.

These are structural ordering checks on shared seams, not proof of every value/concurrency behavior or implementation of nine ecosystems. Runtime controls and source reviews carry those distinct claims.

## Reviews and limits

- Security: bounded CLEAR; `prerequisite-security-round-2.md` preserves findings, resolutions and the reviewer's clarification that incomplete global analyses do not alone block a bounded review. Global formal taint/guard proof remains UNKNOWN; doctor-established unavailable exact IFDS and incomplete inventories are explicit limits.
- Code: SHIP. All four product defects resolved in `prerequisite-code-review-round-2.md`; its sole inventory blocker is closed by the4/0 scanner result and fresh independent `prerequisite-code-review-inventory.md`. The reviewer proved all29 other subject files and scanner logic unchanged.
- Adversarial: PASS; `prerequisite-adversarial-final.md` independently closes all four prior test-effectiveness gaps; `outage-fixture-review.md` independently checks the sole later scenario change on round5. Separate current-image runtime acceptance also passes.
- Independent implementation verification: VERIFIED; `slice-1-verification.md` records current source/requirement correspondence, independently inspected final runtime logs and fresh model/source checks. No blocking finding remains.

Native macOS/Windows, later audit/publishing/unpublish operations and broader ecosystem deployment remain assigned to their approved later slices. No commit, push or deployment is claimed.

## Execution resource limits

After the user reported CPU load, task builds were restricted to cores0–1, nice19,2Cargo jobs and2test threads. E2E builds run sequentially through `.scratch/prerequisite-checks/podman-compose-lowcpu`. A disposable container witness confirmed inherited CPU affinity and priority. Rootless cgroup quota setup was unavailable, so no quota enforcement is claimed. Heavy work/cache/logs use disk-backed repository `.scratch`, not `/tmp`.

The workflow tracker reported repeated witness-to-fix transitions. Each was diagnosed with a concrete failure: independent product defects, followed by inventory registration and its whitespace-normalized key. No failed result is relabeled PASS and no required test was removed.
