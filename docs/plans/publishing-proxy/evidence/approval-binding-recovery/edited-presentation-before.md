## What problem do we have?

The approved product direction changed: the old firewall path admitted package clients with SSL client certificates, while the replacement is a locally installed, shared enforcement service accessed from the local machine or approved cluster nodes. Reusing certificate admission or conflating credentials would give the wrong identity and authority. The policy server must remain distinct from the selected private or public package registry, and existing publishing must still be authorized by that registry.

## How will we solve it?

Keep the three credentials and boundaries separate: the firewall's organization service API key authenticates only to the policy server in the HTTP `Authorization` header for `GET /api/v1/policy/snapshot`; package-manager developer credentials are configured by the user or CI and are forwarded only to the selected registry for upstream authorization; local service access is restricted to the machine or approved nodes and does not claim per-user/workload identity. Package requests do not log in to Probation.

**Decisions for approval**

1. Replace package-request SSL client-certificate admission with local shared-service access; approved-node access is the cluster boundary.
2. Managed mode uses one effective service policy. Standalone mode is explicitly configured with TOML; managed failures never fall back to standalone.
3. The service API key is used only for policy retrieval and appears only in that request's HTTP `Authorization` header.
4. Package-manager credentials remain user/CI-owned and go only to the selected registry. That registry decides upstream read, publish, and management authorization; these credentials are not firewall or policy identity.
5. Keep named npm/PyPI operations and selected-registry isolation; preserve safe audit output and the request-local canonical token-packument exception.
6. Version unpublish uses a durable service-scoped, registry/package/version/filename-bound reference and a revision-bound one-use marker. D42 refuses extra-origin tarballs before advertising an action URL or sending DELETE.
7. Deliver in five slices: local reads; npm audit/token-packument; npm actions/unpublish; PyPI publishing; native release acceptance. Slice 1 depends on lead `package-firewall-mvp` Slice 16; native lifecycle depends on Slice 25.
8. Verify native clients on Linux, macOS and Windows; the policy server runs on Linux. Missing required runners must fail rather than silently skip.

**Connected behavior** (proposed; the finite model is not runtime proof):

```mermaid
sequenceDiagram
  participant PM as npm / pip / CI
  participant FW as Probation firewall
  participant PS as Policy server
  participant REG as Selected registry
  PM->>FW: Package request + user's registry credential
  Note over PM,FW: Old proxy used SSL client certificates; active design uses local or approved-node service access
  FW->>PS: GET policy snapshot + firewall API key in Authorization header
  PS-->>FW: Effective service policy
  FW->>FW: Apply policy and select the configured registry
  FW->>REG: Allowed package operation + package-manager credential
  Note over FW,REG: Registry credential goes only to this selected registry
  REG-->>FW: Registry allow or deny
  FW-->>PM: Operation result
```

| Operation / route | Contract and evidence status |
|---|---|
| `GET /api/v1/policy/snapshot` | Firewall service key in HTTP `Authorization` header only; one service policy. Finite model PASS; runtime credential trace planned. |
| `classify_registry_request` → `serve_package_read` | Named selected-registry request is evaluated under current policy; denial refuses. Six source obligations for future Slice 1/3 files are PENDING overall; operation witnesses are planned. |
| `forward_registry_action` | Package-manager credential goes to selected registry; local policy and upstream authorization remain separate. Existing structural source check and unsafe control PASS; runtime credential routing is pending. |
| `serve_token_packument`, `filter_audit_response` | Token packument is request-local; audit response reveals only safe visible signals. Both existing structural checks and unsafe controls PASS; end-to-end guarantees remain planned. |
| `record_successful_service_removal`, `consume_service_marker_then_send` | D42 commits a revision-bound marker only after accepted PUT and confirmed removal; version-reference DELETE consumes it once before selected-origin I/O. Future source obligations PENDING; durability, atomicity and race witnesses are planned. |

The old certificate path is historical. The service key never goes to a registry; developer credentials never authenticate to policy. The policy key does not identify package callers. No per-user or per-workload identity is claimed.

**Security coverage**

| Threat / property | Spec or obligation | Evidence and limit |
|---|---|---|
| Credential crossover | `upstream-publisher-auth-before-send`, policy snapshot boundary | Existing source obligation/control PASS; exact runtime destinations remain unproved. |
| Route confusion, policy downgrade, stale release | `classify-selected-registry`, `current-policy-before-service-response` | Both future-source obligations PENDING; lead Slice 16/current-authority witnesses required. |
| Token privacy and audit disclosure | `canonical-token-packument`, `audit-filter-before-render` | Existing source obligations/unsafe controls PASS; they prove encoded call order only. |
| Unpublish destination, replay and marker race | `service-reference-before-delete`, `service-marker-before-delete`, `classify-npm-delete-routes`, `service-removal-marker-after-put` | Four future-source obligations PENDING; exact-value, durable/atomic marker and concurrency checks remain planned. |

The supplied finite model is **PASS**. Three existing source obligations passed with unsafe controls; six future-source obligations are **PENDING** because Slice 1/3 files are absent. The source checks establish structural call order only. Threat model **MODELED** and independent Red Team **SOUND** are plan-level evidence. No product tests or runtime proof were run for this replacement design.

## How will we confirm it is solved?

| Scenario | Expected result | Check status |
|---|---|---|
| Managed policy request uses service key | Key appears only in the snapshot request Authorization header; invalid/unavailable managed authority does not trigger TOML fallback. | Planned in lead Slice 16; not observed here. |
| Two callers use the shared local service | Both receive the same selected policy without package-request Probation login; unapproved host/node is refused. | Planned Slice 1 witness; not observed. |
| Allowed and denied package operations | Local policy is enforced; registry credentials reach only the selected registry, whose allow/deny controls publishing. | Three existing structural checks PASS; runtime destination and full caller outcomes planned. |
| npm metadata and audit | Token-bearing canonical metadata stays request-local; hidden audit details do not appear; unsupported bulk audit remains an upstream error. | Structural checks PASS; integration witnesses planned. |
| npm version unpublish | Only accepted removal creates a revision-bound marker; wrong revision/replay sends no DELETE; selected origin only. | Model PASS; six absent-source obligations PENDING; runtime atomicity/race checks planned. |
| Native release matrix | Required client jobs execute on Linux/macOS/Windows, with Linux policy-server checks and no skipped required rows. | Planned Slice 5; not observed. |

**Limits:** Design approval does not mean implementation works. Exact credential routing, current-authority release, reference value binding, marker durability/atomicity, concurrency, quotas, listener exposure and native platform behavior remain delivery checks. Six declared source obligations await future files. No product tests/runtime proof were run.

**Recommendation:** Approve the credential-separated local-service design and five-slice plan. It answers the identity question directly: package clients are admitted by local/approved-node service access, the firewall uses its own API key only for policy retrieval, and package-manager credentials authorize only operations at the selected registry.

**Context:** Gate 1 scope approved; combined design reopened and unapproved. Design QA is READY with no findings. Approval is required before implementation resumes.

**Sources:** `01-product.md` C1006/C1008/C1009/C1015/C1019–C1024/C1027; active sections of `02-architecture.md`; `03-program-design.md`; active five-row plan in `04-slices.md`; `molecule-flow.json` and `molecule-contracts.json`; `gate-4-qa.md`; `evidence/threat-model-selected-origin-only.md`; `evidence/red-team-selected-origin-only-final.md`; `evidence/source-contract-rebind.md`; `evidence/repository-structure.md`; `evidence/local-client-repository-map.md`.

Approve the design, or what should change?
