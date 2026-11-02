# Slice 1 source contract rebinding

The original thirteen proposed obligations did not describe the implemented Rust call sites. The reopened design binds twelve selected obligations to actual or planned sources. The finite model still passes its twelve declared flows. This changes evidence coverage, not the approved certificate, registry, policy, or token behavior.

`router molecule-verify --plan-root docs/plans/publishing-proxy --slice 1` returned `PENDING` with evidence at `/home/john/.local/state/software-factory/contract-evidence/run-CNdxh9`: all seven existing Slice 1 sources and their unsafe mutations passed with Structural fidelity; five obligations for absent Slice 2–4 sources are pending. No existing source check is unknown or failed. `router molecule-check` returned `PASS` for the finite model. The verifier's source snapshots, command records, raw analyzer results and hashes are in that evidence directory.

After the Slice 1 request-path fix, `molecule-verify --slice 1` was rerun with evidence at `/home/john/.local/state/software-factory/contract-evidence/run-Rf9eId`. All seven due Slice 1 source checks and unsafe controls PASS with Structural fidelity. The five absent Slice 2–4 sources remain PENDING. The approved model and sidecar were unchanged; the revised source retained the named analyzer anchors while using one request permit and one rate charge across the final live recheck.

| Slice 1 check | Structural property and limit |
|---|---|
| `classify-before-dispatch` | Registry ID validation precedes npm package dispatch. Exact route table and unknown-route denial need runtime controls. |
| `tls-peer-before-admit` | The required peer option precedes certificate admission. TLS provenance and same-peer value need runtime controls and source review. |
| `current-certificate-before-grant` | Management certificate lookup precedes policy resolution. Exact peer, status, member and registry values need runtime controls. |
| `policy-before-package-send` | Package resolution precedes npm metadata rendering. Policy outcome, artifacts and all routes need runtime controls. |
| `self-service-before-bundle` | Member lookup precedes bundle rendering. Session ownership and the inline self-service switch need runtime controls. |
| `certificate-revoke-before-success` | Certificate update execution precedes success redirect. Commit and next-request refusal need runtime controls. |
| `member-disable-before-commit` | Member disable update auto-commits before success redirect. All-certificate refusal needs runtime controls. |

The former `member-registry-before-grant` obligation is not selected. SMTC could not lower the full `sync::admit_certificate` control flow and could not establish the selected-registry argument on an extracted fluent SQL `bind`/`fetch_optional` chain. A generic `bind` check would pass even after removing the registry bind. Retaining that as a PASS would misstate the evidence. The production query in `crates/probation-server/src/sync.rs::admit_certificate` joins `memberships` to the certificate and organization, binds the selected registry and leaf fingerprint, requires an active member and certificate, and reads group policy in the same transaction. Independent source review must check those exact predicates. The Slice 1 E2E witness must exercise two members with different groups in one organization, foreign organization/registry refusal, disabled-member refusal, root rotation, revocation and management outage with zero upstream I/O on refusal. These are required product behaviors, not optional consequences of the analyzer limit.

The Slice 3 `canonical-token-packument` obligation now points to the planned absent `src/http/token_packument.rs`, so it remains genuinely pending until that slice creates its implementation. All future obligations retain explicit source paths, specs, unsafe mutations and runtime limits. Any source, spec or sidecar change requires fresh verification; design approval is required before delivery completion.
