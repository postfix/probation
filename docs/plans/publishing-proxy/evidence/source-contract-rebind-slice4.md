# Slice 4 source-control rebind

The approved D40/D41 guarantees and analyzer specs are unchanged. The eight planned unsafe controls in `molecule-contracts.json` named exact illustrative source statements that do not occur in the implemented `src/http/unpublish_reference.rs`. All eight production analyzer checks had zero findings, but the mutation controls returned UNKNOWN because their `from` text matched zero sites. The frozen source at `5a5283ab8780e9f45a7f9dcafeda2a9152532fb9fcdb10f69fe09447c57f317b` passed the pinned npm 11.21.1 selected action E2E (1/1), focused URL/scope tests (2/2), offline workspace compile and the finite model check.

The sidecar now replaces only those eight exact `from`/`to` strings with the real guard call and its unsafe counterpart in `send_unpublish_delete` or `forward_revision_put`. It changes no source symbol, approved claim, analyzer spec, flow, slice assignment or required runtime witness. The scope guard was made effective before rebinding: `approve_deletion_scope` runs once after URL validation, and its returned origin and bearer mode supply the outbound `ActionRequest`. A mutation of that call now removes a guard that controls the actual destination and credential choice.

| Obligation | Guarded value whose exact call is rebound | Unsafe control removes |
|---|---|---|
| `unpublish-reference-before-send` | Member, registry, ID and filename-bound lease | Reference identity lookup |
| `unpublish-origin-before-delete` | Decrypted HTTPS destination, filename and revision | Destination validation |
| `revision-links-before-action` | Restored revision JSON from member-bound leases | Revision link restoration |
| `restored-revision-before-send` | The same outgoing JSON before action send | Revision link restoration |
| `unpublish-scope-before-send` | Current approved origin and bearer mode used by outbound action | Scope approval |
| `unpublish-marker-before-send` | One-use marker for the exact resulting revision | Marker consume |
| `accepted-removal-before-marker` | Accepted removal and resulting revision | Accepted-removal classification |
| `marker-commit-before-success` | Durable marker committed before PUT success | Marker commit |

`router molecule-check --plan-root docs/plans/publishing-proxy` returned PASS. `router molecule-verify --plan-root docs/plans/publishing-proxy --slice 4` returned PASS for every declared Slice 1–4 production check and its unsafe mutation, including all eight rebound D40/D41 controls; there were no findings or pending obligations at this slice. Source evidence: `/home/john/.local/state/software-factory/contract-evidence/repo-cc718bf594b6832a/run-7uzC0X`. This establishes selected call order and mutation detection only. Exact URL, sealed query, member/revision binding, outbound peer/credential bytes and concurrency remain runtime and independent-review obligations in Slice 4.
