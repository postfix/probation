# Slice 3 planned spec validation — 2026-11-03

**Overall: UNKNOWN for complete contract certification.** Three unchanged ordered specs earn KEEP for their narrow structural claim; the DELETE classification spec is UNKNOWN because both runs fail CFG dominance analysis. Two approved contract summary strings do not match current runner text. No approved source, model, or spec was changed.

## Dispositions

| Existing planned spec | Verdict | Current safe source | Exact approved unsafe mutation | Scope |
|---|---|---|---|---|
| service-removal-marker-after-put | KEEP (Structural) | 0 findings; 1 operation, 1 guard; 0/1 unguarded | 1 finding, commit_service_removal_marker, service_unpublish.rs:25 | Resolver call dominates marker commit |
| service-unpublish-reference-before-send | KEEP (Structural); model expectation unresolved | 0 findings after scope filter; 10 operations, 1 guard, 9 unrelated findings removed | 1 finding, app.transport.send_action, service_unpublish.rs:103 | Reference-check call dominates send |
| service-unpublish-marker-before-delete | KEEP (Structural); model expectation unresolved | 0 findings after scope filter; 10 operations, 1 guard, 9 unrelated findings removed | 1 finding, app.transport.send_action, service_unpublish.rs:103 | Marker-consumption call dominates send |
| npm-delete-routes-classify-before-dispatch | UNKNOWN | analysis_failed at service_registry.rs:49 | Same analysis_failed at unsafe service_registry.rs:49 | Cannot conclude classification dominance |

Retained unsafe noise: 0 unexpected findings in each of the three successful controls. Safe results contain no VacuousObligation, truncation, refs, or diagnostics. Runner does not publish a functions-analyzed count or an explicit fidelity field; operation/guard counts and cfg_dominance trace are the available completeness evidence. Findings identify structural confidence. No compile/certificate evidence is claimed.

The registry inventory contains 28 existing analyzers, including historical unpublish-reference-before-send, unpublish-marker-before-send and accepted-removal-before-marker. This run reuses the four already approved service-route specs exactly; no new candidate or duplicate analyzer is proposed. Candidate kind/body are the unchanged ordered_obligation YAML at docs/plans/publishing-proxy/specs/<name>.yaml.

## Controls and binding

Safe control root for every spec: `/home/john/go/src/github.com/postfix/probation`.

Unsafe roots are source-only copies of the complete relevant current source file, altered by exactly one approved molecule-contract mutation; they deliberately do not compile because unchecked guard replacements are undefined. Spec controls are structural, not executable Rust tests.

- `/home/john/go/src/github.com/postfix/probation/.scratch/slice3-specs/service-removal-marker-after-put/unsafe`: `src/http/service_unpublish.rs`; replace `let revision = resolve_removed_revision_from_put_or_authenticated_get(&response, &reference).await?;` with `let revision = unchecked_removal_revision(&response, &reference).await?;`.
- `/home/john/go/src/github.com/postfix/probation/.scratch/slice3-specs/service-unpublish-reference-before-send/unsafe`: `src/http/service_unpublish.rs`; replace `let reference = check_service_reference(&app, registry, reference, package, filename).await?;` with `let reference = unchecked_service_reference(&app, registry, reference, package, filename).await?;`.
- `/home/john/go/src/github.com/postfix/probation/.scratch/slice3-specs/service-unpublish-marker-before-delete/unsafe`: `src/http/service_unpublish.rs`; replace `let marker = consume_service_marker(&app, registry, &reference, revision).await?;` with `let marker = unchecked_service_marker(&app, registry, &reference, revision).await?;`.
- `/home/john/go/src/github.com/postfix/probation/.scratch/slice3-specs/npm-delete-routes-classify-before-dispatch/unsafe`: `src/http/service_registry.rs`; replace `let route = classify_direct_or_whole_package_delete(&request)?;` with `let route = unchecked_npm_delete_route(&request)?;`.

Source SHA-256 was captured before the deciding runs and after all runs; both remained unchanged:

- src/http/service_unpublish.rs: `0c49a83b5d1e54edef99a5da501bf246156acb0f2c70907325a0cfac59143301`
- src/http/service_registry.rs: `60a29c429bc434a7f02e399e8d995d591de5ff0a3749e405833ff49afddfb748`

Unsafe SHA-256, in table order:

1. `2359ca96180dccb09bfaaa57003d25115eeb2f6b9cf348a4df5e3795115b3181`
2. `ff8e089c785e0d273e3d853a9e5a86e437391de844a6ddeee4ce3e9955467e9d`
3. `c268996232b5fc82d04943b5e3a7b2c990e03df78bfd54ca4a943f48b281a136`
4. `950d3f3cd39ade535aa85829afc339c84f5fc53bb2fb534138ad9575f51896dd`

Read-only input hashes captured during validation:

- molecule-contracts.json: `7cb3bb8cc92af0e220b771dfc672592b8b7ce9d46a33c70b912df22bbdbbbd7b`
- service-removal-marker-after-put.yaml: `9b10f579ee58592213bf5e4a84983d480851c3f1065ffbf156d7dc23e96ba3c1`
- service-unpublish-reference-before-send.yaml: `cbb99d749b5576acbadf5b54786d4cd552dd45410064e12107c93b6ecca5dabd`
- service-unpublish-marker-before-delete.yaml: `2951b7e029318e172cbd86f9b695aa27bfc5e75e9c862714f06c1886c8881a56`
- npm-delete-routes-classify-before-dispatch.yaml: `8708559028a35ec74bed5a823ca3f69b61ccbc4f31433427676108ca6f1c68d6`

## Model expectation gap

Both send-order contracts expect the literal substring `Operation 'send_action' lacks required guard`. The runner emits `Operation 'app.transport.send_action' lacks required guard`. The expected string is not a substring of that output. This does not invalidate the structural witness at the exact planned send, but the approved model's exact expectation cannot be declared satisfied. Parent must decide how the existing verifier handles qualified names, or approve an explicit expectation update; no silent normalization or weakened anchor was applied here.

## Runtime obligations remain separate

These specs do not prove exact service/registry/package/version/filename/revision/destination values, successful upstream authorization, absence of the leased version, authenticated selected-upstream GET behavior, durable commit, partial-write recovery, quota+1 refusal with unchanged store, transactional concurrent one-winner consumption, replay refusal, credentials/SSRF, restart behavior, whole-package DELETE semantics, or direct tarball zero-I/O refusal. Those remain runtime/source-review obligations, not new ordered specs.

## SMTC receipt

Stable session: sf-slice3-specs-2026-11-03. All paths are local and contain no secrets; argv are unredacted.

Inventory first project operation:

```text
smtc spec list --root /home/john/go/src/github.com/postfix/probation --format json --max-tokens 2048 --session-id sf-slice3-specs-2026-11-03
```

Status run; outer ok=true; 28 specs; no inner refusal, refs or truncation. Synthesis: reuse approved planned specs.

SMTC file reads/find/grep located approved YAML, active design, exact model mutations and source bytes. Broad design read returned ref-85 (5446 estimated tokens), which was not opened. Narrowed lines 70–114 returned ref-86 (2442 tokens), opened with `smtc ref show ref-86 --session-id sf-slice3-specs-2026-11-03`. Source registry read returned ref-87 (2633 tokens), opened likewise. Both opened refs returned complete selected content; source unpublish and four YAML reads were inline and untruncated. A broad summaryIncludes grep hit its 20-result bound and was used only to locate candidates, never to prove verifier behavior. Native source fallback: none.

### service-removal-marker-after-put

```text
smtc spec run --root /home/john/go/src/github.com/postfix/probation --spec-file /home/john/go/src/github.com/postfix/probation/docs/plans/publishing-proxy/specs/service-removal-marker-after-put.yaml --format json --max-tokens 2048 --session-id sf-slice3-specs-2026-11-03
smtc spec run --root /home/john/go/src/github.com/postfix/probation/.scratch/slice3-specs/service-removal-marker-after-put/unsafe --spec-file /home/john/go/src/github.com/postfix/probation/docs/plans/publishing-proxy/specs/service-removal-marker-after-put.yaml --format json --max-tokens 2048 --session-id sf-slice3-specs-2026-11-03
```

### service-unpublish-reference-before-send

```text
smtc spec run --root /home/john/go/src/github.com/postfix/probation --spec-file /home/john/go/src/github.com/postfix/probation/docs/plans/publishing-proxy/specs/service-unpublish-reference-before-send.yaml --format json --max-tokens 2048 --session-id sf-slice3-specs-2026-11-03
smtc spec run --root /home/john/go/src/github.com/postfix/probation/.scratch/slice3-specs/service-unpublish-reference-before-send/unsafe --spec-file /home/john/go/src/github.com/postfix/probation/docs/plans/publishing-proxy/specs/service-unpublish-reference-before-send.yaml --format json --max-tokens 2048 --session-id sf-slice3-specs-2026-11-03
```

### service-unpublish-marker-before-delete

```text
smtc spec run --root /home/john/go/src/github.com/postfix/probation --spec-file /home/john/go/src/github.com/postfix/probation/docs/plans/publishing-proxy/specs/service-unpublish-marker-before-delete.yaml --format json --max-tokens 2048 --session-id sf-slice3-specs-2026-11-03
smtc spec run --root /home/john/go/src/github.com/postfix/probation/.scratch/slice3-specs/service-unpublish-marker-before-delete/unsafe --spec-file /home/john/go/src/github.com/postfix/probation/docs/plans/publishing-proxy/specs/service-unpublish-marker-before-delete.yaml --format json --max-tokens 2048 --session-id sf-slice3-specs-2026-11-03
```

### npm-delete-routes-classify-before-dispatch

```text
smtc spec run --root /home/john/go/src/github.com/postfix/probation --spec-file /home/john/go/src/github.com/postfix/probation/docs/plans/publishing-proxy/specs/npm-delete-routes-classify-before-dispatch.yaml --format json --max-tokens 2048 --session-id sf-slice3-specs-2026-11-03
smtc spec run --root /home/john/go/src/github.com/postfix/probation/.scratch/slice3-specs/npm-delete-routes-classify-before-dispatch/unsafe --spec-file /home/john/go/src/github.com/postfix/probation/docs/plans/publishing-proxy/specs/npm-delete-routes-classify-before-dispatch.yaml --format json --max-tokens 2048 --session-id sf-slice3-specs-2026-11-03
```

All eight spec legs ran. For the three successful pairs, outer ok=true, inner trace as in disposition table, no refs/truncation/diagnostics; structural findings only. Current-source request IDs: removal req-3993313-1793720229880-0, reference req-4002957-1793720293004-0, marker req-4003224-1793720294409-0. Removal safe trace: find_operations 1, find_guards 1, dominance 0/1, where_filter 0/0; duration 17076ms, generation 66. Reference/marker safe generation 67; source hashes unchanged across generations.

Classifier safe and unsafe: status run, outer ok=false, inner error analysis_failed, no analysis count/refs/truncation, no verdict. Error: `required dominance cannot resolve operation block at <root>/src/http/service_registry.rs:49`.

Seven raw result logs are in .scratch/slice3-specs/<name>-<safe|unsafe>.json. The first removal-safe result is recorded by request ID and exact deciding trace above rather than a raw log.

A later ancillary verifier-location search failed with daemon_unavailable (IPC Operation not permitted):

```text
smtc file grep --root /home/john/go/src/github.com/postfix/probation --pattern 'summaryIncludes' --path-include tools/** --max-results 20 --format json --max-tokens 2048 --session-id sf-slice3-specs-2026-11-03
```

Status refused; outer ok=false; no inner analysis. No native fallback. This does not erase already completed runs; verifier implementation behavior remains UNKNOWN.

## Required next action

1. Parent dispatches sf-smtc-doctor capability for the classifier safe/unsafe argv above and source/control files; classify analysis_failed dominance limitation, recover if possible, and rerun once after supported/FRESH verdict. The unsafe root remains the positive control.
2. If daemon IPC refusal persists, sf-smtc-doctor health for the exact ancillary grep argv above.
3. Parent resolves the two qualified-summary expectation gaps explicitly.
4. Parent routes unchanged validated specs and matching unsafe roots through sf-verify-cert for certificate/source-contract evidence. No spec was persisted to .smtc/analyzers; no certificate was generated.

Deciding evidence items: four spec pairs and hash binding (five total); omitted deciding items: 0.
