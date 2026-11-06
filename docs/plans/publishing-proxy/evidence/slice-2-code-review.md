# Slice 2 independent code review

Review kind: code-review
Verdict: SHIP
Question: Does the frozen local-service npm read/audit delta introduce a material code-quality defect?
Reviewing: supplied isolated `.scratch/slice-2/slice-source.diff`, five manifest files, and connected read-path neighbors; not the unrelated dirty checkout changes.

No material defect or unresolved material defect suspicion was found in this bounded delta. This is a code-quality verdict, **not** slice completion or a source-verification PASS. The required analyzer/control gap remains open under separate tooling repair.

## Defects

none.

## Conventions

Standards set: supplied AGENTS.md instructions and active program-design contract. SMTC found no repository `AGENTS.md`, `CLAUDE.md`, `CONTRIBUTING*`, `CODING_STANDARDS*`, or `docs/codebase-overview.md`. No breaches found. Formatter/linter-enforced style was not manually reviewed.

## Simplifications

none recommended. The delta reuses the existing request-local token handler and existing audit/search filtering. No new abstraction or dependency was introduced. No deletion or replacement is proposed; an unresolved/empty semantic blast radius is not treated as proof that code is removable.

## Deciding evidence

1. `service_registry::respond` preserves the incoming body and the existing peer, storage, policy, rate, and publication-generation gates. `classify_selected_registry` opens POST only for the two exact npm audit routes, permits query strings only for exact search, and refuses pending actions before dispatch. The dispatched request changes its URI without replacing its body.
2. `registry_routes::package` checks Axum's original URI before selecting the token exception. Canonical selected Bearer reads reuse `serve_token_packument`; rewritten legacy aliases and Basic reads take ordinary filtering. Version and artifact handlers continue to use ordinary policy. Both package paths recheck current authority before handoff.
3. `token_packument.rs` makes a direct selected-origin request without the shared metadata cache path or conditional validators, verifies document identity, bounds input/output, rewrites artifact links locally, and does not prepare write leases without `write=true`. The service classifier refuses that query in this slice. The transport refuses redirects and caps response bytes.
4. `named_read` caps request bytes, preserves gzip encoding, bounds the complete fetch/filter/recheck operation to 30 seconds, and releases its active permit on completion or timeout. Search rebuilds visible advertised versions; audit rebuilds safe fields from visible versions with lookup/comparison/output bounds. Bulk 404 propagates; there is no synthesized quick request.
5. The changed E2E test uses real HTTP/npm behavior and upstream fixture responses, including accepted/denied/absent credentials, concurrent and restart isolation, legacy/version/artifact restrictions, nonempty gzip audit, safe nonempty reports, malformed reports, caps, header/body limits, and a sole-permit timeout control. The supplied red line fails accepted hidden metadata with HTTP 403 before the fix; supplied GREEN3 passes the complete scenario. These assertions do not recompute expected values using the implementation under test. The fake transport adapter implements the newly exercised token operation, and fixture instrumentation records body length rather than contents.

Evidence tier: Manual for selected source inspection, supplemented by Structural symbol/caller evidence. Supplied runtime evidence is E2E 1 passed/0 failed, workspace 782 passed/0 failed/21 ignored, and compiler PASS; these runs were not repeated. No analyzer certificate or unsafe-control success is claimed.

## Subject and stability

Base resolves to `8d9f5e35b6d92898f6c9c33b852df5a9b04e8d59`. The supplied subject digest matched before inspection and at final check:

`ce808dc2eac9cae3965829109cd5e3de443eb90b4e412d2d34d7896c27bfc7a6  .scratch/slice-2/final-subject.json`

Isolated patch digest also stayed `98a33dc01e8b99d16ff61970797b503d5a04e1a55278c964eba4aeea30fdc4e5`.

All five baseline-copy hashes matched the manifest. All five current hashes matched before and after review:

| File | SHA-256 |
|---|---|
| src/http/service_registry.rs | 554b70a6d61e8f653667083fe36065fb0d619af791a95a616e066dd5b229f31c |
| src/http/registry_routes.rs | 7d9f4c3cc285f3fc9ac064529cb45e684ed142eaa5b3ac34046287bdfd160bb0 |
| tests/shared_service.rs | 0c2bb3b79851551bc17d3d7b16bf3ad22ee192b0fcdd41248558969252af52ba |
| tests/e2e/fixtures/fakes/main.mjs | d1a8f760f5ebed4a89e04d899fe48ab56be07cad119387480d3cca59dd0d9586 |
| tests/e2e/scenarios/publishing-npm-read.mjs | ff6951112437c06cdfec740e3b55042cf309e855d9006afdee0fea5cb331a2cc |

Supporting code fingerprints: `registry_read.rs` 83188bf11ce0d0a0f5258042f037ba1277d7b45568807438aa382e16f1ce3730; `token_packument.rs` 31176bfad7f228496bfb78060a679b8c0e7540be74f52a8a0e684406516c2ab2; `mod.rs` eebdc3111981cfcd9fa594e26b4ffd695afe9414f59dea19580b1871fbc37a3a; `audit_filter.rs` 24baaf46396302c127260447e909408841186cd7e02e9e6c0e82aa0fe65e697f; `src/upstream/reqwest_transport.rs` 08cbadb340daf7a6237c874435b7ef3b521210fa1a5ab977712ffbf87c11a43d; `src/upstream/mod.rs` 29c397e732d5468e8ac70221357dcdaca7428c85cb2475d27a98fafbd2f5c71f.

## SMTC receipt

Root for every rooted command: `/home/john/go/src/github.com/postfix/probation`. Stable session: `sf-slice2-review-2026-11-03`. Every question-specific command used `--root /home/john/go/src/github.com/postfix/probation --format json --max-tokens 2048 --session-id sf-slice2-review-2026-11-03`. No secrets were passed. Below, argv lists the operation arguments before that exact suffix; this is a lossless compact receipt, not a raw tool payload.

| Operation / argv | Status | Fidelity, completeness, interpretation |
|---|---|---|
| `file find --pattern <pattern> --max-results 20`, individually for `AGENTS.md`, `CLAUDE.md`, `CONTRIBUTING*`, `CODING_STANDARDS*`, `docs/codebase-overview.md` | run; outer true; no inner refusal | Five complete zero-match results; empty repository standards set. |
| `file read --path src/http/service_registry.rs --start-line 1 --end-line 145`; `--start-line 147 --end-line 175` | run; outer true; no inner refusal | Complete selected source; middleware, classifier and dispatch. |
| `file read --path src/http/registry_routes.rs` with ranges 1–165, 225–340, 400–530, 530–645, 645–685 | run; outer true; no inner refusal | Complete selected source; last range clamped at EOF, not truncated. Package/version/artifact and named-read neighbors inspected. |
| `file read --path src/http/registry_read.rs` | run; outer true; no inner refusal | Complete 137 lines; service-principal credential validation and authority rechecks. Fingerprint was first recorded immediately after this initial read, then checked unchanged. |
| `file read --path src/http/token_packument.rs --start-line 1 --end-line 150`; range 148–172 | run; outer true; no inner refusal | Complete production file, latter range clamped at EOF. Direct request-local selected-origin path. |
| `file read --path src/http/mod.rs --start-line 35 --end-line 110` | run; outer true; no inner refusal | Complete selected router wiring; original URI preservation and separate audit routes. |
| `file read --path src/http/audit_filter.rs --start-line 1 --end-line 165`; range 165–250 | run; outer true; no inner refusal | Complete production file; EOF clamp only. Safe-field reconstruction and limits. |
| `file read --path src/upstream/reqwest_transport.rs --start-line 189 --end-line 280`; `file read --path src/upstream/mod.rs --start-line 224 --end-line 249` | run; outer true; no inner refusal | Complete selected source; capped direct transport, no redirect follow, semaphore lifetime. |
| `file read --path tests/shared_service.rs --start-line 1 --end-line 105`; `file read --path tests/e2e/fixtures/fakes/main.mjs --start-line 95 --end-line 145` | run; outer true; no inner refusal | Complete changed code units and enclosing collaborators. |
| `file read --path tests/e2e/scenarios/publishing-npm-read.mjs` with ranges 1–80, 81–124, 125–185, 186–245, 246–295, 296–340, 341–400 | run; outer true; no inner refusal | Entire current scenario inspected; last range clamped at EOF. Earlier wider 125–240 and 246–340 reads produced refs 61/62, superseded by these complete narrower reads. |
| `file read --path docs/plans/publishing-proxy/03-program-design.md --start-line 1 --end-line 42`; `file read --path docs/plans/publishing-proxy/evidence/slice-2.md` ranges 1–23 and 24–44 | run; outer true; no inner refusal | Active design and evidence limitations inspected. Earlier wide evidence read ref-66 and broad design grep ref-65 were superseded by narrow reads. |
| `file grep --pattern 'C35\|C37\|C38\|Slice 2' --path-include docs/plans/publishing-proxy/01-product.md --max-results 20` | run; outer true; no inner refusal | Complete four contract matches; selected token exception, safe audit, no fabricated fallback. |
| `file grep --pattern 'async fn named_read\|fn dispatch_selected\|registry_routes::\|BodyLimit\|service_registry' --path-include 'src/http/*' --max-results 20` | run; outer true; no inner refusal | Truncated locator only; followed by complete bounded source reads, no negative claim. |
| `file grep --pattern 'async fn fetch_token_packument\|async fn fetch_named_read' --path-include 'src/upstream/*' --max-results 20` | run; outer true; no inner refusal | Complete six matches; located transport implementations for subsequent reads. |
| `search symbol --name-pattern classify_selected_registry --limit 6`; `inspect symbol --handle /home/john/go/src/github.com/postfix/probation/src/http/service_registry.rs:66:145` | run; outer true; no inner refusal | One unambiguous declaration and complete body; zero-based span 65–144, one-based read 66–145. |
| `search symbol --name-pattern package --limit 6`; `search symbol --name-pattern '^package$' --limit 6`; `search symbol --name-pattern registry_routes::package --limit 6` | run; outer true; no inner refusal | First truncated at six of 53; regex search explicitly warned metacharacters are literal; qualified substring returned zero. These searches do not establish absence. Exact packet path plus inspect-file declaration and impact result disambiguated the handler. |
| `inspect file --path src/http/registry_routes.rs --limit 5`; rootless `smtc ref show ref-63 --session-id sf-slice2-review-2026-11-03`; `inspect symbol --handle /home/john/go/src/github.com/postfix/probation/src/http/registry_routes.rs:26:77` | run; outer true; no inner refusal | Inspect-file ref estimate 2111, under 4096; ref resolved the exact file declaration. Complete symbol body inspected. Ref display itself was host-truncated among imports after the deciding declaration, so no import-completeness claim. |
| `search symbol --name-pattern serve_token_packument --limit 6`; `inspect symbol --handle /home/john/go/src/github.com/postfix/probation/src/http/token_packument.rs:36:45` | run; outer true; no inner refusal | One declaration and complete body. |
| `search symbol --name-pattern respond --limit 6`; `inspect symbol --handle /home/john/go/src/github.com/postfix/probation/src/http/service_registry.rs:19:60` | run; outer true; no inner refusal | Search truncated at six of eight, largely witness declarations. Exact caller receipt resolved the production `respond`; complete production body inspected. |
| `search symbol --name-pattern npmRead --limit 6` | run; outer true; no inner refusal | Two explicit file candidates, current scenario selected by packet path; entire body read in bounded chunks above. |
| `review impact --file src/http/registry_routes.rs --start-line 25 --end-line 58` | run; outer true; no inner refusal | Complete range result identifies `package`; reports no direct callers. This does not prove no router/external consumers; router wiring was inspected explicitly. |
| `review blast-radius --symbol classify_selected_registry --reverse --include-resolution` | run; outer true; no inner refusal | Truncated ref-64, estimate 16312; deliberately not opened. Not used to prove safe deletion. Bounded callers leg substitutes for the deciding direct-consumer question. |
| `callers --name classify_selected_registry --depth 1 --limit 5` | run; outer true; no inner refusal | One exact direct call from production `respond`, unambiguous resolution; parse health one file/zero errors/zero dropped statements. Reports 2182 unresolved dispatch sites globally, retained as a semantic limit. |

Compiler/diagnostics receipt inherited explicitly from packet: daemon HEALTHY, diagnostics unavailable after exact retry; approved native Cargo fallback. No new diagnostic PASS is claimed. No heavy suite was rerun because inspection found no concrete concern requiring another expensive execution.

Unchanged during review: yes, five product/test files and inspected supporting code; manifest and isolated patch unchanged. Scoped Git status preserved three tracked modifications and two existing untracked files.

Reviewed: all five manifest delta units (`respond`/classifier, package handler, credential fake adapter, fake request instrumentation, whole npm scenario), plus selected router wiring, registry admission/recheck, version/artifact policy gates, named-read handling, token handler, audit filter, and transport methods. Deleted: none as files; obsolete certificate-era scenario sections were reviewed through the isolated patch and are explicitly historical under the active design.

Checked clean: correctness/totality/boundaries/types/numerics; errors/partial failure; ownership/cleanup/cancellation/lifecycle; shared state/ordering/races/deadlocks/termination; pre/postconditions/invariants/compatibility/side effects; input bounds and obvious security defects; maintainability drift; meaningful tests and supplied red-before-green evidence; approved-scope changes; conventions; simplifications.

Omitted: defects 0; conventions 0; simplifications 0.

Limitations: Manual source review with bounded Structural support, not a whole-repository safety proof. Existing source-verification capability and diagnostics gaps remain open; graph absence/truncated results were not treated as clean safety evidence. Native OS/client matrix and obsolete certificate/full-matrix migration belong to later slices and were not accepted here. No external API documentation lookup was needed.

Skipped: repeated heavy suites, historical certificate/native-client acceptance, and tooling repair owned by the coordinator. Risk: this review does not close the required source-proof gap.
