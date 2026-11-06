# Slice 2 adversarial review

Review kind: adversarial  
Verdict: PASS  
Review: independent  
Question: Can the frozen local-service npm read changes widen the canonical token exception, leak token-private/audit metadata, lose audit bodies, or strand bounded-work admission, and do the retained tests meaningfully attack those risks?  
Subject: base=`8d9f5e35b6d92898f6c9c33b852df5a9b04e8d59`; task delta `.scratch/slice-2/slice-source.diff`, bounded by `.scratch/slice-2/final-subject.json`.

| Path | Verified current SHA-256 |
|---|---|
| `src/http/service_registry.rs` | `554b70a6d61e8f653667083fe36065fb0d619af791a95a616e066dd5b229f31c` |
| `src/http/registry_routes.rs` | `7d9f4c3cc285f3fc9ac064529cb45e684ed142eaa5b3ac34046287bdfd160bb0` |
| `tests/shared_service.rs` | `0c2bb3b79851551bc17d3d7b16bf3ad22ee192b0fcdd41248558969252af52ba` |
| `tests/e2e/fixtures/fakes/main.mjs` | `d1a8f760f5ebed4a89e04d899fe48ab56be07cad119387480d3cca59dd0d9586` |
| `tests/e2e/scenarios/publishing-npm-read.mjs` | `ff6951112437c06cdfec740e3b55042cf309e855d9006afdee0fea5cb331a2cc` |

Summary: No defect established in the scoped risks; the migrated scenario attacks the main isolation, disclosure, routing and bounded-work promises, with three useful incremental test improvements below.

## Findings

None. The proposed tests are additional falsification opportunities, not demonstrated implementation failures or required scope expansion.

## Deciding evidence

1. `src/http/service_registry.rs:43–149` preserves the request body, selects only configured ecosystem/registry identities, limits POST to exact audit paths, and rejects non-search queries before dispatch. `src/http/registry_routes.rs:26–76` checks the original selected-prefix URI and Bearer authorization before using the token path. `src/http/token_packument.rs:19–145` validates GET/token, fetches directly with the supplied token, parses/bounds the result and renders selected local artifact URLs. No shared-cache operation appears in that selected handler. Legacy alias and explicit version reads retain the ordinary filtered branch/handler.
2. `tests/e2e/scenarios/publishing-npm-read.mjs:48–110` distinguishes owner/denied/absent credentials, version and legacy boundaries, query refusal, credential-bearing redirects, hidden artifact refusal, three concurrent probes, and post-restart isolation. This is substantially stronger than merely asserting that owner metadata is visible. Existing shared-service tests additionally exercise warm artifact reauthorization (`tests/shared_service.rs:639–681`).
3. `src/http/registry_routes.rs:445–681` bounds body collection, preserves gzip, places fetch/filter/recheck inside one 30-second timeout, and drops the permit after timeout completion/error. `src/http/audit_filter.rs:13–170` caps distinct lookups/concurrency/comparisons and computes signals from ordinary policy-filtered packuments. Quick responses with malformed/nonempty unsupported vulnerability reports refuse.
4. `tests/e2e/scenarios/publishing-npm-read.mjs:165–283` uses one active permit, requires real npm gzip audit traffic, taints denied and allowed advisory text, asserts exact safe fields and visible versions, checks malformed/mixed responses and cap excess, exercises real npm nonempty advisories, and preserves upstream bulk-404 without invented quick fallback. Later cases check M+1 request/output, response/artifact bounds, forbidden routes and the 30-second timeout followed by a successful ping.
5. Supplied `slice-2.md` / `tdd-slice-2.md` bind GREEN3 to this five-file subject: E2E 1 passed/0 failed/0 skipped; workspace 782 passed/0 failed/21 ignored; focused shared-service 4 passed; compiler/model pass. These are supplied execution evidence, not tests rerun by this reviewer. Active design `03-program-design.md:28–33` and Slice 2 row `04-slices.md:10` define the reviewed promises. Required source-verifier compatibility recovery remains a separate acceptance condition.

## Proposed tests — not executed

1. **Overlapping cold credential requests:** use a fresh hidden package and an upstream barrier that holds the accepted request while denied and anonymous requests arrive, then release all three. Expect 200/403/403, distinct credential-correct upstream requests, and no private bytes in the latter responses. The current concurrent launch verifies outcomes but does not force an overlapping in-flight window; a barrier would more reliably expose accidental coalescing.
2. **Exact audit body preservation:** send two distinct valid gzip audit payloads and have the fake decompress and compare their dependency maps in memory, recording only equality/digest and length. Expect the exact matching input for each selected upstream POST. Current `bodyBytes > 0` plus gzip witnesses catches body removal but could miss truncation/substitution that remains nonempty; the fake's empty default answer does not depend on input content. Keep body contents out of logs.
3. **Scoped canonical token boundary:** publish and block `@scope/package`; compare canonical `@scope%2Fpackage` GET with accepted/denied/no token, raw legacy `/npm/@scope/package`, explicit scoped version GET, and canonical tarball. Expect the accepted encoded canonical packument alone to reveal hidden metadata; all ordinary hidden reads/artifacts refuse. This targets the interaction between percent-decoding, two-segment scoped-name routing and the original URI guard, complementing the current unscoped fixture and existing raw-scoped artifact test.

Changed paths: only this review report; no product or test edits.  
Out of scope: source-verifier repair and final goal-delivery acceptance; certificate-era and later publishing/native matrices.  
Tier: Manual (selected source/text inspection plus supplied executable results; no fresh executable proof).  
Limitations: no test suite rerun, fuzzing or packet capture; no universal proof of cache isolation or parser safety. Required source verification was explicitly not counted as passing.  
Omitted: 0 findings; receipt lists auxiliary locating legs separately.

## SMTC receipt

Stable session: `sf-slice2-adversarial-2026-11-03`; root: `/home/john/go/src/github.com/postfix/probation`. Every command below used exact `smtc` argv, no pipes/redirection/wrappers. Read recipe: `smtc file read --root <root> --path <path> --start-line <start> --end-line <end> --format json --max-tokens <bound> --session-id <session>`; omitted ranges mean whole file. Grep recipe: `smtc file grep --root <root> --pattern <pattern> --path-include <include> --max-results 20 --format json --max-tokens <bound> --session-id <session>`. Placeholders expand to the root/session above and the literal table entries below.

All legs ran with outer `ok:true`, no inner refusal or errors. Fidelity: raw file/text evidence; functions analyzed: not applicable. No diagnostics/compile/source-certificate verdict was requested. These reads support a Manual review only.

| Operation / literal arguments | Bound | Truncation/ref | Interpretation |
|---|---:|---|---|
| read `src/http/service_registry.rs` 1–220 | 2048 | truncated, ref-78, estimate 2220; not opened | Narrowed immediately to deciding range below. |
| read `src/http/service_registry.rs` 20–155 | 6000 | none | Complete selected classifier/dispatch evidence. |
| read `src/http/registry_routes.rs` 20–160 | 6000 | none | Complete token branch and ordinary version path. |
| read `tests/e2e/scenarios/publishing-npm-read.mjs` 120–225 | 6000 | none | Audit/search/native assertions. |
| read `src/http/token_packument.rs` whole file | 6000 | none | Direct request-local token handler. |
| read `tests/e2e/scenarios/publishing-npm-read.mjs` 225–330 | 5000 | none | Caps, unsupported bulk, limits and network checks. |
| grep `async fn\|MAX_\|timeout\|filter_audit`, include `src/http/registry_routes.rs` | 2048 | none | Located bounded named-read implementation. |
| grep `registry_routes::\|service_registry::`, include `src/http` | 2048 | zero files scanned | Non-deciding directory include; replaced with glob below, not a negative proof. |
| read `src/http/registry_routes.rs` 445–590 | 6500 | none | Bounded body/fetch/filter code. |
| read `src/http/registry_read.rs` 1–170 | 6500 | none; EOF clamp | Service principal and credential parsing. |
| read `tests/shared_service.rs` 1–210 | 6500 | none | Transport and existing test setup; auxiliary. |
| grep `C35\|C37\|C38`, include `docs/plans/publishing-proxy/*` | 4000 | max-results/truncated | Located exact Slice 2 row; broad results not used as exhaustive policy proof. |
| read `src/http/audit_filter.rs` 1–170 | 5500 | none | Work caps, malformed quick handling and policy-visible lookup. |
| grep `registry_routes::\|service_registry::`, include `src/http/*.rs` | 3000 | none | Exact route registrations located. |
| read `docs/plans/publishing-proxy/03-program-design.md` 1–115 | 6500 | none | Active approved boundary, historical-section warning. |
| grep `Basic\|private-only\|Bearer allowed\|async fn`, include `tests/shared_service.rs` | 3000 | max-results/truncated | Located warm reauthorization test; not exhaustive test-absence evidence. |
| read `tests/shared_service.rs` 620–720 | 4000 | none | Warm artifact accepted/denied behavior. |
| read `src/http/registry_routes.rs` 590–690 | 4000 | none; EOF clamp | Final policy recheck, timeout mapping and permit drop. |

Subject binding ran before project evidence: `git rev-parse HEAD`, then separate `sha256sum -- <path>` commands for all five files. Git raw/index evidence records three tracked 100644 modifications and two pre-existing untracked source/test paths; the slice baseline copies, not the broad dirty Git diff, define this task's delta. All five current hashes were rechecked immediately before returning this report and matched the packet.
