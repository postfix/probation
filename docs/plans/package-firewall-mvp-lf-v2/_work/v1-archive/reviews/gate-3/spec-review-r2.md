# Specification QA (re-review r2)

Verdict: REVISE
Review scope: revised Gate 2/3/4 package in docs/plans/package-firewall-mvp-lf/ against 01-product.md, limited to LangSec findings F1-F16 and slice-16 L2: 02-architecture.md, 03-program-design.md (LS-F1..LS-F16 section, edited paragraphs, changelog), 04-slices.md rows 16/28/30 and the rows 17-24 they depend on. Design-only; nothing executed, no builds, no source or design edited. Not assessed: per-family protocol parsers (rows 17-24) beyond F12/F13, and whole-spec readiness.

## Subject hashes (sha256)
| File | sha256 |
|---|---|
| 01-product.md | 609f0355a9ec3390e28f3c315d10e6e7980e3dfdc13f53815f382bfe368dca1f |
| 02-architecture.md | 7af2d4cbb045d038c1436909388e810dff1ae0196b524bccae5181865bf3ca89 |
| 03-program-design.md (revised) | 37c09d60adaa69dea28776f3ec843cabe8af5590b0676e03e73140861e0f4ee2 (matches 00-status.md) |
| 03.orig.md (pre-edit, scratchpad) | 6cdec52905215acf050e2f560e0b9980f50d7444b189549eba523cd81c4c2959 (equals the langsec.md subject hash) |
| 04-slices.md | 3467c3021a4296294de91fc47bc1117a7e94ec8b8f777616a4580d78ebf55a65 |
| reviews/gate-3/langsec.md | d105d4e206c760dc172634487c6ecba6f5d4708f22175a5e3d7753040103557f |
| reviews/slice-16/code-review.md | 3d80d18317a4c594d4696d2f70380b2c03addf95d158a5a5796b1e276298f167 |
Read-only spot check of source: src/osv/mod.rs line 147 (`fetch_add(1, Release)` after the insert) and src/managed/publication_gate.rs lines 28/33/70 (Acquire loads). Source has uncommitted changes (git status), so these are not a baseline.

## 1. Overall assessment
All 16 findings and L2 now have a concrete contract, bound or table, and a named test list. The packaging is strong: one section (LS-F1..F16), blanket "supersedes conflicting wording" clause, a changelog table, and a DEFAULT-confirm list. The word-level diff against 03.orig shows no deletion of a requirement. The edits replace earlier phrases (see L2 below) and add contracts.

Not ready to approve: 2 High-ish consistency gaps and several Medium gaps. The two that matter most are (a) the C1021 "service key authenticates only policy retrieval" text is still present in 01, 03 and 04 while only 02 was reworded, and 02's own OSV section still carries the pre-F2 wording ("identical response shape", "upstream failure answers no-match"); (b) LS-F13 narrows the RubyGems Marshal language in a way that may refuse real quick-gemspec metadata, a possible functionality loss under the binding user rule. All are fixable by the author without a new stakeholder decision, so REVISE. Pending user confirmations (the 8 DEFAULT items plus Q1-Q3 below) are still required before re-approval.

## 2. Detailed findings

### Review basis and coverage
Authority: 01-product.md (C1006-C1031 as copied), 02 C1021/C1028-C1031, 03 active revision, langsec.md, slice-16 code-review.md (L2), user rule "no functionality dropped or weakened". Evidence class: design text plus a small read of source for L2/F14 only.

| Finding | Contract location | Red-first test entry | Status |
|---|---|---|---|
| F1 | LS-F1; l.105; l.140; 02 C1021 | osv_401_never_creates_or_clears_refusal, snapshot_refusal_not_cleared_by_osv_2xx | Covered, but see R2-1 (01/03/04 C1021 not reworded) |
| F2 | LS-F2; T9-7; l.141/157/158; docstring l.140 | 4 named tests | Covered in 03; conflicting stale text in 02 (R2-1) |
| F3 | LS-F3; l.105; l.199 | 3 named tests | Covered; see R2-5 (row 17 text) |
| F4 | LS-F4; l.125 | credential_bearing_read_never_enters_shared_caches per carrier plus control | Covered |
| F5 | LS-F5 table | 4 named tests | Covered; see R2-8 |
| F6 | LS-F6 table | 3 tests + mapping test | Partial; see R2-6 |
| F7 | LS-F7 table + gate | one boundary test per row listed (6 names) | Covered for numbers; some rows without a named test (R2-9) |
| F8 | LS-F8 | 6 tests | Partial; see R2-4 |
| F9 | LS-F9; l.232 | 6 tests | Covered; scope gap R2-7 |
| F10 | LS-F10; l.232 | 5 tests | Covered |
| F11 | LS-F11 | 6 tests + kept tests | Covered |
| F12 | LS-F12 | 4 tests | Partial; R2-3 (no owner for setting osv_scope; Conan contradiction) |
| F13 | LS-F13 | 5 tests | Partial; R2-2 |
| F14 | LS-F14 | osv_generation_bump_follows_store | Partial; R2-10 (red-first/determinism) |
| F15 | LS-F15 + F7 measurement gate | 3 config tests; timing is a measurement gate, not a test | Covered as designed |
| F16 | LS-F16 | 4 tests | Covered; R2-11 (limit as a loss) |
| L2 | l.121/123/192/193; row 16 | existing tests (osv_generation_change_refuses_before_release in code) | Covered; R2-12 (spec 131 stale; availability note) |

### Category results
- Completeness: gaps R2-1, R2-3, R2-5. Contracts exist for every finding.
- Contracts: signatures and tables are specific. Gaps R2-4 (what moves `revision`), R2-6, R2-7.
- Whole-flow: F1/F2/F3 flows traced end to end (snapshot refusal, OSV unreached/degraded/store/replace, mixed-version snapshot). No remaining path where a header or an OSV 401 reaches refusal state. R2-2 and R2-12 are flow-level.
- Testing: every LS-Fn has named tests, planned "red first, no sleeps". Exceptions R2-9, R2-10.
- Security and performance: improved (allow-list, bounds, denylist at connect time). Provisional numbers are labelled DEFAULT with a latency measurement gate; acceptable. R2-7 for scope.
- Operations: R2-4 (rollback/restore wedge), R2-11.
- Compatibility: R2-3, R2-6 (existing npm/PyPI), cache envelope gains `ActiveRevision` with no migration note (R2-4).
- Documentation clarity: R2-1, R2-12, stale test name in R2-8.

### Contradiction checks requested
- C1021 vs C1030: resolved in 02 only. 01-product.md row C1021 (l.46), 03 l.15 and 04 l.11 still say the key "authenticates only policy retrieval" (and 01 C1015 "policy retrieval only"). Open (R2-1).
- Per-query degraded marker vs header: 03 is consistent now (header informational, never read). Stale in 02 l.30/36 (R2-1) and 03 l.131 intro ("osv.dev-shaped body", "re-evaluated or refused"). No remaining 03 text makes the header decisive.
- F3 skip vs reject: 03 is consistent (structural list vs unknown tag; `activation_rejects_invalid_snapshot_before_publish` row rewritten). Conflict remains in 04 row 17 and 03 l.383/329 ("old binary refuses new-ecosystem rows", "explicit refusal") which can be read as whole-snapshot refusal; clarify that this means a server decode/DB refusal and a per-registry refusal in the enforcer (R2-5).
- osv_scope vs existing behaviour: npm/PyPI default Public preserves managed behaviour; standalone unchanged. No conflict with existing npm/PyPI behaviour. Conflict with Conan row 23 and no setter (R2-3).

### Findings
Priority: H high, M medium, L low. B = blocks re-approval, N = nonblocking.

**R2-1 (M, B) C1021 and the F2 shape still conflict outside 03's new section.** Evidence: 01 l.46 and l.49, 03 l.15, 04 l.11 all say the service key "authenticates only policy retrieval"; the changelog and LS-F1 claim only 02 was reworded. 02 l.30 says the server returns an "identical request and response shape to osv.dev" and l.36 says "Upstream failure answers no-match for the affected queries". That is the F2 defect text in the Gate 2 document. LS-F2 adds `probation_osv` and `probation_degraded`. Consequence: an implementer reading 02/04/01 builds the F1/F2 defects back; the blanket "supersedes" sentence is in 03 only. Fix: apply the same C1021 wording to 01/03/04 (they copy the row), reword 02 l.30/36 to "osv.dev shape plus two additive fields; a failed or invalid query is a degraded result, never a confirmed no-match", and add a one-line pointer in 01. Closure: grep for "authenticates only policy retrieval", "identical request and response shape", "answers no-match" returns nothing stale.

**R2-2 (M-H, B) LS-F13 may drop quick-gemspec functionality.** Evidence: 03 l.333 says quick gemspecs "retain permitted dependency metadata" and l.278 includes "RubyGems indexes and quick gemspecs" in the gzip/zlib bound; LS-F13's allow-list (nil, true, false, Integer, String+encoding, Symbol, Array, Hash, links, Gem::Version) refuses "any other type tag". A real quick gemspec is a Marshal of Gem::Specification (object/user-class/user-marshal tags, Time, Gem::Requirement, Gem::Dependency, possibly Float, Regexp). Under LS-F13 as written these would refuse, which would break native gem/Bundler resolution paths that fetch them; the probe (evidence/probe-marshal-codec.md) covers only the version tuple. Binding rule: no loss without the user's "this removes X". Fix: state whether LS-F13 applies only to the tuple indexes (full/latest/prerelease) and give the quick-gemspec contract (identity-gated pass-through of zlib bytes, or an allow-list with the Gem::Specification, Requirement, Dependency, Time tags and bounds), and add the fixture of a real gemspec to row 17. Closure: row 17 test that a real quick gemspec is served byte-identical to a conformant client and a hostile tag is refused.

**R2-3 (M, B) F12 osv_scope: no owner for setting or storing the field, and Conan contradiction.** Evidence: LS-F12 says the operator "sets `osv_scope = Public`" but the descriptor originates in the policy server's registry records; 04 rows 27/28/30 list no migration, server storage, portal/API field or test for setting it (row 30's closing text names "osv_scope descriptor field, additive" but no file). Row 23 and l.175 say Conan queries OSV "only for ConanCenter-origin packages"; LS-F12 allows an explicit Public mirror and `osv_public_mirror_with_explicit_scope_is_queried` is a "row-level case in each of rows 17-24". Also rows 18-22 and 24 do not mention the F12 case (only 03 and row 30 text do). Consequence: either custom mirrors of new families never get OSV (a protection the plan elsewhere promises, see Q2), or each row invents the field. Fix: assign the server-side storage/API/portal owner (row 27 or 30 with migration number), add the F12 case to rows 17-23, and reword row 23 and l.175 to the same rule. Closure: Gate 4 rows name the owner and test.

**R2-4 (M, B) F8 monotonic revision: unproven premise and wedge risk.** Evidence: LS-F8 digests "version, key_id, org, place_chain, layers, revision, account and rate fields" and rejects equal revision with a different digest. 03 l.103 states registry edits do not move the revision, and nothing shows that account or rate changes do. If they do not, a legitimate account/rate change at the same revision is rejected permanently (structural rejection, last good retained, degraded). A server database restore or rollback to a lower revision is also rejected with no operator path (the documented reset command covers only the authority refusal). The cache envelope also gains `ActiveRevision` with no note on loading an existing envelope that lacks it. Fix: state which server changes bump `revision` (and add a server-side test `revision_moves_with_every_digest_field`), or exclude from the digest every field that does not move it; define the operator command or rule for clearing the floor after a server restore; define envelope compatibility. Closure: those tests plus an `activation_floor_reset_by_operator_command` case.

**R2-5 (L, N) F3 wording in rows 17/T6.** 04 row 17 says "prove an old binary refuses new-ecosystem rows" and 03 l.329/383 say "unknown-tag refusal". With LS-F3 the enforcer neither refuses the snapshot nor the family-unaware rules. Clarify these mean the server/database tag decode and the per-registry refusal. Closure: wording check, plus `activation_mixed_version_snapshot_keeps_known_denies` is cited in row 17.

**R2-6 (M, N) F6 may reject names that npm/PyPI send today.** LS-F6 fixes charsets and "PEP 440 canonical" / "PEP 503 normalised" forms; the existing batcher sends names/versions as handed in. A name outside the new charset becomes degraded (fail-open, counted), which is a possible weakening for existing npm/PyPI. Fix: state whether `osv_key` normalises or rejects non-normalised PyPI names and legacy npm names, and add a golden test that every key the delivered batcher accepts today still passes (`osv_key_accepts_all_keys_current_batcher_sends`). Provisional per-family spellings are properly marked "to be confirmed by canary"; closure for those is the opt-in canary per row.

**R2-7 (M, N) F9 denylist scope.** The connector-level denylist (loopback, link-local, RFC cluster ranges) is stated for descriptors; l.232 is the shared-service paragraph. If implemented in the shared HTTP connector it would also block loopback fake registries used by e2e fixtures and standalone/legacy managed targets on private or loopback addresses (a functionality loss). State the scope (shared-service snapshot-sourced descriptors only; standalone and legacy modes unchanged) and the test seam for fixtures. Closure: `standalone_loopback_target_still_allowed`, `service_fixture_loopback_via_seam_only`. Also name the owning files (the connector is not in row 28's list).

**R2-8 (L, N) F5 details.** (a) LS-F5 row 1 rejects duplicate keys at top level but row 3 degrades only the query for a duplicate inside a query object: a duplicate-detecting serde deserializer errors the whole body, so the design needs a two-stage parse (raw values per query); say so. (b) Two rate rules: "429 at admission" and "key over per-credential budget degrades the query"; state which applies when. (c) Test name `osv_route_rejects_unknown_fields_...` still says "rejects"; l.178 still lists it beside the re-specification; rename to avoid a reviewer expecting 4xx. Closure: wording and test names.

**R2-9 (L, N) F7 rows without a named boundary test.** No test for: per-result vuln-ref truncation (still Matched), snapshot over each bound (one test listed, fine), persisted record 512 B, `Retry-After` jitter, counters `osv_results_degraded/total`, the 4 MiB upstream read cap beyond `osv_upstream_response_is_size_capped`. 8192 B x 1000 queries exceeds the 4 MiB upstream cap, so state which bound wins. Also `family cap` in the gzip row is not defined.

**R2-10 (M, N) F14 test cannot be red first as described.** The delivered code already stores then bumps (src/osv/mod.rs l.147), so `osv_generation_bump_follows_store` passes at baseline; and "a reader holding the generation sees the matched entry" is a race unless there is a deterministic seam. Fix: require a hook between store and bump (or a mutation that swaps the order, observed red), and note that the Acquire on the gate read is already present in publication_gate.rs l.70 (the "gate read should be Acquire" caveat in LS-F14 is satisfied there). Closure: mutation probe recorded, run under the capped systemd-run scope.

**R2-11 (L, N) F16 caps as a limit.** 4 GiB per request refuses credential-bearing reads of larger blobs with 503 (private OCI layers or large artifacts). The caller currently streams them, so this is a new ceiling. Marked DEFAULT-confirm, but the changelog should state "this limits X" and offer the alternative of raising per-request cap or streaming without a file where verification allows (user choice, Q3).

**R2-12 (L, N) L2 spec update.** 03 l.121/123/192 are updated to "refuse on first change". Still stale: 03 l.131 ("is re-evaluated or refused") and 02 C1029 ("re-evaluated or refused", acceptable as an either/or). The generation is global per key set, so any newly matched key (unrelated to the response) refuses in-flight responses with 503 where the earlier design re-evaluated and delivered; the user accepted this on 2026-11-18 per the review file, but the plan text cites only "user accepted" without a recorded user answer ID. Fix: fix l.131, and record the decision as a numbered decision with the availability consequence ("an unrelated new match can 503 an in-flight response; retry succeeds").

### Questions
- Q1 (blocking for approval of F12, owner: user): should a custom mirror of a new family default to OSV checked (Public) instead of unchecked? The author's default skips it; the product promises OSV for the new families and the binding rule says never weaken. See R2-3.
- Q2 (owner: user): confirm R2-11 caps (4 GiB / 16 GiB), or choose different numbers.
- Q3 (owner: user, in the existing DEFAULT list): F3 skip-vs-reject, F4 allow-list contents, F7 numbers, F8 equal-revision rule, F6 spellings, F14 residual window, F12 defaults, F16 caps. All remain unconfirmed in 00-status.md l.32.

## 3. Actionable recommendations
- R2-1: align C1021 rows in 01/03/04, reword 02 l.30/36, add one-line pointer in 01. Closure: stale-phrase grep.
- R2-2: define the quick-gemspec contract (or scope LS-F13 to tuple indexes) and add a real-gemspec fixture to row 17.
- R2-3: add owner/migration/portal for `osv_scope`, add the F12 case to rows 17-23, reconcile row 23 / l.175.
- R2-4: define what moves `revision`, add `revision_moves_with_every_digest_field`, operator floor reset, envelope compatibility.
- R2-5, R2-8, R2-9, R2-12: wording fixes as listed.
- R2-6: golden test of current batcher keys and explicit normalise-or-reject rule.
- R2-7: scope statement and two regression tests.
- R2-10: deterministic hook or mutation probe.
- R2-11: state limit explicitly, user choice.

## 4. Next steps
Author fixes R2-1 to R2-4 (blocking) and the nonblocking wording items, then asks the user for Q1-Q3, then a focused re-check of: grep-level stale-text sweep across 01-04, rows 17-24 text, LS-F8/F12/F13 sections. Not assessed: the per-family parsers and any implementation. Planned versus executed: all tests named are planned only; the only executed checks in this review were file reads, hashing, a word-level diff of 03.orig vs 03, and the greps cited.
