# LangSec recheck (affected findings only)
Verdict: FIX FIRST (design scope; informational). No blocker remains from the original four material gaps; two PARTIAL findings (F12, F13) and two new Medium-Low gaps (N1, N2) should be closed in the row 28/30/17 packets. Nothing demonstrated; specification gaps only.
Review coverage: partial. Full for LS-F1..LS-F16 text and the lines they supersede (l.105, 123, 125, 140-141, 155, 157-158, 199, 203, 209-299, 323-325, changelog 1598-1627). Per-family parsers in rows 17-24 remain unreviewed. Nothing executed, no builds.
Subject: design only. `docs/plans/package-firewall-mvp-lf/03-program-design.md` sha256 `37c09d60adaa69dea28776f3ec843cabe8af5590b0676e03e73140861e0f4ee2` (revised, 1627 lines), against prior report `reviews/gate-3/langsec.md` (design sha256 6cdec529...c2959). Also read 02-architecture.md `7af2d4cbb045d038c1436909388e810dff1ae0196b524bccae5181865bf3ca89` (C1021 line only; reworded as LS-F1 claims). 04-slices.md `3467c3021a4296294de91fc47bc1117a7e94ec8b8f777616a4580d78ebf55a65` hashed, not re-reviewed. No snapshot copy was made (read-only recheck, no durable evidence beyond the hashes above); conclusions apply to those bytes.

## Per-finding status
| F | Status | Reason |
|---|---|---|
| F1 | RESOLVED | LS-F1 + l.105: refusal only from GET snapshot; OSV 401/403 and any OSV 2xx never create/clear it; `record_refusal(PolicyRoute::Snapshot only)` makes it structural; C1021 reworded in 02 (verified). |
| F2 | RESOLVED | Per-result `probation_degraded` plus required `probation_osv{v,upstream_ok}` envelope; missing meta = unreached; header never read; only NoMatch from `upstream_ok` answer may store/replace (l.158 consistent). Minor completeness gaps in N3. |
| F3 | RESOLVED | Unknown tag degrades that registry only; unknown-ecosystem rule skipped and counted; structural list is explicit (l.105, l.199 consistent). Remains DEFAULT-confirm. |
| F4 | RESOLVED | Inverted to allow-list (headers, query keys, userinfo, pseudo-headers); unknown header costs only a cache hit; per-carrier test list. Residual Low in N5. |
| F5 | RESOLVED | One envelope-vs-per-query table; duplicate-key-detecting deserializer; duplicate queries rule. Edge cases in N3. |
| F6 | RESOLVED | One `osv_key` shared by client and server, bounds and per-family name charset, Go decoded path, positive-case tests. Version spelling is explicitly provisional pending per-family canary (open closure obligation, not a spec gap). |
| F7 | RESOLVED | Concrete numbers for every listed bound incl. snapshot, Retry-After cap, answer cap formula, cache, matches record, gzip size and ratio; at/over-limit tests. Arithmetic checked: 32 refs x (128+40 B) fits 8192 B; 1000 queries fit 1 MiB. Related new gaps N2, N8. |
| F8 | RESOLVED | Monotonic revision with digest on equality, floor persisted, reset on new binding; registry exclusion from digest is reasoned. Operational follow-on is N1. |
| F9 | RESOLVED | Single `url` parser, canonical IP forms, IPv4-mapped unwrap, resolved-address check at connect time, resolve-once, redirect hops, extended metadata list. Residual Low in N7. |
| F10 | RESOLVED | `host_matches` normalisation, duplicate Host 400, :authority and absolute-form rules, prefix wording fixed in l.325 ("at least 8 / at least 32"). IDN/IPv6-literal Host spelling not stated (Low, fold into the same function's tests). |
| F11 | RESOLVED | Line-framed JSON records, per-line CRC32, per-line `osv_key` revalidation, skip-and-count, torn last line, expiry clamp, later-wins, 16 MiB read cap. Residual Low in N6. |
| F12 | PARTIAL | `osv_scope` closes it for all new families and Conan. For npm and PyPI the default stays `Public` for any custom `target_url` (deliberate, no protection removed), so private npm/PyPI names still go to the shared server/api.osv.dev and can false-deny until the operator sets `Private`. Disclosed in the changelog only as a "new families" default; state the npm/PyPI residual explicitly and surface it in the coverage view. |
| F13 | PARTIAL | Type allow-list, depth 32, link validity, re-render and gzip ratio now stated. Missing: (a) the 20,000,000-object cap is not a memory bound (one allocation per node can reach several GB inside a 128 MiB inflated cap); bound by inflated bytes and a node-memory budget instead; (b) expressiveness: the allow-list (no `o` object, no Time, no Gem::Requirement/Dependency/Specification user types) cannot accept real quick gemspecs, so either those are passed through unfiltered (say so, with the gzip/size guard only) or valid inputs are refused. Rows 17 to decide. |
| F14 | RESOLVED | store then `fetch_add(Release)` under the cache mutex; gate `load(Acquire)`; residual window accepted and listed in DEFAULT-confirm. |
| F15 | RESOLVED | Origin-only https `server_url`, key file printable ASCII, single trailing newline, 512 B cap; timing turned into a measurement gate with counters `osv_results_degraded/total`. The latency question is a gated measurement, not yet evidence. |
| F16 | RESOLVED | Per-request and total caps (503 before more bytes), 0700 dir, unlink at creation, startup sweep, gauge. Low notes in N9. |

## New issues introduced by the revisions
No new High. Evidence class: specification gap from design text.

**N1 (Medium-Low) Revision floor has no reset path (LS-F8).** An equal-or-lower revision for the same binding is a permanent structural rejection and the floor is persisted across restarts. A policy-server restore from backup, database rollback or failover to an older replica makes the whole fleet keep the last good (higher-revision) snapshot indefinitely, so no new deny propagates, with only a degraded-readiness alert. A buggy or compromised server sending a huge revision does the same. Only key rotation resets the floor, and the "operator reset command" in l.105 clears refusal, not the floor. Fix: name an operator command (or an authenticated, explicitly logged server "epoch" field in the snapshot) that clears the floor, say which of the two, and test `activation_floor_reset_by_operator_command`.

**N2 (Medium-Low) Resource bound for the Marshal filter is object count, not memory (LS-F13).** See F13(a). Also gzip bound rows say "family cap" without listing the per-family caps (N8).

**N3 (Low-Medium) OSV answer/envelope parser edge cases left open (LS-F2, LS-F5).** Unstated: (a) a result with both non-empty `vulns` and `probation_degraded:true` (treat as Degraded, store nothing); (b) `queries` empty (allowed? `upstream_ok` value when no upstream call was needed or every query is per-query degraded; must be true or the client treats the batch as unreached and counts the server down); (c) a `queries` element that is not an object (envelope 400 or per-query degrade); (d) client-side duplicate-key and unknown-field policy for the server answer (the duplicate-key deserializer is specified for the request only); `AnswerError` has no variant for duplicate keys or `v` mismatch beyond `UnsupportedVersion`; (e) the LS-F5 table has two budget mechanisms (bucket empty at admission = 429, per-credential key budget = per-query degrade) without saying which applies when; (f) rollout order: a managed client requiring `probation_osv` against a not-yet-upgraded central server is `MissingEnvelopeMeta`, so OSV is unreached fleet-wide until the server is upgraded; state the upgrade order (server first) and that the client degrades, not fails. Each is one sentence plus a test.

**N4 (Low-Medium) Per-credential rate limit can turn cold start into fleet-wide fail-open (LS-F7).** 600 cache-missing keys/min (burst 1000) per credential, one service key per organisation; a CI fleet cold-starting a large dependency set exceeds it, the excess keys return per-query degraded and the client allows without OSV for them. Counters make it visible but no alert threshold or documented operator response is given. Fix: record the expected steady and cold-start key rates in the row 30 measurement gate and set an alert on `osv_results_degraded / osv_results_total`; consider a separate burst budget for cache-missing keys already seen by another endpoint (server cache hits are free by design, so the limit only binds genuinely new keys).

**N5 (Low) Allow-list values and path secrets (LS-F4).** Allow-listed header values are not inspected (for example `Referer`, `npm-session`); if an adapter forwards them upstream or a family accepts secrets in a path segment (token-in-path registries, URL userinfo is covered), cache eligibility is still decided only by names. State that allow-listed headers are never forwarded with credential meaning, and that each family row lists path-embedded credential forms (the test list covers only header/query/userinfo carriers). Also note OCI clients send Authorization on almost every request, so OCI becomes request-scoped (no shared cache): an availability and performance cost to record, not a defect.

**N6 (Low) Matches file (LS-F11).** CRC32 detects corruption only; say it is not an integrity or authenticity control (file is 0600 and trusted). `x` must be defined as an unsigned 64-bit integer (reject negative, float, exponent). A forward wall-clock jump prunes all matches at load (inherent; accepted, record it). If `osv_key` charsets are tightened in a later release, old records are skipped and counted: note it in the upgrade tests.

**N7 (Low) Denylist coverage (LS-F9).** Add IPv4-compatible `::a.b.c.d`, NAT64 `64:ff9b::/96` and 6to4 `2002::/16` embeddings (unwrap and recheck, as for IPv4-mapped), and say that when several addresses resolve all must pass and that environment proxy variables are disabled for registry connectors (a proxy hop would bypass the connect-time check).

**N8 (Low) gzip ratio rule (LS-F7).** Define ratio as inflated bytes / compressed bytes consumed so far, applied over concatenated gzip members and ignoring trailing bytes after the last member (refuse trailing data), and list the per-family caps that `min(family cap, 128 MiB)` refers to. Legit RubyGems indexes compress about 5-10:1, so 100:1 after 1 MiB is safe for valid inputs (not measured).

**N9 (Low) Credential temp dir (LS-F16).** Startup sweep "empties the directory": two overlapping processes on one `data_dir` (rolling restart, Windows where unlink-at-creation is unavailable) delete live files; use a per-process subdirectory or a lock file, refuse a symlinked or non-owned directory, and validate caps against free space or map ENOSPC to the same 503. A permitted peer can still exhaust the 16 GiB total and 503 all credential-bearing reads (peer admission is the only gate, accepted by design; say so).

## Coverage and evidence
Recheck of K1-K12 against the revised text; K13 unreviewed; K14 inapplicable (no formal artifact; LS-F14/F8 are stated as order and arithmetic rules, not proofs).

| Check | Flow | Coverage | Conclusion |
|---|---|---|---|
| K1 OSV request language | P4 | full | supported (F5, F6, N3) |
| K2 OSV response/degraded | P4,P5 | full | supported (F2); N3 edges |
| K3 resource bounds | P4,P5 | full | supported with N2, N4, N8 |
| K4 refusal meaning | P1,P4,P5 | full | supported (F1) |
| K5 snapshot recognition/availability | P1 | full | supported (F3, F8); N1 |
| K6 descriptor/target use | P6 | full | supported (F9); N7 |
| K7 listener admission | P2 | full | supported (F10) |
| K8 credential-read detection | P3 | full | supported (F4); N5 |
| K9 matches file | P5 | full | supported (F11); N6 |
| K10 OSV key meaning across registries | P4,P5 | full | unresolved for npm/PyPI private registries (F12 PARTIAL) |
| K11 `osv_generation` ordering | P5 | full | supported (F14) |
| K12 config language | D7 | full | supported (F15) |
| K13 per-family parsers | D9 | unreviewed | unresolved (F13 PARTIAL, N2) |

Checks run: reading, grep, sha256sum only; no project code executed, so no isolation needed. Not run: any test named in LS-F1..F16 (all planned).

## Closure
Outstanding: F12 (npm/PyPI private-registry residual), F13 (memory bound, quick-gemspec expressiveness), N1 (floor reset path), N3 one-line clarifications, plus the eight DEFAULT-confirm items needing the user's yes (F3, F4 list, F7 numbers, F8 digest rule, F12 scope default, F16 caps, F6 spellings, F14 residual). None reopens Gate 3. Next useful action: fold F12/F13/N1/N3 into the row 30, 17 and 28 packets, then no further design recheck is needed before implementation review.
