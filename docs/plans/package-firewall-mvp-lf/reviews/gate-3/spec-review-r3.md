# Specification QA (focused recheck r3)

Verdict: READY WITH CONDITIONS (no blocking finding; user confirmations and Gate re-approval still required)
Scope: READ-ONLY recheck of the round-2 revisions only: spec-review-r2.md R2-1..R2-12 against revised 01/02/03/04 and the "Round 2" changelog (03 l.1628-1648). Design only; nothing built or executed. Checks run: file reads, sha256, a diff of 01-product.md against the SF copy, stale-phrase greps. Not assessed: per-family parsers (rows 17-24) beyond LS-F12/F13 and whole-spec readiness. All named tests are planned, not run.

## Subject hashes (sha256)
| File | sha256 |
|---|---|
| 01-product.md (revised) | fc9b5432a1ad32b2b41173176ae4304e6703f92107c98c2d05adad61dcecaccf |
| ../package-firewall-mvp/01-product.md (SF copy, Gate 1 approved) | 609f0355a9ec3390e28f3c315d10e6e7980e3dfdc13f53815f382bfe368dca1f |
| 02-architecture.md | 8648f957e579726bee9090c7eaad62b7537485659118a2ea1e05935308e2840f |
| 03-program-design.md | 7859d7fc8b1653926320712645c0486849642721294bdf5c0cf49e0237e93ee6 |
| 04-slices.md | 352b964fa2082be5e67b44988c70d704915eb2b85566092a1aa700446d4d2ebc |
| 00-status.md | db0f8d41a2e3b35a5be5e86daabb83757b700a900a009a19ecff518c891744ab |

## R2 finding status
| ID | Status | Evidence |
|---|---|---|
| R2-1 stale C1021/F2 text | RESOLVED | Greps over 01-04 for "authenticates only policy retrieval", "identical request and response shape", "answers no-match", "re-evaluated or refused", "policy retrieval only", "refuses new-ecosystem", "unknown-tag refusal", "Only for ConanCenter": zero hits. C1021 (01 l.46, 02 l.11, 03 l.15, 04 l.11) and C1015 (01 l.49) now name the OSV route and the "401/403 on OSV is never an authority refusal" rule. 02 l.30/36 now say "two additive fields" and "per-result degraded marker". The remaining "osv.dev-shaped/-compatible" phrases (03 l.131) are correct. |
| R2-2 quick gemspec | RESOLVED | LS-F13 (A) tuple indexes (typed re-render, memory budget) and (B) quick gemspec (validate-and-pass-through, class allow-list Gem::Specification/Version/Requirement/Dependency, Time, Float, bounds, widen-never-narrow rule, real-gemspec fixture, byte-identical test). Row 17 cites it. Minor: (A) has no widen clause; real full-index measurement in row 17 covers it (N). |
| R2-3 osv_scope owner and Conan | RESOLVED | LS-F12 names owners: row 28 (api.rs field, migration 0015, create/update API and portal field), row 30 (enforcer decision), row 27 (view, `osv_coverage_view_shows_scope`). Rows 17-21 and 23 carry the F12 cases; row 23 and 03 l.175 now use the effective-scope rule. Row 24 correctly None. Minor: row 23 lists `conan_osv_query_only_for_conancenter_origin` and the public-mirror test but not a Conan-named private-skip case; the default-scope test covers it (N). |
| R2-4 revision | RESOLVED | LS-F8: digest fields explicit, rate fields and registries excluded, row 28 server bump in the same transaction with `revision_moves_with_every_digest_field` (a field that fails leaves the digest), `reset-revision-floor` operator command, envelope without the field loads, named tests. Row 28 file list includes the reset command and bump. |
| R2-5 F3 wording | RESOLVED | Row 17 and T6 now say server-side decode refusal plus per-registry refusal in the enforcer; `activation_mixed_version_snapshot_keeps_known_denies` cited. |
| R2-6 batcher keys | RESOLVED | LS-F6 validates, never normalises; npm/PyPI charset is the union of what the delivered batcher emits; golden `osv_key_accepts_all_keys_current_batcher_sends`; failures degrade and are counted. |
| R2-7 denylist scope | RESOLVED | LS-F9 scopes to snapshot-sourced registries in shared-service mode; standalone/legacy loopback unchanged; test seam absent from release; both regression tests named; src/http/service_connector.rs in row 28. |
| R2-8 F5/F2 details | RESOLVED | Two-stage parse, one budget rule (429 only at empty bucket on admission, else per-key degrade), test renamed to `osv_route_degrades_unknown_field_...`. No stale "rejects_unknown_fields" outside the rename note. |
| R2-9 test names, bounds | RESOLVED | LS-F7: "which bound wins" paragraph, family caps defined (128 MiB / 4 MiB / 16 MiB), per-row boundary tests, truncation and counter tests named. |
| R2-10 F14 red-first | RESOLVED | `OsvCache::set_put_hook` seam plus a mutation probe under the capped scope; notes the Acquire read already exists. |
| R2-11 F16 limit | RESOLVED (user choice pending) | LS-F16 states the 4 GiB limit as new, with alternatives; changelog item (13) and "this removes X: none; only new ceiling" disclosure. Still needs the user's yes. |
| R2-12 L2 decision | RESOLVED | D-OSV4 in the LS intro with the availability consequence (unrelated new match can 503 an in-flight response; retry succeeds); 03 l.131 and 02 C1029 aligned; row 16 says refuse on first change, no re-evaluation. |

## 01-product.md edits and Gate 1
`diff` of the SF byte-identical copy (hash 609f0355...) against the LF 01-product.md changes exactly two table rows, C1021 and C1015, both only in the sentence about what the service key authenticates. No requirement, ID, status or other row changed. They are wording only in the sense that they record the already approved C1030 amendment (2026-11-17), but C1021 also adds one normative clause ("a 401/403 on the OSV route is never a policy authority refusal") from LS-F1. Because the file hash changed (609f0355 -> fc9b5432), the approval hash no longer matches. Recommendation: Gate 1 needs a hash re-acknowledgement (a one-line user yes naming the two rows and the new hash), not a Gate 1 re-review or re-grilling. 00-status.md l.5 already says this ("confirm with the re-approval"); migration.md l.12/l.59 still cite the old hash as the carried approval (expected, provenance).

## No functionality dropped (user binding rule)
- RubyGems: both tuple indexes and quick gemspecs kept; the validator widens, never narrows.
- npm/PyPI OSV: default scope Public preserves today's managed behaviour; batcher keys never become unchecked (golden test).
- Standalone and legacy managed loopback targets unchanged (LS-F9). Standalone OSV unchanged (LS-F12).
- Only new ceiling: F16 4 GiB per-request limit, disclosed and marked as a user choice. One residual weakening-by-default needing the user's explicit yes: a custom mirror of a NEW family gets no OSV check until set Public (DEFAULT item 11). It is not a loss against delivered behaviour, but conflicts in spirit with full parity; the alternative (Public by default) is stated. Treat as a user decision, not an author default.
- Quick-gemspec contract keeps full feature: identity gate, original bytes passed through, no field lost, class allow-list widened by corpus.

## Rows 17-30 consistency
Rows 17-21, 23, 24 consistently carry mapping witness, C1028 credential case, LS-F4 path credentials and F12 cases (24 notes mapping None). Dependencies (17 after 28/30; 18-24 after 17; 25/26/27) unchanged. Row 28 lists every new owner (migration 0015, connector, reset command, revision bump); row 30 lists osv_scope enforcer, rollout order and alert; row 27 shows scope. Row 22 is absent from the table and the status list (CPAN omitted by C1027), which is consistent. Row 16 consistent with L2. No cross-row contradiction found.

## Remaining items (all nonblocking)
1. User confirmations: DEFAULT items (1)-(13) in the 03 changelog, especially (11) custom-mirror OSV default and (13) 4 GiB cap.
2. Gate 1 hash re-acknowledgement; Gates 2-4 re-approval at the new hashes above.
3. Add a Conan-named private-skip test to row 23 for symmetry (optional).
4. Add a widen-on-corpus clause to LS-F13 (A) (optional).
5. 00-status.md l.5 hash for 01 matches fc9b5432; confirm the 02/03/04 hashes quoted there equal the table above before approval.

## Next step
Present the DEFAULT-confirm list to the user, obtain the decisions, record the new hashes, then dispatch slice 28.
