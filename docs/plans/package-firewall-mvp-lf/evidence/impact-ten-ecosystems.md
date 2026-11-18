# Ten-family identity impact — 2026-11-02

Scope amendment C1027 (2026-11-02): RubyGems is critical; CPAN is omitted. CPAN facts below are retained historical research, not planned release work. Current implementation/acceptance has nine families and must not add the Cpan variant.

sf-impact ecosystem_expansion_impact: PARTIAL, Manual source evidence. Commit8d9f5e35b6d92898f6c9c33b852df5a9b04e8d59; tracked production unchanged. Enum callable graph is UNKNOWN; doctor confirmed healthy daemon and supported SMTC file/read/grep fallback. No edits/builds/tests; no graph-derived completeness/count claim.

## Deciding facts

1. policy lib.rs:54–75 derives serde without renaming: preserve Npm/PyPi wire strings separately from npm/pypi as_tag/from_tag. Policy identity encoding also serializes these values at:326. Add Maven/Go/Cargo/NuGet/Cpan/RubyGems/Conan/Oci with explicit tags maven/go/cargo/nuget/cpan/rubygems/conan/oci; preserve old indexes0/1.
2. Embedded schema7 projects/artifact_references use TEXT without ecosystem CHECK; project key is registry_id/ecosystem/name. Rows decode from_tag and reject unknown values. The enum addition needs no embedded migration or schema bump. Never invoke old4/5 destructive upgrade. Older readers may refuse new rows; downgrade is not implicitly supported.
3. reference.rs:43–82 hashes stable tag/name/version/filename/URL/sorted digests. Registry0 retains legacy hash; nonzero adds probation-registry-reference-v1 +registry ID. cache.rs:61–66 hashes registry/tag/name; store/mod.rs:157–160 uses tag/name for age spread. Preserve old coordinate spelling, tags, URL/digest order and reference encoding.
4. Postgres CHECKs in0001_init.sql constrain policy_blocks:146, policy_exceptions:163, activity:257;0007_registries.sql:44 constrains registries. Append0014_ten_ecosystems.sql to widen four constraints in place; preserve rows/IDs/nullability/other constraints. Do not rewrite historical migrations or recreate tables.
5. Server policy.rs:385–386 currently falls back from unrecognized tag to Npm. Replace with explicit failure before new tags can be written; rollout must not leave an old reader silently misclassifying new data.

## Direct impact set

Shared policy: lib.rs tag/serde/identity; names.rs canonical_name/valid_name/canonical_version and214byte global limit; blocklist_json.rs error text. Root policy/mod.rs ecosystem_index, blocklist.rs ECOSYSTEMS/import normalization. HTTP logging.rs atomic codes/path parsing. OSV batcher.rs exhaustive separate external spelling, osv/mod.rs keyed identity. Artifact download.rs own_origin/health classification and artifacts/mod.rs membership dispatch. Server portal policy.rs labels/input, templates/policy.html options, registries.rs options/admission, activity.rs display. delivery/mod.rs static ecosystem tag does not itself increase allocated record heap; preserve32KiB BYTES_PER_RECORD as heap accounting, not serialized-size cap.

Use per-family normalization and exact version semantics; do not apply npm/PyPI parsers to unrelated families. Identifier availability, adapter support and OSV coverage are distinct. Wildcards must not map an unsupported family into npm/PyPI. Preserve package-manager credentials and existing publishing flow; no new registry credential architecture.

## Required checks

Pin old/new serde/tag round trips and old effective-policy bytes; npm/PyPI reference-ID goldens for registry0 and nonzero; reopen old rows with IDs/pins/generations/content unchanged; new-family separation; migration acceptance in all four Postgres tables with invalid-tag rejection. Extend normalization/blocklist/OSV/log/budget tests and preserve existing selected/legacy publishing scenarios. Unsupported OSV identities remain explicit, never clean. No destructive migration is justified.

## Receipt and limits

Root /home/john/go/src/github.com/postfix/probation; session sf-ecosystem-expansion-impact-2026-11-02. Graph: unique enum55–58 but callers/blast-radius matched0;2,053 unresolved dispatches; no safe negative inference. Doctor capability confirmed that caller/callee graph is not enum reference coverage. Subsequent SMTC file read/grep legs outer/innerOK,2048token bound, functions n/a, no native source fallback. Complete deciding windows cover shared lib/names/blocklist, root schema/rows/cache/reference/store/policy/OSV/logging/delivery, Postgres migrations and portal. Broad capped locators were narrowed; .git/lost-found locator discarded. No source safety proof or runtime acceptance. Omitted deciding findings: zero.
