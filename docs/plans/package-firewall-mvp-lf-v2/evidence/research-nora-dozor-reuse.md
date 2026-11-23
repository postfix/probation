# Nora and Dozor reuse assessment

Scope amendment C1027 (2026-11-02): RubyGems is critical; CPAN is omitted. CPAN facts below are retained historical research, not planned release work. Current implementation/acceptance has nine families and must not add the Cpan variant.

Date: 2026-11-02. Research: sf-research, `upstream_formats`. Verdict: ANSWERED for source inventory and reuse limits; no runtime interoperability claim.

## Question and subjects

Which exact Nora formats and reusable Nora/Dozor components support the requested expansion across Package Firewall MVP, management/portal, OSV intelligence, decision logging and rated load?

- Nora 1.4.3: [`7a6cd78034ab481cf8b823bb59b81c0411c2140f`](https://github.com/getnora-io/nora/commit/7a6cd78034ab481cf8b823bb59b81c0411c2140f), dated 2026-11-01.
- Dozor 0.1.0: [`93f1f091a70927c51600cc15ce694dbddcc0c31c`](https://github.com/getnora-io/dozor/commit/93f1f091a70927c51600cc15ce694dbddcc0c31c), dated 2026-09-05.

## Exact format inventory

Evidence: pinned [registry enum](https://github.com/getnora-io/nora/blob/7a6cd78034ab481cf8b823bb59b81c0411c2140f/nora-registry/src/registry_type.rs#L55), [handlers](https://github.com/getnora-io/nora/tree/7a6cd78034ab481cf8b823bb59b81c0411c2140f/nora-registry/src/registry), and [compatibility matrix](https://github.com/getnora-io/nora/blob/7a6cd78034ab481cf8b823bb59b81c0411c2140f/COMPAT.md). Paths below are under `nora-registry/src/registry/` at that pin.

| Family | Upstream proxy | Hosted/publish in Nora | Source |
|---|---|---|---|
| Docker / OCI | Yes | Yes | docker.rs, docker_auth.rs |
| Maven | Yes | Yes | maven.rs |
| npm | Yes | Yes | npm.rs |
| Cargo | Yes, sparse | Yes | cargo_registry.rs |
| PyPI | Yes | Yes | pypi.rs |
| Go modules | Yes | No push protocol | go.rs |
| Raw files | No | Yes | raw.rs |
| RubyGems | Yes | No | gems.rs |
| Terraform providers/modules | Yes, limited | No | terraform.rs |
| Ansible Galaxy collections | Yes, v3/Pulp | No | ansible.rs |
| NuGet | Yes, v3/aliases | No | nuget.rs |
| Pub / Dart / Flutter | Yes | No | pub_dart.rs |
| Conan | Yes, Conan 2 | No | conan.rs |
| RPM / yum / dnf | Opt-in per repository | Yes | rpm.rs |
| Debian / APT | Opt-in per repository | Yes | deb.rs |
| CPAN | Yes | No | cpan.rs |
| Hugging Face Hub models | Opt-in; excluded from `all` | No | hf.rs |

Helm OCI belongs to OCI. Chocolatey and PowerShell Gallery are NuGet aliases. These are seventeen format families, not a claim that every associated tool/version/workflow is supported.

## Practical reuse

Port focused protocol behavior and regression fixtures into Probation's existing boundaries. Nora's Axum handlers depend on its application state and storage; they are not standalone protocol libraries.

- Name/version canonicalization in [curation.rs](https://github.com/getnora-io/nora/blob/7a6cd78034ab481cf8b823bb59b81c0411c2140f/nora-registry/src/curation.rs#L886), plus Maven paths, gem/platform parsing and CPAN distributions in handlers.
- Metadata URL rewriting and pagination for npm, NuGet, PyPI, Pub, Galaxy and Terraform; OCI manifests/blobs, Go path escaping and Conan revision paths.
- Handler-local tests, npm/NuGet/PyPI conformance suites and RPM/APT proxy/signing tests.
- Generated [testdata](https://github.com/getnora-io/nora/tree/7a6cd78034ab481cf8b823bb59b81c0411c2140f/nora-registry/testdata) records client versions and covers version normalization, paths and representative requests. Preserve fixture provenance; inspect regeneration commands before using them.
- Dozor's [matcher](https://github.com/getnora-io/dozor/blob/93f1f091a70927c51600cc15ce694dbddcc0c31c/crates/dozor-vers/src/lib.rs), [OSV compiler](https://github.com/getnora-io/dozor/blob/93f1f091a70927c51600cc15ce694dbddcc0c31c/crates/dozor-osv/src/lib.rs), [core](https://github.com/getnora-io/dozor/blob/93f1f091a70927c51600cc15ce694dbddcc0c31c/crates/dozor-core/src/lib.rs) and [CLI tests](https://github.com/getnora-io/dozor/blob/93f1f091a70927c51600cc15ce694dbddcc0c31c/crates/dozor/tests/cli.rs) offer tri-state matching, deterministic output, input digests, exceptions and previous-output preservation patterns.

## Security and policy limits

1. RPM/APT [shared proxy download](https://github.com/getnora-io/nora/blob/7a6cd78034ab481cf8b823bb59b81c0411c2140f/nora-registry/src/registry/mod.rs#L697) intentionally omits name-based curation, applying digest quarantine to immutable package bytes. Transport reuse alone does not deliver Probation's package-coordinate policy.
2. Missing publication dates defer age filtering to digest quarantine. [Quarantine](https://github.com/getnora-io/nora/blob/7a6cd78034ab481cf8b823bb59b81c0411c2140f/nora-registry/src/digest_quarantine.rs#L213) normally uses first-seen time; trusted upstream dates may seed it explicitly. [CPAN](https://github.com/getnora-io/nora/blob/7a6cd78034ab481cf8b823bb59b81c0411c2140f/nora-registry/src/registry/cpan.rs#L206) supplies no date. [Maven dates](https://github.com/getnora-io/nora/blob/7a6cd78034ab481cf8b823bb59b81c0411c2140f/nora-registry/src/registry/maven.rs#L265) use a separate best-effort API.
3. [Integrity tiers](https://github.com/getnora-io/nora/blob/7a6cd78034ab481cf8b823bb59b81c0411c2140f/nora-registry/src/verified.rs#L14) distinguish verified buffered bytes, EOF-verified streams and unverified bytes. A self-computed pin is not an independent upstream authenticity guarantee; partial ranges do not verify a whole file.
4. Terraform proxies recognized HTTP archives but passes git/hg/S3 and nonarchive HTTP module sources to clients directly. Network-mirror mode does not verify upstream SHA256SUMS signatures. See [pinned change](https://github.com/getnora-io/nora/commit/7a6cd78034ab481cf8b823bb59b81c0411c2140f) and [mirror behavior](https://github.com/getnora-io/nora/blob/7a6cd78034ab481cf8b823bb59b81c0411c2140f/nora-registry/src/registry/terraform.rs#L986). This cannot be imported as an all-bytes-through-firewall guarantee.
5. [Hugging Face coverage](https://github.com/getnora-io/nora/blob/7a6cd78034ab481cf8b823bb59b81c0411c2140f/COMPAT.md#L426) is public models, excluding datasets/Spaces/Xet. It requires upstream resolution even for cached files, has no stale mode and refuses minimum-release-age configuration without a readable publication date.
6. Dozor's [matcher](https://github.com/getnora-io/dozor/blob/93f1f091a70927c51600cc15ce694dbddcc0c31c/crates/dozor-vers/src/lib.rs#L80) handles npm; PyPI/other formats return Unknown. Its [OSV projection](https://github.com/getnora-io/dozor/blob/93f1f091a70927c51600cc15ce694dbddcc0c31c/crates/dozor-osv/src/lib.rs#L286) omits withdrawn, range type, event limit and CVSS fields. Explicit version lists over 64 entries and malformed JSON are skipped and counted. Unknown does not produce a blocking rule. Its inventory adapters are npm-specific. This is not general cross-format OSV enforcement.

## License and provenance

Both projects' own code is MIT: [Nora license](https://github.com/getnora-io/nora/blob/7a6cd78034ab481cf8b823bb59b81c0411c2140f/LICENSE), [Dozor license](https://github.com/getnora-io/dozor/blob/93f1f091a70927c51600cc15ce694dbddcc0c31c/LICENSE). Retain each project's copyright and permission notices for substantial copies. Record upstream repository, commit, path, modifications and applicable notices for each adopted file/fixture.

Nora vendors Swagger UI with [Apache-2.0](https://github.com/getnora-io/nora/blob/7a6cd78034ab481cf8b823bb59b81c0411c2140f/nora-registry/src/ui/static/swagger-ui/LICENSE) and [NOTICE](https://github.com/getnora-io/nora/blob/7a6cd78034ab481cf8b823bb59b81c0411c2140f/nora-registry/src/ui/static/swagger-ui/NOTICE). CPAN parsing attributes CPAN::DistnameInfo 0.12. Preserve those separate provenances where relevant.

Dozor's blanket CC-BY-4.0 claim for OSV data conflicts with OSV's [source-specific license catalog](https://google.github.io/osv.dev/data/), checked 2026-11-02. Track advisory source licenses separately; the catalog lists OpenSSF malicious packages as Apache-2.0, RustSec as CC0 and Ubuntu as CC-BY-SA.

## Evidence limits and conflicts

Pinned executable source resolves stale upstream prose: Go does proxy fetches despite COMPAT saying direct storage only; Maven generates/merges metadata despite COMPAT's contrary claim; RPM implementation/signing tests supersede a roadmap header.

Source/document inspection only. No upstream build, runtime/client interoperability run or exhaustive dependency license audit was performed. The report identifies reuse candidates and limits; it does not approve architecture or certify protected support.
