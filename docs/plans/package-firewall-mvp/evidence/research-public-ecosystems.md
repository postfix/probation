# Public sources and firewall value by ecosystem

Date: 2026-11-02. Verdict: ANSWERED for public-source existence and artifact classification. Research: sf-research `upstream_formats` (15 families), main agent (APT and Terraform). No implementation/interoperability claim.

## Decision supported

The user asks whether APT, Terraform and other Nora formats have public sources, and whether a firewall is useful without them. Assess actual third-party artifact consumption before choosing scope; a registry product's supported-format count is not itself a firewall requirement.

The user has separately selected local enforcement and direct upstream downloads (Q3 / C1009), with optional API-key policy-server authentication and server-independent TOML operation. This report does not reopen those choices.

## Verified inventory

All public-source links are primary official project/vendor documentation, checked on the research date. Nora's role follows the previously inspected version 1.4.3, commit `7a6cd78034ab481cf8b823bb59b81c0411c2140f`, in [research-nora-dozor-reuse.md](research-nora-dozor-reuse.md). A public catalog may direct downloads to another host; the catalog alone does not establish interception of the bytes.

| Family | Official public source / classification | What is consumed | Firewall assessment |
|---|---|---|---|
| npm | [npm public registry](https://docs.npmjs.com/about-public-packages/) | JavaScript/package archives | Clear developer-dependency policy use case; existing support remains baseline. |
| PyPI | [PyPI](https://docs.pypi.org/using-pypi/finding-and-installing/) | Python distributions | Clear developer-dependency use case; existing support remains baseline. |
| Cargo | [crates.io](https://doc.rust-lang.org/cargo/reference/publishing.html) | Rust source crates compiled as libraries/tools | Public dependency candidate. |
| Go modules | [Go public module mirror, index and checksum database](https://proxy.golang.org/) | Module snapshots from public source repositories | Public dependency candidate; a mirror over decentralized sources, not a central publishing registry. |
| Maven | [Maven Central](https://maven.apache.org/repository/index.html) | Library/build artifacts and metadata | Public dependency candidate. |
| NuGet | [nuget.org](https://learn.microsoft.com/en-us/nuget/what-is-nuget) | .NET package archives | Public dependency candidate. |
| RubyGems | [RubyGems.org](https://guides.rubygems.org/rubygems-basics/) | Gems, including libraries/tools and sometimes native extensions | Public dependency candidate. |
| Pub / Dart / Flutter | [pub.dev](https://dart.dev/tools/pub/packages) | Dart packages and resources | Public dependency candidate. |
| Conan | [ConanCenter](https://conan.io/faq) | Moderated C/C++ recipes and prebuilt packages | Genuine public repository; source recipes and resulting packages need distinct checks. |
| CPAN | [CPAN archive/network](https://www.cpan.org/) | Perl distribution archives | Genuine public developer-dependency source. |
| Ansible Galaxy | [Public Galaxy collections](https://docs.ansible.com/projects/ansible/latest/collections_guide/collections_installing.html) | Automation collection archives | Public executable automation-content use case. Git roles and other sources are separate paths. |
| Terraform | [Public Terraform Registry](https://developer.hashicorp.com/terraform/registry), [providers](https://developer.hashicorp.com/terraform/registry/providers), [module sources](https://docs.hashicorp.com/terraform/language/modules/sources) | Provider plugins and infrastructure modules | Strong public supply-chain use case. Registry discovery, provider archives and module/VCS sources require distinct enforcement paths. |
| Docker / OCI | [Docker Hub public images](https://docs.docker.com/reference/cli/docker/image/pull/) | Container image manifests/configuration/layers | Genuine public-artifact use case; image identity and layer enforcement differ from language-package versions. |
| Debian / APT | [Debian public archives](https://deb.debian.org/), [official mirrors](https://www.debian.org/mirror/list) | OS packages, repository indexes and security updates | Public repositories exist. Deferral may be justified by OS-update scope and signed-metadata semantics, not lack of public sources. |
| RPM / yum / dnf | [Fedora official repository definitions](https://packages.fedoraproject.org/pkgs/fedora-repos/fedora-repos/) | Distribution-curated system software and repository metadata | Public repositories exist; OS-package support is a separate product track if deferred. |
| Hugging Face | [Public Hub models](https://huggingface.co/docs/hub/models-downloading) | Model files consumed by applications/libraries | Public sources exist. Model policy and transfer semantics merit a separate explicit capability. |
| Raw files | Nora's pinned [format matrix](https://github.com/getnora-io/nora/blob/7a6cd78034ab481cf8b823bb59b81c0411c2140f/COMPAT.md#L19) defines hosted generic file storage, with no upstream | Arbitrary uploaded files | No ecosystem-specific public source is defined by this Nora capability. Public arbitrary files can exist; generic storage is not automatically a public-dependency firewall requirement. |

Sixteen of Nora's seventeen families have concrete public distribution sources. This does not mean sixteen equivalent adapters or sixteen complete security integrations already exist. Raw is a generic-storage capability rather than a seventeenth public dependency ecosystem.

## APT and Terraform: deciding facts

APT is a package manager for public distribution repositories, even though those repositories are not called a central community registry. Debian publishes package and security archives through public mirrors. [apt-secure](https://manpages.debian.org/trixie/apt/apt-secure.8.en.html) authenticates repository metadata using signed Release information and its checksum chain. Filtering metadata cannot silently discard that authenticity chain. Blocking package downloads while leaving upstream signed metadata unchanged is also different from the graceful version filtering promised for npm/PyPI. A general age delay for system packages needs an explicit security-update policy; this report selects none.

Terraform has public providers and modules. Providers are [executable plugins run as separate processes](https://developer.hashicorp.com/terraform/plugin/how-terraform-works); they are a concrete third-party software supply-chain surface. The public registry can be a catalog rather than the final download host. Official [module-source documentation](https://docs.hashicorp.com/terraform/language/modules/sources) includes registry, VCS, HTTP and object-storage sources. The [provider mirror protocol](https://developer.hashicorp.com/terraform/internals/provider-network-mirror-protocol) offers another installation path, not universal module coverage. Prior pinned Nora research found some module sources bypass its proxy. Protected Terraform support must name and test the actual provider/module paths covered; a registry API proxy alone is insufficient.

## Proposed expansion scope — not selected

For a developer-dependency firewall, recommend thirteen families: npm, PyPI, Cargo, Go, Maven, NuGet, RubyGems, Pub, Conan, CPAN, Ansible Galaxy, Terraform and Docker/OCI. Preserve existing npm/PyPI private-registry and publishing requirements while selecting the scope of added adapters explicitly.

- Defer APT and RPM as OS-package management, despite their public repositories. Their signed-metadata, security-update and policy semantics need separate design.
- Treat Hugging Face as a separate optional model-protection feature; public availability is established, but matching language-package policy is not.
- Omit generic Raw hosting from this public-dependency expansion. An explicit arbitrary-download use case could justify separate work later.

These priorities are product/engineering inferences, not claims that the deferred formats have no public sources or no possible security benefit. Final inclusion/exclusion remains a user-owned scope choice. Public availability is not required for all firewall value: private upstreams can also benefit from source isolation, version/digest restrictions and audit controls.

## Evidence limits

Source existence and artifact purpose only. No client installs, interception/egress tests, age-metadata checks, advisory coverage tests, signature integration or runtime filtering were executed. Nora's transport coverage does not establish equivalent Probation guarantees; Dozor's implemented version matching remains npm-only. Fedora's general repository documentation blocked automated access; its official repository-definition package catalog supplied the source evidence instead.
