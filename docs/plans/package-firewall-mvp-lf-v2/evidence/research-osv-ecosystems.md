# Research: OSV ecosystem strings and name forms (sf-research ANSWERED, 2026-11-17)

Decision supported: the exact OSV `package.ecosystem` string and `package.name` form per package family (03-program-design.md "OSV ecosystem mapping table"). Sources: ossf/osv-schema "Ecosystems" section (https://ossf.github.io/osv-schema/, raw docs/schema.md on main) and the OSV API doc for POST /v1/querybatch (https://google.github.io/osv.dev/post-v1-querybatch/), both fetched 2026-11-17 by a summarising fetch tool (fragments, not byte-exact).

| Family | ecosystem string (exact case) | package.name form | Covered |
|---|---|---|---|
| npm | `npm` | npm package name (scoped form `@scope/name` is an inference, not stated in the schema) | yes |
| PyPI | `PyPI` | normalized PyPI name (PEP 503) | yes |
| Maven | `Maven` | `groupId:artifactId` | yes |
| Go modules | `Go` | full module path | yes |
| Cargo | `crates.io` | crate name | yes |
| NuGet | `NuGet` | NuGet package name | yes |
| RubyGems | `RubyGems` | gem name | yes |
| Conan | `ConanCenter` | Conan package name | yes, ConanCenter packages only |
| Docker/OCI images | none | n/a | no generic ecosystem (only vendor image sets and distro ecosystems) |

API: a query takes `package {name, ecosystem, purl}`, `version`, `commit`, `page_token`; `version` and a versioned `purl` must not both be sent (400).

Limits: the schema does not state ecosystem case sensitivity or unknown-ecosystem behaviour, so a wrong spelling may silently return nothing; the design therefore sends only the exact strings above from a fixed table and tests them, and each ecosystem gets a known-vulnerable canary query in a live check that is run manually or in an opt-in lane, never in hermetic tests. Whether the API normalises PyPI names was not checked live; the client sends the normalized name.
