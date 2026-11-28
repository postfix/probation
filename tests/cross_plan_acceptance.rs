//! Slice 27: the cross-plan acceptance walk. One test per contract row, each walking EVERY member of
//! `Ecosystem::ALL` (npm, PyPI, RubyGems, Cargo, Go, NuGet, Maven, Conan, OCI), so a tenth family that
//! is added to `ALL` without its row fails here, and a family that stops meeting a row fails here by
//! name. Part 1 runs behavior in-process (the policy engine, the blocklist parser, the credential
//! classifier, the OSV mapping and the real router in shared-service mode). Part 2 reads the repository
//! (migrations, config keys, docs, routes, release suite, witness tests): a witness that a later
//! change deletes or renames fails the walk, and the witnesses themselves run in `cargo test --workspace`.
//! The portal and OSV coverage views are in crates/probation-server/tests/osv_coverage_view.rs.

use std::path::{Path, PathBuf};

mod common;

use axum::http::{StatusCode, Uri};
use common::transport_load::{from_peer, hot_read, service, surfaces};
use probation::config::Config;
use probation::http::credential_read::{FamilyReadRules, ReadClass, RequestParts, classify_read};
use probation::osv::{effective_scope, osv_ecosystem};
use probation::policy::{
    BlocklistSnapshot, Candidate, Decision, DenyReason, Ecosystem, PublicationTime, evaluate,
};
use probation_policy::api::OsvScope;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(relative: &str) -> String {
    std::fs::read_to_string(root().join(relative)).unwrap_or_else(|err| panic!("{relative}: {err}"))
}

/// The nine tags in the order the contract lists them. A family added to `Ecosystem::ALL` must be added here
/// with every other row of this file; the length assertion in `every_family_has_a_stable_tag...` says so.
const TAGS: [&str; 9] = [
    "npm", "pypi", "rubygems", "cargo", "go", "nuget", "maven", "conan", "oci",
];

// ------------------------------------------------------------------------------------------------
// Part 1: behavior, every family
// ------------------------------------------------------------------------------------------------

/// Row "ecosystem tag/identity": a stable tag per family that round-trips, no two alike, no case or
/// whitespace variants, and an unknown tag never decodes as a known family (it fails closed).
#[test]
fn every_family_has_a_stable_tag_and_an_unknown_tag_fails_closed() {
    assert_eq!(
        Ecosystem::ALL.len(),
        TAGS.len(),
        "a family was added to Ecosystem::ALL: add its row to every walk in this file"
    );
    for (ecosystem, tag) in Ecosystem::ALL.into_iter().zip(TAGS) {
        assert_eq!(ecosystem.as_tag(), tag);
        assert_eq!(
            Ecosystem::from_tag(tag),
            Some(ecosystem),
            "{tag} round-trips"
        );
        for variant in [
            tag.to_ascii_uppercase(),
            format!(" {tag}"),
            format!("{tag} "),
            format!("{tag}\n"),
            format!("{tag}2"),
            String::new(),
        ] {
            assert_eq!(
                Ecosystem::from_tag(&variant),
                None,
                "{variant:?} must not decode as {tag}"
            );
        }
    }
    for unknown in [
        "swift", "cpan", "pub", "hex", "docker", "NPM", "Maven", "../npm",
    ] {
        assert_eq!(Ecosystem::from_tag(unknown), None, "{unknown}");
    }
    // A blocklist that names a tag this build has no variant for is refused as a whole, never read as another family.
    for tag in TAGS {
        let ok = document(&format!(
            r#"{{"ecosystem":"{tag}","name":"x","reason":"r"}}"#
        ));
        assert!(
            BlocklistSnapshot::parse_and_validate(ok.as_bytes(), NOW).is_ok(),
            "{tag}"
        );
        let mixed = document(&format!(
            r#"{{"ecosystem":"{tag}","name":"x","reason":"r"}},{{"ecosystem":"swift","name":"evil","reason":"r"}}"#
        ));
        let err = BlocklistSnapshot::parse_and_validate(mixed.as_bytes(), NOW)
            .expect_err("an unknown tag refuses the whole document");
        assert!(
            err.to_string().contains("unknown ecosystem"),
            "{tag}: {err}"
        );
    }
}

const NOW: i64 = 1_790_000_000_000_000;
const DAY: i64 = 86_400_000_000;

fn document(packages: &str) -> String {
    format!(
        r#"{{"schema_version":1,"revision":1,"generated_at":"2020-01-01T00:00:00Z","expires_at":"2099-01-01T00:00:00Z","blocked_packages":[{packages}],"blocked_hashes":[]}}"#
    )
}

/// A name that is valid for the family (the policy sees the normalised form).
fn sample_name(ecosystem: Ecosystem) -> &'static str {
    match ecosystem {
        Ecosystem::Go => "example.com/evil",
        Ecosystem::Maven => "org.evil:evil-art",
        Ecosystem::Oci => "library/evil",
        _ => "evil-pkg",
    }
}

/// Row "publication gate": the same SPEC §5 order for every family: a block beats age, OSV only adds a
/// deny, a too-new version is held until its eligible time, an old one is allowed, a bad or future time
/// is denied, and no blocklist means unavailable.
#[test]
fn the_publication_gate_gives_every_family_the_same_answers() {
    for ecosystem in Ecosystem::ALL {
        let tag = ecosystem.as_tag();
        let blocked = sample_name(ecosystem);
        let snapshot = BlocklistSnapshot::parse_and_validate(
            document(&format!(
                r#"{{"ecosystem":"{tag}","name":"{blocked}","reason":"r"}}"#
            ))
            .as_bytes(),
            NOW,
        )
        .unwrap();
        let cooldown = 3 * 86_400;
        let judge = |name: &str, publication, osv| {
            let candidate = Candidate {
                ecosystem,
                name,
                version: "1.0.0",
                publication,
                advertised_digests: &[],
                pinned_digests: &[],
            };
            evaluate(Some(&snapshot), NOW, cooldown, &candidate, osv)
        };
        let fresh = NOW - DAY;
        assert_eq!(
            judge("fine", PublicationTime::Upstream(fresh), false),
            Decision::Hold {
                eligible_at_micros: fresh + 3 * DAY
            },
            "{tag}: one day old, three-day cooldown"
        );
        assert_eq!(
            judge("fine", PublicationTime::FirstSeen(fresh), false),
            Decision::Hold {
                eligible_at_micros: fresh + 3 * DAY
            },
            "{tag}: first-seen ages the same way"
        );
        assert_eq!(
            judge("fine", PublicationTime::Upstream(NOW - 10 * DAY), false),
            Decision::Allow,
            "{tag}"
        );
        assert_eq!(
            judge(blocked, PublicationTime::Upstream(NOW - 10 * DAY), false),
            Decision::Deny(DenyReason::BlockedPackage),
            "{tag}: a block beats age"
        );
        assert_eq!(
            judge("fine", PublicationTime::Upstream(NOW - 10 * DAY), true),
            Decision::Deny(DenyReason::BlockedByOsv),
            "{tag}: OSV only adds"
        );
        assert_eq!(
            judge("fine", PublicationTime::Malformed, false),
            Decision::Deny(DenyReason::MalformedTimestamp),
            "{tag}"
        );
        assert_eq!(
            judge("fine", PublicationTime::Upstream(NOW + DAY), false),
            Decision::Deny(DenyReason::FutureTimestamp),
            "{tag}"
        );
        let none = Candidate {
            ecosystem,
            name: "fine",
            version: "1.0.0",
            publication: PublicationTime::Upstream(NOW - 10 * DAY),
            advertised_digests: &[],
            pinned_digests: &[],
        };
        assert_eq!(
            evaluate(None, NOW, cooldown, &none, false),
            Decision::Unavailable,
            "{tag}: no blocklist, no service"
        );
    }
}

/// Row "OSV mapping": every family maps or is recorded as not covered (OCI), and a registry's effective
/// scope follows LS-F12 for every family: a custom target is Public unless set Private, and the fixed public
/// source of a covered family is Public whatever the field says.
#[test]
fn osv_mapping_and_default_scope_cover_every_family() {
    let table = [
        ("npm", Some("npm")),
        ("pypi", Some("PyPI")),
        ("rubygems", Some("RubyGems")),
        ("cargo", Some("crates.io")),
        ("go", Some("Go")),
        ("nuget", Some("NuGet")),
        ("maven", Some("Maven")),
        ("conan", Some("ConanCenter")),
        ("oci", None),
    ];
    for ecosystem in Ecosystem::ALL {
        let expected = table
            .iter()
            .find(|(tag, _)| *tag == ecosystem.as_tag())
            .unwrap_or_else(|| panic!("{ecosystem:?} has no row in the mapping table"))
            .1;
        assert_eq!(osv_ecosystem(ecosystem), expected, "{ecosystem:?}");
        let custom = Some("https://mirror.corp.example/");
        assert_eq!(
            effective_scope(ecosystem, custom, None),
            OsvScope::Public,
            "{ecosystem:?}: the default for a custom target"
        );
        assert_eq!(
            effective_scope(ecosystem, custom, Some(OsvScope::Private)),
            OsvScope::Private,
            "{ecosystem:?}: the operator opt-out"
        );
        assert_eq!(
            effective_scope(ecosystem, None, Some(OsvScope::Private)),
            OsvScope::Public,
            "{ecosystem:?}: the family's own default target"
        );
    }
    assert_eq!(
        osv_ecosystem(Ecosystem::Oci),
        None,
        "OCI: OSV has no image ecosystem"
    );
}

/// The family's own non-secret headers and query keys.
fn read_rules(ecosystem: Ecosystem) -> &'static FamilyReadRules {
    match ecosystem {
        Ecosystem::Npm => &FamilyReadRules::NPM,
        Ecosystem::PyPi => &FamilyReadRules::PYPI,
        Ecosystem::RubyGems => &FamilyReadRules::RUBYGEMS,
        Ecosystem::Cargo => &FamilyReadRules::CARGO,
        Ecosystem::Go => &FamilyReadRules::GO,
        Ecosystem::NuGet => &FamilyReadRules::NUGET,
        Ecosystem::Maven => &FamilyReadRules::MAVEN,
        Ecosystem::Conan => &FamilyReadRules::CONAN,
        Ecosystem::Oci => &FamilyReadRules::OCI,
    }
}

/// Row "C1028": a read that carries any credential, in any carrier, is request-scoped (never written to
/// a shared cache) in every family; a plain read and the family's own non-secret headers stay eligible.
#[test]
fn credential_bearing_reads_are_never_cache_eligible_in_any_family() {
    for ecosystem in Ecosystem::ALL {
        let rules = read_rules(ecosystem);
        let tag = ecosystem.as_tag();
        let class = |uri: &str, headers: &[(&str, &str)]| {
            let uri: Uri = uri.parse().unwrap();
            let mut map = axum::http::HeaderMap::new();
            for (name, value) in headers {
                map.append(
                    axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                    value.parse().unwrap(),
                );
            }
            matches!(
                classify_read(
                    &RequestParts {
                        uri: &uri,
                        headers: &map,
                        extra_pseudo_headers: &[]
                    },
                    rules
                ),
                ReadClass::CacheEligible(_)
            )
        };
        assert!(
            class("/x/y", &[("accept", "*/*"), ("user-agent", "t")]),
            "{tag}: a plain read is cache-eligible"
        );
        for header in rules.headers {
            assert!(
                class("/x/y", &[(header, "v")]),
                "{tag}: its own non-secret header {header}"
            );
        }
        for key in rules.query_keys {
            assert!(
                class(&format!("/x/y?{key}=v"), &[]),
                "{tag}: its own query key {key}"
            );
        }
        for (name, value) in [
            ("authorization", "Bearer t"),
            ("authorization", "Basic dTpw"),
            ("cookie", "s=1"),
            ("x-nuget-apikey", "k"),
            ("x-api-key", "k"),
            ("otp", "123456"),
        ] {
            assert!(
                !class("/x/y", &[(name, value)]),
                "{tag}: {name} makes the read request-scoped"
            );
            assert!(
                !class(
                    "/x/y",
                    &[("accept", "*/*"), (name, value), ("user-agent", "t")]
                ),
                "{tag}: {name} among plain headers"
            );
        }
        assert!(
            !class("http://user:pass@host/x/y", &[]),
            "{tag}: URL userinfo is a credential"
        );
        assert!(
            !class("/x/y?token=abc", &[]),
            "{tag}: an unlisted query key is request-scoped"
        );
    }
}

// ---- the real router in shared-service mode (tests/common/transport_load.rs) ----

/// Rows "shared-service mode", "route classes" and "write forwarding": in every family an unlisted peer is
/// refused whatever it forges, an allowed peer is admitted, administrative routes do not exist, a write with
/// no credential of its own is 401 from allowed and loopback peers alike and reaches no upstream, and the
/// family that has no write route (Go) never forwards one.
#[tokio::test]
async fn the_shared_service_contract_holds_in_every_family() {
    let (server, registry, _policy, _dir) = service().await;
    let host = ("host", "packages.example.org");
    let forged = [
        host,
        ("x-forwarded-for", "10.1.2.3"),
        ("x-real-ip", "10.1.2.3"),
        ("forwarded", "for=10.1.2.3"),
        ("x-probation-peer", "trusted"),
    ];
    let surfaces = surfaces();
    assert_eq!(surfaces.len(), Ecosystem::ALL.len());
    for ecosystem in Ecosystem::ALL {
        assert!(
            surfaces
                .iter()
                .any(|surface| surface.ecosystem == ecosystem),
            "{ecosystem:?} has no surface row: add one for this family"
        );
    }
    for surface in &surfaces {
        let tag = surface.ecosystem.as_tag();
        assert_eq!(
            from_peer(&server, "203.0.113.9", "GET", surface.read, &forged).await,
            StatusCode::FORBIDDEN,
            "{tag}: an unlisted peer is refused whatever it forges"
        );
        let admitted = from_peer(
            &server,
            "10.1.2.3",
            "GET",
            &hot_read(surface, true),
            &[host],
        )
        .await;
        assert_eq!(
            admitted.as_u16(),
            surface.expected,
            "{tag}: an allowed peer's read answers its known status (200 served, or the fake's miss), not a refusal or a missing route"
        );
        // What follows must reach no upstream: the admitted read above legitimately did.
        let before = registry.calls().len();
        match surface.write {
            Some((verb, uri)) => {
                assert_eq!(
                    from_peer(&server, "203.0.113.9", verb, uri, &[host]).await,
                    StatusCode::FORBIDDEN,
                    "{tag}: write from an unlisted peer"
                );
                for peer in ["10.1.2.3", "127.0.0.1"] {
                    assert_eq!(
                        from_peer(&server, peer, verb, uri, &forged).await,
                        StatusCode::UNAUTHORIZED,
                        "{tag}: {verb} {uri} from {peer} carries no credential of its own"
                    );
                }
            }
            None => {
                for verb in ["PUT", "POST", "DELETE", "PATCH"] {
                    let status = from_peer(
                        &server,
                        "10.1.2.3",
                        verb,
                        surface.read,
                        &[host, ("authorization", "Bearer own-token")],
                    )
                    .await;
                    assert!(
                        matches!(
                            status,
                            StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED
                        ),
                        "{tag}: {verb} on a read-only family is {status}"
                    );
                }
            }
        }
        // An unknown registry id is not served, from an allowed peer.
        let unknown = surface.read.replacen(
            &format!("/registry/{tag}/{}/", surface.id),
            &format!("/registry/{tag}/9999/"),
            1,
        );
        assert_ne!(unknown, surface.read);
        let status = from_peer(&server, "10.1.2.3", "GET", &unknown, &[host]).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "{tag}: unknown registry {unknown} is a 404"
        );
        assert_eq!(
            registry.calls().len(),
            before,
            "{tag}: no refused or credential-less request reached an upstream"
        );
    }
    for uri in [
        "/api/v1/policy/snapshot",
        "/admin",
        "/portal/",
        "/settings",
        "/org/1/registries",
        "/api/v1/sync/changes",
    ] {
        for verb in ["GET", "POST", "PUT", "DELETE"] {
            assert_eq!(
                from_peer(&server, "127.0.0.1", verb, uri, &[host]).await,
                StatusCode::NOT_FOUND,
                "{verb} {uri}: administrative routes are not on the shared-service listener"
            );
        }
    }
}

// ------------------------------------------------------------------------------------------------
// Part 2: the repository, every family
// ------------------------------------------------------------------------------------------------

/// Row "migrations present and ordered": 0001..N with no gap and no duplicate, one `.sql` per number, the
/// ecosystem-widening and per-family migrations present, and every family tag in the schema's accepted tags.
#[test]
fn migrations_are_present_and_ordered() {
    let dir = root().join("crates/probation-server/migrations");
    let mut numbers: Vec<u32> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|entry| {
            let name = entry.unwrap().file_name().into_string().unwrap();
            assert!(name.ends_with(".sql"), "{name}");
            let (number, rest) = name
                .split_once('_')
                .unwrap_or_else(|| panic!("{name} has no number_ prefix"));
            assert_eq!(number.len(), 4, "{name}: four digits");
            assert!(!rest.trim_end_matches(".sql").is_empty(), "{name}");
            number.parse().unwrap()
        })
        .collect();
    numbers.sort_unstable();
    assert!(
        numbers.len() >= 23,
        "0001..0023 are delivered by slices 5 to 24"
    );
    assert_eq!(
        numbers,
        (1..=numbers.len() as u32).collect::<Vec<_>>(),
        "no gap and no duplicate"
    );
    let names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    for required in [
        "0014_ten_ecosystems.sql",
        "0015_registry_osv_scope.sql",
        "0016_registry_archive_origin.sql",
        "0017_go_archive_origin.sql",
        "0018_nuget_archive_origin.sql",
        "0019_nuget_resource_path_prefix.sql",
        "0020_maven_archive_origin.sql",
        "0021_conan_archive_origin.sql",
        "0022_oci_archive_origin.sql",
        "0023_oci_token_origin.sql",
    ] {
        assert!(
            names.iter().any(|name| name == required),
            "{required} is missing"
        );
    }
    // 0014 widened the ecosystem check to every family: its list must be exactly the nine tags (no more, no fewer), and no later
    // migration may redefine that check (a later one that dropped a family would otherwise pass a search of all files).
    let widening = std::fs::read_to_string(dir.join("0014_ten_ecosystems.sql")).unwrap();
    let list = widening
        .split("CHECK (ecosystem IN (")
        .nth(1)
        .expect("0014 holds the widened ecosystem check")
        .split("))")
        .next()
        .unwrap();
    let mut listed: Vec<&str> = list
        .split(',')
        .map(|tag| tag.trim().trim_matches('\''))
        .collect();
    listed.sort_unstable();
    let mut expected: Vec<&str> = TAGS.to_vec();
    expected.sort_unstable();
    assert_eq!(
        listed, expected,
        "0014's ecosystem check names exactly the nine tags"
    );
    for name in names
        .iter()
        .filter(|name| name.as_str() > "0014_ten_ecosystems.sql")
    {
        let text = std::fs::read_to_string(dir.join(name)).unwrap();
        assert!(
            !text.contains("CHECK (ecosystem IN ('npm'"),
            "{name} redefines the ecosystem check of 0014"
        );
    }
}

/// Row "config keys present in config.sample.toml and docs": every family's keys are in the sample, are
/// accepted by the real parser when set, and are described in docs/operations.md and docs/configuration.md.
#[test]
fn config_keys_are_in_the_sample_the_parser_and_the_docs() {
    // (family, keys). Every family but npm/PyPI/RubyGems/Cargo/Go has a second key for writes or storage.
    let keys: [(&str, &[(&str, &str)]); 9] = [
        (
            "npm",
            &[("npm_upstream_url", r#""https://npm-mirror.example.org""#)],
        ),
        (
            "pypi",
            &[
                ("pypi_upstream_url", r#""https://pypi-mirror.example.org""#),
                (
                    "pypi_artifacts_url",
                    r#""https://files-mirror.example.org""#,
                ),
            ],
        ),
        (
            "rubygems",
            &[(
                "rubygems_upstream_url",
                r#""https://rubygems-mirror.example.org""#,
            )],
        ),
        (
            "cargo",
            &[
                (
                    "cargo_upstream_url",
                    r#""https://cargo-mirror.example.org""#,
                ),
                (
                    "cargo_artifacts_url",
                    r#""https://cargo-files.example.org""#,
                ),
            ],
        ),
        (
            "go",
            &[
                ("go_upstream_url", r#""https://gomirror.example.org""#),
                ("go_artifacts_url", r#""https://go-files.example.org""#),
            ],
        ),
        (
            "nuget",
            &[
                (
                    "nuget_upstream_url",
                    r#""https://nuget-mirror.example.org""#,
                ),
                ("nuget_publish_url", r#""https://nuget-push.example.org""#),
            ],
        ),
        (
            "maven",
            &[
                (
                    "maven_upstream_url",
                    r#""https://nexus.example.org/repository/maven-central""#,
                ),
                (
                    "maven_publish_url",
                    r#""https://nexus.example.org/repository/maven-releases""#,
                ),
            ],
        ),
        (
            "conan",
            &[
                (
                    "conan_upstream_url",
                    r#""https://artifactory.example.org/artifactory/api/conan/conan-center""#,
                ),
                (
                    "conan_publish_url",
                    r#""https://artifactory.example.org/artifactory/api/conan/conan-local""#,
                ),
            ],
        ),
        (
            "oci",
            &[
                (
                    "oci_upstream_url",
                    r#""https://registry.example.org/artifactory/api/docker/images""#,
                ),
                ("oci_artifacts_url", r#""https://objects.example.org""#),
                ("oci_token_url", r#""https://gitlab.example.org""#),
                (
                    "oci_foreign_layer_hosts",
                    r#"["mcr.microsoft.com", "*.data.mcr.microsoft.com"]"#,
                ),
            ],
        ),
    ];
    let sample = read("config.sample.toml");
    let operations = read("docs/operations.md");
    let configuration = read("docs/configuration.md");
    let mut seen: Vec<&str> = Vec::new();
    for (tag, family_keys) in keys {
        assert!(TAGS.contains(&tag), "{tag}");
        for (key, value) in family_keys {
            seen.push(*key);
            assert!(
                sample.lines().any(|line| line
                    .trim_start_matches('#')
                    .trim_start()
                    .starts_with(&format!("{key} ="))),
                "{key} is not in config.sample.toml"
            );
            assert!(
                operations.contains(key),
                "{key} is not described in docs/operations.md"
            );
            assert!(
                configuration.contains(key),
                "{key} is not listed in docs/configuration.md"
            );
            let parsed = Config::from_toml_str(&format!("{key} = {value}\n{sample}"));
            assert!(
                parsed.is_ok(),
                "the real parser must accept {key}: {:?}",
                parsed.err()
            );
        }
        // A misspelt key is refused, so the keys above are the ones that count.
        let bad = Config::from_toml_str(&format!(
            "{tag}_upstream_ur = \"https://x.example\"\n{sample}"
        ));
        assert!(bad.is_err(), "{tag}: an unknown key must be refused");
    }
    // The key set is the parser's own: every `<family>_*_url` / `oci_foreign_layer_hosts` field of `Config` (src/config.rs) is in the table, so a key added
    // to the parser without a sample line, a doc line and a row here fails. (The table is not a count: it is compared with the source.)
    let source = read("src/config.rs");
    let mut declared: Vec<String> = Vec::new();
    for word in source.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
        let family_key = TAGS.iter().any(|tag| word.starts_with(&format!("{tag}_")))
            && [
                "_upstream_url",
                "_publish_url",
                "_artifacts_url",
                "_token_url",
                "_foreign_layer_hosts",
            ]
            .iter()
            .any(|suffix| word.ends_with(suffix));
        if family_key && !declared.iter().any(|known| known == word) {
            declared.push(word.to_owned());
        }
    }
    declared.sort_unstable();
    seen.sort_unstable();
    assert_eq!(
        declared, seen,
        "the parser's family keys and this table differ"
    );
}

/// Row "README/docs coverage": the first page a reader sees and the guides name every family, and
/// docs/operations.md has a client section for each of the seven families beyond npm and PyPI.
#[test]
fn readme_and_docs_cover_every_family() {
    let names = [
        ("npm", "npm"),
        ("pypi", "PyPI"),
        ("rubygems", "RubyGems"),
        ("cargo", "Cargo"),
        ("go", "Go modules"),
        ("nuget", "NuGet"),
        ("maven", "Maven"),
        ("conan", "Conan"),
        ("oci", "OCI"),
    ];
    assert_eq!(names.len(), Ecosystem::ALL.len());
    for file in [
        "README.md",
        "docs/usage.md",
        "docs/configuration.md",
        "docs/operations.md",
    ] {
        let text = read(file);
        for (tag, name) in names {
            assert!(
                text.contains(name),
                "{file} does not name {name} (the tag `{tag}` is not enough)"
            );
        }
    }
    let operations = read("docs/operations.md");
    for heading in [
        "### RubyGems clients",
        "### Cargo clients",
        "### Go clients",
        "### NuGet clients",
        "### Maven and Gradle clients",
        "### OCI clients",
        "### Conan clients",
    ] {
        assert!(
            operations.lines().any(|line| line.trim_end() == heading),
            "docs/operations.md lacks {heading}"
        );
    }
    let readme = read("README.md");
    assert!(
        !readme.contains("checks npm and PyPI packages before"),
        "README still describes a two-family product"
    );
    for (_, name) in names {
        assert!(readme.contains(name), "README.md does not name {name}");
    }
}

/// Row "route classes": every family is routed both on its own prefix (the certificate-managed and standalone
/// firewall) and on its selected-registry prefix `/registry/<tag>/{registry}` (the shared service), and the
/// classified R/W/X table of tests/listener_admission.rs lists a write class entry for each family that publishes.
#[test]
fn every_family_is_routed_on_both_prefixes_and_classified() {
    let router = read("src/http/mod.rs");
    let routes: Vec<&str> = router
        .split(".route(")
        .skip(1)
        .filter_map(|chunk| chunk.split('"').nth(1))
        .collect();
    assert!(routes.len() > 80, "found {} routes", routes.len());
    let direct = [
        ("npm", "/npm/"),
        ("pypi", "/pypi/"),
        ("rubygems", "/rubygems/"),
        ("cargo", "/cargo/"),
        ("go", "/go/"),
        ("nuget", "/nuget/"),
        ("maven", "/maven/"),
        ("conan", "/conan/"),
        ("oci", "/v2"),
    ];
    for (tag, prefix) in direct {
        assert!(
            routes.iter().any(|route| route.starts_with(prefix)),
            "{tag}: no route on {prefix}"
        );
        assert!(
            routes
                .iter()
                .any(|route| route.starts_with(&format!("/registry/{tag}/{{registry}}"))),
            "{tag}: no selected-registry route"
        );
    }
    let table = read("tests/listener_admission.rs");
    // Layout-independent: a table row is a tuple, so its class sits before its first `)`.
    let has_write_row = |tag: &str| {
        let needle = format!("\"/registry/{tag}/");
        table.match_indices(&needle).any(|(at, _)| {
            table[at..]
                .split(')')
                .next()
                .is_some_and(|row| row.contains("'W'"))
        })
    };
    for tag in [
        "npm", "pypi", "rubygems", "cargo", "nuget", "maven", "conan", "oci",
    ] {
        assert!(
            has_write_row(tag),
            "{tag}: the R/W/X table has no write route"
        );
    }
    assert!(table.contains("\"/registry/go/"), "Go rows exist");
    assert!(!has_write_row("go"), "Go modules are read-only");
}

/// Whether `text` defines `fn <name>(` (whole word: `fn a_b` does not match `fn a_bc`) carrying `#[test]` or `#[tokio::test..]` among its
/// attributes and no `#[ignore]`. A name in a comment, a string or a renamed function does not count.
fn is_live_test(text: &str, name: &str) -> bool {
    let lines: Vec<&str> = text.lines().collect();
    lines.iter().enumerate().any(|(at, line)| {
        let code = line.trim_start();
        let code = code.strip_prefix("pub ").unwrap_or(code);
        let code = code.strip_prefix("async ").unwrap_or(code);
        let Some(rest) = code
            .strip_prefix("fn ")
            .and_then(|rest| rest.strip_prefix(name))
        else {
            return false;
        };
        if !rest.starts_with('(') && !rest.starts_with('<') {
            return false;
        }
        let mut attributes = Vec::new();
        for above in lines[..at].iter().rev() {
            let above = above.trim();
            if above.starts_with("#[") || above.starts_with("///") || above.starts_with("//") {
                attributes.push(above);
            } else {
                break;
            }
        }
        attributes
            .iter()
            .any(|a| *a == "#[test]" || a.starts_with("#[tokio::test"))
            && !attributes.iter().any(|a| a.starts_with("#[ignore"))
    })
}

fn scenario_meta(file: &Path) -> (String, Vec<String>) {
    let text = std::fs::read_to_string(file).unwrap();
    let at = text
        .find("export const meta")
        .unwrap_or_else(|| panic!("{} has no meta", file.display()));
    let meta = &text[at..];
    let id = meta
        .split("id:")
        .nth(1)
        .unwrap()
        .split('"')
        .nth(1)
        .unwrap()
        .to_owned();
    let suites = meta
        .split("suites:")
        .nth(1)
        .unwrap()
        .split('[')
        .nth(1)
        .unwrap()
        .split(']')
        .next()
        .unwrap();
    (
        id,
        suites
            .split(',')
            .map(|suite| suite.trim().trim_matches('"').to_owned())
            .filter(|suite| !suite.is_empty())
            .collect(),
    )
}

/// Row "release suite": `node tests/e2e/harness/run.mjs --suite release` contains every existing E2E scenario
/// of every family and every publishing scenario that a container stack can run; the scenarios that need the
/// host (native service lifecycle) or a pinned container runtime (cluster) are in their own named suites
/// (`release-native`, `release-cluster`), which the release runbook runs; nothing else is unaccounted for.
#[test]
fn the_release_suites_account_for_every_scenario() {
    let dir = root().join("tests/e2e/scenarios");
    let mut by_id = std::collections::BTreeMap::new();
    for entry in std::fs::read_dir(&dir).unwrap() {
        let file = entry.unwrap().path();
        if file.extension().is_some_and(|ext| ext == "mjs") {
            let (id, suites) = scenario_meta(&file);
            assert!(
                by_id
                    .insert(
                        id.clone(),
                        (
                            suites,
                            file.file_name().unwrap().to_string_lossy().into_owned()
                        )
                    )
                    .is_none(),
                "{id} is declared twice"
            );
        }
    }
    let suites_of = |id: &str| {
        by_id
            .get(id)
            .unwrap_or_else(|| panic!("scenario {id} does not exist"))
            .0
            .clone()
    };
    // Every family has its own scenario in the release suite.
    for id in [
        "E2E-cargo",
        "E2E-conan",
        "E2E-go",
        "E2E-maven",
        "E2E-nuget",
        "E2E-oci",
        "E2E-rubygems",
        "E2E-002",
        "E2E-001",
    ] {
        assert!(
            suites_of(id).iter().any(|suite| suite == "release"),
            "{id} is not in the release suite"
        );
    }
    // Every shared-service publishing scenario of a publishing family is in the release suite.
    for id in [
        "E2E-publishing-cargo-service",
        "E2E-publishing-conan-service",
        "E2E-publishing-maven-service",
        "E2E-publishing-nuget-service",
        "E2E-publishing-oci-service",
        "E2E-publishing-rubygems-service",
        "E2E-publishing-python-service",
        "E2E-publishing-npm-actions",
        "E2E-service-policy",
    ] {
        assert!(
            suites_of(id).iter().any(|suite| suite == "release"),
            "{id} is not in the release suite"
        );
    }
    // Every other publishing scenario the container stack can run is in it too; the one that needs a quick tunnel (E2E-publishing-native-remote) is the only exception.
    for (id, (suites, file)) in &by_id {
        if id.starts_with("E2E-publishing-") && id != "E2E-publishing-native-remote" {
            assert!(
                suites.iter().any(|suite| suite == "release"),
                "{id} ({file}) is a publishing scenario outside the release suite"
            );
        }
    }
    assert_eq!(
        suites_of("E2E-service-native"),
        ["release-native"],
        "the native lifecycle runs on the host, with --client-host native"
    );
    assert_eq!(suites_of("E2E-service-native-smoke"), ["release-native"]);
    assert_eq!(suites_of("E2E-service-cluster"), ["release-cluster"]);
    assert_eq!(suites_of("E2E-service-cluster-probe"), ["release-cluster"]);
    // The release suite contains the whole pull-request suite: nothing a merge needs is missing from the gate.
    for (id, (suites, file)) in &by_id {
        assert!(
            !suites.iter().any(|suite| suite == "pr")
                || suites.iter().any(|suite| suite == "release"),
            "{id} ({file}) runs on pull requests but not in the release suite"
        );
    }
    // Exactly one release suite per scenario: a scenario in two of `release`, `release-native`, `release-cluster` would run (and be reported) twice.
    for (id, (suites, file)) in &by_id {
        let release_suites: Vec<&String> = suites
            .iter()
            .filter(|suite| suite.starts_with("release"))
            .collect();
        assert!(
            release_suites.len() <= 1,
            "{id} ({file}) is in several release suites: {release_suites:?}"
        );
    }
    // No scenario is in a suite nobody runs: the only scenarios outside every release suite are the named exceptions.
    let exceptions = ["E2E-publishing-native-remote"];
    for (id, (suites, file)) in &by_id {
        let runs_in_release = suites.iter().any(|suite| suite.starts_with("release"));
        let property_based = suites.iter().any(|suite| suite.starts_with("pbt"));
        let canary = suites.iter().any(|suite| suite == "canary");
        assert!(
            runs_in_release || property_based || canary || exceptions.contains(&id.as_str()),
            "{id} ({file}) belongs to no release suite and is not a named exception (suites {suites:?})"
        );
    }
}

/// Rows "write forwarding with the caller's own credential" and "spool owner rules": each publishing family
/// has its witness tests, and the one test that walks every forwarder's spool places per real identity and
/// credential is present. A witness removed or renamed fails here.
#[test]
fn every_publishing_family_keeps_its_write_and_spool_witnesses() {
    let witnesses: [(&str, &str, &[&str]); 8] = [
        (
            "npm",
            "tests/service_unpublish.rs",
            &[
                "write_preflight_commits_a_service_scoped_reference",
                "service_removal_verifies_revision_and_consumes_once_before_send",
            ],
        ),
        (
            "pypi",
            "tests/pypi_service_upload.rs",
            &["local_service_forwards_selected_pypi_upload_and_upstream_denial"],
        ),
        (
            "rubygems",
            "tests/rubygems_service_write.rs",
            &["shared_service_forwards_gem_push_and_yank_with_the_callers_own_key_only"],
        ),
        (
            "cargo",
            "tests/cargo_service_write.rs",
            &[
                "shared_service_forwards_cargo_writes_with_the_callers_own_token_only",
                "an_api_root_outside_the_registrys_own_origin_is_never_written_to",
            ],
        ),
        (
            "nuget",
            "tests/nuget_service_write.rs",
            &[
                "shared_service_forwards_nuget_writes_with_the_callers_own_key_only",
                "one_key_cannot_hold_all_the_spool_places",
            ],
        ),
        (
            "maven",
            "tests/maven_service_write.rs",
            &[
                "a_deploy_is_challenged_then_forwarded_with_the_callers_own_credential_only",
                "all_six_forwarders_count_their_spool_places_per_real_identity_and_credential",
                "one_owner_never_holds_more_than_half_of_the_spool_budget",
                "a_forwarded_for_header_names_the_client_only_from_a_listed_proxy",
            ],
        ),
        (
            "conan",
            "tests/conan_service_write.rs",
            &[
                "an_upload_is_challenged_then_forwarded_with_the_callers_own_credential_only",
                "a_firewall_key_is_refused_as_an_upload_credential",
            ],
        ),
        (
            "oci",
            "tests/oci_service.rs",
            &[
                "a_push_is_forwarded_with_the_callers_own_credential_and_every_location_comes_back_in_the_firewalls_namespace",
            ],
        ),
    ];
    for (tag, file, names) in witnesses {
        let text = read(file);
        for name in names {
            assert!(
                is_live_test(&text, name),
                "{tag}: {file} lost its witness {name} (it must be a `#[test]` or `#[tokio::test]` that is not `#[ignore]`d)"
            );
        }
    }
    // The read side of every family against the shared service, and its native client.
    for (tag, files) in [
        (
            "npm",
            &[
                "tests/shared_service.rs",
                "tests/credential_bearing_reads.rs",
            ][..],
        ),
        ("pypi", &["tests/shared_service.rs"]),
        ("rubygems", &["tests/rubygems_native.rs"]),
        (
            "cargo",
            &["tests/cargo_service_read.rs", "tests/cargo_native.rs"],
        ),
        ("go", &["tests/go_service_read.rs", "tests/go_native.rs"]),
        (
            "nuget",
            &["tests/nuget_service_read.rs", "tests/nuget_native.rs"],
        ),
        (
            "maven",
            &["tests/maven_service_read.rs", "tests/maven_native.rs"],
        ),
        (
            "conan",
            &["tests/conan_service_read.rs", "tests/conan_native.rs"],
        ),
        ("oci", &["tests/oci_service.rs", "tests/oci_native.rs"]),
    ] {
        for file in files {
            assert!(root().join(file).is_file(), "{tag}: {file} is missing");
        }
    }
    // The cross-family witnesses of the other rows.
    for (file, name) in [
        (
            "tests/listener_admission.rs",
            "route_inventory_equals_classified_table",
        ),
        (
            "tests/listener_admission.rs",
            "upstream_write_without_credential_is_refused",
        ),
        (
            "tests/osv_ecosystem_mapping.rs",
            "osv_ecosystem_mapping_matches_the_table_for_every_delivered_family",
        ),
        (
            "tests/credential_bearing_reads.rs",
            "credential_bearing_read_never_enters_shared_caches",
        ),
    ] {
        assert!(
            is_live_test(&read(file), name),
            "{file} lost the live test {name}"
        );
    }
    assert!(
        is_live_test(
            &read("crates/probation-server/tests/osv_coverage_view.rs"),
            "osv_coverage_view_matches_mapping"
        ),
        "the portal coverage witness"
    );
}
