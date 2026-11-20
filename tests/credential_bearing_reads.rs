//! Slice 28, C1028 / LS-F4: credential-bearing reads are detected by an allow-list.

mod common;

use axum::http::{HeaderMap, HeaderName, HeaderValue, Uri};
use common::{FakeAnswer, FakeRegistry, TestClock, TestServer, config_with_open_blocklist, fake_origins, npm_upstream_path};
use probation::config::{FirewallToken, ServicePolicyConfig};
use probation::upstream::{ArtifactBody, ArtifactRequest, MetadataRequest, MetadataResponse, Transport, UpstreamError};
use probation_policy::{Layer, LayerKind, OsvSetting, PlaceRef, api::*};
use reqwest::StatusCode;
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::{method, path}};
use probation::http::credential_read::{FamilyReadRules, ReadClass, RequestParts, classify_read};


fn classify(uri: &str, headers: &[(&str, &str)], pseudo: &[&str]) -> ReadClass {
    let uri: Uri = uri.parse().unwrap();
    let mut map = HeaderMap::new();
    for (name, value) in headers {
        map.append(HeaderName::from_bytes(name.as_bytes()).unwrap(), HeaderValue::from_str(value).unwrap());
    }
    classify_read(&RequestParts { uri: &uri, headers: &map, extra_pseudo_headers: pseudo }, &FamilyReadRules::NPM)
}

fn eligible(uri: &str, headers: &[(&str, &str)]) -> bool {
    matches!(classify(uri, headers, &[]), ReadClass::CacheEligible(_))
}

/// One case per carrier: each must make the read request-scoped.
#[test]
fn credential_bearing_read_never_enters_shared_caches() {
    for (name, value) in [
        ("authorization", "Bearer secret"),
        ("proxy-authorization", "Basic abc"),
        ("cookie", "session=1"),
        ("x-nuget-apikey", "key"),
        ("x-jfrog-art-api", "key"),
        ("x-probe-unknown", "1"),
        ("Authorization", "Bearer secret"),
    ] {
        assert!(!eligible("/npm/left-pad", &[(name, value)]), "{name} must be request-scoped");
    }
    // Repeated and mixed-case instances: one bad instance is enough.
    assert!(!eligible("/npm/left-pad", &[("accept", "*/*"), ("AuThOrIzAtIoN", "x"), ("accept", "*/*")]));
    // Query-string carriers and URL userinfo.
    assert!(!eligible("/npm/left-pad?token=abc", &[]));
    assert!(!eligible("/npm/left-pad?api_key=abc", &[]));
    assert!(!eligible("https://user:pw@registry.example.test/npm/left-pad", &[]));
    assert!(!eligible("https://user@registry.example.test/npm/left-pad", &[]));
    // Any other pseudo-header makes the request request-scoped.
    assert!(matches!(classify("/npm/left-pad", &[], &[":protocol"]), ReadClass::RequestScoped));
    // Control: only allow-listed headers (common and the family's) keep the read cache-eligible.
    assert!(eligible(
        "/npm/left-pad",
        &[("host", "x"), ("accept", "application/json"), ("accept-encoding", "gzip"), ("user-agent", "npm"), ("if-none-match", "\"a\""), ("npm-session", "s"), ("referer", "r"), ("range", "bytes=0-1")]
    ));
    assert!(eligible("https://registry.example.test/npm/left-pad", &[]), "absolute form without userinfo is ordinary");
}

/// Row 17, the RubyGems case of the same contract. RubyGems clients carry a credential as
/// `Authorization` (an API key or Basic from a source URL's userinfo) and registries such as
/// Gemfury take a token as URL userinfo; none uses a token in the path or the query string.
/// The family adds no header beyond the common allow-list (the real-client witness is
/// `rubygems_native_clients_send_only_allow_listed_headers` in tests/rubygems_registry.rs).
#[test]
fn credential_bearing_read_never_enters_shared_caches_rubygems() {
    let rubygems = |uri: &str, headers: &[(&str, &str)]| {
        let uri: Uri = uri.parse().unwrap();
        let mut map = HeaderMap::new();
        for (name, value) in headers {
            map.append(HeaderName::from_bytes(name.as_bytes()).unwrap(), HeaderValue::from_str(value).unwrap());
        }
        matches!(classify_read(&RequestParts { uri: &uri, headers: &map, extra_pseudo_headers: &[] }, &FamilyReadRules::RUBYGEMS), ReadClass::CacheEligible(_))
    };
    for (name, value) in [
        ("authorization", "rubygems_0123456789abcdef"),
        ("authorization", "Basic dXNlcjpwdw=="),
        ("Authorization", "Bearer x"),
        ("proxy-authorization", "Basic abc"),
        ("cookie", "session=1"),
        ("x-jfrog-art-api", "key"),
        ("x-probe-unknown", "1"),
    ] {
        assert!(!rubygems("/rubygems/info/rack", &[(name, value)]), "{name} must be request-scoped");
    }
    assert!(!rubygems("/rubygems/versions?token=abc", &[]));
    assert!(!rubygems("/rubygems/gems/rack-3.0.0.gem?api_key=abc", &[]));
    assert!(!rubygems("https://TOKEN:@gem.example.test/rubygems/info/rack", &[]), "URL userinfo");
    assert!(!rubygems("https://token@gem.example.test/rubygems/info/rack", &[]), "URL userinfo");
    // Control: the headers `gem` and Bundler send for plain reads keep the read cache-eligible.
    assert!(rubygems(
        "/rubygems/info/rack",
        &[("host", "x"), ("accept", "*/*"), ("accept-encoding", "gzip"), ("user-agent", "bundler/2.6"), ("if-none-match", "\"a\""), ("range", "bytes=10-"), ("if-modified-since", "Mon, 01 Jan 2026 00:00:00 GMT")]
    ));
}

/// Row 18, the Cargo case of the same contract. Cargo carries a credential as `Authorization: <token>`
/// (bare, or `Bearer ...`), never in a path or query of this firewall's routes; a registry that
/// embeds a token in a URL (Cloudsmith) or takes userinfo does so in the URL the client was
/// given, which is userinfo here. The family adds no header beyond the common allow-list (the
/// real-client witness is `cargo_native_client_sends_only_allow_listed_headers` in tests/cargo_native.rs).
#[test]
fn credential_bearing_read_never_enters_shared_caches_cargo() {
    let cargo = |uri: &str, headers: &[(&str, &str)]| {
        let uri: Uri = uri.parse().unwrap();
        let mut map = HeaderMap::new();
        for (name, value) in headers {
            map.append(HeaderName::from_bytes(name.as_bytes()).unwrap(), HeaderValue::from_str(value).unwrap());
        }
        matches!(classify_read(&RequestParts { uri: &uri, headers: &map, extra_pseudo_headers: &[] }, &FamilyReadRules::CARGO), ReadClass::CacheEligible(_))
    };
    for (name, value) in [
        ("authorization", "cio0123456789abcdef"),
        ("authorization", "Bearer prb_x"),
        ("Authorization", "Basic dXNlcjpwdw=="),
        ("proxy-authorization", "Basic abc"),
        ("cookie", "session=1"),
        ("x-jfrog-art-api", "key"),
        ("x-probe-unknown", "1"),
    ] {
        assert!(!cargo("/cargo/se/rd/serde", &[(name, value)]), "{name} must be request-scoped");
    }
    assert!(!cargo("/cargo/config.json?token=abc", &[]));
    assert!(!cargo("/cargo/crates/serde/1.0.0/download?api_key=abc", &[]));
    // The path-embedded and userinfo credential forms of the family's registries.
    for form in [
        "https://TOKEN:@crates.example.test/cargo/se/rd/serde",
        "https://token@crates.example.test/cargo/se/rd/serde",
        "https://user:pass@crates.example.test/registry/cargo/7/config.json",
    ] {
        assert!(!cargo(form, &[]), "{form}: URL userinfo");
    }
    // Control: the headers `cargo` sends for plain reads keep the read cache-eligible.
    assert!(cargo(
        "/cargo/se/rd/serde",
        &[("host", "x"), ("accept", "*/*"), ("accept-encoding", "gzip"), ("user-agent", "cargo/1.96.0"), ("if-none-match", "\"a\""), ("if-modified-since", "Mon, 01 Jan 2026 00:00:00 GMT"), ("cache-control", "no-cache")]
    ));
}

/// Row 19, the Go case of the same contract. `go` carries a credential as `Authorization` (Basic from
/// `.netrc` or from the GOPROXY URL's userinfo, or GOAUTH), never in a path or query of this
/// firewall's routes; a module path itself cannot hold one (`[A-Za-z0-9._~/-]` and the `!` escape),
/// and a path that is not one of this firewall's routes is a 404 that asks upstream nothing. The family
/// adds no header beyond the common allow-list (the real-client witness is
/// `go_native_client_sends_only_allow_listed_headers` in tests/go_native.rs).
#[test]
fn credential_bearing_read_never_enters_shared_caches_go() {
    let go = |uri: &str, headers: &[(&str, &str)]| {
        let uri: Uri = uri.parse().unwrap();
        let mut map = HeaderMap::new();
        for (name, value) in headers {
            map.append(HeaderName::from_bytes(name.as_bytes()).unwrap(), HeaderValue::from_str(value).unwrap());
        }
        matches!(classify_read(&RequestParts { uri: &uri, headers: &map, extra_pseudo_headers: &[] }, &FamilyReadRules::GO), ReadClass::CacheEligible(_))
    };
    for (name, value) in [
        ("authorization", "Basic dXNlcjpwdw=="),
        ("Authorization", "Bearer prb_x"),
        ("proxy-authorization", "Basic abc"),
        ("cookie", "session=1"),
        ("x-jfrog-art-api", "key"),
        ("x-probe-unknown", "1"),
    ] {
        assert!(!go("/go/example.com/m/@v/list", &[(name, value)]), "{name} must be request-scoped");
    }
    assert!(!go("/go/example.com/m/@v/list?token=abc", &[]));
    assert!(!go("/go/example.com/m/@v/v1.0.0.zip?api_key=abc", &[]));
    for form in [
        "https://TOKEN:@proxy.example.test/go/example.com/m/@v/list",
        "https://token@proxy.example.test/go/example.com/m/@latest",
        "https://user:pass@proxy.example.test/registry/go/7/example.com/m/@v/v1.0.0.info",
    ] {
        assert!(!go(form, &[]), "{form}: URL userinfo");
    }
    // Control: the headers `go` sends for plain reads keep the read cache-eligible.
    assert!(go(
        "/go/example.com/m/@v/list",
        &[("host", "x"), ("accept", "*/*"), ("accept-encoding", "gzip"), ("user-agent", "Go-http-client/1.1"), ("if-none-match", "\"a\""), ("cache-control", "no-cache")]
    ));
}

/// Row 20, the NuGet case of the same contract. A NuGet client carries a credential as `Authorization` (Basic
/// from `packageSourceCredentials`, or Bearer from a credential provider) and, on a write, as `X-NuGet-ApiKey`;
/// never in a path of this firewall's routes (an id cannot hold one), and the only query keys are the search
/// protocol's own. The family adds the two non-secret headers the real client sends (measured with dotnet 8.0.416,
/// `dotnet_native_client_sends_only_allow_listed_headers` in tests/nuget_native.rs).
#[test]
fn credential_bearing_read_never_enters_shared_caches_nuget() {
    let nuget = |uri: &str, headers: &[(&str, &str)]| {
        let uri: Uri = uri.parse().unwrap();
        let mut map = HeaderMap::new();
        for (name, value) in headers {
            map.append(HeaderName::from_bytes(name.as_bytes()).unwrap(), HeaderValue::from_str(value).unwrap());
        }
        matches!(classify_read(&RequestParts { uri: &uri, headers: &map, extra_pseudo_headers: &[] }, &FamilyReadRules::NUGET), ReadClass::CacheEligible(_))
    };
    for (name, value) in [
        ("authorization", "Basic dXNlcjpwdw=="),
        ("Authorization", "Bearer prb_x"),
        ("proxy-authorization", "Basic abc"),
        ("cookie", "session=1"),
        ("x-nuget-apikey", "key"),
        ("X-NuGet-ApiKey", "key"),
        ("x-jfrog-art-api", "key"),
        ("x-probe-unknown", "1"),
    ] {
        assert!(!nuget("/nuget/v3-flatcontainer/a/index.json", &[(name, value)]), "{name} must be request-scoped");
    }
    assert!(!nuget("/nuget/v3-flatcontainer/a/index.json?token=abc", &[]));
    assert!(!nuget("/nuget/v3/query?q=a&api_key=abc", &[]));
    assert!(!nuget("/nuget/v3/query?q=a&apikey=abc", &[]));
    for form in [
        "https://TOKEN:@pkgs.example.test/nuget/v3/index.json",
        "https://token@pkgs.example.test/nuget/v3-flatcontainer/a/index.json",
        "https://user:pass@pkgs.example.test/registry/nuget/9/v3/query?q=a",
    ] {
        assert!(!nuget(form, &[]), "{form}: URL userinfo");
    }
    // Control: the headers `dotnet` sends for plain reads and the search protocol's own query keys keep the read cache-eligible.
    assert!(nuget(
        "/nuget/v3-flatcontainer/a/index.json",
        &[("host", "x"), ("accept", "*/*"), ("accept-encoding", "gzip, deflate"), ("accept-language", "en-US"), ("user-agent", "NuGet Command Line"), ("x-nuget-session-id", "s"), ("x-nuget-client-version", "6.11.1"), ("if-none-match", "\"a\"")]
    ));
    assert!(nuget("/nuget/v3/query?q=a&skip=0&take=20&prerelease=true&semVerLevel=2.0.0&packageType=dotnet-tool&supportedFramework=net8.0", &[("accept", "*/*")]));
}

/// Row 21, the Maven case of the same contract. A Maven client carries a credential as `Authorization` (Basic from
/// `settings.xml`, or a bearer header), never in a path of this firewall's routes (a coordinate cannot hold one) and never in a
/// query (no route has one); the real client sends no non-secret header beyond the common ones (measured with Maven 3.9,
/// `mvn_native_client_sends_only_allow_listed_headers` in tests/maven_native.rs).
#[test]
fn credential_bearing_read_never_enters_shared_caches_maven() {
    let maven = |uri: &str, headers: &[(&str, &str)]| {
        let uri: Uri = uri.parse().unwrap();
        let mut map = HeaderMap::new();
        for (name, value) in headers {
            map.append(HeaderName::from_bytes(name.as_bytes()).unwrap(), HeaderValue::from_str(value).unwrap());
        }
        matches!(classify_read(&RequestParts { uri: &uri, headers: &map, extra_pseudo_headers: &[] }, &FamilyReadRules::MAVEN), ReadClass::CacheEligible(_))
    };
    for (name, value) in [
        ("authorization", "Basic dXNlcjpwdw=="),
        ("Authorization", "Bearer prb_x"),
        ("proxy-authorization", "Basic abc"),
        ("cookie", "session=1"),
        ("x-jfrog-art-api", "key"),
        ("x-api-key", "key"),
        ("x-probe-unknown", "1"),
    ] {
        assert!(!maven("/maven/org/a/b/maven-metadata.xml", &[(name, value)]), "{name} must be request-scoped");
    }
    assert!(!maven("/maven/org/a/b/maven-metadata.xml?token=abc", &[]));
    assert!(!maven("/maven/org/a/b/1.0/b-1.0.jar?access_token=abc", &[]));
    for form in [
        "https://TOKEN:@repo.example.test/maven/org/a/b/maven-metadata.xml",
        "https://token@repo.example.test/maven/org/a/b/1.0/b-1.0.jar",
        "https://user:pass@repo.example.test/registry/maven/9/org/a/b/maven-metadata.xml",
    ] {
        assert!(!maven(form, &[]), "{form}: URL userinfo");
    }
    // Control: the headers `mvn` sends for plain reads keep the read cache-eligible.
    assert!(maven(
        "/maven/org/a/b/maven-metadata.xml",
        &[("host", "x"), ("accept", "*/*"), ("accept-encoding", "gzip, deflate"), ("user-agent", "Apache-Maven/3.9.9 (Java 21)"), ("cache-control", "no-cache, no-store"), ("pragma", "no-cache"), ("connection", "keep-alive"), ("if-none-match", "\"a\""), ("if-modified-since", "Sat, 13 Feb 2021 16:31:54 GMT"), ("range", "bytes=0-9")]
    ));
}

/// Row 23, the Conan case of the same contract. A Conan client carries a credential as `Authorization` (Basic on `conan remote login`,
/// then the Bearer token it returns), never in a path of this firewall's routes (a reference cannot hold one) and never in a query
/// (the search takes `q` and `ignorecase` only); the real client's own non-secret headers keep a read cache-eligible
/// (measured with conan 2.21.0, `conan_native_client_sends_only_allow_listed_headers` in tests/conan_native.rs).
#[test]
fn credential_bearing_read_never_enters_shared_caches_conan() {
    let conan = |uri: &str, headers: &[(&str, &str)]| {
        let uri: Uri = uri.parse().unwrap();
        let mut map = HeaderMap::new();
        for (name, value) in headers {
            map.append(HeaderName::from_bytes(name.as_bytes()).unwrap(), HeaderValue::from_str(value).unwrap());
        }
        matches!(classify_read(&RequestParts { uri: &uri, headers: &map, extra_pseudo_headers: &[] }, &FamilyReadRules::CONAN), ReadClass::CacheEligible(_))
    };
    for (name, value) in [
        ("authorization", "Basic dXNlcjpwdw=="),
        ("Authorization", "Bearer eyJ0b2tlbiI6IjEifQ"),
        ("proxy-authorization", "Basic abc"),
        ("cookie", "session=1"),
        ("x-jfrog-art-api", "key"),
        ("x-api-key", "key"),
        ("x-probe-unknown", "1"),
    ] {
        assert!(!conan("/conan/v2/conans/zlib/1.3.1/_/_/revisions", &[(name, value)]), "{name} must be request-scoped");
    }
    assert!(!conan("/conan/v2/conans/zlib/1.3.1/_/_/revisions?token=abc", &[]));
    assert!(!conan("/conan/v2/conans/search?q=zlib/*&access_token=abc", &[]));
    for form in [
        "https://TOKEN:@center.example.test/conan/v2/conans/zlib/1.3.1/_/_/latest",
        "https://token@center.example.test/conan/v2/conans/zlib/1.3.1/_/_/revisions",
        "https://user:pass@center.example.test/registry/conan/10/v2/conans/search?q=a",
    ] {
        assert!(!conan(form, &[]), "{form}: URL userinfo");
    }
    // Control: the search pattern and the client's own non-secret headers keep a read cache-eligible.
    assert!(conan("/conan/v2/conans/search?q=zlib/*&ignorecase=False", &[("host", "x"), ("accept", "application/json"), ("accept-encoding", "gzip, deflate"), ("user-agent", "Conan/2.21.0 (Python 3.13.0)"), ("x-client-anonymous-id", "abc"), ("x-client-id", "def")]));
}

// ---- C1028 end to end: bytes fetched under credential A are never served without it ----

/// A registry whose metadata is public but whose artifact needs `Bearer allowed`.
struct PrivateArtifacts(Arc<FakeRegistry>, Mutex<Vec<Option<String>>>);

/// How many recent-versions fetches of the slow registry have started, and their release.
static SLOW_ARRIVED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
/// The read credential every call to the checksum database carried (row 19): none may carry one.
static SUMDB_AUTH: Mutex<Vec<Option<String>>> = Mutex::new(Vec::new());
static SLOW_GATE: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(0);

#[async_trait::async_trait]
impl Transport for PrivateArtifacts {
    async fn fetch_token_packument(&self, mut request: MetadataRequest, authorization: &str) -> Result<MetadataResponse, UpstreamError> {
        request.read_authorization = Some(authorization.to_owned());
        self.fetch_metadata(request).await
    }
    async fn fetch_metadata(&self, request: MetadataRequest) -> Result<MetadataResponse, UpstreamError> {
        if request.url.host_str() == Some("slow.invalid") && request.url.path().ends_with("timeframe_versions.json") {
            SLOW_ARRIVED.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let _ = SLOW_GATE.acquire().await;
        }
        if request.url.host_str() == Some("sum.golang.org") {
            SUMDB_AUTH.lock().unwrap().push(request.read_authorization.clone());
        }
        // A Cargo registry whose `config.json` wants the caller's own credential (row 18).
        if request.url.path() == "/config.json" {
            match request.read_authorization.as_deref() {
                Some("config-login") => return Err(UpstreamError::Status(401)),
                Some("config-deny") => return Err(UpstreamError::Status(403)),
                _ => {}
            }
        }
        if request.url.path().contains("login-meta") {
            return Err(UpstreamError::Status(401));
        }
        if request.url.path().contains("deny-meta") {
            return Err(UpstreamError::Status(403));
        }
        self.0.fetch_metadata(request).await
    }
    async fn fetch_named_read(&self, request: probation::upstream::NamedReadRequest) -> Result<bytes::Bytes, UpstreamError> {
        match request.authorization.as_deref() {
            Some("Bearer expired") => Err(UpstreamError::Status(401)),
            Some("Bearer denied") => Err(UpstreamError::Status(403)),
            _ => Ok(bytes::Bytes::from_static(b"{}")),
        }
    }
    async fn open_artifact(&self, request: ArtifactRequest) -> Result<ArtifactBody, UpstreamError> {
        self.1.lock().unwrap().push(request.read_authorization.clone());
        if request.url.path().contains("login") && request.read_authorization.is_none() {
            return Err(UpstreamError::Status(401));
        }
        if request.url.path().contains("secret") && !request.url.path().ends_with(".whl") && request.read_authorization.as_deref() != Some("Bearer allowed") {
            return Err(UpstreamError::Status(403));
        }
        self.0.open_artifact(request).await
    }
}

fn service_snapshot() -> ServicePolicySnapshot {
    service_snapshot_with(0, false)
}

fn service_snapshot_with(freeze: u64, slow: bool) -> ServicePolicySnapshot {
    let places = [PlaceRef { kind: LayerKind::Platform, id: 1 }, PlaceRef { kind: LayerKind::Org, id: 10 }];
    let mut snapshot = ServicePolicySnapshot {
        version: 1, key_id: KeyId(7), org: OrgId(10), account: places[1], revision: 1,
        place_chain: places.iter().map(|place| ChainLink { place: *place, layer_revision: 1 }).collect(),
        layers: places.iter().map(|place| PlaceLayer {
            place: *place,
            layer: Layer { freeze_seconds: Some(freeze), osv: Some(OsvSetting::Off), ..Layer::empty(place.kind) },
            revision: 1,
        }).collect(),
        rate_limit: None, rate_limit_source: LimitSource::Default,
        registries: vec![RegistryDescriptor {
            registry: RegistryId(3), ecosystem: probation_policy::Ecosystem::Npm, target_url: None, trusted: false,
            registry_private_cidrs: vec![], deletion_scopes: vec![], osv_scope: None, archive_origin: None, resource_path_prefix: None,
        }, RegistryDescriptor {
            registry: RegistryId(4), ecosystem: probation_policy::Ecosystem::PyPi, target_url: None, trusted: false,
            registry_private_cidrs: vec![], deletion_scopes: vec![], osv_scope: None, archive_origin: None, resource_path_prefix: None,
        }, RegistryDescriptor {
            registry: RegistryId(5), ecosystem: probation_policy::Ecosystem::RubyGems, target_url: None, trusted: false,
            registry_private_cidrs: vec![], deletion_scopes: vec![], osv_scope: None, archive_origin: None, resource_path_prefix: None,
        }, RegistryDescriptor {
            registry: RegistryId(7), ecosystem: probation_policy::Ecosystem::Cargo, target_url: None, trusted: false,
            registry_private_cidrs: vec![], deletion_scopes: vec![], osv_scope: None, archive_origin: None, resource_path_prefix: None,
        }, RegistryDescriptor {
            registry: RegistryId(8), ecosystem: probation_policy::Ecosystem::Go, target_url: None, trusted: false,
            registry_private_cidrs: vec![], deletion_scopes: vec![], osv_scope: None, archive_origin: None, resource_path_prefix: None,
        }, RegistryDescriptor {
            registry: RegistryId(9), ecosystem: probation_policy::Ecosystem::NuGet, target_url: None, trusted: false,
            registry_private_cidrs: vec![], deletion_scopes: vec![], osv_scope: None, archive_origin: None, resource_path_prefix: None,
        }, RegistryDescriptor {
            registry: RegistryId(10), ecosystem: probation_policy::Ecosystem::Maven, target_url: None, trusted: false,
            registry_private_cidrs: vec![], deletion_scopes: vec![], osv_scope: None, archive_origin: None, resource_path_prefix: None,
        }, RegistryDescriptor {
            registry: RegistryId(11), ecosystem: probation_policy::Ecosystem::Conan, target_url: None, trusted: false,
            registry_private_cidrs: vec![], deletion_scopes: vec![], osv_scope: None, archive_origin: None, resource_path_prefix: None,
        }],
    };
    if slow {
        // A second RubyGems registry whose recent-versions API never answers until released (N3).
        // Only this test has it: two RubyGems registries make the unqualified `/rubygems` root ambiguous.
        snapshot.registries.push(RegistryDescriptor {
            registry: RegistryId(6), ecosystem: probation_policy::Ecosystem::RubyGems, target_url: Some("https://slow.invalid/".into()), trusted: false,
            registry_private_cidrs: vec![], deletion_scopes: vec![], osv_scope: None, archive_origin: None, resource_path_prefix: None,
        });
    }
    snapshot
}

fn files_under(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_owned()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() { stack.push(path) } else if path.file_name().is_some_and(|n| n != "lock") { found.push(path) }
        }
    }
    found
}

#[tokio::test]
async fn credential_bearing_artifact_never_enters_the_shared_content_cache() {
    let policy_server = MockServer::start().await;
    Mock::given(method("GET")).and(path("/api/v1/policy/snapshot"))
        .respond_with(ResponseTemplate::new(200).set_body_json(service_snapshot()))
        .mount(&policy_server).await;
    let registry = FakeRegistry::new();
    registry.answer(&npm_upstream_path("secret-pkg"), FakeAnswer::Body(serde_json::json!({
        "name":"secret-pkg", "dist-tags":{"latest":"1.0.0"},
        "versions":{"1.0.0":{"name":"secret-pkg","version":"1.0.0","dist":{"tarball":"https://npm.invalid/secret-pkg/-/secret-pkg-1.0.0.tgz",
            "integrity":format!("sha256-{}", common::sync::base64(Sha256::digest(b"secret bytes")))}}},
        "time":{"1.0.0":"2026-01-01T00:00:00Z"}
    }).to_string()));
    registry.answer(&common::npm_artifact_upstream_path("secret-pkg", "secret-pkg-1.0.0.tgz"), FakeAnswer::Body("secret bytes".into()));
    registry.answer(&npm_upstream_path("open-pkg"), FakeAnswer::Body(serde_json::json!({
        "name":"open-pkg", "dist-tags":{"latest":"1.0.0"},
        "versions":{"1.0.0":{"name":"open-pkg","version":"1.0.0","dist":{"tarball":"https://npm.invalid/open-pkg/-/open-pkg-1.0.0.tgz",
            "integrity":format!("sha256-{}", common::sync::base64(Sha256::digest(b"open bytes")))}}},
        "time":{"1.0.0":"2026-01-01T00:00:00Z"}
    }).to_string()));
    registry.answer(&common::npm_artifact_upstream_path("open-pkg", "open-pkg-1.0.0.tgz"), FakeAnswer::Body("open bytes".into()));
    let dir = tempfile::tempdir().unwrap();
    let mut config = config_with_open_blocklist(dir.path());
    config.service_policy = Some(ServicePolicyConfig {
        server_url: policy_server.uri().parse().unwrap(),
        service_key_file: "/test/key".into(),
        service_key: FirewallToken::new("prb_01234567890123456789012345678901".into()),
        sync_interval_seconds: std::num::NonZeroU64::new(60).unwrap(),
        trusted_proxies: vec![],
    });
    let transport = Arc::new(PrivateArtifacts(registry, Mutex::new(Vec::new())));
    let server = TestServer::start_with_upstream(
        config, TestClock::at_rfc3339("2026-04-06T12:00:00Z").shared(),
        Arc::clone(&transport) as Arc<dyn Transport>, fake_origins(),
    ).await;
    let data = server.app().config.data_dir.clone();
    let document: serde_json::Value = serde_json::from_str(&server.get("/registry/npm/3/secret-pkg").await.text().await.unwrap()).unwrap();
    let artifact = reqwest::Url::parse(document["versions"]["1.0.0"]["dist"]["tarball"].as_str().unwrap()).unwrap().path().to_owned();

    // Credential A fetches the bytes.
    let a = server.get_with_headers(&artifact, &[("authorization", "Bearer allowed")]).await;
    assert_eq!((a.status(), a.text().await.unwrap().as_str()), (StatusCode::OK, "secret bytes"));
    assert!(files_under(&data.join("content")).is_empty(), "a credential-bearing body never enters the shared content store");
    assert!(files_under(&data.join("credential-reads")).is_empty(), "the request-owned temporary file is gone");
    // A caller without the credential performs its own upstream request and is refused.
    let none = server.get(&artifact).await;
    assert_eq!(none.status(), StatusCode::FORBIDDEN, "bytes fetched under credential A are never served without it");
    assert_eq!(transport.1.lock().unwrap().last().cloned().flatten(), None, "the credential-less caller reached upstream with no credential");
    // Credential B is judged by upstream, not by A's grant.
    assert_eq!(server.get_with_headers(&artifact, &[("authorization", "Bearer other")]).await.status(), StatusCode::FORBIDDEN);
    // An unlisted header makes the read request-scoped even with no Authorization.
    let before = transport.1.lock().unwrap().len();
    server.get_with_headers(&artifact, &[("x-probe-unknown", "1")]).await;
    assert_eq!(transport.1.lock().unwrap().len(), before + 1, "the unknown-header read performed its own upstream request");

    // Control: a header-only-allow-list read still uses the shared cache (one upstream
    // transfer for two requests), so the bypass costs nothing for eligible reads.
    let open: serde_json::Value = serde_json::from_str(&server.get("/registry/npm/3/open-pkg").await.text().await.unwrap()).unwrap();
    let open_path = reqwest::Url::parse(open["versions"]["1.0.0"]["dist"]["tarball"].as_str().unwrap()).unwrap().path().to_owned();
    let before = transport.1.lock().unwrap().len();
    assert_eq!(server.get(&open_path).await.text().await.unwrap(), "open bytes");
    assert_eq!(server.get(&open_path).await.text().await.unwrap(), "open bytes");
    assert_eq!(transport.1.lock().unwrap().len(), before + 1, "two eligible reads, one transfer");

    // PyPI: the same artifact path, so the same guarantee for a wheel.
    let wheel = "secret_proj-1.0.0-py3-none-any.whl";
    transport.0.answer(&common::pypi_upstream_path("secret-proj"), FakeAnswer::Body(serde_json::json!({
        "meta":{"api-version":"1.1"}, "name":"secret-proj", "files":[{
            "filename": wheel, "url": format!("https://files.invalid/packages/{wheel}"),
            "hashes":{"sha256": hex::encode(Sha256::digest(b"secret wheel"))}, "upload-time":"2026-01-01T00:00:00Z"
        }]
    }).to_string()));
    transport.0.answer(&format!("/packages/{wheel}"), FakeAnswer::Body("secret wheel".into()));
    let index = server.get_with_headers("/registry/pypi/4/simple/secret-proj/", &[("accept", "application/vnd.pypi.simple.v1+json")]).await;
    let index: serde_json::Value = serde_json::from_str(&index.text().await.unwrap()).unwrap();
    let wheel_path = reqwest::Url::parse(index["files"][0]["url"].as_str().unwrap()).unwrap().path().to_owned();
    // The caller's credential is never sent to PyPI's separate files host, but the request
    // is still credential-bearing: its body must not enter the shared store.
    let before = files_under(&data.join("content")).len();
    let a = server.get_with_headers(&wheel_path, &[("authorization", "Bearer allowed")]).await;
    assert_eq!((a.status(), a.text().await.unwrap().as_str()), (StatusCode::OK, "secret wheel"));
    assert_eq!(files_under(&data.join("content")).len(), before, "no PyPI credential-bearing body in the shared store");
    assert!(files_under(&data.join("credential-reads")).is_empty());
}

/// A server in shared-service mode over the two-registry fixture above.
async fn service_server() -> (TestServer, Arc<PrivateArtifacts>, MockServer) {
    service_server_with(0).await
}

async fn service_server_with(freeze: u64) -> (TestServer, Arc<PrivateArtifacts>, MockServer) {
    service_server_full(freeze, false).await
}

async fn service_server_full(freeze: u64, slow: bool) -> (TestServer, Arc<PrivateArtifacts>, MockServer) {
    let policy_server = MockServer::start().await;
    Mock::given(method("GET")).and(path("/api/v1/policy/snapshot"))
        .respond_with(ResponseTemplate::new(200).set_body_json(service_snapshot_with(freeze, slow)))
        .mount(&policy_server).await;
    let registry = FakeRegistry::new();
    registry.answer(&npm_upstream_path("open-pkg"), FakeAnswer::Body(serde_json::json!({
        "name":"open-pkg", "dist-tags":{"latest":"1.0.0"},
        "versions":{"1.0.0":{"name":"open-pkg","version":"1.0.0","dist":{"tarball":"https://npm.invalid/open-pkg/-/open-pkg-1.0.0.tgz",
            "integrity":format!("sha256-{}", common::sync::base64(Sha256::digest(b"open bytes")))}}},
        "time":{"1.0.0":"2026-01-01T00:00:00Z"}
    }).to_string()));
    registry.answer(&common::pypi_upstream_path("open-proj"), FakeAnswer::Body(serde_json::json!({
        "meta":{"api-version":"1.1"}, "name":"open-proj", "files":[{
            "filename": "open_proj-1.0.0-py3-none-any.whl", "url": "https://files.invalid/packages/open_proj-1.0.0-py3-none-any.whl",
            "hashes":{"sha256": hex::encode(Sha256::digest(b"w"))}, "upload-time":"2026-01-01T00:00:00Z"
        }]
    }).to_string()));
    registry.answer("/specs.4.8.gz", FakeAnswer::Bytes(std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/rubygems/full-index-slice.4.8.gz")).unwrap()));
    registry.answer("/api/v1/timeframe_versions.json", FakeAnswer::Body("[]".to_owned()));
    registry.answer("/config.json", FakeAnswer::Body(r#"{"dl":"https://static.crates.io/crates"}"#.to_owned()));
    registry.answer("/op/en/open-crate", FakeAnswer::Body(format!(
        r#"{{"name":"open-crate","vers":"1.0.0","deps":[],"cksum":"{}","features":{{}},"yanked":false,"pubtime":"2025-01-01T00:00:00Z"}}"#, hex::encode(Sha256::digest(b"c"))
    ) + "\n"));
    registry.answer("/crates/open-crate/1.0.0/download", FakeAnswer::Bytes(b"c".to_vec()));
    for module in ["open.example/mod", "secret.example/mod"] {
        registry.answer(&format!("/{module}/@v/list"), FakeAnswer::Body("v1.0.0\n".to_owned()));
        registry.answer(&format!("/{module}/@v/v1.0.0.info"), FakeAnswer::Body(r#"{"Version":"v1.0.0","Time":"2025-01-01T00:00:00Z"}"#.to_owned()));
        registry.answer(&format!("/{module}/@v/v1.0.0.mod"), FakeAnswer::Body(format!("module {module}\n")));
        registry.answer(&format!("/{module}/@v/v1.0.0.zip"), FakeAnswer::Bytes(format!("zip of {module}").into_bytes()));
    }
    registry.answer("/latest", FakeAnswer::Body("go.sum database tree\n".to_owned()));
    // NuGet (row 20): two packages, one of whose files need the caller's own credential.
    registry.answer("/v3/index.json", FakeAnswer::Body(common::nuget::service_index(&[])));
    for id in ["open.pkg", "secret.pkg"] {
        registry.answer(&format!("/v3-flatcontainer/{id}/index.json"), FakeAnswer::Body(common::nuget::flat_index(&["1.0.0"])));
        let (index, _) = common::nuget::registration(id, &[vec![common::nuget::leaf(id, "1.0.0", Some("2025-01-01T00:00:00.000+00:00"), true)]], &[]);
        registry.answer(&format!("/v3/registration5-gz-semver2/{id}/index.json"), FakeAnswer::Body(index));
        registry.answer(&format!("/v3-flatcontainer/{id}/1.0.0/{id}.1.0.0.nupkg"), FakeAnswer::Bytes(format!("nupkg of {id}").into_bytes()));
        registry.answer(&format!("/v3-flatcontainer/{id}/1.0.0/{id}.nuspec"), FakeAnswer::Body(common::nuget::nuspec(id, "1.0.0")));
        registry.answer(&format!("/v3-flatcontainer/{id}/1.0.0/readme"), FakeAnswer::Body("readme".to_owned()));
        registry.answer(&format!("/v3-flatcontainer/{id}/1.0.0/icon"), FakeAnswer::Bytes(b"icon".to_vec()));
    }
    // Maven (row 21): two artifacts, one of whose files need the caller's own credential.
    for name in ["open", "secret"] {
        registry.answer(&format!("/maven2/org/{name}/pkg/maven-metadata.xml"), FakeAnswer::Body(common::maven::metadata(&format!("org.{name}"), "pkg", "1.0", "1.0", &["1.0"])));
        let dated = |body: Vec<u8>| FakeAnswer::Dated { body, last_modified: common::maven::http_date("2025-01-01T00:00:00Z") };
        registry.answer(&format!("/maven2/org/{name}/pkg/1.0/pkg-1.0.pom"), dated(common::maven::pom(&format!("org.{name}"), "pkg", "1.0").into_bytes()));
        registry.answer(&format!("/maven2/org/{name}/pkg/1.0/pkg-1.0.jar"), dated(format!("jar of {name}").into_bytes()));
    }
    // Conan (row 23): two recipes, one of whose files need the caller's own credential.
    for name in ["open", "secret"] {
        common::conan::serve_recipe(&registry, name, "1.0", &[("aaaa0000000000000000000000000001", "2025-01-01T00:00:00Z")]);
    }
    registry.answer("/gems/open-gem-1.0.0.gem", FakeAnswer::Bytes(b"g".to_vec()));
    // A gem whose real name has capitals: files are case-exact upstream (N2).
    registry.answer("/gems/Open-Gem-1.0.0.gem", FakeAnswer::Bytes(b"g".to_vec()));
    registry.answer("/info/Open-Gem", FakeAnswer::Body(format!(
        "---\n1.0.0 |checksum:{},created_at:2025-01-01T00:00:00Z\n", hex::encode(Sha256::digest(b"g"))
    )));
    registry.answer("/info/open-gem", FakeAnswer::Body(format!(
        "---\n1.0.0 |checksum:{},created_at:2025-01-01T00:00:00Z\n", hex::encode(Sha256::digest(b"g"))
    )));
    let dir = tempfile::tempdir().unwrap();
    let mut config = config_with_open_blocklist(dir.path());
    config.service_policy = Some(ServicePolicyConfig {
        server_url: policy_server.uri().parse().unwrap(),
        service_key_file: "/test/key".into(),
        service_key: FirewallToken::new("prb_01234567890123456789012345678901".into()),
        sync_interval_seconds: std::num::NonZeroU64::new(60).unwrap(),
        trusted_proxies: vec![],
    });
    let transport = Arc::new(PrivateArtifacts(registry, Mutex::new(Vec::new())));
    let server = TestServer::start_with_upstream(
        config, TestClock::at_rfc3339("2026-04-06T12:00:00Z").shared(),
        Arc::clone(&transport) as Arc<dyn Transport>,
        fake_origins()
            .with_nuget(url::Url::parse(common::nuget::INDEX_ORIGIN).unwrap(), url::Url::parse(common::nuget::SEARCH_ORIGIN).unwrap(), url::Url::parse(common::nuget::PUBLISH_ORIGIN).unwrap())
            .with_maven(url::Url::parse(common::maven::REPO).unwrap(), url::Url::parse(common::maven::PUBLISH).unwrap())
            .with_conan(url::Url::parse(common::conan::REMOTE).unwrap(), url::Url::parse(common::conan::PUBLISH).unwrap()),
    ).await;
    (server, transport, policy_server)
}

/// Row 17, the RubyGems case of S28-1 through the same seam (C1028): the compact index of a
/// gem read under any credential carrier leaves no entry in a shared cache, and the same
/// read without one is served (and the control: it does populate the cache).
#[tokio::test]
async fn credential_bearing_read_never_enters_shared_caches_rubygems_end_to_end() {
    use probation::store::cache::ProjectKey;
    let carriers: &[(&str, &[(&str, &str)])] = &[
        ("authorization", &[("authorization", "Bearer allowed")]),
        ("basic", &[("authorization", "Basic dXNlcjpwdw==")]),
        ("cookie", &[("cookie", "session=1")]),
        ("x-jfrog-art-api", &[("x-jfrog-art-api", "k")]),
        ("unknown header", &[("x-probe-unknown", "1")]),
    ];
    for (carrier, headers) in carriers {
        let (server, _transport, _policy) = service_server().await;
        let key = ProjectKey::in_registry(5, probation_policy::Ecosystem::RubyGems, "open-gem");
        let response = server.get_with_headers("/registry/rubygems/5/info/open-gem", headers).await;
        assert_eq!(response.status(), StatusCode::OK, "{carrier}");
        assert!(response.text().await.unwrap().contains("1.0.0"), "{carrier}");
        let caches = server.app();
        let store = caches.store().caches();
        assert!(store.projects.get(&key).is_none(), "{carrier}: project snapshot cache is empty");
        assert!(store.absent.get(&key).is_none(), "{carrier}: refusal cache is empty");
    }
    // Control: the same read with only allow-listed headers is served too (the shared-service
    // path refreshes per request and never reuses one caller's snapshot, so for every carrier
    // the cache stays empty; the allow-list decision itself is witnessed by
    // `credential_bearing_read_never_enters_shared_caches_rubygems`).
    let (server, _transport, _policy) = service_server().await;
    assert_eq!(server.get_with_headers("/rubygems/info/open-gem", &[("accept", "*/*")]).await.status(), StatusCode::OK);
    // The gem file through the shared service (the root `/rubygems` is rewritten to the selected
    // registry): delivered verified, and a credential-bearing read of it stays out of the shared store.
    let data = server.app().config.data_dir.clone();
    let before = files_under(&data.join("content")).len();
    let gem = server.get_with_headers("/rubygems/gems/open-gem-1.0.0.gem", &[("authorization", "Bearer allowed")]).await;
    assert_eq!((gem.status(), gem.bytes().await.unwrap().as_ref()), (StatusCode::OK, b"g".as_slice()));
    assert_eq!(files_under(&data.join("content")).len(), before, "no credential-bearing gem body in the shared store");
    assert!(files_under(&data.join("credential-reads")).is_empty());
    // Positive control for the metadata caches, which the per-gem snapshot cannot give in service
    // mode (it never caches there): the filtered tuple index IS cached, for an allow-listed read
    // and only for one. Two plain reads cost one upstream fetch; two credential-bearing reads two.
    let fetches = |transport: &PrivateArtifacts| transport.0.calls().iter().filter(|u| u.path() == "/specs.4.8.gz").count();
    for _ in 0..2 {
        assert_eq!(server.get_with_headers("/rubygems/specs.4.8.gz", &[("accept", "*/*")]).await.status(), StatusCode::OK);
    }
    assert_eq!(fetches(&_transport), 1, "an allow-listed index read is served from the shared cache");
    for _ in 0..2 {
        assert_eq!(server.get_with_headers("/rubygems/specs.4.8.gz", &[("authorization", "Bearer allowed")]).await.status(), StatusCode::OK);
    }
    assert_eq!(fetches(&_transport), 3, "a credential-bearing index read never reads or fills the shared cache");
    // And a read that carries only what RubyGems clients send (the family allow-list adds
    // `keep-alive`) is cache-eligible: its verified body enters the shared content store.
    let eligible = server.get_with_headers("/rubygems/gems/open-gem-1.0.0.gem", &[("keep-alive", "30")]).await;
    assert_eq!(eligible.status(), StatusCode::OK);
    assert!(files_under(&data.join("content")).len() > before, "an allow-listed read is cached");
}

/// Row 18, C1028 for Cargo through the row 28 seam (shared service): the rewritten `config.json`
/// and the crate archive of a credential-bearing read never enter a shared cache; the same reads
/// with only allow-listed headers do (config cached, archive stored).
#[tokio::test]
async fn credential_bearing_read_never_enters_shared_caches_cargo_end_to_end() {
    let (server, transport, _policy) = service_server().await;
    let fetches = |path: &str| transport.0.calls().iter().filter(|u| u.path() == path).count();
    for _ in 0..2 {
        assert_eq!(server.get_with_headers("/cargo/config.json", &[("accept", "*/*")]).await.status(), StatusCode::OK);
    }
    assert_eq!(fetches("/config.json"), 1, "an allow-listed read shares the cached upstream config");
    for (n, carrier) in [("authorization", "cio_token"), ("authorization", "Bearer allowed"), ("cookie", "s=1"), ("x-jfrog-art-api", "k"), ("x-probe-unknown", "1")].into_iter().enumerate() {
        let before = fetches("/config.json");
        let response = server.get_with_headers("/registry/cargo/7/config.json", &[carrier]).await;
        assert_eq!(response.status(), StatusCode::OK, "{carrier:?}");
        assert_eq!(fetches("/config.json"), before + 1, "carrier {n} {carrier:?}: a credential-bearing read fetches its own config and fills nothing");
    }
    assert_eq!(fetches("/config.json"), 6);
    // The index of the crate through the service is never cached either way; with a credential the
    // archive stays out of the shared content store.
    let data = server.app().config.data_dir.clone();
    let before = files_under(&data.join("content")).len();
    let crate_file = server.get_with_headers("/cargo/crates/open-crate/1.0.0/download", &[("authorization", "cio_token")]).await;
    assert_eq!((crate_file.status(), crate_file.bytes().await.unwrap().as_ref()), (StatusCode::OK, b"c".as_slice()));
    assert_eq!(files_under(&data.join("content")).len(), before, "no credential-bearing crate body in the shared store");
    assert!(files_under(&data.join("credential-reads")).is_empty());
    let eligible = server.get_with_headers("/cargo/crates/open-crate/1.0.0/download", &[("accept", "*/*")]).await;
    assert_eq!(eligible.status(), StatusCode::OK);
    assert!(files_under(&data.join("content")).len() > before, "an allow-listed read is cached");
    // Paths that embed a credential in a route this firewall does not have reach nothing.
    let calls = transport.0.calls().len();
    for path in ["/cargo/se/rd/serde;token=abc", "/cargo/tok3n@host/se/rd/serde", "/cargo/%40token/config.json"] {
        assert_eq!(server.get(path).await.status(), StatusCode::NOT_FOUND, "{path}");
    }
    assert_eq!(transport.0.calls().len(), calls, "no upstream call for a path-embedded credential form");
}

/// Row 19, C1028 for Go through the row 28 seam (shared service): the version table of a
/// credential-bearing read is never read or filled, its zip never enters the shared content store, the
/// checksum database never receives the caller's credential, and the same reads with only allow-listed
/// headers do share (control).
#[tokio::test]
async fn credential_bearing_read_never_enters_shared_caches_go_end_to_end() {
    let (server, transport, _policy) = service_server().await;
    let info_calls = |module: &str| transport.0.calls().iter().filter(|u| u.path() == format!("/{module}/@v/v1.0.0.info")).count();
    // Plain reads share the version memory.
    for _ in 0..2 {
        assert_eq!(server.get_with_headers("/go/open.example/mod/@v/v1.0.0.mod", &[("accept", "*/*")]).await.status(), StatusCode::OK);
    }
    assert_eq!(info_calls("open.example/mod"), 1, "an allow-listed read shares the confirmed version");
    for (n, carrier) in [("authorization", "Basic dXNlcjpwdw=="), ("authorization", "Bearer allowed"), ("cookie", "s=1"), ("x-jfrog-art-api", "k"), ("x-probe-unknown", "1")].into_iter().enumerate() {
        let before = info_calls("open.example/mod");
        let response = server.get_with_headers("/registry/go/8/open.example/mod/@v/v1.0.0.mod", &[carrier]).await;
        assert_eq!(response.status(), StatusCode::OK, "{carrier:?}");
        // Three: the reference lookup, the membership check before the transfer and the one after it (SPEC §9)
        // each confirm the version for this request alone.
        assert_eq!(info_calls("open.example/mod"), before + 3, "carrier {n} {carrier:?}: a credential-bearing read confirms the version itself and fills nothing");
    }
    // Its zip never enters the shared store; the control read does.
    let data = server.app().config.data_dir.clone();
    let before = files_under(&data.join("content")).len();
    let zip = server.get_with_headers("/go/secret.example/mod/@v/v1.0.0.zip", &[("authorization", "Bearer allowed")]).await;
    assert_eq!((zip.status(), zip.bytes().await.unwrap().as_ref()), (StatusCode::OK, b"zip of secret.example/mod".as_slice()));
    assert_eq!(files_under(&data.join("content")).len(), before, "no credential-bearing module zip in the shared store");
    assert!(files_under(&data.join("credential-reads")).is_empty());
    assert_eq!(server.get("/go/secret.example/mod/@v/v1.0.0.zip").await.status(), StatusCode::FORBIDDEN, "bytes fetched under a credential are never served without it");
    let eligible = server.get_with_headers("/go/open.example/mod/@v/v1.0.0.zip", &[("accept", "*/*")]).await;
    assert_eq!(eligible.status(), StatusCode::OK);
    assert!(files_under(&data.join("content")).len() > before, "an allow-listed read is cached");
    // The checksum database is asked without the caller's credential, whatever the caller sent.
    for headers in [&[("authorization", "Bearer allowed")][..], &[("accept", "*/*")][..]] {
        assert_eq!(server.get_with_headers("/go/sumdb/sum.golang.org/latest", headers).await.status(), StatusCode::OK);
    }
    let seen = SUMDB_AUTH.lock().unwrap().clone();
    assert!(seen.len() >= 2 && seen.iter().all(Option::is_none), "{seen:?}");
    // Paths that embed a credential in a route this firewall does not have reach nothing.
    let calls = transport.0.calls().len();
    for path in ["/go/tok3n@host/example.com/m/@v/list", "/go/example.com/m;token=abc/@v/list", "/go/%40token/example.com/m/@latest"] {
        assert_eq!(server.get(path).await.status(), StatusCode::NOT_FOUND, "{path}");
    }
    assert_eq!(transport.0.calls().len(), calls, "no upstream call for a path-embedded credential form");
}

/// Row 20: C1028 for NuGet through the row 28 seam (shared service). A read that carries a credential
/// leaves nothing in a shared cache (no stored project, no service-index memory, no stored file), a file fetched
/// under a credential is never served without it, and the control read does populate the caches.
#[tokio::test]
async fn credential_bearing_read_never_enters_shared_caches_nuget_end_to_end() {
    let (server, transport, _policy) = service_server().await;
    let calls = |needle: &str| transport.0.calls().iter().filter(|u| u.path().ends_with(needle)).count();
    // Plain reads share one service index and one project for the share window.
    for _ in 0..2 {
        assert_eq!(server.get_with_headers("/nuget/v3-flatcontainer/open.pkg/index.json", &[("accept", "*/*")]).await.status(), StatusCode::OK);
    }
    assert_eq!(calls("/v3/index.json"), 1, "an allow-listed read shares the service index");
    assert_eq!(calls("/v3-flatcontainer/open.pkg/index.json"), 1, "and the project it just fetched");
    for (n, carrier) in [("authorization", "Basic dXNlcjpwdw=="), ("authorization", "Bearer allowed"), ("cookie", "s=1"), ("x-jfrog-art-api", "k"), ("x-probe-unknown", "1")].into_iter().enumerate() {
        let (index, flat) = (calls("/v3/index.json"), calls("/v3-flatcontainer/open.pkg/index.json"));
        let response = server.get_with_headers("/registry/nuget/9/v3-flatcontainer/open.pkg/index.json", &[carrier]).await;
        assert_eq!(response.status(), StatusCode::OK, "{carrier:?}");
        assert_eq!((calls("/v3/index.json"), calls("/v3-flatcontainer/open.pkg/index.json")), (index + 1, flat + 1), "carrier {n} {carrier:?}: a credential-bearing read reads and fills nothing shared");
    }
    // Its file never enters the shared store; the control read does.
    let data = server.app().config.data_dir.clone();
    let before = files_under(&data.join("content")).len();
    let nupkg = server.get_with_headers("/nuget/v3-flatcontainer/secret.pkg/1.0.0/secret.pkg.1.0.0.nupkg", &[("authorization", "Bearer allowed")]).await;
    assert_eq!((nupkg.status(), nupkg.bytes().await.unwrap().as_ref()), (StatusCode::OK, b"nupkg of secret.pkg".as_slice()));
    assert_eq!(files_under(&data.join("content")).len(), before, "no credential-bearing package in the shared store");
    assert!(files_under(&data.join("credential-reads")).is_empty());
    assert_eq!(server.get("/nuget/v3-flatcontainer/secret.pkg/1.0.0/secret.pkg.1.0.0.nupkg").await.status(), StatusCode::FORBIDDEN, "bytes fetched under a credential are never served without it");
    let eligible = server.get_with_headers("/nuget/v3-flatcontainer/open.pkg/1.0.0/open.pkg.1.0.0.nupkg", &[("accept", "*/*")]).await;
    assert_eq!(eligible.status(), StatusCode::OK);
    assert!(files_under(&data.join("content")).len() > before, "an allow-listed read is cached");
    // Paths that embed a credential in a route this firewall does not have reach nothing.
    let asked = transport.0.calls().len();
    for path in ["/nuget/tok3n@host/v3/index.json", "/nuget/v3/index.json;token=abc", "/nuget/%40token/v3-flatcontainer/a/index.json"] {
        assert_eq!(server.get(path).await.status(), StatusCode::NOT_FOUND, "{path}");
    }
    assert_eq!(transport.0.calls().len(), asked, "no upstream call for a path-embedded credential form");
}

/// Row 21: C1028 for Maven through the row 28 seam (shared service). A read that carries a credential leaves nothing in a shared
/// cache (no shared document, no unit table entry, no stored file), a file fetched under a credential is never served without it,
/// and the control read does populate the caches.
#[tokio::test]
async fn credential_bearing_read_never_enters_shared_caches_maven_end_to_end() {
    let (server, transport, _policy) = service_server().await;
    let calls = |needle: &str| transport.0.calls().iter().filter(|u| u.path().ends_with(needle)).count();
    for _ in 0..2 {
        assert_eq!(server.get_with_headers("/maven/org/open/pkg/maven-metadata.xml", &[("accept", "*/*")]).await.status(), StatusCode::OK);
    }
    assert_eq!(calls("/org/open/pkg/maven-metadata.xml"), 1, "an allow-listed read shares the document it just fetched");
    for (n, carrier) in [("authorization", "Basic dXNlcjpwdw=="), ("authorization", "Bearer allowed"), ("cookie", "s=1"), ("x-jfrog-art-api", "k"), ("x-probe-unknown", "1")].into_iter().enumerate() {
        let before = calls("/org/open/pkg/maven-metadata.xml");
        let response = server.get_with_headers("/registry/maven/10/org/open/pkg/maven-metadata.xml", &[carrier]).await;
        assert_eq!(response.status(), StatusCode::OK, "{carrier:?}");
        assert_eq!(calls("/org/open/pkg/maven-metadata.xml"), before + 1, "carrier {n} {carrier:?}: a credential-bearing read reads and fills nothing shared");
    }
    // Its file never enters the shared store; the control read does.
    let data = server.app().config.data_dir.clone();
    let before = files_under(&data.join("content")).len();
    let jar = server.get_with_headers("/maven/org/secret/pkg/1.0/pkg-1.0.jar", &[("authorization", "Bearer allowed")]).await;
    assert_eq!((jar.status(), jar.bytes().await.unwrap().as_ref()), (StatusCode::OK, b"jar of secret".as_slice()));
    assert_eq!(files_under(&data.join("content")).len(), before, "no credential-bearing artifact in the shared store");
    assert!(files_under(&data.join("credential-reads")).is_empty());
    assert_eq!(server.get("/maven/org/secret/pkg/1.0/pkg-1.0.jar").await.status(), StatusCode::FORBIDDEN, "bytes fetched under a credential are never served without it");
    let eligible = server.get_with_headers("/maven/org/open/pkg/1.0/pkg-1.0.jar", &[("accept", "*/*")]).await;
    assert_eq!(eligible.status(), StatusCode::OK);
    assert!(files_under(&data.join("content")).len() > before, "an allow-listed read is cached");
    // Path-embedded credential forms are no route and reach nothing.
    let asked = transport.0.calls().len();
    for path in ["/maven/tok3n@host/org/open/pkg/maven-metadata.xml", "/maven/org/open/pkg/maven-metadata.xml;token=abc", "/maven/%40token/org/open/pkg/maven-metadata.xml", "/maven/org/open/pkg/1.0/pkg-1.0.jar?access_token=abc"] {
        let status = server.get(path).await.status();
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
    }
    assert_eq!(transport.0.calls().len(), asked, "no upstream call for a path-embedded credential form");
}

/// Row 23: C1028 for Conan through the row 28 seam (shared service). A read that carries a credential leaves nothing in a shared
/// cache (no unit table entry, no stored file), a file fetched under a credential is never served without it, and the control read
/// does populate the caches.
#[tokio::test]
async fn credential_bearing_read_never_enters_shared_caches_conan_end_to_end() {
    let (server, transport, _policy) = service_server().await;
    let calls = |needle: &str| transport.0.calls().iter().filter(|u| u.path().ends_with(needle)).count();
    let rev = "aaaa0000000000000000000000000001";
    let revisions = "/v2/conans/open/1.0/_/_/revisions";
    for _ in 0..2 {
        assert_eq!(server.get_with_headers(&format!("/conan{revisions}"), &[("accept", "*/*")]).await.status(), StatusCode::OK);
    }
    assert_eq!(calls(revisions), 1, "an allow-listed read keeps what it learned: the second one asks nothing for the same unit");
    for (n, carrier) in [("authorization", "Basic dXNlcjpwdw=="), ("authorization", "Bearer allowed"), ("cookie", "s=1"), ("x-jfrog-art-api", "k"), ("x-probe-unknown", "1")].into_iter().enumerate() {
        let before = calls(revisions);
        let response = server.get_with_headers(&format!("/registry/conan/11{revisions}"), &[carrier]).await;
        assert_eq!(response.status(), StatusCode::OK, "{carrier:?}");
        assert_eq!(calls(revisions), before + 1, "carrier {n} {carrier:?}: a credential-bearing read reads and fills nothing shared");
    }
    // Its file never enters the shared store; the control read does.
    let data = server.app().config.data_dir.clone();
    let before = files_under(&data.join("content")).len();
    let secret = format!("/conan/v2/conans/secret/1.0/_/_/revisions/{rev}/files/conan_export.tgz");
    let file = server.get_with_headers(&secret, &[("authorization", "Bearer allowed")]).await;
    assert_eq!(file.status(), StatusCode::OK);
    assert_eq!(files_under(&data.join("content")).len(), before, "no credential-bearing artifact in the shared store");
    assert!(files_under(&data.join("credential-reads")).is_empty());
    assert_eq!(server.get(&secret).await.status(), StatusCode::FORBIDDEN, "bytes fetched under a credential are never served without it");
    let eligible = server.get_with_headers(&format!("/conan/v2/conans/open/1.0/_/_/revisions/{rev}/files/conan_export.tgz"), &[("accept", "*/*")]).await;
    assert_eq!(eligible.status(), StatusCode::OK);
    assert!(files_under(&data.join("content")).len() > before, "an allow-listed read is cached");
    // Path-embedded credential forms are no route and reach nothing.
    let asked = transport.0.calls().len();
    for path in ["/conan/tok3n@host/v2/conans/open/1.0/_/_/revisions", "/conan/v2/conans/open/1.0/_/_/revisions;token=abc", "/conan/%40token/v2/conans/open/1.0/_/_/revisions", "/conan/v2/conans/open/1.0/_/_/latest?access_token=abc", "/conan/v2/conans/open/1.0/_/_/revisions/tok3n@host/files"] {
        let status = server.get(path).await.status();
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
    }
    assert_eq!(transport.0.calls().len(), asked, "no upstream call for a path-embedded credential form");
}

/// Row 18: through the shared service Cargo's index and archives are reads only. Its registry API is
/// forwarded by its own routes (tests/cargo_service_write.rs); every other write verb or path is refused
/// and reaches nothing upstream; a query string on a read route is no route.
#[tokio::test]
async fn cargo_is_read_only_through_the_shared_service() {
    let (server, transport, _policy) = service_server().await;
    let calls = transport.0.calls().len();
    let client = reqwest::Client::new();
    for (method, path) in [
        ("POST", "/cargo/api/v1/crates/new"),
        ("PUT", "/cargo/api/v1/crates/open-crate/1.0.0/yank"),
        ("DELETE", "/registry/cargo/7/api/v1/crates/open-crate/1.0.0/unyank"),
        ("POST", "/registry/cargo/7/op/en/open-crate"),
        ("DELETE", "/cargo/crates/open-crate/1.0.0/download"),
        ("PUT", "/cargo/config.json"),
    ] {
        let response = client.request(method.parse().unwrap(), server.url(path)).body("x").send().await.unwrap();
        assert!(matches!(response.status(), StatusCode::METHOD_NOT_ALLOWED | StatusCode::NOT_FOUND), "{method} {path}: {}", response.status());
    }
    assert_eq!(server.get("/cargo/config.json?x=1").await.status(), StatusCode::NOT_FOUND);
    assert_eq!(transport.0.calls().len(), calls, "nothing reached upstream");
    // The control: the same family's reads work.
    assert_eq!(server.get("/cargo/config.json").await.status(), StatusCode::OK);
}

/// S28-1: one case per carrier on the metadata routes: afterwards no shared metadata,
/// project or refusal cache holds an entry for that project, whatever the request carried.
#[tokio::test]
async fn credential_bearing_metadata_read_never_enters_shared_caches() {
    use probation::store::cache::ProjectKey;
    let carriers: &[(&str, &[(&str, &str)])] = &[
        ("authorization", &[("authorization", "Bearer allowed")]),
        ("cookie", &[("cookie", "session=1")]),
        ("x-nuget-apikey", &[("x-nuget-apikey", "k")]),
        ("x-jfrog-art-api", &[("x-jfrog-art-api", "k")]),
        ("unknown header", &[("x-probe-unknown", "1")]),
    ];
    for (carrier, headers) in carriers {
        let (server, _transport, _policy) = service_server().await;
        let caches = server.app();
        let npm_key = ProjectKey::in_registry(3, probation_policy::Ecosystem::Npm, "open-pkg");
        let pypi_key = ProjectKey::in_registry(4, probation_policy::Ecosystem::PyPi, "open-proj");
        let mut npm_headers = headers.to_vec();
        npm_headers.push(("accept", "application/json"));
        assert_eq!(server.get_with_headers("/registry/npm/3/open-pkg", &npm_headers).await.status(), StatusCode::OK, "{carrier}");
        let mut pypi_headers = headers.to_vec();
        pypi_headers.push(("accept", "application/vnd.pypi.simple.v1+json"));
        assert_eq!(server.get_with_headers("/registry/pypi/4/simple/open-proj/", &pypi_headers).await.status(), StatusCode::OK, "{carrier}");
        let store = caches.store().caches();
        assert!(store.projects.get(&npm_key).is_none() && store.projects.get(&pypi_key).is_none(), "{carrier}: project snapshot cache is empty");
        assert!(store.absent.get(&npm_key).is_none() && store.absent.get(&pypi_key).is_none(), "{carrier}: refusal cache is empty");
        assert_eq!(store.rendered.len(), 0, "{carrier}: rendered cache is empty");
    }
}

/// R28-5: an upstream refusal of an artifact has its own code, distinct from a policy BLOCKED.
#[tokio::test]
async fn artifact_upstream_401_and_403_have_their_own_codes() {
    let (server, transport, _policy) = service_server().await;
    let registry = &transport.0;
    for name in ["login-pkg", "secret-pkg"] {
        registry.answer(&npm_upstream_path(name), FakeAnswer::Body(serde_json::json!({
            "name": name, "dist-tags":{"latest":"1.0.0"},
            "versions":{"1.0.0":{"name":name,"version":"1.0.0","dist":{"tarball":format!("https://npm.invalid/{name}/-/{name}-1.0.0.tgz"),
                "integrity":format!("sha256-{}", common::sync::base64(Sha256::digest(b"bytes")))}}},
            "time":{"1.0.0":"2026-01-01T00:00:00Z"}
        }).to_string()));
        registry.answer(&common::npm_artifact_upstream_path(name, &format!("{name}-1.0.0.tgz")), FakeAnswer::Body("bytes".into()));
    }
    let tarball = |name: &str| format!("/registry/npm/3/{name}/-/{name}-1.0.0.tgz");
    let mut seen = Vec::new();
    for (name, headers) in [("login-pkg", vec![]), ("secret-pkg", vec![("authorization", "Bearer wrong")])] {
        let document: serde_json::Value = serde_json::from_str(&server.get_with_headers(&format!("/registry/npm/3/{name}"), &headers).await.text().await.unwrap()).unwrap();
        let artifact = reqwest::Url::parse(document["versions"]["1.0.0"]["dist"]["tarball"].as_str().unwrap()).unwrap().path().to_owned();
        let _ = tarball(name);
        let answer = server.get_with_headers(&artifact, &headers).await;
        let status = answer.status();
        let body: serde_json::Value = serde_json::from_str(&answer.text().await.unwrap()).unwrap();
        seen.push((status.as_u16(), body["error"].as_str().unwrap().to_owned()));
    }
    assert_eq!(seen[0], (401, "UPSTREAM_AUTHENTICATION_REQUIRED".to_owned()), "upstream 401");
    assert_eq!(seen[1], (403, "UPSTREAM_DENIED".to_owned()), "upstream 403 is not a policy BLOCKED");
}

/// N1: the metadata, token-packument and named-read upstream 401/403 carry the same distinct
/// codes as artifacts (statuses unchanged), never a Probation key error or a policy BLOCKED.
#[tokio::test]
async fn metadata_upstream_401_and_403_have_their_own_codes() {
    let (server, _transport, _policy) = service_server().await;
    let code = |answer: reqwest::Response| async move {
        let status = answer.status().as_u16();
        let body: serde_json::Value = serde_json::from_str(&answer.text().await.unwrap()).unwrap();
        (status, body["error"].as_str().unwrap_or_default().to_owned())
    };
    let login = (401, "UPSTREAM_AUTHENTICATION_REQUIRED".to_owned());
    let denied = (403, "UPSTREAM_DENIED".to_owned());
    // npm packument (src/npm/mod.rs) and PyPI index (src/pypi/mod.rs).
    assert_eq!(code(server.get("/registry/npm/3/login-meta").await).await, login, "npm metadata 401");
    assert_eq!(code(server.get("/registry/npm/3/deny-meta").await).await, denied, "npm metadata 403");
    let simple = [("accept", "application/vnd.pypi.simple.v1+json")];
    assert_eq!(code(server.get_with_headers("/registry/pypi/4/simple/login-meta/", &simple).await).await, login, "pypi index 401");
    assert_eq!(code(server.get_with_headers("/registry/pypi/4/simple/deny-meta/", &simple).await).await, denied, "pypi index 403");
    // The developer-token packument read (src/http/token_packument.rs).
    assert_eq!(code(server.get_with_headers("/registry/npm/3/login-meta?write=true", &[("authorization", "Bearer token")]).await).await, login, "token packument 401");
    assert_eq!(code(server.get_with_headers("/registry/npm/3/deny-meta?write=true", &[("authorization", "Bearer token")]).await).await, denied, "token packument 403");
    // A named read (src/http/registry_routes.rs).
    assert_eq!(code(server.get_with_headers("/registry/npm/3/-/whoami", &[("authorization", "Bearer expired")]).await).await, login, "named read 401");
    assert_eq!(code(server.get_with_headers("/registry/npm/3/-/whoami", &[("authorization", "Bearer denied")]).await).await, denied, "named read 403");
}

/// Row 18: a Cargo registry that refuses the caller's credential at `config.json` or at an index
/// file is reported with the upstream codes, never as a policy refusal or a generic 502.
#[tokio::test]
async fn cargo_upstream_401_and_403_have_their_own_codes() {
    let (server, _transport, _policy) = service_server().await;
    let code = |answer: reqwest::Response| async move {
        let status = answer.status().as_u16();
        let body: serde_json::Value = serde_json::from_str(&answer.text().await.unwrap()).unwrap();
        (status, body["error"].as_str().unwrap_or_default().to_owned())
    };
    let login = (401, "UPSTREAM_AUTHENTICATION_REQUIRED".to_owned());
    let denied = (403, "UPSTREAM_DENIED".to_owned());
    assert_eq!(code(server.get_with_headers("/registry/cargo/7/config.json", &[("authorization", "config-login")]).await).await, login, "config.json 401");
    assert_eq!(code(server.get_with_headers("/registry/cargo/7/config.json", &[("authorization", "config-deny")]).await).await, denied, "config.json 403");
    assert_eq!(code(server.get("/cargo/lo/gi/login-meta").await).await, login, "index file 401");
    assert_eq!(code(server.get("/cargo/de/ny/deny-meta").await).await, denied, "index file 403");
}

/// N2: outside any request context (a background task, a test) shared-service mode has no
/// classification, so no token is minted: fail closed. Other modes keep theirs.
#[tokio::test]
async fn cache_token_fails_closed_without_a_request_context_in_service_mode() {
    let (server, _transport, _policy) = service_server().await;
    assert!(probation::http::credential_read::cache_token(&server.app()).is_none());
    let standalone = TestServer::start().await;
    assert!(probation::http::credential_read::cache_token(&standalone.app()).is_some(), "standalone has no caller credential on reads");
}

/// N2 in shared-service mode: a gem with capitals is delivered under the client's spelling.
#[tokio::test]
async fn rubygems_mixed_case_gem_is_delivered_in_service_mode() {
    let (server, _transport, _policy) = service_server().await;
    let info = server.get("/rubygems/info/Open-Gem").await;
    assert_eq!(info.status(), StatusCode::OK);
    assert!(info.text().await.unwrap().contains("1.0.0"));
    let gem = server.get("/rubygems/gems/Open-Gem-1.0.0.gem").await;
    assert_eq!((gem.status(), gem.bytes().await.unwrap().as_ref()), (StatusCode::OK, b"g".as_slice()));
}

/// N5 (C1028): the recent-versions list obeys the credential rule of the index cache: a
/// credential-bearing index read neither reads nor fills it; two plain reads of two index files
/// share one list (the positive control).
#[tokio::test]
async fn rubygems_recent_versions_cache_is_never_read_or_filled_by_a_credential_bearing_read() {
    let timeframe = |transport: &PrivateArtifacts| transport.0.calls().iter().filter(|u| u.path() == "/api/v1/timeframe_versions.json").count();
    for (headers, expected) in [(&[("accept", "*/*")][..], 1usize), (&[("authorization", "Bearer allowed")][..], 2)] {
        let (server, transport, _policy) = service_server_with(7 * 86_400).await;
        for file in ["specs.4.8.gz", "latest_specs.4.8.gz"] {
            transport.0.answer(&format!("/{file}"), FakeAnswer::Bytes(std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/rubygems/full-index-slice.4.8.gz")).unwrap()));
            assert_eq!(server.get_with_headers(&format!("/rubygems/{file}"), headers).await.status(), StatusCode::OK);
        }
        assert_eq!(timeframe(&transport), expected, "{headers:?}");
    }
}

/// N3: one registry's slow recent-versions API stalls only that registry's index builds.
#[tokio::test]
async fn rubygems_slow_recent_list_of_one_registry_does_not_stall_another() {
    let (server, transport, _policy) = service_server_full(7 * 86_400, true).await;
    transport.0.answer("/specs.4.8.gz", FakeAnswer::Bytes(std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/rubygems/full-index-slice.4.8.gz")).unwrap()));
    let slow_url = server.url("/registry/rubygems/6/specs.4.8.gz");
    let slow = tokio::spawn(async move { reqwest::get(slow_url).await.unwrap().status() });
    while SLOW_ARRIVED.load(std::sync::atomic::Ordering::SeqCst) == 0 {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let other = tokio::time::timeout(std::time::Duration::from_secs(20), server.get("/registry/rubygems/5/specs.4.8.gz")).await;
    SLOW_GATE.add_permits(64);
    assert_eq!(other.expect("the other registry is not stalled behind the slow one").status(), StatusCode::OK);
    let _ = slow.await;
}

/// R3: credential-bearing index reads (which never read or fill the shared caches) queue behind a
/// small per-registry limit instead of each crawling the recent list at once.
#[tokio::test]
async fn rubygems_credential_bearing_index_reads_crawl_at_most_two_at_a_time() {
    let (server, transport, _policy) = service_server_with(7 * 86_400).await;
    transport.0.answer("/specs.4.8.gz", FakeAnswer::Bytes(std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/rubygems/full-index-slice.4.8.gz")).unwrap()));
    let gate = common::Gate::new();
    transport.0.answer("/api/v1/timeframe_versions.json", FakeAnswer::GatedMetadata { body: "[]".to_owned(), gate: Arc::clone(&gate) });
    let url = server.url("/rubygems/specs.4.8.gz");
    let mut tasks = Vec::new();
    for _ in 0..5 {
        let url = url.clone();
        tasks.push(tokio::spawn(async move { reqwest::Client::new().get(url).header("authorization", "Bearer allowed").send().await.unwrap().status() }));
    }
    gate.wait_until_reached().await;
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    let crawling = transport.0.calls().iter().filter(|u| u.path() == "/api/v1/timeframe_versions.json").count();
    assert_eq!(crawling, 2, "five credential-bearing reads, two crawls in flight");
    for _ in 0..16 {
        gate.release();
    }
    for task in tasks {
        assert_eq!(task.await.unwrap(), StatusCode::OK);
    }
}

/// Recheck N2: in the shared service a policy publication between a read's authorisation and its release (a new
/// snapshot, even one that changes nothing it needs) admits the read again under the new snapshot, for every family:
/// one publication is served, a change that keeps landing is reported as 503 after three admissions.
#[tokio::test]
async fn a_publication_between_authorisation_and_release_is_admitted_again_for_every_family() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let (server, _transport, _policy) = service_server().await;
    let gate = Arc::clone(&server.app().service_policy().expect("service mode").publication_gate);
    for path in ["/registry/npm/3/open-pkg", "/registry/pypi/4/simple/open-proj/", "/registry/rubygems/5/info/open-gem", "/cargo/config.json", "/go/open.example/mod/@v/list", "/go/open.example/mod/@v/v1.0.0.mod", "/nuget/v3-flatcontainer/open.pkg/index.json", "/nuget/v3-flatcontainer/open.pkg/1.0.0/open.pkg.nuspec", "/maven/org/open/pkg/maven-metadata.xml", "/maven/org/open/pkg/1.0/pkg-1.0.pom", "/conan/v2/conans/open/1.0/_/_/revisions", "/conan/v2/conans/open/1.0/_/_/revisions/aaaa0000000000000000000000000001/files/conanfile.py"] {
        // An artifact crosses two gates (its own receipt and the service layer's), so a count of publications is exact only for
        // metadata; 100 is "a change that keeps landing" for every route.
        for (publications, expected) in [(0usize, StatusCode::OK), (1, StatusCode::OK), (100, StatusCode::SERVICE_UNAVAILABLE)] {
            let left = Arc::new(AtomicUsize::new(publications));
            let (writer, counter) = (Arc::clone(&gate), Arc::clone(&left));
            gate.set_barrier(Arc::new(move || {
                if counter.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1)).is_ok() {
                    let writer = Arc::clone(&writer);
                    std::thread::spawn(move || writer.publish(|| ()).unwrap()).join().unwrap();
                }
            }));
            let answer = server.get(path).await;
            assert_eq!(answer.status(), expected, "{path}: {publications} publications between authorisation and release");
        }
    }
    gate.set_barrier(Arc::new(|| {}));
}
