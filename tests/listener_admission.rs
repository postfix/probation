//! Slice 28, LS-F10 / T1: listener admission.

use std::net::{IpAddr, SocketAddr};

mod common;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use common::{FakeRegistry, TestClock, TestServer, config_with_open_blocklist, fake_origins};
use probation::config::{Config, FirewallToken, ServicePolicyConfig};
use probation::upstream::Transport;
use probation_policy::{Layer, LayerKind, OsvSetting, PlaceRef, api::*};
use std::sync::Arc;
use tower::ServiceExt;
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::{method, path}};
use probation::http::listener_admission::{HostInput, host_matches, peer_admitted};
use url::Url;

fn public() -> Url {
    Url::parse("https://packages.example.test").unwrap()
}

fn host(header: &str) -> HostInput {
    HostInput { host_headers: vec![header.into()], ..HostInput::default() }
}

#[test]
fn listener_host_duplicate_headers_refused() {
    let input = HostInput { host_headers: vec!["packages.example.test".into(), "packages.example.test".into()], ..HostInput::default() };
    assert!(!host_matches(&public(), &input), "exactly one Host header");
    assert!(!host_matches(&public(), &HostInput::default()), "no Host header at all");
    assert!(host_matches(&public(), &host("packages.example.test")));
    assert!(!host_matches(&public(), &host("evil.example.test")));
}

#[test]
fn listener_host_trailing_dot_and_default_port_equal() {
    for spelling in ["PACKAGES.example.test", "packages.example.test.", "packages.example.test:443", "Packages.Example.Test.:443"] {
        assert!(host_matches(&public(), &host(spelling)), "{spelling}");
    }
    assert!(!host_matches(&public(), &host("packages.example.test:8443")), "a non-default port differs");
    assert!(!host_matches(&public(), &host("packages.example.test..")), "only one trailing dot is stripped");
}

#[test]
fn listener_absolute_form_authority_mismatch_refused() {
    let mut input = host("packages.example.test");
    input.target_authority = Some("packages.example.test".into());
    assert!(host_matches(&public(), &input));
    input.target_authority = Some("evil.example.test".into());
    assert!(!host_matches(&public(), &input));
    input.target_authority = Some("user@packages.example.test".into());
    assert!(!host_matches(&public(), &input), "userinfo in the target is refused");
}

#[test]
fn listener_http2_authority_vs_host_mismatch_refused() {
    let mut input = host("packages.example.test");
    input.authority = Some("PACKAGES.example.test:443".into());
    assert!(host_matches(&public(), &input), "equal after normalisation");
    input.authority = Some("evil.example.test".into());
    assert!(!host_matches(&public(), &input));
}

#[test]
fn listener_ipv6_literal_and_idn_host_equal_canonical() {
    let literal = Url::parse("https://[2001:db8::1]").unwrap();
    assert!(host_matches(&literal, &host("[2001:DB8:0:0:0:0:0:1]")), "IPv6 literal in bracketed canonical form");
    assert!(!host_matches(&literal, &host("2001:db8::1")), "an unbracketed literal is not a Host");
    let idn = Url::parse("https://bücher.example").unwrap();
    assert!(host_matches(&idn, &host("xn--bcher-kva.example")), "internationalised name in punycode");
    assert!(host_matches(&idn, &host("BÜCHER.example")), "the Unicode spelling normalises to the same ASCII form");
}

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

#[test]
fn peer_admission_uses_the_actual_peer_and_ipv4_mapped_normalisation() {
    let allowed = ["10.1.0.0/16".parse().unwrap(), "fd00::/32".parse().unwrap()];
    assert!(peer_admitted(ip("127.0.0.1"), &allowed), "loopback is always the machine itself");
    assert!(peer_admitted(ip("::ffff:127.0.0.1"), &allowed), "IPv4-mapped loopback");
    assert!(peer_admitted(ip("10.1.2.3"), &allowed));
    assert!(peer_admitted(ip("::ffff:10.1.2.3"), &allowed), "IPv4-mapped peer matches the IPv4 CIDR");
    assert!(!peer_admitted(ip("10.2.0.1"), &allowed));
    assert!(!peer_admitted(ip("::ffff:10.2.0.1"), &allowed));
    assert!(peer_admitted(ip("fd00::1"), &allowed));
    assert!(!peer_admitted(ip("fd01::1"), &allowed));
    assert!(!peer_admitted(ip("203.0.113.9"), &[]), "an empty list admits only loopback");
}

fn config_with_peers(cidrs: &str) -> Result<Config, probation::config::ConfigError> {
    Config::from_toml_str(&format!("allowed_peer_cidrs = [{cidrs}]\n{}", include_str!("../config.sample.toml")))
}

#[test]
fn listener_cidr_prefix_floor_boundaries() {
    assert!(config_with_peers("\"10.0.0.0/8\"").is_ok(), "IPv4 /8 is the floor");
    assert!(config_with_peers("\"10.0.0.0/7\"").is_err(), "IPv4 /7 is too wide");
    assert!(config_with_peers("\"fd00::/32\"").is_ok(), "IPv6 /32 is the floor");
    assert!(config_with_peers("\"fd00::/31\"").is_err(), "IPv6 /31 is too wide");
    assert!(config_with_peers("\"0.0.0.0/0\"").is_err());
    assert!(config_with_peers("\"::/0\"").is_err());
}

// ---- HTTP level: actual peer, forged forwarding headers, route classes ----

fn snapshot() -> ServicePolicySnapshot {
    let places = [PlaceRef { kind: LayerKind::Platform, id: 1 }, PlaceRef { kind: LayerKind::Org, id: 10 }];
    let descriptor = |id, ecosystem| RegistryDescriptor {
        registry: RegistryId(id), ecosystem, target_url: None, trusted: false,
        registry_private_cidrs: vec![], deletion_scopes: vec![], osv_scope: None, archive_origin: None, resource_path_prefix: None,
    };
    ServicePolicySnapshot {
        version: 1, key_id: KeyId(7), org: OrgId(10), account: places[1], revision: 1,
        place_chain: places.iter().map(|place| ChainLink { place: *place, layer_revision: 1 }).collect(),
        layers: places.iter().map(|place| PlaceLayer {
            place: *place,
            layer: Layer { freeze_seconds: Some(0), osv: Some(OsvSetting::Off), ..Layer::empty(place.kind) },
            revision: 1,
        }).collect(),
        rate_limit: None, rate_limit_source: LimitSource::Default,
        registries: vec![descriptor(3, probation_policy::Ecosystem::Npm), descriptor(4, probation_policy::Ecosystem::PyPi), descriptor(5, probation_policy::Ecosystem::RubyGems), RegistryDescriptor { target_url: Some("https://cargo-reg.invalid/".into()), ..descriptor(7, probation_policy::Ecosystem::Cargo) }, RegistryDescriptor { target_url: Some("https://nuget-reg.invalid/v3/index.json".into()), ..descriptor(8, probation_policy::Ecosystem::NuGet) }, RegistryDescriptor { target_url: Some("https://maven-reg.invalid/repo/".into()), ..descriptor(9, probation_policy::Ecosystem::Maven) }, RegistryDescriptor { target_url: Some("https://conan-reg.invalid/repo/".into()), ..descriptor(10, probation_policy::Ecosystem::Conan) }],
    }
}

async fn service(allowed: &[&str]) -> (TestServer, Arc<FakeRegistry>, MockServer) {
    let policy_server = MockServer::start().await;
    Mock::given(method("GET")).and(path("/api/v1/policy/snapshot"))
        .respond_with(ResponseTemplate::new(200).set_body_json(snapshot()))
        .mount(&policy_server).await;
    let dir = tempfile::tempdir().unwrap();
    let mut config = config_with_open_blocklist(dir.path());
    config.allowed_peer_cidrs = allowed.iter().map(|c| c.parse().unwrap()).collect();
    config.service_policy = Some(ServicePolicyConfig {
        server_url: policy_server.uri().parse().unwrap(),
        service_key_file: "/test/key".into(),
        service_key: FirewallToken::new("prb_01234567890123456789012345678901".into()),
        sync_interval_seconds: std::num::NonZeroU64::new(60).unwrap(),
        trusted_proxies: vec![],
    });
    let registry = FakeRegistry::new();
    let server = TestServer::start_with_upstream(
        config, TestClock::at_rfc3339("2026-04-06T12:00:00Z").shared(),
        Arc::clone(&registry) as Arc<dyn Transport>, fake_origins(),
    ).await;
    (server, registry, policy_server)
}

/// One request through the real router as if it arrived from `peer`.
async fn from_peer(server: &TestServer, peer: &str, method: &str, uri: &str, headers: &[(&str, &str)]) -> StatusCode {
    let mut builder = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let mut request = builder.body(Body::empty()).unwrap();
    request.extensions_mut().insert(ConnectInfo(format!("{peer}:50000").parse::<SocketAddr>().unwrap()));
    probation::http::router(server.app()).oneshot(request).await.unwrap().status()
}

#[tokio::test]
async fn forged_x_forwarded_for_cannot_admit_a_foreign_peer() {
    let (server, _registry, _policy) = service(&["10.1.0.0/16"]).await;
    let host = ("host", "packages.example.org");
    // A peer outside the allow-list is refused whatever the forwarding headers claim.
    for forged in [
        vec![("x-forwarded-for", "127.0.0.1"), host],
        vec![("x-forwarded-for", "10.1.2.3"), ("x-real-ip", "10.1.2.3"), ("forwarded", "for=10.1.2.3"), host],
        vec![("x-probation-peer", "trusted"), host],
    ] {
        assert_eq!(from_peer(&server, "203.0.113.9", "GET", "/registry/npm/3/left-pad", &forged).await, StatusCode::FORBIDDEN);
    }
    // An allowed peer passes admission (whatever the registry then answers is not 403/400).
    let allowed = from_peer(&server, "10.1.2.3", "GET", "/health/live", &[host]).await;
    assert_eq!(allowed, StatusCode::OK);
    let admitted = from_peer(&server, "10.1.2.3", "GET", "/registry/npm/3/left-pad", &[host]).await;
    assert!(!matches!(admitted, StatusCode::FORBIDDEN | StatusCode::BAD_REQUEST), "{admitted}");
    // IPv4-mapped spelling of an allowed peer is normalised before matching.
    let mapped = from_peer(&server, "[::ffff:10.1.2.3]", "GET", "/registry/npm/3/left-pad", &[host]).await;
    assert!(!matches!(mapped, StatusCode::FORBIDDEN | StatusCode::BAD_REQUEST), "{mapped}");
}

#[tokio::test]
async fn listener_host_checked_at_the_http_boundary() {
    let (server, _registry, _policy) = service(&["10.1.0.0/16"]).await;
    let uri = "/registry/npm/3/left-pad";
    assert_eq!(from_peer(&server, "10.1.2.3", "GET", uri, &[("host", "evil.example.test")]).await, StatusCode::BAD_REQUEST);
    assert_eq!(from_peer(&server, "10.1.2.3", "GET", uri, &[("host", "packages.example.org"), ("host", "packages.example.org")]).await, StatusCode::BAD_REQUEST);
    assert_ne!(from_peer(&server, "10.1.2.3", "GET", uri, &[("host", "PACKAGES.example.org.:443")]).await, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn upstream_write_without_credential_is_refused() {
    let (server, registry, _policy) = service(&["10.1.0.0/16"]).await;
    let before = registry.calls().len();
    let forged = [("host", "packages.example.org"), ("x-forwarded-for", "127.0.0.1"), ("x-probation-peer", "trusted")];
    for (verb, uri) in [
        ("PUT", "/registry/npm/3/left-pad"),
        ("DELETE", "/registry/npm/3/left-pad/-rev/1-old"),
        ("POST", "/registry/pypi/4/"),
    ] {
        // Peer trust never authorizes a write: from an allowed peer and from loopback.
        for peer in ["10.1.2.3", "127.0.0.1"] {
            assert_eq!(from_peer(&server, peer, verb, uri, &forged).await, StatusCode::UNAUTHORIZED, "{verb} {uri} from {peer}");
        }
    }
    assert_eq!(registry.calls().len(), before, "no upstream request was made");
    // Administrative routes are not registered on the shared-service listener.
    for uri in ["/api/v1/policy/snapshot", "/admin", "/portal/", "/settings", "/org/1/registries", "/api/v1/sync/changes"] {
        for verb in ["GET", "POST", "PUT", "DELETE"] {
            assert_eq!(from_peer(&server, "127.0.0.1", verb, uri, &forged).await, StatusCode::NOT_FOUND, "{verb} {uri}");
        }
    }
}

/// The R/W/X table: every registered route, its methods and class. Adding or removing a
/// route, or a method on one, fails this test until the table (03 § listener) is updated.
const ROUTE_TABLE: &[(&str, &str, char)] = &[
    ("/health/live", "get", 'R'),
    ("/health/ready", "get", 'R'),
    ("/health/delivery", "get", 'R'),
    ("/npm/-/ping", "get", 'R'),
    ("/npm/-", "get", 'R'),
    ("/npm/-/{*rest}", "get", 'R'),
    ("/npm/{package}", "get", 'R'),
    ("/registry/npm/{registry}/-/ping", "get", 'R'),
    ("/registry/npm/{registry}/-/whoami", "get", 'R'),
    ("/registry/npm/{registry}/-/v1/search", "get", 'R'),
    ("/npm/{package}/{version_or_tag}", "get", 'R'),
    ("/registry/npm/{registry}/{package}/{version}", "get", 'R'),
    ("/registry/npm/{registry}/{package}", "get put", 'W'),
    ("/registry/npm/{registry}/{package}/-rev/{revision}", "put delete", 'W'),
    ("/registry/pypi/{registry}/simple/", "get", 'R'),
    ("/registry/pypi/{registry}/simple/{project}/", "get", 'R'),
    ("/registry/pypi/{registry}/simple/{project}", "get", 'R'),
    ("/rubygems/info/{gem}", "get", 'R'),
    ("/rubygems/versions", "get", 'R'),
    ("/rubygems/names", "get", 'R'),
    ("/rubygems/specs.4.8.gz", "get", 'R'),
    ("/rubygems/latest_specs.4.8.gz", "get", 'R'),
    ("/rubygems/prerelease_specs.4.8.gz", "get", 'R'),
    ("/registry/rubygems/{registry}/specs.4.8.gz", "get", 'R'),
    ("/registry/rubygems/{registry}/latest_specs.4.8.gz", "get", 'R'),
    ("/registry/rubygems/{registry}/prerelease_specs.4.8.gz", "get", 'R'),
    ("/rubygems/quick/Marshal.4.8/{file}", "get", 'R'),
    ("/registry/rubygems/{registry}/info/{gem}", "get", 'R'),
    ("/registry/rubygems/{registry}/versions", "get", 'R'),
    ("/registry/rubygems/{registry}/names", "get", 'R'),
    ("/registry/rubygems/{registry}/quick/Marshal.4.8/{file}", "get", 'R'),
    ("/rubygems/gems/{file}", "get head", 'R'),
    ("/registry/rubygems/{registry}/gems/{file}", "get head", 'R'),
    ("/cargo/config.json", "get", 'R'),
    ("/cargo/1/{name}", "get", 'R'),
    ("/cargo/2/{name}", "get", 'R'),
    ("/cargo/3/{a}/{name}", "get", 'R'),
    ("/cargo/{ab}/{cd}/{name}", "get", 'R'),
    ("/registry/cargo/{registry}/config.json", "get", 'R'),
    ("/registry/cargo/{registry}/1/{name}", "get", 'R'),
    ("/registry/cargo/{registry}/2/{name}", "get", 'R'),
    ("/registry/cargo/{registry}/3/{a}/{name}", "get", 'R'),
    ("/registry/cargo/{registry}/{ab}/{cd}/{name}", "get", 'R'),
    ("/cargo/crates/{name}/{version}/download", "get head", 'R'),
    ("/registry/cargo/{registry}/crates/{name}/{version}/download", "get head", 'R'),
    ("/registry/cargo/{registry}/api/v1/crates/new", "put", 'W'),
    ("/registry/cargo/{registry}/api/v1/crates/{name}/{version}/yank", "delete", 'W'),
    ("/registry/cargo/{registry}/api/v1/crates/{name}/{version}/unyank", "put", 'W'),
    ("/registry/cargo/{registry}/api/v1/crates/{name}/owners", "delete get put", 'W'),
    ("/registry/cargo/{registry}/api/v1/crates", "get", 'R'),
    ("/go/{*path}", "get head", 'R'),
    ("/registry/go/{registry}/{*path}", "get head", 'R'),
    ("/nuget/{*path}", "get head", 'R'),
    ("/registry/nuget/{registry}/{*path}", "get head", 'R'),
    ("/registry/nuget/{registry}/api/v2/package", "put", 'W'),
    ("/registry/nuget/{registry}/api/v2/package/", "put", 'W'),
    ("/registry/nuget/{registry}/api/v2/symbolpackage", "put", 'W'),
    ("/registry/nuget/{registry}/api/v2/symbolpackage/", "put", 'W'),
    ("/registry/nuget/{registry}/api/v2/package/{id}/{version}", "delete post", 'W'),
    ("/conan/{*path}", "get head", 'R'),
    ("/maven/{*path}", "get head", 'R'),
    ("/registry/conan/{registry}/{*path}", "delete get head put", 'W'),
    ("/registry/maven/{registry}/{*path}", "delete get head put", 'W'),
    ("/registry/rubygems/{registry}/api/v1/gems", "post", 'W'),
    ("/registry/rubygems/{registry}/api/v1/gems/yank", "delete", 'W'),
    ("/pypi/simple/", "get", 'R'),
    ("/pypi/simple/{project}/", "get", 'R'),
    ("/pypi/simple/{project}", "get", 'R'),
    ("/registry/pypi/{registry}/", "post", 'W'),
    ("/registry/npm/{registry}/-/npm/v1/security/advisories/bulk", "post", 'R'),
    ("/registry/npm/{registry}/-/npm/v1/security/audits/quick", "post", 'R'),
    ("/registry/npm/{registry}/-/{*rest}", "any", 'W'),
    ("/registry/npm/{registry}/{package}/-/{filename}", "get head", 'R'),
    ("/registry/npm/{registry}/{package}/-/{filename}/-rev/{revision}", "delete", 'W'),
    ("/registry/npm/{registry}/artifacts/{reference_id}/{filename}/-rev/{revision}", "delete", 'W'),
    ("/npm/artifacts/{reference_id}/{filename}", "get head", 'R'),
    ("/registry/npm/{registry}/artifacts/{reference_id}/{filename}", "get head", 'R'),
    ("/registry/pypi/{registry}/artifacts/{reference_id}/{filename}", "get head", 'R'),
    ("/pypi/artifacts/{reference_id}/{filename}", "get head", 'R'),
    ("/npm/{package}/-/{filename}", "get head", 'R'),
    ("/npm/{scope}/{package}/-/{filename}", "get head", 'R'),
];

#[test]
fn route_inventory_equals_classified_table() {
    let source = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/http/mod.rs")).unwrap();
    let body = &source[source.find("fn package_router").unwrap()..source.find("async fn bound_headers").unwrap()];
    // Split at each `.route(`; the first string literal is the path, the verbs are the
    // `get(`/`.head(`/`post(`/`put(`/`delete(`/`any(` calls inside the same statement.
    let mut found: Vec<(String, String)> = Vec::new();
    for chunk in body.split(".route(").skip(1) {
        let path = chunk.split('"').nth(1).unwrap().to_owned();
        let after = &chunk[chunk.find(path.as_str()).unwrap() + path.len()..];
        let until = after.find("\n        .route(").or_else(|| after.find("\n        .route_layer")).or_else(|| after.find("\n        .fallback")).unwrap_or(after.len());
        let call = &after[..until];
        let mut verbs: Vec<&str> = ["get", "put", "post", "delete", "head", "any"].into_iter()
            .filter(|verb| call.contains(&format!("{verb}(")) || call.contains(&format!("routing::{verb}(")))
            .collect();
        verbs.sort_unstable();
        found.push((path, verbs.join(" ")));
    }
    found.sort();
    let mut expected: Vec<(String, String)> = ROUTE_TABLE.iter().map(|(path, verbs, _)| {
        let mut parts: Vec<&str> = verbs.split(' ').collect();
        parts.sort_unstable();
        ((*path).to_owned(), parts.join(" "))
    }).collect();
    expected.sort();
    assert_eq!(found, expected, "registered routes and methods must equal the classified R/W/X table");
}

// ---- R28-2 (user decision): the Host check applies to every peer, loopback included ----

#[tokio::test]
async fn loopback_peer_host_checked() {
    let (server, _registry, _policy) = service(&["10.1.0.0/16"]).await;
    let uri = "/registry/npm/3/left-pad";
    assert_eq!(from_peer(&server, "127.0.0.1", "GET", uri, &[("host", "evil.example.test")]).await, StatusCode::BAD_REQUEST);
    assert_eq!(from_peer(&server, "127.0.0.1", "GET", uri, &[]).await, StatusCode::BAD_REQUEST, "no Host at all");
    assert_eq!(from_peer(&server, "[::1]", "GET", uri, &[("host", "evil.example.test")]).await, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn dns_rebinding_host_refused_on_loopback() {
    let (server, _registry, _policy) = service(&[]).await;
    let port = server.local_addr().port();
    for rebinding in [format!("attacker.test:{port}"), format!("127.0.0.1.attacker.test:{port}"), format!("localhost.attacker.test:{port}"), "attacker.test".to_owned()] {
        assert_eq!(
            from_peer(&server, "127.0.0.1", "GET", "/registry/npm/3/left-pad", &[("host", rebinding.as_str())]).await,
            StatusCode::BAD_REQUEST,
            "{rebinding}"
        );
    }
}

#[tokio::test]
async fn local_names_accepted() {
    let (server, _registry, _policy) = service(&[]).await;
    let port = server.local_addr().port();
    for name in [format!("127.0.0.1:{port}"), format!("[::1]:{port}"), format!("localhost:{port}"), format!("LOCALHOST.:{port}"), "packages.example.org".to_owned()] {
        let status = from_peer(&server, "127.0.0.1", "GET", "/registry/npm/3/left-pad", &[("host", name.as_str())]).await;
        assert_ne!(status, StatusCode::BAD_REQUEST, "{name}");
    }
    let wrong = from_peer(&server, "127.0.0.1", "GET", "/registry/npm/3/left-pad", &[("host", "127.0.0.1:1")]).await;
    assert_eq!(wrong, StatusCode::BAD_REQUEST, "a loopback name needs the listener's own port");
}

/// R28-4: the class column is behavioural. Every write verb of every class W row is refused
/// locally with 401 when it carries no credential, from an allowed peer and from loopback,
/// with a forged peer-trust header, and without a single upstream call.
#[tokio::test]
async fn every_class_w_route_refuses_without_credential_and_makes_no_upstream_call() {
    let (server, registry, _policy) = service(&["10.1.0.0/16"]).await;
    let before = registry.calls().len();
    let concrete = |template: &str| {
        let eco_registry = if template.contains("/pypi/") { "4" } else if template.contains("/rubygems/") { "5" } else if template.contains("/cargo/") { "7" } else if template.contains("/nuget/") { "8" } else if template.contains("/maven/") { "9" } else if template.contains("/conan/") { "10" } else { "3" };
        template
            .replace("{registry}", eco_registry)
            .replace("{package}", "left-pad")
            .replace("{revision}", "1-old")
            .replace("{filename}", "left-pad-1.0.0.tgz")
            .replace("{reference_id}", "0123456789abcdef0123456789abcdef")
            .replace("{*rest}", "unpublish")
            .replace("{version}", "1.0.0")
            .replace("{name}", "demo")
            .replace("{id}", "demo.pkg")
            .replace("{*path}", if template.contains("/conan/") { "v2/conans/demo/1.0/_/_/revisions/abc/files/conanfile.py" } else { "org/demo/lib/1.0/lib-1.0.jar" })
    };
    let mut driven = 0;
    for (template, verbs, class) in ROUTE_TABLE {
        if *class != 'W' {
            continue;
        }
        // The catch-all named-action row (`any`) is driven with one real action per verb.
        let drives: Vec<(String, String)> = if *verbs == "any" {
            vec![("POST", "npm/v1/user"), ("DELETE", "user/token/abc")]
                .into_iter().map(|(verb, rest)| (verb.to_owned(), concrete(&template.replace("{*rest}", rest)))).collect()
        } else {
            verbs.split(' ').filter(|v| matches!(*v, "put" | "post" | "delete")).map(|v| (v.to_uppercase(), concrete(template))).collect()
        };
        for (verb, uri) in drives {
            for peer in ["10.1.2.3", "127.0.0.1"] {
                let status = from_peer(&server, peer, &verb, &uri, &[("host", "packages.example.org"), ("x-probation-peer", "trusted"), ("x-forwarded-for", "127.0.0.1")]).await;
                // Direct tarball and artifact DELETE are never forwarded at all (405 with or
                // without a credential, or 404 for a reference this service never issued); every other write needs the caller's own credential.
                let never_forwarded = template.contains("{filename}") && template.contains("-rev");
                let ok = status == StatusCode::UNAUTHORIZED || (never_forwarded && matches!(status, StatusCode::METHOD_NOT_ALLOWED | StatusCode::NOT_FOUND));
                assert!(ok, "{verb} {uri} from {peer} must be refused without a credential, got {status}");
                driven += 1;
            }
        }
    }
    assert!(driven >= 26, "every W row was driven ({driven})");
    assert_eq!(registry.calls().len(), before, "no upstream request was made");
}

// ---- S28-7: readiness detail only for admitted peers ----

async fn ready_from(server: &TestServer, peer: &str) -> (StatusCode, String) {
    let mut request = Request::builder().method("GET").uri("/health/ready").header("host", "packages.example.org").body(Body::empty()).unwrap();
    request.extensions_mut().insert(ConnectInfo(format!("{peer}:50000").parse::<SocketAddr>().unwrap()));
    let response = probation::http::router(server.app()).oneshot(request).await.unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap();
    (status, String::from_utf8_lossy(&body).into_owned())
}

#[tokio::test]
async fn readiness_detail_is_only_for_admitted_peers() {
    let (server, _registry, _policy) = service(&["10.1.0.0/16"]).await;
    let (status, body) = ready_from(&server, "203.0.113.9").await;
    assert_eq!(status, StatusCode::OK, "an orchestrator probe from any address keeps its status code");
    assert!(body.is_empty(), "no detail for a peer outside allowed_peer_cidrs: {body}");
    for peer in ["10.1.2.3", "127.0.0.1"] {
        let (status, body) = ready_from(&server, peer).await;
        assert_eq!(status, StatusCode::OK, "{peer}");
        let detail: serde_json::Value = serde_json::from_str(&body).unwrap_or_else(|_| panic!("{peer}: JSON detail expected, got {body:?}"));
        assert_eq!(detail["policy_active"], true, "{peer}");
    }
}
