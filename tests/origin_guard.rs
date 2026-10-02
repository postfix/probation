//! Slice 4's witness: the outbound boundary, attacked from both sides.
//!
//! Every case here runs against a local socket or no socket at all. Nothing in this
//! file reaches the public internet, and the one thing that would — the production
//! `OriginSet` — appears only where it is expected to *refuse*.
//!
//! The two gates are exercised separately on purpose. `OriginSet::admit` is checked
//! directly, because it is the one that runs before a packet exists; the redirect,
//! credential and port cases go through the real `ReqwestTransport` against
//! `wiremock`, because a rule that only holds in a unit test is not a rule an HTTP
//! client obeys.

mod common;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::Arc;

use common::{TestServer, WiremockUpstream, config_with_open_blocklist, fake_origins};
use futures_util::StreamExt;
use probation::upstream::origins::{OriginKind, UrlRejection};
use probation::upstream::reqwest_transport::refusal_in;
use probation::upstream::resolver::{GuardedResolver, is_public};
use probation::upstream::{
    ArtifactRequest, MetadataRequest, MetadataResponse, OriginSet, Transport, UpstreamError,
    UpstreamValidators,
};
use reqwest::dns::{Name, Resolve};
use url::Url;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// `std::env::set_var` is process-wide, so the one test that uses it holds this for
/// as long as the variables are set and every other test that builds an HTTP client
/// waits behind it.
static ENVIRONMENT: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const NPM_ACCEPT: &str = "application/json";
const A_MEGABYTE: u64 = 1024 * 1024;

fn metadata(url: Url) -> MetadataRequest {
    MetadataRequest {
        url,
        accept: NPM_ACCEPT,
        validators: None,
        max_bytes: A_MEGABYTE,
    }
}

fn parse(text: &str) -> Url {
    Url::parse(text).expect("a test URL")
}

/// A `wiremock` socket the transport is pointed at, built while holding
/// [`ENVIRONMENT`] so the client cannot be constructed while another test has the
/// process environment loaded with proxy settings.
async fn upstream() -> WiremockUpstream {
    let _guard = ENVIRONMENT.lock().await;
    WiremockUpstream::start().await
}

// ---------------------------------------------------------------------------
// The constructor seam
// ---------------------------------------------------------------------------

/// A test origin is an ordinary origin: it admits its own URLs, builds URLs under
/// itself, and refuses everything else exactly as the production set does. The
/// relaxation it grants is narrow and named — `http` and private addresses — and it
/// is granted by the constructor and by nothing else.
#[test]
fn test_origins_work_through_the_constructor() {
    let npm = parse("http://127.0.0.1:8080");
    let origins = OriginSet::for_tests(
        npm.clone(),
        parse("http://127.0.0.1:8081"),
        parse("http://127.0.0.1:8082"),
    );

    assert!(
        origins.allows_private_addresses(),
        "a test origin set is the one place the private-address gate opens"
    );
    assert_eq!(
        origins.admit(
            &parse("http://127.0.0.1:8080/left-pad"),
            OriginKind::NpmMetadata
        ),
        Ok(()),
        "the constructor's own origin is admitted"
    );
    assert_eq!(
        origins.kind_of(&npm),
        Some(OriginKind::NpmMetadata),
        "the first origin the constructor was given is the npm one"
    );
    assert_eq!(
        origins
            .url_for(OriginKind::NpmMetadata, &["left-pad"])
            .map(String::from),
        Ok("http://127.0.0.1:8080/left-pad".to_owned())
    );

    // Relaxed, not open: the other two origins are as foreign to npm as anything
    // else, a port nobody configured is refused, and a host nobody configured is
    // refused outright.
    assert_eq!(
        origins.admit(
            &parse("http://127.0.0.1:8081/left-pad"),
            OriginKind::NpmMetadata
        ),
        Err(UrlRejection::ForeignOrigin),
        "the PyPI socket is a different origin even on the same loopback host"
    );
    assert_eq!(
        origins.admit(
            &parse("http://127.0.0.1:9999/left-pad"),
            OriginKind::NpmMetadata
        ),
        Err(UrlRejection::Port)
    );
    assert_eq!(
        origins.admit(
            &parse("https://127.0.0.1:8080/left-pad"),
            OriginKind::NpmMetadata
        ),
        Err(UrlRejection::Scheme),
        "the relaxation is per origin: this one was configured as http"
    );
    assert_eq!(
        origins.admit(&parse("http://evil.test/left-pad"), OriginKind::NpmMetadata),
        Err(UrlRejection::Host)
    );

    // And the production set refuses every one of those URLs, so nothing a test
    // relies on here can also be true of the shipped configuration.
    let production = OriginSet::production();
    assert!(!production.allows_private_addresses());
    assert_eq!(
        production.admit(
            &parse("http://127.0.0.1:8080/left-pad"),
            OriginKind::NpmMetadata
        ),
        Err(UrlRejection::Scheme)
    );
    assert_eq!(
        production.admit(
            &parse("http://registry.npmjs.org/left-pad"),
            OriginKind::NpmMetadata
        ),
        Err(UrlRejection::Scheme),
        "even the right host is refused over plain http"
    );
    assert_eq!(
        production
            .url_for(OriginKind::NpmMetadata, &["left-pad"])
            .map(String::from),
        Ok("https://registry.npmjs.org/left-pad".to_owned())
    );
}

// ---------------------------------------------------------------------------
// The address gate
// ---------------------------------------------------------------------------

/// SPEC §11: "Reject … addresses resolving to loopback/private/link-local networks."
///
/// The resolver is the gate that can see an address at all, so it is asked directly,
/// with a name that resolves without a network. The ranges below are the ones a
/// name pointed at internal infrastructure would land in; `169.254.169.254` is
/// there by name because it is the one every cloud metadata service answers on.
#[tokio::test]
async fn production_origin_set_rejects_private_addresses() {
    let refused: &[IpAddr] = &[
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)),
        IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
        IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        // 0.0.0.0/8, "this network" (RFC 1122). `Ipv4Addr::is_unspecified` matches
        // only the single all-zero address, so the rest of the /8 needs saying.
        IpAddr::V4(Ipv4Addr::new(0, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(0, 1, 2, 3)),
        IpAddr::V4(Ipv4Addr::new(0, 255, 255, 255)),
        // Carrier-grade NAT, benchmarking, reserved: ranges `std` has no stable
        // predicate for, which is why this module writes them out.
        IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(240, 0, 0, 1)),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        "fd00::1".parse().expect("a unique-local address"),
        "fe80::1".parse().expect("a link-local address"),
        // The same loopback address wearing an IPv6 costume.
        "::ffff:127.0.0.1"
            .parse()
            .expect("a mapped loopback address"),
    ];
    for addr in refused {
        assert!(!is_public(*addr), "{addr} must not be treated as public");
    }

    let allowed: &[IpAddr] = &[
        IpAddr::V4(Ipv4Addr::new(104, 16, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        "2606:4700::1".parse().expect("a public v6 address"),
        // 6to4 wrapping an ordinary public address stays public: the embedded
        // address is decoded and judged, not the wrapper.
        "2002:6810:0101::".parse().expect("6to4 over 104.16.1.1"),
    ];
    for addr in allowed {
        assert!(is_public(*addr), "{addr} is an ordinary public address");
    }

    // The gate itself, not just its predicate: `localhost` resolves without a
    // network, and the production resolver refuses the answer it gets back.
    let resolver = GuardedResolver::new(false);
    let refusal = resolver
        .resolve(Name::from_str("localhost").expect("a resolvable name"))
        .await
        .err()
        .expect("the production resolver refuses a loopback answer");
    assert!(
        matches!(
            refusal_in(refusal.as_ref()),
            Some(UpstreamError::RejectedAddress { .. })
        ),
        "the refusal says which address it was: {refusal}"
    );

    // And the same name is resolvable when a test origin set opened the gate, so
    // what the assertion above proves is the gate and not a broken lookup.
    let permissive = GuardedResolver::new(true);
    assert!(
        permissive
            .resolve(Name::from_str("localhost").expect("a resolvable name"))
            .await
            .is_ok(),
        "the relaxed resolver still resolves the same name"
    );
}

/// An IPv6 address can carry an IPv4 one inside it, so a predicate that judges only
/// the IPv6 shape lets a private target through wearing a global-looking address.
/// Every case below embeds a loopback or private IPv4 and must be refused on the
/// strength of what it embeds.
#[test]
fn an_ipv6_address_cannot_hide_a_private_ipv4_target() {
    let hiding: &[(&str, &str)] = &[
        // 64:ff9b::/96, the well-known NAT64 prefix (RFC 6052).
        ("64:ff9b::7f00:1", "NAT64 over 127.0.0.1"),
        ("64:ff9b::a00:1", "NAT64 over 10.0.0.1"),
        ("64:ff9b::a9fe:a9fe", "NAT64 over 169.254.169.254"),
        // 2002::/16, 6to4 (RFC 3056): the IPv4 sits in bits 16-48.
        ("2002:7f00:1::", "6to4 over 127.0.0.1"),
        ("2002:a00:1::", "6to4 over 10.0.0.1"),
        ("2002:c0a8:1::1", "6to4 over 192.168.0.1"),
        // ::/96, the deprecated IPv4-compatible form. Same trick, older spelling.
        ("::7f00:1", "IPv4-compatible 127.0.0.1"),
        ("::a00:1", "IPv4-compatible 10.0.0.1"),
    ];
    for (text, what) in hiding {
        let addr: IpAddr = text.parse().expect("a test address");
        assert!(
            !is_public(addr),
            "{what} ({text}) must not be treated as public"
        );
    }
}

/// The rest of the IANA IPv6 Special-Purpose Address Registry, re-derived rather
/// than patched: nothing outside `2000::/3` global unicast is reachable, and the
/// special blocks that do sit inside it are named.
#[test]
fn every_special_purpose_ipv6_range_is_refused() {
    let refused: &[(&str, &str)] = &[
        ("fec0::1", "site-local, deprecated by RFC 3879"),
        ("feff::1", "the top of fec0::/10"),
        ("64:ff9b:1::1", "local-use NAT64, RFC 8215"),
        ("100::1", "discard-only, RFC 6666"),
        ("5f00::1", "SRv6 SIDs, RFC 9602"),
        ("2001::1", "Teredo, inside IETF protocol assignments"),
        ("2001:2::1", "benchmarking, RFC 5180"),
        (
            "2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff",
            "the top of 2001::/23",
        ),
        ("3fff::1", "documentation, RFC 9637"),
        (
            "3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff",
            "the top of 3fff::/20",
        ),
        ("2620:4f:8000::1", "AS112-v6 direct delegation"),
        ("4000::1", "outside global unicast"),
        ("c000::1", "outside global unicast"),
    ];
    for (text, what) in refused {
        let addr: IpAddr = text.parse().expect("a test address");
        assert!(
            !is_public(addr),
            "{text} ({what}) must not be treated as public"
        );
    }

    // The boundaries of 2000::/3 itself, so the allowlist is not quietly off by one.
    assert!(is_public("2000::1".parse().expect("an address")));
    assert!(is_public("3ffe::1".parse().expect("an address")));
    assert!(!is_public("1fff::1".parse().expect("an address")));
}

// ---------------------------------------------------------------------------
// TEST-01: no release path relaxes the boundary
// ---------------------------------------------------------------------------

/// TEST-01. Three separate ways in are closed, and each is checked as itself.
///
/// The configuration file cannot carry a key that reaches the boundary; the process
/// environment cannot change what `OriginSet::production` returns, nor route its
/// traffic somewhere else through a proxy variable; and no file under `src/` outside
/// `upstream/origins.rs` so much as names `for_tests`, so the binary has no path to
/// the one constructor that could relax anything.
#[tokio::test]
async fn no_config_key_or_env_var_relaxes_origins() {
    use probation::config::Config;

    // 1. No configuration key reaches the boundary. Unknown keys are rejected, so
    //    adding one is a startup failure rather than a silent relaxation.
    let sample = std::fs::read_to_string("config.sample.toml").expect("the shipped sample");
    for forbidden in [
        "allow_private_addresses",
        "npm_registry_url",
        "upstream_origin",
        "insecure",
        "allow_http",
        "proxy",
    ] {
        assert!(
            !sample.contains(forbidden),
            "the shipped configuration must not carry `{forbidden}`"
        );
        let relaxed = format!("{sample}\n{forbidden} = true\n");
        assert!(
            Config::from_toml_str(&relaxed).is_err(),
            "a configuration carrying `{forbidden}` must be refused"
        );
    }

    // 2. No environment variable reaches it either. These are set for real, around
    //    the assertions, with every other client-building test held off meanwhile.
    let guard = ENVIRONMENT.lock().await;
    let variables = [
        ("PROBATION_ALLOW_PRIVATE_ADDRESSES", "1"),
        ("ALLOW_PRIVATE_ADDRESSES", "true"),
        ("PROBATION_NPM_ORIGIN", "http://127.0.0.1:1/"),
        ("NPM_CONFIG_REGISTRY", "http://127.0.0.1:1/"),
        // Port 1 accepts nothing, so a client that honoured this would fail to
        // reach the socket the request below really does reach.
        ("HTTP_PROXY", "http://127.0.0.1:1"),
        ("ALL_PROXY", "http://127.0.0.1:1"),
    ];
    // SAFETY: the process environment is shared, and `ENVIRONMENT` is held for the
    // whole window in which these are set. No other test in this binary reads them.
    unsafe {
        for (name, value) in variables {
            std::env::set_var(name, value);
        }
    }

    let production = OriginSet::production();
    assert!(
        !production.allows_private_addresses(),
        "no environment variable opens the private-address gate"
    );
    assert_eq!(
        production.admit(
            &parse("http://127.0.0.1:1/left-pad"),
            OriginKind::NpmMetadata
        ),
        Err(UrlRejection::Scheme)
    );
    assert_eq!(
        production
            .url_for(OriginKind::NpmMetadata, &["left-pad"])
            .map(String::from),
        Ok("https://registry.npmjs.org/left-pad".to_owned()),
        "the origin the URL is built from is still the compiled-in one"
    );

    // The proxy variables are the live half: this fetch must reach the wiremock
    // socket itself, not the dead port the environment is pointing at.
    let upstream = WiremockUpstream::start().await;
    Mock::given(method("GET"))
        .and(path("/left-pad"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
        .mount(&upstream.server)
        .await;
    let url = upstream
        .origins
        .url_for(OriginKind::NpmMetadata, &["left-pad"])
        .expect("the test origin builds its own URL");
    let fetched = upstream.transport.fetch_metadata(metadata(url)).await;

    // SAFETY: same window, same lock; the variables are removed before it is
    // released, whether or not the assertions below hold.
    unsafe {
        for (name, _) in variables {
            std::env::remove_var(name);
        }
    }
    drop(guard);

    assert!(
        matches!(fetched, Ok(MetadataResponse::Fresh { .. })),
        "the request went to the configured origin, not through the proxy the \
         environment asked for"
    );

    // 3. The binary has no path to `for_tests`. A grep is the whole check, and it is
    //    the check the invariant is actually stated as.
    let mut mentions = Vec::new();
    visit_rust_files("src".as_ref(), &mut |path, source| {
        // Comments stripped first, so a doc comment explaining the rule is not read
        // as a breach of it. This crate uses no block comments.
        let code: String = source
            .lines()
            .map(|line| line.split("//").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n");
        if code.contains("for_tests") {
            mentions.push(path.display().to_string());
        }
    });
    assert_eq!(
        mentions,
        vec!["src/upstream/origins.rs".to_owned()],
        "`for_tests` is named only where it is defined; anything else is a release \
         path into the one constructor that can relax the boundary"
    );
}

fn visit_rust_files(dir: &std::path::Path, seen: &mut impl FnMut(&std::path::Path, &str)) {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .expect("the source directory is readable")
        .map(|entry| entry.expect("a directory entry").path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            visit_rust_files(&path, seen);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            let source = std::fs::read_to_string(&path).expect("a readable source file");
            seen(&path, &source);
        }
    }
}

// ---------------------------------------------------------------------------
// The wire: what the real client does when upstream misbehaves
// ---------------------------------------------------------------------------

/// A redirect off the admitted origin is refused, and the host it pointed at never
/// sees a request. `attempt.stop()` hands the 3xx back to us, so the refusal can
/// name its target rather than arriving as an opaque transport failure.
#[tokio::test]
async fn cross_origin_redirect_rejected() {
    let upstream = upstream().await;
    let foreign = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/left-pad"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("location", format!("{}/left-pad", foreign.uri()).as_str()),
        )
        .mount(&upstream.server)
        .await;
    Mock::given(method("GET"))
        .and(path("/left-pad"))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"stolen":true}"#))
        .mount(&foreign)
        .await;

    let url = upstream
        .origins
        .url_for(OriginKind::NpmMetadata, &["left-pad"])
        .expect("the test origin builds its own URL");
    let refusal = upstream
        .transport
        .fetch_metadata(metadata(url))
        .await
        .err()
        .expect("a cross-origin redirect is refused");

    match refusal {
        UpstreamError::RejectedRedirect { to } => {
            assert_eq!(to.as_str(), format!("{}/left-pad", foreign.uri()))
        }
        other => panic!("expected a refused redirect, got {other:?}"),
    }
    assert_eq!(
        foreign
            .received_requests()
            .await
            .expect("the recorded requests")
            .len(),
        0,
        "the foreign origin was never contacted"
    );
}

/// The refusal has to name the target it refused, which means resolving `Location`
/// against the request URL. A bare `Url::parse` fails on a schemeless value, so both
/// a protocol-relative and a relative `Location` would otherwise be reported as the
/// URL we were already at — and protocol-relative is the shape an exfiltration
/// attempt is most likely to use.
#[tokio::test]
async fn a_refused_redirect_names_its_resolved_target() {
    let upstream = upstream().await;
    let foreign = MockServer::start().await;
    let foreign_authority = foreign
        .uri()
        .strip_prefix("http://")
        .expect("a wiremock http origin")
        .to_owned();

    // Protocol-relative: no scheme, so `Url::parse` alone cannot resolve it.
    Mock::given(method("GET"))
        .and(path("/protocol-relative"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("location", format!("//{foreign_authority}/stolen").as_str()),
        )
        .mount(&upstream.server)
        .await;

    let url = upstream
        .origins
        .url_for(OriginKind::NpmMetadata, &["protocol-relative"])
        .expect("the test origin builds its own URL");
    match upstream.transport.fetch_metadata(metadata(url)).await {
        Err(UpstreamError::RejectedRedirect { to }) => assert_eq!(
            to.as_str(),
            format!("http://{foreign_authority}/stolen"),
            "the refusal must name where it was being sent"
        ),
        other => panic!(
            "expected a refused redirect, got {other:?}",
            other = other.err()
        ),
    }
    assert_eq!(
        foreign
            .received_requests()
            .await
            .expect("the recorded requests")
            .len(),
        0
    );

    // Relative: same origin, so each hop is admitted and followed until the chain
    // runs past the hop limit. The stopped response's `Location` is relative, and the
    // refusal must still name the absolute URL it resolves to.
    for hop in 0..10 {
        Mock::given(method("GET"))
            .and(path(format!("/hop{hop}")))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("location", format!("/hop{}", hop + 1).as_str()),
            )
            .mount(&upstream.server)
            .await;
    }

    let url = upstream
        .origins
        .url_for(OriginKind::NpmMetadata, &["hop0"])
        .expect("the test origin builds its own URL");
    match upstream.transport.fetch_metadata(metadata(url)).await {
        Err(UpstreamError::RejectedRedirect { to }) => {
            assert_eq!(
                to.host_str(),
                upstream.origins.origin(OriginKind::NpmMetadata).host_str()
            );
            let hop: u32 = to
                .path()
                .strip_prefix("/hop")
                .and_then(|n| n.parse().ok())
                .unwrap_or_else(|| panic!("expected a resolved /hopN target, got {to}"));
            assert!(
                hop > 0,
                "the refusal named the hop it was at, not the hop it was sent to: {to}"
            );
        }
        other => panic!(
            "expected a refused redirect, got {other:?}",
            other = other.err()
        ),
    }
}

/// Credentials in a URL are refused before the request, and refused again when they
/// arrive by redirect — which is the interesting half, because the URL the code
/// built had none.
#[tokio::test]
async fn url_credentials_rejected() {
    let upstream = upstream().await;
    let authority = upstream
        .server
        .uri()
        .strip_prefix("http://")
        .expect("a wiremock http origin")
        .to_owned();

    // Before the request: the same origin, wearing credentials.
    let credentialed = parse(&format!("http://npm:secret@{authority}/left-pad"));
    assert_eq!(
        upstream
            .origins
            .admit(&credentialed, OriginKind::NpmMetadata),
        Err(UrlRejection::Credentials)
    );
    assert_eq!(
        upstream
            .transport
            .fetch_metadata(metadata(credentialed))
            .await
            .err()
            .expect("a credentialed URL is refused"),
        UpstreamError::RejectedUrl(UrlRejection::Credentials)
    );
    assert_eq!(
        upstream
            .server
            .received_requests()
            .await
            .expect("the recorded requests")
            .len(),
        0,
        "nothing left the process"
    );

    // On a redirect: upstream tries to hand us a credentialed URL on its own host.
    Mock::given(method("GET"))
        .and(path("/left-pad"))
        .respond_with(ResponseTemplate::new(307).insert_header(
            "location",
            format!("http://npm:secret@{authority}/left-pad-2").as_str(),
        ))
        .mount(&upstream.server)
        .await;

    let url = upstream
        .origins
        .url_for(OriginKind::NpmMetadata, &["left-pad"])
        .expect("the test origin builds its own URL");
    let refusal = upstream
        .transport
        .fetch_metadata(metadata(url))
        .await
        .err()
        .expect("a redirect to a credentialed URL is refused");
    assert!(
        matches!(refusal, UpstreamError::RejectedRedirect { .. }),
        "expected a refused redirect, got {refusal:?}"
    );
}

/// The same host on a port nobody configured is a different origin. Checked before
/// the request and on the redirect, and the port that was pointed at stays silent.
#[tokio::test]
async fn unexpected_port_rejected() {
    let upstream = upstream().await;
    let other = MockServer::start().await;
    let other_port = parse(&other.uri()).port().expect("wiremock binds a port");

    let wrong_port = parse(&format!("http://127.0.0.1:{other_port}/left-pad"));
    assert_eq!(
        upstream.origins.admit(&wrong_port, OriginKind::NpmMetadata),
        Err(UrlRejection::Port)
    );
    assert_eq!(
        upstream
            .transport
            .fetch_metadata(metadata(wrong_port))
            .await
            .err()
            .expect("an unexpected port is refused"),
        UpstreamError::RejectedUrl(UrlRejection::Port)
    );

    Mock::given(method("GET"))
        .and(path("/left-pad"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("location", format!("{}/left-pad", other.uri()).as_str()),
        )
        .mount(&upstream.server)
        .await;
    Mock::given(method("GET"))
        .and(path("/left-pad"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
        .mount(&other)
        .await;

    let url = upstream
        .origins
        .url_for(OriginKind::NpmMetadata, &["left-pad"])
        .expect("the test origin builds its own URL");
    let refusal = upstream
        .transport
        .fetch_metadata(metadata(url))
        .await
        .err()
        .expect("a redirect to another port is refused");
    assert!(
        matches!(refusal, UpstreamError::RejectedRedirect { .. }),
        "expected a refused redirect, got {refusal:?}"
    );
    assert_eq!(
        other
            .received_requests()
            .await
            .expect("the recorded requests")
            .len(),
        0,
        "the other port was never contacted"
    );
}

/// SPEC §11: "Never forward a client's authorization, cookies, or proxy credentials
/// upstream."
///
/// The whole wire, not the transport alone: a real client sends the three headers to
/// a real server, which fetches through the real transport, and the socket upstream
/// records what actually arrived.
#[tokio::test]
async fn client_authorization_cookies_and_proxy_credentials_are_never_forwarded() {
    let upstream = upstream().await;
    Mock::given(method("GET"))
        .and(path("/left-pad"))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"name":"left-pad"}"#))
        .mount(&upstream.server)
        .await;

    let blocklist_dir = tempfile::tempdir().expect("a blocklist directory");
    let server = TestServer::start_with_upstream(
        config_with_open_blocklist(blocklist_dir.path()),
        Arc::new(probation::clock::SystemClock),
        Arc::clone(&upstream.transport),
        upstream.origins.clone(),
    )
    .await;

    let response = server
        .get_with_headers(
            "/npm/left-pad",
            &[
                ("authorization", "Bearer downstream-secret"),
                ("cookie", "session=downstream-secret"),
                ("proxy-authorization", "Basic ZG93bnN0cmVhbTpzZWNyZXQ="),
            ],
        )
        .await;
    assert_ne!(
        response.status().as_u16(),
        503,
        "the blocklist is loaded, so the request reached the outbound boundary"
    );

    let received = upstream
        .server
        .received_requests()
        .await
        .expect("the recorded requests");
    assert_eq!(received.len(), 1, "exactly one upstream request was made");

    for forbidden in ["authorization", "cookie", "proxy-authorization"] {
        assert!(
            received[0].headers.get(forbidden).is_none(),
            "`{forbidden}` reached upstream: {:?}",
            received[0].headers
        );
    }
    // The value, not just the header name: nothing carried it under another name.
    let headers = format!("{:?}", received[0].headers);
    assert!(
        !headers.contains("downstream-secret") && !headers.contains("ZG93bnN0cmVhbTpzZWNyZXQ"),
        "a downstream credential reached upstream under some other header: {headers}"
    );

    server.shutdown().await;
}

/// A conditional request that upstream answers `304` is not a redirect.
///
/// `StatusCode::is_redirection` covers the whole `300..400` range, 304 included, and
/// reqwest never routes a bare `304` through the redirect policy — it arrives as an
/// ordinary terminal response. So the refused-redirect check has to run *after* the
/// status match, or every revalidation in slice 5 becomes a `502`.
#[tokio::test]
async fn a_conditional_request_answered_304_is_not_modified_not_a_redirect() {
    let upstream = upstream().await;
    Mock::given(method("GET"))
        .and(path("/left-pad"))
        .and(header("if-none-match", "\"v1\""))
        .respond_with(ResponseTemplate::new(304).insert_header("etag", "\"v1\""))
        .mount(&upstream.server)
        .await;

    let url = upstream
        .origins
        .url_for(OriginKind::NpmMetadata, &["left-pad"])
        .expect("the test origin builds its own URL");
    let mut request = metadata(url);
    request.validators = Some(UpstreamValidators {
        etag: Some("\"v1\"".to_owned()),
        last_modified: None,
    });

    match upstream.transport.fetch_metadata(request).await {
        Ok(MetadataResponse::NotModified { validators }) => {
            assert_eq!(validators.etag.as_deref(), Some("\"v1\""))
        }
        Ok(MetadataResponse::Fresh { .. }) => panic!("a 304 carries no body to call fresh"),
        Ok(MetadataResponse::Missing) => panic!("a 304 is not an upstream miss"),
        Err(err) => panic!("a 304 must not be an error, got {err:?}"),
    }
}

/// reqwest exposes no response-size cap, so the only thing enforcing `max_bytes` is
/// our own counted loop over `bytes_stream`. This asks a real socket for a body
/// bigger than the cap and checks that the loop, not the client, stops it.
#[tokio::test]
async fn an_oversized_upstream_body_is_refused_by_the_counted_read() {
    let upstream = upstream().await;
    Mock::given(method("GET"))
        .and(path("/huge"))
        .respond_with(ResponseTemplate::new(200).set_body_string("x".repeat(4096)))
        .mount(&upstream.server)
        .await;

    let url = upstream
        .origins
        .url_for(OriginKind::NpmMetadata, &["huge"])
        .expect("the test origin builds its own URL");
    let mut request = metadata(url.clone());
    request.max_bytes = 1024;

    assert_eq!(
        upstream.transport.fetch_metadata(request).await.err(),
        Some(UpstreamError::TooLarge { limit: 1024 }),
    );

    // The same body under a cap that fits still arrives whole, so what failed above
    // was the cap and not the read.
    let mut request = metadata(url);
    request.max_bytes = 8192;
    match upstream.transport.fetch_metadata(request).await {
        Ok(MetadataResponse::Fresh { body, .. }) => assert_eq!(body.len(), 4096),
        other => panic!("expected the whole body, got {:?}", other.err()),
    }
}

/// SPEC §9: artifact transfers are not content-decoded, so the bytes we hash and
/// cache are the distribution itself. The metadata client is the contrast — it
/// *does* decode — and the two are only different because they are two clients.
#[tokio::test]
async fn the_artifact_client_does_not_decode_what_the_metadata_client_does() {
    // `gzip -n -9` over "hello upstream". Embedded rather than generated, so this
    // test needs no compression dependency to say what a codec would have done.
    const GZIPPED: &[u8] = &[
        31, 139, 8, 0, 0, 0, 0, 0, 2, 3, 203, 72, 205, 201, 201, 87, 40, 45, 40, 46, 41, 74, 77,
        204, 5, 0, 221, 41, 155, 225, 14, 0, 0, 0,
    ];

    let upstream = upstream().await;
    Mock::given(method("GET"))
        .and(path("/tarball.tgz"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-encoding", "gzip")
                .set_body_bytes(GZIPPED),
        )
        .mount(&upstream.server)
        .await;

    let url = upstream
        .origins
        .url_for(OriginKind::PypiArtifacts, &["tarball.tgz"])
        .expect("the test origin builds its own URL");

    let body = upstream
        .transport
        .open_artifact(ArtifactRequest {
            url: url.clone(),
            max_bytes: A_MEGABYTE,
        })
        .await
        .expect("the artifact is served");
    let bytes: Vec<u8> = body
        .stream
        .fold(Vec::new(), |mut bytes, chunk| async move {
            bytes.extend_from_slice(&chunk.expect("a body chunk"));
            bytes
        })
        .await;
    assert_eq!(
        bytes, GZIPPED,
        "the artifact client handed back the transferred bytes, undecoded"
    );

    // The metadata client, given the same response, decodes it — which is what makes
    // the assertion above a property of the client rather than of wiremock.
    match upstream.transport.fetch_metadata(metadata(url)).await {
        Ok(MetadataResponse::Fresh { body, .. }) => {
            assert_eq!(body.as_ref(), b"hello upstream")
        }
        other => panic!("expected a decoded metadata body, got {:?}", other.err()),
    }
}

// ---------------------------------------------------------------------------
// UNKNOWN-2: the URL a name cannot rewrite
// ---------------------------------------------------------------------------

/// The threat model's second `UNKNOWN`. `Url::join` resolves its argument as a
/// reference, so `//evil.test` or `https://evil.test/x` would replace the host;
/// `PathSegmentsMut::push` percent-encodes instead, and `admit` re-checks the result.
///
/// Each name below is one of the five shapes that break a joined or concatenated
/// URL, and none of them may move the host, the port, the scheme or the path prefix.
/// `PathSegmentsMut::push` silently *drops* a segment that is exactly `.` or `..`
/// (`url-2.5.8/src/path_segments.rs:246-249` is a bare `continue`). So building a URL
/// from such a name yields the bare origin root, `admit` passes it because nothing
/// was appended, and a request for the wrong resource leaves the process. The name
/// has to be refused by `url_for` itself, before a byte moves.
#[test]
fn a_dot_or_dot_dot_package_name_is_refused_not_dropped() {
    for origins in [OriginSet::production(), fake_origins()] {
        let origin = origins.origin(OriginKind::NpmMetadata).clone();
        for name in [".", ".."] {
            assert_eq!(
                origins.url_for(OriginKind::NpmMetadata, &[name]),
                Err(UrlRejection::PathEscape),
                "`{name}` must be refused, not dropped into {origin}"
            );
        }
        // A name that merely *contains* a dot segment is still an ordinary name: it
        // is percent-encoded into one segment and stays perfectly safe.
        assert!(
            origins
                .url_for(OriginKind::NpmMetadata, &["../../etc/passwd"])
                .is_ok(),
            "only an exactly-dot segment is dropped by push, so only it is refused"
        );
    }
}

/// The same rule at the HTTP level. A status that came back from an upstream miss is
/// not a refusal, so the assertion is on the transport call count: zero.
///
/// Slice 5 moved *which* refusal this is. Slice 4 had no npm name validation, so a
/// dot-segment name got as far as `url_for` and its rejection mapped to `404`; slice
/// 5 validates the route component first, and SPEC §11 answers invalid input with
/// `400`. The property this test exists for — nothing reaches upstream — is
/// unchanged, and is now enforced one layer earlier.
#[tokio::test]
async fn a_dot_dot_package_name_never_reaches_upstream() {
    use common::FakeRegistry;

    let registry = FakeRegistry::new();
    let blocklist_dir = tempfile::tempdir().expect("a blocklist directory");
    let server = TestServer::start_with_upstream(
        config_with_open_blocklist(blocklist_dir.path()),
        Arc::new(probation::clock::SystemClock),
        Arc::clone(&registry) as Arc<dyn Transport>,
        fake_origins(),
    )
    .await;

    // Sent raw: `reqwest` would decode `%2E` and strip the dot segment before the
    // request left the client, so only a hand-written request line delivers this.
    for raw in ["/npm/..", "/npm/%2E%2E", "/npm/."] {
        let status = server.raw_get_status(raw).await;
        assert_eq!(status, 400, "{raw} answered {status}");
    }
    assert_eq!(
        registry.calls(),
        Vec::<url::Url>::new(),
        "a dot-segment name must be refused before any upstream call"
    );

    server.shutdown().await;
}

#[test]
fn a_package_name_cannot_change_the_upstream_host() {
    let hostile = [
        "//evil.test",
        "../../etc/passwd",
        "evil.test:8080",
        "https://evil.test/left-pad",
        "a%2fb",
        "%2f%2fevil.test",
        "@evil.test",
        "left-pad?x=1#y",
    ];

    for origins in [OriginSet::production(), fake_origins()] {
        let origin = origins.origin(OriginKind::NpmMetadata).clone();
        for name in hostile {
            let built = origins
                .url_for(OriginKind::NpmMetadata, &[name])
                .unwrap_or_else(|rejection| {
                    panic!("`{name}` was refused rather than encoded: {rejection}")
                });

            assert_eq!(
                built.host_str(),
                origin.host_str(),
                "`{name}` moved the host"
            );
            assert_eq!(
                built.scheme(),
                origin.scheme(),
                "`{name}` changed the scheme"
            );
            assert_eq!(
                built.port_or_known_default(),
                origin.port_or_known_default(),
                "`{name}` changed the port"
            );
            assert!(
                built.username().is_empty() && built.password().is_none(),
                "`{name}` introduced credentials"
            );
            assert_eq!(built.query(), None, "`{name}` introduced a query");
            assert_eq!(built.fragment(), None, "`{name}` introduced a fragment");
            assert_eq!(
                origins.kind_of(&built),
                Some(OriginKind::NpmMetadata),
                "`{name}` built a URL on some other origin"
            );
            assert_eq!(
                origins.admit(&built, OriginKind::NpmMetadata),
                Ok(()),
                "`{name}` built a URL the second gate refuses"
            );
            assert!(
                !built.path().contains("//evil") && !built.as_str().contains("://evil"),
                "`{name}` left an unencoded authority in {built}"
            );
        }
    }

    // What `Url::join` would have done with the same names, so the rule is not just
    // asserted but shown to be load-bearing.
    let origin = parse("https://registry.npmjs.org/");
    assert_eq!(
        origin.join("//evil.test").expect("join parses").host_str(),
        Some("evil.test"),
        "this is the footgun the construction rule exists to avoid"
    );
    assert_eq!(
        origin
            .join("https://evil.test/left-pad")
            .expect("join parses")
            .host_str(),
        Some("evil.test")
    );
}

// ---------------------------------------------------------------------------
// The route
// ---------------------------------------------------------------------------

/// Slice 4's other half: `GET /npm/{package}` now fetches, and the answers are told
/// apart. Not one of the eight named cases, but the route is the reason the boundary
/// is reachable at all, so it is witnessed here rather than nowhere.
#[tokio::test]
async fn the_npm_route_reports_upstream_outcomes_apart() {
    use common::{FakeAnswer, FakeRegistry};

    let registry = FakeRegistry::new();
    registry.answer("/slow", FakeAnswer::Fail(UpstreamError::Timeout));
    registry.answer("/broken", FakeAnswer::Fail(UpstreamError::Status(500)));
    registry.answer("/garbage", FakeAnswer::Body("not json".to_owned()));
    registry.answer("/fine", FakeAnswer::Body(r#"{"name":"fine"}"#.to_owned()));

    let blocklist_dir = tempfile::tempdir().expect("a blocklist directory");
    let server = TestServer::start_with_upstream(
        config_with_open_blocklist(blocklist_dir.path()),
        Arc::new(probation::clock::SystemClock),
        Arc::clone(&registry) as Arc<dyn Transport>,
        fake_origins(),
    )
    .await;

    assert_eq!(
        server.status("/npm/slow").await,
        504,
        "a timeout is its own row"
    );
    assert_eq!(server.status("/npm/broken").await, 502);
    assert_eq!(server.status("/npm/garbage").await, 502);
    assert_eq!(
        server.status("/npm/missing").await,
        404,
        "upstream not having the package is a 404, not a 502"
    );
    // Slice 5 renders this one; slice 4 proves only that it was fetched.
    assert_eq!(server.status("/npm/fine").await, 404);

    let asked: Vec<String> = registry
        .calls()
        .iter()
        .map(|url| url.path().to_owned())
        .collect();
    assert_eq!(asked, ["/slow", "/broken", "/garbage", "/missing", "/fine"]);

    server.shutdown().await;
}
