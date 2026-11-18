//! Slice 28, LS-F9: the outbound denylist for snapshot-sourced registries.

use std::net::{IpAddr, SocketAddr};

use probation::http::service_connector::{Denylist, TargetError, check_target, resolve_checked};
use url::Url;

fn target(text: &str) -> Result<(), TargetError> {
    check_target(&Url::parse(text).unwrap(), &Denylist::default())
}

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

#[test]
fn descriptor_rejects_userinfo_and_ip_spellings() {
    assert_eq!(target("https://user:pw@registry.example.test/"), Err(TargetError::Userinfo));
    assert_eq!(target("https://user@registry.example.test/"), Err(TargetError::Userinfo));
    assert_eq!(target("https://registry.example.test/#frag"), Err(TargetError::Fragment));
    assert_eq!(target("ftp://registry.example.test/"), Err(TargetError::Scheme));
    for spelling in [
        "https://127.0.0.1/",
        "https://2130706433/",
        "https://0x7f.1/",
        "https://0177.0.0.1/",
        "https://127.1/",
        "https://127.0.0.1./",
        "https://[::1]/",
        "https://0.0.0.0/",
        "https://0.1.2.3/",
        "https://169.254.1.1/",
        "https://[fe80::1]/",
    ] {
        assert!(matches!(target(spelling), Err(TargetError::Denied(_))), "{spelling}");
    }
    assert_eq!(target("https://registry.example.test/"), Ok(()));
    assert_eq!(target("https://93.184.216.34/"), Ok(()));
}

#[test]
fn descriptor_ipv4_mapped_ipv6_is_denied() {
    for spelling in ["https://[::ffff:127.0.0.1]/", "https://[::ffff:7f00:1]/", "https://[::ffff:169.254.169.254]/"] {
        assert!(matches!(target(spelling), Err(TargetError::Denied(_))), "{spelling}");
    }
    assert_eq!(target("https://[::ffff:93.184.216.34]/"), Ok(()));
}

#[test]
fn denylist_includes_extended_metadata_addresses() {
    let deny = Denylist::default();
    for text in ["169.254.169.254", "169.254.170.2", "fd00:ec2::254", "100.100.100.200", "192.0.0.192"] {
        assert!(deny.denies(ip(text)), "{text}");
    }
    assert!(!deny.denies(ip("93.184.216.34")));
}

#[test]
fn denylist_unwraps_ipv4_compatible_nat64_6to4() {
    let deny = Denylist::default();
    for text in [
        "::127.0.0.1",                 // IPv4-compatible
        "64:ff9b::7f00:1",             // NAT64 well-known /96
        "2002:7f00:1::",               // 6to4 of 127.0.0.1
        "2002:a9fe:a9fe::1",           // 6to4 of 169.254.169.254
        "2a00:1450::5efe:7f00:1",      // ISATAP of 127.0.0.1
        "64:ff9b:1:7f00:0:100::",      // local-use NAT64 /48 carrying 127.0.0.1 (octets 6,7,9,10)
        "2001:0:4136:e378:8000:63bf:3fff:fdd2", // Teredo is denied outright
    ] {
        assert!(deny.denies(ip(text)), "{text}");
    }
    // The same wrappers around a public address stay usable.
    assert!(!deny.denies(ip("64:ff9b::5db8:d822")), "NAT64 of 93.184.216.34");
    assert!(!deny.denies(ip("2002:5db8:d822::1")), "6to4 of 93.184.216.34");
    assert!(!deny.denies(ip("2a00:1450::5efe:5db8:d822")), "ISATAP of 93.184.216.34");
}

#[test]
fn denylist_embedded_forms_reach_fixpoint() {
    // A mapped address inside an ISATAP wrapper: unwrapped twice.
    let deny = Denylist::default();
    assert!(deny.denies(ip("2002:7f00:1::")));
    assert!(deny.denies(ip("::ffff:127.0.0.1")));
}

#[test]
fn denylist_names_the_listener_and_control_plane() {
    let deny = Denylist::new(Some("203.0.113.5:8080".parse::<SocketAddr>().unwrap()), vec!["10.96.0.0/12".parse().unwrap()]);
    let check = |text: &str| check_target(&Url::parse(text).unwrap(), &deny);
    assert!(matches!(check("https://203.0.113.5:8080/"), Err(TargetError::Denied(_))), "own listener address and port");
    assert_eq!(check("https://203.0.113.5:9000/"), Ok(()), "same host, other port");
    assert!(matches!(check("https://10.96.0.1/"), Err(TargetError::Denied(_))), "control plane range");
}

#[test]
fn connector_refuses_hostname_resolving_to_denied_address() {
    let mut lookup = |_: &str| vec![ip("127.0.0.1")];
    assert!(matches!(resolve_checked("registry.example.test", &mut lookup, &Denylist::default()), Err(TargetError::Denied(_))));
}

#[test]
fn connector_all_resolved_addresses_must_pass() {
    let mut lookup = |_: &str| vec![ip("93.184.216.34"), ip("169.254.169.254")];
    assert!(resolve_checked("registry.example.test", &mut lookup, &Denylist::default()).is_err());
}

#[test]
fn connector_refuses_rebinding_between_resolutions() {
    let mut calls = 0;
    let mut lookup = |_: &str| {
        calls += 1;
        if calls == 1 { vec![ip("93.184.216.34")] } else { vec![ip("127.0.0.1")] }
    };
    let answer = resolve_checked("registry.example.test", &mut lookup, &Denylist::default()).unwrap();
    assert_eq!(answer, vec![ip("93.184.216.34")], "the checked answer is the one dialled");
    assert_eq!(calls, 1, "resolved exactly once; a second answer is never consulted");
}

// ---- LS-F9: the denylist is enforced at connect, on every hop, and proxies are ignored ----

use std::sync::Arc;

use probation::upstream::{MetadataRequest, OriginSet, ReqwestTransport, Transport, UpstreamError};

fn metadata_request(url: &str, cidrs: &[&str]) -> MetadataRequest {
    let url = Url::parse(url).unwrap();
    MetadataRequest {
        origin: Some(Url::parse(&format!("{}://{}/", url.scheme(), url.authority())).unwrap()),
        url,
        private_cidrs: cidrs.iter().map(|c| c.parse().unwrap()).collect(),
        read_authorization: None,
        accept: "application/json",
        validators: None,
        max_bytes: 1024,
    }
}

#[tokio::test]
async fn connector_refuses_hostname_resolving_to_denied_address_at_connect() {
    let transport = ReqwestTransport::for_origins(OriginSet::production()).with_denylist(Arc::new(Denylist::default()));
    // `localhost` resolves to loopback; the registry's own private CIDR cannot unlock it.
    let error = transport.fetch_metadata(metadata_request("https://localhost:9/pkg", &["127.0.0.0/8", "::1/128"])).await.err().expect("refused");
    assert!(matches!(error, UpstreamError::RejectedAddress { .. }), "{error:?}");
}

#[tokio::test]
async fn standalone_loopback_target_still_allowed() {
    // Control: the same target without the snapshot denylist is governed only by the
    // registry's private CIDR, as before (standalone and legacy managed targets).
    let transport = ReqwestTransport::for_origins(OriginSet::production());
    let error = transport.fetch_metadata(metadata_request("https://localhost:9/pkg", &["127.0.0.0/8", "::1/128"])).await.err().expect("nothing listens on port 9");
    assert!(!matches!(error, UpstreamError::RejectedAddress { .. }), "loopback stays dialable without the denylist: {error:?}");
}

#[test]
fn redirect_to_denied_address_is_refused() {
    // Every redirect hop is admitted against the origin it started on and its connected
    // peer is checked with `allows_address`; with the denylist that check refuses a
    // denied address even when the registry's private CIDRs list it.
    let target: Url = "https://registry.example.test/".parse().unwrap();
    let cidrs = vec!["127.0.0.0/8".parse().unwrap(), "169.254.0.0/16".parse().unwrap(), "10.0.0.0/8".parse().unwrap()];
    let plain = OriginSet::selected_npm_with_private(target.clone(), cidrs.clone()).unwrap();
    assert!(plain.allows_address(ip("127.0.0.1")), "without the denylist the CIDR exemption applies");
    let guarded = OriginSet::selected_npm_with_private(target, cidrs).unwrap().with_denylist(Arc::new(Denylist::default()));
    for denied in ["127.0.0.1", "169.254.169.254", "::ffff:127.0.0.1"] {
        assert!(!guarded.allows_address(ip(denied)), "{denied}");
    }
    assert!(guarded.allows_address(ip("10.1.2.3")), "an ordinary private registry stays allowed by its own CIDR");
}

#[cfg(feature = "test-support")]
#[test]
fn service_fixture_loopback_via_seam_only() {
    // Release builds have no `Denylist::only`; the default denylist always denies loopback.
    assert!(Denylist::default().denies(ip("127.0.0.1")));
    let seam = Denylist::only(vec!["10.9.0.0/16".parse().unwrap()]);
    assert!(!seam.denies(ip("127.0.0.1")), "the test seam reaches loopback fakes");
    assert!(seam.denies(ip("10.9.0.1")), "and still denies what the test names");
}

/// Child half of `connector_ignores_proxy_environment`: runs only when the parent sets the
/// proxy variables and this marker.
#[tokio::test]
async fn proxy_environment_child_probe() {
    if std::env::var("PROBATION_PROXY_CHILD").is_err() {
        return;
    }
    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("{}"))
        .mount(&server)
        .await;
    let base: Url = server.uri().parse().unwrap();
    let origins = OriginSet::for_tests(base.clone(), base.clone(), base.clone());
    let transport = ReqwestTransport::for_origins(origins);
    let mut request = metadata_request(&format!("{}/pkg", server.uri()), &["127.0.0.0/8"]);
    request.origin = None;
    assert!(transport.fetch_metadata(request).await.is_ok(), "the request must go direct, not through HTTP_PROXY");
}

#[test]
fn connector_ignores_proxy_environment() {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "proxy_environment_child_probe", "--nocapture"])
        .env("PROBATION_PROXY_CHILD", "1")
        .env("HTTP_PROXY", "http://127.0.0.1:1")
        .env("http_proxy", "http://127.0.0.1:1")
        .env("HTTPS_PROXY", "http://127.0.0.1:1")
        .env("ALL_PROXY", "http://127.0.0.1:1")
        .env_remove("NO_PROXY")
        .output()
        .unwrap();
    assert!(output.status.success(), "{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
}

// ---- R28-1 / S28-2: the own listener, wildcard binds and hostnames ----

/// This machine's primary non-loopback address, or None offline (the tests below skip).
fn own_address() -> Option<IpAddr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("203.0.113.1:9").ok()?;
    let ip = socket.local_addr().ok()?.ip();
    (!ip.is_loopback() && !ip.is_unspecified()).then_some(ip)
}

#[test]
fn listener_wildcard_bind_denies_own_interface_address_with_listener_port() {
    let Some(own) = own_address() else { return };
    let deny = Denylist::new(Some("0.0.0.0:8080".parse().unwrap()), vec![]);
    let at = |ip: IpAddr, port: u16| check_target(&Url::parse(&format!("https://{}:{port}/", if ip.is_ipv6() { format!("[{ip}]") } else { ip.to_string() })).unwrap(), &deny);
    assert!(matches!(at(own, 8080), Err(TargetError::Denied(_))), "own address on the listener port");
    assert_eq!(at(own, 9000), Ok(()), "own address, another port: a legitimate local registry");
    assert_eq!(at(ip("93.184.216.34"), 8080), Ok(()), "a foreign address on the same port");
    let v6 = Denylist::new(Some("[::]:8080".parse().unwrap()), vec![]);
    assert!(matches!(check_target(&Url::parse(&format!("https://{}:8080/", if own.is_ipv6() { format!("[{own}]") } else { format!("[::ffff:{own}]") })).unwrap(), &v6), Err(TargetError::Denied(_))), "a [::] listener also owns the mapped spelling");
}

#[test]
fn endpoint_denial_uses_address_and_port() {
    let Some(own) = own_address() else { return };
    let wild = Denylist::new(Some("0.0.0.0:8080".parse().unwrap()), vec![]);
    assert!(wild.denies_endpoint(own, 8080));
    assert!(!wild.denies_endpoint(own, 8081));
    let bound = Denylist::new(Some(SocketAddr::new("203.0.113.5".parse().unwrap(), 8080)), vec![]);
    assert!(bound.denies_endpoint(ip("203.0.113.5"), 8080));
    assert!(bound.denies_endpoint(ip("::ffff:203.0.113.5"), 8080));
    assert!(!bound.denies_endpoint(ip("203.0.113.5"), 8443));
    assert!(bound.denies_endpoint(ip("127.0.0.1"), 1), "built-in ranges apply on every port");
}

#[test]
fn hostname_resolving_to_own_listener_endpoint_is_refused_with_its_port() {
    let Some(own) = own_address() else { return };
    let deny = Denylist::new(Some("0.0.0.0:8080".parse().unwrap()), vec![]);
    let mut lookup = |_: &str| vec![own];
    assert!(matches!(probation::http::service_connector::resolve_checked_on("registry.example.test", 8080, &mut lookup, &deny), Err(TargetError::Denied(_))));
    let mut lookup = |_: &str| vec![own];
    assert_eq!(probation::http::service_connector::resolve_checked_on("registry.example.test", 9000, &mut lookup, &deny), Ok(vec![own]), "another port passes");
}
