//! T-key-canary (T19d, T19e, C123): only the key's SHA-256 leaves the firewall, and only
//! in the `sync/lookup` body. A sentinel key is sent every way a client can send one,
//! to every authenticated route, through every slice-2 answer; then everything the
//! firewall wrote or sent is searched for the key, its Basic form and its hash.
//!
//! Its own test binary, so the trace level it captures at is the one it asserts.
//! T-key-canary-sync covers the paths that arrive with the sync loop (slice 3). The two
//! take turns, because T-key-canary points the process's proxy variables at a listener
//! that must see nothing.

mod common;

use std::num::NonZeroU64;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::http::StatusCode;
use common::sync::{FakeSyncServer, PLATFORM, base64, client_with_key, org, siem_collector};
use common::{TestClock, TestServer, WiremockUpstream, config_with_open_blocklist};
use probation_policy::api::{ChainLink, KeyId, KeyLookup, LimitSource, OrgId};
use probation_policy::{Block, Ecosystem, Layer, LayerKind, OsvSetting, Switches};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

const SENTINEL: &str = "prb_CANARY0123456789abcdefghijklmnop";

/// The two tests take turns (see the module comment).
static ONE_AT_A_TIME: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
const NOW: &str = "2026-04-06T12:00:00Z";
const PUBLISHED: &str = "2026-01-01T00:00:00Z";
const TARBALL: &str = "left-pad-1.0.0.tgz";
const WHEEL: &str = "alpha-1.0-py3-none-any.whl";
const TARBALL_BYTES: &str = "canary tarball bytes\n";
const WHEEL_BYTES: &str = "canary wheel bytes\n";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Every form of the key that must not leave: the key, its Basic forms, and its hash
/// as lowercase and uppercase hex, as a `{:?}` byte array and as base64.
fn secrets() -> Vec<String> {
    let hash: [u8; 32] = Sha256::digest(SENTINEL.as_bytes()).into();
    vec![
        SENTINEL.to_owned(),
        base64(format!("u:{SENTINEL}")),
        base64(format!("__token__:{SENTINEL}")),
        hex(&hash),
        hex(&hash).to_uppercase(),
        format!("{hash:?}"),
        base64(hash),
    ]
}

/// The npm document and PyPI project, on the wiremock registry the production
/// transport reaches.
async fn mount(upstream: &WiremockUpstream) {
    let npm = json!({
        "name": "left-pad",
        "dist-tags": {"latest": "1.0.0"},
        "versions": {"1.0.0": {
            "name": "left-pad",
            "version": "1.0.0",
            "dist": {"tarball": upstream.url(&format!("/left-pad/-/{TARBALL}"))},
        }},
        "time": {"1.0.0": PUBLISHED},
    });
    let pypi = json!({
        "meta": {"api-version": "1.1"},
        "name": "alpha",
        "versions": [],
        "files": [{
            "filename": WHEEL,
            "url": upstream.url(&format!("/packages/ab/cd/{WHEEL}")),
            "hashes": {"sha256": hex(&Sha256::digest(WHEEL_BYTES.as_bytes()))},
            "upload-time": PUBLISHED,
        }],
    });
    for (at, body) in [
        ("/left-pad".to_owned(), npm.to_string()),
        (format!("/left-pad/-/{TARBALL}"), TARBALL_BYTES.to_owned()),
        ("/simple/alpha/".to_owned(), pypi.to_string()),
        (format!("/packages/ab/cd/{WHEEL}"), WHEEL_BYTES.to_owned()),
    ] {
        let content_type = if at.starts_with("/simple/") {
            "application/vnd.pypi.simple.v1+json"
        } else {
            "application/json"
        };
        Mock::given(method("GET"))
            .and(path(at))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", content_type)
                    .set_body_string(body),
            )
            .mount(&upstream.server)
            .await;
    }
}

/// Everything one response showed the client: status line, headers and body.
async fn shown(response: reqwest::Response) -> (StatusCode, String) {
    let status = response.status();
    let mut text = format!("{status}\n");
    for (name, value) in response.headers() {
        text.push_str(&format!(
            "{name}: {}\n",
            String::from_utf8_lossy(value.as_bytes())
        ));
    }
    text.push_str(&response.text().await.expect("a body"));
    (status, text)
}

#[tokio::test]
async fn t_key_canary() {
    let _turn = ONE_AT_A_TIME.lock().await;
    let captured = common::logs::capture_trace();
    assert!(
        tracing::enabled!(target: "probation::managed", tracing::Level::TRACE),
        "the firewall's own trace lines are captured"
    );

    // R1: a proxy in the environment never sees a lookup. This binary runs one test,
    // so these process-wide variables reach no other test, and they are set before the
    // firewall builds its clients.
    let proxy = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("the proxy binds");
    let proxy_url = format!("http://{}", proxy.local_addr().expect("its address"));
    let proxied = Arc::new(AtomicUsize::new(0));
    tokio::spawn({
        let proxied = Arc::clone(&proxied);
        async move {
            while proxy.accept().await.is_ok() {
                proxied.fetch_add(1, Ordering::SeqCst);
            }
        }
    });
    // SAFETY: set before any thread of this test reads the environment.
    unsafe {
        for name in [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
        ] {
            std::env::set_var(name, &proxy_url);
        }
        std::env::remove_var("NO_PROXY");
        std::env::remove_var("no_proxy");
    }

    let upstream = WiremockUpstream::start().await;
    mount(&upstream).await;
    let sync = FakeSyncServer::start().await;
    sync.layer(
        PLATFORM,
        Layer {
            freeze_seconds: Some(0),
            osv: Some(OsvSetting::Off),
            ..Layer::empty(LayerKind::Platform)
        },
    );
    sync.layer(org(10), Layer::empty(LayerKind::Org));
    let collector = siem_collector().await;

    let dir = tempfile::tempdir().expect("a directory");
    let log_file = dir.path().join("decisions.ndjson");
    let mut config = sync.managed(config_with_open_blocklist(dir.path()));
    config.log_file_path = Some(log_file.clone());
    config.siem_url = Some(collector.uri().parse().expect("the collector's URL"));
    let clock = TestClock::at_rfc3339(NOW);
    let server = TestServer::start_with_upstream(
        config,
        clock.shared(),
        Arc::clone(&upstream.transport),
        upstream.origins.clone(),
    )
    .await;

    let some_id = "ab".repeat(32);
    let routes = [
        "/npm/left-pad".to_owned(),
        format!("/npm/left-pad/-/{TARBALL}"),
        "/pypi/simple/".to_owned(),
        "/pypi/simple/alpha/".to_owned(),
        format!("/npm/artifacts/{some_id}/{TARBALL}"),
        format!("/pypi/artifacts/{some_id}/{WHEEL}"),
    ];
    let bearer = format!("Bearer {SENTINEL}");
    let basic = format!("Basic {}", base64(format!("u:{SENTINEL}")));
    let token_basic = format!("Basic {}", base64(format!("__token__:{SENTINEL}")));
    let oversized = format!(
        "Basic {}",
        base64(format!("u:{SENTINEL}{}", "x".repeat(1024)))
    );
    let mut seen = String::new();
    let mut send = async |route: &str, authorization: &str| {
        let response = server
            .get_with_headers(route, &[("authorization", authorization)])
            .await;
        let (status, text) = shown(response).await;
        seen.push_str(&text);
        status
    };

    // Malformed, oversized, then unknown: 401 everywhere.
    for authorization in [
        format!("Token {SENTINEL}"),
        format!("Bearer {SENTINEL} trailing"),
        oversized,
        bearer.clone(),
        basic.clone(),
    ] {
        for route in &routes {
            assert_eq!(send(route, &authorization).await, 401, "{route}");
        }
    }

    // The server busy (its 429: 503 here) and down (its 503: 401 here). The unknown
    // answer's 30 s are over first, and each group gets a second of its own budget.
    clock.advance_seconds(31);
    sync.answer_lookups_with(Some(StatusCode::TOO_MANY_REQUESTS));
    for route in &routes[..4] {
        assert_eq!(send(route, &bearer).await, 503, "{route}");
    }
    clock.advance_seconds(1);
    sync.answer_lookups_with(Some(StatusCode::SERVICE_UNAVAILABLE));
    for route in &routes[..4] {
        assert_eq!(send(route, &basic).await, 401, "{route}");
    }

    // The server's chain names a newer layer than its `layers` answer holds: busy, and
    // a warning that names neither the key nor its hash.
    clock.advance_seconds(1);
    sync.answer_lookups_with(None);
    sync.answer(
        SENTINEL,
        KeyLookup::Known {
            key_id: KeyId(1),
            org: Some(OrgId(10)),
            account: org(10),
            place_chain: vec![
                ChainLink {
                    place: PLATFORM,
                    layer_revision: 1,
                },
                ChainLink {
                    place: org(10),
                    layer_revision: 5,
                },
            ],
            rate_limit: None,
            rate_limit_source: LimitSource::Default,
            revision: 5,
        },
    );
    assert_eq!(send(&routes[0], &bearer).await, 503, "behind");
    assert!(
        captured.lines_mentioning("holds a layer older than its chain names") >= 1,
        "the busy answer is logged"
    );

    // Known: every route served, as Bearer and as Basic.
    clock.advance_seconds(1);
    sync.known_key(SENTINEL, &[PLATFORM, org(10)]);
    let listing = server
        .get_with_headers("/npm/left-pad", &[("authorization", &bearer)])
        .await;
    let listing: Value = serde_json::from_str(&listing.text().await.unwrap()).unwrap();
    let npm_artifact = common::artifact_path(&listing, "1.0.0");
    let project = server
        .get_with_headers(
            "/pypi/simple/alpha/",
            &[
                ("authorization", &bearer),
                ("accept", "application/vnd.pypi.simple.v1+json"),
            ],
        )
        .await;
    let project: Value = serde_json::from_str(&project.text().await.unwrap()).unwrap();
    let wheel_url = project["files"][0]["url"].as_str().expect("a file URL");
    let pypi_artifact = url::Url::parse(wheel_url).expect("a URL").path().to_owned();
    for route in [
        routes[0].as_str(),
        routes[1].as_str(),
        routes[2].as_str(),
        routes[3].as_str(),
        npm_artifact.as_str(),
        pypi_artifact.as_str(),
    ] {
        for authorization in [&bearer, &basic, &token_basic] {
            assert_eq!(send(route, authorization).await, 200, "{route}");
        }
    }

    let upstream_requests = upstream
        .server
        .received_requests()
        .await
        .expect("wiremock records requests");
    server.shutdown().await;

    assert_eq!(
        proxied.load(Ordering::SeqCst),
        0,
        "no connection reached the proxy"
    );

    // Only the hash leaves, and only to `sync/lookup`.
    let [key, basic_form, token_form, hash, ..] = <[String; 7]>::try_from(secrets()).unwrap();
    let bodies = sync.bodies();
    assert!(
        bodies
            .iter()
            .any(|(at, body)| at.ends_with("/lookup") && body.contains(&hash)),
        "the lookup carried the hash"
    );
    for (at, body) in &bodies {
        assert!(
            !body.contains(&key) && !body.contains(&basic_form) && !body.contains(&token_form),
            "{at}: {body}"
        );
        assert!(
            at.ends_with("/lookup") || !body.contains(&hash),
            "{at}: {body}"
        );
    }

    for request in &upstream_requests {
        assert!(
            request.headers.get("authorization").is_none(),
            "an upstream request carried Authorization: {}",
            request.url
        );
    }
    let upstream_text: String = upstream_requests
        .iter()
        .map(|request| format!("{} {:?}", request.url, request.headers))
        .collect();

    let logs = captured.text();
    assert!(
        logs.contains("request decided"),
        "the decision lines were captured"
    );
    let ndjson = std::fs::read_to_string(&log_file).expect("the decision log");
    assert!(
        ndjson.contains("\"place\":10"),
        "the records name the place"
    );
    let siem: String = collector
        .received_requests()
        .await
        .expect("the collector records requests")
        .iter()
        .map(|request| String::from_utf8_lossy(&request.body).into_owned())
        .collect();
    assert!(siem.contains("request_decided"), "the SIEM sink delivered");

    for secret in secrets() {
        for (what, text) in [
            ("a log line", &logs),
            ("an NDJSON record", &ndjson),
            ("a SIEM body", &siem),
            ("a response", &seen),
            ("an upstream request", &upstream_text),
        ] {
            assert!(!text.contains(&secret), "{what} carries {secret}");
        }
    }
}

/// T-key-canary-sync (C123): the paths the sync loop brings — a network-lock 403, a
/// per-account 429, an answer served stale while the server is down, and the activity
/// rows and reports sent to the server — carry no form of the key.
#[tokio::test]
async fn t_key_canary_sync() {
    let _turn = ONE_AT_A_TIME.lock().await;
    let captured = common::logs::capture_trace();
    assert!(tracing::enabled!(target: "probation::managed", tracing::Level::TRACE));

    let upstream = WiremockUpstream::start().await;
    mount(&upstream).await;
    let sync = FakeSyncServer::start().await;
    sync.layer(
        PLATFORM,
        Layer {
            freeze_seconds: Some(0),
            osv: Some(OsvSetting::Off),
            allow: Switches::ALL,
            ..Layer::empty(LayerKind::Platform)
        },
    );
    sync.layer(
        org(20),
        Layer {
            blocks: vec![Block::Package {
                ecosystem: Ecosystem::Npm,
                name: "left-pad".to_owned(),
                reason: None,
            }],
            ..Layer::empty(LayerKind::Org)
        },
    );
    // The sentinel is a Globex key, refused inside Acme's range and limited to 3 a
    // minute.
    sync.known_key_limited(SENTINEL, &[PLATFORM, org(20)], Some(3));
    sync.set_ranges(&[("127.0.7.0/24", 10)]);

    let dir = tempfile::tempdir().expect("a directory");
    let log_file = dir.path().join("decisions.ndjson");
    let mut config = sync.managed(config_with_open_blocklist(dir.path()));
    config.log_file_path = Some(log_file.clone());
    // T2: every channel a slice-3 path could leak through, the SIEM sink included.
    let collector = siem_collector().await;
    config.siem_url = Some(collector.uri().parse().expect("the collector's URL"));
    config.sync_interval_seconds = NonZeroU64::new(2).unwrap();
    let management = config.management.as_mut().unwrap();
    management.sync_margin_seconds = NonZeroU64::new(1).unwrap();
    management.request_timeout_seconds = NonZeroU64::new(1).unwrap();
    management.key_cache_ttl_seconds = NonZeroU64::new(1).unwrap();
    let clock = TestClock::at_rfc3339(NOW);
    let server = TestServer::start_with_upstream(
        config,
        clock.shared(),
        Arc::clone(&upstream.transport),
        upstream.origins.clone(),
    )
    .await;

    let mut seen = String::new();
    let client = client_with_key(SENTINEL);
    let mut statuses = Vec::new();
    // Blocked (an activity row), then served twice, then over the rate (429).
    for route in [
        format!("/npm/left-pad/-/{TARBALL}"),
        "/pypi/simple/alpha/".to_owned(),
        "/pypi/simple/".to_owned(),
        "/npm/left-pad".to_owned(),
    ] {
        let (status, text) = shown(client.get(server.url(&route)).send().await.unwrap()).await;
        statuses.push(status.as_u16());
        seen.push_str(&text);
    }
    assert_eq!(statuses, [403, 200, 200, 429]);

    // The network lock: a 403 and a row naming the address, the key sent as Basic (T2).
    clock.advance_seconds(61);
    let inside = reqwest::Client::builder()
        .no_proxy()
        .local_address(std::net::IpAddr::from([127, 0, 7, 1]))
        .build()
        .unwrap();
    let response = inside
        .get(server.url("/npm/left-pad"))
        .header(
            "authorization",
            format!("Basic {}", base64(format!("u:{SENTINEL}"))),
        )
        .send()
        .await
        .unwrap();
    let (status, text) = shown(response).await;
    assert_eq!(status, 403);
    seen.push_str(&text);

    // Served stale while the server is down.
    sync.go_down(true);
    clock.advance_seconds(2);
    // The first is asked about and served when the lookup fails; the server is then
    // marked down, and the second is served with no lookup.
    for authorization in [
        format!("Bearer {SENTINEL}"),
        format!("Basic {}", base64(format!("__token__:{SENTINEL}"))),
    ] {
        let response = reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .get(server.url("/pypi/simple/"))
            .header("authorization", authorization)
            .send()
            .await
            .unwrap();
        let (status, text) = shown(response).await;
        assert_eq!(status, 200, "served stale");
        seen.push_str(&text);
    }
    sync.go_down(false);
    sync.sync_rounds(2).await;
    server.shutdown().await;

    let delivered: Vec<_> = sync.delivered();
    let rows: Vec<_> = delivered
        .iter()
        .flat_map(|request| &request.activity)
        .collect();
    assert!(
        rows.iter().any(|row| row.rule == "blocked_package"),
        "{rows:?}"
    );
    assert!(
        rows.iter().any(|row| row.rule == "network_lock"),
        "{rows:?}"
    );
    let [key, basic_form, token_form, hash, ..] = <[String; 7]>::try_from(secrets()).unwrap();
    for (at, body) in sync.bodies() {
        assert!(
            !body.contains(&key) && !body.contains(&basic_form) && !body.contains(&token_form),
            "{at}: {body}"
        );
        assert!(
            at.ends_with("/lookup") || !body.contains(&hash),
            "{at}: {body}"
        );
    }
    let changes: String = sync
        .bodies()
        .into_iter()
        .filter(|(at, _)| at.ends_with("/changes"))
        .map(|(_, body)| body)
        .collect();
    assert!(
        changes.contains("\"activity\":[{"),
        "activity went out: {changes}"
    );
    let ndjson = std::fs::read_to_string(&log_file).expect("the decision log");
    let logs = captured.text();
    let siem: String = collector
        .received_requests()
        .await
        .expect("the collector records requests")
        .iter()
        .map(|request| String::from_utf8_lossy(&request.body).into_owned())
        .collect();
    assert!(
        siem.matches("request_decided").count() >= 7,
        "the SIEM sink got every decision"
    );
    for secret in secrets() {
        for (what, text) in [
            ("a SIEM body", &siem),
            ("a log line", &logs),
            ("an NDJSON record", &ndjson),
            ("a response", &seen),
            ("a changes body", &changes),
        ] {
            assert!(!text.contains(&secret), "{what} carries {secret}");
        }
    }
}
