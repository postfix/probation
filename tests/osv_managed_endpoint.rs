//! Row 30 / C1030 / C1031: a managed endpoint's `OsvClient` against a fake central server.
//! No real api.osv.dev call is made; the fake central server and the "attacker" server
//! record what reaches them.

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use probation::managed::report::UpstreamHealth;
use probation::osv::{CentralOptions, CentralTarget, OsvClient};
use probation_policy::Ecosystem;
use probation_policy::api::Reachability;
use probation_policy::osv_wire::{RenderedResult, render_answer};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use url::Url;

const CREDENTIAL: &str = "fwt_0123456789abcdef0123456789abcdef";

#[derive(Clone)]
enum Mode {
    /// Names starting `mal-` match, names starting `degraded-` are degraded.
    Normal,
    /// The osv.dev shape without the Probation envelope (an old server, a captive portal).
    NoMeta,
    Status(u16),
    UpstreamNotOk,
    Redirect(String),
    Raw(Vec<u8>),
    /// A well-formed answer in which every name is clean.
    AllClean,
}

struct Seen {
    auth: Option<String>,
    path: String,
}

struct Central {
    seen: Mutex<Vec<Seen>>,
    mode: Mutex<Mode>,
}

impl Central {
    fn set(&self, mode: Mode) {
        *self.mode.lock().unwrap() = mode;
    }
    fn requests(&self) -> usize {
        self.seen.lock().unwrap().len()
    }
}

async fn handler(
    State(c): State<Arc<Central>>,
    uri: axum::http::Uri,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> axum::response::Response {
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
    let names: Vec<String> = value["queries"]
        .as_array()
        .map(|q| {
            q.iter()
                .map(|q| q["package"]["name"].as_str().unwrap_or("").to_owned())
                .collect()
        })
        .unwrap_or_default();
    c.seen.lock().unwrap().push(Seen {
        auth: headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned),
        path: uri.path().to_owned(),
    });
    let results = |ok: bool| -> Vec<u8> {
        let rendered: Vec<RenderedResult> = names
            .iter()
            .map(|n| {
                if n.starts_with("mal-") {
                    RenderedResult::Matched(vec![("MAL-2026-1".into(), None)])
                } else if n.starts_with("degraded-") {
                    RenderedResult::Degraded
                } else {
                    RenderedResult::NoMatch
                }
            })
            .collect();
        render_answer(&rendered, ok)
    };
    let mode = c.mode.lock().unwrap().clone();
    match mode {
        Mode::Normal => results(true).into_response(),
        Mode::UpstreamNotOk => results(false).into_response(),
        Mode::NoMeta => {
            let r: Vec<serde_json::Value> = names
                .iter()
                .map(|n| {
                    if n.starts_with("mal-") {
                        serde_json::json!({"vulns": [{"id": "MAL-2026-1"}]})
                    } else {
                        serde_json::json!({})
                    }
                })
                .collect();
            axum::Json(serde_json::json!({"results": r})).into_response()
        }
        Mode::Status(code) => StatusCode::from_u16(code).unwrap().into_response(),
        Mode::Redirect(to) => (StatusCode::TEMPORARY_REDIRECT, [("location", to)]).into_response(),
        Mode::Raw(bytes) => bytes.into_response(),
        Mode::AllClean => render_answer(
            &names
                .iter()
                .map(|_| RenderedResult::NoMatch)
                .collect::<Vec<_>>(),
            true,
        )
        .into_response(),
    }
}

async fn central() -> (Url, Arc<Central>) {
    let c = Arc::new(Central {
        seen: Mutex::new(Vec::new()),
        mode: Mutex::new(Mode::Normal),
    });
    let router = axum::Router::new()
        .fallback(axum::routing::post(handler))
        .with_state(Arc::clone(&c));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    (Url::parse(&format!("http://{addr}/osv")).unwrap(), c)
}

struct Rig {
    client: OsvClient,
    handle: JoinHandle<()>,
    shutdown: CancellationToken,
    upstreams: Arc<UpstreamHealth>,
}

impl Rig {
    async fn stop(self) {
        self.shutdown.cancel();
        let _ = self.handle.await;
    }
}

fn options() -> CentralOptions {
    CentralOptions {
        cache_ttl: Duration::from_secs(300),
        request_timeout: Duration::from_millis(500),
        stale_window: Duration::from_secs(86_400),
        matches_path: None,
        allow_http: true,
    }
}

fn start(base: Url, options: CentralOptions) -> Rig {
    let shutdown = CancellationToken::new();
    let upstreams = Arc::new(UpstreamHealth::default());
    let (client, handle) = OsvClient::spawn_central(
        CentralTarget {
            base,
            credential: CREDENTIAL.to_owned(),
        },
        options,
        shutdown.clone(),
        Arc::clone(&upstreams),
    );
    Rig {
        client,
        handle,
        shutdown,
        upstreams,
    }
}

async fn check(rig: &Rig, name: &str) -> bool {
    rig.client.check(Ecosystem::Npm, name, "1.0.0").await
}

// ---- tests ------------------------------------------------------------------------

#[tokio::test]
async fn managed_endpoint_sends_credential_to_the_server_osv_route_and_reads_the_answer() {
    let (base, c) = central().await;
    let rig = start(base, options());
    let before = rig.client.generation().load(Ordering::SeqCst);
    assert!(check(&rig, "mal-pkg").await);
    assert!(!check(&rig, "left-pad").await);
    {
        let seen = c.seen.lock().unwrap();
        assert_eq!(seen[0].path, "/osv/v1/querybatch");
        assert_eq!(
            seen[0].auth.as_deref(),
            Some(&*format!("Bearer {CREDENTIAL}"))
        );
    }
    // server_verdict_flip_advances_endpoint_generation (C1029 through the real route)
    assert_eq!(rig.client.generation().load(Ordering::SeqCst), before + 1);
    assert!(check(&rig, "mal-pkg").await, "cached");
    assert_eq!(
        rig.client.generation().load(Ordering::SeqCst),
        before + 1,
        "no change for a held match"
    );
    rig.stop().await;
}

#[tokio::test]
async fn osv_credential_not_sent_on_redirect() {
    let (attacker, a) = central().await;
    let (base, c) = central().await;
    c.set(Mode::Redirect(format!(
        "{}/osv/v1/querybatch",
        attacker.as_str().trim_end_matches("/osv")
    )));
    let rig = start(base, options());
    assert!(!check(&rig, "mal-pkg").await);
    assert_eq!(
        a.requests(),
        0,
        "a redirect is never followed, so the attacker sees nothing"
    );
    assert_eq!(rig.upstreams.take_period().osv, Reachability::Unreachable);
    rig.stop().await;
}

#[test]
fn osv_base_url_requires_https_in_managed_mode() {
    let https = Url::parse("https://policy.example.test/").unwrap();
    assert_eq!(
        probation::osv::central_base(&https, false)
            .unwrap()
            .as_str(),
        "https://policy.example.test/osv"
    );
    let with_port = Url::parse("https://policy.example.test:8443").unwrap();
    assert_eq!(
        probation::osv::central_base(&with_port, false)
            .unwrap()
            .as_str(),
        "https://policy.example.test:8443/osv"
    );
    let http = Url::parse("http://policy.example.test/").unwrap();
    assert!(
        probation::osv::central_base(&http, false).is_err(),
        "http is refused in production"
    );
    assert_eq!(
        probation::osv::central_base(&http, true).unwrap().as_str(),
        "http://policy.example.test/osv",
        "only the test seam may be http"
    );
    for bad in [
        "https://u:p@policy.example.test/",
        "https://policy.example.test/?x=1",
        "https://policy.example.test/#f",
    ] {
        assert!(
            probation::osv::central_base(&Url::parse(bad).unwrap(), false).is_err(),
            "{bad}"
        );
    }
}

#[tokio::test]
async fn osv_test_seam_never_carries_credential() {
    // The plain `osv_base_url` seam is the osv.dev-shaped path with no credential.
    let (base, c) = central().await;
    let url = Url::parse(&format!("{}/v1/querybatch", base)).unwrap();
    c.set(Mode::NoMeta);
    let shutdown = CancellationToken::new();
    let (client, handle) = OsvClient::spawn_with(
        reqwest::Client::new(),
        url,
        Duration::from_secs(60),
        Duration::from_millis(500),
        shutdown.clone(),
        Arc::default(),
    );
    assert!(
        client.check(Ecosystem::Npm, "mal-pkg", "1.0.0").await,
        "plain osv.dev parsing, no meta requirement"
    );
    assert_eq!(c.seen.lock().unwrap()[0].auth, None);
    shutdown.cancel();
    let _ = handle.await;
}

#[tokio::test]
async fn osv_central_answer_without_meta_is_unreached_and_old_server_degrades_not_fails() {
    let (base, c) = central().await;
    c.set(Mode::NoMeta);
    let rig = start(base, options());
    assert!(
        !check(&rig, "mal-pkg").await,
        "nothing from an answer without the envelope is honoured"
    );
    assert_eq!(
        rig.client.cached(Ecosystem::Npm, "mal-pkg", "1.0.0"),
        None,
        "nothing stored"
    );
    assert_eq!(rig.upstreams.take_period().osv, Reachability::Unreachable);
    assert_eq!(rig.upstreams.osv_server_unreached(), 1);
    rig.stop().await;
}

#[tokio::test]
async fn osv_header_stripped_cannot_erase_match() {
    let (base, c) = central().await;
    let rig = start(base, options());
    assert!(check(&rig, "mal-pkg").await);
    rig.client.advance_clock(Duration::from_secs(301));
    // The refresh comes back as a bare osv.dev-shaped answer (envelope stripped).
    c.set(Mode::NoMeta);
    c.seen.lock().unwrap().clear();
    assert!(
        check(&rig, "mal-pkg").await,
        "the retained match still refuses"
    );
    assert_eq!(
        c.requests(),
        1,
        "a refresh was asked and could not erase it"
    );
    rig.stop().await;
}

#[tokio::test]
async fn osv_per_result_degraded_isolated() {
    let (base, _c) = central().await;
    let rig = start(base, options());
    let (a, b, d) = tokio::join!(
        check(&rig, "alpha"),
        check(&rig, "degraded-beta"),
        check(&rig, "mal-gamma")
    );
    assert_eq!((a, b, d), (false, false, true));
    assert_eq!(
        rig.client.cached(Ecosystem::Npm, "alpha", "1.0.0"),
        Some(false),
        "neighbour stored"
    );
    assert_eq!(
        rig.client.cached(Ecosystem::Npm, "mal-gamma", "1.0.0"),
        Some(true)
    );
    assert_eq!(
        rig.client.cached(Ecosystem::Npm, "degraded-beta", "1.0.0"),
        None,
        "the degraded one is not"
    );
    rig.stop().await;
}

#[tokio::test]
async fn managed_osv_survives_server_unavailable_per_c1031() {
    let (base, c) = central().await;
    let rig = start(base, options());
    assert!(check(&rig, "mal-pkg").await);
    assert!(!check(&rig, "clean-pkg").await);
    rig.client.advance_clock(Duration::from_secs(301));
    c.set(Mode::Status(500));
    assert!(
        check(&rig, "mal-pkg").await,
        "a matched entry past its TTL still refuses while the server is down"
    );
    assert!(
        !check(&rig, "clean-pkg").await,
        "a no-match past its TTL does not"
    );
    // osv_degraded_answer_keeps_stale_match: a degraded or upstream-not-ok answer cannot replace it.
    c.set(Mode::UpstreamNotOk);
    assert!(check(&rig, "mal-pkg").await);
    // A refreshed non-degraded answer replaces the stale match.
    c.set(Mode::Normal);
    assert!(check(&rig, "mal-pkg").await);
    rig.stop().await;
}

#[tokio::test]
async fn managed_stale_match_is_replaced_by_a_refreshed_no_match() {
    let (base, c) = central().await;
    let rig = start(base, options());
    assert!(check(&rig, "mal-pkg").await);
    rig.client.advance_clock(Duration::from_secs(301));
    c.set(Mode::AllClean);
    assert!(
        !check(&rig, "mal-pkg").await,
        "only a non-degraded 2xx may replace a match"
    );
    assert_eq!(
        rig.client.cached(Ecosystem::Npm, "mal-pkg", "1.0.0"),
        Some(false)
    );
    rig.stop().await;
}

#[tokio::test]
async fn osv_stale_window_ends_protection_and_counts_it() {
    let (base, c) = central().await;
    let rig = start(
        base,
        CentralOptions {
            stale_window: Duration::from_secs(3600),
            ..options()
        },
    );
    assert!(check(&rig, "mal-pkg").await);
    c.set(Mode::Status(500));
    rig.client.advance_clock(Duration::from_secs(300 + 3601));
    assert!(
        !check(&rig, "mal-pkg").await,
        "past the stale window the match no longer refuses"
    );
    assert_eq!(rig.upstreams.osv_stale_matches_expired(), 1);
    rig.stop().await;
}

#[tokio::test]
async fn osv_unauthorized_or_limited_marks_upstream_unreached() {
    for status in [401u16, 403, 404, 413, 429, 500, 503] {
        let (base, c) = central().await;
        c.set(Mode::Status(status));
        let rig = start(base, options());
        assert!(!check(&rig, "left-pad").await);
        assert_eq!(
            rig.upstreams.take_period().osv,
            Reachability::Unreachable,
            "{status}"
        );
        rig.stop().await;
    }
    let (base, c) = central().await;
    let rig = start(base.clone(), options());
    assert!(!check(&rig, "left-pad").await);
    assert_eq!(
        rig.upstreams.take_period().osv,
        Reachability::Ok,
        "a non-degraded 2xx is reached"
    );
    c.set(Mode::UpstreamNotOk);
    assert!(!check(&rig, "another").await);
    assert_eq!(
        rig.upstreams.take_period().osv,
        Reachability::Unreachable,
        "upstream_ok=false is not reached"
    );
    rig.stop().await;
}

#[tokio::test]
async fn osv_401_never_creates_or_clears_refusal() {
    // The OSV client is handed no reference to the policy refusal store (structural: its
    // constructor takes none). Behaviourally: a 401/403 on the OSV route leaves a refusal
    // marker in the data directory exactly as it was, and creates none.
    let data = tempfile::tempdir().unwrap();
    let marker = data.path().join("service-policy.refused");
    for status in [401u16, 403] {
        for present in [false, true] {
            let _ = std::fs::remove_file(&marker);
            if present {
                std::fs::write(&marker, b"refused\n").unwrap();
            }
            let (base, c) = central().await;
            c.set(Mode::Status(status));
            let rig = start(
                base,
                CentralOptions {
                    matches_path: Some(data.path().join("osv-matches")),
                    ..options()
                },
            );
            assert!(!check(&rig, "left-pad").await);
            rig.stop().await;
            assert_eq!(
                marker.exists(),
                present,
                "status {status}, marker was {present}"
            );
        }
    }
    // A 2xx never clears it either.
    std::fs::write(&marker, b"refused\n").unwrap();
    let (base, _c) = central().await;
    let rig = start(base, options());
    assert!(!check(&rig, "left-pad").await);
    rig.stop().await;
    assert!(marker.exists());
}

#[tokio::test]
async fn managed_osv_fails_open_within_timeout_when_server_down() {
    // Nothing listens: the connection is refused at once.
    let dead = Url::parse("http://127.0.0.1:1/osv").unwrap();
    let rig = start(dead, options());
    let started = std::time::Instant::now();
    assert!(!check(&rig, "never-asked-before").await);
    assert!(started.elapsed() < Duration::from_millis(1500));
    assert_eq!(rig.upstreams.take_period().osv, Reachability::Unreachable);
    rig.stop().await;
}

#[tokio::test]
async fn osv_answer_cap_rejects_oversize_server_answer() {
    let (base, c) = central().await;
    // One query allows 8192 + 4096 bytes; the server sends more.
    c.set(Mode::Raw(vec![b' '; 8192 + 4096 + 1]));
    let rig = start(base, options());
    assert!(!check(&rig, "left-pad").await);
    assert_eq!(rig.upstreams.take_period().osv, Reachability::Unreachable);
    rig.stop().await;
}

#[tokio::test]
async fn osv_degraded_counters_and_ratio_alert_raised_and_cleared() {
    let (base, _c) = central().await;
    let rig = start(base, options());
    let _ = tokio::join!(check(&rig, "a"), check(&rig, "degraded-b"));
    assert_eq!(rig.upstreams.osv_results_total(), 2);
    assert_eq!(rig.upstreams.osv_results_degraded(), 1);
    rig.stop().await;

    // LS-F7: warn when degraded/total exceeds 5% over 5 minutes; cleared when the window empties.
    let health = UpstreamHealth::default();
    let t0 = std::time::Instant::now();
    health.record_osv_results_at(t0, 100, 4);
    assert!(
        !health.osv_degraded_warning(t0),
        "4% is below the threshold"
    );
    health.record_osv_results_at(t0, 100, 8);
    assert!(health.osv_degraded_warning(t0), "6% is above it");
    assert!(
        !health.osv_degraded_warning(t0 + Duration::from_secs(301)),
        "the window moved on and the warning clears"
    );
    health.record_osv_results_at(t0 + Duration::from_secs(302), 100, 0);
    assert!(!health.osv_degraded_warning(t0 + Duration::from_secs(303)));
}

#[tokio::test]
async fn osv_generation_bump_follows_store() {
    let (base, _c) = central().await;
    let rig = start(base, options());
    let generation = rig.client.generation();
    type Observed = Arc<Mutex<Option<(Option<bool>, u64)>>>;
    let seen: Observed = Arc::default();
    let observer = Arc::clone(&seen);
    let counter = Arc::clone(&generation);
    rig.client.set_put_hook(Box::new(move |view| {
        // Between the store and the bump: the entry is already readable, the counter has not moved.
        *observer.lock().unwrap() = Some((
            view.get(Ecosystem::Npm, "mal-pkg", "1.0.0"),
            counter.load(Ordering::SeqCst),
        ));
    }));
    let before = generation.load(Ordering::SeqCst);
    assert!(check(&rig, "mal-pkg").await);
    let (entry, count) = seen.lock().unwrap().take().expect("the hook ran");
    assert_eq!(
        entry,
        Some(true),
        "the matched entry is already readable at the hook"
    );
    assert_eq!(count, before, "the counter has not moved yet");
    assert_eq!(generation.load(Ordering::SeqCst), before + 1);
    rig.stop().await;
}

#[tokio::test]
async fn osv_matches_survive_restart_and_eviction_during_server_outage() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("osv-matches");
    let (base, c) = central().await;
    let rig = start(
        base.clone(),
        CentralOptions {
            matches_path: Some(path.clone()),
            ..options()
        },
    );
    assert!(check(&rig, "mal-pkg").await);
    rig.stop().await;
    assert!(path.exists(), "written when the match was stored");

    // A restart during a server outage: the match comes back from disk and still refuses.
    c.set(Mode::Status(503));
    let rig = start(
        base,
        CentralOptions {
            matches_path: Some(path.clone()),
            ..options()
        },
    );
    assert!(check(&rig, "mal-pkg").await, "loaded at startup");
    // Eviction pressure cannot drop it: matched entries are exempt from LRU eviction.
    rig.client.fill_unmatched_for_test(70_000);
    assert!(check(&rig, "mal-pkg").await);
    rig.stop().await;
}

#[tokio::test]
async fn osv_matches_file_corrupt_loads_empty_and_does_not_block_startup() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("osv-matches");
    std::fs::write(&path, b"\x00\x01 not a matches file").unwrap();
    let (base, _c) = central().await;
    let rig = start(
        base,
        CentralOptions {
            matches_path: Some(path),
            ..options()
        },
    );
    assert!(!check(&rig, "left-pad").await, "started and answering");
    assert_eq!(
        rig.upstreams.osv_matches_file_degraded(),
        1,
        "a health warning, not a startup failure"
    );
    rig.stop().await;
}

#[tokio::test]
async fn osv_matches_pruned_at_configured_stale_window() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("osv-matches");
    let (base, c) = central().await;
    let rig = start(
        base.clone(),
        CentralOptions {
            matches_path: Some(path.clone()),
            stale_window: Duration::from_secs(3600),
            ..options()
        },
    );
    assert!(check(&rig, "mal-pkg").await);
    rig.stop().await;
    // The stored expiry is clamped to the configured window: a restart "later" than that
    // finds nothing to keep. The file's expiry is rewritten to a far future first.
    let text = std::fs::read_to_string(&path).unwrap();
    let far = 4_000_000_000u64;
    let rewritten: String = text
        .lines()
        .map(|line| {
            if line.starts_with('{') {
                let v: serde_json::Value = serde_json::from_str(line).unwrap();
                let (e, n, ver) = (
                    v["e"].as_str().unwrap(),
                    v["n"].as_str().unwrap(),
                    v["v"].as_str().unwrap(),
                );
                let crc = probation::osv::matches::crc32(format!("{e}|{n}|{ver}|{far}").as_bytes());
                format!(r#"{{"e":"{e}","n":"{n}","v":"{ver}","x":{far},"c":"{crc:08x}"}}"#) + "\n"
            } else {
                line.to_owned() + "\n"
            }
        })
        .collect();
    std::fs::write(&path, rewritten).unwrap();
    c.set(Mode::Status(503));
    let rig = start(
        base,
        CentralOptions {
            matches_path: Some(path),
            stale_window: Duration::from_secs(3600),
            ..options()
        },
    );
    rig.client.advance_clock(Duration::from_secs(3601));
    assert!(
        !check(&rig, "mal-pkg").await,
        "a far-future expiry in the file cannot extend protection past the window"
    );
    rig.stop().await;
}

#[tokio::test]
async fn osv_matched_entries_memory_cap() {
    let (base, c) = central().await;
    c.set(Mode::Status(503));
    let rig = start(base, options());
    rig.client.fill_matched_for_test(100_000 + 5);
    assert_eq!(rig.client.matched_len(), 100_000);
    assert!(
        rig.upstreams.osv_matches_file_degraded() >= 1,
        "beyond the cap the nearest-expiry matches are dropped with the health counter"
    );
    rig.stop().await;
}

/// LS-F6: the client validates with the server's own key function; a key it refuses is
/// never sent and never a silent no-match.
#[tokio::test]
async fn osv_server_and_client_share_key_function() {
    let (base, c) = central().await;
    let rig = start(base, options());
    let (bad, good) = tokio::join!(check(&rig, "bad name"), check(&rig, "mal-pkg"));
    assert!(!bad && good);
    assert_eq!(
        rig.client.cached(Ecosystem::Npm, "bad name", "1.0.0"),
        None,
        "not stored as a no-match"
    );
    assert_eq!(c.requests(), 1, "one call, for the one sendable key");
    assert_eq!(rig.upstreams.osv_results_total(), 2);
    assert_eq!(rig.upstreams.osv_results_degraded(), 1);
    // The same verdict as the shared function.
    assert!(probation_policy::osv_key::osv_key(Ecosystem::Npm, "bad name", "1.0.0").is_err());
    // A batch of only refused keys makes no call and records nothing about the server.
    let before = c.requests();
    assert!(!rig.client.check(Ecosystem::Npm, "also bad", "1.0.0").await);
    assert_eq!(c.requests(), before);
    rig.stop().await;
}

/// SEC-1 (visibility): a key refused even at the real maxima is counted and reported, never
/// a silent no-match.
#[tokio::test]
async fn osv_refused_keys_are_counted_and_reported() {
    let (base, c) = central().await;
    let rig = start(base, options());
    assert!(!check(&rig, &"n".repeat(2000)).await);
    assert_eq!(c.requests(), 0, "never sent");
    assert_eq!(rig.upstreams.osv_keys_refused(), 1);
    assert_eq!(rig.upstreams.osv_report().keys_refused, 1);
    rig.stop().await;
}

/// A legacy npm name and a long prerelease version are asked about, not skipped (SEC-1).
#[tokio::test]
async fn osv_long_versions_and_legacy_names_reach_the_server() {
    let (base, c) = central().await;
    let rig = start(base, options());
    let version = format!("1.0.0-{}", "a".repeat(200));
    assert!(!rig.client.check(Ecosystem::Npm, "it's!", &version).await);
    assert_eq!(c.requests(), 1);
    rig.stop().await;
}

/// Code review F1: flushes run concurrently and each persists; the file must end up with every
/// match, never a torn or older snapshot.
#[tokio::test]
async fn osv_persist_is_serialised_across_concurrent_flushes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("osv-matches");
    let (base, _c) = central().await;
    let rig = start(
        base,
        CentralOptions {
            matches_path: Some(path.clone()),
            ..options()
        },
    );
    for round in 0..20 {
        rig.client
            .store_and_persist_concurrently_for_test(16, round);
    }
    let loaded = probation::osv::matches::load_matches(
        &std::fs::read(&path).unwrap(),
        std::time::SystemTime::now(),
        Duration::from_secs(86_400 * 2),
    );
    assert_eq!(loaded.skipped, 0, "no torn lines");
    assert_eq!(
        loaded.entries.len(),
        20 * 16,
        "every stored match is on disk"
    );
    assert_eq!(
        rig.upstreams.osv_matches_file_degraded(),
        0,
        "no rename lost a race"
    );
    rig.stop().await;
}

/// Code review F7: log-only recording reads a match that is past its TTL but inside the stale window.
#[tokio::test]
async fn osv_cached_or_stale_sees_a_stale_window_match() {
    let (base, c) = central().await;
    let rig = start(base, options());
    assert!(check(&rig, "mal-pkg").await);
    rig.client.advance_clock(Duration::from_secs(301));
    c.set(Mode::Status(503));
    assert_eq!(rig.client.cached(Ecosystem::Npm, "mal-pkg", "1.0.0"), None);
    assert_eq!(
        rig.client
            .cached_or_stale(Ecosystem::Npm, "mal-pkg", "1.0.0"),
        Some(true)
    );
    assert_eq!(
        rig.client
            .cached_or_stale(Ecosystem::Npm, "never-seen", "1.0.0"),
        None
    );
    rig.stop().await;
}
