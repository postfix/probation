//! Row 30 / C1030: the policy server's osv.dev-compatible `POST /osv/v1/querybatch`.
//! A fake api.osv.dev is an in-process axum server; no real OSV call is ever made.

mod common;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::{Db, client};
use probation_server::osv::{OsvLimits, OsvState};
use probation_server::sync::SyncState;
use probation_server::tenancy::Actor;
use probation_server::{fleet, keys};
use reqwest::StatusCode;
use serde_json::{Value, json};

// ---- the fake api.osv.dev -------------------------------------------------------

#[derive(Clone)]
enum Mode {
    Normal,
    Status(u16, Option<&'static str>),
    Garbage(Vec<u8>),
    /// Answers one result fewer than the queries.
    Misaligned,
    /// Answers `n` zero bytes of JSON-ish padding.
    Huge(usize),
    /// 4xx for a combined batch, normal for a single key.
    RejectBatches,
    /// 500 for the first call, normal after.
    FailFirst,
}

struct Fake {
    in_flight: AtomicUsize,
    max_in_flight: AtomicUsize,
    calls: AtomicUsize,
    batches: Mutex<Vec<Vec<String>>>,
    mode: Mutex<Mode>,
    delay: Mutex<Duration>,
}

impl Fake {
    fn set(&self, mode: Mode) {
        *self.mode.lock().unwrap() = mode;
    }
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

async fn fake_handler(
    axum::extract::State(fake): axum::extract::State<Arc<Fake>>,
    body: axum::body::Bytes,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    fake.calls.fetch_add(1, Ordering::SeqCst);
    let request: Value = serde_json::from_slice(&body).unwrap();
    let names: Vec<String> = request["queries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|q| q["package"]["name"].as_str().unwrap().to_owned())
        .collect();
    // Pagination: the name `paged` answers a first page without a MAL entry and a token;
    // the page it names carries the MAL entry.
    let tokens: Vec<Option<String>> = request["queries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|q| q["page_token"].as_str().map(str::to_owned))
        .collect();
    if names.iter().any(|n| n == "slowpage") {
        // A chunk whose first key takes 3 x 700 ms of sequential pages.
        tokio::time::sleep(Duration::from_millis(700)).await;
        let page: Vec<Value> = names
            .iter()
            .zip(&tokens)
            .map(|(n, t)| match (n.as_str(), t.as_deref()) {
                ("slowpage", None) => json!({"vulns": [], "next_page_token": "s2"}),
                ("slowpage", Some("s2")) => json!({"vulns": [], "next_page_token": "s3"}),
                _ => json!({}),
            })
            .collect();
        return axum::Json(json!({"results": page})).into_response();
    }
    if names.iter().any(|n| n == "paged") {
        let page: Vec<Value> = names
            .iter()
            .zip(&tokens)
            .map(|(n, t)| match (n.as_str(), t.as_deref()) {
                ("paged", None) => json!({"vulns": [{"id": "GHSA-first"}], "next_page_token": "p2"}),
                ("paged", Some(_)) => json!({"vulns": [{"id": "MAL-2026-5", "modified": "2026-02-02T00:00:00Z"}]}),
                _ => json!({}),
            })
            .collect();
        return axum::Json(json!({"results": page})).into_response();
    }
    fake.batches.lock().unwrap().push(names.clone());
    let delay = *fake.delay.lock().unwrap();
    let now_in_flight = fake.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
    fake.max_in_flight.fetch_max(now_in_flight, Ordering::SeqCst);
    if !delay.is_zero() {
        tokio::time::sleep(delay).await;
    }
    fake.in_flight.fetch_sub(1, Ordering::SeqCst);
    let results = |names: &[String]| -> Value {
        names
            .iter()
            .map(|n| {
                if n.starts_with("mal-") {
                    json!({"vulns": [{"id": "GHSA-aaaa", "modified": "2026-01-01T00:00:00Z"}, {"id": "MAL-2026-1", "modified": "2026-01-02T00:00:00Z"}]})
                } else {
                    json!({})
                }
            })
            .collect()
    };
    let mode = fake.mode.lock().unwrap().clone();
    match mode {
        Mode::Normal => axum::Json(json!({"results": results(&names)})).into_response(),
        Mode::FailFirst if fake.calls.load(Ordering::SeqCst) == 1 => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        Mode::FailFirst => axum::Json(json!({"results": results(&names)})).into_response(),
        Mode::Status(code, retry) => {
            let mut response = StatusCode::from_u16(code).unwrap().into_response();
            if let Some(retry) = retry {
                response.headers_mut().insert("retry-after", retry.parse().unwrap());
            }
            response
        }
        Mode::Garbage(bytes) => bytes.into_response(),
        Mode::Misaligned => axum::Json(json!({"results": results(&names[..names.len() - 1])})).into_response(),
        Mode::Huge(n) => {
            let mut body = br#"{"results":[],"pad":""#.to_vec();
            body.extend(std::iter::repeat_n(b'a', n));
            body.extend(br#""}"#);
            body.into_response()
        }
        Mode::RejectBatches if names.len() > 1 => StatusCode::BAD_REQUEST.into_response(),
        Mode::RejectBatches => {
            if names[0] == "poison" {
                StatusCode::BAD_REQUEST.into_response()
            } else {
                axum::Json(json!({"results": results(&names)})).into_response()
            }
        }
    }
}

async fn fake_upstream() -> (url::Url, Arc<Fake>) {
    let fake = Arc::new(Fake {
        in_flight: AtomicUsize::new(0),
        max_in_flight: AtomicUsize::new(0),
        calls: AtomicUsize::new(0),
        batches: Mutex::new(Vec::new()),
        mode: Mutex::new(Mode::Normal),
        delay: Mutex::new(Duration::ZERO),
    });
    let router = axum::Router::new()
        .route("/v1/querybatch", axum::routing::post(fake_handler))
        .with_state(Arc::clone(&fake));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    (url::Url::parse(&format!("http://{addr}/v1/querybatch")).unwrap(), fake)
}

// ---- the server under test --------------------------------------------------------

struct Rig {
    db: Db,
    base: url::Url,
    osv: Arc<OsvState>,
    fake: Arc<Fake>,
    fw_token: String,
    service_key: String,
    clock_ms: Arc<AtomicU64>,
}

async fn rig_with(configure: impl FnOnce(&mut OsvLimits)) -> Rig {
    rig_proxied(configure, Vec::new()).await
}

async fn rig_proxied(configure: impl FnOnce(&mut OsvLimits), trusted_proxies: Vec<ipnet::IpNet>) -> Rig {
    let db = Db::fresh().await;
    let admin = db.global_admin().await;
    let org = db.org("Osv org").await;
    let (actor, place) = db.as_admin(admin, org).await;
    let service_key = keys::create(&db.app, &actor, &place, "service").await.unwrap().secret;
    let fw_token = fleet::register(&db.app, &Actor::Operator, "fw", &["127.0.0.0/8".parse().unwrap()])
        .await
        .unwrap()
        .token;
    let (upstream, fake) = fake_upstream().await;
    let sync = Arc::new(SyncState::new(db.app.clone(), trusted_proxies, None));
    let mut limits = OsvLimits::default();
    configure(&mut limits);
    let base_instant = Instant::now();
    let clock_ms = Arc::new(AtomicU64::new(0));
    let clock = Arc::clone(&clock_ms);
    let osv = Arc::new(
        OsvState::new(Arc::clone(&sync), upstream)
            .with_limits(limits)
            .with_clock(Arc::new(move || base_instant + Duration::from_millis(clock.load(Ordering::SeqCst)))),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = probation_server::build_router_with_osv(sync, Arc::clone(&osv));
    tokio::spawn(async move {
        let _ = axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>()).await;
    });
    Rig {
        db,
        base: url::Url::parse(&format!("http://{addr}/")).unwrap(),
        osv,
        fake,
        fw_token,
        service_key,
        clock_ms,
    }
}

async fn rig() -> Rig {
    rig_with(|_| {}).await
}

impl Rig {
    fn advance(&self, by: Duration) {
        self.clock_ms.fetch_add(by.as_millis() as u64, Ordering::SeqCst);
    }

    async fn post_raw(&self, token: Option<&str>, body: Vec<u8>) -> reqwest::Response {
        let mut request = client().post(self.base.join("osv/v1/querybatch").unwrap()).body(body);
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        request.send().await.unwrap()
    }

    async fn post(&self, token: Option<&str>, queries: &[(&str, &str)]) -> reqwest::Response {
        self.post_raw(token, query_body(queries)).await
    }

    async fn ask(&self, queries: &[(&str, &str)]) -> Value {
        let response = self.post(Some(&self.fw_token), queries).await;
        assert_eq!(response.status(), StatusCode::OK);
        json(response).await
    }
}

fn query_body(queries: &[(&str, &str)]) -> Vec<u8> {
    let queries: Vec<Value> = queries
        .iter()
        .map(|(name, version)| json!({"package": {"name": name, "ecosystem": "npm"}, "version": version}))
        .collect();
    serde_json::to_vec(&json!({"queries": queries})).unwrap()
}

async fn json(response: reqwest::Response) -> Value {
    serde_json::from_slice(&response.bytes().await.unwrap()).unwrap()
}

// ---- tests ------------------------------------------------------------------------

#[tokio::test]
async fn osv_route_requires_authentication() {
    let rig = rig().await;
    let admin = rig.db.global_admin().await;
    let org = rig.db.org("Other").await;
    let (actor, place) = rig.db.as_admin(admin, org).await;
    let revoked = keys::create(&rig.db.app, &actor, &place, "revoked").await.unwrap();
    keys::revoke_as_operator(&rig.db.app, revoked.id).await.unwrap();
    let login = rig.db.login().await;
    let personal = rig.db.personal(login).await;
    let (uactor, uplace) = rig.db.as_admin(admin, personal).await;
    let user_key = keys::create(&rig.db.app, &uactor, &uplace, "user").await.unwrap().secret;

    for token in [
        None,
        Some("fwt_notarealtoken".to_owned()),
        Some(revoked.secret.clone()),
        Some(user_key),
        Some("garbage".to_owned()),
    ] {
        let response = rig.post(token.as_deref(), &[("left-pad", "1.3.0")]).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{token:?}");
    }
    assert_eq!(rig.fake.calls(), 0, "no upstream call without a credential");
    for token in [&rig.fw_token, &rig.service_key] {
        let response = rig.post(Some(token), &[("left-pad", "1.3.0")]).await;
        assert_eq!(response.status(), StatusCode::OK);
    }
}

#[tokio::test]
async fn firewall_token_from_a_disallowed_source_is_401_on_the_osv_route() {
    let rig = rig().await;
    let other = fleet::register(&rig.db.app, &Actor::Operator, "elsewhere", &["10.9.0.0/16".parse().unwrap()])
        .await
        .unwrap();
    let response = rig.post(Some(&other.token), &[("left-pad", "1.3.0")]).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(rig.fake.calls(), 0);
}

#[tokio::test]
async fn response_shape_matches_osv_dev_golden() {
    let rig = rig().await;
    let answer = rig.ask(&[("mal-pkg", "1.0.0"), ("left-pad", "1.3.0")]).await;
    assert_eq!(
        answer,
        json!({
            "results": [
                {"vulns": [{"id": "MAL-2026-1", "modified": "2026-01-02T00:00:00Z"}]},
                {}
            ],
            "probation_osv": {"v": 1, "upstream_ok": true}
        }),
        "osv.dev shape plus exactly the two additive fields; only MAL ids are relayed"
    );
}

#[tokio::test]
async fn server_cache_hit_makes_no_upstream_call_and_ttl_expiry_re_asks() {
    let rig = rig().await;
    rig.ask(&[("left-pad", "1.3.0"), ("mal-pkg", "1.0.0")]).await;
    assert_eq!(rig.fake.calls(), 1);
    rig.ask(&[("left-pad", "1.3.0"), ("mal-pkg", "1.0.0")]).await;
    assert_eq!(rig.fake.calls(), 1, "both answers held");
    rig.advance(Duration::from_secs(31));
    rig.ask(&[("left-pad", "1.3.0"), ("mal-pkg", "1.0.0")]).await;
    assert_eq!(rig.fake.calls(), 2, "the 30 s no-match expired, the match (3600 s) is still held");
    assert_eq!(rig.fake.batches.lock().unwrap()[1], vec!["left-pad".to_owned()]);
    rig.advance(Duration::from_secs(3600));
    rig.ask(&[("mal-pkg", "1.0.0")]).await;
    assert_eq!(rig.fake.calls(), 3, "the match expired too");
}

#[tokio::test]
async fn server_coalesces_identical_concurrent_queries() {
    let rig = Arc::new(rig().await);
    *rig.fake.delay.lock().unwrap() = Duration::from_millis(120);
    let mut tasks = Vec::new();
    for _ in 0..6 {
        let rig = Arc::clone(&rig);
        tasks.push(tokio::spawn(async move { rig.ask(&[("left-pad", "1.3.0")]).await }));
    }
    for task in tasks {
        let answer = task.await.unwrap();
        assert_eq!(answer["probation_osv"]["upstream_ok"], true);
        assert_eq!(answer["results"][0], json!({}));
    }
    assert_eq!(rig.fake.calls(), 1, "six requests, one upstream call");
}

#[tokio::test]
async fn osv_cancelled_waiter_does_not_fail_coalesced_peer() {
    let rig = Arc::new(rig().await);
    *rig.fake.delay.lock().unwrap() = Duration::from_millis(120);
    let leader = {
        let rig = Arc::clone(&rig);
        tokio::spawn(async move { rig.ask(&[("left-pad", "1.3.0")]).await })
    };
    tokio::time::sleep(Duration::from_millis(30)).await;
    let follower = {
        let rig = Arc::clone(&rig);
        tokio::spawn(async move { rig.ask(&[("left-pad", "1.3.0")]).await })
    };
    tokio::time::sleep(Duration::from_millis(30)).await;
    leader.abort();
    let answer = follower.await.unwrap();
    assert_eq!(answer["results"][0], json!({}), "the follower still got the real answer");
    assert_eq!(answer["probation_osv"]["upstream_ok"], true);
    assert_eq!(rig.fake.calls(), 1);
}

#[tokio::test]
async fn osv_batch_limits_refuse_oversize_and_rate_limited() {
    let rig = rig_with(|l| {
        l.key_rate_per_minute = 2;
        l.key_burst = 2;
    })
    .await;
    // Oversize count: 1001 queries is 413 before any work.
    let many: Vec<(String, String)> = (0..1001).map(|i| (format!("p{i}"), "1.0.0".to_owned())).collect();
    let refs: Vec<(&str, &str)> = many.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
    assert_eq!(rig.post(Some(&rig.fw_token), &refs).await.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(rig.fake.calls(), 0);
    // Two keys spend the burst; the next request finds the bucket empty at admission.
    rig.ask(&[("a", "1.0.0"), ("b", "1.0.0")]).await;
    assert_eq!(rig.post(Some(&rig.fw_token), &[("c", "1.0.0")]).await.status(), StatusCode::TOO_MANY_REQUESTS);
    // Another credential has its own budget.
    assert_eq!(rig.post(Some(&rig.service_key), &[("c", "1.0.0")]).await.status(), StatusCode::OK);
    // Cache hits are never charged.
    rig.advance(Duration::from_secs(60));
    rig.ask(&[("a", "1.0.0"), ("b", "1.0.0")]).await;
}

#[tokio::test]
async fn osv_keys_beyond_the_remaining_budget_are_degraded_not_the_batch() {
    let rig = rig_with(|l| {
        l.key_rate_per_minute = 2;
        l.key_burst = 2;
    })
    .await;
    let answer = rig.ask(&[("a", "1"), ("b", "1"), ("c", "1")]).await;
    assert_eq!(answer["results"][0], json!({}));
    assert_eq!(answer["results"][1], json!({}));
    assert_eq!(answer["results"][2], json!({"probation_degraded": true}));
    assert_eq!(answer["probation_osv"]["upstream_ok"], true, "a budget degrade is not an upstream failure");
}

#[tokio::test]
async fn osv_body_cap_before_parse() {
    let rig = rig().await;
    let response = rig.post_raw(Some(&rig.fw_token), vec![b'x'; 1_048_577]).await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    // At the limit the body is read, then parsed and found malformed.
    let response = rig.post_raw(Some(&rig.fw_token), vec![b'x'; 1_048_576]).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    // A valid body padded to exactly the limit is accepted.
    let mut body = query_body(&[("left-pad", "1.3.0")]);
    body.resize(1_048_576, b' ');
    assert_eq!(rig.post_raw(Some(&rig.fw_token), body).await.status(), StatusCode::OK);
}

#[tokio::test]
async fn osv_envelope_defects_return_4xx() {
    let rig = rig().await;
    for body in ["not json", "[]", "{}", r#"{"queries":5}"#, r#"{"queries":[],"queries":[]}"#] {
        let response = rig.post_raw(Some(&rig.fw_token), body.as_bytes().to_vec()).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{body}");
    }
    let empty = rig.ask(&[]).await;
    assert_eq!(empty, json!({"results": [], "probation_osv": {"v": 1, "upstream_ok": true}}));
    assert_eq!(rig.fake.calls(), 0);
}

#[tokio::test]
async fn osv_bad_key_never_fails_batch_mates() {
    let rig = rig().await;
    let body = json!({"queries": [
        {"package": {"name": "left-pad", "ecosystem": "npm"}, "version": "1.3.0"},
        {"package": {"name": "bad name", "ecosystem": "npm"}, "version": "1.3.0"},
        {"package": {"name": "x", "ecosystem": "Maven"}, "version": "1"},
        {"package": {"name": "x", "ecosystem": "npm"}, "version": "1", "commit": "abc"},
        {"package": {"name": "mal-pkg", "ecosystem": "npm"}, "version": "1.0.0"},
    ]});
    let response = rig.post_raw(Some(&rig.fw_token), serde_json::to_vec(&body).unwrap()).await;
    assert_eq!(response.status(), StatusCode::OK);
    let answer: Value = json(response).await;
    let degraded = json!({"probation_degraded": true});
    assert_eq!(answer["results"][0], json!({}));
    assert_eq!(answer["results"][1], degraded, "charset");
    assert_eq!(answer["results"][2], degraded, "unlisted ecosystem");
    assert_eq!(answer["results"][3], degraded, "unknown field");
    assert_eq!(answer["results"][4]["vulns"][0]["id"], "MAL-2026-1");
    assert_eq!(rig.fake.batches.lock().unwrap()[0].len(), 2, "only the two good keys went upstream");
}

#[tokio::test]
async fn osv_duplicate_queries_charged_once() {
    let rig = rig_with(|l| {
        l.key_rate_per_minute = 1;
        l.key_burst = 1;
    })
    .await;
    let answer = rig.ask(&[("a", "1"), ("a", "1"), ("a", "1")]).await;
    assert_eq!(answer["results"], json!([{}, {}, {}]));
    assert_eq!(rig.fake.batches.lock().unwrap()[0], vec!["a".to_owned()]);
}

#[tokio::test]
async fn server_upstream_failure_answers_degraded_and_counts() {
    let rig = rig().await;
    rig.fake.set(Mode::Status(500, None));
    let response = rig.post(Some(&rig.fw_token), &[("left-pad", "1.3.0")]).await;
    assert_eq!(response.status(), StatusCode::OK, "never 5xx for upstream trouble");
    let answer: Value = json(response).await;
    assert_eq!(answer["results"][0], json!({"probation_degraded": true}));
    assert_eq!(answer["probation_osv"]["upstream_ok"], false);
    let health = rig.osv.health();
    assert_eq!((health.results_total, health.results_degraded, health.upstream_failures), (1, 1, 1));
    // osv_failure_not_cached_as_confirmed_no_match
    rig.fake.set(Mode::Normal);
    let answer = rig.ask(&[("left-pad", "1.3.0")]).await;
    assert_eq!(answer["results"][0], json!({}));
    assert_eq!(rig.fake.calls(), 2, "the failure was not cached");
    let health = rig.osv.health();
    assert_eq!((health.results_total, health.results_degraded), (2, 1), "osv_degraded_counters_move");
}

#[tokio::test]
async fn osv_cache_hits_answered_when_upstream_down() {
    let rig = rig().await;
    rig.ask(&[("mal-pkg", "1.0.0")]).await;
    rig.fake.set(Mode::Status(503, None));
    let answer = rig.ask(&[("mal-pkg", "1.0.0"), ("fresh", "1.0.0")]).await;
    assert_eq!(answer["results"][0]["vulns"][0]["id"], "MAL-2026-1", "the held match is still served");
    assert_eq!(answer["results"][1], json!({"probation_degraded": true}));
    assert_eq!(answer["probation_osv"]["upstream_ok"], false);
}

#[tokio::test]
async fn osv_upstream_response_is_size_capped() {
    let rig = rig().await;
    rig.fake.set(Mode::Huge(4 * 1024 * 1024 + 16));
    let answer = rig.ask(&[("left-pad", "1.3.0")]).await;
    assert_eq!(answer["results"][0], json!({"probation_degraded": true}));
    assert_eq!(answer["probation_osv"]["upstream_ok"], false);
}

#[tokio::test]
async fn osv_misaligned_upstream_response_stores_nothing() {
    let rig = rig().await;
    rig.fake.set(Mode::Misaligned);
    let answer = rig.ask(&[("a", "1"), ("b", "1")]).await;
    assert_eq!(answer["results"], json!([{"probation_degraded": true}, {"probation_degraded": true}]));
    rig.fake.set(Mode::Normal);
    rig.ask(&[("a", "1"), ("b", "1")]).await;
    assert_eq!(rig.fake.calls(), 2, "nothing from the misaligned answer was stored");
}

#[tokio::test]
async fn osv_garbage_upstream_body_degrades() {
    let rig = rig().await;
    rig.fake.set(Mode::Garbage(b"<html>captive portal</html>".to_vec()));
    let answer = rig.ask(&[("a", "1")]).await;
    assert_eq!(answer["results"][0], json!({"probation_degraded": true}));
}

#[tokio::test]
async fn osv_4xx_for_a_combined_batch_is_split_per_key() {
    let rig = rig().await;
    rig.fake.set(Mode::RejectBatches);
    let answer = rig.ask(&[("good", "1"), ("poison", "1"), ("mal-pkg", "1.0.0")]).await;
    assert_eq!(answer["results"][0], json!({}));
    assert_eq!(answer["results"][1], json!({"probation_degraded": true}), "only the poisoned key fails");
    assert_eq!(answer["results"][2]["vulns"][0]["id"], "MAL-2026-1");
}

#[tokio::test]
async fn osv_upstream_429_opens_breaker() {
    let rig = rig().await;
    rig.fake.set(Mode::Status(429, Some("3600")));
    let answer = rig.ask(&[("a", "1")]).await;
    assert_eq!(answer["results"][0], json!({"probation_degraded": true}));
    assert_eq!(rig.fake.calls(), 1);
    // osv_breaker_open_bounded_with_jitter: an upstream-controlled 3600 s never holds it
    // longer than 60 s, and a larger or unparsable value counts as 30 s.
    let open = rig.osv.breaker_open_for();
    assert!(open > Duration::ZERO && open <= Duration::from_secs(60), "{open:?}");
    rig.fake.set(Mode::Normal);
    let answer = rig.ask(&[("b", "1")]).await;
    assert_eq!(answer["results"][0], json!({"probation_degraded": true}));
    assert_eq!(rig.fake.calls(), 1, "no upstream call while the breaker is open");
    rig.advance(Duration::from_secs(61));
    let answer = rig.ask(&[("b", "1")]).await;
    assert_eq!(answer["results"][0], json!({}));
}

#[tokio::test]
async fn osv_retry_after_is_capped() {
    let rig = rig().await;
    rig.fake.set(Mode::Status(429, Some("soon")));
    rig.ask(&[("a", "1")]).await;
    let open = rig.osv.breaker_open_for();
    assert!(open >= Duration::from_secs(29) && open <= Duration::from_secs(34), "unparsable counts as 30 s: {open:?}");
}

#[tokio::test]
async fn osv_slow_upstream_and_coalesced_follower_answer_degraded_before_client_timeout() {
    let rig = Arc::new(rig().await);
    *rig.fake.delay.lock().unwrap() = Duration::from_secs(5);
    let started = Instant::now();
    let leader = {
        let rig = Arc::clone(&rig);
        tokio::spawn(async move { rig.ask(&[("slow", "1")]).await })
    };
    tokio::time::sleep(Duration::from_millis(20)).await;
    let follower = rig.ask(&[("slow", "1")]).await;
    let leader = leader.await.unwrap();
    for answer in [leader, follower] {
        assert_eq!(answer["results"][0], json!({"probation_degraded": true}));
        assert_eq!(answer["probation_osv"]["upstream_ok"], false);
    }
    // The upstream would take 5 s; both answers come at the server's own deadline. The
    // deadline itself is strictly below the client's 400 ms floor (asserted exactly, so
    // the proof does not depend on how loaded this host is).
    assert!(started.elapsed() < Duration::from_secs(4), "{:?}", started.elapsed());
    // User decision: server 1500 ms, strictly below the client's 2000 ms default and its
    // 1600 ms floor.
    assert_eq!(OsvLimits::default().deadline, Duration::from_millis(1500));
}

#[tokio::test]
async fn osv_server_cache_bounds_keep_matched() {
    let rig = rig_with(|l| l.cache_entries = 4).await;
    rig.ask(&[("mal-pkg", "1.0.0")]).await;
    // osv_garbage_keys_do_not_evict_matched: many clean keys cannot push a match out.
    for round in 0..3 {
        let names: Vec<String> = (0..4).map(|i| format!("clean-{round}-{i}")).collect();
        let refs: Vec<(&str, &str)> = names.iter().map(|n| (n.as_str(), "1.0.0")).collect();
        rig.ask(&refs).await;
    }
    let before = rig.fake.calls();
    let answer = rig.ask(&[("mal-pkg", "1.0.0")]).await;
    assert_eq!(answer["results"][0]["vulns"][0]["id"], "MAL-2026-1");
    assert_eq!(rig.fake.calls(), before, "the match was still held");
}

#[tokio::test]
async fn osv_flood_does_not_429_sync_routes() {
    let rig = rig_with(|l| {
        l.key_rate_per_minute = 1;
        l.key_burst = 1;
    })
    .await;
    rig.ask(&[("a", "1")]).await;
    for _ in 0..5 {
        assert_eq!(rig.post(Some(&rig.fw_token), &[("z", "1")]).await.status(), StatusCode::TOO_MANY_REQUESTS);
    }
    let response = client()
        .post(rig.base.join("api/v1/sync/layers").unwrap())
        .bearer_auth(&rig.fw_token)
        .header("content-type", "application/json")
        .body(r#"{"places":[]}"#)
        .send()
        .await
        .unwrap();
    assert_ne!(response.status(), StatusCode::TOO_MANY_REQUESTS, "the OSV budget is separate from the sync window");
    assert_ne!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn osv_pre_auth_failures_are_throttled_per_peer() {
    let rig = rig().await;
    for _ in 0..10 {
        assert_eq!(rig.post(Some("fwt_bad"), &[("a", "1")]).await.status(), StatusCode::UNAUTHORIZED);
    }
    assert_eq!(rig.post(Some("fwt_bad"), &[("a", "1")]).await.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[test]
fn osv_server_batch_cap_not_below_client_batch() {
    assert!(OsvLimits::default().batch_max >= 256);
    assert_eq!(OsvLimits::default().batch_max, 1000);
}

#[tokio::test]
async fn osv_server_allowlist_equals_osv_ecosystem() {
    let mapped: Vec<&'static str> = probation_policy::Ecosystem::ALL
        .into_iter()
        .filter_map(probation::osv::osv_ecosystem)
        .collect();
    let mut listed = OsvState::allowlist();
    listed.sort_unstable();
    let mut mapped = mapped;
    mapped.sort_unstable();
    assert_eq!(listed, mapped);
}

#[tokio::test(flavor = "current_thread")]
async fn osv_logs_contain_no_query_keys() {
    #[derive(Clone, Default)]
    struct Sink(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Sink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Sink {
        type Writer = Sink;
        fn make_writer(&'a self) -> Sink {
            self.clone()
        }
    }
    let sink = Sink::default();
    let _guard = tracing::subscriber::set_default(
        tracing_subscriber::fmt().with_writer(sink.clone()).with_max_level(tracing::Level::TRACE).finish(),
    );
    let rig = rig().await;
    rig.fake.set(Mode::Status(500, None));
    rig.ask(&[("secret-internal-name", "9.9.9")]).await;
    rig.ask(&[("bad name", "9.9.9")]).await;
    let logged = String::from_utf8_lossy(&sink.0.lock().unwrap()).into_owned();
    assert!(!logged.contains("secret-internal-name") && !logged.contains("9.9.9"), "{logged}");
}

#[tokio::test]
async fn osv_duplicate_object_keys() {
    let rig = rig().await;
    // At the top level: the envelope is refused. Inside a query: that query alone degrades.
    let envelope = br#"{"queries":[],"queries":[]}"#.to_vec();
    assert_eq!(rig.post_raw(Some(&rig.fw_token), envelope).await.status(), StatusCode::BAD_REQUEST);
    let body = br#"{"queries":[
        {"package":{"name":"a","ecosystem":"npm"},"version":"1"},
        {"package":{"name":"b","ecosystem":"npm","name":"c"},"version":"1"},
        {"package":{"name":"d","ecosystem":"npm"},"version":"1","version":"2"}]}"#
        .to_vec();
    let response = rig.post_raw(Some(&rig.fw_token), body).await;
    assert_eq!(response.status(), StatusCode::OK);
    let answer = json(response).await;
    assert_eq!(answer["results"], json!([{}, {"probation_degraded": true}, {"probation_degraded": true}]));
    assert_eq!(rig.fake.batches.lock().unwrap()[0], vec!["a".to_owned()]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn osv_saturating_load_leaves_sync_latency_within_bound() {
    let rig = Arc::new(rig_with(|l| {
        l.key_burst = 100_000;
        l.key_rate_per_minute = 100_000;
    })
    .await);
    *rig.fake.delay.lock().unwrap() = Duration::from_millis(150);
    let mut flood = Vec::new();
    for i in 0..300 {
        let rig = Arc::clone(&rig);
        flood.push(tokio::spawn(async move {
            let name = format!("flood-{i}");
            rig.post(Some(&rig.fw_token), &[(name.as_str(), "1.0.0")]).await.status()
        }));
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut slowest = Duration::ZERO;
    for _ in 0..10 {
        let started = Instant::now();
        let response = client()
            .post(rig.base.join("api/v1/sync/layers").unwrap())
            .bearer_auth(&rig.fw_token)
            .header("content-type", "application/json")
            .body(r#"{"places":[]}"#)
            .send()
            .await
            .unwrap();
        assert!(!response.status().is_server_error(), "{}", response.status());
        slowest = slowest.max(started.elapsed());
    }
    for task in flood {
        let _ = task.await;
    }
    // Pool starvation shows as a 5xx above or as stalls of seconds; the bound leaves room for a
    // loaded CI host (this test failed once at 2 s while the host load average was above 10).
    assert!(slowest < Duration::from_secs(10), "sync latency under an OSV flood: {slowest:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn osv_upstream_concurrency_is_capped() {
    let rig = Arc::new(rig_with(|l| {
        l.upstream_concurrency = 2;
        l.deadline = Duration::from_secs(5);
    })
    .await);
    *rig.fake.delay.lock().unwrap() = Duration::from_millis(100);
    let mut tasks = Vec::new();
    for i in 0..8 {
        let rig = Arc::clone(&rig);
        tasks.push(tokio::spawn(async move {
            let name = format!("cap-{i}");
            json(rig.post(Some(&rig.fw_token), &[(name.as_str(), "1.0.0")]).await).await
        }));
    }
    for task in tasks {
        assert_eq!(task.await.unwrap()["probation_osv"]["upstream_ok"], true);
    }
    assert_eq!(rig.fake.calls(), 8);
    assert!(rig.fake.max_in_flight.load(Ordering::SeqCst) <= 2, "{}", rig.fake.max_in_flight.load(Ordering::SeqCst));
}

// ---- review fixes (SEC-1 to SEC-5, SEC-9, code-review F5) ---------------------------------

async fn post_with_forwarded(rig: &Rig, token: &str, forwarded: &str) -> reqwest::Response {
    client()
        .post(rig.base.join("osv/v1/querybatch").unwrap())
        .bearer_auth(token.to_owned())
        .header("x-forwarded-for", forwarded.to_owned())
        .body(query_body(&[("left-pad", "1.3.0")]))
        .send()
        .await
        .unwrap()
}

/// SEC-3: the throttle is keyed on the derived client address, not the proxy; a request that
/// authenticates is never throttled.
#[tokio::test]
async fn osv_pre_auth_throttle_follows_the_forwarded_source_and_exempts_valid_requests() {
    let rig = rig_proxied(|_| {}, vec!["127.0.0.1/32".parse().unwrap()]).await;
    for _ in 0..10 {
        assert_eq!(post_with_forwarded(&rig, "fwt_bad", "10.1.1.9").await.status(), StatusCode::UNAUTHORIZED);
    }
    assert_eq!(post_with_forwarded(&rig, "fwt_bad", "10.1.1.9").await.status(), StatusCode::TOO_MANY_REQUESTS, "that address is throttled");
    assert_eq!(
        post_with_forwarded(&rig, "fwt_bad", "10.1.1.10").await.status(),
        StatusCode::UNAUTHORIZED,
        "another client behind the same proxy has its own count"
    );
    assert_eq!(
        post_with_forwarded(&rig, &rig.service_key, "10.1.1.10").await.status(),
        StatusCode::OK,
        "another client behind the same proxy is unaffected"
    );
    assert_eq!(
        post_with_forwarded(&rig, &rig.service_key, "10.1.1.9").await.status(),
        StatusCode::OK,
        "a request that authenticates is exempt even from a throttled address"
    );
}

/// SEC-2: a follower that receives a foreign leader's failure asks for itself.
#[tokio::test]
async fn osv_follower_retries_as_its_own_leader_when_the_leader_fails() {
    let rig = Arc::new(rig_with(|l| l.deadline = Duration::from_secs(3)).await);
    rig.fake.set(Mode::FailFirst);
    *rig.fake.delay.lock().unwrap() = Duration::from_millis(150);
    let attacker = {
        let rig = Arc::clone(&rig);
        tokio::spawn(async move {
            let response = rig.post(Some(&rig.service_key), &[("victim", "1.0.0"), ("other", "1.0.0")]).await;
            json(response).await
        })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;
    let victim = rig.ask(&[("victim", "1.0.0")]).await;
    assert_eq!(victim["results"][0], json!({}), "the victim got a real answer, not the leader's failure");
    assert_eq!(victim["probation_osv"]["upstream_ok"], true);
    let attacker = attacker.await.unwrap();
    assert_eq!(attacker["probation_osv"]["upstream_ok"], false, "the failing leader itself degrades");
    assert_eq!(rig.fake.calls(), 2);
}

/// The leader finishes into the cache past the request deadline, so a retry converges.
#[tokio::test]
async fn osv_leader_completes_into_the_cache_past_the_deadline() {
    let rig = rig_with(|l| l.deadline = Duration::from_millis(200)).await;
    *rig.fake.delay.lock().unwrap() = Duration::from_millis(700);
    let first = rig.ask(&[("slow-but-fine", "1.0.0")]).await;
    assert_eq!(first["results"][0], json!({"probation_degraded": true}), "answered at the deadline");
    tokio::time::sleep(Duration::from_millis(900)).await;
    let second = rig.ask(&[("slow-but-fine", "1.0.0")]).await;
    assert_eq!(second["results"][0], json!({}), "the late upstream answer was kept");
    assert_eq!(second["probation_osv"]["upstream_ok"], true);
    assert_eq!(rig.fake.calls(), 1, "no second upstream call");
}

#[tokio::test]
async fn osv_leader_batches_are_chunked_to_the_client_batch() {
    let rig = rig().await;
    let names: Vec<String> = (0..600).map(|i| format!("chunk-{i}")).collect();
    let refs: Vec<(&str, &str)> = names.iter().map(|n| (n.as_str(), "1.0.0")).collect();
    let answer = rig.ask(&refs).await;
    assert_eq!(answer["probation_osv"]["upstream_ok"], true);
    let sizes: Vec<usize> = rig.fake.batches.lock().unwrap().iter().map(Vec::len).collect();
    assert!(sizes.iter().all(|n| *n <= 256) && sizes.iter().sum::<usize>() == 600, "{sizes:?}");
}

/// SEC-4: cache-hit traffic is metered too.
#[tokio::test]
async fn osv_authenticated_cache_hit_requests_are_rate_limited() {
    let rig = rig_with(|l| {
        l.request_burst = 3;
        l.request_rate_per_second = 1;
    })
    .await;
    rig.ask(&[("left-pad", "1.3.0")]).await;
    let mut statuses = Vec::new();
    for _ in 0..6 {
        statuses.push(rig.post(Some(&rig.fw_token), &[("left-pad", "1.3.0")]).await.status());
    }
    assert!(statuses.contains(&StatusCode::TOO_MANY_REQUESTS), "{statuses:?}");
    assert_eq!(rig.post(Some(&rig.service_key), &[("left-pad", "1.3.0")]).await.status(), StatusCode::OK, "another credential has its own");
}

/// SEC-5: one shared egress; a global key budget keeps many credentials from tripping the
/// upstream limit for everyone, and a breaker opening is counted.
#[tokio::test]
async fn osv_global_key_budget_bounds_all_credentials_together() {
    let rig = rig_with(|l| {
        l.global_key_burst = 3;
        l.global_key_rate_per_minute = 3;
        l.tenant_share_percent = 100;
        l.global_reserve_percent = 0;
    })
    .await;
    let a = rig.ask(&[("a1", "1"), ("a2", "1")]).await;
    assert_eq!(a["results"], json!([{}, {}]));
    let b = json(rig.post(Some(&rig.service_key), &[("b1", "1"), ("b2", "1")]).await).await;
    assert_eq!(b["results"], json!([{}, {"probation_degraded": true}]), "the third key of the minute is over the global budget");
    rig.fake.set(Mode::Status(429, Some("5")));
    rig.advance(Duration::from_secs(120));
    rig.ask(&[("c1", "1")]).await;
    assert_eq!(rig.osv.health().breaker_openings, 1);
}

/// SEC-9: a page token from upstream is followed, so a MAL entry on page two is found.
#[tokio::test]
async fn osv_upstream_pagination_is_followed() {
    let rig = rig().await;
    let answer = rig.ask(&[("paged", "1.0.0")]).await;
    assert_eq!(answer["results"][0]["vulns"][0]["id"], "MAL-2026-5");
    assert_eq!(answer["probation_osv"]["upstream_ok"], true);
    assert_eq!(rig.fake.calls(), 2, "one call per page");
}

// ---- second review round --------------------------------------------------------------

/// SEC-2 (r2): the victim's key sits in a slow multi-page chunk of another credential; the
/// victim must not give up at the deadline behind a call it cannot influence.
#[tokio::test]
async fn osv_follower_fires_its_own_call_behind_a_slow_chunk() {
    let rig = Arc::new(rig().await);
    let attacker = {
        let rig = Arc::clone(&rig);
        tokio::spawn(async move { rig.post(Some(&rig.service_key), &[("slowpage", "1.0.0"), ("victim", "1.0.0")]).await.status() })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    let started = Instant::now();
    let victim = rig.ask(&[("victim", "1.0.0")]).await;
    assert_eq!(victim["results"][0], json!({}), "a real answer, not degraded");
    assert_eq!(victim["probation_osv"]["upstream_ok"], true);
    assert!(started.elapsed() < Duration::from_millis(1500), "{:?}", started.elapsed());
    let _ = attacker.await;
}

/// (b) a healthy leader still makes one call for many followers (no fallback storm).
#[tokio::test]
async fn osv_healthy_leader_still_serves_followers_with_one_call() {
    let rig = Arc::new(rig().await);
    *rig.fake.delay.lock().unwrap() = Duration::from_millis(150);
    let mut tasks = Vec::new();
    for _ in 0..6 {
        let rig = Arc::clone(&rig);
        tasks.push(tokio::spawn(async move { rig.ask(&[("popular", "1.0.0")]).await }));
    }
    for task in tasks {
        assert_eq!(task.await.unwrap()["probation_osv"]["upstream_ok"], true);
    }
    assert_eq!(rig.fake.calls(), 1);
}

/// NEW-1: a flood of bad tokens from one source never occupies the auth gate for a valid caller.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn osv_bad_token_flood_from_a_blocked_source_does_not_starve_valid_callers() {
    let rig = Arc::new(rig().await);
    // Known good before the flood (it authenticated once).
    assert_eq!(rig.post(Some(&rig.service_key), &[("a", "1")]).await.status(), StatusCode::OK);
    for _ in 0..12 {
        let _ = rig.post(Some("fwt_bad"), &[("a", "1")]).await;
    }
    let mut flood = Vec::new();
    for i in 0..300 {
        let rig = Arc::clone(&rig);
        flood.push(tokio::spawn(async move { rig.post(Some(&format!("fwt_bad{i}")), &[("a", "1")]).await.status() }));
    }
    let valid = rig.post(Some(&rig.service_key), &[("a", "1")]).await;
    assert_eq!(valid.status(), StatusCode::OK, "a known credential from the flooded source still gets in");
    let mut throttled = 0;
    for task in flood {
        if task.await.unwrap() == StatusCode::TOO_MANY_REQUESTS {
            throttled += 1;
        }
    }
    assert!(throttled > 200, "the blocked source is turned away without a lookup: {throttled}");
}

/// NEW-2: connections that drip a body hold neither a parse permit nor anyone else's turn.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn osv_slow_bodies_do_not_hold_parse_permits() {
    use tokio::io::AsyncWriteExt;
    let rig = rig_with(|l| {
        l.parse_concurrency = 4;
        l.body_read_timeout = Duration::from_millis(800);
    })
    .await;
    let addr = rig.base.authority().to_owned();
    let mut drippers = Vec::new();
    for _ in 0..8 {
        let mut stream = tokio::net::TcpStream::connect(&addr).await.unwrap();
        let head = format!(
            "POST /osv/v1/querybatch HTTP/1.1\r\nhost: {addr}\r\nauthorization: Bearer {}\r\ncontent-type: application/json\r\ncontent-length: 100000\r\n\r\n{{\"queries\":",
            rig.service_key
        );
        stream.write_all(head.as_bytes()).await.unwrap();
        drippers.push(stream);
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let answer = rig.post(Some(&rig.fw_token), &[("left-pad", "1.3.0")]).await;
    assert_eq!(answer.status(), StatusCode::OK, "another credential is served while bodies drip");
    drop(drippers);
}

/// SEC-5 (r2): one tenant cannot take the whole shared budget; a light tenant keeps a reserve.
#[tokio::test]
async fn osv_one_tenant_cannot_starve_the_global_budget() {
    let rig = rig_with(|l| {
        l.global_key_burst = 40;
        l.global_key_rate_per_minute = 1;
        l.tenant_share_percent = 25;
        l.global_reserve_percent = 25;
    })
    .await;
    // The service key's tenant asks for 30 keys: it is held to its share (10).
    let names: Vec<String> = (0..30).map(|i| format!("greedy-{i}")).collect();
    let refs: Vec<(&str, &str)> = names.iter().map(|n| (n.as_str(), "1")).collect();
    let greedy = json(rig.post(Some(&rig.service_key), &refs).await).await;
    let degraded = greedy["results"].as_array().unwrap().iter().filter(|r| r["probation_degraded"] == true).count();
    assert!(degraded >= 18, "the tenant stopped at its share: {degraded} degraded of 30");
    // Another tenant (the firewall token) still has budget.
    let other = rig.ask(&[("fresh-1", "1"), ("fresh-2", "1")]).await;
    assert_eq!(other["results"], json!([{}, {}]));
}

/// Contract of the body cap against the batch cap: a legal client batch (256 keys at the
/// largest key sizes) is under the 1 MiB cap; 1000 keys at those sizes are over it and the
/// whole envelope is refused 413 before any per-key work (the count cap and the byte cap are
/// independent, and the byte cap wins when keys are large).
#[tokio::test]
async fn osv_body_cap_and_batch_cap_contract_for_maximum_size_keys() {
    let rig = rig().await;
    let big = |n: usize| -> Vec<u8> {
        let queries: Vec<Value> = (0..n)
            .map(|i| json!({"package": {"name": format!("{i:04}{}", "n".repeat(1020)), "ecosystem": "npm"}, "version": "1".repeat(1024)}))
            .collect();
        serde_json::to_vec(&json!({"queries": queries})).unwrap()
    };
    let legal = big(256);
    assert!(legal.len() < 1_048_576, "a maximum-size client batch fits: {}", legal.len());
    let response = rig.post_raw(Some(&rig.fw_token), legal).await;
    assert_eq!(response.status(), StatusCode::OK);
    let oversized = big(1000);
    assert!(oversized.len() > 1_048_576, "{}", oversized.len());
    let calls = rig.fake.calls();
    assert_eq!(rig.post_raw(Some(&rig.fw_token), oversized).await.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(rig.fake.calls(), calls, "no upstream work for a refused envelope");
}
