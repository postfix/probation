//! Slice 1's witness for decision log delivery: the file sink, end to end, through
//! the real HTTP surface.
//!
//! Nothing here reaches a socket it did not bind itself. The server is the ordinary
//! `App::start`, driven through the existing `tests/common` helpers, and the only
//! new configuration is the two `log_file_*` keys an operator would write.
//!
//! This file installs its own JSON subscriber rather than `common::logs`, because the
//! claim under test is about the *structured* decision line: `TP-13` compares the
//! complete key set of the emitted JSON object, which a substring assertion over the
//! human-readable formatter cannot express.

mod common;

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use common::{
    FakeAnswer, FakeRegistry, Gate, TestClock, TestServer, config_with_open_blocklist,
    downstream_client, fake_origins, fake_upstream, npm_upstream_path, sample_config,
};
use probation::clock::SystemClock;
use probation::upstream::Transport;
use probation::{App, AppDeps, StartupError};
use serde_json::Value;
use url::Url;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

/// The twelve fields SPEC §11 names, in the order the decision line emits them. A
/// renamed, added or missing key is what `TP-13` exists to catch.
const DECISION_FIELDS: [&str; 12] = [
    "request_id",
    "method",
    "ecosystem",
    "package",
    "version",
    "status",
    "result",
    "reason",
    "blocklist_revision",
    "cache",
    "duration_micros",
    "bytes",
];

/// A package request that needs no upstream and no blocklist: it is refused as
/// `POLICY_UNAVAILABLE`, which is still a decision and still a decision line.
const PACKAGE: &str = "/npm/left-pad";

// ---------------------------------------------------------------------------
// TP-1: one NDJSON object per decision, carrying the stdout line's own fields
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tp1_file_sink_appends_ndjson() {
    let captured = stdout::capture();
    let dir = tempfile::tempdir().expect("a temporary directory");
    let path = dir.path().join("decisions.ndjson");

    let mut config = sample_config();
    config.log_file_path = Some(path.clone());

    let server = TestServer::start_with(config, Arc::new(SystemClock)).await;
    let request_id = decided(&server, PACKAGE).await;
    server.shutdown().await;

    let decisions: Vec<Value> = delivered(&path)
        .into_iter()
        .filter(|record| record["event"] == "request_decided")
        .collect();
    assert_eq!(
        decisions.len(),
        1,
        "one delivered object per decision, one decision made: {decisions:?}"
    );
    let record = &decisions[0];
    assert_eq!(
        record["request_id"],
        Value::from(request_id.as_str()),
        "and it is the decision for the request that was answered: {record}"
    );

    let line = captured
        .decision_line(&request_id)
        .unwrap_or_else(|| panic!("a stdout decision line for {request_id}"));
    for field in DECISION_FIELDS {
        let stdout = line
            .get(field)
            .unwrap_or_else(|| panic!("the stdout line carries `{field}`: {line:?}"));
        assert_eq!(
            &record[field], stdout,
            "the delivered `{field}` is the one stdout reported; the two must not drift"
        );
    }
}

// ---------------------------------------------------------------------------
// Slice 4 (D7): `osv_mode: diagnostic` substitutes the reason, never the result
// ---------------------------------------------------------------------------

#[tokio::test]
async fn record_osv_diagnostic_match_sets_the_reason_without_changing_result() {
    use wiremock::matchers::path;

    const NAME: &str = "left-pad";
    const VERSION: &str = "1.0.0";

    let dir = tempfile::tempdir().expect("a temporary directory");
    let log_path = dir.path().join("decisions.ndjson");

    let osv_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": [{"vulns": [{"id": "MAL-2026-0001"}]}]
        })))
        .mount(&osv_server)
        .await;
    let osv_url = Url::parse(&format!("{}/v1/querybatch", osv_server.uri()))
        .expect("a valid OSV mock URL");

    let mut config = config_with_open_blocklist(dir.path());
    config.log_file_path = Some(log_path.clone());
    config.osv_mode = probation::osv::OsvMode::Diagnostic;
    // A solitary lookup — nothing else fills the batch — only flushes on
    // `OSV_BATCH_INTERVAL` (2s), which is longer than the sample config's default
    // `osv_request_timeout_ms` (500ms); without widening it here, `check` always
    // fails open before the batcher ever flushes, and the real match this test needs
    // is never observed. See `tests/e2e_npm.rs`'s identical widening for the same
    // reason.
    config.osv_request_timeout_ms = NonZeroU64::new(4_000).expect("4000 is non-zero");

    let registry = FakeRegistry::new();
    registry.answer(
        &npm_upstream_path(NAME),
        FakeAnswer::Body(
            serde_json::json!({
                "name": NAME,
                "dist-tags": {"latest": VERSION},
                "versions": {
                    VERSION: {
                        "name": NAME,
                        "version": VERSION,
                        "dist": {"tarball": format!("https://packages.example.org/npm/artifacts/x/{NAME}-{VERSION}.tgz")},
                    }
                },
                "time": {VERSION: "2026-04-01T00:00:00Z"},
            })
            .to_string(),
        ),
    );

    let server = TestServer::start_with_upstream_and_osv(
        config,
        Arc::new(SystemClock),
        Arc::clone(&registry) as Arc<dyn Transport>,
        fake_origins(),
        reqwest::Client::new(),
        osv_url,
    )
    .await;

    let response = server.get(&format!("/npm/{NAME}")).await;
    assert!(
        response.status().is_success(),
        "the metadata request itself is served: {}",
        response.status()
    );
    server.shutdown().await;

    let decisions = decided_records(&log_path);
    assert_eq!(
        decisions.len(),
        1,
        "one delivered record for the one request made: {decisions:?}"
    );
    let record = &decisions[0];

    assert_eq!(record["result"], "ALLOWED");
    // `OSV_DIAGNOSTIC_REASON` is `pub(crate)` (D7) and unreachable from an
    // integration test, so this asserts the exact string it names.
    assert_eq!(
        record["reason"],
        "the request would be blocked by a known OSV malicious-package advisory \
         (diagnostic mode: not enforced)"
    );
}

// ---------------------------------------------------------------------------
// TP-2: the pair of files is bounded at twice the cap
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tp2_file_bounded_at_twice_cap() {
    const CAP: u64 = 4_096;

    let dir = tempfile::tempdir().expect("a temporary directory");
    let path = dir.path().join("decisions.ndjson");

    let mut config = sample_config();
    config.log_file_path = Some(path.clone());
    config.log_file_max_bytes = NonZeroU64::new(CAP).expect("a non-zero cap");

    let server = TestServer::start_with(config, Arc::new(SystemClock)).await;
    // Each decision is a few hundred bytes, so this crosses the cap several times.
    for _ in 0..80 {
        server.get(PACKAGE).await;
    }
    server.shutdown().await;

    let rolled = rollover_of(&path);
    assert!(
        rolled.exists(),
        "the live file was rolled to {}, which is the only generation kept",
        rolled.display()
    );

    let live = size_of(&path);
    let previous = size_of(&rolled);
    assert!(
        live < CAP,
        "the live file stays under the cap: {live} bytes against {CAP}"
    );
    assert!(
        live + previous <= 2 * CAP,
        "and the pair is bounded at twice it: {live} + {previous} bytes against {}",
        2 * CAP
    );
}

// ---------------------------------------------------------------------------
// TP-2b: a restart does not overshoot the cap
// ---------------------------------------------------------------------------

/// The byte tally is restored from the file's own length when the sink opens it, so
/// the first record after a restart is appended on top of whatever the previous run
/// left behind. In steady state that is a file *just under* the cap — precisely
/// because rollover always fires before crossing it — so the threshold has to be
/// decided after the tally is restored rather than before.
///
/// `TP-2` cannot see this: it never restarts, so its writer has an open handle and a
/// true tally from its very first record.
#[tokio::test]
async fn tp2b_restart_does_not_overshoot_cap() {
    const CAP: u64 = 4_096;

    let dir = tempfile::tempdir().expect("a temporary directory");
    let path = dir.path().join("decisions.ndjson");

    // What the previous run left: one byte short of the cap, which is where a file
    // whose rollover works correctly spends most of its life.
    let head = r#"{"event":"request_decided","pad":""#;
    let tail = "\"}\n";
    let padding = CAP as usize - 1 - head.len() - tail.len();
    let previous_run = format!("{head}{}{tail}", "x".repeat(padding));
    assert_eq!(
        previous_run.len() as u64,
        CAP - 1,
        "the file this restart is meant to find"
    );
    std::fs::write(&path, &previous_run).expect("the previous run's file is written");

    let mut config = sample_config();
    config.log_file_path = Some(path.clone());
    config.log_file_max_bytes = NonZeroU64::new(CAP).expect("a non-zero cap");

    let server = TestServer::start_with(config, Arc::new(SystemClock)).await;
    server.get(PACKAGE).await;
    server.shutdown().await;

    // Neither generation may exceed the cap — that is what bounds the pair at twice
    // it. A record appended without consulting the restored tally ends up in
    // whichever generation it happened to fall into, so both are asserted.
    let rolled = rollover_of(&path);
    assert!(
        rolled.exists(),
        "the near-full file the restart found is rolled away, not extended"
    );
    let live = size_of(&path);
    let previous = size_of(&rolled);
    assert!(
        live < CAP,
        "the live file stays under the cap across a restart: {live} bytes against {CAP}"
    );
    assert!(
        previous < CAP,
        "and so does the generation rolled away: {previous} bytes against {CAP}"
    );
}

// ---------------------------------------------------------------------------
// TP-3: an operator who configures nothing gets nothing
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tp3_default_config_opens_nothing() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let unconfigured = dir.path().join("decisions.ndjson");

    let config = sample_config();
    assert_eq!(
        config.log_file_path, None,
        "the shipped sample names no log file, so this is the default path"
    );

    let server = TestServer::start_with(config, Arc::new(SystemClock)).await;
    assert!(
        server.running().app().delivery_is_empty(),
        "no sink is enabled, so nothing was opened"
    );
    assert_eq!(
        server.running().background_task_count(),
        3,
        "the blocklist poller, the maintenance pass, and the always-on osv batcher \
         (Slice 1, D3) — no delivery task beside them, since neither sink is configured"
    );

    server.get(PACKAGE).await;
    server.shutdown().await;

    assert!(
        !unconfigured.exists(),
        "no file appears at a path nobody configured"
    );
    assert_eq!(
        std::fs::read_dir(dir.path())
            .expect("the temporary directory is readable")
            .count(),
        0,
        "and nothing else was written either"
    );
}

// ---------------------------------------------------------------------------
// TP-10: a request still in flight when shutdown begins is still delivered
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tp10_in_flight_record_survives_shutdown() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let path = dir.path().join("decisions.ndjson");

    let mut config = config_with_open_blocklist(dir.path());
    config.log_file_path = Some(path.clone());

    // A metadata fetch parked at the gate is a request genuinely in flight: the
    // response has not been produced, so its decision record does not exist yet.
    let gate = Gate::new();
    let registry = FakeRegistry::new();
    registry.answer(
        &npm_upstream_path("left-pad"),
        FakeAnswer::GatedMetadata {
            body: "{}".to_owned(),
            gate: Arc::clone(&gate),
        },
    );

    let server = TestServer::start_with_upstream(
        config,
        Arc::new(SystemClock),
        Arc::clone(&registry) as Arc<dyn Transport>,
        fake_origins(),
    )
    .await;

    let url = server.url(PACKAGE);
    let client = downstream_client();
    let request = tokio::spawn(async move { client.get(url).send().await });
    gate.wait_until_reached().await;

    // Shutdown is asked for while that request is still parked upstream.
    let shutdown = tokio::spawn(async move { server.shutdown().await });
    tokio::time::sleep(Duration::from_millis(100)).await;
    gate.release();

    request
        .await
        .expect("the request task")
        .expect("the in-flight request is still answered");
    tokio::time::timeout(Duration::from_secs(30), shutdown)
        .await
        .expect("HANG: shutdown did not return")
        .expect("the shutdown task");

    let decisions: Vec<Value> = delivered(&path)
        .into_iter()
        .filter(|record| record["event"] == "request_decided")
        .collect();
    assert_eq!(
        decisions.len(),
        1,
        "the record of a request that was still in flight when shutdown began is \
         delivered, not lost: {decisions:?}"
    );
}

// ---------------------------------------------------------------------------
// TP-4: consumer identification is off unless an operator asks for it
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tp4_consumer_off_by_default_and_recorded_when_on() {
    let dir = tempfile::tempdir().expect("a temporary directory");

    // The default an operator who says nothing about it is on.
    let off = dir.path().join("off.ndjson");
    let mut config = sample_config();
    config.log_file_path = Some(off.clone());
    assert!(
        !config.log_consumer_identification,
        "the shipped sample records no consumer, so this is the default path"
    );

    let server = TestServer::start_with(config, Arc::new(SystemClock)).await;
    server.get(PACKAGE).await;
    server.shutdown().await;

    let records = decided_records(&off);
    assert!(!records.is_empty(), "the request was decided and delivered");
    for record in &records {
        assert!(
            record.get("consumer").is_none(),
            "with the opt-in off the record carries no consumer key at all: {record}"
        );
    }

    // And the same request with the opt-in on, from a source address that is neither
    // the listener's own `127.0.0.1` nor any constant a wrong wiring could produce,
    // claiming to be somebody else in both forwarding headers.
    const FORWARDED_FOR: &str = "203.0.113.9";
    const FORWARDED_BY: &str = "198.51.100.17";
    let captured = stdout::capture();
    let on = dir.path().join("on.ndjson");
    let mut config = sample_config();
    config.log_file_path = Some(on.clone());
    config.log_consumer_identification = true;

    let server = TestServer::start_with(config, Arc::new(SystemClock)).await;
    let client = reqwest::Client::builder()
        .no_proxy()
        .local_address(IpAddr::from([127, 0, 0, 2]))
        .build()
        .expect("a client bound to 127.0.0.2");
    let response = client
        .get(server.url(PACKAGE))
        .header("X-Forwarded-For", FORWARDED_FOR)
        .header("Forwarded", format!("for={FORWARDED_BY};proto=http"))
        .send()
        .await
        .expect("the request completes");
    let request_id = request_id_of(response).await;
    server.shutdown().await;

    let records = decided_records(&on);
    assert_eq!(records.len(), 1, "the request was decided and delivered");
    let record = &records[0];
    assert_eq!(
        record["consumer"],
        Value::from("127.0.0.2"),
        "the peer address of the connection that asked, and no port: {record}"
    );
    let line = captured
        .decision_line(&request_id)
        .unwrap_or_else(|| panic!("a stdout decision line for {request_id}"));
    for claimed in [FORWARDED_FOR, FORWARDED_BY] {
        assert!(
            !record.to_string().contains(claimed),
            "nothing the caller says about itself is recorded: {record}"
        );
        assert!(
            !Value::from(line.clone()).to_string().contains(claimed),
            "nor printed: {line:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// TP-16: an unopenable log file stops startup only when peer addresses would be kept
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tp16_unopenable_log_path_fails_startup() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    // Inside a directory nobody created, which is what a typo in the path looks like.
    let unopenable = dir.path().join("missing").join("decisions.ndjson");

    // (a) With the opt-in on, peer addresses would be collected with nowhere durable to
    // go, so the process refuses to start at all.
    let data_dir = tempfile::tempdir().expect("a temporary data directory");
    let mut config = sample_config();
    config.data_dir = data_dir.path().to_path_buf();
    config.log_file_path = Some(unopenable.clone());
    config.log_consumer_identification = true;
    // A port known to be free, so "nothing serves" can be asked of it afterwards.
    config.listen = std::net::TcpListener::bind(("127.0.0.1", 0))
        .and_then(|listener| listener.local_addr())
        .expect("a free loopback port");
    let listen = config.listen;

    let (transport, origins) = fake_upstream();
    let started = App::start(AppDeps {
        config,
        clock: Arc::new(SystemClock),
        transport,
        origins,
        osv_client: probation::osv::unreachable_client(),
        osv_base_url: None,
    })
    .await;
    // `Running` is not `Debug`, so this cannot be an `expect_err`.
    let Err(err) = started else {
        panic!("an unopenable log file with the opt-in on refuses to start");
    };
    assert!(
        matches!(err, StartupError::Delivery(_)),
        "the refusal is delivery's own, not a bind or a data-directory failure: {err}"
    );
    let text = err.to_string();
    assert!(
        text.contains("log_file_path") && text.contains("log_consumer_identification"),
        "an operator is told which key to fix and why it is fatal: {text}"
    );
    assert!(
        !text.contains("127.0.0."),
        "and the refusal carries no peer address: {text}"
    );
    assert!(
        tokio::net::TcpStream::connect(listen).await.is_err(),
        "nothing serves on {listen}"
    );

    // (b) With it off there is no privacy reason to refuse, and a logging typo must not
    // become an outage: one error naming the key, and the firewall keeps serving.
    let captured = stdout::Lines::default();
    let console = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .json()
            .with_writer(captured.clone())
            .with_max_level(tracing::Level::WARN)
            .finish(),
    );
    let mut config = sample_config();
    config.log_file_path = Some(unopenable);
    let server = TestServer::start_with(config, Arc::new(SystemClock)).await;
    let response = server.get(PACKAGE).await;
    server.shutdown().await;
    drop(console);

    assert_eq!(
        response.status(),
        503,
        "the request is answered exactly as it would be without a log file"
    );
    let text = captured.text();
    let errors = levelled(&text, "ERROR")
        .filter(|line| line.to_string().contains("log_file_path"))
        .count();
    assert_eq!(errors, 1, "exactly one error names the key:\n{text}");
}

// ---------------------------------------------------------------------------
// TP-17: the decision log is readable by its owner alone
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tp17_log_file_mode_is_0600() {
    use std::os::unix::fs::PermissionsExt;

    const CAP: u64 = 4_096;
    let mode_of = |path: &Path| {
        std::fs::metadata(path)
            .unwrap_or_else(|err| panic!("{} exists: {err}", path.display()))
            .permissions()
            .mode()
            & 0o777
    };
    let dir = tempfile::tempdir().expect("a temporary directory");

    // (d) Before any request and before shutdown: only the startup probe can have
    // created it, because the sink itself opens the file lazily on its first record.
    let probed = dir.path().join("probed.ndjson");
    let mut config = sample_config();
    config.log_file_path = Some(probed.clone());
    let server = TestServer::start_with(config, Arc::new(SystemClock)).await;
    assert!(
        probed.exists(),
        "startup created the file before any record"
    );
    assert_eq!(mode_of(&probed), 0o600, "and created it owner-only");
    server.shutdown().await;

    // (a) and (b): the live file after one request, and the `.1` generation after a
    // rollover — and the fresh live file that rollover opened.
    let path = dir.path().join("decisions.ndjson");
    let mut config = sample_config();
    config.log_file_path = Some(path.clone());
    config.log_file_max_bytes = NonZeroU64::new(CAP).expect("a non-zero cap");
    let server = TestServer::start_with(config, Arc::new(SystemClock)).await;
    server.get(PACKAGE).await;
    common::wait_until(
        "the first record is written",
        Duration::from_secs(5),
        || size_of(&path) > 0,
    )
    .await;
    assert_eq!(mode_of(&path), 0o600, "the live file is owner-only");
    for _ in 0..80 {
        server.get(PACKAGE).await;
    }
    server.shutdown().await;
    let rolled = rollover_of(&path);
    assert!(rolled.exists(), "the requests crossed the cap");
    assert_eq!(
        mode_of(&rolled),
        0o600,
        "the rolled generation is owner-only"
    );
    assert_eq!(
        mode_of(&path),
        0o600,
        "and so is the fresh file rollover opened"
    );

    // (c) A file an operator — or anyone else — created first keeps its mode, and the
    // process says so once rather than appending peer addresses to it silently.
    let precreated = dir.path().join("precreated.ndjson");
    std::fs::write(&precreated, "").expect("the file is pre-created");
    std::fs::set_permissions(&precreated, std::fs::Permissions::from_mode(0o644))
        .expect("the pre-created file is 0644");
    let captured = stdout::Lines::default();
    let console = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .json()
            .with_writer(captured.clone())
            .with_max_level(tracing::Level::WARN)
            .finish(),
    );
    let mut config = sample_config();
    config.log_file_path = Some(precreated.clone());
    let server = TestServer::start_with(config, Arc::new(SystemClock)).await;
    server.get(PACKAGE).await;
    server.shutdown().await;
    drop(console);

    assert_eq!(
        mode_of(&precreated),
        0o644,
        "a file the process did not create is not re-chmodded"
    );
    let text = captured.text();
    let shown = precreated.display().to_string();
    let warnings = levelled(&text, "WARN")
        .map(|line| line.to_string())
        .filter(|line| line.contains(&shown) && line.contains("644"))
        .count();
    assert_eq!(
        warnings, 1,
        "exactly one warning names the path and its mode:\n{text}"
    );
}

// ---------------------------------------------------------------------------
// TP-13: the stdout decision line's complete key set
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tp13_stdout_decision_key_set() {
    let captured = stdout::capture();
    let server = TestServer::start().await;

    let request_id = decided(&server, PACKAGE).await;
    server.shutdown().await;

    let line = captured
        .decision_line(&request_id)
        .unwrap_or_else(|| panic!("a stdout decision line for {request_id}"));

    assert_eq!(
        line.get("message"),
        Some(&Value::from("request decided")),
        "the message an operator greps for is unchanged: {line:?}"
    );

    let emitted: BTreeSet<&str> = line.keys().map(String::as_str).collect();
    let mut expected: BTreeSet<&str> = DECISION_FIELDS.into_iter().collect();
    expected.insert("message");
    assert_eq!(
        emitted, expected,
        "with consumer identification off, exactly the twelve documented fields and \
         nothing else — no key renamed, added or missing"
    );

    // The opt-in adds one field to that line and changes nothing else about it.
    let dir = tempfile::tempdir().expect("a temporary directory");
    let mut config = sample_config();
    config.log_file_path = Some(dir.path().join("decisions.ndjson"));
    config.log_consumer_identification = true;

    let server = TestServer::start_with(config, Arc::new(SystemClock)).await;
    let request_id = decided(&server, PACKAGE).await;
    server.shutdown().await;

    let line = captured
        .decision_line(&request_id)
        .unwrap_or_else(|| panic!("a stdout decision line for {request_id}"));
    let emitted: BTreeSet<&str> = line.keys().map(String::as_str).collect();
    expected.insert("consumer");
    assert_eq!(
        emitted, expected,
        "and with it on, exactly those twelve plus `consumer`"
    );
}

// ---------------------------------------------------------------------------
// TP-20: every delivered record says when it was made, from the injected clock
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tp20_delivered_records_carry_timestamp() {
    let _env = AuthEnv::set(None).await;
    let collector = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&collector)
        .await;

    let dir = tempfile::tempdir().expect("a temporary directory");
    let path = dir.path().join("decisions.ndjson");
    let mut config = sample_config();
    config.log_file_path = Some(path.clone());
    config.siem_url = Some(Url::parse(&collector.uri()).expect("the collector's URL"));

    // `.120000` rather than `.000000`: plain `Display` would print `.12Z`, so this is
    // what proves the width is fixed.
    let clock = TestClock::at_rfc3339("2026-09-21T14:13:20.120000Z");
    let server = TestServer::start_with(config, clock.shared()).await;
    let request_id = decided(&server, PACKAGE).await;
    // The summary is built at shutdown, a minute later: it reads the clock then rather
    // than copying the decision's time.
    clock.advance_seconds(60);
    server.shutdown().await;

    let records = delivered(&path);
    let decision = records
        .iter()
        .find(|record| record["event"] == "request_decided" && record["request_id"] == request_id)
        .unwrap_or_else(|| panic!("a delivered decision for {request_id}: {records:?}"));
    assert_eq!(
        decision["timestamp"], "2026-09-21T14:13:20.120000Z",
        "the decision carries the injected clock's time in fixed-width UTC RFC 3339: {decision}"
    );

    let summary = records
        .iter()
        .rfind(|record| record["event"] == "request_summary")
        .unwrap_or_else(|| panic!("the shutdown summary was delivered: {records:?}"));
    assert_eq!(
        summary["timestamp"], "2026-09-21T14:14:20.120000Z",
        "the shutdown summary carries the time it was built: {summary}"
    );

    let received = collector
        .received_requests()
        .await
        .expect("the collector recorded what it was sent");
    let sent = received
        .iter()
        .flat_map(|request| {
            String::from_utf8(request.body.clone())
                .expect("a UTF-8 body")
                .lines()
                .map(|line| serde_json::from_str::<Value>(line).expect("one JSON object"))
                .collect::<Vec<_>>()
        })
        .find(|record| record["event"] == "request_decided" && record["request_id"] == request_id)
        .unwrap_or_else(|| panic!("the collector was sent the decision for {request_id}"));
    assert_eq!(
        sent["timestamp"], decision["timestamp"],
        "the collector and the file are told the same time for the same decision"
    );
}

// ---------------------------------------------------------------------------
// TP-7: a drop is counted per sink, and reaches a durable destination
// ---------------------------------------------------------------------------

/// Enough requests to fill the SIEM sink's queue and overflow it while the collector
/// holds the sink's one in-flight batch hostage.
const OVERFLOW_REQUESTS: usize = 5_000;

/// Sixty-four records' worth of SIEM queue, pinned so this test owns its own overflow
/// premise. The shipped default is a memory budget an operator may raise and a later
/// slice will raise again; a test whose premise is "the default queue is smaller than
/// `OVERFLOW_REQUESTS`" would go quietly green the day it stops being true.
const TP7_SIEM_QUEUE_MAX_BYTES: u64 = 64 * 32 * 1024;

#[tokio::test]
async fn tp7_drop_is_counted_and_read_back_from_file() {
    let _env = AuthEnv::set(None).await;
    let dir = tempfile::tempdir().expect("a temporary directory");
    let path = dir.path().join("decisions.ndjson");

    let mut config = sample_config();
    config.log_file_path = Some(path.clone());
    config.siem_url = Some(wedged_collector().await);
    config.siem_queue_max_bytes =
        NonZeroU64::new(TP7_SIEM_QUEUE_MAX_BYTES).expect("a non-zero budget");

    let server = TestServer::start_with(config, Arc::new(SystemClock)).await;

    // The SIEM sink takes one batch and then waits on a collector that never answers,
    // so its queue fills and it starts shedding. The file sink, writing to a local
    // file, keeps up throughout — which is what makes the two counts tell them apart.
    let first = server.get(PACKAGE).await.status();
    let mut last = first;
    for _ in 1..OVERFLOW_REQUESTS {
        last = server.get(PACKAGE).await.status();
    }
    assert_eq!(
        last, first,
        "a request is answered the same whether or not delivery can keep up"
    );

    server.shutdown().await;

    let summaries: Vec<Value> = delivered(&path)
        .into_iter()
        .filter(|record| record["event"] == "request_summary")
        .collect();
    assert!(
        !summaries.is_empty(),
        "the summary that carries the drop counts is delivered to the file too"
    );
    assert!(
        summaries
            .iter()
            .any(|summary| summary["dropped_siem"].as_u64() > Some(0)),
        "the records the wedged collector cost are counted against its own sink, and \
         the count is readable out of the file the operator keeps: {summaries:?}"
    );
    assert!(
        summaries
            .iter()
            .all(|summary| summary["dropped_file"].as_u64() == Some(0)),
        "and not against the sink that kept up: {summaries:?}"
    );
}

// ---------------------------------------------------------------------------
// TP-8: what a collector actually receives, with and without a credential
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tp8_batch_shape_and_optional_credential() {
    const CREDENTIAL: &str = "Bearer tp8-collector-token";

    // Two runs, one either side of the environment variable. They are sequential
    // rather than concurrent because the variable is process-global.
    let authenticated = {
        let _env = AuthEnv::set(Some(CREDENTIAL)).await;
        one_batch().await
    };
    let anonymous = {
        let _env = AuthEnv::set(None).await;
        one_batch().await
    };

    for (received, expected) in [(&authenticated, Some(CREDENTIAL)), (&anonymous, None)] {
        assert_eq!(
            received.len(),
            1,
            "the run's records go to the collector as one batch, not one request each"
        );
        let request = &received[0];

        assert_eq!(
            request
                .headers
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            Some("application/x-ndjson"),
            "the body is announced as newline-delimited JSON"
        );

        let body = String::from_utf8(request.body.clone()).expect("a UTF-8 body");
        assert!(
            body.ends_with('\n'),
            "every record is terminated, so two batches concatenate cleanly: {body:?}"
        );
        let lines: Vec<&str> = body.lines().collect();
        assert!(
            lines.len() >= 4,
            "the three decisions and the closing summary are all in it: {body:?}"
        );
        for line in &lines {
            serde_json::from_str::<Value>(line)
                .unwrap_or_else(|err| panic!("every line is one JSON object: {err}: {line}"));
        }

        assert_eq!(
            request
                .headers
                .get("authorization")
                .map(|value| value.to_str().expect("a printable credential")),
            expected,
            "the credential is sent exactly as the environment gave it, and is absent \
             entirely when the environment did not give one"
        );
    }
}

/// One server run against a collector that accepts everything, returning what that
/// collector was sent.
async fn one_batch() -> Vec<wiremock::Request> {
    let collector = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&collector)
        .await;

    let mut config = sample_config();
    config.siem_url = Some(Url::parse(&collector.uri()).expect("the collector's URL"));

    let server = TestServer::start_with(config, Arc::new(SystemClock)).await;
    for _ in 0..3 {
        server.get(PACKAGE).await;
    }
    // The drain sends the partial batch, so this needs no wait on the batch timer.
    server.shutdown().await;

    collector
        .received_requests()
        .await
        .expect("the collector recorded what it was sent")
}

// ---------------------------------------------------------------------------
// TP-9: a collector cannot redirect this process anywhere
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tp9_redirect_is_not_followed() {
    let _env = AuthEnv::set(None).await;
    let elsewhere = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&elsewhere)
        .await;

    let collector = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(302).insert_header("location", elsewhere.uri().as_str()),
        )
        .mount(&collector)
        .await;

    let dir = tempfile::tempdir().expect("a temporary directory");
    let path = dir.path().join("decisions.ndjson");

    let mut config = sample_config();
    config.log_file_path = Some(path.clone());
    config.siem_url = Some(Url::parse(&collector.uri()).expect("the collector's URL"));

    let server = TestServer::start_with(config, Arc::new(SystemClock)).await;
    server.get(PACKAGE).await;
    // Long enough for the batch timer to fire, so the redirect is answered and the
    // loss counted while the summary that reports it can still be written.
    tokio::time::sleep(Duration::from_millis(2_500)).await;
    server.shutdown().await;

    assert!(
        !collector
            .received_requests()
            .await
            .expect("the collector recorded what it was sent")
            .is_empty(),
        "the configured collector was reached, so its redirect really was answered"
    );
    assert!(
        elsewhere
            .received_requests()
            .await
            .expect("the second collector recorded what it was sent")
            .is_empty(),
        "and the host it pointed at received nothing at all"
    );

    let summaries: Vec<Value> = delivered(&path)
        .into_iter()
        .filter(|record| record["event"] == "request_summary")
        .collect();
    assert!(
        summaries
            .iter()
            .any(|summary| summary["dropped_siem"].as_u64() > Some(0)),
        "the unfollowed batch is counted as lost rather than quietly forgotten: \
         {summaries:?}"
    );
}

// ---------------------------------------------------------------------------
// TP-11a: the credential never reaches the runtime output
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tp11a_credential_absent_from_runtime_output() {
    const SENTINEL: &str = "tp11a-this-must-never-be-logged";

    let captured = stdout::capture();
    let _env = AuthEnv::set(Some(&format!("Bearer {SENTINEL}"))).await;

    // A collector that refuses every batch: the failing path is the one with the most
    // to say about what went wrong, and therefore the most to leak.
    let collector = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(400))
        .mount(&collector)
        .await;

    let dir = tempfile::tempdir().expect("a temporary directory");
    let path = dir.path().join("decisions.ndjson");

    let mut config = sample_config();
    config.log_file_path = Some(path.clone());
    config.siem_url = Some(Url::parse(&collector.uri()).expect("the collector's URL"));

    let server = TestServer::start_with(config, Arc::new(SystemClock)).await;
    server.get(PACKAGE).await;
    server.shutdown().await;

    assert!(
        !collector
            .received_requests()
            .await
            .expect("the collector recorded what it was sent")
            .is_empty(),
        "the delivery really was attempted and really did fail, which is the state \
         this test is about"
    );

    let file = std::fs::read_to_string(&path).expect("the log file is readable");
    assert!(
        !file.contains(SENTINEL),
        "no part of the credential reaches the durable log"
    );
    assert!(
        !captured.text().contains(SENTINEL),
        "nor the console an operator's collector scrapes"
    );
}

// ---------------------------------------------------------------------------
// TP-11b: nor the startup rejection, which is the path with no header to redact
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tp11b_credential_absent_from_startup_rejection() {
    // A newline is what makes this fail `HeaderValue::from_str`, and is also what
    // would forge a second log line if the value were ever printed.
    const SENTINEL: &str = "tp11b-rejected-value";
    let _env = AuthEnv::set(Some(&format!("Bearer {SENTINEL}\nX-Injected: yes"))).await;

    let data_dir = tempfile::tempdir().expect("a temporary data directory");
    let mut config = sample_config();
    config.data_dir = data_dir.path().to_path_buf();
    config.siem_url = Some(Url::parse("https://siem.example.org/ingest").expect("a collector URL"));

    let (transport, origins) = fake_upstream();
    let started = App::start(AppDeps {
        config,
        clock: Arc::new(SystemClock),
        transport,
        origins,
        osv_client: probation::osv::unreachable_client(),
        osv_base_url: None,
    })
    .await;
    // `Running` is not `Debug`, so this cannot be an `expect_err`.
    let Err(err) = started else {
        panic!("a credential that is not a legal header value refuses to start");
    };

    assert!(
        matches!(err, StartupError::Delivery(_)),
        "the refusal is delivery's own, not a bind or a data-directory failure: {err}"
    );

    let text = err.to_string();
    assert!(
        text.contains("PROBATION_SIEM_AUTH"),
        "an operator is told which variable to fix: {text}"
    );
    assert!(
        text.contains("header value"),
        "and why it was refused: {text}"
    );
    for fragment in [SENTINEL, "X-Injected", "Bearer"] {
        assert!(
            !text.contains(fragment),
            "and no part of the value itself, which `check_config` prints straight to \
             a console: {text}"
        );
    }
}

// ---------------------------------------------------------------------------
// TP-15: a wedged collector cannot hold up a restart
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tp15_shutdown_bounded_against_wedged_collector() {
    let _env = AuthEnv::set(None).await;
    let mut config = sample_config();
    config.siem_url = Some(wedged_collector().await);

    let server = TestServer::start_with(config, Arc::new(SystemClock)).await;
    server.get(PACKAGE).await;

    // Straight into shutdown, so the sink is idle in its select when the drain fires
    // and the whole cost of the silent collector is paid inside the deadline the
    // caller imposes. Without that deadline and the client's own timeout this hangs
    // forever, which is why the bound below is the assertion.
    let started = std::time::Instant::now();
    tokio::time::timeout(Duration::from_secs(20), server.shutdown())
        .await
        .expect("HANG: shutdown did not return against a collector that never answers");

    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(10),
        "shutdown is bounded by the five-second drain deadline rather than by the \
         collector: it took {elapsed:?}"
    );
}

// ---------------------------------------------------------------------------
// TP-15b: what the drain deadline cuts off is still counted
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tp15b_drain_cutoff_records_are_counted() {
    let _env = AuthEnv::set(None).await;
    let mut config = sample_config();
    config.siem_url = Some(silent_collector().await);

    // The console is the destination that carries a drain-window drop, not the
    // delivered file: `shutdown` calls `flush_summary` — which reads *and resets* the
    // counters — before it cancels the drain, and by the time this count exists every
    // sink has finished, so no summary record can still reach a sink. That leaves
    // `flush_drop_tail`'s warn line, which is what this reads.
    //
    // The capture is thread-local rather than the binary-wide `stdout::capture()`:
    // other tests here also lose records while draining, and one shared buffer would
    // let another test's line satisfy this assertion.
    let captured = stdout::Lines::default();
    let console = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .json()
            .with_writer(captured.clone())
            .with_max_level(tracing::Level::WARN)
            .finish(),
    );

    let server = TestServer::start_with(config, Arc::new(SystemClock)).await;
    // One record, still on the sink's channel: the drain fires well before the
    // two-second batch timer, so the deadline cuts `send` off in flight rather than
    // before it starts.
    server.get(PACKAGE).await;
    server.shutdown().await;
    drop(console);

    let text = captured.text();
    assert!(
        drain_tail_dropped_siem(&text) >= 1,
        "the one record the silent collector never took must be counted somewhere; \
         the drain tail reported {}:\n{text}",
        drain_tail_dropped_siem(&text)
    );
}

/// Sums `dropped_siem` across every [`flush_drop_tail`](probation) line.
fn drain_tail_dropped_siem(text: &str) -> u64 {
    text.lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter_map(|line| line.get("fields")?.as_object().cloned())
        .filter(|fields| {
            fields.get("message").and_then(Value::as_str)
                == Some(
                    "decision records were dropped while delivery was draining and \
                     could not be delivered",
                )
        })
        .filter_map(|fields| fields.get("dropped_siem").and_then(Value::as_u64))
        .sum()
}

// ---------------------------------------------------------------------------
// A collector that never answers, and the one process-global variable
// ---------------------------------------------------------------------------

/// A collector that accepts the connection and then says nothing at all — the shape
/// that hangs a sink with no timeout of its own. The accepted streams are held rather
/// than dropped, because a closed connection is a prompt error and the absence of one
/// is the whole point.
async fn wedged_collector() -> Url {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("a loopback listener");
    let addr = listener.local_addr().expect("the listener's address");
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });
    Url::parse(&format!("http://{addr}/ingest")).expect("a collector URL")
}

/// Accepts the connection, reads the request, and never answers — unlike
/// [`wedged_collector`], which leaves the request unread, this one lets a `send`
/// attempt run out the client's request timeout and start a retry, so the drain
/// deadline can cut it off *mid-retry* rather than before the first attempt begins.
async fn silent_collector() -> Url {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("a loopback listener");
    let addr = listener.local_addr().expect("the listener's address");
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                use tokio::io::AsyncReadExt;
                let mut buf = [0u8; 4096];
                while let Ok(read) = stream.read(&mut buf).await {
                    if read == 0 {
                        break;
                    }
                }
            });
        }
    });
    Url::parse(&format!("http://{addr}/ingest")).expect("a collector URL")
}

/// `PROBATION_SIEM_AUTH` is process-global and these tests run in parallel, so every test
/// that starts a SIEM sink takes this lock first — whether it wants a credential or
/// not — and clears the variable again on the way out. Serialising only the writers is
/// not enough: a reader started outside the lock picks up whichever value happens to be
/// set at that instant. No test ever reads a credential from the developer's
/// environment.
static SIEM_AUTH_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct AuthEnv(#[allow(dead_code)] tokio::sync::MutexGuard<'static, ()>);

impl AuthEnv {
    async fn set(value: Option<&str>) -> AuthEnv {
        let guard = SIEM_AUTH_LOCK.lock().await;
        // SAFETY: the lock makes this the only thread in the binary mutating the
        // environment, and the only readers are the servers started while it is held.
        unsafe {
            match value {
                Some(value) => std::env::set_var("PROBATION_SIEM_AUTH", value),
                None => std::env::remove_var("PROBATION_SIEM_AUTH"),
            }
        }
        AuthEnv(guard)
    }
}

impl Drop for AuthEnv {
    fn drop(&mut self) {
        // SAFETY: as above — the lock is still held, and is released after this.
        unsafe { std::env::remove_var("PROBATION_SIEM_AUTH") };
    }
}

// ---------------------------------------------------------------------------
// Reading what was delivered
// ---------------------------------------------------------------------------

/// Every line of the delivered file, each parsed as its own JSON object. A line that
/// is not one object is a failure of the format, not of the reader.
/// Just the decision records of [`delivered`], which is what `TP-4` reads.
fn decided_records(path: &Path) -> Vec<Value> {
    delivered(path)
        .into_iter()
        .filter(|record| record["event"] == "request_decided")
        .collect()
}

fn delivered(path: &Path) -> Vec<Value> {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("{} is readable: {err}", path.display()));
    text.lines()
        .map(|line| {
            serde_json::from_str(line).unwrap_or_else(|err| {
                panic!("every delivered line is one JSON object: {err}: {line}")
            })
        })
        .collect()
}

/// Drives one request and returns the request id the server told the client about,
/// which is the same id its decision line carries.
async fn decided(server: &TestServer, path: &str) -> String {
    request_id_of(server.get(path).await).await
}

async fn request_id_of(response: reqwest::Response) -> String {
    let text = response.text().await.expect("a response body");
    let body: Value =
        serde_json::from_str(&text).unwrap_or_else(|err| panic!("a JSON body: {err}: {text}"));
    body["request_id"]
        .as_str()
        .unwrap_or_else(|| panic!("SPEC §11: an error body carries a request_id: {body}"))
        .to_owned()
}

/// The captured JSON lines emitted at `level`.
fn levelled<'a>(text: &'a str, level: &'a str) -> impl Iterator<Item = Value> + 'a {
    text.lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(move |line| line["level"] == level)
}

fn rollover_of(path: &Path) -> PathBuf {
    let mut rolled = path.to_path_buf().into_os_string();
    rolled.push(".1");
    PathBuf::from(rolled)
}

fn size_of(path: &Path) -> u64 {
    std::fs::metadata(path)
        .unwrap_or_else(|err| panic!("{} exists: {err}", path.display()))
        .len()
}

/// The process's own structured stdout, captured as the operator's log collector
/// would see it.
mod stdout {
    use std::io;
    use std::sync::{Arc, Mutex, OnceLock};

    use serde_json::{Map, Value};

    #[derive(Clone, Default)]
    pub struct Lines(Arc<Mutex<Vec<u8>>>);

    impl io::Write for Lines {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0
                .lock()
                .expect("the capture buffer")
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Lines {
        type Writer = Lines;

        fn make_writer(&'a self) -> Lines {
            self.clone()
        }
    }

    /// Installs the JSON subscriber the first time it is called and hands back the
    /// shared buffer. One global subscriber per test binary, as
    /// `set_global_default` requires; tests select their own lines by request id.
    pub fn capture() -> Lines {
        static CAPTURED: OnceLock<Lines> = OnceLock::new();
        CAPTURED
            .get_or_init(|| {
                let lines = Lines::default();
                let subscriber = tracing_subscriber::fmt()
                    .json()
                    .with_writer(lines.clone())
                    .with_max_level(tracing::Level::INFO)
                    .finish();
                let _ = tracing::subscriber::set_global_default(subscriber);
                lines
            })
            .clone()
    }

    impl Lines {
        /// Everything written so far, as one string.
        pub fn text(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().expect("the capture buffer")).into_owned()
        }

        /// The fields of the one decision line carrying `request_id`.
        pub fn decision_line(&self, request_id: &str) -> Option<Map<String, Value>> {
            let text =
                String::from_utf8_lossy(&self.0.lock().expect("the capture buffer")).into_owned();
            text.lines()
                .filter_map(|line| serde_json::from_str::<Value>(line).ok())
                .filter_map(|line| line.get("fields")?.as_object().cloned())
                .find(|fields| {
                    fields.get("message").and_then(Value::as_str) == Some("request decided")
                        && fields.get("request_id").and_then(Value::as_str) == Some(request_id)
                })
        }
    }
}

// ---------------------------------------------------------------------------
// RL-1: a queue holds the operator's memory budget, not a fixed 4096 records
// ---------------------------------------------------------------------------

/// Eight records' worth of SIEM queue — `8 x BYTES_PER_RECORD`, that constant being
/// `pub(crate)` and so unnameable from here. Small enough that the requests below
/// overflow it, and nowhere near the 4096 records the queue held before it was sized
/// from the budget.
const RL1_SIEM_QUEUE_MAX_BYTES: u64 = 8 * 32 * 1024;

/// Deliberately fewer than 4096: a queue that ignored the budget would absorb every
/// one of these and report no loss at all, which is what makes the count below
/// evidence for the budget rather than for overflow in general.
const RL1_REQUESTS: usize = 512;

/// An operator who writes a small `siem_queue_max_bytes` gets a small queue. The
/// observable is the loss: the same run against the fixed 4096-record queue loses
/// nothing, because 512 records fit it.
#[tokio::test]
async fn rl1_queue_capacity_follows_the_budget() {
    let _env = AuthEnv::set(None).await;
    let dir = tempfile::tempdir().expect("a temporary directory");
    let path = dir.path().join("decisions.ndjson");

    let mut config = sample_config();
    config.log_file_path = Some(path.clone());
    config.siem_url = Some(wedged_collector().await);
    config.siem_queue_max_bytes =
        NonZeroU64::new(RL1_SIEM_QUEUE_MAX_BYTES).expect("a non-zero budget");

    let server = TestServer::start_with(config, Arc::new(SystemClock)).await;
    for _ in 0..RL1_REQUESTS {
        server.get(PACKAGE).await;
    }
    server.shutdown().await;

    let summaries: Vec<Value> = delivered(&path)
        .into_iter()
        .filter(|record| record["event"] == "request_summary")
        .collect();
    assert!(
        summaries
            .iter()
            .any(|summary| summary["dropped_siem"].as_u64() > Some(0)),
        "a budget of eight records overflows within {RL1_REQUESTS} requests; a queue \
         still sized at a fixed 4096 would report none of it: {summaries:?}"
    );
    assert!(
        summaries
            .iter()
            .all(|summary| summary["dropped_file"].as_u64() == Some(0)),
        "and the sink whose budget was left alone keeps its own capacity: {summaries:?}"
    );
}

// ---------------------------------------------------------------------------
// RL-24: a record a sink could not take is still on stdout
// ---------------------------------------------------------------------------

/// Sixty-four records' worth of SIEM queue, pinned for the reason `TP-7` pins its
/// own: a test whose premise is "the shipped default is smaller than the loop below"
/// goes quietly green the day a later slice raises the default.
const RL24_SIEM_QUEUE_MAX_BYTES: u64 = 64 * 32 * 1024;

/// SPEC §11 puts the decision line on stdout, and the durable sinks are the copy,
/// not the record. So the line is written before the record is offered, and an
/// operator whose collector is down still has the complete trail on the console —
/// the whole of what makes a dropped record recoverable. This is the regression
/// guard for the extraction of `build_decision`, which rewrote that region.
#[tokio::test]
async fn rl24_a_record_a_sink_lost_is_still_on_stdout() {
    let captured = stdout::capture();
    let _env = AuthEnv::set(None).await;
    let dir = tempfile::tempdir().expect("a temporary directory");
    let path = dir.path().join("decisions.ndjson");

    let mut config = sample_config();
    config.log_file_path = Some(path.clone());
    config.siem_url = Some(wedged_collector().await);
    config.siem_queue_max_bytes =
        NonZeroU64::new(RL24_SIEM_QUEUE_MAX_BYTES).expect("a non-zero budget");

    let server = TestServer::start_with(config, Arc::new(SystemClock)).await;
    // The collector never answers, so the SIEM queue fills and stays full long before
    // this loop ends: the last request's record is offered to a sink with nowhere to
    // put it.
    for _ in 1..OVERFLOW_REQUESTS {
        server.get(PACKAGE).await;
    }
    let request_id = decided(&server, PACKAGE).await;
    server.shutdown().await;

    let summaries: Vec<Value> = delivered(&path)
        .into_iter()
        .filter(|record| record["event"] == "request_summary")
        .collect();
    assert!(
        summaries
            .iter()
            .any(|summary| summary["dropped_siem"].as_u64() > Some(0)),
        "the premise: records were lost by the wedged collector's sink: {summaries:?}"
    );

    let line = captured
        .decision_line(&request_id)
        .unwrap_or_else(|| panic!("a stdout decision line for {request_id}"));
    for field in DECISION_FIELDS {
        assert!(
            line.get(field).is_some(),
            "the console keeps the whole record a sink could not take, including \
             `{field}`: {line:?}"
        );
    }
    // The method a lossy run prints is the record's own, escaped exactly once. Two
    // applications of the bound would read `"\"GET\""` here, and nothing else in this
    // repository asserts the value of this field.
    assert_eq!(
        line.get("method").and_then(Value::as_str),
        Some("\"GET\""),
        "the method is bounded once, by the one place that bounds it: {line:?}"
    );
}

// ---------------------------------------------------------------------------
// RL-24b: an operator's RUST_LOG cannot silence the decision line
// ---------------------------------------------------------------------------

/// Reaps the served child when a failed assertion unwinds past it; the normal path
/// takes the child out first, so this then does nothing.
struct ServedChild(Option<std::process::Child>);

impl Drop for ServedChild {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Runs the built binary with `rust_log`, sends it one decided request, stops it with
/// SIGTERM, and returns its stdout with the file sink's decision records.
async fn serve_once_with_rust_log(rust_log: &str) -> (String, Vec<Value>) {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let log_path = dir.path().join("decisions.ndjson");
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("a free loopback port")
        .local_addr()
        .expect("its address")
        .port();
    let config_path = dir.path().join("config.toml");
    let sample = std::fs::read_to_string("config.sample.toml").expect("the sample config");
    let mut config = String::new();
    for line in sample.lines() {
        let key = line.split('=').next().unwrap_or("").trim();
        match key {
            "listen" => config.push_str(&format!("listen = \"127.0.0.1:{port}\"\n")),
            "data_dir" => config.push_str(&format!("data_dir = {:?}\n", dir.path().join("data"))),
            _ => {
                config.push_str(line);
                config.push('\n');
            }
        }
    }
    config.push_str(&format!("log_file_path = {log_path:?}\n"));
    std::fs::write(&config_path, config).expect("a written config");

    let mut child = ServedChild(Some(
        std::process::Command::new(env!("CARGO_BIN_EXE_probation"))
            .args(["serve", "--config"])
            .arg(&config_path)
            .env("RUST_LOG", rust_log)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("the built binary starts"),
    ));

    let url = format!("http://127.0.0.1:{port}{PACKAGE}");
    let mut answered = false;
    for _ in 0..100 {
        if reqwest::get(&url).await.is_ok() {
            answered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        answered,
        "the served binary answered a request within ten seconds"
    );

    let killed = std::process::Command::new("kill")
        .args([
            "-TERM",
            &child.0.as_ref().expect("a live child").id().to_string(),
        ])
        .status()
        .expect("kill(1) runs");
    assert!(killed.success(), "SIGTERM was delivered");
    let output = child
        .0
        .take()
        .expect("a live child")
        .wait_with_output()
        .expect("the binary exits");
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        decided_records(&log_path),
    )
}

/// The decision line is the audit trail, so a `RUST_LOG` that names some other level
/// or target must not take it off stdout. Span- and field-qualified directives are
/// not claimed.
#[tokio::test]
async fn rl24b_rust_log_cannot_silence_the_decision_line() {
    for rust_log in ["warn", "hyper=debug", "probation::http::logging=off"] {
        let (stdout, records) = serve_once_with_rust_log(rust_log).await;
        assert!(
            stdout
                .lines()
                .filter_map(|l| serde_json::from_str::<Value>(l).ok())
                .any(|line| {
                    line["target"] == "probation::http::logging"
                        && line["fields"]["message"] == "request decided"
                }),
            "RUST_LOG={rust_log}: the decision line is on stdout; stdout was: {stdout:?}"
        );
        assert!(
            !records.is_empty(),
            "RUST_LOG={rust_log}: the record is in the file sink"
        );
    }
}

// ---------------------------------------------------------------------------
// RL-8 / RL-9: the window count is read-and-reset, the total is never reset
// ---------------------------------------------------------------------------

/// A run that spans several summary windows, against a collector that never answers so
/// the SIEM queue keeps overflowing. Each window reports only its own losses (RL-8), so
/// no single window can equal the run's loss; the total nothing resets can (RL-9).
#[tokio::test]
async fn rl9_the_monotonic_total_is_never_reset() {
    let _env = AuthEnv::set(None).await;
    let dir = tempfile::tempdir().expect("a temporary directory");
    let path = dir.path().join("decisions.ndjson");

    let mut config = sample_config();
    config.log_file_path = Some(path.clone());
    config.siem_url = Some(wedged_collector().await);
    config.siem_queue_max_bytes =
        NonZeroU64::new(RL1_SIEM_QUEUE_MAX_BYTES).expect("a non-zero budget");

    probation::http::logging::set_summary_window(Duration::from_millis(100));
    let server = TestServer::start_with(config, Arc::new(SystemClock)).await;
    let app = server.app();

    let mut totals = Vec::new();
    for _ in 0..4 {
        for _ in 0..RL1_REQUESTS {
            server.get(PACKAGE).await;
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
        totals.push(app.delivery_lost_total());
    }
    drop(app);
    server.shutdown().await;
    probation::http::logging::set_summary_window(Duration::from_secs(60));

    assert!(
        totals.windows(2).all(|pair| pair[0] <= pair[1]),
        "the total never goes down: {totals:?}"
    );
    let windows: Vec<u64> = delivered(&path)
        .into_iter()
        .filter(|record| record["event"] == "request_summary")
        .filter_map(|summary| summary["dropped_siem"].as_u64())
        .collect();
    let largest = windows.iter().copied().max().unwrap_or(0);
    assert!(
        windows.iter().filter(|&&lost| lost > 0).count() >= 2,
        "the run spans several windows that each lost something: {windows:?}"
    );
    assert!(
        totals.last().copied().unwrap_or(0) > largest,
        "the total {totals:?} exceeds any one window {windows:?}, because a window is reset"
    );
}

// ---------------------------------------------------------------------------
// RL-12..16c, RL-25: GET /health/delivery, the shedding signal
// ---------------------------------------------------------------------------

const RL_HEALTH_SIEM_QUEUE_MAX_BYTES: u64 = 64 * 32 * 1024;

/// A collector that holds every connection unanswered until `true` is sent on the
/// returned handle, then answers each request `200`. A probe's own record is offered
/// to the sink like any other, so recovery is only observable once the queue can drain.
async fn gated_collector() -> (Url, tokio::sync::watch::Sender<bool>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("a loopback listener");
    let addr = listener.local_addr().expect("the listener's address");
    let (open, _) = tokio::sync::watch::channel(false);
    let gate = open.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut opened = gate.subscribe();
            tokio::spawn(async move {
                if opened.wait_for(|open| *open).await.is_err() {
                    return;
                }
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    // Read until the request goes idle, then answer it.
                    let mut got = false;
                    while let Ok(Ok(n)) =
                        tokio::time::timeout(Duration::from_millis(50), stream.read(&mut buf)).await
                    {
                        if n == 0 {
                            return;
                        }
                        got = true;
                    }
                    if got
                        && stream
                            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
                            .await
                            .is_err()
                    {
                        return;
                    }
                }
            });
        }
    });
    (
        Url::parse(&format!("http://{addr}/ingest")).expect("a collector URL"),
        open,
    )
}

/// A server whose only sink is a gated SIEM, driven until it has lost a record.
async fn shedding_server(
    clock: &Arc<TestClock>,
) -> (
    TestServer,
    tempfile::TempDir,
    tokio::sync::watch::Sender<bool>,
) {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let mut config = config_with_open_blocklist(dir.path());
    let (url, gate) = gated_collector().await;
    config.siem_url = Some(url);
    config.siem_queue_max_bytes =
        NonZeroU64::new(RL_HEALTH_SIEM_QUEUE_MAX_BYTES).expect("a non-zero budget");
    let server = TestServer::start_with(config, clock.shared()).await;
    for _ in 0..OVERFLOW_REQUESTS {
        server.get(PACKAGE).await;
    }
    assert!(
        server.app().delivery_lost_total() > 0,
        "the premise: the wedged collector cost a record"
    );
    (server, dir, gate)
}

/// Lets the collector answer and waits until an offered record is no longer lost, so
/// that the probe under test cannot itself move the total.
async fn recover(server: &TestServer, gate: &tokio::sync::watch::Sender<bool>) {
    gate.send_replace(true);
    let app = server.app();
    for _ in 0..200 {
        let before = app.delivery_lost_total();
        server.get("/health/live").await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        if app.delivery_lost_total() == before {
            return;
        }
    }
    panic!("the queue never drained");
}

#[tokio::test]
async fn rl12_delivery_is_200_when_nothing_is_shed() {
    let _env = AuthEnv::set(None).await;
    let clock = TestClock::at_rfc3339("2026-01-01T00:00:00Z");

    // No sink at all.
    let bare = TestServer::start_with(sample_config(), clock.shared()).await;
    bare.get(PACKAGE).await;
    assert_eq!(bare.status("/health/delivery").await, 200);
    bare.shutdown().await;

    // A sink that keeps up: a file, with some traffic and no loss.
    let dir = tempfile::tempdir().expect("a temporary directory");
    let mut config = sample_config();
    config.log_file_path = Some(dir.path().join("decisions.ndjson"));
    let server = TestServer::start_with(config, clock.shared()).await;
    for _ in 0..20 {
        server.get(PACKAGE).await;
    }
    assert_eq!(server.app().delivery_lost_total(), 0);
    assert_eq!(server.status("/health/delivery").await, 200);
    server.shutdown().await;
}

#[tokio::test]
async fn rl13_delivery_is_503_right_after_a_loss() {
    let _env = AuthEnv::set(None).await;
    let clock = TestClock::at_rfc3339("2026-01-01T00:00:00Z");
    let (server, _dir, gate) = shedding_server(&clock).await;
    assert_eq!(server.status("/health/delivery").await, 503);
    gate.send_replace(true);
    server.shutdown().await;
}

/// The first probe is what stamps the change, so it is made before the clock moves.
#[tokio::test]
async fn rl14_delivery_recovers_after_sixty_quiet_seconds() {
    let _env = AuthEnv::set(None).await;
    let clock = TestClock::at_rfc3339("2026-01-01T00:00:00Z");
    let (server, _dir, gate) = shedding_server(&clock).await;
    recover(&server, &gate).await;
    assert_eq!(server.status("/health/delivery").await, 503);
    clock.advance_seconds(59);
    assert_eq!(server.status("/health/delivery").await, 503);
    clock.advance_seconds(2);
    assert_eq!(server.status("/health/delivery").await, 200);
    server.shutdown().await;
}

#[tokio::test]
async fn rl15_readiness_stays_green_while_delivery_sheds() {
    let _env = AuthEnv::set(None).await;
    let clock = TestClock::at_rfc3339("2026-01-01T00:00:00Z");
    let (server, _dir, gate) = shedding_server(&clock).await;
    assert_eq!(server.status("/health/ready").await, 200);
    assert_eq!(server.status("/health/delivery").await, 503);
    gate.send_replace(true);
    server.shutdown().await;
}

#[tokio::test]
async fn rl16c_a_backwards_clock_step_does_not_latch_503() {
    let _env = AuthEnv::set(None).await;
    let clock = TestClock::at_rfc3339("2026-01-01T00:00:00Z");
    let (server, _dir, gate) = shedding_server(&clock).await;
    recover(&server, &gate).await;
    assert_eq!(server.status("/health/delivery").await, 503);
    clock.rewind_wall_clock_seconds(3_600);
    assert_eq!(server.status("/health/delivery").await, 200);
    server.shutdown().await;
}

#[tokio::test]
async fn rl25_delivery_has_no_body_and_is_not_cacheable() {
    let _env = AuthEnv::set(None).await;
    let clock = TestClock::at_rfc3339("2026-01-01T00:00:00Z");
    let (server, _dir, gate) = shedding_server(&clock).await;
    recover(&server, &gate).await;
    for (expected, label) in [(503, "shedding"), (200, "quiet")] {
        if expected == 200 {
            clock.advance_seconds(61);
        }
        let response = server.get("/health/delivery").await;
        assert_eq!(response.status(), expected, "{label}");
        assert_eq!(
            response
                .headers()
                .get("cache-control")
                .map(|v| v.as_bytes()),
            Some(&b"no-store"[..]),
            "{label}"
        );
        assert!(
            response.bytes().await.expect("a body").is_empty(),
            "{label}"
        );
    }
    server.shutdown().await;
}

// ---------------------------------------------------------------------------
// RL-10 / RL-23: the SIEM sink holds its batch while the collector is unreachable
// ---------------------------------------------------------------------------

/// A collector that answers every request `503` at once and records when each arrived.
/// Unlike [`silent_collector`], whose answer never comes and so hides a hot-spin behind
/// the client's own request timeout, this one makes the retry cadence the only thing
/// spacing the arrivals apart. `Connection: close` keeps every attempt a fresh
/// connection, so an arrival is an attempt.
async fn prompt_503_collector() -> (Url, Arc<std::sync::Mutex<Vec<std::time::Instant>>>) {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("a loopback listener");
    let addr = listener.local_addr().expect("the listener's address");
    let arrivals = Arc::new(std::sync::Mutex::new(Vec::new()));
    let recorded = Arc::clone(&arrivals);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let recorded = Arc::clone(&recorded);
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                // The whole request, body included, so the close is clean.
                loop {
                    let Ok(read) = stream.read(&mut chunk).await else {
                        return;
                    };
                    if read == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..read]);
                    let Some(head) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
                        continue;
                    };
                    let text = String::from_utf8_lossy(&buf[..head]).to_ascii_lowercase();
                    let length = text
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length:"))
                        .and_then(|value| value.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    if buf.len() >= head + 4 + length {
                        break;
                    }
                }
                recorded.lock().unwrap().push(std::time::Instant::now());
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                    )
                    .await;
            });
        }
    });
    (
        Url::parse(&format!("http://{addr}/ingest")).expect("a collector URL"),
        arrivals,
    )
}

/// Distinct decided `request_id`s in the bodies a wiremock collector was sent.
async fn decided_ids_received(collector: &MockServer) -> BTreeSet<String> {
    collector
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .flat_map(|request| {
            String::from_utf8_lossy(&request.body)
                .lines()
                .filter_map(|line| serde_json::from_str::<Value>(line).ok())
                .filter(|record| record["event"] == "request_decided")
                .filter_map(|record| record["request_id"].as_str().map(str::to_owned))
                .collect::<Vec<_>>()
        })
        .collect()
}

#[tokio::test]
async fn rl10_siem_holds_its_queue_while_the_collector_is_unreachable() {
    // Taken outside the timeout: the wait for the lock is other tests' running time.
    let _env = AuthEnv::set(None).await;
    tokio::time::timeout(Duration::from_secs(90), async {
        let collector = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&collector)
            .await;

        let mut config = sample_config();
        config.siem_url = Some(Url::parse(&collector.uri()).expect("the collector's URL"));
        let server = TestServer::start_with(config, Arc::new(SystemClock)).await;

        for _ in 0..20 {
            server.get(PACKAGE).await;
        }
        // Well past the ~2.6 s the retry ladder takes to run out. Without a hold the
        // first batch is discarded here, and only what is offered afterwards survives.
        tokio::time::sleep(Duration::from_secs(9)).await;
        for _ in 0..20 {
            server.get(PACKAGE).await;
        }
        assert_eq!(
            server.app().delivery_lost_total(),
            0,
            "an unreachable collector costs nothing while the queue has room"
        );

        collector.reset().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&collector)
            .await;

        let mut got = 0;
        for _ in 0..40 {
            got = decided_ids_received(&collector).await.len();
            if got >= 40 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        server.shutdown().await;
        assert_eq!(
            got, 40,
            "every record offered during the outage is delivered on recovery"
        );
    })
    .await
    .expect("HANG: rl10 did not finish");
}

#[tokio::test]
async fn rl10b_a_non_retryable_rejection_is_counted_immediately() {
    // Taken outside the timeout: the wait for the lock is other tests' running time.
    let _env = AuthEnv::set(None).await;
    tokio::time::timeout(Duration::from_secs(60), async {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("decisions.ndjson");
        let collector = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(302))
            .up_to_n_times(1)
            .mount(&collector)
            .await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&collector)
            .await;

        let mut config = sample_config();
        config.log_file_path = Some(path.clone());
        config.siem_url = Some(Url::parse(&collector.uri()).expect("the collector's URL"));
        let server = TestServer::start_with(config, Arc::new(SystemClock)).await;
        let app = server.app();

        for expected in [1, 2] {
            server.get(PACKAGE).await;
            // Past the two-second batch timer, so the batch has been sent and refused.
            tokio::time::sleep(Duration::from_millis(3500)).await;
            assert_eq!(
                app.delivery_lost_total(),
                expected,
                "the refused batch is counted before shutdown, not on the drain tail"
            );
        }
        drop(app);
        assert_eq!(
            collector.received_requests().await.expect("recorded").len(),
            2,
            "a 302 and a 401 are each tried once: the hold does not engage"
        );

        server.shutdown().await;
        assert!(
            delivered(&path)
                .iter()
                .filter(|record| record["event"] == "request_summary")
                .any(|summary| summary["dropped_siem"].as_u64() >= Some(2)),
            "and the summary record carries them"
        );
    })
    .await
    .expect("HANG: rl10b did not finish");
}

#[tokio::test]
async fn rl23_shutdown_completes_while_the_collector_is_unreachable() {
    let _env = AuthEnv::set(None).await;
    let mut config = sample_config();
    config.siem_url = Some(wedged_collector().await);
    let server = TestServer::start_with(config, Arc::new(SystemClock)).await;
    let app = server.app();

    for _ in 0..30 {
        server.get(PACKAGE).await;
    }
    // Long enough for the sink to have taken the batch and be holding it.
    tokio::time::sleep(Duration::from_secs(4)).await;

    // `Running::shutdown` cannot finish while this test holds an `App`, because the
    // storage queue stays open, so the held records are read once the sinks are
    // done and the handle is awaited after the clone is dropped.
    let started = std::time::Instant::now();
    let shutdown = tokio::spawn(server.shutdown());
    while app.delivery_lost_total() < 30 {
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the sinks finish within the drain deadline and count what they held: {}",
            app.delivery_lost_total()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    drop(app);
    tokio::time::timeout(Duration::from_secs(20), shutdown)
        .await
        .expect("HANG: shutdown did not return")
        .expect("the shutdown task ran");
}

#[tokio::test]
async fn rl23b_the_hold_does_not_hot_spin() {
    // Taken outside the timeout: the wait for the lock is other tests' running time,
    // not this test's.
    let _env = AuthEnv::set(None).await;
    tokio::time::timeout(Duration::from_secs(60), async {
        let (url, arrivals) = prompt_503_collector().await;
        let mut config = sample_config();
        config.siem_url = Some(url);
        let server = TestServer::start_with(config, Arc::new(SystemClock)).await;

        server.get(PACKAGE).await;
        // Two seconds of batch timer, then at least twelve of hold.
        tokio::time::sleep(Duration::from_secs(15)).await;

        let times = arrivals.lock().unwrap().clone();
        assert!(
            times.len() >= 5,
            "the hold keeps trying: {} arrivals",
            times.len()
        );
        // The first three are the existing ladder's attempt and two short retries.
        for pair in times[3..].windows(2) {
            let gap = pair[1] - pair[0];
            // 50 ms under the 2 s cap: the two ends are stamped on the server side.
            assert!(
                gap >= Duration::from_millis(1950),
                "retries beyond the ladder are spaced by the 2 s cap, not hot-spinning: {gap:?}"
            );
        }
        server.shutdown().await;
    })
    .await
    .expect("HANG: rl23b did not finish");
}
