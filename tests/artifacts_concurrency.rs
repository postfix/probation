//! Slice 8's witness: one transfer per reference however many requests want it, a
//! waiter leaving takes only itself, a publication that has begun always finishes,
//! a slow consumer is bounded, eviction never takes a file out from under a response,
//! and overload is refused rather than queued.
//!
//! **How these tests are made deterministic.** Not one of them creates timing with a
//! sleep. Every interleaving is forced, by one of two means:
//!
//! * a [`Gate`] in the fake transport parks a transfer half-arrived, so a test can be
//!   certain a download is in flight before it does anything else; and
//! * the cancellation tests call `artifacts::download::fetch` directly rather than
//!   through a socket, because dropping a future is an operation this test performs at
//!   an instant of its own choosing, whereas "the client disconnected and hyper
//!   noticed" is not. The coalescing and overload tests go through the real route, so
//!   the HTTP path is witnessed too.
//!
//! `common::wait_until` appears throughout. It never creates an interleaving; it waits
//! for the consequence of one the test has already forced, and fails loudly rather
//! than passing quietly if that consequence never arrives.
//!
//! **The two deadlines.** SPEC §9 fixes them at 30 s and 15 min, which is what
//! `Limits::new` sets and what `http::limits::the_shipped_deadlines_are_thirty_seconds_and_fifteen_minutes`
//! asserts. A test that waited one out would take a quarter of an hour, so the two
//! slow-consumer tests shorten them through `Limits::set_response_timeouts` — which
//! nothing in the binary calls — and then prove the mechanism, not the number.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{
    FakeAnswer, FakeRegistry, Gate, SlowReader, TestClock, TestServer, artifact_path, body_bytes,
    config_with_open_blocklist, npm_artifact_upstream_path, npm_tarball_url, npm_upstream_path,
    wait_until,
};
use probation::artifacts::content::ContentKey;
use probation::artifacts::download;
use probation::config::Config;
use probation::policy::{BlocklistSnapshot, Ecosystem};
use probation::store::rows::{
    ArtifactReference, ProjectRefresh, ReferenceId, ReferenceRow, ReferenceUpsert,
};
use probation::upstream::UpstreamValidators;
use serde_json::{Map, Value, json};
use tempfile::TempDir;
use url::Url;

const WIDGET: &str = "fixture-widget";
const V1: &str = "1.0.0";
const V2: &str = "2.0.0";
const V3: &str = "3.0.0";

/// Five days before [`NOW`], so the sample configuration's one-day cooldown is spent.
const PUBLISHED: &str = "2026-04-01T00:00:00Z";
const NOW: &str = "2026-04-06T12:00:00Z";

/// How long a consequence is allowed to take before the test calls it a failure.
/// Generous on purpose: it bounds a wait, it does not create one.
const PATIENCE: Duration = Duration::from_secs(20);

/// TM-1's "max-size refresh": the configured `max_references_per_project`, so the one
/// transaction a blocklist commit can be made to wait for is the largest this server
/// will run.
const REFRESH_SIZE: u32 = 5_000;

/// The bound TM-1 asks the commit to land inside while that refresh runs. It is a
/// ceiling, not a target: the refresh itself is what the commit waits for, and a
/// loaded machine is allowed to be slow without turning this into a flaky test.
const COMMIT_BOUND: Duration = Duration::from_secs(90);

fn filename(version: &str) -> String {
    format!("fixture-widget-{version}.tgz")
}

/// A document with no advertised integrity at all, so any body verifies and a test
/// can choose bodies by the size it needs rather than by a digest it has to compute.
/// What holds these references together is the permanent pin (STATE-01), which slice
/// 7 already witnesses.
fn document(versions: &[&str]) -> String {
    let mut rendered = Map::new();
    let mut time = Map::new();
    for version in versions {
        rendered.insert(
            (*version).to_owned(),
            json!({
                "name": WIDGET,
                "version": version,
                "dist": {"tarball": npm_tarball_url(WIDGET, &filename(version))},
            }),
        );
        time.insert((*version).to_owned(), json!(PUBLISHED));
    }

    json!({
        "name": WIDGET,
        "dist-tags": {"latest": versions.last().copied().unwrap_or(V1)},
        "versions": Value::Object(rendered),
        "time": Value::Object(time),
    })
    .to_string()
}

struct Harness {
    server: TestServer,
    registry: Arc<FakeRegistry>,
    clock: Arc<TestClock>,
    data_dir: std::path::PathBuf,
    _dir: TempDir,
}

impl Harness {
    /// The firewall's own artifact URL for one version, taken from the rendered
    /// document — the URL a client is actually given.
    async fn artifact_path(&self, version: &str) -> String {
        let document = self.server.json(&format!("/npm/{WIDGET}")).await;
        artifact_path(&document, version)
    }

    fn reference_id(&self, path: &str) -> ReferenceId {
        let hex = path
            .split('/')
            .nth(3)
            .unwrap_or_else(|| panic!("an artifact path has a reference id: {path}"));
        ReferenceId::parse_hex(hex).expect("the reference id is hexadecimal")
    }

    async fn reference(&self, id: ReferenceId) -> ReferenceRow {
        self.server
            .app()
            .store()
            .get_reference(id)
            .await
            .expect("the reference query")
            .expect("the reference was committed before its URL was advertised")
    }

    /// How many upstream *artifact* transfers this version has caused. Metadata calls
    /// are deliberately not counted: coalescing metadata refreshes is a separate,
    /// unowned obligation and this file must not quietly become its test.
    fn artifact_calls(&self, version: &str) -> usize {
        let path = npm_artifact_upstream_path(WIDGET, &filename(version));
        self.registry
            .calls()
            .iter()
            .filter(|url| url.path() == path)
            .count()
    }

    fn temp_files(&self) -> usize {
        std::fs::read_dir(self.data_dir.join("content").join("tmp"))
            .map(|entries| entries.count())
            .unwrap_or(0)
    }

    fn content_files(&self) -> usize {
        let objects = self.data_dir.join("content").join("objects");
        let Ok(fan_out) = std::fs::read_dir(&objects) else {
            return 0;
        };
        fan_out
            .flatten()
            .filter_map(|directory| std::fs::read_dir(directory.path()).ok())
            .map(|entries| entries.flatten().count())
            .sum()
    }

    async fn shutdown(self) {
        self.server.shutdown().await;
    }
}

async fn harness(artifacts: Vec<(&str, FakeAnswer)>) -> Harness {
    harness_with(artifacts, |_| {}).await
}

async fn harness_with(
    artifacts: Vec<(&str, FakeAnswer)>,
    adjust: impl FnOnce(&mut Config),
) -> Harness {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let mut config = config_with_open_blocklist(dir.path());
    adjust(&mut config);
    let data_dir = dir.path().join("data");

    let versions: Vec<&str> = artifacts.iter().map(|(version, _)| *version).collect();
    let registry = FakeRegistry::new();
    registry.answer(
        &npm_upstream_path(WIDGET),
        FakeAnswer::Body(document(&versions)),
    );
    for (version, answer) in artifacts {
        registry.answer(
            &npm_artifact_upstream_path(WIDGET, &filename(version)),
            answer,
        );
    }

    let clock = TestClock::at_rfc3339(NOW);
    let server = TestServer::start_in_with_registry(
        &data_dir,
        config,
        clock.shared(),
        Arc::clone(&registry),
    )
    .await;

    Harness {
        server,
        registry,
        clock,
        data_dir,
        _dir: dir,
    }
}

/// A transfer that delivers half its body and then parks until the test lets it go.
fn gated(gate: &Arc<Gate>) -> FakeAnswer {
    FakeAnswer::Gated {
        head: "first-half-".to_owned(),
        tail: "second-half".to_owned(),
        gate: Arc::clone(gate),
    }
}

const GATED_BODY: &str = "first-half-second-half";

// ---------------------------------------------------------------------------
// One transfer per reference (SPEC §9, FLOW-01)
// ---------------------------------------------------------------------------

/// SPEC §9: "Concurrent requests for one reference share one fetch and verification
/// result."
///
/// Eight requests arrive while the one transfer is parked half-arrived, so all eight
/// are provably *concurrent with* it rather than served one after another from the
/// cache — the gate is not released until the coordinator reports all eight sharing
/// the slot.
#[tokio::test]
async fn concurrent_cold_requests_cause_exactly_one_upstream_transfer() {
    let gate = Gate::new();
    let harness = harness(vec![(V1, gated(&gate))]).await;
    let path = harness.artifact_path(V1).await;
    let id = harness.reference_id(&path);
    let app = harness.server.app();

    let url = harness.server.url(&path);
    let client = common::downstream_client();
    let requests: Vec<_> = (0..8)
        .map(|_| {
            let client = client.clone();
            let url = url.clone();
            tokio::spawn(async move {
                let response = client.get(url).send().await.expect("the request completes");
                let status = response.status().as_u16();
                let body = response.bytes().await.expect("a body");
                (status, body)
            })
        })
        .collect();

    gate.wait_until_reached().await;
    wait_until("all eight requests share one transfer", PATIENCE, || {
        app.downloads.waiting_on(&id) == 8
    })
    .await;
    gate.release();

    for request in requests {
        let (status, body) = request.await.expect("the request task finishes");
        assert_eq!(status, 200);
        assert_eq!(
            body.as_ref(),
            GATED_BODY.as_bytes(),
            "every waiter gets the one verified body"
        );
    }

    assert_eq!(
        harness.artifact_calls(V1),
        1,
        "eight concurrent cold requests, one upstream transfer"
    );
    assert_eq!(harness.temp_files(), 0);
    // The storage task stops when the last handle to it goes; this test is holding one.
    drop(app);
    harness.shutdown().await;
}

/// SPEC §9: "A disconnected waiter releases its request resources without cancelling
/// other waiters."
///
/// The waiters here are futures this test drops itself, which is the only way to be
/// sure the drop happens at the instant the test says it does.
#[tokio::test]
async fn one_waiter_cancels_others_continue() {
    let gate = Gate::new();
    let harness = harness(vec![(V1, gated(&gate))]).await;
    let path = harness.artifact_path(V1).await;
    let id = harness.reference_id(&path);
    let app = harness.server.app();
    let row = harness.reference(id).await;

    let waiters: Vec<_> = (0..3)
        .map(|_| {
            let app = Arc::clone(&app);
            let row = row.clone();
            tokio::spawn(async move { download::fetch(&app, &row).await.map(|done| done.size) })
        })
        .collect();

    gate.wait_until_reached().await;
    wait_until("three waiters share one transfer", PATIENCE, || {
        app.downloads.waiting_on(&id) == 3
    })
    .await;

    let mut waiters = waiters;
    let leaving = waiters.remove(0);
    leaving.abort();
    wait_until("the waiter that left is gone", PATIENCE, || {
        app.downloads.waiting_on(&id) == 2
    })
    .await;

    gate.release();
    for waiter in waiters {
        let size = waiter
            .await
            .expect("the waiter task finishes")
            .expect("the shared transfer succeeded");
        assert_eq!(size, GATED_BODY.len() as u64);
    }

    assert_eq!(
        harness.artifact_calls(V1),
        1,
        "the transfer the other two were on was never restarted"
    );
    assert_eq!(harness.content_files(), 1, "and it published its bytes");
    // The storage task stops when the last handle to it goes; this test is holding one.
    drop(app);
    harness.shutdown().await;
}

/// SPEC §9: "If the last waiter leaves before artifact publication, cancel the fetch
/// and remove its temporary file and reservation."
#[tokio::test]
async fn last_waiter_cancels_download_and_removes_temp_file() {
    let gate = Gate::new();
    let harness = harness(vec![(V1, gated(&gate))]).await;
    let path = harness.artifact_path(V1).await;
    let id = harness.reference_id(&path);
    let app = harness.server.app();
    let row = harness.reference(id).await;

    let waiters: Vec<_> = (0..2)
        .map(|_| {
            let app = Arc::clone(&app);
            let row = row.clone();
            tokio::spawn(async move { download::fetch(&app, &row).await.map(|done| done.size) })
        })
        .collect();

    gate.wait_until_reached().await;
    wait_until("two waiters share one transfer", PATIENCE, || {
        app.downloads.waiting_on(&id) == 2
    })
    .await;
    assert_eq!(harness.temp_files(), 1, "the transfer has a temporary file");
    assert!(
        app.content.reserved_bytes() > 0,
        "and it holds a reservation against the cache budget"
    );

    for waiter in &waiters {
        waiter.abort();
    }
    for waiter in waiters {
        assert!(waiter.await.is_err(), "both waiters left");
    }

    wait_until("the abandoned temporary file is removed", PATIENCE, || {
        harness.temp_files() == 0
    })
    .await;
    wait_until("the abandoned reservation is released", PATIENCE, || {
        app.content.reserved_bytes() == 0
    })
    .await;
    assert_eq!(
        app.downloads.waiting_on(&id),
        0,
        "and nothing is left waiting on it"
    );

    // Whatever the parked transport does now, nothing is published for it.
    gate.release();
    assert_eq!(harness.content_files(), 0);
    assert!(
        harness.reference(id).await.content_key.is_none(),
        "a cancelled transfer commits no mapping"
    );
    // The storage task stops when the last handle to it goes; this test is holding one.
    drop(app);
    harness.shutdown().await;
}

/// SPEC §9: "Once the durable publication transaction starts, finish that bounded
/// operation and leave a valid cache entry."
///
/// The waiter is dropped once the transfer has passed that point, and the bytes still
/// land. Against slice 7's code this fails outright, because there the transfer ran in
/// the requesting task and went away with it.
///
/// The exact race — a waiter leaving *during* the publication rather than after it
/// began — is decided by one compare-and-exchange, and
/// `download::publishing_and_cancelling_cannot_both_win` is what pins that down; this
/// test is the end-to-end half.
#[tokio::test]
async fn publication_once_started_completes() {
    let gate = Gate::new();
    let harness = harness(vec![(V1, gated(&gate))]).await;
    let path = harness.artifact_path(V1).await;
    let id = harness.reference_id(&path);
    let app = harness.server.app();
    let row = harness.reference(id).await;

    let waiter = {
        let app = Arc::clone(&app);
        let row = row.clone();
        tokio::spawn(async move { download::fetch(&app, &row).await.map(|done| done.key) })
    };

    gate.wait_until_reached().await;
    wait_until("the transfer has a waiter", PATIENCE, || {
        app.downloads.waiting_on(&id) == 1
    })
    .await;
    gate.release();

    // Past this point cancellation is refused, so the abort below cannot undo it.
    let deadline = std::time::Instant::now() + PATIENCE;
    loop {
        if app.downloads.publishing(&id) || harness.content_files() == 1 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the transfer never reached its publication"
        );
        tokio::task::yield_now().await;
    }
    waiter.abort();

    wait_until("the publication completed anyway", PATIENCE, || {
        harness.content_files() == 1
    })
    .await;
    let mut committed = None;
    let deadline = std::time::Instant::now() + PATIENCE;
    while committed.is_none() {
        assert!(
            std::time::Instant::now() < deadline,
            "the content mapping was never committed"
        );
        committed = harness.reference(id).await.content_key;
    }

    assert_eq!(harness.temp_files(), 0, "and left no temporary file behind");
    let response = harness.server.get(&path).await;
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(
        response.text().await.expect("a body"),
        GATED_BODY,
        "the cache entry the abandoned publication left is a usable one"
    );
    assert_eq!(
        harness.artifact_calls(V1),
        1,
        "and the later request was served from it rather than re-fetching"
    );
    // The storage task stops when the last handle to it goes; this test is holding one.
    drop(app);
    harness.shutdown().await;
}

/// A transfer task that dies without answering must not take the reference with it.
///
/// `run` owns the only `watch::Sender` for the slot, and every waiter holds the slot
/// alive, so a transfer that ends without sending an outcome leaves `changed().await`
/// waiting on a channel that will never close and leaves the slot in `inflight` for
/// every later request to join. That is a permanent per-reference denial of service
/// from one panic, so the resolution has to survive an unwind and not merely an
/// ordinary error.
#[tokio::test]
async fn a_panic_in_the_transfer_task_does_not_wedge_the_reference() {
    let harness = harness(vec![(
        V1,
        FakeAnswer::PanicsMidStream {
            head: "half-a-body".to_owned(),
        },
    )])
    .await;
    let path = harness.artifact_path(V1).await;
    let id = harness.reference_id(&path);
    let app = harness.server.app();

    let first = tokio::time::timeout(Duration::from_secs(5), harness.server.get(&path))
        .await
        .expect("the first request answers rather than hanging on a panicked transfer");
    assert_eq!(
        first.status().as_u16(),
        503,
        "its waiters are given a real failure, not silence"
    );

    wait_until(
        "the dead slot is gone from the in-flight table",
        PATIENCE,
        || app.downloads.waiting_on(&id) == 0,
    )
    .await;
    assert!(
        !app.downloads.publishing(&id),
        "and nothing is left half-published for it"
    );

    let second = tokio::time::timeout(Duration::from_secs(5), harness.server.get(&path))
        .await
        .expect("a later request for the same reference is not wedged behind the dead one");
    assert_eq!(second.status().as_u16(), 503);
    assert_eq!(
        harness.artifact_calls(V1),
        2,
        "the second request started a transfer of its own rather than joining a dead slot"
    );
    assert_eq!(
        harness.temp_files(),
        0,
        "and neither attempt left a file behind"
    );
    assert_eq!(app.content.reserved_bytes(), 0, "or a reservation");

    // The storage task stops when the last handle to it goes; this test is holding one.
    drop(app);
    harness.shutdown().await;
}

// ---------------------------------------------------------------------------
// The two response deadlines (SPEC §9, FLOW-01)
// ---------------------------------------------------------------------------

/// A body no plausible combination of socket buffers can swallow, so a consumer that
/// reads nothing really does stall the response.
fn large_body() -> String {
    "x".repeat(16 * 1024 * 1024)
}

/// Waits for the reference's committed content mapping, which is what names the file
/// whose pin the assertions are about.
async fn published_key(
    harness: &Harness,
    id: ReferenceId,
) -> probation::artifacts::content::ContentKey {
    let deadline = std::time::Instant::now() + PATIENCE;
    loop {
        if let Some(key) = harness.reference(id).await.content_key {
            return key;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the artifact was never published"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// SPEC §9: "Apply a 30-second downstream write-idle timeout […] timeout or
/// disconnect releases file pins and permits."
#[tokio::test]
async fn slow_downstream_hits_write_idle_timeout() {
    let harness = harness(vec![(V1, FakeAnswer::Body(large_body()))]).await;
    let app = harness.server.app();
    // Short write-idle, long lifetime: whatever ends this response, it is not the
    // lifetime limit.
    app.limits
        .set_response_timeouts(Duration::from_millis(150), Duration::from_secs(600));

    let path = harness.artifact_path(V1).await;
    let id = harness.reference_id(&path);
    let reader = SlowReader::get(&harness.server, &path).await;

    let key = published_key(&harness, id).await;
    wait_until("the response has the file open", PATIENCE, || {
        app.content.open_count(&key) == 1
    })
    .await;
    wait_until(
        "the write-idle limit released the response's pin",
        PATIENCE,
        || app.content.open_count(&key) == 0,
    )
    .await;
    wait_until("and its request permit", PATIENCE, || {
        app.limits.active_available() == app.limits.max_active()
    })
    .await;

    let response = reader.read_what_arrived().await;
    let delivered = body_bytes(&response).len();
    assert!(delivered > 0, "the response had started: {delivered} bytes");
    assert!(
        (delivered as u64) < 16 * 1024 * 1024,
        "a consumer that never read got a cut-off body, not the whole {delivered}-byte artifact"
    );
    // The storage task stops when the last handle to it goes; this test is holding one.
    drop(app);
    harness.shutdown().await;
}

/// SPEC §9: "and a 15-minute response-body lifetime; timeout or disconnect releases
/// file pins and permits."
#[tokio::test]
async fn response_lifetime_timeout_releases_pin_and_permit() {
    let harness = harness(vec![(V1, FakeAnswer::Body(large_body()))]).await;
    let app = harness.server.app();
    // The mirror image of the test above: the write-idle limit cannot be what ends
    // this response, so the lifetime is.
    app.limits
        .set_response_timeouts(Duration::from_secs(600), Duration::from_millis(250));

    let path = harness.artifact_path(V1).await;
    let id = harness.reference_id(&path);
    assert_eq!(
        app.limits.active_available(),
        app.limits.max_active(),
        "no request is holding a permit yet"
    );
    let reader = SlowReader::get(&harness.server, &path).await;

    let key = published_key(&harness, id).await;
    wait_until("the response has the file open", PATIENCE, || {
        app.content.open_count(&key) == 1
    })
    .await;
    wait_until("the lifetime limit released the pin", PATIENCE, || {
        app.content.open_count(&key) == 0
    })
    .await;
    wait_until("and the request permit", PATIENCE, || {
        app.limits.active_available() == app.limits.max_active()
    })
    .await;

    let response = reader.read_what_arrived().await;
    assert!(
        (body_bytes(&response).len() as u64) < 16 * 1024 * 1024,
        "the response ended at its lifetime rather than delivering the whole body"
    );
    // The storage task stops when the last handle to it goes; this test is holding one.
    drop(app);
    harness.shutdown().await;
}

// ---------------------------------------------------------------------------
// Eviction and overload (SPEC §10)
// ---------------------------------------------------------------------------

/// SPEC §10: "Disk eviction uses approximate least-recently-used order, with access
/// updates batched off the request path. Never evict open files."
///
/// Three cached artifacts, and both halves of that sentence are load-bearing at once.
/// Their *publication* order is A, B, C; their *access* order, after a later warm read
/// of A that the maintenance pass writes, is B, C, A. One of the three has to go, and
/// the least recently used one — B — is the one a response is holding open.
///
/// So the pass has to skip B and go on to C. Both mechanisms are what decide that:
///
/// * without the batched access times the order would still be the publication order,
///   the pass would start at A, and C would survive;
/// * without the open-file check the pass would take B, and C would survive.
///
/// C being gone while A and B remain is therefore a claim neither mechanism can be
/// removed from.
#[tokio::test]
async fn eviction_never_removes_an_open_file() {
    let harness = harness(vec![
        (V1, FakeAnswer::Body("first".repeat(500))),
        (V2, FakeAnswer::Body("second".repeat(500))),
        (V3, FakeAnswer::Body("third".repeat(500))),
    ])
    .await;
    let app = harness.server.app();

    // Each artifact is fetched, and each pass writes that read's access time before
    // the clock moves on, so the three are unambiguously ordered.
    let mut paths = Vec::new();
    for version in [V1, V2, V3] {
        let path = harness.artifact_path(version).await;
        assert_eq!(harness.server.get(&path).await.status().as_u16(), 200);
        probation::tasks::maintenance::run_once(&app).await;
        harness.clock.advance_seconds(60);
        paths.push(path);
    }
    assert_eq!(harness.content_files(), 3, "all three are cached");

    // A warm read of the first one, which is what makes it the most recently used.
    let upstream_before = harness.artifact_calls(V1);
    assert_eq!(harness.server.get(&paths[0]).await.status().as_u16(), 200);
    assert_eq!(
        harness.artifact_calls(V1),
        upstream_before,
        "served from the cache, so the only thing that read changed is its access time"
    );
    probation::tasks::maintenance::run_once(&app).await;

    let keys: Vec<_> = {
        let mut keys = Vec::new();
        for path in &paths {
            keys.push(published_key(&harness, harness.reference_id(path)).await);
        }
        keys
    };
    let sizes: Vec<u64> = {
        let mut sizes = Vec::new();
        for path in &paths {
            sizes.push(
                harness
                    .reference(harness.reference_id(path))
                    .await
                    .pinned_size
                    .expect("a published artifact has a pinned size"),
            );
        }
        sizes
    };

    // A response is reading the least recently used file when the pass runs.
    let held = app
        .content
        .open_verified(&keys[1], sizes[1])
        .await
        .expect("a response holds the least recently used file open");

    // Room for two of the three. The budget is passed in rather than configured so
    // that no background pass can have acted on it first.
    let budget = sizes[0] + sizes[1] + 1;
    probation::tasks::maintenance::evict_to_budget(&app, budget).await;

    assert_eq!(
        app.content.open_count(&keys[1]),
        1,
        "the open file is still open"
    );
    assert!(
        app.content.path_for(&keys[1]).exists(),
        "and still there, least recently used or not: SPEC §10 never evicts an open file"
    );
    assert!(
        app.content.path_for(&keys[0]).exists(),
        "the most recently used file is untouched"
    );
    assert!(
        !app.content.path_for(&keys[2]).exists(),
        "the next-least-recently-used one went instead, so the budget is still honoured"
    );
    assert!(
        harness
            .reference(harness.reference_id(&paths[2]))
            .await
            .content_key
            .is_none(),
        "and the evicted file's mapping went with it"
    );

    let plan = app
        .store()
        .eviction_plan()
        .await
        .expect("the content index");
    assert!(
        plan.total_bytes <= budget,
        "the cache is back inside its budget: {} bytes",
        plan.total_bytes
    );

    drop(held);
    assert_eq!(
        harness.server.get(&paths[1]).await.status().as_u16(),
        200,
        "and the file that was open is still servable"
    );
    // The storage task stops when the last handle to it goes; this test is holding one.
    drop(app);
    harness.shutdown().await;
}

/// SPEC §10: "Use semaphores and bounded queues; reject overload instead of allowing
/// unbounded waiters or tasks."
///
/// The refusal is asserted while the one permit is provably still held — the parked
/// transfer has not been released — so "refused" is distinguishable from "waited its
/// turn and then succeeded".
#[tokio::test]
async fn overload_is_refused_not_queued() {
    let gate = Gate::new();
    let harness = harness_with(vec![(V1, gated(&gate))], |config| {
        config.max_active_requests = std::num::NonZeroU32::new(1).expect("one at a time");
    })
    .await;
    let path = harness.artifact_path(V1).await;
    let app = harness.server.app();

    let url = harness.server.url(&path);
    let client = common::downstream_client();
    let holding = tokio::spawn(async move {
        let response = client.get(url).send().await.expect("the request completes");
        (
            response.status().as_u16(),
            response.bytes().await.expect("a body"),
        )
    });

    gate.wait_until_reached().await;
    assert_eq!(
        app.limits.active_available(),
        0,
        "the one permit is held by the parked request"
    );

    let refused = harness.server.get(&path).await;
    assert_eq!(refused.status().as_u16(), 503);
    assert_eq!(common::body_error(refused).await, "OVERLOADED");

    let refused = harness.server.get(&format!("/npm/{WIDGET}")).await;
    assert_eq!(
        refused.status().as_u16(),
        503,
        "a metadata request is bounded by the same front door"
    );
    assert_eq!(common::body_error(refused).await, "OVERLOADED");

    // Only now is the permit given back, which is what makes the refusals above a
    // refusal rather than a wait.
    gate.release();
    let (status, body) = holding.await.expect("the held request finishes");
    assert_eq!(status, 200);
    assert_eq!(body.as_ref(), GATED_BODY.as_bytes());

    wait_until("the permit comes back", PATIENCE, || {
        app.limits.active_available() == 1
    })
    .await;
    assert_eq!(harness.server.get(&path).await.status().as_u16(), 200);
    // The storage task stops when the last handle to it goes; this test is holding one.
    drop(app);
    harness.shutdown().await;
}

// ---------------------------------------------------------------------------
// TM-1: a large refresh does not hold up a blocklist commit
// ---------------------------------------------------------------------------

/// SPEC §10: "give pending blocklist commits priority over ordinary queued cache
/// maintenance, without interrupting an active transaction."
///
/// The store is one task, so the only thing a blocklist commit can be made to wait
/// for is the transaction already running — and TM-1's worst case is the largest one
/// this server will run, a project refresh of `max_references_per_project`
/// references. This starts that refresh, loads the low-priority queue behind it, and
/// sends the commit, all in one `join!` so the queue contents are not a matter of
/// scheduling luck: `join!` polls in order, and each of these futures puts its command
/// on a queue the first time it is polled.
///
/// The commit then has to land inside the bound, and without waiting for the
/// maintenance backlog queued beside it to drain.
///
/// What this does **not** witness is the biased select itself: deleting `biased;` from
/// the store loop leaves this test passing, because a random choice between the two
/// ready queues still costs the commit only about one extra maintenance command, which
/// is well inside the margin below. The bound and the backlog are what TM-1 names; the
/// priority rule's own witness would have to be something other than a clock.
///
/// This one test runs on a multi-threaded runtime. The store is a single task, and on
/// a current-thread runtime it runs every queued command back to back without the test
/// task ever being scheduled in between — so every reply is observed at the same
/// instant and the order they were *executed* in is invisible. A second worker thread
/// is what lets this test see each answer as it lands.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blocklist_commit_is_not_delayed_by_a_large_project_refresh() {
    let harness = harness_with(vec![(V1, FakeAnswer::Body("body".to_owned()))], |config| {
        config.max_references_per_project =
            std::num::NonZeroU32::new(REFRESH_SIZE).expect("a reference cap");
    })
    .await;
    let store = harness.server.app().store().clone();
    let now = common::parse_rfc3339(NOW);

    let references: Vec<ReferenceUpsert> = (0..REFRESH_SIZE)
        .map(|index| {
            let version = format!("1.0.{index}");
            let reference = ArtifactReference {
                ecosystem: Ecosystem::Npm,
                name: "bulk-widget".to_owned(),
                version: version.clone(),
                filename: format!("bulk-widget-{version}.tgz"),
                upstream_url: Url::parse(&npm_tarball_url(
                    "bulk-widget",
                    &format!("bulk-widget-{version}.tgz"),
                ))
                .expect("a tarball URL"),
                expected: Vec::new(),
            };
            ReferenceUpsert {
                id: ReferenceId::compute(&reference),
                reference,
                publication_micros: Some(now),
                first_seen_micros: None,
            }
        })
        .collect();

    let document = common::snapshot(7, "2026-04-05T00:00:00Z", "2099-01-01T00:00:00Z", "");
    let snapshot = Arc::new(
        BlocklistSnapshot::parse_and_validate(document.as_bytes(), now)
            .expect("the test blocklist is valid"),
    );

    let started = std::time::Instant::now();
    let refresh = tokio::spawn({
        let store = store.clone();
        async move {
            let outcome = store
                .commit_project_refresh(ProjectRefresh {
                    ecosystem: Ecosystem::Npm,
                    name: "bulk-widget".to_owned(),
                    payload: Arc::from(b"{}".as_slice()),
                    validators: UpstreamValidators::default(),
                    validated_at_micros: now,
                    fetched_at_micros: now,
                    references,
                })
                .await;
            (outcome, std::time::Instant::now())
        }
    });

    // Wait until that refresh is genuinely inside its transaction. A probe on the
    // critical queue that cannot be answered is what "the store is busy with one
    // transaction" looks like from outside, and it is the only thing this test needs
    // to be sure of before it queues everything else.
    let probing = std::time::Instant::now() + PATIENCE;
    loop {
        assert!(
            std::time::Instant::now() < probing,
            "the maximum-size refresh never reached the store"
        );
        let probe = store.get_reference(
            ReferenceId::parse_hex(&"00".repeat(32)).expect("a reference id nothing matches"),
        );
        if tokio::time::timeout(Duration::from_millis(100), probe)
            .await
            .is_err()
        {
            break;
        }
    }

    // Now, with the store occupied: a real backlog on the low-priority queue, and the
    // blocklist commit beside it on the critical one.
    for batch in 0..4u8 {
        store.touch_content(
            (0..5_000u16)
                .map(|index| {
                    let mut key = [batch; 32];
                    key[..2].copy_from_slice(&index.to_le_bytes());
                    (ContentKey::from_sha256(key), now)
                })
                .collect(),
        );
    }

    // Queued behind that backlog: when this answers, the backlog has been worked
    // through. It is the only way to time work the maintenance queue does not reply to.
    let sentinel = async {
        let outcome = store.eviction_plan().await;
        (outcome, std::time::Instant::now())
    };
    let commit = async {
        let outcome = tokio::time::timeout(COMMIT_BOUND, store.commit_blocklist(snapshot)).await;
        (outcome, std::time::Instant::now())
    };

    let ((planned, sentinel_at), (committed, commit_at)) = tokio::join!(sentinel, commit);
    let (refreshed, refresh_at) = refresh.await.expect("the refresh task finishes");
    let commit_elapsed = commit_at.duration_since(started);
    let refresh_elapsed = refresh_at.duration_since(started);

    refreshed.expect("the maximum-size refresh committed");
    planned.expect("the maintenance backlog was worked through");
    committed
        .unwrap_or_else(|_| panic!("the blocklist commit did not land within {COMMIT_BOUND:?}"))
        .expect("the blocklist commit succeeded");

    assert!(
        commit_elapsed <= refresh_elapsed + Duration::from_millis(500),
        "the commit ({commit_elapsed:?}) waited for the running transaction \
         ({refresh_elapsed:?}) and for nothing beyond it"
    );
    assert!(
        sentinel_at > commit_at + Duration::from_millis(500),
        "the commit did not wait for the maintenance backlog to drain: commit at \
         {commit_elapsed:?}, maintenance done at {:?}",
        sentinel_at.duration_since(started)
    );

    let row = store
        .load_blocklist()
        .await
        .expect("the query")
        .expect("the committed blocklist");
    assert_eq!(row.revision, 7, "and it is the one that was committed");
    // The storage task stops when the last handle to it goes; this test is holding one.
    drop(store);
    harness.shutdown().await;
}
