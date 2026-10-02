//! Adversarial testing of slice 11's shared `SingleFlight` primitive
//! (`src/concurrency/single_flight.rs`), against both callers: artifact transfers
//! (`src/artifacts/download.rs`) and metadata refreshes (`src/npm::refresh_coalesced`,
//! `src/pypi::refresh_coalesced`).
//!
//! Every test here bounds its own waits — a hang is reported, not left to the test
//! runner's own timeout — and none of them modify product code or the existing
//! witness files.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{
    FakeAnswer, FakeRegistry, Gate, TestClock, TestServer, config_with_open_blocklist,
    fake_origins, fixture, npm_artifact_upstream_path, npm_tarball_url, npm_upstream_path,
    pypi_upstream_path, wait_until,
};
use probation::http::error::ApiError;
use probation::policy::Ecosystem;
use probation::store::cache::ProjectKey;
use serde_json::{Map, Value, json};
use tempfile::TempDir;

const WIDGET: &str = "fixture-widget";
const NOW: &str = "2026-04-06T12:00:00Z";
const ONE_DAY: u64 = 86_400;
const PATIENCE: Duration = Duration::from_secs(20);

fn bard_document(project: &str) -> String {
    json!({
        "meta": {"api-version": "1.1"},
        "name": project,
        "versions": [],
        "files": [],
    })
    .to_string()
}

struct Harness {
    server: TestServer,
    registry: Arc<FakeRegistry>,
    clock: Arc<TestClock>,
    _dir: TempDir,
}

impl Harness {
    fn metadata_calls(&self, path: &str) -> usize {
        self.registry
            .calls()
            .iter()
            .filter(|url| url.path() == path)
            .count()
    }

    fn advance_seconds(&self, seconds: i64) {
        self.clock.advance_seconds(seconds);
    }

    async fn shutdown(self) {
        self.server.shutdown().await;
    }
}

async fn harness(now: &str, answers: &[(&str, FakeAnswer)]) -> Harness {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let mut config = config_with_open_blocklist(dir.path());
    config.cooldown_seconds = ONE_DAY;

    let registry = FakeRegistry::new();
    for (path, answer) in answers {
        registry.answer(path, answer.clone());
    }

    let clock = TestClock::at_rfc3339(now);
    let server = TestServer::start_with_upstream(
        config,
        clock.shared(),
        Arc::clone(&registry) as Arc<dyn probation::upstream::Transport>,
        fake_origins(),
    )
    .await;

    Harness {
        server,
        registry,
        clock,
        _dir: dir,
    }
}

// ---------------------------------------------------------------------------
// Starting point 1: a metadata leader whose own request is dropped mid-refresh.
// ---------------------------------------------------------------------------

/// The leader in `refresh_coalesced` runs in the *requesting task itself* (unlike a
/// transfer, which is spawned separately). Aborting that task drops the future at
/// the `.await` inside the gated upstream call — not a panic, a plain future drop —
/// which is exactly the "own request disappears" case the implementer named and no
/// test covers. If `Resolution`'s `Drop` guard is not reached (or reached but does
/// not retire the slot), the joiner hangs and the project is wedged forever.
#[tokio::test]
async fn npm_dropped_leader_does_not_wedge_the_project() {
    let gate = Gate::new();
    let path = npm_upstream_path(WIDGET);
    let harness = harness(
        NOW,
        &[(
            &path,
            FakeAnswer::GatedMetadata {
                body: fixture("npm/representative-100-versions.json"),
                gate: Arc::clone(&gate),
            },
        )],
    )
    .await;
    let app = harness.server.app();
    let key = ProjectKey::new(Ecosystem::Npm, WIDGET);

    let leader = {
        let app = Arc::clone(&app);
        tokio::spawn(async move { probation::npm::ensure_fresh_project(&app, WIDGET).await })
    };
    gate.wait_until_reached().await;

    let joiner = {
        let app = Arc::clone(&app);
        tokio::spawn(async move { probation::npm::ensure_fresh_project(&app, WIDGET).await })
    };
    wait_until("the joiner shares the leader's refresh", PATIENCE, || {
        app.downloads.metadata().waiting_on(&key) == 2
    })
    .await;

    // The leader's own request disappears mid-refresh — not a panic, a future drop.
    leader.abort();

    let answered = tokio::time::timeout(PATIENCE, joiner)
        .await
        .expect(
            "HANG: the joiner is still waiting after the leader's request was dropped; \
             the abandoned Resolution never answered it",
        )
        .expect("the joiner task itself finishes");
    assert_eq!(
        answered.expect_err("the joiner is told the refresh did not finish"),
        ApiError::InternalFailure,
        "the joiner gets 503 INTERNAL_FAILURE rather than hanging or a wrong success"
    );

    wait_until(
        "the dropped leader's slot is retired, not left RUNNING forever",
        PATIENCE,
        || app.downloads.metadata().waiting_on(&key) == 0,
    )
    .await;

    // Upstream is healthy; a retry must succeed rather than being wedged behind the
    // abandoned slot.
    harness.registry.answer(
        &path,
        FakeAnswer::Body(fixture("npm/representative-100-versions.json")),
    );
    let retried = tokio::time::timeout(
        Duration::from_secs(5),
        probation::npm::ensure_fresh_project(&app, WIDGET),
    )
    .await
    .expect("a retry after the dropped leader is not wedged behind it");
    assert!(retried.is_ok(), "and it succeeds: {retried:?}");

    drop(app);
    harness.shutdown().await;
}

/// The PyPI twin of the above — slice 11's whole point is that both callers share one
/// mechanism, so the same attack is repeated against the second caller rather than
/// assumed to hold by analogy.
#[tokio::test]
async fn pypi_dropped_leader_does_not_wedge_the_project() {
    let gate = Gate::new();
    const BARD: &str = "friendly-bard";
    let path = pypi_upstream_path(BARD);
    let harness = harness(
        NOW,
        &[(
            &path,
            FakeAnswer::GatedMetadata {
                body: bard_document(BARD),
                gate: Arc::clone(&gate),
            },
        )],
    )
    .await;
    let app = harness.server.app();
    let key = ProjectKey::new(Ecosystem::PyPi, BARD);

    let leader = {
        let app = Arc::clone(&app);
        tokio::spawn(async move { probation::pypi::ensure_fresh_project(&app, BARD).await })
    };
    gate.wait_until_reached().await;

    let joiner = {
        let app = Arc::clone(&app);
        tokio::spawn(async move { probation::pypi::ensure_fresh_project(&app, BARD).await })
    };
    wait_until("the joiner shares the leader's refresh", PATIENCE, || {
        app.downloads.metadata().waiting_on(&key) == 2
    })
    .await;

    leader.abort();

    let answered = tokio::time::timeout(PATIENCE, joiner)
        .await
        .expect("HANG: the PyPI joiner is still waiting after the leader's request was dropped")
        .expect("the joiner task itself finishes");
    assert_eq!(
        answered.expect_err("the joiner is told the refresh did not finish"),
        ApiError::InternalFailure
    );

    wait_until(
        "the dropped PyPI leader's slot is retired",
        PATIENCE,
        || app.downloads.metadata().waiting_on(&key) == 0,
    )
    .await;

    harness
        .registry
        .answer(&path, FakeAnswer::Body(bard_document(BARD)));
    let retried = tokio::time::timeout(
        Duration::from_secs(5),
        probation::pypi::ensure_fresh_project(&app, BARD),
    )
    .await
    .expect("a retry after the dropped PyPI leader is not wedged behind it");
    assert!(retried.is_ok(), "and it succeeds: {retried:?}");

    drop(app);
    harness.shutdown().await;
}

// ---------------------------------------------------------------------------
// Starting point 4: npm and PyPI share one table, keyed by `ProjectKey`.
// ---------------------------------------------------------------------------

/// An npm project and a PyPI project of the same name must not collide in the shared
/// metadata table: a refresh gated on one ecosystem must not answer, coalesce, or
/// otherwise resolve a concurrent request for the same name in the other ecosystem.
#[tokio::test]
async fn npm_and_pypi_projects_of_the_same_name_do_not_collide() {
    let gate = Gate::new();
    const SHARED_NAME: &str = "shared-name";
    let npm_path = npm_upstream_path(SHARED_NAME);
    let pypi_path = pypi_upstream_path(SHARED_NAME);

    let harness = harness(
        NOW,
        &[
            (
                &npm_path,
                FakeAnswer::GatedMetadata {
                    body: json!({
                        "name": SHARED_NAME,
                        "dist-tags": {"latest": "1.0.0"},
                        "versions": {},
                        "time": {},
                    })
                    .to_string(),
                    gate: Arc::clone(&gate),
                },
            ),
            (&pypi_path, FakeAnswer::Body(bard_document(SHARED_NAME))),
        ],
    )
    .await;
    let app = harness.server.app();
    let npm_key = ProjectKey::new(Ecosystem::Npm, SHARED_NAME);
    let _pypi_key = ProjectKey::new(Ecosystem::PyPi, SHARED_NAME);

    // The npm refresh is parked in flight.
    let npm_request = {
        let app = Arc::clone(&app);
        tokio::spawn(
            async move { probation::npm::ensure_fresh_project(&app, SHARED_NAME).await },
        )
    };
    gate.wait_until_reached().await;
    wait_until("the npm refresh is in flight", PATIENCE, || {
        app.downloads.metadata().waiting_on(&npm_key) == 1
    })
    .await;

    // The PyPI project of the same name must be servable independently, not blocked
    // behind, coalesced into, or answered by the gated npm entry.
    let pypi_result = tokio::time::timeout(
        Duration::from_secs(5),
        probation::pypi::ensure_fresh_project(&app, SHARED_NAME),
    )
    .await
    .expect("HANG: the PyPI request is blocked behind the unrelated gated npm refresh");
    assert!(
        pypi_result.is_ok(),
        "the PyPI project answers on its own, independent of the npm entry: {pypi_result:?}"
    );
    assert_eq!(
        app.downloads.metadata().waiting_on(&npm_key),
        1,
        "the npm slot is untouched by the PyPI request"
    );

    gate.release();
    let npm_result = tokio::time::timeout(PATIENCE, npm_request)
        .await
        .expect("the npm refresh finishes")
        .expect("the npm task finishes");
    assert!(
        npm_result.is_ok(),
        "the npm project also answers: {npm_result:?}"
    );

    assert_eq!(harness.metadata_calls(&npm_path), 1);
    assert_eq!(harness.metadata_calls(&pypi_path), 1);

    drop(app);
    harness.shutdown().await;
}

// ---------------------------------------------------------------------------
// Starting point 5: interleave the two callers.
// ---------------------------------------------------------------------------

fn npm_document(name: &str, version: &str) -> String {
    let mut versions = Map::new();
    let mut time = Map::new();
    versions.insert(
        version.to_owned(),
        json!({
            "name": name,
            "version": version,
            "dist": {"tarball": npm_tarball_url(name, &format!("{name}-{version}.tgz"))},
        }),
    );
    time.insert(version.to_owned(), json!("2026-04-01T00:00:00Z"));
    json!({
        "name": name,
        "dist-tags": {"latest": version},
        "versions": Value::Object(versions),
        "time": Value::Object(time),
    })
    .to_string()
}

/// Both callers now run through one primitive on one `App`. A panic in the artifact
/// path (its own spawned task) racing a dropped leader in the metadata path (the
/// requesting task itself) must not affect each other — separate keys in separate
/// tables inside `DownloadCoordinator`, and this proves it rather than assumes it.
#[tokio::test]
async fn a_panicking_transfer_and_a_dropped_metadata_leader_do_not_affect_each_other() {
    const NAME: &str = "interleave-widget";
    const VERSION: &str = "1.0.0";
    let metadata_gate = Gate::new();
    let npm_path = npm_upstream_path(NAME);
    let artifact_path = npm_artifact_upstream_path(NAME, &format!("{NAME}-{VERSION}.tgz"));

    let harness = harness(
        NOW,
        &[
            (&npm_path, FakeAnswer::Body(npm_document(NAME, VERSION))),
            (
                &artifact_path,
                FakeAnswer::PanicsMidStream {
                    head: "partial-body".to_owned(),
                },
            ),
        ],
    )
    .await;
    let app = harness.server.app();

    // Resolve the reference id the ordinary way, through the rendered document.
    let document = harness.server.json(&format!("/npm/{NAME}")).await;
    let rel_path = common::artifact_path(&document, VERSION);
    let id_hex = rel_path
        .split('/')
        .nth(3)
        .expect("the artifact path has a reference id");
    let reference_id =
        probation::store::rows::ReferenceId::parse_hex(id_hex).expect("hex reference id");
    let row = app
        .store()
        .get_reference(reference_id)
        .await
        .expect("the reference query")
        .expect("the reference was committed");

    // The artifact transfer panics mid-stream, in its own spawned task.
    let transfer = {
        let app = Arc::clone(&app);
        let row = row.clone();
        tokio::spawn(async move { probation::artifacts::download::fetch(&app, &row).await })
    };

    // Concurrently, drop a metadata leader for an unrelated project.
    const OTHER: &str = "interleave-other";
    let other_path = npm_upstream_path(OTHER);
    harness.registry.answer(
        &other_path,
        FakeAnswer::GatedMetadata {
            body: npm_document(OTHER, VERSION),
            gate: Arc::clone(&metadata_gate),
        },
    );
    let metadata_key = ProjectKey::new(Ecosystem::Npm, OTHER);
    let metadata_leader = {
        let app = Arc::clone(&app);
        tokio::spawn(async move { probation::npm::ensure_fresh_project(&app, OTHER).await })
    };
    metadata_gate.wait_until_reached().await;
    metadata_leader.abort();

    let transfer_result = tokio::time::timeout(PATIENCE, transfer)
        .await
        .expect("HANG: the panicking transfer did not resolve")
        .expect(
            "the requesting task itself does not panic; the coalescing mechanism \
                 converts the panic in the spawned transfer task into a normal error",
        );
    assert!(
        transfer_result.is_err(),
        "the request is told the transfer failed rather than seeing a wrong success"
    );

    wait_until(
        "the reference's transfer slot is retired despite the concurrent metadata churn",
        PATIENCE,
        || app.downloads.waiting_on(&reference_id) == 0,
    )
    .await;
    wait_until(
        "the unrelated metadata slot is retired despite the concurrent panic",
        PATIENCE,
        || app.downloads.metadata().waiting_on(&metadata_key) == 0,
    )
    .await;

    // Both are independently servable afterwards.
    harness.registry.answer(
        &artifact_path,
        FakeAnswer::Body("whole-body-now".to_owned()),
    );
    let retried_transfer = tokio::time::timeout(
        Duration::from_secs(5),
        probation::artifacts::download::fetch(&app, &row),
    )
    .await
    .expect("the transfer is retryable after the panic, unaffected by the metadata churn");
    assert!(retried_transfer.is_ok(), "{retried_transfer:?}");

    harness
        .registry
        .answer(&other_path, FakeAnswer::Body(npm_document(OTHER, VERSION)));
    let retried_metadata = tokio::time::timeout(
        Duration::from_secs(5),
        probation::npm::ensure_fresh_project(&app, OTHER),
    )
    .await
    .expect("the metadata project is retryable after its leader was dropped");
    assert!(retried_metadata.is_ok(), "{retried_metadata:?}");

    drop(app);
    harness.shutdown().await;
}

// ---------------------------------------------------------------------------
// A joiner's own disconnect must not affect the leader or other joiners
// (metadata's analogue of slice 8's "one waiter cancels, others continue").
// ---------------------------------------------------------------------------

#[tokio::test]
async fn npm_joiner_dropped_mid_refresh_does_not_affect_the_leader_or_other_joiners() {
    let gate = Gate::new();
    let path = npm_upstream_path(WIDGET);
    let harness = harness(
        NOW,
        &[(
            &path,
            FakeAnswer::GatedMetadata {
                body: fixture("npm/representative-100-versions.json"),
                gate: Arc::clone(&gate),
            },
        )],
    )
    .await;
    let app = harness.server.app();
    let key = ProjectKey::new(Ecosystem::Npm, WIDGET);

    let leader = {
        let app = Arc::clone(&app);
        tokio::spawn(async move { probation::npm::ensure_fresh_project(&app, WIDGET).await })
    };
    gate.wait_until_reached().await;

    let mut joiners: Vec<_> = (0..3)
        .map(|_| {
            let app = Arc::clone(&app);
            tokio::spawn(
                async move { probation::npm::ensure_fresh_project(&app, WIDGET).await },
            )
        })
        .collect();
    wait_until(
        "all three joiners share the leader's refresh",
        PATIENCE,
        || app.downloads.metadata().waiting_on(&key) == 4,
    )
    .await;

    let leaving = joiners.remove(0);
    leaving.abort();
    wait_until(
        "the joiner that left is gone; the leader is unaffected",
        PATIENCE,
        || app.downloads.metadata().waiting_on(&key) == 3,
    )
    .await;

    gate.release();

    let leader_result = tokio::time::timeout(PATIENCE, leader)
        .await
        .expect("HANG: the leader did not finish after an unrelated joiner was dropped")
        .expect("the leader task finishes");
    assert!(leader_result.is_ok(), "{leader_result:?}");

    for joiner in joiners {
        let result = tokio::time::timeout(PATIENCE, joiner)
            .await
            .expect("HANG: a surviving joiner did not finish")
            .expect("the joiner task finishes");
        assert!(
            result.is_ok(),
            "a surviving joiner is served by the one refresh the departed joiner was \
             never allowed to disrupt: {result:?}"
        );
    }

    assert_eq!(
        harness.metadata_calls(&path),
        1,
        "one refresh served the leader and both surviving joiners"
    );

    drop(app);
    harness.shutdown().await;
}

// ---------------------------------------------------------------------------
// Starting point 2: liveness rests on `send_replace`. Attack the "joined but not
// yet subscribed" window with load, since it cannot be forced deterministically
// without a hook inside the primitive itself (join() and slot.wait() have no
// await point between them for a joiner, so only genuine multi-thread scheduling
// pressure can widen the window).
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn many_late_subscribers_never_hang_on_an_already_resolved_refresh() {
    for round in 0..200 {
        let gate = Gate::new();
        let name = format!("race-widget-{round}");
        let path = npm_upstream_path(&name);
        let harness = harness(
            NOW,
            &[(
                &path,
                FakeAnswer::GatedMetadata {
                    body: npm_document(&name, "1.0.0"),
                    gate: Arc::clone(&gate),
                },
            )],
        )
        .await;
        let app = harness.server.app();

        let leader = {
            let app = Arc::clone(&app);
            let name = name.clone();
            tokio::spawn(
                async move { probation::npm::ensure_fresh_project(&app, &name).await },
            )
        };
        gate.wait_until_reached().await;

        // Fire a burst of joiners at the same instant the gate opens, so some of
        // them race `join()` against the leader's `send_replace` on another
        // thread — the exact window the implementer's comment describes.
        gate.release();
        let joiners: Vec<_> = (0..16)
            .map(|_| {
                let app = Arc::clone(&app);
                let name = name.clone();
                tokio::spawn(async move {
                    probation::npm::ensure_fresh_project(&app, &name).await
                })
            })
            .collect();

        tokio::time::timeout(PATIENCE, leader)
            .await
            .unwrap_or_else(|_| panic!("HANG (round {round}): the leader did not finish"))
            .expect("the leader task finishes")
            .expect("the leader's refresh succeeds");

        for (i, joiner) in joiners.into_iter().enumerate() {
            tokio::time::timeout(PATIENCE, joiner)
                .await
                .unwrap_or_else(|_| {
                    panic!("HANG (round {round}, joiner {i}): a late subscriber never resolved")
                })
                .expect("the joiner task finishes")
                .expect("every late subscriber is answered, not left on a closed-never channel");
        }

        drop(app);
        harness.shutdown().await;
    }
}

// ---------------------------------------------------------------------------
// Starting point 3: the claimed pre-existing race between `Resolution` retiring
// the slot and `current_project` inserting into the memory cache.
// ---------------------------------------------------------------------------

/// Two halves, because the first one alone advertises coverage it does not have.
///
/// **The upper bound.** `refresh_coalesced`'s `Resolution` drops (retiring the slot)
/// synchronously before control returns to `current_project`, which then inserts into
/// the memory cache — two steps with no `.await` between them, so only genuine
/// cross-thread parallelism can land a new cold request in that window. The burst loop
/// hammers that boundary with a real multi-thread runtime and many repetitions, looking
/// for *more* than one upstream call inside a single TTL window.
///
/// **The lower bound**, and this is the half that witnesses `finish()`. The bound above
/// is blind to `Resolution::drop` losing its `self.flight.finish(...)` call: without it
/// a new request joins an already-answered slot and is served that stale project, which
/// causes *fewer* upstream calls, never more, so `after - before <= 1` stays satisfied
/// while the project quietly goes stale. The second half forces that case with no timing
/// window at all — this test joins the in-flight slot itself and holds the [`Waiter`]
/// guard past the leader's answer, which pins the waiter count above zero and so
/// disables the `Waiter` guard's own removal path, leaving `Resolution::drop` as the
/// only thing that can retire the slot. A post-TTL request must then cause exactly one
/// *new* refresh; zero means it was served from a stale slot that should have been gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn ttl_expiry_bursts_never_cause_more_than_one_refresh_per_window() {
    let name = "race-boundary-widget";
    let path = npm_upstream_path(name);
    let harness = harness(
        NOW,
        &[(&path, FakeAnswer::Body(npm_document(name, "1.0.0")))],
    )
    .await;
    let app = harness.server.app();

    // Prime the cache once so every later call takes the TTL-expired branch.
    probation::npm::ensure_fresh_project(&app, name)
        .await
        .expect("the priming request succeeds");
    let primed_calls = harness.metadata_calls(&path);
    assert_eq!(primed_calls, 1);

    for burst in 0..300 {
        // Expire the TTL, then release a real burst of parallel requesters at once.
        harness.advance_seconds(ONE_DAY as i64 + 1);

        let before = harness.metadata_calls(&path);
        let requesters: Vec<_> = (0..24)
            .map(|_| {
                let app = Arc::clone(&app);
                tokio::spawn(async move {
                    probation::npm::ensure_fresh_project(&app, name).await
                })
            })
            .collect();
        for requester in requesters {
            tokio::time::timeout(PATIENCE, requester)
                .await
                .unwrap_or_else(|_| panic!("HANG (burst {burst}): a requester did not finish"))
                .expect("the requester task finishes")
                .expect("the requester's project resolves");
        }
        let after = harness.metadata_calls(&path);
        assert!(
            after - before <= 1,
            "burst {burst}: {} upstream calls for one TTL-expiry window (before={before}, \
             after={after}) — the finish()/cache-insert race let a second cold request \
             start a redundant refresh",
            after - before
        );
    }

    // ---- the lower bound: the slot must be retired at the answer, not later ----

    let key = ProjectKey::new(Ecosystem::Npm, name);
    let gate = Gate::new();
    harness.registry.answer(
        &path,
        FakeAnswer::GatedMetadata {
            body: npm_document(name, "1.0.0"),
            gate: Arc::clone(&gate),
        },
    );
    harness.advance_seconds(ONE_DAY as i64 + 1);

    let parked = {
        let app = Arc::clone(&app);
        tokio::spawn(async move { probation::npm::ensure_fresh_project(&app, name).await })
    };
    gate.wait_until_reached().await;

    // This test becomes a participant in the refresh already in flight, and keeps that
    // guard alive past the leader's answer.
    let (_slot, leader, held) = app.downloads.metadata().join(key.clone());
    assert!(
        !leader,
        "the test joined the refresh already in flight rather than starting one of its own"
    );

    gate.release();
    tokio::time::timeout(PATIENCE, parked)
        .await
        .expect("the parked leader finishes")
        .expect("the leader task finishes")
        .expect("the leader's refresh succeeds");

    // The leader has answered and its own `Waiter` has dropped, but `held` keeps the
    // count above zero — so if the slot is still in the table now, only a missing
    // `finish()` can have left it there.
    harness
        .registry
        .answer(&path, FakeAnswer::Body(npm_document(name, "1.0.0")));
    let before_stale = harness.metadata_calls(&path);
    harness.advance_seconds(ONE_DAY as i64 + 1);

    tokio::time::timeout(
        Duration::from_secs(5),
        probation::npm::ensure_fresh_project(&app, name),
    )
    .await
    .expect("the post-TTL request is not wedged behind the answered slot")
    .expect("the post-TTL request resolves");

    let new_calls = harness.metadata_calls(&path) - before_stale;
    assert_eq!(
        new_calls, 1,
        "a request after TTL expiry must cause exactly one NEW upstream refresh, not \
         {new_calls}: zero means it joined an already-answered slot still sitting in the \
         in-flight table and was served that stale project — `Resolution::drop` must \
         retire the slot with `finish()` at the instant it answers, rather than leaving \
         removal to whenever the last participant happens to drop"
    );

    drop(held);
    drop(app);
    harness.shutdown().await;
}
