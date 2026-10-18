//! Slice 3's reload witness: what the poller notices, what it refuses, and the order
//! it does things in.
//!
//! Every test here reads the snapshot in force through the HTTP surface rather than
//! through an accessor of its own, so nothing asserted below depends on a seam the
//! running binary does not have. Two documents are told apart by their validity
//! windows: `/health/ready` is `200` exactly while the snapshot in force covers the
//! clock, so moving the clock past one document's `expires_at` and not the other's
//! says which of the two is in force.

mod common;

use std::fs;
use std::num::NonZeroU64;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use common::{
    TestClock, TestServer, database_path, modified_of, replace_atomically,
    replace_atomically_preserving_mtime, rewrite_in_place, sample_config, set_modified, snapshot,
};
use probation::clock::Clock;
use probation::config::Config;

/// Two polling intervals plus slack: SPEC §12's target for noticing a replaced file.
const TWO_INTERVALS: Duration = Duration::from_millis(2_500);

const NOW: &str = "2026-09-17T00:00:00Z";
const GENERATED: &str = "2026-09-16T00:00:00Z";
/// Comfortably after every clock these tests use.
const FAR: &str = "2026-09-19T00:00:00Z";

fn config_for(blocklist_file: &Path) -> Config {
    let mut config = sample_config();
    config.blocklist_file = blocklist_file.to_path_buf();
    config.blocklist_poll_seconds = NonZeroU64::new(1).expect("one second is not zero");
    config
}

/// SPEC §8: "Persist the last accepted snapshot so restart can use it while still
/// valid." The file is gone by the time the second instance starts, so what makes it
/// ready can only be what the first instance committed.
#[tokio::test]
async fn restart_uses_last_accepted_snapshot_while_valid() {
    let data_dir = tempfile::tempdir().expect("a data directory");
    let blocklist_dir = tempfile::tempdir().expect("a blocklist directory");
    let blocklist_file = blocklist_dir.path().join("blocklist.json");
    fs::write(&blocklist_file, snapshot(3, GENERATED, FAR, "")).expect("the snapshot is written");

    let server = TestServer::start_in(
        data_dir.path(),
        config_for(&blocklist_file),
        TestClock::at_rfc3339(NOW),
    )
    .await;
    assert_eq!(server.status("/health/ready").await, 200);
    server.shutdown().await;

    fs::remove_file(&blocklist_file).expect("the blocklist file is removed");

    let clock = TestClock::at_rfc3339(NOW);
    let restarted =
        TestServer::start_in(data_dir.path(), config_for(&blocklist_file), clock.shared()).await;

    assert_eq!(
        restarted.status("/health/ready").await,
        200,
        "the persisted snapshot is still valid, so the restart starts ready"
    );
    assert_eq!(restarted.status("/npm/left-pad").await, 404);

    // It is the persisted snapshot, carrying its own window — not a new one.
    clock.set_rfc3339(FAR);
    assert_eq!(restarted.status("/health/ready").await, 503);

    restarted.shutdown().await;
}

/// SPEC §8: "A malformed replacement retains the valid last snapshot and logs an
/// error." It never substitutes an empty blocklist.
#[tokio::test]
async fn malformed_replacement_retains_last_good() {
    let data_dir = tempfile::tempdir().expect("a data directory");
    let blocklist_dir = tempfile::tempdir().expect("a blocklist directory");
    let blocklist_file = blocklist_dir.path().join("blocklist.json");
    // Expires on the 18th, so the clock can be used to ask which snapshot is in force.
    fs::write(
        &blocklist_file,
        snapshot(3, GENERATED, "2026-09-18T00:00:00Z", ""),
    )
    .expect("the snapshot is written");

    let clock = TestClock::at_rfc3339(NOW);
    let server =
        TestServer::start_in(data_dir.path(), config_for(&blocklist_file), clock.shared()).await;
    assert_eq!(server.status("/health/ready").await, 200);

    let captured = common::logs::capture();
    let before = captured.lines_mentioning(&blocklist_file.display().to_string());

    replace_atomically(&blocklist_file, "this is not a blocklist at all");
    tokio::time::sleep(TWO_INTERVALS).await;

    assert_eq!(
        server.status("/health/ready").await,
        200,
        "the last good snapshot stays in force"
    );
    assert_eq!(
        captured.lines_mentioning(&blocklist_file.display().to_string()) - before,
        1,
        "a malformed file is structural: nothing about it can change without the file \
         changing, so it is read and reported once and not once per interval"
    );
    assert_eq!(server.status("/npm/left-pad").await, 404);

    // And it is the same snapshot, not a permissive stand-in: it expires when the one
    // that was accepted expires.
    clock.set_rfc3339("2026-09-18T00:00:00Z");
    assert_eq!(server.status("/health/ready").await, 503);

    // And the poller is still polling after the rejection: the next good file is taken.
    replace_atomically(&blocklist_file, &snapshot(4, GENERATED, FAR, ""));
    server
        .wait_for_status("/health/ready", 200, TWO_INTERVALS)
        .await;

    server.shutdown().await;
}

/// The other half of the retry rule: an expired candidate only gets older, so while the
/// file is unchanged it is read and reported once, not once per interval. Only a
/// `generated_at` in the future is worth reading again.
#[tokio::test]
async fn an_expired_candidate_is_not_retried_while_the_file_is_unchanged() {
    let captured = common::logs::capture();
    let data_dir = tempfile::tempdir().expect("a data directory");
    let blocklist_dir = tempfile::tempdir().expect("a blocklist directory");
    let blocklist_file = blocklist_dir.path().join("blocklist.json");
    fs::write(&blocklist_file, snapshot(3, GENERATED, FAR, "")).expect("the snapshot is written");

    let server = TestServer::start_in(
        data_dir.path(),
        config_for(&blocklist_file),
        TestClock::at_rfc3339(NOW),
    )
    .await;
    assert_eq!(server.status("/health/ready").await, 200);

    let marker = blocklist_file.display().to_string();
    let before = captured.lines_mentioning(&marker);
    replace_atomically(
        &blocklist_file,
        &snapshot(4, "2026-09-15T00:00:00Z", "2026-09-16T00:00:00Z", ""),
    );
    // Three intervals and a half: a retried rejection would be reported three times.
    tokio::time::sleep(Duration::from_millis(3_500)).await;

    assert_eq!(
        captured.lines_containing_all(&[&marker, "expired"]),
        1,
        "the expired candidate is reported once"
    );
    assert_eq!(
        captured.lines_mentioning(&marker) - before,
        1,
        "and nothing else about the file was reported"
    );
    assert_eq!(server.status("/health/ready").await, 200);

    server.shutdown().await;
}

/// `max_blocklist_bytes` is a ceiling on the read: a file one byte over it is refused
/// and the snapshot in force stays, and a file exactly at it is accepted.
#[tokio::test]
async fn a_blocklist_over_max_bytes_is_refused_and_one_at_it_is_accepted() {
    const LIMIT: usize = 4_096;
    let padded = |document: String, len: usize| {
        let padding = len - document.len();
        format!("{document}{}", " ".repeat(padding))
    };

    let data_dir = tempfile::tempdir().expect("a data directory");
    let blocklist_dir = tempfile::tempdir().expect("a blocklist directory");
    let blocklist_file = blocklist_dir.path().join("blocklist.json");
    // Expires on the 18th, so the clock can say whether it is still the one in force.
    fs::write(
        &blocklist_file,
        snapshot(3, GENERATED, "2026-09-18T00:00:00Z", ""),
    )
    .expect("the snapshot is written");
    let mut config = config_for(&blocklist_file);
    config.max_blocklist_bytes = NonZeroU64::new(LIMIT as u64).expect("a non-zero limit");

    let clock = TestClock::at_rfc3339(NOW);
    let server = TestServer::start_in(data_dir.path(), config, clock.shared()).await;
    assert_eq!(server.status("/health/ready").await, 200);

    replace_atomically(
        &blocklist_file,
        &padded(snapshot(4, GENERATED, FAR, ""), LIMIT + 1),
    );
    tokio::time::sleep(TWO_INTERVALS).await;
    clock.set_rfc3339("2026-09-18T00:00:00Z");
    assert_eq!(
        server.status("/health/ready").await,
        503,
        "revision 3 is still in force and has now expired: the oversized revision 4 was refused"
    );

    replace_atomically(
        &blocklist_file,
        &padded(snapshot(5, GENERATED, FAR, ""), LIMIT),
    );
    server
        .wait_for_status("/health/ready", 200, TWO_INTERVALS)
        .await;

    server.shutdown().await;
}

/// SPEC §10's ordering, with a previous snapshot in force when a later commit fails.
///
/// A revision above `i64::MAX` is a valid document that storage cannot represent, so
/// its commit fails while the database itself is fine. Had it been published anyway,
/// the later revision 4 would be refused as a rollback and the unstorable revision,
/// expiring with revision 3, would still be in force. That the instance is ready past
/// that expiry shows revision 4 was taken, so the failed commit left revision 3 in
/// force.
#[tokio::test]
async fn a_failed_commit_leaves_the_previous_snapshot_in_force() {
    const EXPIRES: &str = "2026-09-18T00:00:00Z";

    let data_dir = tempfile::tempdir().expect("a data directory");
    let blocklist_dir = tempfile::tempdir().expect("a blocklist directory");
    let blocklist_file = blocklist_dir.path().join("blocklist.json");
    fs::write(&blocklist_file, snapshot(3, GENERATED, EXPIRES, "")).expect("the snapshot");

    let clock = TestClock::at_rfc3339(NOW);
    let server =
        TestServer::start_in(data_dir.path(), config_for(&blocklist_file), clock.shared()).await;
    assert_eq!(server.status("/health/ready").await, 200);

    let unstorable = u64::try_from(i64::MAX).expect("i64::MAX fits a u64") + 1;
    replace_atomically(
        &blocklist_file,
        &snapshot(unstorable, GENERATED, EXPIRES, ""),
    );
    tokio::time::sleep(TWO_INTERVALS).await;

    replace_atomically(&blocklist_file, &snapshot(4, GENERATED, FAR, ""));
    clock.set_rfc3339(EXPIRES);
    server
        .wait_for_status("/health/ready", 200, TWO_INTERVALS)
        .await;

    server.shutdown().await;
}

/// SPEC §8 step 3: "Reject rollback and changed contents with an unchanged
/// revision." The rejected candidate is otherwise perfectly valid and would outlive
/// the snapshot in force, which is how the test can tell a rejection from an
/// acceptance.
#[tokio::test]
async fn rollback_rejected() {
    let data_dir = tempfile::tempdir().expect("a data directory");
    let blocklist_dir = tempfile::tempdir().expect("a blocklist directory");
    let blocklist_file = blocklist_dir.path().join("blocklist.json");
    fs::write(
        &blocklist_file,
        snapshot(3, GENERATED, "2026-09-18T00:00:00Z", ""),
    )
    .expect("the snapshot is written");

    let clock = TestClock::at_rfc3339(NOW);
    let server =
        TestServer::start_in(data_dir.path(), config_for(&blocklist_file), clock.shared()).await;
    assert_eq!(server.status("/health/ready").await, 200);

    // An older revision, valid in itself and with a longer window.
    replace_atomically(&blocklist_file, &snapshot(2, GENERATED, FAR, ""));
    tokio::time::sleep(TWO_INTERVALS).await;
    assert_eq!(server.status("/health/ready").await, 200);

    clock.set_rfc3339("2026-09-18T00:00:00Z");
    assert_eq!(
        server.status("/health/ready").await,
        503,
        "revision 3 is still in force and has now expired: the rollback to revision 2, \
         whose window is still open, was refused"
    );

    // Changed contents at the revision already in force are refused for the same
    // reason: the producer must say what changed by bumping the revision.
    replace_atomically(
        &blocklist_file,
        &snapshot(
            3,
            GENERATED,
            FAR,
            r#"{"ecosystem":"npm","name":"left-pad","version":null,"reason":"malware"}"#,
        ),
    );
    tokio::time::sleep(TWO_INTERVALS).await;
    assert_eq!(server.status("/health/ready").await, 503);

    // The control: a strictly newer revision with that same longer window is accepted,
    // so the two refusals above are about the revision rule and nothing else.
    replace_atomically(&blocklist_file, &snapshot(4, GENERATED, FAR, ""));
    server
        .wait_for_status("/health/ready", 200, TWO_INTERVALS)
        .await;

    server.shutdown().await;
}

/// SPEC §8: "At expiry, both new resolutions and artifact downloads fail with `503`
/// [...] Liveness remains healthy; readiness becomes unhealthy." No poll and no
/// restart is involved: the window is compared with the clock on the request itself.
#[tokio::test]
async fn readiness_false_at_expiry_liveness_true() {
    let data_dir = tempfile::tempdir().expect("a data directory");
    let blocklist_dir = tempfile::tempdir().expect("a blocklist directory");
    let blocklist_file = blocklist_dir.path().join("blocklist.json");
    fs::write(
        &blocklist_file,
        snapshot(3, GENERATED, "2026-09-18T00:00:00Z", ""),
    )
    .expect("the snapshot is written");

    let clock = TestClock::at_rfc3339("2026-09-17T23:59:59Z");
    let server =
        TestServer::start_in(data_dir.path(), config_for(&blocklist_file), clock.shared()).await;

    assert_eq!(server.status("/health/live").await, 200);
    assert_eq!(server.status("/health/ready").await, 200);
    assert_eq!(server.status("/npm/left-pad").await, 404);

    // Expiry is exclusive: at exactly `expires_at` the snapshot is no longer a policy.
    clock.set_rfc3339("2026-09-18T00:00:00Z");

    assert_eq!(server.status("/health/ready").await, 503);
    assert_eq!(
        server.status("/health/live").await,
        200,
        "liveness stays healthy at expiry"
    );

    let refusal = server.get("/npm/left-pad").await;
    assert_eq!(refusal.status().as_u16(), 503);
    let body: serde_json::Value =
        serde_json::from_str(&refusal.text().await.expect("a response body"))
            .expect("a JSON error body");
    assert_eq!(body["error"], serde_json::Value::from("POLICY_UNAVAILABLE"));

    server.shutdown().await;
}

/// TM-5: a producer replaces the file atomically, in the same second, with a document
/// of exactly the same length. Only the inode is different, and the inode is what the
/// change detection is built on.
#[tokio::test]
async fn same_length_same_second_atomic_replacement_is_detected() {
    let data_dir = tempfile::tempdir().expect("a data directory");
    let blocklist_dir = tempfile::tempdir().expect("a blocklist directory");
    let blocklist_file = blocklist_dir.path().join("blocklist.json");

    // Two documents of equal length whose only meaningful difference is how long they
    // stay valid. The first is thirty seconds from expiring.
    let first = snapshot(3, GENERATED, "2026-09-17T00:00:30Z", "");
    let second = snapshot(4, GENERATED, FAR, "");
    assert_eq!(
        first.len(),
        second.len(),
        "the replacement must be exactly as long as what it replaces, or the length \
         alone would give it away"
    );

    fs::write(&blocklist_file, &first).expect("the snapshot is written");
    let clock = TestClock::at_rfc3339(NOW);
    let server =
        TestServer::start_in(data_dir.path(), config_for(&blocklist_file), clock.shared()).await;
    assert_eq!(server.status("/health/ready").await, 200);

    let before = modified_of(&blocklist_file);
    replace_atomically_preserving_mtime(&blocklist_file, &second);
    assert_eq!(
        modified_of(&blocklist_file),
        before,
        "the replacement carries the modification time of the file it replaced"
    );
    assert_eq!(
        fs::metadata(&blocklist_file).expect("the file").len() as usize,
        first.len()
    );

    // Two polling intervals, with the clock left alone so the sixty-second backstop
    // re-read cannot be what does the work.
    tokio::time::sleep(TWO_INTERVALS).await;

    clock.advance_seconds(40);
    assert_eq!(
        server.status("/health/ready").await,
        200,
        "the replacement was noticed within two intervals: revision 3 expired ten seconds \
         ago and revision 4 is in force"
    );

    server.shutdown().await;
}

/// The other half of TM-5: a producer that rewrites the file in place is out of
/// contract, so no metadata says anything changed. The sixty-second unconditional
/// re-read is the only thing that catches it, and this test shows both halves — that
/// the metadata check misses it, and that the backstop does not.
#[tokio::test]
async fn in_place_rewrite_is_detected_by_the_backstop_reread() {
    let data_dir = tempfile::tempdir().expect("a data directory");
    let blocklist_dir = tempfile::tempdir().expect("a blocklist directory");
    let blocklist_file = blocklist_dir.path().join("blocklist.json");

    let first = snapshot(3, GENERATED, "2026-09-17T00:00:30Z", "");
    let second = snapshot(4, GENERATED, FAR, "");
    assert_eq!(first.len(), second.len());

    fs::write(&blocklist_file, &first).expect("the snapshot is written");
    let clock = TestClock::at_rfc3339(NOW);
    let server =
        TestServer::start_in(data_dir.path(), config_for(&blocklist_file), clock.shared()).await;
    assert_eq!(server.status("/health/ready").await, 200);

    let before = modified_of(&blocklist_file);
    rewrite_in_place(&blocklist_file, &second);
    set_modified(&blocklist_file, before);
    assert_eq!(modified_of(&blocklist_file), before);

    // Two intervals, and forty seconds on the clock: past revision 3's expiry, but
    // still short of the sixty-second backstop.
    tokio::time::sleep(TWO_INTERVALS).await;
    clock.advance_seconds(40);
    tokio::time::sleep(TWO_INTERVALS).await;
    assert_eq!(
        server.status("/health/ready").await,
        503,
        "nothing about the file's device, inode, length or modification time changed, so \
         the metadata check alone does not see the rewrite"
    );

    // Past sixty seconds, the file is re-read whether or not anything says it changed.
    clock.advance_seconds(30);
    server
        .wait_for_status("/health/ready", 200, TWO_INTERVALS)
        .await;
    assert_eq!(server.status("/npm/left-pad").await, 404);

    server.shutdown().await;
}

/// A candidate refused because its window has not opened yet — the clock-skew case:
/// a producer whose `generated_at` is a second ahead of this host. The bytes become
/// valid on their own, without anything touching the file, so the poller must keep
/// re-reading them rather than write the file off as unchanged.
#[tokio::test]
async fn a_window_rejection_is_retried_when_the_file_has_not_changed() {
    let data_dir = tempfile::tempdir().expect("a data directory");
    let blocklist_dir = tempfile::tempdir().expect("a blocklist directory");
    let blocklist_file = blocklist_dir.path().join("blocklist.json");

    // Generated thirty seconds after the clock this instance starts on.
    fs::write(
        &blocklist_file,
        snapshot(3, "2026-09-17T00:00:30Z", FAR, ""),
    )
    .expect("the snapshot is written");

    let clock = TestClock::at_rfc3339(NOW);
    let server =
        TestServer::start_in(data_dir.path(), config_for(&blocklist_file), clock.shared()).await;
    assert_eq!(
        server.status("/health/ready").await,
        503,
        "generated_at is still in the future, so there is no policy in force yet"
    );

    // The skew resolves. Nothing about the file changes — same inode, same length,
    // same modification time — and forty seconds is short of the sixty-second
    // backstop, so the re-read can only come from the rejection being retryable.
    clock.advance_seconds(40);
    server
        .wait_for_status("/health/ready", 200, TWO_INTERVALS)
        .await;

    server.shutdown().await;
}

/// A commit that fails is not a reason to stop trying. SPEC §10 makes storage write
/// failures a `503` "until storage is usable again", which is only true if the poller
/// re-reads bytes it has already read once the disk recovers (OPS-01).
#[tokio::test]
async fn a_failed_commit_keeps_retrying_the_same_bytes() {
    let captured = common::logs::capture();

    let data_dir = tempfile::tempdir().expect("a data directory");
    fs::create_dir_all(data_dir.path().join("state")).expect("a state directory");
    fs::write(database_path(data_dir.path()), vec![0xABu8; 8192])
        .expect("the unreadable database is written");

    let blocklist_dir = tempfile::tempdir().expect("a blocklist directory");
    let blocklist_file = blocklist_dir.path().join("blocklist.json");
    fs::write(&blocklist_file, snapshot(3, GENERATED, FAR, "")).expect("the snapshot is written");

    let server = TestServer::start_in(
        data_dir.path(),
        config_for(&blocklist_file),
        TestClock::at_rfc3339(NOW),
    )
    .await;

    // The startup pass fails to commit; two more polling intervals must fail again
    // rather than treat the file as already handled.
    tokio::time::sleep(TWO_INTERVALS).await;

    let marker = blocklist_file.display().to_string();
    let attempts = captured.lines_mentioning(&marker);
    assert!(
        attempts >= 2,
        "the poller gave up after {attempts} attempt(s): a candidate whose commit failed \
         must be retried on the next pass, or a momentary storage failure drops an \
         accepted blocklist until the file changes or the backstop fires"
    );

    server.shutdown().await;
}

/// SPEC §10: "Persist a new blocklist before publishing its memory snapshot."
///
/// The witness is a store that cannot commit. The same blocklist file makes a healthy
/// instance ready, so the document is not what is refused — and the instance whose
/// database will not open never publishes it. Publishing first and committing second
/// would put that snapshot in force here.
#[tokio::test]
async fn blocklist_is_committed_before_it_is_published() {
    let blocklist_dir = tempfile::tempdir().expect("a blocklist directory");
    let blocklist_file = blocklist_dir.path().join("blocklist.json");
    fs::write(&blocklist_file, snapshot(3, GENERATED, FAR, "")).expect("the snapshot is written");

    // The control: with a database that opens, this exact file is accepted, committed
    // and published.
    let healthy_dir = tempfile::tempdir().expect("a data directory");
    let healthy = TestServer::start_in(
        healthy_dir.path(),
        config_for(&blocklist_file),
        TestClock::at_rfc3339(NOW),
    )
    .await;
    assert_eq!(healthy.status("/health/ready").await, 200);
    assert_eq!(healthy.status("/npm/left-pad").await, 404);
    healthy.shutdown().await;

    // The same file, in front of a database that will not open.
    let broken_dir = tempfile::tempdir().expect("a data directory");
    fs::create_dir_all(broken_dir.path().join("state")).expect("a state directory");
    fs::write(database_path(broken_dir.path()), vec![0xABu8; 8192])
        .expect("the unreadable database is written");

    let broken = TestServer::start_in(
        broken_dir.path(),
        config_for(&blocklist_file),
        TestClock::at_rfc3339(NOW),
    )
    .await;

    tokio::time::sleep(TWO_INTERVALS).await;
    // Not readiness: an unusable store makes it `503` whatever is published, so it
    // could not tell the two orders apart. The policy error can, and
    // `a_failed_commit_leaves_the_previous_snapshot_in_force` covers readiness.
    let refusal = broken.get("/npm/left-pad").await;
    assert_eq!(refusal.status().as_u16(), 503);
    let body: serde_json::Value =
        serde_json::from_str(&refusal.text().await.expect("a response body"))
            .expect("a JSON error body");
    assert_eq!(
        body["error"],
        serde_json::Value::from("POLICY_UNAVAILABLE"),
        "no policy is in force, which is only true if publication waited on the commit"
    );

    broken.shutdown().await;
}

/// The poller's file I/O runs off the runtime's worker threads. A blocklist read that
/// blocks — here a FIFO nobody has written yet — must not stall request handling, and
/// on this single-threaded test runtime a read on the worker would stall all of it.
#[tokio::test]
async fn a_blocklist_read_that_blocks_does_not_stall_requests() {
    let data_dir = tempfile::tempdir().expect("a data directory");
    let blocklist_dir = tempfile::tempdir().expect("a blocklist directory");
    let blocklist_file = blocklist_dir.path().join("blocklist.json");
    fs::write(&blocklist_file, snapshot(3, GENERATED, FAR, "")).expect("the snapshot is written");
    let server = TestServer::start_in(
        data_dir.path(),
        config_for(&blocklist_file),
        TestClock::at_rfc3339(NOW),
    )
    .await;
    assert_eq!(server.status("/health/ready").await, 200);

    // A new inode, so the next pass opens it, and opening a FIFO waits for a writer.
    let fifo = blocklist_dir.path().join("blocklist.fifo");
    let made = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("mkfifo runs");
    assert!(made.success(), "the FIFO is made");
    fs::rename(&fifo, &blocklist_file).expect("the FIFO replaces the file");

    // The probe is a thread of its own: if the read does block this runtime's one
    // worker, nothing on it runs again until the FIFO is written.
    let addr = server.local_addr();
    let file = blocklist_file.clone();
    let probe = std::thread::spawn(move || {
        std::thread::sleep(TWO_INTERVALS);
        let answered = live_answers_within(addr, Duration::from_secs(2));
        // Released either way, so the pass — and the runtime — can finish.
        fs::write(&file, snapshot(4, GENERATED, FAR, "")).expect("the FIFO is written");
        answered
    });
    let answered = tokio::task::spawn_blocking(move || probe.join().expect("the probe"))
        .await
        .expect("the probe's join");
    assert!(
        answered,
        "/health/live answered while the poller was waiting on the blocklist read"
    );

    server.shutdown().await;
}

/// Whether `GET /health/live` is answered `200` within `within`, over a plain socket so
/// it needs no runtime at all.
fn live_answers_within(addr: std::net::SocketAddr, within: Duration) -> bool {
    use std::io::{Read, Write};

    let Ok(mut stream) = std::net::TcpStream::connect_timeout(&addr, within) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(within));
    if stream
        .write_all(b"GET /health/live HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n")
        .is_err()
    {
        return false;
    }
    let mut response = String::new();
    let _ = stream.read_to_string(&mut response);
    response.starts_with("HTTP/1.1 200")
}

/// A clock that panics on its first monotonic reading after being armed. Only the
/// poller and the npm and PyPI metadata routes read the monotonic clock, and the test
/// below sends neither kind of request while it is armed, so the panic lands in a poll
/// pass.
struct PanickingClock {
    inner: Arc<TestClock>,
    armed: AtomicBool,
}

impl Clock for PanickingClock {
    fn now_utc_micros(&self) -> i64 {
        self.inner.now_utc_micros()
    }

    fn now_monotonic(&self) -> Instant {
        if self.armed.swap(false, Ordering::SeqCst) {
            // Formatted, so the payload is a `String` as most real panics' are.
            let at = self.inner.now_monotonic();
            panic!("an injected panic inside a blocklist poll pass at {at:?}");
        }
        self.inner.now_monotonic()
    }
}

/// A poll pass that panics must not stop blocklist updates for the life of the
/// process: the panic is reported, and the next interval polls as before.
#[tokio::test]
async fn a_panicking_poll_pass_is_logged_and_polling_continues() {
    let captured = common::logs::capture();
    let data_dir = tempfile::tempdir().expect("a data directory");
    let blocklist_dir = tempfile::tempdir().expect("a blocklist directory");
    let blocklist_file = blocklist_dir.path().join("blocklist.json");
    fs::write(
        &blocklist_file,
        snapshot(3, GENERATED, "2026-09-18T00:00:00Z", ""),
    )
    .expect("the snapshot is written");

    let clock = Arc::new(PanickingClock {
        inner: TestClock::at_rfc3339(NOW),
        armed: AtomicBool::new(false),
    });
    let server = TestServer::start_in(
        data_dir.path(),
        config_for(&blocklist_file),
        Arc::clone(&clock) as Arc<dyn Clock>,
    )
    .await;
    assert_eq!(server.status("/health/ready").await, 200);

    clock.armed.store(true, Ordering::SeqCst);
    common::wait_until("a poll pass reads the clock", TWO_INTERVALS, || {
        !clock.armed.load(Ordering::SeqCst)
    })
    .await;

    // Revision 3 expires on the 18th and revision 4 does not, so past the 18th the
    // instance is ready only if a pass after the panic accepted revision 4.
    replace_atomically(&blocklist_file, &snapshot(4, GENERATED, FAR, ""));
    clock.inner.set_rfc3339("2026-09-18T00:00:00Z");
    server
        .wait_for_status("/health/ready", 200, TWO_INTERVALS)
        .await;

    let marker = blocklist_file.display().to_string();
    assert_eq!(
        captured.lines_containing_all(&[&marker, "panicked"]),
        1,
        "the panicking pass is reported once, at error, naming the file it was polling"
    );

    server.shutdown().await;
}
