//! Slice 3's persistence witness: the write-ahead log really recovers a committed
//! blocklist, a database that will not recover leaves the process alive and the
//! bytes on disk untouched, a restored state directory is not ready until a current
//! blocklist is loaded, and one data directory belongs to one process.

mod common;

use std::fs;
use std::num::NonZeroU64;
use std::path::Path;
use std::time::Duration;

use common::{TestClock, TestServer, database_path, sample_config, snapshot, wal_path};
use probation::config::Config;
use probation::{App, AppDeps};
use tempfile::TempDir;

/// Two polling intervals plus slack: SPEC §12's target for noticing a replaced file.
const TWO_INTERVALS: Duration = Duration::from_millis(2_500);

const NOW: &str = "2026-09-17T00:00:00Z";
const GENERATED: &str = "2026-09-16T00:00:00Z";
const EXPIRES: &str = "2026-09-19T00:00:00Z";

fn config_for(blocklist_file: &Path) -> Config {
    let mut config = sample_config();
    config.blocklist_file = blocklist_file.to_path_buf();
    config.blocklist_poll_seconds = NonZeroU64::new(1).expect("one second is not zero");
    config
}

/// A path no file is at, so the poller has nothing to load and only what was
/// persisted can make the service ready.
fn absent(dir: &TempDir) -> std::path::PathBuf {
    dir.path().join("there-is-no-blocklist.json")
}

/// A committed blocklist survives a process that dies without checkpointing, and it
/// survives *because of the write-ahead log*: the same database file without its log
/// does not carry it.
///
/// **The "kill" here is a dropped runtime, not a process kill.** `run_and_kill`
/// destroys the runtime the server was on, so every task is dropped in-process; no
/// signal is delivered and no shutdown path or checkpoint runs. It does not cover a
/// kill in the middle of a write the kernel has not yet taken, or a partially written
/// log frame. Real-`SIGKILL` coverage was done separately by adversarial testing
/// against spawned processes. The name is the one the approved slice row fixes.
///
/// Not a `#[tokio::test]`, because a test cannot destroy the runtime it is itself on.
#[test]
fn wal_recovery_after_kill() {
    let data_dir = tempfile::tempdir().expect("a data directory");
    let blocklist_dir = tempfile::tempdir().expect("a blocklist directory");
    let blocklist_file = blocklist_dir.path().join("blocklist.json");
    fs::write(&blocklist_file, snapshot(5, GENERATED, EXPIRES, ""))
        .expect("the snapshot is written");

    common::run_and_kill(|| async {
        let server = TestServer::start_in(
            data_dir.path(),
            config_for(&blocklist_file),
            TestClock::at_rfc3339(NOW),
        )
        .await;

        assert_eq!(
            server.status("/health/ready").await,
            200,
            "the snapshot was committed and published during startup"
        );
        // No shutdown, no checkpoint: the runtime is destroyed underneath the server.
    });

    let wal = wal_path(data_dir.path());
    let wal_len = fs::metadata(&wal)
        .expect("the database is in write-ahead-log mode, so it has a log")
        .len();
    assert!(
        wal_len > 0,
        "the commit is still in the write-ahead log, not yet in the database file"
    );

    // The control: the same database file, without its log. If the commit had already
    // reached the database file, this copy would carry it too and the test below would
    // prove nothing about recovery.
    let without_log = tempfile::tempdir().expect("a second data directory");
    fs::create_dir_all(without_log.path().join("state")).expect("a state directory");
    fs::copy(
        database_path(data_dir.path()),
        database_path(without_log.path()),
    )
    .expect("the database file is copied");

    common::run(async {
        let server = TestServer::start_in(
            without_log.path(),
            config_for(&absent(&blocklist_dir)),
            TestClock::at_rfc3339(NOW),
        )
        .await;

        assert_eq!(
            server.status("/health/ready").await,
            503,
            "without the write-ahead log the committed blocklist is not there at all"
        );
        server.shutdown().await;
    });

    // And now the real restart, on the killed instance's own directory, with no
    // blocklist file at all — so readiness can only come from what was recovered.
    common::run(async {
        let clock = TestClock::at_rfc3339(NOW);
        let server = TestServer::start_in(
            data_dir.path(),
            config_for(&absent(&blocklist_dir)),
            clock.shared(),
        )
        .await;

        assert_eq!(
            server.status("/health/ready").await,
            200,
            "the write-ahead log was replayed on open and the committed blocklist is back \
             in force"
        );
        assert_eq!(
            server.status("/npm/left-pad").await,
            404,
            "a policy is in force, so the npm route answers from the decision rather than \
             with POLICY_UNAVAILABLE"
        );

        // The recovered snapshot carries the window it was committed with, not a fresh
        // one: at its own `expires_at` it stops being a policy.
        clock.set_rfc3339(EXPIRES);
        assert_eq!(server.status("/health/ready").await, 503);

        server.shutdown().await;
    });
}

/// SPEC §10: "If database recovery fails, keep readiness false and stop package
/// delivery; never silently recreate the database and lose first-seen times, digest
/// pins, or the blocklist revision."
#[tokio::test]
async fn failed_recovery_keeps_readiness_false_and_never_recreates() {
    let data_dir = tempfile::tempdir().expect("a data directory");
    fs::create_dir_all(data_dir.path().join("state")).expect("a state directory");

    // A file that is not a database. The engine refuses it on open rather than
    // guessing, which is the failure this test is about.
    let database = database_path(data_dir.path());
    let corrupt = vec![0xABu8; 8192];
    fs::write(&database, &corrupt).expect("the unreadable database is written");

    // A blocklist file that is perfectly good, so the only reason nothing is in force
    // is that nothing can be committed.
    let blocklist_dir = tempfile::tempdir().expect("a blocklist directory");
    let blocklist_file = blocklist_dir.path().join("blocklist.json");
    fs::write(&blocklist_file, snapshot(3, GENERATED, EXPIRES, ""))
        .expect("the snapshot is written");

    let server = TestServer::start_in(
        data_dir.path(),
        config_for(&blocklist_file),
        TestClock::at_rfc3339(NOW),
    )
    .await;

    assert_eq!(
        server.status("/health/live").await,
        200,
        "the process is alive: a database that will not recover is reported, not hidden \
         behind a dead process"
    );
    assert_eq!(server.status("/health/ready").await, 503);
    assert_eq!(
        server.status("/npm/left-pad").await,
        503,
        "package delivery stops while storage is unusable"
    );

    // Two more polling intervals of the poller trying and failing, which is where a
    // retry that publishes without committing would show itself.
    tokio::time::sleep(TWO_INTERVALS).await;
    assert_eq!(server.status("/health/ready").await, 503);
    assert_eq!(server.status("/npm/left-pad").await, 503);

    server.shutdown().await;

    assert_eq!(
        fs::read(&database).expect("the database file is still there"),
        corrupt,
        "the database was neither recreated nor truncated: every byte is the one that \
         was there before the process started"
    );
    assert!(
        !wal_path(data_dir.path()).exists(),
        "and no write-ahead log was started beside it"
    );
}

/// A database file that has been emptied while its write-ahead log still holds
/// committed frames is damage, not a first start.
///
/// Opening it would let the engine lay down a fresh database and rewrite the log,
/// destroying a revision that was still salvageable. SPEC §10: "never silently
/// recreate the database and lose first-seen times, digest pins, or the blocklist
/// revision." In slice 3 the loss is one blocklist revision; on the same path in
/// slices 5 and 7 it is first-seen times and permanent digest pins.
#[tokio::test]
async fn an_emptied_database_beside_a_populated_log_is_refused_not_rebuilt() {
    let data_dir = tempfile::tempdir().expect("a data directory");
    let blocklist_dir = tempfile::tempdir().expect("a blocklist directory");
    let blocklist_file = blocklist_dir.path().join("blocklist.json");
    fs::write(&blocklist_file, snapshot(5, GENERATED, EXPIRES, ""))
        .expect("the snapshot is written");

    let server = TestServer::start_in(
        data_dir.path(),
        config_for(&blocklist_file),
        TestClock::at_rfc3339(NOW),
    )
    .await;
    assert_eq!(server.status("/health/ready").await, 200);
    server.shutdown().await;

    let database = database_path(data_dir.path());
    let log = wal_path(data_dir.path());
    assert!(
        fs::metadata(&log).expect("a write-ahead log").len() > 0,
        "the committed revision is in the log, which is what makes the damage below \
         salvageable"
    );

    // The damage: the database file is emptied and the log is left alone. This is
    // what a truncating copy, a partially restored backup, or an interrupted
    // `cp` leaves behind.
    fs::File::create(&database).expect("the database file is emptied");
    assert_eq!(fs::metadata(&database).expect("the database file").len(), 0);

    let restarted = TestServer::start_in(
        data_dir.path(),
        config_for(&blocklist_file),
        TestClock::at_rfc3339(NOW),
    )
    .await;

    assert_eq!(
        restarted.status("/health/live").await,
        200,
        "the process runs and can say what is wrong"
    );
    assert_eq!(restarted.status("/health/ready").await, 503);
    restarted.shutdown().await;

    assert_eq!(
        fs::metadata(&database).expect("the database file").len(),
        0,
        "the emptied database was left exactly as it was found: nothing was written \
         over it, so an operator still has the log to salvage"
    );
}

/// SPEC §10's restore rule: "Restore while stopped, reload a current blocklist
/// before readiness, and treat uncertain metadata freshness as expired."
#[tokio::test]
async fn restore_requires_a_current_blocklist_before_readiness() {
    let data_dir = tempfile::tempdir().expect("a data directory");
    let blocklist_dir = tempfile::tempdir().expect("a blocklist directory");
    let blocklist_file = blocklist_dir.path().join("blocklist.json");

    // A run that persists revision 9, whose window ends on the 18th. The high
    // revision is the point: a restore can put back a state directory whose recorded
    // revision runs ahead of the snapshot the producer currently has on disk.
    fs::write(
        &blocklist_file,
        snapshot(9, GENERATED, "2026-09-18T00:00:00Z", ""),
    )
    .expect("the snapshot is written");
    let server = TestServer::start_in(
        data_dir.path(),
        config_for(&blocklist_file),
        TestClock::at_rfc3339(NOW),
    )
    .await;
    assert_eq!(server.status("/health/ready").await, 200);
    server.shutdown().await;

    // The restore: the state directory is back, but the producer's file is not there
    // yet and the persisted snapshot has since expired.
    fs::remove_file(&blocklist_file).expect("the blocklist file is removed");
    let clock = TestClock::at_rfc3339("2026-09-18T12:00:00Z");
    let server =
        TestServer::start_in(data_dir.path(), config_for(&blocklist_file), clock.shared()).await;

    assert_eq!(
        server.status("/health/live").await,
        200,
        "the restored instance runs"
    );
    assert_eq!(
        server.status("/health/ready").await,
        503,
        "an expired persisted snapshot is not a policy, so the restore is not ready"
    );
    assert_eq!(server.status("/npm/left-pad").await, 503);

    // The producer's current snapshot arrives. Its revision is *lower* than the one
    // the restored directory carries, which is what a restore from an older backup
    // looks like: the expired snapshot is not in force, so it also does not get to
    // veto the current one as a rollback.
    fs::write(
        &blocklist_file,
        snapshot(4, "2026-09-18T00:00:00Z", "2026-09-20T00:00:00Z", ""),
    )
    .expect("the current snapshot is written");

    server
        .wait_for_status("/health/ready", 200, TWO_INTERVALS)
        .await;
    assert_eq!(server.status("/npm/left-pad").await, 404);

    server.shutdown().await;
}

/// SPEC §10: "Hold an exclusive data-directory process lock." Two instances sharing
/// one directory would both believe they own its database and its files.
#[tokio::test]
async fn a_second_instance_cannot_take_the_data_directory_lock() {
    let data_dir = tempfile::tempdir().expect("a data directory");
    let blocklist_dir = tempfile::tempdir().expect("a blocklist directory");

    let server = TestServer::start_in(
        data_dir.path(),
        config_for(&absent(&blocklist_dir)),
        TestClock::at_rfc3339(NOW),
    )
    .await;

    let mut second = config_for(&absent(&blocklist_dir));
    second.data_dir = data_dir.path().to_path_buf();
    let (transport, origins) = common::fake_upstream();
    let outcome = App::start(AppDeps {
        config: second,
        clock: TestClock::at_rfc3339(NOW),
        transport,
        origins,
        osv_client: probation::osv::unreachable_client(),
        osv_base_url: None,
    })
    .await;

    let err = outcome
        .err()
        .expect("a second instance must not start on a data directory that is in use");
    let message = err.to_string();
    assert!(
        message.contains("lock"),
        "the refusal names the lock so an operator can act on it: {message}"
    );

    server.shutdown().await;

    // And once the first instance has released it, the directory is usable again.
    let third = TestServer::start_in(
        data_dir.path(),
        config_for(&absent(&blocklist_dir)),
        TestClock::at_rfc3339(NOW),
    )
    .await;
    assert_eq!(third.status("/health/live").await, 200);
    third.shutdown().await;
}
