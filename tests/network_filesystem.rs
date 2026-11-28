//! Slice 26 (sec F11, recheck R4): `App::start` refuses a data directory on a network file system, `allow_network_data_dir` accepts it,
//! and a file system that cannot be classified refuses too (fail closed). The mount-table probe is replaced through the `test-support`
//! seam `store::lock::set_filesystem_probe`, because no network mount exists on the test host; the probe is process-wide, so the tests
//! of this binary run one at a time.

mod common;

use std::io;
use std::sync::Arc;

use common::{TestClock, config_with_open_blocklist, fake_upstream};
use probation::store::lock::{LockError, set_filesystem_probe};
use probation::store::startup::StartupError as StoreStartup;
use probation::{App, AppDeps, StartupError};

static ONE_AT_A_TIME: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn start(allow: bool) -> Result<probation::Running, StartupError> {
    let dir = tempfile::tempdir().unwrap();
    let mut config = config_with_open_blocklist(dir.path());
    config.data_dir = dir.path().join("data");
    config.allow_network_data_dir = allow;
    let (transport, origins) = fake_upstream();
    let result = App::start(AppDeps {
        config,
        clock: TestClock::at_rfc3339("2026-04-06T12:00:00Z").shared(),
        transport,
        origins,
        osv_client: probation::osv::unreachable_client(),
        osv_base_url: None,
        osv_server_origin_override: None,
    })
    .await;
    std::mem::forget(dir); // the running server owns the directory until the process ends
    result
}

fn probe_says(fstype: &'static str) {
    set_filesystem_probe(Some(Arc::new(move |_| Ok(Some(fstype.to_owned())))));
}

#[tokio::test]
async fn a_data_directory_on_nfs4_refuses_to_start_and_names_the_type() {
    let _one = ONE_AT_A_TIME.lock().await;
    probe_says("nfs4");
    let err = start(false).await.err().expect("start refuses");
    set_filesystem_probe(None);
    assert!(
        matches!(&err, StartupError::DataDir(StoreStartup::Lock(LockError::NetworkFilesystem { fstype, .. })) if fstype == "nfs4"),
        "{err:?}"
    );
    let text = err.to_string();
    assert!(
        text.contains("nfs4") && text.contains("allow_network_data_dir"),
        "the error names the type and the switch: {text}"
    );
}

#[tokio::test]
async fn allow_network_data_dir_starts_on_the_same_file_system() {
    let _one = ONE_AT_A_TIME.lock().await;
    probe_says("nfs4");
    let started = start(true).await;
    set_filesystem_probe(None);
    assert!(
        started.is_ok(),
        "the switch accepts the risk: {:?}",
        started.err()
    );
}

#[tokio::test]
async fn a_local_file_system_starts_without_the_switch() {
    let _one = ONE_AT_A_TIME.lock().await;
    probe_says("ext4");
    let started = start(false).await;
    set_filesystem_probe(None);
    assert!(started.is_ok(), "{:?}", started.err());
}

#[tokio::test]
async fn a_file_system_that_cannot_be_classified_refuses_to_start() {
    let _one = ONE_AT_A_TIME.lock().await;
    set_filesystem_probe(Some(Arc::new(|_| {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "no mount table",
        ))
    })));
    let err = start(false)
        .await
        .err()
        .expect("start refuses when it cannot tell");
    let allowed = start(true).await;
    set_filesystem_probe(None);
    assert!(
        matches!(
            &err,
            StartupError::DataDir(StoreStartup::Lock(LockError::Unclassifiable { .. }))
        ),
        "{err:?}"
    );
    assert!(err.to_string().contains("cannot tell"), "{err}");
    assert!(allowed.is_ok(), "the switch still accepts it");
}
