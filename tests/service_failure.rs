//! The failure record of a Windows service that dies before its log sink exists (fix round 2), and the stop channel of the service host.
//! Both cores are platform independent; the Windows host that uses them is compiled by `cargo check --target x86_64-pc-windows-gnu`.

use probation::lifecycle::{Control, StopChannel, control_to_stop};
use probation::service_failure::{FailureKind, MAX_BYTES, record};

#[test]
fn each_failure_has_its_own_documented_exit_code() {
    assert_eq!((FailureKind::InvalidConfig.code(), FailureKind::CannotStart.code(), FailureKind::LogUnavailable.code()), (78, 70, 73));
}

#[test]
fn a_failure_is_written_to_a_bounded_file_that_the_next_failure_replaces() {
    let dir = tempfile::tempdir().unwrap();
    record(dir.path(), FailureKind::InvalidConfig, "config.toml: unknown key `x`").unwrap();
    let text = std::fs::read_to_string(dir.path().join("service-failure.txt")).unwrap();
    assert!(text.contains("exit code 78") && text.contains("invalid configuration") && text.contains("unknown key"), "{text}");
    record(dir.path(), FailureKind::CannotStart, &"x".repeat(100_000)).unwrap();
    let text = std::fs::read_to_string(dir.path().join("service-failure.txt")).unwrap();
    assert!(text.len() as u64 <= MAX_BYTES && text.contains("exit code 70") && !text.contains("exit code 78"), "{}", text.len());
}

#[test]
fn a_missing_directory_is_an_error_not_a_panic() {
    assert!(record(std::path::Path::new("/nonexistent-probation-dir"), FailureKind::CannotStart, "m").is_err());
}

#[test]
fn only_stop_preshutdown_and_shutdown_stop_the_service() {
    assert_eq!(control_to_stop(Control::Stop), Some("SCM_STOP"));
    assert_eq!(control_to_stop(Control::Preshutdown), Some("SCM_PRESHUTDOWN"));
    assert_eq!(control_to_stop(Control::Shutdown), Some("SCM_SHUTDOWN"));
    assert_eq!(control_to_stop(Control::Interrogate), None);
    assert_eq!(control_to_stop(Control::Other), None);
}

#[tokio::test]
async fn the_first_stop_reports_stop_pending_once_and_names_the_reason() {
    let (channel, mut stop) = StopChannel::new();
    let pending = std::sync::atomic::AtomicUsize::new(0);
    channel.control(Control::Interrogate); // no stop
    channel.control(Control::Preshutdown);
    channel.control(Control::Stop); // a second request while the first is handled
    let why = stop.next(|| { pending.fetch_add(1, std::sync::atomic::Ordering::SeqCst); }).await;
    assert_eq!(why, "SCM_PRESHUTDOWN");
    assert_eq!(pending.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_closed_control_channel_is_a_stop_not_a_hang() {
    let (channel, mut stop) = StopChannel::new();
    drop(channel);
    assert_eq!(stop.next(|| {}).await, "SCM_CLOSED");
}
