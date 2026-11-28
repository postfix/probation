//! What a stop means to each supervisor (row 25). The Windows service control manager treats a process
//! that reports `Stopped` as finished and one that ends WITHOUT reporting it as failed, and only a failure
//! runs the configured restart action; systemd and launchd decide from the exit code alone. The settings
//! restart (exit 75) must therefore never be reported as `Stopped` on Windows, and an explicit stop must.

use probation::lifecycle::{ExitPlan, RESTART_FOR_SETTINGS, StopOutcome, exit_plan};

#[test]
fn an_explicit_stop_exits_zero_and_is_reported_stopped() {
    assert_eq!(
        exit_plan(StopOutcome::Stopped),
        ExitPlan {
            code: 0,
            report_stopped: true
        }
    );
}

#[test]
fn a_settings_restart_exits_75_without_reporting_stopped() {
    assert_eq!(
        RESTART_FOR_SETTINGS, 75,
        "EX_TEMPFAIL, the code docs/operations.md and deploy/probation.service name"
    );
    assert_eq!(
        exit_plan(StopOutcome::SettingsRestart),
        ExitPlan {
            code: 75,
            report_stopped: false
        }
    );
}

#[test]
fn a_failure_exits_one_without_reporting_stopped() {
    assert_eq!(
        exit_plan(StopOutcome::Failed),
        ExitPlan {
            code: 1,
            report_stopped: false
        }
    );
}

/// An unclean shutdown after an operator's stop is still a stop: the exit code says it was not clean, but the service is reported
/// `Stopped` so the service control manager runs no restart action on a service the operator just stopped. An unclean end of a
/// settings restart or a startup failure stays a failure.
#[test]
fn an_unclean_shutdown_after_an_operator_stop_is_still_reported_stopped() {
    assert_eq!(
        exit_plan(StopOutcome::StoppedUnclean),
        ExitPlan {
            code: 1,
            report_stopped: true
        }
    );
    assert_eq!(
        probation::lifecycle::after_shutdown(StopOutcome::Stopped, false),
        StopOutcome::StoppedUnclean
    );
    assert_eq!(
        probation::lifecycle::after_shutdown(StopOutcome::Stopped, true),
        StopOutcome::Stopped
    );
    assert_eq!(
        probation::lifecycle::after_shutdown(StopOutcome::SettingsRestart, false),
        StopOutcome::Failed
    );
    assert_eq!(
        probation::lifecycle::after_shutdown(StopOutcome::SettingsRestart, true),
        StopOutcome::SettingsRestart
    );
}
