//! What a stop means to the supervisor that started the process (row 25).
//!
//! systemd and launchd decide from the exit code alone. The Windows service control manager decides from
//! whether the service reported `Stopped`: a process that reports it is finished, one that ends without
//! reporting it has failed, and only a failure runs the configured restart action. So the settings
//! restart must end the process without reporting `Stopped`, and an explicit stop must report it, or the
//! manager would restart a service an operator just stopped. Platform-independent so every OS's rule is
//! tested on any host; `main.rs` applies it.

/// The exit code that asks the supervisor for a restart after a settings push: EX_TEMPFAIL (C105).
pub const RESTART_FOR_SETTINGS: u8 = 75;

/// Why `serve` is ending.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopOutcome {
    /// An operator or the machine asked for a stop (signal, console control event or SCM stop).
    Stopped,
    /// A settings push was written; the supervisor starts the process again on it.
    SettingsRestart,
    /// An operator's stop whose shutdown was not clean: exit code 1, but still reported `Stopped`, so no restart action runs.
    StoppedUnclean,
    /// Startup or shutdown failed.
    Failed,
}

/// The process exit code and whether a Windows service reports `Stopped` before it ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExitPlan {
    pub code: u8,
    pub report_stopped: bool,
}

pub fn exit_plan(outcome: StopOutcome) -> ExitPlan {
    match outcome {
        StopOutcome::Stopped => ExitPlan {
            code: 0,
            report_stopped: true,
        },
        StopOutcome::SettingsRestart => ExitPlan {
            code: RESTART_FOR_SETTINGS,
            report_stopped: false,
        },
        StopOutcome::StoppedUnclean => ExitPlan {
            code: 1,
            report_stopped: true,
        },
        StopOutcome::Failed => ExitPlan {
            code: 1,
            report_stopped: false,
        },
    }
}

/// What a run that has finished `shutdown` becomes: an operator stop stays a stop even when the shutdown was unclean.
pub fn after_shutdown(outcome: StopOutcome, clean: bool) -> StopOutcome {
    match (outcome, clean) {
        (outcome, true) => outcome,
        (StopOutcome::Stopped, false) => StopOutcome::StoppedUnclean,
        (_, false) => StopOutcome::Failed,
    }
}

/// The control requests a service manager sends, as far as the stop decision cares.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Control {
    Stop,
    Preshutdown,
    Shutdown,
    Interrogate,
    Other,
}

/// The reason a control request stops the service, or `None` when it does not (interrogate and everything unsupported).
pub fn control_to_stop(control: Control) -> Option<&'static str> {
    match control {
        Control::Stop => Some("SCM_STOP"),
        Control::Preshutdown => Some("SCM_PRESHUTDOWN"),
        Control::Shutdown => Some("SCM_SHUTDOWN"),
        Control::Interrogate | Control::Other => None,
    }
}

/// The control handler's side of the stop channel: it only signals and returns, as the service manager requires.
#[derive(Clone)]
pub struct StopChannel(tokio::sync::mpsc::UnboundedSender<&'static str>);

/// The serving side: resolves with the first stop reason.
pub struct StopWaiter(tokio::sync::mpsc::UnboundedReceiver<&'static str>);

impl StopChannel {
    pub fn new() -> (StopChannel, StopWaiter) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        (StopChannel(tx), StopWaiter(rx))
    }

    /// Handles one control request; true when it is a stop.
    pub fn control(&self, control: Control) -> bool {
        match control_to_stop(control) {
            Some(why) => {
                let _ = self.0.send(why);
                true
            }
            None => false,
        }
    }
}

impl StopWaiter {
    /// Waits for the first stop and calls `pending` exactly once (the host reports `StopPending` there). A channel that closed
    /// without a request is a stop, not a hang.
    pub async fn next(&mut self, pending: impl FnOnce()) -> &'static str {
        let why = self.0.recv().await.unwrap_or("SCM_CLOSED");
        pending();
        why
    }
}
