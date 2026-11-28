//! The CLI. Builds the production `AppDeps`, installs the log subscriber, and maps
//! failures to exit codes. No policy or protocol logic lives here.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use probation::AppDeps;
use probation::clock::{Clock, SystemClock};
use probation::config::Config;
use probation::lifecycle::{StopOutcome, exit_plan};
use probation::policy::blocklist;
use probation::upstream::{OriginSet, ReqwestTransport};
#[cfg(unix)]
use tokio::signal::unix::{Signal, SignalKind, signal};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "probation",
    version,
    about = "A filtering proxy for npm and PyPI that withholds packages until they are eligible."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve filtered npm and PyPI metadata and verified artifacts.
    Serve {
        /// Path to the TOML configuration file.
        #[arg(long, value_name = "PATH")]
        config: PathBuf,
    },
    /// Validate a configuration file. Exits non-zero on the first problem, naming
    /// it, and changes nothing.
    CheckConfig {
        /// Path to the TOML configuration file.
        #[arg(value_name = "PATH", required_unless_present = "config")]
        path: Option<PathBuf>,
        /// The same path in the `--config` form SPEC §4 spells the command with.
        #[arg(long, value_name = "PATH", conflicts_with = "path")]
        config: Option<PathBuf>,
    },
    /// Validate a blocklist snapshot. Exits non-zero on the first problem, naming
    /// it, and changes nothing.
    CheckBlocklist {
        /// Path to the JSON blocklist snapshot.
        #[arg(value_name = "PATH")]
        path: PathBuf,
    },
    /// Operator command (LS-F8): clear only the persisted shared-service policy
    /// revision floor, after a server restore, rollback or failover. Never clears a
    /// refusal. Runs with the enforcer stopped or running.
    ResetRevisionFloor {
        /// Path to the TOML configuration file.
        #[arg(long, value_name = "PATH")]
        config: PathBuf,
    },
    /// Windows only: `serve` under the service control manager (the installer registers this
    /// command; running it from a console fails). Stop, shutdown and pre-shutdown reach the same
    /// graceful path as a signal.
    #[cfg(windows)]
    Service {
        /// Path to the TOML configuration file.
        #[arg(long, value_name = "PATH")]
        config: PathBuf,
        /// Directory for the operational log (`probation.log`, 50 MiB, three backups); the installer passes its log directory.
        #[arg(long, value_name = "DIR")]
        log_dir: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    let filter = || {
        EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("info"))
            .add_directive(
                "probation::http::logging=info"
                    .parse()
                    .expect("static directive"),
            )
    };
    // Under the Windows service control manager stdout goes nowhere: the events go to a bounded, self-rotating file in the
    // installer's access-controlled log directory (src/service_log.rs). If it cannot be opened they fall back to stdout.
    #[cfg(windows)]
    let sink = match &cli.command {
        Command::Service {
            log_dir: Some(dir), ..
        } => probation::service_log::RotatingFile::open(&dir.join("probation.log"), 50 << 20, 3)
            .ok()
            .map(probation::service_log::SharedLog::new),
        _ => None,
    };
    #[cfg(not(windows))]
    let sink: Option<probation::service_log::SharedLog> = None;
    match sink {
        Some(sink) => tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter())
            .with_writer(move || sink.clone())
            .init(),
        None => tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter())
            .init(),
    }

    match cli.command {
        Command::Serve { config } => match ShutdownSignals::install() {
            Ok(mut signals) => {
                finish(serve(&config, async move { signals.received().await }, || {}).await)
            }
            Err(err) => {
                tracing::error!(error = %err, "cannot listen for the shutdown signal");
                ExitCode::FAILURE
            }
        },
        #[cfg(windows)]
        Command::Service { config, log_dir } => windows_service_host::run(config, log_dir).await,
        Command::CheckConfig { path, config } => {
            // clap guarantees exactly one of the two forms is present.
            match path.or(config) {
                Some(path) => check_config(&path).await,
                None => ExitCode::FAILURE,
            }
        }
        Command::CheckBlocklist { path } => check_blocklist(&path),
        Command::ResetRevisionFloor { config } => reset_revision_floor(&config),
    }
}

fn reset_revision_floor(path: &Path) -> ExitCode {
    let result = Config::load(path)
        .map_err(|err| err.to_string())
        .and_then(|config| {
            let policy = config
                .service_policy
                .as_ref()
                .ok_or("no [service_policy] section: nothing to reset")?;
            probation::managed::service_policy::ServicePolicy::reset_revision_floor(
                policy,
                &config.data_dir,
            )
            .map_err(|_| "cannot write the data directory".to_owned())
        });
    match result {
        Ok(()) => {
            println!("revision floor reset; the next valid snapshot sets the new floor");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("{}: {err}", path.display());
            ExitCode::FAILURE
        }
    }
}

/// SPEC §4: the validation commands exit non-zero on failure and do not modify
/// state. They read one file and print one line; nothing here writes anywhere.
async fn check_config(path: &Path) -> ExitCode {
    let checked = match Config::load(path) {
        Ok(config) => probation::check_delivery(&config)
            .await
            .map(|()| config)
            .map_err(|err| err.to_string()),
        Err(err) => Err(err.to_string()),
    };
    match checked {
        Ok(config) => {
            println!(
                "{}: valid configuration (listen {}, cooldown {}s)",
                path.display(),
                config.listen,
                config.cooldown_seconds
            );
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("{}: {err}", path.display());
            ExitCode::FAILURE
        }
    }
}

fn check_blocklist(path: &Path) -> ExitCode {
    // The command is handed a path and no configuration, so it validates against the
    // documented size limit rather than an operator's own `max_blocklist_bytes`.
    let now = SystemClock.now_utc_micros();
    match blocklist::load_file(path, blocklist::DEFAULT_MAX_BLOCKLIST_BYTES, now) {
        Ok(snapshot) => {
            println!(
                "{}: valid blocklist (revision {}, {} entries, expires {})",
                path.display(),
                snapshot.revision,
                snapshot.entry_count(),
                jiff::Timestamp::from_microsecond(snapshot.expires_at_micros)
                    .map(|timestamp| timestamp.to_string())
                    .unwrap_or_else(|_| snapshot.expires_at_micros.to_string()),
            );
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("{}: {err}", path.display());
            ExitCode::FAILURE
        }
    }
}

/// The process exit for how `serve` ended (`probation::lifecycle` holds the rule every supervisor shares).
fn finish(outcome: StopOutcome) -> ExitCode {
    ExitCode::from(exit_plan(outcome).code)
}

/// Runs the firewall until `stop` resolves (a signal, a console control event or the service manager's stop) or a settings
/// push asks for a restart. `ready` runs once the listener is up, for a supervisor that wants to be told.
async fn serve(
    config_path: &Path,
    stop: impl std::future::Future<Output = &'static str>,
    ready: impl FnOnce(),
) -> StopOutcome {
    // The stop source is installed by the caller before anything else, so a stop requested while startup is still
    // running is caught and acted on once it finishes rather than killing the process.
    tokio::pin!(stop);

    let config = match Config::load(config_path) {
        Ok(config) => config,
        Err(err) => {
            tracing::error!(path = %config_path.display(), error = %err, "invalid configuration");
            return StopOutcome::Failed;
        }
    };

    // The settings overlay is merged in, and rolled back if the start fails on it (C105,
    // C71). The origins follow whatever configuration finally starts.
    let running = match probation::start_with_settings(config, |config| {
        let origins = OriginSet::configured(&config);
        // LS-F9: snapshot-sourced registries are dialled under the denylist.
        let transport = ReqwestTransport::for_origins(origins.clone());
        let transport = if config.service_policy.is_some() {
            transport.with_denylist(Arc::new(probation::http::service_connector::Denylist::new(
                Some(config.listen),
                config.control_plane_cidrs.clone(),
            )))
        } else {
            transport
        };
        AppDeps {
            config,
            clock: Arc::new(SystemClock),
            transport: Arc::new(transport),
            origins,
            osv_client: reqwest::Client::new(),
            osv_base_url: None,
            osv_server_origin_override: None,
        }
    })
    .await
    {
        Ok(running) => running,
        Err(err) => {
            tracing::error!(error = %err, "cannot start");
            return StopOutcome::Failed;
        }
    };

    tracing::info!(addr = %running.local_addr, "listening");
    ready();

    // A managed firewall that wrote a settings push drains and exits 75, for its
    // supervisor to start it again on the new settings (C105).
    let outcome = tokio::select! {
        signal = &mut stop => {
            tracing::info!(signal, "shutting down");
            StopOutcome::Stopped
        }
        () = running.restart_requested() => {
            tracing::info!("restarting to apply pushed settings");
            StopOutcome::SettingsRestart
        }
    };

    match running.shutdown().await {
        Ok(()) => outcome,
        Err(err) => {
            tracing::error!(error = %err, "unclean shutdown");
            probation::lifecycle::after_shutdown(outcome, false)
        }
    }
}

/// `SIGTERM` is what a service manager sends — systemd's `stop` and a container
/// runtime's `stop` both do — so it must reach the same graceful path as `SIGINT`.
/// Its default disposition kills the process outright, which would leave every
/// queued decision record undelivered and skip the shutdown summary.
#[cfg(unix)]
struct ShutdownSignals {
    interrupt: Signal,
    terminate: Signal,
}

#[cfg(unix)]
impl ShutdownSignals {
    fn install() -> std::io::Result<ShutdownSignals> {
        Ok(ShutdownSignals {
            interrupt: signal(SignalKind::interrupt())?,
            terminate: signal(SignalKind::terminate())?,
        })
    }

    /// Resolves when the service is asked to stop, naming the signal that asked.
    async fn received(&mut self) -> &'static str {
        tokio::select! {
            _ = self.interrupt.recv() => "SIGINT",
            _ = self.terminate.recv() => "SIGTERM",
        }
    }
}

/// Windows has no SIGTERM: Ctrl+C, Ctrl+Break, console close and logoff/shutdown are the
/// console control events, and each takes the same graceful path.
#[cfg(windows)]
struct ShutdownSignals {
    c: tokio::signal::windows::CtrlC,
    brk: tokio::signal::windows::CtrlBreak,
    close: tokio::signal::windows::CtrlClose,
    shutdown: tokio::signal::windows::CtrlShutdown,
}

#[cfg(windows)]
impl ShutdownSignals {
    fn install() -> std::io::Result<ShutdownSignals> {
        use tokio::signal::windows;
        Ok(ShutdownSignals {
            c: windows::ctrl_c()?,
            brk: windows::ctrl_break()?,
            close: windows::ctrl_close()?,
            shutdown: windows::ctrl_shutdown()?,
        })
    }

    async fn received(&mut self) -> &'static str {
        tokio::select! {
            _ = self.c.recv() => "CTRL_C",
            _ = self.brk.recv() => "CTRL_BREAK",
            _ = self.close.recv() => "CTRL_CLOSE",
            _ = self.shutdown.recv() => "CTRL_SHUTDOWN",
        }
    }
}

/// The Windows service host: the service control manager starts `probation service --config PATH`, this reports its state
/// and turns Stop, Pre-shutdown and Shutdown into the same graceful path as a signal. Facts used (research-native-supervision.md,
/// Microsoft docs): the control handler only signals and returns; `Running` is reported after the listener is up; a stop reports
/// `StopPending` with the 45 s allowance; a settings restart (exit 75) or a failure ends the process WITHOUT reporting `Stopped`,
/// which the manager counts as a failure and answers with the restart action the installer configured (5 s delay).
#[cfg(windows)]
mod windows_service_host {
    use std::ffi::OsString;
    use std::path::PathBuf;
    use std::process::ExitCode;
    use std::sync::OnceLock;
    use std::time::Duration;

    use probation::lifecycle::{Control, StopChannel, StopOutcome, exit_plan};
    use probation::service_failure::FailureKind;
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{
        self, ServiceControlHandlerResult, ServiceStatusHandle,
    };
    use windows_service::{define_windows_service, service_dispatcher};

    const NAME: &str = "Probation";
    /// The stop allowance the installer also configures as the pre-shutdown timeout.
    const STOP_WAIT: Duration = Duration::from_secs(45);

    static HOST: OnceLock<(tokio::runtime::Handle, PathBuf, Option<PathBuf>)> = OnceLock::new();

    define_windows_service!(ffi_service_main, service_main);

    /// Hands a blocking thread to the dispatcher, which returns when the service has stopped.
    pub async fn run(config: PathBuf, log_dir: Option<PathBuf>) -> ExitCode {
        let _ = HOST.set((tokio::runtime::Handle::current(), config, log_dir));
        match tokio::task::spawn_blocking(|| service_dispatcher::start(NAME, ffi_service_main))
            .await
        {
            Ok(Ok(())) => ExitCode::SUCCESS,
            Ok(Err(err)) => {
                tracing::error!(error = %err, "not started by the service control manager");
                ExitCode::FAILURE
            }
            Err(_) => ExitCode::FAILURE,
        }
    }

    fn service_main(_arguments: Vec<OsString>) {
        let (runtime, config, log_dir) = HOST
            .get()
            .expect("set before the dispatcher starts")
            .clone();
        let (channel, mut waiter) = StopChannel::new();
        let handler = move |control| {
            let kind = match control {
                ServiceControl::Stop => Control::Stop,
                ServiceControl::Preshutdown => Control::Preshutdown,
                ServiceControl::Shutdown => Control::Shutdown,
                ServiceControl::Interrogate => Control::Interrogate,
                _ => Control::Other,
            };
            channel.control(kind);
            match kind {
                Control::Other => ServiceControlHandlerResult::NotImplemented,
                _ => ServiceControlHandlerResult::NoError,
            }
        };
        let status = match service_control_handler::register(NAME, handler) {
            Ok(status) => status,
            Err(err) => fail(
                log_dir.as_deref(),
                FailureKind::CannotStart,
                &format!("cannot register the service control handler: {err}"),
            ),
        };
        report(
            status,
            ServiceState::StartPending,
            ServiceControlAccept::empty(),
            1,
            STOP_WAIT,
        );
        // A configuration the service cannot load ends it here, with a documented exit code and a file in the log directory,
        // before any log sink could have said why.
        if let Err(err) = probation::config::Config::load(&config) {
            fail(
                log_dir.as_deref(),
                FailureKind::InvalidConfig,
                &format!("{}: {err}", config.display()),
            );
        }
        let stopping = async move {
            waiter
                .next(|| {
                    report(
                        status,
                        ServiceState::StopPending,
                        ServiceControlAccept::empty(),
                        1,
                        STOP_WAIT,
                    )
                })
                .await
        };
        let ready = move || {
            let accepted = ServiceControlAccept::STOP | ServiceControlAccept::PRESHUTDOWN;
            report(
                status,
                ServiceState::Running,
                accepted,
                0,
                Duration::default(),
            );
        };
        let outcome = runtime.block_on(super::serve(&config, stopping, ready));
        let plan = exit_plan(outcome);
        if plan.report_stopped {
            report(
                status,
                ServiceState::Stopped,
                ServiceControlAccept::empty(),
                0,
                Duration::default(),
            );
        } else {
            // Ending without `Stopped` is how the manager is told this was a failure and the restart action runs.
            if outcome == StopOutcome::Failed {
                fail(
                    log_dir.as_deref(),
                    FailureKind::CannotStart,
                    "the service stopped on a failure; see probation.log",
                );
            }
            std::process::exit(i32::from(plan.code));
        }
    }

    /// Leaves the failure file, if the log directory can take it, and ends the process with the failure's own exit code.
    fn fail(log_dir: Option<&std::path::Path>, kind: FailureKind, message: &str) -> ! {
        if let Some(dir) = log_dir {
            let _ = probation::service_failure::record(dir, kind, message);
        }
        std::process::exit(i32::from(kind.code()))
    }

    fn report(
        status: ServiceStatusHandle,
        state: ServiceState,
        accepted: ServiceControlAccept,
        checkpoint: u32,
        wait_hint: Duration,
    ) {
        let result = status.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accepted,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint,
            wait_hint,
            process_id: None,
        });
        if let Err(err) = result {
            tracing::error!(error = %err, "cannot report the service state");
        }
    }
}
