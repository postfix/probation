//! The CLI. Builds the production `AppDeps`, installs the log subscriber, and maps
//! failures to exit codes. No policy or protocol logic lives here.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use probation::clock::{Clock, SystemClock};
use probation::config::Config;
use probation::policy::blocklist;
use probation::upstream::{OriginSet, ReqwestTransport};
use probation::{App, AppDeps};
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
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info"))
                .add_directive(
                    "probation::http::logging=info"
                        .parse()
                        .expect("static directive"),
                ),
        )
        .init();

    match cli.command {
        Command::Serve { config } => serve(&config).await,
        Command::CheckConfig { path, config } => {
            // clap guarantees exactly one of the two forms is present.
            match path.or(config) {
                Some(path) => check_config(&path),
                None => ExitCode::FAILURE,
            }
        }
        Command::CheckBlocklist { path } => check_blocklist(&path),
    }
}

/// SPEC §4: the validation commands exit non-zero on failure and do not modify
/// state. They read one file and print one line; nothing here writes anywhere.
fn check_config(path: &Path) -> ExitCode {
    match Config::load(path) {
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

async fn serve(config_path: &Path) -> ExitCode {
    let config = match Config::load(config_path) {
        Ok(config) => config,
        Err(err) => {
            tracing::error!(path = %config_path.display(), error = %err, "invalid configuration");
            return ExitCode::FAILURE;
        }
    };

    let running = match App::start(AppDeps {
        config,
        clock: Arc::new(SystemClock),
        transport: Arc::new(ReqwestTransport::production()),
        origins: OriginSet::production(),
        osv_client: reqwest::Client::new(),
        osv_base_url: None,
    })
    .await
    {
        Ok(running) => running,
        Err(err) => {
            tracing::error!(error = %err, "cannot start");
            return ExitCode::FAILURE;
        }
    };

    tracing::info!(addr = %running.local_addr, "listening");

    match wait_for_shutdown_signal().await {
        Ok(signal) => tracing::info!(signal, "shutting down"),
        Err(err) => {
            tracing::error!(error = %err, "cannot listen for the shutdown signal");
            return ExitCode::FAILURE;
        }
    }

    match running.shutdown().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            tracing::error!(error = %err, "unclean shutdown");
            ExitCode::FAILURE
        }
    }
}

/// Resolves when the service is asked to stop, naming the signal that asked.
///
/// `SIGTERM` is what a service manager sends — systemd's `stop` and a container
/// runtime's `stop` both do — so it must reach the same graceful path as `SIGINT`.
/// Its default disposition kills the process outright, which would leave every
/// queued decision record undelivered and skip the shutdown summary.
async fn wait_for_shutdown_signal() -> std::io::Result<&'static str> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result.map(|()| "SIGINT"),
        _ = terminate.recv() => Ok("SIGTERM"),
    }
}
