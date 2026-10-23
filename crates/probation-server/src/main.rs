//! `probation-server`: config, Postgres pool, `serve`, `migrate` and `admin`.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use ipnet::IpNet;
use probation_policy::api::KeyId;
use probation_server::accounts::{GuardedClient, Mailer, SmtpMailer};
use probation_server::admin::{self, Bootstrap, BootstrapError};
use probation_server::keys::RevokeError;
use probation_server::portal::PortalDeps;

/// The app role's connection (a login role in `probation_app`).
const DATABASE_URL: &str = "PROBATION_SERVER_DATABASE_URL";
/// The migration owner role's connection, used only by `migrate` (T17).
const MIGRATE_DATABASE_URL: &str = "PROBATION_SERVER_MIGRATE_DATABASE_URL";
/// Seals secrets at rest (T16).
const SECRET_KEY: &str = "PROBATION_SERVER_SECRET_KEY";

#[derive(Parser)]
#[command(version, about = "The probation management server")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve the firewall sync API, and the portal when `[portal]` is set.
    Serve {
        #[arg(long)]
        config: PathBuf,
    },
    /// Apply the database migrations as the owner role.
    Migrate,
    #[command(subcommand)]
    Admin(AdminCommand),
}

#[derive(Subcommand)]
enum AdminCommand {
    /// Create the first global admin, an organisation, a key and a firewall token.
    Bootstrap {
        #[arg(long)]
        org: String,
        #[arg(long)]
        firewall: String,
        /// An address range the firewall's token is accepted from; repeatable.
        #[arg(long = "firewall-source", required = true)]
        firewall_sources: Vec<IpNet>,
    },
    /// Revoke an API key by its id.
    RevokeKey {
        #[arg(long)]
        key_id: u64,
    },
    /// After restoring the database from a backup, before starting the server: every
    /// firewall resets its cache at its next sync (docs/operations.md).
    AfterRestore,
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    match run(Cli::parse().command).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("probation-server: {message}");
            ExitCode::FAILURE
        }
    }
}

async fn run(command: Command) -> Result<(), String> {
    match command {
        Command::Serve { config } => {
            let config = probation_server::Config::load(&config)?;
            let pool = pool(DATABASE_URL).await?;
            let portal = portal_deps(&config, &pool)?;
            probation_server::serve(config, pool, portal)
                .await
                .map_err(|err| format!("serve: {err}"))
        }
        Command::Migrate => {
            // No statement timeout: a migration may run longer than a request.
            let url = std::env::var(MIGRATE_DATABASE_URL)
                .map_err(|_| format!("{MIGRATE_DATABASE_URL} is not set"))?;
            let owner = sqlx::PgPool::connect(&url)
                .await
                .map_err(|err| format!("cannot connect with {MIGRATE_DATABASE_URL}: {err}"))?;
            probation_server::migrate(&owner)
                .await
                .map_err(|err| format!("migrate: {err}"))
        }
        Command::Admin(AdminCommand::Bootstrap {
            org,
            firewall,
            firewall_sources,
        }) => {
            let pool = pool(DATABASE_URL).await?;
            let input = Bootstrap {
                org_name: org,
                firewall_name: firewall,
                firewall_sources,
            };
            match admin::bootstrap(&pool, input).await {
                Ok(done) => {
                    // Shown once: only their hashes are stored.
                    println!("global_admin_login={}", done.login_id);
                    println!("org={}", done.org.0);
                    println!("key_id={}", done.key_id.0);
                    println!("key={}", done.key);
                    println!("firewall_id={}", done.firewall_id);
                    println!("firewall_token={}", done.firewall_token);
                    Ok(())
                }
                Err(BootstrapError::AlreadyDone) => Err(
                    "bootstrap refused: a global admin exists already; nothing changed".to_owned(),
                ),
                Err(BootstrapError::Store(err)) => Err(format!("bootstrap: {err}")),
            }
        }
        Command::Admin(AdminCommand::RevokeKey { key_id }) => {
            let pool = pool(DATABASE_URL).await?;
            match admin::revoke_key(&pool, KeyId(key_id)).await {
                Ok(()) => {
                    println!("revoked key {key_id}");
                    Ok(())
                }
                Err(RevokeError::NotFound) => Err(format!("no live API key {key_id}")),
                Err(RevokeError::Denied) => Err("revoke refused".to_owned()),
                Err(RevokeError::Store(err)) => Err(format!("revoke-key: {err}")),
            }
        }
        Command::Admin(AdminCommand::AfterRestore) => {
            let pool = pool(DATABASE_URL).await?;
            let raised = probation_server::sync::after_restore(&pool)
                .await
                .map_err(|err| format!("after-restore: {err}"))?;
            println!(
                "change_counter raised from value {} (pruned_through {}) to {}; every firewall resets at its next sync",
                raised.before.0, raised.before.1, raised.after
            );
            Ok(())
        }
    }
}

/// The portal's secrets come from the environment, never from the settings file
/// (02 § External); each one a configured part needs must be set.
fn portal_deps(
    config: &probation_server::Config,
    pool: &sqlx::PgPool,
) -> Result<Option<PortalDeps>, String> {
    let Some(mut portal) = config.portal.clone() else {
        return Ok(None);
    };
    let required = |name: &str| std::env::var(name).map_err(|_| format!("{name} is not set"));
    for (variable, provider) in [
        ("PROBATION_SERVER_GOOGLE_CLIENT_SECRET", &mut portal.google),
        ("PROBATION_SERVER_GITHUB_CLIENT_SECRET", &mut portal.github),
        (
            "PROBATION_SERVER_MICROSOFT_CLIENT_SECRET",
            &mut portal.microsoft,
        ),
    ] {
        if let Some(provider) = provider {
            provider.client_secret = required(variable)?;
        }
    }
    let secret_key: [u8; 32] = hex::decode(required(SECRET_KEY)?.trim())
        .ok()
        .and_then(|key| key.try_into().ok())
        .ok_or_else(|| format!("{SECRET_KEY} must be 64 hex characters (32 bytes)"))?;
    let mailer = match &portal.smtp {
        Some(smtp) => {
            let password = std::env::var("PROBATION_SERVER_SMTP_PASSWORD").unwrap_or_default();
            let mailer = SmtpMailer::new(
                &smtp.host,
                smtp.port,
                smtp.username.as_deref(),
                &password,
                &smtp.from,
            )?;
            Some(Arc::new(mailer) as Arc<dyn Mailer>)
        }
        None => None,
    };
    Ok(Some(PortalDeps {
        pool: pool.clone(),
        config: portal,
        outbound: Arc::new(GuardedClient::new()),
        mailer,
        secret_key,
        password_params: argon2::Params::default(),
        trusted_proxies: config.server.trusted_proxies.clone(),
    }))
}

async fn pool(variable: &str) -> Result<sqlx::PgPool, String> {
    let url = std::env::var(variable).map_err(|_| format!("{variable} is not set"))?;
    probation_server::connect(&url)
        .await
        .map_err(|err| format!("cannot connect with {variable}: {err}"))
}
