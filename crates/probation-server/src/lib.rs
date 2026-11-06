//! The probation management server: the firewall sync API, keys, layer policies,
//! tenancy and audit on Postgres (02-architecture.md § Fit, C97). A library, so its
//! tests call internal functions; `main.rs` is a thin binary over it.

pub mod accounts;
pub mod audit;
pub mod fleet;
pub mod keys;
pub mod policy;
pub mod portal;
pub mod sync;
pub mod service_policy;
pub mod tenancy;

use std::net::SocketAddr;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use ipnet::IpNet;
use serde::Deserialize;
use sqlx::PgPool;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

/// The server's own settings file. Secrets come from the environment (02 § External).
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub server: ServerConfig,
    /// The self-service portal; without it the server answers only the sync API.
    #[serde(default)]
    pub portal: Option<portal::PortalConfig>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    /// Load balancers whose `X-Forwarded-For` names the firewall's address (T31).
    #[serde(default)]
    pub trusted_proxies: Vec<IpNet>,
    /// How long `change_log` rows are kept; above a firewall snapshot's expected age.
    #[serde(default = "default_change_log_retention_days")]
    pub change_log_retention_days: u32,
}

fn default_change_log_retention_days() -> u32 {
    7
}

impl Config {
    pub fn load(path: &Path) -> Result<Config, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|err| format!("{}: cannot be read: {err}", path.display()))?;
        let config: Config =
            toml::from_str(&text).map_err(|err| format!("{}: {err}", path.display()))?;
        if config.server.change_log_retention_days == 0 {
            return Err("server.change_log_retention_days must not be zero".to_owned());
        }
        // The address people paste into `.npmrc` and `pip.conf`, with their key next to
        // it: it needs a host, and https unless that host is this machine (C34).
        if let Some(url) = config.portal.as_ref().and_then(|p| p.firewall_url.as_ref()) {
            let loopback = match url.host() {
                Some(url::Host::Ipv4(addr)) => addr.is_loopback(),
                Some(url::Host::Ipv6(addr)) => addr.is_loopback(),
                Some(url::Host::Domain(name)) => name == "localhost",
                None => {
                    return Err("portal.firewall_url must have a host".to_owned());
                }
            };
            if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
                return Err(
                    "portal.firewall_url must use https (http only to this machine)".to_owned(),
                );
            }
        }
        Ok(config)
    }
}

/// The app role's pool. Acquire and statement timeouts of 1 s stay below the firewall's
/// request timeout, so a stuck database answers 5xx before the firewall gives up
/// (03 § Program behavior step 5).
pub async fn connect(database_url: &str) -> Result<PgPool, sqlx::Error> {
    let options = PgConnectOptions::from_str(database_url)?.options([("statement_timeout", "1s")]);
    PgPoolOptions::new()
        .acquire_timeout(Duration::from_secs(1))
        .connect_with(options)
        .await
}

/// Applies `migrations/`, connected as the owner role.
pub async fn migrate(owner: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!("./migrations").run(owner).await
}

/// Serves the sync and automation APIs, and the portal when `portal` is given, on
/// `config.server.listen` until SIGTERM or SIGINT; prunes `change_log`, activity and the
/// audit log by their retention once an hour (C26). On the signal it stops taking
/// connections and lets requests in flight and job runs in progress finish, for
/// `DRAIN` at most or until a second signal, and returns.
pub async fn serve(
    config: Config,
    pool: PgPool,
    portal: Option<portal::PortalDeps>,
) -> std::io::Result<()> {
    if let Some(deps) = &portal {
        let secrets = accounts::SecretBox::new(deps.secret_key);
        // A wrong key would only show as failed sign-ins (ND-2).
        match accounts::secret_key_matches(&deps.pool, &secrets).await {
            Ok(true) => {}
            Ok(false) => {
                let refused = "PROBATION_SERVER_SECRET_KEY does not match the one these secrets were sealed with (a database restored with another key?); serve refused";
                tracing::error!("{refused}");
                return Err(std::io::Error::other(refused));
            }
            Err(err) => {
                tracing::warn!(error = %err, "PROBATION_SERVER_SECRET_KEY could not be checked")
            }
        }
    }
    let mut stop_requests = StopRequests::install()?;
    let (stop, stopping) = tokio::sync::watch::channel(false);
    let retention = config.server.change_log_retention_days;
    let pruner = pool.clone();
    let mut jobs = vec![every(Duration::from_secs(3600), &stopping, move || {
        let pruner = pruner.clone();
        async move {
            if let Err(err) = sync::prune_change_log(&pruner, retention).await {
                tracing::warn!(error = %err, "change_log prune failed");
            }
            if let Err(err) = audit::prune(&pruner).await {
                tracing::warn!(error = %err, "retention prune failed");
            }
        }
    })];
    let listener = tokio::net::TcpListener::bind(config.server.listen).await?;
    let sync_secrets = portal.as_ref().map(|deps| accounts::SecretBox::new(deps.secret_key));
    let state = Arc::new(sync::SyncState::new(pool, config.server.trusted_proxies, sync_secrets));
    let mut router = build_router(state);
    if let Some(deps) = portal {
        let secrets = accounts::SecretBox::new(deps.secret_key);
        jobs.extend(accounts::spawn_jobs(
            deps.pool.clone(),
            deps.mailer.clone(),
            secrets,
            &stopping,
        ));
        router = router.merge(portal::router(Arc::new(portal::Portal::new(deps))));
    }
    let mut stopped = stopping.clone();
    let drained = async move {
        let served = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            let _ = stopped.changed().await;
        })
        .await;
        for job in jobs {
            let _ = job.await;
        }
        served
    };
    let signals = async move {
        tokio::select! {
            () = stop_requests.recv() => {}
        }
        tracing::info!("stopping: finishing the requests in flight");
        stop.send_replace(true);
        tokio::select! {
            () = stop_requests.recv() => {}
            () = tokio::time::sleep(DRAIN) => {}
        }
        tracing::warn!("stopping now: requests or jobs still running are dropped");
    };
    tokio::select! {
        served = drained => served,
        () = signals => Ok(()),
    }
}

/// How long `serve` waits, after SIGTERM or SIGINT, for requests in flight and job runs
/// in progress; a second signal ends the wait at once.
const DRAIN: Duration = Duration::from_secs(20);

/// Runs `job` now and then every `period` until `stopping` turns true; a run in progress
/// finishes first, and none starts after it turned.
pub(crate) fn every<F, Fut>(
    period: Duration,
    stopping: &tokio::sync::watch::Receiver<bool>,
    mut job: F,
) -> tokio::task::JoinHandle<()>
where
    F: FnMut() -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send,
{
    let mut stopping = stopping.clone();
    tokio::spawn(async move {
        let mut ticks = tokio::time::interval(period);
        loop {
            tokio::select! {
                biased;
                _ = stopping.changed() => return,
                _ = ticks.tick() => {}
            }
            job().await;
        }
    })
}

/// Every API route the server answers: the sync API, the automation blocklist API
/// (C86) and the health probes. Serve it with connect info: the sync API checks the
/// firewall's address (T31).
pub fn build_router(state: Arc<sync::SyncState>) -> axum::Router {
    let automation = policy::router(state.pool().clone());
    let health = health(state.pool().clone());
    let service_policy = service_policy::router(state.pool().clone());
    sync::router(state).merge(automation).merge(health).merge(service_policy)
}

/// `GET /health/live`: 200 while the process answers. `GET /health/ready`: 200 while the
/// database answers `SELECT 1` within two seconds, 503 otherwise. Outside sessions, CSRF
/// and the network lock, for an orchestrator's probes.
fn health(pool: PgPool) -> axum::Router {
    use axum::extract::State;
    use axum::http::StatusCode;
    use axum::routing::get;
    axum::Router::new()
        .route("/health/live", get(|| async { StatusCode::OK }))
        .route(
            "/health/ready",
            get(|State(pool): State<PgPool>| async move {
                let select = sqlx::query("SELECT 1").execute(&pool);
                match tokio::time::timeout(Duration::from_secs(2), select).await {
                    Ok(Ok(_)) => StatusCode::OK,
                    _ => StatusCode::SERVICE_UNAVAILABLE,
                }
            }),
        )
        .with_state(pool)
}

/// `probation-server admin …`: the supported first-run path, before the portal exists
/// and after.
pub mod admin {
    use ipnet::IpNet;
    use probation_policy::api::{KeyId, OrgId};
    use sqlx::PgPool;

    use crate::keys::{self, KeyKind, RevokeError};
    use crate::tenancy::{self, Actor};
    use crate::{accounts, audit, fleet};

    pub struct Bootstrap {
        pub org_name: String,
        pub firewall_name: String,
        pub firewall_sources: Vec<IpNet>,
        /// The global admin's email address; the host operator vouches for it.
        pub email: String,
        /// `[portal] base_url`, which the set-password link is built from; `None` for a
        /// server without the portal, which gets no link.
        pub base_url: Option<url::Url>,
    }

    /// What `bootstrap` created. The key and the firewall token are shown once.
    pub struct Bootstrapped {
        pub login_id: i32,
        pub org: OrgId,
        pub key_id: KeyId,
        pub key: String,
        pub firewall_id: i32,
        pub firewall_token: String,
        /// Sets the global admin's first password; single-use, a reset link's lifetime.
        /// `None` without `[portal]`.
        pub set_password_link: Option<String>,
    }

    #[derive(Debug)]
    pub enum BootstrapError {
        /// A global admin exists already; nothing was written.
        AlreadyDone,
        /// Not an email address; nothing was written.
        BadEmail,
        /// The address already has an email-and-password sign-in; nothing was written.
        EmailTaken,
        Store(sqlx::Error),
    }

    impl From<sqlx::Error> for BootstrapError {
        fn from(err: sqlx::Error) -> Self {
            BootstrapError::Store(err)
        }
    }

    /// Creates the first global admin, with an email-and-password sign-in that has no
    /// password yet and a link that sets one, an organisation, a service key on it and a
    /// firewall token, with one audit row, in one transaction. Refused once any global
    /// admin exists (T3): the platform row is locked first, so two concurrent runs
    /// cannot both see none.
    pub async fn bootstrap(
        pool: &PgPool,
        input: Bootstrap,
    ) -> Result<Bootstrapped, BootstrapError> {
        let email = accounts::normal_email(&input.email).ok_or(BootstrapError::BadEmail)?;
        let mut tx = pool.begin().await?;
        sqlx::query("SELECT 1 FROM platform_settings WHERE id = 1 FOR UPDATE")
            .execute(&mut *tx)
            .await?;
        let admins: i64 =
            sqlx::query_scalar("SELECT count(*) FROM memberships WHERE role = 'global_admin'")
                .fetch_one(&mut *tx)
                .await?;
        if admins > 0 {
            return Err(BootstrapError::AlreadyDone);
        }
        let login_id: i32 = sqlx::query_scalar("INSERT INTO logins DEFAULT VALUES RETURNING id")
            .fetch_one(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO memberships (login_id, role) VALUES ($1, 'global_admin')")
            .bind(login_id)
            .execute(&mut *tx)
            .await?;
        let method = accounts::insert_unset_password(&mut tx, login_id, &email)
            .await?
            .ok_or(BootstrapError::EmailTaken)?;
        let set_password_link = match &input.base_url {
            Some(base) => Some(accounts::reset_link(&mut tx, base, method).await?),
            None => None,
        };
        let org = tenancy::create_org(&mut tx, &input.org_name).await?;
        let key = keys::insert(
            &mut tx,
            KeyKind::Service,
            tenancy::org_place(org),
            None,
            "bootstrap",
        )
        .await?;
        let firewall =
            fleet::insert(&mut tx, &input.firewall_name, &input.firewall_sources).await?;
        // The host operator ran this; the admin it creates has not acted yet (F7).
        let actor = Actor::Operator;
        let after = serde_json::json!({
            "global_admin": login_id,
            "email": email,
            "org": org.0,
            "key": key.id.0,
            "firewall": firewall.id,
        });
        let () = audit::record(
            &mut tx,
            audit::Entry {
                actor: &actor,
                org_id: Some(org.0 as i32),
                action: "admin.bootstrap",
                subject: format!("login:{login_id}"),
                before: None,
                after: Some(after),
            },
        )
        .await?;
        let () = tx.commit().await?;
        Ok(Bootstrapped {
            login_id,
            org,
            key_id: key.id,
            key: key.secret,
            firewall_id: firewall.id,
            firewall_token: firewall.token,
            set_password_link,
        })
    }

    /// `admin reset-link`: a fresh set-password link for a live global admin, as the host
    /// operator's recovery for a lost first link.
    pub async fn reset_link(
        pool: &PgPool,
        base_url: &url::Url,
        email: &str,
    ) -> Result<Option<String>, sqlx::Error> {
        accounts::operator_reset_link(pool, base_url, email).await
    }

    /// `admin revoke-key`: the host operator revokes a user or service key by id, never
    /// an automation or firewall token.
    pub async fn revoke_key(pool: &PgPool, key_id: KeyId) -> Result<(), RevokeError> {
        keys::revoke_as_operator(pool, key_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::Config;

    /// T-portal-firewall-url-checked: `[portal] firewall_url` goes into the lines people
    /// paste into `.npmrc` and `pip.conf`, so it needs a host, and https unless the host
    /// is this machine.
    #[test]
    fn t_portal_firewall_url_checked() {
        let dir = tempfile::tempdir().unwrap();
        let load = |url: &str| {
            let path = dir.path().join("server.toml");
            std::fs::write(
                &path,
                format!(
                    "[server]\nlisten = \"127.0.0.1:0\"\n\n[portal]\nbase_url = \"https://portal.test/\"\nfirewall_url = \"{url}\"\n"
                ),
            )
            .unwrap();
            Config::load(&path)
        };
        for good in [
            "https://packages.example.org",
            "https://packages.example.org:8443/probation/",
            "http://127.0.0.1:8080",
            "http://localhost:8080",
            "http://[::1]:8080",
        ] {
            assert!(load(good).is_ok(), "{good}: {:?}", load(good).err());
        }
        for bad in [
            "http://packages.example.org",
            "http://10.0.0.5:8080",
            "ftp://packages.example.org",
            "file:///etc/probation",
            "mailto:ops@example.org",
        ] {
            let refused = load(bad).expect_err(bad);
            assert!(refused.contains("portal.firewall_url"), "{bad}: {refused}");
        }
    }
}

/// The stop requests a service manager sends: SIGTERM and SIGINT on Unix; on Windows the
/// console control events (Ctrl+C, Ctrl+Break, close, shutdown), which have no SIGTERM.
#[cfg(unix)]
struct StopRequests {
    terminate: tokio::signal::unix::Signal,
    interrupt: tokio::signal::unix::Signal,
}

#[cfg(unix)]
impl StopRequests {
    fn install() -> std::io::Result<Self> {
        use tokio::signal::unix::{SignalKind, signal};
        Ok(Self {
            terminate: signal(SignalKind::terminate())?,
            interrupt: signal(SignalKind::interrupt())?,
        })
    }

    async fn recv(&mut self) {
        tokio::select! {
            _ = self.terminate.recv() => {}
            _ = self.interrupt.recv() => {}
        }
    }
}

#[cfg(windows)]
struct StopRequests {
    c: tokio::signal::windows::CtrlC,
    brk: tokio::signal::windows::CtrlBreak,
    close: tokio::signal::windows::CtrlClose,
    shutdown: tokio::signal::windows::CtrlShutdown,
}

#[cfg(windows)]
impl StopRequests {
    fn install() -> std::io::Result<Self> {
        use tokio::signal::windows;
        Ok(Self {
            c: windows::ctrl_c()?,
            brk: windows::ctrl_break()?,
            close: windows::ctrl_close()?,
            shutdown: windows::ctrl_shutdown()?,
        })
    }

    async fn recv(&mut self) {
        tokio::select! {
            _ = self.c.recv() => {}
            _ = self.brk.recv() => {}
            _ = self.close.recv() => {}
            _ = self.shutdown.recv() => {}
        }
    }
}
