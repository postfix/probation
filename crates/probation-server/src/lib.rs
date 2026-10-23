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
/// `config.server.listen` until the process is stopped; prunes `change_log`, activity
/// and the audit log by their retention once an hour (C26).
pub async fn serve(
    config: Config,
    pool: PgPool,
    portal: Option<portal::PortalDeps>,
) -> std::io::Result<()> {
    let retention = config.server.change_log_retention_days;
    let pruner = pool.clone();
    tokio::spawn(async move {
        let mut every_hour = tokio::time::interval(Duration::from_secs(3600));
        loop {
            every_hour.tick().await;
            if let Err(err) = sync::prune_change_log(&pruner, retention).await {
                tracing::warn!(error = %err, "change_log prune failed");
            }
            if let Err(err) = audit::prune(&pruner).await {
                tracing::warn!(error = %err, "retention prune failed");
            }
        }
    });
    let listener = tokio::net::TcpListener::bind(config.server.listen).await?;
    let state = Arc::new(sync::SyncState::new(pool, config.server.trusted_proxies));
    let mut router = build_router(state);
    if let Some(deps) = portal {
        router = router.merge(portal::Portal::launch(deps));
    }
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
}

/// Every API route the server answers: the sync API and the automation blocklist API
/// (C86). Serve it with connect info: the sync API checks the firewall's address (T31).
pub fn build_router(state: Arc<sync::SyncState>) -> axum::Router {
    let automation = policy::router(state.pool().clone());
    sync::router(state).merge(automation)
}

/// `probation-server admin …`: the supported first-run path, before the portal exists
/// and after.
pub mod admin {
    use ipnet::IpNet;
    use probation_policy::api::{KeyId, OrgId};
    use sqlx::PgPool;

    use crate::keys::{self, KeyKind, RevokeError};
    use crate::tenancy::{self, Actor};
    use crate::{audit, fleet};

    pub struct Bootstrap {
        pub org_name: String,
        pub firewall_name: String,
        pub firewall_sources: Vec<IpNet>,
    }

    /// What `bootstrap` created. The key and the firewall token are shown once.
    pub struct Bootstrapped {
        pub login_id: i32,
        pub org: OrgId,
        pub key_id: KeyId,
        pub key: String,
        pub firewall_id: i32,
        pub firewall_token: String,
    }

    #[derive(Debug)]
    pub enum BootstrapError {
        /// A global admin exists already; nothing was written.
        AlreadyDone,
        Store(sqlx::Error),
    }

    impl From<sqlx::Error> for BootstrapError {
        fn from(err: sqlx::Error) -> Self {
            BootstrapError::Store(err)
        }
    }

    /// Creates the first global admin, an organisation, a service key on it and a
    /// firewall token, with one audit row, in one transaction. Refused once any global
    /// admin exists (T3): the platform row is locked first, so two concurrent runs
    /// cannot both see none.
    pub async fn bootstrap(
        pool: &PgPool,
        input: Bootstrap,
    ) -> Result<Bootstrapped, BootstrapError> {
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
        })
    }

    /// `admin revoke-key`: the host operator revokes any key by id.
    pub async fn revoke_key(pool: &PgPool, key_id: KeyId) -> Result<(), RevokeError> {
        keys::revoke_as_operator(pool, key_id).await
    }
}
