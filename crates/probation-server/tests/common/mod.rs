//! The Postgres harness for `probation-server`'s tests (slice 4, reused by slices 5–7).
//!
//! Each test gets a fresh database in the Postgres of `docker-compose.test.yml`
//! (`PROBATION_SERVER_TEST_DATABASE_URL` overrides where it is), migrated by the owner
//! role, and an app pool connected as a login role in `probation_app`, so every test
//! runs under the privileges the server has in production (T17).

#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use ipnet::IpNet;
use probation_policy::{
    CheckedEdit, EditRefusal, EditTarget, Layer, LayerKind, PlaceRef, check_edit,
};
use probation_server::policy::{PolicyStore, SaveError};
use probation_server::tenancy::{Actor, Authorized, Place, Session, Tenancy, authorize};
use sqlx::PgPool;

/// The compose file's Postgres, as its superuser.
const DEFAULT_ADMIN_URL: &str = "postgres://probation:probation@127.0.0.1:55432/probation";
/// The login role the app pool connects as.
const APP_ROLE: &str = "probation_app_test";

fn admin_url() -> String {
    std::env::var("PROBATION_SERVER_TEST_DATABASE_URL")
        .unwrap_or_else(|_| DEFAULT_ADMIN_URL.to_owned())
}

/// `url` with its database name replaced and, when given, its user and password.
fn url_for(database: &str, login: Option<(&str, &str)>) -> String {
    let mut url = url::Url::parse(&admin_url()).expect("a Postgres URL");
    url.set_path(database);
    if let Some((user, password)) = login {
        url.set_username(user).expect("a user");
        url.set_password(Some(password)).expect("a password");
    }
    url.to_string()
}

pub struct Db {
    pub name: String,
    /// The migration owner: for setting up what no app path writes yet, and for faults.
    pub owner: PgPool,
    /// The server's own pool.
    pub app: PgPool,
    /// What `PROBATION_SERVER_DATABASE_URL` is for a server or CLI on this database.
    pub app_url: String,
}

impl Db {
    pub async fn fresh() -> Db {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let name = format!(
            "t{}_{}_{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        );
        let admin = PgPool::connect(&admin_url())
            .await
            .expect("Postgres is up: docker compose -f docker-compose.test.yml up -d postgres");
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
            .execute(&admin)
            .await
            .expect("a test database");
        admin.close().await;

        let owner = PgPool::connect(&url_for(&name, None))
            .await
            .expect("the owner connects");
        probation_server::migrate(&owner)
            .await
            .expect("migrations apply");
        // Shared by every test database on the cluster; the loser of a creation race
        // sees a unique violation.
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DO $$ BEGIN
                 CREATE ROLE {APP_ROLE} LOGIN PASSWORD 'probation' IN ROLE probation_app;
             EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL;
             END $$"
        )))
        .execute(&owner)
        .await
        .expect("the app login role");
        let app_url = url_for(&name, Some((APP_ROLE, "probation")));
        let app = probation_server::connect(&app_url)
            .await
            .expect("the app role connects");
        Db {
            name,
            owner,
            app,
            app_url,
        }
    }

    pub fn tenancy(&self) -> Tenancy {
        Tenancy::new(self.app.clone())
    }

    pub fn store(&self) -> PolicyStore {
        PolicyStore::new(self.app.clone())
    }

    pub async fn count(&self, sql: &'static str) -> i64 {
        sqlx::query_scalar(sql)
            .fetch_one(&self.owner)
            .await
            .expect("a count")
    }

    /// Makes every later `audit_log` insert fail, as a broken disk or constraint would.
    pub async fn break_audit_inserts(&self) {
        sqlx::query(
            "CREATE FUNCTION refuse_audit() RETURNS trigger LANGUAGE plpgsql AS $$
             BEGIN RAISE EXCEPTION 'injected audit insert failure'; END $$",
        )
        .execute(&self.owner)
        .await
        .unwrap();
        sqlx::query(
            "CREATE TRIGGER refuse_audit BEFORE INSERT ON audit_log
             FOR EACH ROW EXECUTE FUNCTION refuse_audit()",
        )
        .execute(&self.owner)
        .await
        .unwrap();
    }

    // Setup the portal will do in slices 5–7, written directly as the owner.

    pub async fn login(&self) -> i32 {
        sqlx::query_scalar("INSERT INTO logins DEFAULT VALUES RETURNING id")
            .fetch_one(&self.owner)
            .await
            .unwrap()
    }

    pub async fn global_admin(&self) -> i32 {
        let login = self.login().await;
        sqlx::query("INSERT INTO memberships (login_id, role) VALUES ($1, 'global_admin')")
            .bind(login)
            .execute(&self.owner)
            .await
            .unwrap();
        login
    }

    pub async fn org(&self, name: &str) -> PlaceRef {
        let id: i32 = sqlx::query_scalar("INSERT INTO orgs (name) VALUES ($1) RETURNING id")
            .bind(name)
            .fetch_one(&self.owner)
            .await
            .unwrap();
        place(LayerKind::Org, id)
    }

    pub async fn group(&self, org: PlaceRef, name: &str) -> PlaceRef {
        let id: i32 =
            sqlx::query_scalar("INSERT INTO groups (org_id, name) VALUES ($1, $2) RETURNING id")
                .bind(org.id as i32)
                .bind(name)
                .fetch_one(&self.owner)
                .await
                .unwrap();
        place(LayerKind::Group, id)
    }

    /// `login` joins `org` (in `group`) as `role`; returns its user place.
    pub async fn member(
        &self,
        login: i32,
        org: PlaceRef,
        group: Option<PlaceRef>,
        role: &str,
    ) -> PlaceRef {
        let id: i32 = sqlx::query_scalar(
            "INSERT INTO memberships (login_id, org_id, group_id, role) VALUES ($1, $2, $3, $4) RETURNING id",
        )
        .bind(login)
        .bind(org.id as i32)
        .bind(group.map(|group| group.id as i32))
        .bind(role)
        .fetch_one(&self.owner)
        .await
        .unwrap();
        place(LayerKind::User, id)
    }

    pub async fn personal(&self, login: i32) -> PlaceRef {
        let id: i32 =
            sqlx::query_scalar("INSERT INTO personal_accounts (login_id) VALUES ($1) RETURNING id")
                .bind(login)
                .fetch_one(&self.owner)
                .await
                .unwrap();
        place(LayerKind::Personal, id)
    }

    pub async fn suspend_org(&self, org: PlaceRef) {
        sqlx::query("UPDATE orgs SET status = 'suspended' WHERE id = $1")
            .bind(org.id as i32)
            .execute(&self.owner)
            .await
            .unwrap();
    }

    /// `place` as a global admin sees it.
    pub async fn as_admin(&self, admin: i32, at: PlaceRef) -> (Actor, Authorized<Place>) {
        let session = Session::new(admin, None);
        let authorized = self
            .tenancy()
            .authorized_place(&session, at)
            .await
            .expect("a global admin sees every place");
        let actor = self.tenancy().actor(&session, &authorized).await.unwrap();
        (actor, authorized)
    }

    /// The whole edit flow as `login`: `authorized_place`, the form loaded from
    /// `PolicyStore`, `check_edit` against `parent_policy`, `authorize`, `save_edit`.
    pub async fn edit(
        &self,
        login: i32,
        at: PlaceRef,
        change: impl FnOnce(&mut Layer),
    ) -> Result<i64, EditFailure> {
        let session = Session::new(login, None);
        let authorized = self
            .tenancy()
            .authorized_place(&session, at)
            .await
            .map_err(|_| EditFailure::NotFound)?;
        let actor = self.tenancy().actor(&session, &authorized).await.unwrap();
        let checked = self.check(&authorized, change).await?;
        let permit = authorize(&actor, &checked).map_err(|_| EditFailure::Denied)?;
        self.store()
            .save_edit(&actor, permit, checked)
            .await
            .map_err(EditFailure::Save)
    }

    /// The stored layer of `place` changed by `change`, checked against its parent.
    pub async fn check(
        &self,
        place: &Authorized<Place>,
        change: impl FnOnce(&mut Layer),
    ) -> Result<CheckedEdit, EditFailure> {
        let store = self.store();
        let (parent, current) = store.parent_policy(place).await.unwrap();
        let (_, revision) = store.layer(place).await.unwrap();
        let mut proposed = current.clone();
        change(&mut proposed);
        let target = EditTarget {
            place: place.place(),
            expected_revision: revision,
        };
        check_edit(&parent, &current, target, proposed).map_err(EditFailure::Refused)
    }
}

#[derive(Debug)]
pub enum EditFailure {
    NotFound,
    Refused(EditRefusal),
    Denied,
    Save(SaveError),
}

pub const fn place(kind: LayerKind, id: i32) -> PlaceRef {
    PlaceRef {
        kind,
        id: id as u32,
    }
}

/// The sync API on a loopback port, served as `probation-server serve` does.
pub async fn serve(app: PgPool, trusted_proxies: Vec<IpNet>) -> url::Url {
    let state = Arc::new(probation_server::sync::SyncState::new(app, trusted_proxies));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            probation_server::build_router(state)
                .into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });
    url::Url::parse(&format!("http://{addr}/")).unwrap()
}

/// A POST of `body` to `url` with `token` as the firewall token, sent and answered
/// within five seconds.
pub async fn post(
    client: &reqwest::Client,
    url: url::Url,
    token: Option<&str>,
    extra: &[(&str, &str)],
    body: Vec<u8>,
) -> reqwest::Response {
    let mut builder = client
        .post(url)
        .header("content-type", "application/json")
        .body(body);
    if let Some(token) = token {
        builder = builder.bearer_auth(token);
    }
    for (name, value) in extra {
        builder = builder.header(*name, *value);
    }
    tokio::time::timeout(Duration::from_secs(5), builder.send())
        .await
        .expect("answered in time")
        .expect("sent")
}

/// A firewall's `[management]` section for the server at `url` with `token`, as a test
/// builds it: a configuration file may only name an `https` server (C34).
pub fn management(url: url::Url, token: &str) -> probation::config::ManagementConfig {
    use std::num::{NonZeroU32, NonZeroU64, NonZeroUsize};
    probation::config::ManagementConfig {
        url,
        token: probation::config::FirewallToken::new(token.to_owned()),
        key_cache_ttl_seconds: NonZeroU64::new(300).unwrap(),
        key_cache_max_entries: NonZeroUsize::new(100_000).unwrap(),
        lookup_budget_per_second: NonZeroU32::new(50).unwrap(),
        client_lookup_allowance_per_second: NonZeroU32::new(5).unwrap(),
        request_timeout_seconds: NonZeroU64::new(2).unwrap(),
        sync_margin_seconds: NonZeroU64::new(5).unwrap(),
        trusted_proxies: Vec::new(),
    }
}

pub fn client() -> reqwest::Client {
    reqwest::Client::builder().no_proxy().build().unwrap()
}

/// A real managed firewall (`probation::App`) against the server at `server`, its
/// upstream an in-process registry that publishes every npm name asked for.
pub struct Firewall {
    pub running: probation::Running,
    _dir: tempfile::TempDir,
}

impl Firewall {
    /// Syncs every `sync_interval_seconds`, `margin_seconds` early (C112).
    pub async fn start(
        server: url::Url,
        token: &str,
        sync_interval_seconds: u64,
        margin_seconds: u64,
    ) -> Firewall {
        use std::num::NonZeroU64;
        let dir = tempfile::tempdir().unwrap();
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut config = probation::config::Config::load(&root.join("config.sample.toml"))
            .expect("config.sample.toml loads");
        config.listen = SocketAddr::from(([127, 0, 0, 1], 0));
        config.data_dir = dir.path().join("data");
        // Ignored in managed mode (C109); a valid, open file keeps an older firewall
        // build from refusing to start without one.
        config.blocklist_file = dir.path().join("blocklist.json");
        std::fs::write(
            &config.blocklist_file,
            r#"{"schema_version":1,"revision":1,"generated_at":"2020-01-01T00:00:00Z","expires_at":"2099-01-01T00:00:00Z","blocked_packages":[],"blocked_hashes":[]}"#,
        )
        .unwrap();
        config.sync_interval_seconds = NonZeroU64::new(sync_interval_seconds).unwrap();
        let mut management = management(server, token);
        management.sync_margin_seconds = NonZeroU64::new(margin_seconds).unwrap();
        management.request_timeout_seconds = NonZeroU64::new(margin_seconds).unwrap();
        config.management = Some(management);
        let origins = probation::upstream::OriginSet::for_tests(
            url::Url::parse("https://npm.invalid").unwrap(),
            url::Url::parse("https://pypi.invalid").unwrap(),
            url::Url::parse("https://files.invalid").unwrap(),
        );
        let running = probation::App::start(probation::AppDeps {
            config,
            clock: Arc::new(probation::clock::SystemClock),
            transport: Arc::new(Registry),
            origins,
            osv_client: probation::osv::unreachable_client(),
            osv_base_url: None,
        })
        .await
        .expect("the firewall starts");
        Firewall { running, _dir: dir }
    }

    pub fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.running.local_addr)
    }

    /// `GET path` with `key` as the npm Bearer token, from `client`.
    pub async fn get(&self, client: &reqwest::Client, path: &str, key: &str) -> reqwest::Response {
        let sent = client.get(self.url(path)).bearer_auth(key).send();
        tokio::time::timeout(Duration::from_secs(10), sent)
            .await
            .expect("the firewall answers in time")
            .expect("the firewall answers")
    }

    /// Waits until `/health/ready` answers 200: the first sync is applied.
    pub async fn ready(&self, within: Duration) {
        let http = client();
        let deadline = tokio::time::Instant::now() + within;
        loop {
            let sent = http.get(self.url("/health/ready")).send();
            if let Ok(Ok(answer)) = tokio::time::timeout(Duration::from_secs(2), sent).await
                && answer.status() == reqwest::StatusCode::OK
            {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the firewall never became ready"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

/// An npm registry that publishes every name it is asked for, with two old versions.
struct Registry;

#[async_trait::async_trait]
impl probation::upstream::Transport for Registry {
    async fn fetch_metadata(
        &self,
        asked: probation::upstream::MetadataRequest,
    ) -> Result<probation::upstream::MetadataResponse, probation::upstream::UpstreamError> {
        let name = asked
            .url
            .path_segments()
            .and_then(|mut segments| segments.next_back())
            .unwrap_or_default()
            .to_owned();
        let version = |version: &str| {
            serde_json::json!({
                "name": name,
                "version": version,
                "dist": {"tarball": format!("https://npm.invalid/{name}/-/{name}-{version}.tgz")},
            })
        };
        let document = serde_json::json!({
            "name": name,
            "dist-tags": {"latest": "1.1.0"},
            "versions": {"1.0.0": version("1.0.0"), "1.1.0": version("1.1.0")},
            "time": {"1.0.0": "2020-01-01T00:00:00Z", "1.1.0": "2020-02-01T00:00:00Z"},
        });
        Ok(probation::upstream::MetadataResponse::Fresh {
            body: bytes::Bytes::from(document.to_string()),
            validators: Default::default(),
        })
    }

    async fn open_artifact(
        &self,
        _asked: probation::upstream::ArtifactRequest,
    ) -> Result<probation::upstream::ArtifactBody, probation::upstream::UpstreamError> {
        Err(probation::upstream::UpstreamError::Transport(
            "no artifacts in this registry".to_owned(),
        ))
    }
}
