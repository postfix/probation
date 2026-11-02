//! Slice 7: global admins (organisations, personal accounts, global admins, limits,
//! retention, network-lock approval, the platform policy and its automation tokens), the
//! fleet (register, settings rollouts, retire, health), blocklist import, export and
//! push, through the real portal routes, the real automation API and the real sync API
//! against Postgres (03 § Portal requirement tests). The T-sync rows run a real firewall;
//! the settings rows check in as fake firewalls through the sync API, because a real one
//! exits 75 to apply a push (C105).

mod common;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use common::Db;
use probation_policy::api::{
    ChangesRequest, ChangesResponse, FirewallReport, Reachability, ReportStatus, Upstreams,
};
use probation_policy::{
    Block, DigestAlgorithm, Ecosystem, Layer, LayerKind, PlaceRef, blocklist_json, resolve,
};
use probation_server::accounts::{self, Mail, Mailer, Outbound, OutboundError};
use probation_server::portal::{self, Portal, PortalConfig, PortalDeps};
use reqwest::StatusCode;

const BASE_URL: &str = "https://portal.test";
const PASSWORD: &str = "correct horse battery";
const SAMPLE: &str = include_str!("../../../blocklist.sample.json");

/// The portal and the server's APIs on loopback ports, with fakes for mail and the
/// network.
struct Fixture {
    db: Db,
    addr: SocketAddr,
    /// The sync and automation APIs, as `probation-server serve` answers them.
    api: url::Url,
    mail: Arc<FakeMail>,
}

impl Fixture {
    async fn start() -> Fixture {
        let db = Db::fresh().await;
        let mail = Arc::new(FakeMail::default());
        let addr = serve(&db, mail.clone()).await;
        let api = common::serve(db.app.clone(), Vec::new()).await;
        Fixture {
            db,
            addr,
            api,
            mail,
        }
    }

    fn browser(&self) -> Browser {
        Browser::new(self.addr, "198.51.100.1")
    }

    async fn deliver(&self) {
        let mailer: Arc<dyn Mailer> = self.mail.clone();
        accounts::deliver_outbox(
            &self.db.app,
            &mailer,
            &accounts::SecretBox::new(common::SECRET_KEY),
            &tokio::sync::watch::channel(false).1,
        )
        .await
        .expect("the outbox runs");
    }

    /// A confirmed login with an email-and-password method and nothing else.
    async fn person(&self, email: &str) -> i32 {
        static HASH: OnceLock<String> = OnceLock::new();
        let hash = HASH.get_or_init(|| {
            use argon2::password_hash::PasswordHasher;
            argon2::Argon2::new(
                argon2::Algorithm::Argon2id,
                argon2::Version::V0x13,
                argon2::Params::new(8, 1, 1, None).unwrap(),
            )
            .hash_password(PASSWORD.as_bytes())
            .unwrap()
            .to_string()
        });
        let login = self.db.login().await;
        sqlx::query(
            "INSERT INTO sign_in_methods (login_id, kind, subject, email, password_hash, verified_at)
             VALUES ($1, 'password', $2, $2, $3, now())",
        )
        .bind(login)
        .bind(email)
        .bind(hash)
        .execute(&self.db.owner)
        .await
        .unwrap();
        login
    }

    /// A global admin who signs in with an email and password.
    async fn operator(&self, email: &str) -> i32 {
        let login = self.person(email).await;
        sqlx::query("INSERT INTO memberships (login_id, role) VALUES ($1, 'global_admin')")
            .bind(login)
            .execute(&self.db.owner)
            .await
            .unwrap();
        login
    }

    async fn signed_in(&self, email: &str) -> Browser {
        let mut browser = self.browser();
        let page = browser
            .submit(
                "/signin",
                "/signin",
                &[("email", email), ("password", PASSWORD)],
            )
            .await;
        assert_eq!(page.location.as_deref(), Some("/account"), "{}", page.body);
        browser
    }

    /// Signed in, with an authenticator turned on (C24, C60).
    async fn admin(&self, email: &str) -> Browser {
        let mut browser = self.signed_in(email).await;
        turn_totp_on(&mut browser).await;
        browser
    }

    /// A firewall registered on this database and started against its sync API,
    /// syncing every 2 s (1 s margin), ready.
    async fn firewall(&self) -> common::Firewall {
        let token = register(&self.db, "fw").await.1;
        self.firewall_with(self.api.clone(), &token).await
    }

    async fn firewall_with(&self, server: url::Url, token: &str) -> common::Firewall {
        let firewall = common::Firewall::start(server, token, 2, 1).await;
        firewall.ready(Duration::from_secs(10)).await;
        firewall
    }
}

/// Registers a firewall as the operator: (id, token).
async fn register(db: &Db, name: &str) -> (i32, String) {
    let registered = probation_server::fleet::register(
        &db.app,
        &probation_server::tenancy::Actor::Operator,
        name,
        &["127.0.0.0/8".parse().unwrap()],
    )
    .await
    .unwrap();
    (registered.id, registered.token)
}

fn config() -> PortalConfig {
    PortalConfig {
        base_url: url::Url::parse(BASE_URL).unwrap(),
        google: None,
        github: None,
        microsoft: None,
        leaked_password_url: url::Url::parse("https://api.pwnedpasswords.com/range/").unwrap(),
        smtp: None,
        firewall_url: None,
    }
}

async fn serve(db: &Db, mail: Arc<FakeMail>) -> SocketAddr {
    let portal = Portal::new(PortalDeps {
        pool: db.app.clone(),
        config: config(),
        outbound: Arc::new(NoNet),
        mailer: Some(mail),
        secret_key: common::SECRET_KEY,
        password_params: argon2::Params::new(8, 1, 1, None).unwrap(),
        trusted_proxies: vec!["127.0.0.0/8".parse().unwrap()],
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            portal::router(Arc::new(portal)).into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });
    addr
}

/// No outside service is called by these tests: every call is refused.
struct NoNet;

#[async_trait::async_trait]
impl Outbound for NoNet {
    async fn get(&self, url: &url::Url, _bearer: Option<&str>) -> Result<Vec<u8>, OutboundError> {
        Err(OutboundError::Refused(url.to_string()))
    }

    async fn post_form(
        &self,
        url: &url::Url,
        _form: &[(&str, &str)],
    ) -> Result<Vec<u8>, OutboundError> {
        Err(OutboundError::Refused(url.to_string()))
    }
}

#[derive(Default)]
struct FakeMail {
    sent: std::sync::Mutex<Vec<Mail>>,
}

#[async_trait::async_trait]
impl Mailer for FakeMail {
    async fn deliver(&self, mail: &Mail) -> Result<(), String> {
        self.sent.lock().unwrap().push(mail.clone());
        Ok(())
    }
}

impl FakeMail {
    /// The path and query of the last link to `address` that starts with `prefix`.
    fn link(&self, address: &str, prefix: &str) -> String {
        let full = format!("{BASE_URL}{prefix}");
        let sent = self.sent.lock().unwrap();
        let mail = sent
            .iter()
            .rev()
            .find(|mail| mail.to == address && mail.body.contains(&full))
            .unwrap_or_else(|| panic!("no mail to {address} with a {prefix} link"));
        let start = mail.body.find(&full).unwrap() + BASE_URL.len();
        let end = mail.body[start..]
            .find(char::is_whitespace)
            .map_or(mail.body.len(), |end| start + end);
        mail.body[start..end].to_owned()
    }
}

/// What a browser keeps: one session cookie, sent back on every request.
struct Browser {
    http: reqwest::Client,
    addr: SocketAddr,
    ip: String,
    cookie: Option<String>,
}

struct Page {
    status: StatusCode,
    location: Option<String>,
    csp: Option<String>,
    content_type: Option<String>,
    body: String,
}

impl Page {
    fn csrf(&self) -> String {
        hidden(&self.body, "csrf").expect("a form with a CSRF token")
    }

    fn has(&self, text: &str) -> bool {
        self.body.contains(text)
    }
}

/// The value of the hidden field `name` in `body`.
fn hidden(body: &str, name: &str) -> Option<String> {
    let marker = format!("name=\"{name}\" value=\"");
    let start = body.find(&marker)? + marker.len();
    let end = body[start..].find('"')? + start;
    Some(body[start..end].to_owned())
}

impl Browser {
    fn new(addr: SocketAddr, ip: &str) -> Browser {
        Browser {
            http: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            addr,
            ip: ip.to_owned(),
            cookie: None,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }

    async fn get(&mut self, path: &str) -> Page {
        let builder = self.http.get(self.url(path));
        self.fetch(builder).await
    }

    /// POSTs `fields` as a form, exactly as given (no CSRF token is added).
    async fn post_raw(&mut self, path: &str, fields: &[(&str, &str)]) -> Page {
        let builder = self.http.post(self.url(path)).form(fields);
        self.fetch(builder).await
    }

    /// Loads `page`, then POSTs `fields` to `path` with that page's CSRF token.
    async fn submit(&mut self, page: &str, path: &str, fields: &[(&str, &str)]) -> Page {
        let csrf = self.get(page).await.csrf();
        let mut fields = fields.to_vec();
        fields.push(("csrf", &csrf));
        self.post_raw(path, &fields).await
    }

    async fn fetch(&mut self, mut builder: reqwest::RequestBuilder) -> Page {
        builder = builder.header("x-forwarded-for", &self.ip);
        if let Some(cookie) = &self.cookie {
            builder = builder.header("cookie", cookie);
        }
        let answer = tokio::time::timeout(Duration::from_secs(10), builder.send())
            .await
            .expect("the portal answers in time")
            .expect("the portal answers");
        let location = header(&answer, "location");
        let csp = header(&answer, "content-security-policy");
        let content_type = header(&answer, "content-type");
        for cookie in answer.headers().get_all("set-cookie") {
            let cookie = cookie.to_str().unwrap();
            if cookie.contains("Max-Age=0") {
                self.cookie = None;
            } else {
                self.cookie = Some(cookie.split(';').next().unwrap().to_owned());
            }
        }
        let status = answer.status();
        let body = answer.text().await.unwrap();
        Page {
            status,
            location,
            csp,
            content_type,
            body,
        }
    }
}

fn header(answer: &reqwest::Response, name: &str) -> Option<String> {
    answer
        .headers()
        .get(name)
        .map(|value| value.to_str().unwrap().to_owned())
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// The text between `start` and the next `end` in `body`.
fn between<'a>(body: &'a str, start: &str, end: &str) -> &'a str {
    let from = body
        .find(start)
        .unwrap_or_else(|| panic!("{start} in {body}"))
        + start.len();
    let to = body[from..].find(end).unwrap() + from;
    &body[from..to]
}

fn totp_code(secret: &str, unix: u64) -> String {
    let secret = totp_rs::Secret::try_from_base32(secret.replace(' ', "")).unwrap();
    totp_rs::Builder::new()
        .with_secret(secret)
        .build_noncompliant()
        .generate(unix)
        .to_string()
}

async fn turn_totp_on(browser: &mut Browser) {
    let setup = browser.submit("/account", "/account/totp/setup", &[]).await;
    assert_eq!(setup.status, StatusCode::OK, "{}", setup.body);
    let secret = between(&setup.body, "<code id=\"totp-key\">", "</code>").to_owned();
    let code = totp_code(&secret, now_unix() - 30);
    let csrf = setup.csrf();
    let on = browser
        .post_raw("/account/totp/enable", &[("code", &code), ("csrf", &csrf)])
        .await;
    assert_eq!(on.status, StatusCode::SEE_OTHER, "{}", on.body);
}

/// Acme and Globex: Ana is Acme's org admin, Mia a member of Acme, Gus Globex's org
/// admin, Pat a login with only a personal account, and Root the global admin. Every
/// login signs in with an email and password and has no authenticator.
struct World {
    acme: PlaceRef,
    globex: PlaceRef,
    ana: i32,
    mia: i32,
    gus: i32,
    pat: i32,
    root: i32,
    pat_personal: PlaceRef,
    /// Each member's user place.
    places: HashMap<i32, PlaceRef>,
}

impl World {
    async fn new(fx: &Fixture) -> World {
        let db = &fx.db;
        let acme = db.org("Acme").await;
        let globex = db.org("Globex").await;
        let ana = fx.person("ana@acme.test").await;
        let mia = fx.person("mia@acme.test").await;
        let gus = fx.person("gus@globex.test").await;
        let pat = fx.person("pat@home.test").await;
        let root = fx.operator("root@probation.test").await;
        let pat_personal = db.personal(pat).await;
        let mut places = HashMap::new();
        places.insert(ana, db.member(ana, acme, None, "org_admin").await);
        places.insert(mia, db.member(mia, acme, None, "member").await);
        places.insert(gus, db.member(gus, globex, None, "org_admin").await);
        World {
            acme,
            globex,
            ana,
            mia,
            gus,
            pat,
            root,
            pat_personal,
            places,
        }
    }
}

fn shown(page: &Page, id: &str) -> String {
    between(&page.body, &format!("<code id=\"{id}\">"), "</code>").to_owned()
}

/// Creates an API key named `name` on `/keys` in the browser's current place.
async fn create_key(browser: &mut Browser, name: &str) -> String {
    let page = browser.submit("/keys", "/keys", &[("name", name)]).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    shown(&page, "new-key")
}

async fn key_id(db: &Db, name: &str) -> i64 {
    sqlx::query_scalar("SELECT id FROM keys WHERE name = $1")
        .bind(name)
        .fetch_one(&db.owner)
        .await
        .unwrap()
}

/// Waits until `key` answers `want` on the firewall, at most one 2 s interval after the
/// change committed.
async fn answers_within_interval(
    firewall: &common::Firewall,
    key: &str,
    want: StatusCode,
    what: &str,
) {
    let http = common::client();
    let committed = std::time::Instant::now();
    loop {
        let status = firewall.get(&http, "/npm/left-pad", key).await.status();
        if status == want {
            return;
        }
        assert!(
            committed.elapsed() <= Duration::from_secs(2),
            "{what}: {want} within one interval, still {status}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn status_of(firewall: &common::Firewall, key: &str) -> StatusCode {
    firewall
        .get(&common::client(), "/npm/left-pad", key)
        .await
        .status()
}

/// Waits up to two intervals for an activity row of `result` for the key `name`: the
/// firewall uploads its queue at its next sync.
async fn activity_row(db: &Db, name: &str, result: &str) {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let rows: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM activity AS a JOIN keys AS k ON k.id = a.key_id
             WHERE k.name = $1 AND a.result = $2",
        )
        .bind(name)
        .bind(result)
        .fetch_one(&db.owner)
        .await
        .unwrap();
        if rows > 0 {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "no {result} row for {name}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn audit_rows(
    db: &Db,
    action: &str,
) -> Vec<(
    Option<i32>,
    bool,
    Option<i32>,
    String,
    Option<serde_json::Value>,
    Option<serde_json::Value>,
)> {
    sqlx::query_as(
        "SELECT actor_login, actor_is_global_admin, org_id, subject, before, after FROM audit_log
         WHERE action = $1 ORDER BY id",
    )
    .bind(action)
    .fetch_all(&db.owner)
    .await
    .unwrap()
}

/// A digest of the rows every admin action could write.
async fn state(db: &Db) -> String {
    let tables = [
        "orgs",
        "groups",
        "memberships",
        "invitations",
        "leave_requests",
        "org_ip_ranges",
        "personal_accounts",
        "keys",
        "policy_layers",
        "policy_blocks",
        "policy_exceptions",
        "totp",
        "limits",
        "platform_settings",
        "firewalls",
        "settings_rollouts",
        "settings_rollout_steps",
        "audit_log",
        "change_log",
        "email_outbox",
    ];
    let mut digest = String::new();
    for table in tables {
        let sql = format!(
            "SELECT coalesce(md5(string_agg(t::text, ',' ORDER BY t::text)), '') FROM {table} AS t"
        );
        let one: String = sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
            .fetch_one(&db.owner)
            .await
            .unwrap();
        digest.push_str(&format!("{table}:{one} "));
    }
    digest
}

fn policy_path(place: PlaceRef) -> String {
    let kind = match place.kind {
        LayerKind::Platform => "platform",
        LayerKind::Org => "org",
        LayerKind::Group => "group",
        LayerKind::User => "user",
        LayerKind::Personal => "personal",
    };
    format!("/policy/{kind}-{}", place.id)
}

fn layer_id(place: PlaceRef) -> String {
    policy_path(place)["/policy/".len()..].to_owned()
}

/// The stored blocks of `place`'s layer, through the server's own store.
async fn blocks_of(db: &Db, admin: i32, place: PlaceRef) -> Vec<Block> {
    let (_, authorized) = db.as_admin(admin, place).await;
    db.store().layer(&authorized).await.unwrap().0.blocks
}

// ---- The automation API ---------------------------------------------------------------

/// `method /api/v1/blocklist/{layer}` with `token`, answered within ten seconds.
async fn blocklist_call(
    fx: &Fixture,
    method: reqwest::Method,
    token: &str,
    layer: &str,
    body: Vec<u8>,
) -> (StatusCode, String) {
    let url = fx.api.join(&format!("api/v1/blocklist/{layer}")).unwrap();
    // A neutral name before `.body`, as the analyzers expect of every caller (02 §
    // Constraints).
    let call = common::client().request(method, url);
    let call = call
        .bearer_auth(token)
        .header("content-type", "application/json");
    let sent = call.body(body).send();
    let answer = tokio::time::timeout(Duration::from_secs(10), sent)
        .await
        .expect("the server answers in time")
        .expect("the server answers");
    let status = answer.status();
    (status, answer.text().await.unwrap())
}

fn one_block_file(ecosystem: &str, name: &str) -> Vec<u8> {
    serde_json::json!({
        "schema_version": 1,
        "revision": 1,
        "generated_at": "2026-01-01T00:00:00Z",
        "expires_at": "2099-01-01T00:00:00Z",
        "blocked_packages": [{"ecosystem": ecosystem, "name": name, "version": null, "reason": "pushed"}],
        "blocked_hashes": [],
    })
    .to_string()
    .into_bytes()
}

/// Creates an automation token for `layer` on the organisation page.
async fn org_token(browser: &mut Browser, org: PlaceRef, layer: &str, name: &str) -> String {
    let page_path = format!("/org/{}", org.id);
    let page = browser
        .submit(
            &page_path,
            &format!("/org/{}/automation", org.id),
            &[("name", name), ("layer", layer)],
        )
        .await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    shown(&page, "new-token")
}

/// Creates a platform automation token on `/admin`.
async fn platform_token(browser: &mut Browser, name: &str) -> String {
    let page = browser
        .submit("/admin", "/admin/tokens", &[("name", name)])
        .await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    shown(&page, "new-token")
}

// ---- Fake firewalls checking in through the sync API ----------------------------------

fn report(settings_revision: u64, error: Option<&str>, period: u64) -> FirewallReport {
    FirewallReport {
        settings_revision,
        last_apply_error: error.map(str::to_owned),
        status: ReportStatus {
            upstreams: Upstreams {
                npm: Reachability::Ok,
                pypi: Reachability::Ok,
                osv: Reachability::Ok,
            },
        },
        effective_period_seconds: period,
        version: "9.9.9".to_owned(),
        failed_revision: None,
    }
}

/// One `changes` call as the firewall with `token` makes it.
async fn check_in(fx: &Fixture, token: &str, report: FirewallReport) -> ChangesResponse {
    let request = ChangesRequest {
        since: 0,
        report,
        activity: Vec::new(),
        activity_dropped: Vec::new(),
    };
    let answer = common::post(
        &common::client(),
        fx.api.join("api/v1/sync/changes").unwrap(),
        Some(token),
        &[],
        serde_json::to_vec(&request).unwrap(),
    )
    .await;
    assert_eq!(answer.status(), StatusCode::OK);
    serde_json::from_slice(&answer.bytes().await.unwrap()).unwrap()
}

/// The fleet page's row for firewall `id`.
fn fleet_row(page: &Page, id: i32) -> String {
    between(&page.body, &format!("<tr id=\"firewall-{id}\">"), "</tr>").to_owned()
}

/// "Save and apply" for `firewalls` on the fleet page.
async fn push_settings(browser: &mut Browser, firewalls: &[i32], toml: &str) -> Page {
    let ids: Vec<String> = firewalls.iter().map(i32::to_string).collect();
    let mut fields: Vec<(&str, &str)> = ids.iter().map(|id| ("firewall", id.as_str())).collect();
    fields.push(("toml", toml));
    browser.submit("/fleet", "/fleet/settings", &fields).await
}

async fn rollout_state(db: &Db, rollout: i32) -> (String, Vec<String>) {
    let state: String = sqlx::query_scalar("SELECT state FROM settings_rollouts WHERE id = $1")
        .bind(rollout)
        .fetch_one(&db.owner)
        .await
        .unwrap();
    let steps: Vec<String> = sqlx::query_scalar(
        "SELECT state FROM settings_rollout_steps WHERE rollout_id = $1 ORDER BY position",
    )
    .bind(rollout)
    .fetch_all(&db.owner)
    .await
    .unwrap();
    (state, steps)
}

async fn last_rollout(db: &Db) -> i32 {
    sqlx::query_scalar("SELECT max(id) FROM settings_rollouts")
        .fetch_one(&db.owner)
        .await
        .unwrap()
}

// ---- Tests ----------------------------------------------------------------------------

/// T-automation-token-creator-removed (C86, T3): removing, demoting or approving the
/// leave of an org admin revokes the automation tokens they created, with an audit row;
/// a later push with one answers 401.
#[tokio::test]
async fn t_automation_token_creator_removed() {
    let fx = Fixture::start().await;
    let world = World::new(&fx).await;
    let oli = fx.person("oli@acme.test").await;
    let oli_place = fx.db.member(oli, world.acme, None, "org_admin").await;
    let kim = fx.person("kim@acme.test").await;
    fx.db.member(kim, world.acme, None, "org_admin").await;
    let acme_layer = layer_id(world.acme);
    let org_page = format!("/org/{}", world.acme.id);
    let ana_place = world.places[&world.ana];
    let mut ana = fx.admin("ana@acme.test").await;
    let mut oli_browser = fx.admin("oli@acme.test").await;
    let mut kim_browser = fx.admin("kim@acme.test").await;

    // Demoted.
    let demoted = org_token(&mut ana, world.acme, &acme_layer, "ci one").await;
    let (pushed, body) = blocklist_call(
        &fx,
        reqwest::Method::POST,
        &demoted,
        &acme_layer,
        one_block_file("npm", "left-pad"),
    )
    .await;
    assert_eq!(pushed, StatusCode::OK, "{body}");
    let role = oli_browser
        .submit(
            &org_page,
            &format!("/org/members/{}/role", ana_place.id),
            &[("role", "member")],
        )
        .await;
    assert_eq!(role.status, StatusCode::SEE_OTHER, "{}", role.body);
    let (after, _) = blocklist_call(
        &fx,
        reqwest::Method::POST,
        &demoted,
        &acme_layer,
        one_block_file("npm", "colors"),
    )
    .await;
    assert_eq!(after, StatusCode::UNAUTHORIZED);

    // Removed.
    oli_browser
        .submit(
            &org_page,
            &format!("/org/members/{}/role", ana_place.id),
            &[("role", "org_admin")],
        )
        .await;
    let removed = org_token(&mut ana, world.acme, &acme_layer, "ci two").await;
    let gone = oli_browser
        .submit(
            &org_page,
            &format!("/org/members/{}/remove", ana_place.id),
            &[],
        )
        .await;
    assert_eq!(gone.status, StatusCode::SEE_OTHER, "{}", gone.body);
    let (after, _) = blocklist_call(
        &fx,
        reqwest::Method::POST,
        &removed,
        &acme_layer,
        one_block_file("npm", "colors"),
    )
    .await;
    assert_eq!(after, StatusCode::UNAUTHORIZED);

    // Left with approval.
    let left = org_token(&mut kim_browser, world.acme, &acme_layer, "ci three").await;
    let asked = kim_browser
        .submit(&org_page, &format!("/org/{}/leave", world.acme.id), &[])
        .await;
    assert_eq!(asked.status, StatusCode::SEE_OTHER, "{}", asked.body);
    let leave: i32 = sqlx::query_scalar("SELECT id FROM leave_requests WHERE login_id = $1")
        .bind(kim)
        .fetch_one(&fx.db.owner)
        .await
        .unwrap();
    let approved = oli_browser
        .submit(&org_page, &format!("/org/leave/{leave}/approve"), &[])
        .await;
    assert_eq!(approved.status, StatusCode::SEE_OTHER, "{}", approved.body);
    let (after, _) = blocklist_call(
        &fx,
        reqwest::Method::POST,
        &left,
        &acme_layer,
        one_block_file("npm", "colors"),
    )
    .await;
    assert_eq!(after, StatusCode::UNAUTHORIZED);

    let revoked = audit_rows(&fx.db, "automation.revoke").await;
    assert_eq!(revoked.len(), 3, "{revoked:?}");
    for (name, row) in ["ci one", "ci two", "ci three"].iter().zip(&revoked) {
        let id = key_id(&fx.db, name).await;
        assert_eq!(row.3, format!("key:{id}"));
        assert_eq!(row.2, Some(world.acme.id as i32));
        assert_eq!(row.0, Some(oli), "the admin whose change revoked it");
    }
    let _ = oli_place;

    // A role lost by any path, the revoking ones bypassed: the token is checked against
    // its creator's role when it is used (B1).
    let raced = org_token(&mut oli_browser, world.acme, &acme_layer, "ci four").await;
    sqlx::query("UPDATE memberships SET role = 'member' WHERE login_id = $1")
        .bind(oli)
        .execute(&fx.db.owner)
        .await
        .unwrap();
    let (after, _) = blocklist_call(
        &fx,
        reqwest::Method::POST,
        &raced,
        &acme_layer,
        one_block_file("npm", "colors"),
    )
    .await;
    assert_eq!(after, StatusCode::UNAUTHORIZED);
    let mut root = fx.admin("root@probation.test").await;
    let platform = platform_token(&mut root, "platform ci").await;
    sqlx::query("DELETE FROM memberships WHERE login_id = $1 AND org_id IS NULL")
        .bind(world.root)
        .execute(&fx.db.owner)
        .await
        .unwrap();
    let (after, _) = blocklist_call(
        &fx,
        reqwest::Method::POST,
        &platform,
        "platform-1",
        one_block_file("npm", "colors"),
    )
    .await;
    assert_eq!(after, StatusCode::UNAUTHORIZED);
}

/// T-portal-admin-in-org (C4, C79): a global admin opens Acme as an org admin, and a
/// member edit there appears in Acme's audit log, flagged global admin; an org admin
/// is appointed only through an invitation link or an explicit login id.
#[tokio::test]
async fn t_portal_admin_in_org() {
    let fx = Fixture::start().await;
    let world = World::new(&fx).await;
    let mut root = fx.admin("root@probation.test").await;
    let admin = root.get("/admin").await;
    assert_eq!(admin.status, StatusCode::OK, "{}", admin.body);
    let org_page = format!("/org/{}", world.acme.id);
    assert!(admin.has(&format!("href=\"{org_page}\"")), "{}", admin.body);
    let inside = root.get(&org_page).await;
    assert_eq!(inside.status, StatusCode::OK);
    assert!(inside.has("mia@acme.test"), "{}", inside.body);

    let mia = world.places[&world.mia];
    let made = root
        .submit(
            &org_page,
            &format!("/org/members/{}/role", mia.id),
            &[("role", "org_admin")],
        )
        .await;
    assert_eq!(made.status, StatusCode::SEE_OTHER, "{}", made.body);
    let rows = audit_rows(&fx.db, "member.role").await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, Some(world.root));
    assert!(rows[0].1, "flagged global admin");
    assert_eq!(rows[0].2, Some(world.acme.id as i32), "in Acme's log");
    let mut ana = fx.admin("ana@acme.test").await;
    let log = ana.get("/audit").await;
    assert!(log.has("(operator)"), "{}", log.body);

    // An invitation creates no membership until a signed-in login accepts the link.
    let members_before = fx
        .db
        .count("SELECT count(*) FROM memberships WHERE role = 'org_admin'")
        .await;
    let invited = root
        .submit(
            &org_page,
            &format!("/org/{}/invitations", world.acme.id),
            &[
                ("email", "new@acme.test"),
                ("role", "org_admin"),
                ("group", "none"),
            ],
        )
        .await;
    assert_eq!(invited.status, StatusCode::SEE_OTHER, "{}", invited.body);
    assert_eq!(
        fx.db
            .count("SELECT count(*) FROM memberships WHERE role = 'org_admin'")
            .await,
        members_before
    );
    fx.deliver().await;
    let link = fx.mail.link("new@acme.test", "/invite?token=");
    fx.person("new@acme.test").await;
    let mut new = fx.signed_in("new@acme.test").await;
    let token = link.split("token=").nth(1).unwrap().to_owned();
    let accepted = new.submit(&link, "/invite", &[("token", &token)]).await;
    assert_eq!(accepted.status, StatusCode::SEE_OTHER, "{}", accepted.body);
    assert_eq!(
        fx.db
            .count("SELECT count(*) FROM memberships WHERE role = 'org_admin'")
            .await,
        members_before + 1
    );
}

/// T-grant-global-admin (C4, C27, T3): a global admin is appointed only through a
/// single-use link from `/admin`, accepted by one signed-in login; an org admin's forged
/// grant is refused and writes nothing.
#[tokio::test]
async fn t_grant_global_admin() {
    let fx = Fixture::start().await;
    let world = World::new(&fx).await;
    let mut root = fx.admin("root@probation.test").await;
    let globals = "SELECT count(*) FROM memberships WHERE role = 'global_admin'";
    let invited = root
        .submit(
            "/admin",
            "/admin/admins/invite",
            &[("email", "lee@probation.test")],
        )
        .await;
    assert_eq!(invited.status, StatusCode::SEE_OTHER, "{}", invited.body);
    assert_eq!(fx.db.count(globals).await, 1, "nothing granted yet");
    fx.deliver().await;
    let link = fx.mail.link("lee@probation.test", "/invite?token=");
    let token = link.split("token=").nth(1).unwrap().to_owned();

    // Lee and a second login race to accept: exactly one grant, to the accepter.
    let lee = fx.person("lee@probation.test").await;
    let other = fx.person("other@example.test").await;
    let mut lee_browser = fx.signed_in("lee@probation.test").await;
    let mut other_browser = fx.signed_in("other@example.test").await;
    let shown = lee_browser.get(&link).await;
    assert!(shown.has("global admin"), "{}", shown.body);
    let lee_csrf = lee_browser.get(&link).await.csrf();
    let other_csrf = other_browser.get(&link).await.csrf();
    let lee_form = [("token", token.as_str()), ("csrf", &lee_csrf)];
    let other_form = [("token", token.as_str()), ("csrf", &other_csrf)];
    let (a, b) = tokio::join!(
        lee_browser.post_raw("/invite", &lee_form),
        other_browser.post_raw("/invite", &other_form),
    );
    let winners = [a.status, b.status]
        .iter()
        .filter(|status| **status == StatusCode::SEE_OTHER)
        .count();
    assert_eq!(
        winners, 1,
        "{} {} / {} {}",
        a.status, a.body, b.status, b.body
    );
    assert_eq!(fx.db.count(globals).await, 2);
    let granted: i32 = sqlx::query_scalar(
        "SELECT login_id FROM memberships WHERE role = 'global_admin' AND login_id <> $1",
    )
    .bind(world.root)
    .fetch_one(&fx.db.owner)
    .await
    .unwrap();
    let winner = if a.status == StatusCode::SEE_OTHER {
        lee
    } else {
        other
    };
    assert_eq!(granted, winner);
    assert_eq!(audit_rows(&fx.db, "invitation.accept").await.len(), 1);

    // An Acme org admin cannot grant it, from the organisation page or from /admin.
    let mut ana = fx.admin("ana@acme.test").await;
    let before = state(&fx.db).await;
    let forged = ana
        .submit(
            "/keys",
            &format!("/org/{}/invitations", world.acme.id),
            &[
                ("email", "x@acme.test"),
                ("role", "global_admin"),
                ("group", "none"),
            ],
        )
        .await;
    assert!(
        [StatusCode::FORBIDDEN, StatusCode::NOT_FOUND].contains(&forged.status),
        "{}",
        forged.status
    );
    let forged = ana
        .submit("/keys", "/admin/admins/invite", &[("email", "x@acme.test")])
        .await;
    assert_eq!(forged.status, StatusCode::NOT_FOUND);
    assert_eq!(state(&fx.db).await, before, "nothing written");

    // A removed global admin's open link grants nothing (M4).
    fx.operator("kim@probation.test").await;
    let mut kim = fx.admin("kim@probation.test").await;
    let invited = kim
        .submit(
            "/admin",
            "/admin/admins/invite",
            &[("email", "late@probation.test")],
        )
        .await;
    assert_eq!(invited.status, StatusCode::SEE_OTHER, "{}", invited.body);
    fx.deliver().await;
    let link = fx.mail.link("late@probation.test", "/invite?token=");
    let token = link.split("token=").nth(1).unwrap().to_owned();
    let kim_login: i32 = sqlx::query_scalar(
        "SELECT login_id FROM sign_in_methods WHERE email = 'kim@probation.test'",
    )
    .fetch_one(&fx.db.owner)
    .await
    .unwrap();
    let removed = root
        .submit("/admin", &format!("/admin/admins/{kim_login}/remove"), &[])
        .await;
    assert_eq!(removed.status, StatusCode::SEE_OTHER, "{}", removed.body);
    let open: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM invitations WHERE created_by = $1 AND accepted_by IS NULL",
    )
    .bind(kim_login)
    .fetch_one(&fx.db.owner)
    .await
    .unwrap();
    assert_eq!(open, 0, "the removed admin's open links are gone");
    fx.person("late@probation.test").await;
    let mut late = fx.signed_in("late@probation.test").await;
    let accepted = late.submit(&link, "/invite", &[("token", &token)]).await;
    assert_ne!(accepted.status, StatusCode::SEE_OTHER, "{}", accepted.body);
    // A link of theirs that survived anyway is refused when it is taken.
    sqlx::query(
        "INSERT INTO invitations (token_hash, role, created_by, expires_at, email)
         VALUES (sha256('surviving'::bytea), 'global_admin', $1, now() + interval '1 day', 'late@probation.test')",
    )
    .bind(kim_login)
    .execute(&fx.db.owner)
    .await
    .unwrap();
    let accepted = late
        .submit(
            "/invite?token=surviving",
            "/invite",
            &[("token", "surviving")],
        )
        .await;
    assert_ne!(accepted.status, StatusCode::SEE_OTHER, "{}", accepted.body);
    assert_eq!(fx.db.count(globals).await, 2, "root and the first winner");
}

/// T-portal-global-admin-totp (C24): a global admin with a password login and no
/// authenticator is sent to set-up on `/admin` and `/fleet`, and acts nowhere there.
#[tokio::test]
async fn t_portal_global_admin_totp() {
    let fx = Fixture::start().await;
    World::new(&fx).await;
    let mut root = fx.signed_in("root@probation.test").await;
    for path in ["/admin", "/fleet"] {
        let page = root.get(path).await;
        assert_eq!(page.status, StatusCode::SEE_OTHER, "{path}: {}", page.body);
        assert_eq!(page.location.as_deref(), Some("/account#totp-heading"));
    }
    let before = state(&fx.db).await;
    let saved = root
        .submit(
            "/account",
            "/admin/retention",
            &[("activity_days", "30"), ("audit_days", "365")],
        )
        .await;
    assert_eq!(saved.status, StatusCode::SEE_OTHER);
    assert_eq!(saved.location.as_deref(), Some("/account#totp-heading"));
    assert_eq!(state(&fx.db).await, before);
    turn_totp_on(&mut root).await;
    for path in ["/admin", "/fleet"] {
        assert_eq!(root.get(path).await.status, StatusCode::OK, "{path}");
    }
}

/// T-portal-global-totp-reset (C39): a global admin resets an org admin's authenticator,
/// with an audit row.
#[tokio::test]
async fn t_portal_global_totp_reset() {
    let fx = Fixture::start().await;
    let world = World::new(&fx).await;
    fx.admin("ana@acme.test").await;
    let mut root = fx.admin("root@probation.test").await;
    let ana = world.places[&world.ana];
    let reset = root
        .submit(
            &format!("/org/{}", world.acme.id),
            &format!("/org/members/{}/totp-reset", ana.id),
            &[],
        )
        .await;
    assert_eq!(reset.status, StatusCode::SEE_OTHER, "{}", reset.body);
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM totp WHERE login_id = $1")
        .bind(world.ana)
        .fetch_one(&fx.db.owner)
        .await
        .unwrap();
    assert_eq!(left, 0);
    let rows = audit_rows(&fx.db, "totp.reset").await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, Some(world.root));
    assert!(rows[0].1);
    assert_eq!(rows[0].3, format!("login:{}", world.ana));
}

/// T-portal-xss-admin (T13): an organisation's name is escaped in the global admin's
/// organisation list, under the CSP header.
#[tokio::test]
async fn t_portal_xss_admin() {
    let fx = Fixture::start().await;
    World::new(&fx).await;
    fx.db.org("<script>alert(1)</script>").await;
    let mut root = fx.admin("root@probation.test").await;
    let page = root.get("/admin").await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(
        page.has("<tr><td>&#60;script&#62;alert(1)&#60;/script&#62;</td>"),
        "{}",
        page.body
    );
    assert!(!page.has("<script>alert(1)"), "{}", page.body);
    assert_eq!(
        page.csp.as_deref(),
        Some("default-src 'self'; frame-ancestors 'none'")
    );
}

/// T-portal-last-global-admin (C90, T21): the last global admin cannot be removed; two
/// admins removing each other at once leave one; the last one cannot delete their own
/// login.
#[tokio::test]
async fn t_portal_last_global_admin() {
    let fx = Fixture::start().await;
    let world = World::new(&fx).await;
    let globals = "SELECT count(*) FROM memberships WHERE role = 'global_admin'";
    let mut root = fx.admin("root@probation.test").await;
    let alone = root
        .submit(
            "/admin",
            &format!("/admin/admins/{}/remove", world.root),
            &[],
        )
        .await;
    assert_eq!(alone.status, StatusCode::CONFLICT, "{}", alone.body);
    assert!(alone.has("at least one global admin"), "{}", alone.body);
    assert_eq!(fx.db.count(globals).await, 1);

    let kim = fx.operator("kim@probation.test").await;
    let mut kim_browser = fx.admin("kim@probation.test").await;
    let root_csrf = root.get("/admin").await.csrf();
    let kim_csrf = kim_browser.get("/admin").await.csrf();
    let root_removes_kim = format!("/admin/admins/{kim}/remove");
    let kim_removes_root = format!("/admin/admins/{}/remove", world.root);
    let root_form = [("csrf", root_csrf.as_str())];
    let kim_form = [("csrf", kim_csrf.as_str())];
    let (a, b) = tokio::join!(
        root.post_raw(&root_removes_kim, &root_form),
        kim_browser.post_raw(&kim_removes_root, &kim_form),
    );
    let done = [a.status, b.status]
        .iter()
        .filter(|status| **status == StatusCode::SEE_OTHER)
        .count();
    assert_eq!(done, 1, "{} {} / {} {}", a.status, a.body, b.status, b.body);
    assert_eq!(fx.db.count(globals).await, 1, "one admin remains");

    // The one left deletes their own login: refused.
    let (mut last, last_login) = if a.status == StatusCode::SEE_OTHER {
        (root, world.root)
    } else {
        (kim_browser, kim)
    };
    let deleted = last
        .submit("/account", "/account/delete", &[("confirm", "delete")])
        .await;
    assert_eq!(deleted.status, StatusCode::CONFLICT, "{}", deleted.body);
    let live: bool = sqlx::query_scalar("SELECT deleted_at IS NULL FROM logins WHERE id = $1")
        .bind(last_login)
        .fetch_one(&fx.db.owner)
        .await
        .unwrap();
    assert!(live);
}

/// T-portal-suspended-banner (C64, C78): an org admin and a member of a suspended
/// organisation sign in read-only with the banner, and every POST into it is refused
/// with nothing written.
#[tokio::test]
async fn t_portal_suspended_banner() {
    let fx = Fixture::start().await;
    let world = World::new(&fx).await;
    let mut ana = fx.admin("ana@acme.test").await;
    let mut mia = fx.signed_in("mia@acme.test").await;
    create_key(&mut mia, "mia laptop").await;
    let mia_key = key_id(&fx.db, "mia laptop").await;
    let mut root = fx.admin("root@probation.test").await;
    let suspended = root
        .submit(
            "/admin",
            &format!("/admin/orgs/{}/suspend", world.acme.id),
            &[],
        )
        .await;
    assert_eq!(
        suspended.status,
        StatusCode::SEE_OTHER,
        "{}",
        suspended.body
    );

    let mia_place = world.places[&world.mia];
    let id_for = |path: &str| -> String {
        if path.starts_with("/keys/") {
            mia_key.to_string()
        } else if path.starts_with("/policy/") {
            layer_id(world.acme)
        } else if path.starts_with("/org/members/") {
            mia_place.id.to_string()
        } else {
            world.acme.id.to_string()
        }
    };
    let routes: Vec<&str> = portal::route_table()
        .into_iter()
        .filter(|(method, path)| {
            *method == "POST"
                && ["/keys", "/policy/", "/org"]
                    .iter()
                    .any(|prefix| path.starts_with(prefix))
        })
        .map(|(_, path)| path)
        .collect();
    assert!(routes.len() >= 25, "{routes:?}");
    for browser in [&mut ana, &mut mia] {
        let keys = browser.get("/keys").await;
        assert_eq!(keys.status, StatusCode::OK);
        assert!(keys.has("This organisation is suspended"), "{}", keys.body);
        let before = state(&fx.db).await;
        for path in &routes {
            let concrete = path
                .replace("{id}", &id_for(path))
                .replace("{org}", &id_for(path))
                .replace("{registry}", "999999");
            let answer = browser
                .submit(
                    "/keys",
                    &concrete,
                    &[
                        ("name", "x"),
                        ("role", "member"),
                        ("group", "none"),
                        ("cidr", "192.0.2.0/24"),
                        ("action", "save"),
                        ("email", "x@acme.test"),
                        ("layer", &layer_id(world.acme)),
                        ("file", SAMPLE),
                        ("identity_field", "uri_san_membership_uuid"),
                        ("expected_ocsp_url", "https://ocsp.example.test/status"),
                        ("root_pem", "forged"),
                        ("chain_pem", "forged"),
                        ("phase", "good"),
                        ("ecosystem", "npm"),
                        ("target_url", "https://registry.npmjs.org/"),
                        ("purpose", "registry"),
                    ],
                )
                .await;
            assert!(
                [StatusCode::FORBIDDEN, StatusCode::NOT_FOUND].contains(&answer.status),
                "{concrete}: {} {}",
                answer.status,
                answer.body
            );
        }
        assert_eq!(state(&fx.db).await, before, "nothing written");
    }
}

/// T-sync-org-suspended (C64, C78): a suspended organisation's keys answer 401 within
/// one interval, with a `refused_suspended` row.
#[tokio::test]
async fn t_sync_org_suspended() {
    let fx = Fixture::start().await;
    let world = World::new(&fx).await;
    let firewall = fx.firewall().await;
    let mut mia = fx.signed_in("mia@acme.test").await;
    let key = create_key(&mut mia, "mia laptop").await;
    assert_eq!(status_of(&firewall, &key).await, StatusCode::OK);
    let mut root = fx.admin("root@probation.test").await;
    root.submit(
        "/admin",
        &format!("/admin/orgs/{}/suspend", world.acme.id),
        &[],
    )
    .await;
    answers_within_interval(&firewall, &key, StatusCode::UNAUTHORIZED, "suspended").await;
    activity_row(&fx.db, "mia laptop", "refused_suspended").await;
}

/// T-sync-org-reactivated (C64): after re-activation the keys answer 200 within one
/// interval, a key requested during the suspension included.
#[tokio::test]
async fn t_sync_org_reactivated() {
    let fx = Fixture::start().await;
    let world = World::new(&fx).await;
    let firewall = fx.firewall().await;
    let mut mia = fx.signed_in("mia@acme.test").await;
    let key = create_key(&mut mia, "mia laptop").await;
    assert_eq!(status_of(&firewall, &key).await, StatusCode::OK);
    let mut root = fx.admin("root@probation.test").await;
    root.submit(
        "/admin",
        &format!("/admin/orgs/{}/suspend", world.acme.id),
        &[],
    )
    .await;
    answers_within_interval(&firewall, &key, StatusCode::UNAUTHORIZED, "suspended").await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(status_of(&firewall, &key).await, StatusCode::UNAUTHORIZED);
    let active = root
        .submit(
            "/admin",
            &format!("/admin/orgs/{}/activate", world.acme.id),
            &[],
        )
        .await;
    assert_eq!(active.status, StatusCode::SEE_OTHER, "{}", active.body);
    answers_within_interval(&firewall, &key, StatusCode::OK, "re-activated").await;
}

/// T-portal-admin-personal (C65): suspend, delete, revoke keys and reset the
/// authenticator of a personal account each work and each writes an audit row.
#[tokio::test]
async fn t_portal_admin_personal() {
    let fx = Fixture::start().await;
    let world = World::new(&fx).await;
    let mut pat = fx.admin("pat@home.test").await;
    create_key(&mut pat, "pat laptop").await;
    let mut root = fx.admin("root@probation.test").await;
    let id = world.pat_personal.id;
    let page = root.get("/admin").await;
    assert!(page.has("pat@home.test"), "{}", page.body);
    // Deleting and revoking ask first (mockup: destructive confirm).
    for (action, heading) in [
        ("delete", "Delete pat@home.test&#39;s personal account?"),
        ("revoke-keys", "Revoke all 1 of pat@home.test&#39;s keys?"),
    ] {
        let path = format!("/admin/personal/{id}/{action}");
        assert!(page.has(&format!("href=\"{path}\"")), "{}", page.body);
        let asked = root.get(&path).await;
        assert!(asked.has(heading), "{}", asked.body);
        assert!(asked.has(&format!("action=\"{path}\"")), "{}", asked.body);
    }

    let mut act = async |action: &str| {
        let done = root
            .submit("/admin", &format!("/admin/personal/{id}/{action}"), &[])
            .await;
        assert_eq!(
            done.status,
            StatusCode::SEE_OTHER,
            "{action}: {}",
            done.body
        );
    };
    act("suspend").await;
    act("activate").await;
    act("revoke-keys").await;
    act("totp-reset").await;
    act("delete").await;

    let (status, deleted): (String, bool) = sqlx::query_as(
        "SELECT status, deleted_at IS NOT NULL FROM personal_accounts WHERE id = $1",
    )
    .bind(id as i32)
    .fetch_one(&fx.db.owner)
    .await
    .unwrap();
    assert_eq!((status.as_str(), deleted), ("active", true));
    let live_keys: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM keys WHERE place_kind = 'personal' AND place_id = $1 AND revoked_at IS NULL",
    )
    .bind(id as i32)
    .fetch_one(&fx.db.owner)
    .await
    .unwrap();
    assert_eq!(live_keys, 0);
    let totp: i64 = sqlx::query_scalar("SELECT count(*) FROM totp WHERE login_id = $1")
        .bind(world.pat)
        .fetch_one(&fx.db.owner)
        .await
        .unwrap();
    assert_eq!(totp, 0);
    for action in [
        "personal.suspend",
        "personal.activate",
        "keys.revoke_all",
        "totp.reset",
        "personal.delete",
    ] {
        let rows = audit_rows(&fx.db, action).await;
        assert_eq!(rows.len(), 1, "{action}: {rows:?}");
        assert_eq!(rows[0].0, Some(world.root), "{action}");
        assert!(rows[0].1, "{action}");
    }
}

/// T-sync-personal-deleted-restored (C33, C65, C73): a personal account a global admin
/// deletes stops within one interval and answers 200 within one interval after its
/// restore; one deleted on day 0 is gone on day 31.
#[tokio::test]
async fn t_sync_personal_deleted_restored() {
    let fx = Fixture::start().await;
    let world = World::new(&fx).await;
    let firewall = fx.firewall().await;
    let mut pat = fx.signed_in("pat@home.test").await;
    let key = create_key(&mut pat, "pat laptop").await;
    assert_eq!(status_of(&firewall, &key).await, StatusCode::OK);
    let mut root = fx.admin("root@probation.test").await;
    let id = world.pat_personal.id;
    root.submit("/admin", &format!("/admin/personal/{id}/delete"), &[])
        .await;
    answers_within_interval(&firewall, &key, StatusCode::UNAUTHORIZED, "deleted").await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(status_of(&firewall, &key).await, StatusCode::UNAUTHORIZED);
    let restored = root
        .submit("/admin", &format!("/admin/personal/{id}/restore"), &[])
        .await;
    assert_eq!(restored.status, StatusCode::SEE_OTHER, "{}", restored.body);
    answers_within_interval(&firewall, &key, StatusCode::OK, "restored").await;

    // Day 0, then day 31 on the fake clock.
    root.submit("/admin", &format!("/admin/personal/{id}/delete"), &[])
        .await;
    sqlx::query(
        "UPDATE personal_accounts SET deleted_at = now() - interval '31 days',
                restore_until = now() - interval '1 day' WHERE id = $1",
    )
    .bind(id as i32)
    .execute(&fx.db.owner)
    .await
    .unwrap();
    accounts::purge(&fx.db.app).await.unwrap();
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM personal_accounts WHERE id = $1")
        .bind(id as i32)
        .fetch_one(&fx.db.owner)
        .await
        .unwrap();
    assert_eq!(left, 0);
}

/// T-sync-personal-suspended (C65): a suspended personal account's keys answer 401 with
/// a `refused_suspended` row within one interval, and 200 after re-activation.
#[tokio::test]
async fn t_sync_personal_suspended() {
    let fx = Fixture::start().await;
    let world = World::new(&fx).await;
    let firewall = fx.firewall().await;
    let mut pat = fx.signed_in("pat@home.test").await;
    let key = create_key(&mut pat, "pat laptop").await;
    assert_eq!(status_of(&firewall, &key).await, StatusCode::OK);
    let mut root = fx.admin("root@probation.test").await;
    let id = world.pat_personal.id;
    root.submit("/admin", &format!("/admin/personal/{id}/suspend"), &[])
        .await;
    answers_within_interval(&firewall, &key, StatusCode::UNAUTHORIZED, "suspended").await;
    activity_row(&fx.db, "pat laptop", "refused_suspended").await;
    root.submit("/admin", &format!("/admin/personal/{id}/activate"), &[])
        .await;
    answers_within_interval(&firewall, &key, StatusCode::OK, "re-activated").await;
}

fn input<'a>(page: &'a Page, id: &str) -> &'a str {
    between(&page.body, &format!("id=\"{id}\""), ">")
}

/// T-portal-limits (C28, C51, C67): a fresh install reports the seeded defaults; the
/// defaults and a per-organisation override are saved, and the override can go back to
/// the default.
#[tokio::test]
async fn t_portal_limits() {
    let fx = Fixture::start().await;
    let world = World::new(&fx).await;
    let mut root = fx.admin("root@probation.test").await;
    let page = root.get("/admin").await;
    for (id, value) in [
        ("limit-personal-rate", "1200"),
        ("limit-personal-keys", "5"),
        ("limit-org-rate", "6000"),
        ("limit-org-keys", "20"),
        ("limit-org-service", "50"),
    ] {
        assert!(
            input(&page, id).contains(&format!("value=\"{value}\"")),
            "{id}: {}",
            input(&page, id)
        );
    }
    let refused = root
        .submit(
            "/admin",
            "/admin/limits",
            &[("kind", "personal"), ("rate", "60"), ("keys", "0")],
        )
        .await;
    assert_eq!(refused.status, StatusCode::CONFLICT, "{}", refused.body);
    assert!(refused.has("at least 1"), "{}", refused.body);
    let saved = root
        .submit(
            "/admin",
            "/admin/limits",
            &[("kind", "personal"), ("rate", "60"), ("keys", "3")],
        )
        .await;
    assert_eq!(saved.status, StatusCode::SEE_OTHER, "{}", saved.body);
    let page = root.get("/admin").await;
    assert!(input(&page, "limit-personal-rate").contains("value=\"60\""));
    assert!(input(&page, "limit-personal-keys").contains("value=\"3\""));

    let own = root
        .submit(
            "/admin",
            &format!("/admin/limits/orgs/{}", world.acme.id),
            &[("rate", "2000"), ("keys", "10"), ("service", "100")],
        )
        .await;
    assert_eq!(own.status, StatusCode::SEE_OTHER, "{}", own.body);
    let row: (i32, i32, Option<i32>) = sqlx::query_as(
        "SELECT rate_per_min, max_keys, max_service_keys FROM limits WHERE scope_kind = 'org' AND scope_id = $1",
    )
    .bind(world.acme.id as i32)
    .fetch_one(&fx.db.owner)
    .await
    .unwrap();
    assert_eq!(row, (2000, 10, Some(100)));
    let page = root.get("/admin").await;
    assert!(
        input(&page, &format!("limit-{}-rate", world.acme.id)).contains("value=\"2000\""),
        "{}",
        page.body
    );
    let back = root
        .submit(
            "/admin",
            &format!("/admin/limits/orgs/{}/reset", world.acme.id),
            &[],
        )
        .await;
    assert_eq!(back.status, StatusCode::SEE_OTHER, "{}", back.body);
    assert_eq!(
        fx.db
            .count("SELECT count(*) FROM limits WHERE scope_id IS NOT NULL")
            .await,
        0
    );

    // No limit on service keys survives a re-save of the page as rendered.
    let blank = root
        .submit(
            "/admin",
            "/admin/limits",
            &[
                ("kind", "org"),
                ("rate", "6000"),
                ("keys", "20"),
                ("service", ""),
            ],
        )
        .await;
    assert_eq!(blank.status, StatusCode::SEE_OTHER, "{}", blank.body);
    let page = root.get("/admin").await;
    assert!(
        input(&page, "limit-org-service").contains("value=\"\""),
        "{}",
        input(&page, "limit-org-service")
    );
    let again = root
        .submit(
            "/admin",
            "/admin/limits",
            &[
                ("kind", "org"),
                ("rate", "6000"),
                ("keys", "20"),
                ("service", ""),
            ],
        )
        .await;
    assert_eq!(again.status, StatusCode::SEE_OTHER, "{}", again.body);
    assert_eq!(
        fx.db
            .count(
                "SELECT count(*) FROM limits WHERE scope_kind = 'org' AND max_service_keys IS NULL"
            )
            .await,
        1
    );
    // A service value that is no number is refused, not taken as "no limit".
    let before = state(&fx.db).await;
    let typo = root
        .submit(
            "/admin",
            "/admin/limits",
            &[
                ("kind", "org"),
                ("rate", "6000"),
                ("keys", "20"),
                ("service", "5O"),
            ],
        )
        .await;
    assert_eq!(typo.status, StatusCode::CONFLICT, "{}", typo.body);
    assert_eq!(state(&fx.db).await, before);
    // A new organisation row starts from the platform default.
    assert!(input(&root.get("/admin").await, "own-rate").contains("value=\"6000\""));
}

/// T-sync-limits-change (C28, C67, K2): an organisation's new limit applies within one
/// interval with zero `sync/lookup` calls: the `limits` row updates the cached entry in
/// place.
#[tokio::test]
async fn t_sync_limits_change() {
    let fx = Fixture::start().await;
    let world = World::new(&fx).await;
    // The sync API behind a counter of `sync/lookup` calls.
    let lookups = Arc::new(AtomicUsize::new(0));
    let counted = lookups.clone();
    let state = Arc::new(probation_server::sync::SyncState::new(
        fx.db.app.clone(),
        Vec::new(),
        Some(probation_server::accounts::SecretBox::new(common::SECRET_KEY)),
    ));
    let router = probation_server::build_router(state).layer(axum::middleware::from_fn(
        move |incoming: axum::extract::Request, next: axum::middleware::Next| {
            let counted = counted.clone();
            async move {
                if incoming.uri().path() == "/api/v1/sync/lookup" {
                    counted.fetch_add(1, Ordering::SeqCst);
                }
                next.run(incoming).await
            }
        },
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = url::Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });
    let token = register(&fx.db, "fw").await.1;
    let firewall = fx.firewall_with(server, &token).await;
    let mut mia = fx.signed_in("mia@acme.test").await;
    let key = create_key(&mut mia, "mia laptop").await;
    assert_eq!(status_of(&firewall, &key).await, StatusCode::OK);
    let looked_up = lookups.load(Ordering::SeqCst);
    assert_eq!(looked_up, 1);

    let mut root = fx.admin("root@probation.test").await;
    let own = root
        .submit(
            "/admin",
            &format!("/admin/limits/orgs/{}", world.acme.id),
            &[("rate", "2"), ("keys", "20"), ("service", "50")],
        )
        .await;
    assert_eq!(own.status, StatusCode::SEE_OTHER, "{}", own.body);
    let committed = std::time::Instant::now();
    loop {
        let status = status_of(&firewall, &key).await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            break;
        }
        assert_eq!(status, StatusCode::OK);
        assert!(
            committed.elapsed() <= Duration::from_secs(2),
            "the new limit within one interval"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(lookups.load(Ordering::SeqCst), looked_up, "no lookup");
}

/// T-retention (C26, C68, T17): a fresh install reports 90 and 365 days; 6 days is
/// refused; a 91-day activity row is pruned while a 91-day audit row is kept; the
/// change is audited.
#[tokio::test]
async fn t_retention() {
    let fx = Fixture::start().await;
    let world = World::new(&fx).await;
    let mut root = fx.admin("root@probation.test").await;
    let page = root.get("/admin").await;
    assert!(input(&page, "retention-activity").contains("value=\"90\""));
    assert!(input(&page, "retention-audit").contains("value=\"365\""));
    let before = state(&fx.db).await;
    let refused = root
        .submit(
            "/admin",
            "/admin/retention",
            &[("activity_days", "6"), ("audit_days", "365")],
        )
        .await;
    assert_eq!(refused.status, StatusCode::CONFLICT, "{}", refused.body);
    assert!(refused.has("at least 7 days"), "{}", refused.body);
    assert_eq!(state(&fx.db).await, before);

    // A firewall's 91-day-old activity row and a 91-day-old audit row.
    let (firewall, _) = register(&fx.db, "fw").await;
    let mut mia = fx.signed_in("mia@acme.test").await;
    create_key(&mut mia, "mia laptop").await;
    let key = key_id(&fx.db, "mia laptop").await;
    for (event, days) in [("old", 91), ("new", 1)] {
        sqlx::query(
            "INSERT INTO activity (event_id, at, firewall_id, place_kind, place_id, key_id, layer, result, rule)
             VALUES ($1, now() - make_interval(days => $2), $3, 'user', $4, $5, 'org', 'blocked', 'rule')",
        )
        .bind(event)
        .bind(days)
        .bind(firewall)
        .bind(world.places[&world.mia].id as i32)
        .bind(key)
        .execute(&fx.db.owner)
        .await
        .unwrap();
    }
    sqlx::query(
        "INSERT INTO audit_log (at, actor_is_global_admin, org_id, action, subject)
         VALUES (now() - interval '91 days', false, $1, 'old.action', 'x')",
    )
    .bind(world.acme.id as i32)
    .execute(&fx.db.owner)
    .await
    .unwrap();
    probation_server::audit::prune(&fx.db.app).await.unwrap();
    let events: Vec<String> = sqlx::query_scalar("SELECT event_id FROM activity ORDER BY event_id")
        .fetch_all(&fx.db.owner)
        .await
        .unwrap();
    assert_eq!(events, ["new"]);
    assert_eq!(audit_rows(&fx.db, "old.action").await.len(), 1);

    let saved = root
        .submit(
            "/admin",
            "/admin/retention",
            &[("activity_days", "30"), ("audit_days", "400")],
        )
        .await;
    assert_eq!(saved.status, StatusCode::SEE_OTHER, "{}", saved.body);
    let rows = audit_rows(&fx.db, "retention.set").await;
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].4,
        Some(serde_json::json!({"activity_days": 90, "audit_days": 365}))
    );
    assert_eq!(
        rows[0].5,
        Some(serde_json::json!({"activity_days": 30, "audit_days": 400}))
    );

    // At most 100 years (M5), in the form and in the table.
    let huge = root
        .submit(
            "/admin",
            "/admin/retention",
            &[("activity_days", "36501"), ("audit_days", "400")],
        )
        .await;
    assert_eq!(huge.status, StatusCode::CONFLICT, "{}", huge.body);
    assert!(huge.has("at most 36500 days"), "{}", huge.body);
    for sql in [
        "UPDATE platform_settings SET activity_retention_days = 36501",
        "UPDATE orgs SET audit_retention_days = 36501",
    ] {
        assert!(
            sqlx::query(sql).execute(&fx.db.owner).await.is_err(),
            "{sql}"
        );
    }
    // One prune failing does not skip the other: with the activity prune refused, the
    // audit prune still runs.
    sqlx::query(
        "INSERT INTO audit_log (at, actor_is_global_admin, org_id, action, subject)
         VALUES (now() - interval '500 days', false, $1, 'ancient.action', 'x')",
    )
    .bind(world.acme.id as i32)
    .execute(&fx.db.owner)
    .await
    .unwrap();
    sqlx::query("REVOKE DELETE ON activity FROM probation_app")
        .execute(&fx.db.owner)
        .await
        .unwrap();
    assert!(probation_server::audit::prune(&fx.db.app).await.is_err());
    assert_eq!(
        audit_rows(&fx.db, "ancient.action").await.len(),
        0,
        "the audit prune ran"
    );
}

async fn range_id(db: &Db, cidr: &str) -> i32 {
    sqlx::query_scalar("SELECT id FROM org_ip_ranges WHERE cidr = $1::cidr")
        .bind(cidr)
        .fetch_one(&db.owner)
        .await
        .unwrap()
}

/// T-portal-ranges-approve (C77, C87): the operator sees a waiting range, approves it
/// (writing `ranges`), refuses one with a reason the org admin sees, and an approval
/// overlapping another approved range is refused.
#[tokio::test]
async fn t_portal_ranges_approve() {
    let fx = Fixture::start().await;
    let world = World::new(&fx).await;
    let mut ana = fx.admin("ana@acme.test").await;
    let org_page = format!("/org/{}", world.acme.id);
    let add = format!("/org/{}/ranges", world.acme.id);
    for cidr in ["198.51.100.16/28", "198.51.100.0/24", "203.0.113.0/24"] {
        let added = ana.submit(&org_page, &add, &[("cidr", cidr)]).await;
        assert_eq!(added.status, StatusCode::SEE_OTHER, "{}", added.body);
    }
    let mut root = fx.admin("root@probation.test").await;
    let page = root.get("/admin").await;
    assert!(page.has("198.51.100.16/28"), "{}", page.body);
    assert!(page.has("ana@acme.test"), "who asked: {}", page.body);

    let first = range_id(&fx.db, "198.51.100.16/28").await;
    let ranges_rows = "SELECT count(*) FROM change_log WHERE kind = 'ranges'";
    let approved = root
        .submit("/admin", &format!("/admin/ranges/{first}/approve"), &[])
        .await;
    assert_eq!(approved.status, StatusCode::SEE_OTHER, "{}", approved.body);
    assert_eq!(fx.db.count(ranges_rows).await, 1);
    let rows = audit_rows(&fx.db, "range.approve").await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].2, Some(world.acme.id as i32), "in Acme's log");

    let overlapping = range_id(&fx.db, "198.51.100.0/24").await;
    let refused = root
        .submit(
            "/admin",
            &format!("/admin/ranges/{overlapping}/approve"),
            &[],
        )
        .await;
    assert_eq!(refused.status, StatusCode::CONFLICT, "{}", refused.body);
    assert!(refused.has("overlaps"), "{}", refused.body);
    assert_eq!(fx.db.count(ranges_rows).await, 1);

    let third = range_id(&fx.db, "203.0.113.0/24").await;
    let turned_down = root
        .submit(
            "/admin",
            &format!("/admin/ranges/{third}/refuse"),
            &[("reason", "not your office")],
        )
        .await;
    assert_eq!(
        turned_down.status,
        StatusCode::SEE_OTHER,
        "{}",
        turned_down.body
    );
    let seen = ana.get(&org_page).await;
    assert!(seen.has("Refused by operator"), "{}", seen.body);
    assert!(seen.has("not your office"), "{}", seen.body);

    // The purge erases a global admin who approved a range and sent an invitation; the
    // range stays approved (M1, C33).
    ana.submit(&org_page, &add, &[("cidr", "192.0.2.0/24")])
        .await;
    let fourth = range_id(&fx.db, "192.0.2.0/24").await;
    let kim = fx.operator("kim@probation.test").await;
    let mut kim_browser = fx.admin("kim@probation.test").await;
    let approved = kim_browser
        .submit("/admin", &format!("/admin/ranges/{fourth}/approve"), &[])
        .await;
    assert_eq!(approved.status, StatusCode::SEE_OTHER, "{}", approved.body);
    kim_browser
        .submit(
            "/admin",
            "/admin/admins/invite",
            &[("email", "x@probation.test")],
        )
        .await;
    // ... and started a settings rollout (S7-1).
    let (firewall, _) = register(&fx.db, "fw").await;
    let pushed = push_settings(&mut kim_browser, &[firewall], "sync_interval_seconds = 30").await;
    assert_eq!(pushed.status, StatusCode::SEE_OTHER, "{}", pushed.body);
    let rollout = last_rollout(&fx.db).await;
    sqlx::query(
        "UPDATE logins SET deleted_at = now() - interval '31 days', restore_until = now() - interval '1 day'
         WHERE id = $1",
    )
    .bind(kim)
    .execute(&fx.db.owner)
    .await
    .unwrap();
    assert_eq!(accounts::purge(&fx.db.app).await.unwrap().0, 1);
    let still: bool =
        sqlx::query_scalar("SELECT approved_by IS NOT NULL FROM org_ip_ranges WHERE id = $1")
            .bind(fourth)
            .fetch_one(&fx.db.owner)
            .await
            .unwrap();
    assert!(still, "the range stays approved");
    let creator: Option<i32> =
        sqlx::query_scalar("SELECT created_by FROM settings_rollouts WHERE id = $1")
            .bind(rollout)
            .fetch_one(&fx.db.owner)
            .await
            .unwrap();
    assert_eq!(creator, None, "the rollout stays, its creator erased");
    assert!(root.get("/admin").await.has("192.0.2.0/24"));
}

/// T-sync-ranges (C30, C77, C87): an approval reaches the firewall within one interval;
/// deleting the approved range lifts the 403 within one interval; after the
/// organisation holding an approved range is purged on day 31, a key of another place
/// from that range answers 200 within one interval.
#[tokio::test]
async fn t_sync_ranges() {
    let fx = Fixture::start().await;
    let world = World::new(&fx).await;
    let firewall = fx.firewall().await;
    // Every request the firewall sees comes from 127.0.0.1.
    let mut gus = fx.signed_in("gus@globex.test").await;
    let globex_key = create_key(&mut gus, "globex laptop").await;
    assert_eq!(status_of(&firewall, &globex_key).await, StatusCode::OK);
    let mut ana = fx.admin("ana@acme.test").await;
    let org_page = format!("/org/{}", world.acme.id);
    let add = format!("/org/{}/ranges", world.acme.id);
    ana.submit(&org_page, &add, &[("cidr", "127.0.0.1/32")])
        .await;
    let range = range_id(&fx.db, "127.0.0.1/32").await;
    let mut root = fx.admin("root@probation.test").await;
    root.submit("/admin", &format!("/admin/ranges/{range}/approve"), &[])
        .await;
    answers_within_interval(&firewall, &globex_key, StatusCode::FORBIDDEN, "approved").await;
    let deleted = root
        .submit("/admin", &format!("/admin/ranges/{range}/delete"), &[])
        .await;
    assert_eq!(deleted.status, StatusCode::SEE_OTHER, "{}", deleted.body);
    answers_within_interval(&firewall, &globex_key, StatusCode::OK, "deleted").await;

    ana.submit(&org_page, &add, &[("cidr", "127.0.0.1/32")])
        .await;
    let range = range_id(&fx.db, "127.0.0.1/32").await;
    root.submit("/admin", &format!("/admin/ranges/{range}/approve"), &[])
        .await;
    answers_within_interval(&firewall, &globex_key, StatusCode::FORBIDDEN, "approved").await;
    ana.submit(
        &org_page,
        &format!("/org/{}/delete", world.acme.id),
        &[("confirm", "Acme")],
    )
    .await;
    sqlx::query(
        "UPDATE orgs SET deleted_at = now() - interval '31 days', restore_until = now() - interval '1 day'
         WHERE id = $1",
    )
    .bind(world.acme.id as i32)
    .execute(&fx.db.owner)
    .await
    .unwrap();
    accounts::purge(&fx.db.app).await.unwrap();
    answers_within_interval(&firewall, &globex_key, StatusCode::OK, "purged").await;
}

/// T-fleet-unhealthy (C22, C69): 3 missed check-ins, or a report marking npm, PyPI or
/// OSV unreachable, shows "unhealthy"; with a 300 s period only after 900 s; the page
/// shows each firewall's reported version.
#[tokio::test]
async fn t_fleet_unhealthy() {
    let fx = Fixture::start().await;
    World::new(&fx).await;
    let (id, token) = register(&fx.db, "fw-eu-1").await;
    let mut root = fx.admin("root@probation.test").await;
    let never = root.get("/fleet").await;
    assert!(fleet_row(&never, id).contains("never"), "{}", never.body);

    check_in(&fx, &token, report(0, None, 60)).await;
    let page = root.get("/fleet").await;
    let row = fleet_row(&page, id);
    assert!(row.contains("Healthy"), "{row}");
    assert!(row.contains("9.9.9"), "{row}");

    let set_seen = async |seconds: i32| {
        sqlx::query(
            "UPDATE firewalls SET last_seen_at = now() - make_interval(secs => $2) WHERE id = $1",
        )
        .bind(id)
        .bind(seconds)
        .execute(&fx.db.owner)
        .await
        .unwrap();
    };
    set_seen(181).await;
    let row = fleet_row(&root.get("/fleet").await, id);
    assert!(row.contains("Unhealthy: missed 3 check-ins"), "{row}");

    let mut unreachable = report(0, None, 60);
    unreachable.status.upstreams.osv = Reachability::Unreachable;
    check_in(&fx, &token, unreachable).await;
    let row = fleet_row(&root.get("/fleet").await, id);
    assert!(row.contains("Unhealthy: cannot reach OSV"), "{row}");

    check_in(&fx, &token, report(0, None, 300)).await;
    set_seen(600).await;
    let row = fleet_row(&root.get("/fleet").await, id);
    assert!(
        row.contains("Healthy") && !row.contains("Unhealthy"),
        "{row}"
    );
    set_seen(901).await;
    let row = fleet_row(&root.get("/fleet").await, id);
    assert!(row.contains("Unhealthy: missed 3 check-ins"), "{row}");

    // A reported period is taken as at most a day.
    check_in(&fx, &token, report(0, None, 1_000_000_000_000_000_000)).await;
    set_seen(3 * 86_400 + 1).await;
    let row = fleet_row(&root.get("/fleet").await, id);
    assert!(row.contains("Unhealthy: missed 3 check-ins"), "{row}");

    // A rollout step times out after 3 × the reported period, taken as 1 s to 1 day:
    // the huge period neither breaks the page nor keeps the step waiting forever.
    let pushed = push_settings(&mut root, &[id], "sync_interval_seconds = 30").await;
    assert_eq!(pushed.status, StatusCode::SEE_OTHER, "{}", pushed.body);
    let huge = last_rollout(&fx.db).await;
    assert_eq!(root.get("/fleet").await.status, StatusCode::OK);
    assert_eq!(rollout_state(&fx.db, huge).await.1, ["sent"]);
    sqlx::query("UPDATE settings_rollout_steps SET sent_at = now() - make_interval(secs => 3 * 86400 + 1) WHERE rollout_id = $1")
        .bind(huge)
        .execute(&fx.db.owner)
        .await
        .unwrap();
    assert_eq!(root.get("/fleet").await.status, StatusCode::OK);
    assert_eq!(rollout_state(&fx.db, huge).await.1, ["timed_out"]);
    // A period of 0 is taken as 1 s: a step just sent is not timed out at once.
    check_in(&fx, &token, report(0, None, 0)).await;
    push_settings(&mut root, &[id], "sync_interval_seconds = 40").await;
    let zero = last_rollout(&fx.db).await;
    assert_eq!(root.get("/fleet").await.status, StatusCode::OK);
    assert_eq!(rollout_state(&fx.db, zero).await.1, ["sent"]);
}

/// T-fleet-settings-push (C22, C35, C70, C71, C118): settings for two firewalls reach
/// the second only after the first reports success; a failed apply shows its error; a
/// push naming a local-only setting is refused and nothing is written.
#[tokio::test]
async fn t_fleet_settings_push() {
    let fx = Fixture::start().await;
    World::new(&fx).await;
    let (one, one_token) = register(&fx.db, "fw-eu-1").await;
    let (two, two_token) = register(&fx.db, "fw-eu-2").await;
    let mut root = fx.admin("root@probation.test").await;

    let before = state(&fx.db).await;
    for local in [
        "listen = \"0.0.0.0:1\"",
        "public_url = \"https://evil.example\"",
        "siem_url = \"https://evil.example\"",
        "siem_auth_header = \"x\"",
        "data_dir = \"/tmp\"",
        "tls_cert_path = \"/x\"",
        "[management]\nurl = \"https://evil.example\"",
        "not toml at all [",
    ] {
        let refused = push_settings(&mut root, &[one, two], local).await;
        assert_eq!(
            refused.status,
            StatusCode::CONFLICT,
            "{local}: {}",
            refused.body
        );
    }
    // The firewall's own list, shared through probation-policy (C35, C118).
    for key in probation_policy::LOCAL_ONLY_SETTINGS {
        let refused = push_settings(&mut root, &[one], &format!("{key} = \"x\"")).await;
        assert_eq!(
            refused.status,
            StatusCode::CONFLICT,
            "{key}: {}",
            refused.body
        );
    }
    assert_eq!(state(&fx.db).await, before, "nothing written");

    let pushed = push_settings(&mut root, &[one, two], "sync_interval_seconds = 30").await;
    assert_eq!(pushed.status, StatusCode::SEE_OTHER, "{}", pushed.body);
    let first = check_in(&fx, &one_token, report(0, None, 60)).await;
    let push = first
        .settings
        .expect("the first firewall gets the settings");
    assert_eq!(push.toml, "sync_interval_seconds = 30");
    assert!(
        check_in(&fx, &two_token, report(0, None, 60))
            .await
            .settings
            .is_none()
    );
    let waiting = root.get("/fleet").await;
    assert!(waiting.has("Waiting"), "{}", waiting.body);
    // The first applies them and restarts.
    assert!(
        check_in(&fx, &one_token, report(push.revision, None, 60))
            .await
            .settings
            .is_none()
    );
    let second = check_in(&fx, &two_token, report(0, None, 60)).await;
    assert_eq!(
        second.settings.map(|push| push.toml).as_deref(),
        Some("sync_interval_seconds = 30")
    );
    check_in(&fx, &two_token, report(push.revision, None, 60)).await;
    let applied = root.get("/fleet").await;
    assert!(applied.has("Applied"), "{}", applied.body);
    assert_eq!(
        rollout_state(&fx.db, last_rollout(&fx.db).await).await.0,
        "done"
    );

    // A push the first firewall cannot apply: it keeps its settings and reports why.
    push_settings(&mut root, &[one], "cache_max_bytes = 0").await;
    let failing = check_in(&fx, &one_token, report(push.revision, None, 60)).await;
    assert!(failing.settings.is_some());
    check_in(
        &fx,
        &one_token,
        report(
            push.revision,
            Some("cannot read /etc/probation/tls/cert.pem"),
            60,
        ),
    )
    .await;
    let page = root.get("/fleet").await;
    assert!(page.has("could not apply"), "{}", page.body);
    assert!(
        page.has("cannot read /etc/probation/tls/cert.pem"),
        "{}",
        page.body
    );
    assert_eq!(audit_rows(&fx.db, "firewall.settings").await.len(), 2);
}

/// T-fleet-push-staggered (C70, C71): a rollout halts when its first step fails, or
/// when the first firewall never reports within 3 intervals; the second firewall's
/// answers carry no settings, and the fleet page shows the halt with resume and skip.
#[tokio::test]
async fn t_fleet_push_staggered() {
    let fx = Fixture::start().await;
    World::new(&fx).await;
    let (one, one_token) = register(&fx.db, "fw-eu-1").await;
    let (two, two_token) = register(&fx.db, "fw-eu-2").await;
    let mut root = fx.admin("root@probation.test").await;

    push_settings(&mut root, &[one, two], "sync_interval_seconds = 30").await;
    let failed_rollout = last_rollout(&fx.db).await;
    assert!(
        check_in(&fx, &one_token, report(0, None, 60))
            .await
            .settings
            .is_some()
    );
    check_in(&fx, &one_token, report(0, Some("refused"), 60)).await;
    assert_eq!(
        rollout_state(&fx.db, failed_rollout).await,
        (
            "halted".to_owned(),
            vec!["failed".to_owned(), "pending".to_owned()]
        )
    );
    for _ in 0..2 {
        assert!(
            check_in(&fx, &two_token, report(0, None, 60))
                .await
                .settings
                .is_none()
        );
    }
    let page = root.get("/fleet").await;
    assert!(page.has("Halted"), "{}", page.body);
    // A failed apply is never retried by the firewall: skip only (M3).
    assert!(
        page.has(&format!("action=\"/fleet/rollouts/{failed_rollout}/skip\"")),
        "{}",
        page.body
    );
    assert!(!page.has(&format!(
        "action=\"/fleet/rollouts/{failed_rollout}/resume\""
    )));
    let before = state(&fx.db).await;
    let resumed = root
        .submit(
            "/fleet",
            &format!("/fleet/rollouts/{failed_rollout}/resume"),
            &[],
        )
        .await;
    assert_ne!(resumed.status, StatusCode::SEE_OTHER, "{}", resumed.body);
    // The second firewall waits in that rollout: a new push to it is refused (M2).
    let overlapping = push_settings(&mut root, &[two], "sync_interval_seconds = 20").await;
    assert_eq!(
        overlapping.status,
        StatusCode::CONFLICT,
        "{}",
        overlapping.body
    );
    assert!(
        overlapping.has(&format!("fw-eu-2 is still in rollout {failed_rollout}")),
        "{}",
        overlapping.body
    );
    assert_eq!(state(&fx.db).await, before, "nothing written");
    let skipped = root
        .submit(
            "/fleet",
            &format!("/fleet/rollouts/{failed_rollout}/skip"),
            &[],
        )
        .await;
    assert_eq!(skipped.status, StatusCode::SEE_OTHER, "{}", skipped.body);
    let pushed = check_in(&fx, &two_token, report(0, None, 60))
        .await
        .settings
        .expect("the next firewall gets the settings");
    // It applies them, and the rollout is done.
    check_in(&fx, &two_token, report(pushed.revision, None, 60)).await;
    assert_eq!(rollout_state(&fx.db, failed_rollout).await.0, "done");

    // The first firewall of the next rollout never reports.
    push_settings(&mut root, &[one, two], "sync_interval_seconds = 45").await;
    let timed_out = last_rollout(&fx.db).await;
    sqlx::query("UPDATE settings_rollout_steps SET sent_at = now() - interval '181 seconds' WHERE rollout_id = $1 AND position = 0")
        .bind(timed_out)
        .execute(&fx.db.owner)
        .await
        .unwrap();
    let page = root.get("/fleet").await;
    assert!(page.has("Halted"), "{}", page.body);
    assert_eq!(
        rollout_state(&fx.db, timed_out).await,
        (
            "halted".to_owned(),
            vec!["timed_out".to_owned(), "pending".to_owned()]
        )
    );
    let answer = check_in(&fx, &two_token, report(0, None, 60)).await;
    assert_ne!(
        answer.settings.map(|push| push.toml).as_deref(),
        Some("sync_interval_seconds = 45")
    );
    let resumed = root
        .submit(
            "/fleet",
            &format!("/fleet/rollouts/{timed_out}/resume"),
            &[],
        )
        .await;
    assert_eq!(resumed.status, StatusCode::SEE_OTHER, "{}", resumed.body);
    assert_eq!(rollout_state(&fx.db, timed_out).await.0, "running");

    // S7-14: the resumed push's answer is lost, and the firewall keeps reporting the
    // error of the revision it refused earlier. That stale error, which names the
    // earlier revision, does not fail the step; an error naming this one does.
    let stale = |failed: i32| FirewallReport {
        failed_revision: Some(failed as u64),
        ..report(0, Some("refused"), 60)
    };
    for _ in 0..2 {
        check_in(&fx, &one_token, stale(failed_rollout)).await;
    }
    assert_eq!(
        rollout_state(&fx.db, timed_out).await,
        (
            "running".to_owned(),
            vec!["sent".to_owned(), "pending".to_owned()]
        )
    );
    check_in(&fx, &one_token, stale(timed_out)).await;
    assert_eq!(
        rollout_state(&fx.db, timed_out).await,
        (
            "halted".to_owned(),
            vec!["failed".to_owned(), "pending".to_owned()]
        )
    );
}

/// T-fleet-retire (C72): a firewall registered and retired on the fleet page: its
/// token answers 401 and it stops serving.
#[tokio::test]
async fn t_fleet_retire() {
    let fx = Fixture::start().await;
    World::new(&fx).await;
    let mut root = fx.admin("root@probation.test").await;
    let registered = root
        .submit(
            "/fleet",
            "/fleet/register",
            &[("name", "fw-us-2"), ("sources", "127.0.0.0/8")],
        )
        .await;
    assert_eq!(registered.status, StatusCode::OK, "{}", registered.body);
    let token = shown(&registered, "new-token");
    assert!(token.starts_with("fwt_"));
    let id: i32 = sqlx::query_scalar("SELECT id FROM firewalls WHERE name = 'fw-us-2'")
        .fetch_one(&fx.db.owner)
        .await
        .unwrap();
    let firewall = fx.firewall_with(fx.api.clone(), &token).await;
    let mut mia = fx.signed_in("mia@acme.test").await;
    let key = create_key(&mut mia, "mia laptop").await;
    assert_eq!(status_of(&firewall, &key).await, StatusCode::OK);

    let wrong = root
        .submit(
            "/fleet",
            &format!("/fleet/{id}/retire"),
            &[("confirm", "fw")],
        )
        .await;
    assert_eq!(wrong.status, StatusCode::CONFLICT, "{}", wrong.body);
    let retired = root
        .submit(
            "/fleet",
            &format!("/fleet/{id}/retire"),
            &[("confirm", "fw-us-2")],
        )
        .await;
    assert_eq!(retired.status, StatusCode::SEE_OTHER, "{}", retired.body);
    let answer = common::post(
        &common::client(),
        fx.api.join("api/v1/sync/changes").unwrap(),
        Some(&token),
        &[],
        serde_json::to_vec(&ChangesRequest {
            since: 0,
            report: report(0, None, 2),
            activity: Vec::new(),
            activity_dropped: Vec::new(),
        })
        .unwrap(),
    )
    .await;
    assert_eq!(answer.status(), StatusCode::UNAUTHORIZED);
    answers_within_interval(&firewall, &key, StatusCode::UNAUTHORIZED, "retired").await;
    assert_eq!(
        fx.db
            .count("SELECT count(*) FROM change_log WHERE kind = 'firewall'")
            .await,
        1
    );
}

/// T-cross-tenant-routes-admin (C1): every route slice 7 adds that takes a place or an
/// id answers an Acme org admin 404 for each Globex id, the same as for an unknown id,
/// and writes nothing.
#[tokio::test]
async fn t_cross_tenant_routes_admin() {
    let fx = Fixture::start().await;
    let world = World::new(&fx).await;
    let mut gus = fx.admin("gus@globex.test").await;
    let globex_token =
        org_token(&mut gus, world.globex, &layer_id(world.globex), "globex ci").await;
    let _ = globex_token;
    let globex_token_id = key_id(&fx.db, "globex ci").await;
    let gus_personal = fx.db.personal(world.gus).await;
    let range: i32 = sqlx::query_scalar(
        "INSERT INTO org_ip_ranges (org_id, cidr) VALUES ($1, '203.0.113.0/24') RETURNING id",
    )
    .bind(world.globex.id as i32)
    .fetch_one(&fx.db.owner)
    .await
    .unwrap();
    let (firewall, _) = register(&fx.db, "fw").await;
    let mut root = fx.admin("root@probation.test").await;
    push_settings(&mut root, &[firewall], "sync_interval_seconds = 30").await;
    let rollout = last_rollout(&fx.db).await;
    let platform_ci = platform_token(&mut root, "platform ci").await;
    let _ = platform_ci;
    let platform_token_id = key_id(&fx.db, "platform ci").await;

    let ids_for = |path: &str| -> i64 {
        if path.starts_with("/admin/personal/") {
            gus_personal.id.into()
        } else if path.starts_with("/admin/ranges/") {
            range.into()
        } else if path.starts_with("/admin/admins/") {
            world.root.into()
        } else if path.starts_with("/admin/tokens/") {
            platform_token_id
        } else if path.starts_with("/fleet/rollouts/") {
            rollout.into()
        } else if path.starts_with("/fleet/") {
            firewall.into()
        } else {
            world.globex.id.into()
        }
    };
    let new_routes = |path: &str| {
        path.starts_with("/admin")
            || path.starts_with("/fleet")
            || path.contains("/automation")
            || path.contains("/blocklist")
    };
    let routes: Vec<_> = portal::route_table()
        .into_iter()
        .filter(|(_, path)| new_routes(path))
        .collect();
    assert!(routes.len() >= 25, "{routes:?}");
    let mut ana = fx.admin("ana@acme.test").await;
    let before = state(&fx.db).await;
    let mut sent = 0;
    for (method, path) in routes {
        let globex = ids_for(path).to_string();
        let mut answers = Vec::new();
        for id in [globex.as_str(), "999999"] {
            let csrf = ana.get("/keys").await.csrf();
            let concrete = path.replace("{id}", id).replace("{org}", id);
            let page = match method {
                "GET" => ana.get(&concrete).await,
                _ => {
                    ana.post_raw(
                        &concrete,
                        &[
                            ("csrf", &csrf),
                            ("confirm", "fw"),
                            ("name", "x"),
                            ("email", "x@acme.test"),
                            ("reason", "x"),
                            ("rate", "1"),
                            ("keys", "1"),
                            ("service", "1"),
                            ("kind", "org"),
                            ("activity_days", "30"),
                            ("audit_days", "30"),
                            ("sources", "127.0.0.0/8"),
                            ("toml", "sync_interval_seconds = 10"),
                            ("firewall", &firewall.to_string()),
                            ("layer", &layer_id(world.globex)),
                            ("file", SAMPLE),
                        ],
                    )
                    .await
                }
            };
            answers.push((page.status, page.body));
        }
        assert_eq!(
            answers[0].0,
            StatusCode::NOT_FOUND,
            "{method} {path} {globex}: {}",
            answers[0].1
        );
        assert_eq!(answers[0], answers[1], "{method} {path}: as an unknown id");
        sent += 1;
    }
    // Forms on Acme's page naming a Globex layer or token.
    let forged = ana
        .submit(
            "/keys",
            &format!("/org/{}/automation", world.acme.id),
            &[("name", "x"), ("layer", &layer_id(world.globex))],
        )
        .await;
    assert_eq!(forged.status, StatusCode::NOT_FOUND, "{}", forged.body);
    let forged = ana
        .submit(
            "/keys",
            &format!("/org/{}/automation/revoke", world.acme.id),
            &[("token", &globex_token_id.to_string())],
        )
        .await;
    assert_eq!(forged.status, StatusCode::NOT_FOUND, "{}", forged.body);
    assert!(sent >= 25, "{sent}");
    assert_eq!(state(&fx.db).await, before, "nothing written");
}

/// T-audit-coverage-admin (C25, C57, C79): each slice-7 action, done once, writes
/// exactly one audit row naming its actor, the global-admin flag, the subject and the
/// values before and after.
#[tokio::test]
async fn t_audit_coverage_admin() {
    let fx = Fixture::start().await;
    let world = World::new(&fx).await;
    let mut root = fx.admin("root@probation.test").await;
    let mut ana = fx.admin("ana@acme.test").await;
    let org_page = format!("/org/{}", world.acme.id);
    let acme = world.acme.id;
    let personal = world.pat_personal.id;

    let mut done = Vec::new();
    let run = async |browser: &mut Browser,
                     page: &str,
                     path: String,
                     fields: &[(&str, &str)],
                     action: &'static str| {
        let answer = browser.submit(page, &path, fields).await;
        assert!(
            [StatusCode::SEE_OTHER, StatusCode::OK].contains(&answer.status),
            "{path}: {} {}",
            answer.status,
            answer.body
        );
        action
    };
    done.push(
        run(
            &mut root,
            "/admin",
            format!("/admin/orgs/{acme}/suspend"),
            &[],
            "org.suspend",
        )
        .await,
    );
    done.push(
        run(
            &mut root,
            "/admin",
            format!("/admin/orgs/{acme}/activate"),
            &[],
            "org.activate",
        )
        .await,
    );
    done.push(
        run(
            &mut root,
            "/admin",
            format!("/admin/personal/{personal}/suspend"),
            &[],
            "personal.suspend",
        )
        .await,
    );
    done.push(
        run(
            &mut root,
            "/admin",
            format!("/admin/personal/{personal}/activate"),
            &[],
            "personal.activate",
        )
        .await,
    );
    done.push(
        run(
            &mut root,
            "/admin",
            format!("/admin/personal/{personal}/revoke-keys"),
            &[],
            "keys.revoke_all",
        )
        .await,
    );
    done.push(
        run(
            &mut root,
            "/admin",
            format!("/admin/personal/{personal}/delete"),
            &[],
            "personal.delete",
        )
        .await,
    );
    done.push(
        run(
            &mut root,
            "/admin",
            format!("/admin/personal/{personal}/restore"),
            &[],
            "personal.restore",
        )
        .await,
    );
    done.push(
        run(
            &mut root,
            "/admin",
            "/admin/limits".to_owned(),
            &[
                ("kind", "org"),
                ("rate", "100"),
                ("keys", "3"),
                ("service", "4"),
            ],
            "limits.set",
        )
        .await,
    );
    // Acme's own limits, set up as the owner, then back to the default.
    sqlx::query("INSERT INTO limits (scope_kind, scope_id, rate_per_min, max_keys, max_service_keys) VALUES ('org', $1, 9, 9, 9)")
        .bind(acme as i32)
        .execute(&fx.db.owner)
        .await
        .unwrap();
    done.push(
        run(
            &mut root,
            "/admin",
            format!("/admin/limits/orgs/{acme}/reset"),
            &[],
            "limits.reset",
        )
        .await,
    );
    done.push(
        run(
            &mut root,
            "/admin",
            "/admin/retention".to_owned(),
            &[("activity_days", "30"), ("audit_days", "400")],
            "retention.set",
        )
        .await,
    );
    ana.submit(
        &org_page,
        &format!("/org/{acme}/ranges"),
        &[("cidr", "192.0.2.0/24")],
    )
    .await;
    ana.submit(
        &org_page,
        &format!("/org/{acme}/ranges"),
        &[("cidr", "203.0.113.0/24")],
    )
    .await;
    let approve = range_id(&fx.db, "192.0.2.0/24").await;
    let refuse = range_id(&fx.db, "203.0.113.0/24").await;
    done.push(
        run(
            &mut root,
            "/admin",
            format!("/admin/ranges/{approve}/approve"),
            &[],
            "range.approve",
        )
        .await,
    );
    done.push(
        run(
            &mut root,
            "/admin",
            format!("/admin/ranges/{refuse}/refuse"),
            &[("reason", "no")],
            "range.refuse",
        )
        .await,
    );
    done.push(
        run(
            &mut root,
            "/fleet",
            "/fleet/register".to_owned(),
            &[("name", "fw-1"), ("sources", "127.0.0.0/8")],
            "firewall.register",
        )
        .await,
    );
    let firewall: i32 = sqlx::query_scalar("SELECT id FROM firewalls WHERE name = 'fw-1'")
        .fetch_one(&fx.db.owner)
        .await
        .unwrap();
    let firewall_id = firewall.to_string();
    done.push(
        run(
            &mut root,
            "/fleet",
            "/fleet/settings".to_owned(),
            &[
                ("firewall", &firewall_id),
                ("toml", "sync_interval_seconds = 30"),
            ],
            "firewall.settings",
        )
        .await,
    );
    done.push(
        run(
            &mut root,
            "/fleet",
            format!("/fleet/{firewall}/retire"),
            &[("confirm", "fw-1")],
            "firewall.retire",
        )
        .await,
    );
    done.push(
        run(
            &mut root,
            "/admin",
            "/admin/admins/invite".to_owned(),
            &[("email", "lee@probation.test")],
            "invitation.create",
        )
        .await,
    );
    let kim = fx.operator("kim@probation.test").await;
    done.push(
        run(
            &mut root,
            "/admin",
            format!("/admin/admins/{kim}/remove"),
            &[],
            "admin.remove",
        )
        .await,
    );
    done.push(
        run(
            &mut root,
            "/admin",
            "/admin/tokens".to_owned(),
            &[("name", "platform ci")],
            "automation.create",
        )
        .await,
    );
    let token = key_id(&fx.db, "platform ci").await;
    done.push(
        run(
            &mut root,
            "/admin",
            format!("/admin/tokens/{token}/revoke"),
            &[],
            "automation.revoke",
        )
        .await,
    );

    for action in done {
        let rows = audit_rows(&fx.db, action).await;
        assert_eq!(rows.len(), 1, "{action}: {rows:?}");
        let (actor, global, _, subject, before, after) = &rows[0];
        assert_eq!(*actor, Some(world.root), "{action}");
        assert!(*global, "{action}");
        assert!(!subject.is_empty(), "{action}");
        assert!(before.is_some() || after.is_some(), "{action}");
    }
    let suspended = audit_rows(&fx.db, "org.suspend").await;
    assert_eq!(suspended[0].2, Some(acme as i32), "in Acme's log (C79)");
}

/// T-portal-platform-policy (C9, C48): a platform block reaches both an organisation key
/// and a personal key within one interval.
#[tokio::test]
async fn t_portal_platform_policy() {
    let fx = Fixture::start().await;
    World::new(&fx).await;
    let firewall = fx.firewall().await;
    let mut mia = fx.signed_in("mia@acme.test").await;
    let org_key = create_key(&mut mia, "mia laptop").await;
    let mut pat = fx.signed_in("pat@home.test").await;
    let personal_key = create_key(&mut pat, "pat laptop").await;
    for key in [&org_key, &personal_key] {
        assert_eq!(status_of(&firewall, key).await, StatusCode::OK);
    }
    let mut root = fx.admin("root@probation.test").await;
    let admin = root.get("/admin").await;
    assert!(admin.has("href=\"/policy/platform-1\""), "{}", admin.body);
    let page = root.get("/policy/platform-1").await;
    let revision = hidden(&page.body, "revision").unwrap();
    let csrf = page.csrf();
    let saved = root
        .post_raw(
            "/policy/platform-1",
            &[
                ("action", "add_block"),
                ("what", "package"),
                ("ecosystem", "npm"),
                ("name", "left-pad"),
                ("revision", &revision),
                ("csrf", &csrf),
            ],
        )
        .await;
    assert_eq!(saved.status, StatusCode::SEE_OTHER, "{}", saved.body);
    answers_within_interval(&firewall, &org_key, StatusCode::FORBIDDEN, "org key").await;
    answers_within_interval(
        &firewall,
        &personal_key,
        StatusCode::FORBIDDEN,
        "personal key",
    )
    .await;
}

/// T-blocklist-roundtrip (C80, C86, C119): today's sample file with a sha512 block
/// imported on the organisation page comes back from its export with the same blocks
/// and reasons; a policy without reasons keeps its fingerprint, and a reason change
/// makes a new one.
#[tokio::test]
async fn t_blocklist_roundtrip() {
    let fx = Fixture::start().await;
    let world = World::new(&fx).await;
    let mut file: serde_json::Value = serde_json::from_str(SAMPLE).unwrap();
    file["blocked_hashes"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({
            "algorithm": "sha512",
            "digest": "cd".repeat(64),
            "reason": "Known malicious wheel",
        }));
    let file = file.to_string();
    let mut ana = fx.admin("ana@acme.test").await;
    let org_page = format!("/org/{}", world.acme.id);
    let imported = ana
        .submit(
            &org_page,
            &format!("/org/{}/blocklist", world.acme.id),
            &[("file", &file)],
        )
        .await;
    assert_eq!(imported.status, StatusCode::SEE_OTHER, "{}", imported.body);
    let stored = blocks_of(&fx.db, world.root, world.acme).await;
    assert_eq!(stored, blocklist_json::import(&file).unwrap());
    assert_eq!(stored.len(), 4);
    assert!(stored.iter().any(|block| matches!(
        block,
        Block::File { algorithm: DigestAlgorithm::Sha512, reason: Some(reason), .. } if reason == "Known malicious wheel"
    )));
    let exported = ana.get(&format!("/org/{}/blocklist", world.acme.id)).await;
    assert_eq!(exported.status, StatusCode::OK);
    assert!(
        exported
            .content_type
            .as_deref()
            .is_some_and(|kind| kind.starts_with("application/json")),
        "{:?}",
        exported.content_type
    );
    assert_eq!(blocklist_json::import(&exported.body).unwrap(), stored);

    // The fingerprint of a policy with no reasons, pinned before `reason` existed.
    let reasonless = |reason: Option<&str>| {
        let mut platform = Layer::empty(LayerKind::Platform);
        platform.freeze_seconds = Some(86400);
        platform.blocks.push(Block::Package {
            ecosystem: Ecosystem::Npm,
            name: "left-pad".into(),
            reason: reason.map(str::to_owned),
        });
        platform.blocks.push(Block::File {
            algorithm: DigestAlgorithm::Sha512,
            digest: "ab".repeat(64),
            reason: None,
        });
        let mut org = Layer::empty(LayerKind::Org);
        org.blocks.push(Block::Version {
            ecosystem: Ecosystem::PyPi,
            name: "Foo_Bar".into(),
            version: "1.0".into(),
            reason: None,
        });
        hex::encode(resolve(&[platform, org]).fingerprint.0)
    };
    assert_eq!(
        reasonless(None),
        "c1f5aae75cb6e7228b8b3c9cc6fca66e9e29992ce0e4b28fdcde909710222331"
    );
    assert_ne!(reasonless(Some("malware")), reasonless(None));
    assert_ne!(reasonless(Some("malware")), reasonless(Some("typosquat")));
}

/// T-automation-push (C80, C86, C47): pushes into an org layer and into the platform
/// layer are audited with their token; the platform push reaches an org key and a
/// personal key within one interval; a push into a layer holding a setting kept under
/// C47 saves, and the setting stays stored.
#[tokio::test]
async fn t_automation_push() {
    let fx = Fixture::start().await;
    let world = World::new(&fx).await;
    let firewall = fx.firewall().await;
    let mut mia = fx.signed_in("mia@acme.test").await;
    let org_key = create_key(&mut mia, "mia laptop").await;
    let mut pat = fx.signed_in("pat@home.test").await;
    let personal_key = create_key(&mut pat, "pat laptop").await;
    for key in [&org_key, &personal_key] {
        assert_eq!(status_of(&firewall, key).await, StatusCode::OK);
    }
    // Acme keeps a 1-day freeze that a 7-day platform freeze puts out of effect (C47).
    sqlx::query(
        "UPDATE policy_layers SET freeze_seconds = CASE place_kind WHEN 'platform' THEN 7 * 86400 ELSE 86400 END
         WHERE place_kind = 'platform' OR (place_kind = 'org' AND place_id = $1)",
    )
    .bind(world.acme.id as i32)
    .execute(&fx.db.owner)
    .await
    .unwrap();

    let mut ana = fx.admin("ana@acme.test").await;
    let acme_layer = layer_id(world.acme);
    let org_ci = org_token(&mut ana, world.acme, &acme_layer, "acme ci").await;
    assert!(org_ci.starts_with("aut_"));
    let (status, body) = blocklist_call(
        &fx,
        reqwest::Method::PUT,
        &org_ci,
        &acme_layer,
        SAMPLE.as_bytes().to_vec(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = blocklist_call(
        &fx,
        reqwest::Method::POST,
        &org_ci,
        &acme_layer,
        one_block_file("npm", "colors"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let stored = blocks_of(&fx.db, world.root, world.acme).await;
    assert_eq!(stored.len(), 4, "{stored:?}");
    let freeze: Option<i64> = sqlx::query_scalar(
        "SELECT freeze_seconds FROM policy_layers WHERE place_kind = 'org' AND place_id = $1",
    )
    .bind(world.acme.id as i32)
    .fetch_one(&fx.db.owner)
    .await
    .unwrap();
    assert_eq!(freeze, Some(86400), "the kept freeze stays stored");
    let (status, exported) =
        blocklist_call(&fx, reqwest::Method::GET, &org_ci, &acme_layer, Vec::new()).await;
    assert_eq!(status, StatusCode::OK);
    let exported = blocklist_json::import(&exported).unwrap();
    assert_eq!(exported.len(), stored.len());
    assert!(
        exported.iter().all(|block| stored.contains(block)),
        "{exported:?}"
    );

    let mut root = fx.admin("root@probation.test").await;
    let platform_ci = platform_token(&mut root, "platform ci").await;
    let (status, body) = blocklist_call(
        &fx,
        reqwest::Method::POST,
        &platform_ci,
        "platform-1",
        one_block_file("npm", "left-pad"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    answers_within_interval(&firewall, &org_key, StatusCode::FORBIDDEN, "org key").await;
    answers_within_interval(
        &firewall,
        &personal_key,
        StatusCode::FORBIDDEN,
        "personal key",
    )
    .await;

    let pushes: Vec<(Option<i32>, Option<i64>, Option<i32>)> = sqlx::query_as(
        "SELECT actor_login, actor_token, org_id FROM audit_log WHERE action = 'layer.edit' ORDER BY id",
    )
    .fetch_all(&fx.db.owner)
    .await
    .unwrap();
    let org_token_id = key_id(&fx.db, "acme ci").await;
    let platform_token_id = key_id(&fx.db, "platform ci").await;
    assert_eq!(
        pushes,
        [
            (
                Some(world.ana),
                Some(org_token_id),
                Some(world.acme.id as i32)
            ),
            (
                Some(world.ana),
                Some(org_token_id),
                Some(world.acme.id as i32)
            ),
            (Some(world.root), Some(platform_token_id), None),
        ]
    );
}

/// T-automation-scope (C86, T9): an automation token writes only its own layer and only
/// that layer's blocks; its audit row names the token and its creator.
#[tokio::test]
async fn t_automation_scope() {
    let fx = Fixture::start().await;
    let world = World::new(&fx).await;
    let mut ana = fx.admin("ana@acme.test").await;
    let acme_layer = layer_id(world.acme);
    let token = org_token(&mut ana, world.acme, &acme_layer, "acme ci").await;
    let before = state(&fx.db).await;
    for other in [
        layer_id(world.globex),
        "platform-1".to_owned(),
        layer_id(world.places[&world.mia]),
        layer_id(world.pat_personal),
    ] {
        for method in [reqwest::Method::PUT, reqwest::Method::POST] {
            let (status, body) = blocklist_call(
                &fx,
                method.clone(),
                &token,
                &other,
                one_block_file("npm", "left-pad"),
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{method} {other}: {body}");
        }
    }
    let (status, _) = blocklist_call(
        &fx,
        reqwest::Method::GET,
        &token,
        &layer_id(world.globex),
        Vec::new(),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // A user's key or a firewall token is no automation token (T9).
    let (status, _) = blocklist_call(
        &fx,
        reqwest::Method::PUT,
        &register(&fx.db, "fw").await.1,
        &acme_layer,
        one_block_file("npm", "left-pad"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    sqlx::query("DELETE FROM firewalls")
        .execute(&fx.db.owner)
        .await
        .unwrap();
    sqlx::query("DELETE FROM keys WHERE kind = 'firewall'")
        .execute(&fx.db.owner)
        .await
        .unwrap();
    sqlx::query("DELETE FROM audit_log WHERE action = 'firewall.register'")
        .execute(&fx.db.owner)
        .await
        .unwrap();
    assert_eq!(state(&fx.db).await, before, "nothing written");

    // Blocks only: the token's actor cannot save its own layer's freeze, OSV or switches,
    // though each would pass `check_edit` (the platform lets Acme grant exceptions).
    sqlx::query("UPDATE policy_layers SET allow_exceptions = true WHERE place_kind = 'platform'")
        .execute(&fx.db.owner)
        .await
        .unwrap();
    let tenancy = fx.db.tenancy();
    let (actor, place) = tenancy
        .automation(&token)
        .await
        .unwrap()
        .expect("a live token");
    assert_eq!(place.place(), world.acme);
    for change in [
        (|layer: &mut Layer| layer.freeze_seconds = Some(0)) as fn(&mut Layer),
        |layer: &mut Layer| layer.allow.exceptions = true,
        |layer: &mut Layer| layer.osv = Some(probation_policy::OsvSetting::On),
    ] {
        let checked = fx.db.check(&place, change).await.unwrap();
        let permit = probation_server::tenancy::authorize(&actor, &checked).unwrap();
        let saved = fx.db.store().save_edit(&actor, permit, checked).await;
        assert!(saved.is_err(), "{saved:?}");
    }
    let checked = fx
        .db
        .check(&place, |layer| {
            layer.blocks.push(Block::Package {
                ecosystem: Ecosystem::Npm,
                name: "left-pad".into(),
                reason: None,
            })
        })
        .await
        .unwrap();
    let permit = probation_server::tenancy::authorize(&actor, &checked).unwrap();
    fx.db
        .store()
        .save_edit(&actor, permit, checked)
        .await
        .unwrap();
    // Another layer: no permit.
    let (_, globex) = fx.db.as_admin(world.root, world.globex).await;
    let checked = fx.db.check(&globex, |_| {}).await.unwrap();
    assert!(probation_server::tenancy::authorize(&actor, &checked).is_err());

    let (login, token_id): (Option<i32>, Option<i64>) = sqlx::query_as(
        "SELECT actor_login, actor_token FROM audit_log WHERE action = 'layer.edit'",
    )
    .fetch_one(&fx.db.owner)
    .await
    .unwrap();
    assert_eq!(login, Some(world.ana));
    assert_eq!(token_id, Some(key_id(&fx.db, "acme ci").await));
}

/// T-automation-body-limit (T24): a push 1 byte over the cap answers 413 and writes
/// nothing.
#[tokio::test]
async fn t_automation_body_limit() {
    let fx = Fixture::start().await;
    let world = World::new(&fx).await;
    let mut ana = fx.admin("ana@acme.test").await;
    let acme_layer = layer_id(world.acme);
    let token = org_token(&mut ana, world.acme, &acme_layer, "acme ci").await;
    let cap = probation_server::policy::MAX_BLOCKLIST_BYTES;
    let mut body = one_block_file("npm", "left-pad");
    body.resize(cap + 1, b' ');
    let before = state(&fx.db).await;
    for method in [reqwest::Method::PUT, reqwest::Method::POST] {
        let (status, _) = blocklist_call(&fx, method, &token, &acme_layer, body.clone()).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    }
    assert_eq!(state(&fx.db).await, before, "nothing written");
    body.truncate(cap);
    let (status, text) = blocklist_call(&fx, reqwest::Method::PUT, &token, &acme_layer, body).await;
    assert_eq!(status, StatusCode::OK, "{text}");

    // Entry caps (M6): a file over `blocklist_json::MAX_ENTRIES`, and a layer over
    // `MAX_LAYER_BLOCKS`, are refused and write nothing.
    let many = |count: usize, prefix: &str| {
        let records: Vec<_> = (0..count)
            .map(|n| serde_json::json!({"ecosystem": "npm", "name": format!("{prefix}-{n}"), "version": null, "reason": "r"}))
            .collect();
        serde_json::json!({"schema_version": 1, "blocked_packages": records, "blocked_hashes": []})
            .to_string()
            .into_bytes()
    };
    let before = state(&fx.db).await;
    let (status, text) = blocklist_call(
        &fx,
        reqwest::Method::POST,
        &token,
        &acme_layer,
        many(blocklist_json::MAX_ENTRIES + 1, "one"),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{text}");
    assert_eq!(state(&fx.db).await, before, "nothing written");
    // 5001 copies of one record in add mode: the file cap, not the layer cap, refuses it.
    let record =
        serde_json::json!({"ecosystem": "npm", "name": "same", "version": null, "reason": "r"});
    let copies = serde_json::json!({
        "schema_version": 1,
        "blocked_packages": vec![record; blocklist_json::MAX_ENTRIES + 1],
        "blocked_hashes": [],
    });
    let (status, text) = blocklist_call(
        &fx,
        reqwest::Method::POST,
        &token,
        &acme_layer,
        copies.to_string().into_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{text}");
    // A reason one byte over `MAX_REASON_BYTES`.
    let long = serde_json::json!({
        "schema_version": 1,
        "blocked_packages": [{"ecosystem": "npm", "name": "long", "version": null,
                              "reason": "r".repeat(blocklist_json::MAX_REASON_BYTES + 1)}],
        "blocked_hashes": [],
    });
    let (status, text) = blocklist_call(
        &fx,
        reqwest::Method::POST,
        &token,
        &acme_layer,
        long.to_string().into_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{text}");
    assert_eq!(state(&fx.db).await, before, "nothing written");
    let (status, text) = blocklist_call(
        &fx,
        reqwest::Method::PUT,
        &token,
        &acme_layer,
        many(probation_policy::MAX_LAYER_BLOCKS, "two"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{text}");
    let before = state(&fx.db).await;
    let (status, text) = blocklist_call(
        &fx,
        reqwest::Method::POST,
        &token,
        &acme_layer,
        one_block_file("npm", "one-more"),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{text}");
    assert_eq!(state(&fx.db).await, before, "nothing written");
}

/// F11: a database outage while the automation token is checked answers 503, not 401,
/// so a CI job retries instead of reporting a bad token.
#[tokio::test]
async fn automation_api_answers_503_when_the_database_is_down() {
    let db = Db::fresh().await;
    let api = common::serve(db.app.clone(), Vec::new()).await;
    db.app.close().await;
    let url = api.join("api/v1/blocklist/org-1").unwrap();
    let answer = tokio::time::timeout(
        Duration::from_secs(10),
        common::client()
            .get(url)
            .bearer_auth("aut_0123456789abcdef")
            .send(),
    )
    .await
    .expect("the server answers in time")
    .expect("the server answers");
    assert_eq!(answer.status(), StatusCode::SERVICE_UNAVAILABLE);
    let checked = db.tenancy().automation("aut_0123456789abcdef").await;
    assert!(checked.is_err(), "{checked:?}");
}
