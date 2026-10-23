//! Slice 4: who may see and edit which place (C1, C4, C27, C78), and the bootstrap
//! grant (T3) (03-program-design.md § Test plan). Needs the Postgres of
//! docker-compose.test.yml.

mod common;

use std::net::SocketAddr;
use std::process::Command;
use std::sync::Arc;

use common::{Db, EditFailure};
use probation_policy::api::KeyId;
use probation_policy::{Block, Ecosystem, Layer, LayerKind, PlaceRef};
use probation_server::accounts::{Outbound, OutboundError};
use probation_server::fleet;
use probation_server::keys::{self, RevokeError};
use probation_server::portal::{self, Portal, PortalConfig, PortalDeps};
use probation_server::tenancy::{NotFound, PLATFORM, Session, authorize};
use reqwest::StatusCode;
use sha2::{Digest, Sha256};

fn stricter(layer: &mut Layer) {
    layer.blocks.push(Block::Package {
        ecosystem: Ecosystem::Npm,
        name: "left-pad".to_owned(),
        reason: None,
    });
}

/// What the matrix expects of one login on one place.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum May {
    Nothing,
    Read,
    Edit,
}

/// Whether `login` may create a key on `place` and revoke one there (created by the
/// global admin `admin`); both answers must agree.
async fn may_manage_keys(db: &Db, admin: i32, login: i32, place: PlaceRef) -> bool {
    let (admin_actor, admin_place) = db.as_admin(admin, place).await;
    let target = keys::create(&db.app, &admin_actor, &admin_place, "target")
        .await
        .unwrap();
    let session = Session::new(login, None);
    let authorized = db
        .tenancy()
        .authorized_place(&session, place)
        .await
        .unwrap();
    let actor = db.tenancy().actor(&session, &authorized).await.unwrap();
    let created = match keys::create(&db.app, &actor, &authorized, "own").await {
        Ok(_) => true,
        Err(keys::KeyError::Denied) => false,
        Err(other) => panic!("create: {other:?}"),
    };
    let revoked = match keys::revoke(&db.app, &actor, &authorized, target.id).await {
        Ok(()) => true,
        Err(RevokeError::Denied) => false,
        Err(other) => panic!("revoke: {other:?}"),
    };
    assert_eq!(
        created, revoked,
        "login {login} on {place:?}: create and revoke disagree"
    );
    created
}

async fn may(db: &Db, login: i32, place: PlaceRef) -> May {
    let session = Session::new(login, None);
    if db
        .tenancy()
        .authorized_place(&session, place)
        .await
        .is_err()
    {
        return May::Nothing;
    }
    match db.edit(login, place, stricter).await {
        Ok(_) => May::Edit,
        Err(EditFailure::Denied) => May::Read,
        Err(other) => panic!("{login} on {place:?}: {other:?}"),
    }
}

/// T-authz-matrix: every role on every layer kind, read and edit, as C4, C9, C27 say;
/// a suspended organisation denies all but global admins (C78).
#[tokio::test]
async fn t_authz_matrix() {
    let db = Db::fresh().await;
    let global = db.global_admin().await;
    let acme = db.org("Acme").await;
    let g1 = db.group(acme, "G1").await;
    let g2 = db.group(acme, "G2").await;
    let org_admin = db.login().await;
    let org_admin_place = db.member(org_admin, acme, None, "org_admin").await;
    let group_admin = db.login().await;
    let group_admin_place = db.member(group_admin, acme, Some(g1), "group_admin").await;
    let m1 = db.login().await;
    let m1_place = db.member(m1, acme, Some(g1), "member").await;
    let m2 = db.login().await;
    let m2_place = db.member(m2, acme, Some(g2), "member").await;
    let solo = db.login().await;
    let personal = db.personal(solo).await;

    use May::{Edit as E, Nothing as N, Read as R};
    let places = [
        PLATFORM,
        acme,
        g1,
        g2,
        org_admin_place,
        group_admin_place,
        m1_place,
        m2_place,
        personal,
    ];
    #[rustfmt::skip]
    let expected = [
        // platform, acme, g1, g2, user(org admin), user(group admin), user(m1), user(m2), personal
        (global,      [E, E, E, E, E, E, E, E, E]),
        (org_admin,   [N, E, E, E, E, E, E, E, N]),
        (group_admin, [N, R, E, R, R, E, R, R, N]),
        (m1,          [N, R, R, R, R, R, E, R, N]),
        (m2,          [N, R, R, R, R, R, R, E, N]),
        (solo,        [N, N, N, N, N, N, N, N, E]),
    ];
    for (login, row) in expected {
        for (place, want) in places.iter().zip(row) {
            assert_eq!(
                may(&db, login, *place).await,
                want,
                "login {login} on {place:?}"
            );
        }
    }

    // Keys: create and revoke, each role on the organisation, a group, the login's own
    // user place and another member's (C14, C27, C50). A global admin has no user place.
    let (yes, no, absent) = (Some(true), Some(false), None);
    #[rustfmt::skip]
    let key_matrix = [
        // org, g1, own user, other user (m2's)
        (global,      [yes, yes, absent, yes]),
        (org_admin,   [yes, yes, yes,    yes]),
        (group_admin, [no,  yes, yes,    no ]),
        (m1,          [no,  no,  yes,    no ]),
    ];
    let own_place = |login| match login {
        l if l == org_admin => Some(org_admin_place),
        l if l == group_admin => Some(group_admin_place),
        l if l == m1 => Some(m1_place),
        _ => None,
    };
    for (login, row) in key_matrix {
        let targets = [Some(acme), Some(g1), own_place(login), Some(m2_place)];
        for (target, want) in targets.into_iter().zip(row) {
            let (Some(target), Some(want)) = (target, want) else {
                continue;
            };
            assert_eq!(
                may_manage_keys(&db, global, login, target).await,
                want,
                "keys: login {login} on {target:?}"
            );
        }
    }
    // Firewalls: only a global admin registers one.
    let sources = ["192.0.2.0/24".parse().unwrap()];
    for (login, at, want) in [
        (global, acme, true),
        (org_admin, acme, false),
        (m1, m1_place, false),
    ] {
        let session = Session::new(login, None);
        let authorized = db.tenancy().authorized_place(&session, at).await.unwrap();
        let actor = db.tenancy().actor(&session, &authorized).await.unwrap();
        let registered = fleet::register(&db.app, &actor, "fw", &sources).await;
        match (want, registered) {
            (true, Ok(_)) | (false, Err(fleet::RegisterError::Denied)) => {}
            (_, other) => panic!("fleet::register by login {login}: {:?}", other.err()),
        }
    }

    // A permit is for one place: m1's permit for its own user layer, paired with a
    // checked edit of the organisation layer, writes nothing (R1).
    let session = Session::new(m1, None);
    let own = db
        .tenancy()
        .authorized_place(&session, m1_place)
        .await
        .unwrap();
    let actor = db.tenancy().actor(&session, &own).await.unwrap();
    let own_edit = db.check(&own, stricter).await.unwrap();
    let permit = authorize(&actor, &own_edit).unwrap();
    let org = db.tenancy().authorized_place(&session, acme).await.unwrap();
    let org_edit = db.check(&org, stricter).await.unwrap();
    let before = db.store().layer(&org).await.unwrap();
    let audits = db.count("SELECT count(*) FROM audit_log").await;
    let changes = db.count("SELECT count(*) FROM change_log").await;
    let saved = db.store().save_edit(&actor, permit, org_edit).await;
    assert!(
        saved.is_err(),
        "a permit for {m1_place:?} saved {acme:?}: {saved:?}"
    );
    assert_eq!(db.store().layer(&org).await.unwrap(), before);
    assert_eq!(db.count("SELECT count(*) FROM audit_log").await, audits);
    assert_eq!(db.count("SELECT count(*) FROM change_log").await, changes);
    // …and it is for one actor: m2 saving m1's own layer with m1's permit writes
    // nothing either (N3).
    let own_edit = db.check(&own, stricter).await.unwrap();
    let permit = authorize(&actor, &own_edit).unwrap();
    let m2_session = Session::new(m2, None);
    let m2_own = db
        .tenancy()
        .authorized_place(&m2_session, m2_place)
        .await
        .unwrap();
    let m2_actor = db.tenancy().actor(&m2_session, &m2_own).await.unwrap();
    let own_before = db.store().layer(&own).await.unwrap();
    let saved = db.store().save_edit(&m2_actor, permit, own_edit).await;
    assert!(saved.is_err(), "m2 saved with m1's permit: {saved:?}");
    assert_eq!(db.store().layer(&own).await.unwrap(), own_before);
    assert_eq!(db.count("SELECT count(*) FROM audit_log").await, audits);
    assert_eq!(db.count("SELECT count(*) FROM change_log").await, changes);

    db.suspend_org(acme).await;
    for (login, want) in [(global, E), (org_admin, R), (group_admin, R), (m1, R)] {
        assert_eq!(
            may(&db, login, g1).await,
            want,
            "suspended Acme, login {login}"
        );
    }
}

/// T-tenant-isolation (C1): an Acme admin gets `NotFound` for every Globex place, the
/// same as for an unknown one, and no repository function reaches a Globex row by id;
/// a session opened through Acme's SSO sees only Acme (T2).
#[tokio::test]
async fn t_tenant_isolation() {
    let db = Db::fresh().await;
    let acme = db.org("Acme").await;
    let globex = db.org("Globex").await;
    let acme_admin = db.login().await;
    let acme_admin_place = db.member(acme_admin, acme, None, "org_admin").await;
    let globex_group = db.group(globex, "Ops").await;
    let globex_member = db.login().await;
    let globex_user = db
        .member(globex_member, globex, Some(globex_group), "member")
        .await;
    let globex_personal = db.personal(globex_member).await;

    let session = Session::new(acme_admin, None);
    let tenancy = db.tenancy();
    for place in [
        globex,
        globex_group,
        globex_user,
        globex_personal,
        PLATFORM,
        common::place(LayerKind::Org, 9_999),
        common::place(LayerKind::User, 9_999),
    ] {
        assert_eq!(
            tenancy.authorized_place(&session, place).await.err(),
            Some(NotFound),
            "{place:?}"
        );
    }

    // A Globex key, reached through an Acme place by its id.
    let globex_session = Session::new(globex_member, None);
    let globex_place = tenancy
        .authorized_place(&globex_session, globex_user)
        .await
        .unwrap();
    let globex_actor = tenancy.actor(&globex_session, &globex_place).await.unwrap();
    let globex_key = keys::create(&db.app, &globex_actor, &globex_place, "laptop")
        .await
        .unwrap();
    for (place, key) in [
        (acme, globex_key.id),
        (acme_admin_place, globex_key.id),
        (acme, KeyId(9_999)),
    ] {
        let authorized = tenancy.authorized_place(&session, place).await.unwrap();
        let acme_actor = tenancy.actor(&session, &authorized).await.unwrap();
        assert!(matches!(
            keys::revoke(&db.app, &acme_actor, &authorized, key).await,
            Err(RevokeError::NotFound)
        ));
    }
    assert_eq!(
        db.count("SELECT count(*) FROM keys WHERE revoked_at IS NOT NULL")
            .await,
        0
    );
    assert!(matches!(
        db.edit(acme_admin, globex, |_| {}).await,
        Err(EditFailure::NotFound)
    ));
    let (layer, revision) = db.store().layer(&globex_place).await.unwrap();
    assert_eq!((layer, revision), (Layer::empty(LayerKind::User), 1));

    // A login in both organisations, signed in through Acme's SSO.
    db.member(acme_admin, globex, None, "member").await;
    let unscoped = Session::new(acme_admin, None);
    assert!(tenancy.authorized_place(&unscoped, globex).await.is_ok());
    let scoped = Session::new(acme_admin, Some(acme.id as i32));
    assert!(tenancy.authorized_place(&scoped, acme).await.is_ok());
    assert_eq!(
        tenancy.authorized_place(&scoped, globex).await.err(),
        Some(NotFound)
    );
}

fn bootstrap(db: &Db, config: &std::path::Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_probation-server"))
        .args(["admin", "bootstrap", "--config"])
        .arg(config)
        .args([
            "--email",
            "Ops@Example.test",
            "--org",
            "Acme",
            "--firewall",
            "fw-1",
            "--firewall-source",
            "10.0.0.0/8",
        ])
        .env("PROBATION_SERVER_DATABASE_URL", &db.app_url)
        .output()
        .expect("the binary runs")
}

/// The leaked-password range API, answering that no password has leaked.
struct NothingLeaked;

#[async_trait::async_trait]
impl Outbound for NothingLeaked {
    async fn get(&self, _url: &url::Url, _bearer: Option<&str>) -> Result<Vec<u8>, OutboundError> {
        Ok(Vec::new())
    }

    async fn post_form(
        &self,
        url: &url::Url,
        _form: &[(&str, &str)],
    ) -> Result<Vec<u8>, OutboundError> {
        Err(OutboundError::Refused(url.to_string()))
    }
}

/// The portal on a loopback port, and one browser's cookie, never following redirects.
struct Visitor {
    http: reqwest::Client,
    base: String,
    cookie: Option<String>,
}

impl Visitor {
    async fn start(db: &Db) -> Visitor {
        let portal = Portal::new(PortalDeps {
            pool: db.app.clone(),
            config: PortalConfig {
                base_url: url::Url::parse(BASE_URL).unwrap(),
                google: None,
                github: None,
                microsoft: None,
                leaked_password_url: url::Url::parse("https://api.pwnedpasswords.com/range/")
                    .unwrap(),
                smtp: None,
                firewall_url: None,
            },
            outbound: Arc::new(NothingLeaked),
            mailer: None,
            secret_key: [7; 32],
            password_params: argon2::Params::new(8, 1, 1, None).unwrap(),
            trusted_proxies: Vec::new(),
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(
                listener,
                portal::router(Arc::new(portal))
                    .into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await;
        });
        Visitor {
            http: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            base: format!("http://{addr}"),
            cookie: None,
        }
    }

    /// (status, Location, body), answered within ten seconds.
    async fn fetch(
        &mut self,
        mut builder: reqwest::RequestBuilder,
    ) -> (StatusCode, Option<String>, String) {
        if let Some(cookie) = &self.cookie {
            builder = builder.header("cookie", cookie);
        }
        let answer = tokio::time::timeout(std::time::Duration::from_secs(10), builder.send())
            .await
            .expect("the portal answers in time")
            .unwrap();
        for value in answer.headers().get_all("set-cookie") {
            let value = value.to_str().unwrap();
            self.cookie =
                (!value.contains("Max-Age=0")).then(|| value.split(';').next().unwrap().to_owned());
        }
        let location = answer
            .headers()
            .get("location")
            .map(|value| value.to_str().unwrap().to_owned());
        (answer.status(), location, answer.text().await.unwrap())
    }

    async fn get(&mut self, path: &str) -> (StatusCode, Option<String>, String) {
        let builder = self.http.get(format!("{}{path}", self.base));
        self.fetch(builder).await
    }

    async fn post(
        &mut self,
        path: &str,
        form: &[(&str, &str)],
    ) -> (StatusCode, Option<String>, String) {
        let builder = self.http.post(format!("{}{path}", self.base)).form(form);
        self.fetch(builder).await
    }
}

/// The value of the hidden field `name` in `body`.
fn hidden(body: &str, name: &str) -> String {
    let marker = format!("name=\"{name}\" value=\"");
    let start = body.find(&marker).expect("a hidden field") + marker.len();
    body[start..start + body[start..].find('"').unwrap()].to_owned()
}

const BASE_URL: &str = "https://portal.test/";

/// T-grant-bootstrap (T3, S8-14): `probation-server admin bootstrap` creates exactly one
/// global admin and one audit row, and prints a single-use link that sets the admin's
/// first password; signed in, the admin must set up an authenticator before `/admin`
/// (C24). Run again it refuses and changes nothing.
#[tokio::test]
async fn t_grant_bootstrap() {
    let db = Db::fresh().await;
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("server.toml");
    std::fs::write(
        &config,
        format!("[server]\nlisten = \"127.0.0.1:0\"\n\n[portal]\nbase_url = \"{BASE_URL}\"\n"),
    )
    .unwrap();
    let first = bootstrap(&db, &config);
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let printed = String::from_utf8(first.stdout).unwrap();
    assert!(
        printed.lines().any(|line| line.starts_with("key=prb_")),
        "{printed}"
    );
    assert!(
        printed
            .lines()
            .any(|line| line.starts_with("firewall_token=fwt_")),
        "{printed}"
    );

    let tables = [
        "SELECT count(*) FROM memberships WHERE role = 'global_admin'",
        "SELECT count(*) FROM audit_log",
        "SELECT count(*) FROM logins",
        "SELECT count(*) FROM orgs",
        "SELECT count(*) FROM keys",
        "SELECT count(*) FROM firewalls",
        "SELECT count(*) FROM memberships",
    ];
    let mut after_first = Vec::new();
    for sql in tables {
        after_first.push(db.count(sql).await);
    }
    assert_eq!(after_first, [1, 1, 1, 1, 2, 1, 1]);
    // The host operator ran it, not the admin it created (F7).
    let actor: (Option<i32>, bool, String) =
        sqlx::query_as("SELECT actor_login, actor_is_global_admin, action FROM audit_log")
            .fetch_one(&db.owner)
            .await
            .unwrap();
    assert_eq!(actor, (None, true, "admin.bootstrap".to_owned()));

    // The printed link sets the first password, once.
    let link = printed
        .lines()
        .find_map(|line| line.strip_prefix("set_password_link="))
        .expect("a set-password link");
    let path = link
        .strip_prefix("https://portal.test")
        .filter(|path| path.starts_with("/reset/confirm?token="))
        .unwrap_or_else(|| panic!("{link}"));
    let token = path.split_once("token=").unwrap().1;
    let mut admin = Visitor::start(&db).await;
    let (status, _, form) = admin.get(path).await;
    assert_eq!(status, StatusCode::OK, "{form}");
    let password = "bootstrap admin passphrase";
    let choose = [
        ("csrf", hidden(&form, "csrf")),
        ("token", token.to_owned()),
        ("new", password.to_owned()),
        ("again", password.to_owned()),
    ];
    let choose: Vec<(&str, &str)> = choose.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let (status, _, done) = admin.post("/reset/confirm", &choose).await;
    assert_eq!(status, StatusCode::OK, "{done}");
    assert!(done.contains("Your password is changed"), "{done}");
    let (status, _, _) = admin.post("/reset/confirm", &choose).await;
    assert_eq!(status, StatusCode::GONE, "a used link is refused");
    assert_eq!(admin.get(path).await.0, StatusCode::GONE);

    // Signed in, the global admin is sent to set up an authenticator first (C24).
    let (_, _, signin) = admin.get("/signin").await;
    let csrf = hidden(&signin, "csrf");
    let (status, location, body) = admin
        .post(
            "/signin",
            &[
                ("csrf", &csrf),
                ("email", "ops@example.test"),
                ("password", password),
            ],
        )
        .await;
    assert_eq!(
        (status, location.as_deref()),
        (StatusCode::SEE_OTHER, Some("/account")),
        "{body}"
    );
    let (status, location, _) = admin.get("/admin").await;
    assert_eq!(
        (status, location.as_deref()),
        (StatusCode::SEE_OTHER, Some("/account#totp-heading"))
    );

    let mut before_second = Vec::new();
    for sql in tables {
        before_second.push(db.count(sql).await);
    }
    let second = bootstrap(&db, &config);
    assert!(!second.status.success());
    assert!(
        String::from_utf8_lossy(&second.stderr).contains("refused"),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    let mut after_second = Vec::new();
    for sql in tables {
        after_second.push(db.count(sql).await);
    }
    assert_eq!(after_second, before_second);

    // `admin reset-link`: a fresh link for a global admin only.
    let reset_link = |email: &str| {
        Command::new(env!("CARGO_BIN_EXE_probation-server"))
            .args(["admin", "reset-link", "--config"])
            .arg(&config)
            .args(["--email", email])
            .env("PROBATION_SERVER_DATABASE_URL", &db.app_url)
            .output()
            .expect("the binary runs")
    };
    let printed_path = |output: std::process::Output| {
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let printed = String::from_utf8(output.stdout).unwrap();
        printed
            .trim()
            .strip_prefix("set_password_link=https://portal.test")
            .unwrap_or_else(|| panic!("{printed}"))
            .to_owned()
    };
    let first_reset = printed_path(reset_link("ops@example.test"));
    assert_eq!(admin.get(&first_reset).await.0, StatusCode::OK);
    // A new link cancels every older one, the bootstrap link included.
    let second_reset = printed_path(reset_link("ops@example.test"));
    assert_eq!(admin.get(&first_reset).await.0, StatusCode::GONE);
    assert_eq!(admin.get(path).await.0, StatusCode::GONE);
    // Setting a password through one link burns any other live link of the sign-in,
    // here one written straight into the table.
    let stray = "stray-reset-token";
    sqlx::query(
        "INSERT INTO email_tokens (token_hash, method_id, purpose, expires_at)
         SELECT $1, id, 'reset', now() + interval '1 hour' FROM sign_in_methods
         WHERE kind = 'password' AND email = 'ops@example.test'",
    )
    .bind(Sha256::digest(stray.as_bytes()).to_vec())
    .execute(&db.owner)
    .await
    .unwrap();
    let stray_path = format!("/reset/confirm?token={stray}");
    assert_eq!(admin.get(&stray_path).await.0, StatusCode::OK);
    let (_, _, form) = admin.get(&second_reset).await;
    let again = "bootstrap admin second passphrase";
    let (status, _, done) = admin
        .post(
            "/reset/confirm",
            &[
                ("csrf", &hidden(&form, "csrf")),
                ("token", second_reset.split_once("token=").unwrap().1),
                ("new", again),
                ("again", again),
            ],
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{done}");
    assert_eq!(admin.get(&stray_path).await.0, StatusCode::GONE);
    assert!(!reset_link("nobody@example.test").status.success());
}

/// T-grant-bootstrap without the portal (S8-17): a settings file with no `[portal]`
/// still bootstraps everything, prints a note instead of a link, and `admin
/// reset-link` gives the link once `[portal]` is added.
#[tokio::test]
async fn t_grant_bootstrap_without_portal() {
    let db = Db::fresh().await;
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("server.toml");
    std::fs::write(&config, "[server]\nlisten = \"127.0.0.1:0\"\n").unwrap();
    let done = bootstrap(&db, &config);
    assert!(
        done.status.success(),
        "{}",
        String::from_utf8_lossy(&done.stderr)
    );
    let printed = String::from_utf8(done.stdout).unwrap();
    assert!(
        printed.contains(
            "note: no [portal] base_url: no sign-in link; add [portal] and run `admin reset-link` later"
        ),
        "{printed}"
    );
    assert!(!printed.contains("set_password_link="), "{printed}");
    assert!(
        printed
            .lines()
            .any(|line| line.starts_with("firewall_token=fwt_"))
    );
    assert_eq!(
        db.count(
            "SELECT count(*) FROM sign_in_methods AS m JOIN memberships AS g ON g.login_id = m.login_id
             WHERE g.role = 'global_admin' AND m.email = 'ops@example.test' AND m.verified_at IS NOT NULL"
        )
        .await,
        1
    );
    assert_eq!(db.count("SELECT count(*) FROM email_tokens").await, 0);

    std::fs::write(
        &config,
        format!("[server]\nlisten = \"127.0.0.1:0\"\n\n[portal]\nbase_url = \"{BASE_URL}\"\n"),
    )
    .unwrap();
    let later = Command::new(env!("CARGO_BIN_EXE_probation-server"))
        .args(["admin", "reset-link", "--config"])
        .arg(&config)
        .args(["--email", "ops@example.test"])
        .env("PROBATION_SERVER_DATABASE_URL", &db.app_url)
        .output()
        .unwrap();
    assert!(
        later.status.success(),
        "{}",
        String::from_utf8_lossy(&later.stderr)
    );
    assert!(
        String::from_utf8(later.stdout)
            .unwrap()
            .starts_with("set_password_link=https://portal.test/reset/confirm?token=")
    );
}
