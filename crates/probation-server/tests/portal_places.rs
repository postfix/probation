//! Slice 6: members, groups, invitations, keys, policy layers, activity, the audit log,
//! network-lock ranges and organisation deletion in the portal, through the real portal
//! routes against Postgres (03 § Portal requirement tests). As in tests/accounts.rs,
//! `FakeMail` stands in for SMTP and `FakeNet` for every IdP and the leaked-password
//! service; the T-sync rows run a real firewall against the real sync API.

mod common;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use common::Db;
use probation_policy::{LayerKind, PlaceRef};
use probation_server::accounts::{self, Mail, Mailer, Outbound, OutboundError};
use probation_server::portal::{self, Portal, PortalConfig, PortalDeps};
use reqwest::StatusCode;

const BASE_URL: &str = "https://portal.test";
const PASSWORD: &str = "correct horse battery";

/// The portal on a loopback port, with fakes for mail and the network.
struct Fixture {
    db: Db,
    addr: SocketAddr,
    mail: Arc<FakeMail>,
    net: Arc<FakeNet>,
}

impl Fixture {
    async fn start() -> Fixture {
        let db = Db::fresh().await;
        let mail = Arc::new(FakeMail::default());
        let net = Arc::new(FakeNet::default());
        let addr = serve(&db, mail.clone(), net.clone()).await;
        Fixture {
            db,
            addr,
            mail,
            net,
        }
    }

    fn browser(&self) -> Browser {
        Browser::new(self.addr, "198.51.100.1")
    }

    /// Sends every due mail through the fake SMTP.
    async fn deliver(&self) {
        let mailer: Arc<dyn Mailer> = self.mail.clone();
        accounts::deliver_outbox(&self.db.app, &mailer)
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

    /// A browser signed in as `email` with its password.
    async fn signed_in(&self, email: &str) -> Browser {
        let mut browser = self.browser();
        let page = sign_in(&mut browser, email, PASSWORD).await;
        assert_eq!(page.location.as_deref(), Some("/account"), "{}", page.body);
        browser
    }

    /// A firewall registered on this database and started against its sync API,
    /// syncing every 2 s (1 s margin), ready.
    async fn firewall(&self) -> common::Firewall {
        let registered = probation_server::fleet::register(
            &self.db.app,
            &probation_server::tenancy::Actor::Operator,
            "fw",
            &["127.0.0.0/8".parse().unwrap()],
        )
        .await
        .unwrap();
        let server = common::serve(self.db.app.clone(), Vec::new()).await;
        let firewall = common::Firewall::start(server, &registered.token, 2, 1).await;
        firewall.ready(Duration::from_secs(10)).await;
        firewall
    }
}

fn config() -> PortalConfig {
    let provider = |id: &str| portal::ProviderConfig {
        client_id: format!("{id}-client"),
        client_secret: format!("{id}-secret"),
    };
    PortalConfig {
        base_url: url::Url::parse(BASE_URL).unwrap(),
        google: Some(provider("google")),
        github: Some(provider("github")),
        microsoft: Some(provider("microsoft")),
        leaked_password_url: url::Url::parse("https://api.pwnedpasswords.com/range/").unwrap(),
        smtp: None,
        firewall_url: Some(url::Url::parse("https://fw.acme.test:8443").unwrap()),
    }
}

async fn serve(db: &Db, mail: Arc<FakeMail>, net: Arc<dyn Outbound>) -> SocketAddr {
    let portal = Portal::new(PortalDeps {
        pool: db.app.clone(),
        config: config(),
        outbound: net,
        mailer: Some(mail),
        secret_key: [7; 32],
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
    body: String,
}

impl Page {
    /// The CSRF token of the page's first form.
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
        let location = answer
            .headers()
            .get("location")
            .map(|value| value.to_str().unwrap().to_owned());
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
            body,
        }
    }
}

/// The SMTP relay: records each mail.
#[derive(Default)]
struct FakeMail {
    sent: Mutex<Vec<Mail>>,
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

async fn sign_in(browser: &mut Browser, email: &str, password: &str) -> Page {
    browser
        .submit(
            "/signin",
            "/signin",
            &[("email", email), ("password", password)],
        )
        .await
}

async fn sign_out(browser: &mut Browser) {
    let csrf = browser.get("/account").await.csrf();
    let out = browser.post_raw("/signout", &[("csrf", &csrf)]).await;
    assert_eq!(out.status, StatusCode::SEE_OTHER);
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

/// The 6-digit code of the base32 `secret` for the 30-second step at `unix` seconds.
fn totp_code(secret: &str, unix: u64) -> String {
    let secret = totp_rs::Secret::try_from_base32(secret.replace(' ', "")).unwrap();
    totp_rs::Builder::new()
        .with_secret(secret)
        .build_noncompliant()
        .generate(unix)
        .to_string()
}

/// Turns the authenticator on from `/account`.
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

/// Signs in through the IdP that `start` redirects to, as the person `claims` describe;
/// returns the portal's answer to the callback.
async fn oauth(
    fx: &Fixture,
    browser: &mut Browser,
    start: &str,
    claims: serde_json::Value,
) -> Page {
    let started = if start.starts_with("/account/") {
        browser.submit("/account", start, &[]).await
    } else {
        browser.get(start).await
    };
    assert_eq!(
        started.status,
        StatusCode::SEE_OTHER,
        "{start}: {}",
        started.body
    );
    let location = started.location.expect("a redirect to the IdP");
    let back = fx.net.authorize(&location, claims);
    browser.get(&back).await
}

/// Acme and Globex as most tests need them: Ana is Acme's org admin, Bob the group admin
/// of its Frontend group, Mia a member of Frontend, Max a member in no group, and Gus
/// Globex's org admin. Every login signs in with an email and password and has no
/// authenticator.
struct World {
    acme: PlaceRef,
    globex: PlaceRef,
    frontend: PlaceRef,
    data: PlaceRef,
    ana: i32,
    bob: i32,
    mia: i32,
    max: i32,
    gus: i32,
    /// Each login's user place.
    places: HashMap<i32, PlaceRef>,
}

impl World {
    async fn new(fx: &Fixture) -> World {
        let db = &fx.db;
        let acme = db.org("Acme").await;
        let globex = db.org("Globex").await;
        let frontend = db.group(acme, "Frontend").await;
        let data = db.group(acme, "Data").await;
        let ana = fx.person("ana@acme.test").await;
        let bob = fx.person("bob@acme.test").await;
        let mia = fx.person("mia@acme.test").await;
        let max = fx.person("max@acme.test").await;
        let gus = fx.person("gus@globex.test").await;
        let mut places = HashMap::new();
        places.insert(ana, db.member(ana, acme, None, "org_admin").await);
        places.insert(
            bob,
            db.member(bob, acme, Some(frontend), "group_admin").await,
        );
        places.insert(mia, db.member(mia, acme, Some(frontend), "member").await);
        places.insert(max, db.member(max, acme, None, "member").await);
        places.insert(gus, db.member(gus, globex, None, "org_admin").await);
        World {
            acme,
            globex,
            frontend,
            data,
            ana,
            bob,
            mia,
            max,
            gus,
            places,
        }
    }
}

/// The secret the keys page shows once after "Create key".
fn shown_key(page: &Page) -> String {
    between(&page.body, "<code id=\"new-key\">", "</code>").to_owned()
}

/// Creates a key named `name` on `/keys` in the browser's current place.
async fn create_key(browser: &mut Browser, name: &str) -> String {
    let page = browser.submit("/keys", "/keys", &[("name", name)]).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    shown_key(&page)
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

const IDP_KEY_DER: &str = concat!(
    "MIIEowIBAAKCAQEA1FhdRHb3tVOB7UA6+8qVngYxepSdA5xeZqX7kXGeVF0QNbZau39WLMYWNUr9c+v2MMXbfJzUx2f6IZhK",
    "NSSLEcPFcRpa379mcxyZ33hzqS96bmzs0iJG3mvIM6YA3QlIQ+4plRrqLcwNzOQLXjJRXGsslPKFHfp1zbwVkGyokwlbNtH7",
    "fMp03bhk7fwChnFyNGwmjPunuDZsSAULRCR247FMI3DRzdORQU7fyUClg1bXS9Fl/XvS77JnW7SjV7Zovr2Wm56CiA/oXfJa",
    "oHsPm46XH3J3XC4ahCQmopKmFiqOekWVBR7lrc79pyvUH1pbpAXQPqN0GabUGh5KbjZLcQIDAQABAoIBAA5y+tm7TKzCg29M",
    "9RaIGPk5S6mfLjX+MHBEsCMb+52a/YziHTdv+UGvsvgqY6e9MTHtbLuEgngVK7CYh8go9eueCjPhirh58jM4CYJq1Ff5Wpfk",
    "ApNj8LWW2Pcmvx1LUecJcDvsqm22WmQMSne87ctfoZd7DzLUhaqbt03uDuR+WUJmthJb/Igq3/Q08hkRfh9WL0qN5RUplsZq",
    "Ov4QPlEx9SbyAUZtKbZdLgU6JCAs/chY6fkUGU4iDZQ7O9ZHX7bOPc4sbT6gNyGnfg6pn2Douppztbxj0FIcAVqPTAhXnP/n",
    "2auKXOmXcUByHlW4plRqVjcV9/RJYVvdhFpvPEkCgYEA7C47j98QEmxLYTiDQwt6umY3KrUg+NM3d7yOuxFT3kt3FyNa46rj",
    "lQCvxR3ohiMC7uDzo7KZcwCf4N2TOEBajLubxYzPgCrd24sfB73X71hMxUSYm/SX8Gr2PHK8CNCSQayP/5rzmYVbJlUJArRq",
    "dRJ00DLSQoJpTDr3qISbJ4UCgYEA5ioV3LrM9iOAz/tXCI6IqR6V9oxTmZ9aZ+amigvhXYciKbJvhxGawkVzI18hDOb3OqGm",
    "B0teO96w89V721jYsCw8rRHHx+S7dtSRuc31/RJBXBsR38MAhlp89t6ogyxMpgoUcSQEhdMR8efxdjz8IAcflooKmNHrFon/",
    "NgWHWf0CgYAk2xYaXnHQniupMTtyk/ED8316YaeSjMtkGP2g/ZQ75UThTHgbfQhksSW8ue0WOZJ0mpAKpI1Dn/5TBeC6b3hx",
    "67jkPBQJaScT4oLmH176D6pzQkAaXjHzp41jY3gqW/nm27ng5lpLQ780nSJ51JOkT0wBTVz4Wgd6iN0q4/6eTQKBgQCz9tYv",
    "R9Q45Nu0Q5byttf+PE8PfvtjE+lRclRnfhCR27aHmeCAYPB71GfJkXk7KGDI9FnoPDMLZv0/On5krNyJK52pyUxHbP5zVJQ5",
    "DuS3Iw394aChMEz5wEkTkld6cSnhbeI78OikZrwSRMRVKiwNMuStBXRxtzk032OwrrP9VQKBgHHviFbZKmwV3b5aQv5y0wZY",
    "TVIvBm2sF7uinbGBKlfGHZnXLse2RcHidIAtfY57NrKsX3fBAXvfcqkAeW3/thxQuiLSYmFWlF+ZLpc1NGU4aTRqa+vOZbKk",
    "w+qvdOR802kM0QFN5trnFeUCZtp7GdVEOLr0+2WhuLp1MGT6STmk",
);
/// Its public modulus, base64url, for the JWKS.
const IDP_KEY_N: &str = "1FhdRHb3tVOB7UA6-8qVngYxepSdA5xeZqX7kXGeVF0QNbZau39WLMYWNUr9c-v2MMXbfJzUx2f6IZhKNSSLEcPFcRpa379mcxyZ33hzqS96bmzs0iJG3mvIM6YA3QlIQ-4plRrqLcwNzOQLXjJRXGsslPKFHfp1zbwVkGyokwlbNtH7fMp03bhk7fwChnFyNGwmjPunuDZsSAULRCR247FMI3DRzdORQU7fyUClg1bXS9Fl_XvS77JnW7SjV7Zovr2Wm56CiA_oXfJaoHsPm46XH3J3XC4ahCQmopKmFiqOekWVBR7lrc79pyvUH1pbpAXQPqN0GabUGh5KbjZLcQ";

/// One authorization the fake IdP granted, waiting for its code to be redeemed.
struct Grant {
    client_id: String,
    redirect_uri: String,
    challenge: String,
    /// The ID token claims, or GitHub's `/user` answer.
    claims: serde_json::Value,
    github: bool,
}

/// Every outside service the portal calls: the IdPs (each OIDC issuer answers discovery,
/// JWKS and its token endpoint; GitHub answers OAuth and `/user`) and the leaked-password
/// range API.
#[derive(Default)]
struct FakeNet {
    requests: Mutex<Vec<String>>,
    /// Passwords the range API reports as leaked.
    leaked: Mutex<Vec<String>>,
    codes: Mutex<HashMap<String, Grant>>,
    github_tokens: Mutex<HashMap<String, serde_json::Value>>,
    /// The range API never answers.
    leak_check_hangs: std::sync::atomic::AtomicBool,
}

const MICROSOFT_COMMON: &str = "https://login.microsoftonline.com/common/v2.0";

impl FakeNet {
    /// The user signs in at the IdP that `location` (the portal's redirect) points to and
    /// consents; returns the path the IdP sends the browser back to. `claims` are what the
    /// IdP asserts; `iss`, `aud`, `nonce`, `iat` and `exp` are filled in unless given.
    fn authorize(&self, location: &str, claims: serde_json::Value) -> String {
        let url = url::Url::parse(location).unwrap();
        let query: HashMap<String, String> = url.query_pairs().into_owned().collect();
        let github = url.host_str() == Some("github.com");
        let issuer = url
            .as_str()
            .split('?')
            .next()
            .unwrap()
            .trim_end_matches("/authorize")
            .to_owned();
        let issuer = if issuer == MICROSOFT_COMMON {
            format!(
                "https://login.microsoftonline.com/{}/v2.0",
                claims["tid"].as_str().unwrap()
            )
        } else {
            issuer
        };
        let mut claims = claims;
        if !github {
            let now = now_unix();
            let fill = [
                ("iss", serde_json::json!(issuer)),
                ("aud", serde_json::json!(query["client_id"])),
                ("nonce", serde_json::json!(query["nonce"])),
                ("iat", serde_json::json!(now)),
                ("exp", serde_json::json!(now + 300)),
            ];
            for (name, value) in fill {
                if claims.get(name).is_none() {
                    claims[name] = value;
                }
            }
        }
        let code = format!("code-{}", self.codes.lock().unwrap().len() + 1);
        self.codes.lock().unwrap().insert(
            code.clone(),
            Grant {
                client_id: query["client_id"].clone(),
                redirect_uri: query["redirect_uri"].clone(),
                challenge: query["code_challenge"].clone(),
                claims,
                github,
            },
        );
        let back = url::Url::parse_with_params(
            &query["redirect_uri"],
            &[("code", code.as_str()), ("state", query["state"].as_str())],
        )
        .unwrap();
        back.as_str().trim_start_matches(BASE_URL).to_owned()
    }

    fn id_token(claims: &serde_json::Value) -> String {
        use base64::Engine;
        let der = base64::engine::general_purpose::STANDARD
            .decode(IDP_KEY_DER)
            .unwrap();
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some("k1".to_owned());
        jsonwebtoken::encode(
            &header,
            claims,
            &jsonwebtoken::EncodingKey::from_rsa_der(&der),
        )
        .unwrap()
    }

    /// Redeems `code` as the token endpoint does: once, for its client, its redirect URI
    /// and the PKCE verifier of its challenge.
    fn redeem(&self, form: &HashMap<&str, &str>) -> Result<Grant, OutboundError> {
        use base64::Engine;
        use sha2::Digest;
        let grant = self
            .codes
            .lock()
            .unwrap()
            .remove(form.get("code").copied().unwrap_or_default())
            .ok_or(OutboundError::Status(400))?;
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
            sha2::Sha256::digest(form.get("code_verifier").copied().unwrap_or_default()),
        );
        let secret = format!("{}-secret", grant.client_id.trim_end_matches("-client"));
        let valid = form.get("client_id") == Some(&grant.client_id.as_str())
            && form.get("client_secret") == Some(&secret.as_str())
            && form.get("redirect_uri") == Some(&grant.redirect_uri.as_str())
            && challenge == grant.challenge;
        if valid {
            Ok(grant)
        } else {
            Err(OutboundError::Status(400))
        }
    }
}

impl FakeNet {
    /// The range API's answer for a 5-character SHA-1 prefix.
    fn range(&self, prefix: &str) -> Vec<u8> {
        use sha1::Digest;
        let mut lines = String::from("0018A45C4D1DEF81644B54AB7F969B88D65:0\r\n");
        for password in self.leaked.lock().unwrap().iter() {
            let digest = hex::encode_upper(sha1::Sha1::digest(password.as_bytes()));
            if digest.starts_with(prefix) {
                lines.push_str(&format!("{}:42\r\n", &digest[5..]));
            }
        }
        lines.into_bytes()
    }
}

#[async_trait::async_trait]
impl Outbound for FakeNet {
    async fn get(&self, url: &url::Url, _bearer: Option<&str>) -> Result<Vec<u8>, OutboundError> {
        self.requests.lock().unwrap().push(url.to_string());
        if url.host_str() == Some("api.pwnedpasswords.com") {
            if self.leak_check_hangs.load(Ordering::SeqCst) {
                std::future::pending::<()>().await;
            }
            let prefix = url.path().trim_start_matches("/range/");
            return Ok(self.range(prefix));
        }
        let text = url.as_str();
        if let Some(issuer) = text.strip_suffix("/.well-known/openid-configuration") {
            let named = if issuer == MICROSOFT_COMMON {
                "https://login.microsoftonline.com/{tenantid}/v2.0"
            } else {
                issuer
            };
            return Ok(serde_json::json!({
                "issuer": named,
                "authorization_endpoint": format!("{issuer}/authorize"),
                "token_endpoint": format!("{issuer}/token"),
                "jwks_uri": format!("{issuer}/jwks"),
            })
            .to_string()
            .into_bytes());
        }
        if text.ends_with("/jwks") {
            return Ok(serde_json::json!({"keys": [{
                "kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig", "n": IDP_KEY_N, "e": "AQAB",
            }]})
            .to_string()
            .into_bytes());
        }
        if text == "https://api.github.com/user" {
            let tokens = self.github_tokens.lock().unwrap();
            return match _bearer.and_then(|token| tokens.get(token)) {
                Some(user) => Ok(user.to_string().into_bytes()),
                None => Err(OutboundError::Status(401)),
            };
        }
        Err(OutboundError::Status(404))
    }

    async fn post_form(
        &self,
        url: &url::Url,
        form: &[(&str, &str)],
    ) -> Result<Vec<u8>, OutboundError> {
        self.requests.lock().unwrap().push(url.to_string());
        let form: HashMap<&str, &str> = form.iter().copied().collect();
        let text = url.as_str();
        if text == "https://github.com/login/oauth/access_token" {
            let grant = self.redeem(&form)?;
            assert!(grant.github);
            let token = format!("gho_{}", self.github_tokens.lock().unwrap().len() + 1);
            self.github_tokens
                .lock()
                .unwrap()
                .insert(token.clone(), grant.claims);
            return Ok(
                serde_json::json!({"access_token": token, "token_type": "bearer"})
                    .to_string()
                    .into_bytes(),
            );
        }
        if text.ends_with("/token") {
            let grant = self.redeem(&form)?;
            return Ok(serde_json::json!({
                "id_token": FakeNet::id_token(&grant.claims),
                "access_token": "unused",
                "token_type": "Bearer",
            })
            .to_string()
            .into_bytes());
        }
        Err(OutboundError::Status(404))
    }
}

/// T-portal-keys-create-once (C14, C99): the key is shown once; the list shows its name
/// and last 4 characters only (from `keys.last4`).
#[tokio::test]
async fn t_portal_keys_create_once() {
    let fx = Fixture::start().await;
    let world = World::new(&fx).await;
    let mut mia = fx.signed_in("mia@acme.test").await;
    let empty = mia.get("/keys").await;
    assert_eq!(empty.status, StatusCode::OK, "{}", empty.body);
    assert!(empty.has("Your keys in Acme"), "{}", empty.body);
    assert!(empty.has("You have no keys in Acme yet"), "{}", empty.body);

    let created = mia
        .submit("/keys", "/keys", &[("name", "work laptop")])
        .await;
    assert_eq!(created.status, StatusCode::OK, "{}", created.body);
    let secret = shown_key(&created);
    assert!(secret.starts_with("prb_") && secret.len() == 36, "{secret}");
    // The lines carry `[portal] firewall_url`, ready to paste (S6-10).
    assert!(
        created.has(&format!(
            "registry=https://fw.acme.test:8443/npm/\n//fw.acme.test:8443/npm/:_authToken={secret}"
        )),
        "the .npmrc lines: {}",
        created.body
    );
    assert!(
        created.has(&format!(
            "index-url = https://key:{secret}@fw.acme.test:8443/pypi/simple/"
        )),
        "the pip.conf line"
    );
    assert!(!created.has("FIREWALL"), "no placeholder once it is set");

    let (owner, place_kind, place_id, last4, hash): (i32, String, i32, String, Vec<u8>) =
        sqlx::query_as("SELECT owner_login, place_kind, place_id, last4, hash FROM keys")
            .fetch_one(&fx.db.owner)
            .await
            .unwrap();
    assert_eq!(owner, world.mia);
    assert_eq!(
        (place_kind.as_str(), place_id as u32),
        ("user", world.places[&world.mia].id)
    );
    assert_eq!(last4, secret[32..]);
    assert_ne!(hash, secret.as_bytes(), "only the hash is stored");

    let listed = mia.get("/keys").await;
    assert!(listed.has("work laptop"), "{}", listed.body);
    assert!(listed.has(&format!("…{last4}")), "{}", listed.body);
    assert!(!listed.has(&secret), "the key is never shown again");
    assert!(!listed.has(&secret[4..32]));
}

/// The place each key named `name` sits in.
async fn key_place(db: &Db, name: &str) -> (String, i32) {
    sqlx::query_as("SELECT place_kind, place_id FROM keys WHERE name = $1")
        .bind(name)
        .fetch_one(&db.owner)
        .await
        .unwrap()
}

/// T-portal-place-switch (C29): a login with a personal account and two organisations
/// switches place; a new key belongs to the chosen place.
#[tokio::test]
async fn t_portal_place_switch() {
    let fx = Fixture::start().await;
    let world = World::new(&fx).await;
    let personal = fx.db.personal(world.ana).await;
    let in_globex = fx.db.member(world.ana, world.globex, None, "member").await;
    let initech = fx.db.org("Initech").await;
    let mut ana = fx.signed_in("ana@acme.test").await;

    // The personal account comes first.
    let first = ana.get("/keys").await;
    assert!(
        first.has("Your keys in your personal account"),
        "{}",
        first.body
    );
    create_key(&mut ana, "home").await;
    assert_eq!(
        key_place(&fx.db, "home").await,
        ("personal".to_owned(), personal.id as i32)
    );

    // Two of Ana's organisations whose names differ only in inner whitespace, as rows
    // written before names were normalised: each is chosen by its id, never its label.
    let spaced = fx.db.org("Initrode  Inc").await;
    let single = fx.db.org("Initrode Inc").await;
    let in_spaced = fx.db.member(world.ana, spaced, None, "member").await;
    let in_single = fx.db.member(world.ana, single, None, "member").await;
    for (org, name, place) in [
        (world.globex, "globex box", in_globex),
        (spaced, "spaced box", in_spaced),
        (single, "single box", in_single),
        (world.acme, "acme box", world.places[&world.ana]),
    ] {
        let to = format!("org:{}", org.id);
        let switched = ana.submit("/keys", "/place", &[("to", &to)]).await;
        assert_eq!(
            switched.location.as_deref(),
            Some("/keys"),
            "{}",
            switched.body
        );
        let page = ana.get("/keys").await;
        assert!(
            page.has(&format!("<option value=\"{to}\" selected>")),
            "the chosen place is selected: {}",
            page.body
        );
        create_key(&mut ana, name).await;
        assert_eq!(
            key_place(&fx.db, name).await,
            ("user".to_owned(), place.id as i32)
        );
    }
    let back = ana.submit("/keys", "/place", &[("to", "personal")]).await;
    assert_eq!(back.location.as_deref(), Some("/keys"), "{}", back.body);
    assert!(
        ana.get("/keys")
            .await
            .has("<option value=\"personal\" selected>")
    );
    ana.submit(
        "/keys",
        "/place",
        &[("to", &format!("org:{}", world.acme.id))],
    )
    .await;

    // A place the login is not in, and a value that names none, are not found, and the
    // choice stays.
    for to in [
        format!("org:{}", initech.id),
        "Acme (organisation)".to_owned(),
        "org:x".to_owned(),
    ] {
        let foreign = ana.submit("/keys", "/place", &[("to", &to)]).await;
        assert_eq!(foreign.status, StatusCode::NOT_FOUND, "{to}");
    }
    assert!(ana.get("/keys").await.has("Your keys in Acme"));

    // Organisation names are stored with inner whitespace collapsed, and a name that
    // differs from a taken one only in whitespace or case is taken (C40).
    let created = ana
        .submit(
            "/account",
            "/account/org",
            &[("name", " Wayne   Enterprises ")],
        )
        .await;
    assert_eq!(created.status, StatusCode::SEE_OTHER, "{}", created.body);
    assert_eq!(
        fx.db
            .count("SELECT count(*) FROM orgs WHERE name = 'Wayne Enterprises'")
            .await,
        1
    );
    let taken = ana
        .submit(
            "/account",
            "/account/org",
            &[("name", "wayne\tenterprises")],
        )
        .await;
    assert_eq!(
        taken.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{}",
        taken.body
    );
    assert!(
        taken.has("That organisation name is taken"),
        "{}",
        taken.body
    );
    // The same at sign-up.
    let mut stark = fx.browser();
    stark
        .submit(
            "/signup",
            "/signup",
            &[
                ("email", "tony@stark.test"),
                ("password", PASSWORD),
                ("kind", "org"),
                ("org_name", "Stark \t  Industries"),
            ],
        )
        .await;
    fx.deliver().await;
    let link = fx.mail.link("tony@stark.test", "/verify-email?token=");
    stark.get(&link).await;
    assert_eq!(
        fx.db
            .count("SELECT count(*) FROM orgs WHERE name = 'Stark Industries'")
            .await,
        1
    );
}

/// T-portal-key-revoke (C14): the owner revokes a key on /keys and it answers 401 within
/// one interval; another member's attempt answers 404.
#[tokio::test]
async fn t_portal_key_revoke() {
    let fx = Fixture::start().await;
    World::new(&fx).await;
    let firewall = fx.firewall().await;
    let http = common::client();
    let mut mia = fx.signed_in("mia@acme.test").await;
    let key = create_key(&mut mia, "work laptop").await;
    assert_eq!(
        firewall.get(&http, "/npm/left-pad", &key).await.status(),
        StatusCode::OK
    );
    let id = key_id(&fx.db, "work laptop").await;
    let path = format!("/keys/{id}/revoke");

    let mut max = fx.signed_in("max@acme.test").await;
    let other = max.submit("/keys", &path, &[]).await;
    assert_eq!(other.status, StatusCode::NOT_FOUND, "{}", other.body);
    let unknown = max.submit("/keys", "/keys/999999/revoke", &[]).await;
    assert_eq!((other.status, &other.body), (unknown.status, &unknown.body));
    assert_eq!(
        firewall.get(&http, "/npm/left-pad", &key).await.status(),
        StatusCode::OK
    );

    let listed = mia.get("/keys").await;
    assert!(listed.has(&format!("action=\"{path}\"")), "{}", listed.body);
    let revoked = mia.submit("/keys", &path, &[]).await;
    assert_eq!(
        revoked.location.as_deref(),
        Some("/keys"),
        "{}",
        revoked.body
    );
    answers_within_interval(&firewall, &key, StatusCode::UNAUTHORIZED, "revoked").await;
    assert!(!mia.get("/keys").await.has("work laptop"));
}

/// Blocks npm `name` on `at`'s layer, saved by `login` through the edit flow.
async fn block(db: &Db, login: i32, at: PlaceRef, name: &str) {
    db.edit(login, at, |layer| {
        layer.blocks.push(probation_policy::Block::Package {
            ecosystem: probation_policy::Ecosystem::Npm,
            name: name.to_owned(),
            reason: None,
        })
    })
    .await
    .unwrap();
}

/// Creates a service key on `/keys`, attached to `attach` ("org" or a group id).
async fn create_service_key(browser: &mut Browser, name: &str, attach: &str) -> Page {
    browser
        .submit(
            "/keys",
            "/keys/service",
            &[("name", name), ("attach", attach)],
        )
        .await
}

/// T-portal-service-key-group (C14, C15): an org admin's service key attached to group G
/// is served under G's policy.
#[tokio::test]
async fn t_portal_service_key_group() {
    let fx = Fixture::start().await;
    let world = World::new(&fx).await;
    block(&fx.db, world.ana, world.frontend, "left-pad").await;
    let firewall = fx.firewall().await;
    let http = common::client();
    let mut ana = admin_browser(&fx, "ana@acme.test").await;

    let page = ana.get("/keys").await;
    assert!(page.has("Service keys"), "{}", page.body);
    let frontend = world.frontend.id.to_string();
    let created = create_service_key(&mut ana, "Frontend devices", &frontend).await;
    assert_eq!(created.status, StatusCode::OK, "{}", created.body);
    let in_group = shown_key(&created);
    let created = create_service_key(&mut ana, "All laptops", "org").await;
    let in_org = shown_key(&created);
    assert_eq!(
        key_place(&fx.db, "Frontend devices").await,
        ("group".to_owned(), world.frontend.id as i32)
    );

    assert_eq!(
        firewall
            .get(&http, "/npm/left-pad", &in_group)
            .await
            .status(),
        StatusCode::FORBIDDEN,
        "Frontend blocks left-pad"
    );
    assert_eq!(
        firewall.get(&http, "/npm/left-pad", &in_org).await.status(),
        StatusCode::OK
    );
    let listed = ana.get("/keys").await;
    assert!(listed.has("Frontend group"), "{}", listed.body);
    assert!(listed.has("ana@acme.test"), "created by: {}", listed.body);

    // A member creates none, and nothing attaches to another tenant's group.
    let mut mia = fx.signed_in("mia@acme.test").await;
    assert!(!mia.get("/keys").await.has("Service keys"));
    let refused = create_service_key(&mut mia, "mine", &frontend).await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN, "{}", refused.body);
    let globex_group = fx.db.group(world.globex, "Ops").await;
    let foreign = create_service_key(&mut ana, "theirs", &globex_group.id.to_string()).await;
    assert_eq!(foreign.status, StatusCode::NOT_FOUND, "{}", foreign.body);
    assert_eq!(
        fx.db
            .count("SELECT count(*) FROM keys WHERE kind = 'service'")
            .await,
        2
    );
}

/// T-portal-group-admin-revoke-service-key (C50): a group admin revokes a service key of
/// their group created by an org admin; a key of another group answers 404.
#[tokio::test]
async fn t_portal_group_admin_revoke_service_key() {
    let fx = Fixture::start().await;
    let world = World::new(&fx).await;
    let mut ana = admin_browser(&fx, "ana@acme.test").await;
    create_service_key(&mut ana, "Frontend devices", &world.frontend.id.to_string()).await;
    create_service_key(&mut ana, "Data boxes", &world.data.id.to_string()).await;
    create_service_key(&mut ana, "All laptops", "org").await;

    let mut bob = admin_browser(&fx, "bob@acme.test").await;
    let page = bob.get("/keys").await;
    assert!(page.has("Frontend devices"), "{}", page.body);
    assert!(
        !page.has("Data boxes") && !page.has("All laptops"),
        "{}",
        page.body
    );
    for name in ["Data boxes", "All laptops"] {
        let id = key_id(&fx.db, name).await;
        let other = bob
            .submit("/keys", &format!("/keys/{id}/revoke"), &[])
            .await;
        assert_eq!(
            other.status,
            StatusCode::NOT_FOUND,
            "{name}: {}",
            other.body
        );
    }
    let id = key_id(&fx.db, "Frontend devices").await;
    let revoked = bob
        .submit("/keys", &format!("/keys/{id}/revoke"), &[])
        .await;
    assert_eq!(
        revoked.location.as_deref(),
        Some("/keys"),
        "{}",
        revoked.body
    );
    let live: Vec<String> =
        sqlx::query_scalar("SELECT name FROM keys WHERE revoked_at IS NULL ORDER BY id")
            .fetch_all(&fx.db.owner)
            .await
            .unwrap();
    assert_eq!(live, ["Data boxes", "All laptops"]);
}

/// Sets the organisation default limits (the global admin's limits page is slice 7).
async fn org_limits(db: &Db, max_keys: i32, max_service_keys: i32) {
    sqlx::query(
        "UPDATE limits SET max_keys = $1, max_service_keys = $2
         WHERE scope_kind = 'org' AND scope_id IS NULL",
    )
    .bind(max_keys)
    .bind(max_service_keys)
    .execute(&db.owner)
    .await
    .unwrap();
}

/// T-portal-key-limits (C51, C53): creating past the limit is refused, for a member's
/// own keys and for the organisation's service keys; after the limit is lowered below
/// the count, existing keys still answer 200.
#[tokio::test]
async fn t_portal_key_limits() {
    let fx = Fixture::start().await;
    World::new(&fx).await;
    org_limits(&fx.db, 2, 1).await;
    let firewall = fx.firewall().await;
    let http = common::client();
    let mut mia = fx.signed_in("mia@acme.test").await;
    let first = create_key(&mut mia, "one").await;
    let second = create_key(&mut mia, "two").await;
    let third = mia.submit("/keys", "/keys", &[("name", "three")]).await;
    assert_eq!(third.status, StatusCode::CONFLICT, "{}", third.body);
    assert!(
        third.has("You already have 2 keys in Acme, the most each member may have."),
        "{}",
        third.body
    );
    // The limit is per member: Max still has room.
    let mut max = fx.signed_in("max@acme.test").await;
    create_key(&mut max, "max's").await;

    let mut ana = admin_browser(&fx, "ana@acme.test").await;
    let service = create_service_key(&mut ana, "All laptops", "org").await;
    assert_eq!(service.status, StatusCode::OK, "{}", service.body);
    let past = create_service_key(&mut ana, "More laptops", "org").await;
    assert_eq!(past.status, StatusCode::CONFLICT, "{}", past.body);
    assert!(
        past.has("Acme already has 1 service keys, the most it may have."),
        "{}",
        past.body
    );
    assert_eq!(
        fx.db
            .count("SELECT count(*) FROM keys WHERE kind <> 'firewall'")
            .await,
        4
    );

    // Lowered below the count: nothing stops, but nothing new is made (C53).
    org_limits(&fx.db, 1, 0).await;
    for key in [&first, &second] {
        assert_eq!(
            firewall.get(&http, "/npm/left-pad", key).await.status(),
            StatusCode::OK
        );
    }
    let again = mia.submit("/keys", "/keys", &[("name", "again")]).await;
    assert_eq!(again.status, StatusCode::CONFLICT, "{}", again.body);
}

const DAY: u64 = 86_400;

/// The policy page of `place`.
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

/// The stored revision and freeze of `place`'s layer.
async fn layer_row(db: &Db, place: PlaceRef) -> (i64, Option<i64>) {
    let kind = &policy_path(place)[8..];
    let kind = kind.split('-').next().unwrap().to_owned();
    sqlx::query_as(
        "SELECT revision, freeze_seconds FROM policy_layers WHERE place_kind = $1 AND place_id = $2",
    )
    .bind(kind)
    .bind(place.id as i32)
    .fetch_one(&db.owner)
    .await
    .unwrap()
}

/// Submits one action of `place`'s policy form, at the revision the page shows.
async fn policy_action(browser: &mut Browser, place: PlaceRef, fields: &[(&str, &str)]) -> Page {
    let path = policy_path(place);
    let page = browser.get(&path).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    let revision = hidden(&page.body, "revision").expect("the form's revision");
    let csrf = page.csrf();
    let mut fields = fields.to_vec();
    fields.push(("revision", &revision));
    fields.push(("csrf", &csrf));
    browser.post_raw(&path, &fields).await
}

/// "Save changes" with a freeze, an OSV setting and no switch on.
fn save(
    freeze: &'static str,
    unit: &'static str,
    osv: &'static str,
) -> [(&'static str, &'static str); 4] {
    [
        ("action", "save"),
        ("freeze", freeze),
        ("unit", unit),
        ("osv", osv),
    ]
}

/// T-portal-edit-refusal (C8): a looser edit whose switch is off re-renders the form
/// naming the switch, and the layer revision is unchanged.
#[tokio::test]
async fn t_portal_edit_refusal() {
    let fx = Fixture::start().await;
    let world = World::new(&fx).await;
    fx.db
        .edit(world.ana, world.acme, |layer| {
            layer.freeze_seconds = Some(2 * DAY);
            layer.osv = Some(probation_policy::OsvSetting::On);
        })
        .await
        .unwrap();
    let before = layer_row(&fx.db, world.frontend).await;
    let mut bob = admin_browser(&fx, "bob@acme.test").await;
    for (fields, switch) in [
        (
            save("1", "days", "inherit").to_vec(),
            "Allow a shorter freeze",
        ),
        (
            save("", "days", "log_only").to_vec(),
            "Allow turning OSV off",
        ),
        (
            vec![
                ("action", "add_exception"),
                ("ecosystem", "npm"),
                ("name", "event-stream"),
                ("version", ""),
                ("lifts_block", "on"),
            ],
            "Allow package exceptions",
        ),
    ] {
        let refused = policy_action(&mut bob, world.frontend, &fields).await;
        assert_eq!(
            refused.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{}",
            refused.body
        );
        assert!(refused.has("Not saved"), "{}", refused.body);
        assert!(refused.has(switch), "{switch}: {}", refused.body);
        assert!(refused.has("name=\"revision\""), "the form is shown again");
        assert_eq!(layer_row(&fx.db, world.frontend).await, before);
    }
    // A stricter edit saves.
    let saved = policy_action(&mut bob, world.frontend, &save("3", "days", "on")).await;
    assert_eq!(saved.status, StatusCode::SEE_OTHER, "{}", saved.body);
    assert_eq!(
        layer_row(&fx.db, world.frontend).await,
        (before.0 + 1, Some(3 * DAY as i64))
    );
}

/// T-portal-edit-conflict (C8, C25): two forms opened at the same revision: the second
/// save shows "changed meanwhile" and the layer holds the first edit.
#[tokio::test]
async fn t_portal_edit_conflict() {
    let fx = Fixture::start().await;
    let world = World::new(&fx).await;
    let mut bob = admin_browser(&fx, "bob@acme.test").await;
    let path = policy_path(world.frontend);
    let first = bob.get(&path).await;
    let second = bob.get(&path).await;
    let revision = hidden(&first.body, "revision").unwrap();
    assert_eq!(hidden(&second.body, "revision").unwrap(), revision);
    let post = |freeze: &'static str| {
        let mut fields = save(freeze, "days", "inherit").to_vec();
        fields.push(("revision", &revision));
        fields
    };
    let csrf = first.csrf();
    let mut fields = post("3");
    fields.push(("csrf", &csrf));
    let saved = bob.post_raw(&path, &fields).await;
    assert_eq!(saved.status, StatusCode::SEE_OTHER, "{}", saved.body);
    let mut fields = post("5");
    fields.push(("csrf", &csrf));
    let late = bob.post_raw(&path, &fields).await;
    assert_eq!(late.status, StatusCode::CONFLICT, "{}", late.body);
    assert!(late.has("changed meanwhile"), "{}", late.body);
    assert_eq!(
        layer_row(&fx.db, world.frontend).await.1,
        Some(3 * DAY as i64),
        "the layer holds the first edit"
    );
}

/// The `<input>` of the checkbox `name` on `page`.
fn checkbox<'a>(page: &'a Page, name: &str) -> &'a str {
    let start = page
        .body
        .find(&format!("<input type=\"checkbox\" name=\"{name}\""))
        .unwrap_or_else(|| panic!("a {name} checkbox in {}", page.body));
    let end = page.body[start..].find('>').unwrap() + start;
    &page.body[start..=end]
}

/// T-portal-switch-not-grantable (C45): a switch the layer above does not give is
/// rendered disabled, and a forged POST turning it on is refused.
#[tokio::test]
async fn t_portal_switch_not_grantable() {
    let fx = Fixture::start().await;
    let world = World::new(&fx).await;
    let admin = fx.db.global_admin().await;
    // The platform lets organisations pass down exceptions only.
    fx.db
        .edit(admin, tenancy_platform(), |layer| {
            layer.allow.exceptions = true
        })
        .await
        .unwrap();
    let mut ana = fx.signed_in("ana@acme.test").await;
    let page = ana.get(&policy_path(world.acme)).await;
    assert!(
        !checkbox(&page, "allow_exceptions").contains("disabled"),
        "{}",
        page.body
    );
    for name in ["allow_osv_off", "allow_shorter_freeze"] {
        assert!(
            checkbox(&page, name).contains("disabled"),
            "{name}: {}",
            page.body
        );
    }
    let before = layer_row(&fx.db, world.acme).await;
    let mut forged = save("", "days", "inherit").to_vec();
    forged.push(("allow_osv_off", "on"));
    let refused = policy_action(&mut ana, world.acme, &forged).await;
    assert_eq!(
        refused.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{}",
        refused.body
    );
    assert!(refused.has("Allow turning OSV off"), "{}", refused.body);
    assert_eq!(layer_row(&fx.db, world.acme).await, before);
    // The one it holds passes down.
    let mut granted = save("", "days", "inherit").to_vec();
    granted.push(("allow_exceptions", "on"));
    let saved = policy_action(&mut ana, world.acme, &granted).await;
    assert_eq!(saved.status, StatusCode::SEE_OTHER, "{}", saved.body);
}

fn tenancy_platform() -> PlaceRef {
    probation_server::tenancy::PLATFORM
}

/// The effective policy of `place`, resolved from its stored chain as a firewall would.
async fn effective(db: &Db, admin: i32, place: PlaceRef) -> probation_policy::EffectivePolicy {
    let (_, authorized) = db.as_admin(admin, place).await;
    let mut layers = Vec::new();
    for link in authorized.chain() {
        let (_, link) = db.as_admin(admin, *link).await;
        layers.push(db.store().layer(&link).await.unwrap().0);
    }
    probation_policy::resolve(&layers)
}

fn freeze_for(policy: &probation_policy::EffectivePolicy, name: &str) -> u64 {
    policy
        .rules_for(probation_policy::Ecosystem::Npm, name, "1.0.0")
        .freeze_seconds
}

/// T-portal-not-in-effect (C47, C124): a saved shorter freeze shows "not in effect while
/// a stricter rule above applies" after the parent switch goes off, and applies again
/// when it goes back on; for a package whose upper freeze an exception lifts, the kept
/// value applies; while it is not in effect, adding a block saves and the freeze stays
/// stored.
#[tokio::test]
async fn t_portal_not_in_effect() {
    const LABEL: &str = "not in effect while a stricter rule above applies";
    let fx = Fixture::start().await;
    let world = World::new(&fx).await;
    let admin = fx.db.global_admin().await;
    fx.db
        .edit(admin, tenancy_platform(), |layer| {
            layer.allow.shorter_freeze = true;
        })
        .await
        .unwrap();
    let acme_switch = |on: bool| {
        let db = &fx.db;
        let ana = world.ana;
        let acme = world.acme;
        async move {
            db.edit(ana, acme, |layer| {
                layer.freeze_seconds = Some(2 * DAY);
                layer.allow.shorter_freeze = on;
            })
            .await
            .unwrap();
        }
    };
    acme_switch(true).await;
    let mut bob = admin_browser(&fx, "bob@acme.test").await;
    let saved = policy_action(&mut bob, world.frontend, &save("1", "days", "inherit")).await;
    assert_eq!(saved.status, StatusCode::SEE_OTHER, "{}", saved.body);
    assert!(!bob.get(&policy_path(world.frontend)).await.has(LABEL));
    assert_eq!(
        freeze_for(&effective(&fx.db, admin, world.frontend).await, "x"),
        DAY
    );

    acme_switch(false).await;
    let page = bob.get(&policy_path(world.frontend)).await;
    assert!(page.has(LABEL), "{}", page.body);
    assert_eq!(
        freeze_for(&effective(&fx.db, admin, world.frontend).await, "x"),
        2 * DAY
    );

    // An organisation exception lifts its own freeze for acme-kit: the kept day applies.
    fx.db
        .edit(world.ana, world.acme, |layer| {
            layer.exceptions.push(probation_policy::Exception {
                ecosystem: probation_policy::Ecosystem::Npm,
                name: "acme-kit".to_owned(),
                version: None,
                lifts: probation_policy::Lifts {
                    freeze: true,
                    ..Default::default()
                },
            })
        })
        .await
        .unwrap();
    let policy = effective(&fx.db, admin, world.frontend).await;
    assert_eq!(freeze_for(&policy, "acme-kit"), DAY);
    assert_eq!(freeze_for(&policy, "x"), 2 * DAY);

    // A block still saves, and the kept freeze stays stored.
    let blocked = policy_action(
        &mut bob,
        world.frontend,
        &[
            ("action", "add_block"),
            ("ecosystem", "npm"),
            ("name", "colors"),
            ("what", "package"),
        ],
    )
    .await;
    assert_eq!(blocked.status, StatusCode::SEE_OTHER, "{}", blocked.body);
    assert_eq!(layer_row(&fx.db, world.frontend).await.1, Some(DAY as i64));

    acme_switch(true).await;
    assert!(!bob.get(&policy_path(world.frontend)).await.has(LABEL));
    assert_eq!(
        freeze_for(&effective(&fx.db, admin, world.frontend).await, "x"),
        DAY
    );
}

/// T-portal-freeze-range (C44): 0 hours and 365 days are accepted; 366 days is refused.
#[tokio::test]
async fn t_portal_freeze_range() {
    let fx = Fixture::start().await;
    let world = World::new(&fx).await;
    let mut ana = admin_browser(&fx, "ana@acme.test").await;
    for (freeze, unit, want) in [
        ("0", "hours", Some(0)),
        ("365", "days", Some(365 * DAY as i64)),
    ] {
        let saved = policy_action(&mut ana, world.acme, &save(freeze, unit, "inherit")).await;
        assert_eq!(
            saved.status,
            StatusCode::SEE_OTHER,
            "{freeze} {unit}: {}",
            saved.body
        );
        assert_eq!(layer_row(&fx.db, world.acme).await.1, want);
    }
    let before = layer_row(&fx.db, world.acme).await;
    let refused = policy_action(&mut ana, world.acme, &save("366", "days", "inherit")).await;
    assert_eq!(
        refused.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{}",
        refused.body
    );
    assert!(refused.has("from 0 hours to 365 days"), "{}", refused.body);
    assert_eq!(layer_row(&fx.db, world.acme).await, before);
}

/// T-portal-block-ecosystem (C31, C119): a package or version block, or an exception,
/// without npm or PyPI is refused; a digest-only file block is accepted.
#[tokio::test]
async fn t_portal_block_ecosystem() {
    let fx = Fixture::start().await;
    let world = World::new(&fx).await;
    let mut ana = admin_browser(&fx, "ana@acme.test").await;
    let before = layer_row(&fx.db, world.acme).await;
    for fields in [
        vec![
            ("action", "add_block"),
            ("name", "left-pad"),
            ("what", "package"),
        ],
        vec![
            ("action", "add_block"),
            ("ecosystem", "cargo"),
            ("name", "left-pad"),
            ("what", "version"),
            ("version", "1.3.0"),
        ],
        vec![
            ("action", "add_exception"),
            ("ecosystem", ""),
            ("name", "left-pad"),
            ("lifts_block", "on"),
        ],
    ] {
        let refused = policy_action(&mut ana, world.acme, &fields).await;
        assert_eq!(
            refused.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{fields:?}: {}",
            refused.body
        );
        assert!(refused.has("Choose npm or PyPI"), "{}", refused.body);
        assert_eq!(layer_row(&fx.db, world.acme).await, before);
    }
    let digest = "a".repeat(64);
    let file = policy_action(
        &mut ana,
        world.acme,
        &[
            ("action", "add_block"),
            ("what", "file"),
            ("algorithm", "sha256"),
            ("digest", &digest),
        ],
    )
    .await;
    assert_eq!(file.status, StatusCode::SEE_OTHER, "{}", file.body);
    let stored: (Option<String>, Option<String>, String) =
        sqlx::query_as("SELECT ecosystem, name, digest FROM policy_blocks")
            .fetch_one(&fx.db.owner)
            .await
            .unwrap();
    assert_eq!(stored, (None, None, digest));
}

/// Every row the slice's routes can write, as one digest.
async fn state(db: &Db) -> String {
    let tables = [
        "orgs",
        "groups",
        "memberships",
        "invitations",
        "leave_requests",
        "org_ip_ranges",
        "keys",
        "policy_layers",
        "policy_blocks",
        "policy_exceptions",
        "totp",
        "sign_in_methods",
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

/// One of each row an organisation page acts on, owned by Acme: (invitation, range,
/// leave request).
async fn acme_rows(db: &Db, world: &World) -> (i32, i32, i32) {
    let invitation: i32 = sqlx::query_scalar(
        "INSERT INTO invitations (token_hash, org_id, role, created_by, expires_at, email)
         VALUES ('\\x00', $1, 'member', $2, now() + interval '7 days', 'erin@acme.test') RETURNING id",
    )
    .bind(world.acme.id as i32)
    .bind(world.ana)
    .fetch_one(&db.owner)
    .await
    .unwrap();
    let range: i32 = sqlx::query_scalar(
        "INSERT INTO org_ip_ranges (org_id, cidr) VALUES ($1, '192.0.2.0/24') RETURNING id",
    )
    .bind(world.acme.id as i32)
    .fetch_one(&db.owner)
    .await
    .unwrap();
    let leave: i32 = sqlx::query_scalar(
        "INSERT INTO leave_requests (login_id, org_id) VALUES ($1, $2) RETURNING id",
    )
    .bind(world.max)
    .bind(world.acme.id as i32)
    .fetch_one(&db.owner)
    .await
    .unwrap();
    (invitation, range, leave)
}

/// The organisation page's routes for org admins, with every `{…}` replaced by an Acme
/// id the route accepts. The leave and cancel routes are every member's own.
async fn org_admin_routes(db: &Db, world: &World) -> Vec<(&'static str, String)> {
    let (invitation, range, leave) = acme_rows(db, world).await;
    // Restoring needs a deleted organisation Ana runs.
    let deleted = db.org("Initech").await;
    db.member(world.ana, deleted, None, "org_admin").await;
    sqlx::query(
        "UPDATE orgs SET deleted_at = now(), restore_until = now() + interval '30 days' WHERE id = $1",
    )
    .bind(deleted.id as i32)
    .execute(&db.owner)
    .await
    .unwrap();
    let id_for = |path: &str| {
        let id = if path.ends_with("/restore") {
            deleted.id as i32
        } else if path.starts_with("/org/members/") {
            world.places[&world.mia].id as i32
        } else if path.starts_with("/org/groups/") {
            world.frontend.id as i32
        } else if path.starts_with("/org/invitations/") {
            invitation
        } else if path.starts_with("/org/ranges/") {
            range
        } else if path.starts_with("/org/leave/") {
            leave
        } else {
            world.acme.id as i32
        };
        id.to_string()
    };
    portal::route_table()
        .into_iter()
        .filter(|(_, path)| {
            path.starts_with("/org/")
                && !path.ends_with("/leave")
                && !path.ends_with("/leave/cancel")
        })
        .map(|(method, path)| {
            let concrete = path
                .replace("{id}", &id_for(path))
                .replace("{org}", &id_for(path));
            (method, concrete)
        })
        .collect()
}

/// T-portal-admin-totp-required (C24, C38, C60): an org admin with a password login and
/// no TOTP is sent to TOTP set-up on every /org admin route, and nothing is written; a
/// Google-only org admin reaches them with no TOTP prompt.
#[tokio::test]
async fn t_portal_admin_totp_required() {
    let fx = Fixture::start().await;
    let world = World::new(&fx).await;
    let routes = org_admin_routes(&fx.db, &world).await;
    assert!(routes.len() >= 19, "{routes:?}");
    // A member's key, and what a firewall reported for another member's.
    let mut mia = fx.signed_in("mia@acme.test").await;
    create_key(&mut mia, "mia key").await;
    let mut max = fx.signed_in("max@acme.test").await;
    create_key(&mut max, "max key").await;
    let firewall = registered_firewall(&fx.db).await;
    activity(
        &fx.db,
        firewall,
        "max key",
        "pkg-max",
        "blocked",
        "org",
        "NULL, NULL",
    )
    .await;
    let mut ana = fx.signed_in("ana@acme.test").await;
    let csrf = ana.get("/keys").await.csrf();
    let before = state(&fx.db).await;
    for (method, path) in &routes {
        let page = match *method {
            "GET" => ana.get(path).await,
            _ => {
                ana.post_raw(
                    path,
                    &[
                        ("csrf", &csrf),
                        ("confirm", "Acme"),
                        ("name", "x"),
                        ("role", "member"),
                        ("group", "none"),
                    ],
                )
                .await
            }
        };
        assert_eq!(
            (page.status, page.location.as_deref()),
            (StatusCode::SEE_OTHER, Some("/account#totp-heading")),
            "{method} {path}: {}",
            page.body
        );
    }
    // Every other admin action is held back the same way: the organisation's and a
    // group's policy, a service key, revoking another member's key (B1).
    let to_setup = (StatusCode::SEE_OTHER, Some("/account#totp-heading"));
    for place in [world.acme, world.frontend] {
        let saved = policy_action(&mut ana, place, &save("9", "days", "on")).await;
        assert_eq!(
            (saved.status, saved.location.as_deref()),
            to_setup,
            "{place:?}: {}",
            saved.body
        );
    }
    let service = create_service_key(&mut ana, "laptops", "org").await;
    assert_eq!(
        (service.status, service.location.as_deref()),
        to_setup,
        "{}",
        service.body
    );
    let mia_key = key_id(&fx.db, "mia key").await;
    let revoke = ana
        .submit("/keys", &format!("/keys/{mia_key}/revoke"), &[])
        .await;
    assert_eq!(
        (revoke.status, revoke.location.as_deref()),
        to_setup,
        "{}",
        revoke.body
    );
    assert_eq!(state(&fx.db).await, before, "nothing written");
    // Activity and the audit log fall back to what a member sees.
    let activity_page = ana.get("/activity").await;
    assert!(!activity_page.has("pkg-max"), "{}", activity_page.body);
    let audit_page = ana.get("/audit").await;
    assert!(audit_page.has("Only org admins"), "{}", audit_page.body);
    // C24 asks the authenticator of global and org admins only: a group admin with a
    // password alone runs their group.
    let mut bob = fx.signed_in("bob@acme.test").await;
    let group_saved = policy_action(&mut bob, world.frontend, &save("4", "days", "on")).await;
    assert_eq!(
        (group_saved.status, group_saved.location),
        (StatusCode::SEE_OTHER, Some(policy_path(world.frontend))),
        "{}",
        group_saved.body
    );

    let org_page = format!("/org/{}", world.acme.id);
    // A password session opened before the authenticator was turned on ends then: it
    // never becomes an admin session without the code.
    let mut earlier = fx.signed_in("ana@acme.test").await;
    turn_totp_on(&mut ana).await;
    let ended = earlier.get("/keys").await;
    assert_eq!(ended.location.as_deref(), Some("/signin"), "{}", ended.body);
    let late_save = earlier
        .post_raw(
            &policy_path(world.acme),
            &[("csrf", &csrf), ("action", "save")],
        )
        .await;
    assert_eq!(
        late_save.status,
        StatusCode::FORBIDDEN,
        "{}",
        late_save.body
    );
    assert!(
        ana.get("/activity").await.has("pkg-max"),
        "with the authenticator, all of Acme"
    );
    let saved = policy_action(&mut ana, world.acme, &save("9", "days", "on")).await;
    assert_eq!(saved.status, StatusCode::SEE_OTHER, "{}", saved.body);
    assert_eq!(saved.location, Some(policy_path(world.acme)));
    let page = ana.get(&org_page).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    assert!(page.has("Members"), "{}", page.body);

    // An org admin who signs in with Google relies on Google's second factor.
    let mut google = fx.browser();
    let back = oauth(
        &fx,
        &mut google,
        "/oauth/google/start",
        serde_json::json!({"sub": "g-7", "email": "gina@gmail.test"}),
    )
    .await;
    assert_eq!(back.location.as_deref(), Some("/account"), "{}", back.body);
    let gina: i32 =
        sqlx::query_scalar("SELECT login_id FROM sign_in_methods WHERE subject = 'g-7'")
            .fetch_one(&fx.db.owner)
            .await
            .unwrap();
    fx.db.member(gina, world.acme, None, "org_admin").await;
    let page = google.get(&org_page).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
}

/// `email` signed in with its password and an authenticator turned on: what an org
/// admin needs for /org (C24).
async fn admin_browser(fx: &Fixture, email: &str) -> Browser {
    let mut browser = fx.signed_in(email).await;
    turn_totp_on(&mut browser).await;
    browser
}

async fn group_of(db: &Db, member: PlaceRef) -> Option<i32> {
    sqlx::query_scalar("SELECT group_id FROM memberships WHERE id = $1")
        .bind(member.id as i32)
        .fetch_one(&db.owner)
        .await
        .unwrap()
}

/// T-portal-group-move-org-admin-only (C27): a group admin moving a user answers 403.
#[tokio::test]
async fn t_portal_group_move_org_admin_only() {
    let fx = Fixture::start().await;
    let world = World::new(&fx).await;
    let mia = world.places[&world.mia];
    let mut bob = admin_browser(&fx, "bob@acme.test").await;
    let before = state(&fx.db).await;
    let path = format!("/org/members/{}/group", mia.id);
    let data = world.data.id.to_string();
    let moved = bob.submit("/keys", &path, &[("group", &data)]).await;
    assert_eq!(moved.status, StatusCode::FORBIDDEN, "{}", moved.body);
    assert_eq!(state(&fx.db).await, before);
    assert_eq!(group_of(&fx.db, mia).await, Some(world.frontend.id as i32));
}

/// T-sync-group-move (C10, C27): an org admin's move succeeds, and the user's keys are
/// served under the new group's policy within one interval.
#[tokio::test]
async fn t_sync_group_move() {
    let fx = Fixture::start().await;
    let world = World::new(&fx).await;
    block(&fx.db, world.ana, world.data, "left-pad").await;
    let firewall = fx.firewall().await;
    let http = common::client();
    let mut mia = fx.signed_in("mia@acme.test").await;
    let key = create_key(&mut mia, "laptop").await;
    assert_eq!(
        firewall.get(&http, "/npm/left-pad", &key).await.status(),
        StatusCode::OK
    );
    let mut ana = admin_browser(&fx, "ana@acme.test").await;
    let member = world.places[&world.mia];
    let org_page = format!("/org/{}", world.acme.id);
    let page = ana.get(&org_page).await;
    let path = format!("/org/members/{}/group", member.id);
    assert!(page.has(&format!("action=\"{path}\"")), "{}", page.body);
    let data = world.data.id.to_string();
    let moved = ana.submit(&org_page, &path, &[("group", &data)]).await;
    assert_eq!(
        moved.location.as_deref(),
        Some(org_page.as_str()),
        "{}",
        moved.body
    );
    assert_eq!(group_of(&fx.db, member).await, Some(world.data.id as i32));
    answers_within_interval(&firewall, &key, StatusCode::FORBIDDEN, "moved to Data").await;
    // Back to no group: the organisation policy, which blocks nothing.
    ana.submit(&org_page, &path, &[("group", "none")]).await;
    answers_within_interval(&firewall, &key, StatusCode::OK, "moved to no group").await;
}

async fn role_of(db: &Db, member: PlaceRef) -> String {
    sqlx::query_scalar("SELECT role FROM memberships WHERE id = $1")
        .bind(member.id as i32)
        .fetch_one(&db.owner)
        .await
        .unwrap()
}

/// T-portal-group-admin-in-group (C59): appointing someone who is in no group as a group
/// admin is refused; a member of a group can be appointed, and runs that group.
#[tokio::test]
async fn t_portal_group_admin_in_group() {
    let fx = Fixture::start().await;
    let world = World::new(&fx).await;
    let mut ana = admin_browser(&fx, "ana@acme.test").await;
    let org_page = format!("/org/{}", world.acme.id);
    let max = world.places[&world.max];
    let before = state(&fx.db).await;
    let refused = ana
        .submit(
            &org_page,
            &format!("/org/members/{}/role", max.id),
            &[("role", "group_admin")],
        )
        .await;
    assert_eq!(refused.status, StatusCode::CONFLICT, "{}", refused.body);
    assert!(refused.has("is in no group"), "{}", refused.body);
    assert_eq!(state(&fx.db).await, before);
    assert_eq!(role_of(&fx.db, max).await, "member");

    let mia = world.places[&world.mia];
    let appointed = ana
        .submit(
            &org_page,
            &format!("/org/members/{}/role", mia.id),
            &[("role", "group_admin")],
        )
        .await;
    assert_eq!(
        appointed.location.as_deref(),
        Some(org_page.as_str()),
        "{}",
        appointed.body
    );
    assert_eq!(role_of(&fx.db, mia).await, "group_admin");
}

async fn org_admins(db: &Db, org: PlaceRef) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM memberships WHERE org_id = $1 AND role = 'org_admin'")
        .bind(org.id as i32)
        .fetch_one(&db.owner)
        .await
        .unwrap()
}

async fn leave_request_of(db: &Db, login: i32) -> i32 {
    sqlx::query_scalar("SELECT id FROM leave_requests WHERE login_id = $1")
        .bind(login)
        .fetch_one(&db.owner)
        .await
        .unwrap()
}

/// T-portal-last-org-admin (C60, T21): removing or demoting the last org admin is
/// refused; when two org admins approve each other's leave request at the same moment,
/// one is refused and one admin remains.
#[tokio::test]
async fn t_portal_last_org_admin() {
    let fx = Fixture::start().await;
    let world = World::new(&fx).await;
    let mut ana = admin_browser(&fx, "ana@acme.test").await;
    let org_page = format!("/org/{}", world.acme.id);
    let own = world.places[&world.ana].id;
    let before = state(&fx.db).await;
    for (path, fields) in [
        (format!("/org/members/{own}/role"), vec![("role", "member")]),
        (format!("/org/members/{own}/remove"), vec![]),
    ] {
        let refused = ana.submit(&org_page, &path, &fields).await;
        assert_eq!(
            refused.status,
            StatusCode::CONFLICT,
            "{path}: {}",
            refused.body
        );
        assert!(refused.has("at least one org admin"), "{}", refused.body);
    }
    assert_eq!(state(&fx.db).await, before);
    assert_eq!(org_admins(&fx.db, world.acme).await, 1);

    // Max becomes the second org admin; both ask to leave and approve each other's
    // request at once.
    let max_place = world.places[&world.max];
    ana.submit(
        &org_page,
        &format!("/org/members/{}/role", max_place.id),
        &[("role", "org_admin")],
    )
    .await;
    let mut max = admin_browser(&fx, "max@acme.test").await;
    let leave = format!("/org/{}/leave", world.acme.id);
    for browser in [&mut ana, &mut max] {
        let asked = browser.submit(&org_page, &leave, &[]).await;
        assert_eq!(asked.status, StatusCode::SEE_OTHER, "{}", asked.body);
    }
    let ana_leave = leave_request_of(&fx.db, world.ana).await;
    let max_leave = leave_request_of(&fx.db, world.max).await;
    let ana_csrf = ana.get(&org_page).await.csrf();
    let max_csrf = max.get(&org_page).await.csrf();
    let (ana_approves, max_approves) = (
        format!("/org/leave/{max_leave}/approve"),
        format!("/org/leave/{ana_leave}/approve"),
    );
    let (ana_fields, max_fields) = ([("csrf", ana_csrf.as_str())], [("csrf", max_csrf.as_str())]);
    // Both memberships are held locked until both approvals wait on a lock, so the two
    // run at the same moment every time (T21).
    let hold = hold_rows(
        &fx.db,
        "SELECT 1 FROM memberships WHERE id IN ($1, $2) FOR UPDATE",
        &[world.places[&world.ana].id as i32, max_place.id as i32],
    )
    .await;
    let (by_ana, by_max, ()) = tokio::join!(
        ana.post_raw(&ana_approves, &ana_fields),
        max.post_raw(&max_approves, &max_fields),
        release_when_waiting(&fx.db, hold, 2),
    );
    let mut statuses = [by_ana.status, by_max.status];
    statuses.sort();
    assert_eq!(
        statuses[0],
        StatusCode::SEE_OTHER,
        "{} / {}",
        by_ana.body,
        by_max.body
    );
    assert!(
        matches!(statuses[1], StatusCode::CONFLICT | StatusCode::NOT_FOUND),
        "one is refused: {statuses:?}"
    );
    assert_eq!(org_admins(&fx.db, world.acme).await, 1, "one admin remains");
}

/// Locks the rows `sql` selects (with `ids` as $1, $2, …) in an owner transaction.
async fn hold_rows(
    db: &Db,
    sql: &'static str,
    ids: &[i32],
) -> sqlx::Transaction<'static, sqlx::Postgres> {
    let mut hold = db.owner.begin().await.unwrap();
    let mut query = sqlx::query(sql);
    for id in ids {
        query = query.bind(*id);
    }
    query.execute(&mut *hold).await.unwrap();
    hold
}

/// Commits `hold` once `waiting` other backends of this database wait on a lock, so
/// concurrent requests reach their locks before any of them goes on.
async fn release_when_waiting(
    db: &Db,
    hold: sqlx::Transaction<'static, sqlx::Postgres>,
    waiting: i64,
) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity
             WHERE datname = current_database() AND wait_event_type = 'Lock'",
        )
        .fetch_one(&db.owner)
        .await
        .unwrap();
        if count >= waiting {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "{count} of {waiting} requests wait on a lock"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    hold.commit().await.unwrap();
}

/// T-portal-leave-approval (C85, C88): a member can cancel while waiting; on approval
/// the membership ends and their keys answer 401 within one interval; a key created
/// while the removal commits answers 401 too (the lookup derives membership at read
/// time).
#[tokio::test]
async fn t_portal_leave_approval() {
    let fx = Fixture::start().await;
    let world = World::new(&fx).await;
    let firewall = fx.firewall().await;
    let http = common::client();
    let mut mia = fx.signed_in("mia@acme.test").await;
    let key = create_key(&mut mia, "laptop").await;
    let org_page = format!("/org/{}", world.acme.id);
    let leave = format!("/org/{}/leave", world.acme.id);
    let page = mia.get(&org_page).await;
    assert!(page.has(&format!("action=\"{leave}\"")), "{}", page.body);
    mia.submit(&org_page, &leave, &[]).await;
    let waiting = mia.get(&org_page).await;
    assert!(waiting.has("waiting for an org admin"), "{}", waiting.body);
    let cancelled = mia.submit(&org_page, &format!("{leave}/cancel"), &[]).await;
    assert_eq!(
        cancelled.status,
        StatusCode::SEE_OTHER,
        "{}",
        cancelled.body
    );
    assert_eq!(fx.db.count("SELECT count(*) FROM leave_requests").await, 0);

    // An org admin refuses one request and approves the next.
    let mut ana = admin_browser(&fx, "ana@acme.test").await;
    mia.submit(&org_page, &leave, &[]).await;
    let request = leave_request_of(&fx.db, world.mia).await;
    let listed = ana.get(&org_page).await;
    assert!(
        listed.has(&format!("/org/leave/{request}/refuse")),
        "{}",
        listed.body
    );
    ana.submit(&org_page, &format!("/org/leave/{request}/refuse"), &[])
        .await;
    assert_eq!(fx.db.count("SELECT count(*) FROM leave_requests").await, 0);
    assert_eq!(
        group_of(&fx.db, world.places[&world.mia]).await,
        Some(world.frontend.id as i32)
    );

    mia.submit(&org_page, &leave, &[]).await;
    let request = leave_request_of(&fx.db, world.mia).await;
    // Mia's place as a key creation already past its checks holds it.
    let session = probation_server::tenancy::Session::new(world.mia, None);
    let own = fx
        .db
        .tenancy()
        .authorized_place(&session, world.places[&world.mia])
        .await
        .unwrap();
    let actor = fx.db.tenancy().actor(&session, &own).await.unwrap();
    let approved = ana
        .submit(&org_page, &format!("/org/leave/{request}/approve"), &[])
        .await;
    assert_eq!(approved.status, StatusCode::SEE_OTHER, "{}", approved.body);
    let late = probation_server::keys::create(&fx.db.app, &actor, &own, "late")
        .await
        .unwrap()
        .secret;
    answers_within_interval(&firewall, &key, StatusCode::UNAUTHORIZED, "left Acme").await;
    assert_eq!(
        firewall.get(&http, "/npm/left-pad", &late).await.status(),
        StatusCode::UNAUTHORIZED,
        "a key created as the removal committed"
    );
    assert_eq!(
        fx.db
            .count("SELECT count(*) FROM memberships WHERE org_id IS NOT NULL AND role = 'member' AND group_id IS NOT NULL")
            .await,
        0,
        "Mia is no longer a member"
    );
}

/// T-sync-member-removed (C52): a removed member's keys answer 401 within one interval.
#[tokio::test]
async fn t_sync_member_removed() {
    let fx = Fixture::start().await;
    let world = World::new(&fx).await;
    let firewall = fx.firewall().await;
    let http = common::client();
    let mut max = fx.signed_in("max@acme.test").await;
    let key = create_key(&mut max, "laptop").await;
    assert_eq!(
        firewall.get(&http, "/npm/left-pad", &key).await.status(),
        StatusCode::OK
    );
    let mut ana = admin_browser(&fx, "ana@acme.test").await;
    let org_page = format!("/org/{}", world.acme.id);
    let path = format!("/org/members/{}/remove", world.places[&world.max].id);
    assert!(ana.get(&org_page).await.has(&format!("action=\"{path}\"")));
    let removed = ana.submit(&org_page, &path, &[]).await;
    assert_eq!(removed.status, StatusCode::SEE_OTHER, "{}", removed.body);
    answers_within_interval(&firewall, &key, StatusCode::UNAUTHORIZED, "removed").await;
    let revoked: bool =
        sqlx::query_scalar("SELECT revoked_at IS NOT NULL FROM keys WHERE name = 'laptop'")
            .fetch_one(&fx.db.owner)
            .await
            .unwrap();
    assert!(revoked);
}

/// T-sync-group-deleted (C61): the confirmation lists the effects; the group's service
/// keys answer 401 and its members are served under the organisation policy, within one
/// interval.
#[tokio::test]
async fn t_sync_group_deleted() {
    let fx = Fixture::start().await;
    let world = World::new(&fx).await;
    block(&fx.db, world.ana, world.frontend, "left-pad").await;
    let firewall = fx.firewall().await;
    let http = common::client();
    let mut mia = fx.signed_in("mia@acme.test").await;
    let member_key = create_key(&mut mia, "laptop").await;
    let mut ana = admin_browser(&fx, "ana@acme.test").await;
    let service = shown_key(
        &create_service_key(&mut ana, "Frontend devices", &world.frontend.id.to_string()).await,
    );
    for key in [&member_key, &service] {
        assert_eq!(
            firewall.get(&http, "/npm/left-pad", key).await.status(),
            StatusCode::FORBIDDEN
        );
    }
    let confirm_path = format!("/org/groups/{}/delete", world.frontend.id);
    let confirm = ana.get(&confirm_path).await;
    assert_eq!(confirm.status, StatusCode::OK, "{}", confirm.body);
    for effect in [
        "Delete the Frontend group?",
        "move its 2 members to \"No group\"",
        "revoke its 1 service keys (Frontend devices)",
    ] {
        assert!(confirm.has(effect), "{effect}: {}", confirm.body);
    }
    let deleted = ana.submit(&confirm_path, &confirm_path, &[]).await;
    assert_eq!(deleted.status, StatusCode::SEE_OTHER, "{}", deleted.body);
    answers_within_interval(&firewall, &service, StatusCode::UNAUTHORIZED, "service key").await;
    answers_within_interval(&firewall, &member_key, StatusCode::OK, "member key").await;
    assert_eq!(
        fx.db
            .count("SELECT count(*) FROM groups WHERE name = 'Frontend'")
            .await,
        0
    );
    assert_eq!(role_of(&fx.db, world.places[&world.bob]).await, "member");
}

/// Ana invites `email` as `role` from the organisation page; returns the page.
async fn invite(ana: &mut Browser, world: &World, fields: &[(&str, &str)]) -> Page {
    let org_page = format!("/org/{}", world.acme.id);
    let path = format!("/org/{}/invitations", world.acme.id);
    ana.submit(&org_page, &path, fields).await
}

/// The invitation link mailed to `email`, after the outbox ran.
async fn invitation_link(fx: &Fixture, email: &str) -> String {
    fx.deliver().await;
    fx.mail.link(email, "/invite?token=")
}

/// Opens `link` and accepts it; returns the answer to the accept.
async fn accept(browser: &mut Browser, link: &str) -> Page {
    let page = browser.get(link).await;
    let token = hidden(&page.body, "token").unwrap_or_default();
    browser
        .post_raw("/invite", &[("token", &token), ("csrf", &page.csrf())])
        .await
}

async fn memberships_in(db: &Db, org: PlaceRef) -> Vec<(i32, String)> {
    sqlx::query_as("SELECT login_id, role FROM memberships WHERE org_id = $1 ORDER BY login_id")
        .bind(org.id as i32)
        .fetch_all(&db.owner)
        .await
        .unwrap()
}

/// T-grant-by-invitation (C43, T3): no grant reads an email: a second login showing the
/// invitee's email gets nothing; when two logins accept the same link at once, the
/// grant goes to exactly one, and the link works once.
#[tokio::test]
async fn t_grant_by_invitation() {
    let fx = Fixture::start().await;
    let world = World::new(&fx).await;
    let erin = fx.person("erin@acme.test").await;
    // Another login whose Google account shows the same address.
    let mut eve = fx.browser();
    oauth(
        &fx,
        &mut eve,
        "/oauth/google/start",
        serde_json::json!({"sub": "g-eve", "email": "erin@acme.test"}),
    )
    .await;
    let mut ana = admin_browser(&fx, "ana@acme.test").await;
    let before = memberships_in(&fx.db, world.acme).await;
    let invited = invite(
        &mut ana,
        &world,
        &[
            ("email", "erin@acme.test"),
            ("role", "member"),
            ("group", "none"),
        ],
    )
    .await;
    assert_eq!(invited.status, StatusCode::SEE_OTHER, "{}", invited.body);
    assert!(
        ana.get(&format!("/org/{}", world.acme.id))
            .await
            .has("erin@acme.test")
    );
    let link = invitation_link(&fx, "erin@acme.test").await;
    assert_eq!(
        memberships_in(&fx.db, world.acme).await,
        before,
        "nothing by email"
    );

    let mut erin_browser = fx.signed_in("erin@acme.test").await;
    let page = erin_browser.get(&link).await;
    assert!(page.has("Join Acme as a member"), "{}", page.body);
    let (erin_csrf, eve_page) = (page.csrf(), eve.get(&link).await);
    let token = hidden(&page.body, "token").unwrap();
    let (erin_fields, eve_fields) = (
        [("token", token.as_str()), ("csrf", erin_csrf.as_str())],
        [("token", token.clone()), ("csrf", eve_page.csrf())],
    );
    let eve_fields: Vec<(&str, &str)> = eve_fields.iter().map(|(k, v)| (*k, v.as_str())).collect();
    // The invitation row is held locked until both accepts wait on it (T3).
    let invitation: i32 = sqlx::query_scalar("SELECT id FROM invitations")
        .fetch_one(&fx.db.owner)
        .await
        .unwrap();
    let hold = hold_rows(
        &fx.db,
        "SELECT 1 FROM invitations WHERE id = $1 FOR UPDATE",
        &[invitation],
    )
    .await;
    let (by_erin, by_eve, ()) = tokio::join!(
        erin_browser.post_raw("/invite", &erin_fields),
        eve.post_raw("/invite", &eve_fields),
        release_when_waiting(&fx.db, hold, 2),
    );
    let joined: Vec<i32> = memberships_in(&fx.db, world.acme)
        .await
        .into_iter()
        .filter(|row| !before.contains(row))
        .map(|(login, _)| login)
        .collect();
    assert_eq!(
        joined.len(),
        1,
        "exactly one grant: {} / {}",
        by_erin.body,
        by_eve.body
    );
    let winner = if joined[0] == erin { &by_erin } else { &by_eve };
    let loser = if joined[0] == erin { &by_eve } else { &by_erin };
    assert_eq!(winner.status, StatusCode::SEE_OTHER, "{}", winner.body);
    assert!(loser.has("expired or was already used"), "{}", loser.body);
    // The link works once.
    let again = accept(&mut erin_browser, &link).await;
    assert!(again.has("expired or was already used"), "{}", again.body);

    // A login whose address is not confirmed gains no place by a link (S5-4, C41): the
    // portal sends it to /verify-email first, and tenancy refuses it too.
    invite(
        &mut ana,
        &world,
        &[
            ("email", "nora@acme.test"),
            ("role", "member"),
            ("group", "none"),
        ],
    )
    .await;
    let link = invitation_link(&fx, "nora@acme.test").await;
    let nora = fx.person("nora@acme.test").await;
    sqlx::query("UPDATE sign_in_methods SET verified_at = NULL WHERE login_id = $1")
        .bind(nora)
        .execute(&fx.db.owner)
        .await
        .unwrap();
    let token = link.split("token=").nth(1).unwrap();
    let refused = probation_server::tenancy::accept_invitation(&fx.db.app, nora, token).await;
    assert!(
        matches!(
            refused,
            Err(probation_server::tenancy::ChangeError::Refused(_))
        ),
        "{refused:?}"
    );
    assert!(
        memberships_in(&fx.db, world.acme)
            .await
            .iter()
            .all(|(login, _)| *login != nora)
    );
    assert_eq!(
        memberships_in(&fx.db, world.acme).await.len(),
        before.len() + 1
    );

    // An invitation stands only while its sender may still send it (S6-SEC-4). Max, an
    // org admin, invites Bea; demoting him from the organisation page withdraws his
    // open invitations.
    let set_max_role = |role: &'static str| {
        let pool = fx.db.owner.clone();
        let max = world.max;
        async move {
            sqlx::query("UPDATE memberships SET role = $2 WHERE login_id = $1")
                .bind(max)
                .bind(role)
                .execute(&pool)
                .await
                .unwrap();
        }
    };
    set_max_role("org_admin").await;
    let mut max = admin_browser(&fx, "max@acme.test").await;
    fx.person("bea@acme.test").await;
    invite(
        &mut max,
        &world,
        &[
            ("email", "bea@acme.test"),
            ("role", "member"),
            ("group", "none"),
        ],
    )
    .await;
    let bea_link = invitation_link(&fx, "bea@acme.test").await;
    let org_page = format!("/org/{}", world.acme.id);
    let max_place = world.places[&world.max];
    ana.submit(
        &org_page,
        &format!("/org/members/{}/role", max_place.id),
        &[("role", "member")],
    )
    .await;
    assert!(
        !ana.get(&org_page).await.has("bea@acme.test"),
        "a demoted admin's open invitations are withdrawn"
    );
    let mut bea = fx.signed_in("bea@acme.test").await;
    let bea_answer = accept(&mut bea, &bea_link).await;
    assert!(
        bea_answer.has("expired or was already used"),
        "{}",
        bea_answer.body
    );

    // When his role goes by a way that leaves the invitation (written directly here, as a
    // path outside this page would), accepting it answers 403 and grants nothing.
    set_max_role("org_admin").await;
    let cal = fx.person("cal@acme.test").await;
    invite(
        &mut max,
        &world,
        &[
            ("email", "cal@acme.test"),
            ("role", "member"),
            ("group", "none"),
        ],
    )
    .await;
    let cal_link = invitation_link(&fx, "cal@acme.test").await;
    set_max_role("member").await;
    let mut cal_browser = fx.signed_in("cal@acme.test").await;
    let cal_answer = accept(&mut cal_browser, &cal_link).await;
    assert_eq!(
        cal_answer.status,
        StatusCode::FORBIDDEN,
        "{}",
        cal_answer.body
    );
    assert!(!is_member(&fx.db, world.acme, cal).await, "no grant");
}

/// T-portal-invitation-expiry (C43): an invitation link works for 7 days; after that it
/// is refused.
#[tokio::test]
async fn t_portal_invitation_expiry() {
    let fx = Fixture::start().await;
    let world = World::new(&fx).await;
    fx.person("erin@acme.test").await;
    let mut ana = admin_browser(&fx, "ana@acme.test").await;
    invite(
        &mut ana,
        &world,
        &[
            ("email", "erin@acme.test"),
            ("role", "member"),
            ("group", "none"),
        ],
    )
    .await;
    let days: f64 = sqlx::query_scalar(
        "SELECT extract(epoch FROM expires_at - now())::float8 / 86400 FROM invitations",
    )
    .fetch_one(&fx.db.owner)
    .await
    .unwrap();
    assert!((6.99..=7.0).contains(&days), "{days}");
    let link = invitation_link(&fx, "erin@acme.test").await;
    // The fake clock: the 7 days have passed.
    sqlx::query("UPDATE invitations SET expires_at = now() - interval '1 second'")
        .execute(&fx.db.owner)
        .await
        .unwrap();
    let before = memberships_in(&fx.db, world.acme).await;
    let mut erin = fx.signed_in("erin@acme.test").await;
    let page = erin.get(&link).await;
    assert!(page.has("expired or was already used"), "{}", page.body);
    let accepted = accept(&mut erin, &link).await;
    assert!(
        accepted.has("expired or was already used"),
        "{}",
        accepted.body
    );
    assert_eq!(memberships_in(&fx.db, world.acme).await, before);

    // The purge erases the inviter's login past its 30 days: the links it sent go with
    // it, and a range it approved stays approved and in every firewall's network lock.
    // (Ana approves here as the global admin's page will in slice 7; the firewall sees
    // every test request from 127.0.0.1, so Gus's Globex key is refused from it.)
    let mut gus = fx.signed_in("gus@globex.test").await;
    let globex_key = create_key(&mut gus, "globex laptop").await;
    sqlx::query(
        "INSERT INTO org_ip_ranges (org_id, cidr, approved_by) VALUES ($1, '127.0.0.0/8', $2)",
    )
    .bind(world.acme.id as i32)
    .bind(world.ana)
    .execute(&fx.db.owner)
    .await
    .unwrap();
    let http = common::client();
    let locked = fx.firewall().await;
    assert_eq!(
        locked
            .get(&http, "/npm/left-pad", &globex_key)
            .await
            .status(),
        StatusCode::FORBIDDEN,
        "Acme's approved range refuses a Globex key"
    );
    sqlx::query(
        "UPDATE logins SET deleted_at = now() - interval '31 days', restore_until = now() - interval '1 day'
         WHERE id = $1",
    )
    .bind(world.ana)
    .execute(&fx.db.owner)
    .await
    .unwrap();
    let (logins, ..) = accounts::purge(&fx.db.app).await.expect("the purge runs");
    assert_eq!(logins, 1, "the inviter's login is erased");
    assert_eq!(fx.db.count("SELECT count(*) FROM invitations").await, 0);
    assert_eq!(
        fx.db
            .count("SELECT count(*) FROM org_ip_ranges WHERE approved_by IS NOT NULL")
            .await,
        1
    );
    // A firewall that loads the network lock after the purge still has the range.
    let fresh = fx.firewall().await;
    assert_eq!(
        fresh
            .get(&http, "/npm/left-pad", &globex_key)
            .await
            .status(),
        StatusCode::FORBIDDEN,
        "the range stays in the network lock"
    );
}

/// T-grant-ceiling (C27, T3): an Acme org admin's forged `role=global_admin` and a Globex
/// `group_id` are refused with no row; a group admin cannot invite.
#[tokio::test]
async fn t_grant_ceiling() {
    let fx = Fixture::start().await;
    let world = World::new(&fx).await;
    let globex_group = fx.db.group(world.globex, "Ops").await.id.to_string();
    let mut ana = admin_browser(&fx, "ana@acme.test").await;
    let mut bob = admin_browser(&fx, "bob@acme.test").await;
    let before = state(&fx.db).await;
    let forged_role = invite(
        &mut ana,
        &world,
        &[
            ("email", "x@acme.test"),
            ("role", "global_admin"),
            ("group", "none"),
        ],
    )
    .await;
    assert_eq!(
        forged_role.status,
        StatusCode::FORBIDDEN,
        "{}",
        forged_role.body
    );
    let forged_group = invite(
        &mut ana,
        &world,
        &[
            ("email", "x@acme.test"),
            ("role", "member"),
            ("group", &globex_group),
        ],
    )
    .await;
    assert_eq!(
        forged_group.status,
        StatusCode::NOT_FOUND,
        "{}",
        forged_group.body
    );
    let by_group_admin = invite(
        &mut bob,
        &world,
        &[
            ("email", "x@acme.test"),
            ("role", "member"),
            ("group", "none"),
        ],
    )
    .await;
    assert_eq!(
        by_group_admin.status,
        StatusCode::FORBIDDEN,
        "{}",
        by_group_admin.body
    );
    assert_eq!(state(&fx.db).await, before, "no row written");
}

async fn totp_rows(db: &Db, login: i32) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM totp WHERE login_id = $1")
        .bind(login)
        .fetch_one(&db.owner)
        .await
        .unwrap()
}

/// T-portal-totp-reset-scope (C39, C76): an org admin resets the authenticator of a
/// login that belongs only to that organisation; a login that also has a personal
/// account answers 403; resetting another org admin of the same organisation answers
/// 403 and writes no audit row: only a global admin resets an org admin's.
#[tokio::test]
async fn t_portal_totp_reset_scope() {
    let fx = Fixture::start().await;
    let world = World::new(&fx).await;
    let mut ana = admin_browser(&fx, "ana@acme.test").await;
    let org_page = format!("/org/{}", world.acme.id);
    // Mia (Acme only), Max (also a personal account) and Oli (another org admin of Acme
    // only), each with an authenticator.
    fx.db.personal(world.max).await;
    let oli = fx.person("oli@acme.test").await;
    let oli_place = fx.db.member(oli, world.acme, None, "org_admin").await;
    for email in ["mia@acme.test", "max@acme.test", "oli@acme.test"] {
        admin_browser(&fx, email).await;
    }
    let reset = |place: PlaceRef| format!("/org/members/{}/totp-reset", place.id);
    let audits = fx
        .db
        .count("SELECT count(*) FROM audit_log WHERE action = 'totp.reset'")
        .await;
    let page = ana.get(&org_page).await;
    assert!(page.has(&reset(world.places[&world.mia])), "{}", page.body);
    assert!(!page.has(&reset(world.places[&world.max])), "{}", page.body);

    for (place, login) in [(world.places[&world.max], world.max), (oli_place, oli)] {
        let refused = ana.submit(&org_page, &reset(place), &[]).await;
        assert_eq!(refused.status, StatusCode::FORBIDDEN, "{}", refused.body);
        assert_eq!(totp_rows(&fx.db, login).await, 1);
    }
    assert_eq!(
        fx.db
            .count("SELECT count(*) FROM audit_log WHERE action = 'totp.reset'")
            .await,
        audits,
        "no audit row for a refused reset"
    );
    let done = ana
        .submit(&org_page, &reset(world.places[&world.mia]), &[])
        .await;
    assert_eq!(done.status, StatusCode::SEE_OTHER, "{}", done.body);
    assert_eq!(totp_rows(&fx.db, world.mia).await, 0);
    assert_eq!(
        fx.db
            .count("SELECT count(*) FROM audit_log WHERE action = 'totp.reset'")
            .await,
        audits + 1
    );

    // Demoting Oli does not open the way: a login that held org admin here in the last
    // 30 days is reset only by a global admin (S6-4, C39).
    let demoted = ana
        .submit(
            &org_page,
            &format!("/org/members/{}/role", oli_place.id),
            &[("role", "member")],
        )
        .await;
    assert_eq!(demoted.status, StatusCode::SEE_OTHER, "{}", demoted.body);
    let refused = ana.submit(&org_page, &reset(oli_place), &[]).await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN, "{}", refused.body);
    assert_eq!(totp_rows(&fx.db, oli).await, 1);
    let root = fx.person("root@probation.test").await;
    sqlx::query("INSERT INTO memberships (login_id, role) VALUES ($1, 'global_admin')")
        .bind(root)
        .execute(&fx.db.owner)
        .await
        .unwrap();
    let mut root_browser = admin_browser(&fx, "root@probation.test").await;
    let by_root = root_browser.submit(&org_page, &reset(oli_place), &[]).await;
    assert_eq!(by_root.status, StatusCode::SEE_OTHER, "{}", by_root.body);
    assert_eq!(totp_rows(&fx.db, oli).await, 0);

    // Nor does removing an org admin and inviting them back: Pia, an org admin of Acme
    // alone, is removed, re-invited as a member and accepts; Ana's reset is refused.
    let pia = fx.person("pia@acme.test").await;
    fx.db.member(pia, world.acme, None, "org_admin").await;
    let mut pia_browser = admin_browser(&fx, "pia@acme.test").await;
    remove_member(&fx, &mut ana, world.acme, pia).await;
    invite(
        &mut ana,
        &world,
        &[
            ("email", "pia@acme.test"),
            ("role", "member"),
            ("group", "none"),
        ],
    )
    .await;
    let link = invitation_link(&fx, "pia@acme.test").await;
    assert_eq!(
        accept(&mut pia_browser, &link).await.status,
        StatusCode::SEE_OTHER
    );
    let pia_place: i32 = sqlx::query_scalar("SELECT id FROM memberships WHERE login_id = $1")
        .bind(pia)
        .fetch_one(&fx.db.owner)
        .await
        .unwrap();
    let refused = ana
        .submit(
            &org_page,
            &format!("/org/members/{pia_place}/totp-reset"),
            &[],
        )
        .await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN, "{}", refused.body);
    assert_eq!(totp_rows(&fx.db, pia).await, 1);
}

/// Saves `org`'s company SSO on its organisation page.
async fn save_sso(admin: &mut Browser, org: PlaceRef, fields: &[(&str, &str)]) -> Page {
    let org_page = format!("/org/{}", org.id);
    admin
        .submit(&org_page, &format!("/org/{}/sso", org.id), fields)
        .await
}

/// T-portal-sso-secret (T16): the SSO client secret saved on the organisation page is
/// stored sealed: its bytes hold no plaintext, it opens only with its own row's id as
/// AAD, and the audit row shows `[redacted]`.
#[tokio::test]
async fn t_portal_sso_secret() {
    const SECRET: &str = "acme-sso-client-secret";
    let fx = Fixture::start().await;
    let world = World::new(&fx).await;
    let mut ana = admin_browser(&fx, "ana@acme.test").await;
    let saved = save_sso(
        &mut ana,
        world.acme,
        &[
            ("enabled", "on"),
            ("issuer", "https://idp.acme.test"),
            ("client_id", "acme-client"),
            ("client_secret", SECRET),
            ("allowed_tenant", ""),
        ],
    )
    .await;
    assert_eq!(saved.status, StatusCode::SEE_OTHER, "{}", saved.body);
    let (issuer, sealed): (String, Vec<u8>) =
        sqlx::query_as("SELECT sso_issuer, sso_client_secret_enc FROM orgs WHERE id = $1")
            .bind(world.acme.id as i32)
            .fetch_one(&fx.db.owner)
            .await
            .unwrap();
    assert_eq!(issuer, "https://idp.acme.test");
    assert!(!sealed.windows(SECRET.len()).any(|w| w == SECRET.as_bytes()));
    let secrets = accounts::SecretBox::new([7; 32]);
    let opened = secrets.open(&accounts::sso_secret_aad(world.acme.id as i32), &sealed);
    assert_eq!(opened.as_deref(), Some(SECRET.as_bytes()));
    assert!(
        secrets
            .open(&accounts::sso_secret_aad(world.globex.id as i32), &sealed)
            .is_none(),
        "another row's id does not open it"
    );
    let (before, after): (serde_json::Value, serde_json::Value) =
        sqlx::query_as("SELECT before, after FROM audit_log WHERE action = 'sso.save'")
            .fetch_one(&fx.db.owner)
            .await
            .unwrap();
    let text = format!("{before} {after}");
    assert!(!text.contains(SECRET), "{text}");
    assert_eq!(after["client_secret"], "[redacted]");
    assert!(
        !ana.get(&format!("/org/{}", world.acme.id))
            .await
            .has(SECRET),
        "never shown again"
    );

    // An empty secret keeps the stored one only while the issuer and client stay the
    // same: it never goes to a new issuer (M2).
    let stored = |db: &Db| {
        let pool = db.owner.clone();
        async move {
            sqlx::query_as::<_, (String, Vec<u8>)>(
                "SELECT sso_issuer, sso_client_secret_enc FROM orgs WHERE id = $1",
            )
            .bind(world.acme.id as i32)
            .fetch_one(&pool)
            .await
            .unwrap()
        }
    };
    let before = stored(&fx.db).await;
    for (issuer, client) in [
        ("https://evil.test", "acme-client"),
        ("https://idp.acme.test", "other-client"),
    ] {
        let moved = save_sso(
            &mut ana,
            world.acme,
            &[
                ("enabled", "on"),
                ("issuer", issuer),
                ("client_id", client),
                ("client_secret", ""),
            ],
        )
        .await;
        assert_eq!(
            moved.status,
            StatusCode::CONFLICT,
            "{issuer} {client}: {}",
            moved.body
        );
        assert!(
            moved.has("Enter the client secret your provider gave you."),
            "{}",
            moved.body
        );
        assert_eq!(stored(&fx.db).await, before);
    }
    let kept = save_sso(
        &mut ana,
        world.acme,
        &[
            ("enabled", "on"),
            ("issuer", "https://idp.acme.test"),
            ("client_id", "acme-client"),
            ("client_secret", ""),
            ("allowed_tenant", "acme.test"),
        ],
    )
    .await;
    assert_eq!(kept.status, StatusCode::SEE_OTHER, "{}", kept.body);
    assert_eq!(
        stored(&fx.db).await.1,
        before.1,
        "the same issuer keeps its secret"
    );
}

/// Links `org`'s SSO to the signed-in login as the IdP subject `sub`.
async fn link_sso(fx: &Fixture, browser: &mut Browser, org: &str, sub: &str) -> Page {
    let started = browser
        .submit("/account", "/account/link/sso", &[("name", org)])
        .await;
    let location = started
        .location
        .expect("a redirect to the organisation's IdP");
    let back = fx.net.authorize(&location, serde_json::json!({"sub": sub}));
    browser.get(&back).await
}

/// Signs in through `org`'s SSO as the IdP subject `sub`; the portal's answer.
async fn sso_sign_in(fx: &Fixture, browser: &mut Browser, org: PlaceRef, sub: &str) -> Page {
    let claims = serde_json::json!({"sub": sub, "email": format!("{sub}@acme.test")});
    oauth(fx, browser, &format!("/sso/{}/start", org.id), claims).await
}

async fn login_of_subject(db: &Db, sub: &str) -> i32 {
    sqlx::query_scalar("SELECT login_id FROM sign_in_methods WHERE subject = $1")
        .bind(sub)
        .fetch_one(&db.owner)
        .await
        .unwrap()
}

async fn is_member(db: &Db, org: PlaceRef, login: i32) -> bool {
    memberships_in(db, org)
        .await
        .iter()
        .any(|(member, _)| *member == login)
}

/// Ana removes `login`'s membership from its row on the organisation page.
async fn remove_member(fx: &Fixture, ana: &mut Browser, org: PlaceRef, login: i32) {
    let place: i32 =
        sqlx::query_scalar("SELECT id FROM memberships WHERE login_id = $1 AND org_id = $2")
            .bind(login)
            .bind(org.id as i32)
            .fetch_one(&fx.db.owner)
            .await
            .unwrap();
    let org_page = format!("/org/{}", org.id);
    let removed = ana
        .submit(&org_page, &format!("/org/members/{place}/remove"), &[])
        .await;
    assert_eq!(removed.status, StatusCode::SEE_OTHER, "{}", removed.body);
}

/// T-portal-sso-removed-not-rejoined (C128, C130): a member an org admin removed is not
/// added back by the organisation's SSO while the removed login exists, not even as a
/// new login after unlinking the method; an accepted invitation brings them back; an
/// approved leave does not block SSO; once the removed login is erased, a new login with
/// that SSO identity joins again.
#[tokio::test]
async fn t_portal_sso_removed_not_rejoined() {
    let fx = Fixture::start().await;
    let world = World::new(&fx).await;
    let acme = world.acme;
    let mut ana = admin_browser(&fx, "ana@acme.test").await;
    let on = [
        ("enabled", "on"),
        ("issuer", "https://idp.acme.test"),
        ("client_id", "acme-client"),
        ("client_secret", "acme-secret"),
    ];
    save_sso(&mut ana, acme, &on).await;
    let org_page = format!("/org/{}", acme.id);

    // Dave joins through SSO and becomes an org admin with a key. Before he is removed
    // he sends an invitation to his own address (S6-SEC-4).
    let mut dave = fx.browser();
    sso_sign_in(&fx, &mut dave, acme, "acme-dave").await;
    let dave_login = login_of_subject(&fx.db, "acme-dave").await;
    assert!(is_member(&fx.db, acme, dave_login).await);
    sqlx::query("UPDATE memberships SET role = 'org_admin' WHERE login_id = $1")
        .bind(dave_login)
        .execute(&fx.db.owner)
        .await
        .unwrap();
    create_key(&mut dave, "dave laptop").await;
    invite(
        &mut dave,
        &world,
        &[
            ("email", "acme-dave@acme.test"),
            ("role", "org_admin"),
            ("group", "none"),
        ],
    )
    .await;
    let own_link = invitation_link(&fx, "acme-dave@acme.test").await;
    // Ana, who stays an org admin, also invites him before the removal.
    invite(
        &mut ana,
        &world,
        &[
            ("email", "acme-dave@acme.test"),
            ("role", "member"),
            ("group", "none"),
        ],
    )
    .await;
    let old_link = invitation_link(&fx, "acme-dave@acme.test").await;

    // Removed, his next SSO sign-in leaves him no member, with no key and no place.
    remove_member(&fx, &mut ana, acme, dave_login).await;
    sign_out(&mut dave).await;
    sso_sign_in(&fx, &mut dave, acme, "acme-dave").await;
    assert!(
        !is_member(&fx.db, acme, dave_login).await,
        "removed: SSO does not re-add"
    );
    let live_keys: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM keys WHERE owner_login = $1 AND revoked_at IS NULL",
    )
    .bind(dave_login)
    .fetch_one(&fx.db.owner)
    .await
    .unwrap();
    assert_eq!(live_keys, 0, "no keys");
    let keys_page = dave.get("/keys").await;
    assert!(keys_page.has("You have no place yet"), "{}", keys_page.body);

    // His own link went with his admin role; Ana's link from before the removal is
    // refused and clears nothing (AC3).
    let own = accept(&mut dave, &own_link).await;
    assert!(own.has("expired or was already used"), "{}", own.body);
    let stale = accept(&mut dave, &old_link).await;
    assert_eq!(stale.status, StatusCode::FORBIDDEN, "{}", stale.body);
    assert!(
        !is_member(&fx.db, acme, dave_login).await,
        "an older link does not re-admit"
    );
    sign_out(&mut dave).await;
    sso_sign_in(&fx, &mut dave, acme, "acme-dave").await;
    assert!(
        !is_member(&fx.db, acme, dave_login).await,
        "the removal stands"
    );

    // An accepted invitation brings him back.
    invite(
        &mut ana,
        &world,
        &[
            ("email", "acme-dave@acme.test"),
            ("role", "member"),
            ("group", "none"),
        ],
    )
    .await;
    let link = invitation_link(&fx, "acme-dave@acme.test").await;
    let accepted = accept(&mut dave, &link).await;
    assert_eq!(accepted.status, StatusCode::SEE_OTHER, "{}", accepted.body);
    assert!(is_member(&fx.db, acme, dave_login).await, "invited back");

    // An approved leave is not a removal: his next SSO sign-in adds him again (C130).
    dave.submit(&org_page, &format!("/org/{}/leave", acme.id), &[])
        .await;
    let request = leave_request_of(&fx.db, dave_login).await;
    let approved = ana
        .submit(&org_page, &format!("/org/leave/{request}/approve"), &[])
        .await;
    assert_eq!(approved.status, StatusCode::SEE_OTHER, "{}", approved.body);
    assert!(!is_member(&fx.db, acme, dave_login).await);
    sign_out(&mut dave).await;
    sso_sign_in(&fx, &mut dave, acme, "acme-dave").await;
    assert!(
        is_member(&fx.db, acme, dave_login).await,
        "after a leave, SSO adds him again"
    );

    // Rob links Acme's SSO to his password login and is removed. He unlinks the method
    // and signs in through SSO, which makes a new login: it does not join while his
    // removed login exists.
    let rob = fx.person("rob@acme.test").await;
    let mut rob_browser = fx.signed_in("rob@acme.test").await;
    link_sso(&fx, &mut rob_browser, "Acme", "acme-rob").await;
    assert!(is_member(&fx.db, acme, rob).await);
    remove_member(&fx, &mut ana, acme, rob).await;
    let method: i32 =
        sqlx::query_scalar("SELECT id FROM sign_in_methods WHERE subject = 'acme-rob'")
            .fetch_one(&fx.db.owner)
            .await
            .unwrap();
    rob_browser
        .submit(
            "/account",
            &format!("/account/methods/{method}/remove"),
            &[],
        )
        .await;
    let mut fresh = fx.browser();
    sso_sign_in(&fx, &mut fresh, acme, "acme-rob").await;
    let new_rob = login_of_subject(&fx.db, "acme-rob").await;
    assert_ne!(new_rob, rob, "a new login");
    assert!(
        !is_member(&fx.db, acme, new_rob).await,
        "blocked while the removed login exists"
    );
    // Still blocked while the removed login is in its 30-day deletion window.
    sqlx::query(
        "UPDATE logins SET deleted_at = now(), restore_until = now() + interval '30 days' WHERE id = $1",
    )
    .bind(rob)
    .execute(&fx.db.owner)
    .await
    .unwrap();
    sign_out(&mut fresh).await;
    sso_sign_in(&fx, &mut fresh, acme, "acme-rob").await;
    assert!(
        !is_member(&fx.db, acme, new_rob).await,
        "blocked during the deletion window"
    );

    // Sam is removed, and his login is erased by the purge after its 30 days: a new
    // login with his SSO identity joins again (C130).
    let mut sam = fx.browser();
    sso_sign_in(&fx, &mut sam, acme, "acme-sam").await;
    let sam_login = login_of_subject(&fx.db, "acme-sam").await;
    remove_member(&fx, &mut ana, acme, sam_login).await;
    sqlx::query(
        "UPDATE logins SET deleted_at = now() - interval '31 days', restore_until = now() - interval '1 day'
         WHERE id = $1",
    )
    .bind(sam_login)
    .execute(&fx.db.owner)
    .await
    .unwrap();
    accounts::purge(&fx.db.app).await.expect("the purge runs");
    let mut again = fx.browser();
    sso_sign_in(&fx, &mut again, acme, "acme-sam").await;
    let new_sam = login_of_subject(&fx.db, "acme-sam").await;
    assert_ne!(new_sam, sam_login, "a new login");
    assert!(
        is_member(&fx.db, acme, new_sam).await,
        "the erased login took its removal with it"
    );
}

/// T-portal-sso-off-members-stay (C62)/// T-portal-sso-off-members-stay (C62): when SSO is turned off, the members who joined
/// through it stay, and a reset email lets one set a password and sign in with it.
#[tokio::test]
async fn t_portal_sso_off_members_stay() {
    let fx = Fixture::start().await;
    let world = World::new(&fx).await;
    let mut ana = admin_browser(&fx, "ana@acme.test").await;
    let on = [
        ("enabled", "on"),
        ("issuer", "https://idp.acme.test"),
        ("client_id", "acme-client"),
        ("client_secret", "acme-secret"),
        ("allowed_tenant", ""),
    ];
    save_sso(&mut ana, world.acme, &on).await;
    let mut dave = fx.browser();
    let joined = oauth(
        &fx,
        &mut dave,
        &format!("/sso/{}/start", world.acme.id),
        serde_json::json!({"sub": "acme-dave", "email": "dave@acme.test"}),
    )
    .await;
    assert_eq!(
        joined.location.as_deref(),
        Some("/account"),
        "{}",
        joined.body
    );
    let members = memberships_in(&fx.db, world.acme).await.len();
    let off = save_sso(
        &mut ana,
        world.acme,
        &[("issuer", ""), ("client_id", ""), ("client_secret", "")],
    )
    .await;
    assert_eq!(off.status, StatusCode::SEE_OTHER, "{}", off.body);
    let issuer: Option<String> = sqlx::query_scalar("SELECT sso_issuer FROM orgs WHERE id = $1")
        .bind(world.acme.id as i32)
        .fetch_one(&fx.db.owner)
        .await
        .unwrap();
    assert_eq!(issuer, None, "SSO is off");
    assert_eq!(
        memberships_in(&fx.db, world.acme).await.len(),
        members,
        "members stay"
    );

    // Dave asks for a reset email and sets a password from it.
    let mut browser = fx.browser();
    browser
        .submit("/reset", "/reset", &[("email", "dave@acme.test")])
        .await;
    fx.deliver().await;
    let link = fx.mail.link("dave@acme.test", "/reset/confirm?token=");
    let form = browser.get(&link).await;
    assert_eq!(form.status, StatusCode::OK, "{}", form.body);
    let token = hidden(&form.body, "token").unwrap();
    let chosen = browser
        .post_raw(
            "/reset/confirm",
            &[
                ("token", &token),
                ("new", PASSWORD),
                ("again", PASSWORD),
                ("csrf", &form.csrf()),
            ],
        )
        .await;
    assert_eq!(chosen.status, StatusCode::OK, "{}", chosen.body);
    let mut dave = fx.signed_in("dave@acme.test").await;
    assert!(dave.get("/keys").await.has("Your keys in Acme"));
}

/// Connects `org`'s own OIDC sign-in directly (what the organisation page saves).
async fn connect_sso(db: &Db, org: PlaceRef, client: &str) {
    let sealed = accounts::SecretBox::new([7; 32]).seal(
        &accounts::sso_secret_aad(org.id as i32),
        format!("{client}-secret").as_bytes(),
    );
    sqlx::query(
        "UPDATE orgs SET sso_issuer = $2, sso_client_id = $3, sso_client_secret_enc = $4 WHERE id = $1",
    )
    .bind(org.id as i32)
    .bind(format!("https://idp.{client}.test"))
    .bind(format!("{client}-client"))
    .bind(sealed)
    .execute(&db.owner)
    .await
    .unwrap();
}

/// T-sso-session-scope (T2): a login that is Acme's org admin, a global admin and has a
/// personal account signs in through Globex's SSO: that session gets 404 on Acme's and
/// the personal account's pages, and is a plain member in Globex; a password sign-in of
/// the same login reaches both.
#[tokio::test]
async fn t_sso_session_scope() {
    let fx = Fixture::start().await;
    let world = World::new(&fx).await;
    let personal = fx.db.personal(world.ana).await;
    sqlx::query("INSERT INTO memberships (login_id, role) VALUES ($1, 'global_admin')")
        .bind(world.ana)
        .execute(&fx.db.owner)
        .await
        .unwrap();
    connect_sso(&fx.db, world.globex, "globex").await;
    // Ana links Globex's SSO while signed in with her password, and joins Globex.
    let mut ana = fx.signed_in("ana@acme.test").await;
    let linked = {
        let started = ana
            .submit("/account", "/account/link/sso", &[("name", "Globex")])
            .await;
        let location = started.location.expect("a redirect to Globex's IdP");
        let back = fx
            .net
            .authorize(&location, serde_json::json!({"sub": "globex-ana"}));
        ana.get(&back).await
    };
    assert_eq!(linked.status, StatusCode::SEE_OTHER, "{}", linked.body);
    sign_out(&mut ana).await;

    let mut scoped = fx.browser();
    let back = oauth(
        &fx,
        &mut scoped,
        &format!("/sso/{}/start", world.globex.id),
        serde_json::json!({"sub": "globex-ana"}),
    )
    .await;
    assert_eq!(back.location.as_deref(), Some("/account"), "{}", back.body);
    for path in [
        format!("/org/{}", world.acme.id),
        policy_path(world.acme),
        policy_path(personal),
    ] {
        assert_eq!(
            scoped.get(&path).await.status,
            StatusCode::NOT_FOUND,
            "{path}"
        );
    }
    let switched = scoped
        .submit("/keys", "/place", &[("to", "personal")])
        .await;
    assert_eq!(switched.status, StatusCode::NOT_FOUND, "{}", switched.body);
    for to in [
        format!("org:{}", world.acme.id),
        format!("org:{}", world.globex.id),
    ] {
        let switched = scoped.submit("/keys", "/place", &[("to", &to)]).await;
        let want = if to.ends_with(&world.globex.id.to_string()) {
            StatusCode::SEE_OTHER
        } else {
            StatusCode::NOT_FOUND
        };
        assert_eq!(switched.status, want, "{to}: {}", switched.body);
    }
    assert!(scoped.get("/keys").await.has("Your keys in Globex"));
    let globex = scoped.get(&format!("/org/{}", world.globex.id)).await;
    assert_eq!(globex.status, StatusCode::OK, "{}", globex.body);
    assert!(
        !globex.has("Members"),
        "no admin view in Globex: {}",
        globex.body
    );

    let mut password = fx.signed_in("ana@acme.test").await;
    for path in [policy_path(world.acme), policy_path(personal)] {
        assert_eq!(password.get(&path).await.status, StatusCode::OK, "{path}");
    }
}

async fn audit_count(db: &Db, action: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE action = $1")
        .bind(action)
        .fetch_one(&db.owner)
        .await
        .unwrap()
}

/// T-portal-ranges-org (C30, C77, C87): a registered range is "waiting for approval" and
/// has no effect; a refused one shows "Refused by operator" with the reason and can be
/// deleted or resubmitted; deleting an approved range writes `ranges`.
#[tokio::test]
async fn t_portal_ranges_org() {
    let fx = Fixture::start().await;
    let world = World::new(&fx).await;
    let firewall = fx.firewall().await;
    let http = common::client();
    // Gus's key belongs to Globex; the firewall sees every test request from 127.0.0.1.
    let mut gus = fx.signed_in("gus@globex.test").await;
    let globex_key = create_key(&mut gus, "globex laptop").await;
    let mut ana = admin_browser(&fx, "ana@acme.test").await;
    let org_page = format!("/org/{}", world.acme.id);
    let add = format!("/org/{}/ranges", world.acme.id);

    let bad = ana
        .submit(&org_page, &add, &[("cidr", "192.0.2.300/24")])
        .await;
    assert_eq!(bad.status, StatusCode::CONFLICT, "{}", bad.body);
    assert!(bad.has("is not a valid IP range"), "{}", bad.body);
    let added = ana
        .submit(&org_page, &add, &[("cidr", "127.0.0.1/8")])
        .await;
    assert_eq!(added.status, StatusCode::SEE_OTHER, "{}", added.body);
    let page = ana.get(&org_page).await;
    assert!(
        page.has("127.0.0.0/8"),
        "stored as its network: {}",
        page.body
    );
    assert!(page.has("Waiting for operator approval"), "{}", page.body);
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(
        firewall
            .get(&http, "/npm/left-pad", &globex_key)
            .await
            .status(),
        StatusCode::OK,
        "a waiting range has no effect"
    );

    let range: i32 = sqlx::query_scalar("SELECT id FROM org_ip_ranges")
        .fetch_one(&fx.db.owner)
        .await
        .unwrap();
    // The operator refuses it (the approval page is slice 7's).
    sqlx::query("UPDATE org_ip_ranges SET refused_reason = 'covers too much' WHERE id = $1")
        .bind(range)
        .execute(&fx.db.owner)
        .await
        .unwrap();
    let page = ana.get(&org_page).await;
    assert!(
        page.has("Refused by operator: covers too much"),
        "{}",
        page.body
    );
    let resubmit = format!("/org/ranges/{range}/resubmit");
    assert!(page.has(&format!("action=\"{resubmit}\"")), "{}", page.body);
    let again = ana.submit(&org_page, &resubmit, &[]).await;
    assert_eq!(again.status, StatusCode::SEE_OTHER, "{}", again.body);
    assert!(
        ana.get(&org_page)
            .await
            .has("Waiting for operator approval")
    );

    let delete = format!("/org/ranges/{range}/delete");
    let deleted = ana.submit(&org_page, &delete, &[]).await;
    assert_eq!(deleted.status, StatusCode::SEE_OTHER, "{}", deleted.body);
    assert_eq!(fx.db.count("SELECT count(*) FROM org_ip_ranges").await, 0);
    assert_eq!(
        fx.db
            .count("SELECT count(*) FROM change_log WHERE kind = 'ranges'")
            .await,
        0
    );

    // Deleting an approved range tells every firewall (C87).
    let approved: i32 = sqlx::query_scalar(
        "INSERT INTO org_ip_ranges (org_id, cidr, approved_by) VALUES ($1, '198.51.100.0/24', $2) RETURNING id",
    )
    .bind(world.acme.id as i32)
    .bind(world.ana)
    .fetch_one(&fx.db.owner)
    .await
    .unwrap();
    assert!(ana.get(&org_page).await.has("Approved"));
    ana.submit(&org_page, &format!("/org/ranges/{approved}/delete"), &[])
        .await;
    assert_eq!(
        fx.db
            .count("SELECT count(*) FROM change_log WHERE kind = 'ranges'")
            .await,
        1
    );
    for action in ["range.add", "range.resubmit", "range.delete"] {
        assert!(audit_count(&fx.db, action).await >= 1, "{action}");
    }
}

/// Moves Acme's deletion `days` into its 30 days (the fake clock).
async fn age_org_deletion(db: &Db, org: PlaceRef, days: i32) {
    sqlx::query(
        "UPDATE orgs SET deleted_at = now() - make_interval(days => $2),
             restore_until = now() - make_interval(days => $2) + interval '30 days' WHERE id = $1",
    )
    .bind(org.id as i32)
    .bind(days)
    .execute(&db.owner)
    .await
    .unwrap();
}

/// T-portal-org-delete-restore (C33, C63): deleting the organisation stops its keys
/// within one interval; any of its org admins restores it within 30 days and the keys
/// work again; on day 31 the purge erases it, and an approved range it held is sent to
/// every firewall in the same transaction.
#[tokio::test]
async fn t_portal_org_delete_restore() {
    let fx = Fixture::start().await;
    let world = World::new(&fx).await;
    sqlx::query("UPDATE memberships SET role = 'org_admin' WHERE id = $1")
        .bind(world.places[&world.max].id as i32)
        .execute(&fx.db.owner)
        .await
        .unwrap();
    let firewall = fx.firewall().await;
    let mut ana = admin_browser(&fx, "ana@acme.test").await;
    let service = shown_key(&create_service_key(&mut ana, "All laptops", "org").await);
    let org_page = format!("/org/{}", world.acme.id);
    let delete = format!("/org/{}/delete", world.acme.id);
    let wrong = ana
        .submit(&org_page, &delete, &[("confirm", "acme inc")])
        .await;
    assert_eq!(wrong.status, StatusCode::CONFLICT, "{}", wrong.body);
    assert!(wrong.has("Type Acme to confirm"), "{}", wrong.body);
    let deleted = ana.submit(&org_page, &delete, &[("confirm", "Acme")]).await;
    assert_eq!(deleted.status, StatusCode::SEE_OTHER, "{}", deleted.body);
    answers_within_interval(
        &firewall,
        &service,
        StatusCode::UNAUTHORIZED,
        "Acme deleted",
    )
    .await;
    assert_eq!(ana.get(&org_page).await.status, StatusCode::NOT_FOUND);

    // Day 29: Max, another org admin, restores it.
    age_org_deletion(&fx.db, world.acme, 29).await;
    let mut max = admin_browser(&fx, "max@acme.test").await;
    let page = max.get("/org").await;
    assert!(page.has("Acme was deleted on"), "{}", page.body);
    let restore = format!("/org/{}/restore", world.acme.id);
    let restored = max.submit("/org", &restore, &[]).await;
    assert_eq!(
        restored.location.as_deref(),
        Some(org_page.as_str()),
        "{}",
        restored.body
    );
    answers_within_interval(&firewall, &service, StatusCode::OK, "Acme restored").await;

    // Day 31: gone for good, and its approved range leaves every firewall.
    sqlx::query(
        "INSERT INTO org_ip_ranges (org_id, cidr, approved_by) VALUES ($1, '198.51.100.0/24', $2)",
    )
    .bind(world.acme.id as i32)
    .bind(world.ana)
    .execute(&fx.db.owner)
    .await
    .unwrap();
    ana.submit(&org_page, &delete, &[("confirm", "Acme")]).await;
    age_org_deletion(&fx.db, world.acme, 31).await;
    let late = max.submit("/org", &restore, &[]).await;
    assert_eq!(late.status, StatusCode::NOT_FOUND, "{}", late.body);

    // A restore that commits while the purge is on its way does not lose Acme: the
    // purge waits on the organisation's row, then finds it restored (M3).
    let mut restoring = hold_rows(
        &fx.db,
        "SELECT 1 FROM orgs WHERE id = $1 FOR UPDATE",
        &[world.acme.id as i32],
    )
    .await;
    sqlx::query("UPDATE orgs SET deleted_at = NULL, restore_until = NULL WHERE id = $1")
        .bind(world.acme.id as i32)
        .execute(&mut *restoring)
        .await
        .unwrap();
    let (purged, ()) = tokio::join!(
        accounts::purge(&fx.db.app),
        release_when_waiting(&fx.db, restoring, 1),
    );
    assert_eq!(purged.expect("the purge runs").2, 0, "nothing erased");
    assert_eq!(
        fx.db
            .count("SELECT count(*) FROM orgs WHERE name = 'Acme' AND deleted_at IS NULL")
            .await,
        1
    );
    assert_eq!(
        fx.db
            .count("SELECT count(*) FROM keys WHERE kind = 'service' AND revoked_at IS NULL")
            .await,
        1,
        "its keys are kept"
    );
    age_org_deletion(&fx.db, world.acme, 31).await;
    let ranges = fx
        .db
        .count("SELECT count(*) FROM change_log WHERE kind = 'ranges'")
        .await;
    accounts::purge(&fx.db.app).await.expect("the purge runs");
    assert_eq!(
        fx.db
            .count("SELECT count(*) FROM orgs WHERE name = 'Acme'")
            .await,
        0
    );
    assert_eq!(
        fx.db
            .count("SELECT count(*) FROM keys WHERE kind IN ('user', 'service')")
            .await,
        0
    );
    assert_eq!(
        fx.db
            .count("SELECT count(*) FROM change_log WHERE kind = 'ranges'")
            .await,
        ranges + 1
    );
    assert_eq!(
        fx.db
            .count("SELECT count(*) FROM orgs WHERE name = 'Globex'")
            .await,
        1
    );
}

/// T-sync-org-deleted-restored (C33, C63): a member key requested while the organisation
/// is deleted answers 401, and 200 within one interval after the restore.
#[tokio::test]
async fn t_sync_org_deleted_restored() {
    let fx = Fixture::start().await;
    let world = World::new(&fx).await;
    let firewall = fx.firewall().await;
    let http = common::client();
    let mut mia = fx.signed_in("mia@acme.test").await;
    let key = create_key(&mut mia, "laptop").await;
    assert_eq!(
        firewall.get(&http, "/npm/left-pad", &key).await.status(),
        StatusCode::OK
    );
    let mut ana = admin_browser(&fx, "ana@acme.test").await;
    let org_page = format!("/org/{}", world.acme.id);
    ana.submit(
        &org_page,
        &format!("/org/{}/delete", world.acme.id),
        &[("confirm", "Acme")],
    )
    .await;
    answers_within_interval(&firewall, &key, StatusCode::UNAUTHORIZED, "deleted").await;
    // Requested during the deletion: the firewall holds a negative entry for it.
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(
        firewall.get(&http, "/npm/left-pad", &key).await.status(),
        StatusCode::UNAUTHORIZED
    );
    let restored = ana
        .submit("/org", &format!("/org/{}/restore", world.acme.id), &[])
        .await;
    assert_eq!(restored.status, StatusCode::SEE_OTHER, "{}", restored.body);
    answers_within_interval(&firewall, &key, StatusCode::OK, "restored").await;
}

/// One activity row as a firewall would have uploaded it for the key named `key`: the
/// place comes from the key, as the sync API derives it (T18).
async fn activity(
    db: &Db,
    firewall: i32,
    key: &str,
    package: &str,
    result: &str,
    layer: &str,
    extra: &str,
) {
    let sql = format!(
        "INSERT INTO activity (event_id, at, firewall_id, place_kind, place_id, key_id, layer,
                               ecosystem, package, version, result, rule, client_ip, eligible_at)
         SELECT gen_random_uuid()::text, now(), $1, k.place_kind, k.place_id, k.id, $3, 'npm', $4, '1.0.0',
                $5, 'rule', {extra}
         FROM keys AS k WHERE k.name = $2"
    );
    sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(firewall)
        .bind(key)
        .bind(layer)
        .bind(package)
        .bind(result)
        .execute(&db.owner)
        .await
        .unwrap();
}

async fn registered_firewall(db: &Db) -> i32 {
    probation_server::fleet::register(
        &db.app,
        &probation_server::tenancy::Actor::Operator,
        "fw",
        &["127.0.0.0/8".parse().unwrap()],
    )
    .await
    .unwrap()
    .id
}

/// T-portal-activity-scope (C54): a member sees only their own keys' rows; a group admin
/// sees their group's members' and service keys' rows; an org admin sees all.
#[tokio::test]
async fn t_portal_activity_scope() {
    let fx = Fixture::start().await;
    let world = World::new(&fx).await;
    let firewall = registered_firewall(&fx.db).await;
    let mut mia = fx.signed_in("mia@acme.test").await;
    create_key(&mut mia, "mia key").await;
    let mut max = fx.signed_in("max@acme.test").await;
    create_key(&mut max, "max key").await;
    let mut ana = admin_browser(&fx, "ana@acme.test").await;
    create_service_key(&mut ana, "frontend devices", &world.frontend.id.to_string()).await;
    create_service_key(&mut ana, "all laptops", "org").await;
    let mut gus = fx.signed_in("gus@globex.test").await;
    create_key(&mut gus, "gus key").await;
    for (key, package) in [
        ("mia key", "pkg-mia"),
        ("max key", "pkg-max"),
        ("frontend devices", "pkg-frontend"),
        ("all laptops", "pkg-org"),
        ("gus key", "pkg-globex"),
    ] {
        activity(
            &fx.db,
            firewall,
            key,
            package,
            "blocked",
            "org",
            "NULL, NULL",
        )
        .await;
    }
    let mut bob = admin_browser(&fx, "bob@acme.test").await;
    for (browser, sees) in [
        (&mut mia, vec!["pkg-mia"]),
        (&mut bob, vec!["pkg-mia", "pkg-frontend"]),
        (
            &mut ana,
            vec!["pkg-mia", "pkg-max", "pkg-frontend", "pkg-org"],
        ),
    ] {
        let page = browser.get("/activity").await;
        assert_eq!(page.status, StatusCode::OK, "{}", page.body);
        for package in [
            "pkg-mia",
            "pkg-max",
            "pkg-frontend",
            "pkg-org",
            "pkg-globex",
        ] {
            assert_eq!(
                page.has(package),
                sees.contains(&package),
                "{package}: {}",
                page.body
            );
        }
    }
}

/// T-portal-activity-columns (C23, C56, C92): a held row shows when the version leaves
/// the freeze; a revoked-key row shows Layer "none"; a network-lock row shows the IP and
/// no organisation name.
#[tokio::test]
async fn t_portal_activity_columns() {
    let fx = Fixture::start().await;
    World::new(&fx).await;
    let firewall = registered_firewall(&fx.db).await;
    let mut mia = fx.signed_in("mia@acme.test").await;
    create_key(&mut mia, "mia key").await;
    activity(
        &fx.db,
        firewall,
        "mia key",
        "react-dom",
        "held",
        "org",
        "NULL, '2026-10-22 07:47:00+00'",
    )
    .await;
    activity(
        &fx.db,
        firewall,
        "mia key",
        "numpy",
        "refused_revoked",
        "none",
        "NULL, NULL",
    )
    .await;
    activity(
        &fx.db,
        firewall,
        "mia key",
        "lodash",
        "refused_network",
        "network",
        "'203.0.113.42', NULL",
    )
    .await;
    let page = mia.get("/activity").await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    let row = |package: &str| {
        let start = page
            .body
            .find(&format!("{package}@1.0.0"))
            .unwrap_or_else(|| panic!("{package}: {}", page.body));
        let start = page.body[..start].rfind("<tr>").unwrap();
        let end = page.body[start..].find("</tr>").unwrap() + start;
        page.body[start..end].to_owned()
    };
    assert!(
        row("react-dom").contains("Held until 22 Oct 2026 07:47 UTC"),
        "{}",
        row("react-dom")
    );
    assert!(row("numpy").contains("<td>none</td>"), "{}", row("numpy"));
    let network = row("lodash");
    assert!(network.contains("203.0.113.42"), "{network}");
    assert!(!page.has("Globex"), "no organisation name");
}

/// T-portal-audit-scope (C25, C57, C58): SSO and range changes appear; a group admin sees
/// only their group's entries; an Acme org admin's /audit lists no Globex entry; a
/// global admin's lists both organisations and the platform.
#[tokio::test]
async fn t_portal_audit_scope() {
    let fx = Fixture::start().await;
    let world = World::new(&fx).await;
    let root = fx.person("root@probation.test").await;
    sqlx::query("INSERT INTO memberships (login_id, role) VALUES ($1, 'global_admin')")
        .bind(root)
        .execute(&fx.db.owner)
        .await
        .unwrap();
    let mut ana = admin_browser(&fx, "ana@acme.test").await;
    save_sso(
        &mut ana,
        world.acme,
        &[
            ("enabled", "on"),
            ("issuer", "https://idp.acme.test"),
            ("client_id", "acme-client"),
            ("client_secret", "s"),
        ],
    )
    .await;
    let org_page = format!("/org/{}", world.acme.id);
    ana.submit(
        &org_page,
        &format!("/org/{}/ranges", world.acme.id),
        &[("cidr", "192.0.2.0/24")],
    )
    .await;
    block(&fx.db, world.bob, world.frontend, "colors").await;
    block(&fx.db, world.ana, world.data, "faker").await;
    block(&fx.db, world.gus, world.globex, "globex-only").await;
    block(&fx.db, root, tenancy_platform(), "event-stream").await;

    let frontend = format!("group:{}", world.frontend.id);
    let data = format!("group:{}", world.data.id);
    let globex = format!("org:{}", world.globex.id);
    let page = ana.get("/audit").await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    for seen in [
        "Company SSO",
        "Network lock",
        "192.0.2.0/24",
        &frontend,
        &data,
    ] {
        assert!(page.has(seen), "Ana sees {seen}: {}", page.body);
    }
    for unseen in [&globex, "gus@globex.test", "platform:1"] {
        assert!(!page.has(unseen), "Ana does not see {unseen}");
    }

    let mut bob = admin_browser(&fx, "bob@acme.test").await;
    let page = bob.get("/audit").await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    assert!(page.has(&frontend), "{}", page.body);
    for unseen in [&data, "Company SSO", "Network lock", &globex] {
        assert!(
            !page.has(unseen),
            "Bob does not see {unseen}: {}",
            page.body
        );
    }

    let mut admin = admin_browser(&fx, "root@probation.test").await;
    let page = admin.get("/audit").await;
    for seen in [&frontend, &globex, "platform:1", "gus@globex.test"] {
        assert!(
            page.has(seen),
            "the global admin sees {seen}: {}",
            page.body
        );
    }
}

/// The audit rows of `action`: (actor, global-admin flag, organisation, subject, before,
/// after).
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

/// T-audit-coverage-places (C25, C57, C79): group moves and changes, role grants,
/// invitations, leave requests, service keys, SSO, range registration, TOTP reset and
/// organisation delete and restore, each done once, write exactly one audit row naming
/// the actor, the global-admin flag, the subject and before/after; a global admin's
/// change inside Acme is in Acme's log, flagged.
#[tokio::test]
async fn t_audit_coverage_places() {
    let fx = Fixture::start().await;
    let world = World::new(&fx).await;
    let root = fx.person("root@probation.test").await;
    sqlx::query("INSERT INTO memberships (login_id, role) VALUES ($1, 'global_admin')")
        .bind(root)
        .execute(&fx.db.owner)
        .await
        .unwrap();
    fx.person("erin@acme.test").await;
    fx.person("fred@acme.test").await;
    admin_browser(&fx, "mia@acme.test").await;
    let mut ana = admin_browser(&fx, "ana@acme.test").await;
    let mut root_browser = admin_browser(&fx, "root@probation.test").await;
    let acme = world.acme.id;
    let org_page = format!("/org/{acme}");
    let member = |login: i32| world.places[&login].id;
    let mut steps: Vec<(&str, i32, bool, Option<&str>)> = Vec::new();
    let step = async |browser: &mut Browser, path: String, fields: &[(&str, &str)]| {
        let page = browser.submit(&org_page, &path, fields).await;
        assert_eq!(page.status, StatusCode::SEE_OTHER, "{path}: {}", page.body);
    };

    step(
        &mut ana,
        format!("/org/{acme}/groups"),
        &[("name", "Mobile")],
    )
    .await;
    steps.push(("group.create", world.ana, false, None));
    step(
        &mut ana,
        format!("/org/groups/{}/rename", world.data.id),
        &[("name", "Analytics")],
    )
    .await;
    steps.push(("group.rename", world.ana, false, Some("before")));
    step(
        &mut root_browser,
        format!("/org/members/{}/group", member(world.max)),
        &[("group", &world.data.id.to_string())],
    )
    .await;
    steps.push(("member.move", root, true, Some("before")));
    step(
        &mut ana,
        format!("/org/members/{}/role", member(world.max)),
        &[("role", "group_admin")],
    )
    .await;
    steps.push(("member.role", world.ana, false, Some("before")));
    step(
        &mut ana,
        format!("/org/members/{}/totp-reset", member(world.mia)),
        &[],
    )
    .await;
    steps.push(("totp.reset", world.ana, false, Some("before")));
    step(
        &mut ana,
        format!("/org/{acme}/invitations"),
        &[
            ("email", "erin@acme.test"),
            ("role", "member"),
            ("group", "none"),
        ],
    )
    .await;
    steps.push(("invitation.create", world.ana, false, None));
    let link = invitation_link(&fx, "erin@acme.test").await;
    let mut erin = fx.signed_in("erin@acme.test").await;
    assert_eq!(accept(&mut erin, &link).await.status, StatusCode::SEE_OTHER);
    let erin_login: i32 =
        sqlx::query_scalar("SELECT login_id FROM sign_in_methods WHERE email = 'erin@acme.test'")
            .fetch_one(&fx.db.owner)
            .await
            .unwrap();
    steps.push(("invitation.accept", erin_login, false, None));
    step(
        &mut ana,
        format!("/org/{acme}/invitations"),
        &[
            ("email", "fred@acme.test"),
            ("role", "member"),
            ("group", "none"),
        ],
    )
    .await;
    let fred_invitation: i32 =
        sqlx::query_scalar("SELECT id FROM invitations WHERE email = 'fred@acme.test'")
            .fetch_one(&fx.db.owner)
            .await
            .unwrap();
    step(
        &mut ana,
        format!("/org/invitations/{fred_invitation}/cancel"),
        &[],
    )
    .await;
    steps.push(("invitation.cancel", world.ana, false, Some("before")));
    let created = create_service_key(&mut ana, "All laptops", "org").await;
    assert_eq!(created.status, StatusCode::OK);
    steps.push(("key.create", world.ana, false, None));
    let key = key_id(&fx.db, "All laptops").await;
    ana.submit("/keys", &format!("/keys/{key}/revoke"), &[])
        .await;
    steps.push(("key.revoke", world.ana, false, Some("before")));
    step(
        &mut ana,
        format!("/org/{acme}/ranges"),
        &[("cidr", "192.0.2.0/24")],
    )
    .await;
    steps.push(("range.add", world.ana, false, None));
    let range: i32 = sqlx::query_scalar("SELECT id FROM org_ip_ranges")
        .fetch_one(&fx.db.owner)
        .await
        .unwrap();
    sqlx::query("UPDATE org_ip_ranges SET refused_reason = 'no'")
        .execute(&fx.db.owner)
        .await
        .unwrap();
    step(&mut ana, format!("/org/ranges/{range}/resubmit"), &[]).await;
    steps.push(("range.resubmit", world.ana, false, Some("before")));
    step(&mut ana, format!("/org/ranges/{range}/delete"), &[]).await;
    steps.push(("range.delete", world.ana, false, Some("before")));
    step(
        &mut ana,
        format!("/org/{acme}/sso"),
        &[
            ("enabled", "on"),
            ("issuer", "https://idp.acme.test"),
            ("client_id", "c"),
            ("client_secret", "s"),
        ],
    )
    .await;
    steps.push(("sso.save", world.ana, false, Some("before")));
    let mut bob = fx.signed_in("bob@acme.test").await;
    bob.submit(&org_page, &format!("/org/{acme}/leave"), &[])
        .await;
    bob.submit(&org_page, &format!("/org/{acme}/leave/cancel"), &[])
        .await;
    steps.push(("leave.cancel", world.bob, false, Some("before")));
    bob.submit(&org_page, &format!("/org/{acme}/leave"), &[])
        .await;
    let request = leave_request_of(&fx.db, world.bob).await;
    step(&mut ana, format!("/org/leave/{request}/refuse"), &[]).await;
    steps.push(("leave.refuse", world.ana, false, Some("before")));
    bob.submit(&org_page, &format!("/org/{acme}/leave"), &[])
        .await;
    let request = leave_request_of(&fx.db, world.bob).await;
    step(&mut ana, format!("/org/leave/{request}/approve"), &[]).await;
    steps.push(("leave.approve", world.ana, false, Some("before")));
    steps.push(("leave.ask", world.bob, false, None));
    step(
        &mut ana,
        format!("/org/members/{}/remove", member(world.max)),
        &[],
    )
    .await;
    steps.push(("member.remove", world.ana, false, Some("before")));
    step(
        &mut ana,
        format!("/org/groups/{}/delete", world.frontend.id),
        &[],
    )
    .await;
    steps.push(("group.delete", world.ana, false, Some("before")));
    step(
        &mut ana,
        format!("/org/{acme}/delete"),
        &[("confirm", "Acme")],
    )
    .await;
    steps.push(("org.delete", world.ana, false, Some("before")));
    let restored = ana
        .submit("/org", &format!("/org/{acme}/restore"), &[])
        .await;
    assert_eq!(restored.status, StatusCode::SEE_OTHER, "{}", restored.body);
    steps.push(("org.restore", world.ana, false, Some("before")));

    for (action, actor, global, before) in steps {
        let rows = audit_rows(&fx.db, action).await;
        // Bob asked to leave three times and two invitations went out (one accepted,
        // one cancelled); every other action ran once.
        let expected = match action {
            "leave.ask" => 3,
            "invitation.create" => 2,
            _ => 1,
        };
        assert_eq!(rows.len(), expected, "{action}: {rows:?}");
        let (who, flagged, org, subject, was, now) = &rows[0];
        assert_eq!((*who, *flagged), (Some(actor), global), "{action}");
        assert_eq!(*org, Some(acme as i32), "{action} is in Acme's log");
        assert!(!subject.is_empty(), "{action}");
        assert!(was.is_some() || before.is_none(), "{action}: before");
        assert!(now.is_some() || was.is_some(), "{action}: before or after");
    }
}

/// T-cross-tenant-routes-places (C1, T9): for every route this slice adds that takes an
/// id (read from the router's table), and for the forms that carry one, an Acme org
/// admin sending each Globex id gets 404 with the same body as for an unknown id, and
/// nothing is written.
#[tokio::test]
async fn t_cross_tenant_routes_places() {
    let fx = Fixture::start().await;
    let world = World::new(&fx).await;
    let ops = fx.db.group(world.globex, "Ops").await;
    let gus_personal = fx.db.personal(world.gus).await;
    let gus_member = world.places[&world.gus];
    let mut gus = fx.signed_in("gus@globex.test").await;
    create_key(&mut gus, "gus key").await;
    let gus_key = key_id(&fx.db, "gus key").await;
    let invitation: i32 = sqlx::query_scalar(
        "INSERT INTO invitations (token_hash, org_id, role, created_by, expires_at, email)
         VALUES ('\\x01', $1, 'member', $2, now() + interval '7 days', 'x@globex.test') RETURNING id",
    )
    .bind(world.globex.id as i32)
    .bind(world.gus)
    .fetch_one(&fx.db.owner)
    .await
    .unwrap();
    let range: i32 = sqlx::query_scalar(
        "INSERT INTO org_ip_ranges (org_id, cidr, refused_reason) VALUES ($1, '203.0.113.0/24', 'no') RETURNING id",
    )
    .bind(world.globex.id as i32)
    .fetch_one(&fx.db.owner)
    .await
    .unwrap();
    let globex_helper = fx.person("hal@globex.test").await;
    fx.db
        .member(globex_helper, world.globex, None, "member")
        .await;
    let leave: i32 = sqlx::query_scalar(
        "INSERT INTO leave_requests (login_id, org_id) VALUES ($1, $2) RETURNING id",
    )
    .bind(globex_helper)
    .bind(world.globex.id as i32)
    .fetch_one(&fx.db.owner)
    .await
    .unwrap();

    // Each id-taking route with the Globex ids it is sent and the unknown id it is
    // compared with.
    let ids_for = |path: &str| -> Vec<(String, String)> {
        let pair = |id: i64| vec![(id.to_string(), "999999".to_owned())];
        if path.starts_with("/keys/") {
            pair(gus_key)
        } else if path.starts_with("/policy/") {
            [
                format!("org-{}", world.globex.id),
                format!("group-{}", ops.id),
                format!("user-{}", gus_member.id),
                format!("personal-{}", gus_personal.id),
            ]
            .into_iter()
            .map(|id| {
                let unknown = format!("{}-999999", id.split('-').next().unwrap());
                (id, unknown)
            })
            .collect()
        } else if path.starts_with("/org/members/") {
            pair(gus_member.id.into())
        } else if path.starts_with("/org/groups/") {
            pair(ops.id.into())
        } else if path.starts_with("/org/invitations/") {
            pair(invitation.into())
        } else if path.starts_with("/org/ranges/") {
            pair(range.into())
        } else if path.starts_with("/org/leave/") {
            pair(leave.into())
        } else {
            pair(world.globex.id.into())
        }
    };
    let routes: Vec<_> = portal::route_table()
        .into_iter()
        .filter(|(_, path)| {
            path.contains('{')
                && ["/keys/", "/policy/", "/org/"]
                    .iter()
                    .any(|prefix| path.starts_with(prefix))
        })
        .collect();
    assert!(routes.len() >= 24, "{routes:?}");
    let mut ana = admin_browser(&fx, "ana@acme.test").await;
    let acme_member = world.places[&world.max].id;
    let before = state(&fx.db).await;
    let mut sent = 0;
    for (method, path) in routes {
        for (globex_id, unknown) in ids_for(path) {
            let csrf = ana.get("/keys").await.csrf();
            let mut answers = Vec::new();
            for id in [&globex_id, &unknown] {
                let concrete = path.replace("{id}", id).replace("{org}", id);
                let page = match method {
                    "GET" => ana.get(&concrete).await,
                    _ => {
                        ana.post_raw(
                            &concrete,
                            &[
                                ("csrf", &csrf),
                                ("confirm", "Globex"),
                                ("name", "x"),
                                ("role", "member"),
                                ("group", "none"),
                                ("cidr", "192.0.2.0/24"),
                                ("action", "save"),
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
                "{method} {path} {globex_id}: {}",
                answers[0].1
            );
            assert_eq!(
                answers[0], answers[1],
                "{method} {path}: the same as an unknown id"
            );
            sent += 1;
        }
    }
    // Forms that carry an id: the switcher (by value; Ana has no personal account), a
    // service key's group, a member's new group. The switcher's positive control first.
    let own = ana
        .submit(
            "/keys",
            "/place",
            &[("to", &format!("org:{}", world.acme.id))],
        )
        .await;
    assert_eq!(own.status, StatusCode::SEE_OTHER, "{}", own.body);
    let ops_id = ops.id.to_string();
    for (page, path, fields) in [
        (
            "/keys",
            "/place".to_owned(),
            vec![("to", format!("org:{}", world.globex.id))],
        ),
        (
            "/keys",
            "/place".to_owned(),
            vec![("to", "personal".to_owned())],
        ),
        (
            "/keys",
            "/keys/service".to_owned(),
            vec![("name", "x".to_owned()), ("attach", ops_id.clone())],
        ),
        (
            "/keys",
            format!("/org/members/{acme_member}/group"),
            vec![("group", ops_id.clone())],
        ),
        (
            "/keys",
            format!("/org/{}/invitations", world.acme.id),
            vec![
                ("email", "x@acme.test".to_owned()),
                ("role", "member".to_owned()),
                ("group", ops_id.clone()),
            ],
        ),
    ] {
        let fields: Vec<(&str, &str)> = fields.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let answer = ana.submit(page, &path, &fields).await;
        assert_eq!(
            answer.status,
            StatusCode::NOT_FOUND,
            "{path} {fields:?}: {}",
            answer.body
        );
        sent += 1;
    }
    assert!(sent >= 30, "{sent}");
    assert_eq!(state(&fx.db).await, before, "nothing written");
}
