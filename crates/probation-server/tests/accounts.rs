//! Slice 5: sign-up, sign-in, linking, TOTP, deletion and restore, through the real
//! portal routes against Postgres (03 § Portal requirement tests). The outside world is
//! faked: `FakeMail` stands in for SMTP and `FakeNet` for every IdP and the
//! leaked-password service, so no test reaches Google, GitHub, Microsoft or HIBP.

mod common;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::Db;
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

    /// Makes every waiting outbox row due now (the fake clock).
    async fn outbox_due(&self) {
        sqlx::query("UPDATE email_outbox SET next_attempt_at = now() WHERE sent_at IS NULL")
            .execute(&self.db.owner)
            .await
            .unwrap();
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
    }
}

async fn serve(db: &Db, mail: Arc<FakeMail>, net: Arc<dyn Outbound>) -> SocketAddr {
    let portal = Portal::new(PortalDeps {
        pool: db.app.clone(),
        config: config(),
        outbound: net,
        mailer: Some(mail),
        secret_key: [7; 32],
        // Cheap hashing keeps 100 sign-in attempts fast in a debug build.
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

/// What a browser keeps: one session cookie, sent back on every request, and the client
/// address the trusted proxy in front reports.
struct Browser {
    http: reqwest::Client,
    addr: SocketAddr,
    ip: String,
    cookie: Option<String>,
}

struct Page {
    status: StatusCode,
    location: Option<String>,
    set_cookie: Vec<String>,
    csp: Option<String>,
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

    /// Like `submit`, with a `Host` header of the client's choosing.
    async fn submit_as_host(
        &mut self,
        host: &str,
        page: &str,
        path: &str,
        fields: &[(&str, &str)],
    ) -> Page {
        let csrf = self.get(page).await.csrf();
        let mut fields = fields.to_vec();
        fields.push(("csrf", &csrf));
        let builder = self
            .http
            .post(self.url(path))
            .header("host", host)
            .form(&fields);
        self.fetch(builder).await
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
        let header = |name: &str| {
            answer
                .headers()
                .get(name)
                .map(|value| value.to_str().unwrap().to_owned())
        };
        let location = header("location");
        let csp = header("content-security-policy");
        let set_cookie: Vec<String> = answer
            .headers()
            .get_all("set-cookie")
            .iter()
            .map(|value| value.to_str().unwrap().to_owned())
            .collect();
        for cookie in &set_cookie {
            let pair = cookie.split(';').next().unwrap().to_owned();
            if cookie.contains("Max-Age=0") {
                self.cookie = None;
            } else {
                self.cookie = Some(pair);
            }
        }
        let status = answer.status();
        let body = answer.text().await.unwrap();
        Page {
            status,
            location,
            set_cookie,
            csp,
            body,
        }
    }

    /// The session id this browser holds.
    fn session(&self) -> Option<String> {
        self.cookie.clone()
    }
}

/// The SMTP relay: records each mail, and refuses the next `refuse` sends.
#[derive(Default)]
struct FakeMail {
    sent: Mutex<Vec<Mail>>,
    refuse: AtomicUsize,
}

#[async_trait::async_trait]
impl Mailer for FakeMail {
    async fn deliver(&self, mail: &Mail) -> Result<(), String> {
        if self
            .refuse
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            return Err("421 try again later".to_owned());
        }
        self.sent.lock().unwrap().push(mail.clone());
        Ok(())
    }
}

impl FakeMail {
    fn to(&self, address: &str) -> Vec<Mail> {
        self.sent
            .lock()
            .unwrap()
            .iter()
            .filter(|mail| mail.to == address)
            .cloned()
            .collect()
    }

    /// The path and query of the last link to `address` that starts with `prefix`.
    fn link(&self, address: &str, prefix: &str) -> String {
        let full = format!("{BASE_URL}{prefix}");
        let mail = self
            .to(address)
            .into_iter()
            .rev()
            .find(|mail| mail.body.contains(&full))
            .unwrap_or_else(|| panic!("no mail to {address} with a {prefix} link"));
        let start = mail.body.find(&full).unwrap() + BASE_URL.len();
        let end = mail.body[start..]
            .find(char::is_whitespace)
            .map_or(mail.body.len(), |end| start + end);
        mail.body[start..end].to_owned()
    }
}

/// The fake IdPs' RSA signing key (PKCS#1 DER, base64), made for these tests only.
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
    /// The IdPs redeem a code without checking its PKCE verifier, as one that does not
    /// support PKCE would, so the portal's own `state` and `nonce` checks stand alone.
    ignore_pkce: std::sync::atomic::AtomicBool,
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
            && (challenge == grant.challenge || self.ignore_pkce.load(Ordering::SeqCst));
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

/// Signs `email` up with `fields` and confirms the address through the mailed link.
async fn sign_up(fx: &Fixture, email: &str, fields: &[(&str, &str)]) -> Browser {
    let mut browser = fx.browser();
    let mut all = vec![("email", email), ("password", PASSWORD)];
    all.extend_from_slice(fields);
    let page = browser.submit("/signup", "/signup", &all).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    fx.deliver().await;
    let link = fx.mail.link(email, "/verify-email?token=");
    let confirmed = browser.get(&link).await;
    assert_eq!(confirmed.status, StatusCode::OK, "{}", confirmed.body);
    assert!(confirmed.has("Your email address is confirmed"));
    browser
}

async fn login_of(db: &Db, email: &str) -> i32 {
    sqlx::query_scalar(
        "SELECT login_id FROM sign_in_methods WHERE kind = 'password' AND email = $1",
    )
    .bind(email)
    .fetch_one(&db.owner)
    .await
    .unwrap()
}

/// T-portal-signup-creates-org (C5): after email confirmation the signer is the only org
/// admin of a new organisation; the same page is shown whether or not the mail went out;
/// the mail is delivered on the outbox retry, and "resend" works.
#[tokio::test]
async fn t_portal_signup_creates_org() {
    let fx = Fixture::start().await;
    let mut browser = fx.browser();
    fx.mail.refuse.store(1, Ordering::SeqCst);
    let fields = [
        ("email", "ana@acme.test"),
        ("password", PASSWORD),
        ("kind", "org"),
        ("org_name", "Acme"),
    ];
    let first = browser.submit("/signup", "/signup", &fields).await;
    assert_eq!(first.status, StatusCode::OK);
    assert!(first.has("We sent a link to"), "{}", first.body);
    assert!(first.has("ana@acme.test"));

    // The SMTP fake refuses the first send; the outbox retries it.
    fx.deliver().await;
    assert!(fx.mail.to("ana@acme.test").is_empty());
    fx.outbox_due().await;
    fx.deliver().await;
    assert_eq!(fx.mail.to("ana@acme.test").len(), 1);

    // "Send the link again" shows the same page and sends a second link.
    let again = browser
        .post_raw(
            "/verify-email/resend",
            &[("email", "ana@acme.test"), ("csrf", &first.csrf())],
        )
        .await;
    assert_eq!(again.status, StatusCode::OK);
    assert_eq!(again.body, first.body, "the same page either way");
    fx.deliver().await;
    assert_eq!(fx.mail.to("ana@acme.test").len(), 2);

    // Nothing exists before the address is confirmed.
    assert_eq!(fx.db.count("SELECT count(*) FROM orgs").await, 0);
    let link = fx.mail.link("ana@acme.test", "/verify-email?token=");
    let confirmed = browser.get(&link).await;
    assert_eq!(confirmed.status, StatusCode::OK, "{}", confirmed.body);
    assert!(confirmed.has("Your email address is confirmed"));

    let login = login_of(&fx.db, "ana@acme.test").await;
    let admins: Vec<(i32, String)> = sqlx::query_as(
        "SELECT m.login_id, o.name FROM memberships AS m JOIN orgs AS o ON o.id = m.org_id
         WHERE m.role = 'org_admin'",
    )
    .fetch_all(&fx.db.owner)
    .await
    .unwrap();
    assert_eq!(admins, vec![(login, "Acme".to_owned())]);
    assert_eq!(fx.db.count("SELECT count(*) FROM memberships").await, 1);
    // The link works once.
    let reused = browser.get(&link).await;
    assert!(reused.has("This link has expired or was already used"));
    assert_eq!(fx.db.count("SELECT count(*) FROM orgs").await, 1);
}

/// T-portal-signup-personal (C6): a personal account whose chain is platform -> personal.
#[tokio::test]
async fn t_portal_signup_personal() {
    let fx = Fixture::start().await;
    sign_up(&fx, "pat@home.test", &[("kind", "personal")]).await;
    let login = login_of(&fx.db, "pat@home.test").await;
    let personal: i32 = sqlx::query_scalar("SELECT id FROM personal_accounts WHERE login_id = $1")
        .bind(login)
        .fetch_one(&fx.db.owner)
        .await
        .unwrap();
    let place = common::place(probation_policy::LayerKind::Personal, personal);
    let session = probation_server::tenancy::Session::new(login, None);
    let authorized = fx
        .db
        .tenancy()
        .authorized_place(&session, place)
        .await
        .expect("the owner sees their personal account");
    assert_eq!(
        authorized.chain(),
        &[probation_server::tenancy::PLATFORM, place]
    );
    assert_eq!(fx.db.count("SELECT count(*) FROM orgs").await, 0);
    assert_eq!(fx.db.count("SELECT count(*) FROM memberships").await, 0);
}

/// T-portal-password-rules (C42): 11 characters refused; a password on the leaked list
/// refused; 12 characters accepted.
#[tokio::test]
async fn t_portal_password_rules() {
    let fx = Fixture::start().await;
    fx.net
        .leaked
        .lock()
        .unwrap()
        .push("password1234".to_owned());
    let mut browser = fx.browser();
    let attempt = |password: &'static str| {
        [
            ("email", "rules@home.test"),
            ("password", password),
            ("kind", "personal"),
        ]
    };
    let short = browser
        .submit("/signup", "/signup", &attempt("elevenchars"))
        .await;
    assert!(short.has("Use at least 12 characters."), "{}", short.body);
    let leaked = browser
        .submit("/signup", "/signup", &attempt("password1234"))
        .await;
    assert!(
        leaked.has("This password has appeared in a known data leak."),
        "{}",
        leaked.body
    );
    assert_eq!(fx.db.count("SELECT count(*) FROM sign_in_methods").await, 0);
    let twelve = browser
        .submit("/signup", "/signup", &attempt("twelve chars"))
        .await;
    assert!(twelve.has("We sent a link to"), "{}", twelve.body);
    assert_eq!(fx.db.count("SELECT count(*) FROM sign_in_methods").await, 1);
}

/// T-portal-signup-duplicate-email (C91): the same "check your email" page byte for byte;
/// no second method is created.
#[tokio::test]
async fn t_portal_signup_duplicate_email() {
    let fx = Fixture::start().await;
    let mut first = fx.browser();
    let fields = [
        ("email", "dup@acme.test"),
        ("password", PASSWORD),
        ("kind", "personal"),
    ];
    let page = first.submit("/signup", "/signup", &fields).await;
    // A second visitor with the same address, and the first one again after confirming.
    let mut second = fx.browser();
    second.cookie = first.cookie.clone();
    let again = second.submit("/signup", "/signup", &fields).await;
    assert_eq!(again.status, page.status);
    assert_eq!(again.body, page.body, "byte for byte");
    fx.deliver().await;
    let link = fx.mail.link("dup@acme.test", "/verify-email?token=");
    first.get(&link).await;
    let after = first.submit("/signup", "/signup", &fields).await;
    assert_eq!(after.body, page.body, "byte for byte once confirmed too");
    assert_eq!(fx.db.count("SELECT count(*) FROM sign_in_methods").await, 1);
    assert_eq!(fx.db.count("SELECT count(*) FROM logins").await, 1);
    // The address's owner is told someone tried.
    fx.deliver().await;
    assert!(
        fx.mail
            .to("dup@acme.test")
            .iter()
            .any(|mail| mail.subject == "You already have a Probation login")
    );

    // R3: sign-ups from one client IP are capped; past the cap the page is the same and
    // nothing is created or mailed.
    let mut flood = Browser::new(fx.addr, "203.0.113.50");
    let mut last = None;
    for n in 0..25 {
        let email = format!("flood{n}@spam.test");
        let fields = [
            ("email", email.as_str()),
            ("password", PASSWORD),
            ("kind", "personal"),
        ];
        let page = flood.submit("/signup", "/signup", &fields).await;
        assert!(page.has("We sent a link to"), "{}", page.body);
        last = Some((email, page));
    }
    let (email, page) = last.unwrap();
    let fresh = signup_page(&fx, "fresh@spam.test").await;
    assert_eq!(
        without_csrf(&page.body).replace(&email, "x"),
        without_csrf(&fresh.body).replace("fresh@spam.test", "x")
    );
    let flooded = "SELECT count(*) FROM sign_in_methods WHERE email LIKE 'flood%'";
    let made = fx.db.count(flooded).await;
    assert!(made < 25, "{made} sign-ups from one IP");

    // N5: past the cap, a weak password still shows its own error.
    let weak = [
        ("email", "weak@spam.test"),
        ("password", "short"),
        ("kind", "personal"),
    ];
    let page = flood.submit("/signup", "/signup", &weak).await;
    assert!(page.has("Use at least 12 characters."), "{}", page.body);
}

/// `path` with every `{…}` segment replaced by `with`.
fn concrete(path: &str, with: &str) -> String {
    path.split('/')
        .map(|segment| {
            if segment.starts_with('{') {
                with
            } else {
                segment
            }
        })
        .collect::<Vec<_>>()
        .join("/")
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

/// T-portal-unverified-blocked (C41): every route except /verify-email and /signout
/// redirects to "confirm your email"; the login has no place, so `keys::create`, which
/// takes an `Authorized<Place>`, cannot be reached for it.
#[tokio::test]
async fn t_portal_unverified_blocked() {
    let fx = Fixture::start().await;
    let mut browser = fx.browser();
    let fields = [
        ("email", "new@acme.test"),
        ("password", PASSWORD),
        ("kind", "org"),
        ("org_name", "Unconfirmed"),
    ];
    browser.submit("/signup", "/signup", &fields).await;
    let signed_in = sign_in(&mut browser, "new@acme.test", PASSWORD).await;
    assert_eq!(
        signed_in.status,
        StatusCode::SEE_OTHER,
        "{}",
        signed_in.body
    );
    let confirm = browser.get("/verify-email").await;
    assert!(confirm.has("Confirm your email"), "{}", confirm.body);
    let csrf = confirm.csrf();
    for (method, path) in portal::route_table() {
        if path.starts_with("/verify-email") || path == "/signout" || path.starts_with("/static/") {
            continue;
        }
        let path = concrete(path, "1");
        let page = match method {
            "GET" => browser.get(&path).await,
            _ => browser.post_raw(&path, &[("csrf", &csrf)]).await,
        };
        assert_eq!(
            (page.status, page.location.as_deref()),
            (StatusCode::SEE_OTHER, Some("/verify-email")),
            "{method} {path}"
        );
    }
    let login = login_of(&fx.db, "new@acme.test").await;
    let places: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM memberships WHERE login_id = $1)
              + (SELECT count(*) FROM personal_accounts WHERE login_id = $1)",
    )
    .bind(login)
    .fetch_one(&fx.db.owner)
    .await
    .unwrap();
    assert_eq!(places, 0, "no place, so no key can be created for it");
    assert_eq!(fx.db.count("SELECT count(*) FROM keys").await, 0);
    let out = browser.post_raw("/signout", &[("csrf", &csrf)]).await;
    assert_eq!(out.status, StatusCode::SEE_OTHER);
    assert!(browser.session().is_none(), "the cookie is cleared");
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

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Turns the authenticator on from `/account`; returns its secret and backup codes.
async fn turn_totp_on(browser: &mut Browser) -> (String, Vec<String>) {
    let setup = browser.submit("/account", "/account/totp/setup", &[]).await;
    assert_eq!(setup.status, StatusCode::OK, "{}", setup.body);
    let secret = between(&setup.body, "<code id=\"totp-key\">", "</code>").to_owned();
    let codes: Vec<String> = between(&setup.body, "<pre id=\"backup-codes\">", "</pre>")
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    let code = totp_code(&secret, now_unix() - 30);
    let csrf = setup.csrf();
    let on = browser
        .post_raw("/account/totp/enable", &[("code", &code), ("csrf", &csrf)])
        .await;
    assert_eq!(on.status, StatusCode::SEE_OTHER, "{}", on.body);
    (secret, codes)
}

/// A confirmed login signed in with its password.
async fn member(fx: &Fixture, email: &str, fields: &[(&str, &str)]) -> Browser {
    let mut browser = sign_up(fx, email, fields).await;
    let signed_in = sign_in(&mut browser, email, PASSWORD).await;
    assert_eq!(
        signed_in.location.as_deref(),
        Some("/account"),
        "{}",
        signed_in.body
    );
    browser
}

/// T-portal-totp-toggle (C24, C40): a member turns TOTP on and then off on /account; an
/// org admin's attempt to turn it off is refused.
#[tokio::test]
async fn t_portal_totp_toggle() {
    let fx = Fixture::start().await;
    let mut pat = member(&fx, "pat@home.test", &[("kind", "personal")]).await;
    assert!(pat.get("/account").await.has("Authenticator app: off"));
    turn_totp_on(&mut pat).await;
    assert!(pat.get("/account").await.has("Authenticator app: on"));
    let off = pat.submit("/account", "/account/totp/disable", &[]).await;
    assert_eq!(off.status, StatusCode::SEE_OTHER, "{}", off.body);
    assert!(pat.get("/account").await.has("Authenticator app: off"));
    assert_eq!(fx.db.count("SELECT count(*) FROM totp").await, 0);

    let mut ana = member(
        &fx,
        "ana@acme.test",
        &[("kind", "org"), ("org_name", "Acme")],
    )
    .await;
    turn_totp_on(&mut ana).await;
    let refused = ana.submit("/account", "/account/totp/disable", &[]).await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN, "{}", refused.body);
    let account = ana.get("/account").await;
    assert!(account.has("Authenticator app: on"));
    assert!(account.has("Org admins and global admins cannot turn it off"));
    assert_eq!(
        fx.db
            .count("SELECT count(*) FROM totp WHERE enabled_at IS NOT NULL")
            .await,
        1
    );
}

async fn sign_out(browser: &mut Browser) {
    let csrf = browser.get("/account").await.csrf();
    let out = browser.post_raw("/signout", &[("csrf", &csrf)]).await;
    assert_eq!(out.status, StatusCode::SEE_OTHER);
}

/// Signs in with the password, then answers the authenticator step with `code`.
async fn sign_in_with_code(browser: &mut Browser, email: &str, code: &str) -> Page {
    let first = sign_in(browser, email, PASSWORD).await;
    assert_eq!(first.location.as_deref(), Some("/totp"), "{}", first.body);
    browser.submit("/totp", "/totp", &[("code", code)]).await
}

/// T-portal-backup-codes (C39): 10 codes shown once; each signs in once; a reused code is
/// refused.
#[tokio::test]
async fn t_portal_backup_codes() {
    let fx = Fixture::start().await;
    let mut browser = member(&fx, "bo@home.test", &[("kind", "personal")]).await;
    let (_, codes) = turn_totp_on(&mut browser).await;
    assert_eq!(codes.len(), 10);
    let distinct: std::collections::HashSet<_> = codes.iter().collect();
    assert_eq!(distinct.len(), 10);
    assert!(!browser.get("/account").await.has(&codes[0]), "shown once");
    for code in &codes {
        sign_out(&mut browser).await;
        let page = sign_in_with_code(&mut browser, "bo@home.test", code).await;
        assert_eq!(
            page.location.as_deref(),
            Some("/account"),
            "{code}: {}",
            page.body
        );
    }
    sign_out(&mut browser).await;
    let reused = sign_in_with_code(&mut browser, "bo@home.test", &codes[3]).await;
    assert_eq!(reused.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        reused.has("That code is wrong or has expired"),
        "{}",
        reused.body
    );
    assert_eq!(
        browser.get("/account").await.location.as_deref(),
        Some("/signin")
    );
}

/// `body` with every CSRF token blanked, to compare pages of different sessions.
fn without_csrf(body: &str) -> String {
    let mut out = String::new();
    let mut rest = body;
    let marker = "name=\"csrf\" value=\"";
    while let Some(at) = rest.find(marker) {
        out.push_str(&rest[..at + marker.len()]);
        rest = &rest[at + marker.len()..];
        rest = &rest[rest.find('"').unwrap()..];
    }
    out.push_str(rest);
    out
}

const THROTTLED: &str = "Too many attempts";

/// One burst: each browser POSTs `fields` (plus its own CSRF token from `page`) to
/// `path`, all at once; returns the answers.
async fn burst(
    browsers: Vec<Browser>,
    page: &str,
    path: &str,
    fields: &[(&str, &str)],
) -> Vec<Page> {
    let mut ready = Vec::new();
    for mut browser in browsers {
        let csrf = browser.get(page).await.csrf();
        ready.push((browser, csrf));
    }
    let mut set = tokio::task::JoinSet::new();
    for (mut browser, csrf) in ready {
        let path = path.to_owned();
        let mut fields: Vec<(String, String)> = fields
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        fields.push(("csrf".to_owned(), csrf));
        set.spawn(async move {
            let fields: Vec<(&str, &str)> = fields
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            browser.post_raw(&path, &fields).await
        });
    }
    set.join_all().await
}

/// T-portal-auth-session (T15, T32): the sign-in cookie is Secure and HttpOnly; the
/// session id changes at sign-in and after TOTP; the 6th wrong TOTP code is refused by
/// throttling; a reused code is refused; the 11th password attempt for one email is
/// refused even when right, the same way for an unknown email; after 100 failures from
/// one client IP a right password from it is refused, and accepted from another IP.
#[tokio::test]
async fn t_portal_auth_session() {
    let fx = Fixture::start().await;
    let mut sam = member(&fx, "sam@home.test", &[("kind", "personal")]).await;
    let (secret, _) = turn_totp_on(&mut sam).await;
    sign_out(&mut sam).await;
    sam.get("/signin").await;
    let anonymous = sam.session().expect("a signed-out session");
    let first = sign_in(&mut sam, "sam@home.test", PASSWORD).await;
    assert_eq!(first.location.as_deref(), Some("/totp"));
    let cookie = first.set_cookie.first().expect("a new session cookie");
    assert!(
        cookie.contains("; Secure") && cookie.contains("; HttpOnly"),
        "{cookie}"
    );
    let pending = sam.session().unwrap();
    assert_ne!(pending, anonymous, "a new id at sign-in");
    for _ in 0..5 {
        let wrong = sam.submit("/totp", "/totp", &[("code", "000000")]).await;
        assert!(wrong.has("That code is wrong"), "{}", wrong.body);
    }
    let code = totp_code(&secret, now_unix());
    let sixth = sam.submit("/totp", "/totp", &[("code", &code)]).await;
    assert!(
        sixth.has(THROTTLED),
        "the 6th code is throttled: {}",
        sixth.body
    );
    // 15 minutes later (the fake clock).
    sqlx::query("UPDATE sign_in_failures SET at = at - interval '16 minutes'")
        .execute(&fx.db.owner)
        .await
        .unwrap();
    let ok = sam.submit("/totp", "/totp", &[("code", &code)]).await;
    assert_eq!(ok.location.as_deref(), Some("/account"), "{}", ok.body);
    assert_ne!(sam.session().unwrap(), pending, "a new id after TOTP");
    sign_out(&mut sam).await;
    let replayed = sign_in_with_code(&mut sam, "sam@home.test", &code).await;
    assert!(
        replayed.has("That code is wrong"),
        "a used code: {}",
        replayed.body
    );

    // Per email: 10 failures, then even the right password is refused.
    member(&fx, "ivy@home.test", &[("kind", "personal")]).await;
    let mut known = fx.browser();
    let mut unknown = fx.browser();
    for _ in 0..10 {
        let wrong = sign_in(&mut known, "ivy@home.test", "wrong password!").await;
        assert!(wrong.has("That email and password do not match"));
        sign_in(&mut unknown, "ghost@home.test", "wrong password!").await;
    }
    let known_11th = sign_in(&mut known, "ivy@home.test", PASSWORD).await;
    assert!(known_11th.has(THROTTLED), "{}", known_11th.body);
    let unknown_11th = sign_in(&mut unknown, "ghost@home.test", PASSWORD).await;
    assert_eq!(known_11th.status, unknown_11th.status);
    assert_eq!(
        without_csrf(&known_11th.body),
        without_csrf(&unknown_11th.body)
    );

    // Per client IP: 100 failures for 100 addresses, then a right password elsewhere.
    member(&fx, "kim@home.test", &[("kind", "personal")]).await;
    let mut flood = Browser::new(fx.addr, "203.0.113.9");
    for n in 0..100 {
        sign_in(
            &mut flood,
            &format!("user{n}@stuffing.test"),
            "wrong password!",
        )
        .await;
    }
    let refused = sign_in(&mut flood, "kim@home.test", PASSWORD).await;
    assert_eq!(
        without_csrf(&refused.body),
        without_csrf(&unknown_11th.body)
    );
    let mut elsewhere = Browser::new(fx.addr, "203.0.113.10");
    let accepted = sign_in(&mut elsewhere, "kim@home.test", PASSWORD).await;
    assert_eq!(
        accepted.location.as_deref(),
        Some("/account"),
        "{}",
        accepted.body
    );

    // R2: one burst of limit + 5 concurrent attempts verifies at most the limit.
    member(&fx, "zed@home.test", &[("kind", "personal")]).await;
    let browsers = (0..15).map(|_| fx.browser()).collect();
    let pages = burst(
        browsers,
        "/signin",
        "/signin",
        &[("email", "zed@home.test"), ("password", "wrong password!")],
    )
    .await;
    let verified = pages
        .iter()
        .filter(|page| page.has("That email and password do not match"))
        .count();
    let throttled = pages.iter().filter(|page| page.has(THROTTLED)).count();
    assert_eq!(verified + throttled, 15);
    assert!(
        verified <= 10,
        "{verified} of 15 password attempts were verified"
    );
    let mut una = member(&fx, "una@home.test", &[("kind", "personal")]).await;
    turn_totp_on(&mut una).await;
    let mut waiting = Vec::new();
    for _ in 0..10 {
        let mut browser = fx.browser();
        let first = sign_in(&mut browser, "una@home.test", PASSWORD).await;
        assert_eq!(first.location.as_deref(), Some("/totp"));
        waiting.push(browser);
    }
    let pages = burst(waiting, "/totp", "/totp", &[("code", "000000")]).await;
    let verified = pages
        .iter()
        .filter(|page| page.has("That code is wrong"))
        .count();
    let throttled = pages.iter().filter(|page| page.has(THROTTLED)).count();
    assert_eq!(verified + throttled, 10);
    assert!(verified <= 5, "{verified} of 10 codes were verified");
}

const NEW_PASSWORD: &str = "a brand new passphrase";

/// T-portal-change-password (C40): a password change needs the current password and
/// rotates the session; another session of the login, opened earlier, is signed out.
#[tokio::test]
async fn t_portal_change_password() {
    let fx = Fixture::start().await;
    let mut other = member(&fx, "cy@home.test", &[("kind", "personal")]).await;
    let mut browser = fx.browser();
    sign_in(&mut browser, "cy@home.test", PASSWORD).await;
    let change = |current: &'static str, new: &'static str, again: &'static str| {
        [("current", current), ("new", new), ("again", again)]
    };
    let wrong = browser
        .submit(
            "/account",
            "/account/password",
            &change("not my password", NEW_PASSWORD, NEW_PASSWORD),
        )
        .await;
    assert!(
        wrong.has("Your current password is not right"),
        "{}",
        wrong.body
    );
    let mismatch = browser
        .submit(
            "/account",
            "/account/password",
            &change(PASSWORD, NEW_PASSWORD, "something else entirely"),
        )
        .await;
    assert!(
        mismatch.has("The two passwords do not match"),
        "{}",
        mismatch.body
    );
    let short = browser
        .submit(
            "/account",
            "/account/password",
            &change(PASSWORD, "too short", "too short"),
        )
        .await;
    assert!(short.has("Use at least 12 characters."), "{}", short.body);
    let before = browser.session().unwrap();
    let changed = browser
        .submit(
            "/account",
            "/account/password",
            &change(PASSWORD, NEW_PASSWORD, NEW_PASSWORD),
        )
        .await;
    assert_eq!(
        changed.location.as_deref(),
        Some("/account"),
        "{}",
        changed.body
    );
    assert_ne!(browser.session().unwrap(), before, "the session is rotated");
    assert_eq!(browser.get("/account").await.status, StatusCode::OK);
    assert_eq!(
        other.get("/account").await.location.as_deref(),
        Some("/signin")
    );
    let mut fresh = fx.browser();
    assert!(
        sign_in(&mut fresh, "cy@home.test", PASSWORD)
            .await
            .has("do not match")
    );
    assert_eq!(
        sign_in(&mut fresh, "cy@home.test", NEW_PASSWORD)
            .await
            .location
            .as_deref(),
        Some("/account")
    );
}

/// Asks for a reset link for `email` and returns its path, as mailed.
async fn reset_link(fx: &Fixture, email: &str) -> String {
    let mut browser = fx.browser();
    let asked = browser
        .submit("/reset", "/reset", &[("email", email)])
        .await;
    assert!(
        asked.has("If an account uses this address"),
        "{}",
        asked.body
    );
    fx.deliver().await;
    fx.mail.link(email, "/reset/confirm?token=")
}

async fn choose_password(browser: &mut Browser, link: &str, password: &str) -> Page {
    let form = browser.get(link).await;
    assert_eq!(form.status, StatusCode::OK, "{}", form.body);
    let token = hidden(&form.body, "token").expect("the token in the form");
    browser
        .post_raw(
            "/reset/confirm",
            &[
                ("token", &token),
                ("new", password),
                ("again", password),
                ("csrf", &form.csrf()),
            ],
        )
        .await
}

/// T-portal-password-reset (C24): the emailed link works once, sets the new password and
/// expires; a login with TOTP still gets the TOTP prompt after the reset; another
/// session of the login, opened earlier, is signed out.
#[tokio::test]
async fn t_portal_password_reset() {
    let fx = Fixture::start().await;
    let mut other = member(&fx, "rae@home.test", &[("kind", "personal")]).await;
    let (secret, _) = turn_totp_on(&mut other).await;
    let link = reset_link(&fx, "rae@home.test").await;
    let mut browser = fx.browser();
    let done = choose_password(&mut browser, &link, NEW_PASSWORD).await;
    assert!(done.has("Your password is changed"), "{}", done.body);
    assert_eq!(
        other.get("/account").await.location.as_deref(),
        Some("/signin")
    );
    let used = browser.get(&link).await;
    assert!(
        used.has("This link has expired or was already used"),
        "{}",
        used.body
    );
    assert!(
        sign_in(&mut browser, "rae@home.test", PASSWORD)
            .await
            .has("do not match")
    );
    let new = sign_in(&mut browser, "rae@home.test", NEW_PASSWORD).await;
    assert_eq!(
        new.location.as_deref(),
        Some("/totp"),
        "the TOTP step stays"
    );

    let expiring = reset_link(&fx, "rae@home.test").await;
    sqlx::query(
        "UPDATE email_tokens SET expires_at = now() - interval '1 second' WHERE used_at IS NULL",
    )
    .execute(&fx.db.owner)
    .await
    .unwrap();
    let expired = fx.browser().get(&expiring).await;
    assert!(
        expired.has("This link has expired or was already used"),
        "{}",
        expired.body
    );

    // R5: a session waiting at the TOTP step does not survive a password reset.
    let mut waiting = fx.browser();
    let first = sign_in(&mut waiting, "rae@home.test", NEW_PASSWORD).await;
    assert_eq!(first.location.as_deref(), Some("/totp"));
    let csrf = waiting.get("/totp").await.csrf();
    let link = reset_link(&fx, "rae@home.test").await;
    choose_password(&mut fx.browser(), &link, "yet another passphrase").await;
    let code = totp_code(&secret, now_unix());
    let late = waiting
        .post_raw("/totp", &[("code", &code), ("csrf", &csrf)])
        .await;
    assert_ne!(late.location.as_deref(), Some("/account"), "{}", late.body);
    assert_eq!(
        waiting.get("/account").await.location.as_deref(),
        Some("/signin")
    );
}

/// T-portal-auth-links (T14): a reset requested with `Host: evil.example` mails a link on
/// the configured base URL; a used token is refused; a reset login with TOTP still gets
/// the TOTP prompt.
#[tokio::test]
async fn t_portal_auth_links() {
    let fx = Fixture::start().await;
    let mut owner = member(&fx, "lu@home.test", &[("kind", "personal")]).await;
    turn_totp_on(&mut owner).await;
    let mut browser = fx.browser();
    let asked = browser
        .submit_as_host(
            "evil.example",
            "/reset",
            "/reset",
            &[("email", "lu@home.test")],
        )
        .await;
    assert_eq!(asked.status, StatusCode::OK, "{}", asked.body);
    fx.deliver().await;
    let mail = fx.mail.to("lu@home.test").pop().unwrap();
    assert!(!mail.body.contains("evil.example"), "{}", mail.body);
    assert!(
        mail.body
            .contains(&format!("{BASE_URL}/reset/confirm?token=")),
        "{}",
        mail.body
    );
    let link = fx.mail.link("lu@home.test", "/reset/confirm?token=");
    let form = browser.get(&link).await;
    let token = hidden(&form.body, "token").unwrap();
    choose_password(&mut browser, &link, NEW_PASSWORD).await;
    let replay = browser
        .post_raw(
            "/reset/confirm",
            &[
                ("token", &token),
                ("new", "another passphrase"),
                ("again", "another passphrase"),
                ("csrf", &form.csrf()),
            ],
        )
        .await;
    assert!(
        replay.has("This link has expired or was already used"),
        "{}",
        replay.body
    );
    assert!(
        sign_in(&mut browser, "lu@home.test", "another passphrase")
            .await
            .has("do not match")
    );
    let signed = sign_in(&mut browser, "lu@home.test", NEW_PASSWORD).await;
    assert_eq!(signed.location.as_deref(), Some("/totp"));

    // R3: a few mails per address in 15 minutes, with the same answer for a known and an
    // unknown address.
    let fx = &fx;
    let asked = |email: &'static str| async move {
        let mut browser = fx.browser();
        browser
            .submit("/reset", "/reset", &[("email", email)])
            .await
    };
    let before = fx.mail.to("lu@home.test").len();
    let mut answers = Vec::new();
    for _ in 0..5 {
        answers.push(without_csrf(&asked("lu@home.test").await.body));
        answers.push(without_csrf(&asked("nobody@home.test").await.body));
    }
    fx.deliver().await;
    assert!(
        answers.iter().all(|answer| *answer == answers[0]),
        "the same page every time"
    );
    let sent = fx.mail.to("lu@home.test").len() - before;
    assert!(sent < 5, "{sent} reset mails in a row");
    assert!(fx.mail.to("nobody@home.test").is_empty());

    // N2: failed sign-ins under an address shaped like the mail cap's key do not count
    // against that address's mail.
    member(fx, "vic@home.test", &[("kind", "personal")]).await;
    let mut odd = fx.browser();
    for _ in 0..5 {
        sign_in(&mut odd, "mail:vic@home.test", "wrong password!").await;
    }
    fx.deliver().await;
    let before = fx.mail.to("vic@home.test").len();
    fx.browser()
        .submit("/reset", "/reset", &[("email", "vic@home.test")])
        .await;
    fx.deliver().await;
    assert_eq!(
        fx.mail.to("vic@home.test").len(),
        before + 1,
        "vic's reset mail"
    );

    // N3: the mail paths need one connection at a time.
    let single = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(2))
        .connect(&fx.db.app_url)
        .await
        .unwrap();
    let base = url::Url::parse(BASE_URL).unwrap();
    accounts::request_reset(&single, &base, "vic@home.test")
        .await
        .expect("a reset on one connection");
    accounts::sign_up(
        &single,
        &base,
        "solo@home.test",
        "not-a-hash",
        accounts::SignupKind::Personal,
    )
    .await
    .expect("a sign-up on one connection");
    accounts::resend_verification(&single, &base, "solo@home.test")
        .await
        .expect("a resend on one connection");
}

/// The place switcher's options on `page`.
fn switcher(page: &Page) -> Vec<String> {
    let select = between(&page.body, "<select id=\"place-switcher\"", "</select>");
    select
        .split("<option>")
        .skip(1)
        .map(|option| option.trim_end_matches("</option>").to_owned())
        .collect()
}

/// T-portal-account-create-place (C40): creating a personal account or an organisation
/// from Account settings adds it to the place switcher.
#[tokio::test]
async fn t_portal_account_create_place() {
    let fx = Fixture::start().await;
    let mut browser = member(
        &fx,
        "ana@acme.test",
        &[("kind", "org"), ("org_name", "Acme")],
    )
    .await;
    assert_eq!(
        switcher(&browser.get("/account").await),
        ["Acme (organisation)"]
    );
    let personal = browser.submit("/account", "/account/personal", &[]).await;
    assert_eq!(personal.status, StatusCode::SEE_OTHER, "{}", personal.body);
    let org = browser
        .submit("/account", "/account/org", &[("name", "Northwind")])
        .await;
    assert_eq!(org.status, StatusCode::SEE_OTHER, "{}", org.body);
    assert_eq!(
        switcher(&browser.get("/account").await),
        [
            "Personal account",
            "Acme (organisation)",
            "Northwind (organisation)"
        ]
    );
    let login = login_of(&fx.db, "ana@acme.test").await;
    let role: String = sqlx::query_scalar(
        "SELECT m.role FROM memberships AS m JOIN orgs AS o ON o.id = m.org_id
         WHERE o.name = 'Northwind' AND m.login_id = $1",
    )
    .bind(login)
    .fetch_one(&fx.db.owner)
    .await
    .unwrap();
    assert_eq!(role, "org_admin");
    // A second personal account, or a taken name, is refused.
    let twice = browser.submit("/account", "/account/personal", &[]).await;
    assert_eq!(twice.status, StatusCode::UNPROCESSABLE_ENTITY);
    let taken = browser
        .submit("/account", "/account/org", &[("name", "acme")])
        .await;
    assert!(
        taken.has("That organisation name is taken"),
        "{}",
        taken.body
    );
    assert_eq!(fx.db.count("SELECT count(*) FROM orgs").await, 2);
    assert_eq!(
        fx.db.count("SELECT count(*) FROM personal_accounts").await,
        1
    );
}

/// T-portal-xss (T13): an organisation named `<script>alert(1)</script>` appears escaped
/// in the /account place switcher, with the CSP header.
#[tokio::test]
async fn t_portal_xss() {
    let fx = Fixture::start().await;
    let mut browser = member(&fx, "eve@home.test", &[("kind", "personal")]).await;
    browser
        .submit(
            "/account",
            "/account/org",
            &[("name", "<script>alert(1)</script>")],
        )
        .await;
    let page = browser.get("/account").await;
    assert!(
        page.has("&#60;script&#62;alert(1)&#60;/script&#62; (organisation)"),
        "{}",
        page.body
    );
    assert!(!page.has("<script>"), "{}", page.body);
    assert_eq!(
        page.csp.as_deref(),
        Some("default-src 'self'; frame-ancestors 'none'")
    );
}

/// Signs in through `provider` at the fake IdP as the person `claims` describe; returns
/// the portal's answer to the callback.
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

async fn session_row(db: &Db, browser: &Browser) -> Option<(Option<i32>, bool)> {
    use sha2::Digest;
    let token = browser.session()?.split_once('=')?.1.to_owned();
    sqlx::query_as("SELECT login_id, totp_ok FROM sessions WHERE id_hash = $1")
        .bind(sha2::Sha256::digest(token.as_bytes()).to_vec())
        .fetch_optional(&db.owner)
        .await
        .unwrap()
}

/// T-portal-oauth-no-totp (C38): a Google sign-in of a login without a password method
/// gets no TOTP prompt, even with an authenticator turned on.
#[tokio::test]
async fn t_portal_oauth_no_totp() {
    let fx = Fixture::start().await;
    let mut browser = fx.browser();
    let gina = serde_json::json!({"sub": "g-1", "email": "gina@gmail.test"});
    let first = oauth(&fx, &mut browser, "/oauth/google/start", gina.clone()).await;
    assert_eq!(
        first.location.as_deref(),
        Some("/account"),
        "{}",
        first.body
    );
    assert_eq!(browser.get("/account").await.status, StatusCode::OK);
    turn_totp_on(&mut browser).await;
    sign_out(&mut browser).await;
    let again = oauth(&fx, &mut browser, "/oauth/google/start", gina).await;
    assert_eq!(
        again.location.as_deref(),
        Some("/account"),
        "no TOTP step: {}",
        again.body
    );
    let (login, totp_ok) = session_row(&fx.db, &browser).await.expect("a session");
    assert!(
        login.is_some() && totp_ok,
        "an OAuth session counts as second-factor checked"
    );
    assert_eq!(fx.db.count("SELECT count(*) FROM logins").await, 1);
    let method: (String, String, String) =
        sqlx::query_as("SELECT kind, issuer, subject FROM sign_in_methods")
            .fetch_one(&fx.db.owner)
            .await
            .unwrap();
    assert_eq!(
        method,
        (
            "google".to_owned(),
            "https://accounts.google.com".to_owned(),
            "g-1".to_owned()
        )
    );
}

async fn methods_of(db: &Db, login: i32) -> Vec<(String, String)> {
    sqlx::query_as("SELECT kind, subject FROM sign_in_methods WHERE login_id = $1 ORDER BY id")
        .bind(login)
        .fetch_all(&db.owner)
        .await
        .unwrap()
}

/// T-portal-link-never-by-email (C75): a Google sign-in with the email of a password login
/// creates a separate login; linking while signed in joins it.
#[tokio::test]
async fn t_portal_link_never_by_email() {
    let fx = Fixture::start().await;
    let mut ana = member(&fx, "ana@acme.test", &[("kind", "personal")]).await;
    let ana_login = login_of(&fx.db, "ana@acme.test").await;
    let mut stranger = fx.browser();
    let same_email = serde_json::json!({"sub": "g-other", "email": "ana@acme.test"});
    let separate = oauth(
        &fx,
        &mut stranger,
        "/oauth/google/start",
        same_email.clone(),
    )
    .await;
    assert_eq!(separate.location.as_deref(), Some("/account"));
    assert_eq!(
        fx.db.count("SELECT count(*) FROM logins").await,
        2,
        "a separate login"
    );
    assert_eq!(
        methods_of(&fx.db, ana_login).await.len(),
        1,
        "nothing joined by email"
    );

    let linked = oauth(
        &fx,
        &mut ana,
        "/account/link/google",
        serde_json::json!({"sub": "g-ana", "email": "ana.personal@gmail.test"}),
    )
    .await;
    assert_eq!(
        linked.location.as_deref(),
        Some("/account"),
        "{}",
        linked.body
    );
    assert_eq!(
        methods_of(&fx.db, ana_login).await,
        [
            ("password".to_owned(), "ana@acme.test".to_owned()),
            ("google".to_owned(), "g-ana".to_owned())
        ]
    );
    let account = ana.get("/account").await;
    assert!(
        account.has("ana.personal@gmail.test"),
        "the linked method is listed"
    );
    // A method of another login is not taken over by linking it.
    let taken = oauth(&fx, &mut ana, "/account/link/google", same_email).await;
    assert!(taken.has("belongs to another login"), "{}", taken.body);
    assert_eq!(methods_of(&fx.db, ana_login).await.len(), 2);
    assert_eq!(fx.db.count("SELECT count(*) FROM logins").await, 2);
}

async fn method_id(db: &Db, login: i32, kind: &str) -> i32 {
    sqlx::query_scalar("SELECT id FROM sign_in_methods WHERE login_id = $1 AND kind = $2")
        .bind(login)
        .bind(kind)
        .fetch_one(&db.owner)
        .await
        .unwrap()
}

/// T-portal-unlink-last-refused (C89): removing the last method is refused; removing one
/// of two succeeds and signs the login's other sessions out.
#[tokio::test]
async fn t_portal_unlink_last_refused() {
    let fx = Fixture::start().await;
    let mut other = member(&fx, "ana@acme.test", &[("kind", "personal")]).await;
    let mut ana = fx.browser();
    sign_in(&mut ana, "ana@acme.test", PASSWORD).await;
    let login = login_of(&fx.db, "ana@acme.test").await;
    oauth(
        &fx,
        &mut ana,
        "/account/link/github",
        serde_json::json!({"id": 4242, "email": "ana@github.test"}),
    )
    .await;
    assert_eq!(methods_of(&fx.db, login).await.len(), 2);
    // N4: a session waiting at the TOTP step ends when a method is unlinked.
    let (secret, _) = turn_totp_on(&mut ana).await;
    let mut waiting = fx.browser();
    let first = sign_in(&mut waiting, "ana@acme.test", PASSWORD).await;
    assert_eq!(first.location.as_deref(), Some("/totp"));
    let waiting_csrf = waiting.get("/totp").await.csrf();
    let github = method_id(&fx.db, login, "github").await;
    let removed = ana
        .submit(
            "/account",
            &format!("/account/methods/{github}/remove"),
            &[],
        )
        .await;
    assert_eq!(removed.status, StatusCode::SEE_OTHER, "{}", removed.body);
    assert_eq!(
        methods_of(&fx.db, login).await,
        [("password".to_owned(), "ana@acme.test".to_owned())]
    );
    assert_eq!(
        other.get("/account").await.location.as_deref(),
        Some("/signin")
    );
    let code = totp_code(&secret, now_unix());
    let late = waiting
        .post_raw("/totp", &[("code", &code), ("csrf", &waiting_csrf)])
        .await;
    assert_eq!(
        late.status,
        StatusCode::FORBIDDEN,
        "ended by the unlink: {}",
        late.body
    );
    assert_eq!(
        ana.get("/account").await.status,
        StatusCode::OK,
        "this session stays"
    );
    let password = method_id(&fx.db, login, "password").await;
    let last = ana
        .submit(
            "/account",
            &format!("/account/methods/{password}/remove"),
            &[],
        )
        .await;
    assert_eq!(last.status, StatusCode::CONFLICT, "{}", last.body);
    assert!(
        last.has("The last sign-in method cannot be removed"),
        "{}",
        last.body
    );
    assert_eq!(methods_of(&fx.db, login).await.len(), 1);
}

/// T-portal-auth-state (T12): a callback with a `state` from another session, and a
/// replayed `state`, are both refused, and no session is signed in by them.
#[tokio::test]
async fn t_portal_auth_state() {
    let fx = Fixture::start().await;
    let signed_in = "SELECT count(*) FROM sessions WHERE login_id IS NOT NULL";
    let mut victim = fx.browser();
    let mut attacker = fx.browser();
    let victims = victim.get("/oauth/google/start").await.location.unwrap();
    attacker.get("/oauth/google/start").await;
    // The attacker's own IdP answer, carried by another browser (login CSRF).
    let foreign = fx
        .net
        .authorize(&victims, serde_json::json!({"sub": "g-mallory"}));
    let crossed = attacker.get(&foreign).await;
    assert_eq!(crossed.status, StatusCode::BAD_REQUEST, "{}", crossed.body);
    assert_eq!(fx.db.count(signed_in).await, 0);
    assert_eq!(fx.db.count("SELECT count(*) FROM logins").await, 0);
    let mut no_cookie = fx.browser();
    assert_eq!(
        no_cookie.get(&foreign).await.location.as_deref(),
        Some("/signin")
    );
    assert_eq!(fx.db.count(signed_in).await, 0);

    let mut browser = fx.browser();
    let location = browser.get("/oauth/google/start").await.location.unwrap();
    let back = fx
        .net
        .authorize(&location, serde_json::json!({"sub": "g-1"}));
    assert_eq!(
        browser.get(&back).await.location.as_deref(),
        Some("/account")
    );
    assert_eq!(fx.db.count(signed_in).await, 1);
    let replayed = browser.get(&back).await;
    assert_eq!(
        replayed.status,
        StatusCode::BAD_REQUEST,
        "{}",
        replayed.body
    );
    assert_eq!(fx.db.count(signed_in).await, 1, "no second session");
    assert_eq!(fx.db.count("SELECT count(*) FROM logins").await, 1);

    // R6: with an IdP that does not enforce PKCE, the `state` check stands alone (GitHub
    // has no nonce), and a wrong `nonce` is refused on its own.
    fx.net.ignore_pkce.store(true, Ordering::SeqCst);
    let mut victim = fx.browser();
    let mut attacker = fx.browser();
    let victims = victim.get("/oauth/github/start").await.location.unwrap();
    attacker.get("/oauth/github/start").await;
    let foreign = fx.net.authorize(&victims, serde_json::json!({"id": 666}));
    let crossed = attacker.get(&foreign).await;
    assert_eq!(crossed.status, StatusCode::BAD_REQUEST, "{}", crossed.body);
    let mut wrong_nonce = fx.browser();
    let refused = oauth(
        &fx,
        &mut wrong_nonce,
        "/oauth/google/start",
        serde_json::json!({"sub": "g-9", "nonce": "not-yours"}),
    )
    .await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{}", refused.body);
    assert_eq!(fx.db.count(signed_in).await, 1, "neither signed in");
}

/// Connects `org`'s own OIDC sign-in: issuer, client and its sealed secret (what the
/// organisation page saves in slice 6), and the tenant a shared issuer must assert.
async fn connect_sso(fx: &Fixture, org: &str, issuer: &str, tenant: Option<&str>) -> i32 {
    let id: i32 = sqlx::query_scalar("SELECT id FROM orgs WHERE name = $1")
        .bind(org)
        .fetch_optional(&fx.db.owner)
        .await
        .unwrap()
        .unwrap_or(fx.db.org(org).await.id as i32);
    let client = org.to_lowercase();
    let sealed = accounts::SecretBox::new([7; 32]).seal(
        &accounts::sso_secret_aad(id),
        format!("{client}-secret").as_bytes(),
    );
    sqlx::query(
        "UPDATE orgs SET sso_issuer = $2, sso_client_id = $3, sso_client_secret_enc = $4,
             sso_allowed_tenant = $5 WHERE id = $1",
    )
    .bind(id)
    .bind(issuer)
    .bind(format!("{client}-client"))
    .bind(sealed)
    .bind(tenant)
    .execute(&fx.db.owner)
    .await
    .unwrap();
    id
}

async fn memberships_of(db: &Db, login: i32) -> Vec<(i32, String)> {
    sqlx::query_as("SELECT org_id, role FROM memberships WHERE login_id = $1 ORDER BY org_id")
        .bind(login)
        .fetch_all(&db.owner)
        .await
        .unwrap()
}

async fn login_of_subject(db: &Db, subject: &str, org: i32) -> Option<i32> {
    sqlx::query_scalar(
        "SELECT login_id FROM sign_in_methods WHERE kind = 'oidc' AND subject = $1 AND org_id = $2",
    )
    .bind(subject)
    .bind(org)
    .fetch_optional(&db.owner)
    .await
    .unwrap()
}

/// T-portal-sso-join (C5, C21): a first SSO sign-in creates a login that is a member of
/// that organisation, and its session is confined to it (T2).
#[tokio::test]
async fn t_portal_sso_join() {
    let fx = Fixture::start().await;
    let acme = connect_sso(&fx, "Acme", "https://idp.acme.test", None).await;
    let mut browser = fx.browser();
    let start = format!("/sso/{acme}/start");
    let back = oauth(
        &fx,
        &mut browser,
        &start,
        serde_json::json!({"sub": "acme-7", "email": "seven@acme.test"}),
    )
    .await;
    assert_eq!(back.location.as_deref(), Some("/account"), "{}", back.body);
    let login = login_of_subject(&fx.db, "acme-7", acme)
        .await
        .expect("a new login");
    assert_eq!(
        memberships_of(&fx.db, login).await,
        [(acme, "member".to_owned())]
    );
    let scope: Option<i32> =
        sqlx::query_scalar("SELECT scope_org_id FROM sessions WHERE login_id = $1")
            .bind(login)
            .fetch_one(&fx.db.owner)
            .await
            .unwrap();
    assert_eq!(scope, Some(acme));
    // The second sign-in finds the same login.
    sign_out(&mut browser).await;
    oauth(
        &fx,
        &mut browser,
        &start,
        serde_json::json!({"sub": "acme-7"}),
    )
    .await;
    assert_eq!(fx.db.count("SELECT count(*) FROM logins").await, 1);
    assert_eq!(fx.db.count("SELECT count(*) FROM memberships").await, 1);

    // R4: a session opened through an organisation's SSO cannot change the login.
    let csrf = browser.get("/account").await.csrf();
    let method = sqlx::query_scalar::<_, i32>("SELECT id FROM sign_in_methods WHERE login_id = $1")
        .bind(login)
        .fetch_one(&fx.db.owner)
        .await
        .unwrap()
        .to_string();
    let before = state(&fx.db).await;
    for path in [
        "/account/link/google".to_owned(),
        format!("/account/methods/{method}/remove"),
        "/account/delete".to_owned(),
        "/account/personal".to_owned(),
        "/account/totp/setup".to_owned(),
    ] {
        let page = browser
            .post_raw(&path, &[("csrf", &csrf), ("confirm", "delete")])
            .await;
        assert_eq!(page.status, StatusCode::FORBIDDEN, "{path}: {}", page.body);
    }
    assert_eq!(state(&fx.db).await, before, "nothing written");
}

/// T-portal-org-signin-link (C37): `/o/acme` and typing "acme" in the organisation field
/// on /signin both redirect to Acme's SSO; `/o/unknown` and an unknown typed name render
/// the same page as /signin.
#[tokio::test]
async fn t_portal_org_signin_link() {
    let fx = Fixture::start().await;
    let acme = connect_sso(&fx, "Acme", "https://idp.acme.test", None).await;
    fx.db.org("Globex").await;
    let mut browser = fx.browser();
    let signin = browser.get("/signin").await;
    let to_sso = Some(format!("/sso/{acme}/start"));
    assert_eq!(browser.get("/o/acme").await.location, to_sso);
    assert_eq!(browser.get("/o?name=acme").await.location, to_sso);
    assert_eq!(browser.get("/o?name=%20ACME%20").await.location, to_sso);
    for path in ["/o/unknown", "/o?name=unknown", "/o/globex", "/o?name="] {
        let page = browser.get(path).await;
        assert_eq!(page.status, signin.status, "{path}");
        assert_eq!(page.body, signin.body, "{path}: the /signin page");
    }
    let sso = browser.get(&format!("/sso/{acme}/start")).await;
    assert!(
        sso.location
            .unwrap()
            .starts_with("https://idp.acme.test/authorize?")
    );
}

/// T-oidc-issuer-scoped (T2): org B's IdP asserting the same `sub` as a login of org A's
/// IdP signs in a different login, never A's; a token from Acme's shared-issuer SSO client
/// with the right `iss` and `aud` but another `hd` creates no login and no membership; a
/// token whose `iss` or `aud` differs never yields a session.
#[tokio::test]
async fn t_oidc_issuer_scoped() {
    let fx = Fixture::start().await;
    let acme = connect_sso(&fx, "Acme", "https://idp.acme.test", None).await;
    let globex = connect_sso(&fx, "Globex", "https://idp.globex.test", None).await;
    let same = serde_json::json!({"sub": "shared-sub"});
    let mut a = fx.browser();
    oauth(&fx, &mut a, &format!("/sso/{acme}/start"), same.clone()).await;
    let mut b = fx.browser();
    oauth(&fx, &mut b, &format!("/sso/{globex}/start"), same).await;
    let in_acme = login_of_subject(&fx.db, "shared-sub", acme).await.unwrap();
    let in_globex = login_of_subject(&fx.db, "shared-sub", globex)
        .await
        .unwrap();
    assert_ne!(in_acme, in_globex, "a different login");
    assert_eq!(
        memberships_of(&fx.db, in_acme).await,
        [(acme, "member".to_owned())]
    );
    assert_eq!(
        memberships_of(&fx.db, in_globex).await,
        [(globex, "member".to_owned())]
    );

    let logins = "SELECT count(*) FROM logins";
    let before = fx.db.count(logins).await;
    let members = fx.db.count("SELECT count(*) FROM memberships").await;
    for claims in [
        serde_json::json!({"sub": "x-1", "iss": "https://idp.globex.test"}),
        serde_json::json!({"sub": "x-2", "aud": "globex-client"}),
    ] {
        let mut c = fx.browser();
        let refused = oauth(&fx, &mut c, &format!("/sso/{acme}/start"), claims.clone()).await;
        assert_eq!(
            refused.status,
            StatusCode::BAD_REQUEST,
            "{claims}: {}",
            refused.body
        );
        assert_eq!(
            session_row(&fx.db, &c).await.and_then(|(login, _)| login),
            None
        );
    }
    // A shared issuer: only the organisation's own Google Workspace domain.
    let northwind = connect_sso(
        &fx,
        "Northwind",
        "https://accounts.google.com",
        Some("northwind.test"),
    )
    .await;
    let mut d = fx.browser();
    let other = serde_json::json!({"sub": "g-77", "hd": "elsewhere.test"});
    let refused = oauth(&fx, &mut d, &format!("/sso/{northwind}/start"), other).await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{}", refused.body);
    assert_eq!(fx.db.count(logins).await, before, "no login");
    assert_eq!(
        fx.db.count("SELECT count(*) FROM memberships").await,
        members,
        "no membership"
    );
    let own = serde_json::json!({"sub": "g-78", "hd": "northwind.test"});
    let accepted = oauth(&fx, &mut d, &format!("/sso/{northwind}/start"), own).await;
    assert_eq!(
        accepted.location.as_deref(),
        Some("/account"),
        "{}",
        accepted.body
    );

    // R6: Microsoft's common endpoint: a token signs in under its own tenant's issuer,
    // and one whose `iss` names another tenant than its `tid` is refused.
    let mut m = fx.browser();
    let ok = oauth(
        &fx,
        &mut m,
        "/oauth/microsoft/start",
        serde_json::json!({"sub": "s", "tid": "t1", "oid": "o1"}),
    )
    .await;
    assert_eq!(ok.location.as_deref(), Some("/account"), "{}", ok.body);
    let subject: String =
        sqlx::query_scalar("SELECT subject FROM sign_in_methods WHERE kind = 'microsoft'")
            .fetch_one(&fx.db.owner)
            .await
            .unwrap();
    assert_eq!(subject, "t1/o1");
    let mut n = fx.browser();
    let other_tenant = serde_json::json!({
        "sub": "s", "tid": "t1", "oid": "o2",
        "iss": "https://login.microsoftonline.com/t2/v2.0",
    });
    let refused = oauth(&fx, &mut n, "/oauth/microsoft/start", other_tenant).await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{}", refused.body);
    assert_eq!(
        fx.db
            .count("SELECT count(*) FROM sign_in_methods WHERE kind = 'microsoft'")
            .await,
        1
    );
}

/// A loopback listener that counts the connections it accepts.
async fn counting_listener() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = accepted.clone();
    tokio::spawn(async move {
        while let Ok((_stream, _)) = listener.accept().await {
            count.fetch_add(1, Ordering::SeqCst);
        }
    });
    (addr, accepted)
}

/// A loopback HTTP server whose every answer redirects to `to`.
async fn redirector(to: String) -> SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut buffer = [0u8; 4096];
            let _ = stream.read(&mut buffer).await;
            let answer = format!(
                "HTTP/1.1 302 Found\r\nLocation: {to}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            let _ = stream.write_all(answer.as_bytes()).await;
        }
    });
    addr
}

/// T-portal-auth-ssrf (T11): organisation issuers `https://127.0.0.1/`, `https://10.0.0.1/`
/// and `http://idp.example/`, and a discovery answer that redirects, are each refused
/// before connecting; no request reaches a local listener.
#[tokio::test]
async fn t_portal_auth_ssrf() {
    let db = Db::fresh().await;
    let (local, accepted) = counting_listener().await;
    let guarded: Arc<dyn Outbound> = Arc::new(accounts::GuardedClient::new());
    let addr = serve(&db, Arc::new(FakeMail::default()), guarded.clone()).await;
    let fx = Fixture {
        db,
        addr,
        mail: Arc::new(FakeMail::default()),
        net: Arc::new(FakeNet::default()),
    };
    let issuers = [
        format!("https://127.0.0.1:{}/", local.port()),
        format!("https://localhost:{}/", local.port()),
        "https://10.0.0.1/".to_owned(),
        "https://[::ffff:10.0.0.1]/".to_owned(),
        "http://idp.example/".to_owned(),
    ];
    for (n, issuer) in issuers.iter().enumerate() {
        let org = connect_sso(&fx, &format!("Org{n}"), issuer, None).await;
        let started = std::time::Instant::now();
        let page = fx.browser().get(&format!("/sso/{org}/start")).await;
        assert_eq!(
            page.status,
            StatusCode::BAD_GATEWAY,
            "{issuer}: {}",
            page.body
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "{issuer}: refused before connecting"
        );
    }
    // The guard itself refuses a redirect, even between addresses it would allow.
    let followed = redirector(format!("http://{local}/.well-known/openid-configuration")).await;
    let loopback = accounts::GuardedClient::allowing_loopback_for_tests();
    let url = url::Url::parse(&format!(
        "http://{followed}/.well-known/openid-configuration"
    ))
    .unwrap();
    let answer = loopback.get(&url, None).await;
    assert!(
        matches!(answer, Err(OutboundError::Status(302))),
        "{answer:?}"
    );
    let direct = url::Url::parse(&format!("https://127.0.0.1:{}/", local.port())).unwrap();
    assert!(matches!(
        guarded.get(&direct, None).await,
        Err(OutboundError::Refused(_))
    ));
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        0,
        "no request reached the local listener"
    );
}

/// T-portal-auth-pwned (T29): the leaked-password service receives only the first 5 hex
/// characters of the SHA-1; when it times out, sign-up shows "try again" and creates no
/// method (fail closed, 2 s).
#[tokio::test]
async fn t_portal_auth_pwned() {
    use sha1::Digest;
    let fx = Fixture::start().await;
    let digest = hex::encode_upper(sha1::Sha1::digest(PASSWORD.as_bytes()));
    let mut browser = fx.browser();
    let fields = [
        ("email", "kay@home.test"),
        ("password", PASSWORD),
        ("kind", "personal"),
    ];
    assert!(
        browser
            .submit("/signup", "/signup", &fields)
            .await
            .has("We sent a link to")
    );
    let asked: Vec<String> = fx.net.requests.lock().unwrap().clone();
    assert_eq!(
        asked,
        [format!(
            "https://api.pwnedpasswords.com/range/{}",
            &digest[..5]
        )]
    );
    for request in &asked {
        assert!(!request.contains(&digest[5..]) && !request.contains(PASSWORD));
    }

    fx.net.leak_check_hangs.store(true, Ordering::SeqCst);
    let started = std::time::Instant::now();
    let other = [
        ("email", "lee@home.test"),
        ("password", PASSWORD),
        ("kind", "personal"),
    ];
    let page = browser.submit("/signup", "/signup", &other).await;
    let waited = started.elapsed();
    assert!(
        page.has("We could not check this password just now. Please try again."),
        "{}",
        page.body
    );
    assert!(
        waited >= Duration::from_secs(2) && waited < Duration::from_secs(4),
        "{waited:?}"
    );
    assert_eq!(
        fx.db.count("SELECT count(*) FROM sign_in_methods").await,
        1,
        "no method for lee"
    );
}

const DELETE: [(&str, &str); 1] = [("confirm", "delete")];

async fn google_login(fx: &Fixture, browser: &mut Browser, sub: &str) -> Page {
    oauth(
        fx,
        browser,
        "/oauth/google/start",
        serde_json::json!({"sub": sub, "email": format!("{sub}@gmail.test")}),
    )
    .await
}

async fn login_of_google(db: &Db, sub: &str) -> Option<i32> {
    sqlx::query_scalar(
        "SELECT login_id FROM sign_in_methods WHERE kind = 'google' AND subject = $1",
    )
    .bind(sub)
    .fetch_optional(&db.owner)
    .await
    .unwrap()
}

async fn deleted(db: &Db, login: i32) -> Option<bool> {
    sqlx::query_scalar("SELECT deleted_at IS NOT NULL FROM logins WHERE id = $1")
        .bind(login)
        .fetch_optional(&db.owner)
        .await
        .unwrap()
}

/// Moves a deleted login `days` into its 30 days (the fake clock).
async fn age_deletion(db: &Db, login: i32, days: i32) {
    sqlx::query(
        "UPDATE logins SET deleted_at = now() - make_interval(days => $2),
             restore_until = now() - make_interval(days => $2) + interval '30 days' WHERE id = $1",
    )
    .bind(login)
    .bind(days)
    .execute(&db.owner)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE personal_accounts SET deleted_at = now() - make_interval(days => $2),
             restore_until = now() - make_interval(days => $2) + interval '30 days'
         WHERE login_id = $1 AND deleted_at IS NOT NULL",
    )
    .bind(login)
    .bind(days)
    .execute(&db.owner)
    .await
    .unwrap();
}

async fn signup_page(fx: &Fixture, email: &str) -> Page {
    let fields = [
        ("email", email),
        ("password", PASSWORD),
        ("kind", "personal"),
    ];
    fx.browser().submit("/signup", "/signup", &fields).await
}

/// T-portal-delete-restore (C33, C85, C90, C93, C94): restore at day 29 works; "Start a
/// new login" erases at once; the only global admin deleting their own login is refused;
/// during the 30 days a sign-up with the deleted login's address shows the "check your
/// email" page and creates no method; after "Start a new login" or the purge the address
/// is free; a member of an organisation is not offered "Delete your login", and a forged
/// delete POST from it answers 403 with its memberships, login and keys unchanged.
#[tokio::test]
async fn t_portal_delete_restore() {
    let fx = Fixture::start().await;
    // A login with no personal account and no organisation (C93).
    let mut gil = fx.browser();
    google_login(&fx, &mut gil, "gil").await;
    let gil_login = login_of_google(&fx.db, "gil").await.unwrap();
    assert!(gil.get("/account").await.has("Delete your login"));
    let gone = gil.submit("/account", "/account/delete", &DELETE).await;
    assert_eq!(gone.location.as_deref(), Some("/signin"), "{}", gone.body);
    assert!(gil.session().is_none(), "signed out");
    assert_eq!(deleted(&fx.db, gil_login).await, Some(true));
    // Day 29: signing in offers the choice (C94), and "Restore login" brings it back.
    age_deletion(&fx.db, gil_login, 29).await;
    let choice = google_login(&fx, &mut gil, "gil").await;
    assert_eq!(
        choice.location.as_deref(),
        Some("/deleted"),
        "{}",
        choice.body
    );
    let page = gil.get("/deleted").await;
    assert!(page.has("This login was deleted on"), "{}", page.body);
    let restored = gil.submit("/deleted", "/deleted/restore", &[]).await;
    assert_eq!(
        restored.location.as_deref(),
        Some("/account"),
        "{}",
        restored.body
    );
    assert_eq!(deleted(&fx.db, gil_login).await, Some(false));
    assert_eq!(gil.get("/account").await.status, StatusCode::OK);
    // "Start a new login" erases the old one at once.
    gil.submit("/account", "/account/delete", &DELETE).await;
    google_login(&fx, &mut gil, "gil").await;
    let fresh = gil.submit("/deleted", "/deleted/new", &[]).await;
    assert_eq!(
        fresh.location.as_deref(),
        Some("/account"),
        "{}",
        fresh.body
    );
    assert_eq!(deleted(&fx.db, gil_login).await, None, "erased");
    let new_login = login_of_google(&fx.db, "gil").await.unwrap();
    assert_ne!(new_login, gil_login);
    assert_eq!(gil.get("/account").await.status, StatusCode::OK);

    // The address of a deleted login stays reserved for 30 days, then is free.
    let mut pia = member(&fx, "pia@home.test", &[("kind", "personal")]).await;
    oauth(
        &fx,
        &mut pia,
        "/account/link/google",
        serde_json::json!({"sub": "pia-g"}),
    )
    .await;
    pia.submit("/account", "/account/personal/delete", &DELETE)
        .await;
    let pia_login = login_of(&fx.db, "pia@home.test").await;
    assert_eq!(deleted(&fx.db, pia_login).await, Some(true));
    let methods = "SELECT count(*) FROM sign_in_methods";
    let before = fx.db.count(methods).await;
    let reserved = signup_page(&fx, "pia@home.test").await;
    assert_eq!(
        without_csrf(&reserved.body),
        without_csrf(&signup_page(&fx, "x@new.test").await.body)
            .replace("x@new.test", "pia@home.test")
    );
    assert_eq!(
        fx.db.count(methods).await,
        before + 1,
        "only x@new.test got a method"
    );
    let mut other_way = fx.browser();
    google_login(&fx, &mut other_way, "pia-g").await;
    other_way.submit("/deleted", "/deleted/new", &[]).await;
    assert!(
        signup_page(&fx, "pia@home.test")
            .await
            .has("We sent a link to")
    );
    assert_eq!(
        fx.db
            .count("SELECT count(*) FROM sign_in_methods WHERE email = 'pia@home.test'")
            .await,
        1
    );
    let pia_methods = "SELECT count(*) FROM sign_in_methods WHERE email = 'pia@home.test' AND verified_at IS NULL";
    assert_eq!(
        fx.db.count(pia_methods).await,
        1,
        "the address is free after Start a new login"
    );

    let mut quin = member(&fx, "quin@home.test", &[("kind", "personal")]).await;
    quin.submit("/account", "/account/personal/delete", &DELETE)
        .await;
    let quin_login = login_of(&fx.db, "quin@home.test").await;
    let count_quin = "SELECT count(*) FROM sign_in_methods WHERE email = 'quin@home.test'";
    signup_page(&fx, "quin@home.test").await;
    assert_eq!(fx.db.count(count_quin).await, 1);
    age_deletion(&fx.db, quin_login, 31).await;
    accounts::purge(&fx.db.app).await.expect("the purge runs");
    assert_eq!(deleted(&fx.db, quin_login).await, None, "purged on day 31");
    signup_page(&fx, "quin@home.test").await;
    assert_eq!(
        fx.db.count(count_quin).await,
        1,
        "the address is free after the purge"
    );
    assert_ne!(login_of(&fx.db, "quin@home.test").await, quin_login);

    // The only global admin cannot delete their own login (C90).
    let mut root = fx.browser();
    google_login(&fx, &mut root, "root").await;
    let root_login = login_of_google(&fx.db, "root").await.unwrap();
    sqlx::query("INSERT INTO memberships (login_id, role) VALUES ($1, 'global_admin')")
        .bind(root_login)
        .execute(&fx.db.owner)
        .await
        .unwrap();
    let refused = root.submit("/account", "/account/delete", &DELETE).await;
    assert_eq!(refused.status, StatusCode::CONFLICT, "{}", refused.body);
    assert!(refused.has("last global admin"), "{}", refused.body);
    assert_eq!(deleted(&fx.db, root_login).await, Some(false));

    // A member of an organisation is not offered it, and a forged POST changes nothing.
    let mut ana = member(
        &fx,
        "ana@acme.test",
        &[("kind", "org"), ("org_name", "Acme")],
    )
    .await;
    let ana_login = login_of(&fx.db, "ana@acme.test").await;
    let user_place: i32 = sqlx::query_scalar("SELECT id FROM memberships WHERE login_id = $1")
        .bind(ana_login)
        .fetch_one(&fx.db.owner)
        .await
        .unwrap();
    let session = probation_server::tenancy::Session::new(ana_login, None);
    let place = fx
        .db
        .tenancy()
        .authorized_place(
            &session,
            common::place(probation_policy::LayerKind::User, user_place),
        )
        .await
        .unwrap();
    let actor = fx.db.tenancy().actor(&session, &place).await.unwrap();
    probation_server::keys::create(&fx.db.app, &actor, &place, "laptop")
        .await
        .unwrap();
    assert!(!ana.get("/account").await.has("Delete your login"));
    let state = "SELECT (SELECT count(*) FROM memberships) * 1000 + (SELECT count(*) FROM keys WHERE revoked_at IS NULL)";
    let before = fx.db.count(state).await;
    let forged = ana.submit("/account", "/account/delete", &DELETE).await;
    assert_eq!(forged.status, StatusCode::FORBIDDEN, "{}", forged.body);
    assert_eq!(fx.db.count(state).await, before);
    assert_eq!(deleted(&fx.db, ana_login).await, Some(false));

    // R1: a deleted login with an authenticator offers the C94 choice only after its
    // code; its password alone can neither erase nor restore it.
    let mut tess = member(&fx, "tess@home.test", &[("kind", "personal")]).await;
    let (secret, _) = turn_totp_on(&mut tess).await;
    tess.submit("/account", "/account/personal/delete", &DELETE)
        .await;
    let tess_login = login_of(&fx.db, "tess@home.test").await;
    assert_eq!(deleted(&fx.db, tess_login).await, Some(true));
    let mut thief = fx.browser();
    let first = sign_in(&mut thief, "tess@home.test", PASSWORD).await;
    assert_eq!(
        first.location.as_deref(),
        Some("/totp"),
        "the code comes first: {}",
        first.body
    );
    for path in ["/deleted/new", "/deleted/restore"] {
        let csrf = thief.get("/totp").await.csrf();
        let refused = thief.post_raw(path, &[("csrf", &csrf)]).await;
        assert_ne!(
            refused.location.as_deref(),
            Some("/account"),
            "{path}: {}",
            refused.body
        );
        assert_eq!(
            deleted(&fx.db, tess_login).await,
            Some(true),
            "{path}: still deleted"
        );
        assert_eq!(
            personal_deleted(&fx.db, tess_login).await,
            Some(true),
            "{path}: intact"
        );
    }
    assert_eq!(
        thief.get("/deleted").await.location.as_deref(),
        Some("/signin")
    );
    // Even a session put at the choice without the code is refused there.
    let tess_method = method_id(&fx.db, tess_login, "password").await;
    let forged =
        serde_json::json!({"deleted": tess_login, "method": tess_method, "by_password": true});
    sqlx::query("UPDATE sessions SET pending = $1 WHERE pending->>'totp' = $2::text")
        .bind(&forged)
        .bind(tess_login.to_string())
        .execute(&fx.db.owner)
        .await
        .unwrap();
    for path in ["/deleted/new", "/deleted/restore"] {
        let csrf = thief.get("/deleted").await.csrf();
        let refused = thief.post_raw(path, &[("csrf", &csrf)]).await;
        assert_eq!(
            refused.status,
            StatusCode::FORBIDDEN,
            "{path}: {}",
            refused.body
        );
        assert_eq!(
            deleted(&fx.db, tess_login).await,
            Some(true),
            "{path}: still deleted"
        );
        assert_eq!(
            personal_deleted(&fx.db, tess_login).await,
            Some(true),
            "{path}: intact"
        );
    }
    let mut owner = fx.browser();
    sign_in(&mut owner, "tess@home.test", PASSWORD).await;
    let coded = owner
        .submit(
            "/totp",
            "/totp",
            &[("code", &totp_code(&secret, now_unix()))],
        )
        .await;
    assert_eq!(
        coded.location.as_deref(),
        Some("/deleted"),
        "{}",
        coded.body
    );
    let back = owner.submit("/deleted", "/deleted/restore", &[]).await;
    assert_eq!(
        back.location.as_deref(),
        Some("/account"),
        "no second code: {}",
        back.body
    );
    assert_eq!(deleted(&fx.db, tess_login).await, Some(false));

    // N4: a session waiting at the deleted-login choice ends when the login is deleted
    // again, and when its password changes.
    let mut val = member(&fx, "val@home.test", &[("kind", "personal")]).await;
    let val_login = login_of(&fx.db, "val@home.test").await;
    val.submit("/account", "/account/personal/delete", &DELETE)
        .await;
    let mut waiting = fx.browser();
    let first = sign_in(&mut waiting, "val@home.test", PASSWORD).await;
    assert_eq!(first.location.as_deref(), Some("/deleted"));
    let waiting_csrf = waiting.get("/deleted").await.csrf();
    sign_in(&mut val, "val@home.test", PASSWORD).await;
    val.submit("/deleted", "/deleted/restore", &[]).await;
    val.submit("/account", "/account/personal/delete", &DELETE)
        .await;
    assert_eq!(deleted(&fx.db, val_login).await, Some(true));
    let late = waiting
        .post_raw("/deleted/restore", &[("csrf", &waiting_csrf)])
        .await;
    assert_eq!(
        late.status,
        StatusCode::FORBIDDEN,
        "ended by the re-delete: {}",
        late.body
    );
    assert_eq!(deleted(&fx.db, val_login).await, Some(true));

    let mut waiting = fx.browser();
    sign_in(&mut waiting, "val@home.test", PASSWORD).await;
    let waiting_csrf = waiting.get("/deleted").await.csrf();
    let mut owner = fx.browser();
    sign_in(&mut owner, "val@home.test", PASSWORD).await;
    owner.submit("/deleted", "/deleted/restore", &[]).await;
    let change = [
        ("current", PASSWORD),
        ("new", NEW_PASSWORD),
        ("again", NEW_PASSWORD),
    ];
    let changed = owner.submit("/account", "/account/password", &change).await;
    assert_eq!(
        changed.location.as_deref(),
        Some("/account"),
        "{}",
        changed.body
    );
    let late = waiting
        .post_raw("/deleted/new", &[("csrf", &waiting_csrf)])
        .await;
    assert_eq!(
        late.status,
        StatusCode::FORBIDDEN,
        "ended by the password change: {}",
        late.body
    );
    assert_eq!(deleted(&fx.db, val_login).await, Some(false), "not erased");
}

async fn personal_deleted(db: &Db, login: i32) -> Option<bool> {
    sqlx::query_scalar("SELECT deleted_at IS NOT NULL FROM personal_accounts WHERE login_id = $1")
        .bind(login)
        .fetch_optional(&db.owner)
        .await
        .unwrap()
}

/// T-portal-personal-delete-restore (C33, C40, C73): a login that is also in an
/// organisation deletes its personal account: the login and membership remain, and the
/// owner restores it on /account within 30 days; a login with only a personal account
/// deletes it: the login is deleted too, signing in shows the C94 choice, and restoring
/// within 30 days brings back both.
#[tokio::test]
async fn t_portal_personal_delete_restore() {
    let fx = Fixture::start().await;
    let mut ana = member(
        &fx,
        "ana@acme.test",
        &[("kind", "org"), ("org_name", "Acme")],
    )
    .await;
    ana.submit("/account", "/account/personal", &[]).await;
    let ana_login = login_of(&fx.db, "ana@acme.test").await;
    let deleted_page = ana
        .submit("/account", "/account/personal/delete", &DELETE)
        .await;
    assert_eq!(
        deleted_page.location.as_deref(),
        Some("/account"),
        "{}",
        deleted_page.body
    );
    assert_eq!(personal_deleted(&fx.db, ana_login).await, Some(true));
    assert_eq!(
        deleted(&fx.db, ana_login).await,
        Some(false),
        "the login stays"
    );
    assert_eq!(
        memberships_of(&fx.db, ana_login).await.len(),
        1,
        "the membership stays"
    );
    let account = ana.get("/account").await;
    assert!(
        account.has("Your personal account was deleted on"),
        "{}",
        account.body
    );
    assert_eq!(switcher(&account), ["Acme (organisation)"]);
    age_deletion(&fx.db, ana_login, 29).await;
    sqlx::query(
        "UPDATE personal_accounts SET deleted_at = now() - interval '29 days',
             restore_until = now() + interval '1 day' WHERE login_id = $1",
    )
    .bind(ana_login)
    .execute(&fx.db.owner)
    .await
    .unwrap();
    let restored = ana
        .submit("/account", "/account/personal/restore", &[])
        .await;
    assert_eq!(
        restored.location.as_deref(),
        Some("/account"),
        "{}",
        restored.body
    );
    assert_eq!(personal_deleted(&fx.db, ana_login).await, Some(false));
    assert_eq!(
        switcher(&ana.get("/account").await),
        ["Personal account", "Acme (organisation)"]
    );

    let mut pat = member(&fx, "pat@home.test", &[("kind", "personal")]).await;
    let pat_login = login_of(&fx.db, "pat@home.test").await;
    let gone = pat
        .submit("/account", "/account/personal/delete", &DELETE)
        .await;
    assert_eq!(
        gone.location.as_deref(),
        Some("/signin"),
        "signed out: {}",
        gone.body
    );
    assert_eq!(
        deleted(&fx.db, pat_login).await,
        Some(true),
        "the login went too"
    );
    let choice = sign_in(&mut pat, "pat@home.test", PASSWORD).await;
    assert_eq!(choice.location.as_deref(), Some("/deleted"));
    assert!(pat.get("/deleted").await.has("This login was deleted on"));
    let back = pat.submit("/deleted", "/deleted/restore", &[]).await;
    assert_eq!(back.location.as_deref(), Some("/account"), "{}", back.body);
    assert_eq!(deleted(&fx.db, pat_login).await, Some(false));
    assert_eq!(
        personal_deleted(&fx.db, pat_login).await,
        Some(false),
        "both come back"
    );
    assert_eq!(switcher(&pat.get("/account").await), ["Personal account"]);
}

/// A user key on the personal account of `email`'s login.
async fn personal_key(db: &Db, email: &str) -> String {
    let login = login_of(db, email).await;
    let personal: i32 = sqlx::query_scalar("SELECT id FROM personal_accounts WHERE login_id = $1")
        .bind(login)
        .fetch_one(&db.owner)
        .await
        .unwrap();
    let session = probation_server::tenancy::Session::new(login, None);
    let place = db
        .tenancy()
        .authorized_place(
            &session,
            common::place(probation_policy::LayerKind::Personal, personal),
        )
        .await
        .unwrap();
    let actor = db.tenancy().actor(&session, &place).await.unwrap();
    probation_server::keys::create(&db.app, &actor, &place, "laptop")
        .await
        .unwrap()
        .secret
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

/// T-sync-login-deleted-restored (C33, C73, C93, C94): the keys of a deleted login answer
/// 401 within one interval and, after a request made during the deletion, 200 within one
/// interval after restore; the same for a personal account its owner deletes while the
/// login stays in an organisation.
#[tokio::test]
async fn t_sync_login_deleted_restored() {
    let fx = Fixture::start().await;
    let registered = probation_server::fleet::register(
        &fx.db.app,
        &probation_server::tenancy::Actor::Operator,
        "fw",
        &["127.0.0.0/8".parse().unwrap()],
    )
    .await
    .unwrap();
    let server = common::serve(fx.db.app.clone(), Vec::new()).await;
    let firewall = common::Firewall::start(server, &registered.token, 2, 1).await;
    firewall.ready(Duration::from_secs(10)).await;
    let http = common::client();

    // A login with only a personal account: deleting it deletes the login (C85).
    let mut pat = member(&fx, "pat@home.test", &[("kind", "personal")]).await;
    let key = personal_key(&fx.db, "pat@home.test").await;
    assert_eq!(
        firewall.get(&http, "/npm/left-pad", &key).await.status(),
        StatusCode::OK
    );
    let gone = pat
        .submit("/account", "/account/personal/delete", &DELETE)
        .await;
    assert_eq!(gone.location.as_deref(), Some("/signin"));
    answers_within_interval(&firewall, &key, StatusCode::UNAUTHORIZED, "login deleted").await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(
        firewall.get(&http, "/npm/left-pad", &key).await.status(),
        StatusCode::UNAUTHORIZED
    );
    sign_in(&mut pat, "pat@home.test", PASSWORD).await;
    let restored = pat.submit("/deleted", "/deleted/restore", &[]).await;
    assert_eq!(restored.location.as_deref(), Some("/account"));
    answers_within_interval(&firewall, &key, StatusCode::OK, "login restored").await;

    // A personal account deleted by its owner while the login stays in an organisation.
    let mut ana = member(
        &fx,
        "ana@acme.test",
        &[("kind", "org"), ("org_name", "Acme")],
    )
    .await;
    ana.submit("/account", "/account/personal", &[]).await;
    let key = personal_key(&fx.db, "ana@acme.test").await;
    assert_eq!(
        firewall.get(&http, "/npm/left-pad", &key).await.status(),
        StatusCode::OK
    );
    ana.submit("/account", "/account/personal/delete", &DELETE)
        .await;
    answers_within_interval(
        &firewall,
        &key,
        StatusCode::UNAUTHORIZED,
        "personal deleted",
    )
    .await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(
        firewall.get(&http, "/npm/left-pad", &key).await.status(),
        StatusCode::UNAUTHORIZED
    );
    ana.submit("/account", "/account/personal/restore", &[])
        .await;
    answers_within_interval(&firewall, &key, StatusCode::OK, "personal restored").await;
}

/// Every row the slice's routes can write, as one digest.
async fn state(db: &Db) -> String {
    let tables = [
        "logins",
        "sign_in_methods",
        "sessions",
        "personal_accounts",
        "orgs",
        "memberships",
        "totp",
        "backup_codes",
        "email_tokens",
        "email_outbox",
        "audit_log",
        "change_log",
        "sign_in_failures",
        "keys",
        "policy_layers",
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

/// T-portal-csrf (C101): every POST route in the router table answers 403 and writes no
/// row, both with no CSRF token and with another session's token.
#[tokio::test]
async fn t_portal_csrf() {
    let fx = Fixture::start().await;
    let mut ana = member(&fx, "ana@acme.test", &[("kind", "personal")]).await;
    let ana_login = login_of(&fx.db, "ana@acme.test").await;
    let method = method_id(&fx.db, ana_login, "password").await;
    let mut other = fx.browser();
    let foreign = other.get("/signin").await.csrf();
    let fields = [
        ("email", "ana@acme.test"),
        ("password", PASSWORD),
        ("kind", "org"),
        ("org_name", "Forged"),
        ("name", "Forged"),
        ("confirm", "delete"),
        ("current", PASSWORD),
        ("new", NEW_PASSWORD),
        ("again", NEW_PASSWORD),
        ("code", "123456"),
        ("token", "forged"),
    ];
    let posts: Vec<_> = portal::route_table()
        .into_iter()
        .filter(|(method, _)| *method == "POST")
        .collect();
    assert!(posts.len() >= 15, "{posts:?}");
    let before = state(&fx.db).await;
    for (_, path) in posts {
        let path = path
            .replace("{provider}", "google")
            .replace("{id}", &method.to_string());
        for token in [None, Some(foreign.as_str())] {
            let mut sent = fields.to_vec();
            if let Some(token) = token {
                sent.push(("csrf", token));
            }
            let page = ana.post_raw(&path, &sent).await;
            assert_eq!(
                page.status,
                StatusCode::FORBIDDEN,
                "{path} with {token:?}: {}",
                page.body
            );
            assert_eq!(
                state(&fx.db).await,
                before,
                "{path} with {token:?} wrote a row"
            );
        }
    }
    assert_eq!(
        ana.get("/account").await.status,
        StatusCode::OK,
        "still signed in"
    );
}

/// T-cross-tenant-routes-accounts (C1): for every route the slice adds that takes an id
/// (read from the router's table), an Acme session sending a Globex id gets 404 with the
/// same body as for an unknown id. (`{provider}` names a provider, not a tenant's row;
/// `/o/{org}` takes a name and is covered by T-portal-org-signin-link; an organisation's
/// SSO entry is public by design, C37 and A3, so Globex has none here.)
#[tokio::test]
async fn t_cross_tenant_routes_accounts() {
    let fx = Fixture::start().await;
    let mut ana = member(
        &fx,
        "ana@acme.test",
        &[("kind", "org"), ("org_name", "Acme")],
    )
    .await;
    member(
        &fx,
        "gus@globex.test",
        &[("kind", "org"), ("org_name", "Globex")],
    )
    .await;
    let gus = login_of(&fx.db, "gus@globex.test").await;
    let globex: i32 = sqlx::query_scalar("SELECT id FROM orgs WHERE name = 'Globex'")
        .fetch_one(&fx.db.owner)
        .await
        .unwrap();
    let ids = HashMap::from([
        ("{id}", method_id(&fx.db, gus, "password").await),
        ("{org}", globex),
    ]);
    let routes: Vec<_> = portal::route_table()
        .into_iter()
        .filter(|(_, path)| {
            ids.keys().any(|param| path.contains(param)) && !path.starts_with("/o/")
        })
        .collect();
    assert!(routes.len() >= 3, "{routes:?}");
    let before = state(&fx.db).await;
    for (method, path) in routes {
        let (param, globex_id) = ids.iter().find(|(param, _)| path.contains(*param)).unwrap();
        let with_id = |id: i32| path.replace(param, &id.to_string());
        let csrf = ana.get("/account").await.csrf();
        let mut answers = Vec::new();
        for id in [*globex_id, 999_999] {
            let page = match method {
                "GET" => ana.get(&with_id(id)).await,
                _ => ana.post_raw(&with_id(id), &[("csrf", &csrf)]).await,
            };
            answers.push((page.status, page.body));
        }
        assert_eq!(
            answers[0].0,
            StatusCode::NOT_FOUND,
            "{method} {path}: {}",
            answers[0].1
        );
        assert_eq!(
            answers[0], answers[1],
            "{method} {path}: the same as an unknown id"
        );
    }
    assert_eq!(state(&fx.db).await, before);
}

/// The audit rows of `action`: (actor, global-admin flag, subject, before, after).
async fn audit_rows(
    db: &Db,
    action: &str,
) -> Vec<(
    Option<i32>,
    bool,
    String,
    Option<serde_json::Value>,
    Option<serde_json::Value>,
)> {
    sqlx::query_as(
        "SELECT actor_login, actor_is_global_admin, subject, before, after FROM audit_log
         WHERE action = $1 ORDER BY id",
    )
    .bind(action)
    .fetch_all(&db.owner)
    .await
    .unwrap()
}

/// T-audit-coverage-accounts (C25): method link and unlink, login delete and restore,
/// each done once, write exactly one audit row naming the actor, the global-admin flag,
/// the subject and before/after.
#[tokio::test]
async fn t_audit_coverage_accounts() {
    let fx = Fixture::start().await;
    let mut gil = fx.browser();
    google_login(&fx, &mut gil, "gil").await;
    let gil_login = login_of_google(&fx.db, "gil").await.unwrap();
    // A global admin, so the flag is checked set.
    sqlx::query("INSERT INTO memberships (login_id, role) VALUES ($1, 'global_admin')")
        .bind(gil_login)
        .execute(&fx.db.owner)
        .await
        .unwrap();
    fx.db.global_admin().await;
    oauth(
        &fx,
        &mut gil,
        "/account/link/github",
        serde_json::json!({"id": 99, "email": "gil@github.test"}),
    )
    .await;
    let github = method_id(&fx.db, gil_login, "github").await;
    gil.submit(
        "/account",
        &format!("/account/methods/{github}/remove"),
        &[],
    )
    .await;
    gil.submit("/account", "/account/delete", &DELETE).await;
    google_login(&fx, &mut gil, "gil").await;
    gil.submit("/deleted", "/deleted/restore", &[]).await;
    let subject = format!("login:{gil_login}");
    for (action, before, after) in [
        ("method.link", false, true),
        ("method.unlink", true, false),
        ("login.delete", true, true),
        ("login.restore", true, true),
    ] {
        let rows = audit_rows(&fx.db, action).await;
        assert_eq!(rows.len(), 1, "{action}: {rows:?}");
        let (actor, global, named, was, is) = &rows[0];
        assert_eq!(
            (*actor, *global, named.as_str()),
            (Some(gil_login), true, subject.as_str()),
            "{action}"
        );
        assert_eq!(
            (was.is_some(), is.is_some()),
            (before, after),
            "{action}: {was:?} {is:?}"
        );
    }
    assert_eq!(
        audit_rows(&fx.db, "method.link").await[0]
            .4
            .as_ref()
            .unwrap()["method"],
        "github"
    );
    assert_eq!(
        audit_rows(&fx.db, "method.unlink").await[0]
            .3
            .as_ref()
            .unwrap()["method"],
        "github"
    );
}

/// T-secrets-at-rest (T16): a TOTP secret, backup codes and an API key leave no plaintext
/// in the stored bytes, and the `keys` row holds no `prb_` key; a sealed secret opened
/// with another row's id as AAD fails, and copied into that row it signs nothing in; the
/// audit before/after show `[redacted]`.
#[tokio::test]
async fn t_secrets_at_rest() {
    let fx = Fixture::start().await;
    let mut a = member(&fx, "a@home.test", &[("kind", "personal")]).await;
    let (secret, codes) = turn_totp_on(&mut a).await;
    let mut b = member(&fx, "b@home.test", &[("kind", "personal")]).await;
    turn_totp_on(&mut b).await;
    let key = personal_key(&fx.db, "a@home.test").await;
    let stored: String = sqlx::query_scalar(
        "SELECT (SELECT string_agg(t::text, ',') FROM totp AS t)
             || (SELECT string_agg(c::text, ',') FROM backup_codes AS c)
             || (SELECT string_agg(k::text, ',') FROM keys AS k)
             || (SELECT string_agg(a::text, ',') FROM audit_log AS a)",
    )
    .fetch_one(&fx.db.owner)
    .await
    .unwrap();
    let raw = totp_rs::Secret::try_from_base32(secret.replace(' ', "")).unwrap();
    let raw_hex = hex::encode(raw.as_ref());
    for plain in [
        secret.replace(' ', ""),
        raw_hex.clone(),
        key.clone(),
        "prb_".to_owned(),
    ] {
        assert!(!stored.contains(&plain), "{plain} is stored in the clear");
    }
    for code in &codes {
        assert!(!stored.contains(code.as_str()), "backup code {code} stored");
    }
    let (a_login, b_login) = (
        login_of(&fx.db, "a@home.test").await,
        login_of(&fx.db, "b@home.test").await,
    );
    let sealed: Vec<u8> = sqlx::query_scalar("SELECT secret_enc FROM totp WHERE login_id = $1")
        .bind(a_login)
        .fetch_one(&fx.db.owner)
        .await
        .unwrap();
    let opener = accounts::SecretBox::new([7; 32]);
    assert_eq!(
        opener.open(&accounts::totp_aad(a_login), &sealed),
        Some(raw.as_ref().to_vec())
    );
    assert_eq!(
        opener.open(&accounts::totp_aad(b_login), &sealed),
        None,
        "another row's id as AAD"
    );
    // Copied into B's row, A's secret does not open there: A's code does not sign B in.
    sqlx::query("UPDATE totp SET secret_enc = $2, last_step = 0 WHERE login_id = $1")
        .bind(b_login)
        .bind(&sealed)
        .execute(&fx.db.owner)
        .await
        .unwrap();
    sign_out(&mut b).await;
    let refused = sign_in_with_code(&mut b, "b@home.test", &totp_code(&secret, now_unix())).await;
    assert!(refused.has("That code is wrong"), "{}", refused.body);
    let enabled = audit_rows(&fx.db, "totp.enable").await;
    assert_eq!(enabled.len(), 2);
    assert_eq!(enabled[0].4.as_ref().unwrap()["secret"], "[redacted]");
    assert_eq!(enabled[0].4.as_ref().unwrap()["backup_codes"], "[redacted]");
}
