//! Logins and how people prove who they are (03 § accounts): sign-up (C5, C6), email
//! verification (C41), Argon2id passwords (C42, C101), the outbox that sends mail
//! (02 § Data `email_outbox`), and the two seams to the outside world, `Mailer` (SMTP)
//! and `Outbound` (IdPs and the leaked-password range API), which tests replace.

use std::sync::Arc;
use std::time::Duration;

use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, PgPool};
use url::Url;

use probation_policy::api::KeyId;
use probation_policy::{LayerKind, PlaceRef};

use crate::audit;
use crate::sync::{ChangeKind, record_change};
use crate::tenancy::{self, Actor};

/// One mail, rendered. Links in it are built from the configured base URL, never from a
/// request's `Host` (T14).
#[derive(Clone, Debug)]
pub struct Mail {
    pub to: String,
    pub subject: String,
    pub body: String,
}

/// The SMTP relay.
#[async_trait::async_trait]
pub trait Mailer: Send + Sync {
    async fn deliver(&self, mail: &Mail) -> Result<(), String>;
}

#[derive(Debug)]
pub enum OutboundError {
    /// The address or scheme is not one the server may call (T11).
    Refused(String),
    /// A non-2xx answer; redirects are never followed, so a 3xx lands here too.
    Status(u16),
    Timeout,
    TooLarge,
    Transport(String),
}

/// Every call the server makes to the outside: OIDC discovery, JWKS and token
/// endpoints, GitHub's API, and the leaked-password range API.
#[async_trait::async_trait]
pub trait Outbound: Send + Sync {
    /// The body of a 2xx answer to `GET url`, with `bearer` as the access token.
    async fn get(&self, url: &Url, bearer: Option<&str>) -> Result<Vec<u8>, OutboundError>;
    /// The body of a 2xx answer to a form POST.
    async fn post_form(&self, url: &Url, form: &[(&str, &str)]) -> Result<Vec<u8>, OutboundError>;
}

/// How long the leaked-password check may take before sign-up fails closed (T29).
const LEAK_CHECK_TIMEOUT: Duration = Duration::from_secs(2);
/// How long one SMTP delivery may take.
const MAIL_TIMEOUT: Duration = Duration::from_secs(10);
/// A verification link's lifetime.
const VERIFY_HOURS: i32 = 24;

/// A random 256-bit token for a link or a session, URL-safe.
pub(crate) fn random_token() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("the operating system's random source");
    URL_SAFE_NO_PAD.encode(bytes)
}

/// What is stored for a token: its SHA-256 only.
pub(crate) fn token_hash(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

/// Argon2id with the server's parameters (C101).
#[derive(Clone)]
pub struct Passwords {
    argon: Argon2<'static>,
    /// Argon2id runs at most one per CPU at a time, so a burst queues instead of
    /// exhausting memory and the blocking pool (R2).
    permits: Arc<tokio::sync::Semaphore>,
    /// Verified against when the email has no password, so an unknown email costs the
    /// same as a wrong password (T32).
    dummy: String,
}

impl Passwords {
    pub fn new(params: Params) -> Passwords {
        let cpus = std::thread::available_parallelism().map_or(2, usize::from);
        Passwords::with_permits(params, cpus)
    }

    fn with_permits(params: Params, permits: usize) -> Passwords {
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let dummy = argon
            .hash_password(b"no such login")
            .expect("argon2 hashes")
            .to_string();
        Passwords {
            argon,
            permits: Arc::new(tokio::sync::Semaphore::new(permits)),
            dummy,
        }
    }

    pub(crate) fn hash(&self, password: &str) -> String {
        self.argon
            .hash_password(password.as_bytes())
            .expect("argon2 hashes")
            .to_string()
    }

    /// The permit for one Argon2id run. It moves into the blocking closure, so it is
    /// held until the hash finishes even when the caller is cancelled (N1).
    async fn permit(&self) -> tokio::sync::OwnedSemaphorePermit {
        self.permits
            .clone()
            .acquire_owned()
            .await
            .expect("the semaphore is never closed")
    }

    /// `hash` off the async runtime: Argon2id is deliberately slow.
    pub(crate) async fn hash_blocking(&self, password: String) -> String {
        let permit = self.permit().await;
        let passwords = self.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            passwords.hash(&password)
        })
        .await
        .expect("hashing does not panic")
    }

    /// `verify` off the async runtime.
    pub(crate) async fn verify_blocking(&self, password: String, hash: Option<String>) -> bool {
        let permit = self.permit().await;
        let passwords = self.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            passwords.verify(&password, hash.as_deref())
        })
        .await
        .expect("verifying does not panic")
    }

    /// Whether `password` matches `hash`; `None` runs the same work and answers false.
    pub(crate) fn verify(&self, password: &str, hash: Option<&str>) -> bool {
        let stored = hash.unwrap_or(&self.dummy);
        let matches = PasswordHash::new(stored).ok().is_some_and(|parsed| {
            self.argon
                .verify_password(password.as_bytes(), &parsed)
                .is_ok()
        });
        matches && hash.is_some()
    }
}

/// Why a new password is refused (C42).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PasswordProblem {
    TooShort,
    TooLong,
    Leaked,
    /// The leaked-password service did not answer in time: fail closed (T29).
    CheckUnavailable,
}

impl PasswordProblem {
    pub fn message(self) -> &'static str {
        match self {
            PasswordProblem::TooShort => "Use at least 12 characters.",
            PasswordProblem::TooLong => "Use at most 1024 characters.",
            PasswordProblem::Leaked => {
                "This password has appeared in a known data leak. Choose a different one."
            }
            PasswordProblem::CheckUnavailable => {
                "We could not check this password just now. Please try again."
            }
        }
    }
}

/// At least 12 characters, no composition rules, not on the leaked list (C42). The
/// range API sees only the first 5 hex characters of the SHA-1 (T29).
pub async fn check_new_password(
    outbound: &dyn Outbound,
    leaked_url: &Url,
    password: &str,
) -> Result<(), PasswordProblem> {
    if password.chars().count() < 12 {
        return Err(PasswordProblem::TooShort);
    }
    if password.len() > 1024 {
        return Err(PasswordProblem::TooLong);
    }
    let digest = hex::encode_upper(Sha1::digest(password.as_bytes()));
    let (prefix, suffix) = digest.split_at(5);
    let url = leaked_url
        .join(prefix)
        .map_err(|_| PasswordProblem::CheckUnavailable)?;
    let body = match tokio::time::timeout(LEAK_CHECK_TIMEOUT, outbound.get(&url, None)).await {
        Ok(Ok(body)) => body,
        Ok(Err(err)) => {
            tracing::warn!(error = ?err, "leaked-password check failed");
            return Err(PasswordProblem::CheckUnavailable);
        }
        Err(_) => {
            tracing::warn!("leaked-password check timed out");
            return Err(PasswordProblem::CheckUnavailable);
        }
    };
    let leaked = String::from_utf8_lossy(&body).lines().any(|line| {
        line.split_once(':').is_some_and(|(hash, count)| {
            hash.trim().eq_ignore_ascii_case(suffix) && count.trim() != "0"
        })
    });
    if leaked {
        Err(PasswordProblem::Leaked)
    } else {
        Ok(())
    }
}

/// An email address as it is stored and compared.
pub(crate) fn normal_email(email: &str) -> Option<String> {
    let email = email.trim().to_lowercase();
    let (local, domain) = email.split_once('@')?;
    (!local.is_empty()
        && domain.contains('.')
        && email.len() <= 254
        && !email.contains(char::is_whitespace))
    .then_some(email)
}

/// An organisation name as it is stored: inner whitespace collapsed to one space, none
/// at the ends.
pub(crate) fn org_name(name: &str) -> String {
    name.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Whether an organisation of that name exists. Names are unique ignoring case and
/// whitespace, so `/o/<name>` and the typed name on `/signin` find one organisation
/// (C37), and two places in the switcher never read alike.
pub(crate) async fn org_name_taken(pool: &PgPool, name: &str) -> Result<bool, sqlx::Error> {
    let mut conn = pool.acquire().await?;
    name_taken(&mut conn, name).await
}

async fn name_taken(conn: &mut PgConnection, name: &str) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM orgs
                        WHERE lower(regexp_replace(name, '\\s+', ' ', 'g')) = lower($1))",
    )
    .bind(org_name(name))
    .fetch_one(conn)
    .await
}

/// Writes one mail to the outbox in the caller's transaction; the outbox job sends it.
pub(crate) async fn enqueue(
    conn: &mut PgConnection,
    to: &str,
    template: &str,
    subject: &str,
    body: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO email_outbox (to_address, template, payload) VALUES ($1, $2, $3)")
        .bind(to)
        .bind(template)
        .bind(json!({"subject": subject, "body": body}))
        .execute(conn)
        .await
        .map(drop)
}

/// Sends every due outbox row once. A refused send is retried later with backoff; a sent
/// row keeps no body, so no link outlives its delivery in the outbox.
pub async fn deliver_outbox(pool: &PgPool, mailer: &Arc<dyn Mailer>) -> Result<usize, sqlx::Error> {
    let mut sent = 0;
    for _ in 0..100 {
        let mut tx = pool.begin().await?;
        let row: Option<(i64, String, Value)> = sqlx::query_as(
            "SELECT id, to_address, payload FROM email_outbox
             WHERE sent_at IS NULL AND next_attempt_at <= now() AND attempts < 10
             ORDER BY id LIMIT 1 FOR UPDATE SKIP LOCKED",
        )
        .fetch_optional(&mut *tx)
        .await?;
        let Some((id, to, payload)) = row else {
            break;
        };
        let text = |field: &str| payload[field].as_str().unwrap_or_default().to_owned();
        let mail = Mail {
            to,
            subject: text("subject"),
            body: text("body"),
        };
        let outcome = match tokio::time::timeout(MAIL_TIMEOUT, mailer.deliver(&mail)).await {
            Ok(outcome) => outcome,
            Err(_) => Err("timed out".to_owned()),
        };
        match outcome {
            Ok(()) => {
                sqlx::query(
                    "UPDATE email_outbox SET sent_at = now(), payload = '{}', attempts = attempts + 1
                     WHERE id = $1",
                )
                .bind(id)
                .execute(&mut *tx)
                .await?;
                sent += 1;
            }
            Err(err) => {
                tracing::warn!(outbox = id, error = %err, "mail not sent; retrying later");
                sqlx::query(
                    "UPDATE email_outbox SET attempts = attempts + 1,
                         next_attempt_at = now() + make_interval(mins => least(60, 1 << attempts))
                     WHERE id = $1",
                )
                .bind(id)
                .execute(&mut *tx)
                .await?;
            }
        }
        let () = tx.commit().await?;
    }
    Ok(sent)
}

/// What a sign-up asks for once its address is confirmed.
#[derive(Clone, Debug)]
pub enum SignupKind {
    Personal,
    Org(String),
}

impl SignupKind {
    fn payload(&self) -> Value {
        match self {
            SignupKind::Personal => json!({"kind": "personal"}),
            SignupKind::Org(name) => json!({"kind": "org", "org_name": name}),
        }
    }
}

/// Mails that carry a link, built from `base`.
fn verify_mail(base: &Url, token: &str) -> (String, String) {
    (
        "Confirm your email address".to_owned(),
        format!(
            "Open this link to confirm your email address for Probation:\n\n{}verify-email?token={token}\n\nThe link works once and expires in {VERIFY_HOURS} hours.\n",
            base_path(base)
        ),
    )
}

fn already_mail(base: &Url) -> (String, String) {
    (
        "You already have a Probation login".to_owned(),
        format!(
            "Someone tried to sign up with this address, which already has an email-and-password sign-in.\n\nSign in at {}signin, or reset your password there.\n",
            base_path(base)
        ),
    )
}

/// The base URL with exactly one trailing slash.
pub(crate) fn base_path(base: &Url) -> String {
    format!("{}/", base.as_str().trim_end_matches('/'))
}

/// A new email-and-password login, unusable until confirmed. An address that already
/// has a password method gets a "you already have a login" mail and nothing is created;
/// the caller shows the same page either way (C91).
pub async fn sign_up(
    pool: &PgPool,
    base: &Url,
    email: &str,
    password_hash: &str,
    kind: SignupKind,
) -> Result<(), sqlx::Error> {
    // Every sign-up mails the address once; counted before the transaction, so the cap
    // never needs a second connection (N3).
    let allowed = mail_allowed(pool, email).await?;
    loop {
        let mut tx = pool.begin().await?;
        let taken: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM sign_in_methods WHERE kind = 'password' AND lower(email) = $1)",
        )
        .bind(email)
        .fetch_one(&mut *tx)
        .await?;
        if taken {
            if allowed {
                let (subject, body) = already_mail(base);
                enqueue(&mut tx, email, "already", &subject, &body).await?;
            }
            return tx.commit().await;
        }
        let login: i32 = sqlx::query_scalar("INSERT INTO logins DEFAULT VALUES RETURNING id")
            .fetch_one(&mut *tx)
            .await?;
        let inserted: Option<i32> = sqlx::query_scalar(
            "INSERT INTO sign_in_methods (login_id, kind, subject, email, password_hash)
             VALUES ($1, 'password', $2, $2, $3)
             ON CONFLICT DO NOTHING RETURNING id",
        )
        .bind(login)
        .bind(email)
        .bind(password_hash)
        .fetch_optional(&mut *tx)
        .await?;
        // `None`: a concurrent sign-up took the address first; this one rolls back and
        // answers as for a taken address.
        let Some(method) = inserted else {
            continue;
        };
        if allowed {
            send_verify(&mut tx, base, method, email, kind.payload()).await?;
        }
        return tx.commit().await;
    }
}

async fn send_verify(
    conn: &mut PgConnection,
    base: &Url,
    method: i32,
    email: &str,
    payload: Value,
) -> Result<(), sqlx::Error> {
    let token = random_token();
    sqlx::query(
        "INSERT INTO email_tokens (token_hash, method_id, purpose, payload, expires_at)
         VALUES ($1, $2, 'verify', $3, now() + make_interval(hours => $4))",
    )
    .bind(token_hash(&token))
    .bind(method)
    .bind(payload)
    .bind(VERIFY_HOURS)
    .execute(&mut *conn)
    .await?;
    let (subject, body) = verify_mail(base, &token);
    enqueue(conn, email, "verify", &subject, &body).await
}

/// "Send the link again": a new link for an address whose password method is not yet
/// confirmed; nothing otherwise. The page is the same either way (C91).
pub async fn resend_verification(
    pool: &PgPool,
    base: &Url,
    email: &str,
) -> Result<(), sqlx::Error> {
    let pending: Option<(i32, Option<Value>)> = sqlx::query_as(
        "SELECT m.id, (SELECT t.payload FROM email_tokens AS t
                       WHERE t.method_id = m.id AND t.purpose = 'verify'
                       ORDER BY t.expires_at DESC LIMIT 1)
         FROM sign_in_methods AS m
         WHERE m.kind = 'password' AND lower(m.email) = $1 AND m.verified_at IS NULL",
    )
    .bind(email)
    .fetch_optional(pool)
    .await?;
    // Counted only when a mail would go, and before the transaction (N3).
    let Some((method, payload)) = pending else {
        return Ok(());
    };
    if !mail_allowed(pool, email).await? {
        return Ok(());
    }
    let mut tx = pool.begin().await?;
    send_verify(
        &mut tx,
        base,
        method,
        email,
        payload.unwrap_or_else(|| json!({})),
    )
    .await?;
    tx.commit().await
}

/// What confirming an address did.
#[derive(Debug, PartialEq, Eq)]
pub enum Verified {
    Done {
        login_id: i32,
    },
    /// Unknown, used or expired.
    BadLink,
}

/// Confirms the address of the link's method, once, and creates what the sign-up asked
/// for: an organisation with the signer as its only org admin (C5) or a personal
/// account (C6).
pub async fn verify_email(pool: &PgPool, token: &str) -> Result<Verified, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let used: Option<(i32, Value)> = sqlx::query_as(
        "UPDATE email_tokens SET used_at = now()
         WHERE token_hash = $1 AND purpose = 'verify' AND used_at IS NULL AND expires_at > now()
         RETURNING method_id, payload",
    )
    .bind(token_hash(token))
    .fetch_optional(&mut *tx)
    .await?;
    let Some((method, payload)) = used else {
        return Ok(Verified::BadLink);
    };
    let confirmed: Option<i32> = sqlx::query_scalar(
        "UPDATE sign_in_methods SET verified_at = now()
         WHERE id = $1 AND verified_at IS NULL RETURNING login_id",
    )
    .bind(method)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(login_id) = confirmed else {
        return Ok(Verified::BadLink);
    };
    let actor = Actor::own_account(login_id, false);
    match payload["kind"].as_str() {
        Some("org") => {
            let name = org_name(payload["org_name"].as_str().unwrap_or_default());
            let taken = name_taken(&mut tx, &name).await?;
            // Taken meanwhile: the login is confirmed and creates one from Account settings.
            if !taken && !name.is_empty() {
                create_org(&mut tx, &actor, &name).await?;
            }
        }
        Some("personal") => create_personal(&mut tx, &actor).await?,
        _ => {}
    }
    let () = tx.commit().await?;
    Ok(Verified::Done { login_id })
}

/// A new organisation with `actor` as its org admin, audited in its own log.
pub(crate) async fn create_org(
    conn: &mut PgConnection,
    actor: &Actor,
    name: &str,
) -> Result<i32, sqlx::Error> {
    let org = tenancy::create_org(conn, name).await?.0 as i32;
    sqlx::query("INSERT INTO memberships (login_id, org_id, role) VALUES ($1, $2, 'org_admin')")
        .bind(actor.login_id())
        .bind(org)
        .execute(&mut *conn)
        .await?;
    let () = audit::record(
        conn,
        audit::Entry {
            actor,
            org_id: Some(org),
            action: "org.create",
            subject: format!("org:{org}"),
            before: None,
            after: Some(json!({"name": name, "org_admin": actor.login_id()})),
        },
    )
    .await?;
    Ok(org)
}

/// A personal account for `actor`'s login, audited.
pub(crate) async fn create_personal(
    conn: &mut PgConnection,
    actor: &Actor,
) -> Result<(), sqlx::Error> {
    let id: i32 =
        sqlx::query_scalar("INSERT INTO personal_accounts (login_id) VALUES ($1) RETURNING id")
            .bind(actor.login_id())
            .fetch_one(&mut *conn)
            .await?;
    audit::record(
        conn,
        audit::Entry {
            actor,
            org_id: None,
            action: "personal.create",
            subject: format!("personal:{id}"),
            before: None,
            after: Some(json!({"owner": actor.login_id()})),
        },
    )
    .await
}

/// A browser's session row (02 § Data `sessions`). Signed out while `login_id` is
/// `None`; it still carries a CSRF token, so the sign-in forms have one too (C101).
#[derive(Clone, Debug)]
pub struct Session {
    pub(crate) id_hash: Vec<u8>,
    pub login_id: Option<i32>,
    csrf: String,
    pub totp_ok: bool,
    pub scope_org_id: Option<i32>,
    /// What the session waits for before it is signed in (TOTP, an OAuth round trip,
    /// the choice for a deleted login).
    pub(crate) pending: Option<Value>,
    /// The place chosen with the switcher ("org:3", "personal:5"), unchecked.
    pub(crate) place: Option<String>,
}

impl Session {
    pub(crate) fn csrf(&self) -> &str {
        &self.csrf
    }

    /// Constant-time comparison with the form's token.
    pub(crate) fn csrf_matches(&self, presented: &str) -> bool {
        use subtle::ConstantTimeEq;
        !presented.is_empty() && bool::from(self.csrf.as_bytes().ct_eq(presented.as_bytes()))
    }
}

/// A signed-out session lives an hour; a signed-in one 12 hours.
const ANONYMOUS_SESSION_MINUTES: i32 = 60;
const SESSION_MINUTES: i32 = 12 * 60;

/// `sessions` as `load_session` reads it.
type SessionRow = (
    Vec<u8>,
    Option<i32>,
    String,
    bool,
    Option<i32>,
    Option<Value>,
    Option<String>,
);

pub(crate) async fn load_session(
    pool: &PgPool,
    token: &str,
) -> Result<Option<Session>, sqlx::Error> {
    let row: Option<SessionRow> = sqlx::query_as(
        "SELECT id_hash, login_id, csrf_token, totp_ok, scope_org_id, pending, place FROM sessions
         WHERE id_hash = $1 AND expires_at > now()",
    )
    .bind(token_hash(token))
    .fetch_optional(pool)
    .await?;
    Ok(row.map(
        |(id_hash, login_id, csrf, totp_ok, scope_org_id, pending, place)| Session {
            id_hash,
            login_id,
            csrf,
            totp_ok,
            scope_org_id,
            pending,
            place,
        },
    ))
}

/// A new session with a new id and CSRF token; returns it and the cookie token.
pub(crate) async fn open_session(
    pool: &PgPool,
    login_id: Option<i32>,
    totp_ok: bool,
    scope_org_id: Option<i32>,
    pending: Option<Value>,
) -> Result<(Session, String), sqlx::Error> {
    let mut conn = pool.acquire().await?;
    open_session_in(&mut conn, login_id, totp_ok, scope_org_id, pending).await
}

pub(crate) async fn open_session_in(
    conn: &mut PgConnection,
    login_id: Option<i32>,
    totp_ok: bool,
    scope_org_id: Option<i32>,
    pending: Option<Value>,
) -> Result<(Session, String), sqlx::Error> {
    let token = random_token();
    let session = Session {
        id_hash: token_hash(&token),
        login_id,
        csrf: random_token(),
        totp_ok,
        scope_org_id,
        pending,
        place: None,
    };
    let minutes = if login_id.is_some() {
        SESSION_MINUTES
    } else {
        ANONYMOUS_SESSION_MINUTES
    };
    sqlx::query(
        "INSERT INTO sessions (id_hash, login_id, csrf_token, expires_at, totp_ok, scope_org_id, pending)
         VALUES ($1, $2, $3, now() + make_interval(mins => $4), $5, $6, $7)",
    )
    .bind(&session.id_hash)
    .bind(login_id)
    .bind(&session.csrf)
    .bind(minutes)
    .bind(totp_ok)
    .bind(scope_org_id)
    .bind(&session.pending)
    .execute(conn)
    .await?;
    Ok((session, token))
}

/// Replaces `old` with a new session (new id, new CSRF token) in one transaction, so a
/// session id never survives a change of who is signed in (T15).
pub(crate) async fn rotate_session(
    pool: &PgPool,
    old: &Session,
    login_id: Option<i32>,
    totp_ok: bool,
    scope_org_id: Option<i32>,
    pending: Option<Value>,
) -> Result<(Session, String), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM sessions WHERE id_hash = $1")
        .bind(&old.id_hash)
        .execute(&mut *tx)
        .await?;
    let opened = open_session_in(&mut tx, login_id, totp_ok, scope_org_id, pending).await?;
    let () = tx.commit().await?;
    Ok(opened)
}

pub(crate) async fn close_session(pool: &PgPool, session: &Session) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM sessions WHERE id_hash = $1")
        .bind(&session.id_hash)
        .execute(pool)
        .await
        .map(drop)
}

/// The email-and-password method of an address, as sign-in needs it.
pub(crate) struct PasswordMethod {
    pub method_id: i32,
    pub login_id: i32,
    pub hash: Option<String>,
}

pub(crate) async fn password_method(
    pool: &PgPool,
    email: &str,
) -> Result<Option<PasswordMethod>, sqlx::Error> {
    let row: Option<(i32, i32, Option<String>)> = sqlx::query_as(
        "SELECT id, login_id, password_hash FROM sign_in_methods
         WHERE kind = 'password' AND lower(email) = $1",
    )
    .bind(email)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(method_id, login_id, hash)| PasswordMethod {
        method_id,
        login_id,
        hash,
    }))
}

/// Whether the login has an email-and-password address it has not confirmed (C41).
pub(crate) async fn unconfirmed(
    conn: &mut PgConnection,
    login_id: i32,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM sign_in_methods
                        WHERE login_id = $1 AND kind = 'password' AND verified_at IS NULL)",
    )
    .bind(login_id)
    .fetch_one(conn)
    .await
}

/// A login whose email-and-password address is not confirmed yet can do nothing but
/// confirm it (C41). Answers that address.
pub(crate) async fn unconfirmed_email(
    pool: &PgPool,
    login_id: i32,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT email FROM sign_in_methods
         WHERE login_id = $1 AND kind = 'password' AND verified_at IS NULL",
    )
    .bind(login_id)
    .fetch_optional(pool)
    .await
}

/// What the top bar shows for a login: a name (its first method's email) and its live
/// places, personal account first; only the organisation of a session opened through
/// that organisation's SSO (T2).
pub(crate) async fn top_bar(
    pool: &PgPool,
    login_id: i32,
    scope_org_id: Option<i32>,
) -> Result<(String, Vec<SwitcherPlace>), sqlx::Error> {
    let name: Option<String> = sqlx::query_scalar(
        "SELECT email FROM sign_in_methods WHERE login_id = $1 AND email IS NOT NULL ORDER BY id LIMIT 1",
    )
    .bind(login_id)
    .fetch_optional(pool)
    .await?;
    let rows: Vec<(bool, String, i32)> = sqlx::query_as(
        "SELECT rank = 0, label, id FROM (
             SELECT 0 AS rank, 'Personal account' AS label, id FROM personal_accounts
             WHERE login_id = $1 AND deleted_at IS NULL AND $2::integer IS NULL
             UNION ALL
             SELECT 1, o.name || ' (organisation)', o.id FROM memberships AS m
             JOIN orgs AS o ON o.id = m.org_id
             WHERE m.login_id = $1 AND o.deleted_at IS NULL AND ($2::integer IS NULL OR o.id = $2)
         ) AS places ORDER BY rank, id",
    )
    .bind(login_id)
    .bind(scope_org_id)
    .fetch_all(pool)
    .await?;
    let places = rows
        .into_iter()
        .map(|(personal, label, id)| {
            let (value, kind) = if personal {
                ("personal".to_owned(), LayerKind::Personal)
            } else {
                (format!("org:{id}"), LayerKind::Org)
            };
            SwitcherPlace {
                label,
                value,
                place: PlaceRef {
                    kind,
                    id: id as u32,
                },
            }
        })
        .collect();
    Ok((name.unwrap_or_else(|| format!("Login {login_id}")), places))
}

/// One of a login's places in the switcher: its label, the value the form posts
/// ("personal" or "org:<id>"), and the place itself.
pub(crate) struct SwitcherPlace {
    pub label: String,
    pub value: String,
    pub place: PlaceRef,
}

/// Remembers the place chosen with the switcher; every page checks it again.
pub(crate) async fn choose_place(
    pool: &PgPool,
    session: &Session,
    place: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE sessions SET place = $2 WHERE id_hash = $1")
        .bind(&session.id_hash)
        .bind(place)
        .execute(pool)
        .await
        .map(drop)
}

/// Secrets at rest (T16): AES-256-GCM under `PROBATION_SERVER_SECRET_KEY`, with the
/// owning row's id as associated data, so a sealed value copied to another row does not
/// open there. Backup codes are stored as keyed hashes.
pub struct SecretBox {
    cipher: aes_gcm::Aes256Gcm,
    mac_key: [u8; 32],
}

impl SecretBox {
    pub fn new(key: [u8; 32]) -> SecretBox {
        use aes_gcm::KeyInit;
        let mut mac = Sha256::new();
        mac.update(b"probation backup codes\0");
        mac.update(key);
        SecretBox {
            cipher: aes_gcm::Aes256Gcm::new_from_slice(&key).expect("a 256-bit key"),
            mac_key: mac.finalize().into(),
        }
    }

    /// The nonce followed by the ciphertext.
    pub fn seal(&self, aad: &str, plaintext: &[u8]) -> Vec<u8> {
        use aes_gcm::aead::{Aead, Payload};
        let mut nonce = [0u8; 12];
        getrandom::fill(&mut nonce).expect("the operating system's random source");
        let sealed = self
            .cipher
            .encrypt(
                aes_gcm::Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: aad.as_bytes(),
                },
            )
            .expect("AES-GCM seals");
        [nonce.as_slice(), &sealed].concat()
    }

    /// `None` when `sealed` was not sealed under this key for `aad`.
    pub fn open(&self, aad: &str, sealed: &[u8]) -> Option<Vec<u8>> {
        use aes_gcm::aead::{Aead, Payload};
        let (nonce, body) = sealed.split_at_checked(12)?;
        self.cipher
            .decrypt(
                aes_gcm::Nonce::from_slice(nonce),
                Payload {
                    msg: body,
                    aad: aad.as_bytes(),
                },
            )
            .ok()
    }

    fn code_hash(&self, code: &str) -> Vec<u8> {
        use hmac::{KeyInit, Mac};
        let mut mac = hmac::Hmac::<Sha256>::new_from_slice(&self.mac_key).expect("an HMAC key");
        mac.update(code.as_bytes());
        mac.finalize().into_bytes().to_vec()
    }
}

/// The associated data of an organisation's SSO client secret: its row's id.
pub fn sso_secret_aad(org_id: i32) -> String {
    format!("org:{org_id}")
}

/// The associated data of a login's TOTP secret: its row's id.
pub fn totp_aad(login_id: i32) -> String {
    format!("totp:{login_id}")
}

/// `actor` for a login acting on its own account, flagged when it is a global admin.
pub(crate) async fn login_actor(
    conn: &mut PgConnection,
    login_id: i32,
) -> Result<Actor, sqlx::Error> {
    let global_admin: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM memberships WHERE login_id = $1 AND org_id IS NULL)",
    )
    .bind(login_id)
    .fetch_one(conn)
    .await?;
    Ok(Actor::own_account(login_id, global_admin))
}

/// A login must keep its authenticator while it is an org admin of a live organisation
/// or a global admin (C24).
pub(crate) async fn totp_required(
    conn: &mut PgConnection,
    login_id: i32,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM memberships AS m LEFT JOIN orgs AS o ON o.id = m.org_id
                        WHERE m.login_id = $1
                          AND (m.role = 'global_admin' OR (m.role = 'org_admin' AND o.deleted_at IS NULL)))",
    )
    .bind(login_id)
    .fetch_one(conn)
    .await
}

pub(crate) async fn totp_enabled(
    conn: &mut PgConnection,
    login_id: i32,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM totp WHERE login_id = $1 AND enabled_at IS NOT NULL)",
    )
    .bind(login_id)
    .fetch_one(conn)
    .await
}

/// A new authenticator secret and 10 backup codes, shown once (C39).
pub(crate) struct TotpSetup {
    pub key: String,
    pub codes: Vec<String>,
}

fn totp(secret: &[u8]) -> totp_rs::Totp {
    totp_rs::Builder::new()
        .with_secret(secret.to_vec())
        .build_noncompliant()
}

/// The 30-second step `code` belongs to, within one step either side of now, if it is
/// after `last_step` (a code is accepted once, T15).
fn code_step(secret: &[u8], code: &str, last_step: i64) -> Option<i64> {
    let code: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    let step = i64::try_from(totp(secret).check(&code, now)?).ok()?;
    (step > last_step).then_some(step)
}

fn backup_code() -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijkmnpqrstuvwxyz23456789";
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).expect("the operating system's random source");
    let chars: String = bytes
        .iter()
        .map(|byte| char::from(ALPHABET[usize::from(byte % 32)]))
        .collect();
    format!("{}-{}", &chars[..4], &chars[4..])
}

/// Starts turning the authenticator on: a new sealed secret, not yet enabled, and 10
/// new backup codes replacing any old ones. `None` when it is on already.
pub(crate) async fn totp_setup(
    pool: &PgPool,
    secrets: &SecretBox,
    login_id: i32,
) -> Result<Option<TotpSetup>, sqlx::Error> {
    let mut secret = [0u8; 20];
    getrandom::fill(&mut secret).expect("the operating system's random source");
    let mut tx = pool.begin().await?;
    if totp_enabled(&mut tx, login_id).await? {
        return Ok(None);
    }
    sqlx::query(
        "INSERT INTO totp (login_id, secret_enc) VALUES ($1, $2)
         ON CONFLICT (login_id) DO UPDATE SET secret_enc = EXCLUDED.secret_enc, last_step = 0",
    )
    .bind(login_id)
    .bind(secrets.seal(&totp_aad(login_id), &secret))
    .execute(&mut *tx)
    .await?;
    let codes = replace_backup_codes(&mut tx, secrets, login_id).await?;
    let () = tx.commit().await?;
    Ok(Some(TotpSetup {
        key: totp_rs::Secret::from(secret.to_vec()).to_base32(),
        codes,
    }))
}

async fn replace_backup_codes(
    conn: &mut PgConnection,
    secrets: &SecretBox,
    login_id: i32,
) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query("DELETE FROM backup_codes WHERE login_id = $1")
        .bind(login_id)
        .execute(&mut *conn)
        .await?;
    let codes: Vec<String> = (0..10).map(|_| backup_code()).collect();
    for code in &codes {
        sqlx::query("INSERT INTO backup_codes (login_id, code_hash) VALUES ($1, $2)")
            .bind(login_id)
            .bind(secrets.code_hash(code))
            .execute(&mut *conn)
            .await?;
    }
    Ok(codes)
}

/// The pending secret's otpauth URI, for the set-up QR code.
pub(crate) async fn totp_uri(
    pool: &PgPool,
    secrets: &SecretBox,
    login_id: i32,
) -> Result<Option<String>, sqlx::Error> {
    let row: Option<(Vec<u8>, Option<String>)> = sqlx::query_as(
        "SELECT t.secret_enc, (SELECT email FROM sign_in_methods WHERE login_id = $1 AND email IS NOT NULL ORDER BY id LIMIT 1)
         FROM totp AS t WHERE t.login_id = $1 AND t.enabled_at IS NULL",
    )
    .bind(login_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.and_then(|(sealed, email)| {
        let secret = secrets.open(&totp_aad(login_id), &sealed)?;
        let key = totp_rs::Secret::from(secret).to_base32();
        let account = email.unwrap_or_else(|| format!("login {login_id}"));
        let mut uri = Url::parse("otpauth://totp/").ok()?;
        uri.set_path(&format!("Probation:{account}"));
        uri.query_pairs_mut()
            .append_pair("secret", &key)
            .append_pair("issuer", "Probation");
        Some(uri.to_string())
    }))
}

/// Turns the authenticator on once `code` matches the pending secret; audited with the
/// secret redacted (T16). Every other session of the login ends: one opened with a
/// password alone must not become an admin session (C24, T15); `session` proved the
/// code and stays.
pub(crate) async fn totp_enable(
    pool: &PgPool,
    secrets: &SecretBox,
    session: &Session,
    login_id: i32,
    code: &str,
) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let pending: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT secret_enc FROM totp WHERE login_id = $1 AND enabled_at IS NULL FOR UPDATE",
    )
    .bind(login_id)
    .fetch_optional(&mut *tx)
    .await?;
    let step = pending
        .and_then(|sealed| secrets.open(&totp_aad(login_id), &sealed))
        .and_then(|secret| code_step(&secret, code, 0));
    let Some(step) = step else {
        return Ok(false);
    };
    sqlx::query("UPDATE totp SET enabled_at = now(), last_step = $2 WHERE login_id = $1")
        .bind(login_id)
        .bind(step)
        .execute(&mut *tx)
        .await?;
    end_sessions(&mut tx, login_id, Some(&session.id_hash)).await?;
    let actor = login_actor(&mut tx, login_id).await?;
    let () = audit::record(
        &mut tx,
        audit::Entry {
            actor: &actor,
            org_id: None,
            action: "totp.enable",
            subject: format!("login:{login_id}"),
            before: Some(json!({"totp": "off"})),
            after: Some(
                json!({"totp": "on", "secret": "[redacted]", "backup_codes": "[redacted]"}),
            ),
        },
    )
    .await?;
    let () = tx.commit().await?;
    Ok(true)
}

/// Turns the authenticator off, unless the login must keep it (C24). `false` when
/// refused.
pub(crate) async fn totp_disable(pool: &PgPool, login_id: i32) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;
    if totp_required(&mut tx, login_id).await? || !totp_enabled(&mut tx, login_id).await? {
        return Ok(false);
    }
    sqlx::query("DELETE FROM totp WHERE login_id = $1")
        .bind(login_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM backup_codes WHERE login_id = $1")
        .bind(login_id)
        .execute(&mut *tx)
        .await?;
    let actor = login_actor(&mut tx, login_id).await?;
    let () = audit::record(
        &mut tx,
        audit::Entry {
            actor: &actor,
            org_id: None,
            action: "totp.disable",
            subject: format!("login:{login_id}"),
            before: Some(json!({"totp": "on"})),
            after: Some(json!({"totp": "off"})),
        },
    )
    .await?;
    let () = tx.commit().await?;
    Ok(true)
}

/// An org admin resets the authenticator of a member whose login belongs to their
/// organisation alone; any other login's, and any org admin's or one who was an org
/// admin there in the last 30 days (S6-4), is reset by a global admin (C39, C76). The authenticator, its backup codes and every session of the login
/// go in one transaction, with the audit row; a refusal writes nothing.
pub(crate) async fn reset_totp(
    pool: &PgPool,
    actor: &Actor,
    member: &tenancy::Authorized<tenancy::Place>,
) -> Result<(), tenancy::ChangeError> {
    use tenancy::{ChangeError, Role};
    let global = actor.is_global_admin();
    let runs = matches!(
        actor.role(member.place()),
        Some(Role::OrgAdmin | Role::GlobalAdmin)
    );
    let (Some(login), Some(org), true) = (member.owner_login(), member.org(), runs) else {
        return Err(ChangeError::Denied);
    };
    let mut tx = pool.begin().await?;
    // Under the organisation's lock, so no role change slips in between (S6-4).
    tenancy::lock_org(&mut tx, org).await?;
    let (org_only, org_admin): (bool, bool) = sqlx::query_as(
        "SELECT NOT EXISTS (SELECT 1 FROM personal_accounts WHERE login_id = $1)
                    AND NOT EXISTS (SELECT 1 FROM memberships WHERE login_id = $1 AND org_id IS DISTINCT FROM $2),
                EXISTS (SELECT 1 FROM memberships WHERE login_id = $1 AND org_id = $2 AND role = 'org_admin')
                    OR EXISTS (SELECT 1 FROM former_org_admins
                               WHERE login_id = $1 AND org_id = $2 AND until > now() - interval '30 days')",
    )
    .bind(login)
    .bind(org)
    .fetch_one(&mut *tx)
    .await?;
    if !global && (!org_only || org_admin) {
        return Err(ChangeError::Denied);
    }
    let removed = sqlx::query("DELETE FROM totp WHERE login_id = $1")
        .bind(login)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    sqlx::query("DELETE FROM backup_codes WHERE login_id = $1")
        .bind(login)
        .execute(&mut *tx)
        .await?;
    end_sessions(&mut tx, login, None).await?;
    let () = audit::record(
        &mut tx,
        audit::Entry {
            actor,
            org_id: Some(org),
            action: "totp.reset",
            subject: format!("login:{login}"),
            before: Some(json!({"totp": if removed > 0 { "on" } else { "off" }})),
            after: Some(json!({"totp": "off"})),
        },
    )
    .await?;
    let () = tx.commit().await?;
    Ok(())
}

impl Session {
    /// The login a pending step of `kind` is for (`{"<kind>": login_id}`).
    pub(crate) fn pending_login(&self, kind: &str) -> Option<i32> {
        self.pending
            .as_ref()?
            .get(kind)?
            .as_i64()
            .and_then(|id| i32::try_from(id).ok())
    }
}

/// The second sign-in step of a password login with an authenticator: a TOTP code not
/// used before, or an unused backup code, each accepted once (C39, T15).
pub(crate) async fn second_factor(
    pool: &PgPool,
    secrets: &SecretBox,
    login_id: i32,
    code: &str,
) -> Result<bool, sqlx::Error> {
    let code = code.trim().to_lowercase();
    let mut tx = pool.begin().await?;
    let accepted = if code.contains('-') {
        sqlx::query(
            "UPDATE backup_codes SET used_at = now()
             WHERE id = (SELECT id FROM backup_codes
                         WHERE login_id = $1 AND code_hash = $2 AND used_at IS NULL
                         LIMIT 1 FOR UPDATE)",
        )
        .bind(login_id)
        .bind(secrets.code_hash(&code))
        .execute(&mut *tx)
        .await?
        .rows_affected()
            == 1
    } else {
        let row: Option<(Vec<u8>, i64)> = sqlx::query_as(
            "SELECT secret_enc, last_step FROM totp
             WHERE login_id = $1 AND enabled_at IS NOT NULL FOR UPDATE",
        )
        .bind(login_id)
        .fetch_optional(&mut *tx)
        .await?;
        let step = row.and_then(|(sealed, last_step)| {
            let secret = secrets.open(&totp_aad(login_id), &sealed)?;
            code_step(&secret, &code, last_step)
        });
        match step {
            Some(step) => {
                sqlx::query("UPDATE totp SET last_step = $2 WHERE login_id = $1")
                    .bind(login_id)
                    .bind(step)
                    .execute(&mut *tx)
                    .await?;
                true
            }
            None => false,
        }
    };
    let () = tx.commit().await?;
    Ok(accepted)
}

pub(crate) async fn has_totp(pool: &PgPool, login_id: i32) -> Result<bool, sqlx::Error> {
    let mut conn = pool.acquire().await?;
    totp_enabled(&mut conn, login_id).await
}

/// Failed steps allowed in 15 minutes before the next attempt is refused unchecked
/// (T15, T32): per email (known or not), per client IP, per login's TOTP step.
pub(crate) const EMAIL_FAILURES: i64 = 10;
pub(crate) const IP_FAILURES: i64 = 100;
pub(crate) const TOTP_FAILURES: i64 = 5;

async fn failures(pool: &PgPool, scope: &str, subject: &str) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT count(*) FROM sign_in_failures
         WHERE scope = $1 AND subject = $2 AND at > now() - interval '15 minutes'",
    )
    .bind(scope)
    .bind(subject)
    .fetch_one(pool)
    .await
}

/// At most this many mails to one address in 15 minutes (sign-up, "send the link
/// again", reset), and this many mail-sending requests from one client IP.
pub(crate) const MAIL_PER_ADDRESS: i64 = 5;
pub(crate) const MAIL_PER_IP: i64 = 20;

/// One attempt, recorded in `sign_in_failures` before it is checked, so a concurrent
/// burst cannot all see the count from before it (R2): the n-th attempt to be recorded
/// counts at least n rows. A failed check keeps its rows; `release` removes them.
#[must_use]
pub(crate) struct Attempt {
    rows: Vec<(&'static str, String, String)>,
}

/// Records one attempt against each `(scope, subject, limit)`; `None`, with nothing
/// left recorded, when any count including it is over its limit.
pub(crate) async fn attempt(
    pool: &PgPool,
    checks: &[(&'static str, String, i64)],
) -> Result<Option<Attempt>, sqlx::Error> {
    let mut attempt = Attempt { rows: Vec::new() };
    for (scope, subject, _) in checks {
        let at: String = sqlx::query_scalar(
            "INSERT INTO sign_in_failures (scope, subject) VALUES ($1, $2) RETURNING at::text",
        )
        .bind(*scope)
        .bind(subject)
        .fetch_one(pool)
        .await?;
        attempt.rows.push((*scope, subject.clone(), at));
    }
    for (scope, subject, limit) in checks {
        if failures(pool, scope, subject).await? > *limit {
            attempt.release(pool).await?;
            return Ok(None);
        }
    }
    Ok(Some(attempt))
}

impl Attempt {
    /// Removes this attempt's rows: it succeeded, or it was refused unchecked.
    pub(crate) async fn release(self, pool: &PgPool) -> Result<(), sqlx::Error> {
        for (scope, subject, at) in &self.rows {
            sqlx::query(
                "DELETE FROM sign_in_failures
                 WHERE ctid = (SELECT ctid FROM sign_in_failures
                               WHERE scope = $1 AND subject = $2 AND at = $3::timestamptz LIMIT 1)",
            )
            .bind(*scope)
            .bind(subject)
            .bind(at)
            .execute(pool)
            .await?;
        }
        Ok(())
    }

    /// Keeps this attempt's rows: a failure, or a mail that counts against its cap.
    pub(crate) fn keep(self) {}
}

/// Whether one more mail may go to `email` now (R3); counted when it may.
async fn mail_allowed(pool: &PgPool, email: &str) -> Result<bool, sqlx::Error> {
    let checks = [("email", format!("mail {email}"), MAIL_PER_ADDRESS)];
    Ok(match attempt(pool, &checks).await? {
        Some(sent) => {
            sent.keep();
            true
        }
        None => false,
    })
}

/// Ends every session of the login, signed in or waiting at its TOTP step or its
/// deleted-login choice (R5), except `keep`.
async fn end_sessions(
    conn: &mut PgConnection,
    login_id: i32,
    keep: Option<&[u8]>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "DELETE FROM sessions
         WHERE (login_id = $1 OR pending->>'totp' = $1::text OR pending->>'deleted' = $1::text)
           AND ($2::bytea IS NULL OR id_hash <> $2)",
    )
    .bind(login_id)
    .bind(keep)
    .execute(conn)
    .await
    .map(drop)
}

pub(crate) async fn password_hash_of(
    pool: &PgPool,
    login_id: i32,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT password_hash FROM sign_in_methods WHERE login_id = $1 AND kind = 'password'",
    )
    .bind(login_id)
    .fetch_optional(pool)
    .await
    .map(Option::flatten)
}

/// Sets the login's password. Every session of the login ends in the same transaction
/// (02 § Data `sessions`), and a new one replaces `session`; returns its token.
pub(crate) async fn change_password(
    pool: &PgPool,
    session: &Session,
    login_id: i32,
    new_hash: &str,
) -> Result<String, sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        "UPDATE sign_in_methods SET password_hash = $2 WHERE login_id = $1 AND kind = 'password'",
    )
    .bind(login_id)
    .bind(new_hash)
    .execute(&mut *tx)
    .await?;
    end_sessions(&mut tx, login_id, None).await?;
    let (_, token) = open_session_in(
        &mut tx,
        Some(login_id),
        session.totp_ok,
        session.scope_org_id,
        None,
    )
    .await?;
    let actor = login_actor(&mut tx, login_id).await?;
    let () = audit::record(
        &mut tx,
        audit::Entry {
            actor: &actor,
            org_id: None,
            action: "password.change",
            subject: format!("login:{login_id}"),
            before: Some(json!({"password": "[redacted]"})),
            after: Some(json!({"password": "[redacted]"})),
        },
    )
    .await?;
    let () = tx.commit().await?;
    Ok(token)
}

/// A reset link's lifetime.
const RESET_MINUTES: i32 = 60;

/// Mails a reset link when the address has an email-and-password method on a live
/// login; nothing otherwise. The link is built from the configured base URL (T14).
pub async fn request_reset(pool: &PgPool, base: &Url, email: &str) -> Result<(), sqlx::Error> {
    // A member who joined through company SSO, now turned off, has no password yet: the
    // link sets one on their SSO method's login (C62). An address that has a password
    // method anywhere is that method's alone (C91).
    let method: Option<i32> = sqlx::query_scalar(
        "SELECT m.id FROM sign_in_methods AS m JOIN logins AS l ON l.id = m.login_id
         WHERE lower(m.email) = $1 AND l.deleted_at IS NULL
           AND (m.kind = 'password'
                OR (m.kind = 'oidc'
                    AND NOT EXISTS (SELECT 1 FROM sign_in_methods AS p
                                    WHERE p.kind = 'password'
                                      AND (p.login_id = m.login_id OR lower(p.email) = $1))
                    AND EXISTS (SELECT 1 FROM orgs AS o WHERE o.id = m.org_id AND o.sso_issuer IS NULL)))
         ORDER BY m.kind = 'password' DESC, m.id LIMIT 1",
    )
    .bind(email)
    .fetch_optional(pool)
    .await?;
    // Counted only when a mail would go, and before the transaction (N3).
    let Some(method) = method else {
        return Ok(());
    };
    if !mail_allowed(pool, email).await? {
        return Ok(());
    }
    let mut tx = pool.begin().await?;
    let link = reset_link(&mut tx, base, method).await?;
    let body = format!(
        "Open this link to choose a new password for Probation:\n\n{link}\n\nThe link works once and expires in {RESET_MINUTES} minutes. If you did not ask for it, ignore this mail.\n"
    );
    enqueue(&mut tx, email, "reset", "Choose a new password", &body).await?;
    tx.commit().await
}

/// A link that sets the password of the email-and-password `method`: a hashed,
/// single-use reset token with a reset link's lifetime, written in the caller's
/// transaction.
pub(crate) async fn reset_link(
    conn: &mut PgConnection,
    base: &Url,
    method: i32,
) -> Result<String, sqlx::Error> {
    let token = random_token();
    sqlx::query(
        "INSERT INTO email_tokens (token_hash, method_id, purpose, expires_at)
         VALUES ($1, $2, 'reset', now() + make_interval(mins => $3))",
    )
    .bind(token_hash(&token))
    .bind(method)
    .bind(RESET_MINUTES)
    .execute(conn)
    .await?;
    Ok(format!("{}reset/confirm?token={token}", base_path(base)))
}

/// `admin bootstrap`'s global admin: an email-and-password method with no password
/// yet, confirmed because the host operator vouches for the address. `None` when the
/// address already has an email-and-password method.
pub(crate) async fn insert_unset_password(
    conn: &mut PgConnection,
    login_id: i32,
    email: &str,
) -> Result<Option<i32>, sqlx::Error> {
    sqlx::query_scalar(
        "INSERT INTO sign_in_methods (login_id, kind, subject, email, verified_at)
         VALUES ($1, 'password', $2, $2, now())
         ON CONFLICT DO NOTHING RETURNING id",
    )
    .bind(login_id)
    .bind(email)
    .fetch_optional(conn)
    .await
}

/// `admin reset-link`: a fresh set-password link for the live global admin whose
/// email-and-password address is `email`, with an audit row; `None` when there is no
/// such admin. It signs no one in, so an admin with an authenticator still needs it.
pub async fn operator_reset_link(
    pool: &PgPool,
    base: &Url,
    email: &str,
) -> Result<Option<String>, sqlx::Error> {
    let Some(email) = normal_email(email) else {
        return Ok(None);
    };
    let mut tx = pool.begin().await?;
    let found: Option<(i32, i32)> = sqlx::query_as(
        "SELECT m.id, m.login_id FROM sign_in_methods AS m
         JOIN logins AS l ON l.id = m.login_id
         WHERE m.kind = 'password' AND lower(m.email) = $1 AND l.deleted_at IS NULL
           AND EXISTS (SELECT 1 FROM memberships AS g
                       WHERE g.login_id = m.login_id AND g.role = 'global_admin')",
    )
    .bind(&email)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((method, login_id)) = found else {
        return Ok(None);
    };
    let link = reset_link(&mut tx, base, method).await?;
    let () = audit::record(
        &mut tx,
        audit::Entry {
            actor: &Actor::Operator,
            org_id: None,
            action: "admin.reset_link",
            subject: format!("login:{login_id}"),
            before: None,
            after: None,
        },
    )
    .await?;
    let () = tx.commit().await?;
    Ok(Some(link))
}

pub(crate) async fn reset_token_live(pool: &PgPool, token: &str) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM email_tokens
                        WHERE token_hash = $1 AND purpose = 'reset' AND used_at IS NULL AND expires_at > now())",
    )
    .bind(token_hash(token))
    .fetch_one(pool)
    .await
}

/// Uses a reset link once: sets the password and ends every session of the login in
/// the same transaction. It signs no one in, so a login with an authenticator still
/// gets its TOTP step (T14). `false` for an unknown, used or expired link.
pub(crate) async fn reset_password(
    pool: &PgPool,
    token: &str,
    new_hash: &str,
) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let used: Option<(i32, i32, String, Option<String>)> = sqlx::query_as(
        "WITH used AS (
             UPDATE email_tokens SET used_at = now()
             WHERE token_hash = $1 AND purpose = 'reset' AND used_at IS NULL AND expires_at > now()
             RETURNING method_id
         )
         SELECT m.id, m.login_id, m.kind, m.email FROM sign_in_methods AS m
         WHERE m.id = (SELECT method_id FROM used) FOR UPDATE",
    )
    .bind(token_hash(token))
    .fetch_optional(&mut *tx)
    .await?;
    let Some((method, login_id, kind, email)) = used else {
        return Ok(false);
    };
    if kind == "password" {
        sqlx::query("UPDATE sign_in_methods SET password_hash = $2 WHERE id = $1")
            .bind(method)
            .bind(new_hash)
            .execute(&mut *tx)
            .await?;
    } else {
        // An SSO member's first password, after their organisation turned SSO off (C62).
        let added = sqlx::query(
            "INSERT INTO sign_in_methods (login_id, kind, subject, email, password_hash, verified_at)
             VALUES ($1, 'password', $2, $2, $3, now()) ON CONFLICT DO NOTHING",
        )
        .bind(login_id)
        .bind(email.as_deref().map(str::to_lowercase))
        .bind(new_hash)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if added == 0 {
            return Ok(false);
        }
    }
    end_sessions(&mut tx, login_id, None).await?;
    let actor = login_actor(&mut tx, login_id).await?;
    let () = audit::record(
        &mut tx,
        audit::Entry {
            actor: &actor,
            org_id: None,
            action: "password.reset",
            subject: format!("login:{login_id}"),
            before: Some(json!({"password": "[redacted]"})),
            after: Some(json!({"password": "[redacted]"})),
        },
    )
    .await?;
    let () = tx.commit().await?;
    Ok(true)
}

/// Adds a personal account to a login that has none (C40). `false` when it has one,
/// live or deleted and still restorable.
pub(crate) async fn add_personal(pool: &PgPool, login_id: i32) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM personal_accounts WHERE login_id = $1)")
            .bind(login_id)
            .fetch_one(&mut *tx)
            .await?;
    if exists {
        return Ok(false);
    }
    let actor = login_actor(&mut tx, login_id).await?;
    create_personal(&mut tx, &actor).await?;
    let () = tx.commit().await?;
    Ok(true)
}

/// Why an organisation name is refused.
pub(crate) fn org_name_problem(name: &str) -> Option<&'static str> {
    (name.is_empty() || name.chars().count() > 100)
        .then_some("Enter an organisation name of at most 100 characters.")
}

pub(crate) const ORG_NAME_TAKEN: &str = "That organisation name is taken. Choose another.";

/// A new organisation with the login as its org admin (C40). `Err` with the reason when
/// the name is refused.
pub(crate) async fn add_org(
    pool: &PgPool,
    login_id: i32,
    name: &str,
) -> Result<Result<(), &'static str>, sqlx::Error> {
    let name = org_name(name);
    if let Some(problem) = org_name_problem(&name) {
        return Ok(Err(problem));
    }
    let mut tx = pool.begin().await?;
    if name_taken(&mut tx, &name).await? {
        return Ok(Err(ORG_NAME_TAKEN));
    }
    let actor = login_actor(&mut tx, login_id).await?;
    create_org(&mut tx, &actor, &name).await?;
    let () = tx.commit().await?;
    Ok(Ok(()))
}

// ---- OAuth and OIDC (C21, C38, C75; T2, T11, T12) -------------------------------------

const GOOGLE_ISSUER: &str = "https://accounts.google.com";
const MICROSOFT_COMMON: &str = "https://login.microsoftonline.com/common/v2.0";
/// What Microsoft's common discovery document names as its issuer; each ID token names
/// its own tenant in place of `{tenantid}`.
const MICROSOFT_TEMPLATE: &str = "https://login.microsoftonline.com/{tenantid}/v2.0";
const MICROSOFT_ISSUER: &str = "https://login.microsoftonline.com";
const GITHUB_ISSUER: &str = "https://github.com";
const GITHUB_AUTHORIZE: &str = "https://github.com/login/oauth/authorize";
const GITHUB_TOKEN: &str = "https://github.com/login/oauth/access_token";
const GITHUB_USER: &str = "https://api.github.com/user";
/// How long one call to an IdP may take.
const IDP_TIMEOUT: Duration = Duration::from_secs(5);

/// A sign-in provider: one of the platform's (Google, GitHub, Microsoft) or an
/// organisation's own OIDC issuer.
pub(crate) struct Idp {
    pub kind: IdpKind,
    pub client_id: String,
    pub client_secret: String,
    /// Where the IdP sends the browser back: built from the configured base URL.
    pub redirect_uri: Url,
}

pub(crate) enum IdpKind {
    Google,
    Github,
    Microsoft,
    /// Organisation SSO (C21): methods are scoped to the organisation (T2).
    Sso {
        org: i32,
        issuer: String,
        allowed_tenant: Option<String>,
    },
}

/// Why an OAuth or OIDC sign-in failed. Shown to no one in detail; logged.
#[derive(Debug)]
pub enum OidcError {
    Outbound(OutboundError),
    /// Bad JSON, a missing field, a bad signature or a claim that does not check out.
    Invalid(&'static str),
    State,
}

impl From<OutboundError> for OidcError {
    fn from(err: OutboundError) -> Self {
        OidcError::Outbound(err)
    }
}

#[derive(serde::Deserialize)]
struct Discovery {
    issuer: String,
    authorization_endpoint: Url,
    token_endpoint: Url,
    jwks_uri: Url,
}

async fn fetch_json<T: serde::de::DeserializeOwned>(
    outbound: &dyn Outbound,
    url: &Url,
    bearer: Option<&str>,
) -> Result<T, OidcError> {
    let body = tokio::time::timeout(IDP_TIMEOUT, outbound.get(url, bearer))
        .await
        .map_err(|_| OutboundError::Timeout)??;
    serde_json::from_slice(&body).map_err(|_| OidcError::Invalid("not the JSON expected"))
}

async fn post_json<T: serde::de::DeserializeOwned>(
    outbound: &dyn Outbound,
    url: &Url,
    form: &[(&str, &str)],
) -> Result<T, OidcError> {
    let body = tokio::time::timeout(IDP_TIMEOUT, outbound.post_form(url, form))
        .await
        .map_err(|_| OutboundError::Timeout)??;
    serde_json::from_slice(&body).map_err(|_| OidcError::Invalid("not the JSON expected"))
}

impl Idp {
    /// The provider's name in `/oauth/{provider}/…` and the flow record.
    pub(crate) fn name(&self) -> &'static str {
        match self.kind {
            IdpKind::Google => "google",
            IdpKind::Github => "github",
            IdpKind::Microsoft => "microsoft",
            IdpKind::Sso { .. } => "sso",
        }
    }

    /// `sign_in_methods.kind`.
    fn method_kind(&self) -> &'static str {
        match self.kind {
            IdpKind::Sso { .. } => "oidc",
            _ => self.name(),
        }
    }

    /// Where discovery is fetched from; GitHub has none.
    fn discovery_base(&self) -> Option<&str> {
        match &self.kind {
            IdpKind::Google => Some(GOOGLE_ISSUER),
            IdpKind::Microsoft => Some(MICROSOFT_COMMON),
            IdpKind::Sso { issuer, .. } => Some(issuer),
            IdpKind::Github => None,
        }
    }

    /// The discovery document, refused unless it names the issuer it was fetched for.
    async fn discover(&self, outbound: &dyn Outbound) -> Result<Option<Discovery>, OidcError> {
        let Some(base) = self.discovery_base() else {
            return Ok(None);
        };
        let base = base.trim_end_matches('/');
        let url = Url::parse(&format!("{base}/.well-known/openid-configuration"))
            .map_err(|_| OidcError::Invalid("issuer is not a URL"))?;
        let found: Discovery = fetch_json(outbound, &url, None).await?;
        let expected = match self.kind {
            IdpKind::Microsoft => MICROSOFT_TEMPLATE,
            _ => base,
        };
        if found.issuer.trim_end_matches('/') != expected {
            return Err(OidcError::Invalid("discovery names another issuer"));
        }
        Ok(Some(found))
    }
}

/// Where to send the browser, and what the session keeps until the IdP sends it back.
pub(crate) struct Started {
    pub location: Url,
    pub flow: Value,
}

fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// The first leg: a fresh `state` and `nonce` and a PKCE verifier, kept in the session
/// (T12); `link` marks a method being added to the signed-in login (C75).
pub(crate) async fn oauth_start(
    outbound: &dyn Outbound,
    idp: &Idp,
    link: bool,
) -> Result<Started, OidcError> {
    let (state, nonce, verifier) = (random_token(), random_token(), random_token());
    let (mut location, scope) = match idp.discover(outbound).await? {
        Some(found) => (found.authorization_endpoint, "openid email"),
        None => (
            Url::parse(GITHUB_AUTHORIZE).expect("a URL"),
            "read:user user:email",
        ),
    };
    location
        .query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &idp.client_id)
        .append_pair("redirect_uri", idp.redirect_uri.as_str())
        .append_pair("scope", scope)
        .append_pair("state", &state)
        .append_pair("nonce", &nonce)
        .append_pair("code_challenge", &pkce_challenge(&verifier))
        .append_pair("code_challenge_method", "S256");
    let org = match idp.kind {
        IdpKind::Sso { org, .. } => Some(org),
        _ => None,
    };
    Ok(Started {
        location,
        flow: json!({
            "provider": idp.name(),
            "org": org,
            "state": state,
            "nonce": nonce,
            "verifier": verifier,
            "link": link,
        }),
    })
}

/// Who an IdP says signed in: the method's (kind, issuer, subject) and, for SSO, its
/// organisation. Never matched on email (C75).
#[derive(Clone, Debug)]
pub(crate) struct Identity {
    pub kind: &'static str,
    pub issuer: String,
    pub subject: String,
    pub email: Option<String>,
    pub org: Option<i32>,
}

#[derive(serde::Deserialize)]
struct TokenAnswer {
    access_token: Option<String>,
    id_token: Option<String>,
}

#[derive(serde::Deserialize)]
struct IdClaims {
    iss: String,
    sub: String,
    nonce: Option<String>,
    email: Option<String>,
    /// Google Workspace domain.
    hd: Option<String>,
    /// Microsoft tenant and object id.
    tid: Option<String>,
    oid: Option<String>,
}

#[derive(serde::Deserialize)]
struct GithubUser {
    id: u64,
    email: Option<String>,
}

fn same(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

/// The second leg: checks `state` against the session's flow, redeems the code with the
/// PKCE verifier, and checks the ID token's signature (the issuer's JWKS), `iss`, `aud`,
/// `exp` and `nonce` (T2, T12).
pub(crate) async fn oauth_finish(
    outbound: &dyn Outbound,
    idp: &Idp,
    flow: &Value,
    state: &str,
    code: &str,
) -> Result<Identity, OidcError> {
    let field = |name: &str| flow[name].as_str().unwrap_or_default().to_owned();
    // The callback's organisation must be the one the flow started for, or an IdP
    // mix-up could finish one organisation's flow at another's (F4).
    let idp_org = match idp.kind {
        IdpKind::Sso { org, .. } => Some(i64::from(org)),
        _ => None,
    };
    if field("provider") != idp.name()
        || flow["org"].as_i64() != idp_org
        || field("state").is_empty()
        || !same(&field("state"), state)
    {
        return Err(OidcError::State);
    }
    let discovery = idp.discover(outbound).await?;
    let token_url = match &discovery {
        Some(found) => found.token_endpoint.clone(),
        None => Url::parse(GITHUB_TOKEN).expect("a URL"),
    };
    let verifier = field("verifier");
    let answer: TokenAnswer = post_json(
        outbound,
        &token_url,
        &[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", idp.redirect_uri.as_str()),
            ("client_id", &idp.client_id),
            ("client_secret", &idp.client_secret),
            ("code_verifier", &verifier),
        ],
    )
    .await?;
    let Some(found) = discovery else {
        let token = answer
            .access_token
            .ok_or(OidcError::Invalid("no access token"))?;
        let user: GithubUser = fetch_json(
            outbound,
            &Url::parse(GITHUB_USER).expect("a URL"),
            Some(&token),
        )
        .await?;
        return Ok(Identity {
            kind: "github",
            issuer: GITHUB_ISSUER.to_owned(),
            subject: user.id.to_string(),
            email: user.email,
            org: None,
        });
    };
    let id_token = answer.id_token.ok_or(OidcError::Invalid("no ID token"))?;
    let claims = verify_id_token(outbound, idp, &found, &id_token).await?;
    if !claims
        .nonce
        .as_deref()
        .is_some_and(|nonce| same(nonce, &field("nonce")))
    {
        return Err(OidcError::Invalid("nonce"));
    }
    let (issuer, subject, org) = match &idp.kind {
        IdpKind::Google => (GOOGLE_ISSUER.to_owned(), claims.sub, None),
        IdpKind::Microsoft => {
            let tid = claims.tid.ok_or(OidcError::Invalid("no tid"))?;
            let oid = claims.oid.ok_or(OidcError::Invalid("no oid"))?;
            if claims.iss != MICROSOFT_TEMPLATE.replace("{tenantid}", &tid) {
                return Err(OidcError::Invalid("iss is not the token's tenant"));
            }
            (MICROSOFT_ISSUER.to_owned(), format!("{tid}/{oid}"), None)
        }
        IdpKind::Sso {
            org,
            issuer,
            allowed_tenant,
        } => {
            // A shared issuer serves every customer of Google or Microsoft, so the
            // organisation's own tenant must be named and must match (T2).
            let shared = issuer.trim_end_matches('/') == GOOGLE_ISSUER
                || issuer.starts_with(MICROSOFT_ISSUER);
            match allowed_tenant {
                Some(tenant) => {
                    let matches = [&claims.hd, &claims.tid]
                        .into_iter()
                        .flatten()
                        .any(|claimed| claimed == tenant);
                    if !matches {
                        return Err(OidcError::Invalid("another tenant"));
                    }
                }
                None if shared => return Err(OidcError::Invalid("a shared issuer needs a tenant")),
                None => {}
            }
            (
                issuer.trim_end_matches('/').to_owned(),
                claims.sub,
                Some(*org),
            )
        }
        IdpKind::Github => unreachable!("GitHub has no discovery"),
    };
    Ok(Identity {
        kind: idp.method_kind(),
        issuer,
        subject,
        email: claims.email,
        org,
    })
}

async fn verify_id_token(
    outbound: &dyn Outbound,
    idp: &Idp,
    found: &Discovery,
    id_token: &str,
) -> Result<IdClaims, OidcError> {
    use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
    let header = decode_header(id_token).map_err(|_| OidcError::Invalid("ID token header"))?;
    // Asymmetric algorithms only: the client secret is never a verification key.
    if !matches!(
        header.alg,
        Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::ES256
            | Algorithm::ES384
    ) {
        return Err(OidcError::Invalid("ID token algorithm"));
    }
    let keys: JwkSet = fetch_json(outbound, &found.jwks_uri, None).await?;
    let jwk = match &header.kid {
        Some(kid) => keys.find(kid),
        None if keys.keys.len() == 1 => keys.keys.first(),
        None => None,
    }
    .ok_or(OidcError::Invalid("no JWKS key for the ID token"))?;
    let key = DecodingKey::from_jwk(jwk).map_err(|_| OidcError::Invalid("JWKS key"))?;
    let mut validation = Validation::new(header.alg);
    validation.set_audience(&[&idp.client_id]);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    validation.leeway = 60;
    match idp.kind {
        // Checked against the token's own tenant by the caller.
        IdpKind::Microsoft => {}
        IdpKind::Google => validation.set_issuer(&[GOOGLE_ISSUER, "accounts.google.com"]),
        _ => validation.set_issuer(&[found.issuer.trim_end_matches('/')]),
    }
    decode::<IdClaims>(id_token, &key, &validation)
        .map(|data| data.claims)
        .map_err(|err| {
            tracing::info!(error = %err, "ID token refused");
            OidcError::Invalid("ID token")
        })
}

/// Takes the session's pending flow, once: a second callback with the same `state`
/// finds none (T12).
pub(crate) async fn take_pending(
    pool: &PgPool,
    session: &Session,
) -> Result<Option<Value>, sqlx::Error> {
    sqlx::query_scalar(
        "UPDATE sessions AS s SET pending = NULL
         FROM (SELECT id_hash, pending FROM sessions WHERE id_hash = $1 FOR UPDATE) AS old
         WHERE s.id_hash = old.id_hash RETURNING old.pending",
    )
    .bind(&session.id_hash)
    .fetch_optional(pool)
    .await
    .map(Option::flatten)
}

pub(crate) async fn set_pending(
    pool: &PgPool,
    session: &Session,
    pending: &Value,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE sessions SET pending = $2 WHERE id_hash = $1")
        .bind(&session.id_hash)
        .bind(pending)
        .execute(pool)
        .await
        .map(drop)
}

/// The login an identity signs in to: the one its method belongs to, or a new login
/// with that method (and, through an organisation's SSO, a membership there, C5).
/// Looked up by (kind, issuer, subject, organisation) only (C75).
pub(crate) async fn identity_login(
    pool: &PgPool,
    identity: &Identity,
) -> Result<(i32, i32), sqlx::Error> {
    let mut tx = pool.begin().await?;
    let found: Option<(i32, i32)> = sqlx::query_as(
        "SELECT login_id, id FROM sign_in_methods
         WHERE kind = $1 AND issuer = $2 AND subject = $3 AND org_id IS NOT DISTINCT FROM $4",
    )
    .bind(identity.kind)
    .bind(&identity.issuer)
    .bind(&identity.subject)
    .bind(identity.org)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some((login, method)) = found {
        match login_state(pool, login).await? {
            // Every sign-in through an organisation's SSO joins it, unless an org admin
            // removed this login or identity there (C5, C128, C130).
            LoginState::Live => {
                if let Some(org) = identity.org {
                    join_through_sso(&mut tx, login, org).await?;
                    let () = tx.commit().await?;
                }
                return Ok((login, method));
            }
            LoginState::Deleted { .. } => return Ok((login, method)),
            // Past its 30 days the old login is erased now, and the method starts anew.
            LoginState::Expired => erase_login(&mut tx, login).await?,
        }
    }
    let login: i32 = sqlx::query_scalar("INSERT INTO logins DEFAULT VALUES RETURNING id")
        .fetch_one(&mut *tx)
        .await?;
    let method = insert_method(&mut tx, login, identity).await?;
    if let Some(org) = identity.org {
        join_through_sso(&mut tx, login, org).await?;
    }
    let () = tx.commit().await?;
    Ok((login, method))
}

/// A login that signs in through, or links, an organisation's SSO joins it (C5), unless
/// an org admin removed it, or the SSO identity it holds, there while the removed login
/// exists; only an invitation brings it back (C128, C130).
async fn join_through_sso(
    conn: &mut PgConnection,
    login: i32,
    org: i32,
) -> Result<(), sqlx::Error> {
    let joined = sqlx::query(
        "INSERT INTO memberships (login_id, org_id, role)
         SELECT $1, $2, 'member'
         WHERE NOT EXISTS (SELECT 1 FROM org_removals WHERE login_id = $1 AND org_id = $2)
           AND NOT EXISTS (SELECT 1 FROM org_sso_removals AS r JOIN sign_in_methods AS m
                             ON m.org_id = r.org_id AND m.issuer = r.issuer AND m.subject = r.subject
                           WHERE m.login_id = $1 AND r.org_id = $2)
         ON CONFLICT DO NOTHING",
    )
    .bind(login)
    .bind(org)
    .execute(&mut *conn)
    .await?
    .rows_affected();
    if joined == 0 {
        return Ok(());
    }
    let actor = login_actor(conn, login).await?;
    audit::record(
        conn,
        audit::Entry {
            actor: &actor,
            org_id: Some(org),
            action: "member.join",
            subject: format!("login:{login}"),
            before: None,
            after: Some(json!({"role": "member", "through": "sso"})),
        },
    )
    .await
}

/// An organisation's SSO settings, its client secret opened (T16).
pub(crate) async fn sso_idp(
    pool: &PgPool,
    secrets: &SecretBox,
    org: i32,
    redirect_uri: Url,
) -> Result<Option<Idp>, sqlx::Error> {
    let row: Option<(String, String, Vec<u8>, Option<String>)> = sqlx::query_as(
        "SELECT sso_issuer, sso_client_id, sso_client_secret_enc, sso_allowed_tenant FROM orgs
         WHERE id = $1 AND deleted_at IS NULL AND sso_issuer IS NOT NULL
           AND sso_client_id IS NOT NULL AND sso_client_secret_enc IS NOT NULL",
    )
    .bind(org)
    .fetch_optional(pool)
    .await?;
    Ok(row.and_then(|(issuer, client_id, sealed, allowed_tenant)| {
        let Some(secret) = secrets.open(&sso_secret_aad(org), &sealed) else {
            tracing::error!(
                org,
                "the SSO client secret does not open under this server's key"
            );
            return None;
        };
        Some(Idp {
            kind: IdpKind::Sso {
                org,
                issuer,
                allowed_tenant,
            },
            client_id,
            client_secret: String::from_utf8_lossy(&secret).into_owned(),
            redirect_uri,
        })
    }))
}

/// An organisation's company SSO as its page shows it: issuer, client id and required
/// tenant, never the secret.
pub(crate) async fn sso_settings(
    pool: &PgPool,
    org: i32,
) -> Result<Option<(String, String, Option<String>)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT sso_issuer, sso_client_id, sso_allowed_tenant FROM orgs
         WHERE id = $1 AND sso_issuer IS NOT NULL AND sso_client_id IS NOT NULL",
    )
    .bind(org)
    .fetch_optional(pool)
    .await
}

/// What the organisation page's SSO form saves.
pub(crate) struct SsoForm<'a> {
    pub enabled: bool,
    pub issuer: &'a str,
    pub client_id: &'a str,
    /// Empty keeps the stored one.
    pub client_secret: &'a str,
    pub allowed_tenant: &'a str,
}

/// Saves `org`'s company SSO, or turns it off, as only its org admin may (C21, C57,
/// C62). The client secret is sealed with the organisation's id as AAD and never shown
/// or audited (T16); members who joined through SSO stay when it is turned off (C62).
pub(crate) async fn save_sso(
    pool: &PgPool,
    secrets: &SecretBox,
    actor: &Actor,
    org: &tenancy::Authorized<tenancy::Place>,
    form: SsoForm<'_>,
) -> Result<(), tenancy::ChangeError> {
    use tenancy::{ChangeError, Role};
    let refuse = |reason: &str| Err(ChangeError::Refused(reason.to_owned()));
    let (Some(org_id), true) = (
        org.org(),
        matches!(
            actor.role(org.place()),
            Some(Role::OrgAdmin | Role::GlobalAdmin)
        ),
    ) else {
        return Err(ChangeError::Denied);
    };
    let issuer = form.issuer.trim().trim_end_matches('/');
    let client_id = form.client_id.trim();
    let tenant = form.allowed_tenant.trim();
    if form.enabled {
        if Url::parse(issuer).map_or(true, |url| url.scheme() != "https") {
            return refuse("Enter the issuer as an https URL.");
        }
        if client_id.is_empty() {
            return refuse("Enter the client ID your provider gave you.");
        }
        let shared = issuer == GOOGLE_ISSUER
            || issuer.starts_with("https://login.microsoftonline.com/common");
        if shared && tenant.is_empty() {
            return refuse(
                "A shared issuer needs the tenant your people sign in from: the Google Workspace domain (hd) or the Microsoft tenant id (tid).",
            );
        }
    }
    let mut tx = pool.begin().await?;
    let before: (Option<String>, Option<String>, Option<String>, bool) = sqlx::query_as(
        "SELECT sso_issuer, sso_client_id, sso_allowed_tenant, sso_client_secret_enc IS NOT NULL
         FROM orgs WHERE id = $1 FOR UPDATE",
    )
    .bind(org_id)
    .fetch_one(&mut *tx)
    .await?;
    let sealed = match (form.enabled, form.client_secret.trim()) {
        (false, _) => None,
        // The stored secret stays only with the issuer and client it was given for.
        (true, "")
            if before.3
                && before.0.as_deref() == Some(issuer)
                && before.1.as_deref() == Some(client_id) =>
        {
            Some(None)
        }
        (true, "") => return refuse("Enter the client secret your provider gave you."),
        (true, secret) => Some(Some(
            secrets.seal(&sso_secret_aad(org_id), secret.as_bytes()),
        )),
    };
    let saved = if form.enabled {
        sqlx::query(
            "UPDATE orgs SET sso_issuer = $2, sso_client_id = $3, sso_allowed_tenant = $4,
                 sso_client_secret_enc = coalesce($5, sso_client_secret_enc)
             WHERE id = $1",
        )
        .bind(org_id)
        .bind(issuer)
        .bind(client_id)
        .bind((!tenant.is_empty()).then_some(tenant))
        .bind(sealed.flatten())
        .execute(&mut *tx)
        .await
    } else {
        sqlx::query(
            "UPDATE orgs SET sso_issuer = NULL, sso_client_id = NULL, sso_allowed_tenant = NULL,
                 sso_client_secret_enc = NULL WHERE id = $1",
        )
        .bind(org_id)
        .execute(&mut *tx)
        .await
    };
    match saved {
        Ok(_) => {}
        Err(sqlx::Error::Database(err)) if err.is_unique_violation() => {
            return refuse("Another organisation already uses this issuer and client ID.");
        }
        Err(err) => return Err(err.into()),
    }
    let redacted = |on: bool| on.then_some("[redacted]");
    let () = audit::record(
        &mut tx,
        audit::Entry {
            actor,
            org_id: Some(org_id),
            action: "sso.save",
            subject: format!("org:{org_id}"),
            before: Some(json!({
                "enabled": before.0.is_some(),
                "issuer": before.0,
                "client_id": before.1,
                "allowed_tenant": before.2,
                "client_secret": redacted(before.3),
            })),
            after: Some(json!({
                "enabled": form.enabled,
                "issuer": form.enabled.then_some(issuer),
                "client_id": form.enabled.then_some(client_id),
                "allowed_tenant": (form.enabled && !tenant.is_empty()).then_some(tenant),
                "client_secret": redacted(form.enabled),
            })),
        },
    )
    .await?;
    let () = tx.commit().await?;
    Ok(())
}

/// The organisation `/o/<name>` or the typed name on `/signin` means, when it has SSO
/// (C37).
pub(crate) async fn sso_org_named(pool: &PgPool, name: &str) -> Result<Option<i32>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT id FROM orgs WHERE lower(name) = lower($1) AND deleted_at IS NULL AND sso_issuer IS NOT NULL",
    )
    .bind(name.trim())
    .fetch_optional(pool)
    .await
}

async fn insert_method(
    conn: &mut PgConnection,
    login: i32,
    identity: &Identity,
) -> Result<i32, sqlx::Error> {
    sqlx::query_scalar(
        "INSERT INTO sign_in_methods (login_id, kind, issuer, subject, org_id, email, verified_at)
         VALUES ($1, $2, $3, $4, $5, $6, now()) RETURNING id",
    )
    .bind(login)
    .bind(identity.kind)
    .bind(&identity.issuer)
    .bind(&identity.subject)
    .bind(identity.org)
    .bind(&identity.email)
    .fetch_one(conn)
    .await
}

/// Adds `identity` to the signed-in `login_id` (C75): the only way a method joins an
/// existing login. `false`, with nothing written, when it belongs to another login.
pub(crate) async fn link_method(
    pool: &PgPool,
    login_id: i32,
    identity: &Identity,
) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let owner: Option<i32> = sqlx::query_scalar(
        "SELECT login_id FROM sign_in_methods
         WHERE kind = $1 AND issuer = $2 AND subject = $3 AND org_id IS NOT DISTINCT FROM $4",
    )
    .bind(identity.kind)
    .bind(&identity.issuer)
    .bind(&identity.subject)
    .bind(identity.org)
    .fetch_optional(&mut *tx)
    .await?;
    match owner {
        Some(owner) => return Ok(owner == login_id),
        None => {
            insert_method(&mut tx, login_id, identity).await?;
        }
    }
    if let Some(org) = identity.org {
        join_through_sso(&mut tx, login_id, org).await?;
    }
    let actor = login_actor(&mut tx, login_id).await?;
    let () = audit::record(
        &mut tx,
        audit::Entry {
            actor: &actor,
            org_id: None,
            action: "method.link",
            subject: format!("login:{login_id}"),
            before: None,
            after: Some(json!({"method": identity.kind, "issuer": identity.issuer, "email": identity.email})),
        },
    )
    .await?;
    let () = tx.commit().await?;
    Ok(true)
}

/// One sign-in method as Account settings lists it.
pub(crate) struct MethodRow {
    pub id: i32,
    pub kind: String,
    pub email: String,
    pub linked: String,
}

impl MethodRow {
    pub(crate) fn label(&self) -> &'static str {
        match self.kind.as_str() {
            "password" => "Email and password",
            "google" => "Google",
            "github" => "GitHub",
            "microsoft" => "Microsoft",
            _ => "Company SSO",
        }
    }
}

pub(crate) async fn methods(pool: &PgPool, login_id: i32) -> Result<Vec<MethodRow>, sqlx::Error> {
    let rows: Vec<(i32, String, Option<String>, String)> = sqlx::query_as(
        "SELECT id, kind, email, to_char(created_at, 'DD Mon YYYY') FROM sign_in_methods
         WHERE login_id = $1 ORDER BY id",
    )
    .bind(login_id)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, kind, email, linked)| MethodRow {
            id,
            kind,
            email: email.unwrap_or_default(),
            linked,
        })
        .collect())
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Unlink {
    Done,
    /// Not a method of this login: the same answer for another login's and for none (C1).
    NotFound,
    /// The login's last method (C89).
    Last,
}

/// Removes one of the login's methods while another stays (C89). Every other session
/// of the login ends in the same transaction (02 § Data `sessions`).
pub(crate) async fn unlink_method(
    pool: &PgPool,
    session: &Session,
    login_id: i32,
    method_id: i32,
) -> Result<Unlink, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let methods: Vec<(i32, String, String, Option<String>)> = sqlx::query_as(
        "SELECT id, kind, issuer, email FROM sign_in_methods WHERE login_id = $1 ORDER BY id FOR UPDATE",
    )
    .bind(login_id)
    .fetch_all(&mut *tx)
    .await?;
    let Some((_, kind, issuer, email)) = methods.iter().find(|(id, ..)| *id == method_id) else {
        return Ok(Unlink::NotFound);
    };
    if methods.len() == 1 {
        return Ok(Unlink::Last);
    }
    sqlx::query("DELETE FROM sign_in_methods WHERE id = $1")
        .bind(method_id)
        .execute(&mut *tx)
        .await?;
    end_sessions(&mut tx, login_id, Some(&session.id_hash)).await?;
    let actor = login_actor(&mut tx, login_id).await?;
    let () = audit::record(
        &mut tx,
        audit::Entry {
            actor: &actor,
            org_id: None,
            action: "method.unlink",
            subject: format!("login:{login_id}"),
            before: Some(json!({"method": kind, "issuer": issuer, "email": email})),
            after: None,
        },
    )
    .await?;
    let () = tx.commit().await?;
    Ok(Unlink::Done)
}

// ---- The outbound client (T11) --------------------------------------------------------

/// The production `Outbound`: https only; no proxy; no redirects (a 3xx is an error);
/// the address is checked when the connection is made, so a name that resolves to a
/// loopback, private, link-local or otherwise non-public address is never connected to;
/// time and size caps on every call.
pub struct GuardedClient {
    client: reqwest::Client,
    allow_loopback: bool,
}

/// The largest answer read from an IdP or the range API.
const MAX_ANSWER_BYTES: usize = 1024 * 1024;

impl Default for GuardedClient {
    fn default() -> Self {
        GuardedClient::new()
    }
}

impl GuardedClient {
    pub fn new() -> GuardedClient {
        GuardedClient::build(false)
    }

    /// Also lets plain `http` reach loopback addresses, and nothing else; for tests of
    /// the guard's other rules (redirects) against a local server. Never used by the
    /// server.
    #[doc(hidden)]
    pub fn allowing_loopback_for_tests() -> GuardedClient {
        GuardedClient::build(true)
    }

    fn build(allow_loopback: bool) -> GuardedClient {
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .https_only(!allow_loopback)
            .connect_timeout(Duration::from_secs(2))
            .timeout(IDP_TIMEOUT)
            .dns_resolver(PublicOnly { allow_loopback })
            .user_agent("probation-server")
            .build()
            .expect("an HTTP client");
        GuardedClient {
            client,
            allow_loopback,
        }
    }

    /// Refuses a URL before any connection: not https, or an address literal that is
    /// not public. Names are checked by the resolver.
    fn admit(&self, url: &Url) -> Result<(), OutboundError> {
        let loopback_ok =
            |ip: std::net::IpAddr| self.allow_loopback && ip.to_canonical().is_loopback();
        match url.scheme() {
            "https" => {}
            "http" if self.allow_loopback => {}
            other => return Err(OutboundError::Refused(format!("scheme {other}"))),
        }
        let literal = match url.host() {
            Some(url::Host::Ipv4(ip)) => Some(std::net::IpAddr::V4(ip)),
            Some(url::Host::Ipv6(ip)) => Some(std::net::IpAddr::V6(ip)),
            Some(url::Host::Domain(_)) => None,
            None => return Err(OutboundError::Refused("no host".to_owned())),
        };
        match literal {
            Some(ip) if !is_public(ip) && !loopback_ok(ip) => {
                Err(OutboundError::Refused(format!("address {ip}")))
            }
            _ => Ok(()),
        }
    }

    async fn call(&self, builder: reqwest::RequestBuilder) -> Result<Vec<u8>, OutboundError> {
        let mut answer = match tokio::time::timeout(IDP_TIMEOUT, builder.send()).await {
            Err(_) => return Err(OutboundError::Timeout),
            Ok(Err(err)) => return Err(OutboundError::Transport(err.to_string())),
            Ok(Ok(answer)) => answer,
        };
        if !answer.status().is_success() {
            return Err(OutboundError::Status(answer.status().as_u16()));
        }
        let mut body = Vec::new();
        loop {
            let chunk = tokio::time::timeout(IDP_TIMEOUT, answer.chunk())
                .await
                .map_err(|_| OutboundError::Timeout)?
                .map_err(|err| OutboundError::Transport(err.to_string()))?;
            let Some(chunk) = chunk else {
                return Ok(body);
            };
            if body.len() + chunk.len() > MAX_ANSWER_BYTES {
                return Err(OutboundError::TooLarge);
            }
            body.extend_from_slice(&chunk);
        }
    }
}

#[async_trait::async_trait]
impl Outbound for GuardedClient {
    async fn get(&self, url: &Url, bearer: Option<&str>) -> Result<Vec<u8>, OutboundError> {
        self.admit(url)?;
        let mut builder = self
            .client
            .get(url.clone())
            .header("accept", "application/json");
        if let Some(token) = bearer {
            builder = builder.bearer_auth(token);
        }
        self.call(builder).await
    }

    async fn post_form(&self, url: &Url, form: &[(&str, &str)]) -> Result<Vec<u8>, OutboundError> {
        self.admit(url)?;
        let builder = self
            .client
            .post(url.clone())
            .header("accept", "application/json")
            .form(form);
        self.call(builder).await
    }
}

/// Resolves names to their public addresses only (T11).
struct PublicOnly {
    allow_loopback: bool,
}

impl reqwest::dns::Resolve for PublicOnly {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let allow_loopback = self.allow_loopback;
        Box::pin(async move {
            let found = tokio::net::lookup_host((name.as_str(), 0)).await?;
            let admitted: Vec<std::net::SocketAddr> = found
                .filter(|addr| {
                    is_public(addr.ip())
                        || (allow_loopback && addr.ip().to_canonical().is_loopback())
                })
                .collect();
            if admitted.is_empty() {
                return Err(format!("{} has no public address", name.as_str()).into());
            }
            Ok(Box::new(admitted.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// A globally routable unicast address: not loopback, private, shared (CGNAT),
/// link-local, unspecified, multicast, broadcast, documentation, benchmarking, reserved
/// or unique-local. IPv4-mapped IPv6 is judged as its IPv4 address.
pub(crate) fn is_public(ip: std::net::IpAddr) -> bool {
    match ip.to_canonical() {
        std::net::IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_documentation()
                || a == 0
                || a >= 240
                || (a == 100 && (64..128).contains(&b))
                || (a == 198 && (b == 18 || b == 19))
                || (a == 192 && b == 0 && c == 0))
        }
        std::net::IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (first & 0xfe00) == 0xfc00
                || (first & 0xffc0) == 0xfe80
                || (first == 0x2001 && v6.segments()[1] == 0x0db8)
                || first == 0x0064)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    /// N1: a hash whose caller is cancelled keeps its permit until Argon2id finishes, so
    /// cancelled requests never let more hashes run than there are permits.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_cancelled_hash_keeps_its_permit_until_it_finishes() {
        let params = argon2::Params::new(16 * 1024, 2, 1, None).unwrap();
        let passwords = super::Passwords::with_permits(params, 2);
        for _ in 0..6 {
            let verify = passwords.verify_blocking("a guess".to_owned(), None);
            let _ = tokio::time::timeout(Duration::from_millis(5), verify).await;
        }
        assert_eq!(
            passwords.permits.available_permits(),
            0,
            "both permits still held"
        );
        let deadline = Instant::now() + Duration::from_secs(60);
        while passwords.permits.available_permits() < 2 {
            assert!(Instant::now() < deadline, "the permits never came back");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    use super::is_public;

    #[test]
    fn only_global_addresses_are_public() {
        for refused in [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "0.0.0.0",
            "100.64.0.1",
            "192.0.2.1",
            "255.255.255.255",
            "::1",
            "fe80::1",
            "fd00::1",
            "::ffff:10.0.0.1",
            "::ffff:127.0.0.1",
            "2001:db8::1",
        ] {
            assert!(!is_public(refused.parse().unwrap()), "{refused}");
        }
        for allowed in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"] {
            assert!(is_public(allowed.parse().unwrap()), "{allowed}");
        }
    }
}

// ---- Deletion and restore (C33, C85, C90, C93, C94) ------------------------------------

/// How long a deleted login or personal account can be restored.
const RESTORE_DAYS: i32 = 30;

/// Where a login stands.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum LoginState {
    Live,
    /// Deleted and restorable until `until`.
    Deleted {
        on: String,
        until: String,
    },
    /// Deleted and past its 30 days: erased by the purge, or now.
    Expired,
}

pub(crate) async fn login_state(pool: &PgPool, login_id: i32) -> Result<LoginState, sqlx::Error> {
    let row: Option<(bool, bool, String, String)> = sqlx::query_as(
        "SELECT deleted_at IS NOT NULL, coalesce(restore_until > now(), false),
                coalesce(to_char(deleted_at, 'DD Mon YYYY'), ''), coalesce(to_char(restore_until, 'DD Mon YYYY'), '')
         FROM logins WHERE id = $1",
    )
    .bind(login_id)
    .fetch_optional(pool)
    .await?;
    Ok(match row {
        None => LoginState::Expired,
        Some((false, ..)) => LoginState::Live,
        Some((true, true, on, until)) => LoginState::Deleted { on, until },
        Some((true, false, ..)) => LoginState::Expired,
    })
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Deletion {
    Done,
    /// The login belongs to an organisation or has a personal account (C85, C93).
    NotOffered,
    /// It is the last global admin (C90).
    LastGlobalAdmin,
}

/// Locks the platform row and answers whether `login_id` is a global admin with no
/// other live one left: every path that ends a global admin's role recounts under that
/// lock (C90, T21).
pub(crate) async fn last_global_admin(
    conn: &mut PgConnection,
    login_id: i32,
) -> Result<bool, sqlx::Error> {
    sqlx::query("SELECT 1 FROM platform_settings WHERE id = 1 FOR UPDATE")
        .execute(&mut *conn)
        .await?;
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM memberships WHERE login_id = $1 AND org_id IS NULL)
            AND NOT EXISTS (SELECT 1 FROM memberships AS m JOIN logins AS l ON l.id = m.login_id
                            WHERE m.org_id IS NULL AND m.login_id <> $1 AND l.deleted_at IS NULL)",
    )
    .bind(login_id)
    .fetch_one(conn)
    .await
}

/// Writes `key` for every key the login owns, so each firewall drops them within one
/// interval; the lookup derives revoked or live from the login's state (02 § Change
/// propagation).
async fn change_owned_keys(conn: &mut PgConnection, login_id: i32) -> Result<(), sqlx::Error> {
    let keys: Vec<i64> =
        sqlx::query_scalar("SELECT id FROM keys WHERE owner_login = $1 ORDER BY id")
            .bind(login_id)
            .fetch_all(&mut *conn)
            .await?;
    for key in keys {
        record_change(conn, ChangeKind::Key, &KeyId(key as u64)).await?;
    }
    Ok(())
}

fn personal_place(id: i32) -> PlaceRef {
    PlaceRef {
        kind: LayerKind::Personal,
        id: id as u32,
    }
}

/// Marks the login deleted for 30 days, ends its sessions and writes `key` for its keys,
/// in the caller's transaction.
async fn mark_login_deleted(conn: &mut PgConnection, login_id: i32) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE logins SET deleted_at = now(), restore_until = now() + make_interval(days => $2)
         WHERE id = $1",
    )
    .bind(login_id)
    .bind(RESTORE_DAYS)
    .execute(&mut *conn)
    .await?;
    end_sessions(conn, login_id, None).await?;
    change_owned_keys(conn, login_id).await?;
    let actor = login_actor(conn, login_id).await?;
    // Its automation tokens and open global-admin links go with the login (C86, T3).
    crate::keys::revoke_tokens_of(conn, &actor, login_id, true).await?;
    sqlx::query(
        "DELETE FROM invitations WHERE created_by = $1 AND org_id IS NULL AND accepted_by IS NULL",
    )
    .bind(login_id)
    .execute(&mut *conn)
    .await?;
    audit::record(
        conn,
        audit::Entry {
            actor: &actor,
            org_id: None,
            action: "login.delete",
            subject: format!("login:{login_id}"),
            before: Some(json!({"deleted": false})),
            after: Some(json!({"deleted": true})),
        },
    )
    .await
}

async fn in_an_org(conn: &mut PgConnection, login_id: i32) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM memberships WHERE login_id = $1 AND org_id IS NOT NULL)",
    )
    .bind(login_id)
    .fetch_one(conn)
    .await
}

/// "Delete your login", offered only to a login with no personal account and no
/// organisation (C93), and never to the last global admin (C90).
pub(crate) async fn delete_login(pool: &PgPool, login_id: i32) -> Result<Deletion, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let has_personal: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM personal_accounts WHERE login_id = $1)")
            .bind(login_id)
            .fetch_one(&mut *tx)
            .await?;
    if has_personal || in_an_org(&mut tx, login_id).await? {
        return Ok(Deletion::NotOffered);
    }
    if last_global_admin(&mut tx, login_id).await? {
        return Ok(Deletion::LastGlobalAdmin);
    }
    mark_login_deleted(&mut tx, login_id).await?;
    let () = tx.commit().await?;
    Ok(Deletion::Done)
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PersonalDeletion {
    /// The personal account only: the login stays in its organisations.
    Account,
    /// The login belonged to no organisation, so it went too (C85).
    WithLogin,
    NotFound,
    LastGlobalAdmin,
}

/// Deletes the login's personal account for 30 days: `place` for it, and when the login
/// belongs to no organisation the login too, with `key` for its keys, all in one
/// transaction (C33, C85).
pub(crate) async fn delete_personal(
    pool: &PgPool,
    login_id: i32,
) -> Result<PersonalDeletion, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let personal: Option<i32> = sqlx::query_scalar(
        "SELECT id FROM personal_accounts WHERE login_id = $1 AND deleted_at IS NULL FOR UPDATE",
    )
    .bind(login_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(personal) = personal else {
        return Ok(PersonalDeletion::NotFound);
    };
    let with_login = !in_an_org(&mut tx, login_id).await?;
    if with_login && last_global_admin(&mut tx, login_id).await? {
        return Ok(PersonalDeletion::LastGlobalAdmin);
    }
    sqlx::query(
        "UPDATE personal_accounts SET deleted_at = now(), restore_until = now() + make_interval(days => $2)
         WHERE id = $1",
    )
    .bind(personal)
    .bind(RESTORE_DAYS)
    .execute(&mut *tx)
    .await?;
    record_change(&mut tx, ChangeKind::Place, &personal_place(personal)).await?;
    let actor = login_actor(&mut tx, login_id).await?;
    let () = audit::record(
        &mut tx,
        audit::Entry {
            actor: &actor,
            org_id: None,
            action: "personal.delete",
            subject: format!("personal:{personal}"),
            before: Some(json!({"deleted": false})),
            after: Some(json!({"deleted": true})),
        },
    )
    .await?;
    if with_login {
        mark_login_deleted(&mut tx, login_id).await?;
    }
    let () = tx.commit().await?;
    Ok(if with_login {
        PersonalDeletion::WithLogin
    } else {
        PersonalDeletion::Account
    })
}

/// The deleted personal account of a live login, while restorable: (deleted on,
/// erased on).
pub(crate) async fn deleted_personal(
    pool: &PgPool,
    login_id: i32,
) -> Result<Option<(String, String)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT to_char(deleted_at, 'DD Mon YYYY'), to_char(restore_until, 'DD Mon YYYY')
         FROM personal_accounts WHERE login_id = $1 AND deleted_at IS NOT NULL AND restore_until > now()",
    )
    .bind(login_id)
    .fetch_optional(pool)
    .await
}

pub(crate) async fn has_live_personal(pool: &PgPool, login_id: i32) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM personal_accounts WHERE login_id = $1 AND deleted_at IS NULL)",
    )
    .bind(login_id)
    .fetch_one(pool)
    .await
}

pub(crate) async fn belongs_to_org(pool: &PgPool, login_id: i32) -> Result<bool, sqlx::Error> {
    let mut conn = pool.acquire().await?;
    in_an_org(&mut conn, login_id).await
}

/// Restores a personal account within its 30 days, writing `place` for it.
pub(crate) async fn restore_personal(pool: &PgPool, login_id: i32) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let restored: Option<i32> = sqlx::query_scalar(
        "UPDATE personal_accounts SET deleted_at = NULL, restore_until = NULL
         WHERE login_id = $1 AND deleted_at IS NOT NULL AND restore_until > now() RETURNING id",
    )
    .bind(login_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(personal) = restored else {
        return Ok(false);
    };
    record_change(&mut tx, ChangeKind::Place, &personal_place(personal)).await?;
    let actor = login_actor(&mut tx, login_id).await?;
    let () = audit::record(
        &mut tx,
        audit::Entry {
            actor: &actor,
            org_id: None,
            action: "personal.restore",
            subject: format!("personal:{personal}"),
            before: Some(json!({"deleted": true})),
            after: Some(json!({"deleted": false})),
        },
    )
    .await?;
    let () = tx.commit().await?;
    Ok(true)
}

/// "Restore login" (C94): the login, and a personal account deleted with it, come back;
/// `key` for its keys and `place` for that account, in one transaction.
pub(crate) async fn restore_login(pool: &PgPool, login_id: i32) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let deleted_at: Option<String> = sqlx::query_scalar(
        "SELECT deleted_at::text FROM logins
         WHERE id = $1 AND deleted_at IS NOT NULL AND restore_until > now() FOR UPDATE",
    )
    .bind(login_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(deleted_at) = deleted_at else {
        return Ok(false);
    };
    sqlx::query("UPDATE logins SET deleted_at = NULL, restore_until = NULL WHERE id = $1")
        .bind(login_id)
        .execute(&mut *tx)
        .await?;
    let with_it: Vec<i32> = sqlx::query_scalar(
        "UPDATE personal_accounts SET deleted_at = NULL, restore_until = NULL
         WHERE login_id = $1 AND deleted_at = $2::timestamptz RETURNING id",
    )
    .bind(login_id)
    .bind(&deleted_at)
    .fetch_all(&mut *tx)
    .await?;
    for personal in with_it {
        record_change(&mut tx, ChangeKind::Place, &personal_place(personal)).await?;
    }
    change_owned_keys(&mut tx, login_id).await?;
    let actor = login_actor(&mut tx, login_id).await?;
    let () = audit::record(
        &mut tx,
        audit::Entry {
            actor: &actor,
            org_id: None,
            action: "login.restore",
            subject: format!("login:{login_id}"),
            before: Some(json!({"deleted": true})),
            after: Some(json!({"deleted": false})),
        },
    )
    .await?;
    let () = tx.commit().await?;
    Ok(true)
}

/// A global admin deletes a personal account (C65): a `place` row stops its keys within
/// one interval, and it stays restorable for 30 days; the login stays.
pub(crate) async fn admin_delete_personal(
    pool: &PgPool,
    actor: &Actor,
    personal: &tenancy::Authorized<tenancy::Place>,
) -> Result<(), tenancy::ChangeError> {
    if personal.place().kind != LayerKind::Personal
        || actor.role(personal.place()) != Some(tenancy::Role::GlobalAdmin)
    {
        return Err(tenancy::ChangeError::Denied);
    }
    let id = personal.place().id as i32;
    let mut tx = pool.begin().await?;
    let deleted = sqlx::query(
        "UPDATE personal_accounts SET deleted_at = now(), restore_until = now() + make_interval(days => $2)
         WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(id)
    .bind(RESTORE_DAYS)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if deleted == 0 {
        return Err(tenancy::ChangeError::NotFound);
    }
    record_change(&mut tx, ChangeKind::Place, &personal_place(id)).await?;
    let () = audit::record(
        &mut tx,
        audit::Entry {
            actor,
            org_id: None,
            action: "personal.delete",
            subject: format!("personal:{id}"),
            before: Some(json!({"deleted": false})),
            after: Some(json!({"deleted": true})),
        },
    )
    .await?;
    let () = tx.commit().await?;
    Ok(())
}

/// A global admin restores a deleted personal account within its 30 days, whoever
/// deleted it (C33, C65): a `place` row lets its keys work again within one interval.
pub(crate) async fn admin_restore_personal(
    pool: &PgPool,
    actor: &Actor,
    id: i32,
) -> Result<(), tenancy::ChangeError> {
    if !actor.is_global_admin() {
        return Err(tenancy::ChangeError::Denied);
    }
    let mut tx = pool.begin().await?;
    let restored = sqlx::query(
        "UPDATE personal_accounts AS p SET deleted_at = NULL, restore_until = NULL
         FROM logins AS l
         WHERE p.id = $1 AND l.id = p.login_id AND l.deleted_at IS NULL
           AND p.deleted_at IS NOT NULL AND p.restore_until > now()",
    )
    .bind(id)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if restored == 0 {
        return Err(tenancy::ChangeError::NotFound);
    }
    record_change(&mut tx, ChangeKind::Place, &personal_place(id)).await?;
    let () = audit::record(
        &mut tx,
        audit::Entry {
            actor,
            org_id: None,
            action: "personal.restore",
            subject: format!("personal:{id}"),
            before: Some(json!({"deleted": true})),
            after: Some(json!({"deleted": false})),
        },
    )
    .await?;
    let () = tx.commit().await?;
    Ok(())
}

/// A global admin resets the authenticator of a personal account's login (C39, C65):
/// its authenticator, backup codes and sessions go, with the audit row.
pub(crate) async fn admin_reset_totp(
    pool: &PgPool,
    actor: &Actor,
    personal: &tenancy::Authorized<tenancy::Place>,
) -> Result<(), tenancy::ChangeError> {
    let Some(login) = personal
        .owner_login()
        .filter(|_| actor.role(personal.place()) == Some(tenancy::Role::GlobalAdmin))
    else {
        return Err(tenancy::ChangeError::Denied);
    };
    let mut tx = pool.begin().await?;
    let removed = sqlx::query("DELETE FROM totp WHERE login_id = $1")
        .bind(login)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    sqlx::query("DELETE FROM backup_codes WHERE login_id = $1")
        .bind(login)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM sessions WHERE login_id = $1")
        .bind(login)
        .execute(&mut *tx)
        .await?;
    let () = audit::record(
        &mut tx,
        audit::Entry {
            actor,
            org_id: None,
            action: "totp.reset",
            subject: format!("login:{login}"),
            before: Some(json!({"totp": if removed > 0 { "on" } else { "off" }})),
            after: Some(json!({"totp": "off"})),
        },
    )
    .await?;
    let () = tx.commit().await?;
    Ok(())
}

/// Erases a personal account's data: its keys (with their activity), its layer and the
/// account itself. Its keys were already reported revoked when it was deleted.
async fn erase_personal(conn: &mut PgConnection, personal: i32) -> Result<(), sqlx::Error> {
    sqlx::query(
        "DELETE FROM activity WHERE key_id IN (SELECT id FROM keys WHERE place_kind = 'personal' AND place_id = $1)
            OR (place_kind = 'personal' AND place_id = $1)",
    )
    .bind(personal)
    .execute(&mut *conn)
    .await?;
    sqlx::query("DELETE FROM keys WHERE place_kind = 'personal' AND place_id = $1")
        .bind(personal)
        .execute(&mut *conn)
        .await?;
    sqlx::query("DELETE FROM policy_layers WHERE place_kind = 'personal' AND place_id = $1")
        .bind(personal)
        .execute(&mut *conn)
        .await?;
    sqlx::query("DELETE FROM personal_accounts WHERE id = $1")
        .bind(personal)
        .execute(conn)
        .await
        .map(drop)
}

/// Erases a login whose 30 days have passed, when it is found before the purge runs.
pub(crate) async fn erase_expired(pool: &PgPool, login_id: i32) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    let expired: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM logins WHERE id = $1 AND deleted_at IS NOT NULL AND restore_until <= now())",
    )
    .bind(login_id)
    .fetch_one(&mut *tx)
    .await?;
    if expired {
        erase_login(&mut tx, login_id).await?;
    }
    tx.commit().await
}

/// Erases a deleted login for good, with its personal account; its methods, sessions
/// and memberships go with the row. The audit log keeps its rows (C33).
async fn erase_login(conn: &mut PgConnection, login_id: i32) -> Result<(), sqlx::Error> {
    let personal: Option<i32> =
        sqlx::query_scalar("SELECT id FROM personal_accounts WHERE login_id = $1")
            .bind(login_id)
            .fetch_optional(&mut *conn)
            .await?;
    if let Some(personal) = personal {
        erase_personal(conn, personal).await?;
    }
    sqlx::query("DELETE FROM logins WHERE id = $1")
        .bind(login_id)
        .execute(conn)
        .await
        .map(drop)
}

/// A method moving to a new login: kind, issuer, subject, organisation, email,
/// password hash, and whether its address was confirmed.
type MovedMethod = (
    String,
    String,
    String,
    Option<i32>,
    Option<String>,
    Option<String>,
    bool,
);

/// "Start a new login instead" (C94): erases the deleted login now and signs `identity`
/// in to a new login with that method; an email-and-password method keeps its address
/// and password. Returns the new login, or `None` when the old one is not deleted.
pub(crate) async fn start_new_login(
    pool: &PgPool,
    old_login: i32,
    method_id: i32,
) -> Result<Option<i32>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let method: Option<MovedMethod> = sqlx::query_as(
        "SELECT m.kind, m.issuer, m.subject, m.org_id, m.email, m.password_hash, m.verified_at IS NOT NULL
         FROM sign_in_methods AS m JOIN logins AS l ON l.id = m.login_id
         WHERE m.id = $1 AND m.login_id = $2 AND l.deleted_at IS NOT NULL FOR UPDATE OF l",
    )
    .bind(method_id)
    .bind(old_login)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((kind, issuer, subject, org, email, hash, verified)) = method else {
        return Ok(None);
    };
    // The removals of the erased login go with it (C130).
    erase_login(&mut tx, old_login).await?;
    let login: i32 = sqlx::query_scalar("INSERT INTO logins DEFAULT VALUES RETURNING id")
        .fetch_one(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO sign_in_methods (login_id, kind, issuer, subject, org_id, email, password_hash, verified_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, CASE WHEN $8 THEN now() END)",
    )
    .bind(login)
    .bind(&kind)
    .bind(&issuer)
    .bind(&subject)
    .bind(org)
    .bind(&email)
    .bind(&hash)
    .bind(verified)
    .execute(&mut *tx)
    .await?;
    if let Some(org) = org {
        join_through_sso(&mut tx, login, org).await?;
    }
    let actor = login_actor(&mut tx, login).await?;
    let () = audit::record(
        &mut tx,
        audit::Entry {
            actor: &actor,
            org_id: None,
            action: "login.erase",
            subject: format!("login:{old_login}"),
            before: Some(json!({"deleted": true})),
            after: Some(json!({"erased": true, "new_login": login})),
        },
    )
    .await?;
    let () = tx.commit().await?;
    Ok(Some(login))
}

/// The daily purge (C33): erases logins, personal accounts and organisations whose 30
/// days have passed, each in its own transaction, so one that cannot be erased is logged
/// and does not hold back the others. Returns how many logins, personal accounts and
/// organisations it erased.
pub async fn purge(pool: &PgPool) -> Result<(u64, u64, u64), sqlx::Error> {
    let logins: Vec<i32> = sqlx::query_scalar(
        "SELECT id FROM logins WHERE deleted_at IS NOT NULL AND restore_until <= now()",
    )
    .fetch_all(pool)
    .await?;
    let mut erased = (0, 0, 0);
    for login in logins {
        match erase_expired(pool, login).await {
            Ok(()) => erased.0 += 1,
            Err(err) => tracing::error!(login, error = %err, "purge could not erase a login"),
        }
    }
    let accounts: Vec<i32> = sqlx::query_scalar(
        "SELECT id FROM personal_accounts WHERE deleted_at IS NOT NULL AND restore_until <= now()",
    )
    .fetch_all(pool)
    .await?;
    for personal in accounts {
        let erase = async {
            let mut tx = pool.begin().await?;
            erase_personal(&mut tx, personal).await?;
            tx.commit().await
        };
        match erase.await {
            Ok(()) => erased.1 += 1,
            Err(err) => {
                tracing::error!(personal, error = %err, "purge could not erase a personal account")
            }
        }
    }
    let orgs: Vec<i32> = sqlx::query_scalar(
        "SELECT id FROM orgs WHERE deleted_at IS NOT NULL AND restore_until <= now()",
    )
    .fetch_all(pool)
    .await?;
    for org in orgs {
        let erase = async {
            let mut tx = pool.begin().await?;
            let erased = tenancy::erase_org(&mut tx, org).await?;
            tx.commit().await.map(|()| erased)
        };
        match erase.await {
            Ok(true) => erased.2 += 1,
            Ok(false) => {}
            Err(err) => tracing::error!(org, error = %err, "purge could not erase an organisation"),
        }
    }
    // Expired sessions and old sign-in failures go too.
    sqlx::query("DELETE FROM sessions WHERE expires_at < now()")
        .execute(pool)
        .await?;
    sqlx::query("DELETE FROM sign_in_failures WHERE at < now() - interval '1 day'")
        .execute(pool)
        .await?;
    Ok(erased)
}

// ---- Mail and the background jobs ------------------------------------------------------

/// SMTP through the relay in `[portal.smtp]` (STARTTLS), password from
/// `PROBATION_SERVER_SMTP_PASSWORD`.
pub struct SmtpMailer {
    transport: lettre::AsyncSmtpTransport<lettre::Tokio1Executor>,
    from: lettre::message::Mailbox,
}

impl SmtpMailer {
    pub fn new(
        host: &str,
        port: u16,
        username: Option<&str>,
        password: &str,
        from: &str,
    ) -> Result<SmtpMailer, String> {
        let mut builder =
            lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::starttls_relay(host)
                .map_err(|err| format!("portal.smtp.host: {err}"))?
                .port(port)
                .timeout(Some(MAIL_TIMEOUT));
        if let Some(username) = username {
            builder =
                builder.credentials(lettre::transport::smtp::authentication::Credentials::new(
                    username.to_owned(),
                    password.to_owned(),
                ));
        }
        Ok(SmtpMailer {
            transport: builder.build(),
            from: from
                .parse()
                .map_err(|err| format!("portal.smtp.from: {err}"))?,
        })
    }
}

#[async_trait::async_trait]
impl Mailer for SmtpMailer {
    async fn deliver(&self, mail: &Mail) -> Result<(), String> {
        use lettre::AsyncTransport;
        let to = mail.to.parse().map_err(|err| format!("recipient: {err}"))?;
        let message = lettre::Message::builder()
            .from(self.from.clone())
            .to(to)
            .subject(&mail.subject)
            .header(lettre::message::header::ContentType::TEXT_PLAIN)
            .body(mail.body.clone())
            .map_err(|err| err.to_string())?;
        match tokio::time::timeout(MAIL_TIMEOUT, self.transport.send(message)).await {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(err)) => Err(err.to_string()),
            Err(_) => Err("timed out".to_owned()),
        }
    }
}

/// The portal's background work: the outbox every 30 seconds (when SMTP is set) and the
/// daily purge (C33).
pub fn spawn_jobs(pool: PgPool, mailer: Option<Arc<dyn Mailer>>) {
    if let Some(mailer) = mailer {
        let outbox = pool.clone();
        tokio::spawn(async move {
            let mut every = tokio::time::interval(Duration::from_secs(30));
            loop {
                every.tick().await;
                if let Err(err) = deliver_outbox(&outbox, &mailer).await {
                    tracing::warn!(error = %err, "outbox run failed");
                }
            }
        });
    } else {
        tracing::warn!("[portal.smtp] is not set: mail stays in the outbox");
    }
    tokio::spawn(async move {
        let mut every_day = tokio::time::interval(Duration::from_secs(24 * 3600));
        loop {
            every_day.tick().await;
            match purge(&pool).await {
                Ok((logins, personal, orgs)) => {
                    tracing::info!(logins, personal, orgs, "purge erased")
                }
                Err(err) => tracing::warn!(error = %err, "purge failed"),
            }
        }
    });
}
