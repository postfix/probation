//! The self-service portal: server-rendered pages (askama, autoescaped) behind a
//! session cookie, with a CSRF token on every form (C101) and the CSP header on every
//! answer (T13). One route group per mockup: sign-in and account in slice 5; keys, policy,
//! activity, organisation and audit log in slice 6; global admin and fleet in slice 7.

mod account;
mod activity;
mod admin;
mod audit;
mod fleet;
mod keys;
mod organisation;
mod policy;
mod signin;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use askama::Template;
use axum::Router;
use axum::extract::{Form, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE, COOKIE, LOCATION, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{MethodRouter, get, post};
use ipnet::IpNet;
use serde::Deserialize;
use sqlx::PgPool;
use url::Url;

use crate::accounts::{self, Mailer, Outbound, Passwords};
use crate::tenancy::{self, Authorized, Place, Tenancy};

/// `[portal]` in the server's settings file. Client secrets come from the environment
/// (02 § External), never from this file.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortalConfig {
    /// The portal's public URL: every emailed link is built from it (T14).
    pub base_url: Url,
    #[serde(default)]
    pub google: Option<ProviderConfig>,
    #[serde(default)]
    pub github: Option<ProviderConfig>,
    #[serde(default)]
    pub microsoft: Option<ProviderConfig>,
    /// The k-anonymity range API (T29).
    #[serde(default = "default_leaked_password_url")]
    pub leaked_password_url: Url,
    #[serde(default)]
    pub smtp: Option<SmtpConfig>,
    /// The firewalls' address as clients reach it (`https://packages.example.org`): the
    /// `.npmrc` and `pip.conf` lines on the keys page are built from it. Unset, they
    /// show a `FIREWALL` placeholder.
    #[serde(default)]
    pub firewall_url: Option<Url>,
}

fn default_leaked_password_url() -> Url {
    Url::parse("https://api.pwnedpasswords.com/range/").expect("a URL")
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfig {
    pub client_id: String,
    /// From `PROBATION_SERVER_<PROVIDER>_CLIENT_SECRET`.
    #[serde(skip)]
    pub client_secret: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SmtpConfig {
    pub host: String,
    #[serde(default = "default_smtp_port")]
    pub port: u16,
    /// Signs in with `PROBATION_SERVER_SMTP_PASSWORD` when set.
    #[serde(default)]
    pub username: Option<String>,
    pub from: String,
}

fn default_smtp_port() -> u16 {
    587
}

/// What the portal is built from; tests pass fakes for mail and the network.
pub struct PortalDeps {
    pub pool: PgPool,
    pub config: PortalConfig,
    pub outbound: Arc<dyn Outbound>,
    /// SMTP for the outbox job; `None` when `[portal.smtp]` is not set.
    pub mailer: Option<Arc<dyn Mailer>>,
    /// `PROBATION_SERVER_SECRET_KEY`: seals secrets at rest (T16).
    pub secret_key: [u8; 32],
    pub password_params: argon2::Params,
    /// `[server] trusted_proxies`: whose `X-Forwarded-For` names the client (T32).
    pub trusted_proxies: Vec<IpNet>,
}

pub struct Portal {
    pool: PgPool,
    config: PortalConfig,
    outbound: Arc<dyn Outbound>,
    passwords: Passwords,
    secrets: accounts::SecretBox,
    trusted_proxies: Vec<IpNet>,
}

/// A sign-in provider shown on the pages: only the configured ones.
pub(crate) struct Provider {
    pub name: &'static str,
    pub label: &'static str,
}

impl Portal {
    /// Starts the portal's jobs (outbox, purge) and answers its routes.
    pub fn launch(deps: PortalDeps) -> Router {
        accounts::spawn_jobs(deps.pool.clone(), deps.mailer.clone());
        router(Arc::new(Portal::new(deps)))
    }

    pub fn new(deps: PortalDeps) -> Portal {
        Portal {
            pool: deps.pool,
            config: deps.config,
            outbound: deps.outbound,
            passwords: Passwords::new(deps.password_params),
            secrets: accounts::SecretBox::new(deps.secret_key),
            trusted_proxies: deps.trusted_proxies,
        }
    }
}

type Shared = Arc<Portal>;

/// Builds the router and its route table from the same calls, so tests that walk every
/// route (T-portal-csrf, T-cross-tenant-routes-accounts) read the real table.
struct Routes {
    router: Router<Shared>,
    table: Vec<(&'static str, &'static str)>,
}

impl Routes {
    fn get(mut self, path: &'static str, handler: MethodRouter<Shared>) -> Routes {
        self.table.push(("GET", path));
        self.router = self.router.route(path, handler);
        self
    }

    fn post(mut self, path: &'static str, handler: MethodRouter<Shared>) -> Routes {
        self.table.push(("POST", path));
        self.router = self.router.route(path, handler);
        self
    }
}

fn routes() -> Routes {
    Routes {
        router: Router::new(),
        table: Vec::new(),
    }
    .get("/static/portal.css", get(stylesheet))
    .get("/", get(home))
    .get("/signin", get(signin::signin_form))
    .post("/signin", post(signin::signin))
    .post("/signout", post(signin::signout))
    .get("/oauth/{provider}/start", get(signin::oauth_start))
    .get("/oauth/{provider}/callback", get(signin::oauth_callback))
    .get("/deleted", get(signin::deleted_form))
    .post("/deleted/restore", post(signin::deleted_restore))
    .post("/deleted/new", post(signin::deleted_new))
    .get("/o", get(signin::org_typed))
    .get("/o/{org}", get(signin::org_link))
    .get("/sso/{org}/start", get(signin::sso_start))
    .get("/sso/{org}/callback", get(signin::sso_callback))
    .get("/totp", get(signin::totp_form))
    .post("/totp", post(signin::totp))
    .get("/reset", get(signin::reset_form))
    .post("/reset", post(signin::reset))
    .get("/reset/confirm", get(signin::reset_confirm_form))
    .post("/reset/confirm", post(signin::reset_confirm))
    .get("/signup", get(signin::signup_form))
    .post("/signup", post(signin::signup))
    .get("/verify-email", get(signin::verify_email))
    .post("/verify-email/resend", post(signin::resend))
    .get("/account", get(account::show))
    .post("/account/link/{provider}", post(account::link))
    .post("/account/methods/{id}/remove", post(account::unlink))
    .post("/account/password", post(account::change_password))
    .post("/account/personal", post(account::add_personal))
    .post("/account/personal/delete", post(account::delete_personal))
    .post("/account/personal/restore", post(account::restore_personal))
    .post("/account/delete", post(account::delete_login))
    .post("/account/org", post(account::add_org))
    .post("/account/totp/setup", post(account::totp_setup))
    .post("/account/totp/enable", post(account::totp_enable))
    .post("/account/totp/disable", post(account::totp_disable))
    .get("/account/totp/qr.svg", get(account::totp_qr))
    .post("/place", post(choose_place))
    .get("/keys", get(keys::show))
    .post("/keys", post(keys::create))
    .post("/keys/service", post(keys::create_service))
    .post("/keys/{id}/revoke", post(keys::revoke))
    .get("/policy", get(policy::start))
    .get("/policy/{id}", get(policy::show))
    .post("/policy/{id}", post(policy::edit))
    .get("/activity", get(activity::show))
    .get("/audit", get(audit::show))
    .get("/org", get(organisation::start))
    .get("/org/{org}", get(organisation::show))
    .post("/org/members/{id}/group", post(organisation::move_member))
    .post("/org/members/{id}/role", post(organisation::set_role))
    .post(
        "/org/members/{id}/remove",
        post(organisation::remove_member),
    )
    .post(
        "/org/members/{id}/totp-reset",
        post(organisation::reset_totp),
    )
    .post("/org/{id}/leave", post(organisation::ask_to_leave))
    .post("/org/{id}/leave/cancel", post(organisation::cancel_leave))
    .post("/org/leave/{id}/approve", post(organisation::approve_leave))
    .post("/org/leave/{id}/refuse", post(organisation::refuse_leave))
    .post("/org/{id}/invitations", post(organisation::invite))
    .post(
        "/org/invitations/{id}/cancel",
        post(organisation::cancel_invitation),
    )
    .post("/org/{id}/sso", post(organisation::save_sso))
    .post("/org/{id}/ranges", post(organisation::add_range))
    .post("/org/ranges/{id}/delete", post(organisation::delete_range))
    .post(
        "/org/ranges/{id}/resubmit",
        post(organisation::resubmit_range),
    )
    .post("/org/{id}/delete", post(organisation::delete_org))
    .post("/org/{id}/restore", post(organisation::restore_org))
    .get("/invite", get(organisation::invitation))
    .post("/invite", post(organisation::accept_invitation))
    .post("/org/{id}/groups", post(organisation::create_group))
    .post("/org/groups/{id}/rename", post(organisation::rename_group))
    .get(
        "/org/groups/{id}/delete",
        get(organisation::confirm_delete_group),
    )
    .post("/org/groups/{id}/delete", post(organisation::delete_group))
    .post("/org/{id}/automation", post(organisation::create_token))
    .post(
        "/org/{id}/automation/revoke",
        post(organisation::revoke_token),
    )
    .get("/org/{id}/blocklist", get(organisation::export_blocklist))
    .post("/org/{id}/blocklist", post(organisation::import_blocklist))
    .get("/admin", get(admin::show))
    .get("/admin/orgs/{id}/suspend", get(admin::confirm_suspend_org))
    .post("/admin/orgs/{id}/suspend", post(admin::suspend_org))
    .post("/admin/orgs/{id}/activate", post(admin::activate_org))
    .post(
        "/admin/personal/{id}/suspend",
        post(admin::suspend_personal),
    )
    .post(
        "/admin/personal/{id}/activate",
        post(admin::activate_personal),
    )
    .get(
        "/admin/personal/{id}/revoke-keys",
        get(admin::confirm_revoke_keys),
    )
    .post("/admin/personal/{id}/revoke-keys", post(admin::revoke_keys))
    .post("/admin/personal/{id}/totp-reset", post(admin::reset_totp))
    .get(
        "/admin/personal/{id}/delete",
        get(admin::confirm_delete_personal),
    )
    .post("/admin/personal/{id}/delete", post(admin::delete_personal))
    .post(
        "/admin/personal/{id}/restore",
        post(admin::restore_personal),
    )
    .post("/admin/ranges/{id}/approve", post(admin::approve_range))
    .post("/admin/ranges/{id}/refuse", post(admin::refuse_range))
    .post("/admin/ranges/{id}/delete", post(admin::delete_range))
    .post("/admin/admins/invite", post(admin::invite_admin))
    .post("/admin/admins/{id}/remove", post(admin::remove_admin))
    .post("/admin/limits", post(admin::save_limits))
    .post("/admin/limits/orgs/{id}", post(admin::save_org_limits))
    .post(
        "/admin/limits/orgs/{id}/reset",
        post(admin::reset_org_limits),
    )
    .post("/admin/retention", post(admin::save_retention))
    .post("/admin/tokens", post(admin::create_token))
    .post("/admin/tokens/{id}/revoke", post(admin::revoke_token))
    .get("/admin/blocklist", get(admin::export_blocklist))
    .post("/admin/blocklist", post(admin::import_blocklist))
    .get("/fleet", get(fleet::show))
    .post("/fleet/register", post(fleet::register))
    .post("/fleet/settings", post(fleet::push_settings))
    .post("/fleet/{id}/retire", post(fleet::retire))
    .post("/fleet/rollouts/{id}/resume", post(fleet::resume))
    .post("/fleet/rollouts/{id}/skip", post(fleet::skip))
}

/// Every portal route as (method, path pattern).
pub fn route_table() -> Vec<(&'static str, &'static str)> {
    routes().table
}

/// The portal's routes. Serve them with connect info: sign-in throttling reads the
/// client address (T32).
pub fn router(portal: Shared) -> Router {
    routes()
        .router
        .layer(axum::middleware::from_fn_with_state(
            portal.clone(),
            confirm_first,
        ))
        .layer(axum::middleware::map_response(security_headers))
        .with_state(portal)
}

/// A signed-in login whose address is not confirmed reaches only `/verify-email` and
/// `/signout`; everything else redirects there (C41).
async fn confirm_first(
    State(portal): State<Shared>,
    headers: HeaderMap,
    incoming: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let path = incoming.uri().path();
    let exempt =
        path.starts_with("/verify-email") || path == "/signout" || path.starts_with("/static/");
    if !exempt {
        let unconfirmed = async {
            match portal.session(&headers).await? {
                Some(accounts::Session {
                    login_id: Some(login),
                    ..
                }) => Ok(accounts::unconfirmed_email(&portal.pool, login)
                    .await?
                    .is_some()),
                _ => Ok::<_, sqlx::Error>(false),
            }
        }
        .await;
        match unconfirmed {
            Ok(true) => return redirect("/verify-email"),
            Ok(false) => {}
            Err(err) => return unavailable(err),
        }
    }
    next.run(incoming).await
}

/// `/`: the account page when signed in, else sign-in.
async fn home(State(portal): State<Shared>, headers: HeaderMap) -> Response {
    match portal.session(&headers).await {
        Ok(Some(accounts::Session {
            login_id: Some(_), ..
        })) => redirect("/account"),
        Ok(_) => redirect("/signin"),
        Err(err) => unavailable(err),
    }
}

/// On every portal answer: the CSP (T13), no framing, no caching of pages that carry a
/// CSRF token, and no referrer, so a link token never leaves in one.
async fn security_headers(mut answer: Response) -> Response {
    let headers = answer.headers_mut();
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static("default-src 'self'; frame-ancestors 'none'"),
    );
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    answer
}

async fn stylesheet() -> Response {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/css; charset=utf-8"),
        )],
        include_str!("../../static/portal.css"),
    )
        .into_response()
}

/// The top bar of a signed-in page.
pub(crate) struct Top {
    pub name: String,
    /// The switcher's places (C29): (label, value, selected).
    pub places: Vec<(String, String, bool)>,
    pub csrf: String,
    /// The page the navigation marks current: "account", "keys", "policy", "activity",
    /// "org", "audit", "admin" or "fleet".
    pub page: &'static str,
    /// A global admin's session: the navigation links `/admin` and `/fleet`.
    pub admin: bool,
    /// "organisation" or "personal account" when the chosen place is suspended: the
    /// read-only banner (C64).
    pub suspended: Option<&'static str>,
}

pub(crate) fn render(status: StatusCode, page: &impl Template) -> Response {
    match page.render() {
        Ok(html) => (status, Html(html)).into_response(),
        Err(err) => {
            tracing::error!(error = %err, "a portal template failed to render");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

pub(crate) fn redirect(to: &str) -> Response {
    (
        StatusCode::SEE_OTHER,
        [(LOCATION, HeaderValue::from_str(to).expect("a path"))],
    )
        .into_response()
}

/// A store failure: logged, and a plain 503 page.
pub(crate) fn unavailable(err: sqlx::Error) -> Response {
    tracing::error!(error = %err, "portal request failed in the store");
    (
        StatusCode::SERVICE_UNAVAILABLE,
        "The portal is unavailable. Try again shortly.",
    )
        .into_response()
}

/// 404: the same page for another tenant's id and an unknown one (C1).
pub(crate) fn not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        Html("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Not found · Probation</title></head><body><main><h1>Not found</h1><p><a href=\"/account\">Account settings</a></p></main></body></html>"),
    )
        .into_response()
}

/// A refused action: 403 with a short page saying why.
pub(crate) fn refused(message: &str) -> Response {
    #[derive(Template)]
    #[template(
        source = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Not allowed · Probation</title><link rel=\"stylesheet\" href=\"/static/portal.css\"></head><body><main id=\"main\"><h1>Not allowed</h1><p class=\"err\" role=\"alert\">{{ message }}</p><p><a href=\"/account\">Back to Account settings</a></p></main></body></html>",
        ext = "html"
    )]
    struct Refused<'a> {
        message: &'a str,
    }
    let mut answer = render(StatusCode::FORBIDDEN, &Refused { message });
    *answer.status_mut() = StatusCode::FORBIDDEN;
    answer
}

/// The answer to a POST whose CSRF token is missing or not the session's: 403, and
/// nothing is written (C101).
fn forbidden() -> Response {
    (
        StatusCode::FORBIDDEN,
        Html("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Forbidden · Probation</title></head><body><main><h1>This form has expired</h1><p>Reload the page and try again.</p></main></body></html>"),
    )
        .into_response()
}

const COOKIE_NAME: &str = "probation_session";

/// The session token the browser sent, if any.
fn cookie_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(name, _)| *name == COOKIE_NAME)
        .map(|(_, value)| value.to_owned())
}

/// The cookie for a new session: `Secure` and `HttpOnly` (C101), `Lax` so an IdP's
/// redirect back still carries it.
pub(crate) fn session_cookie(token: &str) -> HeaderValue {
    HeaderValue::from_str(&format!(
        "{COOKIE_NAME}={token}; Path=/; Secure; HttpOnly; SameSite=Lax"
    ))
    .expect("a cookie")
}

pub(crate) fn cleared_cookie() -> HeaderValue {
    HeaderValue::from_str(&format!(
        "{COOKIE_NAME}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0"
    ))
    .expect("a cookie")
}

pub(crate) fn with_cookie(mut answer: Response, cookie: Option<HeaderValue>) -> Response {
    if let Some(cookie) = cookie {
        answer.headers_mut().append(SET_COOKIE, cookie);
    }
    answer
}

impl Portal {
    /// A platform provider by its name in `/oauth/{provider}/…`, when configured.
    fn idp(&self, provider: &str) -> Option<accounts::Idp> {
        let (kind, config) = match provider {
            "google" => (accounts::IdpKind::Google, self.config.google.as_ref()?),
            "github" => (accounts::IdpKind::Github, self.config.github.as_ref()?),
            "microsoft" => (
                accounts::IdpKind::Microsoft,
                self.config.microsoft.as_ref()?,
            ),
            _ => return None,
        };
        Some(accounts::Idp {
            kind,
            client_id: config.client_id.clone(),
            client_secret: config.client_secret.clone(),
            redirect_uri: self.link(&format!("oauth/{provider}/callback")),
        })
    }

    /// The platform providers configured, in the mockup's order.
    pub(crate) fn providers(&self) -> Vec<Provider> {
        [
            (self.config.google.is_some(), "google", "Google"),
            (self.config.github.is_some(), "github", "GitHub"),
            (self.config.microsoft.is_some(), "microsoft", "Microsoft"),
        ]
        .into_iter()
        .filter(|(configured, ..)| *configured)
        .map(|(_, name, label)| Provider { name, label })
        .collect()
    }

    /// An organisation's SSO, when it has one.
    async fn sso(&self, org: i32) -> Result<Option<accounts::Idp>, sqlx::Error> {
        let redirect_uri = self.link(&format!("sso/{org}/callback"));
        accounts::sso_idp(&self.pool, &self.secrets, org, redirect_uri).await
    }

    /// `path` on the configured base URL (T14).
    fn link(&self, path: &str) -> Url {
        Url::parse(&format!(
            "{}{path}",
            accounts::base_path(&self.config.base_url)
        ))
        .expect("a URL")
    }

    async fn session(&self, headers: &HeaderMap) -> Result<Option<accounts::Session>, sqlx::Error> {
        match cookie_token(headers) {
            Some(token) => accounts::load_session(&self.pool, &token).await,
            None => Ok(None),
        }
    }

    /// The visitor's session, or a new signed-out one with its cookie, for a page that
    /// shows a form.
    async fn visit(
        &self,
        headers: &HeaderMap,
    ) -> Result<(accounts::Session, Option<HeaderValue>), sqlx::Error> {
        if let Some(session) = self.session(headers).await? {
            return Ok((session, None));
        }
        let (session, token) = accounts::open_session(&self.pool, None, false, None, None).await?;
        Ok((session, Some(session_cookie(&token))))
    }

    /// The session of a POST whose form carries that session's CSRF token.
    async fn posted(&self, headers: &HeaderMap, csrf: &str) -> Result<accounts::Session, Response> {
        let session = self.session(headers).await.map_err(unavailable)?;
        match session {
            Some(session) if session.csrf_matches(csrf) => Ok(session),
            _ => Err(forbidden()),
        }
    }
}

/// A signed-in session and its login.
pub(crate) struct SignedIn {
    pub session: accounts::Session,
    pub login_id: i32,
    /// The session passed a second factor: its provider's (an OAuth or SSO sign-in) or
    /// the login's authenticator. Global and org admin roles depend on it (C24, C60, T15).
    pub second_factor: bool,
}

impl SignedIn {
    pub(crate) async fn top(&self, portal: &Portal) -> Result<Top, sqlx::Error> {
        let (name, places) =
            accounts::top_bar(&portal.pool, self.login_id, self.session.scope_org_id).await?;
        let place = self.chosen(&places).map(|choice| choice.place);
        let chosen = self.chosen(&places).map(|choice| choice.value.clone());
        let tenancy = portal.tenancy();
        let session = self.tenancy_session();
        let suspended = match place {
            Some(place) => tenancy
                .authorized_place(&session, place)
                .await
                .ok()
                .filter(|place| place.suspended())
                .map(|place| match place.place().kind {
                    probation_policy::LayerKind::Personal => "personal account",
                    _ => "organisation",
                }),
            None => None,
        };
        Ok(Top {
            name,
            places: places
                .into_iter()
                .map(|choice| {
                    let selected = Some(&choice.value) == chosen.as_ref();
                    (choice.label, choice.value, selected)
                })
                .collect(),
            csrf: self.session.csrf().to_owned(),
            page: "account",
            admin: tenancy.global_admin(&session).await,
            suspended,
        })
    }

    /// The session's place: the one chosen when it is still listed, else the first.
    fn chosen<'a>(
        &self,
        places: &'a [accounts::SwitcherPlace],
    ) -> Option<&'a accounts::SwitcherPlace> {
        places
            .iter()
            .find(|choice| Some(&choice.value) == self.session.place.as_ref())
            .or(places.first())
    }

    pub(crate) fn tenancy_session(&self) -> tenancy::Session {
        tenancy::Session::new(self.login_id, self.session.scope_org_id)
            .with_second_factor(self.second_factor)
    }

    /// The account the session works in: its chosen organisation or personal account,
    /// checked by `authorized_place`; `None` when it has no place.
    pub(crate) async fn account(
        &self,
        portal: &Portal,
    ) -> Result<Option<Authorized<Place>>, sqlx::Error> {
        let (_, places) =
            accounts::top_bar(&portal.pool, self.login_id, self.session.scope_org_id).await?;
        let Some(place) = self.chosen(&places).map(|choice| choice.place) else {
            return Ok(None);
        };
        Ok(portal
            .tenancy()
            .authorized_place(&self.tenancy_session(), place)
            .await
            .ok())
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(crate) struct PlaceForm {
    csrf: String,
    /// The chosen place's value: "personal" or "org:<id>".
    to: String,
}

/// The switcher (C29): remembers the chosen place, one of the session's own, once
/// `authorized_place` admits it.
async fn choose_place(
    State(portal): State<Shared>,
    headers: HeaderMap,
    Form(form): Form<PlaceForm>,
) -> Response {
    let signed_in = match portal.signed_in_post(&headers, &form.csrf).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    let places = match accounts::top_bar(
        &portal.pool,
        signed_in.login_id,
        signed_in.session.scope_org_id,
    )
    .await
    {
        Ok((_, places)) => places,
        Err(err) => return unavailable(err),
    };
    // Only one of the session's own places, by its value, never its label; then
    // `authorized_place` (C1, C29).
    let Some(choice) = places.into_iter().find(|choice| choice.value == form.to) else {
        return not_found();
    };
    let place = choice.place;
    if portal
        .tenancy()
        .authorized_place(&signed_in.tenancy_session(), place)
        .await
        .is_err()
    {
        return not_found();
    }
    match accounts::choose_place(&portal.pool, &signed_in.session, &choice.value).await {
        Ok(()) => redirect("/keys"),
        Err(err) => unavailable(err),
    }
}

impl Portal {
    pub(crate) fn tenancy(&self) -> Tenancy {
        Tenancy::new(self.pool.clone())
    }

    /// The signed-in session of a page, or a redirect to sign-in.
    async fn signed_in(&self, headers: &HeaderMap) -> Result<SignedIn, Response> {
        match self.session(headers).await.map_err(unavailable)? {
            Some(session) => self.signed_in_as(session).await,
            None => Err(redirect("/signin")),
        }
    }

    /// Like `signed_in_post`, refused for a session opened through an organisation's
    /// SSO: such a session acts only inside that organisation (T2), so it cannot change
    /// the login itself (its methods, password, authenticator or places).
    async fn unscoped_post(&self, headers: &HeaderMap, csrf: &str) -> Result<SignedIn, Response> {
        let signed_in = self.signed_in_post(headers, csrf).await?;
        if signed_in.session.scope_org_id.is_some() {
            return Err(refused(
                "You signed in through your organisation's SSO. Sign in another way to change your login's settings.",
            ));
        }
        Ok(signed_in)
    }

    /// The signed-in session of a POST carrying its CSRF token.
    async fn signed_in_post(&self, headers: &HeaderMap, csrf: &str) -> Result<SignedIn, Response> {
        let session = self.posted(headers, csrf).await?;
        self.signed_in_as(session).await
    }

    /// A password session counts as second-factor checked once its login has an
    /// authenticator: it passed the code at sign-in, or proved one turning it on.
    async fn signed_in_as(&self, session: accounts::Session) -> Result<SignedIn, Response> {
        let Some(login_id) = session.login_id else {
            return Err(redirect("/signin"));
        };
        let second_factor = session.totp_ok
            || accounts::has_totp(&self.pool, login_id)
                .await
                .map_err(unavailable)?;
        Ok(SignedIn {
            session,
            login_id,
            second_factor,
        })
    }
}

/// Where an admin action goes when its role was held back for want of a second factor:
/// setting up the authenticator (C24, C60).
pub(crate) fn second_factor_first() -> Response {
    redirect("/account#totp-heading")
}

/// The client's address: the peer, or behind a proxy in `trusted_proxies` the rightmost
/// `X-Forwarded-For` entry not in it (as `sync` derives a firewall's). `None` when that
/// entry is not an address.
pub(crate) fn client_ip(
    peer: SocketAddr,
    headers: &HeaderMap,
    trusted: &[IpNet],
) -> Option<IpAddr> {
    let peer = peer.ip().to_canonical();
    let is_trusted = |ip: &IpAddr| trusted.iter().any(|range| range.contains(ip));
    if !is_trusted(&peer) {
        return Some(peer);
    }
    let mut lines = Vec::new();
    for line in headers.get_all("x-forwarded-for") {
        lines.push(line.to_str().ok()?);
    }
    let joined = lines.join(",");
    for entry in joined
        .rsplit(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
    {
        let ip = entry.parse::<IpAddr>().ok()?.to_canonical();
        if !is_trusted(&ip) {
            return Some(ip);
        }
    }
    Some(peer)
}
