//! Signed-out pages: sign-in, sign-up and email confirmation (mockup sign-in.html).

use std::net::SocketAddr;

use askama::Template;
use axum::extract::{ConnectInfo, Form, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use super::account::{TotpPage, TotpView};
use super::{
    Shared, Top, cleared_cookie, client_ip, redirect, refused, render, session_cookie, unavailable,
    with_cookie,
};
use crate::accounts::{self, SignupKind, Verified};

#[derive(Template)]
#[template(path = "signup.html")]
pub(crate) struct SignupPage<'a> {
    pub top: Option<Top>,
    pub title: &'static str,
    pub csrf: &'a str,
    pub providers: Vec<super::Provider>,
    pub view: SignupView<'a>,
}

pub(crate) enum SignupView<'a> {
    Form {
        error: Option<&'a str>,
        email: &'a str,
        org: bool,
        org_name: &'a str,
    },
    /// "We sent a link": the same page whether or not the address was new (C91).
    CheckEmail {
        email: &'a str,
    },
    /// A signed-in login whose address is not confirmed yet (C41).
    ConfirmEmail {
        email: &'a str,
    },
    Confirmed {
        next: &'static str,
    },
    BadLink,
}

fn signup_page<'a>(portal: &super::Portal, csrf: &'a str, view: SignupView<'a>) -> SignupPage<'a> {
    let title = match view {
        SignupView::Form { .. } => "Create an account",
        SignupView::CheckEmail { .. } | SignupView::ConfirmEmail { .. } => "Check your email",
        SignupView::Confirmed { .. } => "Email confirmed",
        SignupView::BadLink => "Link expired",
    };
    SignupPage {
        top: None,
        title,
        csrf,
        providers: portal.providers(),
        view,
    }
}

pub(crate) async fn signup_form(State(portal): State<Shared>, headers: HeaderMap) -> Response {
    let (session, cookie) = match portal.visit(&headers).await {
        Ok(visit) => visit,
        Err(err) => return unavailable(err),
    };
    let view = SignupView::Form {
        error: None,
        email: "",
        org: false,
        org_name: "",
    };
    with_cookie(
        render(StatusCode::OK, &signup_page(&portal, session.csrf(), view)),
        cookie,
    )
}

/// Whether this client IP may make one more request that sends mail (sign-up, "send
/// the link again", reset); counted when it may (R3).
async fn mail_ip_allowed(
    portal: &super::Portal,
    peer: SocketAddr,
    headers: &HeaderMap,
) -> Result<bool, sqlx::Error> {
    let ip = client_ip(peer, headers, &portal.trusted_proxies)
        .map_or_else(|| "unparsable".to_owned(), |ip| ip.to_string());
    let checks = [("ip", format!("mail {ip}"), accounts::MAIL_PER_IP)];
    Ok(match accounts::attempt(&portal.pool, &checks).await? {
        Some(counted) => {
            counted.keep();
            true
        }
        None => false,
    })
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(crate) struct SignupForm {
    csrf: String,
    email: String,
    password: String,
    kind: String,
    org_name: String,
}

pub(crate) async fn signup(
    State(portal): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<SignupForm>,
) -> Response {
    let session = match portal.posted(&headers, &form.csrf).await {
        Ok(session) => session,
        Err(refused) => return refused,
    };
    let org = form.kind == "org";
    let again = |error: &str| {
        let view = SignupView::Form {
            error: Some(error),
            email: &form.email,
            org,
            org_name: &form.org_name,
        };
        render(
            StatusCode::UNPROCESSABLE_ENTITY,
            &signup_page(&portal, session.csrf(), view),
        )
    };
    let Some(email) = accounts::normal_email(&form.email) else {
        return again("Enter a valid email address.");
    };
    let kind = if org {
        let name = form.org_name.trim();
        if let Some(problem) = accounts::org_name_problem(name) {
            return again(problem);
        }
        match accounts::org_name_taken(&portal.pool, name).await {
            Ok(false) => {}
            Ok(true) => return again(accounts::ORG_NAME_TAKEN),
            Err(err) => return unavailable(err),
        }
        SignupKind::Org(name.to_owned())
    } else {
        SignupKind::Personal
    };
    if let Err(problem) = accounts::check_new_password(
        portal.outbound.as_ref(),
        &portal.config.leaked_password_url,
        &form.password,
    )
    .await
    {
        return again(problem.message());
    }
    // Counted only for a request that would send mail, so form errors show as usual
    // (N5); over the cap the page is the one a sent link shows (C91), with nothing done.
    match mail_ip_allowed(&portal, peer, &headers).await {
        Ok(true) => {}
        Ok(false) => {
            let view = SignupView::CheckEmail { email: &email };
            return render(StatusCode::OK, &signup_page(&portal, session.csrf(), view));
        }
        Err(err) => return unavailable(err),
    }
    let hash = portal.passwords.hash_blocking(form.password.clone()).await;
    match accounts::sign_up(
        &portal.pool,
        &portal.config.base_url,
        &portal.secrets,
        &email,
        &hash,
        kind,
    )
    .await
    {
        Ok(()) => render(
            StatusCode::OK,
            &signup_page(
                &portal,
                session.csrf(),
                SignupView::CheckEmail { email: &email },
            ),
        ),
        Err(err) => unavailable(err),
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(crate) struct ResendForm {
    csrf: String,
    email: String,
}

pub(crate) async fn resend(
    State(portal): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<ResendForm>,
) -> Response {
    let session = match portal.posted(&headers, &form.csrf).await {
        Ok(session) => session,
        Err(refused) => return refused,
    };
    let email = accounts::normal_email(&form.email).unwrap_or_default();
    let allowed = match mail_ip_allowed(&portal, peer, &headers).await {
        Ok(allowed) => allowed,
        Err(err) => return unavailable(err),
    };
    if allowed
        && !email.is_empty()
        && let Err(err) = accounts::resend_verification(
            &portal.pool,
            &portal.config.base_url,
            &portal.secrets,
            &email,
        )
        .await
    {
        return unavailable(err);
    }
    render(
        StatusCode::OK,
        &signup_page(
            &portal,
            session.csrf(),
            SignupView::CheckEmail { email: &email },
        ),
    )
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(crate) struct LinkQuery {
    token: String,
}

/// The emailed confirmation link (C41).
pub(crate) async fn verify_email(
    State(portal): State<Shared>,
    headers: HeaderMap,
    Query(query): Query<LinkQuery>,
) -> Response {
    let (session, cookie) = match portal.visit(&headers).await {
        Ok(visit) => visit,
        Err(err) => return unavailable(err),
    };
    if query.token.is_empty() {
        let Some(login) = session.login_id else {
            return redirect("/signin");
        };
        return match accounts::unconfirmed_email(&portal.pool, login).await {
            Ok(Some(email)) => render(
                StatusCode::OK,
                &signup_page(
                    &portal,
                    session.csrf(),
                    SignupView::ConfirmEmail { email: &email },
                ),
            ),
            Ok(None) => redirect("/account"),
            Err(err) => unavailable(err),
        };
    }
    let (status, view) = match accounts::verify_email(&portal.pool, &query.token).await {
        // The login's sessions ended with the confirmation (F7): whoever confirmed signs
        // in with the password.
        Ok(Verified::Done { .. }) => (StatusCode::OK, SignupView::Confirmed { next: "/signin" }),
        Ok(Verified::BadLink) => (StatusCode::GONE, SignupView::BadLink),
        Err(err) => return unavailable(err),
    };
    with_cookie(
        render(status, &signup_page(&portal, session.csrf(), view)),
        cookie,
    )
}

#[derive(Template)]
#[template(path = "signin.html")]
pub(crate) struct SigninPage<'a> {
    pub top: Option<Top>,
    pub title: &'static str,
    pub csrf: &'a str,
    pub providers: Vec<super::Provider>,
    pub view: SigninView<'a>,
}

pub(crate) enum SigninView<'a> {
    Form {
        error: Option<&'a str>,
        notice: Option<&'a str>,
        email: &'a str,
    },
    /// "Forgot your password?", and the answer after sending, the same for any address.
    Reset {
        sent: bool,
    },
    ChooseNew {
        token: &'a str,
        error: Option<&'a str>,
    },
    BadLink,
    /// Signing in to a deleted login (C94).
    Deleted {
        on: &'a str,
        until: &'a str,
    },
}

const WRONG_PASSWORD: &str =
    "That email and password do not match. Try again, or reset your password.";

fn signin_page<'a>(portal: &super::Portal, csrf: &'a str, view: SigninView<'a>) -> SigninPage<'a> {
    let title = match view {
        SigninView::Form { .. } => "Sign in",
        SigninView::Reset { .. } => "Forgot your password",
        SigninView::ChooseNew { .. } => "Choose a new password",
        SigninView::BadLink => "Link expired",
        SigninView::Deleted { .. } => "This login was deleted",
    };
    SigninPage {
        top: None,
        title,
        csrf,
        providers: portal.providers(),
        view,
    }
}

pub(crate) async fn signin_form(State(portal): State<Shared>, headers: HeaderMap) -> Response {
    let (session, cookie) = match portal.visit(&headers).await {
        Ok(visit) => visit,
        Err(err) => return unavailable(err),
    };
    if session.login_id.is_some() {
        return redirect("/account");
    }
    let view = SigninView::Form {
        error: None,
        notice: None,
        email: "",
    };
    with_cookie(
        render(StatusCode::OK, &signin_page(&portal, session.csrf(), view)),
        cookie,
    )
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(crate) struct SigninForm {
    csrf: String,
    email: String,
    password: String,
}

const THROTTLED: &str = "Too many attempts. Wait 15 minutes and try again.";

/// Email-and-password sign-in. Over 10 failures for the email or 100 for the client IP
/// in 15 minutes, the attempt is refused before the password is checked, the same way
/// for an unknown email (T32). The session is replaced by a new one (T15).
pub(crate) async fn signin(
    State(portal): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<SigninForm>,
) -> Response {
    let session = match portal.posted(&headers, &form.csrf).await {
        Ok(session) => session,
        Err(refused) => return refused,
    };
    let email = accounts::normal_email(&form.email).unwrap_or_default();
    let ip = client_ip(peer, &headers, &portal.trusted_proxies)
        .map_or_else(|| "unparsable".to_owned(), |ip| ip.to_string());
    let checks = [
        ("email", email.clone(), accounts::EMAIL_FAILURES),
        ("ip", ip, accounts::IP_FAILURES),
    ];
    let attempt = match accounts::attempt(&portal.pool, &checks).await {
        Ok(Some(attempt)) => attempt,
        Ok(None) => {
            let view = SigninView::Form {
                error: Some(THROTTLED),
                notice: None,
                email: "",
            };
            return render(
                StatusCode::TOO_MANY_REQUESTS,
                &signin_page(&portal, session.csrf(), view),
            );
        }
        Err(err) => return unavailable(err),
    };
    let method = match accounts::password_method(&portal.pool, &email).await {
        Ok(method) => method,
        Err(err) => return unavailable(err),
    };
    let hash = method.as_ref().and_then(|method| method.hash.clone());
    let matches = portal.passwords.verify_blocking(form.password, hash).await;
    let Some(method) = method.filter(|_| matches) else {
        // A failure keeps its recorded attempt.
        attempt.keep();
        let view = SigninView::Form {
            error: Some(WRONG_PASSWORD),
            notice: None,
            email: &form.email,
        };
        return render(
            StatusCode::UNPROCESSABLE_ENTITY,
            &signin_page(&portal, session.csrf(), view),
        );
    };
    if let Err(err) = attempt.release(&portal.pool).await {
        return unavailable(err);
    }
    match accounts::login_state(&portal.pool, method.login_id).await {
        Ok(accounts::LoginState::Live) => {}
        // A deleted login with an authenticator asks for its code before it offers the
        // choice, which can erase it (R1).
        Ok(accounts::LoginState::Deleted { .. }) => {
            return match accounts::has_totp(&portal.pool, method.login_id).await {
                Ok(true) => {
                    let pending = serde_json::json!({
                        "totp": method.login_id,
                        "then_deleted": method.method_id,
                    });
                    match accounts::rotate_session(
                        &portal.pool,
                        &session,
                        None,
                        false,
                        None,
                        Some(pending),
                    )
                    .await
                    {
                        Ok((_, token)) => {
                            with_cookie(redirect("/totp"), Some(session_cookie(&token)))
                        }
                        Err(err) => unavailable(err),
                    }
                }
                Ok(false) => {
                    let choice = DeletedChoice {
                        by_password: true,
                        second_factor_done: false,
                        scope: None,
                    };
                    deleted_choice(&portal, &session, method.login_id, method.method_id, choice)
                        .await
                }
                Err(err) => unavailable(err),
            };
        }
        // Past its 30 days: erased now, and the address is free (C94).
        Ok(accounts::LoginState::Expired) => {
            if let Err(err) = accounts::erase_expired(&portal.pool, method.login_id).await {
                return unavailable(err);
            }
            let view = SigninView::Form {
                error: Some(WRONG_PASSWORD),
                notice: None,
                email: &form.email,
            };
            return render(
                StatusCode::UNPROCESSABLE_ENTITY,
                &signin_page(&portal, session.csrf(), view),
            );
        }
        Err(err) => return unavailable(err),
    }
    sign_in_as(&portal, &session, method.login_id, true, None).await
}

/// Opens the signed-in session for `login` under a new id (T15). A password sign-in of
/// a login with an authenticator waits for its code first; an OAuth or SSO sign-in
/// counts as second-factor checked (C38).
pub(crate) async fn sign_in_as(
    portal: &super::Portal,
    session: &accounts::Session,
    login: i32,
    by_password: bool,
    scope_org_id: Option<i32>,
) -> Response {
    let with_totp = if by_password {
        match accounts::has_totp(&portal.pool, login).await {
            Ok(with_totp) => with_totp,
            Err(err) => return unavailable(err),
        }
    } else {
        false
    };
    // With an authenticator the new session is still signed out, waiting for the code.
    let (signed_in, pending, next) = if with_totp {
        (None, Some(serde_json::json!({"totp": login})), "/totp")
    } else {
        (Some(login), None, "/account")
    };
    match accounts::rotate_session(
        &portal.pool,
        session,
        signed_in,
        !by_password,
        scope_org_id,
        pending,
    )
    .await
    {
        Ok((_, token)) => with_cookie(redirect(next), Some(session_cookie(&token))),
        Err(err) => unavailable(err),
    }
}

/// A sign-in with a method of a deleted login: the session waits for the choice
/// between "Restore login" and "Start a new login" (C94).
async fn deleted_choice(
    portal: &super::Portal,
    session: &accounts::Session,
    login: i32,
    method: i32,
    choice: DeletedChoice,
) -> Response {
    let pending = serde_json::json!({
        "deleted": login,
        "method": method,
        "by_password": choice.by_password,
        "second_factor": choice.second_factor_done,
        "scope": choice.scope,
    });
    match accounts::rotate_session(&portal.pool, session, None, false, None, Some(pending)).await {
        Ok((_, token)) => with_cookie(redirect("/deleted"), Some(session_cookie(&token))),
        Err(err) => unavailable(err),
    }
}

/// How a session reached the deleted-login choice.
struct DeletedChoice {
    by_password: bool,
    /// The login's authenticator code was given first (R1).
    second_factor_done: bool,
    scope: Option<i32>,
}

impl DeletedChoice {
    /// The session's choice, or `None` when a password reached it without the code of a
    /// login that has an authenticator (R1).
    async fn of(
        portal: &super::Portal,
        session: &accounts::Session,
        login: i32,
    ) -> Result<Option<DeletedChoice>, sqlx::Error> {
        let pending = session.pending.clone().unwrap_or_default();
        let choice = DeletedChoice {
            by_password: pending["by_password"].as_bool().unwrap_or(true),
            second_factor_done: pending["second_factor"].as_bool().unwrap_or(false),
            scope: pending["scope"]
                .as_i64()
                .and_then(|id| i32::try_from(id).ok()),
        };
        if choice.by_password
            && !choice.second_factor_done
            && accounts::has_totp(&portal.pool, login).await?
        {
            return Ok(None);
        }
        Ok(Some(choice))
    }

    /// Signs `login` in; a code given before the choice counts as its TOTP step.
    async fn sign_in(
        &self,
        portal: &super::Portal,
        session: &accounts::Session,
        login: i32,
    ) -> Response {
        if !self.second_factor_done {
            return sign_in_as(portal, session, login, self.by_password, self.scope).await;
        }
        match accounts::rotate_session(&portal.pool, session, Some(login), true, self.scope, None)
            .await
        {
            Ok((_, token)) => with_cookie(redirect("/account"), Some(session_cookie(&token))),
            Err(err) => unavailable(err),
        }
    }
}

fn refused_choice(portal: &super::Portal, session: &accounts::Session) -> Response {
    let view = SigninView::Form {
        error: Some("Sign in again and enter your authenticator code first."),
        notice: None,
        email: "",
    };
    render(
        StatusCode::FORBIDDEN,
        &signin_page(portal, session.csrf(), view),
    )
}

pub(crate) async fn deleted_form(State(portal): State<Shared>, headers: HeaderMap) -> Response {
    let session = match portal.session(&headers).await {
        Ok(Some(session)) => session,
        Ok(None) => return redirect("/signin"),
        Err(err) => return unavailable(err),
    };
    let Some(login) = session.pending_login("deleted") else {
        return redirect("/signin");
    };
    match accounts::login_state(&portal.pool, login).await {
        Ok(accounts::LoginState::Deleted { on, until }) => render(
            StatusCode::OK,
            &signin_page(
                &portal,
                session.csrf(),
                SigninView::Deleted {
                    on: &on,
                    until: &until,
                },
            ),
        ),
        Ok(_) => redirect("/signin"),
        Err(err) => unavailable(err),
    }
}

/// "Restore login" (C94): the login comes back and the sign-in goes on.
pub(crate) async fn deleted_restore(
    State(portal): State<Shared>,
    headers: HeaderMap,
    Form(form): Form<CsrfOnly>,
) -> Response {
    let session = match portal.posted(&headers, &form.csrf).await {
        Ok(session) => session,
        Err(refused) => return refused,
    };
    let Some(login) = session.pending_login("deleted") else {
        return redirect("/signin");
    };
    let choice = match DeletedChoice::of(&portal, &session, login).await {
        Ok(Some(choice)) => choice,
        Ok(None) => return refused_choice(&portal, &session),
        Err(err) => return unavailable(err),
    };
    match accounts::restore_login(&portal.pool, login).await {
        Ok(true) => {}
        Ok(false) => return redirect("/signin"),
        Err(err) => return unavailable(err),
    }
    choice.sign_in(&portal, &session, login).await
}

/// "Start a new login instead" (C94): the old login is erased now, and a new one with
/// the method just used is signed in.
pub(crate) async fn deleted_new(
    State(portal): State<Shared>,
    headers: HeaderMap,
    Form(form): Form<CsrfOnly>,
) -> Response {
    let session = match portal.posted(&headers, &form.csrf).await {
        Ok(session) => session,
        Err(refused) => return refused,
    };
    let (Some(login), Some(method)) = (
        session.pending_login("deleted"),
        session.pending_login("method"),
    ) else {
        return redirect("/signin");
    };
    let choice = match DeletedChoice::of(&portal, &session, login).await {
        Ok(Some(choice)) => choice,
        Ok(None) => return refused_choice(&portal, &session),
        Err(err) => return unavailable(err),
    };
    match accounts::start_new_login(&portal.pool, login, method).await {
        Ok(Some(new_login)) => choice.sign_in(&portal, &session, new_login).await,
        Ok(None) => redirect("/signin"),
        Err(err) => unavailable(err),
    }
}

const WRONG_CODE: &str = "That code is wrong or has expired. Wait for the next code and try again.";

fn totp_step<'a>(csrf: &'a str, error: Option<&'a str>) -> TotpPage<'a> {
    TotpPage {
        top: None,
        title: "Authenticator code",
        csrf,
        view: TotpView::Code { error },
    }
}

pub(crate) async fn totp_form(State(portal): State<Shared>, headers: HeaderMap) -> Response {
    match portal.session(&headers).await {
        Ok(Some(session)) if session.pending_login("totp").is_some() => {
            render(StatusCode::OK, &totp_step(session.csrf(), None))
        }
        Ok(_) => redirect("/signin"),
        Err(err) => unavailable(err),
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(crate) struct CodeForm {
    csrf: String,
    code: String,
}

/// The authenticator step: a TOTP or backup code signs the session in, under a new id
/// (T15).
pub(crate) async fn totp(
    State(portal): State<Shared>,
    headers: HeaderMap,
    Form(form): Form<CodeForm>,
) -> Response {
    let session = match portal.posted(&headers, &form.csrf).await {
        Ok(session) => session,
        Err(refused) => return refused,
    };
    let Some(login) = session.pending_login("totp") else {
        return redirect("/signin");
    };
    let checks = [("totp", login.to_string(), accounts::TOTP_FAILURES)];
    let attempt = match accounts::attempt(&portal.pool, &checks).await {
        Ok(Some(attempt)) => attempt,
        Ok(None) => {
            return render(
                StatusCode::TOO_MANY_REQUESTS,
                &totp_step(session.csrf(), Some(THROTTLED)),
            );
        }
        Err(err) => return unavailable(err),
    };
    match accounts::second_factor(&portal.pool, &portal.secrets, login, &form.code).await {
        Ok(true) => {}
        Ok(false) => {
            attempt.keep();
            return render(
                StatusCode::UNPROCESSABLE_ENTITY,
                &totp_step(session.csrf(), Some(WRONG_CODE)),
            );
        }
        Err(err) => return unavailable(err),
    }
    if let Err(err) = attempt.release(&portal.pool).await {
        return unavailable(err);
    }
    // A deleted login's code leads on to its choice (R1, C94).
    if let Some(method) = session.pending_login("then_deleted") {
        let choice = DeletedChoice {
            by_password: true,
            second_factor_done: true,
            scope: None,
        };
        return deleted_choice(&portal, &session, login, method, choice).await;
    }
    match accounts::rotate_session(&portal.pool, &session, Some(login), true, None, None).await {
        Ok((_, token)) => with_cookie(redirect("/account"), Some(session_cookie(&token))),
        Err(err) => unavailable(err),
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(crate) struct CsrfOnly {
    csrf: String,
}

pub(crate) async fn signout(
    State(portal): State<Shared>,
    headers: HeaderMap,
    Form(form): Form<CsrfOnly>,
) -> Response {
    let session = match portal.posted(&headers, &form.csrf).await {
        Ok(session) => session,
        Err(refused) => return refused,
    };
    match accounts::close_session(&portal.pool, &session).await {
        Ok(()) => with_cookie(redirect("/signin"), Some(cleared_cookie())),
        Err(err) => unavailable(err),
    }
}

pub(crate) async fn reset_form(State(portal): State<Shared>, headers: HeaderMap) -> Response {
    let (session, cookie) = match portal.visit(&headers).await {
        Ok(visit) => visit,
        Err(err) => return unavailable(err),
    };
    with_cookie(
        render(
            StatusCode::OK,
            &signin_page(&portal, session.csrf(), SigninView::Reset { sent: false }),
        ),
        cookie,
    )
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(crate) struct ResetForm {
    csrf: String,
    email: String,
}

/// Sends a reset link; the answer is the same whether or not the address has a login.
pub(crate) async fn reset(
    State(portal): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<ResetForm>,
) -> Response {
    let session = match portal.posted(&headers, &form.csrf).await {
        Ok(session) => session,
        Err(refused) => return refused,
    };
    let allowed = match mail_ip_allowed(&portal, peer, &headers).await {
        Ok(allowed) => allowed,
        Err(err) => return unavailable(err),
    };
    if allowed
        && let Some(email) = accounts::normal_email(&form.email)
        && let Err(err) = accounts::request_reset(
            &portal.pool,
            &portal.config.base_url,
            &portal.secrets,
            &email,
        )
        .await
    {
        return unavailable(err);
    }
    render(
        StatusCode::OK,
        &signin_page(&portal, session.csrf(), SigninView::Reset { sent: true }),
    )
}

/// The emailed reset link: the new-password form, or "expired" for a dead link.
pub(crate) async fn reset_confirm_form(
    State(portal): State<Shared>,
    headers: HeaderMap,
    Query(query): Query<LinkQuery>,
) -> Response {
    let (session, cookie) = match portal.visit(&headers).await {
        Ok(visit) => visit,
        Err(err) => return unavailable(err),
    };
    let (status, view) = match accounts::reset_token_live(&portal.pool, &query.token).await {
        Ok(true) => (
            StatusCode::OK,
            SigninView::ChooseNew {
                token: &query.token,
                error: None,
            },
        ),
        Ok(false) => (StatusCode::GONE, SigninView::BadLink),
        Err(err) => return unavailable(err),
    };
    with_cookie(
        render(status, &signin_page(&portal, session.csrf(), view)),
        cookie,
    )
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(crate) struct ChooseForm {
    csrf: String,
    token: String,
    new: String,
    again: String,
}

pub(crate) async fn reset_confirm(
    State(portal): State<Shared>,
    headers: HeaderMap,
    Form(form): Form<ChooseForm>,
) -> Response {
    let session = match portal.posted(&headers, &form.csrf).await {
        Ok(session) => session,
        Err(refused) => return refused,
    };
    let again = |error: &str| {
        let view = SigninView::ChooseNew {
            token: &form.token,
            error: Some(error),
        };
        render(
            StatusCode::UNPROCESSABLE_ENTITY,
            &signin_page(&portal, session.csrf(), view),
        )
    };
    match accounts::reset_token_live(&portal.pool, &form.token).await {
        Ok(true) => {}
        Ok(false) => {
            return render(
                StatusCode::GONE,
                &signin_page(&portal, session.csrf(), SigninView::BadLink),
            );
        }
        Err(err) => return unavailable(err),
    }
    if form.new != form.again {
        return again("The two passwords do not match.");
    }
    if let Err(problem) = accounts::check_new_password(
        portal.outbound.as_ref(),
        &portal.config.leaked_password_url,
        &form.new,
    )
    .await
    {
        return again(problem.message());
    }
    let hash = portal.passwords.hash_blocking(form.new.clone()).await;
    match accounts::reset_password(&portal.pool, &form.token, &hash).await {
        Ok(true) => {
            let view = SigninView::Form {
                error: None,
                notice: Some("Your password is changed. Sign in with your new password."),
                email: "",
            };
            render(StatusCode::OK, &signin_page(&portal, session.csrf(), view))
        }
        Ok(false) => render(
            StatusCode::GONE,
            &signin_page(&portal, session.csrf(), SigninView::BadLink),
        ),
        Err(err) => unavailable(err),
    }
}

/// Starts a sign-in with Google, GitHub or Microsoft: the flow is bound to this browser's
/// session (T12).
pub(crate) async fn oauth_start(
    State(portal): State<Shared>,
    Path(provider): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(idp) = portal.idp(&provider) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let (session, cookie) = match portal.visit(&headers).await {
        Ok(visit) => visit,
        Err(err) => return unavailable(err),
    };
    with_cookie(start_flow(&portal, &session, &idp, false).await, cookie)
}

/// Keeps the flow in the session and sends the browser to the IdP.
pub(crate) async fn start_flow(
    portal: &super::Portal,
    session: &accounts::Session,
    idp: &accounts::Idp,
    link: bool,
) -> Response {
    let started = match accounts::oauth_start(portal.outbound.as_ref(), idp, link).await {
        Ok(started) => started,
        Err(err) => {
            tracing::warn!(provider = idp.name(), error = ?err, "sign-in could not start");
            return idp_failed(portal, session, StatusCode::BAD_GATEWAY);
        }
    };
    let pending = serde_json::json!({"oauth": started.flow});
    match accounts::set_pending(&portal.pool, session, &pending).await {
        Ok(()) => redirect(started.location.as_str()),
        Err(err) => unavailable(err),
    }
}

const IDP_FAILED: &str =
    "We could not sign you in that way. Try again, or use another sign-in method.";

fn idp_failed(portal: &super::Portal, session: &accounts::Session, status: StatusCode) -> Response {
    let view = SigninView::Form {
        error: Some(IDP_FAILED),
        notice: None,
        email: "",
    };
    render(status, &signin_page(portal, session.csrf(), view))
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(crate) struct CallbackQuery {
    code: String,
    state: String,
}

pub(crate) async fn oauth_callback(
    State(portal): State<Shared>,
    Path(provider): Path<String>,
    headers: HeaderMap,
    Query(query): Query<CallbackQuery>,
) -> Response {
    let Some(idp) = portal.idp(&provider) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    finish_flow(&portal, &headers, &idp, &query).await
}

/// The IdP's answer: checked against the flow this session started, which is used up
/// whatever the outcome (T12). A sign-in opens a new session (T15) with the second
/// factor counted as the IdP's (C38); a link adds the method to the signed-in login.
pub(crate) async fn finish_flow(
    portal: &super::Portal,
    headers: &HeaderMap,
    idp: &accounts::Idp,
    query: &CallbackQuery,
) -> Response {
    let session = match portal.session(headers).await {
        Ok(Some(session)) => session,
        Ok(None) => return redirect("/signin"),
        Err(err) => return unavailable(err),
    };
    let flow = match accounts::take_pending(&portal.pool, &session).await {
        Ok(pending) => pending.and_then(|pending| pending.get("oauth").cloned()),
        Err(err) => return unavailable(err),
    };
    let Some(flow) = flow else {
        return idp_failed(portal, &session, StatusCode::BAD_REQUEST);
    };
    let identity = match accounts::oauth_finish(
        portal.outbound.as_ref(),
        idp,
        &flow,
        &query.state,
        &query.code,
    )
    .await
    {
        Ok(identity) => identity,
        Err(err) => {
            tracing::info!(provider = idp.name(), error = ?err, "sign-in refused");
            return idp_failed(portal, &session, StatusCode::BAD_REQUEST);
        }
    };
    if flow["link"].as_bool() == Some(true) {
        let Some(login) = session.login_id else {
            return redirect("/signin");
        };
        return match accounts::link_method(&portal.pool, login, &identity).await {
            Ok(true) => redirect("/account"),
            Ok(false) => refused(
                "That sign-in method belongs to another login. Sign in with it to use that login, or remove it there first.",
            ),
            Err(err) => unavailable(err),
        };
    }
    let (login, method) = match accounts::identity_login(&portal.pool, &identity).await {
        Ok(found) => found,
        Err(err) => return unavailable(err),
    };
    match accounts::login_state(&portal.pool, login).await {
        Ok(accounts::LoginState::Deleted { .. }) => {
            let choice = DeletedChoice {
                by_password: false,
                second_factor_done: false,
                scope: identity.org,
            };
            deleted_choice(portal, &session, login, method, choice).await
        }
        Ok(_) => sign_in_as(portal, &session, login, false, identity.org).await,
        Err(err) => unavailable(err),
    }
}

/// `/o/<name>`, an organisation's own sign-in link (C37): to its SSO, or the plain
/// sign-in page for an unknown name or one without SSO, so the page alone does not tell
/// whether the organisation exists (A3).
pub(crate) async fn org_link(
    State(portal): State<Shared>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Response {
    to_org_sso(&portal, &headers, &name).await
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(crate) struct OrgQuery {
    name: String,
}

/// The organisation name typed on `/signin` (C37).
pub(crate) async fn org_typed(
    State(portal): State<Shared>,
    headers: HeaderMap,
    Query(query): Query<OrgQuery>,
) -> Response {
    to_org_sso(&portal, &headers, &query.name).await
}

async fn to_org_sso(portal: &Shared, headers: &HeaderMap, name: &str) -> Response {
    match accounts::sso_org_named(&portal.pool, name).await {
        Ok(Some(org)) => redirect(&format!("/sso/{org}/start")),
        Ok(None) => signin_form(State(portal.clone()), headers.clone()).await,
        Err(err) => unavailable(err),
    }
}

pub(crate) async fn sso_start(
    State(portal): State<Shared>,
    Path(org): Path<i32>,
    headers: HeaderMap,
) -> Response {
    let (session, cookie) = match portal.visit(&headers).await {
        Ok(visit) => visit,
        Err(err) => return unavailable(err),
    };
    let answer = match portal.sso(org).await {
        Ok(Some(idp)) => start_flow(&portal, &session, &idp, false).await,
        Ok(None) => idp_failed(&portal, &session, StatusCode::NOT_FOUND),
        Err(err) => unavailable(err),
    };
    with_cookie(answer, cookie)
}

pub(crate) async fn sso_callback(
    State(portal): State<Shared>,
    Path(org): Path<i32>,
    headers: HeaderMap,
    Query(query): Query<CallbackQuery>,
) -> Response {
    match portal.sso(org).await {
        Ok(Some(idp)) => finish_flow(&portal, &headers, &idp, &query).await,
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(err) => unavailable(err),
    }
}
