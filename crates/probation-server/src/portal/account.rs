//! Account settings (mockup account.html, C40).

use std::fmt::Write as _;

use askama::Template;
use axum::extract::{Form, Path, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use super::{
    Shared, SignedIn, Top, cleared_cookie, not_found, redirect, refused, render, session_cookie,
    unavailable, with_cookie,
};
use crate::accounts;

#[derive(Template)]
#[template(path = "account.html")]
pub(crate) struct AccountPage {
    pub top: Option<Top>,
    pub title: &'static str,
    pub csrf: String,
    pub totp_on: bool,
    pub totp_required: bool,
    pub has_password: bool,
    pub password_error: Option<&'static str>,
    pub places_error: Option<&'static str>,
    pub methods: Vec<accounts::MethodRow>,
    pub methods_error: Option<&'static str>,
    pub personal: Personal,
    /// "Delete your login": only for a login with no personal account and no
    /// organisation (C93).
    pub offer_login_delete: bool,
    pub delete_error: Option<&'static str>,
    pub providers: Vec<super::Provider>,
}

pub(crate) enum Personal {
    None,
    Live {
        with_login: bool,
    },
    /// Deleted and restorable: (deleted on, erased on).
    Deleted {
        on: String,
        until: String,
    },
}

pub(crate) async fn show(State(portal): State<Shared>, headers: HeaderMap) -> Response {
    let signed_in = match portal.signed_in(&headers).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    show_with(&portal, &signed_in, StatusCode::OK, |_| {}).await
}

/// The account page, adjusted by `with` (an error in one of its sections).
async fn show_with(
    portal: &super::Portal,
    signed_in: &SignedIn,
    status: StatusCode,
    with: impl FnOnce(&mut AccountPage),
) -> Response {
    match page(portal, signed_in).await {
        Ok(mut page) => {
            with(&mut page);
            render(status, &page)
        }
        Err(err) => unavailable(err),
    }
}

async fn page(portal: &super::Portal, signed_in: &SignedIn) -> Result<AccountPage, sqlx::Error> {
    let top = signed_in.top(portal).await?;
    let mut conn = portal.pool.acquire().await?;
    Ok(AccountPage {
        top: Some(top),
        title: "Account settings",
        csrf: signed_in.session.csrf().to_owned(),
        totp_on: accounts::totp_enabled(&mut conn, signed_in.login_id).await?,
        totp_required: accounts::totp_required(&mut conn, signed_in.login_id).await?,
        has_password: accounts::password_hash_of(&portal.pool, signed_in.login_id)
            .await?
            .is_some(),
        password_error: None,
        places_error: None,
        methods: accounts::methods(&portal.pool, signed_in.login_id).await?,
        methods_error: None,
        personal: personal_state(portal, signed_in.login_id).await?,
        offer_login_delete: !accounts::belongs_to_org(&portal.pool, signed_in.login_id).await?
            && !has_any_personal(portal, signed_in.login_id).await?,
        delete_error: None,
        providers: portal.providers(),
    })
}

/// "Link Google" and the others: an OAuth round trip whose answer joins this login
/// (C75).
pub(crate) async fn link(
    State(portal): State<Shared>,
    Path(provider): Path<String>,
    headers: HeaderMap,
    Form(form): Form<NameForm>,
) -> Response {
    let signed_in = match portal.unscoped_post(&headers, &form.csrf).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    let idp = if provider == "sso" {
        // "Link company SSO": the organisation by its name, as on /signin (C37).
        match accounts::sso_org_named(&portal.pool, &form.name).await {
            Ok(Some(org)) => portal.sso(org).await,
            Ok(None) => Ok(None),
            Err(err) => Err(err),
        }
    } else {
        Ok(portal.idp(&provider))
    };
    match idp {
        Ok(Some(idp)) => super::signin::start_flow(&portal, &signed_in.session, &idp, true).await,
        Ok(None) => {
            show_with(&portal, &signed_in, StatusCode::NOT_FOUND, |page| {
                page.methods_error =
                    Some("No organisation of that name has connected its sign-in.");
            })
            .await
        }
        Err(err) => unavailable(err),
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(crate) struct NameForm {
    csrf: String,
    name: String,
}

/// "Add a personal account" (C40).
pub(crate) async fn add_personal(
    State(portal): State<Shared>,
    headers: HeaderMap,
    Form(form): Form<NameForm>,
) -> Response {
    let signed_in = match portal.unscoped_post(&headers, &form.csrf).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    match accounts::add_personal(&portal.pool, signed_in.login_id).await {
        Ok(true) => redirect("/account"),
        Ok(false) => {
            show_with(
                &portal,
                &signed_in,
                StatusCode::UNPROCESSABLE_ENTITY,
                |page| {
                    page.places_error = Some("You have a personal account already.");
                },
            )
            .await
        }
        Err(err) => unavailable(err),
    }
}

/// "Create an organisation" (C40): the login becomes its org admin.
pub(crate) async fn add_org(
    State(portal): State<Shared>,
    headers: HeaderMap,
    Form(form): Form<NameForm>,
) -> Response {
    let signed_in = match portal.unscoped_post(&headers, &form.csrf).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    match accounts::add_org(&portal.pool, signed_in.login_id, &form.name).await {
        Ok(Ok(())) => redirect("/account"),
        Ok(Err(problem)) => {
            show_with(
                &portal,
                &signed_in,
                StatusCode::UNPROCESSABLE_ENTITY,
                |page| {
                    page.places_error = Some(problem);
                },
            )
            .await
        }
        Err(err) => unavailable(err),
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(crate) struct PasswordForm {
    csrf: String,
    current: String,
    new: String,
    again: String,
}

/// Change password (C40): needs the current one; every other session ends and this
/// one is replaced (T15).
pub(crate) async fn change_password(
    State(portal): State<Shared>,
    headers: HeaderMap,
    Form(form): Form<PasswordForm>,
) -> Response {
    let signed_in = match portal.unscoped_post(&headers, &form.csrf).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    let refuse = |message: &'static str| {
        show_with(
            &portal,
            &signed_in,
            StatusCode::UNPROCESSABLE_ENTITY,
            move |page| {
                page.password_error = Some(message);
            },
        )
    };
    let current = match accounts::password_hash_of(&portal.pool, signed_in.login_id).await {
        Ok(Some(current)) => current,
        Ok(None) => return refused("This login has no email-and-password sign-in."),
        Err(err) => return unavailable(err),
    };
    if !portal
        .passwords
        .verify_blocking(form.current.clone(), Some(current))
        .await
    {
        return refuse("Your current password is not right.").await;
    }
    if form.new != form.again {
        return refuse("The two passwords do not match.").await;
    }
    if let Err(problem) = accounts::check_new_password(
        portal.outbound.as_ref(),
        &portal.config.leaked_password_url,
        &form.new,
    )
    .await
    {
        return refuse(problem.message()).await;
    }
    let hash = portal.passwords.hash_blocking(form.new.clone()).await;
    match accounts::change_password(&portal.pool, &signed_in.session, signed_in.login_id, &hash)
        .await
    {
        Ok(token) => with_cookie(redirect("/account"), Some(session_cookie(&token))),
        Err(err) => unavailable(err),
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(crate) struct CodeForm {
    csrf: String,
    code: String,
}

#[derive(Template)]
#[template(path = "totp.html")]
pub(crate) struct TotpPage<'a> {
    pub top: Option<Top>,
    pub title: &'static str,
    pub csrf: &'a str,
    pub view: TotpView<'a>,
}

pub(crate) enum TotpView<'a> {
    /// Turning the authenticator on: the key and the backup codes, shown once.
    Setup {
        error: Option<&'a str>,
        key: String,
        codes: Vec<String>,
    },
    /// The sign-in step of a password login with an authenticator.
    Code { error: Option<&'a str> },
}

/// Groups a base32 key in fours, as authenticator apps print it.
fn grouped(key: &str) -> String {
    key.as_bytes()
        .chunks(4)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

async fn show_setup(portal: &super::Portal, signed_in: &SignedIn, error: Option<&str>) -> Response {
    let setup = match accounts::totp_setup(&portal.pool, &portal.secrets, signed_in.login_id).await
    {
        Ok(Some(setup)) => setup,
        Ok(None) => return redirect("/account"),
        Err(err) => return unavailable(err),
    };
    let top = match signed_in.top(portal).await {
        Ok(top) => top,
        Err(err) => return unavailable(err),
    };
    let view = TotpView::Setup {
        error,
        key: grouped(&setup.key),
        codes: setup.codes,
    };
    let status = if error.is_some() {
        StatusCode::UNPROCESSABLE_ENTITY
    } else {
        StatusCode::OK
    };
    render(
        status,
        &TotpPage {
            top: Some(top),
            title: "Set up an authenticator",
            csrf: signed_in.session.csrf(),
            view,
        },
    )
}

pub(crate) async fn totp_setup(
    State(portal): State<Shared>,
    headers: HeaderMap,
    Form(form): Form<CodeForm>,
) -> Response {
    match portal.unscoped_post(&headers, &form.csrf).await {
        Ok(signed_in) => show_setup(&portal, &signed_in, None).await,
        Err(answer) => answer,
    }
}

pub(crate) async fn totp_enable(
    State(portal): State<Shared>,
    headers: HeaderMap,
    Form(form): Form<CodeForm>,
) -> Response {
    let signed_in = match portal.unscoped_post(&headers, &form.csrf).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    match accounts::totp_enable(
        &portal.pool,
        &portal.secrets,
        &signed_in.session,
        signed_in.login_id,
        &form.code,
    )
    .await
    {
        Ok(true) => redirect("/account"),
        // A new key and new codes: the ones shown before are not shown again.
        Ok(false) => {
            show_setup(
                &portal,
                &signed_in,
                Some("That code is wrong or has expired. Scan this new code and try again."),
            )
            .await
        }
        Err(err) => unavailable(err),
    }
}

pub(crate) async fn totp_disable(
    State(portal): State<Shared>,
    headers: HeaderMap,
    Form(form): Form<CodeForm>,
) -> Response {
    let signed_in = match portal.unscoped_post(&headers, &form.csrf).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    match accounts::totp_disable(&portal.pool, signed_in.login_id).await {
        Ok(true) => redirect("/account"),
        Ok(false) => refused("Org admins and global admins cannot turn their authenticator off."),
        Err(err) => unavailable(err),
    }
}

/// The QR code of the authenticator being set up, as SVG from 'self' (the CSP allows no
/// `data:` image).
pub(crate) async fn totp_qr(State(portal): State<Shared>, headers: HeaderMap) -> Response {
    let signed_in = match portal.signed_in(&headers).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    match accounts::totp_uri(&portal.pool, &portal.secrets, signed_in.login_id).await {
        Ok(Some(uri)) => (
            [(CONTENT_TYPE, HeaderValue::from_static("image/svg+xml"))],
            qr_svg(&uri),
        )
            .into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(err) => unavailable(err),
    }
}

fn qr_svg(text: &str) -> String {
    let Ok(qr) = qrcodegen::QrCode::encode_text(text, qrcodegen::QrCodeEcc::Medium) else {
        return String::new();
    };
    let border = 4;
    let side = qr.size() + 2 * border;
    let mut path = String::new();
    for y in 0..qr.size() {
        for x in 0..qr.size() {
            if qr.get_module(x, y) {
                let _ = write!(path, "M{},{}h1v1h-1z", x + border, y + border);
            }
        }
    }
    format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {side} {side}\" shape-rendering=\"crispEdges\"><rect width=\"{side}\" height=\"{side}\" fill=\"#fff\"/><path d=\"{path}\" fill=\"#000\"/></svg>"
    )
}

/// "Remove" on one sign-in method (C89).
pub(crate) async fn unlink(
    State(portal): State<Shared>,
    Path(method): Path<i32>,
    headers: HeaderMap,
    Form(form): Form<NameForm>,
) -> Response {
    let signed_in = match portal.unscoped_post(&headers, &form.csrf).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    match accounts::unlink_method(&portal.pool, &signed_in.session, signed_in.login_id, method)
        .await
    {
        Ok(accounts::Unlink::Done) => redirect("/account"),
        Ok(accounts::Unlink::NotFound) => not_found(),
        Ok(accounts::Unlink::Last) => {
            show_with(&portal, &signed_in, StatusCode::CONFLICT, |page| {
                page.methods_error = Some(
                    "The last sign-in method cannot be removed. To remove it, delete your login.",
                );
            })
            .await
        }
        Err(err) => unavailable(err),
    }
}

async fn personal_state(portal: &super::Portal, login: i32) -> Result<Personal, sqlx::Error> {
    if accounts::has_live_personal(&portal.pool, login).await? {
        let with_login = !accounts::belongs_to_org(&portal.pool, login).await?;
        return Ok(Personal::Live { with_login });
    }
    Ok(
        match accounts::deleted_personal(&portal.pool, login).await? {
            Some((on, until)) => Personal::Deleted { on, until },
            None => Personal::None,
        },
    )
}

async fn has_any_personal(portal: &super::Portal, login: i32) -> Result<bool, sqlx::Error> {
    Ok(!matches!(
        personal_state(portal, login).await?,
        Personal::None
    ))
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(crate) struct ConfirmForm {
    csrf: String,
    confirm: String,
}

const TYPE_DELETE: &str = "Type delete to confirm.";

/// "Delete your login" (C93): only for a login with no personal account and no
/// organisation, and never the last global admin (C90). Signs out.
pub(crate) async fn delete_login(
    State(portal): State<Shared>,
    headers: HeaderMap,
    Form(form): Form<ConfirmForm>,
) -> Response {
    let signed_in = match portal.unscoped_post(&headers, &form.csrf).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    if form.confirm.trim() != "delete" {
        return show_with(
            &portal,
            &signed_in,
            StatusCode::UNPROCESSABLE_ENTITY,
            |page| {
                page.delete_error = Some(TYPE_DELETE);
            },
        )
        .await;
    }
    match accounts::delete_login(&portal.pool, signed_in.login_id).await {
        Ok(accounts::Deletion::Done) => with_cookie(redirect("/signin"), Some(cleared_cookie())),
        Ok(accounts::Deletion::NotOffered) => refused(
            "A login that belongs to an organisation or has a personal account cannot be deleted here.",
        ),
        Ok(accounts::Deletion::LastGlobalAdmin) => last_global_admin(&portal, &signed_in).await,
        Err(err) => unavailable(err),
    }
}

async fn last_global_admin(portal: &super::Portal, signed_in: &SignedIn) -> Response {
    show_with(portal, signed_in, StatusCode::CONFLICT, |page| {
        page.delete_error =
            Some("You are the last global admin. Appoint another global admin first.");
    })
    .await
}

/// "Delete personal account" (C33): with the login too when it belongs to no
/// organisation (C85).
pub(crate) async fn delete_personal(
    State(portal): State<Shared>,
    headers: HeaderMap,
    Form(form): Form<ConfirmForm>,
) -> Response {
    let signed_in = match portal.unscoped_post(&headers, &form.csrf).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    if form.confirm.trim() != "delete" {
        return show_with(
            &portal,
            &signed_in,
            StatusCode::UNPROCESSABLE_ENTITY,
            |page| {
                page.delete_error = Some(TYPE_DELETE);
            },
        )
        .await;
    }
    match accounts::delete_personal(&portal.pool, signed_in.login_id).await {
        Ok(accounts::PersonalDeletion::Account) => redirect("/account"),
        Ok(accounts::PersonalDeletion::WithLogin) => {
            with_cookie(redirect("/signin"), Some(cleared_cookie()))
        }
        Ok(accounts::PersonalDeletion::NotFound) => not_found(),
        Ok(accounts::PersonalDeletion::LastGlobalAdmin) => {
            last_global_admin(&portal, &signed_in).await
        }
        Err(err) => unavailable(err),
    }
}

/// "Restore personal account", within its 30 days (C33).
pub(crate) async fn restore_personal(
    State(portal): State<Shared>,
    headers: HeaderMap,
    Form(form): Form<NameForm>,
) -> Response {
    let signed_in = match portal.unscoped_post(&headers, &form.csrf).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    match accounts::restore_personal(&portal.pool, signed_in.login_id).await {
        Ok(true) => redirect("/account"),
        Ok(false) => not_found(),
        Err(err) => unavailable(err),
    }
}
