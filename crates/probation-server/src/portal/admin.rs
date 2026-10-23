//! The global admin page (mockup global-admin.html): organisations, personal accounts,
//! network-lock approval, global admins, limits, retention, the platform policy and its
//! automation tokens and blocklist file. Only a global admin's session reaches it; any
//! other answers 404, the same page as an unknown id (C1), and a password session needs
//! its authenticator first (C24). Every id in a path goes through `authorized_place` or
//! `authorized_owner`, and the actor is loaded for the place it acts on.

use askama::Template;
use axum::extract::{Form, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use probation_policy::api::AccountKind;
use probation_policy::{LayerKind, PlaceRef};
use serde::Deserialize;
use sqlx::PgPool;

use super::organisation::{blocklist_file, import_into};
use super::{
    Shared, SignedIn, Top, not_found, redirect, refused, render, second_factor_first, unavailable,
};
use crate::keys::{self, Limits, LimitsRow, TokenRow};
use crate::tenancy::{self, Actor, Authorized, ChangeError, Owned, PLATFORM, Place};
use crate::{accounts, audit, policy};

#[derive(Template)]
#[template(path = "global-admin.html")]
pub(crate) struct AdminPage {
    pub top: Option<Top>,
    pub title: &'static str,
    pub csrf: String,
    pub view: AdminView,
}

/// One organisation in the list.
pub(crate) struct OrgRow {
    pub id: i32,
    pub name: String,
    pub suspended: bool,
    /// "Deleted, erased on 19 Nov 2026" while it waits to be erased.
    pub deleted: Option<String>,
    pub members: i64,
    pub keys: i64,
}

/// One personal account in the list.
pub(crate) struct PersonalRow {
    pub id: i32,
    pub email: String,
    pub suspended: bool,
    /// The day it is erased, while it is deleted and restorable.
    pub erased_on: Option<String>,
    pub keys: i64,
    pub created: String,
}

/// One network-lock range: waiting for approval, or approved.
pub(crate) struct RangeRow {
    pub id: i32,
    pub org: String,
    pub cidr: String,
    pub asked_by: String,
    pub asked: String,
    pub approved: bool,
}

pub(crate) struct AdminView {
    pub orgs: Vec<OrgRow>,
    pub personal: Vec<PersonalRow>,
    pub ranges: Vec<RangeRow>,
    /// (login, email).
    pub admins: Vec<(i32, String)>,
    pub limits: Vec<LimitsRow>,
    /// Organisations with no limits of their own, for "Set own limits": (id, name).
    pub default_orgs: Vec<(i32, String)>,
    pub activity_days: i32,
    pub audit_days: i32,
    pub tokens: Vec<TokenRow>,
    pub new_token: Option<String>,
    pub error: Option<String>,
}

impl AdminView {
    fn default_limits(&self, kind: AccountKind) -> Option<&Limits> {
        self.limits
            .iter()
            .find(|row| row.kind == kind && row.org.is_none())
            .map(|row| &row.limits)
    }

    pub fn personal_limits(&self) -> Option<&Limits> {
        self.default_limits(AccountKind::Personal)
    }

    pub fn org_limits(&self) -> Option<&Limits> {
        self.default_limits(AccountKind::Org)
    }

    /// The organisations' own limits: (id, name, limits).
    pub fn own_limits(&self) -> Vec<(i32, &str, &Limits)> {
        self.limits
            .iter()
            .filter_map(|row| {
                let (id, name) = row.org.as_ref()?;
                Some((*id, name.as_str(), &row.limits))
            })
            .collect()
    }
}

/// The session acting as a global admin on the platform; 404 for any other session. A
/// global admin's session without its second factor holds no admin role (`Tenancy`), so
/// it is sent to set one up (C24).
pub(super) async fn operator(
    portal: &super::Portal,
    signed_in: &SignedIn,
) -> Result<Actor, Response> {
    let session = signed_in.tenancy_session();
    // Whether the login is a global admin at all, second factor aside.
    if !portal
        .tenancy()
        .global_admin(&session.with_second_factor(true))
        .await
    {
        return Err(not_found());
    }
    if !signed_in.second_factor {
        return Err(second_factor_first());
    }
    let platform = portal
        .tenancy()
        .authorized_place(&session, PLATFORM)
        .await
        .map_err(|_| not_found())?;
    acting_on(portal, signed_in, &platform).await
}

/// The session's actor loaded for `place`.
async fn acting_on(
    portal: &super::Portal,
    signed_in: &SignedIn,
    place: &Authorized<Place>,
) -> Result<Actor, Response> {
    portal
        .tenancy()
        .actor(&signed_in.tenancy_session(), place)
        .await
        .map_err(unavailable)
}

/// `place` through `authorized_place`, for a global admin's session.
async fn place_of(
    portal: &super::Portal,
    signed_in: &SignedIn,
    kind: LayerKind,
    id: i32,
) -> Option<Authorized<Place>> {
    let place = PlaceRef {
        kind,
        id: u32::try_from(id).ok()?,
    };
    portal
        .tenancy()
        .authorized_place(&signed_in.tenancy_session(), place)
        .await
        .ok()
}

pub(crate) async fn show(State(portal): State<Shared>, headers: HeaderMap) -> Response {
    let signed_in = match portal.signed_in(&headers).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    if let Err(answer) = operator(&portal, &signed_in).await {
        return answer;
    }
    page(&portal, &signed_in, StatusCode::OK, None, None).await
}

async fn page(
    portal: &super::Portal,
    signed_in: &SignedIn,
    status: StatusCode,
    error: Option<String>,
    new_token: Option<String>,
) -> Response {
    let built = async {
        let platform = portal
            .tenancy()
            .authorized_place(&signed_in.tenancy_session(), PLATFORM)
            .await
            .map_err(|_| sqlx::Error::RowNotFound)?;
        let limits = keys::limits(&portal.pool).await?;
        let orgs = orgs(&portal.pool).await?;
        let default_orgs = orgs
            .iter()
            .filter(|org| {
                org.deleted.is_none()
                    && !limits
                        .iter()
                        .any(|row| row.org.as_ref().is_some_and(|(id, _)| *id == org.id))
            })
            .map(|org| (org.id, org.name.clone()))
            .collect();
        let (activity_days, audit_days) = audit::retention(&portal.pool).await?;
        let mut top = signed_in.top(portal).await?;
        top.page = "admin";
        Ok::<_, sqlx::Error>(AdminPage {
            csrf: top.csrf.clone(),
            top: Some(top),
            title: "Global admin",
            view: AdminView {
                orgs,
                personal: personal(&portal.pool).await?,
                ranges: ranges(&portal.pool).await?,
                admins: admins(&portal.pool).await?,
                limits,
                default_orgs,
                activity_days,
                audit_days,
                tokens: keys::tokens(&portal.pool, &platform).await?,
                new_token,
                error,
            },
        })
    };
    match built.await {
        Ok(page) => render(status, &page),
        Err(err) => unavailable(err),
    }
}

async fn orgs(pool: &PgPool) -> Result<Vec<OrgRow>, sqlx::Error> {
    type Row = (i32, String, bool, Option<String>, i64, i64);
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT o.id, o.name, o.status = 'suspended', to_char(o.restore_until, 'DD Mon YYYY'),
                (SELECT count(*) FROM memberships AS m WHERE m.org_id = o.id),
                (SELECT count(*) FROM keys AS k WHERE k.revoked_at IS NULL AND k.kind IN ('user', 'service')
                   AND place_org(k.place_kind, k.place_id) = o.id)
         FROM orgs AS o ORDER BY lower(o.name), o.id",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, name, suspended, deleted, members, keys)| OrgRow {
            id,
            name,
            suspended,
            deleted,
            members,
            keys,
        })
        .collect())
}

async fn personal(pool: &PgPool) -> Result<Vec<PersonalRow>, sqlx::Error> {
    type Row = (i32, Option<String>, bool, Option<String>, i64, String);
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT p.id,
                (SELECT s.email FROM sign_in_methods AS s WHERE s.login_id = p.login_id
                   AND s.email IS NOT NULL ORDER BY s.id LIMIT 1),
                p.status = 'suspended',
                CASE WHEN p.deleted_at IS NOT NULL THEN to_char(p.restore_until, 'DD Mon YYYY') END,
                (SELECT count(*) FROM keys AS k WHERE k.place_kind = 'personal' AND k.place_id = p.id
                   AND k.revoked_at IS NULL),
                to_char(l.created_at, 'DD Mon YYYY')
         FROM personal_accounts AS p JOIN logins AS l ON l.id = p.login_id AND l.deleted_at IS NULL
         WHERE p.deleted_at IS NULL OR p.restore_until > now()
         ORDER BY 2, p.id",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(id, email, suspended, erased_on, keys, created)| PersonalRow {
                id,
                email: email.unwrap_or_else(|| format!("Personal account {id}")),
                suspended,
                erased_on,
                keys,
                created,
            },
        )
        .collect())
}

/// The ranges waiting for approval, then the approved ones, of live organisations.
async fn ranges(pool: &PgPool) -> Result<Vec<RangeRow>, sqlx::Error> {
    type Row = (i32, String, String, Option<String>, String, bool);
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT r.id, o.name, r.cidr::text,
                (SELECT s.email FROM audit_log AS a JOIN sign_in_methods AS s ON s.login_id = a.actor_login
                 WHERE a.action IN ('range.add', 'range.resubmit') AND a.subject = 'range:' || r.id
                   AND s.email IS NOT NULL ORDER BY a.id DESC, s.id LIMIT 1),
                to_char(r.created_at, 'DD Mon YYYY'), r.approved_by IS NOT NULL
         FROM org_ip_ranges AS r JOIN orgs AS o ON o.id = r.org_id AND o.deleted_at IS NULL
         WHERE r.refused_reason IS NULL
         ORDER BY r.approved_by IS NOT NULL, r.id",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, org, cidr, asked_by, asked, approved)| RangeRow {
            id,
            org,
            cidr,
            asked_by: asked_by.unwrap_or_default(),
            asked,
            approved,
        })
        .collect())
}

async fn admins(pool: &PgPool) -> Result<Vec<(i32, String)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT m.login_id,
                coalesce((SELECT s.email FROM sign_in_methods AS s WHERE s.login_id = m.login_id
                            AND s.email IS NOT NULL ORDER BY s.id LIMIT 1), 'Login ' || m.login_id)
         FROM memberships AS m JOIN logins AS l ON l.id = m.login_id AND l.deleted_at IS NULL
         WHERE m.org_id IS NULL ORDER BY 2",
    )
    .fetch_all(pool)
    .await
}

/// The answer to an admin action: back to `/admin`, or the page with what was refused.
async fn after(
    portal: &super::Portal,
    signed_in: &SignedIn,
    done: Result<(), ChangeError>,
) -> Response {
    match done {
        Ok(()) => redirect("/admin"),
        Err(ChangeError::Denied) => refused("Only a global admin can do this."),
        Err(ChangeError::NotFound) => not_found(),
        Err(ChangeError::Refused(reason)) => {
            page(portal, signed_in, StatusCode::CONFLICT, Some(reason), None).await
        }
        Err(ChangeError::Store(err)) => unavailable(err),
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(crate) struct CsrfForm {
    csrf: String,
}

/// A POST on a place of `kind` named by the path: the session, the operator gate, the
/// place and the actor loaded for it.
async fn on_place(
    portal: &super::Portal,
    headers: &HeaderMap,
    csrf: &str,
    kind: LayerKind,
    id: i32,
) -> Result<(SignedIn, Actor, Authorized<Place>), Response> {
    let signed_in = portal.signed_in_post(headers, csrf).await?;
    operator(portal, &signed_in).await?;
    let place = place_of(portal, &signed_in, kind, id)
        .await
        .ok_or_else(not_found)?;
    let actor = acting_on(portal, &signed_in, &place).await?;
    Ok((signed_in, actor, place))
}

/// "Suspend Northwind?", "Delete jane@example.com's personal account?" and "Revoke all
/// of jane@example.com's keys?": what a destructive action does, before its POST
/// (mockup global-admin.html, destructive confirm states).
#[derive(Template)]
#[template(
    source = r#"{% extends "base.html" %}{% block content %}
<h1>{{ heading }}</h1>
<p>{{ effect }}</p>
<form method="post" action="{{ action }}" class="row">
<input type="hidden" name="csrf" value="{{ csrf }}">
<button type="submit" class="danger">{{ button }}</button>
<a href="/admin">Cancel</a>
</form>
{% endblock %}"#,
    ext = "html"
)]
pub(crate) struct ConfirmPage {
    pub top: Option<Top>,
    pub title: &'static str,
    pub csrf: String,
    pub heading: String,
    pub effect: String,
    pub action: String,
    pub button: &'static str,
}

/// The confirmation of `what` on organisation or personal account `id`.
async fn confirm(
    portal: Shared,
    headers: HeaderMap,
    kind: LayerKind,
    id: i32,
    what: &str,
) -> Response {
    let signed_in = match portal.signed_in(&headers).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    if let Err(answer) = operator(&portal, &signed_in).await {
        return answer;
    }
    let Some(place) = place_of(&portal, &signed_in, kind, id).await else {
        return not_found();
    };
    let found = async {
        let keys: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM keys AS k WHERE k.revoked_at IS NULL AND k.kind IN ('user', 'service')
               AND ((k.place_kind = 'personal' AND k.place_id = $1 AND $2 = 'personal')
                    OR ($2 = 'org' AND place_org(k.place_kind, k.place_id) = $1))",
        )
        .bind(id)
        .bind(tenancy::kind_str(kind))
        .fetch_one(&portal.pool)
        .await?;
        let name = match place.org_name() {
            Some(name) => name.to_owned(),
            None => sqlx::query_scalar(
                "SELECT coalesce((SELECT s.email FROM sign_in_methods AS s WHERE s.login_id = p.login_id
                   AND s.email IS NOT NULL ORDER BY s.id LIMIT 1), 'Personal account ' || p.id)
                 FROM personal_accounts AS p WHERE p.id = $1",
            )
            .bind(id)
            .fetch_one(&portal.pool)
            .await?,
        };
        let mut top = signed_in.top(&portal).await?;
        top.page = "admin";
        Ok::<_, sqlx::Error>((keys, name, top))
    };
    let (keys, name, top) = match found.await {
        Ok(found) => found,
        Err(err) => return unavailable(err),
    };
    let (heading, effect, button) = match what {
        "suspend" => (
            format!("Suspend {name}?"),
            format!(
                "Probation refuses all of {name}'s {keys} keys within about 1 minute, until you re-activate it. Its members can still sign in to the portal, read-only, with a banner explaining the suspension."
            ),
            "Suspend",
        ),
        "revoke-keys" => (
            format!("Revoke all {keys} of {name}'s keys?"),
            "Anything using them stops downloading within about 1 minute. This cannot be undone."
                .to_owned(),
            "Revoke keys",
        ),
        _ => (
            format!("Delete {name}'s personal account?"),
            format!(
                "Its {keys} keys stop working within about 1 minute. Everything else is erased after 30 days and can be restored until then."
            ),
            "Delete account",
        ),
    };
    let noun = if kind == LayerKind::Org {
        "orgs"
    } else {
        "personal"
    };
    let page = ConfirmPage {
        csrf: top.csrf.clone(),
        top: Some(top),
        title: "Global admin",
        heading,
        effect,
        action: format!("/admin/{noun}/{id}/{what}"),
        button,
    };
    render(StatusCode::OK, &page)
}

pub(crate) async fn confirm_suspend_org(
    State(portal): State<Shared>,
    Path(id): Path<i32>,
    headers: HeaderMap,
) -> Response {
    confirm(portal, headers, LayerKind::Org, id, "suspend").await
}

pub(crate) async fn confirm_revoke_keys(
    State(portal): State<Shared>,
    Path(id): Path<i32>,
    headers: HeaderMap,
) -> Response {
    confirm(portal, headers, LayerKind::Personal, id, "revoke-keys").await
}

pub(crate) async fn confirm_delete_personal(
    State(portal): State<Shared>,
    Path(id): Path<i32>,
    headers: HeaderMap,
) -> Response {
    confirm(portal, headers, LayerKind::Personal, id, "delete").await
}

async fn org_status(
    portal: Shared,
    headers: HeaderMap,
    id: i32,
    csrf: &str,
    suspend: bool,
) -> Response {
    match on_place(&portal, &headers, csrf, LayerKind::Org, id).await {
        Ok((signed_in, actor, org)) => {
            let done = tenancy::set_status(&portal.pool, &actor, &org, suspend).await;
            after(&portal, &signed_in, done).await
        }
        Err(answer) => answer,
    }
}

/// "Suspend" an organisation (C64, C78).
pub(crate) async fn suspend_org(
    State(portal): State<Shared>,
    Path(id): Path<i32>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    org_status(portal, headers, id, &form.csrf, true).await
}

/// "Re-activate" an organisation.
pub(crate) async fn activate_org(
    State(portal): State<Shared>,
    Path(id): Path<i32>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    org_status(portal, headers, id, &form.csrf, false).await
}

/// One action on a live personal account (C65).
async fn on_personal(
    portal: Shared,
    headers: HeaderMap,
    id: i32,
    csrf: &str,
    action: &str,
) -> Response {
    let (signed_in, actor, place) =
        match on_place(&portal, &headers, csrf, LayerKind::Personal, id).await {
            Ok(found) => found,
            Err(answer) => return answer,
        };
    let pool = &portal.pool;
    let done = match action {
        "suspend" => tenancy::set_status(pool, &actor, &place, true).await,
        "activate" => tenancy::set_status(pool, &actor, &place, false).await,
        "revoke-keys" => keys::revoke_all(pool, &actor, &place)
            .await
            .map_err(|err| match err {
                keys::RevokeError::Store(err) => ChangeError::Store(err),
                keys::RevokeError::NotFound => ChangeError::NotFound,
                keys::RevokeError::Denied => ChangeError::Denied,
            }),
        "totp-reset" => accounts::admin_reset_totp(pool, &actor, &place).await,
        _ => accounts::admin_delete_personal(pool, &actor, &place).await,
    };
    after(&portal, &signed_in, done).await
}

pub(crate) async fn suspend_personal(
    State(portal): State<Shared>,
    Path(id): Path<i32>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    on_personal(portal, headers, id, &form.csrf, "suspend").await
}

pub(crate) async fn activate_personal(
    State(portal): State<Shared>,
    Path(id): Path<i32>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    on_personal(portal, headers, id, &form.csrf, "activate").await
}

pub(crate) async fn revoke_keys(
    State(portal): State<Shared>,
    Path(id): Path<i32>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    on_personal(portal, headers, id, &form.csrf, "revoke-keys").await
}

pub(crate) async fn reset_totp(
    State(portal): State<Shared>,
    Path(id): Path<i32>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    on_personal(portal, headers, id, &form.csrf, "totp-reset").await
}

pub(crate) async fn delete_personal(
    State(portal): State<Shared>,
    Path(id): Path<i32>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    on_personal(portal, headers, id, &form.csrf, "delete").await
}

/// "Restore" a deleted personal account within its 30 days (C33, C65). A deleted account
/// is no `Authorized<Place>`, so the store checks it is restorable.
pub(crate) async fn restore_personal(
    State(portal): State<Shared>,
    Path(id): Path<i32>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    let signed_in = match portal.signed_in_post(&headers, &form.csrf).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    let actor = match operator(&portal, &signed_in).await {
        Ok(actor) => actor,
        Err(answer) => return answer,
    };
    let done = accounts::admin_restore_personal(&portal.pool, &actor, id).await;
    after(&portal, &signed_in, done).await
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(crate) struct ReasonForm {
    csrf: String,
    reason: String,
}

/// A range of a live organisation, with the actor loaded for its organisation.
async fn on_range(
    portal: &super::Portal,
    headers: &HeaderMap,
    csrf: &str,
    id: i32,
) -> Result<(SignedIn, Actor, Authorized<Place>), Response> {
    let signed_in = portal.signed_in_post(headers, csrf).await?;
    operator(portal, &signed_in).await?;
    let org = portal
        .tenancy()
        .authorized_owner(&signed_in.tenancy_session(), Owned::Range(id))
        .await
        .map_err(|_| not_found())?;
    let actor = acting_on(portal, &signed_in, &org).await?;
    Ok((signed_in, actor, org))
}

/// "Approve" a network-lock range (C77, C87).
pub(crate) async fn approve_range(
    State(portal): State<Shared>,
    Path(id): Path<i32>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    match on_range(&portal, &headers, &form.csrf, id).await {
        Ok((signed_in, actor, org)) => {
            let done = tenancy::decide_range(&portal.pool, &actor, &org, id, None).await;
            after(&portal, &signed_in, done).await
        }
        Err(answer) => answer,
    }
}

/// "Refuse" a range, with the reason its org admins see (C87).
pub(crate) async fn refuse_range(
    State(portal): State<Shared>,
    Path(id): Path<i32>,
    headers: HeaderMap,
    Form(form): Form<ReasonForm>,
) -> Response {
    match on_range(&portal, &headers, &form.csrf, id).await {
        Ok((signed_in, actor, org)) => {
            let done =
                tenancy::decide_range(&portal.pool, &actor, &org, id, Some(&form.reason)).await;
            after(&portal, &signed_in, done).await
        }
        Err(answer) => answer,
    }
}

/// "Remove" an approved range: firewalls drop it within one interval (C87).
pub(crate) async fn delete_range(
    State(portal): State<Shared>,
    Path(id): Path<i32>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    match on_range(&portal, &headers, &form.csrf, id).await {
        Ok((signed_in, actor, org)) => {
            let done = tenancy::delete_range(&portal.pool, &actor, &org, id).await;
            after(&portal, &signed_in, done).await
        }
        Err(answer) => answer,
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(crate) struct EmailForm {
    csrf: String,
    email: String,
}

/// "Add global admin": a single-use invitation link (C4, T3).
pub(crate) async fn invite_admin(
    State(portal): State<Shared>,
    headers: HeaderMap,
    Form(form): Form<EmailForm>,
) -> Response {
    let signed_in = match portal.signed_in_post(&headers, &form.csrf).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    let actor = match operator(&portal, &signed_in).await {
        Ok(actor) => actor,
        Err(answer) => return answer,
    };
    let done =
        tenancy::invite_global_admin(&portal.pool, &actor, &form.email, &portal.config.base_url)
            .await;
    after(&portal, &signed_in, done).await
}

/// "Remove" a global admin; the last one stays (C90).
pub(crate) async fn remove_admin(
    State(portal): State<Shared>,
    Path(id): Path<i32>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    let signed_in = match portal.signed_in_post(&headers, &form.csrf).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    let actor = match operator(&portal, &signed_in).await {
        Ok(actor) => actor,
        Err(answer) => return answer,
    };
    let done = tenancy::remove_global_admin(&portal.pool, &actor, id).await;
    after(&portal, &signed_in, done).await
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(crate) struct LimitsForm {
    csrf: String,
    /// `personal` or `org`.
    kind: String,
    /// An organisation's id for its own limits, from "Set own limits".
    org: String,
    rate: String,
    keys: String,
    service: String,
}

impl LimitsForm {
    fn limits(&self) -> Result<Limits, ChangeError> {
        let number = |text: &str| text.trim().parse::<i32>().ok();
        let (Some(rate_per_min), Some(max_keys)) = (number(&self.rate), number(&self.keys)) else {
            return Err(ChangeError::Refused(
                "Not saved. Enter whole numbers.".to_owned(),
            ));
        };
        Ok(Limits {
            rate_per_min,
            max_keys,
            max_service_keys: number(&self.service),
        })
    }
}

/// "Save limits" for an account kind's default, or "Set own limits" for an organisation
/// (C28, C51, C67).
pub(crate) async fn save_limits(
    State(portal): State<Shared>,
    headers: HeaderMap,
    Form(form): Form<LimitsForm>,
) -> Response {
    let signed_in = match portal.signed_in_post(&headers, &form.csrf).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    let actor = match operator(&portal, &signed_in).await {
        Ok(actor) => actor,
        Err(answer) => return answer,
    };
    if let Ok(org) = form.org.parse::<i32>() {
        return org_limits(portal, signed_in, org, &form).await;
    }
    let kind = match form.kind.as_str() {
        "personal" => AccountKind::Personal,
        "org" => AccountKind::Org,
        _ => return not_found(),
    };
    let done = match form.limits() {
        Ok(limits) => keys::set_limits(&portal.pool, &actor, kind, None, limits).await,
        Err(refusal) => Err(refusal),
    };
    after(&portal, &signed_in, done).await
}

async fn org_limits(portal: Shared, signed_in: SignedIn, org: i32, form: &LimitsForm) -> Response {
    let Some(place) = place_of(&portal, &signed_in, LayerKind::Org, org).await else {
        return not_found();
    };
    let actor = match acting_on(&portal, &signed_in, &place).await {
        Ok(actor) => actor,
        Err(answer) => return answer,
    };
    let done = match form.limits() {
        Ok(limits) => {
            keys::set_limits(&portal.pool, &actor, AccountKind::Org, Some(&place), limits).await
        }
        Err(refusal) => Err(refusal),
    };
    after(&portal, &signed_in, done).await
}

/// "Save" on an organisation's own limits (C67).
pub(crate) async fn save_org_limits(
    State(portal): State<Shared>,
    Path(id): Path<i32>,
    headers: HeaderMap,
    Form(form): Form<LimitsForm>,
) -> Response {
    let signed_in = match portal.signed_in_post(&headers, &form.csrf).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    if let Err(answer) = operator(&portal, &signed_in).await {
        return answer;
    }
    org_limits(portal, signed_in, id, &form).await
}

/// "Back to default" on an organisation's own limits.
pub(crate) async fn reset_org_limits(
    State(portal): State<Shared>,
    Path(id): Path<i32>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    match on_place(&portal, &headers, &form.csrf, LayerKind::Org, id).await {
        Ok((signed_in, actor, org)) => {
            let done = keys::reset_limits(&portal.pool, &actor, &org).await;
            after(&portal, &signed_in, done).await
        }
        Err(answer) => answer,
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(crate) struct RetentionForm {
    csrf: String,
    activity_days: String,
    audit_days: String,
}

/// "Save" on how long history is kept (C26, C68).
pub(crate) async fn save_retention(
    State(portal): State<Shared>,
    headers: HeaderMap,
    Form(form): Form<RetentionForm>,
) -> Response {
    let signed_in = match portal.signed_in_post(&headers, &form.csrf).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    let actor = match operator(&portal, &signed_in).await {
        Ok(actor) => actor,
        Err(answer) => return answer,
    };
    let days = |text: &str| text.trim().parse::<i32>().unwrap_or(0);
    let done = audit::set_retention(
        &portal.pool,
        &actor,
        days(&form.activity_days),
        days(&form.audit_days),
    )
    .await;
    after(&portal, &signed_in, done).await
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(crate) struct NameForm {
    csrf: String,
    name: String,
}

/// "Create token" for the platform layer (C80, C86): shown once.
pub(crate) async fn create_token(
    State(portal): State<Shared>,
    headers: HeaderMap,
    Form(form): Form<NameForm>,
) -> Response {
    let signed_in = match portal.signed_in_post(&headers, &form.csrf).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    let actor = match operator(&portal, &signed_in).await {
        Ok(actor) => actor,
        Err(answer) => return answer,
    };
    let Some(platform) = place_of(&portal, &signed_in, LayerKind::Platform, 1).await else {
        return not_found();
    };
    let name = form.name.trim();
    if name.is_empty() || name.chars().count() > 100 {
        let refusal = "Give the token a name of at most 100 characters.".to_owned();
        return after(&portal, &signed_in, Err(ChangeError::Refused(refusal))).await;
    }
    match keys::create_token(&portal.pool, &actor, &platform, name).await {
        Ok(token) => {
            page(
                &portal,
                &signed_in,
                StatusCode::OK,
                None,
                Some(token.secret),
            )
            .await
        }
        Err(keys::KeyError::Store(err)) => unavailable(err),
        Err(_) => refused("Only a global admin can do this."),
    }
}

/// "Revoke" on a platform automation token.
pub(crate) async fn revoke_token(
    State(portal): State<Shared>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    let signed_in = match portal.signed_in_post(&headers, &form.csrf).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    let actor = match operator(&portal, &signed_in).await {
        Ok(actor) => actor,
        Err(answer) => return answer,
    };
    let Some(platform) = place_of(&portal, &signed_in, LayerKind::Platform, 1).await else {
        return not_found();
    };
    let done = match keys::revoke_token(&portal.pool, &actor, &platform, id).await {
        Ok(()) => Ok(()),
        Err(keys::RevokeError::NotFound) => Err(ChangeError::NotFound),
        Err(keys::RevokeError::Denied) => Err(ChangeError::Denied),
        Err(keys::RevokeError::Store(err)) => Err(ChangeError::Store(err)),
    };
    after(&portal, &signed_in, done).await
}

/// "Export" the platform layer's blocks (C80).
pub(crate) async fn export_blocklist(State(portal): State<Shared>, headers: HeaderMap) -> Response {
    let signed_in = match portal.signed_in(&headers).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    if let Err(answer) = operator(&portal, &signed_in).await {
        return answer;
    }
    let Some(platform) = place_of(&portal, &signed_in, LayerKind::Platform, 1).await else {
        return not_found();
    };
    blocklist_file(policy::export_blocks(&portal.pool, &platform).await)
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(crate) struct ImportForm {
    csrf: String,
    file: String,
}

/// "Import" a blocklist file into the platform layer (C80).
pub(crate) async fn import_blocklist(
    State(portal): State<Shared>,
    headers: HeaderMap,
    Form(form): Form<ImportForm>,
) -> Response {
    let signed_in = match portal.signed_in_post(&headers, &form.csrf).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    let actor = match operator(&portal, &signed_in).await {
        Ok(actor) => actor,
        Err(answer) => return answer,
    };
    let Some(platform) = place_of(&portal, &signed_in, LayerKind::Platform, 1).await else {
        return not_found();
    };
    let done = import_into(&portal, &actor, &platform, &form.file).await;
    after(&portal, &signed_in, done).await
}
