//! The organisation page (mockup organisation.html): members, roles and groups,
//! invitations, leave requests, company SSO, network-lock ranges, automation tokens and
//! blocklist files for its layers (C80, C86), and deleting and restoring the
//! organisation. Every id in a path goes through `authorized_owner` or
//! `authorized_place` first (404, C1, T9); then the org admin's role (403) and, for a
//! password session, the authenticator (C24, C60).

use askama::Template;
use axum::extract::{Form, Path, Query, State};
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use probation_policy::{LayerKind, PlaceRef};
use serde::Deserialize;

use super::{Shared, SignedIn, Top, not_found, redirect, refused, render, unavailable};
use crate::accounts;
use crate::keys::{self, TokenRow};
use crate::policy::{self, PushError, StoreError};
use crate::tenancy::{
    self, Actor, Authorized, ChangeError, GroupRow, MemberRow, Owned, Place, RangeRow, Role,
};

#[derive(Template)]
#[template(path = "organisation.html")]
pub(crate) struct OrgPage {
    pub top: Option<Top>,
    pub title: &'static str,
    pub csrf: String,
    pub view: OrgView,
}

pub(crate) enum OrgView {
    /// The session's place is no organisation; the deleted organisations it may
    /// restore, as (id, name, deleted on, erased on), and its organisation's page.
    None {
        restorable: Vec<(i32, String, String, String)>,
        current: Option<i32>,
    },
    /// A member who is no org admin: only their own leave request.
    Member(Leaving),
    Admin(Box<AdminView>),
    /// An invitation link opened by a signed-in login: what it grants, or `None` when
    /// it is unknown, used or expired (C43).
    Invitation {
        token: String,
        grant: Option<(String, String, Option<String>)>,
    },
    /// "Delete the Frontend group?" with what it does (C61).
    DeleteGroup {
        id: i32,
        org: i32,
        name: String,
        members: i64,
        service_keys: Vec<String>,
    },
}

/// The session's own leave request in an organisation (C85, C88).
pub(crate) struct Leaving {
    pub id: i32,
    pub name: String,
    /// Asked on this date and waiting.
    pub asked: Option<String>,
}

pub(crate) struct AdminView {
    pub id: i32,
    pub name: String,
    pub leaving: Leaving,
    /// Waiting leave requests: (id, email, asked on).
    pub leave_requests: Vec<(i32, String, String)>,
    /// Waiting invitations: (id, email, role, expires on).
    pub invitations: Vec<(i32, String, String, String)>,
    /// Company SSO when it is on: (issuer, client id, required tenant).
    pub sso: Option<(String, String, Option<String>)>,
    /// The redirect address to give the provider.
    pub sso_callback: String,
    pub ranges: Vec<RangeRow>,
    pub members: Vec<MemberRow>,
    pub groups: Vec<GroupRow>,
    /// Live automation tokens of its layers, and one just created, shown once (C86).
    pub tokens: Vec<TokenRow>,
    pub new_token: Option<String>,
    pub error: Option<String>,
}

/// `/org`: the organisation of the session's place.
pub(crate) async fn start(State(portal): State<Shared>, headers: HeaderMap) -> Response {
    let signed_in = match portal.signed_in(&headers).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    let found = async {
        let current = signed_in
            .account(&portal)
            .await?
            .and_then(|account| account.org());
        let restorable =
            tenancy::restorable_orgs(&portal.pool, &signed_in.tenancy_session()).await?;
        Ok::<_, sqlx::Error>((current, restorable))
    };
    match found.await {
        Ok((Some(org), restorable)) if restorable.is_empty() => redirect(&format!("/org/{org}")),
        Ok((current, restorable)) => {
            let view = OrgView::None {
                restorable,
                current,
            };
            render_page(&portal, &signed_in, StatusCode::OK, view).await
        }
        Err(err) => unavailable(err),
    }
}

pub(crate) async fn show(
    State(portal): State<Shared>,
    Path(org): Path<i32>,
    headers: HeaderMap,
) -> Response {
    let signed_in = match portal.signed_in(&headers).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    let Some(place) = org_place(&portal, &signed_in, org).await else {
        return not_found();
    };
    let actor = match portal
        .tenancy()
        .actor(&signed_in.tenancy_session(), &place)
        .await
    {
        Ok(actor) => actor,
        Err(err) => return unavailable(err),
    };
    if !is_admin(&actor, &place) {
        return match leaving(&portal, &signed_in, &place).await {
            Ok(leaving) => {
                render_page(
                    &portal,
                    &signed_in,
                    StatusCode::OK,
                    OrgView::Member(leaving),
                )
                .await
            }
            Err(err) => unavailable(err),
        };
    }
    if let Err(answer) = second_factor(&portal, &signed_in).await {
        return answer;
    }
    admin_page(&portal, &signed_in, &place, StatusCode::OK, None).await
}

/// The organisation `org` through `authorized_place`.
async fn org_place(
    portal: &super::Portal,
    signed_in: &SignedIn,
    org: i32,
) -> Option<Authorized<Place>> {
    let place = PlaceRef {
        kind: LayerKind::Org,
        id: u32::try_from(org).ok()?,
    };
    portal
        .tenancy()
        .authorized_place(&signed_in.tenancy_session(), place)
        .await
        .ok()
}

fn is_admin(actor: &Actor, place: &Authorized<Place>) -> bool {
    matches!(
        actor.role(place.place()),
        Some(Role::OrgAdmin | Role::GlobalAdmin)
    )
}

/// A password session acts as an admin only once its login has an authenticator; an
/// OAuth or SSO session has its provider's second factor (C24, C38, C60, T15).
pub(super) async fn second_factor(
    portal: &super::Portal,
    signed_in: &SignedIn,
) -> Result<(), Response> {
    if signed_in.session.totp_ok {
        return Ok(());
    }
    match accounts::has_totp(&portal.pool, signed_in.login_id).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(redirect("/account#totp-heading")),
        Err(err) => Err(unavailable(err)),
    }
}

/// The actor on `place` when it is an org admin there (or a global admin) with its
/// second factor: every admin action's check after `authorized_*`.
async fn admin_on(
    portal: &super::Portal,
    signed_in: &SignedIn,
    place: &Authorized<Place>,
) -> Result<Actor, Response> {
    let actor = portal
        .tenancy()
        .actor(&signed_in.tenancy_session(), place)
        .await
        .map_err(unavailable)?;
    if !is_admin(&actor, place) {
        return Err(refused("Only the organisation's org admins can do this."));
    }
    second_factor(portal, signed_in).await?;
    Ok(actor)
}

async fn admin_page(
    portal: &super::Portal,
    signed_in: &SignedIn,
    place: &Authorized<Place>,
    status: StatusCode,
    error: Option<String>,
) -> Response {
    admin_page_with(portal, signed_in, place, status, error, None).await
}

async fn admin_page_with(
    portal: &super::Portal,
    signed_in: &SignedIn,
    place: &Authorized<Place>,
    status: StatusCode,
    error: Option<String>,
    new_token: Option<String>,
) -> Response {
    let built = async {
        Ok::<_, sqlx::Error>(AdminView {
            id: place.place().id as i32,
            name: place.org_name().unwrap_or_default().to_owned(),
            leaving: leaving(portal, signed_in, place).await?,
            leave_requests: tenancy::leave_requests(&portal.pool, place).await?,
            invitations: tenancy::invitations(&portal.pool, place).await?,
            sso: accounts::sso_settings(&portal.pool, place.place().id as i32).await?,
            ranges: tenancy::ranges(&portal.pool, place).await?,
            sso_callback: portal
                .link(&format!("sso/{}/callback", place.place().id))
                .to_string(),
            members: tenancy::members(&portal.pool, place).await?,
            groups: tenancy::groups(&portal.pool, place).await?,
            tokens: keys::tokens(&portal.pool, place).await?,
            new_token,
            error,
        })
    };
    match built.await {
        Ok(view) => render_page(portal, signed_in, status, OrgView::Admin(Box::new(view))).await,
        Err(err) => unavailable(err),
    }
}

async fn leaving(
    portal: &super::Portal,
    signed_in: &SignedIn,
    place: &Authorized<Place>,
) -> Result<Leaving, sqlx::Error> {
    Ok(Leaving {
        id: place.place().id as i32,
        name: place.org_name().unwrap_or_default().to_owned(),
        asked: tenancy::own_leave_request(&portal.pool, signed_in.login_id, place).await?,
    })
}

async fn render_page(
    portal: &super::Portal,
    signed_in: &SignedIn,
    status: StatusCode,
    view: OrgView,
) -> Response {
    match signed_in.top(portal).await {
        Ok(mut top) => {
            top.page = "org";
            let page = OrgPage {
                csrf: top.csrf.clone(),
                top: Some(top),
                title: "Organisation",
                view,
            };
            render(status, &page)
        }
        Err(err) => unavailable(err),
    }
}

/// The member at user place `id`, through `authorized_place`.
async fn member_place(
    portal: &super::Portal,
    signed_in: &SignedIn,
    id: i32,
) -> Option<Authorized<Place>> {
    let place = PlaceRef {
        kind: LayerKind::User,
        id: u32::try_from(id).ok()?,
    };
    portal
        .tenancy()
        .authorized_place(&signed_in.tenancy_session(), place)
        .await
        .ok()
}

/// A group of the organisation `org`, through `authorized_owner`; `None` for another
/// organisation's or an unknown one.
async fn group_place(
    portal: &super::Portal,
    signed_in: &SignedIn,
    org: Option<i32>,
    id: &str,
) -> Option<Authorized<Place>> {
    let group = portal
        .tenancy()
        .authorized_owner(&signed_in.tenancy_session(), Owned::Group(id.parse().ok()?))
        .await
        .ok()?;
    (group.org() == org).then_some(group)
}

/// The answer to an admin action: back to the organisation page, or the page with what
/// was refused.
async fn after(
    portal: &super::Portal,
    signed_in: &SignedIn,
    place: &Authorized<Place>,
    done: Result<(), ChangeError>,
) -> Response {
    let org = place.org().unwrap_or_default();
    match done {
        Ok(()) => redirect(&format!("/org/{org}")),
        Err(ChangeError::Denied) => refused("Only the organisation's org admins can do this."),
        Err(ChangeError::NotFound) => not_found(),
        Err(ChangeError::Refused(reason)) => {
            let Some(org) = org_place(portal, signed_in, org).await else {
                return not_found();
            };
            admin_page(portal, signed_in, &org, StatusCode::CONFLICT, Some(reason)).await
        }
        Err(ChangeError::Store(err)) => unavailable(err),
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(crate) struct MemberForm {
    csrf: String,
    /// A group id, or "none".
    group: String,
    role: String,
}

/// "Group" on a member's row: only org admins move people (C27).
pub(crate) async fn move_member(
    State(portal): State<Shared>,
    Path(id): Path<i32>,
    headers: HeaderMap,
    Form(form): Form<MemberForm>,
) -> Response {
    let signed_in = match portal.signed_in_post(&headers, &form.csrf).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    let Some(member) = member_place(&portal, &signed_in, id).await else {
        return not_found();
    };
    let group = if form.group == "none" {
        None
    } else {
        match group_place(&portal, &signed_in, member.org(), &form.group).await {
            Some(group) => Some(group),
            None => return not_found(),
        }
    };
    let actor = match admin_on(&portal, &signed_in, &member).await {
        Ok(actor) => actor,
        Err(answer) => return answer,
    };
    let done = tenancy::move_member(&portal.pool, &actor, &member, group.as_ref()).await;
    after(&portal, &signed_in, &member, done).await
}

/// "Role" on a member's row (C27, C59).
pub(crate) async fn set_role(
    State(portal): State<Shared>,
    Path(id): Path<i32>,
    headers: HeaderMap,
    Form(form): Form<MemberForm>,
) -> Response {
    let signed_in = match portal.signed_in_post(&headers, &form.csrf).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    let Some(member) = member_place(&portal, &signed_in, id).await else {
        return not_found();
    };
    let actor = match admin_on(&portal, &signed_in, &member).await {
        Ok(actor) => actor,
        Err(answer) => return answer,
    };
    let done = tenancy::set_role(&portal.pool, &actor, &member, &form.role).await;
    after(&portal, &signed_in, &member, done).await
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(crate) struct CsrfForm {
    csrf: String,
}

/// "Remove" on a member's row (C52, C60).
pub(crate) async fn remove_member(
    State(portal): State<Shared>,
    Path(id): Path<i32>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    let signed_in = match portal.signed_in_post(&headers, &form.csrf).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    let Some(member) = member_place(&portal, &signed_in, id).await else {
        return not_found();
    };
    let actor = match admin_on(&portal, &signed_in, &member).await {
        Ok(actor) => actor,
        Err(answer) => return answer,
    };
    let done = tenancy::remove_member(&portal.pool, &actor, &member).await;
    after(&portal, &signed_in, &member, done).await
}

/// "Ask to leave": any member's own request (C85).
pub(crate) async fn ask_to_leave(
    State(portal): State<Shared>,
    Path(org): Path<i32>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    let signed_in = match portal.signed_in_post(&headers, &form.csrf).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    let Some(place) = org_place(&portal, &signed_in, org).await else {
        return not_found();
    };
    let actor = match portal
        .tenancy()
        .actor(&signed_in.tenancy_session(), &place)
        .await
    {
        Ok(actor) => actor,
        Err(err) => return unavailable(err),
    };
    let done = tenancy::ask_to_leave(&portal.pool, &actor, &place).await;
    after(&portal, &signed_in, &place, done).await
}

/// "Approve" on a leave request (C85).
pub(crate) async fn approve_leave(
    State(portal): State<Shared>,
    Path(id): Path<i32>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    let signed_in = match portal.signed_in_post(&headers, &form.csrf).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    let Ok(place) = portal
        .tenancy()
        .authorized_owner(&signed_in.tenancy_session(), Owned::Leave(id))
        .await
    else {
        return not_found();
    };
    let actor = match admin_on(&portal, &signed_in, &place).await {
        Ok(actor) => actor,
        Err(answer) => return answer,
    };
    let done = tenancy::approve_leave(&portal.pool, &actor, &place, id).await;
    after(&portal, &signed_in, &place, done).await
}

/// "Cancel my request" while it waits (C88).
pub(crate) async fn cancel_leave(
    State(portal): State<Shared>,
    Path(org): Path<i32>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    let signed_in = match portal.signed_in_post(&headers, &form.csrf).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    let Some(place) = org_place(&portal, &signed_in, org).await else {
        return not_found();
    };
    let actor = match portal
        .tenancy()
        .actor(&signed_in.tenancy_session(), &place)
        .await
    {
        Ok(actor) => actor,
        Err(err) => return unavailable(err),
    };
    let done = tenancy::cancel_leave(&portal.pool, &actor, &place).await;
    after(&portal, &signed_in, &place, done).await
}

/// "Refuse" on a leave request (C85).
pub(crate) async fn refuse_leave(
    State(portal): State<Shared>,
    Path(id): Path<i32>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    let signed_in = match portal.signed_in_post(&headers, &form.csrf).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    let Ok(place) = portal
        .tenancy()
        .authorized_owner(&signed_in.tenancy_session(), Owned::Leave(id))
        .await
    else {
        return not_found();
    };
    let actor = match admin_on(&portal, &signed_in, &place).await {
        Ok(actor) => actor,
        Err(answer) => return answer,
    };
    let done = tenancy::refuse_leave(&portal.pool, &actor, &place, id).await;
    after(&portal, &signed_in, &place, done).await
}

/// The group `id` of an organisation the session runs, through `authorized_owner`.
async fn admin_group(
    portal: &super::Portal,
    signed_in: &SignedIn,
    id: i32,
) -> Result<(Actor, Authorized<Place>), Response> {
    let Ok(group) = portal
        .tenancy()
        .authorized_owner(&signed_in.tenancy_session(), Owned::Group(id))
        .await
    else {
        return Err(not_found());
    };
    let actor = admin_on(portal, signed_in, &group).await?;
    Ok((actor, group))
}

/// The confirmation of deleting a group, listing what it does (C61).
pub(crate) async fn confirm_delete_group(
    State(portal): State<Shared>,
    Path(id): Path<i32>,
    headers: HeaderMap,
) -> Response {
    let signed_in = match portal.signed_in(&headers).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    let group = match admin_group(&portal, &signed_in, id).await {
        Ok((_, group)) => group,
        Err(answer) => return answer,
    };
    match tenancy::group_effects(&portal.pool, &group).await {
        Ok((members, service_keys)) => {
            let view = OrgView::DeleteGroup {
                id,
                org: group.org().unwrap_or_default(),
                name: group.group_name().unwrap_or_default().to_owned(),
                members,
                service_keys,
            };
            render_page(&portal, &signed_in, StatusCode::OK, view).await
        }
        Err(err) => unavailable(err),
    }
}

/// "Delete group" on its confirmation (C61).
pub(crate) async fn delete_group(
    State(portal): State<Shared>,
    Path(id): Path<i32>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    let signed_in = match portal.signed_in_post(&headers, &form.csrf).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    let (actor, group) = match admin_group(&portal, &signed_in, id).await {
        Ok(found) => found,
        Err(answer) => return answer,
    };
    let done = tenancy::delete_group(&portal.pool, &actor, &group).await;
    after(&portal, &signed_in, &group, done).await
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(crate) struct InviteForm {
    csrf: String,
    email: String,
    role: String,
    /// A group id, or "none".
    group: String,
}

/// "Send invitation" (C43, T3).
pub(crate) async fn invite(
    State(portal): State<Shared>,
    Path(org): Path<i32>,
    headers: HeaderMap,
    Form(form): Form<InviteForm>,
) -> Response {
    let signed_in = match portal.signed_in_post(&headers, &form.csrf).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    let Some(place) = org_place(&portal, &signed_in, org).await else {
        return not_found();
    };
    let group = if form.group == "none" || form.group.is_empty() {
        None
    } else {
        match group_place(&portal, &signed_in, place.org(), &form.group).await {
            Some(group) => Some(group),
            None => return not_found(),
        }
    };
    let actor = match admin_on(&portal, &signed_in, &place).await {
        Ok(actor) => actor,
        Err(answer) => return answer,
    };
    let done = tenancy::invite(
        &portal.pool,
        &actor,
        &place,
        &form.email,
        &form.role,
        group.as_ref(),
        &portal.config.base_url,
    )
    .await;
    after(&portal, &signed_in, &place, done).await
}

/// "Cancel invitation".
pub(crate) async fn cancel_invitation(
    State(portal): State<Shared>,
    Path(id): Path<i32>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    let signed_in = match portal.signed_in_post(&headers, &form.csrf).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    let Ok(place) = portal
        .tenancy()
        .authorized_owner(&signed_in.tenancy_session(), Owned::Invitation(id))
        .await
    else {
        return not_found();
    };
    let actor = match admin_on(&portal, &signed_in, &place).await {
        Ok(actor) => actor,
        Err(answer) => return answer,
    };
    let done = tenancy::cancel_invitation(&portal.pool, &actor, &place, id).await;
    after(&portal, &signed_in, &place, done).await
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(crate) struct TokenQuery {
    token: String,
}

/// `/invite?token=…`: what the link grants, for the signed-in login to accept.
pub(crate) async fn invitation(
    State(portal): State<Shared>,
    Query(query): Query<TokenQuery>,
    headers: HeaderMap,
) -> Response {
    let signed_in = match portal.signed_in(&headers).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    match tenancy::invitation(&portal.pool, &query.token).await {
        Ok(grant) => {
            let view = OrgView::Invitation {
                token: query.token,
                grant,
            };
            render_page(&portal, &signed_in, StatusCode::OK, view).await
        }
        Err(err) => unavailable(err),
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(crate) struct AcceptForm {
    csrf: String,
    token: String,
}

/// "Accept": the grant goes to the login that accepts the link, once (T3).
pub(crate) async fn accept_invitation(
    State(portal): State<Shared>,
    headers: HeaderMap,
    Form(form): Form<AcceptForm>,
) -> Response {
    let signed_in = match portal.signed_in_post(&headers, &form.csrf).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    match tenancy::accept_invitation(&portal.pool, signed_in.login_id, &form.token).await {
        Ok(Some(Some(org))) => redirect(&format!("/org/{org}")),
        // A global admin's link: they set up an authenticator before acting (C24).
        Ok(Some(None)) => redirect("/admin"),
        Ok(None) => {
            let view = OrgView::Invitation {
                token: String::new(),
                grant: None,
            };
            render_page(&portal, &signed_in, StatusCode::GONE, view).await
        }
        Err(ChangeError::Refused(reason)) => refused(&reason),
        Err(ChangeError::Store(err)) => unavailable(err),
        Err(_) => not_found(),
    }
}

/// "Reset authenticator" on a member's row (C39, C76).
pub(crate) async fn reset_totp(
    State(portal): State<Shared>,
    Path(id): Path<i32>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    let signed_in = match portal.signed_in_post(&headers, &form.csrf).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    let Some(member) = member_place(&portal, &signed_in, id).await else {
        return not_found();
    };
    let actor = match admin_on(&portal, &signed_in, &member).await {
        Ok(actor) => actor,
        Err(answer) => return answer,
    };
    match accounts::reset_totp(&portal.pool, &actor, &member).await {
        Err(ChangeError::Denied) => refused(
            "You can reset the authenticator only of a member whose login belongs to this organisation alone, and never of an org admin. Ask the service operator.",
        ),
        done => after(&portal, &signed_in, &member, done).await,
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(crate) struct SsoFields {
    csrf: String,
    enabled: Option<String>,
    issuer: String,
    client_id: String,
    client_secret: String,
    allowed_tenant: String,
}

/// "Save" on company SSO (C21, C57, C62; T16).
pub(crate) async fn save_sso(
    State(portal): State<Shared>,
    Path(org): Path<i32>,
    headers: HeaderMap,
    Form(form): Form<SsoFields>,
) -> Response {
    let signed_in = match portal.signed_in_post(&headers, &form.csrf).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    let Some(place) = org_place(&portal, &signed_in, org).await else {
        return not_found();
    };
    let actor = match admin_on(&portal, &signed_in, &place).await {
        Ok(actor) => actor,
        Err(answer) => return answer,
    };
    let fields = accounts::SsoForm {
        enabled: form.enabled.is_some(),
        issuer: &form.issuer,
        client_id: &form.client_id,
        client_secret: &form.client_secret,
        allowed_tenant: &form.allowed_tenant,
    };
    let done = accounts::save_sso(&portal.pool, &portal.secrets, &actor, &place, fields).await;
    after(&portal, &signed_in, &place, done).await
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(crate) struct RangeForm {
    csrf: String,
    cidr: String,
}

/// "Add range" to the network lock (C30, C77).
pub(crate) async fn add_range(
    State(portal): State<Shared>,
    Path(org): Path<i32>,
    headers: HeaderMap,
    Form(form): Form<RangeForm>,
) -> Response {
    let signed_in = match portal.signed_in_post(&headers, &form.csrf).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    let Some(place) = org_place(&portal, &signed_in, org).await else {
        return not_found();
    };
    let actor = match admin_on(&portal, &signed_in, &place).await {
        Ok(actor) => actor,
        Err(answer) => return answer,
    };
    let done = tenancy::add_range(&portal.pool, &actor, &place, &form.cidr).await;
    after(&portal, &signed_in, &place, done).await
}

/// The range `id` of an organisation the session runs, through `authorized_owner`.
async fn admin_range(
    portal: &super::Portal,
    signed_in: &SignedIn,
    id: i32,
) -> Result<(Actor, Authorized<Place>), Response> {
    let Ok(place) = portal
        .tenancy()
        .authorized_owner(&signed_in.tenancy_session(), Owned::Range(id))
        .await
    else {
        return Err(not_found());
    };
    let actor = admin_on(portal, signed_in, &place).await?;
    Ok((actor, place))
}

/// "Remove" on a range (C87).
pub(crate) async fn delete_range(
    State(portal): State<Shared>,
    Path(id): Path<i32>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    let signed_in = match portal.signed_in_post(&headers, &form.csrf).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    let (actor, place) = match admin_range(&portal, &signed_in, id).await {
        Ok(found) => found,
        Err(answer) => return answer,
    };
    let done = tenancy::delete_range(&portal.pool, &actor, &place, id).await;
    after(&portal, &signed_in, &place, done).await
}

/// "Resubmit" on a refused range (C87).
pub(crate) async fn resubmit_range(
    State(portal): State<Shared>,
    Path(id): Path<i32>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    let signed_in = match portal.signed_in_post(&headers, &form.csrf).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    let (actor, place) = match admin_range(&portal, &signed_in, id).await {
        Ok(found) => found,
        Err(answer) => return answer,
    };
    let done = tenancy::resubmit_range(&portal.pool, &actor, &place, id).await;
    after(&portal, &signed_in, &place, done).await
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(crate) struct ConfirmForm {
    csrf: String,
    confirm: String,
}

/// "Delete organisation", with its name typed (C33).
pub(crate) async fn delete_org(
    State(portal): State<Shared>,
    Path(org): Path<i32>,
    headers: HeaderMap,
    Form(form): Form<ConfirmForm>,
) -> Response {
    let signed_in = match portal.signed_in_post(&headers, &form.csrf).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    let Some(place) = org_place(&portal, &signed_in, org).await else {
        return not_found();
    };
    let actor = match admin_on(&portal, &signed_in, &place).await {
        Ok(actor) => actor,
        Err(answer) => return answer,
    };
    match tenancy::delete_org(&portal.pool, &actor, &place, &form.confirm).await {
        Ok(()) => redirect("/org"),
        done => after(&portal, &signed_in, &place, done).await,
    }
}

/// "Restore", within the 30 days, by any of its org admins (C63).
pub(crate) async fn restore_org(
    State(portal): State<Shared>,
    Path(org): Path<i32>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    let signed_in = match portal.signed_in_post(&headers, &form.csrf).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    // The id first (404 for another tenant's or an unknown one, C1), then the second
    // factor; `restore_org` checks the role again under the row's lock.
    let session = signed_in.tenancy_session();
    match tenancy::restorable_orgs(&portal.pool, &session).await {
        Ok(restorable) if restorable.iter().any(|(id, ..)| *id == org) => {}
        Ok(_) => return not_found(),
        Err(err) => return unavailable(err),
    }
    if let Err(answer) = second_factor(&portal, &signed_in).await {
        return answer;
    }
    match tenancy::restore_org(&portal.pool, &session, org).await {
        Ok(()) => redirect(&format!("/org/{org}")),
        Err(ChangeError::Store(err)) => unavailable(err),
        Err(_) => not_found(),
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(crate) struct GroupForm {
    csrf: String,
    name: String,
}

/// "Create group".
pub(crate) async fn create_group(
    State(portal): State<Shared>,
    Path(org): Path<i32>,
    headers: HeaderMap,
    Form(form): Form<GroupForm>,
) -> Response {
    let signed_in = match portal.signed_in_post(&headers, &form.csrf).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    let Some(place) = org_place(&portal, &signed_in, org).await else {
        return not_found();
    };
    let actor = match admin_on(&portal, &signed_in, &place).await {
        Ok(actor) => actor,
        Err(answer) => return answer,
    };
    let done = tenancy::create_group(&portal.pool, &actor, &place, &form.name).await;
    after(&portal, &signed_in, &place, done).await
}

/// "Rename" on a group.
pub(crate) async fn rename_group(
    State(portal): State<Shared>,
    Path(id): Path<i32>,
    headers: HeaderMap,
    Form(form): Form<GroupForm>,
) -> Response {
    let signed_in = match portal.signed_in_post(&headers, &form.csrf).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    let (actor, group) = match admin_group(&portal, &signed_in, id).await {
        Ok(found) => found,
        Err(answer) => return answer,
    };
    let done = tenancy::rename_group(&portal.pool, &actor, &group, &form.name).await;
    after(&portal, &signed_in, &group, done).await
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(crate) struct TokenForm {
    csrf: String,
    name: String,
    /// The layer: `org-3`, or `group-5` of the same organisation.
    layer: String,
}

/// "Create token" for one of the organisation's layers (C86): shown once.
pub(crate) async fn create_token(
    State(portal): State<Shared>,
    Path(org): Path<i32>,
    headers: HeaderMap,
    Form(form): Form<TokenForm>,
) -> Response {
    let signed_in = match portal.signed_in_post(&headers, &form.csrf).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    let Some(place) = org_place(&portal, &signed_in, org).await else {
        return not_found();
    };
    if let Err(answer) = admin_on(&portal, &signed_in, &place).await {
        return answer;
    }
    let layer = match policy::layer_ref(&form.layer) {
        Some(layer) => portal
            .tenancy()
            .authorized_place(&signed_in.tenancy_session(), layer)
            .await
            .ok()
            .filter(|layer| {
                matches!(layer.place().kind, LayerKind::Org | LayerKind::Group)
                    && layer.org() == place.org()
            }),
        None => None,
    };
    let Some(layer) = layer else {
        return not_found();
    };
    let actor = match admin_on(&portal, &signed_in, &layer).await {
        Ok(actor) => actor,
        Err(answer) => return answer,
    };
    let name = form.name.trim();
    if name.is_empty() || name.chars().count() > 100 {
        return after(
            &portal,
            &signed_in,
            &place,
            Err(ChangeError::Refused(
                "Give the token a name of at most 100 characters.".to_owned(),
            )),
        )
        .await;
    }
    match keys::create_token(&portal.pool, &actor, &layer, name).await {
        Ok(token) => {
            admin_page_with(
                &portal,
                &signed_in,
                &place,
                StatusCode::OK,
                None,
                Some(token.secret),
            )
            .await
        }
        Err(keys::KeyError::Store(err)) => unavailable(err),
        Err(_) => refused("Only the organisation's org admins can do this."),
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(crate) struct RevokeTokenForm {
    csrf: String,
    /// The token's id.
    token: String,
}

/// "Revoke" on an automation token of the organisation's layers: one of another
/// organisation is not found (C1).
pub(crate) async fn revoke_token(
    State(portal): State<Shared>,
    Path(org): Path<i32>,
    headers: HeaderMap,
    Form(form): Form<RevokeTokenForm>,
) -> Response {
    let signed_in = match portal.signed_in_post(&headers, &form.csrf).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    let Some(place) = org_place(&portal, &signed_in, org).await else {
        return not_found();
    };
    let actor = match admin_on(&portal, &signed_in, &place).await {
        Ok(actor) => actor,
        Err(answer) => return answer,
    };
    let Ok(token) = form.token.parse() else {
        return not_found();
    };
    let done = match keys::revoke_token(&portal.pool, &actor, &place, token).await {
        Ok(()) => Ok(()),
        Err(keys::RevokeError::NotFound) => Err(ChangeError::NotFound),
        Err(keys::RevokeError::Denied) => Err(ChangeError::Denied),
        Err(keys::RevokeError::Store(err)) => Err(ChangeError::Store(err)),
    };
    after(&portal, &signed_in, &place, done).await
}

/// "Export blocklist": the organisation layer's blocks as today's file (C80, C86).
pub(crate) async fn export_blocklist(
    State(portal): State<Shared>,
    Path(org): Path<i32>,
    headers: HeaderMap,
) -> Response {
    let signed_in = match portal.signed_in(&headers).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    let Some(place) = org_place(&portal, &signed_in, org).await else {
        return not_found();
    };
    if let Err(answer) = admin_on(&portal, &signed_in, &place).await {
        return answer;
    }
    blocklist_file(policy::export_blocks(&portal.pool, &place).await)
}

/// The export as a download, or the store's failure.
pub(crate) fn blocklist_file(file: Result<String, StoreError>) -> Response {
    match file {
        Ok(file) => (
            [
                (CONTENT_TYPE, HeaderValue::from_static("application/json")),
                (
                    CONTENT_DISPOSITION,
                    HeaderValue::from_static("attachment; filename=\"blocklist.json\""),
                ),
            ],
            file,
        )
            .into_response(),
        Err(StoreError::Db(err)) => unavailable(err),
        Err(StoreError::MissingLayer(_)) => not_found(),
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(crate) struct ImportForm {
    csrf: String,
    /// The blocklist file's text.
    file: String,
}

/// "Import blocklist": adds the file's blocks to the organisation layer (C80, C86),
/// through the same checks as any edit.
pub(crate) async fn import_blocklist(
    State(portal): State<Shared>,
    Path(org): Path<i32>,
    headers: HeaderMap,
    Form(form): Form<ImportForm>,
) -> Response {
    let signed_in = match portal.signed_in_post(&headers, &form.csrf).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    let Some(place) = org_place(&portal, &signed_in, org).await else {
        return not_found();
    };
    let actor = match admin_on(&portal, &signed_in, &place).await {
        Ok(actor) => actor,
        Err(answer) => return answer,
    };
    let done = import_into(&portal, &actor, &place, &form.file).await;
    after(&portal, &signed_in, &place, done).await
}

/// Adds the blocks of `file` to `place`'s layer as `actor`, for an import form.
pub(crate) async fn import_into(
    portal: &super::Portal,
    actor: &Actor,
    place: &Authorized<Place>,
    file: &str,
) -> Result<(), ChangeError> {
    let blocks = probation_policy::blocklist_json::import(file)
        .map_err(|problem| ChangeError::Refused(format!("Not imported: {problem}.")))?;
    match policy::push_blocks(&portal.pool, actor, place, blocks, false).await {
        Ok(_) => Ok(()),
        Err(PushError::Denied) => Err(ChangeError::Denied),
        Err(PushError::Refused(problem)) => {
            Err(ChangeError::Refused(format!("Not imported: {problem}.")))
        }
        Err(PushError::Conflict) => Err(ChangeError::Refused(
            "Not imported: the policy changed meanwhile. Import the file again.".to_owned(),
        )),
        Err(PushError::Store(StoreError::Db(err))) => Err(ChangeError::Store(err)),
        Err(PushError::Store(StoreError::MissingLayer(_))) => Err(ChangeError::NotFound),
    }
}
