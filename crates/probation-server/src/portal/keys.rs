//! API keys and service keys (mockup api-keys.html; C14, C15, C99).

use askama::Template;
use axum::extract::{Form, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use serde::Deserialize;

use probation_policy::api::KeyId;

use super::{Shared, SignedIn, Top, not_found, redirect, refused, render, unavailable};
use crate::keys::{self, KeyError, KeyRow, RevokeError, ServiceKeyRow};
use crate::tenancy::{self, Authorized, Owned, Place, Role};

#[derive(Template)]
#[template(path = "keys.html")]
pub(crate) struct KeysPage {
    pub top: Option<Top>,
    pub title: &'static str,
    pub csrf: String,
    /// `None` when the login has no place yet.
    pub view: Option<KeysView>,
}

pub(crate) struct KeysView {
    /// "Acme", or "your personal account".
    pub account: String,
    pub own: Vec<KeyRow>,
    /// For org admins and group admins only (C14, C50).
    pub service: Option<ServiceView>,
    /// A key just created: shown once.
    pub new_key: Option<String>,
    pub error: Option<String>,
}

pub(crate) struct ServiceView {
    pub keys: Vec<ServiceKeyRow>,
    /// Where a new one may be attached: ("org" or a group id, label).
    pub attach: Vec<(String, String)>,
}

pub(crate) async fn show(State(portal): State<Shared>, headers: HeaderMap) -> Response {
    match portal.signed_in(&headers).await {
        Ok(signed_in) => page(&portal, &signed_in, StatusCode::OK, None, None).await,
        Err(answer) => answer,
    }
}

/// The keys page of the session's place, with a key just created or an error.
async fn page(
    portal: &super::Portal,
    signed_in: &SignedIn,
    status: StatusCode,
    new_key: Option<String>,
    error: Option<String>,
) -> Response {
    let built = async {
        let mut top = signed_in.top(portal).await?;
        top.page = "keys";
        let view = match signed_in.account(portal).await? {
            Some(account) => Some(view(portal, signed_in, &account, new_key, error).await?),
            None => None,
        };
        Ok::<_, sqlx::Error>(KeysPage {
            csrf: top.csrf.clone(),
            top: Some(top),
            title: "API keys",
            view,
        })
    };
    match built.await {
        Ok(page) => render(status, &page),
        Err(err) => unavailable(err),
    }
}

async fn view(
    portal: &super::Portal,
    signed_in: &SignedIn,
    account: &Authorized<Place>,
    new_key: Option<String>,
    error: Option<String>,
) -> Result<KeysView, sqlx::Error> {
    let own = match portal
        .tenancy()
        .own_place(&signed_in.tenancy_session(), account)
        .await
    {
        Ok(own) => keys::own(&portal.pool, &own).await?,
        Err(_) => Vec::new(),
    };
    Ok(KeysView {
        account: account_name(account),
        own,
        service: service_view(portal, signed_in, account).await?,
        new_key,
        error,
    })
}

/// The service keys an org admin (all of the organisation's) or a group admin (their
/// group's) manages, and where they may attach a new one; `None` for anyone else.
async fn service_view(
    portal: &super::Portal,
    signed_in: &SignedIn,
    account: &Authorized<Place>,
) -> Result<Option<ServiceView>, sqlx::Error> {
    let Some(org) = account.org() else {
        return Ok(None);
    };
    let session = signed_in.tenancy_session();
    let tenancy = portal.tenancy();
    if matches!(
        tenancy
            .actor(&session, account)
            .await?
            .role(account.place()),
        Some(Role::OrgAdmin | Role::GlobalAdmin)
    ) {
        let mut attach = vec![(
            "org".to_owned(),
            format!("{} organisation", account_name(account)),
        )];
        for group in tenancy::groups(&portal.pool, account).await? {
            attach.push((group.id.to_string(), format!("{} group", group.name)));
        }
        return Ok(Some(ServiceView {
            keys: keys::service(&portal.pool, org, None).await?,
            attach,
        }));
    }
    // A group admin: the group of their own place, if they run it.
    let group = match tenancy.own_place(&session, account).await {
        Ok(own) => own.group(),
        Err(_) => None,
    };
    let Some(group) = group else {
        return Ok(None);
    };
    let Ok(group_place) = tenancy
        .authorized_owner(&session, Owned::Group(group))
        .await
    else {
        return Ok(None);
    };
    if tenancy
        .actor(&session, &group_place)
        .await?
        .role(group_place.place())
        != Some(Role::GroupAdmin)
    {
        return Ok(None);
    }
    Ok(Some(ServiceView {
        keys: keys::service(&portal.pool, org, Some(group)).await?,
        attach: vec![(
            group.to_string(),
            format!("{} group", group_place.group_name().unwrap_or_default()),
        )],
    }))
}

pub(crate) fn account_name(account: &Authorized<Place>) -> String {
    account
        .org_name()
        .map_or_else(|| "your personal account".to_owned(), str::to_owned)
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(crate) struct NameForm {
    csrf: String,
    name: String,
}

/// "Create key": a user key on the session's own place in its account (C14).
pub(crate) async fn create(
    State(portal): State<Shared>,
    headers: HeaderMap,
    Form(form): Form<NameForm>,
) -> Response {
    let signed_in = match portal.signed_in_post(&headers, &form.csrf).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    let session = signed_in.tenancy_session();
    let account = match signed_in.account(&portal).await {
        Ok(Some(account)) => account,
        Ok(None) => return not_found(),
        Err(err) => return unavailable(err),
    };
    let Ok(own) = portal.tenancy().own_place(&session, &account).await else {
        return not_found();
    };
    let name = form.name.trim();
    if name.is_empty() || name.chars().count() > 100 {
        return page(
            &portal,
            &signed_in,
            StatusCode::UNPROCESSABLE_ENTITY,
            None,
            Some("Give the key a name of at most 100 characters.".to_owned()),
        )
        .await;
    }
    let actor = match portal.tenancy().actor(&session, &own).await {
        Ok(actor) => actor,
        Err(err) => return unavailable(err),
    };
    match keys::create(&portal.pool, &actor, &own, name).await {
        Ok(key) => page(&portal, &signed_in, StatusCode::OK, Some(key.secret), None).await,
        Err(KeyError::Limit(limit)) => {
            let account = account_name(&account);
            let who = if own.org().is_some() {
                "each member"
            } else {
                "it"
            };
            let error = format!(
                "Key not created. You already have {limit} keys in {account}, the most {who} may have. Revoke a key you no longer use, or ask the service operator to raise the limit."
            );
            page(&portal, &signed_in, StatusCode::CONFLICT, None, Some(error)).await
        }
        Err(KeyError::Denied) => refused("You cannot create keys here."),
        Err(KeyError::Store(err)) => unavailable(err),
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(crate) struct CsrfForm {
    csrf: String,
}

/// "Revoke" on one key (flow F-key): the key's place through `authorized_owner`, then
/// the role check in `keys::revoke`. Another member's key, another tenant's and an
/// unknown one answer the same 404 (C1).
pub(crate) async fn revoke(
    State(portal): State<Shared>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    let signed_in = match portal.signed_in_post(&headers, &form.csrf).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    let session = signed_in.tenancy_session();
    let Ok(place) = portal
        .tenancy()
        .authorized_owner(&session, Owned::Key(id))
        .await
    else {
        return not_found();
    };
    let actor = match portal.tenancy().actor(&session, &place).await {
        Ok(actor) => actor,
        Err(err) => return unavailable(err),
    };
    match keys::revoke(&portal.pool, &actor, &place, KeyId(id as u64)).await {
        Ok(()) => redirect("/keys"),
        Err(RevokeError::NotFound | RevokeError::Denied) => not_found(),
        Err(RevokeError::Store(err)) => unavailable(err),
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(crate) struct ServiceForm {
    csrf: String,
    name: String,
    /// "org", or the id of one of the organisation's groups.
    attach: String,
}

/// "Create service key" (C14, C15): attached to the session's organisation or to one of
/// its groups; the role check is `keys::create`'s.
pub(crate) async fn create_service(
    State(portal): State<Shared>,
    headers: HeaderMap,
    Form(form): Form<ServiceForm>,
) -> Response {
    let signed_in = match portal.signed_in_post(&headers, &form.csrf).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    let session = signed_in.tenancy_session();
    let account = match signed_in.account(&portal).await {
        Ok(Some(account)) if account.org().is_some() => account,
        Ok(_) => return not_found(),
        Err(err) => return unavailable(err),
    };
    let place = if form.attach == "org" {
        account.clone()
    } else {
        let Ok(group) = form.attach.parse::<i32>() else {
            return not_found();
        };
        match portal
            .tenancy()
            .authorized_owner(&session, Owned::Group(group))
            .await
        {
            Ok(place) if place.org() == account.org() => place,
            _ => return not_found(),
        }
    };
    let name = form.name.trim();
    if name.is_empty() || name.chars().count() > 100 {
        return page(
            &portal,
            &signed_in,
            StatusCode::UNPROCESSABLE_ENTITY,
            None,
            Some("Give the key a name of at most 100 characters.".to_owned()),
        )
        .await;
    }
    let actor = match portal.tenancy().actor(&session, &place).await {
        Ok(actor) => actor,
        Err(err) => return unavailable(err),
    };
    match keys::create(&portal.pool, &actor, &place, name).await {
        Ok(key) => page(&portal, &signed_in, StatusCode::OK, Some(key.secret), None).await,
        Err(KeyError::Limit(limit)) => {
            let error = format!(
                "Service key not created. {} already has {limit} service keys, the most it may have.",
                account_name(&account)
            );
            page(&portal, &signed_in, StatusCode::CONFLICT, None, Some(error)).await
        }
        Err(KeyError::Denied) => refused("Only org admins and group admins create service keys."),
        Err(KeyError::Store(err)) => unavailable(err),
    }
}
