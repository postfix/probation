//! Blocked and held downloads (mockup activity.html; C23, C54, C55, C56, C92): what the
//! firewalls stopped for the session's place, as its role lets it see (C54).

use askama::Template;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use probation_policy::LayerKind;

use super::{Shared, SignedIn, Top, render, unavailable};
use crate::tenancy::{Authorized, Place, Role};

/// The most rows the page lists, newest first.
const ROWS: i64 = 500;

#[derive(Template)]
#[template(path = "activity.html")]
pub(crate) struct ActivityPage {
    pub top: Option<Top>,
    pub title: &'static str,
    /// `None` when the login has no place yet.
    pub view: Option<ActivityView>,
}

pub(crate) struct ActivityView {
    pub account: String,
    /// "all of Acme", "the Frontend group's members and service keys" or "your own keys".
    pub scope: String,
    pub rows: Vec<Row>,
    pub retention_days: i32,
}

pub(crate) struct Row {
    pub at: String,
    pub key: String,
    /// The key's owner, or "service key".
    pub whose: String,
    pub ecosystem: String,
    pub package: String,
    pub result: String,
    pub rule: String,
    pub layer: &'static str,
}

/// Which rows a role sees (C54).
enum Scope {
    /// A member's own user place, or a personal account.
    Own(Authorized<Place>),
    /// A group admin's group: its service keys and its members' keys.
    Group(i32),
    /// An org admin: every place of the organisation.
    Org(i32),
}

pub(crate) async fn show(State(portal): State<Shared>, headers: HeaderMap) -> Response {
    let signed_in = match portal.signed_in(&headers).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    let built = async {
        let mut top = signed_in.top(&portal).await?;
        top.page = "activity";
        let view = match signed_in.account(&portal).await? {
            Some(account) => view(&portal, &signed_in, &account).await?,
            None => None,
        };
        Ok::<_, sqlx::Error>(ActivityPage {
            top: Some(top),
            title: "Activity",
            view,
        })
    };
    match built.await {
        Ok(page) => render(StatusCode::OK, &page),
        Err(err) => unavailable(err),
    }
}

async fn view(
    portal: &super::Portal,
    signed_in: &SignedIn,
    account: &Authorized<Place>,
) -> Result<Option<ActivityView>, sqlx::Error> {
    let Some(scope) = scope(portal, signed_in, account).await? else {
        return Ok(None);
    };
    let name = super::keys::account_name(account);
    let described = match &scope {
        Scope::Org(_) => format!("all of {name}"),
        Scope::Group(_) => "your group's members and service keys".to_owned(),
        Scope::Own(_) => "your own keys".to_owned(),
    };
    let (mode, place, org, group) = match &scope {
        Scope::Own(own) => ("own", Some(own.place()), None, None),
        Scope::Group(group) => ("group", None, None, Some(*group)),
        Scope::Org(org) => ("org", None, Some(*org), None),
    };
    type Fetched = (
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        String,
        String,
        String,
        Option<String>,
        Option<String>,
    );
    let fetched: Vec<Fetched> = sqlx::query_as(
        "SELECT to_char(a.at AT TIME ZONE 'UTC', 'DD Mon HH24:MI'), k.name, k.kind,
                (SELECT s.email FROM sign_in_methods AS s
                 WHERE s.login_id = k.owner_login AND s.email IS NOT NULL ORDER BY s.id LIMIT 1),
                a.ecosystem, a.package, a.version, a.result, a.rule, a.layer, host(a.client_ip),
                to_char(a.eligible_at AT TIME ZONE 'UTC', 'DD Mon YYYY HH24:MI \"UTC\"')
         FROM activity AS a JOIN keys AS k ON k.id = a.key_id
         WHERE CASE $1
             WHEN 'own' THEN a.place_kind = $2 AND a.place_id = $3
             WHEN 'group' THEN (a.place_kind = 'group' AND a.place_id = $5)
                 OR (a.place_kind = 'user'
                     AND a.place_id IN (SELECT m.id FROM memberships AS m WHERE m.group_id = $5))
             ELSE place_org(a.place_kind, a.place_id) = $4
         END
         ORDER BY a.at DESC, a.event_id LIMIT $6",
    )
    .bind(mode)
    .bind(place.map(|place| crate::tenancy::kind_str(place.kind)))
    .bind(place.map(|place| place.id as i32))
    .bind(org)
    .bind(group)
    .bind(ROWS)
    .fetch_all(&portal.pool)
    .await?;
    let rows = fetched
        .into_iter()
        .map(
            |(
                at,
                key,
                kind,
                owner,
                ecosystem,
                package,
                version,
                result,
                rule,
                layer,
                ip,
                eligible,
            )| {
                let ip = ip.unwrap_or_default();
                let shown = match result.as_str() {
                    "held" => format!("Held until {}", eligible.unwrap_or_default()),
                    "would_block" => "Would have blocked (log only)".to_owned(),
                    "refused_revoked" => "Refused: the key was revoked".to_owned(),
                    "refused_suspended" => "Refused: the account is suspended".to_owned(),
                    "refused_network" => format!("Refused by a network lock (used from {ip})"),
                    _ => "Blocked".to_owned(),
                };
                Row {
                    at,
                    key,
                    whose: if kind == "service" {
                        "service key".to_owned()
                    } else {
                        owner.unwrap_or_default()
                    },
                    ecosystem: match ecosystem.as_deref() {
                        Some("pypi") => "PyPI".to_owned(),
                        Some(other) => other.to_owned(),
                        None => String::new(),
                    },
                    package: match (package, version) {
                        (Some(package), Some(version)) => format!("{package}@{version}"),
                        (Some(package), None) => package,
                        _ => String::new(),
                    },
                    result: shown,
                    rule,
                    layer: layer_label(&layer),
                }
            },
        )
        .collect();
    let retention_days: i32 = sqlx::query_scalar(
        "SELECT coalesce((SELECT activity_retention_days FROM orgs WHERE id = $1),
                         (SELECT activity_retention_days FROM platform_settings WHERE id = 1))",
    )
    .bind(account.org())
    .fetch_one(&portal.pool)
    .await?;
    Ok(Some(ActivityView {
        account: name,
        scope: described,
        rows,
        retention_days,
    }))
}

/// What the session's role on its account lets it see (C54).
async fn scope(
    portal: &super::Portal,
    signed_in: &SignedIn,
    account: &Authorized<Place>,
) -> Result<Option<Scope>, sqlx::Error> {
    let session = signed_in.tenancy_session();
    let tenancy = portal.tenancy();
    let Some(org) = account.org() else {
        return Ok(Some(Scope::Own(account.clone())));
    };
    if matches!(
        tenancy
            .actor(&session, account)
            .await?
            .role(account.place()),
        Some(Role::OrgAdmin | Role::GlobalAdmin)
    ) {
        return Ok(Some(Scope::Org(org)));
    }
    let Ok(own) = tenancy.own_place(&session, account).await else {
        return Ok(None);
    };
    if let Some(group) = own.group() {
        let place = probation_policy::PlaceRef {
            kind: LayerKind::Group,
            id: group as u32,
        };
        if let Ok(group_place) = tenancy.authorized_place(&session, place).await
            && tenancy.actor(&session, &group_place).await?.role(place) == Some(Role::GroupAdmin)
        {
            return Ok(Some(Scope::Group(group)));
        }
    }
    Ok(Some(Scope::Own(own)))
}

fn layer_label(layer: &str) -> &'static str {
    match layer {
        "platform" => "Platform",
        "org" => "Organisation",
        "group" => "Group",
        "user" => "User",
        "personal" => "Personal account",
        "network" => "Network lock",
        _ => "none",
    }
}
