//! The audit log (mockup audit-log.html; C25, C57, C58, C79): an org admin sees their
//! organisation's log, global admins' changes inside it included; a group admin sees
//! their group's entries; a global admin sees everything.

use askama::Template;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use probation_policy::{LayerKind, PlaceRef};

use super::{Shared, SignedIn, Top, render, unavailable};
use crate::tenancy::{Authorized, Place, Role};

/// The most rows the page lists, newest first.
const ROWS: i64 = 500;

#[derive(Template)]
#[template(path = "audit.html")]
pub(crate) struct AuditPage {
    pub top: Option<Top>,
    pub title: &'static str,
    /// `None` when the session's role shows it no log.
    pub view: Option<AuditView>,
}

pub(crate) struct AuditView {
    /// "Acme", "the Frontend group" or "every organisation and the platform".
    pub scope: String,
    /// The "Where" column, for a global admin.
    pub everywhere: bool,
    pub rows: Vec<Row>,
}

pub(crate) struct Row {
    pub at: String,
    pub who: String,
    pub place: String,
    pub kind: &'static str,
    pub subject: String,
    pub before: String,
    pub after: String,
}

/// Which entries a role sees (C25, C58).
enum Scope {
    All,
    Org(i32),
    Group(i32, i32),
    Personal(i32),
}

pub(crate) async fn show(State(portal): State<Shared>, headers: HeaderMap) -> Response {
    let signed_in = match portal.signed_in(&headers).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    let built = async {
        let mut top = signed_in.top(&portal).await?;
        top.page = "audit";
        let view = match scope(&portal, &signed_in).await? {
            Some((scope, label)) => Some(view(&portal, scope, label).await?),
            None => None,
        };
        Ok::<_, sqlx::Error>(AuditPage {
            top: Some(top),
            title: "Audit log",
            view,
        })
    };
    match built.await {
        Ok(page) => render(StatusCode::OK, &page),
        Err(err) => unavailable(err),
    }
}

async fn scope(
    portal: &super::Portal,
    signed_in: &SignedIn,
) -> Result<Option<(Scope, String)>, sqlx::Error> {
    let session = signed_in.tenancy_session();
    let tenancy = portal.tenancy();
    if tenancy.global_admin(&session).await {
        return Ok(Some((
            Scope::All,
            "every organisation, every personal account and the platform".to_owned(),
        )));
    }
    let Some(account) = signed_in.account(portal).await? else {
        return Ok(None);
    };
    let Some(org) = account.org() else {
        return Ok(Some((
            Scope::Personal(account.place().id as i32),
            "your personal account".to_owned(),
        )));
    };
    if tenancy
        .actor(&session, &account)
        .await?
        .role(account.place())
        == Some(Role::OrgAdmin)
    {
        return Ok(Some((Scope::Org(org), super::keys::account_name(&account))));
    }
    group_scope(portal, signed_in, &account, org).await
}

/// A group admin's own group, if the session runs one.
async fn group_scope(
    portal: &super::Portal,
    signed_in: &SignedIn,
    account: &Authorized<Place>,
    org: i32,
) -> Result<Option<(Scope, String)>, sqlx::Error> {
    let session = signed_in.tenancy_session();
    let tenancy = portal.tenancy();
    let Some(group) = tenancy
        .own_place(&session, account)
        .await
        .ok()
        .and_then(|own| own.group())
    else {
        return Ok(None);
    };
    let place = PlaceRef {
        kind: LayerKind::Group,
        id: group as u32,
    };
    let Ok(group_place) = tenancy.authorized_place(&session, place).await else {
        return Ok(None);
    };
    if tenancy.actor(&session, &group_place).await?.role(place) != Some(Role::GroupAdmin) {
        return Ok(None);
    }
    let label = format!("the {} group", group_place.group_name().unwrap_or_default());
    Ok(Some((Scope::Group(org, group), label)))
}

async fn view(
    portal: &super::Portal,
    scope: Scope,
    label: String,
) -> Result<AuditView, sqlx::Error> {
    let (mode, org, group, personal) = match scope {
        Scope::All => ("all", None, None, None),
        Scope::Org(org) => ("org", Some(org), None, None),
        Scope::Group(org, group) => ("group", Some(org), Some(group), None),
        Scope::Personal(personal) => ("personal", None, None, Some(personal)),
    };
    type Fetched = (
        String,
        Option<String>,
        bool,
        Option<String>,
        String,
        String,
        Option<String>,
        Option<String>,
    );
    // A group's entries: its layer and the group itself, its service keys, and member
    // changes that name it (C58). A personal account's: the account, its layer and its
    // keys.
    let fetched: Vec<Fetched> = sqlx::query_as(
        "SELECT to_char(a.at AT TIME ZONE 'UTC', 'DD Mon YYYY HH24:MI'),
                (SELECT s.email FROM sign_in_methods AS s
                 WHERE s.login_id = a.actor_login AND s.email IS NOT NULL ORDER BY s.id LIMIT 1),
                a.actor_is_global_admin,
                (SELECT o.name FROM orgs AS o WHERE o.id = a.org_id),
                a.action, a.subject, a.before::text, a.after::text
         FROM audit_log AS a
         WHERE CASE $1
             WHEN 'all' THEN true
             WHEN 'org' THEN a.org_id = $2
             WHEN 'group' THEN a.org_id = $2 AND (
                 a.subject = 'group:' || $3
                 OR a.before ->> 'group' = $3::text OR a.after ->> 'group' = $3::text
                 OR EXISTS (SELECT 1 FROM keys AS k
                            WHERE a.subject = 'key:' || k.id AND k.place_kind = 'group' AND k.place_id = $3))
             ELSE a.org_id IS NULL AND (
                 a.subject = 'personal:' || $4
                 OR EXISTS (SELECT 1 FROM keys AS k
                            WHERE a.subject = 'key:' || k.id AND k.place_kind = 'personal' AND k.place_id = $4))
         END
         ORDER BY a.at DESC, a.id DESC LIMIT $5",
    )
    .bind(mode)
    .bind(org)
    .bind(group)
    .bind(personal)
    .bind(ROWS)
    .fetch_all(&portal.pool)
    .await?;
    let rows = fetched
        .into_iter()
        .map(
            |(at, email, global, org, action, subject, before, after)| Row {
                at,
                who: match (email, global) {
                    (Some(email), true) => format!("{email} (operator)"),
                    (Some(email), false) => email,
                    (None, _) => "the operator".to_owned(),
                },
                place: org.unwrap_or_else(|| "Platform or personal account".to_owned()),
                kind: kind(&action),
                subject,
                before: before.unwrap_or_else(|| "none".to_owned()),
                after: after.unwrap_or_else(|| "none".to_owned()),
            },
        )
        .collect();
    Ok(AuditView {
        scope: label,
        everywhere: mode == "all",
        rows,
    })
}

/// The "Kind" column, from the audited action.
fn kind(action: &str) -> &'static str {
    match action.split('.').next().unwrap_or_default() {
        "layer" => "Policy",
        "key" => "Key",
        "member" if action == "member.role" => "Admin role",
        "member" | "leave" | "invitation" | "group" => "Membership",
        "sso" => "Company SSO",
        "range" => "Network lock",
        "org" => "Organisation",
        "totp" => "Authenticator",
        "personal" | "login" | "method" | "password" => "Account",
        _ => "Other",
    }
}
