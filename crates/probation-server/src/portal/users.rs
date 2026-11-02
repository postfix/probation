//! Member certificate status changes, scoped to the signed-in organisation.

use askama::Template;
use axum::extract::{Form, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use probation_policy::{LayerKind, PlaceRef};
use serde::Deserialize;

use super::{Shared, Top, not_found, redirect, refused, render, second_factor_first, unavailable};
use crate::tenancy::{self, GroupRow, MemberRow, Role};

#[derive(Template)]
#[template(path = "users.html")]
struct UsersPage {
    top: Option<Top>,
    title: &'static str,
    csrf: String,
    org: i32,
    name: String,
    members: Vec<MemberRow>,
    groups: Vec<GroupRow>,
}

pub(crate) async fn manage(
    State(portal): State<Shared>,
    Path(org): Path<i32>,
    headers: HeaderMap,
) -> Response {
    let signed_in = match portal.signed_in(&headers).await {
        Ok(value) => value,
        Err(answer) => return answer,
    };
    let Some(place) = super::organisation::org_place(&portal, &signed_in, org).await else {
        return not_found();
    };
    if let Err(answer) = super::organisation::admin_on(&portal, &signed_in, &place).await {
        return answer;
    }
    let (members, groups, top) = match tokio::try_join!(
        tenancy::members(&portal.pool, &place),
        tenancy::groups(&portal.pool, &place),
        signed_in.top(&portal)
    ) {
        Ok(value) => value,
        Err(err) => return unavailable(err),
    };
    let mut top = top;
    top.page = "org";
    render(
        StatusCode::OK,
        &UsersPage {
            csrf: top.csrf.clone(),
            top: Some(top),
            title: "Users and groups",
            org,
            name: place.org_name().unwrap_or_default().to_owned(),
            members,
            groups,
        },
    )
}

#[derive(Deserialize)]
pub(crate) struct Csrf {
    #[serde(default)]
    csrf: String,
}

#[derive(Deserialize)]
pub(crate) struct CertificateLookup {
    #[serde(default)]
    email: String,
    before: Option<i64>,
}

#[derive(Template)]
#[template(
    source = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Find package certificates · Probation</title></head><body><a class=\"skip\" href=\"#main\">Skip to main content</a><main id=\"main\"><h1>Find package certificates</h1><form method=\"get\" action=\"/org/{{ org }}/certificates/lookup\"><label>Member email<input type=\"email\" name=\"email\" value=\"{{ email }}\" required></label><button type=\"submit\">Find certificates</button></form>{% if searched %}<p>Certificates for {{ email }}</p>{% for row in certificates %}<form method=\"post\" action=\"/certificates/{{ row.0 }}/revoke\"><input type=\"hidden\" name=\"csrf\" value=\"{{ csrf }}\"><span>Certificate {{ row.0 }} · SHA-256 {{ row.1 }}{% if row.2 %} · revoked{% endif %}</span><button type=\"submit\"{% if row.2 %} disabled{% endif %}>Revoke this certificate</button></form>{% endfor %}{% if certificates.is_empty() %}<p>No certificates for that member.</p>{% endif %}{% if let Some(url) = next_url %}<p><a href=\"{{ url }}\">Older certificates</a></p>{% endif %}{% endif %}<p><a href=\"/org/{{ org }}\">Organisation members</a></p></main></body></html>",
    ext = "html"
)]
struct CertificateLookupPage<'a> {
    org: i32,
    email: &'a str,
    csrf: &'a str,
    searched: bool,
    certificates: &'a [(i64, String, bool)],
    next_url: Option<String>,
}

/// An administrator looks up one exact member, then revokes one public leaf.
/// An empty search never enumerates the organisation's certificates.
pub(crate) async fn lookup_certificate(
    State(portal): State<Shared>,
    Path(org): Path<i32>,
    Query(query): Query<CertificateLookup>,
    headers: HeaderMap,
) -> Response {
    let signed_in = match portal.signed_in(&headers).await {
        Ok(value) => value,
        Err(answer) => return answer,
    };
    let Some(place) = super::organisation::org_place(&portal, &signed_in, org).await else {
        return not_found();
    };
    if let Err(answer) = super::organisation::admin_on(&portal, &signed_in, &place).await {
        return answer;
    }
    let email = query.email.trim();
    if email.len() > 320 || email.chars().any(char::is_control) {
        return refused("Enter one valid member email.");
    }
    if query.before.is_some_and(|id| id <= 0) {
        return refused("Invalid certificate page.");
    }
    let mut certificates = if email.is_empty() {
        Vec::new()
    } else {
        match sqlx::query_as::<_, (i64, String, bool)>(
            "SELECT c.id, encode(c.leaf_fingerprint, 'hex'), c.revoked_at IS NOT NULL
             FROM memberships AS m
             JOIN registry_member_certificates AS c ON c.membership_id = m.id AND c.org_id = m.org_id
             WHERE m.org_id = $1 AND EXISTS (
               SELECT 1 FROM sign_in_methods AS s
               WHERE s.login_id = m.login_id AND s.email IS NOT NULL AND lower(s.email) = lower($2)
             )
               AND ($3::bigint IS NULL OR c.id < $3)
             ORDER BY c.id DESC LIMIT 51",
        )
        .bind(org)
        .bind(email)
        .bind(query.before)
        .fetch_all(&portal.pool)
        .await
        {
            Ok(rows) => rows,
            Err(err) => return unavailable(err),
        }
    };
    let next_url = if certificates.len() > 50 {
        certificates.truncate(50);
        let before = certificates.last().expect("page contains 50 certificates").0;
        let encoded: String = url::form_urlencoded::byte_serialize(email.as_bytes()).collect();
        Some(format!("/org/{org}/certificates/lookup?email={encoded}&before={before}"))
    } else {
        None
    };
    render(
        StatusCode::OK,
        &CertificateLookupPage {
            org,
            email,
            csrf: signed_in.session.csrf(),
            searched: !email.is_empty(),
            certificates: &certificates,
            next_url,
        },
    )
}

/// Revoke exactly one public certificate row. The member can revoke their own;
/// an organisation admin with a second factor can revoke a member's certificate.
pub(crate) async fn revoke_certificate(
    State(portal): State<Shared>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    Form(form): Form<Csrf>,
) -> Response {
    let signed_in = match portal.signed_in_post(&headers, &form.csrf).await {
        Ok(value) => value,
        Err(answer) => return answer,
    };
    let account = match signed_in.account(&portal).await {
        Ok(Some(account)) if account.org().is_some() => account,
        Ok(_) => return not_found(),
        Err(err) => return unavailable(err),
    };
    let org = account.org().expect("an organisation account");
    let actor = match portal
        .tenancy()
        .actor(&signed_in.tenancy_session(), &account)
        .await
    {
        Ok(actor) => actor,
        Err(err) => return unavailable(err),
    };
    let admin = matches!(
        actor.role(account.place()),
        Some(Role::OrgAdmin | Role::GlobalAdmin)
    );
    let mut tx = match portal.pool.begin().await {
        Ok(tx) => tx,
        Err(err) => return unavailable(err),
    };
    let owner: Option<i32> = match sqlx::query_scalar(
        "SELECT m.login_id FROM registry_member_certificates AS c
         JOIN memberships AS m ON m.id = c.membership_id
         WHERE c.id = $1 AND c.org_id = $2 AND m.org_id = $2 FOR UPDATE OF c",
    )
    .bind(id)
    .bind(org)
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(value) => value,
        Err(err) => return unavailable(err),
    };
    let Some(owner) = owner else {
        return not_found();
    };
    if owner != signed_in.login_id && actor.needs_second_factor() {
        return second_factor_first();
    }
    if owner != signed_in.login_id && !admin {
        return refused("Only this member or an organisation admin can revoke the certificate.");
    }
    if let Err(err) = sqlx::query(
        "UPDATE registry_member_certificates SET revoked_at = COALESCE(revoked_at, now()) WHERE id = $1 AND org_id = $2",
    ).bind(id).bind(org).execute(&mut *tx).await { return unavailable(err) }
    if let Err(err) = tx.commit().await {
        return unavailable(err);
    }
    redirect("/certificates/setup")
}

/// One committed member disable closes every certificate for that member on the
/// next package admission, including certificates issued before this action.
pub(crate) async fn disable_member(
    State(portal): State<Shared>,
    Path(id): Path<i32>,
    headers: HeaderMap,
    Form(form): Form<Csrf>,
) -> Response {
    let signed_in = match portal.signed_in_post(&headers, &form.csrf).await {
        Ok(value) => value,
        Err(answer) => return answer,
    };
    let account = match signed_in.account(&portal).await {
        Ok(Some(account)) if account.org().is_some() => account,
        Ok(_) => return not_found(),
        Err(err) => return unavailable(err),
    };
    let org = account.org().expect("an organisation account");
    let target = portal
        .tenancy()
        .authorized_place(
            &signed_in.tenancy_session(),
            PlaceRef {
                kind: LayerKind::User,
                id: id as u32,
            },
        )
        .await;
    let Ok(target) = target else {
        return not_found();
    };
    if target.org() != Some(org) {
        return not_found();
    }
    let actor = match portal
        .tenancy()
        .actor(&signed_in.tenancy_session(), &account)
        .await
    {
        Ok(actor) => actor,
        Err(err) => return unavailable(err),
    };
    if actor.needs_second_factor() {
        return second_factor_first();
    }
    if !matches!(
        actor.role(account.place()),
        Some(Role::OrgAdmin | Role::GlobalAdmin)
    ) {
        return refused("Only the organisation's org admins can disable package access.");
    }
    let result = sqlx::query(
        "UPDATE memberships SET package_access_disabled_at = COALESCE(package_access_disabled_at, now())
         WHERE id = $1 AND org_id = $2",
    ).bind(id).bind(org).execute(&portal.pool).await;
    match result {
        Ok(done) if done.rows_affected() == 1 => redirect(&format!("/org/{org}")),
        Ok(_) => not_found(),
        Err(err) => unavailable(err),
    }
}
