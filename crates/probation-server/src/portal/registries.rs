//! Administrator catalog of immutable, organization-scoped registry targets.

use askama::Template;
use axum::extract::{Form, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use super::{Shared, not_found, redirect, refused, unavailable};

#[derive(Template)]
#[template(
    source = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Package registries · Probation</title></head><body><a class=\"skip\" href=\"#main\">Skip to main content</a><main id=\"main\"><h1>Package registries</h1><ul>{% for row in rows %}<li>{{ row.0 }} {{ row.1 }} {{ row.2 }} {{ row.3 }}<form method=\"post\" action=\"/org/{{ org }}/registries/{{ row.0 }}/trust\"><input type=\"hidden\" name=\"csrf\" value=\"{{ csrf }}\"><label><input name=\"trusted\" type=\"checkbox\"{% if row.4 %} checked{% endif %}>Skip age delay</label><button type=\"submit\">Save trust</button></form><form method=\"post\" action=\"/org/{{ org }}/registries/{{ row.0 }}/read-credential\"><input type=\"hidden\" name=\"csrf\" value=\"{{ csrf }}\"><label>Read-only Authorization{% if row.5 %} (configured){% endif %}<input name=\"read_authorization\" type=\"password\" autocomplete=\"new-password\" placeholder=\"Bearer token or Basic credentials\"></label><label><input name=\"clear\" type=\"checkbox\">Clear credential</label><button type=\"submit\">Save credential</button></form><form method=\"post\" action=\"/org/{{ org }}/registries/{{ row.0 }}/delete-scope\"><input type=\"hidden\" name=\"csrf\" value=\"{{ csrf }}\"><label>Deletion HTTPS origin<input name=\"origin\" type=\"url\" placeholder=\"https://tarballs.example.test\" required></label><label>Path prefix<input name=\"path_prefix\" placeholder=\"/packages\" required></label><label><input name=\"forward_bearer\" type=\"checkbox\">Forward developer bearer to this origin and path</label><button type=\"submit\">Approve deletion destination</button></form><form method=\"post\" action=\"/org/{{ org }}/registries/{{ row.0 }}/remove\"><input type=\"hidden\" name=\"csrf\" value=\"{{ csrf }}\"><button type=\"submit\">Remove</button></form></li>{% endfor %}</ul><h2>Approved deletion destinations</h2><ul>{% for scope in scopes %}<li>Registry {{ scope.0 }}: {{ scope.1 }}{{ scope.2 }}{% if scope.3 %} (developer bearer enabled){% endif %}<form method=\"post\" action=\"/org/{{ org }}/registries/{{ scope.0 }}/delete-scope\"><input type=\"hidden\" name=\"csrf\" value=\"{{ csrf }}\"><input type=\"hidden\" name=\"origin\" value=\"{{ scope.1 }}\"><input type=\"hidden\" name=\"path_prefix\" value=\"{{ scope.2 }}\"><input type=\"hidden\" name=\"remove\" value=\"on\"><button type=\"submit\">Remove destination</button></form></li>{% endfor %}</ul><form method=\"post\"><input type=\"hidden\" name=\"csrf\" value=\"{{ csrf }}\"><label>Name<input name=\"name\" required></label><label>Ecosystem<select name=\"ecosystem\"><option value=\"npm\">npm</option><option value=\"pypi\">PyPI</option></select></label><label>HTTPS target<input name=\"target_url\" type=\"url\" required></label><label>Read-only Authorization value, if needed<input name=\"read_authorization\" type=\"password\" autocomplete=\"new-password\" placeholder=\"Bearer token or Basic credentials\"></label><label><input name=\"trusted\" type=\"checkbox\">Skip age delay</label><button type=\"submit\">Add registry</button></form><h2>Request private destination</h2><form method=\"post\" action=\"/org/{{ org }}/private-egress\"><input type=\"hidden\" name=\"csrf\" value=\"{{ csrf }}\"><label>Purpose<select name=\"purpose\"><option value=\"registry\">Registry</option><option value=\"ocsp\">OCSP status</option></select></label><label>Saved HTTPS target<input name=\"target_url\" type=\"url\" required></label><label>Allowed CIDR<input name=\"cidr\" required></label><button type=\"submit\">Request operator approval</button></form></main></body></html>",
    ext = "html"
)]
struct CatalogPage<'a> {
    org: i32,
    csrf: &'a str,
    rows: &'a [(i64, String, String, String, bool, bool)],
    scopes: &'a [(i64, String, String, bool)],
}

#[derive(Deserialize)]
pub(crate) struct RegistryForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    ecosystem: String,
    #[serde(default)]
    target_url: String,
    #[serde(default)]
    read_authorization: String,
    trusted: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct RemoveForm {
    #[serde(default)]
    csrf: String,
}

#[derive(Deserialize)]
pub(crate) struct TrustForm {
    #[serde(default)]
    csrf: String,
    trusted: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct ReadCredentialForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    read_authorization: String,
    clear: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct DeleteScopeForm {
    #[serde(default)] csrf: String,
    #[serde(default)] origin: String,
    #[serde(default)] path_prefix: String,
    forward_bearer: Option<String>,
    remove: Option<String>,
}

pub(crate) async fn set_delete_scope(
    State(portal): State<Shared>,
    Path((org, registry)): Path<(i32, i64)>,
    headers: HeaderMap,
    Form(form): Form<DeleteScopeForm>,
) -> Response {
    let signed_in = match portal.signed_in_post(&headers, &form.csrf).await {
        Ok(value) => value,
        Err(answer) => return answer,
    };
    let Some(place) = super::organisation::org_place(&portal, &signed_in, org).await else { return not_found(); };
    if let Err(answer) = super::organisation::admin_on(&portal, &signed_in, &place).await { return answer; }
    let Ok(origin) = url::Url::parse(&form.origin) else { return refused("Enter an exact HTTPS origin."); };
    if origin.scheme() != "https" || origin.host_str().is_none() || !origin.username().is_empty()
        || origin.password().is_some() || origin.query().is_some() || origin.fragment().is_some()
        || origin.path() != "/" || form.path_prefix.is_empty() || !form.path_prefix.starts_with('/')
        || form.path_prefix.contains("//") || form.path_prefix.contains('\\')
        || form.path_prefix.split('/').any(|part| part == "." || part == "..")
        || form.path_prefix.to_ascii_lowercase().contains("%2e")
        || form.path_prefix.to_ascii_lowercase().contains("%2f")
        || form.path_prefix.to_ascii_lowercase().contains("%5c")
    { return refused("Enter an exact HTTPS origin and unambiguous path prefix."); }
    let exact_origin = origin.origin().ascii_serialization();
    let result = if form.remove.is_some() {
        sqlx::query("DELETE FROM registry_delete_origins WHERE registry_id = $1 AND origin = $2 AND path_prefix = $3 AND EXISTS (SELECT 1 FROM registries WHERE id = $1 AND org_id = $4 AND ecosystem = 'npm' AND removed_at IS NULL)")
            .bind(registry).bind(&exact_origin).bind(&form.path_prefix).bind(org).execute(&portal.pool).await
    } else {
        sqlx::query("INSERT INTO registry_delete_origins (registry_id, origin, path_prefix, forward_bearer) SELECT id, $2, $3, $4 FROM registries WHERE id = $1 AND org_id = $5 AND ecosystem = 'npm' AND removed_at IS NULL ON CONFLICT (registry_id, origin, path_prefix) DO UPDATE SET forward_bearer = excluded.forward_bearer")
            .bind(registry).bind(&exact_origin).bind(&form.path_prefix).bind(form.forward_bearer.is_some()).bind(org).execute(&portal.pool).await
    };
    match result {
        Ok(done) if done.rows_affected() == 1 => redirect(&format!("/org/{org}/registries")),
        Ok(_) => not_found(),
        Err(err) => unavailable(err),
    }
}

pub(crate) async fn catalog(
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
    let rows = sqlx::query_as::<_, (i64, String, String, String, bool, bool)>(
        "SELECT id, name, ecosystem, coalesce(target_url, ''), trusted, read_authorization_enc IS NOT NULL FROM registries WHERE org_id = $1 AND removed_at IS NULL ORDER BY id",
    )
    .bind(org)
    .fetch_all(&portal.pool)
    .await;
    let scopes = sqlx::query_as::<_, (i64, String, String, bool)>(
        "SELECT d.registry_id, d.origin, d.path_prefix, d.forward_bearer FROM registry_delete_origins d JOIN registries r ON r.id = d.registry_id WHERE r.org_id = $1 AND r.removed_at IS NULL ORDER BY d.registry_id, d.origin, d.path_prefix",
    ).bind(org).fetch_all(&portal.pool).await;
    match (rows, scopes) {
        (Ok(rows), Ok(scopes)) => (
            StatusCode::OK,
            axum::response::Html(
                CatalogPage {
                    org,
                    csrf: signed_in.session.csrf(),
                    rows: &rows,
                    scopes: &scopes,
                }
                .render()
                .expect("registry catalog template"),
            ),
        )
            .into_response(),
        (Err(err), _) | (_, Err(err)) => unavailable(err),
    }
}

pub(crate) async fn add(
    State(portal): State<Shared>,
    Path(org): Path<i32>,
    headers: HeaderMap,
    Form(form): Form<RegistryForm>,
) -> Response {
    let signed_in = match portal.signed_in_post(&headers, &form.csrf).await {
        Ok(value) => value,
        Err(answer) => return answer,
    };
    let Some(place) = super::organisation::org_place(&portal, &signed_in, org).await else {
        return not_found();
    };
    if let Err(answer) = super::organisation::admin_on(&portal, &signed_in, &place).await {
        return answer;
    }
    let Ok(target) = url::Url::parse(&form.target_url) else {
        return refused("A valid HTTPS registry target is required.");
    };
    if !matches!(form.ecosystem.as_str(), "npm" | "pypi")
        || form.name.trim().is_empty()
        || form.name.len() > 200
        || target.scheme() != "https"
        || target.host_str().is_none()
        || !target.username().is_empty()
        || target.password().is_some()
        || target.query().is_some()
        || target.fragment().is_some()
    {
        return refused("A name, ecosystem and HTTPS target are required.");
    }
    let read_authorization = form.read_authorization.trim();
    if read_authorization.len() > 8192
        || (!read_authorization.is_empty()
            && (!read_authorization.contains(' ')
                || axum::http::HeaderValue::from_str(read_authorization).is_err()))
    {
        return refused("A valid read-only Authorization value is required.");
    }
    let sealed = (!read_authorization.is_empty()).then(|| portal.secrets.seal(
        &format!("registry read org {org}"), read_authorization.as_bytes(),
    ));
    let done = sqlx::query(
        "INSERT INTO registries (org_id, ecosystem, name, target_url, trusted, read_authorization_enc) VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(org)
    .bind(&form.ecosystem)
    .bind(form.name.trim())
    .bind(target.as_str())
    .bind(form.trusted.is_some())
    .bind(sealed)
    .execute(&portal.pool)
    .await;
    match done {
        Ok(_) => redirect(&format!("/org/{org}/registries")),
        Err(err) => unavailable(err),
    }
}

pub(crate) async fn remove(
    State(portal): State<Shared>,
    Path((org, registry)): Path<(i32, i64)>,
    headers: HeaderMap,
    Form(form): Form<RemoveForm>,
) -> Response {
    let signed_in = match portal.signed_in_post(&headers, &form.csrf).await {
        Ok(value) => value,
        Err(answer) => return answer,
    };
    let Some(place) = super::organisation::org_place(&portal, &signed_in, org).await else {
        return not_found();
    };
    if let Err(answer) = super::organisation::admin_on(&portal, &signed_in, &place).await {
        return answer;
    }
    match sqlx::query("UPDATE registries SET removed_at = now() WHERE id = $1 AND org_id = $2 AND removed_at IS NULL")
        .bind(registry).bind(org).execute(&portal.pool).await
    {
        Ok(done) if done.rows_affected() == 1 => redirect(&format!("/org/{org}/registries")),
        Ok(_) => not_found(),
        Err(err) => unavailable(err),
    }
}

pub(crate) async fn set_trust(
    State(portal): State<Shared>,
    Path((org, registry)): Path<(i32, i64)>,
    headers: HeaderMap,
    Form(form): Form<TrustForm>,
) -> Response {
    let signed_in = match portal.signed_in_post(&headers, &form.csrf).await {
        Ok(value) => value,
        Err(answer) => return answer,
    };
    let Some(place) = super::organisation::org_place(&portal, &signed_in, org).await else {
        return not_found();
    };
    if let Err(answer) = super::organisation::admin_on(&portal, &signed_in, &place).await {
        return answer;
    }
    match sqlx::query("UPDATE registries SET trusted = $1 WHERE id = $2 AND org_id = $3 AND removed_at IS NULL")
        .bind(form.trusted.is_some()).bind(registry).bind(org).execute(&portal.pool).await
    {
        Ok(done) if done.rows_affected() == 1 => redirect(&format!("/org/{org}/registries")),
        Ok(_) => not_found(),
        Err(err) => unavailable(err),
    }
}

pub(crate) async fn set_read_credential(
    State(portal): State<Shared>,
    Path((org, registry)): Path<(i32, i64)>,
    headers: HeaderMap,
    Form(form): Form<ReadCredentialForm>,
) -> Response {
    let signed_in = match portal.signed_in_post(&headers, &form.csrf).await {
        Ok(value) => value,
        Err(answer) => return answer,
    };
    let Some(place) = super::organisation::org_place(&portal, &signed_in, org).await else {
        return not_found();
    };
    if let Err(answer) = super::organisation::admin_on(&portal, &signed_in, &place).await {
        return answer;
    }
    let value = form.read_authorization.trim();
    let clear = form.clear.is_some();
    if clear != value.is_empty()
        || value.len() > 8192
        || (!clear && (!value.contains(' ') || axum::http::HeaderValue::from_str(value).is_err()))
    {
        return refused("Enter a valid Authorization value or select Clear credential.");
    }
    let sealed = (!clear).then(|| portal.secrets.seal(&format!("registry read org {org}"), value.as_bytes()));
    match sqlx::query("UPDATE registries SET read_authorization_enc = $1 WHERE id = $2 AND org_id = $3 AND removed_at IS NULL")
        .bind(sealed).bind(registry).bind(org).execute(&portal.pool).await
    {
        Ok(done) if done.rows_affected() == 1 => redirect(&format!("/org/{org}/registries")),
        Ok(_) => not_found(),
        Err(err) => unavailable(err),
    }
}

#[derive(Deserialize)]
pub(crate) struct EgressRequestForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    purpose: String,
    #[serde(default)]
    target_url: String,
    #[serde(default)]
    cidr: String,
}

/// A company admin requests one exact destination/CIDR. A request has no egress
/// effect until a global operator approves it.
pub(crate) async fn request_private_egress(
    State(portal): State<Shared>,
    Path(org): Path<i32>,
    headers: HeaderMap,
    Form(form): Form<EgressRequestForm>,
) -> Response {
    let signed_in = match portal.signed_in_post(&headers, &form.csrf).await {
        Ok(value) => value,
        Err(answer) => return answer,
    };
    let Some(place) = super::organisation::org_place(&portal, &signed_in, org).await else {
        return not_found();
    };
    if let Err(answer) = super::organisation::admin_on(&portal, &signed_in, &place).await {
        return answer;
    }
    let Ok(target) = url::Url::parse(&form.target_url) else {
        return refused("An exact HTTPS destination is required.");
    };
    let Ok(cidr) = form.cidr.parse::<ipnet::IpNet>() else {
        return refused("A valid destination CIDR is required.");
    };
    if target.scheme() != "https" || target.host_str().is_none()
        || !target.username().is_empty() || target.password().is_some()
        || target.fragment().is_some() || !matches!(form.purpose.as_str(), "registry" | "ocsp") {
        return refused("An exact HTTPS destination is required.");
    }
    let configured: Result<bool, _> = if form.purpose == "registry" {
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM registries WHERE org_id = $1 AND target_url = $2 AND removed_at IS NULL)")
            .bind(org).bind(target.as_str()).fetch_one(&portal.pool).await
    } else {
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM registry_certificate_providers WHERE org_id = $1 AND expected_ocsp_url = $2)")
            .bind(org).bind(target.as_str()).fetch_one(&portal.pool).await
    };
    match configured {
        Ok(false) => return refused("Save the destination before requesting private egress."),
        Err(err) => return unavailable(err),
        Ok(true) => {}
    }
    let host = target.host_str().expect("validated host").to_ascii_lowercase();
    let port = target.port_or_known_default().expect("HTTPS has a port") as i32;
    let done = sqlx::query(
        "INSERT INTO registry_private_egress (org_id, purpose, host, port, cidr, requested_by)
         VALUES ($1, $2, $3, $4, $5::cidr, $6)
         ON CONFLICT (org_id, purpose, host, port, cidr) DO NOTHING",
    )
    .bind(org).bind(&form.purpose).bind(host).bind(port).bind(cidr.to_string())
    .bind(signed_in.login_id).execute(&portal.pool).await;
    match done {
        Ok(_) => redirect(&format!("/org/{org}/registries")),
        Err(err) => unavailable(err),
    }
}

#[derive(Template)]
#[template(source = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Private egress approvals</title></head><body><a class=\"skip\" href=\"#main\">Skip to main content</a><main id=\"main\"><h1>Private egress approvals</h1><ul>{% for row in rows %}<li>{{ row.0 }} org {{ row.1 }} {{ row.2 }} {{ row.3 }}:{{ row.4 }} {{ row.5 }}{% if row.6 %} approved{% else %}<form method=\"post\" action=\"/admin/private-egress/{{ row.0 }}/approve\"><input type=\"hidden\" name=\"csrf\" value=\"{{ csrf }}\"><button type=\"submit\">Approve</button></form>{% endif %}</li>{% endfor %}</ul></main></body></html>", ext = "html")]
struct EgressPage<'a> {
    csrf: &'a str,
    rows: &'a [(i64, i32, String, String, i32, String, bool)],
}

pub(crate) async fn private_egress_queue(State(portal): State<Shared>, headers: HeaderMap) -> Response {
    let signed_in = match portal.signed_in(&headers).await {
        Ok(value) => value,
        Err(answer) => return answer,
    };
    if let Err(answer) = super::admin::operator(&portal, &signed_in).await {
        return answer;
    }
    let rows = sqlx::query_as::<_, (i64, i32, String, String, i32, String, bool)>(
        "SELECT id, org_id, purpose, host, port, cidr::text, approved_at IS NOT NULL
         FROM registry_private_egress ORDER BY id",
    ).fetch_all(&portal.pool).await;
    match rows {
        Ok(rows) => (StatusCode::OK, axum::response::Html(EgressPage {
            csrf: signed_in.session.csrf(), rows: &rows,
        }.render().expect("private egress template"))).into_response(),
        Err(err) => unavailable(err),
    }
}

pub(crate) async fn approve_private_egress(
    State(portal): State<Shared>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    Form(form): Form<RemoveForm>,
) -> Response {
    let signed_in = match portal.signed_in_post(&headers, &form.csrf).await {
        Ok(value) => value,
        Err(answer) => return answer,
    };
    if let Err(answer) = super::admin::operator(&portal, &signed_in).await {
        return answer;
    }
    let done = sqlx::query(
        "UPDATE registry_private_egress SET approved_by = $1, approved_at = now()
         WHERE id = $2 AND approved_at IS NULL",
    ).bind(signed_in.login_id).bind(id).execute(&portal.pool).await;
    match done {
        Ok(done) if done.rows_affected() == 1 => redirect("/admin/private-egress"),
        Ok(_) => not_found(),
        Err(err) => unavailable(err),
    }
}
