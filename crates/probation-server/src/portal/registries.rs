//! Administrator catalog of immutable, organization-scoped registry targets.

use askama::Template;
use axum::extract::{Form, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use super::{Shared, not_found, redirect, refused, unavailable};

/// id, name, ecosystem, target, trusted, has a read credential, archive origin, resource path prefix, token origin.
/// then the stored `osv_scope` (empty: the default rule) and what it means for the names this registry sends (row 27).
type CatalogRow = (i64, String, String, String, bool, bool, String, String, String, String, &'static str);
type StoredRow = (i64, String, String, String, bool, bool, String, String, String, String);

#[derive(Template)]
#[template(
    source = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Package registries · Probation</title></head><body><a class=\"skip\" href=\"#main\">Skip to main content</a><main id=\"main\"><h1>Package registries</h1><h2>OSV coverage</h2><ul>{% for family in families %}<li data-osv-family=\"{{ family.0 }}\">{{ family.0 }}: {{ family.1 }}</li>{% endfor %}</ul><ul>{% for row in rows %}<li>{{ row.0 }} {{ row.1 }} {{ row.2 }} {{ row.3 }}<p data-osv-registry=\"{{ row.0 }}\">{{ row.10 }}</p><form method=\"post\" action=\"/org/{{ org }}/registries/{{ row.0 }}/trust\"><input type=\"hidden\" name=\"csrf\" value=\"{{ csrf }}\"><label><input name=\"trusted\" type=\"checkbox\"{% if row.4 %} checked{% endif %}>Skip age delay</label><button type=\"submit\">Save trust</button></form><form method=\"post\" action=\"/org/{{ org }}/registries/{{ row.0 }}/osv-scope\"><input type=\"hidden\" name=\"csrf\" value=\"{{ csrf }}\"><label>OSV scope<select name=\"osv_scope\"><option value=\"\"{% if row.9.is_empty() %} selected{% endif %}>Default (queried: package names reach the shared OSV server unless the registry is on its family's public source)</option><option value=\"public\"{% if row.9 == \"public\" %} selected{% endif %}>Public: names reach the shared server</option><option value=\"private\"{% if row.9 == \"private\" %} selected{% endif %}>Private: OSV not applicable</option></select></label><button type=\"submit\">Save OSV scope</button></form>{% if row.2 == \"cargo\" || row.2 == \"go\" || row.2 == \"nuget\" || row.2 == \"maven\" || row.2 == \"conan\" || row.2 == \"oci\" %}{% if !row.6.is_empty() %}<span>Archive origin: {{ row.6 }}</span>{% endif %}<form method=\"post\" action=\"/org/{{ org }}/registries/{{ row.0 }}/archive-origin\"><input type=\"hidden\" name=\"csrf\" value=\"{{ csrf }}\"><label>Archive origin (empty for none)<input name=\"archive_origin\" type=\"url\" value=\"{{ row.6 }}\" placeholder=\"https://host/api/cargo/repo/crates (Cargo) or the storage a Go zip, NuGet package, Maven artifact, Conan archive or OCI blob redirect lands on\"></label><button type=\"submit\">Save archive origin</button></form>{% endif %}{% if row.2 == \"oci\" %}{% if !row.8.is_empty() %}<span>Token origin: {{ row.8 }}</span>{% endif %}<form method=\"post\" action=\"/org/{{ org }}/registries/{{ row.0 }}/token-origin\"><input type=\"hidden\" name=\"csrf\" value=\"{{ csrf }}\"><label>Token origin (empty for the registry's own host and the built-in table)<input name=\"token_origin\" type=\"url\" value=\"{{ row.8 }}\" placeholder=\"https://gitlab.example.org\"></label><button type=\"submit\">Save token origin</button></form>{% endif %}{% if row.2 == \"nuget\" %}{% if !row.7.is_empty() %}<span>Resource path prefix: {{ row.7 }}</span>{% endif %}<form method=\"post\" action=\"/org/{{ org }}/registries/{{ row.0 }}/resource-prefix\"><input type=\"hidden\" name=\"csrf\" value=\"{{ csrf }}\"><label>Resource path prefix (empty for the whole host)<input name=\"resource_path_prefix\" value=\"{{ row.7 }}\" placeholder=\"/org-a/_packaging\"></label><button type=\"submit\">Save resource path prefix</button></form>{% endif %}<form method=\"post\" action=\"/org/{{ org }}/registries/{{ row.0 }}/read-credential\"><input type=\"hidden\" name=\"csrf\" value=\"{{ csrf }}\"><label>Read-only Authorization{% if row.5 %} (configured){% endif %}<input name=\"read_authorization\" type=\"password\" autocomplete=\"new-password\" placeholder=\"Bearer token or Basic credentials\"></label><label><input name=\"clear\" type=\"checkbox\">Clear credential</label><button type=\"submit\">Save credential</button></form><form method=\"post\" action=\"/org/{{ org }}/registries/{{ row.0 }}/delete-scope\"><input type=\"hidden\" name=\"csrf\" value=\"{{ csrf }}\"><label>Deletion HTTPS origin<input name=\"origin\" type=\"url\" placeholder=\"https://tarballs.example.test\" required></label><label>Path prefix<input name=\"path_prefix\" placeholder=\"/packages\" required></label><label><input name=\"forward_bearer\" type=\"checkbox\">Forward developer bearer to this origin and path</label><button type=\"submit\">Approve deletion destination</button></form><form method=\"post\" action=\"/org/{{ org }}/registries/{{ row.0 }}/remove\"><input type=\"hidden\" name=\"csrf\" value=\"{{ csrf }}\"><button type=\"submit\">Remove</button></form></li>{% endfor %}</ul><h2>Approved deletion destinations</h2><ul>{% for scope in scopes %}<li>Registry {{ scope.0 }}: {{ scope.1 }}{{ scope.2 }}{% if scope.3 %} (developer bearer enabled){% endif %}<form method=\"post\" action=\"/org/{{ org }}/registries/{{ scope.0 }}/delete-scope\"><input type=\"hidden\" name=\"csrf\" value=\"{{ csrf }}\"><input type=\"hidden\" name=\"origin\" value=\"{{ scope.1 }}\"><input type=\"hidden\" name=\"path_prefix\" value=\"{{ scope.2 }}\"><input type=\"hidden\" name=\"remove\" value=\"on\"><button type=\"submit\">Remove destination</button></form></li>{% endfor %}</ul><form method=\"post\"><input type=\"hidden\" name=\"csrf\" value=\"{{ csrf }}\"><p data-osv-privacy=\"add\">Privacy: unless you choose the Private OSV scope after adding it, the package names of a registry that is not on its family's public source (an internal mirror, for example) reach the shared OSV server and api.osv.dev. That is the default.</p><label>Name<input name=\"name\" required></label><label>Ecosystem<select name=\"ecosystem\">{% for family in families %}<option value=\"{{ family.0 }}\">{{ family.2 }}</option>{% endfor %}</select></label><label>HTTPS target<input name=\"target_url\" type=\"url\" required></label><label>Read-only Authorization value, if needed<input name=\"read_authorization\" type=\"password\" autocomplete=\"new-password\" placeholder=\"Bearer token or Basic credentials\"></label><label><input name=\"trusted\" type=\"checkbox\">Skip age delay</label><button type=\"submit\">Add registry</button></form><h2>Request private destination</h2><form method=\"post\" action=\"/org/{{ org }}/private-egress\"><input type=\"hidden\" name=\"csrf\" value=\"{{ csrf }}\"><label>Purpose<select name=\"purpose\"><option value=\"registry\">Registry</option><option value=\"ocsp\">OCSP status</option></select></label><label>Saved HTTPS target<input name=\"target_url\" type=\"url\" required></label><label>Allowed CIDR<input name=\"cidr\" required></label><button type=\"submit\">Request operator approval</button></form></main></body></html>",
    ext = "html"
)]
struct CatalogPage<'a> {
    org: i32,
    csrf: &'a str,
    rows: &'a [CatalogRow],
    families: &'a [(&'static str, String, &'static str)],
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
pub(crate) struct OsvScopeForm {
    #[serde(default)]
    csrf: String,
    /// `public`, `private`, or empty to clear (the default rule).
    #[serde(default)]
    osv_scope: String,
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
    let rows = sqlx::query_as::<_, StoredRow>(
        "SELECT id, name, ecosystem, coalesce(target_url, ''), trusted, read_authorization_enc IS NOT NULL, coalesce(archive_origin, ''), coalesce(resource_path_prefix, ''), coalesce(token_origin, ''), coalesce(osv_scope, '') FROM registries WHERE org_id = $1 AND removed_at IS NULL ORDER BY id",
    )
    .bind(org)
    .fetch_all(&portal.pool)
    .await;
    let scopes = sqlx::query_as::<_, (i64, String, String, bool)>(
        "SELECT d.registry_id, d.origin, d.path_prefix, d.forward_bearer FROM registry_delete_origins d JOIN registries r ON r.id = d.registry_id WHERE r.org_id = $1 AND r.removed_at IS NULL ORDER BY d.registry_id, d.origin, d.path_prefix",
    ).bind(org).fetch_all(&portal.pool).await;
    match (rows, scopes) {
        (Ok(rows), Ok(scopes)) => {
            let rows: Vec<CatalogRow> = rows.into_iter().map(|row| {
                let explicit = match row.9.as_str() { "public" => Some(probation_policy::api::OsvScope::Public), "private" => Some(probation_policy::api::OsvScope::Private), _ => None };
                let ecosystem = probation_policy::Ecosystem::from_tag(&row.2);
                let target = (!row.3.is_empty()).then_some(row.3.as_str());
                let line = ecosystem.map_or(crate::osv_view::NOT_APPLICABLE, |ecosystem| crate::osv_view::registry_line(ecosystem, target, explicit));
                (row.0, row.1, row.2, row.3, row.4, row.5, row.6, row.7, row.8, row.9, line)
            }).collect();
            let families: Vec<(&'static str, String, &'static str)> = crate::osv_view::coverage().iter().map(|row| (row.tag, crate::osv_view::coverage_label(row), row.name)).collect();
            (
            StatusCode::OK,
            axum::response::Html(
                CatalogPage {
                    org,
                    csrf: signed_in.session.csrf(),
                    rows: &rows,
                    families: &families,
                    scopes: &scopes,
                }
                .render()
                .expect("registry catalog template"),
            ),
        )
            .into_response()
        }
        (Err(err), _) | (_, Err(err)) => unavailable(err),
    }
}

/// The audited columns of a registry, as the audit log shows them, read `FOR UPDATE` so a `before` is the row the UPDATE then replaces (never the credential itself: only whether one is configured).
async fn registry_state(conn: &mut sqlx::PgConnection, org: i32, registry: i64) -> Result<Option<serde_json::Value>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT jsonb_build_object('name', name, 'ecosystem', ecosystem, 'target_url', target_url, 'trusted', trusted, 'osv_scope', osv_scope, 'archive_origin', archive_origin, 'token_origin', token_origin, 'resource_path_prefix', resource_path_prefix, 'read_credential_configured', read_authorization_enc IS NOT NULL, 'removed', removed_at IS NOT NULL) FROM registries WHERE id = $1 AND org_id = $2 FOR UPDATE",
    )
    .bind(registry).bind(org).fetch_optional(conn).await
}

/// Records one audit row for a registry change in the SAME transaction as the change (the audit log's rule: a change and its row commit together
/// or not at all), then commits. `before` is `registry_state` taken before the change.
async fn commit_audited(mut tx: sqlx::Transaction<'static, sqlx::Postgres>, actor: &crate::tenancy::Actor, org: i32, registry: i64, action: &str, before: Option<serde_json::Value>) -> Result<(), sqlx::Error> {
    let after = registry_state(&mut tx, org, registry).await?;
    crate::audit::record(&mut tx, crate::audit::Entry { actor, org_id: Some(org), action, subject: format!("registry:{registry}"), before, after }).await?;
    tx.commit().await
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
    let actor = match super::organisation::admin_on(&portal, &signed_in, &place).await {
        Ok(actor) => actor,
        Err(answer) => return answer,
    };
    let Ok(target) = url::Url::parse(&form.target_url) else {
        return refused("A valid HTTPS registry target is required.");
    };
    if !matches!(form.ecosystem.as_str(), "npm" | "pypi" | "rubygems" | "cargo" | "go" | "nuget" | "maven" | "conan" | "oci")
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
    let added: Result<(), sqlx::Error> = async {
        let mut tx = portal.pool.begin().await?;
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO registries (org_id, ecosystem, name, target_url, trusted, read_authorization_enc) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
        )
        .bind(org)
        .bind(&form.ecosystem)
        .bind(form.name.trim())
        .bind(target.as_str())
        .bind(form.trusted.is_some())
        .bind(sealed)
        .fetch_one(&mut *tx)
        .await?;
        commit_audited(tx, &actor, org, id, "registry.add", None).await
    }
    .await;
    match added {
        Ok(()) => redirect(&format!("/org/{org}/registries")),
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
    let actor = match super::organisation::admin_on(&portal, &signed_in, &place).await {
        Ok(actor) => actor,
        Err(answer) => return answer,
    };
    let changed: Result<bool, sqlx::Error> = async {
        let mut tx = portal.pool.begin().await?;
        let before = registry_state(&mut tx, org, registry).await?;
        let done = sqlx::query("UPDATE registries SET removed_at = now() WHERE id = $1 AND org_id = $2 AND removed_at IS NULL").bind(registry).bind(org).execute(&mut *tx).await?;
        if done.rows_affected() != 1 {
            return Ok(false);
        }
        commit_audited(tx, &actor, org, registry, "registry.remove", before).await?;
        Ok(true)
    }
    .await;
    match changed {
        Ok(true) => redirect(&format!("/org/{org}/registries")),
        Ok(false) => not_found(),
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
    let actor = match super::organisation::admin_on(&portal, &signed_in, &place).await {
        Ok(actor) => actor,
        Err(answer) => return answer,
    };
    let changed: Result<bool, sqlx::Error> = async {
        let mut tx = portal.pool.begin().await?;
        let before = registry_state(&mut tx, org, registry).await?;
        let done = sqlx::query("UPDATE registries SET trusted = $1 WHERE id = $2 AND org_id = $3 AND removed_at IS NULL").bind(form.trusted.is_some()).bind(registry).bind(org).execute(&mut *tx).await?;
        if done.rows_affected() != 1 {
            return Ok(false);
        }
        commit_audited(tx, &actor, org, registry, "registry.trust", before).await?;
        Ok(true)
    }
    .await;
    match changed {
        Ok(true) => redirect(&format!("/org/{org}/registries")),
        Ok(false) => not_found(),
        Err(err) => unavailable(err),
    }
}

pub(crate) async fn set_osv_scope(
    State(portal): State<Shared>,
    Path((org, registry)): Path<(i32, i64)>,
    headers: HeaderMap,
    Form(form): Form<OsvScopeForm>,
) -> Response {
    let signed_in = match portal.signed_in_post(&headers, &form.csrf).await {
        Ok(value) => value,
        Err(answer) => return answer,
    };
    let Some(place) = super::organisation::org_place(&portal, &signed_in, org).await else {
        return not_found();
    };
    let actor = match super::organisation::admin_on(&portal, &signed_in, &place).await {
        Ok(actor) => actor,
        Err(answer) => return answer,
    };
    let scope = match form.osv_scope.as_str() {
        "public" => Some(probation_policy::api::OsvScope::Public),
        "private" => Some(probation_policy::api::OsvScope::Private),
        "" => None,
        _ => return refused("Choose Public, Private or the default."),
    };
    let changed: Result<bool, sqlx::Error> = async {
        let mut tx = portal.pool.begin().await?;
        let before = registry_state(&mut tx, org, registry).await?;
        if !crate::service_policy::set_osv_scope(&mut *tx, org, registry, scope).await? {
            return Ok(false);
        }
        commit_audited(tx, &actor, org, registry, "registry.osv_scope", before).await?;
        Ok(true)
    }
    .await;
    match changed {
        Ok(true) => redirect(&format!("/org/{org}/registries")),
        Ok(false) => not_found(),
        Err(err) => unavailable(err),
    }
}

#[derive(serde::Deserialize)]
pub(crate) struct ArchiveOriginForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    archive_origin: String,
}

/// Sets or clears a Cargo, Go, NuGet, Maven, Conan or OCI registry's archive origin (an https origin and path prefix, the same shape
/// rules as a target).
pub(crate) async fn set_archive_origin(
    State(portal): State<Shared>,
    Path((org, registry)): Path<(i32, i64)>,
    headers: HeaderMap,
    Form(form): Form<ArchiveOriginForm>,
) -> Response {
    let signed_in = match portal.signed_in_post(&headers, &form.csrf).await {
        Ok(value) => value,
        Err(answer) => return answer,
    };
    let Some(place) = super::organisation::org_place(&portal, &signed_in, org).await else {
        return not_found();
    };
    let actor = match super::organisation::admin_on(&portal, &signed_in, &place).await {
        Ok(actor) => actor,
        Err(answer) => return answer,
    };
    let text = form.archive_origin.trim();
    let origin = if text.is_empty() {
        None
    } else {
        match crate::service_policy::valid_archive_origin(text) {
            Some(url) => Some(url.to_string()),
            None => return refused("An archive origin is an HTTPS URL without credentials, query or fragment."),
        }
    };
    let changed: Result<bool, sqlx::Error> = async {
        let mut tx = portal.pool.begin().await?;
        let before = registry_state(&mut tx, org, registry).await?;
        if !crate::service_policy::set_archive_origin(&mut *tx, org, registry, origin.as_deref()).await? {
            return Ok(false);
        }
        commit_audited(tx, &actor, org, registry, "registry.archive_origin", before).await?;
        Ok(true)
    }
    .await;
    match changed {
        Ok(true) => redirect(&format!("/org/{org}/registries")),
        Ok(false) => not_found(),
        Err(err) => unavailable(err),
    }
}

#[derive(serde::Deserialize)]
pub(crate) struct TokenOriginForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    token_origin: String,
}

/// Sets or clears an OCI registry's token origin (an https origin, no path; empty keeps the registry's own host and the built-in table).
pub(crate) async fn set_token_origin(
    State(portal): State<Shared>,
    Path((org, registry)): Path<(i32, i64)>,
    headers: HeaderMap,
    Form(form): Form<TokenOriginForm>,
) -> Response {
    let signed_in = match portal.signed_in_post(&headers, &form.csrf).await {
        Ok(value) => value,
        Err(answer) => return answer,
    };
    let Some(place) = super::organisation::org_place(&portal, &signed_in, org).await else {
        return not_found();
    };
    let actor = match super::organisation::admin_on(&portal, &signed_in, &place).await {
        Ok(actor) => actor,
        Err(answer) => return answer,
    };
    let text = form.token_origin.trim();
    let origin = if text.is_empty() {
        None
    } else {
        match crate::service_policy::valid_token_origin(text) {
            Some(url) => Some(url.origin().ascii_serialization()),
            None => return refused("A token origin is an HTTPS origin without a path, credentials, query or fragment."),
        }
    };
    let changed: Result<bool, sqlx::Error> = async {
        let mut tx = portal.pool.begin().await?;
        let before = registry_state(&mut tx, org, registry).await?;
        if !crate::service_policy::set_token_origin(&mut *tx, org, registry, origin.as_deref()).await? {
            return Ok(false);
        }
        commit_audited(tx, &actor, org, registry, "registry.token_origin", before).await?;
        Ok(true)
    }
    .await;
    match changed {
        Ok(true) => redirect(&format!("/org/{org}/registries")),
        Ok(false) => not_found(),
        Err(err) => unavailable(err),
    }
}

#[derive(serde::Deserialize)]
pub(crate) struct ResourcePrefixForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    resource_path_prefix: String,
}

/// Sets or clears a NuGet registry's resource path prefix (whole path segments; empty keeps the whole host).
pub(crate) async fn set_resource_prefix(
    State(portal): State<Shared>,
    Path((org, registry)): Path<(i32, i64)>,
    headers: HeaderMap,
    Form(form): Form<ResourcePrefixForm>,
) -> Response {
    let signed_in = match portal.signed_in_post(&headers, &form.csrf).await {
        Ok(value) => value,
        Err(answer) => return answer,
    };
    let Some(place) = super::organisation::org_place(&portal, &signed_in, org).await else {
        return not_found();
    };
    let actor = match super::organisation::admin_on(&portal, &signed_in, &place).await {
        Ok(actor) => actor,
        Err(answer) => return answer,
    };
    let text = form.resource_path_prefix.trim();
    let prefix = if text.is_empty() {
        None
    } else if probation::managed::service_policy::valid_resource_prefix(text) {
        Some(text)
    } else {
        return refused("A resource path prefix starts with / and is whole path segments (letters, digits, . _ ~ -), without a trailing slash.");
    };
    let changed: Result<bool, sqlx::Error> = async {
        let mut tx = portal.pool.begin().await?;
        let before = registry_state(&mut tx, org, registry).await?;
        if !crate::service_policy::set_resource_prefix(&mut *tx, org, registry, prefix).await? {
            return Ok(false);
        }
        commit_audited(tx, &actor, org, registry, "registry.resource_prefix", before).await?;
        Ok(true)
    }
    .await;
    match changed {
        Ok(true) => redirect(&format!("/org/{org}/registries")),
        Ok(false) => not_found(),
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
    let actor = match super::organisation::admin_on(&portal, &signed_in, &place).await {
        Ok(actor) => actor,
        Err(answer) => return answer,
    };
    let value = form.read_authorization.trim();
    let clear = form.clear.is_some();
    if clear != value.is_empty()
        || value.len() > 8192
        || (!clear && (!value.contains(' ') || axum::http::HeaderValue::from_str(value).is_err()))
    {
        return refused("Enter a valid Authorization value or select Clear credential.");
    }
    let sealed = (!clear).then(|| portal.secrets.seal(&format!("registry read org {org}"), value.as_bytes()));
    let changed: Result<bool, sqlx::Error> = async {
        let mut tx = portal.pool.begin().await?;
        let before = registry_state(&mut tx, org, registry).await?;
        let done = sqlx::query("UPDATE registries SET read_authorization_enc = $1 WHERE id = $2 AND org_id = $3 AND removed_at IS NULL").bind(sealed).bind(registry).bind(org).execute(&mut *tx).await?;
        if done.rows_affected() != 1 {
            return Ok(false);
        }
        commit_audited(tx, &actor, org, registry, "registry.read_credential", before).await?;
        Ok(true)
    }
    .await;
    match changed {
        Ok(true) => redirect(&format!("/org/{org}/registries")),
        Ok(false) => not_found(),
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
