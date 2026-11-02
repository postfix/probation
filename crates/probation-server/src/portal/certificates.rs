//! Signed-in, client-specific certificate setup. Only public certificate status is retained.

use askama::Template;
use axum::extract::{Form, Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SanType, SerialNumber,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};

use super::{Shared, not_found, redirect, refused, unavailable};

#[derive(Template)]
#[template(
    source = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Package client setup · Probation</title></head><body><a class=\"skip\" href=\"#main\">Skip to main content</a><main id=\"main\"><h1>Package client setup</h1><form method=\"post\" action=\"/certificates/setup\"><input type=\"hidden\" name=\"csrf\" value=\"{{ csrf }}\"><button type=\"submit\">Download my setup bundle</button></form></main></body></html>",
    ext = "html"
)]
struct SetupPage<'a> {
    csrf: &'a str,
}

#[derive(Deserialize)]
pub(crate) struct SetupForm {
    #[serde(default)]
    csrf: String,
}

#[derive(Template)]
#[template(
    source = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Enterprise certificates · Probation</title></head><body><a class=\"skip\" href=\"#main\">Skip to main content</a><main id=\"main\"><h1>Enterprise certificates</h1><p>Save public trust, then check a sample leaf as good. Have the issuer commit revocation of that leaf; check the same leaf as revoked to activate.</p><form method=\"post\"><input type=\"hidden\" name=\"csrf\" value=\"{{ csrf }}\"><label>Identity field<input name=\"identity_field\" value=\"uri_san_membership_uuid\"></label><label>Expected OCSP AIA URL<input name=\"expected_ocsp_url\" type=\"url\"></label><label>CA certificate PEM<textarea name=\"root_pem\"></textarea></label><button type=\"submit\">Save</button></form><form method=\"post\" action=\"/org/{{ org }}/certificates/test\"><input type=\"hidden\" name=\"csrf\" value=\"{{ csrf }}\"><label>Sample leaf and issuer chain PEM<textarea name=\"chain_pem\" required></textarea></label><button name=\"phase\" value=\"good\" type=\"submit\">Check good sample</button><button name=\"phase\" value=\"revoked\" type=\"submit\">Check committed revocation and activate</button></form></main></body></html>",
    ext = "html"
)]
struct EnterprisePage<'a> {
    csrf: &'a str,
    org: i32,
}

#[derive(Deserialize)]
pub(crate) struct EnterpriseForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    identity_field: String,
    #[serde(default)]
    expected_ocsp_url: String,
    #[serde(default)]
    root_pem: String,
}

#[derive(Deserialize)]
pub(crate) struct EnterpriseTestForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    chain_pem: String,
    #[serde(default)]
    phase: String,
}

fn validate_identity_field(field: &str) -> Result<(), &'static str> {
    if field == "uri_san_membership_uuid" {
        Ok(())
    } else {
        Err("The identity field must be the URI SAN membership UUID.")
    }
}

pub(crate) async fn enterprise_page(
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
    (
        StatusCode::OK,
        axum::response::Html(
            EnterprisePage {
                csrf: signed_in.session.csrf(),
                org,
            }
            .render()
            .expect("enterprise settings template"),
        ),
    )
        .into_response()
}

pub(crate) async fn save_enterprise_settings(
    State(portal): State<Shared>,
    Path(org): Path<i32>,
    headers: HeaderMap,
    Form(form): Form<EnterpriseForm>,
) -> Response {
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject;

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
    if let Err(message) = validate_identity_field(&form.identity_field) {
        return refused(message);
    }
    let Ok(status_url) = url::Url::parse(&form.expected_ocsp_url) else {
        return refused("A valid HTTPS OCSP URL is required.");
    };
    if status_url.scheme() != "https"
        || status_url.host_str().is_none()
        || !status_url.username().is_empty()
        || status_url.password().is_some()
        || status_url.fragment().is_some()
    {
        return refused("A valid HTTPS OCSP URL is required.");
    }
    let Ok(root) = CertificateDer::from_pem_slice(form.root_pem.as_bytes()) else {
        return refused("A valid CA certificate PEM is required.");
    };
    let Ok((_, cert)) = x509_parser::parse_x509_certificate(root.as_ref()) else {
        return refused("A valid CA certificate PEM is required.");
    };
    if !cert.is_ca() {
        return refused("The certificate must be a CA.");
    }
    let fingerprint = Sha256::digest(root.as_ref());
    let saved = async {
        let mut tx = portal.pool.begin().await?;
        sqlx::query("INSERT INTO registry_certificate_providers (org_id, kind, self_service, expected_ocsp_url, identity_field, settings_revision) VALUES ($1, 'pending', false, $2, $3, 1) ON CONFLICT (org_id) DO UPDATE SET kind = 'pending', self_service = false, issuer_key_enc = NULL, issuer_cert_pem = NULL, issuer_fingerprint = NULL, expected_ocsp_url = EXCLUDED.expected_ocsp_url, identity_field = EXCLUDED.identity_field, settings_revision = registry_certificate_providers.settings_revision + 1")
            .bind(org).bind(status_url.as_str()).bind(&form.identity_field).execute(&mut *tx).await?;
        sqlx::query("UPDATE registry_certificate_roots SET active = false WHERE org_id = $1")
            .bind(org).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO registry_certificate_roots (org_id, fingerprint, certificate_pem) VALUES ($1, $2, $3) ON CONFLICT (org_id, fingerprint) DO UPDATE SET active = true, certificate_pem = EXCLUDED.certificate_pem")
            .bind(org).bind(fingerprint.as_slice()).bind(&form.root_pem).execute(&mut *tx).await?;
        sqlx::query("DELETE FROM registry_enterprise_activation_samples WHERE org_id = $1")
            .bind(org).execute(&mut *tx).await?;
        tx.commit().await
    }
    .await;
    match saved {
        Ok(()) => redirect(&format!("/org/{org}/certificates")),
        Err(err) => unavailable(err),
    }
}

/// A real issuer transition is the activation gate. Both actions fetch a fresh
/// nonce-bound status; the second must verify `revoked` for the exact same leaf.
pub(crate) async fn test_enterprise_certificate(
    State(portal): State<Shared>,
    Path(org): Path<i32>,
    headers: HeaderMap,
    Form(form): Form<EnterpriseTestForm>,
) -> Response {
    use probation::managed::enterprise_certificate::{VerifiedIssuerStatus, check_sample_issuer_status};
    use probation_policy::api::EnterpriseStatus;
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject;
    use x509_parser::extensions::{GeneralName, ParsedExtension};

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
    if form.phase != "good" && form.phase != "revoked" {
        return refused("Choose a sample status check.");
    }
    let certs = CertificateDer::pem_slice_iter(form.chain_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>();
    let Ok(certs) = certs else { return refused("A valid certificate chain PEM is required."); };
    if certs.is_empty() || certs.len() > 8 || certs.iter().any(|cert| cert.is_empty() || cert.len() > 64 * 1024) {
        return refused("A bounded certificate chain is required.");
    }
    let chain: Vec<Vec<u8>> = certs.iter().map(|cert| cert.as_ref().to_vec()).collect();
    let Ok((_, leaf)) = x509_parser::parse_x509_certificate(&chain[0]) else {
        return refused("The sample leaf is invalid.");
    };
    let uris: Vec<&str> = leaf.subject_alternative_name().ok().flatten()
        .map(|san| san.value.general_names.iter().filter_map(|name| match name {
            GeneralName::URI(uri) => Some(*uri), _ => None,
        }).collect()).unwrap_or_default();
    let [member_uri] = uris.as_slice() else { return refused("The sample must identify one member UUID."); };
    let Some(member_uuid) = member_uri.strip_prefix("urn:probation:member:") else {
        return refused("The sample member identity is invalid.");
    };
    let aias: Vec<&str> = leaf.extensions().iter().flat_map(|extension| match extension.parsed_extension() {
        ParsedExtension::AuthorityInfoAccess(access) => access.accessdescs.iter()
            .filter(|entry| entry.access_method.to_id_string() == "1.3.6.1.5.5.7.48.1")
            .filter_map(|entry| match &entry.access_location { GeneralName::URI(uri) => Some(*uri), _ => None })
            .collect::<Vec<_>>(),
        _ => Vec::new(),
    }).collect();
    let setup: Result<Option<(String, String, i64)>, _> = sqlx::query_as(
        "SELECT expected_ocsp_url, identity_field, settings_revision FROM registry_certificate_providers WHERE org_id = $1"
    ).bind(org).fetch_optional(&portal.pool).await;
    let (expected, identity_field, revision) = match setup {
        Ok(Some(value)) => value, Ok(None) => return refused("Save enterprise trust first."),
        Err(err) => return unavailable(err),
    };
    if validate_identity_field(&identity_field).is_err() || aias.as_slice() != [expected.as_str()] {
        return refused("The sample AIA or identity field differs from saved settings.");
    }
    let member: Result<Option<String>, _> = sqlx::query_scalar(
        "SELECT m.certificate_uuid::text FROM memberships AS m
         JOIN logins AS l ON l.id = m.login_id JOIN orgs AS o ON o.id = m.org_id
         WHERE m.org_id = $1 AND m.certificate_uuid::text = $2
           AND m.package_access_disabled_at IS NULL AND l.deleted_at IS NULL
           AND o.status = 'active' AND o.deleted_at IS NULL"
    ).bind(org).bind(member_uuid).fetch_optional(&portal.pool).await;
    match member {
        Ok(Some(_)) => {}, Ok(None) => return refused("The sample member is inactive or foreign."),
        Err(err) => return unavailable(err),
    }
    let roots: Vec<String> = match sqlx::query_scalar(
        "SELECT certificate_pem FROM registry_certificate_roots WHERE org_id = $1 AND active ORDER BY fingerprint"
    ).bind(org).fetch_all(&portal.pool).await {
        Ok(roots) => roots, Err(err) => return unavailable(err),
    };
    let Some(root_der) = roots.iter().find_map(|root| crate::sync::verifies_client_chain(root, &chain)) else {
        return refused("The sample chain does not match active organization trust.");
    };
    let leaf_fingerprint = Sha256::digest(&chain[0]);
    let root_fingerprint = Sha256::digest(&root_der);
    let issuer_der = chain.get(1).cloned().unwrap_or_else(|| root_der.clone());
    let mut tx = match portal.pool.begin().await { Ok(tx) => tx, Err(err) => return unavailable(err) };
    let private_cidrs = match crate::sync::approved_private_cidrs(&mut tx, org, "ocsp", &expected).await {
        Ok(cidrs) => cidrs, Err(err) => return unavailable(err),
    };
    if let Err(err) = tx.commit().await { return unavailable(err); }
    let status = EnterpriseStatus { status_url: expected.clone(), issuer_der, root_der, private_cidrs };
    let observed = match check_sample_issuer_status(chain.clone(), status).await {
        Ok(status) => status,
        Err(_) => return refused("The issuer did not return a verifiable current status."),
    };
    let mut tx = match portal.pool.begin().await { Ok(tx) => tx, Err(err) => return unavailable(err) };
    let active_org: Result<Option<bool>, _> = sqlx::query_scalar(
        "SELECT status = 'active' AND deleted_at IS NULL FROM orgs WHERE id = $1 FOR UPDATE"
    ).bind(org).fetch_optional(&mut *tx).await;
    match active_org {
        Ok(Some(true)) => {}, Ok(_) => return refused("The organisation is inactive."),
        Err(err) => return unavailable(err),
    }
    let session: Result<Option<(bool, Option<i32>, String)>, _> = sqlx::query_as(
        "SELECT s.totp_ok, s.scope_org_id, s.csrf_token FROM sessions AS s
         JOIN logins AS l ON l.id = s.login_id
         WHERE s.id_hash = $1 AND s.login_id = $2 AND s.expires_at > now()
           AND l.deleted_at IS NULL FOR UPDATE OF s, l"
    ).bind(&signed_in.session.id_hash).bind(signed_in.login_id).fetch_optional(&mut *tx).await;
    let (totp_ok, scope, csrf) = match session {
        Ok(Some(value)) => value, Ok(None) => return refused("The operator session changed; sign in and retry."),
        Err(err) => return unavailable(err),
    };
    if scope != signed_in.session.scope_org_id || scope.is_some_and(|id| id != org) || csrf != form.csrf {
        return refused("The operator session changed; sign in and retry.");
    }
    let totp: Result<Option<i32>, _> = sqlx::query_scalar(
        "SELECT login_id FROM totp WHERE login_id = $1 AND enabled_at IS NOT NULL FOR SHARE"
    ).bind(signed_in.login_id).fetch_optional(&mut *tx).await;
    let second_factor = match totp { Ok(value) => totp_ok || value.is_some(), Err(err) => return unavailable(err) };
    let roles: Result<Vec<(String, Option<i32>)>, _> = sqlx::query_as(
        "SELECT role, org_id FROM memberships WHERE login_id = $1
           AND (org_id = $2 OR org_id IS NULL) FOR UPDATE"
    ).bind(signed_in.login_id).bind(org).fetch_all(&mut *tx).await;
    let roles = match roles { Ok(value) => value, Err(err) => return unavailable(err) };
    if !second_factor || !roles.iter().any(|(role, member_org)|
        (role == "org_admin" && *member_org == Some(org)) ||
        (role == "global_admin" && member_org.is_none() && scope.is_none())) {
        return refused("Only a current organisation admin can complete this check.");
    }
    let member: Result<Option<i32>, _> = sqlx::query_scalar(
        "SELECT m.id FROM memberships AS m
         JOIN logins AS l ON l.id = m.login_id JOIN orgs AS o ON o.id = m.org_id
         WHERE m.org_id = $1 AND m.certificate_uuid::text = $2
           AND m.package_access_disabled_at IS NULL AND l.deleted_at IS NULL
           AND o.status = 'active' AND o.deleted_at IS NULL
         FOR UPDATE OF m, l"
    ).bind(org).bind(member_uuid).fetch_optional(&mut *tx).await;
    match member {
        Ok(Some(_)) => {},
        Ok(None) => return refused("The sample member is inactive or foreign."),
        Err(err) => return unavailable(err),
    }
    let current: Result<Option<(String, i64)>, _> = sqlx::query_as(
        "SELECT kind, settings_revision FROM registry_certificate_providers WHERE org_id = $1 FOR UPDATE"
    ).bind(org).fetch_optional(&mut *tx).await;
    match current {
        Ok(Some((kind, current_revision))) if kind == "pending" && current_revision == revision => {},
        Ok(_) => return refused("Enterprise settings changed; save and retest."),
        Err(err) => return unavailable(err),
    }
    match (form.phase.as_str(), observed) {
        ("good", VerifiedIssuerStatus::Good) => {
            let saved = sqlx::query(
                "INSERT INTO registry_enterprise_activation_samples
                 (org_id, leaf_fingerprint, root_fingerprint, member_uuid, expected_ocsp_url)
                 VALUES ($1, $2, $3, $4::uuid, $5)
                 ON CONFLICT (org_id) DO UPDATE SET leaf_fingerprint = EXCLUDED.leaf_fingerprint,
                   root_fingerprint = EXCLUDED.root_fingerprint, member_uuid = EXCLUDED.member_uuid,
                   expected_ocsp_url = EXCLUDED.expected_ocsp_url, good_checked_at = now()"
            ).bind(org).bind(leaf_fingerprint.as_slice()).bind(root_fingerprint.as_slice())
                .bind(member_uuid).bind(&expected).execute(&mut *tx).await;
            match saved {
                Ok(_) => match tx.commit().await {
                    Ok(()) => (StatusCode::OK, "Sample good. Commit its revocation at the issuer, then check revoked status.").into_response(),
                    Err(err) => unavailable(err),
                },
                Err(err) => unavailable(err),
            }
        }
        ("revoked", VerifiedIssuerStatus::Revoked) => {
            let pending: Result<Option<i32>, _> = sqlx::query_scalar(
                "SELECT org_id FROM registry_enterprise_activation_samples
                 WHERE org_id = $1 AND leaf_fingerprint = $2 AND root_fingerprint = $3
                   AND member_uuid = $4::uuid AND expected_ocsp_url = $5 FOR UPDATE"
            ).bind(org).bind(leaf_fingerprint.as_slice()).bind(root_fingerprint.as_slice())
                .bind(member_uuid).bind(&expected).fetch_optional(&mut *tx).await;
            match pending {
                Ok(Some(_)) => {}, Ok(None) => return refused("Check this same sample as good before revoking it."),
                Err(err) => return unavailable(err),
            }
            let activated = sqlx::query(
                "UPDATE registry_certificate_providers SET kind = 'organisation', self_service = false,
                   issuer_key_enc = NULL, issuer_cert_pem = NULL, issuer_fingerprint = NULL
                 WHERE org_id = $1 AND kind = 'pending' AND settings_revision = $3
                   AND expected_ocsp_url = $2 AND identity_field = 'uri_san_membership_uuid'"
            ).bind(org).bind(&expected).bind(revision).execute(&mut *tx).await;
            match activated {
                Ok(done) if done.rows_affected() == 1 => {},
                Ok(_) => return refused("Enterprise settings changed; save and retest."),
                Err(err) => return unavailable(err),
            }
            if let Err(err) = sqlx::query("DELETE FROM registry_enterprise_activation_samples WHERE org_id = $1")
                .bind(org).execute(&mut *tx).await { return unavailable(err); }
            match tx.commit().await {
                Ok(()) => redirect(&format!("/org/{org}/certificates")),
                Err(err) => unavailable(err),
            }
        }
        _ => refused("The sample status did not match this activation step."),
    }
}

pub(crate) async fn setup_page(State(portal): State<Shared>, headers: HeaderMap) -> Response {
    let signed_in = match portal.signed_in(&headers).await {
        Ok(value) => value,
        Err(answer) => return answer,
    };
    let account = match signed_in.account(&portal).await {
        Ok(Some(account)) if account.org().is_some() && !account.suspended() => account,
        Ok(_) => return not_found(),
        Err(err) => return unavailable(err),
    };
    let org = account.org().expect("an organisation account");
    match self_service(&portal.pool, org).await {
        Ok(true) => (
            StatusCode::OK,
            axum::response::Html(
                SetupPage {
                    csrf: signed_in.session.csrf(),
                }
                .render()
                .expect("setup template"),
            ),
        )
            .into_response(),
        Ok(false) => refused("Client certificate self-service is disabled for this organisation."),
        Err(err) => unavailable(err),
    }
}

pub(crate) async fn issue_setup_bundle(
    State(portal): State<Shared>,
    headers: HeaderMap,
    Form(form): Form<SetupForm>,
) -> Response {
    let signed_in = match portal.signed_in_post(&headers, &form.csrf).await {
        Ok(value) => value,
        Err(answer) => return answer,
    };
    let account = match signed_in.account(&portal).await {
        Ok(Some(account)) if account.org().is_some() && !account.suspended() => account,
        Ok(_) => return not_found(),
        Err(err) => return unavailable(err),
    };
    let org = account.org().expect("an organisation account");
    let Some(firewall) = portal.config.firewall_url.as_ref() else {
        return refused("Package firewall setup is unavailable.");
    };
    match issue(&portal, signed_in.login_id, org, firewall).await {
        Ok(Some(bundle)) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "application/x-sh; charset=utf-8"),
                (
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=probation-setup.sh",
                ),
            ],
            bundle,
        )
            .into_response(),
        Ok(None) => not_found(),
        Err(IssueError::Store(err)) => unavailable(err),
        Err(IssueError::Crypto) => {
            tracing::error!("certificate issuance failed");
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    }
}

async fn self_service(pool: &sqlx::PgPool, org: i32) -> Result<bool, sqlx::Error> {
    let setting: Option<(String, bool)> = sqlx::query_as(
        "SELECT kind, self_service FROM registry_certificate_providers WHERE org_id = $1",
    )
    .bind(org)
    .fetch_optional(pool)
    .await?;
    Ok(setting.is_none_or(|(kind, enabled)| kind == "probation" && enabled))
}

enum IssueError {
    Store(sqlx::Error),
    Crypto,
}

impl From<sqlx::Error> for IssueError {
    fn from(value: sqlx::Error) -> Self {
        Self::Store(value)
    }
}

async fn issue(
    portal: &super::Portal,
    login: i32,
    org: i32,
    firewall: &url::Url,
) -> Result<Option<String>, IssueError> {
    let mut tx = portal.pool.begin().await?;
    let member: Option<(i32, String)> = sqlx::query_as(
        "SELECT m.id, m.certificate_uuid::text FROM memberships AS m
         JOIN orgs AS o ON o.id = m.org_id JOIN logins AS l ON l.id = m.login_id
         WHERE m.login_id = $1 AND m.org_id = $2 AND m.package_access_disabled_at IS NULL
           AND o.status = 'active' AND o.deleted_at IS NULL AND l.deleted_at IS NULL
         FOR UPDATE OF m",
    )
    .bind(login)
    .bind(org)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((member_id, member_uuid)) = member else {
        return Ok(None);
    };
    sqlx::query(
        "INSERT INTO registry_certificate_providers (org_id) VALUES ($1) ON CONFLICT DO NOTHING",
    )
    .bind(org)
    .execute(&mut *tx)
    .await?;
    #[allow(clippy::type_complexity)]
    let (kind, enabled, key_enc, root_pem, root_fingerprint): (
        String,
        bool,
        Option<Vec<u8>>,
        Option<String>,
        Option<Vec<u8>>,
    ) = sqlx::query_as(
        "SELECT kind, self_service, issuer_key_enc, issuer_cert_pem, issuer_fingerprint
         FROM registry_certificate_providers WHERE org_id = $1 FOR UPDATE",
    )
    .bind(org)
    .fetch_one(&mut *tx)
    .await?;
    if kind != "probation" || !enabled {
        return Ok(None);
    }
    let registry_id: Option<i64> = sqlx::query_scalar(
        "SELECT (SELECT id FROM registries WHERE org_id = $1 AND ecosystem = 'npm' AND removed_at IS NULL ORDER BY id LIMIT 1)",
    ).bind(org).fetch_one(&mut *tx).await?;

    let pypi_registry_id: Option<i64> = sqlx::query_scalar(
        "SELECT (SELECT id FROM registries WHERE org_id = $1 AND ecosystem = 'pypi' AND removed_at IS NULL ORDER BY id LIMIT 1)",
    ).bind(org).fetch_one(&mut *tx).await?;

    let aad = format!("registry issuer org {org}");
    let (issuer_key, issuer_pem, issuer_fingerprint) = match (key_enc, root_pem, root_fingerprint) {
        (Some(sealed), Some(pem), Some(fingerprint)) => {
            let plain = portal
                .secrets
                .open(&aad, &sealed)
                .ok_or(IssueError::Crypto)?;
            (
                String::from_utf8(plain).map_err(|_| IssueError::Crypto)?,
                pem,
                fingerprint,
            )
        }
        (None, None, None) => {
            let key = KeyPair::generate().map_err(|_| IssueError::Crypto)?;
            let mut params = CertificateParams::default();
            params.distinguished_name.push(
                rcgen::DnType::CommonName,
                format!("Probation org {org} client CA"),
            );
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            params.not_before = OffsetDateTime::now_utc() - Duration::days(1);
            params.not_after = OffsetDateTime::now_utc() + Duration::days(3650);
            let cert = params.self_signed(&key).map_err(|_| IssueError::Crypto)?;
            let pem = cert.pem();
            let fingerprint = Sha256::digest(cert.der()).to_vec();
            let key_pem = key.serialize_pem();
            sqlx::query("UPDATE registry_certificate_providers SET issuer_key_enc = $2, issuer_cert_pem = $3, issuer_fingerprint = $4 WHERE org_id = $1")
                .bind(org).bind(portal.secrets.seal(&aad, key_pem.as_bytes())).bind(&pem).bind(&fingerprint)
                .execute(&mut *tx).await?;
            sqlx::query("INSERT INTO registry_certificate_roots (org_id, fingerprint, certificate_pem) VALUES ($1, $2, $3)")
                .bind(org).bind(&fingerprint).bind(&pem).execute(&mut *tx).await?;
            (key_pem, pem, fingerprint)
        }
        _ => return Err(IssueError::Crypto),
    };

    let signing_key = KeyPair::from_pem(&issuer_key).map_err(|_| IssueError::Crypto)?;
    let issuer =
        Issuer::from_ca_cert_pem(&issuer_pem, signing_key).map_err(|_| IssueError::Crypto)?;
    let client_key = KeyPair::generate().map_err(|_| IssueError::Crypto)?;
    let serial = serial_bytes().map_err(|_| IssueError::Crypto)?;
    let mut params = CertificateParams::default();
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        format!("Probation member {member_uuid}"),
    );
    params.subject_alt_names = vec![SanType::URI(
        format!("urn:probation:member:{member_uuid}")
            .try_into()
            .map_err(|_| IssueError::Crypto)?,
    )];
    params.serial_number = Some(SerialNumber::from(serial.to_vec()));
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    params.not_before = OffsetDateTime::now_utc() - Duration::minutes(5);
    params.not_after = OffsetDateTime::now_utc() + Duration::days(365);
    let cert = params
        .signed_by(&client_key, &issuer)
        .map_err(|_| IssueError::Crypto)?;
    let leaf_fingerprint = Sha256::digest(cert.der()).to_vec();
    sqlx::query("INSERT INTO registry_member_certificates (org_id, membership_id, issuer_fingerprint, leaf_fingerprint, serial, expires_at)
                 VALUES ($1, $2, $3, $4, $5, now() + interval '365 days')")
        .bind(org).bind(member_id).bind(issuer_fingerprint).bind(leaf_fingerprint).bind(serial.as_slice())
        .execute(&mut *tx).await?;
    tx.commit().await?;
    let npm_url = registry_id.map(|id| firewall.join(&format!("registry/npm/{id}/")))
        .transpose().map_err(|_| IssueError::Crypto)?;
    let pypi_url = pypi_registry_id.map(|id| firewall.join(&format!("registry/pypi/{id}/")))
        .transpose().map_err(|_| IssueError::Crypto)?;
    Ok(Some(render_bundle(
        npm_url.as_ref(),
        pypi_url.as_ref(),
        &cert.pem(),
        &issuer_pem,
        &client_key.serialize_pem(),
    )))
}

fn serial_bytes() -> Result<[u8; 16], getrandom::Error> {
    let mut serial = [0u8; 16];
    getrandom::fill(&mut serial)?;
    // DER INTEGER prepends 00 for a high bit and drops a leading zero. Keep the
    // stored bytes identical to the certificate's canonical serial representation.
    serial[0] = (serial[0] & 0x7f) | 1;
    Ok(serial)
}

fn render_bundle(npm_url: Option<&url::Url>, pypi_url: Option<&url::Url>, cert: &str, ca: &str, key: &str) -> String {
    let npm = npm_url.map(|url| {
        let authority = url.host_str().expect("firewall URL host");
        let scope = format!("//{authority}{}/", url.path().trim_end_matches('/'));
        format!("cat >>\"$HOME/.npmrc\" <<'PROBATION_NPM'\nregistry={url}\n{scope}:certfile=${{HOME}}/.config/probation/client-cert.pem\n{scope}:keyfile=${{HOME}}/.config/probation/client-key.pem\nPROBATION_NPM\n")
    }).unwrap_or_default();
    let python = pypi_url.map(|url| format!(r#"cat "$base/client-cert.pem" "$base/client-key.pem" >"$base/client.pem"
mkdir -p "$HOME/.config/pip" "$HOME/.config/uv"
cat >"$HOME/.config/pip/pip.conf" <<PROBATION_PIP
[global]
index-url = {url}simple/
client-cert = $base/client.pem
PROBATION_PIP
cat >"$HOME/.config/uv/uv.toml" <<'PROBATION_UV'
index-url = "{url}simple/"
PROBATION_UV
cat >"$HOME/.pypirc" <<PROBATION_TWINE
[distutils]
index-servers = probation
[probation]
repository = {url}
client_cert = $base/client.pem
PROBATION_TWINE
cat >"$base/python-env.sh" <<'PROBATION_PYTHON'
export PIP_INDEX_URL={url}simple/
export PIP_CLIENT_CERT=$HOME/.config/probation/client.pem
export SSL_CLIENT_CERT=$HOME/.config/probation/client.pem
export UV_DEFAULT_INDEX={url}simple/
export TWINE_REPOSITORY=probation
PROBATION_PYTHON
if ! grep -Fq 'probation/python-env.sh' "$HOME/.profile" 2>/dev/null; then
    printf '%s\n' '. "$HOME/.config/probation/python-env.sh"' >>"$HOME/.profile"
fi
"#)).unwrap_or_default();
    format!(
        "#!/bin/sh\nset -eu\numask 077\nbase=\"$HOME/.config/probation\"\nmkdir -p \"$base\"\ncat >\"$base/client-cert.pem\" <<'PROBATION_CERT'\n{cert}PROBATION_CERT\ncat >\"$base/client-key.pem\" <<'PROBATION_KEY'\n{key}PROBATION_KEY\ncat >\"$base/issuer.pem\" <<'PROBATION_CA'\n{ca}PROBATION_CA\n{npm}{python}"
    )
}

#[cfg(test)]
mod enterprise_settings_tests {
    use super::validate_identity_field;

    #[test]
    fn identity_field_rejects_alternate_selectors() {
        assert!(validate_identity_field("uri_san_membership_uuid").is_ok());
        for field in ["subject_cn", "email_san", "dns_san", "uri_san"] {
            assert!(validate_identity_field(field).is_err(), "accepted {field}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_bundle_keeps_key_in_user_local_config() {
        let npm = url::Url::parse("https://fw.test/registry/npm/7/").unwrap();
        let pypi = url::Url::parse("https://fw.test/registry/pypi/9/").unwrap();
        let bundle = render_bundle(Some(&npm), Some(&pypi), "CERT\n", "CA\n", "KEY\n");
        assert!(bundle.contains("PIP_INDEX_URL=https://fw.test/registry/pypi/9/simple/"));
        assert!(bundle.contains("index-url = \"https://fw.test/registry/pypi/9/simple/\""));
        assert!(!bundle.contains("TWINE_REPOSITORY_URL="));
        assert!(bundle.contains("TWINE_REPOSITORY=probation"));
        assert!(bundle.contains("client_cert = $base/client.pem"));
        assert!(bundle.contains("SSL_CLIENT_CERT=$HOME/.config/probation/client.pem"));
        assert!(!bundle.contains("TWINE_PASSWORD="));
    }

    #[test]
    fn pypi_only_bundle_does_not_require_an_npm_registry() {
        let pypi = url::Url::parse("https://fw.test/registry/pypi/9/").unwrap();
        let bundle = render_bundle(None, Some(&pypi), "CERT\n", "CA\n", "KEY\n");
        assert!(bundle.contains("index-url = https://fw.test/registry/pypi/9/simple/"));
        assert!(!bundle.contains("registry=https://"));
        assert!(!bundle.contains("PROBATION_NPM"));
    }

    #[test]
    fn generated_serials_have_one_canonical_der_representation() {
        for _ in 0..1000 {
            let serial = serial_bytes().expect("random serial");
            assert!((1..=127).contains(&serial[0]));
        }
    }

    #[test]
    fn issued_certificate_serial_matches_stored_bytes() {
        let ca_key = KeyPair::generate().expect("CA key");
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_key).expect("CA certificate");
        let issuer = Issuer::from_ca_cert_pem(&ca.pem(), ca_key).expect("issuer");
        for _ in 0..64 {
            let serial = serial_bytes().expect("serial");
            let key = KeyPair::generate().expect("client key");
            let mut params = CertificateParams::default();
            params.serial_number = Some(SerialNumber::from(serial.to_vec()));
            let cert = params.signed_by(&key, &issuer).expect("client certificate");
            let (_, parsed) = x509_parser::parse_x509_certificate(cert.der()).expect("DER");
            assert_eq!(parsed.raw_serial(), serial.as_slice());
        }
    }
}
