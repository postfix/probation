//! Explicit read-only npm routes under a selected certificate registry.

use std::sync::Arc;
use std::time::Duration;

use axum::Extension;
use axum::body::{Body, to_bytes};
use axum::extract::{Path, RawQuery, State};
use axum::http::{HeaderMap, Method, header};
use axum::response::{IntoResponse, Response};
use probation_policy::api::RegistryId;
use tokio::sync::OwnedSemaphorePermit;

use crate::App;
use crate::artifacts;
use crate::http::error::ApiError;
use crate::http::{audit_filter, npm_routes, registry_action, registry_read, token_packument, unpublish_reference};
use crate::managed::Principal;
use crate::managed::certificates::VerifiedPeer;
use crate::npm;
use crate::policy::Ecosystem;
use crate::store::cache::Representation;
use crate::store::rows::ReferenceId;
use crate::upstream::{NamedReadRequest, OriginKind, OriginSet, UpstreamError};

pub async fn package(
    State(app): State<Arc<App>>,
    peer: Option<Extension<VerifiedPeer>>,
    method: Method,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
    Path((registry, package)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let registry = registry_read::registry_id(&registry)?;
    if package == "-" {
        return Err(ApiError::NotFound);
    }
    let (permit, principal) = registry_read::admit(&app, peer.clone(), registry, &headers).await?;
    let name = npm_routes::parse_name(&package)?;
    let representation = npm_routes::negotiate(&headers);
    let rendered = if headers.contains_key(header::AUTHORIZATION) {
        token_packument::serve_token_packument(
            &app,
            &principal,
            registry.0,
            token_packument::TokenPackumentRequest {
                method: &method,
                query: query.as_deref(),
                headers: &headers,
                name: &name,
            },
        )
        .await?
    } else {
        if query.is_some() || method != Method::GET {
            return Err(ApiError::NotFound);
        }
        npm::serve_registry(&app, &principal, &name, representation, registry.0).await?
    };
    let current = registry_read::recheck(&app, peer, registry, &headers).await?;
    if current.policy.policy.fingerprint != principal.policy.policy.fingerprint
        || current.registry_trusted != principal.registry_trusted
        || current.registry_origin != principal.registry_origin
        || current.registry_private_cidrs != principal.registry_private_cidrs
        || current.registry_read_authorization != principal.registry_read_authorization
        || current.deletion_scopes != principal.deletion_scopes
    {
        return Err(ApiError::PolicyUnavailable);
    }
    drop(permit);
    Ok(npm_routes::respond(rendered))
}

pub async fn version(
    State(app): State<Arc<App>>,
    peer: Option<Extension<VerifiedPeer>>,
    headers: HeaderMap,
    Path((registry, package, version)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let registry = registry_read::registry_id(&registry)?;
    if package == "-" {
        return Err(ApiError::NotFound);
    }
    let (permit, principal) = registry_read::admit(&app, peer.clone(), registry, &headers).await?;
    let (name, representation) = if package.starts_with('@') && !package.contains('/') {
        (
            npm_routes::parse_name(&format!("{package}/{version}"))?,
            Representation::NpmFull,
        )
    } else {
        (
            npm_routes::parse_name(&package)?,
            Representation::NpmVersion(version),
        )
    };
    let rendered = npm::serve_registry(&app, &principal, &name, representation, registry.0).await?;
    let current = registry_read::recheck(&app, peer, registry, &headers).await?;
    if current.policy.policy.fingerprint != principal.policy.policy.fingerprint
        || current.registry_trusted != principal.registry_trusted
        || current.registry_origin != principal.registry_origin
        || current.registry_private_cidrs != principal.registry_private_cidrs
        || current.registry_read_authorization != principal.registry_read_authorization
        || current.deletion_scopes != principal.deletion_scopes
    {
        return Err(ApiError::PolicyUnavailable);
    }
    drop(permit);
    Ok(npm_routes::respond(rendered))
}

pub async fn artifact(
    State(app): State<Arc<App>>,
    peer: Option<Extension<VerifiedPeer>>,
    method: Method,
    headers: HeaderMap,
    Path((registry, reference, filename)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let registry = registry_read::registry_id(&registry)?;
    let (permit, principal) = registry_read::admit(&app, peer.clone(), registry, &headers).await?;
    let id = ReferenceId::parse_hex(&reference)
        .map_err(|_| ApiError::InvalidInput("a reference id is 64 hexadecimal characters"))?;
    serve_admitted_artifact(
        app, peer, method, headers, registry, permit, principal, id, filename,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn serve_admitted_artifact(
    app: Arc<App>,
    peer: Option<Extension<VerifiedPeer>>,
    method: Method,
    headers: HeaderMap,
    registry: RegistryId,
    permit: OwnedSemaphorePermit,
    principal: Principal,
    id: ReferenceId,
    filename: String,
) -> Result<Response, ApiError> {
    let range = headers
        .get(header::RANGE)
        .and_then(|value| value.to_str().ok());
    let response = artifacts::serve_artifact_in(
        &app,
        Some(&principal),
        Ecosystem::Npm,
        registry.0,
        id,
        &filename,
        &method,
        range,
    )
    .await?;
    // The transfer may have taken time. Refetch status after all artifact I/O and
    // before committing bytes. A changed policy cannot authorize the prepared file.
    let current = registry_read::recheck(&app, peer, registry, &headers).await?;
    if current.policy.policy.fingerprint != principal.policy.policy.fingerprint
        || current.registry_trusted != principal.registry_trusted
        || current.registry_origin != principal.registry_origin
        || current.registry_private_cidrs != principal.registry_private_cidrs
        || current.registry_read_authorization != principal.registry_read_authorization
        || current.deletion_scopes != principal.deletion_scopes
    {
        return Err(ApiError::PolicyUnavailable);
    }
    Ok(response.under(&app.limits, permit).into_response())
}

enum NamedRead {
    Search,
    AuditBulk,
    AuditQuick,
    Whoami,
    Ping,
}

pub async fn search(
    State(app): State<Arc<App>>,
    peer: Option<Extension<VerifiedPeer>>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
    Path(registry): Path<String>,
) -> Result<Response, ApiError> {
    named_read(
        app,
        peer,
        headers,
        registry,
        query,
        Body::empty(),
        NamedRead::Search,
    )
    .await
}

pub async fn audit_bulk(
    State(app): State<Arc<App>>,
    peer: Option<Extension<VerifiedPeer>>,
    headers: HeaderMap,
    Path(registry): Path<String>,
    body: Body,
) -> Result<Response, ApiError> {
    named_read(
        app,
        peer,
        headers,
        registry,
        None,
        body,
        NamedRead::AuditBulk,
    )
    .await
}

pub async fn audit_quick(
    State(app): State<Arc<App>>,
    peer: Option<Extension<VerifiedPeer>>,
    headers: HeaderMap,
    Path(registry): Path<String>,
    body: Body,
) -> Result<Response, ApiError> {
    named_read(
        app,
        peer,
        headers,
        registry,
        None,
        body,
        NamedRead::AuditQuick,
    )
    .await
}

pub async fn whoami(
    State(app): State<Arc<App>>,
    peer: Option<Extension<VerifiedPeer>>,
    headers: HeaderMap,
    Path(registry): Path<String>,
) -> Result<Response, ApiError> {
    named_read(
        app,
        peer,
        headers,
        registry,
        None,
        Body::empty(),
        NamedRead::Whoami,
    )
    .await
}

pub async fn ping(
    State(app): State<Arc<App>>,
    peer: Option<Extension<VerifiedPeer>>,
    headers: HeaderMap,
    Path(registry): Path<String>,
) -> Result<Response, ApiError> {
    named_read(
        app,
        peer,
        headers,
        registry,
        None,
        Body::empty(),
        NamedRead::Ping,
    )
    .await
}

pub async fn action(
    State(app): State<Arc<App>>,
    peer: Option<Extension<VerifiedPeer>>,
    method: Method,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
    Path((registry, rest)): Path<(String, String)>,
    body: Body,
) -> Result<Response, ApiError> {
    forward_action(
        app,
        peer,
        method,
        headers,
        query,
        registry,
        format!("-/{}", rest.trim_start_matches('/')),
        body,
    )
    .await
}

pub async fn package_action(
    State(app): State<Arc<App>>,
    peer: Option<Extension<VerifiedPeer>>,
    method: Method,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
    Path((registry, package)): Path<(String, String)>,
    body: Body,
) -> Result<Response, ApiError> {
    if method != Method::PUT || package == "-" {
        return Err(ApiError::NotFound);
    }
    let name = npm_routes::parse_name(&package)?;
    forward_action(
        app,
        peer,
        method,
        headers,
        query,
        registry,
        name.as_str().to_owned(),
        body,
    )
    .await
}

pub async fn revision_action(
    State(app): State<Arc<App>>,
    peer: Option<Extension<VerifiedPeer>>,
    method: Method,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
    Path((registry, package, revision)): Path<(String, String, String)>,
    body: Body,
) -> Result<Response, ApiError> {
    if !matches!(method, Method::PUT | Method::DELETE)
        || revision.is_empty()
        || revision.len() > 100
    {
        return Err(ApiError::NotFound);
    }
    let name = npm_routes::parse_name(&package)?;
    forward_action(
        app,
        peer,
        method,
        headers,
        query,
        registry,
        format!("{}/-rev/{revision}", name.as_str()),
        body,
    )
    .await
}

pub async fn package_tarball(
    State(app): State<Arc<App>>,
    peer: Option<Extension<VerifiedPeer>>,
    method: Method,
    headers: HeaderMap,
    Path((registry, package, filename)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let id = registry_read::registry_id(&registry)?;
    let (permit, principal) = registry_read::admit(&app, peer.clone(), id, &headers).await?;
    let name = npm_routes::parse_name(&package)?;
    let advertised = npm::ensure_fresh_project_at(
        &app,
        name.as_str(),
        id.0,
        principal.registry_origin.as_ref(),
        &principal.registry_private_cidrs,
        principal.registry_read_authorization.as_deref(),
    )
    .await?;
    let reference = advertised
        .by_filename(&filename)
        .ok_or(ApiError::NotFound)?;
    serve_admitted_artifact(
        app, peer, method, headers, id, permit, principal, reference, filename,
    )
    .await
}

pub async fn package_tarball_delete() -> Result<Response, ApiError> {
    Err(ApiError::NotFound)
}

pub async fn unsupported_artifact_delete(
    State(app): State<Arc<App>>,
    peer: Option<Extension<VerifiedPeer>>,
    headers: HeaderMap,
    Path((registry, reference, filename, revision)): Path<(String, String, String, String)>,
) -> Result<Response, ApiError> {
    let registry = registry_read::registry_id(&registry)?;
    let id = ReferenceId::parse_hex(&reference).map_err(|_| ApiError::NotFound)?;
    let authorization = headers.get(header::AUTHORIZATION).and_then(|value| value.to_str().ok())
        .filter(|value| value.starts_with("Bearer ") && value.len() > 7).ok_or(ApiError::Unauthenticated)?.to_owned();
    let (permit, principal) = registry_read::admit(&app, peer.clone(), registry, &headers).await?;
    let response = unpublish_reference::send_unpublish_delete(&app, &principal, registry.0, id, &filename, &revision, authorization).await?;
    let current = registry_read::recheck(&app, peer, registry, &headers).await?;
    if current.registry_origin != principal.registry_origin || current.deletion_scopes != principal.deletion_scopes {
        return Err(ApiError::PolicyUnavailable);
    }
    drop(permit);
    Ok(response)
}

#[allow(clippy::too_many_arguments)]
async fn forward_action(
    app: Arc<App>,
    peer: Option<Extension<VerifiedPeer>>,
    method: Method,
    headers: HeaderMap,
    query: Option<String>,
    registry: String,
    path: String,
    body: Body,
) -> Result<Response, ApiError> {
    let registry = registry_read::registry_id(&registry)?;
    let (permit, principal) = registry_read::admit(&app, peer.clone(), registry, &headers).await?;
    let response = registry_action::forward_registry_action(
        &app,
        &principal,
        registry_action::RegistryActionRequest {
            selected_registry: registry.0,
            selected_base: format!("/registry/npm/{}/", registry.0),
            method,
            path,
            query,
            headers: headers.clone(),
            body,
        },
    )
    .await?;
    let current = registry_read::recheck(&app, peer, registry, &headers).await?;
    if current.policy.policy.fingerprint != principal.policy.policy.fingerprint
        || current.registry_trusted != principal.registry_trusted
        || current.registry_origin != principal.registry_origin
        || current.registry_private_cidrs != principal.registry_private_cidrs
        || current.registry_read_authorization != principal.registry_read_authorization
        || current.deletion_scopes != principal.deletion_scopes
    {
        return Err(ApiError::PolicyUnavailable);
    }
    drop(permit);
    Ok(response)
}

async fn named_read(
    app: Arc<App>,
    peer: Option<Extension<VerifiedPeer>>,
    headers: HeaderMap,
    registry: String,
    query: Option<String>,
    body: Body,
    kind: NamedRead,
) -> Result<Response, ApiError> {
    let registry = registry_read::registry_id(&registry)?;
    let (permit, principal) = registry_read::admit(&app, peer.clone(), registry, &headers).await?;
    let answer = tokio::time::timeout(Duration::from_secs(30), async {
        let origin = principal
            .registry_origin
            .as_ref()
            .unwrap_or_else(|| app.origins.origin(OriginKind::NpmMetadata));
        let origins = OriginSet::selected_npm_with_private(
            origin.clone(),
            principal.registry_private_cidrs.clone(),
        )
        .map_err(|_| ApiError::NotFound)?;
        let segments: &[&str] = match kind {
            NamedRead::Search => &["-", "v1", "search"],
            NamedRead::AuditBulk => &["-", "npm", "v1", "security", "advisories", "bulk"],
            NamedRead::AuditQuick => &["-", "npm", "v1", "security", "audits", "quick"],
            NamedRead::Whoami => &["-", "whoami"],
            NamedRead::Ping => &["-", "ping"],
        };
        let mut url = origins
            .url_for(OriginKind::NpmMetadata, segments)
            .map_err(|_| ApiError::NotFound)?;
        if matches!(kind, NamedRead::Search) {
            url.set_query(query.as_deref());
        }
        let authorization = if matches!(kind, NamedRead::Whoami) {
            let value = headers
                .get(header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .ok_or(ApiError::Unauthenticated)?;
            if !value.starts_with("Bearer ") || value.len() <= 7 {
                return Err(ApiError::Unauthenticated);
            }
            Some(value.to_owned())
        } else {
            principal.registry_read_authorization.clone()
        };
        let payload = to_bytes(body, app.config.max_metadata_bytes.get() as usize)
            .await
            .map_err(|_| ApiError::InvalidInput("audit request is too large"))?;
        let method = if matches!(kind, NamedRead::AuditBulk | NamedRead::AuditQuick) {
            Method::POST
        } else {
            Method::GET
        };
        let content_encoding = match headers.get(header::CONTENT_ENCODING) {
            None => None,
            Some(value)
                if method == Method::POST && value.as_bytes().eq_ignore_ascii_case(b"gzip") =>
            {
                Some("gzip")
            }
            Some(_) => return Err(ApiError::InvalidInput("unsupported content encoding")),
        };
        let fetched = app
            .transport
            .fetch_named_read(NamedReadRequest {
                url,
                origin: origin.clone(),
                private_cidrs: principal.registry_private_cidrs.clone(),
                method,
                authorization,
                content_encoding,
                body: payload,
                max_bytes: app.config.max_metadata_bytes.get(),
            })
            .await;
        let bytes = match fetched {
            Ok(bytes) => bytes,
            Err(UpstreamError::Status(401)) => return Err(ApiError::Unauthenticated),
            Err(UpstreamError::Status(403)) => {
                return Err(ApiError::Blocked {
                    reason: "the upstream registry denied this read",
                });
            }
            Err(UpstreamError::Status(404)) => return Err(ApiError::NotFound),
            Err(UpstreamError::Timeout) => return Err(ApiError::UpstreamTimeout),
            Err(err) => {
                tracing::warn!(error = %err, "named npm read failed");
                return Err(ApiError::UpstreamFailure);
            }
        };
        let bytes = if matches!(kind, NamedRead::AuditBulk | NamedRead::AuditQuick) {
            let audit_kind = if matches!(kind, NamedRead::AuditBulk) {
                audit_filter::AuditKind::Bulk
            } else {
                audit_filter::AuditKind::Quick
            };
            audit_filter::filter_audit_response(
                &app,
                &principal,
                registry.0,
                audit_kind,
                &bytes,
                app.config.max_metadata_bytes.get() as usize,
            )
            .await?
            .into()
        } else if matches!(kind, NamedRead::Search) {
            let result: serde_json::Value =
                serde_json::from_slice(&bytes).map_err(|_| ApiError::UpstreamInvalid)?;
            let objects = result
                .get("objects")
                .and_then(serde_json::Value::as_array)
                .ok_or(ApiError::UpstreamInvalid)?;
            if objects.len() > 250 {
                return Err(ApiError::UpstreamInvalid);
            }
            let mut kept = Vec::new();
            let mut kept_bytes = 0usize;
            for item in objects {
                let Some(name) = item
                    .get("package")
                    .and_then(|p| p.get("name"))
                    .and_then(serde_json::Value::as_str)
                else {
                    continue;
                };
                let Some(advertised) = item
                    .get("package")
                    .and_then(|p| p.get("version"))
                    .and_then(serde_json::Value::as_str)
                else {
                    continue;
                };
                let Ok(name) = npm_routes::parse_name(name) else {
                    continue;
                };
                let Ok(rendered) = npm::serve_registry(
                    &app,
                    &principal,
                    &name,
                    Representation::NpmFull,
                    registry.0,
                )
                .await
                else {
                    continue;
                };
                let filtered: serde_json::Value = serde_json::from_slice(&rendered.body)
                    .map_err(|_| ApiError::UpstreamInvalid)?;
                let Some(version) = filtered
                    .get("versions")
                    .and_then(|versions| versions.get(advertised))
                else {
                    continue;
                };
                let mut package = serde_json::Map::new();
                package.insert("name".to_owned(), serde_json::Value::from(name.as_str()));
                package.insert("version".to_owned(), serde_json::Value::from(advertised));
                package.insert(
                    "description".to_owned(),
                    version
                        .get("description")
                        .filter(|value| value.is_string())
                        .cloned()
                        .unwrap_or_else(|| serde_json::Value::from("")),
                );
                package.insert(
                    "keywords".to_owned(),
                    version
                        .get("keywords")
                        .filter(|value| value.is_array())
                        .cloned()
                        .unwrap_or_else(|| serde_json::Value::Array(Vec::new())),
                );
                package.insert(
                    "maintainers".to_owned(),
                    version
                        .get("maintainers")
                        .filter(|value| value.is_array())
                        .cloned()
                        .unwrap_or_else(|| serde_json::Value::Array(Vec::new())),
                );
                let hit = serde_json::json!({ "package": package });
                let hit_bytes = serde_json::to_vec(&hit)
                    .map_err(|_| ApiError::UpstreamInvalid)?
                    .len();
                let next_count = kept.len() + 1;
                let envelope_bytes =
                    serde_json::to_vec(&serde_json::json!({ "objects": [], "total": next_count }))
                        .map_err(|_| ApiError::UpstreamInvalid)?
                        .len();
                kept_bytes = kept_bytes
                    .checked_add(hit_bytes)
                    .and_then(|n| n.checked_add(usize::from(!kept.is_empty())))
                    .ok_or(ApiError::UpstreamInvalid)?;
                if kept_bytes
                    .checked_add(envelope_bytes)
                    .ok_or(ApiError::UpstreamInvalid)?
                    > app.config.max_metadata_bytes.get() as usize
                {
                    return Err(ApiError::UpstreamInvalid);
                }
                kept.push(hit);
            }
            let visible = kept.len();
            let response =
                serde_json::to_vec(&serde_json::json!({ "objects": kept, "total": visible }))
                    .map_err(|_| ApiError::UpstreamInvalid)?;
            if response.len() > app.config.max_metadata_bytes.get() as usize {
                return Err(ApiError::UpstreamInvalid);
            }
            response.into()
        } else {
            bytes
        };
        let current = registry_read::recheck(&app, peer, registry, &headers).await?;
        if current.policy.policy.fingerprint != principal.policy.policy.fingerprint
            || current.registry_trusted != principal.registry_trusted
            || current.registry_origin != principal.registry_origin
            || current.registry_private_cidrs != principal.registry_private_cidrs
            || current.registry_read_authorization != principal.registry_read_authorization
        || current.deletion_scopes != principal.deletion_scopes
        {
            return Err(ApiError::PolicyUnavailable);
        }
        let mut response = bytes.to_vec().into_response();
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json"),
        );
        Ok(response)
    })
    .await;
    drop(permit);
    answer.map_err(|_| ApiError::UpstreamTimeout)?
}
