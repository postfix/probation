//! One-request npm packument read with a developer token.

use axum::http::{HeaderMap, Method, header};

use crate::App;
use crate::http::error::ApiError;
use crate::http::unpublish_reference;
use crate::managed::Principal;
use crate::npm::{self, PackageName};
use crate::upstream::{MetadataRequest, MetadataResponse, OriginKind, OriginSet, UpstreamError};

pub struct TokenPackumentRequest<'a> {
    pub method: &'a Method,
    pub query: Option<&'a str>,
    pub headers: &'a HeaderMap,
    pub name: &'a PackageName,
}

fn check_canonical_token_packument<'a>(
    request: &'a TokenPackumentRequest<'_>,
) -> Result<&'a str, ApiError> {
    if request.method != Method::GET || request.query.is_some_and(|query| query != "write=true") {
        return Err(ApiError::NotFound);
    }
    let token = request
        .headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or(ApiError::Unauthenticated)?;
    if !token.starts_with("Bearer ") || token.len() <= "Bearer ".len() {
        return Err(ApiError::Unauthenticated);
    }
    Ok(token)
}

pub async fn serve_token_packument(
    app: &App,
    principal: &Principal,
    registry: u64,
    request: TokenPackumentRequest<'_>,
) -> Result<npm::Rendered, ApiError> {
    let route = check_canonical_token_packument(&request)?;
    send_selected_upstream_packument(app, principal, registry, request.name, request.query, route)
        .await
}

async fn send_selected_upstream_packument(
    app: &App,
    principal: &Principal,
    registry: u64,
    name: &PackageName,
    query: Option<&str>,
    authorization: &str,
) -> Result<npm::Rendered, ApiError> {
    let origin = principal
        .registry_origin
        .as_ref()
        .unwrap_or_else(|| app.origins.origin(OriginKind::NpmMetadata));
    let origins = OriginSet::selected_npm_with_private(
        origin.clone(),
        principal.registry_private_cidrs.clone(),
    )
    .map_err(|_| ApiError::NotFound)?;
    let mut url = origins
        .url_for(OriginKind::NpmMetadata, &[name.upstream_segment()])
        .map_err(|_| ApiError::NotFound)?;
    url.set_query(query);
    let result = app
        .transport
        .fetch_token_packument(
            MetadataRequest {
                url,
                origin: Some(origin.clone()),
                private_cidrs: principal.registry_private_cidrs.clone(),
                read_authorization: None,
                accept: "application/json",
                validators: None,
                max_bytes: app.config.max_metadata_bytes.get(),
            },
            authorization,
        )
        .await;
    let body = match result {
        Ok(MetadataResponse::Fresh { body, .. }) => body,
        Ok(MetadataResponse::Missing) => return Err(ApiError::NotFound),
        Err(UpstreamError::Status(401)) => return Err(ApiError::Unauthenticated),
        Err(UpstreamError::Status(403)) => {
            return Err(ApiError::Blocked {
                reason: "the upstream registry denied this token",
            });
        }
        Err(UpstreamError::Timeout) => return Err(ApiError::UpstreamTimeout),
        Err(err) => {
            tracing::warn!(error = %err, "token packument read failed");
            return Err(ApiError::UpstreamFailure);
        }
        Ok(MetadataResponse::NotModified { .. }) => return Err(ApiError::UpstreamInvalid),
    };
    let document =
        npm::document::PackageDocument::parse(&body).map_err(|_| ApiError::UpstreamInvalid)?;
    if document.name != name.as_str() {
        return Err(ApiError::UpstreamInvalid);
    }
    let entries = document
        .entries_in_registry(registry, app.config.max_references_per_project.get())
        .map_err(|_| ApiError::UpstreamInvalid)?;
    if query == Some("write=true") && entries.len() != document.versions.len() {
        return Err(ApiError::UpstreamInvalid);
    }
    let kept = entries.iter().collect::<Vec<_>>();
    let mut public_url = app.config.public_url.clone();
    public_url.set_path(&format!("/registry/npm/{registry}/"));
    let mut rendered: serde_json::Value = serde_json::from_slice(&npm::render::full(
        &document,
        &kept,
        &document.dist_tags,
        &public_url,
    ))
    .map_err(|_| ApiError::UpstreamInvalid)?;
    for entry in &entries {
        if query == Some("write=true") { continue; }
        let segments: Vec<_> = name
            .as_str()
            .split('/')
            .chain(["-", entry.reference.filename.as_str()])
            .collect();
        let canonical = origins
            .url_for(OriginKind::NpmMetadata, &segments)
            .map_err(|_| ApiError::UpstreamInvalid)?;
        if entry.reference.upstream_url != canonical {
            continue;
        }
        let mut local = app.config.public_url.clone();
        local
            .path_segments_mut()
            .map_err(|_| ApiError::UpstreamInvalid)?
            .push("registry")
            .push("npm")
            .push(&registry.to_string())
            .push(name.as_str())
            .push("-")
            .push(&entry.reference.filename);
        rendered["versions"][entry.version()]["dist"]["tarball"] = local.to_string().into();
    }
    let rendered = serde_json::to_vec(&rendered).map_err(|_| ApiError::UpstreamInvalid)?;
    if rendered.len() as u64 > app.config.max_metadata_bytes.get() { return Err(ApiError::UpstreamInvalid); }
    if query == Some("write=true") {
        unpublish_reference::prepare_leases(app, principal, registry, name.as_str(), &entries).await?;
    }
    Ok(npm::Rendered {
        body: rendered.into(),
        content_type: "application/json",
    })
}
