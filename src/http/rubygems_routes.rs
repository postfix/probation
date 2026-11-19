//! The RubyGems endpoint group. Handlers admit, delegate to `rubygems::serve` and map
//! errors only. Standalone and certificate-managed callers use `/rubygems/...`; a shared
//! service's selected registry is `/registry/rubygems/{registry}/...` (the shared-service
//! middleware rewrites `/rubygems/...` into it).

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, Method, header};
use axum::response::{IntoResponse, Response};

use crate::App;
use crate::http::error::ApiError;
use crate::managed::certificates::VerifiedPeer;
use crate::rubygems::serve::{self, Rendered};
use crate::store::rows::ReferenceId;

fn respond(rendered: Rendered) -> Response {
    let mut response = rendered.body.to_vec().into_response();
    response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static(rendered.content_type));
    response
}

#[derive(Clone, Copy)]
enum Route<'a> {
    Info(&'a str),
    List(&'static str),
    Quick(&'a str),
    Index(&'static str),
}

async fn metadata(app: Arc<App>, headers: HeaderMap, route: Route<'_>) -> Result<Response, ApiError> {
    let (_permit, principal) = super::admit(&app, &headers).await?;
    let rendered = run(&app, principal.as_ref(), route, 0).await?;
    Ok(respond(rendered))
}

async fn selected_metadata(
    app: Arc<App>,
    peer: Option<axum::Extension<VerifiedPeer>>,
    headers: HeaderMap,
    registry: &str,
    route: Route<'_>,
) -> Result<Response, ApiError> {
    let registry = super::registry_read::registry_id(registry)?;
    let (_permit, principal) = super::registry_read::admit_rubygems(&app, peer.clone(), registry, &headers).await?;
    let rendered = run(&app, Some(&principal), route, registry.0).await?;
    super::registry_read::recheck_rubygems(&app, peer, registry, &headers).await?;
    Ok(respond(rendered))
}

async fn run(app: &Arc<App>, principal: Option<&crate::managed::Principal>, route: Route<'_>, registry_id: u64) -> Result<Rendered, ApiError> {
    match route {
        Route::Info(gem) => serve::serve_info(app, principal, gem, registry_id).await,
        Route::List(which) => serve::serve_list(app, principal, which).await,
        Route::Quick(file) => serve::serve_quick_gemspec(app, principal, file, registry_id).await,
        Route::Index(file) => serve::serve_index(app, principal, file, registry_id).await,
    }
}

pub async fn info(State(app): State<Arc<App>>, headers: HeaderMap, Path(gem): Path<String>) -> Result<Response, ApiError> {
    metadata(app, headers, Route::Info(&gem)).await
}
pub async fn versions(State(app): State<Arc<App>>, headers: HeaderMap) -> Result<Response, ApiError> {
    metadata(app, headers, Route::List("versions")).await
}
pub async fn names(State(app): State<Arc<App>>, headers: HeaderMap) -> Result<Response, ApiError> {
    metadata(app, headers, Route::List("names")).await
}
pub async fn quick(State(app): State<Arc<App>>, headers: HeaderMap, Path(file): Path<String>) -> Result<Response, ApiError> {
    metadata(app, headers, Route::Quick(&file)).await
}

pub async fn specs(State(app): State<Arc<App>>, headers: HeaderMap) -> Result<Response, ApiError> {
    metadata(app, headers, Route::Index("specs.4.8.gz")).await
}
pub async fn latest_specs(State(app): State<Arc<App>>, headers: HeaderMap) -> Result<Response, ApiError> {
    metadata(app, headers, Route::Index("latest_specs.4.8.gz")).await
}
pub async fn prerelease_specs(State(app): State<Arc<App>>, headers: HeaderMap) -> Result<Response, ApiError> {
    metadata(app, headers, Route::Index("prerelease_specs.4.8.gz")).await
}

type Peer = Option<axum::Extension<VerifiedPeer>>;

pub async fn selected_specs(State(app): State<Arc<App>>, peer: Peer, headers: HeaderMap, Path(registry): Path<String>) -> Result<Response, ApiError> {
    selected_metadata(app, peer, headers, &registry, Route::Index("specs.4.8.gz")).await
}
pub async fn selected_latest_specs(State(app): State<Arc<App>>, peer: Peer, headers: HeaderMap, Path(registry): Path<String>) -> Result<Response, ApiError> {
    selected_metadata(app, peer, headers, &registry, Route::Index("latest_specs.4.8.gz")).await
}
pub async fn selected_prerelease_specs(State(app): State<Arc<App>>, peer: Peer, headers: HeaderMap, Path(registry): Path<String>) -> Result<Response, ApiError> {
    selected_metadata(app, peer, headers, &registry, Route::Index("prerelease_specs.4.8.gz")).await
}

pub async fn selected_info(State(app): State<Arc<App>>, peer: Peer, headers: HeaderMap, Path((registry, gem)): Path<(String, String)>) -> Result<Response, ApiError> {
    selected_metadata(app, peer, headers, &registry, Route::Info(&gem)).await
}
pub async fn selected_versions(State(app): State<Arc<App>>, peer: Peer, headers: HeaderMap, Path(registry): Path<String>) -> Result<Response, ApiError> {
    selected_metadata(app, peer, headers, &registry, Route::List("versions")).await
}
pub async fn selected_names(State(app): State<Arc<App>>, peer: Peer, headers: HeaderMap, Path(registry): Path<String>) -> Result<Response, ApiError> {
    selected_metadata(app, peer, headers, &registry, Route::List("names")).await
}
pub async fn selected_quick(State(app): State<Arc<App>>, peer: Peer, headers: HeaderMap, Path((registry, file)): Path<(String, String)>) -> Result<Response, ApiError> {
    selected_metadata(app, peer, headers, &registry, Route::Quick(&file)).await
}

/// `GET|HEAD /rubygems/gems/{name}-{version}[-{platform}].gem`.
pub async fn gem(State(app): State<Arc<App>>, method: Method, headers: HeaderMap, Path(file): Path<String>) -> Result<Response, ApiError> {
    let (permit, principal) = super::admit(&app, &headers).await?;
    let (id, _name) = serve::reference_for_file(&app, principal.as_ref(), &file, 0).await?;
    deliver(&app, principal.as_ref(), 0, id, &file, &method, &headers, permit).await
}

pub async fn selected_gem(
    State(app): State<Arc<App>>,
    peer: Peer,
    method: Method,
    headers: HeaderMap,
    Path((registry, file)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let registry = super::registry_read::registry_id(&registry)?;
    let (permit, principal) = super::registry_read::admit_rubygems(&app, peer.clone(), registry, &headers).await?;
    let (id, _name) = serve::reference_for_file(&app, Some(&principal), &file, registry.0).await?;
    let response = deliver(&app, Some(&principal), registry.0, id, &file, &method, &headers, permit).await?;
    let current = super::registry_read::recheck_rubygems(&app, peer, registry, &headers).await?;
    if current.policy.policy.fingerprint != principal.policy.policy.fingerprint
        || current.registry_origin != principal.registry_origin
        || current.registry_trusted != principal.registry_trusted
        || current.registry_private_cidrs != principal.registry_private_cidrs
        || current.registry_read_authorization != principal.registry_read_authorization
    {
        return Err(ApiError::PolicyUnavailable);
    }
    Ok(response)
}

#[allow(clippy::too_many_arguments)]
async fn deliver(
    app: &Arc<App>,
    principal: Option<&crate::managed::Principal>,
    registry_id: u64,
    id: ReferenceId,
    file: &str,
    method: &Method,
    headers: &HeaderMap,
    permit: tokio::sync::OwnedSemaphorePermit,
) -> Result<Response, ApiError> {
    let range = headers.get(header::RANGE).and_then(|value| value.to_str().ok());
    let response = crate::artifacts::serve_artifact_in(app, principal, crate::policy::Ecosystem::RubyGems, registry_id, id, file, method, range).await?;
    Ok(response.under(&app.limits, permit).into_response())
}

// ------------------------------------------------------------------ writes (`gem push`, `gem yank`)
//
// Parity with `pypi_routes::selected_upload`: class W of the shared service. A write is forwarded
// only with the caller's own credential (RubyGems sends its API key bare in `Authorization`), to
// the selected registry's configured origin, and never to rubygems.org's public API through a
// registry that has no target of its own.

async fn forward_write(
    app: Arc<App>,
    peer: Peer,
    headers: HeaderMap,
    registry: String,
    method: Method,
    rest: &[&str],
    body: axum::body::Body,
) -> Result<Response, ApiError> {
    use futures_util::StreamExt;
    use tokio::io::{AsyncSeekExt, AsyncWriteExt};
    // A write without the caller's own credential is refused locally with 401 before admission,
    // a permit or any registry lookup.
    let auth = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty() && value.len() <= 8192)
        .ok_or(ApiError::Unauthenticated)?
        .to_owned();
    let registry = super::registry_read::registry_id(&registry)?;
    let (_permit, principal) = super::registry_read::admit_rubygems(&app, peer.clone(), registry, &headers).await?;
    let origin = principal.registry_origin.clone().ok_or(ApiError::NotFound)?;
    let origins = crate::upstream::OriginSet::selected_npm_with_private(origin.clone(), principal.registry_private_cidrs.clone())
        .map_err(|_| ApiError::NotFound)?;
    let url = origins.url_for(crate::upstream::OriginKind::NpmMetadata, rest).map_err(|_| ApiError::NotFound)?;
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .filter(|value| value.len() <= 256)
        .map(str::to_owned);
    // MFA accounts send the one-time password in `OTP`; it is the caller's own, bounded, forwarded as is.
    let otp = headers.get("otp").and_then(|value| value.to_str().ok()).filter(|value| !value.is_empty() && value.len() <= 64).map(str::to_owned);
    let cap = app.config.max_artifact_bytes.get().min(app.config.max_artifact_bytes.get().saturating_mul(2));
    if headers.get(header::CONTENT_LENGTH).and_then(|value| value.to_str().ok()).and_then(|value| value.parse::<u64>().ok()).is_some_and(|length| length > cap) {
        return Ok(axum::http::StatusCode::PAYLOAD_TOO_LARGE.into_response());
    }
    let file = tempfile::tempfile_in(&app.config.data_dir).map_err(|_| ApiError::StorageUnusable)?;
    let mut file = tokio::fs::File::from_std(file);
    let mut length = 0u64;
    let mut stream = body.into_data_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| ApiError::InvalidInput("upload is incomplete"))?;
        length = length.saturating_add(chunk.len() as u64);
        if length > cap {
            return Ok(axum::http::StatusCode::PAYLOAD_TOO_LARGE.into_response());
        }
        file.write_all(&chunk).await.map_err(|_| ApiError::StorageUnusable)?;
    }
    file.flush().await.map_err(|_| ApiError::StorageUnusable)?;
    file.seek(std::io::SeekFrom::Start(0)).await.map_err(|_| ApiError::StorageUnusable)?;
    let current = super::registry_read::recheck_rubygems(&app, peer, registry, &headers).await?;
    if current.registry_origin != principal.registry_origin
        || current.registry_private_cidrs != principal.registry_private_cidrs
        || current.policy.policy.fingerprint != principal.policy.policy.fingerprint
    {
        return Err(ApiError::PolicyUnavailable);
    }
    let result = app
        .transport
        .send_action(crate::upstream::ActionRequest {
            url,
            origin,
            private_cidrs: principal.registry_private_cidrs.clone(),
            method,
            authorization: Some(auth),
            content_type,
            otp,
            body: file,
            body_len: length,
            max_bytes: app.config.max_metadata_bytes.get(),
        })
        .await
        .map_err(|error| match error {
            crate::upstream::UpstreamError::Timeout => ApiError::UpstreamTimeout,
            _ => ApiError::UpstreamFailure,
        })?;
    let status = axum::http::StatusCode::from_u16(result.status).map_err(|_| ApiError::UpstreamInvalid)?;
    let mut response = (status, result.body).into_response();
    if let Some(content_type) = result.content_type.and_then(|value| value.parse().ok()) {
        response.headers_mut().insert(header::CONTENT_TYPE, content_type);
    }
    Ok(response)
}

/// `POST /registry/rubygems/{registry}/api/v1/gems` (`gem push`).
pub async fn selected_push(State(app): State<Arc<App>>, peer: Peer, headers: HeaderMap, Path(registry): Path<String>, body: axum::body::Body) -> Result<Response, ApiError> {
    forward_write(app, peer, headers, registry, Method::POST, &["api", "v1", "gems"], body).await
}

/// `DELETE /registry/rubygems/{registry}/api/v1/gems/yank` (`gem yank`).
pub async fn selected_yank(State(app): State<Arc<App>>, peer: Peer, headers: HeaderMap, Path(registry): Path<String>, body: axum::body::Body) -> Result<Response, ApiError> {
    forward_write(app, peer, headers, registry, Method::DELETE, &["api", "v1", "gems", "yank"], body).await
}
