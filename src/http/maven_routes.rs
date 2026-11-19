//! The Maven repository endpoint group. Handlers admit, delegate to `maven::serve` and map errors only. Standalone and
//! certificate-managed callers use `/maven/...`; a shared service's selected registry is `/registry/maven/{registry}/...`
//! (the shared-service middleware rewrites `/maven/...` into it). A client's repository (or mirror) URL is `{origin}/maven/`.
//!
//! A path is parsed once, strictly, before any admission or upstream call (src/maven/coords.rs): a coordinate, a version and
//! a file name have one spelling, anything else is a 404.
//!
//! Writes (class W, shared service only): `mvn deploy` is a `PUT` of each file, each checksum, each signature and each
//! `maven-metadata.xml` to the same layout path, and an operator's clean-up is a `DELETE` of one. They are forwarded
//! with the caller's own `Authorization` to the registry's own origin (or, for the public registry, the configured
//! `maven_publish_url`), never with any credential of this service. A write without a credential is answered with the
//! `Basic` challenge Maven waits for before it sends one, and nothing is read or asked.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::App;
use crate::http::error::ApiError;
use crate::managed::certificates::VerifiedPeer;
use crate::maven::coords::{self, Parsed};
use crate::maven::serve::{self, Rendered};

type Peer = Option<axum::Extension<VerifiedPeer>>;

fn plain(rendered: Rendered) -> Response {
    let mut response = rendered.body.into_response();
    response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static(rendered.content_type));
    response
}

fn reads_only(method: &Method) -> Result<(), ApiError> {
    if matches!(*method, Method::GET | Method::HEAD) { Ok(()) } else { Err(ApiError::MethodNotAllowed) }
}

/// A repository's own 401 reaches Maven with the challenge it needs to send its credential.
fn challenge(result: Result<Response, ApiError>) -> Result<Response, ApiError> {
    match result {
        Err(error @ ApiError::UpstreamUnauthenticated) => {
            let mut response = error.into_response();
            response.headers_mut().append(header::WWW_AUTHENTICATE, HeaderValue::from_static("Basic realm=\"registry\""));
            Ok(response)
        }
        other => other,
    }
}

#[allow(clippy::too_many_arguments)]
async fn run(
    app: &Arc<App>,
    principal: Option<&crate::managed::Principal>,
    registry_id: u64,
    parsed: Parsed,
    method: &Method,
    headers: &HeaderMap,
    permit: tokio::sync::OwnedSemaphorePermit,
) -> Result<Response, ApiError> {
    reads_only(method)?;
    match parsed {
        Parsed::File(file) => {
            let (reference, name) = serve::reference_for_file(app, principal, &file, registry_id).await?;
            let range = headers.get(header::RANGE).and_then(|value| value.to_str().ok());
            let response = crate::artifacts::serve_artifact_in(app, principal, crate::policy::Ecosystem::Maven, registry_id, reference, &name, method, range).await?;
            Ok(response.under(&app.limits, permit).into_response())
        }
        // A document request has one deadline for everything it asks upstream.
        Parsed::Metadata { dirs, level, side } => tokio::time::timeout(serve::DOCUMENT_DEADLINE, serve::serve_metadata(app, principal, registry_id, &dirs, level, side))
            .await
            .unwrap_or(Err(ApiError::UpstreamTimeout))
            .map(plain),
        Parsed::Catalog(side) => tokio::time::timeout(serve::DOCUMENT_DEADLINE, serve::serve_catalog(app, principal, registry_id, side))
            .await
            .unwrap_or(Err(ApiError::UpstreamTimeout))
            .map(plain),
    }
}

fn parse(path: &str, uri: &axum::http::Uri) -> Result<Parsed, ApiError> {
    if uri.query().is_some() {
        return Err(ApiError::NotFound);
    }
    coords::parse(path).ok_or(ApiError::NotFound)
}

/// `GET|HEAD /maven/{path}` for the standalone and certificate-managed firewall. A response the release gate refuses is
/// admitted again by the shared layer (src/http/readmit.rs).
pub async fn legacy(State(app): State<Arc<App>>, method: Method, headers: HeaderMap, uri: axum::http::Uri, Path(path): Path<String>) -> Result<Response, ApiError> {
    let parsed = parse(&path, &uri)?;
    let (permit, principal) = super::admit(&app, &headers).await?;
    run(&app, principal.as_ref(), 0, parsed, &method, &headers, permit).await
}

/// `GET|HEAD /registry/maven/{registry}/{path}`: a selected registry.
pub async fn selected(State(app): State<Arc<App>>, peer: Peer, method: Method, headers: HeaderMap, uri: axum::http::Uri, Path((registry, path)): Path<(String, String)>, body: axum::body::Body) -> Result<Response, ApiError> {
    if matches!(method, Method::PUT | Method::DELETE) {
        return challenge(forward_write(app, peer, headers, uri, registry, path, method, body).await);
    }
    let parsed = parse(&path, &uri)?;
    let registry_id = super::registry_read::registry_id(&registry)?;
    let (permit, principal) = super::registry_read::admit_maven(&app, peer.clone(), registry_id, &headers).await?;
    let response = match challenge(run(&app, Some(&principal), registry_id.0, parsed, &method, &headers, permit).await) {
        Ok(response) if response.status() == StatusCode::UNAUTHORIZED => return Ok(response),
        other => other?,
    };
    let current = super::registry_read::recheck_maven(&app, peer, registry_id, &headers).await?;
    // The answer was decided under `principal`; it stands only if nothing it was decided by has changed.
    if current.policy.policy.fingerprint != principal.policy.policy.fingerprint
        || current.registry_origin != principal.registry_origin
        || current.registry_trusted != principal.registry_trusted
        || current.registry_private_cidrs != principal.registry_private_cidrs
        || current.registry_archive_origin != principal.registry_archive_origin
        || current.registry_read_authorization != principal.registry_read_authorization
    {
        return Ok(super::readmit::refusal());
    }
    Ok(response)
}

// ------------------------------------------------------------------ the deploy endpoints (class W)

fn credential(headers: &HeaderMap) -> Option<String> {
    headers.get(header::AUTHORIZATION).and_then(|value| value.to_str().ok()).filter(|value| !value.trim().is_empty() && value.len() <= 8192).map(str::to_owned)
}

fn unauthorized() -> Response {
    let mut response = StatusCode::UNAUTHORIZED.into_response();
    response.headers_mut().insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Basic realm=\"registry\""));
    response
}

#[allow(clippy::too_many_arguments)]
async fn forward_write(app: Arc<App>, peer: Peer, headers: HeaderMap, uri: axum::http::Uri, registry: String, path: String, method: Method, body: axum::body::Body) -> Result<Response, ApiError> {
    // Maven sends no credential until it is challenged: the challenge is answered before anything is read or asked.
    let Some(authorization) = credential(&headers) else { return Ok(unauthorized()) };
    // A clean-up of a whole artifact or version directory (`DELETE .../lib/1.0/`, as Nexus and Artifactory take it) names a directory.
    let directory = (method == Method::DELETE && uri.query().is_none()).then(|| coords::parse_dir(&path)).flatten().filter(|_| path.ends_with('/') || coords::parse(&path).is_none());
    let segments = match directory {
        Some(mut segments) => {
            segments.push(String::new());
            segments
        }
        None => match parse(&path, &uri)? {
            Parsed::File(file) => coords::file_segments(&file),
            Parsed::Metadata { dirs, side, .. } => coords::metadata_segments(&dirs, side),
            Parsed::Catalog(_) => return Err(ApiError::NotFound),
        },
    };
    let cap = app.config.max_artifact_bytes.get().saturating_mul(2).max(app.config.max_artifact_bytes.get());
    let declared = headers.get(header::CONTENT_LENGTH).and_then(|value| value.to_str().ok()).and_then(|value| value.parse::<u64>().ok());
    if declared.is_some_and(|length| length > cap) {
        return Ok(StatusCode::PAYLOAD_TOO_LARGE.into_response());
    }
    let registry = super::registry_read::registry_id(&registry)?;
    let (_permit, principal) = super::registry_read::admit_maven(&app, peer.clone(), registry, &headers).await?;
    // This request carries the caller's credential: nothing it reads may enter a shared cache (C1028).
    super::logging::record_request_scoped();
    let target = serve::publish_target(&app, &principal, &segments)?;
    let content_type = headers.get(header::CONTENT_TYPE).and_then(|value| value.to_str().ok()).filter(|value| value.len() <= 256).map(str::to_owned);
    let super::spool::Spooled::Body(spool) = super::spool::spool(&app, super::spool::owner_of(&app, &principal, &headers), declared, cap, body).await? else {
        return Ok(StatusCode::PAYLOAD_TOO_LARGE.into_response());
    };
    // The spool's place and bytes are held until this request is done with the file.
    let (file, length) = (spool.file, spool.length);
    let current = super::registry_read::recheck_maven(&app, peer, registry, &headers).await?;
    if current.registry_origin != principal.registry_origin || current.registry_private_cidrs != principal.registry_private_cidrs || current.policy.policy.fingerprint != principal.policy.policy.fingerprint {
        return Err(ApiError::PolicyUnavailable);
    }
    let result = app
        .transport
        .send_action(crate::upstream::ActionRequest {
            url: target.url,
            origin: target.origin,
            private_cidrs: principal.registry_private_cidrs.clone(),
            method,
            authorization: Some(authorization),
            content_type,
            otp: None,
            api_key: None,
            body: file,
            body_len: length,
            max_bytes: app.config.max_metadata_bytes.get(),
        })
        .await
        .map_err(|error| match error {
            crate::upstream::UpstreamError::Timeout => ApiError::UpstreamTimeout,
            _ => ApiError::UpstreamFailure,
        })?;
    // Only the answers a deploy endpoint gives are relayed, as plain text that no browser is asked to sniff.
    let status = StatusCode::from_u16(result.status).ok().filter(|status| matches!(status.as_u16(), 200 | 201 | 202 | 204 | 400 | 401 | 403 | 404 | 405 | 409 | 413 | 422 | 429)).ok_or(ApiError::UpstreamInvalid)?;
    let mut response = (status, result.body).into_response();
    response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain; charset=utf-8"));
    response.headers_mut().insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    if status == StatusCode::UNAUTHORIZED {
        response.headers_mut().insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Basic realm=\"registry\""));
    }
    Ok(response)
}
