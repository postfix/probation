//! `GET|HEAD /npm/artifacts/{reference_id}/{filename}` and its PyPI twin (SPEC §11).
//! The handler validates, delegates, and maps errors — every policy decision belongs
//! to `artifacts::serve_artifact`.
//!
//! The ecosystem is in the route rather than in a path capture, so it is a fact about
//! which registration matched and not a string a client chose.

use std::sync::Arc;

use axum::extract::rejection::PathRejection;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, Method, header};
use axum::response::{IntoResponse, Response};
use tokio::sync::OwnedSemaphorePermit;

use crate::App;
use crate::artifacts::{self};
use crate::http::error::ApiError;
use crate::http::npm_routes;
use crate::npm;
use crate::policy::Ecosystem;
use crate::store::rows::ReferenceId;

pub async fn serve_npm(
    state: State<Arc<App>>,
    method: Method,
    headers: HeaderMap,
    path: Result<Path<(String, String)>, PathRejection>,
) -> Result<Response, ApiError> {
    // `/npm/artifacts/-/{filename}` is the upstream tarball path of a package named
    // `artifacts`, which this static route outranks. No reference id is `-`.
    if let Ok(Path((reference_id, filename))) = &path
        && reference_id == "-"
    {
        let State(app) = state;
        return serve_npm_named(&app, "artifacts", filename, &method, &headers).await;
    }
    serve(Ecosystem::Npm, state, method, headers, path).await
}

pub async fn serve_pypi(
    state: State<Arc<App>>,
    method: Method,
    headers: HeaderMap,
    path: Result<Path<(String, String)>, PathRejection>,
) -> Result<Response, ApiError> {
    serve(Ecosystem::PyPi, state, method, headers, path).await
}

async fn serve(
    ecosystem: Ecosystem,
    State(app): State<Arc<App>>,
    method: Method,
    headers: HeaderMap,
    path: Result<Path<(String, String)>, PathRejection>,
) -> Result<Response, ApiError> {
    let Path((reference_id, filename)) = path?;
    // The permit is handed to the response below, so it is held for as long as bytes
    // are still going out and not merely until this function returns.
    let permit = super::admit(&app)?;

    // A reference id is 64 hexadecimal characters and nothing else. SPEC §9: it is a
    // lookup key, so an unparseable one is invalid input rather than a miss.
    let id = ReferenceId::parse_hex(&reference_id).map_err(|err| {
        tracing::debug!(error = %err, "refused an artifact reference id");
        ApiError::InvalidInput("a reference id is 64 hexadecimal characters")
    })?;

    deliver(&app, ecosystem, id, &filename, &method, &headers, permit).await
}

/// `GET|HEAD /npm/{package}/-/{filename}`: upstream's own tarball path, which is what
/// an existing lockfile names. npm rewrites only the host of a `resolved` URL to the
/// configured registry, so this is the path it asks for, and the one a yarn 1
/// lockfile asks for once its host is rewritten here.
pub async fn serve_npm_upstream(
    State(app): State<Arc<App>>,
    method: Method,
    headers: HeaderMap,
    path: Result<Path<(String, String)>, PathRejection>,
) -> Result<Response, ApiError> {
    let Path((package, filename)) = path?;
    serve_npm_named(&app, &package, &filename, &method, &headers).await
}

/// `GET|HEAD /npm/@{scope}/{package}/-/{filename}`: the same, for a scoped package.
pub async fn serve_npm_upstream_scoped(
    State(app): State<Arc<App>>,
    method: Method,
    headers: HeaderMap,
    path: Result<Path<(String, String, String)>, PathRejection>,
) -> Result<Response, ApiError> {
    let Path((scope, package, filename)) = path?;
    if !scope.starts_with('@') {
        return Err(ApiError::NotFound);
    }
    serve_npm_named(
        &app,
        &format!("{scope}/{package}"),
        &filename,
        &method,
        &headers,
    )
    .await
}

/// `GET /npm/-/{*rest}`, npm's own namespace, refused without a lookup except for one
/// path. npm 11 and later add the registry's path to a lockfile URL only when the URL
/// does not already start with it, so the package named `npm`, whose upstream path is
/// `/npm/-/npm-{version}.tgz`, arrives here unprefixed.
pub async fn serve_npm_namespace(
    State(app): State<Arc<App>>,
    method: Method,
    headers: HeaderMap,
    path: Result<Path<String>, PathRejection>,
) -> Result<Response, ApiError> {
    let Path(rest) = path?;
    if rest.contains('/') || !rest.starts_with("npm-") || !rest.ends_with(".tgz") {
        return Err(ApiError::NotFound);
    }
    serve_npm_named(&app, "npm", &rest, &method, &headers).await
}

/// The reference is the one the current upstream snapshot advertises under this
/// filename. SPEC §9: the server looks it up; it never builds an upstream URL from the
/// path it was given.
async fn serve_npm_named(
    app: &Arc<App>,
    package: &str,
    filename: &str,
    method: &Method,
    headers: &HeaderMap,
) -> Result<Response, ApiError> {
    let permit = super::admit(app)?;
    let name = npm_routes::parse_name(package)?;
    let id = npm::reference_for_file(app, &name, filename).await?;
    deliver(app, Ecosystem::Npm, id, filename, method, headers, permit).await
}

async fn deliver(
    app: &Arc<App>,
    ecosystem: Ecosystem,
    id: ReferenceId,
    filename: &str,
    method: &Method,
    headers: &HeaderMap,
    permit: OwnedSemaphorePermit,
) -> Result<Response, ApiError> {
    let range = headers
        .get(header::RANGE)
        .and_then(|value| value.to_str().ok());

    let response = artifacts::serve_artifact(app, ecosystem, id, filename, method, range).await?;
    Ok(response.under(&app.limits, permit).into_response())
}
