//! The explicit router (no catch-all), the layer stack, and graceful shutdown.

pub mod artifact_routes;
pub mod audit_filter;
pub mod error;
pub mod health;
pub mod limits;
pub mod logging;
pub mod npm_routes;
pub mod pypi_routes;
pub mod registry_read;
pub mod registry_action;
pub mod registry_routes;
pub mod service_registry;
pub(crate) mod service_unpublish;
pub mod token_packument;
pub mod unpublish_reference;

use std::sync::Arc;

use axum::Router;
use axum::extract::Request;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use tokio::sync::OwnedSemaphorePermit;

use crate::App;
use crate::http::error::ApiError;
use crate::managed::{Principal, Refusal};

/// Routes are registered explicitly; every other path is `404` and every unsupported
/// method on a route that does exist is `405` (SPEC §11).
///
/// `/npm/-/…` is registered ahead of the package routes because `-` is npm's own API
/// namespace and not a package name — `PackageName::parse_route` admits it, so
/// without these three lines `GET /npm/-/ping` would leave this process as an upstream
/// fetch for a package called `-`. SPEC §6: "Unsupported API routes receive an
/// explicit error and are never blindly forwarded." A static segment outranks a
/// capture in the router, so `ping` is served and everything else under `-` is refused
/// without a lookup, bar the tarball of the package named `npm`
/// ([`artifact_routes::serve_npm_namespace`]).
///
/// Artifacts are served under each ecosystem's own root rather than a root of their
/// own, because npm 12 refuses a tarball whose path does not start with the
/// registry's (`allow-remote` defaults to `none`). Each is four segments against
/// package routes of two and three, so a package or project literally named
/// `artifacts` is unaffected, and the same static-outranks-capture rule keeps it that
/// way.
pub fn router(app: Arc<App>) -> Router {
    Router::new()
        .fallback_service(package_router(Arc::clone(&app)))
        .layer(middleware::from_fn_with_state(Arc::clone(&app), service_registry::respond))
        .layer(middleware::map_response(no_store))
        .layer(middleware::from_fn_with_state(Arc::clone(&app), logging::decide))
        .layer(middleware::from_fn(bound_headers))
}

fn package_router(app: Arc<App>) -> Router {
    Router::new()
        .route("/health/live", get(health::live))
        .route("/health/ready", get(health::ready))
        .route("/health/delivery", get(health::delivery))
        .route("/npm/-/ping", get(npm_routes::ping))
        .route("/npm/-", get(unknown_route))
        .route("/npm/-/{*rest}", get(artifact_routes::serve_npm_namespace))
        .route("/npm/{package}", get(npm_routes::package))
        .route("/registry/npm/{registry}/-/ping", get(registry_routes::ping))
        .route("/registry/npm/{registry}/-/whoami", get(registry_routes::whoami))
        .route("/registry/npm/{registry}/-/v1/search", get(registry_routes::search))
        .route(
            "/npm/{package}/{version_or_tag}",
            get(npm_routes::package_version),
        )
        .route(
            "/registry/npm/{registry}/{package}/{version}",
            get(registry_routes::version),
        )
        .route("/registry/npm/{registry}/{package}", get(registry_routes::package).put(registry_routes::package_action))
        .route("/registry/npm/{registry}/{package}/-rev/{revision}", axum::routing::put(registry_routes::revision_action).delete(registry_routes::revision_action))
        .route("/registry/pypi/{registry}/simple/", get(pypi_routes::selected_index))
        .route("/registry/pypi/{registry}/simple/{project}/", get(pypi_routes::selected_project))
        .route("/registry/pypi/{registry}/simple/{project}", get(pypi_routes::selected_project_without_slash))
        .route("/pypi/simple/", get(pypi_routes::index))
        .route("/pypi/simple/{project}/", get(pypi_routes::project))
        .route(
            "/pypi/simple/{project}",
            get(pypi_routes::project_without_slash),
        )
        // Only the routes above: the artifact routes below serve `HEAD` as SPEC §11
        // lists it.
        .route_layer(middleware::from_fn(get_only))
        .route("/registry/pypi/{registry}/", axum::routing::post(pypi_routes::selected_upload))
        .route("/registry/npm/{registry}/-/npm/v1/security/advisories/bulk", axum::routing::post(registry_routes::audit_bulk))
        .route("/registry/npm/{registry}/-/npm/v1/security/audits/quick", axum::routing::post(registry_routes::audit_quick))
        .route("/registry/npm/{registry}/-/{*rest}", axum::routing::any(registry_routes::action))
        .route("/registry/npm/{registry}/{package}/-/{filename}", get(registry_routes::package_tarball).head(registry_routes::package_tarball))
        .route("/registry/npm/{registry}/{package}/-/{filename}/-rev/{revision}", axum::routing::delete(registry_routes::package_tarball_delete))
        .route("/registry/npm/{registry}/artifacts/{reference_id}/{filename}/-rev/{revision}", axum::routing::delete(registry_routes::unsupported_artifact_delete))
        .route(
            "/npm/artifacts/{reference_id}/{filename}",
            get(artifact_routes::serve_npm).head(artifact_routes::serve_npm),
        )
        .route(
            "/registry/npm/{registry}/artifacts/{reference_id}/{filename}",
            get(registry_routes::artifact).head(registry_routes::artifact),
        )
        .route(
            "/registry/pypi/{registry}/artifacts/{reference_id}/{filename}",
            get(pypi_routes::selected_artifact).head(pypi_routes::selected_artifact),
        )
        .route(
            "/pypi/artifacts/{reference_id}/{filename}",
            get(artifact_routes::serve_pypi).head(artifact_routes::serve_pypi),
        )
        // Upstream's own tarball paths, which existing lockfiles name.
        .route(
            "/npm/{package}/-/{filename}",
            get(artifact_routes::serve_npm_upstream).head(artifact_routes::serve_npm_upstream),
        )
        .route(
            "/npm/{scope}/{package}/-/{filename}",
            get(artifact_routes::serve_npm_upstream_scoped)
                .head(artifact_routes::serve_npm_upstream_scoped),
        )
        .fallback(unknown_route)
        .method_not_allowed_fallback(unsupported_method)
        .with_state(app)
}

async fn bound_headers(request: Request, next: Next) -> Response {
    let size = request.headers().iter().fold(0usize, |total, (name, value)|
        total.saturating_add(name.as_str().len()).saturating_add(value.as_bytes().len()));
    if size > 64 * 1024 {
        return StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE.into_response();
    }
    next.run(request).await
}

/// What every package route asks before it does any work: a request permit
/// (SPEC §10: "reject overload instead of allowing unbounded waiters or tasks"), and
/// usable storage — SPEC §10: "Storage write failures make readiness false and deny
/// package responses with `503` until storage is usable again." Checked here rather
/// than left to the first storage command, because a warm response issues none.
///
/// With no valid policy in force the handler's own `POLICY_UNAVAILABLE` answers
/// instead: SPEC §5 puts that check first, and it is the more fundamental refusal.
///
/// In managed mode the local blocklist is not consulted (C109): the request waits for
/// the first sync or a loaded cache snapshot, then its key is authenticated, once, and
/// the principal whose policy the request is decided under is handed on.
async fn admit(
    app: &App,
    headers: &HeaderMap,
) -> Result<(OwnedSemaphorePermit, Option<Principal>), ApiError> {
    let permit = app.limits.active_permit().ok_or(ApiError::Overloaded)?;
    let Some(managed) = app.managed() else {
        let policy_valid = app
            .blocklist()
            .is_some_and(|snapshot| snapshot.is_valid_at(app.clock.now_utc_micros()));
        if !app.store().is_healthy() && policy_valid {
            return Err(ApiError::StorageUnusable);
        }
        return Ok((permit, None));
    };
    // Until then the network lock would run on an empty table (T1).
    if !managed.ready() {
        return Err(ApiError::NotReady);
    }
    if !app.store().is_healthy() {
        return Err(ApiError::StorageUnusable);
    }
    // Managed mode always builds the server with connect-info, so a missing address
    // is a fault: fail closed, as not ready.
    let peer = logging::peer().ok_or(ApiError::NotReady)?;
    let principal = managed
        .authenticate(headers, peer)
        .await
        .map_err(|refusal| match refusal {
            Refusal::Unauthenticated => ApiError::Unauthenticated,
            Refusal::Network(client) => ApiError::NetworkNotAllowed(client),
            Refusal::RateLimited => ApiError::TooManyRequests,
            Refusal::Busy => ApiError::LookupBusy,
        })?;
    logging::record_place(principal.place.id);
    Ok((permit, Some(principal)))
}

async fn unknown_route() -> ApiError {
    ApiError::NotFound
}

/// SPEC §11: "Reject request methods outside the supported set." Axum adds the `Allow`
/// header to this response, because the body does not set one itself.
async fn unsupported_method() -> ApiError {
    ApiError::MethodNotAllowed
}

/// SPEC §11 lists `GET` alone on every route but the artifact ones. Axum answers
/// `HEAD` with any `GET` handler, so it is refused here, and every `405` from these
/// routes names `GET` alone rather than axum's `GET,HEAD`.
async fn get_only(request: Request, next: Next) -> Response {
    let mut response = if request.method() == Method::HEAD {
        ApiError::MethodNotAllowed.into_response()
    } else {
        next.run(request).await
    };
    if response.status() == StatusCode::METHOD_NOT_ALLOWED {
        response
            .headers_mut()
            .insert(header::ALLOW, HeaderValue::from_static("GET"));
    }
    response
}

/// SPEC §11: every response, including errors, carries `Cache-Control: no-store`.
async fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}
