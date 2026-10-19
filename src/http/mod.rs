//! The explicit router (no catch-all), the layer stack, and graceful shutdown.

pub mod artifact_routes;
pub mod error;
pub mod health;
pub mod limits;
pub mod logging;
pub mod npm_routes;
pub mod pypi_routes;

use std::sync::Arc;

use axum::Router;
use axum::extract::Request;
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use tokio::sync::OwnedSemaphorePermit;

use crate::App;
use crate::http::error::ApiError;

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
        .route("/health/live", get(health::live))
        .route("/health/ready", get(health::ready))
        .route("/health/delivery", get(health::delivery))
        .route("/npm/-/ping", get(npm_routes::ping))
        .route("/npm/-", get(unknown_route))
        .route("/npm/-/{*rest}", get(artifact_routes::serve_npm_namespace))
        .route("/npm/{package}", get(npm_routes::package))
        .route(
            "/npm/{package}/{version_or_tag}",
            get(npm_routes::package_version),
        )
        .route("/pypi/simple/", get(pypi_routes::index))
        .route("/pypi/simple/{project}/", get(pypi_routes::project))
        .route(
            "/pypi/simple/{project}",
            get(pypi_routes::project_without_slash),
        )
        // Only the routes above: the artifact routes below serve `HEAD` as SPEC §11
        // lists it.
        .route_layer(middleware::from_fn(get_only))
        .route(
            "/npm/artifacts/{reference_id}/{filename}",
            get(artifact_routes::serve_npm).head(artifact_routes::serve_npm),
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
        .layer(middleware::map_response(no_store))
        // Outermost, so the decision line describes the response that actually left —
        // including a `404` or `405` the router produced without reaching a handler.
        .layer(middleware::from_fn_with_state(
            Arc::clone(&app),
            logging::decide,
        ))
        .with_state(app)
}

/// What every package route asks before it does any work: a request permit
/// (SPEC §10: "reject overload instead of allowing unbounded waiters or tasks"), and
/// usable storage — SPEC §10: "Storage write failures make readiness false and deny
/// package responses with `503` until storage is usable again." Checked here rather
/// than left to the first storage command, because a warm response issues none.
///
/// With no valid policy in force the handler's own `POLICY_UNAVAILABLE` answers
/// instead: SPEC §5 puts that check first, and it is the more fundamental refusal.
fn admit(app: &App) -> Result<OwnedSemaphorePermit, ApiError> {
    let permit = app.limits.active_permit().ok_or(ApiError::Overloaded)?;
    if !app.store().is_healthy()
        && app
            .blocklist()
            .is_some_and(|snapshot| snapshot.is_valid_at(app.clock.now_utc_micros()))
    {
        return Err(ApiError::StorageUnusable);
    }
    Ok(permit)
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
