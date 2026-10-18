//! The npm endpoint group (SPEC §11). Handlers validate, delegate, and map errors.

use std::sync::Arc;

use axum::extract::rejection::PathRejection;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, header};
use axum::response::{IntoResponse, Response};

use crate::App;
use crate::http::error::ApiError;
use crate::npm::{self, PackageName};
use crate::store::cache::Representation;

/// What npm asks for when it wants the abbreviated install document.
const ABBREVIATED_ACCEPT: &str = "application/vnd.npm.install-v1+json";

/// `GET /npm/-/ping` (SPEC §11: "npm connectivity response").
///
/// The empty object is what npm's own registry answers, and what `npm ping` expects.
/// It deliberately asks nothing of policy or storage: this is the route a client uses
/// to find out whether the proxy is reachable at all, and answering it from the
/// blocklist would make an expired snapshot look like an unreachable server. Readiness
/// is the endpoint that says whether packages can be served.
pub async fn ping() -> Response {
    let mut response = "{}".into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
}

/// `GET /npm/{package}`.
pub async fn package(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    path: Result<Path<String>, PathRejection>,
) -> Result<Response, ApiError> {
    let Path(package) = path?;
    let _permit = super::admit(&app)?;
    let name = parse_name(&package)?;
    let rendered = npm::serve(&app, &name, negotiate(&headers)).await?;
    Ok(respond(rendered))
}

/// `GET /npm/{package}/{version-or-tag}`.
///
/// The same two path components also spell an unencoded scoped package name —
/// `/npm/@scope/name` — which npm's own registry accepts beside the `@scope%2fname`
/// form. A leading `@` on the first component with no `/` already in it is therefore
/// read as a scope, exactly as the registry reads it, and the request is a package
/// document rather than a version.
pub async fn package_version(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    path: Result<Path<(String, String)>, PathRejection>,
) -> Result<Response, ApiError> {
    let Path((package, version_or_tag)) = path?;
    let _permit = super::admit(&app)?;
    if package.starts_with('@') && !package.contains('/') {
        let name = parse_name(&format!("{package}/{version_or_tag}"))?;
        let rendered = npm::serve(&app, &name, negotiate(&headers)).await?;
        return Ok(respond(rendered));
    }

    let name = parse_name(&package)?;
    let rendered = npm::serve(&app, &name, Representation::NpmVersion(version_or_tag)).await?;
    Ok(respond(rendered))
}

fn parse_name(raw: &str) -> Result<PackageName, ApiError> {
    PackageName::parse_route(raw).map_err(|err| {
        tracing::debug!(error = %err, "refused a package name");
        ApiError::InvalidInput("the package name is not a valid npm package name")
    })
}

/// SPEC §6: the abbreviated install response is derived from the same snapshot as
/// the full one. Anything that does not ask for it by name gets the full document,
/// which is what every other client expects.
fn negotiate(headers: &HeaderMap) -> Representation {
    let accepts_abbreviated = headers
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|accept| accept.contains(ABBREVIATED_ACCEPT));

    if accepts_abbreviated {
        Representation::NpmAbbreviated
    } else {
        Representation::NpmFull
    }
}

fn respond(rendered: npm::Rendered) -> Response {
    let mut response = rendered.body.to_vec().into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(rendered.content_type),
    );
    response
}
