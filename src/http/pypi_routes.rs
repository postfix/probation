//! The PyPI endpoint group (SPEC §11). Handlers validate, negotiate, delegate, and
//! map errors only.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::App;
use crate::http::error::ApiError;
use crate::pypi::{self, ProjectName};
use crate::store::cache::Representation;

/// The two media types this server actually produces, beside their legacy aliases.
const JSON_MEDIA: &str = "application/vnd.pypi.simple.v1+json";
const HTML_MEDIA: &str = "application/vnd.pypi.simple.v1+html";

/// `GET /pypi/simple/`.
pub async fn index(State(app): State<Arc<App>>, headers: HeaderMap) -> Result<Response, ApiError> {
    // SPEC §10: "reject overload instead of allowing unbounded waiters or tasks."
    let _permit = app.limits.active_permit().ok_or(ApiError::Overloaded)?;
    let rendered = pypi::index(&app, &negotiate(&headers)?).await?;
    Ok(respond(rendered))
}

/// `GET /pypi/simple/{project}/`.
///
/// A request that spelled the project any way but the PEP 503 canonical one is
/// answered with a local `301` rather than served, so one project never has two live
/// URLs and a client's own cache cannot hold two answers for it.
pub async fn project(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(project): Path<String>,
) -> Result<Response, ApiError> {
    let _permit = app.limits.active_permit().ok_or(ApiError::Overloaded)?;
    let name = parse_name(&project)?;
    // Negotiated before the redirect, so a client that accepts nothing this server
    // produces is told so once rather than sent to a second URL to be refused there.
    let representation = negotiate(&headers)?;
    if !name.is_canonical() {
        return Ok(canonical_redirect(&name));
    }
    let rendered = pypi::serve(&app, &name, representation).await?;
    Ok(respond(rendered))
}

/// `GET /pypi/simple/{project}` — SPEC §7's "required canonical trailing-slash
/// redirects", answered locally rather than by forwarding the client upstream.
pub async fn project_without_slash(Path(project): Path<String>) -> Result<Response, ApiError> {
    Ok(canonical_redirect(&parse_name(&project)?))
}

fn parse_name(raw: &str) -> Result<ProjectName, ApiError> {
    ProjectName::parse_route(raw).map_err(|err| {
        tracing::debug!(error = %err, "refused a project name");
        ApiError::InvalidInput("the project name is not a valid PyPI project name")
    })
}

/// The canonical form is `[a-z0-9-]` by construction — normalisation admits nothing
/// else — so the `Location` it builds can carry neither a path segment of its own nor
/// a header-splitting character.
fn canonical_redirect(name: &ProjectName) -> Response {
    let location = format!("/pypi/simple/{}/", name.as_str());
    match HeaderValue::from_str(&location) {
        Ok(value) => {
            let mut response = StatusCode::MOVED_PERMANENTLY.into_response();
            response.headers_mut().insert(header::LOCATION, value);
            response
        }
        // Unreachable for a normalised name; refusing is still better than serving a
        // redirect with no target.
        Err(_) => ApiError::InvalidInput("the project name cannot be redirected").into_response(),
    }
}

/// Which serialisation the client prefers.
///
/// Media types this server does not produce are ignored, and a tie goes to HTML —
/// the form PEP 503 has always required and the one a browser or `curl` wants. A
/// client that accepts *nothing* this server produces is SPEC §11's `406` row: an
/// unsupported representation is refused rather than defaulted, because serving HTML
/// to a client that said it cannot read HTML is a parse error later instead of a clear
/// answer now.
///
/// An absent `Accept` header is not that case. HTTP treats it as "anything", and a
/// header this server cannot read as text is treated the same way rather than being
/// held against the client.
fn negotiate(headers: &HeaderMap) -> Result<Representation, ApiError> {
    let Some(accept) = headers
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
    else {
        return Ok(Representation::PypiHtml);
    };

    let (mut json, mut html) = (-1.0f32, -1.0f32);
    for entry in accept.split(',') {
        let mut parts = entry.split(';');
        let media = parts.next().unwrap_or_default().trim().to_ascii_lowercase();
        let quality = parts
            .filter_map(|parameter| {
                parameter
                    .trim()
                    .strip_prefix("q=")
                    .and_then(|value| value.parse::<f32>().ok())
            })
            .next()
            .unwrap_or(1.0);

        match media.as_str() {
            JSON_MEDIA | "application/json" => json = json.max(quality),
            HTML_MEDIA | "text/html" => html = html.max(quality),
            "*/*" | "application/*" => {
                json = json.max(quality);
                html = html.max(quality);
            }
            _ => {}
        }
    }

    // `q=0` means "not acceptable", so a representation that only ever scored zero is
    // as unacceptable as one that was never named at all.
    if json <= 0.0 && html <= 0.0 {
        return Err(ApiError::NotAcceptable);
    }

    Ok(if json > html {
        Representation::PypiJson
    } else {
        Representation::PypiHtml
    })
}

fn respond(rendered: pypi::Rendered) -> Response {
    let mut response = rendered.body.to_vec().into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(rendered.content_type),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    fn accepting(accept: &str) -> Representation {
        try_accepting(accept).expect("a representation this server produces")
    }

    fn try_accepting(accept: &str) -> Result<Representation, ApiError> {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            HeaderValue::from_str(accept).expect("a header"),
        );
        negotiate(&headers)
    }

    /// The header pip actually sends, and the ones that must not be read as asking
    /// for JSON.
    #[test]
    fn quality_decides_the_serialisation() {
        assert_eq!(
            accepting(
                "application/vnd.pypi.simple.v1+json, \
                 application/vnd.pypi.simple.v1+html;q=0.2, text/html;q=0.01"
            ),
            Representation::PypiJson
        );
        assert_eq!(
            accepting("application/vnd.pypi.simple.v1+json;q=0.1, text/html"),
            Representation::PypiHtml,
            "a low quality on JSON is honoured rather than matched on substring"
        );
        assert_eq!(accepting("text/html"), Representation::PypiHtml);
        assert_eq!(
            accepting("*/*"),
            Representation::PypiHtml,
            "a tie goes to HTML"
        );
        assert_eq!(
            negotiate(&HeaderMap::new()).expect("an absent Accept header means anything"),
            Representation::PypiHtml
        );
    }

    /// SPEC §11's `406` row: a representation this server does not produce is refused,
    /// not silently replaced with one the client said it cannot read.
    #[test]
    fn a_representation_this_server_does_not_produce_is_refused() {
        assert_eq!(
            try_accepting("application/xml"),
            Err(ApiError::NotAcceptable)
        );
        assert_eq!(
            try_accepting("text/html;q=0, application/json;q=0"),
            Err(ApiError::NotAcceptable),
            "`q=0` says a type is not acceptable, so naming one is not accepting it"
        );
        assert_eq!(
            try_accepting("application/xml, text/html;q=0.1"),
            Ok(Representation::PypiHtml),
            "one acceptable type among several is enough"
        );
    }
}
