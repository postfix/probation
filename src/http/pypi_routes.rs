//! The PyPI endpoint group (SPEC §11). Handlers validate, negotiate, delegate, and
//! map errors only.

use std::sync::Arc;

use axum::extract::rejection::PathRejection;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::App;
use crate::http::error::ApiError;
use crate::pypi::{self, ProjectName};
use crate::store::cache::Representation;

/// Each representation's served media type, then the alias that also asks for it.
const JSON_TYPES: [&str; 2] = [pypi::render::JSON_CONTENT_TYPE, "application/json"];
const HTML_TYPES: [&str; 2] = ["text/html", "application/vnd.pypi.simple.v1+html"];

/// How specifically `range` names a representation: its served type, its alias, a
/// `type/*` covering either, `*/*`, or not at all (zero).
fn specificity(range: &str, types: &[&str; 2]) -> u8 {
    if range == types[0] {
        4
    } else if range == types[1] {
        3
    } else if range == "*/*" {
        1
    } else if let Some(kind) = range.strip_suffix("/*")
        && types
            .iter()
            .any(|media| media.split('/').next() == Some(kind))
    {
        2
    } else {
        0
    }
}

/// `GET /pypi/simple/`.
pub async fn index(State(app): State<Arc<App>>, headers: HeaderMap) -> Result<Response, ApiError> {
    let (_permit, principal) = super::admit(&app, &headers).await?;
    let rendered = pypi::index(&app, principal.as_ref(), &negotiate(&headers)?).await?;
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
    path: Result<Path<String>, PathRejection>,
) -> Result<Response, ApiError> {
    let Path(project) = path?;
    let (_permit, principal) = super::admit(&app, &headers).await?;
    let name = parse_name(&project)?;
    // Negotiated before the redirect, so a client that accepts nothing this server
    // produces is told so once rather than sent to a second URL to be refused there.
    let representation = negotiate(&headers)?;
    if !name.is_canonical() {
        return Ok(canonical_redirect(&name));
    }
    let rendered = pypi::serve(&app, principal.as_ref(), &name, representation).await?;
    Ok(respond(rendered))
}

/// `GET /pypi/simple/{project}` — SPEC §7's "required canonical trailing-slash
/// redirects", answered locally rather than by forwarding the client upstream.
pub async fn project_without_slash(
    path: Result<Path<String>, PathRejection>,
) -> Result<Response, ApiError> {
    let Path(project) = path?;
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

    // RFC 9110 §12.5.1: the most specific range that matches a representation sets
    // its quality, so `text/html;q=0` refuses HTML however broad a `*/*` beside it.
    let (mut json, mut html) = ((0u8, 0.0f32), (0u8, 0.0f32));
    for entry in accept.split(',') {
        let mut parts = entry.split(';');
        let media = parts.next().unwrap_or_default().trim().to_ascii_lowercase();
        let quality = parts
            .filter_map(|parameter| {
                let (name, value) = parameter.split_once('=')?;
                name.trim()
                    .eq_ignore_ascii_case("q")
                    .then(|| value.trim().parse::<f32>().ok())
                    .flatten()
            })
            .next()
            .unwrap_or(1.0);

        for (best, types) in [(&mut json, &JSON_TYPES), (&mut html, &HTML_TYPES)] {
            let specificity = specificity(&media, types);
            if specificity > best.0 {
                *best = (specificity, quality);
            } else if specificity != 0 && specificity == best.0 {
                // Two ranges equally specific: the stricter one, so a repeated
                // `q=0` is never outvoted.
                best.1 = best.1.min(quality);
            }
        }
    }
    let (json, html) = (json.1, html.1);

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
#[allow(clippy::items_after_test_module)]
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

/// Selected Simple API project. The registry identity is part of every cache and file reference.
pub async fn selected_project(
    State(app): State<Arc<App>>,
    peer: Option<axum::Extension<crate::managed::certificates::VerifiedPeer>>,
    headers: HeaderMap,
    Path((registry, project)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let registry = super::registry_read::registry_id(&registry)?;
    let (_permit, principal) = super::registry_read::admit_pypi(&app, peer.clone(), registry, &headers).await?;
    let name = parse_name(&project)?;
    let representation = negotiate(&headers)?;
    if !name.is_canonical() {
        let mut response = StatusCode::MOVED_PERMANENTLY.into_response();
        let location = format!("/registry/pypi/{}/simple/{}/", registry.0, name.as_str());
        response.headers_mut().insert(header::LOCATION, HeaderValue::from_str(&location).map_err(|_| ApiError::NotFound)?);
        return Ok(response);
    }
    let rendered = pypi::serve_in(&app, Some(&principal), &name, representation, registry.0).await?;
    let current = super::registry_read::recheck_pypi(&app, peer, registry, &headers).await?;
    if current.policy.policy.fingerprint != principal.policy.policy.fingerprint
        || current.registry_origin != principal.registry_origin
        || current.registry_trusted != principal.registry_trusted
        || current.registry_private_cidrs != principal.registry_private_cidrs
        || current.registry_read_authorization != principal.registry_read_authorization {
        return Err(ApiError::PolicyUnavailable);
    }
    Ok(respond(rendered))
}

pub async fn selected_project_without_slash(
    State(app): State<Arc<App>>,
    peer: Option<axum::Extension<crate::managed::certificates::VerifiedPeer>>,
    headers: HeaderMap,
    Path((registry, project)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let registry = super::registry_read::registry_id(&registry)?;
    let (_permit, _principal) = super::registry_read::admit_pypi(&app, peer, registry, &headers).await?;
    let name = parse_name(&project)?;
    let mut response = StatusCode::MOVED_PERMANENTLY.into_response();
    let location = format!("/registry/pypi/{}/simple/{}/", registry.0, name.as_str());
    response.headers_mut().insert(header::LOCATION, HeaderValue::from_str(&location).map_err(|_| ApiError::NotFound)?);
    Ok(response)
}

pub async fn selected_index(
    State(app): State<Arc<App>>,
    peer: Option<axum::Extension<crate::managed::certificates::VerifiedPeer>>,
    headers: HeaderMap,
    Path(registry): Path<String>,
) -> Result<Response, ApiError> {
    let registry = super::registry_read::registry_id(&registry)?;
    let (_permit, principal) = super::registry_read::admit_pypi(&app, peer.clone(), registry, &headers).await?;
    let policy = app.policy_for(Some(&principal)).ok_or(ApiError::PolicyUnavailable)?;
    if !policy.snapshot.as_ref().is_some_and(|snapshot| snapshot.is_valid_at(app.clock.now_utc_micros())) {
        return Err(ApiError::PolicyUnavailable);
    }
    let rendered = pypi::index(&app, Some(&principal), &negotiate(&headers)?).await?;
    super::registry_read::recheck_pypi(&app, peer, registry, &headers).await?;
    Ok(respond(rendered))
}

pub async fn selected_artifact(
    State(app): State<Arc<App>>,
    peer: Option<axum::Extension<crate::managed::certificates::VerifiedPeer>>,
    method: axum::http::Method,
    headers: HeaderMap,
    Path((registry, reference, filename)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let registry = super::registry_read::registry_id(&registry)?;
    let (permit, principal) = super::registry_read::admit_pypi(&app, peer.clone(), registry, &headers).await?;
    let id = crate::store::rows::ReferenceId::parse_hex(&reference)
        .map_err(|_| ApiError::InvalidInput("a reference id is 64 hexadecimal characters"))?;
    let range = headers.get(header::RANGE).and_then(|value| value.to_str().ok());
    let response = crate::artifacts::serve_artifact_in(
        &app, Some(&principal), crate::policy::Ecosystem::PyPi, registry.0,
        id, &filename, &method, range,
    ).await?;
    let current = super::registry_read::recheck_pypi(&app, peer, registry, &headers).await?;
    if current.policy.policy.fingerprint != principal.policy.policy.fingerprint
        || current.registry_origin != principal.registry_origin
        || current.registry_trusted != principal.registry_trusted
        || current.registry_private_cidrs != principal.registry_private_cidrs
        || current.registry_read_authorization != principal.registry_read_authorization {
        return Err(ApiError::PolicyUnavailable);
    }
    Ok(response.under(&app.limits, permit).into_response())
}

pub async fn selected_upload(
    State(app): State<Arc<App>>,
    peer: Option<axum::Extension<crate::managed::certificates::VerifiedPeer>>,
    headers: HeaderMap,
    Path(registry): Path<String>,
    body: axum::body::Body,
) -> Result<Response, ApiError> {
    use futures_util::StreamExt;
    use tokio::io::{AsyncSeekExt, AsyncWriteExt};
    let registry = super::registry_read::registry_id(&registry)?;
    let (_permit, principal) = super::registry_read::admit_pypi(&app, peer.clone(), registry, &headers).await?;
    let origin = principal.registry_origin.clone().ok_or(ApiError::NotFound)?;
    let origins = crate::upstream::OriginSet::selected_npm_with_private(origin.clone(), principal.registry_private_cidrs.clone())
        .map_err(|_| ApiError::NotFound)?;
    origins.admit(&origin, crate::upstream::OriginKind::NpmMetadata).map_err(|_| ApiError::NotFound)?;
    let auth = headers.get(header::AUTHORIZATION).and_then(|value| value.to_str().ok())
        .filter(|value| (value.starts_with("Basic ") && value.len() > 6) || (value.starts_with("Bearer ") && value.len() > 7))
        .ok_or(ApiError::Unauthenticated)?.to_owned();
    let content_type = headers.get(header::CONTENT_TYPE).and_then(|value| value.to_str().ok())
        .filter(|value| value.starts_with("multipart/form-data; boundary=") && value.len() <= 256)
        .ok_or(ApiError::InvalidInput("Twine upload requires multipart content type"))?.to_owned();
    let cap = app.config.max_artifact_bytes.get().checked_mul(2)
        .and_then(|limit| limit.checked_add(app.config.max_metadata_bytes.get()))
        .ok_or(ApiError::InvalidInput("upload size limit overflow"))?;
    if headers.get(header::CONTENT_LENGTH).and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok()).is_some_and(|length| length > cap) {
        return Ok(StatusCode::PAYLOAD_TOO_LARGE.into_response());
    }
    let file = tempfile::tempfile_in(&app.config.data_dir).map_err(|_| ApiError::StorageUnusable)?;
    let mut file = tokio::fs::File::from_std(file);
    let mut length = 0u64;
    let mut stream = body.into_data_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| ApiError::InvalidInput("upload is incomplete"))?;
        length = length.saturating_add(chunk.len() as u64);
        if length > cap { return Ok(StatusCode::PAYLOAD_TOO_LARGE.into_response()); }
        file.write_all(&chunk).await.map_err(|_| ApiError::StorageUnusable)?;
    }
    file.flush().await.map_err(|_| ApiError::StorageUnusable)?;
    file.seek(std::io::SeekFrom::Start(0)).await.map_err(|_| ApiError::StorageUnusable)?;
    let current = super::registry_read::recheck_pypi(&app, peer, registry, &headers).await?;
    if current.registry_origin != principal.registry_origin
        || current.registry_private_cidrs != principal.registry_private_cidrs
        || current.policy.policy.fingerprint != principal.policy.policy.fingerprint {
        return Err(ApiError::PolicyUnavailable);
    }
    let result = app.transport.send_action(crate::upstream::ActionRequest {
        url: origin.clone(), origin, private_cidrs: principal.registry_private_cidrs.clone(),
        method: axum::http::Method::POST, authorization: Some(auth), content_type: Some(content_type),
        body: file, body_len: length, max_bytes: app.config.max_metadata_bytes.get(),
    }).await.map_err(|error| match error {
        crate::upstream::UpstreamError::Timeout => ApiError::UpstreamTimeout,
        _ => ApiError::UpstreamFailure,
    })?;
    let status = StatusCode::from_u16(result.status).map_err(|_| ApiError::UpstreamInvalid)?;
    let mut response = (status, result.body).into_response();
    if let Some(content_type) = result.content_type.and_then(|value| value.parse().ok()) {
        response.headers_mut().insert(header::CONTENT_TYPE, content_type);
    }
    Ok(response)
}
