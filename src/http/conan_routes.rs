//! The Conan 2 remote endpoint group. Handlers admit, delegate to `conan::serve` and map errors only. Standalone and
//! certificate-managed callers use `/conan/...`; a shared service's selected registry is `/registry/conan/{registry}/...`
//! (the shared-service middleware rewrites `/conan/...` into it). A client's remote URL is `{origin}/conan` (the client appends
//! `/v2/...`) or `{origin}/registry/conan/{registry}`.
//!
//! A path is parsed once, strictly, before any admission or upstream call (src/conan/coords.rs): a reference, a revision, a package
//! id and a file name have one spelling, anything else is a 404. Nothing of the Conan 1 API (`v1/...`, `download_urls`,
//! `upload_urls`) is routed: a client cannot be led to a location this firewall does not serve.
//!
//! Writes (class W, shared service only): `conan upload` is a `PUT` of each file of a recipe or package revision, and an operator's
//! clean-up is a `DELETE`. They are forwarded with the caller's own `Authorization` (the token a Conan login returned) to the
//! registry's own origin (or, for the public registry, the configured `conan_publish_url`), never with any credential of this
//! service. A write without a credential is answered with a 401 challenge and nothing is read or asked.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::App;
use crate::conan::coords::{self, Parsed};
use crate::conan::serve::{self, Parent, Rendered, UnitRef};
use crate::http::error::ApiError;
use crate::managed::certificates::VerifiedPeer;

type Peer = Option<axum::Extension<VerifiedPeer>>;

const CHALLENGE: &str = "Bearer realm=\"conan\"";

fn plain(rendered: Rendered) -> Response {
    let mut response = rendered.body.into_response();
    response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static(rendered.content_type));
    if rendered.withheld > 0 {
        response.headers_mut().insert("x-probation-withheld", HeaderValue::from(rendered.withheld));
    }
    response
}

fn reads_only(method: &Method) -> Result<(), ApiError> {
    if matches!(*method, Method::GET | Method::HEAD) { Ok(()) } else { Err(ApiError::MethodNotAllowed) }
}

/// A remote's own 401 reaches the client with the challenge it needs to log in.
fn challenge(result: Result<Response, ApiError>) -> Result<Response, ApiError> {
    match result {
        Err(error @ ApiError::UpstreamUnauthenticated) => {
            let mut response = error.into_response();
            response.headers_mut().append(header::WWW_AUTHENTICATE, HeaderValue::from_static(CHALLENGE));
            Ok(response)
        }
        other => other,
    }
}

/// Every document request has one deadline for everything it asks upstream.
async fn within<F: std::future::Future<Output = Result<Rendered, ApiError>>>(work: F) -> Result<Response, ApiError> {
    tokio::time::timeout(serve::DOCUMENT_DEADLINE, work).await.unwrap_or(Err(ApiError::UpstreamTimeout)).map(plain)
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
    // Who a search belongs to, for its shares (the account, or the client address and credential, as for an upload); none for a standalone firewall.
    let owner = principal.map(|principal| super::spool::owner_of(app, principal, headers).key);
    let file = |unit: UnitRef, file: String| async move {
        let (reference, name) = serve::reference_for_file(app, principal, &unit, &file, registry_id).await?;
        let range = headers.get(header::RANGE).and_then(|value| value.to_str().ok());
        let response = crate::artifacts::serve_artifact_in(app, principal, crate::policy::Ecosystem::Conan, registry_id, reference, &name, method, range).await?;
        Ok::<_, ApiError>(response.under(&app.limits, permit).into_response())
    };
    match parsed {
        Parsed::Ping => {
            // Revisions are the one capability this firewall serves (the Conan 2 client needs nothing else).
            let mut response = StatusCode::OK.into_response();
            response.headers_mut().insert("x-conan-server-capabilities", HeaderValue::from_static("revisions"));
            Ok(response)
        }
        Parsed::Authenticate => within(serve::serve_auth(app, principal, registry_id, true)).await,
        Parsed::CheckCredentials => within(serve::serve_auth(app, principal, registry_id, false)).await,
        Parsed::Search { pattern, ignorecase } => within(serve::serve_search(app, principal, registry_id, owner, &pattern, ignorecase)).await,
        Parsed::Latest(rref) => within(serve::serve_revisions(app, principal, registry_id, &Parent::Recipe(rref), true)).await,
        Parsed::Revisions(rref) => within(serve::serve_revisions(app, principal, registry_id, &Parent::Recipe(rref), false)).await,
        Parsed::PackageLatest(package) => within(serve::serve_revisions(app, principal, registry_id, &Parent::Package(package), true)).await,
        Parsed::PackageRevisions(package) => within(serve::serve_revisions(app, principal, registry_id, &Parent::Package(package), false)).await,
        Parsed::RecipeFiles(recipe) => within(serve::serve_files(app, principal, registry_id, &UnitRef::Recipe(recipe))).await,
        Parsed::PackageFiles(package) => within(serve::serve_files(app, principal, registry_id, &UnitRef::Package(package))).await,
        Parsed::PackageSearch(recipe) => within(serve::serve_package_search(app, principal, registry_id, owner, &recipe)).await,
        Parsed::RecipeFile(recipe, name) => file(UnitRef::Recipe(recipe), name).await,
        Parsed::PackageFile(package, name) => file(UnitRef::Package(package), name).await,
        // A directory of the layout is no document: it is only the target of a clean-up.
        Parsed::Directory(_) => Err(ApiError::NotFound),
    }
}

fn parse(path: &str, uri: &axum::http::Uri) -> Result<Parsed, ApiError> {
    coords::parse(path, uri.query()).ok_or(ApiError::NotFound)
}

/// `GET|HEAD /conan/{path}` for the standalone and certificate-managed firewall. A response the release gate refuses is
/// admitted again by the shared layer (src/http/readmit.rs).
pub async fn legacy(State(app): State<Arc<App>>, method: Method, headers: HeaderMap, uri: axum::http::Uri, Path(path): Path<String>) -> Result<Response, ApiError> {
    let parsed = parse(&path, &uri)?;
    let (permit, principal) = super::admit(&app, &headers).await?;
    // A certificate-managed firewall admits a request by the API key it carries (`conan remote login <remote> <user> -p <key>`): the
    // login is answered here with that key as the token the client sends from then on, and a credential check is its admission.
    if principal.is_some() && matches!(parsed, Parsed::Authenticate | Parsed::CheckCredentials) {
        let presented = credential(&headers).and_then(|value| HeaderValue::from_str(&value).ok());
        let key = presented.as_ref().and_then(crate::managed::bearer_or_basic_password).ok_or(ApiError::Unauthenticated)?;
        let body = if parsed == Parsed::Authenticate { key } else { String::new() };
        return Ok(plain(Rendered { body: body.into(), content_type: "text/plain; charset=utf-8", withheld: 0 }));
    }
    let search = matches!(parsed, Parsed::Search { .. } | Parsed::PackageSearch(_));
    let response = run(&app, principal.as_ref(), 0, parsed, &method, &headers, permit).await?;
    // A search judges for a long time: the answer stands only if the key's policy is still the one it was decided under (the other documents are
    // answered in moments, and a file is gated at delivery). A change is admitted again by the shared layer, under the new policy.
    if let (true, Some(principal)) = (search, principal.as_ref()) {
        let (Some(managed), Some(peer)) = (app.managed(), super::logging::peer()) else { return Err(ApiError::NotReady) };
        // (without charging the account's rate a second time)
        let current = managed.reauthenticate(&headers, peer).await.map_err(|_| ApiError::PolicyUnavailable)?;
        if current.policy.policy.fingerprint != principal.policy.policy.fingerprint {
            return Ok(super::readmit::refusal());
        }
    }
    Ok(response)
}

/// `GET|HEAD /registry/conan/{registry}/{path}`: a selected registry.
pub async fn selected(State(app): State<Arc<App>>, peer: Peer, method: Method, headers: HeaderMap, uri: axum::http::Uri, Path((registry, path)): Path<(String, String)>, body: axum::body::Body) -> Result<Response, ApiError> {
    if matches!(method, Method::PUT | Method::DELETE) {
        return challenge(forward_write(app, peer, headers, uri, registry, path, method, body).await);
    }
    let parsed = parse(&path, &uri)?;
    let registry_id = super::registry_read::registry_id(&registry)?;
    let (permit, principal) = super::registry_read::admit_conan(&app, peer.clone(), registry_id, &headers).await?;
    let response = match challenge(run(&app, Some(&principal), registry_id.0, parsed, &method, &headers, permit).await) {
        Ok(response) if response.status() == StatusCode::UNAUTHORIZED => return Ok(response),
        other => other?,
    };
    let current = super::registry_read::recheck_conan(&app, peer, registry_id, &headers).await?;
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

// ------------------------------------------------------------------ the upload endpoints (class W)

fn credential(headers: &HeaderMap) -> Option<String> {
    headers.get(header::AUTHORIZATION).and_then(|value| value.to_str().ok()).filter(|value| !value.trim().is_empty() && value.len() <= 8192).map(str::to_owned)
}

fn unauthorized() -> Response {
    let mut response = StatusCode::UNAUTHORIZED.into_response();
    response.headers_mut().insert(header::WWW_AUTHENTICATE, HeaderValue::from_static(CHALLENGE));
    response
}

/// The segments below the remote root of a write's target: a file (`PUT` or `DELETE`) or a directory of the layout (`DELETE`).
fn write_segments(parsed: Parsed, method: &Method) -> Result<(Vec<String>, Vec<UnitRef>), ApiError> {
    let files = |mut below: Vec<String>, file: String| {
        below.push("files".to_owned());
        below.extend(file.split('/').map(str::to_owned));
        coords::upstream_segments(&below)
    };
    match parsed {
        Parsed::RecipeFile(recipe, file) => Ok((files(coords::recipe_segments(&recipe), file), vec![UnitRef::Recipe(recipe)])),
        Parsed::PackageFile(package, file) => {
            let recipe = UnitRef::Recipe(package.package.recipe.clone());
            Ok((files(coords::package_rev_segments(&package), file), vec![UnitRef::Package(package), recipe]))
        }
        Parsed::Directory(below) if *method == Method::DELETE => Ok((coords::upstream_segments(&below), Vec::new())),
        _ => Err(ApiError::NotFound),
    }
}

#[allow(clippy::too_many_arguments)]
async fn forward_write(app: Arc<App>, peer: Peer, headers: HeaderMap, uri: axum::http::Uri, registry: String, path: String, method: Method, body: axum::body::Body) -> Result<Response, ApiError> {
    // The client sends its token only on a challenge-less request it already holds one for: without one, the challenge comes first.
    let Some(authorization) = credential(&headers) else { return Ok(unauthorized()) };
    // The firewall's own key is never an upload credential: it is refused here, not forwarded to a registry.
    if HeaderValue::from_str(&authorization).ok().and_then(|value| crate::managed::bearer_or_basic_password(&value)).is_some() {
        return Ok((StatusCode::FORBIDDEN, "a firewall key is not a registry credential").into_response());
    }
    let (segments, units) = write_segments(parse(&path, &uri)?, &method)?;
    let cap = app.config.max_artifact_bytes.get().saturating_mul(2).max(app.config.max_artifact_bytes.get());
    let declared = headers.get(header::CONTENT_LENGTH).and_then(|value| value.to_str().ok()).and_then(|value| value.parse::<u64>().ok());
    if declared.is_some_and(|length| length > cap) {
        return Ok(StatusCode::PAYLOAD_TOO_LARGE.into_response());
    }
    let registry = super::registry_read::registry_id(&registry)?;
    let (_permit, principal) = super::registry_read::admit_conan(&app, peer.clone(), registry, &headers).await?;
    // This request carries the caller's credential: nothing it reads may enter a shared cache (C1028).
    super::logging::record_request_scoped();
    let target = serve::publish_target(&app, &principal, &segments)?;
    let content_type = headers.get(header::CONTENT_TYPE).and_then(|value| value.to_str().ok()).filter(|value| value.len() <= 256).map(str::to_owned);
    let super::spool::Spooled::Body(spool) = super::spool::spool(&app, super::spool::owner_of(&app, &principal, &headers), declared, cap, body).await? else {
        return Ok(StatusCode::PAYLOAD_TOO_LARGE.into_response());
    };
    // The spool's place and bytes are held until this request is done with the file.
    let (file, length) = (spool.file, spool.length);
    let current = super::registry_read::recheck_conan(&app, peer, registry, &headers).await?;
    if current.registry_origin != principal.registry_origin || current.registry_private_cidrs != principal.registry_private_cidrs || current.policy.policy.fingerprint != principal.policy.policy.fingerprint {
        return Err(ApiError::PolicyUnavailable);
    }
    let (method_was_put, credential_used) = (method == Method::PUT, authorization.clone());
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
    // Only the answers an upload endpoint gives are relayed, as plain text that no browser is asked to sniff.
    let status = StatusCode::from_u16(result.status).ok().filter(|status| matches!(status.as_u16(), 200 | 201 | 202 | 204 | 400 | 401 | 403 | 404 | 405 | 409 | 413 | 422 | 429)).ok_or(ApiError::UpstreamInvalid)?;
    if method_was_put && status.is_success() {
        for unit in &units {
            serve::note_upload(&app, &credential_used, registry.0, unit);
        }
    }
    let mut response = (status, result.body).into_response();
    response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain; charset=utf-8"));
    response.headers_mut().insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    if status == StatusCode::UNAUTHORIZED {
        response.headers_mut().insert(header::WWW_AUTHENTICATE, HeaderValue::from_static(CHALLENGE));
    }
    Ok(response)
}
