//! The Cargo sparse registry endpoint group. Handlers admit, delegate to `cargo_registry::serve`
//! and map errors only. Standalone and certificate-managed callers use `/cargo/...`; a shared
//! service's selected registry is `/registry/cargo/{registry}/...` (the shared-service
//! middleware rewrites `/cargo/...` into it). A client points `sparse+{origin}/cargo/` here.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::App;
use crate::cargo_registry::index;
use crate::cargo_registry::serve::{self, Rendered};
use crate::http::error::ApiError;
use crate::managed::certificates::VerifiedPeer;

type Peer = Option<axum::Extension<VerifiedPeer>>;

/// The public root of the registry a request reads: `{public_url}/cargo/` or the selected one.
fn root(app: &App, registry_id: u64) -> url::Url {
    let mut base = app.config.public_url.clone();
    base.set_path(&if registry_id == 0 {
        "/cargo/".to_owned()
    } else {
        format!("/registry/cargo/{registry_id}/")
    });
    base
}

fn respond(rendered: Rendered, headers: &HeaderMap) -> Response {
    let mut response = if let Some(etag) = &rendered.etag
        && matches_etag(headers, etag)
    {
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        rendered.body.to_vec().into_response()
    };
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(rendered.content_type),
    );
    if let Some(etag) = rendered
        .etag
        .as_deref()
        .and_then(|etag| HeaderValue::from_str(etag).ok())
    {
        response.headers_mut().insert(header::ETAG, etag);
    }
    response
}

/// `If-None-Match` names the validator of the body this request would get (strong or weak form).
fn matches_etag(headers: &HeaderMap, etag: &str) -> bool {
    headers
        .get_all(header::IF_NONE_MATCH)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|candidate| candidate.trim().trim_start_matches("W/") == etag)
}

#[derive(Clone, Copy)]
enum Route<'a> {
    Config,
    Index(&'a str),
}

async fn run(
    app: &Arc<App>,
    principal: Option<&crate::managed::Principal>,
    route: Route<'_>,
    registry_id: u64,
) -> Result<Rendered, ApiError> {
    match route {
        Route::Config => {
            serve::serve_config(app, principal, registry_id, &root(app, registry_id)).await
        }
        Route::Index(name) => serve::serve_index(app, principal, name, registry_id).await,
    }
}

async fn metadata(
    app: Arc<App>,
    headers: HeaderMap,
    route: Route<'_>,
) -> Result<Response, ApiError> {
    let (_permit, principal) = super::admit(&app, &headers).await?;
    let rendered = run(&app, principal.as_ref(), route, 0).await?;
    Ok(respond(rendered, &headers))
}

async fn selected_metadata(
    app: Arc<App>,
    peer: Peer,
    headers: HeaderMap,
    registry: &str,
    route: Route<'_>,
) -> Result<Response, ApiError> {
    let id = registry.parse::<u64>().unwrap_or(0);
    let result = selected_metadata_inner(Arc::clone(&app), peer, headers, registry, route).await;
    challenge(&app, id, result)
}

async fn selected_metadata_inner(
    app: Arc<App>,
    peer: Peer,
    headers: HeaderMap,
    registry: &str,
    route: Route<'_>,
) -> Result<Response, ApiError> {
    let registry = super::registry_read::registry_id(registry)?;
    let (_permit, principal) =
        super::registry_read::admit_cargo(&app, peer.clone(), registry, &headers).await?;
    let rendered = run(&app, Some(&principal), route, registry.0).await?;
    super::registry_read::recheck_cargo(&app, peer, registry, &headers).await?;
    Ok(respond(rendered, &headers))
}

/// An index path the sparse layout would build for a name, else 404 before any upstream call.
fn name_of(segments: &[&str]) -> Result<String, ApiError> {
    index::name_of_path(segments).ok_or(ApiError::NotFound)
}

/// A `401` also carries Cargo's own challenge, the header that makes `cargo` fetch its token
/// and retry (a registry answering 401 without it is reported to the user as unusable). It follows
/// both a refused key (managed key route) and a registry's own 401 (shared service), and names the
/// public root of the registry the request selected.
fn challenge(
    app: &App,
    registry_id: u64,
    result: Result<Response, ApiError>,
) -> Result<Response, ApiError> {
    match result {
        Err(error @ (ApiError::Unauthenticated | ApiError::UpstreamUnauthenticated)) => {
            let mut response = error.into_response();
            let value = format!("Cargo login_url=\"{}\"", root(app, registry_id));
            if let Ok(value) = HeaderValue::from_str(&value) {
                response
                    .headers_mut()
                    .append(header::WWW_AUTHENTICATE, value);
            }
            Ok(response)
        }
        other => other,
    }
}

pub async fn config(State(app): State<Arc<App>>, headers: HeaderMap) -> Result<Response, ApiError> {
    let result = metadata(Arc::clone(&app), headers, Route::Config).await;
    challenge(&app, 0, result)
}
pub async fn index_1(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Result<Response, ApiError> {
    let route = Route::Index(&name_of(&["1", &name])?);
    let result = metadata(Arc::clone(&app), headers, route).await;
    challenge(&app, 0, result)
}
pub async fn index_2(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Result<Response, ApiError> {
    let route = Route::Index(&name_of(&["2", &name])?);
    let result = metadata(Arc::clone(&app), headers, route).await;
    challenge(&app, 0, result)
}
pub async fn index_3(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path((a, name)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let route = Route::Index(&name_of(&["3", &a, &name])?);
    let result = metadata(Arc::clone(&app), headers, route).await;
    challenge(&app, 0, result)
}
pub async fn index_4(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path((ab, cd, name)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let route = Route::Index(&name_of(&[&ab, &cd, &name])?);
    let result = metadata(Arc::clone(&app), headers, route).await;
    challenge(&app, 0, result)
}

pub async fn selected_config(
    State(app): State<Arc<App>>,
    peer: Peer,
    headers: HeaderMap,
    Path(registry): Path<String>,
) -> Result<Response, ApiError> {
    selected_metadata(app, peer, headers, &registry, Route::Config).await
}
pub async fn selected_index_1(
    State(app): State<Arc<App>>,
    peer: Peer,
    headers: HeaderMap,
    Path((registry, name)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    selected_metadata(
        app,
        peer,
        headers,
        &registry,
        Route::Index(&name_of(&["1", &name])?),
    )
    .await
}
pub async fn selected_index_2(
    State(app): State<Arc<App>>,
    peer: Peer,
    headers: HeaderMap,
    Path((registry, name)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    selected_metadata(
        app,
        peer,
        headers,
        &registry,
        Route::Index(&name_of(&["2", &name])?),
    )
    .await
}
pub async fn selected_index_3(
    State(app): State<Arc<App>>,
    peer: Peer,
    headers: HeaderMap,
    Path((registry, a, name)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    selected_metadata(
        app,
        peer,
        headers,
        &registry,
        Route::Index(&name_of(&["3", &a, &name])?),
    )
    .await
}
pub async fn selected_index_4(
    State(app): State<Arc<App>>,
    peer: Peer,
    headers: HeaderMap,
    Path((registry, ab, cd, name)): Path<(String, String, String, String)>,
) -> Result<Response, ApiError> {
    selected_metadata(
        app,
        peer,
        headers,
        &registry,
        Route::Index(&name_of(&[&ab, &cd, &name])?),
    )
    .await
}

/// `GET|HEAD /cargo/crates/{crate}/{version}/download`.
pub async fn download(
    State(app): State<Arc<App>>,
    method: Method,
    headers: HeaderMap,
    Path((name, version)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let result = download_inner(Arc::clone(&app), method, headers, name, version).await;
    challenge(&app, 0, result)
}

async fn download_inner(
    app: Arc<App>,
    method: Method,
    headers: HeaderMap,
    name: String,
    version: String,
) -> Result<Response, ApiError> {
    let (permit, principal) = super::admit(&app, &headers).await?;
    let id = serve::reference_for_download(&app, principal.as_ref(), &name, &version, 0).await?;
    deliver(
        &app,
        principal.as_ref(),
        0,
        id,
        &name,
        &version,
        &method,
        &headers,
        permit,
    )
    .await
}

pub async fn selected_download(
    State(app): State<Arc<App>>,
    peer: Peer,
    method: Method,
    headers: HeaderMap,
    Path((registry, name, version)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let id = registry.parse::<u64>().unwrap_or(0);
    let result = selected_download_inner(
        Arc::clone(&app),
        peer,
        method,
        headers,
        registry,
        name,
        version,
    )
    .await;
    challenge(&app, id, result)
}

async fn selected_download_inner(
    app: Arc<App>,
    peer: Peer,
    method: Method,
    headers: HeaderMap,
    registry: String,
    name: String,
    version: String,
) -> Result<Response, ApiError> {
    let registry = super::registry_read::registry_id(&registry)?;
    let (permit, principal) =
        super::registry_read::admit_cargo(&app, peer.clone(), registry, &headers).await?;
    let id =
        serve::reference_for_download(&app, Some(&principal), &name, &version, registry.0).await?;
    let response = deliver(
        &app,
        Some(&principal),
        registry.0,
        id,
        &name,
        &version,
        &method,
        &headers,
        permit,
    )
    .await?;
    let current = super::registry_read::recheck_cargo(&app, peer, registry, &headers).await?;
    if current.policy.policy.fingerprint != principal.policy.policy.fingerprint
        || current.registry_origin != principal.registry_origin
        || current.registry_trusted != principal.registry_trusted
        || current.registry_private_cidrs != principal.registry_private_cidrs
        || current.registry_archive_origin != principal.registry_archive_origin
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
    id: crate::store::rows::ReferenceId,
    name: &str,
    version: &str,
    method: &Method,
    headers: &HeaderMap,
    permit: tokio::sync::OwnedSemaphorePermit,
) -> Result<Response, ApiError> {
    let range = headers
        .get(header::RANGE)
        .and_then(|value| value.to_str().ok());
    let file = format!("{name}-{version}.crate");
    let response = crate::artifacts::serve_artifact_in(
        app,
        principal,
        crate::policy::Ecosystem::Cargo,
        registry_id,
        id,
        &file,
        method,
        range,
    )
    .await?;
    Ok(response.under(&app.limits, permit).into_response())
}

// ------------------------------------------------------------------ the registry's API (writes and reads)
//
// Parity with `rubygems_routes::forward_write` and PyPI's upload: class W of the shared service.
// `cargo publish`, `yank`, `unyank` and `owner` are forwarded only with the caller's own token (Cargo
// sends it bare in `Authorization`) to the API root the registry's own `config.json` names, which must
// be the registry's origin (or, for the public pair, index.crates.io's `https://crates.io`); a write
// without a token is refused locally with 401 before any lookup. The owner list and search are reads:
// forwarded with whatever credential the caller sent, never cached.

/// The API root a registry's `config.json` names, when it is the registry's own: the same scheme, host
/// and port as `registry`, or crates.io's API host for crates.io's index host.
fn own_api_root(registry: &url::Url, api: &str) -> Option<url::Url> {
    let api = url::Url::parse(api).ok()?;
    let same = api.scheme() == registry.scheme()
        && api.host_str() == registry.host_str()
        && api.port_or_known_default() == registry.port_or_known_default();
    let public_pair = registry.scheme() == "https"
        && registry.host_str() == Some("index.crates.io")
        && api.scheme() == "https"
        && api.host_str() == Some("crates.io")
        && api.port_or_known_default() == Some(443);
    // The path is pinned too: the API root and the registry's own path are nested (equal, one below the
    // other: Artifactory's `.../repo` is above `.../repo/index`), so the token cannot be steered to an
    // unrelated path of the registry's host. The public pair is two different hosts and needs none.
    let nested = public_pair || {
        let (own, theirs) = (
            registry.path().trim_end_matches('/'),
            api.path().trim_end_matches('/'),
        );
        let under = |inner: &str, outer: &str| {
            outer.is_empty() || inner == outer || inner.starts_with(&format!("{outer}/"))
        };
        under(own, theirs) || under(theirs, own)
    };
    ((same || public_pair)
        && nested
        && api.username().is_empty()
        && api.password().is_none()
        && api.query().is_none()
        && api.fragment().is_none())
    .then_some(api)
}

/// The search keys of crates.io's `GET /api/v1/crates` that are passed on; any other is dropped.
const SEARCH_KEYS: &[&str] = &[
    "q", "per_page", "page", "sort", "category", "keyword", "letter",
];

#[allow(clippy::too_many_arguments)]
async fn forward_api(
    app: Arc<App>,
    peer: Peer,
    headers: HeaderMap,
    registry: String,
    method: Method,
    segments: Vec<String>,
    query: Option<String>,
    body: axum::body::Body,
    write: bool,
) -> Result<Response, ApiError> {
    let credential = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty() && value.len() <= 8192)
        .map(str::to_owned);
    // A write without the caller's own token is refused locally before admission, a permit or any lookup.
    if write && credential.is_none() {
        return Err(ApiError::Unauthenticated);
    }
    // Names and versions are checked before anything is asked of the registry.
    if let Some(name) = segments.get(3).filter(|name| *name != "new")
        && !index::valid_crate_name(name)
    {
        return Err(ApiError::NotFound);
    }
    if segments
        .last()
        .is_some_and(|last| last == "yank" || last == "unyank")
        && !segments.get(4).is_some_and(|version| {
            version.len() <= serve::MAX_VERSION && semver::Version::parse(version).is_ok()
        })
    {
        return Err(ApiError::NotFound);
    }
    let cap = app
        .config
        .max_artifact_bytes
        .get()
        .saturating_mul(2)
        .max(app.config.max_artifact_bytes.get());
    if headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|length| length > cap)
    {
        return Ok(StatusCode::PAYLOAD_TOO_LARGE.into_response());
    }
    let registry = super::registry_read::registry_id(&registry)?;
    let (_permit, principal) =
        super::registry_read::admit_cargo(&app, peer.clone(), registry, &headers).await?;
    let origin = principal
        .registry_origin
        .clone()
        .ok_or(ApiError::NotFound)?;
    // This request carries the caller's credential: nothing it reads may enter a shared cache (C1028).
    if credential.is_some() {
        super::logging::record_request_scoped();
    }
    let origins = crate::upstream::OriginSet::selected_npm_with_private(
        origin.clone(),
        principal.registry_private_cidrs.clone(),
    )
    .map_err(|_| ApiError::NotFound)?;
    let config_url = origins
        .url_for(crate::upstream::OriginKind::NpmMetadata, &["config.json"])
        .map_err(|_| ApiError::NotFound)?;
    let fetched = app
        .transport
        .fetch_metadata(crate::upstream::MetadataRequest {
            url: config_url,
            origin: Some(origin.clone()),
            private_cidrs: principal.registry_private_cidrs.clone(),
            read_authorization: credential
                .clone()
                .or_else(|| principal.registry_read_authorization.clone()),
            accept: "application/json",
            validators: None,
            max_bytes: (64u64 << 10).min(app.config.max_metadata_bytes.get()),
        })
        .await;
    app.upstreams
        .record_upstream(crate::managed::report::Call::Cargo, &fetched);
    let config = match fetched {
        Ok(crate::upstream::MetadataResponse::Fresh { body, .. }) => {
            index::parse_config(&body).ok_or(ApiError::UpstreamInvalid)?
        }
        Err(crate::upstream::UpstreamError::Timeout) => return Err(ApiError::UpstreamTimeout),
        _ => return Err(ApiError::UpstreamFailure),
    };
    let api = config.api.as_deref().ok_or(ApiError::NotFound)?;
    let root = own_api_root(&origin, api).ok_or_else(|| {
        tracing::warn!("the registry's config.json names an API root outside its own origin");
        ApiError::UpstreamInvalid
    })?;
    let mut url = root.clone();
    url.path_segments_mut()
        .map_err(|()| ApiError::UpstreamInvalid)?
        .pop_if_empty()
        .extend(&segments);
    if let Some(query) = query.as_deref().filter(|query| query.len() <= 1024) {
        let kept: Vec<(String, String)> = url::form_urlencoded::parse(query.as_bytes())
            .filter(|(key, _)| SEARCH_KEYS.contains(&key.as_ref()))
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect();
        if !kept.is_empty() {
            url.query_pairs_mut().extend_pairs(kept);
        }
    }
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .filter(|value| value.len() <= 256)
        .map(str::to_owned);
    let super::spool::Spooled::Body(spool) = super::spool::spool(
        &app,
        super::spool::owner_of(&app, &principal, &headers),
        headers
            .get(header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok()),
        cap,
        body,
    )
    .await?
    else {
        return Ok(StatusCode::PAYLOAD_TOO_LARGE.into_response());
    };
    // The spool's place and bytes are held until this request is done with the file.
    let (file, length) = (spool.file, spool.length);
    let current = super::registry_read::recheck_cargo(&app, peer, registry, &headers).await?;
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
            origin: root,
            private_cidrs: principal.registry_private_cidrs.clone(),
            method,
            authorization: credential,
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
    let status = StatusCode::from_u16(result.status).map_err(|_| ApiError::UpstreamInvalid)?;
    let mut response = (status, result.body).into_response();
    if let Some(content_type) = result.content_type.and_then(|value| value.parse().ok()) {
        response
            .headers_mut()
            .insert(header::CONTENT_TYPE, content_type);
    }
    Ok(response)
}

type Body = axum::body::Body;

/// `PUT /registry/cargo/{registry}/api/v1/crates/new` (`cargo publish`).
pub async fn selected_publish(
    State(app): State<Arc<App>>,
    peer: Peer,
    headers: HeaderMap,
    Path(registry): Path<String>,
    body: Body,
) -> Result<Response, ApiError> {
    let segments = ["api", "v1", "crates", "new"].map(str::to_owned).to_vec();
    forward_api(
        app,
        peer,
        headers,
        registry,
        Method::PUT,
        segments,
        None,
        body,
        true,
    )
    .await
}

/// `DELETE .../crates/{name}/{version}/yank`.
pub async fn selected_yank(
    State(app): State<Arc<App>>,
    peer: Peer,
    headers: HeaderMap,
    Path((registry, name, version)): Path<(String, String, String)>,
    body: Body,
) -> Result<Response, ApiError> {
    let segments = vec![
        "api".to_owned(),
        "v1".to_owned(),
        "crates".to_owned(),
        name,
        version,
        "yank".to_owned(),
    ];
    forward_api(
        app,
        peer,
        headers,
        registry,
        Method::DELETE,
        segments,
        None,
        body,
        true,
    )
    .await
}

/// `PUT .../crates/{name}/{version}/unyank`.
pub async fn selected_unyank(
    State(app): State<Arc<App>>,
    peer: Peer,
    headers: HeaderMap,
    Path((registry, name, version)): Path<(String, String, String)>,
    body: Body,
) -> Result<Response, ApiError> {
    let segments = vec![
        "api".to_owned(),
        "v1".to_owned(),
        "crates".to_owned(),
        name,
        version,
        "unyank".to_owned(),
    ];
    forward_api(
        app,
        peer,
        headers,
        registry,
        Method::PUT,
        segments,
        None,
        body,
        true,
    )
    .await
}

/// `GET|PUT|DELETE .../crates/{name}/owners`: the owner list is a read, adding and removing are writes.
pub async fn selected_owners(
    State(app): State<Arc<App>>,
    peer: Peer,
    method: Method,
    headers: HeaderMap,
    Path((registry, name)): Path<(String, String)>,
    body: Body,
) -> Result<Response, ApiError> {
    let write = method != Method::GET;
    let segments = vec![
        "api".to_owned(),
        "v1".to_owned(),
        "crates".to_owned(),
        name,
        "owners".to_owned(),
    ];
    forward_api(
        app, peer, headers, registry, method, segments, None, body, write,
    )
    .await
}

/// `GET .../api/v1/crates?q=...`: search, a read.
pub async fn selected_search(
    State(app): State<Arc<App>>,
    peer: Peer,
    headers: HeaderMap,
    Path(registry): Path<String>,
    uri: axum::http::Uri,
    body: Body,
) -> Result<Response, ApiError> {
    let segments = ["api", "v1", "crates"].map(str::to_owned).to_vec();
    forward_api(
        app,
        peer,
        headers,
        registry,
        Method::GET,
        segments,
        uri.query().map(str::to_owned),
        body,
        false,
    )
    .await
}
