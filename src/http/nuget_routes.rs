//! The NuGet v3 endpoint group. Handlers admit, delegate to `nuget::serve` and map errors only.
//! Standalone and certificate-managed callers use `/nuget/...`; a shared service's selected registry
//! is `/registry/nuget/{registry}/...` (the shared-service middleware rewrites `/nuget/...` into it).
//! A client's package source is `{origin}/nuget/v3/index.json`.
//!
//! A path is parsed once, strictly, before any admission or upstream call: the id is the one lower-case
//! spelling, the version the one normalised lower-case spelling, anything else is a 404 (a second spelling
//! of one package would be a second identity).

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use probation_policy::names::{nuget_version, valid_name};

use crate::App;
use crate::http::error::ApiError;
use crate::managed::certificates::VerifiedPeer;
use crate::nuget::serve::{self, Rendered};

type Peer = Option<axum::Extension<VerifiedPeer>>;

/// What a request path below `/nuget/` names.
#[derive(Debug, PartialEq, Eq)]
pub enum Parsed {
    ServiceIndex,
    FlatIndex(String),
    File(String, String, String),
    RegistrationIndex(String),
    RegistrationLeaf(String, String),
    RegistrationPage(String, String, String),
    Search,
    Autocomplete,
    VulnerabilityIndex,
    VulnerabilityFile(String),
    SignatureIndex(String),
    SignatureCertificate(String),
}

fn id_of(segment: &str) -> Result<String, ApiError> {
    (valid_name(probation_policy::Ecosystem::NuGet, segment)
        && !segment.bytes().any(|b| b.is_ascii_uppercase()))
    .then(|| segment.to_owned())
    .ok_or(ApiError::NotFound)
}

fn version_of(segment: &str) -> Result<String, ApiError> {
    (segment.len() <= serve::MAX_VERSION && nuget_version(segment).as_deref() == Some(segment))
        .then(|| segment.to_owned())
        .ok_or(ApiError::NotFound)
}

/// Parses a path below the registry root. Anything but one canonical spelling of a route is a 404.
pub fn parse(path: &str) -> Result<Parsed, ApiError> {
    let segments: Vec<&str> = path.split('/').collect();
    match segments.as_slice() {
        ["v3", "index.json"] => Ok(Parsed::ServiceIndex),
        ["v3", "query"] => Ok(Parsed::Search),
        ["v3", "autocomplete"] => Ok(Parsed::Autocomplete),
        ["v3-flatcontainer", id, "index.json"] => Ok(Parsed::FlatIndex(id_of(id)?)),
        ["v3-flatcontainer", id, version, file] => Ok(Parsed::File(
            id_of(id)?,
            version_of(version)?,
            (*file).to_owned(),
        )),
        ["v3", "registration", id, "index.json"] => Ok(Parsed::RegistrationIndex(id_of(id)?)),
        ["v3", "registration", id, "page", lower, upper] => {
            let upper = upper.strip_suffix(".json").ok_or(ApiError::NotFound)?;
            Ok(Parsed::RegistrationPage(
                id_of(id)?,
                version_of(lower)?,
                version_of(upper)?,
            ))
        }
        ["v3", "registration", id, leaf] => {
            let version = leaf.strip_suffix(".json").ok_or(ApiError::NotFound)?;
            Ok(Parsed::RegistrationLeaf(id_of(id)?, version_of(version)?))
        }
        ["v3", "vulnerabilities", "index.json"] => Ok(Parsed::VulnerabilityIndex),
        ["v3", "vulnerabilities", file] => match file.strip_suffix(".json") {
            Some(name @ ("base" | "update")) => Ok(Parsed::VulnerabilityFile(name.to_owned())),
            _ => Err(ApiError::NotFound),
        },
        ["v3", "repository-signatures", version, "index.json"]
            if version.len() <= 16 && version.bytes().all(|b| b.is_ascii_digit() || b == b'.') =>
        {
            Ok(Parsed::SignatureIndex((*version).to_owned()))
        }
        ["v3", "repository-signatures", "certificates", file] => {
            let fingerprint = file.strip_suffix(".crt").ok_or(ApiError::NotFound)?;
            Ok(Parsed::SignatureCertificate(fingerprint.to_owned()))
        }
        _ => Err(ApiError::NotFound),
    }
}

/// The public root of the registry a request reads: `{public_url}/nuget/` or the selected one.
fn root(app: &App, registry_id: u64) -> url::Url {
    let mut base = app.config.public_url.clone();
    base.set_path(&if registry_id == 0 {
        "/nuget/".to_owned()
    } else {
        format!("/registry/nuget/{registry_id}/")
    });
    base
}

fn plain(rendered: Rendered) -> Response {
    let mut response = rendered.body.into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(rendered.content_type),
    );
    response
}

fn reads_only(method: &Method) -> Result<(), ApiError> {
    if *method == Method::GET {
        Ok(())
    } else {
        Err(ApiError::MethodNotAllowed)
    }
}

/// A registry's own 401 reaches a NuGet client with the challenge it needs to send its credential.
fn challenge(result: Result<Response, ApiError>) -> Result<Response, ApiError> {
    match result {
        Err(error @ ApiError::UpstreamUnauthenticated) => {
            let mut response = error.into_response();
            response.headers_mut().append(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Basic realm=\"registry\""),
            );
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
    query: Option<&str>,
    permit: tokio::sync::OwnedSemaphorePermit,
) -> Result<Response, ApiError> {
    let root = root(app, registry_id);
    // A document request has one deadline for everything it asks upstream (a file transfer has its own lifetime).
    if !matches!(parsed, Parsed::File(..)) {
        return tokio::time::timeout(
            serve::DOCUMENT_DEADLINE,
            run_document(app, principal, registry_id, parsed, method, query, &root),
        )
        .await
        .unwrap_or(Err(ApiError::UpstreamTimeout));
    }
    match parsed {
        Parsed::File(id, version, file) => {
            let (reference, file) =
                serve::reference_for_file(app, principal, &id, &version, &file, registry_id)
                    .await?;
            let range = headers
                .get(header::RANGE)
                .and_then(|value| value.to_str().ok());
            let response = crate::artifacts::serve_artifact_in(
                app,
                principal,
                crate::policy::Ecosystem::NuGet,
                registry_id,
                reference,
                &file,
                method,
                range,
            )
            .await?;
            Ok(response.under(&app.limits, permit).into_response())
        }
        _ => Err(ApiError::InternalFailure),
    }
}

async fn run_document(
    app: &Arc<App>,
    principal: Option<&crate::managed::Principal>,
    registry_id: u64,
    parsed: Parsed,
    method: &Method,
    query: Option<&str>,
    root: &url::Url,
) -> Result<Response, ApiError> {
    reads_only(method)?;
    let rendered = match parsed {
        Parsed::ServiceIndex => {
            serve::serve_service_index(app, principal, registry_id, root).await?
        }
        Parsed::FlatIndex(id) => serve::serve_flat_index(app, principal, &id, registry_id).await?,
        Parsed::RegistrationIndex(id) => {
            serve::serve_registration_index(app, principal, &id, registry_id, root).await?
        }
        Parsed::RegistrationPage(id, lower, upper) => {
            serve::serve_registration_page(app, principal, &id, &lower, &upper, registry_id, root)
                .await?
        }
        Parsed::RegistrationLeaf(id, version) => {
            serve::serve_registration_leaf(app, principal, &id, &version, registry_id, root).await?
        }
        Parsed::Search => serve::serve_search(app, principal, registry_id, query, root).await?,
        Parsed::Autocomplete => {
            serve::serve_autocomplete(app, principal, registry_id, query).await?
        }
        Parsed::VulnerabilityIndex => {
            serve::serve_vulnerability_index(app, principal, registry_id, root).await?
        }
        Parsed::VulnerabilityFile(name) => {
            serve::serve_vulnerability_file(app, principal, registry_id, &name).await?
        }
        Parsed::SignatureIndex(version) => {
            serve::serve_signature_index(app, principal, registry_id, &version, root).await?
        }
        Parsed::SignatureCertificate(fingerprint) => {
            serve::serve_signature_certificate(app, principal, registry_id, &fingerprint).await?
        }
        Parsed::File(..) => return Err(ApiError::InternalFailure),
    };
    Ok(plain(rendered))
}

/// Only search and autocomplete take a query; every other route is a 404 with one (nothing to forward, nothing
/// to cache differently).
fn query_allowed(parsed: &Parsed, uri: &axum::http::Uri) -> Result<(), ApiError> {
    if uri.query().is_some() && !matches!(parsed, Parsed::Search | Parsed::Autocomplete) {
        return Err(ApiError::NotFound);
    }
    Ok(())
}

/// `GET|HEAD /nuget/{path}` for the standalone and certificate-managed firewall. A response the release gate refuses
/// is admitted again by the shared layer (src/http/readmit.rs).
pub async fn legacy(
    State(app): State<Arc<App>>,
    method: Method,
    headers: HeaderMap,
    uri: axum::http::Uri,
    Path(path): Path<String>,
) -> Result<Response, ApiError> {
    let parsed = parse(&path)?;
    query_allowed(&parsed, &uri)?;
    let (permit, principal) = super::admit(&app, &headers).await?;
    challenge(
        run(
            &app,
            principal.as_ref(),
            0,
            parsed,
            &method,
            &headers,
            uri.query(),
            permit,
        )
        .await,
    )
}

/// `GET|HEAD /registry/nuget/{registry}/{path}`: a selected registry.
pub async fn selected(
    State(app): State<Arc<App>>,
    peer: Peer,
    method: Method,
    headers: HeaderMap,
    uri: axum::http::Uri,
    Path((registry, path)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let parsed = parse(&path)?;
    query_allowed(&parsed, &uri)?;
    let registry_id = super::registry_read::registry_id(&registry)?;
    let (permit, principal) =
        super::registry_read::admit_nuget(&app, peer.clone(), registry_id, &headers).await?;
    let result = run(
        &app,
        Some(&principal),
        registry_id.0,
        parsed,
        &method,
        &headers,
        uri.query(),
        permit,
    )
    .await;
    let response = match challenge(result) {
        Ok(response) if response.status() == StatusCode::UNAUTHORIZED => return Ok(response),
        other => other?,
    };
    let current = super::registry_read::recheck_nuget(&app, peer, registry_id, &headers).await?;
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

// ------------------------------------------------------------------ the publish endpoints (class W)
//
// `dotnet nuget push` (`PUT api/v2/package`, a multipart body, `X-NuGet-ApiKey`), the symbol package push
// (`PUT api/v2/symbolpackage`), unlist (`DELETE api/v2/package/{id}/{version}`) and relist (`POST` the same). They
// are forwarded only with the caller's own credential (the API key header, and the `Authorization` a private feed
// asks for), to the endpoint the registry's own service index names for them, which must lie on the registry's own
// origin (or, for the public registry, on the configured publish host). A write without a credential is refused
// locally with 401 before any admission, permit or lookup.

#[derive(Clone, Copy)]
pub enum Write {
    Push,
    SymbolPush,
    Unlist,
    Relist,
}

fn credential(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty() && value.len() <= 8192)
        .map(str::to_owned)
}

#[allow(clippy::too_many_arguments)]
async fn forward_write(
    app: Arc<App>,
    peer: Peer,
    headers: HeaderMap,
    registry: String,
    method: Method,
    write: Write,
    package: Option<(String, String)>,
    body: axum::body::Body,
) -> Result<Response, ApiError> {
    let api_key = credential(&headers, "x-nuget-apikey");
    let authorization = credential(&headers, "authorization");
    if api_key.is_none() && authorization.is_none() {
        return Err(ApiError::Unauthenticated);
    }
    // Names and versions are checked before anything is asked of the registry.
    if let Some((id, version)) = &package
        && !(valid_name(probation_policy::Ecosystem::NuGet, id)
            && version.len() <= serve::MAX_VERSION
            && nuget_version(version).is_some())
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
        super::registry_read::admit_nuget(&app, peer.clone(), registry, &headers).await?;
    // This request carries the caller's credential: nothing it reads may enter a shared cache (C1028).
    super::logging::record_request_scoped();
    let tail: Vec<&str> = package
        .as_ref()
        .map(|(id, version)| vec![id.as_str(), version.as_str()])
        .unwrap_or_default();
    let target = serve::publish_target(
        &app,
        &principal,
        registry.0,
        matches!(write, Write::SymbolPush),
        &tail,
    )
    .await?;
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
    let current = super::registry_read::recheck_nuget(&app, peer, registry, &headers).await?;
    if current.registry_origin != principal.registry_origin
        || current.registry_private_cidrs != principal.registry_private_cidrs
        || current.policy.policy.fingerprint != principal.policy.policy.fingerprint
    {
        return Err(ApiError::PolicyUnavailable);
    }
    let result = app
        .transport
        .send_action(crate::upstream::ActionRequest {
            url: target.url,
            origin: target.origin,
            private_cidrs: principal.registry_private_cidrs.clone(),
            method,
            authorization,
            content_type,
            otp: None,
            api_key,
            body: file,
            body_len: length,
            max_bytes: app.config.max_metadata_bytes.get(),
        })
        .await
        .map_err(|error| match error {
            crate::upstream::UpstreamError::Timeout => ApiError::UpstreamTimeout,
            _ => ApiError::UpstreamFailure,
        })?;
    // Only the answers a publish endpoint gives are relayed, as plain text or JSON that no browser is asked to sniff:
    // the registry's own HTML or script cannot be served from this origin.
    let status = StatusCode::from_u16(result.status)
        .ok()
        .filter(|status| {
            matches!(
                status.as_u16(),
                200 | 201 | 202 | 204 | 400 | 401 | 403 | 404 | 409 | 413 | 422 | 429
            )
        })
        .ok_or(ApiError::UpstreamInvalid)?;
    let mut response = (status, result.body).into_response();
    let kind = match result.content_type.as_deref().map(|value| {
        value
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase()
    }) {
        Some(kind) if kind == "application/json" => "application/json",
        _ => "text/plain; charset=utf-8",
    };
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(kind));
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    Ok(response)
}

type Body = axum::body::Body;

/// `PUT /registry/nuget/{registry}/api/v2/package` (`dotnet nuget push`).
pub async fn selected_push(
    State(app): State<Arc<App>>,
    peer: Peer,
    headers: HeaderMap,
    Path(registry): Path<String>,
    body: Body,
) -> Result<Response, ApiError> {
    challenge(
        forward_write(
            app,
            peer,
            headers,
            registry,
            Method::PUT,
            Write::Push,
            None,
            body,
        )
        .await,
    )
}

/// `PUT /registry/nuget/{registry}/api/v2/symbolpackage` (`dotnet nuget push x.snupkg`).
pub async fn selected_symbol_push(
    State(app): State<Arc<App>>,
    peer: Peer,
    headers: HeaderMap,
    Path(registry): Path<String>,
    body: Body,
) -> Result<Response, ApiError> {
    challenge(
        forward_write(
            app,
            peer,
            headers,
            registry,
            Method::PUT,
            Write::SymbolPush,
            None,
            body,
        )
        .await,
    )
}

/// `DELETE` (unlist, `dotnet nuget delete`) and `POST` (relist) of `.../api/v2/package/{id}/{version}`.
pub async fn selected_package_action(
    State(app): State<Arc<App>>,
    peer: Peer,
    method: Method,
    headers: HeaderMap,
    Path((registry, id, version)): Path<(String, String, String)>,
    body: Body,
) -> Result<Response, ApiError> {
    let write = if method == Method::DELETE {
        Write::Unlist
    } else {
        Write::Relist
    };
    challenge(
        forward_write(
            app,
            peer,
            headers,
            registry,
            method,
            write,
            Some((id, version)),
            body,
        )
        .await,
    )
}
