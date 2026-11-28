//! The Go module proxy endpoint group (GOPROXY protocol). Handlers admit, delegate to
//! `go_modules::serve` and map errors only. Standalone and certificate-managed callers use
//! `/go/...`; a shared service's selected registry is `/registry/go/{registry}/...` (the
//! shared-service middleware rewrites `/go/...` into it). A client sets `GOPROXY` to the one
//! `{origin}/go/` URL, with no `,direct` or `|` fallback.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, Method, header};
use axum::response::{IntoResponse, Response};

use crate::App;
use crate::go_modules::serve::{self, Kind, Rendered};
use crate::go_modules::{escape, sumdb};
use crate::http::error::ApiError;
use crate::managed::certificates::VerifiedPeer;

type Peer = Option<axum::Extension<VerifiedPeer>>;

/// What a request path below `/go/` names.
#[derive(Debug, PartialEq, Eq)]
pub enum Parsed {
    List(String),
    Latest(String),
    File(String, String, Kind),
    /// `{module}/@v/{rev}.info` for a revision that is not a canonical version (a branch, a commit, `v1`).
    Rev(String, String),
    Sumdb(String),
}

/// Parses the escaped spelling a client sends. Anything but one canonical spelling of a module
/// path and version is a 404 here, before any upstream call (a second spelling of one module
/// would be a second identity).
pub fn parse(path: &str) -> Result<Parsed, ApiError> {
    if let Some(rest) = path.strip_prefix("sumdb/") {
        return Ok(Parsed::Sumdb(rest.to_owned()));
    }
    if let Some(module) = path.strip_suffix("/@latest") {
        return Ok(Parsed::Latest(
            escape::module_of(module).ok_or(ApiError::NotFound)?,
        ));
    }
    let (module, file) = path.rsplit_once("/@v/").ok_or(ApiError::NotFound)?;
    let module = escape::module_of(module).ok_or(ApiError::NotFound)?;
    if file == "list" {
        return Ok(Parsed::List(module));
    }
    let (stem, ext) = file.rsplit_once('.').ok_or(ApiError::NotFound)?;
    let kind = Kind::from_ext(ext).ok_or(ApiError::NotFound)?;
    match escape::version_of(stem) {
        Some(version) => Ok(Parsed::File(module, version, kind)),
        // Only `go get mod@rev`'s `.info` asks for a revision; `.mod` and `.zip` name a resolved version.
        None if kind == Kind::Info => Ok(Parsed::Rev(
            module,
            escape::rev_of(stem).ok_or(ApiError::NotFound)?,
        )),
        None => Err(ApiError::NotFound),
    }
}

fn plain(rendered: Rendered) -> Response {
    let mut response = rendered.body.to_vec().into_response();
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

#[allow(clippy::too_many_arguments)]
async fn deliver(
    app: &Arc<App>,
    principal: Option<&crate::managed::Principal>,
    registry_id: u64,
    id: crate::store::rows::ReferenceId,
    version: &str,
    kind: Kind,
    method: &Method,
    headers: &HeaderMap,
    permit: tokio::sync::OwnedSemaphorePermit,
) -> Result<Response, ApiError> {
    let range = headers
        .get(header::RANGE)
        .and_then(|value| value.to_str().ok());
    let file = serve::file_name(version, kind).ok_or(ApiError::NotFound)?;
    let response = crate::artifacts::serve_artifact_in(
        app,
        principal,
        crate::policy::Ecosystem::Go,
        registry_id,
        id,
        &file,
        method,
        range,
    )
    .await?;
    Ok(response.under(&app.limits, permit).into_response())
}

/// One request, standalone or selected: admission has already given `principal`.
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
    match parsed {
        Parsed::List(module) => {
            reads_only(method)?;
            Ok(plain(
                serve::serve_list(app, principal, &module, registry_id).await?,
            ))
        }
        Parsed::Sumdb(rest) => {
            reads_only(method)?;
            // The checksum record of the public namespace: a registry with a target of its own has none.
            if principal.is_some_and(|p| p.registry_origin.is_some()) {
                return Err(ApiError::NotFound);
            }
            Ok(plain(sumdb::serve(app, &rest).await?))
        }
        Parsed::Latest(module) => {
            let (version, id) =
                serve::latest_reference(app, principal, &module, registry_id).await?;
            deliver(
                app,
                principal,
                registry_id,
                id,
                &version,
                Kind::Info,
                method,
                headers,
                permit,
            )
            .await
        }
        Parsed::Rev(module, rev) => {
            let (version, id) =
                serve::rev_reference(app, principal, &module, &rev, registry_id).await?;
            deliver(
                app,
                principal,
                registry_id,
                id,
                &version,
                Kind::Info,
                method,
                headers,
                permit,
            )
            .await
        }
        Parsed::File(module, version, kind) => {
            let id =
                serve::reference_for_version(app, principal, &module, &version, kind, registry_id)
                    .await?;
            deliver(
                app,
                principal,
                registry_id,
                id,
                &version,
                kind,
                method,
                headers,
                permit,
            )
            .await
        }
    }
}

/// `GET|HEAD /go/{path}` for the standalone and certificate-managed firewall. A response the release gate refuses is
/// admitted again by the shared layer (src/http/readmit.rs).
pub async fn legacy(
    State(app): State<Arc<App>>,
    method: Method,
    headers: HeaderMap,
    Path(path): Path<String>,
) -> Result<Response, ApiError> {
    let parsed = parse(&path)?;
    let (permit, principal) = super::admit(&app, &headers).await?;
    run(
        &app,
        principal.as_ref(),
        0,
        parsed,
        &method,
        &headers,
        permit,
    )
    .await
}

/// `GET|HEAD /registry/go/{registry}/{path}`: a selected registry.
pub async fn selected(
    State(app): State<Arc<App>>,
    peer: Peer,
    method: Method,
    headers: HeaderMap,
    Path((registry, path)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let parsed = parse(&path)?;
    let registry_id = super::registry_read::registry_id(&registry)?;
    let (permit, principal) =
        super::registry_read::admit_go(&app, peer.clone(), registry_id, &headers).await?;
    let response = run(
        &app,
        Some(&principal),
        registry_id.0,
        parsed,
        &method,
        &headers,
        permit,
    )
    .await?;
    let current = super::registry_read::recheck_go(&app, peer, registry_id, &headers).await?;
    // The answer was decided under `principal`; it stands only if nothing it was decided by has changed. A change that
    // keeps the policy's fingerprint (and the registry's own settings) is not one; one that does is admitted again.
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
