//! Common-policy admission and final response handoff for shared service reads.

use crate::{
    App,
    http::{error::ApiError, logging},
    managed::service_policy::{
        AuthorizedResponse, PolicyPublicationGate, PreparedResponse, release_verified_response,
    },
};
use axum::{
    extract::{Request, State},
    http::{Method, Uri},
    middleware::Next,
    response::Response,
};
use probation_policy::{Ecosystem, api::ServicePolicySnapshot};
use std::sync::Arc;

pub async fn respond(
    State(app): State<Arc<App>>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let Some(service) = app.service_policy() else {
        return Ok(next.run(request).await);
    };
    if request.uri().path().starts_with("/health/") {
        return Ok(next.run(request).await);
    }
    let peer = logging::peer().ok_or(ApiError::NotReady)?.to_canonical();
    if !peer.is_loopback()
        && !app
            .config
            .allowed_peer_cidrs
            .iter()
            .any(|cidr| cidr.contains(&peer))
    {
        return Err(ApiError::NetworkNotAllowed(peer));
    }
    if !app.store().is_healthy() {
        return Err(ApiError::StorageUnusable);
    }
    let publication_gate = Arc::clone(&service.publication_gate);
    let generation = publication_gate.generation();
    let policy = service.snapshot().ok_or(ApiError::PolicyUnavailable)?;
    let selected = classify_selected_registry(&request, &policy)?;
    if request.method() == Method::DELETE {
        let route = classify_direct_or_whole_package_delete(&request)?;
        dispatch_npm_delete_route(route)?;
    }
    if !service.admit_request(&policy) {
        return Err(ApiError::TooManyRequests);
    }
    let response = dispatch_selected_registry(request, selected, next).await;
    // A changed generation refuses this prepared request. Replaying it would
    // require a new admission and budget; clients may make a fresh request.
    let prepared = PreparedResponse::new(Arc::clone(&publication_gate), generation, response);
    let authorization = authorize_current_policy(&publication_gate, &prepared)?;
    release_verified_response(authorization).map_err(|_| ApiError::PolicyUnavailable)
}

struct SelectedRegistry {
    uri: Uri,
}

fn classify_selected_registry(
    request: &Request,
    policy: &ServicePolicySnapshot,
) -> Result<SelectedRegistry, ApiError> {
    if request.method() != Method::GET
        && request.method() != Method::HEAD
        && request.method() != Method::DELETE
        && request.method() != Method::POST
        && request.method() != Method::PUT
    {
        return Err(ApiError::MethodNotAllowed);
    }
    let path = request.uri().path();
    let (ecosystem, registry, rest) = if let Some(path) = path.strip_prefix("/registry/") {
        let mut parts = path.splitn(3, '/');
        let ecosystem = match parts.next() {
            Some("npm") => Ecosystem::Npm,
            Some("pypi") => Ecosystem::PyPi,
            _ => return Err(ApiError::NotFound),
        };
        let registry = super::registry_read::registry_id(parts.next().ok_or(ApiError::NotFound)?)?;
        (ecosystem, registry, parts.next().ok_or(ApiError::NotFound)?)
    } else {
        let (ecosystem, rest) = if let Some(rest) = path.strip_prefix("/npm/") {
            (Ecosystem::Npm, rest)
        } else if let Some(rest) = path.strip_prefix("/pypi/") {
            (Ecosystem::PyPi, rest)
        } else {
            return Err(ApiError::NotFound);
        };
        let mut registries = policy
            .registries
            .iter()
            .filter(|registry| registry.ecosystem == ecosystem);
        let registry = registries.next().ok_or(ApiError::NotFound)?.registry;
        if registries.next().is_some() {
            return Err(ApiError::NotFound);
        }
        (ecosystem, registry, rest)
    };
    if !policy
        .registries
        .iter()
        .any(|item| item.registry == registry && item.ecosystem == ecosystem)
    {
        return Err(ApiError::NotFound);
    }
    let audit = ecosystem == Ecosystem::Npm
        && matches!(rest, "-/npm/v1/security/advisories/bulk" | "-/npm/v1/security/audits/quick");
    let pypi_upload = ecosystem == Ecosystem::PyPi
        && path.starts_with("/registry/pypi/")
        && request.method() == Method::POST
        && rest.is_empty();
    if ecosystem == Ecosystem::PyPi
        && !matches!(*request.method(), Method::GET | Method::HEAD)
        && !pypi_upload
    {
        return Err(ApiError::MethodNotAllowed);
    }
    let search = ecosystem == Ecosystem::Npm && rest == "-/v1/search";
    let named_action = ecosystem == Ecosystem::Npm && rest.starts_with("-/")
        && rest != "-/ping" && !search && !audit;
    let write_preflight = ecosystem == Ecosystem::Npm
        && request.method() == Method::GET
        && request.uri().query() == Some("write=true")
        && parse_uri_package(rest).is_ok();
    if request.uri().query().is_some() && !search && !write_preflight && !named_action {
        return Err(ApiError::NotFound);
    }
    // Existing action handlers classify named operations and credentials before I/O.
    // Selected tarball routes carry a package in one segment. Preserve raw scoped
    // lockfile URLs by encoding only the validated package's scope separator.
    let scoped;
    let rest = if ecosystem == Ecosystem::Npm && rest.starts_with('@') {
        if let Some((package, filename)) = rest.split_once("/-/") {
            parse_uri_package(package)?;
            scoped = format!("{}/-/{filename}", package.replace('/', "%2F"));
            scoped.as_str()
        } else {
            rest
        }
    } else {
        rest
    };
    let query = request.uri().query().map(|query| format!("?{query}")).unwrap_or_default();
    let uri = format!("/registry/{}/{}/{rest}{query}", ecosystem.as_tag(), registry.0)
        .parse()
        .map_err(|_| ApiError::NotFound)?;
    Ok(SelectedRegistry { uri })
}

async fn dispatch_selected_registry(
    mut request: Request,
    selected: SelectedRegistry,
    next: Next,
) -> Response {
    *request.uri_mut() = selected.uri;
    next.run(request).await
}

fn authorize_current_policy<'a>(
    gate: &'a PolicyPublicationGate,
    prepared: &'a PreparedResponse,
) -> Result<AuthorizedResponse<'a>, ApiError> {
    gate.authorize_current_policy(prepared)
        .map_err(|_| ApiError::PolicyUnavailable)
}

#[derive(Debug, PartialEq, Eq)]
enum NpmDeleteRoute {
    CanonicalTarball,
    WholePackageRevision,
    VersionReference,
    NamedAction,
}

fn parse_uri_package(raw: &str) -> Result<crate::npm::PackageName, ApiError> {
    let decoded = percent_encoding::percent_decode_str(raw).decode_utf8().map_err(|_| ApiError::NotFound)?;
    crate::npm::PackageName::parse_route(&decoded).map_err(|_| ApiError::NotFound)
}

fn classify_direct_or_whole_package_delete(request: &Request) -> Result<NpmDeleteRoute, ApiError> {
    use super::registry_action::{canonical_tarball, valid_revision};
    if request.method() != Method::DELETE || request.uri().query().is_some() {
        return Err(ApiError::MethodNotAllowed);
    }
    let path = request.uri().path();
    let path = if let Some(path) = path.strip_prefix("/registry/npm/") {
        let (registry, path) = path.split_once('/').ok_or(ApiError::NotFound)?;
        super::registry_read::registry_id(registry)?;
        path
    } else {
        path.strip_prefix("/npm/")
            .ok_or(ApiError::MethodNotAllowed)?
    };
    if path.starts_with("-/") { return Ok(NpmDeleteRoute::NamedAction); }
    if let Some((subject, revision)) = path.rsplit_once("/-rev/") {
        if !valid_revision(revision) {
            return Err(ApiError::NotFound);
        }
        if let Some(reference) = subject.strip_prefix("artifacts/") {
            let (reference, filename) = reference.split_once('/').ok_or(ApiError::NotFound)?;
            crate::store::rows::ReferenceId::parse_hex(reference)
                .map_err(|_| ApiError::NotFound)?;
            if filename.is_empty() || filename.len() > 255 || filename.contains('/') {
                return Err(ApiError::NotFound);
            }
            return Ok(NpmDeleteRoute::VersionReference);
        }
        if let Some((package, filename)) = subject.split_once("/-/") {
            let package = parse_uri_package(package)?;
            return canonical_tarball(package.as_str(), filename)
                .then_some(NpmDeleteRoute::CanonicalTarball)
                .ok_or(ApiError::NotFound);
        }
        parse_uri_package(subject)?;
        return Ok(NpmDeleteRoute::WholePackageRevision);
    }
    let (package, filename) = path.split_once("/-/").ok_or(ApiError::MethodNotAllowed)?;
    let package = parse_uri_package(package)?;
    canonical_tarball(package.as_str(), filename)
        .then_some(NpmDeleteRoute::CanonicalTarball)
        .ok_or(ApiError::NotFound)
}

fn dispatch_npm_delete_route(route: NpmDeleteRoute) -> Result<(), ApiError> {
    match route {
        NpmDeleteRoute::CanonicalTarball => Err(ApiError::MethodNotAllowed),
        NpmDeleteRoute::WholePackageRevision | NpmDeleteRoute::VersionReference
        | NpmDeleteRoute::NamedAction => Ok(()),
    }
}

#[cfg(test)]
mod delete_route_tests {
    use super::*;
    use axum::body::Body;

    #[test]
    fn delete_route_classification_distinguishes_refusal_and_future_actions() {
        let reference = "ab".repeat(32);
        for (path, expected) in [
            (
                "/registry/npm/3/example/-/example-1.0.0.tgz".to_owned(),
                NpmDeleteRoute::CanonicalTarball,
            ),
            (
                "/registry/npm/3/example/-rev/1-old".to_owned(),
                NpmDeleteRoute::WholePackageRevision,
            ),
            (
                format!("/registry/npm/3/artifacts/{reference}/example-1.0.0.tgz/-rev/1-old"),
                NpmDeleteRoute::VersionReference,
            ),
            (
                "/npm/@scope/example/-rev/1-old".to_owned(),
                NpmDeleteRoute::WholePackageRevision,
            ),
        ] {
            let request = Request::builder()
                .method(Method::DELETE)
                .uri(path)
                .body(Body::empty())
                .unwrap();
            assert_eq!(
                classify_direct_or_whole_package_delete(&request).ok(),
                Some(expected),
                "the foundation must distinguish DELETE routes before refusing unsupported writes"
            );
        }
    }
}
