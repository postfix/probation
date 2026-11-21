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
use probation_policy::{Ecosystem, api::{RegistryDescriptor, RegistryId, ServicePolicySnapshot}};
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
    if !super::listener_admission::peer_admitted(peer, &app.config.allowed_peer_cidrs) {
        return Err(ApiError::NetworkNotAllowed(peer));
    }
    // LS-F10 (user decision 2026-11-18): every peer, loopback included, must address the
    // public host or one of this machine's own names on the listener's port. A rebinding
    // host (a browser reaching 127.0.0.1 with `Host: attacker.test`) is refused.
    if !host_admitted(&app.config.public_url, app.bound.get().map(|addr| addr.port()), &request) {
        return Err(ApiError::InvalidInput("Host does not match the public URL"));
    }
    if !app.store().is_healthy() {
        return Err(ApiError::StorageUnusable);
    }
    let publication_gate = Arc::clone(&service.publication_gate);
    let generation = publication_gate.generation();
    let policy = service.snapshot().ok_or(ApiError::PolicyUnavailable)?;
    let selected = classify_selected_registry(&request, &policy)?;
    // C1028 / LS-F4: a read is cache-eligible only on the allow-list; anything else is
    // request-scoped and never touches a shared cache.
    if matches!(*request.method(), Method::GET | Method::HEAD) {
        let rules = if request.uri().path() == "/v2" || request.uri().path().starts_with("/v2/") || request.uri().path().starts_with("/registry/oci/") {
            &super::credential_read::FamilyReadRules::OCI
        } else if request.uri().path().starts_with("/conan/") || request.uri().path().starts_with("/registry/conan/") {
            &super::credential_read::FamilyReadRules::CONAN
        } else if request.uri().path().starts_with("/maven/") || request.uri().path().starts_with("/registry/maven/") {
            &super::credential_read::FamilyReadRules::MAVEN
        } else if request.uri().path().starts_with("/nuget/") || request.uri().path().starts_with("/registry/nuget/") {
            &super::credential_read::FamilyReadRules::NUGET
        } else if request.uri().path().starts_with("/pypi/") || request.uri().path().starts_with("/registry/pypi/") {
            &super::credential_read::FamilyReadRules::PYPI
        } else if request.uri().path().starts_with("/rubygems/") || request.uri().path().starts_with("/registry/rubygems/") {
            &super::credential_read::FamilyReadRules::RUBYGEMS
        } else if request.uri().path().starts_with("/cargo/") || request.uri().path().starts_with("/registry/cargo/") {
            &super::credential_read::FamilyReadRules::CARGO
        } else if request.uri().path().starts_with("/go/") || request.uri().path().starts_with("/registry/go/") {
            &super::credential_read::FamilyReadRules::GO
        } else {
            &super::credential_read::FamilyReadRules::NPM
        };
        let parts = super::credential_read::RequestParts { uri: request.uri(), headers: request.headers(), extra_pseudo_headers: &[] };
        if matches!(super::credential_read::classify_read(&parts, rules), super::credential_read::ReadClass::RequestScoped) {
            logging::record_request_scoped();
        }
    }
    // (RubyGems' `gem yank` is its own class-W route, forwarded by the family handler.)
    if request.method() == Method::DELETE && !request.uri().path().starts_with("/registry/rubygems/") && !request.uri().path().starts_with("/rubygems/") && !request.uri().path().starts_with("/registry/cargo/") && !request.uri().path().starts_with("/cargo/") && !request.uri().path().starts_with("/registry/go/") && !request.uri().path().starts_with("/go/") && !request.uri().path().starts_with("/registry/nuget/") && !request.uri().path().starts_with("/nuget/") && !request.uri().path().starts_with("/registry/maven/") && !request.uri().path().starts_with("/maven/") && !request.uri().path().starts_with("/registry/conan/") && !request.uri().path().starts_with("/conan/") && !request.uri().path().starts_with("/registry/oci/") && request.uri().path() != "/v2" && !request.uri().path().starts_with("/v2/") {
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
    // A refusal is the marked 503 the shared layer admits again (src/http/readmit.rs), not a final answer.
    let Ok(authorization) = authorize_current_policy(&publication_gate, &prepared) else { return Ok(super::readmit::refusal()) };
    Ok(release_verified_response(authorization).unwrap_or_else(|_| super::readmit::refusal()))
}

struct SelectedRegistry {
    uri: Uri,
}

/// The one registry of a family, or none when there are several (which one is not a guess).
fn ns_registry<'a>(registries: impl Iterator<Item = &'a RegistryDescriptor>, ns: &str) -> Result<RegistryId, ApiError> {
    only_registry(registries.filter(|item| oci_hosts(item.target_url.as_deref()).iter().any(|host| host == ns)))
}

fn only_registry<'a>(mut registries: impl Iterator<Item = &'a RegistryDescriptor>) -> Result<RegistryId, ApiError> {
    let registry = registries.next().ok_or(ApiError::NotFound)?.registry;
    if registries.next().is_some() {
        return Err(ApiError::NotFound);
    }
    Ok(registry)
}

/// The value of the query's `ns`, lower case (its shape is checked by the OCI route itself).
fn oci_ns(query: Option<&str>) -> Option<String> {
    query.and_then(|query| url::form_urlencoded::parse(query.as_bytes()).find(|(key, _)| key == "ns")).map(|(_, value)| value.to_ascii_lowercase())
}

/// The names a client uses for an OCI registry: the host (and port) of its target, and for a registry that targets Docker Hub (by any of its host names) the three names Hub goes by.
fn oci_hosts(target: Option<&str>) -> Vec<String> {
    const HUB: [&str; 3] = ["docker.io", "registry-1.docker.io", "index.docker.io"];
    let Some(target) = target else { return HUB.iter().map(|name| (*name).to_owned()).collect() };
    let Ok(url) = url::Url::parse(target) else { return Vec::new() };
    let Some(host) = url.host_str() else { return Vec::new() };
    let host = host.to_ascii_lowercase();
    let mut names = vec![match url.port() { Some(port) => format!("{host}:{port}"), None => host.clone() }];
    if matches!(host.as_str(), "registry-1.docker.io" | "index.docker.io" | "registry.hub.docker.com") {
        names.extend(HUB.iter().map(|name| (*name).to_owned()));
    }
    names
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
        && request.method() != Method::PATCH
    {
        return Err(ApiError::MethodNotAllowed);
    }
    let path = request.uri().path();
    let (ecosystem, registry, rest) = if let Some(path) = path.strip_prefix("/registry/") {
        let mut parts = path.splitn(3, '/');
        let ecosystem = match parts.next() {
            Some("npm") => Ecosystem::Npm,
            Some("pypi") => Ecosystem::PyPi,
            Some("rubygems") => Ecosystem::RubyGems,
            Some("cargo") => Ecosystem::Cargo,
            Some("go") => Ecosystem::Go,
            Some("nuget") => Ecosystem::NuGet,
            Some("maven") => Ecosystem::Maven,
            Some("conan") => Ecosystem::Conan,
            Some("oci") => Ecosystem::Oci,
            _ => return Err(ApiError::NotFound),
        };
        let registry = super::registry_read::registry_id(parts.next().ok_or(ApiError::NotFound)?)?;
        let rest = parts.next().ok_or(ApiError::NotFound)?;
        // OCI's namespace is the registry API's own `v2` tree: `rest` is what follows it.
        let rest = if ecosystem == Ecosystem::Oci { rest.strip_prefix("v2").filter(|tail| tail.is_empty() || tail.starts_with('/')).ok_or(ApiError::NotFound)?.trim_start_matches('/') } else { rest };
        (ecosystem, registry, rest)
    } else {
        let (ecosystem, rest) = if let Some(rest) = path.strip_prefix("/npm/") {
            (Ecosystem::Npm, rest)
        } else if let Some(rest) = path.strip_prefix("/pypi/") {
            (Ecosystem::PyPi, rest)
        } else if let Some(rest) = path.strip_prefix("/rubygems/") {
            (Ecosystem::RubyGems, rest)
        } else if let Some(rest) = path.strip_prefix("/cargo/") {
            (Ecosystem::Cargo, rest)
        } else if let Some(rest) = path.strip_prefix("/go/") {
            (Ecosystem::Go, rest)
        } else if let Some(rest) = path.strip_prefix("/nuget/") {
            (Ecosystem::NuGet, rest)
        } else if let Some(rest) = path.strip_prefix("/maven/") {
            (Ecosystem::Maven, rest)
        } else if let Some(rest) = path.strip_prefix("/conan/") {
            (Ecosystem::Conan, rest)
        } else if path == "/v2" || path.starts_with("/v2/") {
            (Ecosystem::Oci, path.strip_prefix("/v2").unwrap_or("").trim_start_matches('/'))
        } else {
            return Err(ApiError::NotFound);
        };
        let registries = policy
            .registries
            .iter()
            .filter(|registry| registry.ecosystem == ecosystem);
        let registry = match (ecosystem, oci_ns(request.uri().query())) {
            // `ns` names the registry the client meant (containerd and the Docker daemon send it): the one registry whose configured
            // host it is, or none (never another registry that happens to have the same repository path).
            // Two registries on one host are ambiguous, and an ambiguity is a refusal, never a guess (`/registry/oci/{id}/v2` disambiguates).
            (Ecosystem::Oci, Some(ns)) => ns_registry(registries, &ns)?,
            _ => only_registry(registries)?,
        };
        (ecosystem, registry, rest)
    };
    if !policy
        .registries
        .iter()
        .any(|item| item.registry == registry && item.ecosystem == ecosystem)
    {
        return Err(ApiError::NotFound);
    }
    if request.method() == Method::PATCH && ecosystem != Ecosystem::Oci {
        return Err(ApiError::MethodNotAllowed);
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
    // RubyGems is read-only through the shared service: writes (`gem push`, `gem yank`) are
    // not forwarded by this family, and the read routes take no query string.
    // Class W: `gem push` (POST api/v1/gems) and `gem yank` (DELETE api/v1/gems/yank) only.
    let rubygems_write = ecosystem == Ecosystem::RubyGems
        && ((*request.method() == Method::POST && rest == "api/v1/gems") || (*request.method() == Method::DELETE && rest == "api/v1/gems/yank"));
    if ecosystem == Ecosystem::RubyGems && !rubygems_write && (!matches!(*request.method(), Method::GET | Method::HEAD) || request.uri().query().is_some()) {
        return Err(if request.uri().query().is_some() { ApiError::NotFound } else { ApiError::MethodNotAllowed });
    }
    // Cargo's registry API (publish, yank, unyank, owners, search) is forwarded by the family handler
    // (class W with the caller's own token, or the owner list and search as reads); any other
    // non-read request is refused here.
    let cargo_api = ecosystem == Ecosystem::Cargo && rest.starts_with("api/v1/crates");
    if ecosystem == Ecosystem::Cargo && !cargo_api && !matches!(*request.method(), Method::GET | Method::HEAD) {
        return Err(ApiError::MethodNotAllowed);
    }
    // Go has no write protocol: GOPROXY is read-only, so a module is published to its repository and
    // never through this service. Reads only.
    if ecosystem == Ecosystem::Go && !matches!(*request.method(), Method::GET | Method::HEAD) {
        return Err(ApiError::MethodNotAllowed);
    }
    // NuGet's push, symbol push, unlist and relist are class-W routes the family handler forwards (with the
    // caller's own credential); any other non-read is refused here.
    let nuget_write = ecosystem == Ecosystem::NuGet
        && match *request.method() {
            Method::PUT => matches!(rest, "api/v2/package" | "api/v2/package/" | "api/v2/symbolpackage" | "api/v2/symbolpackage/"),
            Method::DELETE | Method::POST => rest.strip_prefix("api/v2/package/").is_some_and(|tail| tail.split('/').count() == 2),
            _ => false,
        };
    if ecosystem == Ecosystem::NuGet && !nuget_write && !matches!(*request.method(), Method::GET | Method::HEAD) {
        return Err(ApiError::MethodNotAllowed);
    }
    // Maven's deploy (`PUT` of a file, a checksum, a signature or a metadata document) and its clean-up (`DELETE`) are class-W
    // routes the family handler forwards (with the caller's own credential); any other non-read is refused here.
    if ecosystem == Ecosystem::Maven && !matches!(*request.method(), Method::GET | Method::HEAD | Method::PUT | Method::DELETE) {
        return Err(ApiError::MethodNotAllowed);
    }
    // Conan's upload (`PUT` of a file of a revision) and its clean-up (`DELETE`) are class-W routes the family handler forwards (with the
    // caller's own token); any other non-read is refused here.
    if ecosystem == Ecosystem::Conan && !matches!(*request.method(), Method::GET | Method::HEAD | Method::PUT | Method::DELETE) {
        return Err(ApiError::MethodNotAllowed);
    }
    // Conan's search is the one Conan read with a query string (the handler parses `q` and `ignorecase` only).
    let conan_search = ecosystem == Ecosystem::Conan && rest == "v2/conans/search" && request.method() == Method::GET;
    // NuGet's search and autocomplete are the two reads with a query string (the handler keeps the known keys only).
    let nuget_query = ecosystem == Ecosystem::NuGet && matches!(rest, "v3/query" | "v3/autocomplete") && request.method() == Method::GET;
    let search = ecosystem == Ecosystem::Npm && rest == "-/v1/search";
    let named_action = ecosystem == Ecosystem::Npm && rest.starts_with("-/")
        && rest != "-/ping" && !search && !audit;
    let write_preflight = ecosystem == Ecosystem::Npm
        && request.method() == Method::GET
        && request.uri().query() == Some("write=true")
        && parse_uri_package(rest).is_ok();
    // Cargo's search is the one Cargo read with a query string (the handler keeps the known keys only).
    let cargo_search = cargo_api && rest == "api/v1/crates" && request.method() == Method::GET;
    // OCI's reads and writes carry the registry API's own parameters (paging, `ns`, upload state, `digest`, `mount`): the handler reads
    // the keys of its route and refuses any other.
    if request.uri().query().is_some() && ecosystem != Ecosystem::Oci && !search && !write_preflight && !named_action && !cargo_search && !nuget_query && !conan_search {
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
    let uri = if ecosystem == Ecosystem::Oci { format!("/registry/oci/{}/v2/{rest}{query}", registry.0) } else { format!("/registry/{}/{}/{rest}{query}", ecosystem.as_tag(), registry.0) }
        .parse()
        .map_err(|_| ApiError::NotFound)?;
    Ok(SelectedRegistry { uri })
}

async fn dispatch_selected_registry(
    mut request: Request,
    selected: SelectedRegistry,
    next: Next,
) -> Response {
    // A client that used the plain `/v2/` namespace is answered in it (an OCI `Link` or `Location` points back there).
    if request.uri().path() == "/v2" || request.uri().path().starts_with("/v2/") {
        request.extensions_mut().insert(super::oci_routes::Direct);
    }
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

fn host_admitted(public_url: &url::Url, local_port: Option<u16>, request: &Request) -> bool {
    use axum::http::header::HOST;
    let host = super::listener_admission::HostInput {
        host_headers: request.headers().get_all(HOST).iter().map(|v| v.to_str().unwrap_or("\u{0}").to_owned()).collect(),
        authority: request.uri().authority().map(|a| a.as_str().to_owned()).filter(|_| request.version() == axum::http::Version::HTTP_2),
        target_authority: request.uri().authority().map(|a| a.as_str().to_owned()).filter(|_| request.version() != axum::http::Version::HTTP_2),
    };
    super::listener_admission::host_matches(public_url, &host)
        || local_port.is_some_and(|port| super::listener_admission::local_host_matches(port, &host))
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

#[cfg(test)]
mod ns_tests {
    use super::*;

    #[test]
    fn a_percent_encoded_ns_with_a_port_names_the_registry() {
        // Go's url.Values.Encode (containerd, the Docker daemon) writes the colon of `host:5000` as %3A.
        assert_eq!(oci_ns(Some("ns=localhost%3A5000")).as_deref(), Some("localhost:5000"));
        assert_eq!(oci_ns(Some("n=5&ns=Docker.IO")).as_deref(), Some("docker.io"), "case folds, other keys are skipped");
        assert_eq!(oci_ns(Some("n=5")), None);
        assert!(oci_hosts(Some("https://registry.example:5000/repo/")).contains(&"registry.example:5000".to_owned()));
    }

    #[test]
    fn a_registry_targeting_any_docker_hub_host_answers_to_every_hub_name() {
        // containerd sends `ns=docker.io` for Hub; a registry that targets Hub through another of its host names must still serve it (L-1).
        for target in ["https://registry-1.docker.io", "https://index.docker.io", "https://registry.hub.docker.com"] {
            let hosts = oci_hosts(Some(target));
            for name in ["docker.io", "registry-1.docker.io", "index.docker.io"] {
                assert!(hosts.contains(&name.to_owned()), "{target} answers to {name}: {hosts:?}");
            }
        }
        assert!(!oci_hosts(Some("https://mirror.example")).contains(&"docker.io".to_owned()), "an unrelated host is not Hub");
    }

    fn oci(id: u64, url: &str) -> RegistryDescriptor {
        RegistryDescriptor { registry: RegistryId(id), ecosystem: Ecosystem::Oci, target_url: Some(url.to_owned()), trusted: false, registry_private_cidrs: vec![], deletion_scopes: vec![], osv_scope: None, archive_origin: None, resource_path_prefix: None, token_origin: None }
    }

    #[test]
    fn two_registries_on_one_host_are_an_ambiguity_not_a_first_match() {
        let both = [oci(1, "https://ghcr.io/org-a"), oci(2, "https://ghcr.io/org-b"), oci(3, "https://quay.io")];
        assert!(matches!(ns_registry(both.iter(), "ghcr.io"), Err(ApiError::NotFound)), "two registries claim ghcr.io");
        assert_eq!(ns_registry(both.iter(), "quay.io").unwrap(), RegistryId(3), "a unique host still routes");
        assert!(matches!(ns_registry(both.iter(), "other.io"), Err(ApiError::NotFound)));
    }
}
