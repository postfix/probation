//! The OCI distribution endpoint group (`/v2/...`): what `docker`, `podman`, `containerd`, `skopeo` and `crane` speak. Handlers admit,
//! delegate to `oci::serve` and map errors only. Standalone and certificate-managed callers use `/v2/...` (the process's default
//! registry); a shared service's selected registry is `/registry/oci/{registry}/v2/...` (the shared-service middleware rewrites
//! `/v2/...` into it).
//!
//! A path is parsed once, strictly, before any admission or upstream call (src/oci/coords.rs). Every answer is in the registry API's
//! own shape: its error document, `Docker-Distribution-API-Version`, `Docker-Content-Digest`, and the `WWW-Authenticate` challenge of
//! the token flow (`Bearer realm=<this firewall's /v2/token>`), so the client's own login and token cache work unchanged.
//!
//! Writes (class W, shared service only): blob uploads (`POST`, `PATCH`, `PUT`), manifest `PUT` and the `DELETE`s are forwarded with
//! the caller's own credential to the registry's own origin and nowhere else; every `Location` that comes back is rewritten into this
//! firewall's namespace or refused; a write without a credential is answered with the challenge before anything is read.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::App;
use crate::http::error::ApiError;
use crate::managed::certificates::VerifiedPeer;
use crate::oci::coords::{self, Parsed};
use crate::oci::serve::{self, Challenge, Document, Manifest, Prefix};

type Peer = Option<axum::Extension<VerifiedPeer>>;

/// Set by the shared-service middleware on a request that arrived at `/v2/...` (rewritten to the selected registry's route), so a
/// `Link` or `Location` points back into the namespace the client used.
#[derive(Clone, Copy, Debug)]
pub struct Direct;

const API_VERSION: &str = "registry/2.0";

/// What an error is called in the registry API's error document.
#[derive(Clone, Copy)]
enum Subject {
    Manifest,
    Blob,
    Other,
}

fn error_response(error: ApiError, subject: Subject, challenge: Option<String>) -> Response {
    let reason = error.shown_reason();
    let mut response = error.into_response();
    let status = response.status();
    let code = match status.as_u16() {
        401 => "UNAUTHORIZED",
        403 => "DENIED",
        404 => match subject {
            Subject::Manifest => "MANIFEST_UNKNOWN",
            Subject::Blob => "BLOB_UNKNOWN",
            Subject::Other => "NAME_UNKNOWN",
        },
        405 | 406 | 400 | 413 => "UNSUPPORTED",
        429 => "TOOMANYREQUESTS",
        _ => "UNAVAILABLE",
    };
    let body = serde_json::json!({"errors": [{"code": code, "message": reason}]}).to_string();
    *response.body_mut() = Body::from(body);
    let headers = response.headers_mut();
    headers.remove(header::CONTENT_LENGTH);
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert("docker-distribution-api-version", HeaderValue::from_static(API_VERSION));
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.remove(header::WWW_AUTHENTICATE);
    if status == StatusCode::UNAUTHORIZED
        && let Some(challenge) = challenge.and_then(|text| HeaderValue::from_str(&text).ok())
    {
        headers.insert(header::WWW_AUTHENTICATE, challenge);
    }
    response
}

fn with_api_version(mut response: Response) -> Response {
    response.headers_mut().insert("docker-distribution-api-version", HeaderValue::from_static(API_VERSION));
    // Nothing of a registry is ever a page: no browser is asked to sniff a manifest, a list or a token into one.
    response.headers_mut().insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    response
}

/// `Bearer realm=<this firewall's token endpoint>` (the client logs in there with its own credential), or the registry's own Basic.
/// The registry host a client named in `ns` (containerd and the Docker daemon send it), in the shape the route already accepted.
fn ns_of(uri: &axum::http::Uri) -> Option<String> {
    let (_, ns) = url::form_urlencoded::parse(uri.query()?.as_bytes()).find(|(key, _)| key == "ns")?;
    (!ns.is_empty() && ns.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'_'))).then(|| ns.into_owned())
}

async fn challenge_header(app: &App, principal: Option<&crate::managed::Principal>, prefix: &Prefix, scope: Option<&str>, probe: bool, ns: Option<&str>) -> String {
    let basic = "Basic realm=\"probation\"".to_owned();
    if app.service_policy().is_some() {
        // A shared service's registry decides: a Basic-only registry gets the Basic challenge. A write that has no credential yet asks
        // nothing of any registry (it is answered from what is already known).
        if let Ok(Some(Challenge::Basic)) = serve::registry_challenge(app, principal, probe).await {
            return basic;
        }
    }
    let mut realm = app.config.public_url.clone();
    realm.set_path(&format!("{}/v2/token", prefix.0));
    realm.set_query(None);
    // A client that used the plain `/v2/` root asks the realm without an `ns` of its own: the realm carries it, so that, with several
    // registries, the token request selects the same registry as the request it answers.
    if prefix.0.is_empty()
        && let Some(ns) = ns
    {
        realm.query_pairs_mut().append_pair("ns", ns);
    }
    match scope {
        Some(scope) => format!("Bearer realm=\"{realm}\",service=\"probation\",scope=\"{scope}\""),
        None => format!("Bearer realm=\"{realm}\",service=\"probation\""),
    }
}

fn subject_of(parsed: &Parsed) -> Subject {
    match parsed {
        Parsed::Manifest { .. } => Subject::Manifest,
        Parsed::Blob { .. } | Parsed::Upload { .. } | Parsed::UploadStart { .. } => Subject::Blob,
        _ => Subject::Other,
    }
}

fn scope_of(parsed: &Parsed, write: bool) -> Option<String> {
    let actions = if write { "pull,push" } else { "pull" };
    match parsed {
        Parsed::Manifest { name, .. } | Parsed::Blob { name, .. } | Parsed::Tags { name } | Parsed::Referrers { name, .. } | Parsed::UploadStart { name } | Parsed::Upload { name, .. } => Some(format!("repository:{name}:{actions}")),
        Parsed::Catalog => Some("registry:catalog:*".to_owned()),
        _ => None,
    }
}

fn plain(body: bytes::Bytes, content_type: &str) -> Response {
    let mut response = Body::from(body).into_response();
    if let Ok(value) = HeaderValue::from_str(content_type) {
        response.headers_mut().insert(header::CONTENT_TYPE, value);
    }
    with_api_version(response)
}

fn document(doc: Document) -> Response {
    let mut response = plain(doc.body, doc.content_type);
    if let Some(link) = doc.link.and_then(|text| HeaderValue::from_str(&text).ok()) {
        response.headers_mut().insert(header::LINK, link);
    }
    if let Some(filters) = doc.filters_applied.and_then(|text| HeaderValue::from_str(&text).ok()) {
        response.headers_mut().insert("oci-filters-applied", filters);
    }
    response
}

fn manifest_response(manifest: Manifest, head: bool) -> Response {
    let length = manifest.length;
    let mut response = if head { StatusCode::OK.into_response() } else { Body::from(manifest.body).into_response() };
    let headers = response.headers_mut();
    if let Ok(value) = HeaderValue::from_str(&manifest.media_type) {
        headers.insert(header::CONTENT_TYPE, value);
    }
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(length));
    if let Ok(value) = HeaderValue::from_str(&manifest.served.to_string()) {
        headers.insert("docker-content-digest", value);
    }
    headers.insert(header::ETAG, HeaderValue::from_str(&format!("\"{}\"", manifest.served)).unwrap_or_else(|_| HeaderValue::from_static("\"\"")));
    with_api_version(response)
}

fn accept_of(headers: &HeaderMap) -> Option<String> {
    let mut all = Vec::new();
    for value in headers.get_all(header::ACCEPT) {
        all.push(value.to_str().ok().filter(|text| text.len() <= 2048 && text.bytes().all(|b| (0x20..0x7f).contains(&b)))?.to_owned());
    }
    (!all.is_empty()).then(|| all.join(", ")).filter(|text| text.len() <= 2048)
}

/// Aborts its task when dropped: a client that goes away during a first pull stops waiting for the transfer, and the transfer stops with its last
/// waiter (a request that shares it keeps it: the single flight counts waiters and only the last to leave cancels).
struct AbortOnDrop<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// The first pull of a layer: the decision has been made, the headers go out at once and the body follows the verified file; `Err(permit)` when the
/// layer is already on disk (or its length is unknown, or it lives elsewhere) and the ordinary path serves it.
#[allow(clippy::too_many_arguments)]
async fn early_blob(
    app: &Arc<App>,
    principal: Option<&crate::managed::Principal>,
    registry_id: u64,
    owner: u64,
    name: &str,
    digest: &coords::Digest,
    reference: crate::store::rows::ReferenceId,
    filename: &str,
    permit: tokio::sync::OwnedSemaphorePermit,
) -> Result<Result<Response, tokio::sync::OwnedSemaphorePermit>, ApiError> {
    use futures_util::StreamExt as _;
    let row = crate::artifacts::preflight(app, principal, crate::policy::Ecosystem::Oci, registry_id, reference, filename).await?;
    if row.content_key.is_some() || !serve::on_registry(app, principal, &row.reference.upstream_url) {
        return Ok(Err(permit));
    }
    let length = match within(serve::head_blob(app, principal, registry_id, name, digest)).await {
        Ok((Some(length), _)) => length.parse::<u64>().ok().filter(|length| *length > 0),
        _ => None,
    };
    let Some(length) = length else { return Ok(Err(permit)) };
    let (work_app, work_principal, work_name) = (Arc::clone(app), principal.cloned(), filename.to_owned());
    let mut work = AbortOnDrop(tokio::spawn(serve::with_owner(owner, async move {
        crate::artifacts::serve_artifact_in(&work_app, work_principal.as_ref(), crate::policy::Ecosystem::Oci, registry_id, reference, &work_name, &Method::GET, None).await
    })));
    let stream_app = Arc::clone(app);
    let body = futures_util::stream::once(async move {
        let refused = || std::io::Error::other("the layer failed its verification or its policy check: the connection is closed, no unverified byte is sent");
        match (&mut work.0).await {
            Ok(Ok(artifact)) => {
                let response = artifact.under(&stream_app.limits, permit).into_response();
                let same = response.headers().get(header::CONTENT_LENGTH).and_then(|value| value.to_str().ok()).and_then(|text| text.parse::<u64>().ok()) == Some(length);
                if response.status() == StatusCode::OK && same { Ok(response.into_body()) } else { Err(refused()) }
            }
            _ => Err(refused()),
        }
    })
    .map(|opened| match opened {
        Ok(body) => body.into_data_stream().map(|chunk| chunk.map_err(std::io::Error::other)).boxed(),
        Err(error) => futures_util::stream::once(async move { Err(error) }).boxed(),
    })
    .flatten();
    let mut response = Response::new(Body::from_stream(body));
    let out = response.headers_mut();
    out.insert(header::CONTENT_LENGTH, HeaderValue::from(length));
    out.insert("docker-content-digest", HeaderValue::from_str(&digest.to_string()).map_err(|_| ApiError::InternalFailure)?);
    out.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
    Ok(Ok(with_api_version(response)))
}

async fn within<T, F: std::future::Future<Output = Result<T, ApiError>>>(work: F) -> Result<T, ApiError> {
    tokio::time::timeout(serve::DEADLINE, work).await.unwrap_or(Err(ApiError::UpstreamTimeout))
}

#[allow(clippy::too_many_arguments)]
async fn run(
    app: &Arc<App>,
    principal: Option<&crate::managed::Principal>,
    registry_id: u64,
    parsed: Parsed,
    method: &Method,
    headers: &HeaderMap,
    uri: &axum::http::Uri,
    prefix: &Prefix,
    permit: tokio::sync::OwnedSemaphorePermit,
) -> Result<Response, ApiError> {
    if !matches!(*method, Method::GET | Method::HEAD) {
        return Err(ApiError::MethodNotAllowed);
    }
    let head = *method == Method::HEAD;
    // A token of the firewall's own (certificate-managed) is checked when one is presented.
    if parsed != Parsed::Token && app.service_policy().is_none() && principal.is_some() {
        serve::check_local_token(credential(headers).as_deref())?;
    }
    // `ns` names the registry the client was asked to pull from (containerd and the daemon send it to a mirror); the route has already
    // chosen the one registry this namespace is served from, so it is checked for its shape and read for nothing else.
    let ns_ok = |query: &[(String, String)]| query.iter().all(|(key, value)| key != "ns" || (value.len() <= 255 && value.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'_' | b'[' | b']'))));
    let query = |keys: &[&str]| coords::read_query(uri.query(), keys).filter(|q| ns_ok(q)).ok_or(ApiError::NotFound);
    match parsed {
        Parsed::Ping => {
            query(&["ns"])?;
            match within(serve::ping(app, principal, registry_id)).await? {
                None => Ok(with_api_version(StatusCode::OK.into_response())),
                Some(_) => Err(ApiError::Unauthenticated),
            }
        }
        Parsed::Token => {
            let text = uri.query().unwrap_or("");
            let own = credential(headers);
            let body = within(serve::serve_token(app, principal, registry_id, text, own.as_deref())).await?;
            Ok(plain(body, "application/json"))
        }
        Parsed::Catalog => {
            let q = query(&["ns", "n", "last"])?;
            Ok(document(within(serve::serve_catalog(app, principal, registry_id, prefix, &q)).await?))
        }
        Parsed::Tags { name } => {
            let q = query(&["ns", "n", "last"])?;
            Ok(document(within(serve::serve_tags(app, principal, registry_id, prefix, &name, &q)).await?))
        }
        Parsed::Referrers { name, digest } => {
            let q = query(&["ns", "artifactType"])?;
            Ok(document(within(serve::serve_referrers(app, principal, registry_id, &name, &digest, &q)).await?))
        }
        Parsed::Manifest { name, reference } => {
            query(&["ns"])?;
            let accept = accept_of(headers);
            let manifest = within(serve::serve_manifest(app, principal, registry_id, &name, &reference, accept.as_deref(), head)).await?;
            Ok(manifest_response(manifest, head))
        }
        Parsed::Blob { name, digest } => {
            query(&["ns"])?;
            // A credentialed HEAD is an existence check (a push asks before it uploads a layer): the registry's answer, no bytes.
            // (In a shared service, to a registry that asked for a credential: a registry that asked for none proves nothing about one, and a
            // key route has no push.)
            if head && app.service_policy().is_some() && principal.is_some_and(|p| p.registry_read_authorization.is_some()) && within(serve::registry_requires_auth(app, principal)).await.unwrap_or(false) {
                let (length, text) = within(serve::head_blob(app, principal, registry_id, &name, &digest)).await?;
                let mut response = StatusCode::OK.into_response();
                if let Some(length) = length.and_then(|text| text.parse::<u64>().ok()) {
                    response.headers_mut().insert(header::CONTENT_LENGTH, HeaderValue::from(length));
                }
                response.headers_mut().insert("docker-content-digest", HeaderValue::from_str(&text).map_err(|_| ApiError::InternalFailure)?);
                response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
                return Ok(with_api_version(response));
            }
            let (reference, filename) = within(serve::reference_for_blob(app, principal, registry_id, &name, &digest)).await?;
            let range = headers.get(header::RANGE).and_then(|value| value.to_str().ok());
            // A layer that is not on disk yet (its first pull) is verified in full before a byte of it is released, which takes the download plus
            // the hashing. The policy decision is made first; then the headers go out AT ONCE (the length is the registry's own), and the body
            // waits for the verified file. A digest that does not match aborts the connection: no client ever gets bytes that are not its digest.
            let mut permit = permit;
            if !head && range.is_none() && digest.algorithm == coords::Algorithm::Sha256 {
                let owner = principal.map_or_else(|| serve::owner_of_peer(super::logging::peer()), |principal| super::spool::owner_of(app, principal, headers).key);
                match early_blob(app, principal, registry_id, owner, &name, &digest, reference, &filename, permit).await? {
                    Ok(early) => return Ok(early),
                    Err(back) => permit = back,
                }
            }
            let response = crate::artifacts::serve_artifact_in(app, principal, crate::policy::Ecosystem::Oci, registry_id, reference, &filename, method, range).await?;
            let mut response = response.under(&app.limits, permit).into_response();
            response.headers_mut().insert("docker-content-digest", HeaderValue::from_str(&digest.to_string()).map_err(|_| ApiError::InternalFailure)?);
            response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
            Ok(with_api_version(response))
        }
        Parsed::UploadStart { .. } | Parsed::Upload { .. } => Err(ApiError::MethodNotAllowed),
    }
}

fn parse(path: &str) -> Result<Parsed, ApiError> {
    coords::parse(path.trim_start_matches('/')).ok_or(ApiError::NotFound)
}

fn path_of(path: Option<Path<String>>) -> String {
    path.map(|Path(path)| path).unwrap_or_default()
}

/// `GET|HEAD /v2/{path}` for the standalone and certificate-managed firewall: the process's default registry.
pub async fn legacy(State(app): State<Arc<App>>, method: Method, headers: HeaderMap, uri: axum::http::Uri, path: Option<Path<String>>) -> Response {
    let prefix = Prefix(String::new());
    let path = path_of(path);
    let parsed = match parse(&path) {
        Ok(parsed) => parsed,
        Err(error) => return error_response(error, Subject::Other, None),
    };
    let subject = subject_of(&parsed);
    let scope = scope_of(&parsed, false);
    let result = async {
        if !matches!(method, Method::GET | Method::HEAD) {
            return Err(ApiError::MethodNotAllowed);
        }
        let (permit, principal) = super::admit(&app, &headers).await?;
        let owner = principal.as_ref().map_or_else(|| serve::owner_of_peer(super::logging::peer()), |principal| super::spool::owner_of(&app, principal, &headers).key);
        // A certificate-managed firewall admits a request by the API key it carries (`docker login <host> -u any -p <key>`): the login's
        // token request is answered here with that key as the token the client sends from then on.
        if principal.is_some() && parsed == Parsed::Token {
            let presented = credential(&headers).and_then(|text| HeaderValue::from_str(&text).ok());
            let key = presented.as_ref().and_then(crate::managed::bearer_or_basic_password).ok_or(ApiError::Unauthenticated)?;
            let body = serde_json::json!({"token": key, "access_token": key, "expires_in": 300}).to_string();
            return Ok(plain(body.into(), "application/json"));
        }
        if app.managed().is_none() && parsed == Parsed::Token {
            return Err(ApiError::NotFound);
        }
        // Without a service the firewall takes its own anonymous tokens: the ping is its own answer.
        if parsed == Parsed::Ping {
            return Ok(with_api_version(StatusCode::OK.into_response()));
        }
        let response = serve::with_owner(owner, run(&app, principal.as_ref(), 0, parsed.clone(), &method, &headers, &uri, &prefix, permit)).await?;
        // A document is decided under the policy the key had when it was admitted, after one or more registry calls: it stands only if that
        // policy is still the key's (a blob is gated at delivery). A change is admitted again by the shared layer, under the new policy,
        // without charging the account's rate a second time.
        if let (Some(principal), false) = (principal.as_ref(), matches!(parsed, Parsed::Blob { .. })) {
            let (Some(managed), Some(peer)) = (app.managed(), super::logging::peer()) else { return Err(ApiError::NotReady) };
            let current = managed.reauthenticate(&headers, peer).await.map_err(|_| ApiError::PolicyUnavailable)?;
            if current.policy.policy.fingerprint != principal.policy.policy.fingerprint {
                return Ok(super::readmit::refusal());
            }
        }
        Ok(response)
    }
    .await;
    match result {
        Ok(response) => response,
        Err(error @ (ApiError::Unauthenticated | ApiError::UpstreamUnauthenticated)) => {
            let challenge = challenge_header(&app, None, &prefix, scope.as_deref(), true, None).await;
            error_response(error, subject, Some(challenge))
        }
        Err(error) => error_response(error, subject, None),
    }
}

/// The selected registry's own principal (what a 401 challenge is about), when it can be had without a credential check.
async fn challenge_principal(app: &Arc<App>, peer: Peer, registry: &str, headers: &HeaderMap) -> Option<crate::managed::Principal> {
    let id = parts_of(registry).ok()?;
    super::registry_read::recheck_oci(app, peer, id, headers).await.ok()
}

fn parts_of(registry: &str) -> Result<probation_policy::api::RegistryId, ApiError> {
    super::registry_read::registry_id(registry)
}

/// `/registry/oci/{registry}/v2/{path}`: a selected registry (reads, and the class-W writes).
#[allow(clippy::too_many_arguments)]
pub async fn selected(
    State(app): State<Arc<App>>,
    peer: Peer,
    direct: Option<axum::Extension<Direct>>,
    method: Method,
    headers: HeaderMap,
    uri: axum::http::Uri,
    Path(args): Path<Vec<String>>,
    body: Body,
) -> Response {
    let (registry, path) = (args.first().cloned().unwrap_or_default(), args.get(1).cloned().unwrap_or_default());
    // The registry segment is an id and nothing else, before anything is built from it (the challenge's realm, a `Location`'s namespace).
    if parts_of(&registry).is_err() {
        return error_response(ApiError::NotFound, Subject::Other, None);
    }
    let prefix = Prefix(if direct.is_some() { String::new() } else { format!("/registry/oci/{registry}") });
    let parsed = match parse(&path) {
        Ok(parsed) => parsed,
        Err(error) => return error_response(error, Subject::Other, None),
    };
    // (the status of an upload session is a GET with a credential that goes to the registry: class W too)
    let write = !matches!(method, Method::GET | Method::HEAD) || matches!(parsed, Parsed::Upload { .. });
    let subject = subject_of(&parsed);
    let scope = scope_of(&parsed, write);
    let (peer_again, headers_again) = (peer.clone(), headers.clone());
    let result = if write {
        match forward_write(app.clone(), peer, headers.clone(), &uri, &registry, &prefix, parsed.clone(), &method, body).await {
            Ok(response) => Ok(response),
            Err(error) => Err((error, true)),
        }
    } else {
        read(&app, peer, &headers, &uri, &registry, &prefix, parsed.clone(), &method).await.map_err(|error| (error, false))
    };
    match result {
        Ok(response) => response,
        Err((error @ (ApiError::UpstreamUnauthenticated | ApiError::Unauthenticated), written)) => {
            let selected = challenge_principal(&app, peer_again, &registry, &headers_again).await;
            let challenge = challenge_header(&app, selected.as_ref(), &prefix, scope.as_deref(), !written, ns_of(&uri).as_deref()).await;
            error_response(error, subject, Some(challenge))
        }
        Err((error, _)) => error_response(error, subject, None),
    }
}

#[allow(clippy::too_many_arguments)]
async fn read(app: &Arc<App>, peer: Peer, headers: &HeaderMap, uri: &axum::http::Uri, registry: &str, prefix: &Prefix, parsed: Parsed, method: &Method) -> Result<Response, ApiError> {
    let registry_id = parts_of(registry)?;
    let (permit, principal) = super::registry_read::admit_oci(app, peer.clone(), registry_id, headers).await?;
    let owner = super::spool::owner_of(app, &principal, headers).key;
    let response = serve::with_owner(owner, run(app, Some(&principal), registry_id.0, parsed, method, headers, uri, prefix, permit)).await?;
    let current = super::registry_read::recheck_oci(app, peer, registry_id, headers).await?;
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

// ------------------------------------------------------------------ writes (class W)

fn credential(headers: &HeaderMap) -> Option<String> {
    headers.get(header::AUTHORIZATION).and_then(|value| value.to_str().ok()).filter(|value| !value.trim().is_empty() && value.len() <= 8192).map(str::to_owned)
}

/// How long a body with no declared length may take: the rate floor over the whole cap, at least the shared five minutes and at most two hours (a
/// 5 GiB layer needs 0.7 MiB/s on average); a declared length has the shared rule (`spool::body_deadline`).
pub fn body_deadline(declared: Option<u64>, cap: u64) -> std::time::Duration {
    use std::time::Duration;
    match declared {
        Some(_) => super::spool::body_deadline(declared),
        None => (super::spool::RATE_GRACE + Duration::from_secs(cap / super::spool::MIN_RATE)).clamp(super::spool::UNDECLARED_DEADLINE, Duration::from_secs(2 * 3600)),
    }
}

/// Whether a request's body can be a layer (`empty`: the body has no byte at all, which the server knows before it reads any): a `PATCH`, or a `PUT`/`POST` that declares more than a megabyte or no length at all. The empty upload
/// start, the finishing `PUT` and a manifest (8 MiB at most) are small.
pub fn big_body(parsed: &Parsed, method: &Method, declared: Option<u64>, empty: bool) -> bool {
    if empty || matches!(parsed, Parsed::Manifest { .. }) {
        return false;
    }
    match *method {
        Method::PATCH => true,
        Method::PUT | Method::POST => declared.is_none_or(|length| length > 1 << 20),
        _ => false,
    }
}

fn write_blocks(app: &App, principal: &crate::managed::Principal, parsed: &Parsed, uri: &axum::http::Uri) -> Result<(), ApiError> {
    let query: Vec<(String, String)> = uri.query().map(|text| url::form_urlencoded::parse(text.as_bytes()).map(|(k, v)| (k.into_owned(), v.into_owned())).collect()).unwrap_or_default();
    let named = |key: &str| query.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone());
    let principal = Some(principal);
    match parsed {
        Parsed::Manifest { name, reference } => {
            serve::locally_blocked(app, principal, name, None)?;
            serve::locally_blocked(app, principal, name, Some(&reference.text()))
        }
        Parsed::Blob { name, digest } => {
            serve::locally_blocked(app, principal, name, None)?;
            serve::locally_blocked(app, principal, name, Some(&digest.to_string()))
        }
        Parsed::UploadStart { name } | Parsed::Upload { name, .. } => {
            serve::locally_blocked(app, principal, name, None)?;
            // A digest the upload finishes with, or a blob it mounts from another repository, is blocked everywhere it is blocked anywhere.
            for key in ["digest", "mount"] {
                if let Some(text) = named(key).filter(|text| coords::Digest::parse(text).is_some()) {
                    serve::locally_blocked(app, principal, name, Some(&text))?;
                }
            }
            if let Some(from) = named("from").filter(|from| probation_policy::names::valid_oci_name(from)) {
                serve::locally_blocked(app, principal, &from, None)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn write_segments(parsed: &Parsed, method: &Method) -> Result<Vec<String>, ApiError> {
    match (parsed, method) {
        (Parsed::UploadStart { name }, &Method::POST) => Ok(vec![name.clone(), "blobs".into(), "uploads".into(), String::new()]),
        (Parsed::Upload { name, session }, &(Method::PATCH | Method::PUT | Method::DELETE | Method::GET)) => Ok(vec![name.clone(), "blobs".into(), "uploads".into(), session.clone()]),
        (Parsed::Manifest { name, reference }, &(Method::PUT | Method::DELETE)) => Ok(vec![name.clone(), "manifests".into(), reference.text()]),
        (Parsed::Blob { name, digest }, &Method::DELETE) => Ok(vec![name.clone(), "blobs".into(), digest.to_string()]),
        (Parsed::Upload { .. } | Parsed::UploadStart { .. } | Parsed::Manifest { .. } | Parsed::Blob { .. }, _) => Err(ApiError::MethodNotAllowed),
        _ => Err(ApiError::NotFound),
    }
}

/// The query of a write: the registry's own opaque upload state and the documented parameters, bounded.
fn write_query(uri: &axum::http::Uri) -> Result<Option<String>, ApiError> {
    match uri.query() {
        None => Ok(None),
        Some(query) if query.len() <= 4096 && query.bytes().all(|b| b.is_ascii_graphic() && b != b'#') => Ok(Some(query.to_owned())),
        Some(_) => Err(ApiError::NotFound),
    }
}

#[allow(clippy::too_many_arguments)]
async fn forward_write(app: Arc<App>, peer: Peer, headers: HeaderMap, uri: &axum::http::Uri, registry: &str, prefix: &Prefix, parsed: Parsed, method: &Method, body: Body) -> Result<Response, ApiError> {
    // Writes are the shared service's: a standalone or certificate-managed firewall has no write route (nothing is read, nothing is asked).
    if app.service_policy().is_none() {
        return Err(ApiError::MethodNotAllowed);
    }
    // The client sends its token only on a request the challenge told it to; without a credential the challenge comes first.
    let Some(authorization) = credential(&headers) else { return Err(ApiError::Unauthenticated) };
    let segments = write_segments(&parsed, method)?;
    // The firewall's own key is never a registry credential: it is refused here, not forwarded.
    if HeaderValue::from_str(&authorization).ok().and_then(|value| crate::managed::bearer_or_basic_password(&value)).is_some() {
        return Ok((StatusCode::FORBIDDEN, "a firewall key is not a registry credential").into_response());
    }
    let query = write_query(uri)?;
    let is_manifest = matches!(parsed, Parsed::Manifest { .. });
    // A layer is pushed up to what can be pulled back (`max_artifact_bytes`); a manifest up to 8 MiB.
    let cap = if is_manifest { 8 << 20 } else { app.config.max_artifact_bytes.get() };
    let declared = headers.get(header::CONTENT_LENGTH).and_then(|value| value.to_str().ok()).and_then(|value| value.parse::<u64>().ok());
    if declared.is_some_and(|length| length > cap) {
        return Ok(StatusCode::PAYLOAD_TOO_LARGE.into_response());
    }
    let registry_id = parts_of(registry)?;
    let (permit, principal) = super::registry_read::admit_oci(&app, peer.clone(), registry_id, &headers).await?;
    // The write carries the caller's credential: nothing it reads may enter a shared cache (C1028).
    super::logging::record_request_scoped();
    // What a policy blocks is not written either: the repository, a manifest's tag or digest, a blob's digest (a blocked digest is blocked in every repository,
    // so a mount or a push of the same bytes elsewhere is refused too), and the repository a mount names.
    write_blocks(&app, &principal, &parsed, uri)?;
    let parts: Vec<&str> = segments.iter().map(String::as_str).collect();
    let target = serve::publish_target(&app, &principal, &parts, query.as_deref())?;
    let content_type = headers.get(header::CONTENT_TYPE).and_then(|value| value.to_str().ok()).filter(|value| value.len() <= 256 && value.bytes().all(|b| (0x20..0x7f).contains(&b))).map(str::to_owned);
    let content_range = headers.get(header::CONTENT_RANGE).and_then(|value| value.to_str().ok()).filter(|value| value.len() <= 64 && value.bytes().all(|b| b.is_ascii_digit() || matches!(b, b'-' | b'/' | b'*' | b' ' | b'b' | b'y' | b't' | b'e' | b's'))).map(str::to_owned);
    let has_body = !matches!(*method, Method::DELETE | Method::GET);
    let owner = super::spool::owner_of(&app, &principal, &headers);
    let mut permit = Some(permit);
    let (file, length, _spool, _lane) = if has_body {
        // Layers queue behind each other per owner (docker pushes several at once): the lane is taken BEFORE the body is read, so a layer
        // that has to wait is a waiting request and never a stream cut mid-way when the owner's share of the spool is full. Only a body that can
        // be big takes a lane (the empty start, the finishing PUT and a manifest never wait behind a layer), and a request that waits holds no
        // active-request permit: it takes one again when its turn comes.
        let lane = if big_body(&parsed, method, declared, axum::body::HttpBody::is_end_stream(&body)) {
            drop(permit.take());
            let lane = serve::upload_lane(&app, owner.key).await?;
            permit = Some(app.limits.active_permit().ok_or(ApiError::Overloaded)?);
            Some(lane)
        } else {
            None
        };
        let deadline = body_deadline(declared, cap);
        let super::spool::Spooled::Body(spool) = super::spool::spool_paced(&app, owner, declared, cap, body, super::spool::BODY_IDLE, deadline, super::spool::RATE_GRACE, super::spool::FIRST_CHUNK_WAIT).await? else {
            return Ok(StatusCode::PAYLOAD_TOO_LARGE.into_response());
        };
        let (file, length) = (spool.file.try_clone().await.map_err(|_| ApiError::InternalFailure)?, spool.length);
        (Some(file), length, Some(spool), lane)
    } else {
        (None, 0, None, None)
    };
    let _permit = permit;
    let current = super::registry_read::recheck_oci(&app, peer, registry_id, &headers).await?;
    if current.registry_origin != principal.registry_origin || current.registry_private_cidrs != principal.registry_private_cidrs || current.policy.policy.fingerprint != principal.policy.policy.fingerprint {
        return Err(ApiError::PolicyUnavailable);
    }
    let result = app
        .transport
        .fetch_oci(crate::upstream::OciRequest {
            url: target.url,
            origin: target.origin,
            private_cidrs: principal.registry_private_cidrs.clone(),
            method: method.clone(),
            authorization: Some(authorization),
            accept: Some("application/json".to_owned()),
            content_type,
            content_range,
            body: file.map(|file| (file, length)),
            max_bytes: 64 << 10,
        })
        .await;
    app.upstreams.record_upstream(crate::managed::report::Call::Oci, &result.as_ref().map(|_| ()).map_err(Clone::clone));
    let result = result.map_err(|error| match error {
        crate::upstream::UpstreamError::Timeout => ApiError::UpstreamTimeout,
        _ => ApiError::UpstreamFailure,
    })?;
    // Only the answers a registry's write endpoint gives are relayed.
    let status = StatusCode::from_u16(result.status).ok().filter(|status| matches!(status.as_u16(), 200 | 201 | 202 | 204 | 206 | 400 | 401 | 403 | 404 | 405 | 409 | 413 | 416 | 422 | 429)).ok_or(ApiError::UpstreamInvalid)?;
    let mut response = (status, result.body.clone()).into_response();
    let out = response.headers_mut();
    let json = result.header("content-type").is_some_and(|text| text.starts_with("application/json"));
    out.insert(header::CONTENT_TYPE, HeaderValue::from_static(if json { "application/json" } else { "text/plain; charset=utf-8" }));
    out.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    out.insert("docker-distribution-api-version", HeaderValue::from_static(API_VERSION));
    if let Some(location) = result.header("location") {
        // Every Location is this registry's, in this firewall's namespace; one that leaves the registry's origin is not passed on.
        let rewritten = serve::client_location(&app, &principal, prefix, location).ok_or(ApiError::UpstreamInvalid)?;
        out.insert(header::LOCATION, HeaderValue::from_str(&rewritten).map_err(|_| ApiError::UpstreamInvalid)?);
    }
    if let Some(range) = result.header("range").filter(|text| text.len() <= 64 && text.bytes().all(|b| b.is_ascii_digit() || matches!(b, b'-' | b'/'))) {
        out.insert(header::RANGE, HeaderValue::from_str(range).map_err(|_| ApiError::UpstreamInvalid)?);
    }
    if let Some(uuid) = result.header("docker-upload-uuid").filter(|text| coords::valid_session(text)) {
        out.insert("docker-upload-uuid", HeaderValue::from_str(uuid).map_err(|_| ApiError::UpstreamInvalid)?);
    }
    if let Some(digest) = result.header("docker-content-digest").filter(|text| coords::Digest::parse(text).is_some()) {
        out.insert("docker-content-digest", HeaderValue::from_str(digest).map_err(|_| ApiError::UpstreamInvalid)?);
    }
    // A registry that supports the referrers API answers a manifest PUT that names a subject with `OCI-Subject`: a client that sees it does not
    // write the tag-schema fallback, and asks the referrers API (which this firewall serves).
    if let Some(subject) = result.header("oci-subject").filter(|text| coords::Digest::parse(text).is_some()) {
        out.insert("oci-subject", HeaderValue::from_str(subject).map_err(|_| ApiError::UpstreamInvalid)?);
    }
    if status == StatusCode::UNAUTHORIZED {
        let scope = scope_of(&parsed, true);
        let challenge = challenge_header(&app, Some(&principal), prefix, scope.as_deref(), false, ns_of(uri).as_deref()).await;
        response.headers_mut().insert(header::WWW_AUTHENTICATE, HeaderValue::from_str(&challenge).map_err(|_| ApiError::InternalFailure)?);
    }
    Ok(response)
}
