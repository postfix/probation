//! Named npm actions through the certificate-selected upstream.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use futures_util::StreamExt;
use probation_policy::PlaceRef;
use std::io::SeekFrom;
use tokio::io::{AsyncSeekExt, AsyncWriteExt};
use url::Url;

use crate::App;
use crate::http::error::ApiError;
use crate::http::unpublish_reference;
use crate::managed::Principal;
use crate::npm::PackageName;
use crate::upstream::{ActionRequest, OriginKind, OriginSet, UpstreamError};

pub struct RegistryActionRequest {
    pub selected_registry: u64,
    pub selected_base: String,
    pub method: Method,
    pub path: String,
    pub query: Option<String>,
    pub headers: HeaderMap,
    pub body: Body,
}

#[derive(Default)]
pub(crate) struct LoginRates(Mutex<HashMap<(u64, PlaceRef), (Instant, u32)>>);

impl LoginRates {
    fn admit(&self, registry: u64, member: PlaceRef, now: Instant) -> bool {
        let mut rates = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if rates.len() > 1024 {
            rates.retain(|_, (at, _)| now.saturating_duration_since(*at) < Duration::from_secs(60));
        }
        let window = rates.entry((registry, member)).or_insert((now, 0));
        if now.saturating_duration_since(window.0) >= Duration::from_secs(60) {
            *window = (now, 0);
        }
        if window.1 >= 120 {
            return false;
        }
        window.1 += 1;
        true
    }
}

pub async fn forward_registry_action(
    app: &Arc<App>,
    principal: &Principal,
    request: RegistryActionRequest,
) -> Result<Response, ApiError> {
    let (origin, url) = admit_selected_origin(app, principal, &request)?;
    let admission = admit_publish_request(principal, &request)?;
    if (admission.is_none() || legacy_login_path(&request.path, &request.method))
        && !app.login_rates.admit(
            request.selected_registry,
            principal.place,
            app.clock.now_monotonic(),
        )
    {
        return Err(ApiError::TooManyRequests);
    }
    let cap = app.config.max_artifact_bytes.get();
    let revision_package = if request.method == Method::PUT {
        request.path.split_once("/-rev/").map(|(package, _)| package.to_owned())
    } else { None };
    if revision_package.is_some() && request.headers.get(header::CONTENT_ENCODING).is_some_and(|value| value != "identity") {
        return Err(ApiError::InvalidInput("revision content encoding must be identity"));
    }
    if request
        .headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .is_some_and(|length| length > cap)
    {
        return Ok(StatusCode::PAYLOAD_TOO_LARGE.into_response());
    }
    let file =
        tempfile::tempfile_in(&app.config.data_dir).map_err(|_| ApiError::StorageUnusable)?;
    let mut file = tokio::fs::File::from_std(file);
    let mut body_len = 0u64;
    let mut stream = request.body.into_data_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| ApiError::InvalidInput("action upload is incomplete"))?;
        body_len = body_len.saturating_add(chunk.len() as u64);
        if body_len > cap {
            return Ok(StatusCode::PAYLOAD_TOO_LARGE.into_response());
        }
        file.write_all(&chunk)
            .await
            .map_err(|_| ApiError::StorageUnusable)?;
    }
    file.flush().await.map_err(|_| ApiError::StorageUnusable)?;
    file.seek(SeekFrom::Start(0))
        .await
        .map_err(|_| ApiError::StorageUnusable)?;
    let action = ActionRequest {
        url,
        origin: origin.clone(),
        private_cidrs: principal.registry_private_cidrs.clone(),
        method: request.method,
        authorization: admission,
        content_type: request
            .headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned),
        body: file,
        body_len,
        max_bytes: app.config.max_metadata_bytes.get(),
    };
    let result = if let Some(package) = revision_package {
        unpublish_reference::forward_revision_put(app, principal, request.selected_registry, &package, action).await?
    } else {
        send_action(app, action).await.map_err(|error| match error {
            UpstreamError::Timeout => ApiError::UpstreamTimeout,
            _ => ApiError::UpstreamFailure,
        })?
    };
    let mut body = result.body;
    if request.path == "-/v1/login" && result.status == 200 {
        body = map_login_start(
            &body,
            &origin,
            &app.config.public_url,
            &request.selected_base,
        )?;
    }
    let status = StatusCode::from_u16(result.status).map_err(|_| ApiError::UpstreamInvalid)?;
    let mut response = (status, body).into_response();
    if let Some(content_type) = result.content_type.and_then(|value| value.parse().ok()) {
        response
            .headers_mut()
            .insert(header::CONTENT_TYPE, content_type);
    }
    Ok(response)
}

fn admit_selected_origin(
    app: &Arc<App>,
    principal: &Principal,
    request: &RegistryActionRequest,
) -> Result<(Url, Url), ApiError> {
    // The seeded default registry has a NULL target and uses the configured npm origin.
    let origin = principal
        .registry_origin
        .clone()
        .unwrap_or_else(|| app.origins.origin(OriginKind::NpmMetadata).clone());
    let origins = OriginSet::selected_npm_with_private(
        origin.clone(),
        principal.registry_private_cidrs.clone(),
    )
    .map_err(|_| ApiError::NotFound)?;
    let normalized = normalized_named_segments(&request.path);
    let segments: Vec<_> = if let Some((name, revision)) = request.path.split_once("/-rev/") {
        if let Some((package, filename)) = name.split_once("/-/") {
            package
                .split('/')
                .chain(["-", filename, "-rev", revision])
                .collect()
        } else if name.starts_with("-/") {
            name.split('/').chain(["-rev", revision]).collect()
        } else {
            vec![name, "-rev", revision]
        }
    } else if request.path.starts_with("-/") {
        normalized.iter().map(String::as_str).collect()
    } else {
        vec![request.path.as_str()]
    };
    let mut url = origins
        .url_for(OriginKind::NpmMetadata, &segments)
        .map_err(|_| ApiError::NotFound)?;
    url.set_query(request.query.as_deref());
    origins
        .admit(&url, OriginKind::NpmMetadata)
        .map_err(|_| ApiError::NotFound)?;
    Ok((origin, url))
}

fn normalized_named_segments(path: &str) -> Vec<String> {
    let parts: Vec<_> = path.split('/').collect();
    if parts.len() >= 5 && parts[0] == "-" && parts[1] == "package" && parts[2].starts_with('@') {
        let mut normalized = vec![
            parts[0].to_owned(),
            parts[1].to_owned(),
            format!("{}/{}", parts[2], parts[3]),
        ];
        normalized.extend(parts[4..].iter().map(|part| (*part).to_owned()));
        normalized
    } else {
        parts.into_iter().map(str::to_owned).collect()
    }
}

fn admit_publish_request(
    _principal: &Principal,
    request: &RegistryActionRequest,
) -> Result<Option<String>, ApiError> {
    if matches!(
        (request.method.as_str(), request.path.as_str()),
        ("POST", "-/v1/login") | ("GET", "-/v1/login/done")
    ) {
        return Ok(None);
    }
    let path = request.path.as_str();
    if legacy_login_path(path, &request.method) {
        let authorization = request
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok());
        return match authorization {
            None => Ok(None),
            Some(value) if value.starts_with("Basic ") && value.len() > 6 => {
                Ok(Some(value.to_owned()))
            }
            _ => Err(ApiError::Unauthenticated),
        };
    }
    let normalized = normalized_named_segments(path);
    let segments: Vec<_> = normalized.iter().map(String::as_str).collect();
    let named = match segments.as_slice() {
        ["-", "package", _, "dist-tags"]
        | ["-", "package", _, "visibility"]
        | ["-", "package", _, "collaborators"]
        | ["-", "package", _, "trust"] => matches!(request.method, Method::GET | Method::POST),
        ["-", "package", _, "dist-tags", _] => {
            matches!(request.method, Method::PUT | Method::DELETE)
        }
        ["-", "package", _, "access"] => request.method == Method::POST,
        ["-", "package", _, "trust", _] => request.method == Method::DELETE,
        ["-", "team", _, _, "package"]
        | ["-", "team", _, _, "user"]
        | ["-", "org", _, "team"]
        | ["-", "org", _, "user"] => {
            matches!(request.method, Method::GET | Method::PUT | Method::DELETE)
        }
        ["-", "team", _, _] => request.method == Method::DELETE,
        ["-", "org", _, "package"] | ["-", "user", _, "package"] => request.method == Method::GET,
        ["-", "user", user] if user.starts_with("org.couchdb.user:") => {
            request.method == Method::GET
        }
        ["-", "user", "token", _] => request.method == Method::DELETE,
        ["-", "npm", "v1", "user"] => matches!(request.method, Method::GET | Method::POST),
        ["-", "npm", "v1", "tokens"] => matches!(request.method, Method::GET | Method::POST),
        ["-", "npm", "v1", "tokens", "token", _] => request.method == Method::DELETE,
        ["-", "_view", "starredByUser"] => request.method == Method::GET,
        ["-", "stage"] => request.method == Method::GET,
        ["-", "stage", "package", _] => request.method == Method::POST,
        ["-", "stage", _] => matches!(request.method, Method::GET | Method::DELETE),
        ["-", "stage", _, "approve"] => request.method == Method::POST,
        ["-", "stage", _, "tarball"] => request.method == Method::GET,
        _ => false,
    };
    if !named && !canonical_package_action(request) {
        return Err(ApiError::NotFound);
    }
    let value = request
        .headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(ApiError::Unauthenticated)?;
    if !value.starts_with("Bearer ") || value.len() <= 7 {
        return Err(ApiError::Unauthenticated);
    }
    Ok(Some(value.to_owned()))
}

fn legacy_login_path(path: &str, method: &Method) -> bool {
    if method != Method::PUT {
        return false;
    }
    let Some(rest) = path.strip_prefix("-/user/org.couchdb.user:") else {
        return false;
    };
    let (username, revision) = rest
        .split_once("/-rev/")
        .map_or((rest, None), |(name, rev)| (name, Some(rev)));
    !username.is_empty()
        && username.len() <= 214
        && username
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        && revision.is_none_or(valid_revision)
}

fn canonical_package_action(request: &RegistryActionRequest) -> bool {
    let path = request.path.as_str();
    if path.starts_with("-/") || request.query.is_some() {
        return false;
    }
    if request.method == Method::PUT && PackageName::parse_route(path).is_ok() {
        return true;
    }
    if let Some((name, revision)) = path.split_once("/-rev/") {
        if !valid_revision(revision) {
            return false;
        }
        if let Some((package, filename)) = name.split_once("/-/") {
            return request.method == Method::DELETE
                && canonical_tarball(package, filename);
        }
        return matches!(request.method, Method::PUT | Method::DELETE)
            && PackageName::parse_route(name).is_ok();
    }
    false
}

pub(super) fn canonical_tarball(package: &str, filename: &str) -> bool {
    let base = package.rsplit('/').next().unwrap_or("");
    PackageName::parse_route(package).is_ok()
        && filename.len() <= 255
        && filename.starts_with(&format!("{base}-"))
        && filename.ends_with(".tgz")
        && !filename.contains('/')
}

pub(super) fn valid_revision(revision: &str) -> bool {
    !revision.is_empty()
        && revision.len() <= 100
        && revision
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

async fn send_action(
    app: &Arc<App>,
    request: ActionRequest,
) -> Result<crate::upstream::ActionResponse, UpstreamError> {
    app.transport.send_action(request).await
}

fn map_login_start(
    body: &Bytes,
    origin: &Url,
    public_url: &Url,
    selected_base: &str,
) -> Result<Bytes, ApiError> {
    let mut value: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| ApiError::UpstreamInvalid)?;
    let done = value
        .get("doneUrl")
        .and_then(serde_json::Value::as_str)
        .ok_or(ApiError::UpstreamInvalid)?;
    let done = Url::parse(done).map_err(|_| ApiError::UpstreamInvalid)?;
    if done.scheme() != origin.scheme()
        || done.host_str() != origin.host_str()
        || done.port_or_known_default() != origin.port_or_known_default()
        || done.path() != "/-/v1/login/done"
        || done.query().is_some()
        || done.fragment().is_some()
    {
        return Err(ApiError::UpstreamInvalid);
    }
    let selected = public_url
        .join(&format!("{selected_base}-/v1/login/done"))
        .map_err(|_| ApiError::UpstreamInvalid)?;
    value["doneUrl"] = serde_json::Value::String(selected.to_string());
    serde_json::to_vec(&value)
        .map(Bytes::from)
        .map_err(|_| ApiError::UpstreamInvalid)
}
