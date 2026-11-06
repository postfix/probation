//! The npm version-unpublish lease: only a listed, member-bound destination can be deleted.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::sync::Arc;
use std::collections::HashMap;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use axum::http::Method;
use axum::response::{IntoResponse, Response};
use tokio::io::{AsyncReadExt, AsyncWriteExt, AsyncSeekExt};
use url::Url;

use crate::App;
use crate::http::error::ApiError;
use crate::managed::Principal;
use crate::npm::document::VersionEntry;
use crate::store::action_leases::ActionLease;
use crate::store::rows::ReferenceId;
use crate::upstream::{ActionRequest, ActionResponse, OriginKind, UpstreamError};

const LEASE_LIFETIME_MICROS: i64 = 24 * 60 * 60 * 1_000_000;

fn lease_aad(registry: u64, member: u32, id: ReferenceId) -> String {
    if member == 0 {
        return format!("npm-service-unpublish:{registry}:{}", id.to_hex());
    }
    format!("npm-unpublish:{registry}:{member}:{}", id.to_hex())
}

fn lease_owner(app: &App, principal: &Principal) -> Result<u32, ApiError> {
    // Zero is the local store namespace; historical membership identities are positive.
    if app.service_policy().is_some() { return Ok(0); }
    if principal.place.id == 0 { return Err(ApiError::Unauthenticated); }
    Ok(principal.place.id)
}

fn data_key(app: &App) -> Result<[u8; 32], ApiError> {
    let path = app.config.data_dir.join("npm-unpublish.key");
    let marker = app.config.data_dir.join("npm-unpublish-key-created");
    if !path.exists() {
        if marker.exists() { return Err(ApiError::StorageUnusable); }
        let mut key = [0; 32];
        getrandom::fill(&mut key).map_err(|_| ApiError::StorageUnusable)?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        let mut file = match crate::delivery::owner_only(&mut options).open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => return read_key(&path),
            Err(_) => return Err(ApiError::StorageUnusable),
        };
        file.write_all(&key).and_then(|_| file.sync_all()).map_err(|_| ApiError::StorageUnusable)?;
        fs::write(&marker, b"v1").map_err(|_| ApiError::StorageUnusable)?;
        crate::config::sync_directory(&app.config.data_dir).map_err(|_| ApiError::StorageUnusable)?;
        return Ok(key);
    }
    read_key(&path)
}

fn read_key(path: &std::path::Path) -> Result<[u8; 32], ApiError> {
    fs::read(path).map_err(|_| ApiError::StorageUnusable)?.try_into().map_err(|_| ApiError::StorageUnusable)
}

fn seal_url(app: &App, registry: u64, member: u32, id: ReferenceId, url: &Url) -> Result<Vec<u8>, ApiError> {
    let key = data_key(app)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| ApiError::StorageUnusable)?;
    let mut nonce = [0; 12];
    getrandom::fill(&mut nonce).map_err(|_| ApiError::StorageUnusable)?;
    let aad = lease_aad(registry, member, id);
    let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce), Payload { msg: url.as_str().as_bytes(), aad: aad.as_bytes() })
        .map_err(|_| ApiError::StorageUnusable)?;
    Ok([nonce.as_slice(), &ciphertext].concat())
}

pub(super) fn open_url(app: &App, lease: &ActionLease) -> Result<Url, ApiError> {
    let key = data_key(app)?;
    let (nonce, ciphertext) = lease.sealed_url.split_at_checked(12).ok_or(ApiError::StorageUnusable)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| ApiError::StorageUnusable)?;
    let aad = lease_aad(lease.registry_id, lease.member_id, lease.reference_id);
    let clear = cipher.decrypt(Nonce::from_slice(nonce), Payload { msg: ciphertext, aad: aad.as_bytes() })
        .map_err(|_| ApiError::StorageUnusable)?;
    Url::parse(std::str::from_utf8(&clear).map_err(|_| ApiError::StorageUnusable)?)
        .map_err(|_| ApiError::StorageUnusable)
}

fn unambiguous_url(url: &Url) -> bool {
    let path = url.path();
    url.scheme() == "https" && url.host_str().is_some() && url.username().is_empty()
        && url.password().is_none() && url.fragment().is_none() && url.as_str().len() <= 2048
        && !path.contains('\\') && !path.contains("//")
        && !path.to_ascii_lowercase().contains("%2e") && !path.to_ascii_lowercase().contains("%2f") && !path.to_ascii_lowercase().contains("%5c")
        && !path.split('/').any(|segment| segment == "." || segment == "..")
}

fn unambiguous_raw_path(raw: &str) -> bool {
    let Some((_, authority_and_path)) = raw.split_once("://") else { return false; };
    let Some((_, path_and_query)) = authority_and_path.split_once('/') else { return false; };
    let path = path_and_query.split(['?', '#']).next().unwrap_or("").to_ascii_lowercase();
    !path.contains("//") && !path.contains('\\') && !path.contains("%2e")
        && !path.contains("%2f") && !path.contains("%5c")
        && !path.split('/').any(|segment| segment == "." || segment == "..")
}

fn same_origin(left: &Url, right: &Url) -> bool { left.origin() == right.origin() }
fn within_prefix(path: &str, prefix: &str) -> bool {
    if prefix == "/" { return path.starts_with('/'); }
    path == prefix || path.strip_prefix(prefix).is_some_and(|tail| tail.starts_with('/'))
}

pub(super) fn approve_deletion_scope(app: &App, principal: &Principal, lease: &ActionLease, url: &Url) -> Result<(Url, bool), ApiError> {
    if !unambiguous_url(url) || !url.path().ends_with(&format!("/{}", lease.filename)) {
        return Err(ApiError::InvalidInput("the advertised tarball destination is not approved"));
    }
    let selected = principal.registry_origin.as_ref().unwrap_or_else(|| app.origins.origin(OriginKind::NpmMetadata));
    if app.service_policy().is_some() && !same_origin(url, selected) {
        return Err(ApiError::InvalidInput("service unpublish requires the selected registry origin"));
    }
    let canonical = format!("/{}/-/{}", lease.package, lease.filename);
    if same_origin(url, selected) && url.path() == canonical && within_prefix(url.path(), selected.path().trim_end_matches('/')) {
        return Ok((selected.clone(), true));
    }
    for scope in &principal.deletion_scopes {
        let Ok(origin) = Url::parse(&scope.origin) else { continue; };
        if same_origin(url, &origin) && within_prefix(url.path(), &scope.path_prefix) {
            let bearer = same_origin(&origin, selected) || scope.forward_bearer;
            return Ok((origin, bearer));
        }
    }
    Err(ApiError::InvalidInput("the advertised tarball destination is not approved"))
}

pub async fn prepare_leases(app: &App, principal: &Principal, registry: u64, package: &str, entries: &[VersionEntry]) -> Result<(), ApiError> {
    let now = app.clock.now_utc_micros();
    let owner = lease_owner(app, principal)?;
    let mut leases = Vec::with_capacity(entries.len());
    for entry in entries {
        let raw = entry.record.get("dist").and_then(|dist| dist.get("tarball")).and_then(serde_json::Value::as_str)
            .ok_or(ApiError::UpstreamInvalid)?;
        if !unambiguous_raw_path(raw) { return Err(ApiError::UpstreamInvalid); }
        let id = entry.id;
        let lease = ActionLease { registry_id: registry, member_id: owner, reference_id: id,
            package: entry.reference.name.clone(), version: entry.reference.version.clone(), filename: entry.reference.filename.clone(),
            sealed_url: Vec::new(), expires_at_micros: now.saturating_add(LEASE_LIFETIME_MICROS) };
        approve_deletion_scope(app, principal, &lease, &entry.reference.upstream_url)?;
        leases.push(ActionLease { sealed_url: seal_url(app, registry, owner, id, &entry.reference.upstream_url)?, ..lease });
    }
    app.store().commit_action_leases(registry, owner, package, leases, now).await.map_err(|_| ApiError::StorageUnusable)
}

async fn check_registry_reference(app: &App, principal: &Principal, registry: u64, id: ReferenceId, filename: &str) -> Result<ActionLease, ApiError> {
    let lease = app.store().get_action_lease(registry, principal.place.id, id, app.clock.now_utc_micros()).await.map_err(|_| ApiError::StorageUnusable)?
        .ok_or(ApiError::NotFound)?;
    if lease.registry_id != registry || lease.member_id != principal.place.id || lease.filename != filename { return Err(ApiError::NotFound); }
    Ok(lease)
}

fn admit_stored_destination(app: &App, lease: &ActionLease, revision: &str) -> Result<Url, ApiError> {
    if !valid_revision(revision) { return Err(ApiError::InvalidInput("invalid revision")); }
    let mut url = open_url(app, lease)?;
    if !unambiguous_url(&url) || !url.path().ends_with(&format!("/{}", lease.filename)) {
        return Err(ApiError::InvalidInput("invalid stored destination"));
    }
    url.path_segments_mut().map_err(|_| ApiError::InvalidInput("invalid destination"))?.push("-rev").push(revision);
    Ok(url)
}

fn valid_revision(revision: &str) -> bool {
    !revision.is_empty() && revision.len() <= 100 && revision.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

async fn check_removal_marker(app: &App, lease: &ActionLease, revision: &str) -> Result<(), ApiError> {
    let consumed = app.store().consume_action_marker(lease.registry_id, lease.member_id, lease.reference_id, revision.to_owned(), app.clock.now_utc_micros()).await.map_err(|_| ApiError::StorageUnusable)?;
    if consumed { Ok(()) } else { Err(ApiError::NotFound) }
}

pub async fn send_unpublish_delete(app: &Arc<App>, principal: &Principal, registry: u64, id: ReferenceId, filename: &str, revision: &str, authorization: String) -> Result<Response, ApiError> {
    let reference = check_registry_reference(app, principal, registry, id, filename).await?;
    let url = admit_stored_destination(app, &reference, revision)?;
    let advertised = open_url(app, &reference)?;
    let (origin, bearer) = approve_deletion_scope(app, principal, &reference, &advertised)?;
    let file = tempfile::tempfile_in(&app.config.data_dir).map_err(|_| ApiError::StorageUnusable)?;
    let marker = check_removal_marker(app, &reference, revision);
    marker.await?;
    let action = ActionRequest { url, origin, private_cidrs: principal.registry_private_cidrs.clone(), method: Method::DELETE,
        authorization: bearer.then_some(authorization), content_type: None, body: tokio::fs::File::from_std(file), body_len: 0,
        max_bytes: app.config.max_metadata_bytes.get() };
    let result = app.transport.send_action(action).await.map_err(|error| match error { UpstreamError::Timeout => ApiError::UpstreamTimeout, _ => ApiError::UpstreamFailure })?;
    let status = axum::http::StatusCode::from_u16(result.status).map_err(|_| ApiError::UpstreamInvalid)?;
    Ok((status, result.body).into_response())
}

struct RestoredRevision { body: Vec<u8>, removed: Vec<ActionLease> }

async fn restore_revision_links(app: &App, principal: &Principal, registry: u64, package: &str, body: &[u8]) -> Result<RestoredRevision, ApiError> {
    let mut value: serde_json::Value = serde_json::from_slice(body).map_err(|_| ApiError::InvalidInput("invalid revision JSON"))?;
    if value.get("name").and_then(serde_json::Value::as_str) != Some(package) { return Err(ApiError::InvalidInput("revision package mismatch")); }
    let versions = value.get_mut("versions").and_then(serde_json::Value::as_object_mut)
        .ok_or(ApiError::InvalidInput("revision has no versions"))?;
    if versions.len() > app.config.max_references_per_project.get() as usize { return Err(ApiError::InvalidInput("too many revision references")); }
    let leases = app.store().list_action_leases(registry, lease_owner(app, principal)?, package, app.clock.now_utc_micros()).await.map_err(|_| ApiError::StorageUnusable)?;
    let by_version: HashMap<_, _> = leases.iter().map(|lease| (lease.version.as_str(), lease)).collect();
    for (version, record) in versions.iter_mut() {
        let tarball = record.get_mut("dist").and_then(serde_json::Value::as_object_mut)
            .and_then(|dist| dist.get_mut("tarball")).and_then(|value| value.as_str())
            .ok_or(ApiError::InvalidInput("revision tarball missing"))?.to_owned();
        if let Some(lease) = by_version.get(version.as_str()) {
            let old = open_url(app, lease)?;
            approve_deletion_scope(app, principal, lease, &old)?;
            let mut public_url = app.config.public_url.clone();
            public_url.set_path(&format!("/registry/npm/{registry}/"));
            let local = crate::npm::render::artifact_url(&public_url, crate::policy::Ecosystem::Npm,
                &lease.reference_id, &lease.filename);
            if tarball != local && tarball != old.as_str() {
                return Err(ApiError::InvalidInput("revision link has no lease"));
            }
            record["dist"]["tarball"] = old.as_str().into();
            continue;
        }
        let local = Url::parse(&tarball).map_err(|_| ApiError::InvalidInput("invalid local tarball link"))?;
        if !same_origin(&local, &app.config.public_url) { continue; }
        return Err(ApiError::InvalidInput("revision link has no lease"));
    }
    let removed = leases.iter().filter(|lease| !versions.contains_key(&lease.version)).cloned().collect();
    let body = serde_json::to_vec(&value).map_err(|_| ApiError::InvalidInput("invalid revision JSON"))?;
    if body.len() as u64 > app.config.max_metadata_bytes.get() { return Err(ApiError::InvalidInput("revision body too large")); }
    Ok(RestoredRevision { body, removed })
}

fn classify_accepted_removal(result: &ActionResponse, restored: &RestoredRevision) -> Result<Option<(Vec<ReferenceId>, String)>, ApiError> {
    if !(200..300).contains(&result.status) || restored.removed.is_empty() { return Ok(None); }
    let value: serde_json::Value = serde_json::from_slice(&result.body).map_err(|_| ApiError::PartialWriteUncertain)?;
    let revision = value.get("rev").and_then(serde_json::Value::as_str).filter(|value| valid_revision(value))
        .ok_or(ApiError::PartialWriteUncertain)?;
    Ok(Some((restored.removed.iter().map(|lease| lease.reference_id).collect(), revision.to_owned())))
}

async fn commit_removal_marker(app: &App, principal: &Principal, registry: u64, removal: Option<(Vec<ReferenceId>, String)>) -> Result<(), ApiError> {
    if let Some((removed, revision)) = removal {
        app.store().mark_removed_leases(registry, principal.place.id, removed, revision).await.map_err(|_| ApiError::PartialWriteUncertain)?;
    }
    Ok(())
}

fn return_put_success(result: ActionResponse) -> ActionResponse { result }

async fn forward_owner_revision_put(app: &App, mut action: ActionRequest) -> Result<ActionResponse, ApiError> {
    action.body.rewind().await.map_err(|_| ApiError::StorageUnusable)?;
    app.transport.send_action(action).await.map_err(|error| match error {
        UpstreamError::Timeout => ApiError::UpstreamTimeout,
        _ => ApiError::UpstreamFailure,
    })
}

pub async fn forward_revision_put(app: &Arc<App>, principal: &Principal, registry: u64, package: &str, mut action: ActionRequest) -> Result<ActionResponse, ApiError> {
    if action.body_len > app.config.max_metadata_bytes.get() { return Err(ApiError::InvalidInput("revision body too large")); }
    let mut original = Vec::with_capacity(action.body_len as usize);
    action.body.read_to_end(&mut original).await.map_err(|_| ApiError::StorageUnusable)?;
    let shape: serde_json::Value = serde_json::from_slice(&original).map_err(|_| ApiError::InvalidInput("invalid revision JSON"))?;
    if shape.get("versions").is_none() {
        return forward_owner_revision_put(app, action).await;
    }
    let outgoing = restore_revision_links(app, principal, registry, package, &original).await?;
    let file = tempfile::tempfile_in(&app.config.data_dir).map_err(|_| ApiError::StorageUnusable)?;
    let mut file = tokio::fs::File::from_std(file);
    file.write_all(&outgoing.body).await.map_err(|_| ApiError::StorageUnusable)?;
    file.flush().await.map_err(|_| ApiError::StorageUnusable)?;
    file.rewind().await.map_err(|_| ApiError::StorageUnusable)?;
    action.body = file;
    action.body_len = outgoing.body.len() as u64;
    let service_removal = super::service_unpublish::ServiceRemoval {
        app, registry, package, removed: &outgoing.removed, origin: action.origin.clone(),
        private_cidrs: action.private_cidrs.clone(), authorization: action.authorization.clone(),
    };
    let result = app.transport.send_action(action).await.map_err(|error| match error { UpstreamError::Timeout => ApiError::UpstreamTimeout, _ => ApiError::UpstreamFailure })?;
    if app.service_policy().is_some() {
        super::service_unpublish::record_successful_service_removal(&result, service_removal).await?;
    } else {
        let removal = classify_accepted_removal(&result, &outgoing)?;
        let marker = commit_removal_marker(app, principal, registry, removal);
        marker.await?;
    }
    Ok(return_put_success(result))
}

#[cfg(test)]
mod tests {
    use super::{unambiguous_raw_path, within_prefix, LEASE_LIFETIME_MICROS};

    #[test]
    fn unpublish_lease_lives_for_exactly_24_hours() {
        assert_eq!(LEASE_LIFETIME_MICROS, 24 * 60 * 60 * 1_000_000);
    }

    #[test]
    fn deletion_scope_uses_segment_boundaries_including_root() {
        assert!(within_prefix("/packages/one/file.tgz", "/packages"));
        assert!(!within_prefix("/packages-extra/file.tgz", "/packages"));
        assert!(within_prefix("/packages/file.tgz", "/"));
    }

    #[test]
    fn advertised_url_rejects_ambiguous_raw_path() {
        for candidate in [
            "https://registry.example/a/../b/file.tgz",
            "https://registry.example/a/%2e%2e/b/file.tgz",
            "https://registry.example/a/%2f/b/file.tgz",
            "https://registry.example/a/\\/b/file.tgz",
            "https://registry.example/a//b/file.tgz",
        ] {
            assert!(!unambiguous_raw_path(candidate), "{candidate}");
        }
    }
}
