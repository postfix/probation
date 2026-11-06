//! Service-store removal verification and one-use selected-origin npm deletion.

use std::sync::Arc;

use axum::{http::{Method, StatusCode}, response::{IntoResponse, Response}};
use probation_policy::{Ecosystem, api::RegistryId};
use url::Url;

use crate::{App, http::error::ApiError, store::{action_leases::ActionLease, rows::ReferenceId},
    upstream::{ActionRequest, ActionResponse, MetadataRequest, MetadataResponse, OriginKind, OriginSet, UpstreamError}};
use super::{registry_action::valid_revision, unpublish_reference::{approve_deletion_scope, open_url}};

pub(super) struct ServiceRemoval<'a> {
    pub app: &'a App,
    pub registry: u64,
    pub package: &'a str,
    pub removed: &'a [ActionLease],
    pub origin: Url,
    pub private_cidrs: Vec<ipnet::IpNet>,
    pub authorization: Option<String>,
}

pub(super) async fn record_successful_service_removal(response: &ActionResponse, reference: ServiceRemoval<'_>) -> Result<(), ApiError> {
    let revision = resolve_removed_revision_from_put_or_authenticated_get(&response, &reference).await?;
    commit_service_removal_marker(&reference, revision).await
}

async fn resolve_removed_revision_from_put_or_authenticated_get(response: &ActionResponse, reference: &ServiceRemoval<'_>) -> Result<Option<String>, ApiError> {
    if !(200..300).contains(&response.status) || reference.removed.is_empty() { return Ok(None); }
    let value: serde_json::Value = serde_json::from_slice(&response.body).map_err(|_| ApiError::PartialWriteUncertain)?;
    if !value.is_object() || value.get("id").is_some_and(|id| id.as_str() != Some(reference.package)) {
        return Err(ApiError::PartialWriteUncertain);
    }
    if let Some(revision) = value.get("rev") {
        return revision.as_str().filter(|rev| valid_revision(rev)).map(|rev| Some(rev.to_owned())).ok_or(ApiError::PartialWriteUncertain);
    }
    let origins = OriginSet::selected_npm_with_private(reference.origin.clone(), reference.private_cidrs.clone())
        .map_err(|_| ApiError::PartialWriteUncertain)?;
    let url = origins.url_for(OriginKind::NpmMetadata, &[reference.package]).map_err(|_| ApiError::PartialWriteUncertain)?;
    let authorization = reference.authorization.as_deref().ok_or(ApiError::PartialWriteUncertain)?;
    let fetched = reference.app.transport.fetch_token_packument(MetadataRequest {
        url, origin: Some(reference.origin.clone()), private_cidrs: reference.private_cidrs.clone(),
        read_authorization: None, accept: "application/json", validators: None,
        max_bytes: reference.app.config.max_metadata_bytes.get(),
    }, authorization).await.map_err(|_| ApiError::PartialWriteUncertain)?;
    let MetadataResponse::Fresh { body, .. } = fetched else { return Err(ApiError::PartialWriteUncertain); };
    let value: serde_json::Value = serde_json::from_slice(&body).map_err(|_| ApiError::PartialWriteUncertain)?;
    let versions = value.get("versions").and_then(serde_json::Value::as_object).ok_or(ApiError::PartialWriteUncertain)?;
    if value.get("name").and_then(serde_json::Value::as_str) != Some(reference.package)
        || reference.removed.iter().any(|lease| versions.contains_key(&lease.version)) {
        return Err(ApiError::PartialWriteUncertain);
    }
    value.get("_rev").and_then(serde_json::Value::as_str).filter(|rev| valid_revision(rev))
        .map(|rev| Some(rev.to_owned())).ok_or(ApiError::PartialWriteUncertain)
}

async fn commit_service_removal_marker(reference: &ServiceRemoval<'_>, revision: Option<String>) -> Result<(), ApiError> {
    if let Some(revision) = revision {
        reference.app.store().mark_removed_leases(reference.registry, 0,
            reference.removed.iter().map(|lease| lease.reference_id).collect(), revision).await
            .map_err(|_| ApiError::PartialWriteUncertain)?;
    }
    Ok(())
}

struct ServiceReference {
    lease: ActionLease,
    url: Url,
    origin: Url,
    private_cidrs: Vec<ipnet::IpNet>,
}

async fn check_service_reference(app: &App, registry: u64, reference: ReferenceId, package: Option<&str>, filename: &str) -> Result<ServiceReference, ApiError> {
    let lease = app.store().get_action_lease(registry, 0, reference, app.clock.now_utc_micros()).await
        .map_err(|_| ApiError::StorageUnusable)?.ok_or(ApiError::NotFound)?;
    if lease.registry_id != registry || lease.member_id != 0 || lease.reference_id != reference
        || lease.filename != filename || package.is_some_and(|package| package != lease.package)
        || lease.version.is_empty() || crate::npm::PackageName::parse_route(&lease.package).is_err() {
        return Err(ApiError::NotFound);
    }
    let principal = app.service_policy().ok_or(ApiError::NotReady)?.principal(RegistryId(registry), Ecosystem::Npm)
        .ok_or(ApiError::PolicyUnavailable)?;
    let url = open_url(app, &lease)?;
    let (origin, _) = approve_deletion_scope(app, &principal, &lease, &url)?;
    Ok(ServiceReference { lease, url, origin, private_cidrs: principal.registry_private_cidrs })
}

async fn consume_service_marker(app: &App, registry: u64, reference: &ServiceReference, revision: &str) -> Result<bool, ApiError> {
    app.store().consume_action_marker(registry, 0, reference.lease.reference_id, revision.to_owned(), app.clock.now_utc_micros()).await
        .map_err(|_| ApiError::StorageUnusable)
}

pub(super) async fn consume_service_marker_then_send(app: &Arc<App>, registry: u64, reference: ReferenceId, package: Option<&str>, filename: &str, revision: &str, authorization: String) -> Result<Response, ApiError> {
    if !valid_revision(revision) || !authorization.starts_with("Bearer ") || authorization.len() <= 7 {
        return Err(ApiError::NotFound);
    }
    let reference = check_service_reference(&app, registry, reference, package, filename).await?;
    let mut url = reference.url.clone();
    url.path_segments_mut().map_err(|_| ApiError::NotFound)?.push("-rev").push(revision);
    let file = tempfile::tempfile_in(&app.config.data_dir).map_err(|_| ApiError::StorageUnusable)?;
    let marker = consume_service_marker(&app, registry, &reference, revision).await?;
    if !marker { return Err(ApiError::NotFound); }
    let result = app.transport.send_action(ActionRequest {
        url, origin: reference.origin, private_cidrs: reference.private_cidrs, method: Method::DELETE,
        authorization: Some(authorization), content_type: None, body: tokio::fs::File::from_std(file), body_len: 0,
        max_bytes: app.config.max_metadata_bytes.get(),
    }).await.map_err(|error| match error { UpstreamError::Timeout => ApiError::UpstreamTimeout, _ => ApiError::UpstreamFailure })?;
    Ok((StatusCode::from_u16(result.status).map_err(|_| ApiError::UpstreamInvalid)?, result.body).into_response())
}
