//! Per-request certificate admission for a selected registry.

use std::sync::Arc;

use axum::Extension;
use axum::http::HeaderMap;
use probation_policy::api::RegistryId;
use tokio::sync::OwnedSemaphorePermit;

use crate::App;
use crate::http::error::ApiError;
use crate::http::logging;
use crate::managed::certificates::VerifiedPeer;
use crate::managed::{Principal, Refusal};
use crate::policy::Ecosystem;

pub(super) fn registry_id(raw: &str) -> Result<RegistryId, ApiError> {
    let id = raw.parse::<u64>().map_err(|_| ApiError::NotFound)?;
    if id == 0 || id > i64::MAX as u64 || id.to_string() != raw {
        return Err(ApiError::NotFound);
    }
    Ok(RegistryId(id))
}

pub(super) async fn admit(
    app: &Arc<App>,
    peer: Option<Extension<VerifiedPeer>>,
    registry: RegistryId,
    headers: &HeaderMap,
) -> Result<(OwnedSemaphorePermit, Principal), ApiError> {
    let permit = app.limits.active_permit().ok_or(ApiError::Overloaded)?;
    if !app.store().is_healthy() {
        return Err(ApiError::StorageUnusable);
    }
    let managed = app.managed().ok_or(ApiError::NotReady)?;
    if !managed.ready() {
        return Err(ApiError::NotReady);
    }
    let peer = peer.ok_or(ApiError::Unauthenticated)?;
    let socket = logging::peer().ok_or(ApiError::NotReady)?;
    let principal = managed
        .admit_certificate(&peer, registry, Ecosystem::Npm, socket, headers, true)
        .await
        .map_err(map_refusal)?;
    logging::record_place(principal.place.id);
    Ok((permit, principal))
}

pub(super) async fn admit_pypi(
    app: &Arc<App>, peer: Option<Extension<VerifiedPeer>>, registry: RegistryId, headers: &HeaderMap,
) -> Result<(OwnedSemaphorePermit, Principal), ApiError> {
    admit_for(app, peer, registry, headers, Ecosystem::PyPi).await
}

async fn admit_for(
    app: &Arc<App>, peer: Option<Extension<VerifiedPeer>>, registry: RegistryId, headers: &HeaderMap,
    ecosystem: Ecosystem,
) -> Result<(OwnedSemaphorePermit, Principal), ApiError> {
    let permit = app.limits.active_permit().ok_or(ApiError::Overloaded)?;
    if !app.store().is_healthy() {
        return Err(ApiError::StorageUnusable);
    }
    let managed = app.managed().ok_or(ApiError::NotReady)?;
    if !managed.ready() {
        return Err(ApiError::NotReady);
    }
    let peer = peer.ok_or(ApiError::Unauthenticated)?;
    let socket = logging::peer().ok_or(ApiError::NotReady)?;
    let principal = managed
        .admit_certificate(&peer, registry, ecosystem, socket, headers, true)
        .await
        .map_err(map_refusal)?;
    logging::record_place(principal.place.id);
    Ok((permit, principal))
}

pub(super) async fn recheck(
    app: &Arc<App>,
    peer: Option<Extension<VerifiedPeer>>,
    registry: RegistryId,
    headers: &HeaderMap,
) -> Result<Principal, ApiError> {
    recheck_for(app, peer, registry, headers, Ecosystem::Npm).await
}

pub(super) async fn recheck_pypi(
    app: &Arc<App>, peer: Option<Extension<VerifiedPeer>>, registry: RegistryId, headers: &HeaderMap,
) -> Result<Principal, ApiError> {
    recheck_for(app, peer, registry, headers, Ecosystem::PyPi).await
}

async fn recheck_for(
    app: &Arc<App>, peer: Option<Extension<VerifiedPeer>>, registry: RegistryId, headers: &HeaderMap,
    ecosystem: Ecosystem,
) -> Result<Principal, ApiError> {
    if !app.store().is_healthy() {
        return Err(ApiError::StorageUnusable);
    }
    let managed = app.managed().ok_or(ApiError::NotReady)?;
    if !managed.ready() {
        return Err(ApiError::NotReady);
    }
    let peer = peer.ok_or(ApiError::Unauthenticated)?;
    let socket = logging::peer().ok_or(ApiError::NotReady)?;
    let principal = managed
        .admit_certificate(&peer, registry, ecosystem, socket, headers, false)
        .await
        .map_err(map_refusal)?;
    logging::record_place(principal.place.id);
    Ok(principal)
}

fn map_refusal(refusal: Refusal) -> ApiError {
    match refusal {
        Refusal::Unauthenticated => ApiError::Unauthenticated,
        Refusal::Network(address) => ApiError::NetworkNotAllowed(address),
        Refusal::RateLimited => ApiError::TooManyRequests,
        Refusal::Busy => ApiError::LookupBusy,
    }
}
