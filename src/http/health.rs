//! `GET /health/live` and `GET /health/ready` (SPEC §11).

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;

use crate::App;

/// Process liveness. True as soon as the router answers, and it stays true through
/// an expired blocklist or an unusable store — that is what readiness is for.
pub async fn live() -> StatusCode {
    StatusCode::OK
}

/// Valid policy, usable storage, service ready; no live upstream probe.
///
/// Readiness is exactly "is a valid blocklist in force?". Expiry needs no poller: the
/// window is compared against the clock on every request, which is the same reading
/// `policy::evaluate` decides with. SPEC §8: at expiry readiness becomes unhealthy
/// while liveness stays healthy.
///
/// Storage is checked explicitly from slice 7 on. Until then it held transitively —
/// a store that would not open published no snapshot, so readiness was already false.
/// Slice 7 adds a second writer, and SPEC §10 requires that a write failing *after* a
/// snapshot is in force turns readiness false too: "Storage write failures make
/// readiness false and deny package responses with `503` until storage is usable
/// again." `StoreHandle::is_healthy` is that flag, and it goes back to true when a
/// command succeeds again.
///
/// A managed firewall ignores its local blocklist (C109): it is ready once a cache
/// snapshot is loaded or a sync applied, while it is not retired and its store is
/// healthy — the condition `admit` serves under — and not while the management server
/// refuses even an empty sync.
pub async fn ready(State(app): State<Arc<App>>) -> axum::response::Response {
    use axum::response::IntoResponse;
    if let Some(policy) = app.service_policy() {
        return service_ready(&app, policy).into_response();
    }
    plain_ready(State(app)).await.into_response()
}

/// Shared-service readiness: the status of the plain rule plus the state an operator needs
/// to see (policy, gate, degraded registries, skipped rules, credential-read bytes).
fn service_ready(app: &App, policy: &crate::managed::service_policy::ServicePolicy) -> axum::response::Response {
    use axum::response::IntoResponse;
    let active = policy.snapshot().is_some();
    let poisoned = policy.publication_gate.is_poisoned();
    let ok = active && !poisoned && app.store().is_healthy();
    let status = if ok { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE };
    // The status code is the orchestrator probe and stays the same for every peer. The detail
    // (registry ids, counters, temp bytes) is for peers the listener admits (S28-7).
    let admitted = super::logging::peer()
        .is_some_and(|peer| super::listener_admission::peer_admitted(peer, &app.config.allowed_peer_cidrs));
    if !admitted {
        return status.into_response();
    }
    let degraded: Vec<u64> = policy.unavailable_registries().iter().map(|id| id.0).collect();
    (
        status,
        axum::Json(serde_json::json!({
            "policy_active": active,
            "gate_poisoned": poisoned,
            "degraded_registries": degraded,
            "policy_rules_skipped_unknown_ecosystem": policy.rules_skipped_unknown_ecosystem(),
            "credential_temp_bytes": app.credential_temp.as_ref().map_or(0, |temp| temp.used_bytes()),
            // LS-F7: a warning beside readiness, never a change to it.
            "osv_degraded_warning": app.upstreams.osv_degraded_warning(std::time::Instant::now()),
            "osv_results_total": app.upstreams.osv_results_total(),
            "osv_results_degraded": app.upstreams.osv_results_degraded(),
            "osv_server_unreached": app.upstreams.osv_server_unreached(),
            "osv_matches_file_degraded": app.upstreams.osv_matches_file_degraded(),
            "osv_stale_matches_expired": app.upstreams.osv_stale_matches_expired(),
            "osv_matches_records_skipped": app.upstreams.osv_matches_records_skipped(),
            "osv_keys_refused": app.upstreams.osv_keys_refused(),
        })),
    )
        .into_response()
}

async fn plain_ready(State(app): State<Arc<App>>) -> StatusCode {
    if !app.store().is_healthy() {
        return StatusCode::SERVICE_UNAVAILABLE;
    }
    if let Some(managed) = app.managed() {
        return if managed.healthy() {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        };
    }
    if let Some(policy) = app.service_policy() {
        return if policy.snapshot().is_some() { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE };
    }
    let now = app.clock.now_utc_micros();
    match app.blocklist() {
        Some(snapshot) if snapshot.is_valid_at(now) => StatusCode::OK,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    }
}

/// `503` while a decision-log record was lost in the last 60 s, `200` otherwise
/// (including with no sink). An alerting signal, not a probe target: `/health/ready`
/// stays green while records are shed, and no serving decision reads this state.
pub async fn delivery(State(app): State<Arc<App>>) -> StatusCode {
    if app.delivery.is_shedding(app.clock.now_utc_micros()) {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::OK
    }
}
