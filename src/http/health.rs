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
pub async fn ready(State(app): State<Arc<App>>) -> StatusCode {
    let now = app.clock.now_utc_micros();
    if !app.store().is_healthy() {
        return StatusCode::SERVICE_UNAVAILABLE;
    }
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
