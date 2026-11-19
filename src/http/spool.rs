//! The one place an upload is spooled to disk before it is forwarded (npm publish, PyPI upload, `gem push`,
//! `cargo publish`, `dotnet nuget push`). The body is read to an unnamed temporary file so the policy snapshot can be
//! rechecked before the first byte goes upstream; that file is bounded here for every forwarder alike: at most
//! `SPOOLS` uploads at once, the bytes of all of them together within one budget, and a deadline on the body. A caller
//! whose key the registry would refuse (the value is not validated here) therefore cannot pin more than the budget.

use std::time::Duration;

use axum::body::Body;
use futures_util::StreamExt;
use tokio::io::{AsyncSeekExt, AsyncWriteExt};

use crate::App;
use crate::http::error::ApiError;
use crate::http::limits::{SPOOL_BUDGET_WAIT, SpoolReservation, SpoolSeat};

/// How long one upload body may take to arrive, and how long it may stall between two chunks.
pub const BODY_DEADLINE: Duration = Duration::from_secs(15 * 60);
pub const BODY_IDLE: Duration = Duration::from_secs(60);

/// A spooled body, rewound; its place and bytes are returned when it is dropped (after the upstream send).
pub struct Spool {
    pub file: tokio::fs::File,
    pub length: u64,
    _slot: Option<SpoolSeat>,
    _reservation: SpoolReservation,
}

pub enum Spooled {
    Body(Spool),
    TooLarge,
}

/// Reads `body` to a temporary file, at most `cap` bytes. A declared length over `cap` or over the whole budget is
/// `TooLarge` before anything is taken; no free place (or a key already holding its share of them) is `Overloaded`, and
/// so is a budget still taken after `SPOOL_BUDGET_WAIT` (an upload that finds it taken waits for the others first); bytes are reserved as they arrive
/// (never the declared length whole), a body that stalls for `BODY_IDLE` or takes `BODY_DEADLINE` is refused, and an
/// empty body takes no place.
pub async fn spool(app: &App, owner: u64, declared: Option<u64>, cap: u64, body: Body) -> Result<Spooled, ApiError> {
    spool_with(app, owner, declared, cap, body, BODY_IDLE, BODY_DEADLINE).await
}

pub async fn spool_with(
    app: &App,
    owner: u64,
    declared: Option<u64>,
    cap: u64,
    body: Body,
    idle: Duration,
    deadline: Duration,
) -> Result<Spooled, ApiError> {
    let cap = cap.min(app.limits.spool_budget_total());
    if declared.is_some_and(|length| length > cap) {
        return Ok(Spooled::TooLarge);
    }
    let slot = if declared == Some(0) { None } else { Some(app.limits.spool_seat(owner).ok_or(ApiError::Overloaded)?) };
    let mut reservation = app.limits.spool_reservation();
    let file = tempfile::tempfile_in(&app.config.data_dir).map_err(|_| ApiError::StorageUnusable)?;
    let mut file = tokio::fs::File::from_std(file);
    let mut length = 0u64;
    let mut stream = body.into_data_stream();
    let read = async {
        loop {
            let chunk = match tokio::time::timeout(idle, stream.next()).await {
                Err(_) => return Err(ApiError::InvalidInput("the upload stalled")),
                Ok(None) => return Ok(true),
                Ok(Some(chunk)) => chunk.map_err(|_| ApiError::InvalidInput("upload is incomplete"))?,
            };
            length = length.saturating_add(chunk.len() as u64);
            if length > cap {
                return Ok(false);
            }
            if !reservation.grow_waiting(chunk.len() as u64, SPOOL_BUDGET_WAIT).await {
                return Err(ApiError::Overloaded);
            }
            file.write_all(&chunk).await.map_err(|_| ApiError::StorageUnusable)?;
        }
    };
    match tokio::time::timeout(deadline, read).await {
        Err(_) => return Err(ApiError::InvalidInput("the upload took too long")),
        Ok(Err(error)) => return Err(error),
        Ok(Ok(false)) => return Ok(Spooled::TooLarge),
        Ok(Ok(true)) => {}
    }
    file.flush().await.map_err(|_| ApiError::StorageUnusable)?;
    file.seek(std::io::SeekFrom::Start(0)).await.map_err(|_| ApiError::StorageUnusable)?;
    Ok(Spooled::Body(Spool { file, length, _slot: slot, _reservation: reservation }))
}
