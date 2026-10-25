//! The managed firewall's sync loop: every `sync_interval − sync_margin` (C112) it asks
//! the management server what changed, uploading its report and queued activity, and
//! applies the answer. A settings push is validated, written to the overlay and the
//! process asked to restart (C105). Shape copied from `blocklist_poller::run`.

use std::panic::AssertUnwindSafe;
use std::sync::Arc;

use futures_util::FutureExt;
use probation_policy::api::{ChangesRequest, SettingsPush};
use tokio::time::MissedTickBehavior;
use tokio_util::sync::CancellationToken;

use crate::App;
use crate::config;
use crate::managed::Managed;
use crate::managed::activity::Batch;
use crate::managed::sync::{SyncFailure, Synced};

/// What the loop remembers between rounds.
#[derive(Default)]
struct Round {
    /// The last call's batch was refused: the next one is sent empty, and if that is
    /// refused too the server is treated as unreachable.
    rejected: bool,
}

/// Runs the sync loop until `shutdown` is cancelled, then waits for `drain`, so the
/// activity of the requests answered meanwhile goes out in one last call before the
/// process exits, on every graceful stop (F2). The call is skipped when there is
/// nothing to send and no restart is pending; it is bounded by
/// `request_timeout_seconds`.
pub async fn run(app: Arc<App>, shutdown: CancellationToken, drain: CancellationToken) {
    let Some(managed) = app.managed() else {
        return;
    };
    let mut ticks = tokio::time::interval(managed.sync_period());
    ticks.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut round = Round::default();
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = ticks.tick() => {}
        }
        // A round that panics is reported and the next tick syncs again, as the
        // blocklist poller does: the cache it would have changed stays as it was.
        let pass = AssertUnwindSafe(sync_once(&app, managed, &mut round)).catch_unwind();
        if pass.await.is_err() {
            tracing::error!("a policy sync round panicked; the cache stays as it was");
        }
    }
    drain.cancelled().await;
    let batch = managed.activity().take_batch();
    if batch.events.is_empty() && batch.dropped.is_empty() && !managed.restart_pending() {
        return;
    }
    let request = request(&app, managed, &batch);
    let result = managed.sync().fetch_changes(&request).await;
    if !matches!(result, Ok(Synced::Applied)) {
        tracing::warn!(
            events = batch.events.len(),
            "the activity queued before the stop could not be delivered"
        );
    }
    if matches!(result, Ok(Synced::BatchRejected)) {
        managed.activity().count_rejected(batch);
    }
}

async fn sync_once(app: &App, managed: &Managed, round: &mut Round) {
    let batch = if round.rejected {
        Batch::default()
    } else {
        managed.activity().take_batch()
    };
    let request = request(app, managed, &batch);
    match managed.sync().fetch_changes(&request).await {
        Ok(Synced::Applied) => {
            round.rejected = false;
            if let Some(push) = managed.sync().take_settings() {
                apply_settings(app, managed, push).await;
            }
            managed.after_answer().await;
            managed.save_snapshot().await;
        }
        Ok(Synced::BatchRejected) if round.rejected => {
            tracing::error!(
                "the management server refused an empty sync; treating it as unreachable"
            );
            managed.note_unreachable(Some(
                "the management server refused the sync request".to_owned(),
            ));
        }
        Ok(Synced::BatchRejected) => {
            tracing::warn!(
                events = batch.events.len(),
                "the management server refused an activity batch; counting it as dropped"
            );
            managed.activity().count_rejected(batch);
            round.rejected = true;
        }
        Err(SyncFailure::Unreadable) => {
            managed.note_unreadable();
            managed.activity().requeue(batch);
            managed.note_unreachable(None);
        }
        Err(SyncFailure::Unreachable) => {
            tracing::warn!("the management server could not be reached; serving from the cache");
            managed.activity().requeue(batch);
            managed.note_unreachable(None);
        }
    }
}

fn request(app: &App, managed: &Managed, batch: &Batch) -> ChangesRequest {
    ChangesRequest {
        since: managed.sync().cursor(),
        report: managed.report(app.upstreams.take_period()),
        activity: batch
            .events
            .iter()
            .map(|queued| queued.event.clone())
            .collect(),
        activity_dropped: batch.dropped.clone(),
    }
}

/// C105: a push whose revision differs from the applied one, and that never failed, is
/// validated as start-up validates (`check_delivery` included) and written to the
/// overlay, keeping the previous one; the process then drains and exits 75. An invalid
/// push leaves every file untouched and is reported.
async fn apply_settings(app: &App, managed: &Managed, push: SettingsPush) {
    let mut state = managed.settings();
    if push.revision == state.settings_revision || state.failed_revision == Some(push.revision) {
        return;
    }
    let checked = match app.config.with_overlay(&push.toml) {
        Ok(merged) => crate::check_delivery(&merged)
            .await
            .map_err(|err| err.to_string()),
        Err(reason) => Err(reason),
    };
    let written = checked.and_then(|()| {
        config::write_atomically(
            &managed.data_dir().join(config::SETTINGS_OVERLAY),
            push.toml.as_bytes(),
            Some(&managed.data_dir().join(config::PREVIOUS_SETTINGS_OVERLAY)),
        )
        .map_err(|err| format!("the pushed settings could not be written: {err}"))
    });
    match written {
        Ok(()) => {
            tracing::info!(
                revision = push.revision,
                "settings pushed; restarting to apply them"
            );
            state.previous_revision = state.settings_revision;
            state.settings_revision = push.revision;
            state.failed_revision = None;
            state.last_apply_error = None;
            managed.settle_settings(state, true);
        }
        Err(reason) => {
            tracing::error!(revision = push.revision, error = %reason, "a settings push was refused");
            state.failed_revision = Some(push.revision);
            state.last_apply_error = Some(reason);
            managed.settle_settings(state, false);
        }
    }
}
