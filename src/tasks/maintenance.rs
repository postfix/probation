//! The low-priority loop: batched access times, disk eviction, and the write-ahead
//! log checkpoint.
//!
//! Everything here goes on the store's **maintenance** queue, which the store task
//! looks at only when nothing is waiting on the critical one (SPEC §10: "give pending
//! blocklist commits priority over ordinary queued cache maintenance"). Nothing here
//! is ever awaited by an HTTP handler, which is the other half of that sentence:
//! a request records a key and moves on, and this loop is what writes it.
//!
//! The order within a pass is deliberate. Access times are written first, so the
//! eviction that follows judges recency by what has just been read rather than by
//! what was read a pass ago. The checkpoint runs last, after whatever eviction wrote.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use crate::App;

/// How often a pass runs. Eviction is allowed to lag the budget — SPEC §10 calls the
/// order approximate and Gate 3 records the lag as accepted — and nothing on the
/// request path waits for a pass, so the cost of a longer interval is bounded while
/// the cost of a shorter one is a write every few seconds on an idle instance.
const INTERVAL: Duration = Duration::from_secs(30);

pub async fn run(app: Arc<App>, shutdown: CancellationToken) {
    loop {
        tokio::select! {
            () = shutdown.cancelled() => return,
            () = tokio::time::sleep(INTERVAL) => {}
        }
        run_once(&app).await;
    }
}

/// One complete pass. Public because it is also how a test runs maintenance at an
/// instant of its choosing rather than waiting out [`INTERVAL`].
pub async fn run_once(app: &App) {
    probe_storage(app).await;
    write_access_times(app).await;
    evict_to_budget(app, app.config.cache_max_bytes.get()).await;

    // SPEC §10: "Checkpoint with the pinned engine's supported API outside HTTP
    // handling." A busy log is not a failure; the next pass takes it.
    if let Err(err) = app.store().checkpoint().await {
        tracing::debug!(error = %err, "the write-ahead log checkpoint did not run this pass");
    }
}

/// SPEC §10: readiness is false "until storage is usable again". A storage that
/// refused a write is retried here, once per pass, so it recovers without waiting
/// for a request — which an instance out of rotation would never receive.
async fn probe_storage(app: &App) {
    if app.store().is_healthy() {
        return;
    }
    if let Err(err) = app.store().probe().await {
        tracing::warn!(error = %err, "the database still refuses writes");
    }
    let content = app.content.probe().await;
    if let Err(err) = &content {
        tracing::warn!(error = %err, "the content directory still refuses writes");
    }
    app.store().note_content_write(content.is_ok());
}

/// SPEC §10: "access updates batched off the request path". One write per distinct
/// key read since the last pass, all in one transaction.
async fn write_access_times(app: &App) {
    let touched: HashSet<_> = app.content.drain_touched().into_iter().collect();
    if touched.is_empty() {
        return;
    }
    let now = app.clock.now_utc_micros();
    app.store()
        .touch_content(touched.into_iter().map(|key| (key, now)).collect());
}

/// SPEC §10: "Disk eviction uses approximate least-recently-used order […] Never
/// evict open files."
///
/// The budget is a parameter rather than read from the configuration here, so a test
/// can run a pass against a budget of its choosing without a second server; a pass
/// always runs against `cache_max_bytes`.
///
/// The file goes before its mapping, which is the opposite of the publication order
/// and for the same reason: only [`crate::artifacts::content::ContentStore::evict`]
/// knows what is open, so it has to be what decides. Clearing the mapping first would
/// mean either losing the mapping of a file that turned out to be open, or asking the
/// store about a question only the content cache can answer. The window it leaves — a
/// mapping whose file has gone — is the case SPEC §9 already requires handling:
/// "Detect missing files and size mismatches and discard their cache mappings."
pub async fn evict_to_budget(app: &App, budget: u64) {
    let plan = match app.store().eviction_plan().await {
        Ok(plan) => plan,
        Err(err) => {
            tracing::warn!(error = %err, "the eviction pass could not read the content index");
            return;
        }
    };
    let mut total = plan.total_bytes;
    if total <= budget {
        return;
    }

    let (mut evicted, mut freed, mut held) = (0usize, 0u64, 0usize);
    for (key, size) in plan.oldest_first {
        if total <= budget {
            break;
        }
        if !app.content.evict(&key).await {
            // Open right now. It stays — and the pass moves on to the next-oldest
            // rather than abandoning the budget, which is how both halves of SPEC
            // §10's sentence hold at once.
            held += 1;
            continue;
        }
        if let Err(err) = app.store().clear_evicted_content(key).await {
            tracing::warn!(
                content = %key,
                error = %err,
                "an evicted file's mapping could not be cleared; the next request for it will"
            );
        }
        evicted += 1;
        freed = freed.saturating_add(size);
        total = total.saturating_sub(size);
    }

    tracing::info!(
        evicted,
        freed,
        held,
        budget,
        "evicted cached artifact bytes down towards the cache budget"
    );
}
