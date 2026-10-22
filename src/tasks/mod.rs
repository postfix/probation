//! The background loops. Nothing depends on this module; it depends on the rest.
//!
//! Each loop is handed the same `CancellationToken`, so a graceful shutdown stops
//! all of them at once and `Tasks::shutdown` can wait for each to finish the pass it
//! was in.

pub mod blocklist_poller;
pub mod maintenance;
pub mod policy_sync;

use std::sync::Arc;

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::App;

/// The loops this build runs: the blocklist poller (the policy sync in managed mode)
/// and the maintenance pass (batched access times, eviction and the WAL checkpoint).
pub struct Tasks {
    handles: Vec<JoinHandle<()>>,
}

/// Spawns every background loop. `watcher` carries whatever the startup pass already
/// learned about the blocklist file, so the first scheduled pass does not re-read a
/// file it has just read.
/// `delivery` carries the sink tasks, which `delivery::build` has already spawned
/// with the *drain* token rather than `shutdown`. They are only adopted here, so the
/// existing `Tasks::join` waits for them along with everything else.
/// `drain` is cancelled once the last request is answered; the policy sync waits for
/// it to send the activity those requests recorded before a restart (C105).
pub fn spawn(
    app: Arc<App>,
    shutdown: CancellationToken,
    drain: CancellationToken,
    watcher: blocklist_poller::Watcher,
    delivery: Vec<JoinHandle<()>>,
) -> Tasks {
    let policy = if app.managed().is_some() {
        // A managed firewall ignores its local blocklist (C109).
        tokio::spawn(policy_sync::run(Arc::clone(&app), shutdown.clone(), drain))
    } else {
        tokio::spawn(blocklist_poller::run(
            Arc::clone(&app),
            shutdown.clone(),
            watcher,
        ))
    };
    let mut handles = vec![policy, tokio::spawn(maintenance::run(app, shutdown))];
    handles.extend(delivery);

    Tasks { handles }
}

impl Tasks {
    /// How many loops are running. **Compiled only under `test-support`.** The
    /// "configuring nothing spawns nothing" promise is otherwise unobservable.
    #[cfg(feature = "test-support")]
    pub fn count(&self) -> usize {
        self.handles.len()
    }

    /// Waits for every loop to leave the pass it is in. The caller cancels the token
    /// first; a loop that has already stopped joins immediately.
    pub async fn join(self) {
        for handle in self.handles {
            // A task is only ever cancelled by the runtime going away, which means
            // the process is going away with it.
            let _ = handle.await;
        }
    }
}
