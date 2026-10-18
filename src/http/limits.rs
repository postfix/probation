//! The bounds SPEC §4 configures and SPEC §10 requires: "Use semaphores and bounded
//! queues; reject overload instead of allowing unbounded waiters or tasks."
//!
//! Three of them live here. `max_active_requests` is the front door: a request that
//! cannot take a permit is refused with `503` rather than queued behind the ones that
//! did. `max_artifact_downloads` bounds how many upstream transfers run at once, and
//! is taken by the *leader* of a coalesced download only — the waiters sharing that
//! transfer do not each hold one. The two response deadlines SPEC §9 fixes live here
//! too, because they bound work in exactly the same sense.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::config::Config;

/// SPEC §9: "Apply a 30-second downstream write-idle timeout […] These are initial
/// implementation defaults."
pub const WRITE_IDLE: Duration = Duration::from_secs(30);

/// SPEC §9: "and a 15-minute response-body lifetime".
pub const RESPONSE_LIFETIME: Duration = Duration::from_secs(15 * 60);

pub struct Limits {
    downloads: Arc<Semaphore>,
    active: Arc<Semaphore>,
    active_permits: usize,
    write_idle_millis: AtomicU64,
    lifetime_millis: AtomicU64,
}

impl Limits {
    pub fn new(config: &Config) -> Limits {
        let active_permits = config.max_active_requests.get() as usize;
        Limits {
            downloads: Arc::new(Semaphore::new(config.max_artifact_downloads.get() as usize)),
            active: Arc::new(Semaphore::new(active_permits)),
            active_permits,
            write_idle_millis: AtomicU64::new(WRITE_IDLE.as_millis() as u64),
            lifetime_millis: AtomicU64::new(RESPONSE_LIFETIME.as_millis() as u64),
        }
    }

    /// SPEC §4's `max_active_requests`, and SPEC §10's "reject overload instead of
    /// allowing unbounded waiters". `None` is a `503`, never a wait: a request that
    /// joins a queue it cannot be served from has only converted a refusal into a
    /// timeout.
    ///
    /// An artifact response holds its permit until the last body byte has left, so
    /// the bound covers the streaming too and not merely the handler.
    pub fn active_permit(&self) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&self.active).try_acquire_owned().ok()
    }

    /// How many of `max_active_requests` are free. A test reads this to assert that a
    /// timed-out response gave its permit back.
    pub fn active_available(&self) -> usize {
        self.active.available_permits()
    }

    pub fn max_active(&self) -> usize {
        self.active_permits
    }

    /// SPEC §9: "Bound active downloads globally." Taken once per upstream transfer,
    /// by whichever request starts it; concurrent requests for the same reference
    /// share that one transfer and therefore that one permit. `None` is overload and
    /// is refused rather than queued, for the same reason as above.
    pub fn download_permit(&self) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&self.downloads).try_acquire_owned().ok()
    }

    pub fn download_available(&self) -> usize {
        self.downloads.available_permits()
    }

    pub fn write_idle(&self) -> Duration {
        Duration::from_millis(self.write_idle_millis.load(Ordering::Relaxed))
    }

    pub fn response_lifetime(&self) -> Duration {
        Duration::from_millis(self.lifetime_millis.load(Ordering::Relaxed))
    }

    /// Shortens the two deadlines above. **Compiled only under `test-support`.**
    ///
    /// SPEC §9 calls 30 s and 15 min "initial implementation defaults, to be included
    /// in slow-client tests", and a test that waited them out would take a quarter of
    /// an hour. It is behind a default-off feature rather than merely unused, because
    /// these two deadlines are the only bound on how long a slow reader keeps a file
    /// pin and a request permit — permits are refused rather than queued, and eviction
    /// exempts a pinned file for as long as it stays pinned — so a setter that can
    /// *lengthen* them is FLOW-01's own risk offered to any consumer embedding this
    /// crate. A default build does not contain it.
    #[cfg(feature = "test-support")]
    pub fn set_response_timeouts(&self, write_idle: Duration, lifetime: Duration) {
        self.write_idle_millis
            .store(write_idle.as_millis() as u64, Ordering::Relaxed);
        self.lifetime_millis
            .store(lifetime.as_millis() as u64, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Config {
        Config::load(std::path::Path::new("config.sample.toml")).expect("the shipped sample")
    }

    /// The deadlines a deployment actually runs with are SPEC §9's, not whatever a
    /// test last set.
    #[test]
    fn the_shipped_deadlines_are_thirty_seconds_and_fifteen_minutes() {
        let limits = Limits::new(&config());
        assert_eq!(limits.write_idle(), Duration::from_secs(30));
        assert_eq!(limits.response_lifetime(), Duration::from_secs(900));
    }

    /// Overload is a refusal: the permit is either there or it is not, and asking
    /// never blocks.
    #[test]
    fn an_exhausted_permit_is_refused_rather_than_queued() {
        let mut config = config();
        config.max_active_requests = std::num::NonZeroU32::new(1).expect("one");
        let limits = Limits::new(&config);

        let held = limits.active_permit().expect("the only permit");
        assert!(limits.active_permit().is_none(), "the second is refused");
        assert_eq!(limits.active_available(), 0);

        drop(held);
        assert_eq!(limits.active_available(), 1);
        assert!(limits.active_permit().is_some());
    }
}
