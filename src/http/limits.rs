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

/// Concurrent tiny-file transfers (ponytail: a constant; a key if a deployment measures a need).
pub const SMALL_DOWNLOADS: usize = 64;

/// Concurrent upload spools (every publish forwarder), and the floor of the bytes they may hold together.
pub const SPOOLS: usize = 8;
/// The most of the places, and of the bytes, one owner may hold: half. An owner is counted under two identities, each
/// capped apart ([`Owner`]), so neither one account, one client address nor one presented credential can take them all.
pub const SPOOLS_PER_OWNER: usize = SPOOLS / 2;

/// Who an upload's place and bytes are counted against, always a REAL identity and never an unvalidated credential alone:
/// `key` is the caller's account (certificate and managed mode, where the firewall has authenticated it) or the client
/// network address (shared-service mode, where the credential is forwarded to the registry unvalidated), and `credential`
/// is a hash of what the caller presented (also capped, so one credential spread over many addresses does not take them
/// either). Callers behind one NAT share an address, hence a share.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Owner {
    pub key: u64,
    pub credential: u64,
}

impl From<u64> for Owner {
    /// A bare number is an identity and its only credential (tests and callers that present none).
    fn from(value: u64) -> Owner {
        Owner { key: value, credential: value }
    }
}
/// How long an upload that has run out of budget waits for another to give bytes back before it is refused.
pub const SPOOL_BUDGET_WAIT: Duration = Duration::from_secs(30);
const SPOOL_BUDGET_FLOOR: u64 = 64 << 20;

/// What one owner dimension holds: places and bytes.
#[derive(Default)]
struct Held {
    seats: usize,
    bytes: u64,
}

type Turns = Arc<std::sync::Mutex<std::collections::HashMap<u64, Arc<Semaphore>>>>;

/// One owner's turn for a big upload: an owner's big uploads go one at a time (returned when dropped).
pub struct SpoolTurn {
    permit: Option<OwnedSemaphorePermit>,
    key: u64,
    turns: Turns,
}

impl Drop for SpoolTurn {
    fn drop(&mut self) {
        drop(self.permit.take());
        let mut turns = self.turns.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if turns.get(&self.key).is_some_and(|turn| Arc::strong_count(turn) == 1) {
            turns.remove(&self.key);
        }
    }
}

type Owners = Arc<std::sync::Mutex<std::collections::HashMap<(bool, u64), Held>>>;

fn counted(owner: Owner) -> [(bool, u64); 2] {
    [(false, owner.key), (true, owner.credential)]
}

fn release(owners: &Owners, owner: Owner, seats: usize, bytes: u64) {
    let mut owners = owners.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    for key in counted(owner) {
        if let Some(held) = owners.get_mut(&key) {
            held.seats -= seats;
            held.bytes -= bytes;
            if held.seats == 0 && held.bytes == 0 {
                owners.remove(&key);
            }
        }
    }
}

/// Bytes reserved from the shared spool budget (and from its owner's half of it); returned when dropped.
pub struct SpoolReservation {
    budget: Arc<AtomicU64>,
    freed: Arc<tokio::sync::Notify>,
    owners: Owners,
    owner: Owner,
    share: u64,
    held: u64,
}

/// One upload's place, counted against its owner as well; returned when dropped.
pub struct SpoolSeat {
    _permit: OwnedSemaphorePermit,
    owner: Owner,
    owners: Owners,
}

impl Drop for SpoolSeat {
    fn drop(&mut self) {
        release(&self.owners, self.owner, 1, 0);
    }
}

impl SpoolReservation {
    /// Takes `more` bytes of the budget; `false` (and nothing taken) when it is not there or the owner already holds its
    /// half of it.
    pub fn grow(&mut self, more: u64) -> bool {
        let mut owners = self.owners.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if counted(self.owner).iter().any(|key| owners.get(key).is_some_and(|held| held.bytes.saturating_add(more) > self.share))
            || more > self.share
        {
            return false;
        }
        if self.budget.fetch_update(Ordering::AcqRel, Ordering::Acquire, |free| free.checked_sub(more)).is_err() {
            return false;
        }
        for key in counted(self.owner) {
            owners.entry(key).or_default().bytes += more;
        }
        self.held += more;
        true
    }

    /// Like `grow`, but an upload that finds the budget taken waits (up to `wait`) for another to give bytes back: two
    /// large uploads that together exceed it go one after the other instead of the second being refused.
    pub async fn grow_waiting(&mut self, more: u64, wait: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let freed = Arc::clone(&self.freed);
            let notified = freed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.grow(more) {
                return true;
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                return self.grow(more);
            }
        }
    }
}

impl Drop for SpoolReservation {
    fn drop(&mut self) {
        // Bytes back to the owner's count first, then to the budget, then the waiters are woken.
        release(&self.owners, self.owner, 0, self.held);
        self.budget.fetch_add(self.held, Ordering::AcqRel);
        self.freed.notify_waiters();
    }
}

pub struct Limits {
    /// Places for an upload being spooled to disk, and the bytes all of them may hold together: an anonymous or
    /// junk-keyed caller cannot pin more than this, whatever the number of requests.
    spool_slots: Arc<Semaphore>,
    spool_budget: Arc<AtomicU64>,
    spool_total: u64,
    spool_freed: Arc<tokio::sync::Notify>,
    spool_owners: Owners,
    spool_turns: Turns,
    downloads: Arc<Semaphore>,
    /// Places for the transfer of a tiny metadata file (a Go `.info` or `.mod`), apart from the large-transfer places:
    /// a handful of multi-megabyte zips must not make the few hundred bytes that precede them wait and fail.
    small_downloads: Arc<Semaphore>,
    /// One place per request waiting for a download permit (`max_download_waiters`).
    download_waiters: Arc<Semaphore>,
    /// The same count of places for the small transfers, counted apart: slow tiny files cannot make a zip wait-less.
    small_waiters: Arc<Semaphore>,
    max_download_waiters: usize,
    download_wait: Duration,
    active: Arc<Semaphore>,
    active_permits: usize,
    write_idle_millis: AtomicU64,
    lifetime_millis: AtomicU64,
}

impl Limits {
    pub fn new(config: &Config) -> Limits {
        let active_permits = config.max_active_requests.get() as usize;
        Limits {
            spool_slots: Arc::new(Semaphore::new(SPOOLS)),
            spool_total: config.max_artifact_bytes.get().saturating_mul(4).max(SPOOL_BUDGET_FLOOR),
            spool_freed: Arc::default(),
            spool_owners: Arc::default(),
            spool_turns: Arc::default(),
            spool_budget: Arc::new(AtomicU64::new(config.max_artifact_bytes.get().saturating_mul(4).max(SPOOL_BUDGET_FLOOR))),
            downloads: Arc::new(Semaphore::new(config.max_artifact_downloads.get() as usize)),
            small_downloads: Arc::new(Semaphore::new(SMALL_DOWNLOADS)),
            download_waiters: Arc::new(Semaphore::new(config.max_download_waiters as usize)),
            small_waiters: Arc::new(Semaphore::new(config.max_download_waiters as usize)),
            max_download_waiters: config.max_download_waiters as usize,
            download_wait: Duration::from_secs(config.download_wait_seconds),
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

    /// How many spool places are free.
    pub fn spool_places_free(&self) -> usize {
        self.spool_slots.available_permits()
    }

    /// A place to spool an upload: `None` (a `503`) when all are taken, never a wait.
    pub fn spool_slot(&self) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&self.spool_slots).try_acquire_owned().ok()
    }

    /// A place for `owner`: `None` (a `503`) when all are taken or either of its identities already holds its half of them.
    pub fn spool_seat(&self, owner: impl Into<Owner>) -> Option<SpoolSeat> {
        let owner = owner.into();
        let mut owners = self.spool_owners.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if counted(owner).iter().any(|key| owners.get(key).is_some_and(|held| held.seats >= SPOOLS_PER_OWNER)) {
            return None;
        }
        let permit = self.spool_slot()?;
        for key in counted(owner) {
            owners.entry(key).or_default().seats += 1;
        }
        Some(SpoolSeat { _permit: permit, owner, owners: Arc::clone(&self.spool_owners) })
    }

    /// The owner's turn for a big upload, waiting up to `wait` for the owner's other big upload to finish; `None` when it does not.
    pub async fn spool_turn(&self, owner: impl Into<Owner>, wait: Duration) -> Option<SpoolTurn> {
        let key = owner.into().key;
        let turn = Arc::clone(self.spool_turns.lock().unwrap_or_else(std::sync::PoisonError::into_inner).entry(key).or_insert_with(|| Arc::new(Semaphore::new(1))));
        let permit = tokio::time::timeout(wait, turn.acquire_owned()).await.ok().and_then(Result::ok);
        let held = SpoolTurn { permit, key, turns: Arc::clone(&self.spool_turns) };
        if held.permit.is_none() { None } else { Some(held) }
    }

    /// An empty reservation on the shared spool budget for `owner`, to `grow` as bytes are accepted (never past the owner's half).
    pub fn spool_reservation(&self, owner: impl Into<Owner>) -> SpoolReservation {
        SpoolReservation {
            budget: Arc::clone(&self.spool_budget),
            freed: Arc::clone(&self.spool_freed),
            owners: Arc::clone(&self.spool_owners),
            owner: owner.into(),
            share: self.spool_total / 2,
            held: 0,
        }
    }

    /// The whole budget; one owner may hold half of it (at least one artifact cap, since the budget is twice an artifact).
    pub fn spool_budget_total(&self) -> u64 {
        self.spool_total
    }

    pub fn spool_budget_free(&self) -> u64 {
        self.spool_budget.load(Ordering::Acquire)
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
    /// share that one transfer and therefore that one permit.
    ///
    /// With none free, the request waits for one in one of `max_download_waiters`
    /// places, first come first served, for at most `download_wait_seconds` (decision
    /// 2026-10-23: npm opens more connections than the default permits). `None`, a
    /// `503`, when every place is taken or the wait runs out: the queue and the wait
    /// are both bounded. Dropping the future gives its place back.
    pub async fn download_permit(&self) -> Option<OwnedSemaphorePermit> {
        if let Ok(permit) = Arc::clone(&self.downloads).try_acquire_owned() {
            return Some(permit);
        }
        let _place = Arc::clone(&self.download_waiters)
            .try_acquire_owned()
            .ok()?;
        let waited = Arc::clone(&self.downloads).acquire_owned();
        tokio::time::timeout(self.download_wait, waited)
            .await
            .ok()?
            .ok()
    }

    /// The permit of a tiny metadata transfer: its own pool, the same bounded wait.
    /// Waiters are bounded by `max_download_waiters` too, counted apart from the large transfers' waiters; the places are in addition to
    /// `max_artifact_downloads` (bounded sizes: a `.info` is read to at most 256 KiB, a `.mod` to 16 MiB).
    pub async fn small_download_permit(&self) -> Option<OwnedSemaphorePermit> {
        if let Ok(permit) = Arc::clone(&self.small_downloads).try_acquire_owned() {
            return Some(permit);
        }
        let _place = Arc::clone(&self.small_waiters).try_acquire_owned().ok()?;
        let waited = Arc::clone(&self.small_downloads).acquire_owned();
        tokio::time::timeout(self.download_wait, waited).await.ok()?.ok()
    }

    pub fn download_available(&self) -> usize {
        self.downloads.available_permits()
    }

    /// How many requests are waiting for a download permit now.
    pub fn download_waiting(&self) -> usize {
        (self.max_download_waiters - self.download_waiters.available_permits()) + (self.max_download_waiters - self.small_waiters.available_permits())
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

    /// R3: one owner's half of the budget holds the largest upload any forwarder accepts (twice an artifact, the artifact plus its envelope), whatever the artifact cap.
    #[test]
    fn the_spool_budget_holds_four_times_the_artifact_cap_so_an_owners_half_takes_a_body_with_its_envelope() {
        let mut config = config();
        config.max_artifact_bytes = std::num::NonZeroU64::new(200 << 20).expect("200 MiB");
        let limits = Limits::new(&config);
        assert_eq!(limits.spool_budget_total(), 800 << 20);
        assert_eq!(limits.spool_budget_free(), 800 << 20);
        // R3-3: cargo, NuGet, Maven and Conan accept a body of twice the artifact cap (the artifact plus its envelope); one owner's half takes it.
        assert!(limits.spool_reservation(1).grow((200 << 20) + 1024), "an artifact plus its envelope is accepted");
        assert!(limits.spool_reservation(1).grow(400 << 20), "and so is the whole 2 x cap a forwarder passes");
    }

    /// Spooled uploads share one budget and a few places, and give both back when dropped.
    #[test]
    fn the_spool_places_and_bytes_are_bounded_and_returned() {
        let mut config = config();
        config.max_artifact_bytes = std::num::NonZeroU64::new(100).expect("one hundred");
        let limits = Limits::new(&config);
        let free = limits.spool_budget_free();
        assert_eq!(free, 64 << 20, "the budget has a floor");
        let places: Vec<_> = (0..SPOOLS).map(|_| limits.spool_slot().expect("a place")).collect();
        assert!(limits.spool_slot().is_none(), "the ninth upload is refused, not queued");
        drop(places);
        assert!(limits.spool_slot().is_some());
        let half = free / 2;
        let mut first = limits.spool_reservation(1);
        assert!(first.grow(half - 10));
        assert!(!first.grow(11), "one owner never holds more than half of the budget");
        let mut second = limits.spool_reservation(2);
        assert!(second.grow(half));
        assert!(first.grow(10));
        let mut third = limits.spool_reservation(3);
        assert!(!third.grow(1), "past the budget nothing is taken");
        assert_eq!(limits.spool_budget_free(), 0);
        drop(first);
        assert!(third.grow(1), "bytes returned are available to the next owner");
        drop(third);
        drop(second);
        assert_eq!(limits.spool_budget_free(), free, "every byte is returned");
    }
}
