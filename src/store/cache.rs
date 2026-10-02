//! The bounded memory caches (SPEC §10) — what keeps a warm request off the
//! database and off the network.
//!
//! **Why these are sharded and second-chance rather than strict LRU.** A strict LRU
//! hit has to move its entry to the front of a recency list, and that is a
//! *mutation*: it needs an exclusive lock, so every warm metadata request and every
//! warm denial in the process would serialize on one mutex per cache. SPEC §12 asks
//! for at least 1,000 warm responses a second at p95 ≤ 5 ms and a warm denial at
//! p95 ≤ 2 ms, and one exclusive lock on the hottest path is the wrong shape for that
//! by construction. So a hit takes a per-shard **read** lock and sets an atomic
//! `referenced` bit with a relaxed store; eviction is a second-chance (CLOCK) sweep
//! over that one shard which clears the bit and reclaims the first entry it finds
//! unreferenced. Recency is therefore approximate, which SPEC §10 permits
//! ("bounded" for memory caches).
//!
//! Sixteen shards is a starting number and a tuning knob; the lock shape is not.

use std::collections::{HashMap, HashSet};
use std::hash::{BuildHasher, Hash, Hasher, RandomState};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Instant;

use crate::policy::{Digest, Ecosystem};
use crate::store::rows::{Generation, ProjectRow, ReferenceId, ReferenceRow};

const SHARDS: usize = 16;

/// One project, in the ecosystem it belongs to. `Ecosystem` is not `Hash`, so the
/// tag it already prints in log lines is what gets hashed.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ProjectKey {
    pub ecosystem: Ecosystem,
    pub name: String,
}

impl ProjectKey {
    pub fn new(ecosystem: Ecosystem, name: impl Into<String>) -> ProjectKey {
        ProjectKey {
            ecosystem,
            name: name.into(),
        }
    }
}

impl Hash for ProjectKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.ecosystem.as_tag().hash(state);
        self.name.hash(state);
    }
}

/// Which rendering of a project a cache entry holds. SPEC §10 makes the requested
/// representation one of the conditions an entry is reusable under, so it is part of
/// the key rather than something checked afterwards.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum Representation {
    NpmFull,
    NpmAbbreviated,
    /// One version or tag, as the client spelled it.
    NpmVersion(String),
    /// PyPI's two Simple API serialisations. Content negotiation picks between them,
    /// so which one was asked for is part of the key rather than checked afterwards.
    PypiHtml,
    PypiJson,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct RenderKey {
    pub project: ProjectKey,
    pub representation: Representation,
}

/// A response already serialised, with everything needed to decide whether it may be
/// sent again without asking anyone.
#[derive(Clone, Debug)]
pub struct RenderedResponse {
    pub body: Arc<[u8]>,
    pub content_type: &'static str,
    pub project_generation: Generation,
    pub blocklist_revision: u64,
    pub digest_generation: u64,
    /// The earliest of upstream metadata TTL, blocklist expiry, and the next held
    /// version's eligibility time (SPEC §10).
    pub deadline_utc_micros: i64,
    /// The same deadline on the monotonic clock, so a backward wall-clock jump
    /// cannot extend an entry's life (SPEC §5).
    pub deadline_monotonic: Instant,
}

impl RenderedResponse {
    /// All five conditions of SPEC §10, plus the monotonic deadline.
    pub fn is_reusable(
        &self,
        project_generation: Generation,
        blocklist_revision: u64,
        digest_generation: u64,
        now_utc_micros: i64,
        now_monotonic: Instant,
    ) -> bool {
        // The representation is the fifth condition and is already part of the key.
        self.project_generation == project_generation
            && self.blocklist_revision == blocklist_revision
            && self.digest_generation == digest_generation
            && now_utc_micros < self.deadline_utc_micros
            && now_monotonic < self.deadline_monotonic
    }
}

/// One project as a request needs it: the stored snapshot, and the committed
/// first-seen time of every reference that has one.
///
/// The two travel together because they are decided together — a refresh commits the
/// snapshot and the first-seen values in one transaction (SPEC §10) — and because
/// filtering needs an age for every version without asking the database once per
/// version.
#[derive(Clone, Debug)]
pub struct CachedProject {
    pub row: ProjectRow,
    pub first_seen: HashMap<ReferenceId, i64>,
    /// The digests this instance computed and pinned for this project's references
    /// (SPEC §9). A block on one of them has to deny the version in the listing, not
    /// only the bytes at the artifact endpoint — so they are loaded with the project
    /// rather than asked for per version. A download that establishes a pin drops
    /// this entry, which is what makes the next listing see it; a reader that read
    /// this snapshot first cannot put it back afterwards, because the insert is
    /// guarded by [`ShardedCache::get_with_seen`] — see `artifacts::download::fetch`.
    pub pins: HashMap<ReferenceId, Vec<Digest>>,
    /// The reference ids this snapshot advertises, parsed once and kept with the
    /// snapshot they came from.
    ///
    /// SPEC §9 makes *every* artifact request confirm that its reference is still
    /// advertised, and the document that answers that question runs to megabytes on a
    /// real package carrying thousands of versions. Re-parsing it per request is the
    /// cost SPEC §12's warm-artifact target cannot pay, so it is paid once per
    /// snapshot. Filled through the `Arc` this cache hands out, so the next request
    /// for the same snapshot finds it; a new snapshot is a new `CachedProject` and
    /// therefore a new, empty cell, which is what keeps it from ever being stale.
    ///
    /// Not counted in [`CachedProject::approximate_bytes`]: it is filled after the
    /// entry is sized, and it is small beside the payload it is derived from.
    pub advertised: OnceLock<Arc<HashSet<ReferenceId>>>,
}

impl CachedProject {
    /// A rough size for the cache budget: the upstream payload plus the first-seen
    /// map. Exactness is not the point; bounding is.
    pub fn approximate_bytes(&self) -> u64 {
        self.row.payload.len() as u64
            + self.first_seen.len() as u64 * 48
            + self.pins.len() as u64 * 144
            + 256
    }

    /// The pins of one reference, in the shape `policy::evaluate` takes them.
    pub fn pins_of(&self, id: &ReferenceId) -> &[Digest] {
        self.pins.get(id).map_or(&[], Vec::as_slice)
    }
}

/// A name upstream confirmed it does not have (TM-4). Memory only, never persisted:
/// a restart may re-ask upstream, which is harmless.
#[derive(Clone, Copy, Debug)]
pub struct AbsentMark {
    pub observed_monotonic: Instant,
}

/// The three caches a metadata request touches.
pub struct MemoryCaches {
    /// Hot project records, so a cache miss on the rendered form does not always
    /// mean a database query.
    pub projects: ShardedCache<ProjectKey, CachedProject>,
    /// Serialized filtered responses. This is the one that makes a fully warm
    /// request cost no query, no upstream call, and no repeated JSON parsing.
    pub rendered: ShardedCache<RenderKey, RenderedResponse>,
    /// Hot reference records, so a warm artifact request does not query for the row
    /// it is about to check. Entries are dropped rather than edited whenever a
    /// download changes what the row says (pins, content mapping).
    pub references: ShardedCache<ReferenceId, ReferenceRow>,
    /// Confirmed-absent upstream names, TTL = `metadata_ttl` (TM-4).
    pub absent: ShardedCache<ProjectKey, AbsentMark>,
    /// How many times a *stored* project document has been parsed — never an upstream
    /// one, which a refresh must always parse.
    ///
    /// SPEC §10's warm path is "no database query, no upstream call, and no repeated
    /// parse", and `StoreHandle::commands_issued` is what a test asserts the first two
    /// on. This is the third, counted here beside the caches whose job it is to make
    /// the parse unnecessary.
    stored_parses: AtomicU64,
}

impl MemoryCaches {
    /// `budget_bytes` is SPEC §4's `memory_cache_max_bytes`. Rendered responses are
    /// the largest and hottest, so they get the bulk; the absent set holds a few
    /// dozen bytes per entry and needs a floor rather than a share.
    pub fn new(budget_bytes: u64) -> MemoryCaches {
        let absent = (budget_bytes / 32).max(64 * 1024);
        let references = (budget_bytes / 16).max(64 * 1024);
        let rest = budget_bytes
            .saturating_sub(absent)
            .saturating_sub(references)
            .max(2);
        MemoryCaches {
            projects: ShardedCache::new(rest / 2),
            rendered: ShardedCache::new(rest - rest / 2),
            references: ShardedCache::new(references),
            absent: ShardedCache::new(absent),
            stored_parses: AtomicU64::new(0),
        }
    }

    /// One stored project document parsed. Relaxed: nothing orders on this count, and
    /// the tests that read it do so with every request already finished.
    pub fn note_stored_parse(&self) {
        self.stored_parses.fetch_add(1, Ordering::Relaxed);
    }

    /// The count [`MemoryCaches::note_stored_parse`] keeps.
    pub fn stored_parses(&self) -> u64 {
        self.stored_parses.load(Ordering::Relaxed)
    }
}

pub struct ShardedCache<K, V> {
    shards: Box<[RwLock<Shard<K, V>>]>,
    /// Per shard, not overall: a shard evicts within itself, so the total is bounded
    /// by construction without any cross-shard bookkeeping on the hot path.
    shard_budget_bytes: u64,
    hasher: RandomState,
}

struct Shard<K, V> {
    entries: HashMap<K, Entry<V>>,
    /// The CLOCK ring. Keys are appended on insert and removed as the hand reclaims
    /// them, so it holds exactly the live keys of this shard.
    ring: Vec<K>,
    hand: usize,
    used_bytes: u64,
    /// Explicit invalidations of any key in this shard — see
    /// [`ShardedCache::invalidations`]. Eviction does not count: it drops a value
    /// without contradicting it, so a reader holding that value is still right.
    invalidations: u64,
}

struct Entry<V> {
    value: Arc<V>,
    bytes: u64,
    referenced: AtomicBool,
}

impl<K: Hash + Eq + Clone, V> ShardedCache<K, V> {
    pub fn new(budget_bytes: u64) -> ShardedCache<K, V> {
        let shards = (0..SHARDS)
            .map(|_| {
                RwLock::new(Shard {
                    entries: HashMap::new(),
                    ring: Vec::new(),
                    hand: 0,
                    used_bytes: 0,
                    invalidations: 0,
                })
            })
            .collect::<Vec<_>>();

        ShardedCache {
            shards: shards.into_boxed_slice(),
            shard_budget_bytes: (budget_bytes / SHARDS as u64).max(1),
            hasher: RandomState::new(),
        }
    }

    /// The warm path: one read lock on one shard, one `Arc` clone, one relaxed store.
    /// No list mutation and no write lock.
    pub fn get(&self, key: &K) -> Option<Arc<V>> {
        let shard = self.shard(key).read().ok()?;
        let entry = shard.entries.get(key)?;
        entry.referenced.store(true, Ordering::Relaxed);
        Some(Arc::clone(&entry.value))
    }

    /// The cold path: the write lock for that one shard, and eviction within it.
    pub fn insert(&self, key: K, value: Arc<V>, bytes: u64) {
        let Ok(mut shard) = self.shard(&key).write() else {
            return;
        };
        shard.install(key, value, bytes, self.shard_budget_bytes);
    }

    /// [`ShardedCache::get`], with the invalidation count that value was read at.
    ///
    /// The count is handed back to [`ShardedCache::insert_if_current`], and the two
    /// together are a compare-and-swap: a reader that read a snapshot before an
    /// invalidation cannot put that snapshot back afterwards. Reuse is then
    /// generation-checked rather than time-checked, which is what
    /// `RenderedResponse::is_reusable` already does for the rendered form.
    ///
    /// **One accessor, and that is the point.** Read as two calls, the count has to be
    /// taken *before* the value or the invalidation that happens between them is
    /// absorbed into the baseline and the compare succeeds against a snapshot it was
    /// meant to reject. Both orders typecheck and both read correctly, so the wrong
    /// one is not something a test can be relied on to catch — it is removed by
    /// returning the pair from one lock acquisition instead, which no caller can
    /// reorder.
    ///
    /// Per shard rather than per key, because a per-key table would grow without a
    /// bound while this count is bounded by construction. The cost of the imprecision
    /// is one skipped cache fill when an unrelated key in the same shard is
    /// invalidated in the same window — never a wrong answer, only a cold one.
    ///
    /// A poisoned shard answers `(u64::MAX, None)`. No shard can have counted to
    /// `u64::MAX`, so every insert guarded by it is refused; that matches `get` and
    /// `insert`, which also stop caching rather than panicking.
    pub fn get_with_seen(&self, key: &K) -> (u64, Option<Arc<V>>) {
        let Ok(shard) = self.shard(key).read() else {
            return (u64::MAX, None);
        };
        let value = shard.entries.get(key).map(|entry| {
            entry.referenced.store(true, Ordering::Relaxed);
            Arc::clone(&entry.value)
        });
        (shard.invalidations, value)
    }

    /// [`ShardedCache::insert`], unless this key's shard has been invalidated since
    /// `seen` came back from [`ShardedCache::get_with_seen`].
    pub fn insert_if_current(&self, key: K, value: Arc<V>, bytes: u64, seen: u64) {
        let Ok(mut shard) = self.shard(&key).write() else {
            return;
        };
        if shard.invalidations != seen {
            return;
        }
        shard.install(key, value, bytes, self.shard_budget_bytes);
    }

    /// Drops this key's entry and counts the invalidation, whether or not the key was
    /// cached: a reader may be holding a copy of a value this removal contradicts even
    /// when the cache itself no longer is.
    pub fn remove(&self, key: &K) {
        if let Ok(mut shard) = self.shard(key).write() {
            shard.invalidations = shard.invalidations.wrapping_add(1);
            shard.remove(key);
        }
    }

    pub fn len(&self) -> usize {
        self.shards
            .iter()
            .filter_map(|shard| shard.read().ok())
            .map(|shard| shard.entries.len())
            .sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn shard(&self, key: &K) -> &RwLock<Shard<K, V>> {
        let hash = self.hasher.hash_one(key);
        &self.shards[(hash % SHARDS as u64) as usize]
    }
}

impl<K: Hash + Eq + Clone, V> Shard<K, V> {
    /// The cold path with the write lock already held. An entry larger than a whole
    /// shard's budget is not cached at all rather than emptying the shard to hold it.
    fn install(&mut self, key: K, value: Arc<V>, bytes: u64, budget_bytes: u64) {
        self.remove(&key);
        if bytes > budget_bytes {
            return;
        }
        while self.used_bytes + bytes > budget_bytes {
            if !self.reclaim_one() {
                return;
            }
        }
        self.used_bytes += bytes;
        self.ring.push(key.clone());
        self.entries.insert(
            key,
            Entry {
                value,
                bytes,
                referenced: AtomicBool::new(true),
            },
        );
    }

    fn remove(&mut self, key: &K) {
        if let Some(entry) = self.entries.remove(key) {
            self.used_bytes -= entry.bytes;
            if let Some(position) = self.ring.iter().position(|held| held == key) {
                self.ring.remove(position);
                if self.hand > position {
                    self.hand -= 1;
                }
            }
        }
    }

    /// One second-chance sweep step: clear the bit of every entry that has been read
    /// since the hand last passed it, and reclaim the first one that has not.
    /// Returns false only when the shard is already empty.
    fn reclaim_one(&mut self) -> bool {
        if self.ring.is_empty() {
            return false;
        }
        // At most two laps: one to clear every bit, one to find an entry whose bit
        // is now clear. A third lap is impossible because nothing sets a bit while
        // this write lock is held.
        for _ in 0..self.ring.len() * 2 {
            if self.hand >= self.ring.len() {
                self.hand = 0;
            }
            let key = self.ring[self.hand].clone();
            let Some(entry) = self.entries.get(&key) else {
                // Not reachable while ring and entries are kept in step; dropping the
                // stale key is still the right repair.
                self.ring.remove(self.hand);
                continue;
            };
            if entry.referenced.swap(false, Ordering::Relaxed) {
                self.hand += 1;
                continue;
            }
            self.remove(&key);
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cache() -> ShardedCache<ProjectKey, u32> {
        // One shard's worth of budget is what the entries are sized against, so the
        // per-shard figure is what matters: 4 entries of 64 bytes each.
        ShardedCache::new(256 * SHARDS as u64)
    }

    fn shard() -> Shard<&'static str, u32> {
        Shard {
            entries: HashMap::new(),
            ring: Vec::new(),
            hand: 0,
            used_bytes: 0,
            invalidations: 0,
        }
    }

    fn put(shard: &mut Shard<&'static str, u32>, key: &'static str) {
        shard.used_bytes += 1;
        shard.ring.push(key);
        shard.entries.insert(
            key,
            Entry {
                value: Arc::new(0),
                bytes: 1,
                referenced: AtomicBool::new(true),
            },
        );
    }

    /// The second chance is the whole mechanism: an entry read since the hand last
    /// passed it survives that pass, and the first one that was not read is what the
    /// sweep reclaims. Asserted on one shard directly, because which shard a key
    /// lands in is a hash and not something a test may assume.
    #[test]
    fn a_read_entry_survives_the_sweep_that_reclaims_an_unread_one() {
        let mut shard = shard();
        put(&mut shard, "first");
        put(&mut shard, "second");

        // Both bits start set, so the first sweep clears both and then reclaims the
        // one the hand reaches first.
        assert!(shard.reclaim_one());
        assert!(!shard.entries.contains_key("first"));
        assert!(shard.entries.contains_key("second"));

        // Reading "second" sets its bit again, so the next sweep spends a lap on it
        // and reclaims the newcomer instead.
        put(&mut shard, "third");
        shard.entries["second"]
            .referenced
            .store(true, Ordering::Relaxed);
        shard.entries["third"]
            .referenced
            .store(false, Ordering::Relaxed);
        assert!(shard.reclaim_one());
        assert!(
            shard.entries.contains_key("second"),
            "an entry read since the last pass survives it"
        );
        assert!(!shard.entries.contains_key("third"));
        assert_eq!(shard.used_bytes, 1, "byte accounting follows the reclaim");
    }

    /// The budget is the point: a cache that grows without bound is not bounded work.
    #[test]
    fn a_shard_never_exceeds_its_budget() {
        // One shard, sized to hold two 64-byte entries.
        let cache: ShardedCache<u64, u64> = ShardedCache::new(128 * SHARDS as u64);
        for index in 0..1_000u64 {
            cache.insert(index, Arc::new(index), 64);
        }
        assert!(
            cache.len() <= 2 * SHARDS,
            "every shard holds at most two entries, so the whole cache holds at most {}",
            2 * SHARDS
        );
        assert!(!cache.is_empty(), "and it does not evict itself empty");
    }

    /// An entry too large for a whole shard is refused rather than emptying it.
    #[test]
    fn an_oversized_entry_does_not_empty_a_shard() {
        let cache = cache();
        let small = ProjectKey::new(Ecosystem::Npm, "small");
        cache.insert(small.clone(), Arc::new(1), 8);
        cache.insert(
            ProjectKey::new(Ecosystem::Npm, "huge"),
            Arc::new(2),
            1 << 40,
        );

        assert_eq!(cache.get(&small).as_deref(), Some(&1));
        assert!(
            cache
                .get(&ProjectKey::new(Ecosystem::Npm, "huge"))
                .is_none()
        );
    }

    #[test]
    fn reuse_requires_every_condition_of_spec_10() {
        let now = 1_000_000i64;
        let monotonic = Instant::now();
        let rendered = RenderedResponse {
            body: Arc::from(b"{}".as_slice()),
            content_type: "application/json",
            project_generation: Generation(4),
            blocklist_revision: 7,
            digest_generation: 2,
            deadline_utc_micros: now + 1,
            deadline_monotonic: monotonic + std::time::Duration::from_secs(60),
        };

        assert!(rendered.is_reusable(Generation(4), 7, 2, now, monotonic));
        assert!(!rendered.is_reusable(Generation(5), 7, 2, now, monotonic));
        assert!(!rendered.is_reusable(Generation(4), 8, 2, now, monotonic));
        assert!(!rendered.is_reusable(Generation(4), 7, 3, now, monotonic));
        assert!(
            !rendered.is_reusable(Generation(4), 7, 2, now + 1, monotonic),
            "the deadline is exclusive: at it, the entry is spent"
        );
        assert!(
            !rendered.is_reusable(
                Generation(4),
                7,
                2,
                now,
                monotonic + std::time::Duration::from_secs(61)
            ),
            "a backward wall-clock jump cannot extend an entry past its monotonic deadline"
        );
    }
}
