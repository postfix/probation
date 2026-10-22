//! What a managed firewall remembers between requests: the key cache, the lookup
//! budget, and the layers and compiled policies the keys share (C111).
//!
//! Slice 3 adds the snapshot, idle pruning, place expiry and the invalidation
//! revisions.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use probation_policy::api::{ChainLink, KeyHash, PlaceLayer};
use probation_policy::{Layer, PlaceRef, PolicyFingerprint, is_chain, resolve};

use super::Principal;
use crate::clock::Clock;
use crate::policy::CompiledPolicy;

const SHARDS: usize = 16;

/// How long an `Unknown` answer is believed (T10).
pub(super) const UNKNOWN_FOR: Duration = Duration::from_secs(30);

enum Entry {
    Live {
        principal: Principal,
        expires_at: Instant,
        last_used: Instant,
    },
    /// Unknown, revoked or suspended: refused without asking until `expires_at`.
    Refused { expires_at: Instant },
}

/// What the cache holds for a hash that has no live entry.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Standing {
    /// A refusal that has not expired.
    Refused,
    /// A key whose entry outlived its TTL; it is looked up again.
    Expired,
    Missing,
}

/// Key hash -> entry, in 16 shards each holding at most its share of
/// `key_cache_max_entries`. A full shard evicts its least recently used entry.
pub(super) struct KeyCache {
    shards: Vec<Mutex<HashMap<KeyHash, Entry>>>,
    shard_capacity: usize,
    ttl: Duration,
    clock: Arc<dyn Clock>,
}

impl KeyCache {
    pub(super) fn new(max_entries: usize, ttl: Duration, clock: Arc<dyn Clock>) -> KeyCache {
        KeyCache {
            shards: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
            shard_capacity: max_entries.div_ceil(SHARDS),
            ttl,
            clock,
        }
    }

    fn shard(&self, hash: &KeyHash) -> std::sync::MutexGuard<'_, HashMap<KeyHash, Entry>> {
        // The hash is SHA-256 output, so its first byte is already uniform.
        let shard = &self.shards[usize::from(hash.0[0]) % SHARDS];
        // Nothing panics while a shard is held, so a poisoned lock holds no torn entry.
        shard
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The principal of a live, unexpired entry, marked as used now.
    pub(super) fn fresh(&self, hash: &KeyHash) -> Option<Principal> {
        let now = self.clock.now_monotonic();
        match self.shard(hash).get_mut(hash) {
            Some(Entry::Live {
                principal,
                expires_at,
                last_used,
            }) if now < *expires_at => {
                *last_used = now;
                Some(principal.clone())
            }
            _ => None,
        }
    }

    pub(super) fn standing(&self, hash: &KeyHash) -> Standing {
        let now = self.clock.now_monotonic();
        match self.shard(hash).get(hash) {
            Some(Entry::Refused { expires_at }) if now < *expires_at => Standing::Refused,
            Some(Entry::Live { .. }) => Standing::Expired,
            _ => Standing::Missing,
        }
    }

    pub(super) fn insert(&self, hash: KeyHash, principal: Principal) {
        let now = self.clock.now_monotonic();
        self.put(
            hash,
            Entry::Live {
                principal,
                expires_at: now + self.ttl,
                last_used: now,
            },
        );
    }

    /// Refuses `hash` without asking for `unknown_for`, or for one TTL when `None`
    /// (revoked and suspended keys).
    pub(super) fn refuse(&self, hash: KeyHash, unknown_for: Option<Duration>) {
        let expires_at = self.clock.now_monotonic() + unknown_for.unwrap_or(self.ttl);
        self.put(hash, Entry::Refused { expires_at });
    }

    fn put(&self, hash: KeyHash, entry: Entry) {
        let mut shard = self.shard(&hash);
        if shard.len() >= self.shard_capacity && !shard.contains_key(&hash) {
            // ponytail: a scan of one full shard per insert; keep an LRU order per shard
            // if a cache this full shows up in profiles.
            let victim = shard
                .iter()
                .min_by_key(|(_, entry)| match entry {
                    // Refusals go first: they cost a client nothing to lose.
                    Entry::Refused { .. } => None,
                    Entry::Live { last_used, .. } => Some(*last_used),
                })
                .map(|(victim, _)| *victim);
            if let Some(victim) = victim {
                shard.remove(&victim);
            }
        }
        shard.insert(hash, entry);
    }
}

/// The lookups this firewall may send each second (T10, C120). Fixed one-second
/// windows on the injected clock: the firewall-wide budget, a fifth of it (at least one
/// once the budget is two) kept for keys that already have an entry so a flood of unknown keys cannot starve re-lookups, and
/// each client address's allowance for keys with no entry.
///
/// ponytail: fixed windows let a burst straddling a boundary reach twice the rate for
/// an instant; a sliding window if the server ever notices.
pub(super) struct Budget {
    per_second: u32,
    per_client: u32,
    clock: Arc<dyn Clock>,
    origin: Instant,
    window: Mutex<Window>,
}

#[derive(Default)]
struct Window {
    second: u64,
    used: u32,
    clients: HashMap<IpAddr, u32>,
}

impl Budget {
    pub(super) fn new(per_second: u32, per_client: u32, clock: Arc<dyn Clock>) -> Budget {
        Budget {
            per_second,
            per_client,
            origin: clock.now_monotonic(),
            clock,
            window: Mutex::new(Window::default()),
        }
    }

    /// Takes one lookup from this second's budget, if there is one left for this client.
    pub(super) fn take(&self, client: IpAddr, has_entry: bool) -> bool {
        let second = self
            .clock
            .now_monotonic()
            .saturating_duration_since(self.origin)
            .as_secs();
        let mut window = self.window.lock().unwrap_or_else(|p| p.into_inner());
        if window.second != second {
            *window = Window {
                second,
                ..Window::default()
            };
        }
        let allowed = if has_entry {
            window.used < self.per_second
        } else {
            // A fifth of the budget, and at least one lookup once there are two.
            let reserved = (self.per_second / 5).max(u32::from(self.per_second >= 2));
            let unreserved = self.per_second - reserved;
            window.used < unreserved
                && window.clients.get(&client).copied().unwrap_or(0) < self.per_client
        };
        if allowed {
            window.used += 1;
            if !has_entry {
                *window.clients.entry(client).or_insert(0) += 1;
            }
        }
        allowed
    }
}

/// Why a chain's policy cannot be built.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Unresolved {
    /// A layer is missing, or older than the revision the chain names: the server's
    /// answers have not caught up with each other yet.
    Behind,
    /// A layer is not the kind of its place, or the chain is not one `resolve`
    /// accepts: an answer this firewall cannot trust.
    Inconsistent,
}

/// Each place's layer, held once however many keys share it, and the compiled
/// policies built from them, interned by fingerprint (C111). A policy no key holds any
/// more is dropped with its last principal.
#[derive(Default)]
pub(super) struct Policies {
    layers: Mutex<HashMap<PlaceRef, (u64, Layer)>>,
    interned: Mutex<HashMap<PolicyFingerprint, Weak<CompiledPolicy>>>,
}

impl Policies {
    /// The places of `chain` whose layer is not held at the revision it names.
    pub(super) fn missing(&self, chain: &[ChainLink]) -> Vec<PlaceRef> {
        let layers = self.layers.lock().unwrap_or_else(|p| p.into_inner());
        chain
            .iter()
            .filter(|link| {
                layers
                    .get(&link.place)
                    .is_none_or(|(revision, _)| *revision < link.layer_revision)
            })
            .map(|link| link.place)
            .collect()
    }

    /// Keeps each place's newest layer: an answer older than the one held is dropped.
    pub(super) fn store(&self, answer: Vec<PlaceLayer>) {
        let mut layers = self.layers.lock().unwrap_or_else(|p| p.into_inner());
        for place in answer {
            let newer = layers
                .get(&place.place)
                .is_none_or(|(held, _)| *held < place.revision);
            if newer {
                layers.insert(place.place, (place.revision, place.layer));
            }
        }
    }

    /// The policy of `chain`, interned, or why it cannot be built from what is held.
    pub(super) fn compile(&self, chain: &[ChainLink]) -> Result<Arc<CompiledPolicy>, Unresolved> {
        let layers = {
            let held = self.layers.lock().unwrap_or_else(|p| p.into_inner());
            chain
                .iter()
                .map(|link| match held.get(&link.place) {
                    Some((revision, _)) if *revision < link.layer_revision => {
                        Err(Unresolved::Behind)
                    }
                    Some((_, layer)) if layer.kind == link.place.kind => Ok(layer.clone()),
                    Some(_) => Err(Unresolved::Inconsistent),
                    None => Err(Unresolved::Behind),
                })
                .collect::<Result<Vec<Layer>, Unresolved>>()?
        };
        let kinds: Vec<_> = layers.iter().map(|layer| layer.kind).collect();
        if kinds.is_empty() || !is_chain(&kinds) {
            return Err(Unresolved::Inconsistent);
        }
        let policy = resolve(&layers);

        let mut interned = self.interned.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(compiled) = interned.get(&policy.fingerprint).and_then(Weak::upgrade) {
            return Ok(compiled);
        }
        interned.retain(|_, compiled| compiled.strong_count() > 0);
        let fingerprint = policy.fingerprint;
        let compiled = Arc::new(CompiledPolicy::managed(policy));
        interned.insert(fingerprint, Arc::downgrade(&compiled));
        Ok(compiled)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use probation_policy::api::{KeyId, LimitSource};
    use probation_policy::{LayerKind, Switches};

    use super::*;

    struct ManualClock {
        base: Instant,
        micros: AtomicU64,
    }

    impl Clock for ManualClock {
        fn now_utc_micros(&self) -> i64 {
            0
        }
        fn now_monotonic(&self) -> Instant {
            self.base + Duration::from_micros(self.micros.load(Ordering::SeqCst))
        }
    }

    fn clock() -> Arc<ManualClock> {
        Arc::new(ManualClock {
            base: Instant::now(),
            micros: AtomicU64::new(0),
        })
    }

    const PLATFORM: PlaceRef = PlaceRef {
        kind: LayerKind::Platform,
        id: 1,
    };

    fn link(place: PlaceRef) -> ChainLink {
        ChainLink {
            place,
            layer_revision: 1,
        }
    }

    fn principal(policies: &Policies) -> Principal {
        policies.store(vec![PlaceLayer {
            place: PLATFORM,
            layer: Layer::empty(LayerKind::Platform),
            revision: 1,
        }]);
        Principal {
            place: PLATFORM,
            key_id: KeyId(1),
            policy: policies.compile(&[link(PLATFORM)]).expect("a policy"),
            account: PLATFORM,
            rate_limit: None,
            rate_limit_source: LimitSource::Default,
            org: None,
            chain: Arc::from([PLATFORM]),
        }
    }

    /// Four hashes that land in one shard.
    fn same_shard() -> Vec<KeyHash> {
        (0u8..4).map(|n| KeyHash([n * 16; 32])).collect()
    }

    /// A full shard makes room by dropping its least recently used entry: here the one
    /// inserted second, because the first was used since.
    #[test]
    fn a_full_shard_evicts_the_least_recently_used_entry() {
        let clock = clock();
        // Two entries a shard.
        let cache = KeyCache::new(2 * SHARDS, Duration::from_secs(300), clock.clone());
        let policies = Policies::default();
        let hashes = same_shard();
        cache.insert(hashes[0], principal(&policies));
        clock.micros.store(1, Ordering::SeqCst);
        cache.insert(hashes[1], principal(&policies));
        clock.micros.store(2, Ordering::SeqCst);
        assert!(cache.fresh(&hashes[0]).is_some(), "the first is used again");
        clock.micros.store(3, Ordering::SeqCst);
        cache.insert(hashes[2], principal(&policies));
        assert_eq!(
            cache.standing(&hashes[1]),
            Standing::Missing,
            "the LRU entry"
        );
        assert!(cache.fresh(&hashes[0]).is_some());
        assert!(cache.fresh(&hashes[2]).is_some());
    }

    /// A refusal is evicted before any live entry, however recently it was made.
    #[test]
    fn a_full_shard_evicts_refusals_first() {
        let clock = clock();
        let cache = KeyCache::new(2 * SHARDS, Duration::from_secs(300), clock.clone());
        let policies = Policies::default();
        let hashes = same_shard();
        cache.insert(hashes[0], principal(&policies));
        clock.micros.store(1, Ordering::SeqCst);
        cache.refuse(hashes[1], Some(UNKNOWN_FOR));
        clock.micros.store(2, Ordering::SeqCst);
        cache.insert(hashes[2], principal(&policies));
        assert_eq!(cache.standing(&hashes[1]), Standing::Missing, "the refusal");
        assert!(
            cache.fresh(&hashes[0]).is_some(),
            "the older live entry stays"
        );
        assert!(cache.fresh(&hashes[2]).is_some());
    }

    /// A layer answer older than the one held never replaces it, and a chain naming a
    /// newer revision than the one held does not compile from the older one.
    #[test]
    fn an_older_layer_never_replaces_a_newer_one() {
        let policies = Policies::default();
        let at = |revision, freeze| PlaceLayer {
            place: PLATFORM,
            layer: Layer {
                freeze_seconds: Some(freeze),
                ..Layer::empty(LayerKind::Platform)
            },
            revision,
        };
        let names = |layer_revision| ChainLink {
            place: PLATFORM,
            layer_revision,
        };
        policies.store(vec![at(1, 60)]);
        assert_eq!(
            policies.compile(&[names(2)]).err(),
            Some(Unresolved::Behind),
            "rev 1 is not rev 2"
        );
        assert_eq!(policies.missing(&[names(2)]), vec![PLATFORM]);
        policies.store(vec![at(2, 3_600)]);
        policies.store(vec![at(1, 60)]);
        let compiled = policies.compile(&[names(2)]).expect("rev 2 is held");
        assert_eq!(compiled.policy.chain[0].freeze_seconds, Some(3_600));
        assert!(policies.missing(&[names(2)]).is_empty());
    }

    /// The reserve kept for keys with an entry is a fifth of the budget, and at least
    /// one lookup once the budget is two or more.
    #[test]
    fn the_budget_keeps_a_reserve_for_known_keys() {
        let client: IpAddr = [127, 0, 0, 1].into();
        for (budget, unknown) in [(1, 1), (2, 1), (4, 3), (50, 40)] {
            let take = Budget::new(budget, u32::MAX, clock());
            let taken = (0..budget).filter(|_| take.take(client, false)).count();
            assert_eq!(
                taken, unknown as usize,
                "unknown keys under a budget of {budget}"
            );
            let reserved = (0..budget).filter(|_| take.take(client, true)).count();
            assert_eq!(reserved as u32, budget - unknown, "the reserve of {budget}");
        }
    }

    /// An entry past its TTL is not served, and is looked up as one that has an entry.
    #[test]
    fn an_expired_entry_is_not_fresh() {
        let clock = clock();
        let cache = KeyCache::new(100, Duration::from_secs(300), clock.clone());
        let hash = KeyHash([7; 32]);
        cache.insert(hash, principal(&Policies::default()));
        clock.micros.store(300_000_000, Ordering::SeqCst);
        assert!(cache.fresh(&hash).is_none());
        assert_eq!(cache.standing(&hash), Standing::Expired);
    }

    /// A chain whose layers disagree with its places, or that is not a C9 chain, is not
    /// compiled; one compiled twice is the same policy.
    #[test]
    fn only_a_consistent_chain_compiles() {
        let policies = Policies::default();
        let org = PlaceRef {
            kind: LayerKind::Org,
            id: 2,
        };
        policies.store(vec![
            PlaceLayer {
                place: PLATFORM,
                layer: Layer {
                    allow: Switches::ALL,
                    ..Layer::empty(LayerKind::Platform)
                },
                revision: 1,
            },
            PlaceLayer {
                place: org,
                layer: Layer::empty(LayerKind::Group),
                revision: 1,
            },
        ]);
        let inconsistent = Some(Unresolved::Inconsistent);
        assert_eq!(
            policies.compile(&[link(PLATFORM), link(org)]).err(),
            inconsistent
        );
        assert_eq!(policies.compile(&[link(org)]).err(), inconsistent);
        assert_eq!(policies.compile(&[]).err(), inconsistent);
        let first = policies.compile(&[link(PLATFORM)]).expect("a policy");
        let second = policies.compile(&[link(PLATFORM)]).expect("a policy");
        assert!(Arc::ptr_eq(&first, &second), "interned by fingerprint");
        assert_eq!(policies.missing(&[link(PLATFORM), link(org)]), Vec::new());
        let newer = ChainLink {
            place: org,
            layer_revision: 2,
        };
        assert_eq!(policies.missing(&[newer]), vec![org]);
    }
}
