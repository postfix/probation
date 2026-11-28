//! Shared-service mode: the project a credential-free npm or PyPI METADATA read just fetched, kept for [`TTL`] so a
//! burst of plain reads costs one upstream fetch and one store commit (as the cargo, NuGet, Maven and RubyGems
//! families do). The cell holds the fetched project only: the policy is judged per request, so a publication governs
//! the next read. A request-scoped (credential-bearing) read never reads or fills it (C1028), and an ARTIFACT request
//! never reads or fills it either: every artifact request revalidates upstream, so a takedown is seen at once.
//!
//! Bounds (memory is new in this slice): at most [`MAX`] cells and [`MAX_TOTAL_BYTES`] in all, a document above
//! [`MAX_CELL_BYTES`] is served but not kept, every `put` drops the expired cells first, and a full table evicts the
//! oldest cell, never the whole table. Concurrent reads of one project share one upstream fetch (single flight).

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::store::cache::CachedProject;

pub(crate) const TTL: Duration = Duration::from_secs(5);
const MAX: usize = 256;
/// A document above this is served, not cached (the shipped `max_metadata_bytes` is 64 MiB).
const MAX_CELL_BYTES: u64 = 32 << 20;
/// All cells together, by `CachedProject::approximate_bytes`.
const MAX_TOTAL_BYTES: u64 = 256 << 20;

/// (family tag, registry, selected origin, project name): never across registries or origins.
pub(crate) type Key = (&'static str, u64, Option<String>, String);

struct Cell {
    at: Instant,
    bytes: u64,
    /// Insertion order, so equal instants still evict the earliest first.
    seq: u64,
    project: Arc<CachedProject>,
}

type Flight = Arc<tokio::sync::Mutex<()>>;

#[derive(Default)]
pub(crate) struct ServiceShare {
    cells: Mutex<(HashMap<Key, Cell>, u64)>,
    flights: Mutex<HashMap<Key, Flight>>,
}

/// Removes a finished (or dropped) flight, so a cancelled leader never leaves a stale entry behind.
struct Cleanup<'a> {
    share: &'a ServiceShare,
    key: &'a Key,
    flight: &'a Flight,
}

impl Drop for Cleanup<'_> {
    fn drop(&mut self) {
        if let Ok(mut flights) = self.share.flights.lock()
            && flights
                .get(self.key)
                .is_some_and(|held| Arc::ptr_eq(held, self.flight))
        {
            flights.remove(self.key);
        }
    }
}

impl ServiceShare {
    pub(crate) fn get(&self, key: &Key, now: Instant) -> Option<Arc<CachedProject>> {
        let table = self.cells.lock().ok()?;
        let cell = table.0.get(key)?;
        (now.saturating_duration_since(cell.at) < TTL).then(|| Arc::clone(&cell.project))
    }

    pub(crate) fn put(&self, key: Key, now: Instant, project: &Arc<CachedProject>) {
        let bytes = project.approximate_bytes();
        if bytes > MAX_CELL_BYTES {
            return;
        }
        if let Ok(mut table) = self.cells.lock() {
            let (cells, seq) = &mut *table;
            *seq += 1;
            cells.retain(|_, cell| now.saturating_duration_since(cell.at) < TTL);
            cells.remove(&key);
            let mut total: u64 = cells.values().map(|cell| cell.bytes).sum();
            while cells.len() >= MAX || total + bytes > MAX_TOTAL_BYTES {
                let Some(oldest) = cells
                    .iter()
                    .min_by_key(|(_, cell)| (cell.at, cell.seq))
                    .map(|(key, _)| key.clone())
                else {
                    break;
                };
                if let Some(gone) = cells.remove(&oldest) {
                    total -= gone.bytes;
                }
            }
            cells.insert(
                key,
                Cell {
                    at: now,
                    bytes,
                    seq: *seq,
                    project: Arc::clone(project),
                },
            );
        }
    }

    /// The cell count and the bytes they account for. **Test support.**
    #[cfg(feature = "test-support")]
    pub(crate) fn stats(&self) -> (usize, u64) {
        self.cells.lock().map_or((0, 0), |table| {
            (table.0.len(), table.0.values().map(|cell| cell.bytes).sum())
        })
    }

    /// The cell if it is fresh, else one fetch for every concurrent caller of this key. The first caller fetches while the
    /// others wait on its lock; a fetch that failed or was dropped leaves no cell, and each waiter then fetches for itself
    /// (concurrently, so one failure never queues the others behind it). Failures are never cached.
    pub(crate) async fn get_or_fetch<E, F, Fut>(
        &self,
        key: Key,
        now: Instant,
        fetch: F,
    ) -> Result<Arc<CachedProject>, E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Arc<CachedProject>, E>>,
    {
        if let Some(project) = self.get(&key, now) {
            return Ok(project);
        }
        let flight = self
            .flights
            .lock()
            .ok()
            .map(|mut flights| Arc::clone(flights.entry(key.clone()).or_default()));
        let Some(flight) = flight else {
            return fetch().await;
        };
        let (guard, leader) = match Arc::clone(&flight).try_lock_owned() {
            Ok(guard) => (guard, true),
            Err(_) => (Arc::clone(&flight).lock_owned().await, false),
        };
        let _cleanup = leader.then_some(Cleanup {
            share: self,
            key: &key,
            flight: &flight,
        });
        if let Some(project) = self.get(&key, now) {
            return Ok(project);
        }
        if !leader {
            drop(guard);
        }
        let project = fetch().await?;
        self.put(key.clone(), now, &project);
        Ok(project)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> Key {
        ("npm", 1, None, "p".to_owned())
    }

    /// A leader dropped mid-fetch (a cancelled request) neither poisons the key nor hangs a waiter, and leaves no flight behind.
    #[tokio::test]
    async fn a_dropped_leader_does_not_hang_or_poison_a_waiter() {
        let share = Arc::new(ServiceShare::default());
        let now = Instant::now();
        let leader = tokio::spawn({
            let share = Arc::clone(&share);
            async move {
                share
                    .get_or_fetch::<&str, _, _>(key(), now, std::future::pending)
                    .await
            }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        let waiter = tokio::spawn({
            let share = Arc::clone(&share);
            async move {
                share
                    .get_or_fetch::<&str, _, _>(key(), now, || async { Err("upstream failed") })
                    .await
                    .err()
            }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        leader.abort();
        let outcome = tokio::time::timeout(Duration::from_secs(5), waiter)
            .await
            .expect("the waiter must not hang")
            .unwrap();
        assert_eq!(outcome, Some("upstream failed"));
        assert!(
            share.flights.lock().unwrap().is_empty(),
            "no flight entry outlives its leader"
        );
    }
}
