//! One piece of upstream work per key, however many requests want it.
//!
//! Two paths need exactly this. SPEC §9: "Concurrent requests for one reference share
//! one fetch and verification result." SPEC §10: "Coalesce concurrent metadata
//! refreshes per project." Slice 8 built the latch for the first; this is that latch,
//! keyed and typed by its caller so the second uses the same one rather than a second
//! implementation of the same three races.
//!
//! Four decisions carry it, and each is structural rather than remembered:
//!
//! * a waiter is counted by a [`Waiter`] guard whose increment and decrement both
//!   happen **under the table's lock**, which is also the lock a joining request takes.
//!   So the count cannot be decremented twice, cannot go negative, and a request cannot
//!   join a slot in the instant between its last waiter leaving and its removal.
//! * a slot's life is one `AtomicU8` with exactly two transitions out of `RUNNING`,
//!   each a compare-and-exchange: the last waiter takes `CANCELLED`, the worker takes
//!   `PUBLISHING` immediately before the point of no return. Whichever wins, the other
//!   is refused — a publication can never begin after a cancellation, and a
//!   cancellation can never abandon a publication that has begun.
//! * the outcome and the slot's removal are a [`Resolution`] guard rather than two
//!   statements at the end of the worker. The worker owns the only `watch::Sender` for
//!   the slot and every waiter holds the slot alive, so a worker that ended without
//!   sending would leave its waiters blocked on a channel that can never close and
//!   leave the slot in the table for every later request to join — one panic, and that
//!   key is unservable for the life of the process.
//! * `Drop` rather than a `catch_unwind` around the work, because the ways a worker can
//!   end without an outcome are not only panics: it can also be dropped where it stands
//!   when the runtime goes away, or when the request driving it disappears. `Drop`
//!   covers a normal return, an unwind and a cancellation with one rule, needs no
//!   `UnwindSafe` reasoning, and does not catch the panic — which therefore still
//!   unwinds to its task boundary and is still reported.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use tokio::sync::watch;
use tokio_util::sync::{CancellationToken, WaitForCancellationFuture};

/// A slot is `RUNNING` until exactly one of the two transitions below wins.
const RUNNING: u8 = 0;
/// The last waiter left before publication began.
const CANCELLED: u8 = 1;
/// The publication began, and from here on it always completes.
const PUBLISHING: u8 = 2;

/// The in-flight work, one slot per key.
///
/// Cheap to clone — every clone is the same table — so a worker that outlives the
/// request that started it can carry one into its own task.
pub struct SingleFlight<K, V> {
    inner: Arc<Table<K, V>>,
}

struct Table<K, V> {
    inflight: Mutex<HashMap<K, Arc<Slot<V>>>>,
}

impl<K, V> Clone for SingleFlight<K, V> {
    fn clone(&self) -> SingleFlight<K, V> {
        SingleFlight {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<K, V> Default for SingleFlight<K, V> {
    fn default() -> SingleFlight<K, V> {
        SingleFlight {
            inner: Arc::new(Table {
                inflight: Mutex::new(HashMap::new()),
            }),
        }
    }
}

/// One piece of work, shared by every request that joined it.
pub struct Slot<V> {
    state: AtomicU8,
    waiters: AtomicUsize,
    /// Only ever used to wake the worker out of an await; the decision itself is
    /// `state`.
    cancel: CancellationToken,
    outcome: watch::Sender<Option<V>>,
}

impl<V> Slot<V> {
    /// A slot outside any table. [`SingleFlight::join`] is what puts one in.
    pub(crate) fn new() -> Slot<V> {
        Slot {
            state: AtomicU8::new(RUNNING),
            waiters: AtomicUsize::new(0),
            cancel: CancellationToken::new(),
            outcome: watch::Sender::new(None),
        }
    }

    /// Called once, immediately before the point of no return. `false` means the last
    /// waiter already cancelled, so there is nothing to publish for.
    pub fn begin_publishing(&self) -> bool {
        self.state
            .compare_exchange(RUNNING, PUBLISHING, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// Called by the last waiter to leave. `false` means the publication has already
    /// begun, and SPEC §9 requires it to finish.
    pub fn begin_cancel(&self) -> bool {
        self.state
            .compare_exchange(RUNNING, CANCELLED, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// Resolves once the last waiter has left, for a worker that can abandon its work
    /// part way.
    pub fn cancelled(&self) -> WaitForCancellationFuture<'_> {
        self.cancel.cancelled()
    }
}

impl<V: Clone> Slot<V> {
    /// This slot's outcome, waited for. `None` means the worker went away without
    /// recording one *and* without its [`Resolution`] running, which happens only if
    /// the runtime itself is going away.
    pub async fn wait(&self) -> Option<V> {
        let mut outcome = self.outcome.subscribe();
        loop {
            let done = outcome.borrow_and_update().clone();
            if done.is_some() {
                return done;
            }
            if outcome.changed().await.is_err() {
                return None;
            }
        }
    }
}

impl<K: Eq + Hash + Clone, V> SingleFlight<K, V> {
    pub fn new() -> SingleFlight<K, V> {
        SingleFlight::default()
    }

    /// The in-flight table, poisoning and all.
    ///
    /// A panic while this lock is held would otherwise make every later request for
    /// every key panic too — a far worse failure than the one that poisoned it. Nothing
    /// under this lock is a multi-step invariant: it is a map from key to slot, and a
    /// panic mid-insert leaves it structurally intact either way.
    fn table(&self) -> MutexGuard<'_, HashMap<K, Arc<Slot<V>>>> {
        self.inner
            .inflight
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// How many requests are currently sharing this key's work. Zero when none is in
    /// flight.
    pub fn waiting_on(&self, key: &K) -> usize {
        self.table()
            .get(key)
            .map(|slot| slot.waiters.load(Ordering::Acquire))
            .unwrap_or(0)
    }

    /// Whether this key's work has passed the point after which it always completes.
    pub fn publishing(&self, key: &K) -> bool {
        self.table()
            .get(key)
            .is_some_and(|slot| slot.state.load(Ordering::Acquire) == PUBLISHING)
    }

    /// Joins this key's work or claims the right to start it. The returned guard is
    /// what counts the caller as a waiter; the flag is true for the caller that has to
    /// do the work.
    pub fn join(&self, key: K) -> (Arc<Slot<V>>, bool, Waiter<K, V>) {
        let mut inflight = self.table();
        let (slot, leader) = match inflight.get(&key) {
            Some(slot) => (Arc::clone(slot), false),
            None => {
                let slot = Arc::new(Slot::new());
                inflight.insert(key.clone(), Arc::clone(&slot));
                (slot, true)
            }
        };
        slot.waiters.fetch_add(1, Ordering::AcqRel);
        (
            Arc::clone(&slot),
            leader,
            Waiter {
                flight: self.clone(),
                key,
                slot,
            },
        )
    }

    /// Drops finished work's slot, so the next request for this key starts a new one
    /// rather than joining an answered one.
    fn finish(&self, key: &K, slot: &Arc<Slot<V>>) {
        let mut inflight = self.table();
        if inflight
            .get(key)
            .is_some_and(|held| Arc::ptr_eq(held, slot))
        {
            inflight.remove(key);
        }
    }
}

/// One request's share of one piece of work. Dropping it — because the request
/// finished, or because the client went away and its future was dropped — releases that
/// share and nothing else.
pub struct Waiter<K: Eq + Hash + Clone, V> {
    flight: SingleFlight<K, V>,
    key: K,
    slot: Arc<Slot<V>>,
}

impl<K: Eq + Hash + Clone, V> Drop for Waiter<K, V> {
    fn drop(&mut self) {
        // Under the table's lock, which is also the lock `join` increments under: a
        // request cannot join between this decrement and the removal below.
        let mut inflight = self.flight.table();
        if self.slot.waiters.fetch_sub(1, Ordering::AcqRel) != 1 {
            return;
        }
        // The last one out. SPEC §9: cancel the work — unless the publication has
        // begun, in which case `begin_cancel` refuses and it runs to completion.
        if self.slot.begin_cancel() {
            self.slot.cancel.cancel();
            if inflight
                .get(&self.key)
                .is_some_and(|held| Arc::ptr_eq(held, &self.slot))
            {
                inflight.remove(&self.key);
            }
        }
    }
}

/// Answers the waiters and retires the slot, on every way out of the worker.
///
/// Held by whatever is doing the work — a task of its own for an artifact transfer, the
/// leading request itself for a metadata refresh. Either way, the waiters are answered
/// exactly once and the key is left servable.
pub struct Resolution<K: Eq + Hash + Clone, V: Clone> {
    flight: SingleFlight<K, V>,
    key: K,
    slot: Arc<Slot<V>>,
    /// What the waiters are told if this guard is dropped without an answer. Taken by
    /// [`Resolution::answer`], so a `Some` here at drop time *is* the abandonment.
    abandoned: Option<V>,
    /// The key as a log line should spell it.
    subject: String,
}

impl<K: Eq + Hash + Clone, V: Clone> Resolution<K, V> {
    pub fn new(
        flight: SingleFlight<K, V>,
        key: K,
        slot: Arc<Slot<V>>,
        abandoned: V,
        subject: String,
    ) -> Resolution<K, V> {
        Resolution {
            flight,
            key,
            slot,
            abandoned: Some(abandoned),
            subject,
        }
    }

    pub fn answer(&mut self, outcome: V) {
        // Answer first, then stop accepting joiners: every request that joined gets
        // this result, and the next one starts fresh work (SPEC §9: "A subsequent
        // request may retry; no detached infinite retry loop").
        //
        // `send_replace` and not `send`: `send` refuses when the receiver count is
        // zero and then leaves the stored value untouched. A request that has joined
        // the slot under the table's lock but has not reached `Slot::wait` yet is
        // exactly that case, and it would go on to subscribe to a channel whose value
        // is still `None` and whose sender it is itself keeping alive — so
        // `changed()` would never fire and never close. `send_replace` always stores.
        self.slot.outcome.send_replace(Some(outcome));
        self.abandoned = None;
    }
}

impl<K: Eq + Hash + Clone, V: Clone> Drop for Resolution<K, V> {
    fn drop(&mut self) {
        if let Some(abandoned) = self.abandoned.take() {
            tracing::error!(
                subject = %self.subject,
                "coalesced upstream work ended without an outcome; failing its waiters \
                 and retiring the slot so the key stays servable"
            );
            self.slot.outcome.send_replace(Some(abandoned));
        }
        self.flight.finish(&self.key, &self.slot);
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    /// Every wait below is bounded, and that is the point rather than politeness.
    ///
    /// `Resolution` must publish with `send_replace`; `send` refuses when the receiver
    /// count is zero and leaves the stored value untouched, so a waiter that has not
    /// subscribed yet would block on a channel it is itself keeping alive. Unbounded,
    /// that regression deadlocks the whole test binary, which reads in CI as a stuck
    /// job rather than a located fault. Bounded, it names its own cause.
    const BOUND: Duration = Duration::from_secs(5);

    /// The message every one of those bounds fails with.
    const WHY: &str = "the waiter never resolved: `Resolution` must publish with `send_replace`, not \
         `send`, which is a no-op when no receiver has subscribed yet";

    /// A slot answers its waiters once, and a later waiter reads the answer that is
    /// already there rather than waiting for a second one.
    #[tokio::test]
    async fn an_answer_reaches_a_waiter_that_arrived_before_it_and_one_that_arrived_after() {
        let flight: SingleFlight<u8, &'static str> = SingleFlight::new();
        let (slot, leader, _waiter) = flight.join(1);
        assert!(leader);

        let early = {
            let slot = Arc::clone(&slot);
            tokio::spawn(async move { tokio::time::timeout(BOUND, slot.wait()).await })
        };
        let mut resolution = Resolution::new(
            flight.clone(),
            1,
            Arc::clone(&slot),
            "abandoned",
            "1".to_owned(),
        );
        resolution.answer("done");

        assert_eq!(
            early.await.expect("the waiter task finishes").expect(WHY),
            Some("done")
        );
        assert_eq!(
            tokio::time::timeout(BOUND, slot.wait()).await.expect(WHY),
            Some("done"),
            "and a waiter that subscribes after the answer reads the answer that is there"
        );
    }

    /// The panic case, without a panic: a resolution dropped without an answer still
    /// resolves its waiters and still retires the slot.
    #[tokio::test]
    async fn an_abandoned_resolution_answers_its_waiters_and_retires_the_slot() {
        let flight: SingleFlight<u8, &'static str> = SingleFlight::new();
        let (slot, _leader, waiter) = flight.join(1);

        drop(Resolution::new(
            flight.clone(),
            1,
            Arc::clone(&slot),
            "abandoned",
            "1".to_owned(),
        ));

        assert_eq!(
            tokio::time::timeout(BOUND, slot.wait()).await.expect(WHY),
            Some("abandoned")
        );
        drop(waiter);
        let (_slot, leader, _waiter) = flight.join(1);
        assert!(leader, "and the next request starts work of its own");
    }
}
