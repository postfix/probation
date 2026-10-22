//! The bounded queue of activity rows waiting for the next sync: blocked, held and
//! would-have-blocked decisions, and refused known keys (C23, C55, C81, C92).

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};

use probation_policy::PlaceRef;
use probation_policy::api::{ActivityEvent, DroppedCount};

/// The most events queued at once; the oldest goes first when it is full.
pub const ACTIVITY_QUEUE_CAP: usize = 10_000;
/// The most events one account may hold in the queue, so one tenant cannot evict the
/// others (T18). Its further events are counted as dropped instead.
pub const ACTIVITY_ACCOUNT_CAP: usize = 1_000;
/// The most events, and the most `activity_dropped` entries, one `changes` call carries.
pub const ACTIVITY_BATCH_MAX: usize = 1_000;

/// One queued event and the account whose cap it counts against.
pub struct Queued {
    pub account: PlaceRef,
    pub event: ActivityEvent,
}

/// What one `changes` call takes from the queue.
#[derive(Default)]
pub struct Batch {
    pub events: Vec<Queued>,
    pub dropped: Vec<DroppedCount>,
}

#[derive(Default)]
struct Held {
    events: VecDeque<Queued>,
    per_account: HashMap<PlaceRef, usize>,
    dropped: HashMap<PlaceRef, u64>,
}

pub struct ActivityQueue {
    held: Mutex<Held>,
    /// Event ids are this firewall's start time and a counter, so a restart never
    /// reuses one.
    epoch: i64,
    next_id: AtomicU64,
}

impl ActivityQueue {
    pub fn new(epoch_utc_micros: i64) -> ActivityQueue {
        ActivityQueue {
            held: Mutex::new(Held::default()),
            epoch: epoch_utc_micros,
            next_id: AtomicU64::new(1),
        }
    }

    /// Queues one event for `account`, dropping the oldest events beyond the cap. An
    /// account already holding its share has the event counted as dropped instead.
    pub fn record_activity(&self, account: PlaceRef, mut event: ActivityEvent) {
        event.event_id = format!(
            "{:x}-{}",
            self.epoch,
            self.next_id.fetch_add(1, Ordering::Relaxed)
        );
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        let Held {
            events: queue,
            per_account,
            dropped,
        } = &mut *held;
        let share = per_account.entry(account).or_insert(0);
        if *share >= ACTIVITY_ACCOUNT_CAP {
            *dropped.entry(account).or_insert(0) += 1;
            return;
        }
        *share += 1;
        let event = Queued { account, event };
        let overflow = (queue.len() + 1).saturating_sub(ACTIVITY_QUEUE_CAP);
        for gone in queue.iter().take(overflow) {
            release(per_account, gone.account);
        }
        queue.drain(..overflow);
        queue.push_back(event);
    }

    /// The oldest events and drop counts, up to [`ACTIVITY_BATCH_MAX`] of each, for one
    /// upload.
    pub fn take_batch(&self) -> Batch {
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        let Held {
            events,
            per_account,
            dropped,
        } = &mut *held;
        let taken = events.len().min(ACTIVITY_BATCH_MAX);
        let events: Vec<Queued> = events.drain(..taken).collect();
        for sent in &events {
            release(per_account, sent.account);
        }
        let accounts: Vec<PlaceRef> = dropped.keys().take(ACTIVITY_BATCH_MAX).copied().collect();
        let dropped = accounts
            .into_iter()
            .filter_map(|account| {
                let count = dropped.remove(&account)?;
                Some(DroppedCount { account, count })
            })
            .collect();
        Batch { events, dropped }
    }

    /// Puts an unsent batch back in front of newer events, still dropping the oldest
    /// beyond the cap.
    pub fn requeue(&self, batch: Batch) {
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        let mut back: VecDeque<Queued> = batch.events.into();
        back.append(&mut held.events);
        let overflow = back.len().saturating_sub(ACTIVITY_QUEUE_CAP);
        back.drain(..overflow);
        held.per_account.clear();
        for kept in &back {
            *held.per_account.entry(kept.account).or_insert(0) += 1;
        }
        held.events = back;
        for lost in batch.dropped {
            *held.dropped.entry(lost.account).or_insert(0) += lost.count;
        }
    }

    /// A batch the server refused: its events are counted as dropped for their
    /// accounts, with the drop counts it carried, in the next upload.
    pub fn count_rejected(&self, batch: Batch) {
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        for lost in batch.events {
            *held.dropped.entry(lost.account).or_insert(0) += 1;
        }
        for lost in batch.dropped {
            *held.dropped.entry(lost.account).or_insert(0) += lost.count;
        }
    }
}

fn release(per_account: &mut HashMap<PlaceRef, usize>, account: PlaceRef) {
    if let Some(share) = per_account.get_mut(&account) {
        *share -= 1;
        if *share == 0 {
            per_account.remove(&account);
        }
    }
}

#[cfg(test)]
mod tests {
    use probation_policy::LayerKind;
    use probation_policy::api::{ActivityLayer, ActivityResult, KeyId};

    use super::*;

    fn account(id: u32) -> PlaceRef {
        PlaceRef {
            kind: LayerKind::Org,
            id,
        }
    }

    fn event(key: u64) -> ActivityEvent {
        ActivityEvent {
            event_id: String::new(),
            key_id: KeyId(key),
            place: account(1),
            ecosystem: None,
            package: None,
            version: None,
            result: ActivityResult::Blocked,
            rule: "blocked_package".to_owned(),
            layer: ActivityLayer::Layer(LayerKind::Org),
            client_ip: None,
            eligible_at: None,
        }
    }

    fn drain_all(queue: &ActivityQueue) -> (Vec<Queued>, HashMap<PlaceRef, u64>) {
        let mut events = Vec::new();
        let mut dropped = HashMap::new();
        loop {
            let batch = queue.take_batch();
            if batch.events.is_empty() && batch.dropped.is_empty() {
                return (events, dropped);
            }
            events.extend(batch.events);
            for lost in batch.dropped {
                *dropped.entry(lost.account).or_insert(0) += lost.count;
            }
        }
    }

    /// A batch put back goes in front of newer events and keeps the shares right; a
    /// rejected one is counted as dropped.
    #[test]
    fn requeued_and_rejected_batches() {
        let queue = ActivityQueue::new(1);
        for n in 0..3 {
            queue.record_activity(account(1), event(n));
        }
        let batch = queue.take_batch();
        assert_eq!(batch.events.len(), 3);
        queue.record_activity(account(1), event(3));
        queue.requeue(batch);
        let batch = queue.take_batch();
        let keys: Vec<u64> = batch.events.iter().map(|q| q.event.key_id.0).collect();
        assert_eq!(keys, vec![0, 1, 2, 3]);
        queue.count_rejected(batch);
        let (events, dropped) = drain_all(&queue);
        assert!(events.is_empty());
        assert_eq!(dropped.get(&account(1)), Some(&4));
    }
}
