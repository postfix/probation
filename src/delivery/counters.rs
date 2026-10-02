//! Loss accounting for one sink. Its own module so that `file` and `siem` cannot reach
//! the fields: a loss can only be recorded through [`SinkCounters::lose`].

use std::sync::atomic::{AtomicU64, Ordering};

pub(super) struct SinkCounters {
    /// Read and reset by the summary path via `take_window`.
    window: AtomicU64,
    /// Monotonic; nothing resets it.
    total: AtomicU64,
}

impl SinkCounters {
    pub(super) fn new() -> SinkCounters {
        SinkCounters {
            window: AtomicU64::new(0),
            total: AtomicU64::new(0),
        }
    }

    /// Records `n` lost records. Two relaxed adds and nothing else: it runs on the
    /// request path's `push`, which must stay lock-free and infallible.
    pub(super) fn lose(&self, n: u64) {
        self.window.fetch_add(n, Ordering::Relaxed);
        self.total.fetch_add(n, Ordering::Relaxed);
    }

    pub(super) fn take_window(&self) -> u64 {
        self.window.swap(0, Ordering::Relaxed)
    }

    pub(super) fn total(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }
}
