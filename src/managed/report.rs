//! Whether each upstream answered in the current sync period (C69), for the
//! `FirewallReport`. Each call is recorded where it is made, under the kind of call it
//! is, never by matching its URL; the sync task reads and resets the period.

use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use probation_policy::api::{Reachability, Upstreams};

use crate::upstream::UpstreamError;

/// The four trackers: npm metadata and tarballs, PyPI metadata, PyPI files, OSV.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Call {
    Npm,
    PypiMetadata,
    PypiArtifacts,
    Osv,
}

const ANSWERED: u8 = 1;
const FAILED: u8 = 2;

/// One kind of call. Starts `ok`; a period in which every call failed makes it
/// `unreachable`, one with a success makes it `ok`, and one with no calls changes
/// nothing.
#[derive(Default)]
struct Tracker {
    period: AtomicU8,
    unreachable: AtomicBool,
}

impl Tracker {
    fn close_period(&self) -> bool {
        match self.period.swap(0, Ordering::AcqRel) {
            0 => {}
            seen => self
                .unreachable
                .store(seen & ANSWERED == 0, Ordering::Release),
        }
        self.unreachable.load(Ordering::Acquire)
    }
}

#[derive(Default)]
pub struct UpstreamHealth {
    trackers: [Tracker; 4],
}

impl UpstreamHealth {
    /// One call's outcome: one atomic update.
    pub fn record(&self, call: Call, answered: bool) {
        let bit = if answered { ANSWERED } else { FAILED };
        self.trackers[call as usize]
            .period
            .fetch_or(bit, Ordering::AcqRel);
    }

    /// A call to a registry: a connect error, a timeout or a `5xx` is a failure;
    /// any other answer, a `404` included, means it was reached.
    pub fn record_upstream<T>(&self, call: Call, result: &Result<T, UpstreamError>) {
        let failed = matches!(
            result,
            Err(UpstreamError::Timeout
                | UpstreamError::Transport(_)
                | UpstreamError::RejectedAddress { .. })
        ) || matches!(result, Err(UpstreamError::Status(status)) if *status >= 500);
        self.record(call, !failed);
    }

    /// Closes the period and reports it. `pypi` is unreachable when either of its
    /// trackers is, so a files outage shows even while metadata refreshes succeed.
    pub fn take_period(&self) -> Upstreams {
        let [npm, metadata, artifacts, osv] = &self.trackers;
        let state = |down| {
            if down {
                Reachability::Unreachable
            } else {
                Reachability::Ok
            }
        };
        let pypi = metadata.close_period() | artifacts.close_period();
        Upstreams {
            npm: state(npm.close_period()),
            pypi: state(pypi),
            osv: state(osv.close_period()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_period_of_failures_marks_a_tracker_until_a_success() {
        let health = UpstreamHealth::default();
        let ok = Upstreams {
            npm: Reachability::Ok,
            pypi: Reachability::Ok,
            osv: Reachability::Ok,
        };
        assert_eq!(health.take_period(), ok, "no calls yet");
        health.record_upstream::<()>(Call::Npm, &Err(UpstreamError::Status(503)));
        health.record_upstream::<()>(Call::PypiMetadata, &Err(UpstreamError::Status(404)));
        health.record_upstream::<()>(Call::PypiArtifacts, &Err(UpstreamError::Timeout));
        let down = health.take_period();
        assert_eq!(down.npm, Reachability::Unreachable);
        assert_eq!(down.pypi, Reachability::Unreachable, "the files tracker");
        assert_eq!(down.osv, Reachability::Ok);
        assert_eq!(
            health.take_period(),
            down,
            "a period with no calls keeps it"
        );
        health.record(Call::Npm, false);
        health.record(Call::Npm, true);
        health.record(Call::PypiArtifacts, true);
        assert_eq!(health.take_period(), ok, "one success is enough");
    }
}
