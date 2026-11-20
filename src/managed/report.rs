//! Whether each upstream answered in the current sync period (C69), for the
//! `FirewallReport`. Each call is recorded where it is made, under the kind of call it
//! is, never by matching its URL; the sync task reads and resets the period.

use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};

use probation_policy::api::{Reachability, Upstreams};

use crate::upstream::UpstreamError;

/// The four trackers: npm metadata and tarballs, PyPI metadata, PyPI files, OSV.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Call {
    Npm,
    PypiMetadata,
    PypiArtifacts,
    Osv,
    Rubygems,
    Cargo,
    Go,
    Nuget,
    Maven,
    Conan,
    Oci,
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
    /// Set by the first call ever recorded (a firewall that never calls a registry never reports it).
    touched: AtomicBool,
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
    trackers: [Tracker; 11],
    /// LS-F3: layer rules of the active snapshot skipped for an unknown ecosystem tag.
    policy_rules_skipped_unknown_ecosystem: std::sync::atomic::AtomicU64,
    /// Central OSV (row 30): counters that travel in the sync report (`osv_report`) and the
    /// shared-service readiness detail. Aggregate only; no key is ever recorded.
    osv: OsvCounters,
}

#[derive(Default)]
struct OsvCounters {
    matches_file_degraded: AtomicU64,
    stale_matches_expired: AtomicU64,
    server_unreached: AtomicU64,
    matches_records_skipped: AtomicU64,
    keys_refused: AtomicU64,
    results_total: AtomicU64,
    results_degraded: AtomicU64,
    /// `(when, total, degraded)` batches of the last five minutes (LS-F7 alert).
    window: std::sync::Mutex<std::collections::VecDeque<(std::time::Instant, u64, u64)>>,
}

/// LS-F7: the degraded ratio is judged over this long.
const OSV_ALERT_WINDOW: std::time::Duration = std::time::Duration::from_secs(300);

impl UpstreamHealth {
    pub fn set_policy_rules_skipped_unknown_ecosystem(&self, count: u64) {
        self.policy_rules_skipped_unknown_ecosystem.store(count, Ordering::Relaxed);
    }

    pub fn policy_rules_skipped_unknown_ecosystem(&self) -> u64 {
        self.policy_rules_skipped_unknown_ecosystem.load(Ordering::Relaxed)
    }

    /// The counters as the sync report carries them (LS-F7, C1031).
    pub fn osv_report(&self) -> probation_policy::api::OsvReport {
        probation_policy::api::OsvReport {
            degraded_warning: self.osv_degraded_warning(std::time::Instant::now()),
            results_total: self.osv_results_total(),
            results_degraded: self.osv_results_degraded(),
            server_unreached: self.osv_server_unreached(),
            matches_file_degraded: self.osv_matches_file_degraded(),
            stale_matches_expired: self.osv_stale_matches_expired(),
            matches_records_skipped: self.osv_matches_records_skipped(),
            keys_refused: self.osv_keys_refused(),
        }
    }

    pub fn osv_keys_refused(&self) -> u64 {
        self.osv.keys_refused.load(Ordering::Relaxed)
    }
    pub fn add_osv_keys_refused(&self, count: u64) {
        self.osv.keys_refused.fetch_add(count, Ordering::Relaxed);
    }
    pub fn osv_matches_file_degraded(&self) -> u64 {
        self.osv.matches_file_degraded.load(Ordering::Relaxed)
    }
    pub fn add_osv_matches_file_degraded(&self, count: u64) {
        self.osv.matches_file_degraded.fetch_add(count, Ordering::Relaxed);
    }
    pub fn osv_stale_matches_expired(&self) -> u64 {
        self.osv.stale_matches_expired.load(Ordering::Relaxed)
    }
    pub fn add_osv_stale_matches_expired(&self, count: u64) {
        self.osv.stale_matches_expired.fetch_add(count, Ordering::Relaxed);
    }
    pub fn osv_server_unreached(&self) -> u64 {
        self.osv.server_unreached.load(Ordering::Relaxed)
    }
    pub fn add_osv_server_unreached(&self, count: u64) {
        self.osv.server_unreached.fetch_add(count, Ordering::Relaxed);
    }
    pub fn osv_matches_records_skipped(&self) -> u64 {
        self.osv.matches_records_skipped.load(Ordering::Relaxed)
    }
    pub fn add_osv_matches_records_skipped(&self, count: u64) {
        self.osv.matches_records_skipped.fetch_add(count, Ordering::Relaxed);
    }
    pub fn osv_results_total(&self) -> u64 {
        self.osv.results_total.load(Ordering::Relaxed)
    }
    pub fn osv_results_degraded(&self) -> u64 {
        self.osv.results_degraded.load(Ordering::Relaxed)
    }

    /// One answer's results: `total` queries of which `degraded` carried the degraded
    /// marker (or were part of an unreached batch).
    pub fn record_osv_results(&self, total: u64, degraded: u64) {
        self.record_osv_results_at(std::time::Instant::now(), total, degraded);
    }

    pub fn record_osv_results_at(&self, now: std::time::Instant, total: u64, degraded: u64) {
        self.osv.results_total.fetch_add(total, Ordering::Relaxed);
        self.osv.results_degraded.fetch_add(degraded, Ordering::Relaxed);
        let mut window = self.osv.window.lock().expect("the OSV window");
        window.push_back((now, total, degraded));
        while window.front().is_some_and(|(at, ..)| now.saturating_duration_since(*at) >= OSV_ALERT_WINDOW) {
            window.pop_front();
        }
    }

    /// LS-F7: true while more than 5% of the last five minutes' results were degraded.
    /// Readiness itself is unchanged; this is the warning shown beside it.
    pub fn osv_degraded_warning(&self, now: std::time::Instant) -> bool {
        let window = self.osv.window.lock().expect("the OSV window");
        let (total, degraded) = window
            .iter()
            .filter(|(at, ..)| now.saturating_duration_since(*at) < OSV_ALERT_WINDOW)
            .fold((0u64, 0u64), |(t, d), (_, bt, bd)| (t + bt, d + bd));
        total > 0 && degraded * 20 > total
    }

    /// One call's outcome: one atomic update.
    pub fn record(&self, call: Call, answered: bool) {
        self.trackers[call as usize].touched.store(true, Ordering::Release);
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
        let [npm, metadata, artifacts, osv, rubygems, cargo, go, nuget, maven, conan, oci] = &self.trackers;
        // Reported only once RubyGems has been called, so a firewall that serves none never names it.
        let rubygems_down = rubygems.close_period();
        let cargo_down = cargo.close_period();
        let go_down = go.close_period();
        let nuget_down = nuget.close_period();
        let maven_down = maven.close_period();
        let conan_down = conan.close_period();
        let oci_down = oci.close_period();
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
            rubygems: rubygems.touched.load(Ordering::Acquire).then(|| state(rubygems_down)),
            cargo: cargo.touched.load(Ordering::Acquire).then(|| state(cargo_down)),
            go: go.touched.load(Ordering::Acquire).then(|| state(go_down)),
            nuget: nuget.touched.load(Ordering::Acquire).then(|| state(nuget_down)),
            maven: maven.touched.load(Ordering::Acquire).then(|| state(maven_down)),
            conan: conan.touched.load(Ordering::Acquire).then(|| state(conan_down)),
            oci: oci.touched.load(Ordering::Acquire).then(|| state(oci_down)),
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
            osv: Reachability::Ok, rubygems: None, cargo: None, go: None, nuget: None, maven: None, conan: None, oci: None,
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

    /// Row 21: Maven is reported only once a Maven call was made, and follows the same rule as every family before it.
    #[test]
    fn a_maven_tracker_is_reported_only_after_its_first_call_and_follows_the_same_rule() {
        let health = UpstreamHealth::default();
        assert_eq!(health.take_period().maven, None, "no call, no entry");
        health.record_upstream::<()>(Call::Maven, &Err(UpstreamError::Status(503)));
        assert_eq!(health.take_period().maven, Some(Reachability::Unreachable));
        assert_eq!(health.take_period().maven, Some(Reachability::Unreachable), "a period with no calls keeps it");
        health.record_upstream::<()>(Call::Maven, &Err(UpstreamError::Status(404)));
        assert_eq!(health.take_period().maven, Some(Reachability::Ok), "a 404 means the repository answered");
        assert_eq!(health.take_period().nuget, None, "another family's entry stays absent");
    }

    /// Row 20: NuGet is reported only once a NuGet call was made (a firewall that serves none never names it),
    /// and a period of failures marks it until a success, like every family before it.
    #[test]
    fn a_nuget_tracker_is_reported_only_after_its_first_call_and_follows_the_same_rule() {
        let health = UpstreamHealth::default();
        assert_eq!(health.take_period().nuget, None, "no call, no entry");
        health.record_upstream::<()>(Call::Nuget, &Err(UpstreamError::Status(503)));
        assert_eq!(health.take_period().nuget, Some(Reachability::Unreachable));
        assert_eq!(health.take_period().nuget, Some(Reachability::Unreachable), "a period with no calls keeps it");
        health.record_upstream::<()>(Call::Nuget, &Err(UpstreamError::Status(404)));
        assert_eq!(health.take_period().nuget, Some(Reachability::Ok), "a 404 means the registry answered");
        assert_eq!(health.take_period().go, None, "another family's entry stays absent");
    }
}
