//! Where a decision record goes once this process has made it.
//!
//! `http::logging` owns "a line reaches stdout". This module owns "a copy of that
//! record leaves this process", which is not the same promise and not the same
//! failure mode: stdout cannot fill up, and a file or a collector can.
//!
//! The shape of the interface is the product promise made structural. [`Sinks::offer`]
//! is not `async`, takes no lock, does no I/O and returns nothing, so delivery cannot
//! slow or fail a request without changing a signature. A record that cannot be
//! handed over is counted rather than discarded silently, and the counts are read
//! back out by the summary path.

mod counters;
use counters::SinkCounters;
mod file;
mod siem;

use std::net::IpAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::Duration;

use reqwest::header::{HeaderName, HeaderValue};
use reqwest::redirect;
use serde::Serialize;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::StartupError;
use crate::config::Config;

/// The ceiling on one `loggable`-bounded field's heap cost, in bytes:
/// `MAX_LOGGED_TARGET` (256) characters x 4 bytes of UTF-8 x the worst-case `Debug`
/// escape expansion (a character rendered `\u{10ffff}`, ten bytes), plus the two
/// quote characters `Debug` adds. The expansion term is what makes this a ceiling
/// rather than a mean: `loggable` bounds the *character* count and then escapes,
/// so the escaping runs after the bound.
pub(crate) const FIELD_CEILING_BYTES: u64 = 256 * 4 * 10 + 2;

/// A conservative ceiling on one decision record's heap footprint, in bytes —
/// `size_of::<Decision>()` plus every `String`'s capacity, never its serialized
/// size. This is the unit the operator's queue budget is divided by, so it must
/// over-state a record rather than under-state one: too low a figure lets a queue
/// hold more bytes than the budget promises.
///
/// Derivation, summed over [`Decision`]:
///   3 x FIELD_CEILING_BYTES  = 30_726   `package` and `version`, bounded by `loggable` today;
///                                       `method` from slice 2 (C22) — until then it is
///                                       `method.to_string()` and this term does not bound it
///   timestamp                =     64   RFC 3339 with six fractional digits is 27 bytes
///   request_id               =     64   `req-` and sixteen hex digits is 20 bytes
///   reason                   =    512   every `ApiError` arm is a `&'static str`; the longest is 77 bytes
///   size_of::<Decision>()    =    256   allowed for six `String`, three `&'static str`, four
///                                       integers and one `Option<IpAddr>`; the assert below
///                                       reads the real size rather than trusting this figure
///   ------------------------------------
///   total                      31_622, rounded up to the next power of two.
pub(crate) const BYTES_PER_RECORD: u64 = 32 * 1024;

/// The arithmetic of the derivation above: the three `FIELD_CEILING_BYTES` terms,
/// the timestamp, the request id, the reason and the struct, against the constant
/// they were rounded up to. It catches a term or a constant edited without its
/// figure, and nothing else — `BYTES_PER_RECORD` carries 1,162 bytes of slack over
/// this sum, so a small new term slips under it.
const _: () = assert!(
    BYTES_PER_RECORD >= 3 * FIELD_CEILING_BYTES + 64 + 64 + 512 + size_of::<Decision>() as u64
);

/// The struct's own allowance, tight where the sum above is loose: 240 bytes today
/// against 256 allowed. One added field larger than 16 bytes trips this at compile
/// time; a pointer-shaped field (`Box<str>`, `Arc<str>`, `u64`) fits the remaining
/// slack and passes silently, as does a `bool` in the struct's 5 bytes of tail
/// padding — which is why the re-derivation below is not optional.
///
/// **Neither assert sees heap content.** `size_of` measures the struct, so a new
/// `String` field adds 24 bytes here while adding its whole capacity — unbounded,
/// unless `loggable` bounds it — to the record this constant claims to bound. That
/// is exactly how `method` came to exceed `BYTES_PER_RECORD` (C22). An engineer who
/// adds a field to [`Decision`] must re-derive `BYTES_PER_RECORD` by hand; what
/// these two lines buy is that the compiler makes them notice, not that it checks
/// the answer.
const _: () = assert!(size_of::<Decision>() <= 256);

/// The per-sink budget an operator who writes neither key gets.
///
/// **Final (C13 as amended, C39).** `benches/delivery_rated_load.rs` measures the
/// rated figure `N` — on the reference hardware named in `docs/operations.md` §8,
/// **59,288 decided requests/s, sustained ten minutes with zero records dropped** —
/// but `N` is published as that machine's ceiling, not used as this constant's
/// multiplicand: `ceil(5 min x N x BYTES_PER_RECORD)` wants roughly 543 GiB, no
/// honest budget could cover it, and raising `MAX_QUEUE_MAX_BYTES` to fit it reopens
/// the accepted host-memory risk (G3-T8) for no realistic benefit. Instead this is
/// derived from a **stated 200 requests/second reference load** (`01-product.md`'s
/// Problem section): `ceil(5 min x 200 x BYTES_PER_RECORD) = 1,875 MiB`. At that
/// reference load the default buys the full five minutes C13 promised; at the
/// measured `N` it buys about 1 s, which `docs/operations.md` states honestly
/// alongside the formula an operator can use to compute their own tolerance at their
/// real, ecosystem-bottlenecked traffic rate.
pub(crate) const DEFAULT_QUEUE_MAX_BYTES: u64 = 1875 * 1024 * 1024;

/// The largest budget either key accepts. Two sinks at the ceiling is 8 GiB of
/// resident queue — a figure that holds once slice 2 bounds `method` (C22); until
/// then a record has no upper bound and neither does the queue. It is the operator's
/// call to make and not this process's, but a budget beyond it is more likely a typo
/// than an intention.
pub(crate) const MAX_QUEUE_MAX_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// The largest buffer `mpsc::channel` accepts, for the target actually compiled:
/// above it the constructor panics, exactly as it does at zero.
pub(crate) const MAX_SAFE_CAPACITY: usize = tokio::sync::Semaphore::MAX_PERMITS;

/// Why a budget cannot become a queue capacity. Both arms are inputs on which
/// `mpsc::channel` panics, which is why `config` refuses them at load rather than
/// letting startup discover them.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CapacityError {
    /// The quotient is `0`: the budget cannot hold one whole record.
    TooSmall,
    /// The quotient exceeds `MAX_SAFE_CAPACITY`, or does not fit a `usize` at all.
    TooLarge,
}

/// How many records a budget of `budget` bytes may hold.
///
/// Total over the whole `u64` domain, `0` included — it returns `Err` where
/// `mpsc::channel` would panic. That totality is what lets `config` decide its
/// lower bound by calling this function rather than restating the division, so the
/// rule and the arithmetic cannot disagree.
pub(crate) fn capacity_for(budget: u64) -> Result<usize, CapacityError> {
    let records = budget / BYTES_PER_RECORD;
    if records == 0 {
        return Err(CapacityError::TooSmall);
    }
    // `try_from` and never `as`, so a budget beyond a 32-bit `usize` is refused
    // rather than truncated into a small capacity.
    let capacity = usize::try_from(records).map_err(|_| CapacityError::TooLarge)?;
    if capacity > MAX_SAFE_CAPACITY {
        return Err(CapacityError::TooLarge);
    }
    Ok(capacity)
}

/// One line of delivered output. The tag is what lets a reader of the file tell a
/// decision from a summary without guessing at the key set.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub(crate) enum Record {
    RequestDecided(Decision),
    RequestSummary(Summary),
}

/// The stdout decision line's twelve SPEC §11 fields, in the order it carries them,
/// so one NDJSON line and one stdout line cannot drift apart — preceded by
/// `timestamp`, which only the file and the SIEM receive because the console
/// formatter stamps stdout itself, plus `consumer` last when an operator has opted in
/// to it.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct Decision {
    pub timestamp: String,
    pub request_id: String,
    pub method: String,
    pub ecosystem: &'static str,
    pub package: String,
    pub version: String,
    pub status: u16,
    pub result: &'static str,
    pub reason: String,
    pub blocklist_revision: u64,
    pub cache: &'static str,
    pub duration_micros: u64,
    pub bytes: u64,
    /// The peer address of the connection that asked, and never its port — `Some`
    /// only while consumer identification is on. An absent field rather than a null
    /// one, so the default key set an operator reads is the twelve above.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consumer: Option<IpAddr>,
}

/// The periodic counter summary, plus the per-sink drop counts for the window it
/// closes — so "a record was dropped" reaches the durable destinations rather than
/// only the console.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct Summary {
    pub timestamp: String,
    pub requests: u64,
    pub errors: u64,
    pub bytes: u64,
    pub mean_duration_micros: u64,
    pub window_micros: u64,
    pub dropped_file: u64,
    pub dropped_siem: u64,
}

/// `utc_micros` as UTC RFC 3339 with exactly six fractional digits, so every record's
/// timestamp has the same width. Out of `jiff`'s range, the raw count is written
/// rather than a made-up date.
pub(crate) fn rfc3339(utc_micros: i64) -> String {
    jiff::Timestamp::from_microsecond(utc_micros)
        .map(|t| format!("{t:.6}"))
        .unwrap_or_else(|_| utc_micros.to_string())
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Drops {
    pub file: u64,
    pub siem: u64,
}

/// One destination: the sending half of its queue and the counter both sides
/// increment.
struct Sink {
    tx: mpsc::Sender<Record>,
    counters: Arc<SinkCounters>,
}

impl Sink {
    fn push(&self, record: Record) {
        if self.tx.try_send(record).is_err() {
            self.counters.lose(1);
        }
    }
}

/// The enabled destinations. Empty unless an operator configured one, which is what
/// makes "not on by default" a property of the value rather than of a code path.
pub(crate) struct Sinks {
    file: Option<Sink>,
    siem: Option<Sink>,
    /// The watch pair behind [`Sinks::is_shedding`]: when `lost_total` last moved as
    /// a prober saw it, and the total that was. One pair for the process, because one
    /// `503` covers both sinks.
    last_change_micros: AtomicI64,
    last_total: AtomicU64,
}

/// How long without a new loss before the shedding signal clears.
const SHED_QUIET: Duration = Duration::from_secs(60);

impl Sinks {
    fn new(file: Option<Sink>, siem: Option<Sink>) -> Sinks {
        Sinks {
            file,
            siem,
            last_change_micros: AtomicI64::new(i64::MIN),
            last_total: AtomicU64::new(0),
        }
    }

    /// Hands `record` to every enabled sink. Never blocks, never fails, never tells
    /// the caller anything — a full or closed queue counts a drop and returns.
    ///
    /// The record is cloned only when both sinks are enabled, so the common
    /// single-sink case moves it rather than copying it.
    pub(crate) fn offer(&self, record: Record) {
        match (&self.file, &self.siem) {
            (Some(file), Some(siem)) => {
                file.push(record.clone());
                siem.push(record);
            }
            (Some(file), None) => file.push(record),
            (None, Some(siem)) => siem.push(record),
            (None, None) => {}
        }
    }

    /// The drops accumulated since the previous call, per sink. Read-and-reset, so
    /// the counts are per summary window exactly as `requests` and `errors` are.
    ///
    /// Called only from the summary path, which serialises itself under the existing
    /// counters mutex; a second caller would silently steal a window's counts.
    pub(crate) fn drops(&self) -> Drops {
        Drops {
            file: self
                .file
                .as_ref()
                .map_or(0, |sink| sink.counters.take_window()),
            siem: self
                .siem
                .as_ref()
                .map_or(0, |sink| sink.counters.take_window()),
        }
    }

    /// Every record either sink has lost since start. Never reset, and safe to call
    /// from any number of readers, unlike `drops`.
    pub(crate) fn lost_total(&self) -> u64 {
        [&self.file, &self.siem]
            .into_iter()
            .flatten()
            .map(|sink| sink.counters.total())
            .sum()
    }

    /// True while a record was lost within the last `SHED_QUIET`, as seen by probes.
    ///
    /// `last_change_micros` is stored before `last_total` (Release, read Acquire), so
    /// a prober that sees the new total also sees its timestamp. The delta must be
    /// non-negative: a backwards wall-clock step would otherwise latch `true`.
    pub(crate) fn is_shedding(&self, now_utc_micros: i64) -> bool {
        let total = self.lost_total();
        if total != self.last_total.load(Ordering::Acquire) {
            self.last_change_micros
                .store(now_utc_micros, Ordering::Relaxed);
            self.last_total.store(total, Ordering::Release);
        }
        let since = now_utc_micros.saturating_sub(self.last_change_micros.load(Ordering::Relaxed));
        (0..SHED_QUIET.as_micros() as i64).contains(&since)
    }

    /// True when no sink is enabled, and therefore when nothing was opened and
    /// nothing was spawned.
    ///
    /// Its one caller is `App::delivery_is_empty`, compiled only under
    /// `test-support`: the promise it reads is "an operator who configures nothing
    /// gets nothing", which product code has no reason to ask about and a witness
    /// has every reason to.
    #[cfg_attr(not(feature = "test-support"), allow(dead_code))]
    pub(crate) fn is_empty(&self) -> bool {
        self.file.is_none() && self.siem.is_none()
    }
}

/// The environment variable the SIEM credential is read from. It is read exactly once,
/// in [`build`], and is never placed on `Config` — which derives `Debug`, so any
/// `{config:?}` anywhere in the process would print every field it holds.
const SIEM_AUTH_ENV: &str = "PROBATION_SIEM_AUTH";

/// The whole of what an operator is told when that variable cannot be used. A
/// `&'static str` rather than a `String`, so no part of the rejected value can reach
/// `check_config`'s printed `path: err` (`src/main.rs`) however this is later edited.
const SIEM_AUTH_REJECTED: &str = "PROBATION_SIEM_AUTH is not a valid HTTP header value; \
     it must be printable ASCII with no line break";

/// How long one delivery attempt may take, and how long its connect may take.
/// reqwest's async client has no default timeout at all, so an untimed `POST` to a
/// collector that accepts the connection and then goes silent would outlive any drain
/// deadline.
const SIEM_REQUEST_TIMEOUT: Duration = Duration::from_secs(3);
const SIEM_CONNECT_TIMEOUT: Duration = Duration::from_secs(1);

/// Builds the enabled sinks and spawns their tasks.
///
/// With neither `log_file_path` nor `siem_url` set this opens no file, constructs no
/// HTTP client, spawns nothing and returns an empty `Sinks` — the default path an
/// operator who configures nothing is on.
///
/// `drain` must be the token cancelled *after* the HTTP server has joined, never the
/// shutdown token: a sink that stopped when the server did would lose the records of
/// the requests that were still being answered.
pub(crate) fn build(
    config: &Config,
    drain: CancellationToken,
) -> Result<(Sinks, Vec<JoinHandle<()>>), StartupError> {
    let mut tasks = Vec::new();

    if let Some(path) = &config.log_file_path {
        probe(path, config.log_consumer_identification)?;
    }

    let file = config.log_file_path.as_ref().map(|path| {
        let (tx, rx) = mpsc::channel(
            capacity_for(config.log_queue_max_bytes.get()).expect("config validated"),
        );
        let counters = Arc::new(SinkCounters::new());
        tasks.push(tokio::spawn(file::run(
            path.clone(),
            config.log_file_max_bytes,
            rx,
            drain.clone(),
            Arc::clone(&counters),
        )));
        Sink { tx, counters }
    });

    // The header *name* of the credential, and only when one was actually configured.
    // The value never leaves this function except as a sensitive `HeaderValue`.
    let mut siem_auth_header = None;

    let siem = match &config.siem_url {
        Some(url) => {
            let auth = siem_auth(&config.siem_auth_header)?;
            siem_auth_header = auth.as_ref().map(|(name, _)| name.as_str().to_owned());

            let client = reqwest::Client::builder()
                // Gate 2 C4: a collector that redirects must not be able to point
                // this process — credential attached — at a host nobody configured.
                .redirect(redirect::Policy::none())
                .timeout(SIEM_REQUEST_TIMEOUT)
                .connect_timeout(SIEM_CONNECT_TIMEOUT)
                // Ignore `HTTP_PROXY`/`HTTPS_PROXY`, as the upstream registry client
                // does, so both leave the host by the same route.
                .no_proxy()
                .build()
                .map_err(|err| {
                    tracing::error!(error = %err, "the SIEM delivery client could not be built");
                    StartupError::Delivery("the SIEM delivery client could not be built")
                })?;

            let (tx, rx) = mpsc::channel(
                capacity_for(config.siem_queue_max_bytes.get()).expect("config validated"),
            );
            let counters = Arc::new(SinkCounters::new());
            tasks.push(tokio::spawn(siem::run(
                client,
                url.clone(),
                auth,
                rx,
                drain.clone(),
                Arc::clone(&counters),
            )));
            Some(Sink { tx, counters })
        }
        None => None,
    };

    if config.log_file_path.is_some() || config.siem_url.is_some() {
        tracing::info!(
            log_file = ?config.log_file_path,
            log_file_max_bytes = config.log_file_max_bytes.get(),
            siem_url = config.siem_url.as_ref().map(Url::as_str),
            siem_auth_header = siem_auth_header.as_deref(),
            "decision records are delivered off this process"
        );
    }

    Ok((Sinks::new(file, siem), tasks))
}

/// What an operator is told when the log file cannot be opened while peer addresses
/// would be recorded. Fixed text, so no address and no path can reach it.
const LOG_FILE_REJECTED: &str = "log_file_path cannot be opened for append, and \
     log_consumer_identification is on: peer addresses would be collected with nowhere \
     durable to go";

/// Opens the log file once at startup and lets it go: the one place a typo in
/// `log_file_path` can be told apart from working delivery, and the open that creates
/// the file `0o600`. It reads no length — `file::run` restores its own tally.
///
/// Fatal only while `consumer_identification` is on, because that is when an
/// unopenable file means peer addresses kept for nothing. With it off, a logging typo
/// is not worth an outage: one error, and the sink retries per record as before.
///
/// `std::fs` rather than `tokio::fs`: this runs once, before anything is served.
fn probe(path: &Path, consumer_identification: bool) -> Result<(), StartupError> {
    let Err(err) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
    else {
        return Ok(());
    };
    if consumer_identification {
        return Err(StartupError::Delivery(LOG_FILE_REJECTED));
    }
    tracing::error!(
        key = "log_file_path",
        path = %path.display(),
        error = %err,
        "log_file_path cannot be opened for append; decision records will be dropped and \
         counted until it can"
    );
    Ok(())
}

/// Reads the SIEM credential out of the environment, once.
///
/// Set-but-unusable is deliberately not the same as unset: shipping decision records
/// unauthenticated because the credential could not be decoded is a silent downgrade,
/// so it fails startup instead.
fn siem_auth(name: &HeaderName) -> Result<Option<(HeaderName, HeaderValue)>, StartupError> {
    let value = match std::env::var(SIEM_AUTH_ENV) {
        Ok(value) => value,
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(StartupError::Delivery(SIEM_AUTH_REJECTED));
        }
    };

    let mut value =
        HeaderValue::from_str(&value).map_err(|_| StartupError::Delivery(SIEM_AUTH_REJECTED))?;
    // Redacts it in any `Debug` rendering, including reqwest's own.
    value.set_sensitive(true);
    Ok(Some((name.clone(), value)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `MAX_SAFE_CAPACITY` as a `u64`, saturating on a target where it does not fit,
    /// so the property states its bound without a cast that could wrap.
    fn max_safe_capacity_u64() -> u64 {
        u64::try_from(MAX_SAFE_CAPACITY).unwrap_or(u64::MAX)
    }

    proptest::proptest! {
        /// No budget an operator can write — including `0`, which `NonZeroU64` would
        /// have excluded from the sweep — reaches `mpsc::channel` as a panicking
        /// capacity. Every value lands in exactly one of three arms, and the property
        /// asserts *which*: a quotient of zero is refused as `TooSmall`, a quotient
        /// above the channel's own limit as `TooLarge`, and everything else returns a
        /// capacity `mpsc::channel` accepts.
        #[test]
        fn rl6_no_budget_panics_or_yields_a_bad_capacity(budget: u64) {
            let records = budget / BYTES_PER_RECORD;
            match capacity_for(budget) {
                Ok(capacity) => {
                    proptest::prop_assert!(
                        (1..=MAX_SAFE_CAPACITY).contains(&capacity),
                        "budget {} yielded capacity {}, which mpsc::channel would refuse",
                        budget,
                        capacity
                    );
                    // The 32-bit-build guard, and only that: it discriminates
                    // `usize::try_from` from `as usize`, which can disagree solely
                    // where `usize` is narrower than the quotient. On a 64-bit
                    // target this line is vacuous; the arm selection and the range
                    // above are what carry content here.
                    proptest::prop_assert_eq!(u64::try_from(capacity).unwrap(), records);
                }
                Err(CapacityError::TooSmall) => {
                    proptest::prop_assert_eq!(records, 0, "budget {} holds a whole record", budget);
                }
                Err(CapacityError::TooLarge) => {
                    proptest::prop_assert!(
                        records > max_safe_capacity_u64(),
                        "budget {} is within the channel's limit and was still refused",
                        budget
                    );
                }
            }
        }
    }

    fn summary() -> Record {
        Record::RequestSummary(Summary {
            timestamp: String::new(),
            requests: 0,
            errors: 0,
            bytes: 0,
            mean_duration_micros: 0,
            window_micros: 0,
            dropped_file: 0,
            dropped_siem: 0,
        })
    }

    /// A file sink whose queue holds one record and is never read.
    fn full_file_sink() -> (Sinks, mpsc::Receiver<Record>) {
        let (tx, rx) = mpsc::channel(1);
        let sink = Sink {
            tx,
            counters: Arc::new(SinkCounters::new()),
        };
        (Sinks::new(Some(sink), None), rx)
    }

    /// rl7, the queue-full site: a record the full queue refuses is counted.
    #[test]
    fn rl7_queue_full_counts_in_the_window() {
        let (sinks, _rx) = full_file_sink();
        sinks.offer(summary());
        assert_eq!(sinks.drops().file, 0, "the first record fits");
        sinks.offer(summary());
        assert_eq!(sinks.drops().file, 1);
    }

    /// rl8: `drops()` reads and resets, so the second window reports only its own
    /// losses, while the total keeps both.
    #[test]
    fn rl8_the_second_window_reports_only_its_own_losses() {
        let (sinks, _rx) = full_file_sink();
        for _ in 0..4 {
            sinks.offer(summary()); // one queued, three lost
        }
        assert_eq!(sinks.drops().file, 3);
        sinks.offer(summary());
        assert_eq!(sinks.drops().file, 1, "not 4: the first window was reset");
        assert_eq!(sinks.drops().file, 0);
        assert_eq!(sinks.lost_total(), 4);
    }
}
