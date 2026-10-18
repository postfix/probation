//! The file sink: one NDJSON object per record, appended to one operator-named file
//! with a hard ceiling on what it can cost the disk.
//!
//! Everything here is `tokio::fs`. A `std::fs` call would block the runtime worker
//! this task happens to be on, which is the request path's thread too.

use std::num::NonZeroU64;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::fs::{File, OpenOptions};
use tokio::io::AsyncWriteExt;
use tokio_util::sync::CancellationToken;

use super::counters::SinkCounters;
use super::{Queue, Record};

/// How long the drain may take once it has been asked to finish. Imposed by the
/// caller rather than trusted to the write, so the deadline holds even when the
/// filesystem does not answer.
const DRAIN_DEADLINE: Duration = Duration::from_secs(5);

/// Appends records until the drain token fires.
///
/// Exactly one process may write `path`. There is no interprocess lock, so a second
/// instance pointed at the same file — or an external `logrotate` renaming it away —
/// interleaves or loses records.
pub(super) async fn run(
    path: PathBuf,
    max_bytes: NonZeroU64,
    mut queue: Queue,
    drain: CancellationToken,
    counters: Arc<SinkCounters>,
) {
    let mut writer = Writer::new(path, max_bytes);

    loop {
        tokio::select! {
            received = queue.recv() => match received {
                Some(record) => writer.append(record, &counters).await,
                None => break,
            },
            () = drain.cancelled() => {
                self::drain(&mut writer, &mut queue, &counters, DRAIN_DEADLINE).await;
                break;
            }
        }
    }
}

/// Writes whatever is already queued, and nothing more, within `deadline`. Waiting on
/// `recv` here would wait for the senders to close, and the last `App` is dropped only
/// *after* this task has been joined.
///
/// What the deadline cuts off is counted: the records still queued, plus the one in
/// hand — there always is one, because `try_recv` never waits, so the drain can only be
/// pending inside `append`. When the cut lands after that record's write finished it is
/// both written and counted, so the count may be one high and is never low.
async fn drain(
    writer: &mut Writer,
    queue: &mut Queue,
    counters: &SinkCounters,
    deadline: Duration,
) {
    let drained = tokio::time::timeout(deadline, async {
        while let Some(record) = queue.try_recv() {
            writer.append(record, counters).await;
        }
    })
    .await;
    if drained.is_err() {
        counters.lose(queue.len() as u64 + 1);
    }
}

/// The open handle and the byte tally that bounds it.
struct Writer {
    path: PathBuf,
    max_bytes: u64,
    /// `None` before the first record and after any I/O error, so the next record
    /// reopens rather than the task giving up.
    file: Option<File>,
    written: u64,
    /// Whether the group- or world-accessible warning has been given, so a file that
    /// is reopened after every I/O error is reported once rather than per record.
    warned: bool,
    /// Whether the rollover rename is failing, so a rename that fails for every record
    /// — a bind-mounted single file, an unwritable directory — is reported once per run
    /// of failures. The count keeps going up in `dropped_file`.
    rollover_failing: bool,
}

impl Writer {
    fn new(path: PathBuf, max_bytes: NonZeroU64) -> Writer {
        Writer {
            path,
            max_bytes: max_bytes.get(),
            file: None,
            written: 0,
            warned: false,
            rollover_failing: false,
        }
    }

    async fn append(&mut self, record: Record, counters: &SinkCounters) {
        let Ok(mut line) = serde_json::to_string(&record) else {
            counters.lose(1);
            return;
        };
        line.push('\n');
        let cost = line.len() as u64;
        // A record that would breach the ceiling even in an empty file is never
        // written, and does not roll the previous generation away for nothing.
        if cost >= self.max_bytes {
            counters.lose(1);
            return;
        }

        // Open first: the tally is restored from the file's own length, and until
        // that has happened there is nothing truthful to compare the threshold
        // against. Deciding before it is what lets the first record after a restart
        // land on top of a file that is already at the cap.
        if !self.open(counters).await {
            return;
        }
        if self.written.saturating_add(cost) >= self.max_bytes {
            // The ceiling is hard: a file that cannot be rolled away is not extended.
            if !self.roll_over().await {
                counters.lose(1);
                return;
            }
            if !self.open(counters).await {
                return;
            }
        }

        let file = self.file.as_mut().expect("the file was just opened");
        // `tokio::fs::File` buffers, and dropping it does not promise the bytes
        // reached the file. An operator tailing this file is the whole point of it.
        let written = async {
            file.write_all(line.as_bytes()).await?;
            file.flush().await
        }
        .await;

        match written {
            Ok(()) => self.written = self.written.saturating_add(cost),
            Err(err) => {
                tracing::warn!(
                    path = %self.path.display(),
                    error = %err,
                    "a decision record could not be written to the log file"
                );
                counters.lose(1);
                // A write that failed partway — a full disk — leaves part of the
                // line behind, and the next record would be glued onto it. The tally
                // is the length before this write, so cutting back to it removes the
                // fragment. Best effort: the handle is reopened either way.
                let _ = file.set_len(self.written).await;
                self.file = None;
            }
        }
    }

    /// Opens the file for append when there is no handle, and takes its current
    /// length as the tally — so a restart does not forget how full the file already
    /// is. Returns whether there is a handle to write to.
    async fn open(&mut self, counters: &SinkCounters) -> bool {
        if self.file.is_some() {
            return true;
        }
        // Owner-only, because once consumer identification is on every line carries a
        // peer address. It applies only when this open creates the file.
        match OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&self.path)
            .await
        {
            Ok(file) => {
                self.written = match file.metadata().await {
                    Ok(metadata) => {
                        self.warn_if_shared(metadata.permissions().mode());
                        metadata.len()
                    }
                    Err(_) => 0,
                };
                self.file = Some(file);
                true
            }
            Err(err) => {
                tracing::warn!(
                    path = %self.path.display(),
                    error = %err,
                    "the decision log file could not be opened"
                );
                counters.lose(1);
                false
            }
        }
    }

    /// Says once that a file this process did not create is readable or writable by
    /// someone other than its owner. The mode is left alone — `0640` with a group may be
    /// deliberate — but it is no longer silent.
    fn warn_if_shared(&mut self, mode: u32) {
        if self.warned || mode & 0o077 == 0 {
            return;
        }
        self.warned = true;
        tracing::warn!(
            path = %self.path.display(),
            mode = %format_args!("{:o}", mode & 0o777),
            "the decision log file is accessible to users other than its owner"
        );
    }

    /// Renames the live file to `<path>.1`, replacing any previous generation, and
    /// starts a fresh one. One generation only, so the disk cost is bounded at twice
    /// `max_bytes`. Returns whether it did.
    ///
    /// The handle is dropped either way, so the next record reopens the path and reads
    /// its length again: a live file someone deleted is then simply recreated.
    async fn roll_over(&mut self) -> bool {
        self.file = None;
        // Pushed onto the `OsString` rather than formatted through a `str`, so a
        // path this process cannot decode still rolls over.
        let mut rolled = self.path.clone().into_os_string();
        rolled.push(".1");
        if let Err(err) = tokio::fs::rename(&self.path, PathBuf::from(rolled)).await {
            if !self.rollover_failing {
                self.rollover_failing = true;
                tracing::warn!(
                    path = %self.path.display(),
                    error = %err,
                    "the decision log file could not be rolled over; records are dropped \
                     and counted until it can"
                );
            }
            return false;
        }
        self.rollover_failing = false;
        self.written = 0;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delivery::{Summary, channel};

    #[tokio::test]
    async fn tp19_file_drain_deadline_counts_cut_off_records() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("decisions.ndjson");
        // Enough records that the zero deadline, which fires at tokio's next millisecond
        // tick, cuts the drain off partway; about 8 fit in that tick here.
        const QUEUED: u64 = 10_000;
        let (sink, mut queue) = channel(QUEUED as usize);
        for index in 0..QUEUED as usize {
            sink.push(padded(index, 0));
        }
        let mut writer = Writer::new(path.clone(), NonZeroU64::MAX);
        let counters = SinkCounters::new();

        drain(&mut writer, &mut queue, &counters, Duration::ZERO).await;

        let written = std::fs::read_to_string(&path)
            .map(|text| text.lines().count() as u64)
            .unwrap_or(0);
        assert!(
            written < QUEUED,
            "inconclusive: no cut-off happened, all {written} records were written"
        );
        let dropped = counters.total();
        // One high when the cut lands after the in-hand record's write finished.
        assert!(
            (QUEUED..=QUEUED + 1).contains(&(written + dropped)),
            "every queued record is either in the file or counted as dropped: \
             {written} written, {dropped} dropped"
        );
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

    /// rl7, the drain-deadline site: what the deadline cuts off lands in the window.
    #[tokio::test]
    async fn rl7_file_drain_deadline_counts_in_the_window() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let (sink, mut queue) = channel(10_000);
        for index in 0..10_000 {
            sink.push(padded(index, 0));
        }
        let mut writer = Writer::new(dir.path().join("d.ndjson"), NonZeroU64::MAX);
        let counters = SinkCounters::new();
        drain(&mut writer, &mut queue, &counters, Duration::ZERO).await;
        assert!(counters.take_window() > 0);
    }

    /// rl7, the write-error site: `/dev/full` opens and then refuses every write.
    #[tokio::test]
    async fn rl7_file_write_error_counts_in_the_window() {
        let mut writer = Writer::new(PathBuf::from("/dev/full"), NonZeroU64::MAX);
        let counters = SinkCounters::new();
        writer.append(summary(), &counters).await;
        assert_eq!(counters.take_window(), 1);
    }

    /// A decision whose serialized size is driven by `pad`, and whose `request_id` says
    /// which offer it was, so the file can be asked whether this record was written.
    fn padded(index: usize, pad: usize) -> Record {
        Record::RequestDecided(crate::delivery::Decision {
            timestamp: String::new(),
            request_id: index.to_string(),
            method: String::new(),
            ecosystem: "npm",
            package: String::new(),
            version: String::new(),
            status: 503,
            result: "POLICY_UNAVAILABLE",
            reason: "x".repeat(pad),
            blocklist_revision: 0,
            cache: "unattempted",
            duration_micros: 0,
            bytes: 0,
            consumer: None,
        })
    }

    /// A directory at `<path>.1` is what makes the rollover rename fail: a file cannot
    /// be renamed over a directory. Its absence lets the rename succeed again.
    fn set_rename_failing(rolled: &std::path::Path, failing: bool) {
        if failing {
            if rolled.is_file() {
                std::fs::remove_file(rolled).expect("the rolled generation is removed");
            }
            if !rolled.is_dir() {
                std::fs::create_dir(rolled).expect("a directory where `.1` would go");
            }
        } else if rolled.is_dir() {
            std::fs::remove_dir(rolled).expect("the blocking directory is removed");
        }
    }

    fn last_request_id(path: &std::path::Path) -> Option<String> {
        let text = std::fs::read_to_string(path).ok()?;
        let line = text.lines().last()?;
        let record: serde_json::Value = serde_json::from_str(line).ok()?;
        record["request_id"].as_str().map(str::to_owned)
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(64))]

        /// Finding 1: whatever the record sizes and however often the rollover rename
        /// fails, neither generation ever exceeds `max_bytes`, and every offered record
        /// is exactly one of written or counted as dropped.
        #[test]
        fn the_ceiling_holds_and_every_record_is_written_or_counted(
            max_bytes in 200u64..4_000,
            steps in proptest::collection::vec((0usize..2_500, proptest::bool::ANY), 1..40),
        ) {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("a runtime");
            runtime.block_on(async {
                let dir = tempfile::tempdir().expect("a temporary directory");
                let path = dir.path().join("d.ndjson");
                let rolled = dir.path().join("d.ndjson.1");
                let mut writer = Writer::new(path.clone(), NonZeroU64::new(max_bytes).unwrap());
                let counters = SinkCounters::new();
                let mut written = 0u64;

                for (index, &(pad, rename_fails)) in steps.iter().enumerate() {
                    set_rename_failing(&rolled, rename_fails);
                    let dropped_before = counters.total();
                    writer.append(padded(index, pad), &counters).await;

                    for generation in [&path, &rolled] {
                        if generation.is_file() {
                            let len = std::fs::metadata(generation).unwrap().len();
                            proptest::prop_assert!(
                                len <= max_bytes,
                                "{} is {len} bytes against a ceiling of {max_bytes}",
                                generation.display()
                            );
                        }
                    }
                    let landed = last_request_id(&path) == Some(index.to_string());
                    match (landed, counters.total() - dropped_before) {
                        (true, 0) => written += 1,
                        (false, 1) => {}
                        other => proptest::prop_assert!(
                            false,
                            "record {index} must be written or counted, exactly once: \
                             (written, counted) = {other:?}"
                        ),
                    }
                }
                proptest::prop_assert_eq!(written + counters.total(), steps.len() as u64);
                Ok(())
            })?;
        }
    }

    const PARTIAL_WRITE_PATH: &str = "PROBATION_PARTIAL_WRITE_PATH";

    /// Finding 2: a write that fails partway — the disk filling up mid-record — leaves
    /// the file exactly as it was, so the next record is not glued onto a torn
    /// fragment. `RLIMIT_FSIZE` is the one unprivileged way to make a regular file
    /// accept part of a write and refuse the rest, and it is per process, so the
    /// append runs in a child test binary under `prlimit`.
    #[test]
    fn a_failed_write_leaves_no_torn_fragment() {
        const LIMIT: usize = 1024;
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("d.ndjson");
        // One whole record, 64 bytes short of the limit: the next record crosses it.
        let head = r#"{"event":"request_decided","pad":""#;
        let tail = "\"}\n";
        let before = format!(
            "{head}{}{tail}",
            "x".repeat(LIMIT - 64 - head.len() - tail.len())
        );
        std::fs::write(&path, &before).expect("the earlier record is written");

        let child = std::process::Command::new("prlimit")
            .arg(format!("--fsize={LIMIT}:{LIMIT}"))
            .arg("--")
            .arg(std::env::current_exe().expect("this test binary"))
            .args([
                "--exact",
                "delivery::file::tests::partial_write_child",
                "--include-ignored",
                "--test-threads=1",
            ])
            .env(PARTIAL_WRITE_PATH, &path)
            // A coverage build writes a profile at exit, and under this limit it would
            // be truncated into one `llvm-profdata` refuses to merge.
            .env("LLVM_PROFILE_FILE", "/dev/null")
            // Piped, never inherited: the limit applies to every regular file the
            // child writes, and this process's stdout may be one.
            .output()
            .expect("prlimit runs");
        assert!(
            child.status.success(),
            "the child append ran: {}\n{}",
            child.status,
            String::from_utf8_lossy(&child.stdout)
        );

        assert_eq!(
            std::fs::read_to_string(&path).expect("the log file"),
            before,
            "a write that failed partway leaves no fragment behind"
        );
    }

    /// The child half of `a_failed_write_leaves_no_torn_fragment`.
    #[tokio::test]
    #[ignore = "run under prlimit by a_failed_write_leaves_no_torn_fragment"]
    async fn partial_write_child() {
        let Some(path) = std::env::var_os(PARTIAL_WRITE_PATH) else {
            return;
        };
        // SIGXFSZ's default action kills the process at the write that crosses the
        // limit. With a handler installed, the write returns `EFBIG` instead.
        let _sigxfsz = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::from_raw(25))
            .expect("a SIGXFSZ handler");
        let counters = SinkCounters::new();
        let mut writer = Writer::new(PathBuf::from(path), NonZeroU64::MAX);
        writer.append(padded(1, 400), &counters).await;
        assert_eq!(counters.total(), 1, "the failed write is counted");
    }

    /// The sink stops once every sender is gone, without a drain.
    #[tokio::test]
    async fn run_returns_when_its_queue_closes() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let (sink, queue) = channel(1);
        drop(sink);
        run(
            dir.path().join("d.ndjson"),
            NonZeroU64::MAX,
            queue,
            CancellationToken::new(),
            Arc::new(SinkCounters::new()),
        )
        .await;
    }

    /// rl7, the unopenable site.
    #[tokio::test]
    async fn rl7_file_unopenable_counts_in_the_window() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let mut writer = Writer::new(dir.path().join("missing/d.ndjson"), NonZeroU64::MAX);
        let counters = SinkCounters::new();
        writer.append(summary(), &counters).await;
        assert_eq!(counters.take_window(), 1);
    }
}
