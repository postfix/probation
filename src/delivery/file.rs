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
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::Record;
use super::counters::SinkCounters;

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
    mut rx: mpsc::Receiver<Record>,
    drain: CancellationToken,
    counters: Arc<SinkCounters>,
) {
    let mut writer = Writer::new(path, max_bytes);

    loop {
        tokio::select! {
            received = rx.recv() => match received {
                Some(record) => writer.append(record, &counters).await,
                None => break,
            },
            () = drain.cancelled() => {
                self::drain(&mut writer, &mut rx, &counters, DRAIN_DEADLINE).await;
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
    rx: &mut mpsc::Receiver<Record>,
    counters: &SinkCounters,
    deadline: Duration,
) {
    let drained = tokio::time::timeout(deadline, async {
        while let Ok(record) = rx.try_recv() {
            writer.append(record, counters).await;
        }
    })
    .await;
    if drained.is_err() {
        counters.lose(rx.len() as u64 + 1);
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
}

impl Writer {
    fn new(path: PathBuf, max_bytes: NonZeroU64) -> Writer {
        Writer {
            path,
            max_bytes: max_bytes.get(),
            file: None,
            written: 0,
            warned: false,
        }
    }

    async fn append(&mut self, record: Record, counters: &SinkCounters) {
        let Ok(mut line) = serde_json::to_string(&record) else {
            counters.lose(1);
            return;
        };
        line.push('\n');
        let cost = line.len() as u64;

        // Open first: the tally is restored from the file's own length, and until
        // that has happened there is nothing truthful to compare the threshold
        // against. Deciding before it is what lets the first record after a restart
        // land on top of a file that is already at the cap.
        if !self.open(counters).await {
            return;
        }
        if self.written.saturating_add(cost) >= self.max_bytes {
            self.roll_over().await;
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
    /// `max_bytes`.
    async fn roll_over(&mut self) {
        self.file = None;
        // Pushed onto the `OsString` rather than formatted through a `str`, so a
        // path this process cannot decode still rolls over.
        let mut rolled = self.path.clone().into_os_string();
        rolled.push(".1");
        if let Err(err) = tokio::fs::rename(&self.path, PathBuf::from(rolled)).await {
            tracing::warn!(
                path = %self.path.display(),
                error = %err,
                "the decision log file could not be rolled over"
            );
        }
        self.written = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delivery::Summary;

    #[tokio::test]
    async fn tp19_file_drain_deadline_counts_cut_off_records() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("decisions.ndjson");
        // Enough records that the zero deadline, which fires at tokio's next millisecond
        // tick, cuts the drain off partway; about 8 fit in that tick here.
        const QUEUED: u64 = 10_000;
        let (tx, mut rx) = mpsc::channel(QUEUED as usize);
        for _ in 0..QUEUED {
            tx.try_send(Record::RequestSummary(Summary {
                timestamp: String::new(),
                requests: 0,
                errors: 0,
                bytes: 0,
                mean_duration_micros: 0,
                window_micros: 0,
                dropped_file: 0,
                dropped_siem: 0,
            }))
            .expect("the channel has room");
        }
        let mut writer = Writer::new(path.clone(), NonZeroU64::MAX);
        let counters = SinkCounters::new();

        drain(&mut writer, &mut rx, &counters, Duration::ZERO).await;

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
        let (tx, mut rx) = mpsc::channel(10_000);
        for _ in 0..10_000 {
            tx.try_send(summary()).expect("the channel has room");
        }
        let mut writer = Writer::new(dir.path().join("d.ndjson"), NonZeroU64::MAX);
        let counters = SinkCounters::new();
        drain(&mut writer, &mut rx, &counters, Duration::ZERO).await;
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
