//! SPEC §8's reload procedure: change detection, a capped read, whole-candidate
//! validation off the request path, the revision and window rules, the commit, and
//! only then the atomic publish.
//!
//! The order at the end of [`poll_once`] is the load-bearing part. SPEC §10 says
//! "Persist a new blocklist before publishing its memory snapshot", so a commit that
//! fails must leave the previous snapshot in force — including the case where there
//! is no previous snapshot and the answer to every request stays `503`. Publishing
//! first would make a block enforceable that a restart would then silently forget.

use std::io;
use std::panic::AssertUnwindSafe;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::FutureExt;
use tokio::io::AsyncReadExt;
use tokio_util::sync::CancellationToken;

use crate::App;
use crate::policy::blocklist::{self, Replacement};
use crate::policy::{BlocklistError, BlocklistSnapshot};

/// How long the metadata check may keep saying "unchanged" before the file is read
/// anyway.
///
/// SPEC §8 requires the producer to replace the file atomically, and an atomic
/// replacement is a rename, so it always changes the inode — which is why the
/// identity below carries one (TM-5). A producer that rewrites the file in place
/// instead is out of contract, and this bound is how long such a write can go
/// unnoticed. It is measured on the injected clock's monotonic reading, so it is the
/// same sixty seconds in a test as in production.
pub const BACKSTOP_REREAD: Duration = Duration::from_secs(60);

/// Runs the poll loop until `shutdown` is cancelled.
pub async fn run(app: Arc<App>, shutdown: CancellationToken, mut watcher: Watcher) {
    let interval = Duration::from_secs(app.config.blocklist_poll_seconds.get());

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = tokio::time::sleep(interval) => {}
        }

        // A pass that panics is reported, and the next interval polls again. Exiting
        // would turn whatever made it panic — possibly the bytes of the file itself —
        // into a crash loop; letting this task end would stop blocklist updates
        // silently while the snapshot in force ran out.
        let pass = AssertUnwindSafe(poll_once(&app, &mut watcher)).catch_unwind();
        if let Err(panic) = pass.await {
            let message = panic
                .downcast_ref::<&str>()
                .copied()
                .or_else(|| panic.downcast_ref::<String>().map(String::as_str))
                .unwrap_or("a non-string panic payload");
            tracing::error!(
                path = %app.config.blocklist_file.display(),
                panic = message,
                "a blocklist poll pass panicked; the last accepted snapshot stays in force \
                 and polling continues"
            );
            // The pass may have recorded the file as seen before it panicked.
            watcher.retry();
        }
    }
}

/// Everything the poller remembers between passes.
#[derive(Default)]
pub struct Watcher {
    seen: Option<FileIdentity>,
    last_full_read: Option<Instant>,
}

impl Watcher {
    pub fn new() -> Watcher {
        Watcher::default()
    }

    /// Forgets the file's identity so the next pass reads it again even though
    /// nothing about the file has changed.
    ///
    /// The metadata check exists to avoid re-reading bytes whose answer cannot have
    /// changed. When the answer *can* change on its own — storage recovering, a clock
    /// catching up — that reasoning no longer holds, and leaving the identity in place
    /// would hide the file until it is rewritten or the backstop fires a minute later.
    fn retry(&mut self) {
        self.seen = None;
    }

    fn retry_if(&mut self, retry: Retry) {
        if retry == Retry::Later {
            self.retry();
        }
    }
}

/// Whether a refused candidate is worth reading again while the file is unchanged.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Retry {
    /// What refused it can change without the file changing.
    Later,
    /// Only a different file can change this answer, so re-reading it every interval
    /// would do nothing but repeat the same log line.
    NotUntilItChanges,
}

/// One pass of SPEC §8's reload procedure.
///
/// Called once by `App::start` before the listener accepts anything, so a server
/// that has a valid blocklist file is ready on its first request rather than one
/// poll interval later, and then on every interval by [`run`].
pub async fn poll_once(app: &App, watcher: &mut Watcher) {
    let path = app.config.blocklist_file.as_path();
    let now_monotonic = app.clock.now_monotonic();

    let identity = match FileIdentity::of(path).await {
        Ok(identity) => Some(identity),
        Err(err) => {
            tracing::error!(
                path = %path.display(),
                error = %err,
                "the blocklist file cannot be examined; the last accepted snapshot stays in force"
            );
            None
        }
    };

    let unchanged = identity.is_some() && identity == watcher.seen;
    let backstop_due = watcher
        .last_full_read
        .is_none_or(|last| now_monotonic.saturating_duration_since(last) >= BACKSTOP_REREAD);
    if unchanged && !backstop_due {
        return;
    }

    let bytes = match read_capped(path, app.config.max_blocklist_bytes.get()).await {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            tracing::error!(
                path = %path.display(),
                limit = app.config.max_blocklist_bytes.get(),
                "the blocklist file is larger than max_blocklist_bytes; the last accepted \
                 snapshot stays in force"
            );
            return;
        }
        Err(err) => {
            tracing::error!(
                path = %path.display(),
                error = %err,
                "the blocklist file cannot be read; the last accepted snapshot stays in force"
            );
            return;
        }
    };

    // The file was read, so the next pass can trust its metadata again and the
    // backstop clock restarts — whatever the candidate turns out to be worth.
    watcher.seen = identity;
    watcher.last_full_read = Some(now_monotonic);

    let accepted = app.blocklist();
    if accepted
        .as_ref()
        .is_some_and(|snapshot| snapshot.raw.as_ref() == bytes.as_slice())
    {
        // Byte-identical to what is already in force: nothing to validate and
        // nothing to commit. Comparing the accepted snapshot's own bytes is what
        // SPEC §8's "identical revision/content is a no-op" costs here.
        return;
    }

    let now = app.clock.now_utc_micros();
    // Parsing up to `max_blocklist_bytes` of JSON is CPU work, so it runs off the
    // runtime's workers, as the file I/O above does. A panic inside it is re-raised
    // here, where `run` reports it.
    let parsed =
        tokio::task::spawn_blocking(move || BlocklistSnapshot::parse_and_validate(&bytes, now))
            .await
            .unwrap_or_else(|join| std::panic::resume_unwind(join.into_panic()));
    let candidate = match parsed {
        Ok(candidate) => candidate,
        Err(err) => {
            watcher.retry_if(reject(path, &err));
            return;
        }
    };
    match blocklist::check_replacement(accepted.as_deref(), &candidate) {
        Ok(Replacement::Accept) => {}
        Ok(Replacement::NoOp) => return,
        Err(err) => {
            watcher.retry_if(reject(path, &err));
            return;
        }
    }

    let candidate = Arc::new(candidate);
    let revision = candidate.revision;
    let entries = candidate.entry_count();

    // Commit, then publish. Never the other way round, and never both under one
    // "best effort": a commit that fails leaves the previous snapshot in force.
    if let Err(err) = app.store().commit_blocklist(Arc::clone(&candidate)).await {
        tracing::error!(
            path = %path.display(),
            revision,
            error = %err,
            "the accepted blocklist could not be persisted, so it is not published; the \
             previous snapshot stays in force"
        );
        // The document was accepted; only storage refused it, and storage recovers
        // (SPEC §10: `503` "until storage is usable again"). Without this the next
        // pass would see an unchanged file and skip it, so a momentary write failure
        // would drop an accepted blocklist until the file changed or the sixty-second
        // backstop fired — well past the two intervals SPEC §12 allows.
        watcher.retry();
        return;
    }

    app.publish_blocklist(candidate);
    tracing::info!(
        path = %path.display(),
        revision,
        entries,
        "blocklist accepted, committed and published"
    );
}

/// The one rejection reason that is a statement about *time* rather than about the
/// document: the producer's clock is ahead of this host's, so bytes refused now are
/// the same bytes that will be accepted shortly, with nothing touching the file.
///
/// Matched by its message because `BlocklistError::Window` carries no code of its
/// own and `src/policy/blocklist.rs` is not this slice's to change. If that message
/// is ever reworded the match stops hitting, which costs a retry rather than granting
/// one — and `blocklist_reload::a_window_rejection_is_retried_when_the_file_has_not_changed`
/// fails the moment it drifts.
const RETRYABLE_WINDOW_REASON: &str = "generated_at is in the future";

/// Logs a refused candidate and says whether the same bytes are worth re-reading.
fn reject(path: &Path, err: &BlocklistError) -> Retry {
    // Every other refusal is structural — malformed JSON, an unsupported schema, an
    // unparseable timestamp, a revision that is not newer. Re-reading those every
    // interval would repeat one log line forever and never change the answer. An
    // expired window is refused permanently for the same reason: it only gets older.
    let retry = match err {
        BlocklistError::Window { reason } if *reason == RETRYABLE_WINDOW_REASON => Retry::Later,
        _ => Retry::NotUntilItChanges,
    };

    // SPEC §8: a rejected candidate leaves the previous snapshot in place and logs
    // the error. It never substitutes an empty blocklist.
    tracing::error!(
        path = %path.display(),
        error = %err,
        retry = ?retry,
        "the blocklist candidate was rejected; the last accepted snapshot stays in force"
    );
    retry
}

/// Reads at most `max_bytes`, answering `Ok(None)` when the file is larger. The cap
/// is applied to the read itself, so an oversized file is never buffered whole.
async fn read_capped(path: &Path, max_bytes: u64) -> io::Result<Option<Vec<u8>>> {
    let file = tokio::fs::File::open(path).await?;
    let mut bytes = Vec::new();
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .await?;
    if bytes.len() as u64 > max_bytes {
        return Ok(None);
    }
    Ok(Some(bytes))
}

/// What the poller compares to decide whether the file changed (TM-5).
///
/// The inode is the part that matters: SPEC §8 requires an atomic replacement, an
/// atomic replacement is a rename, and a rename always produces a different inode
/// even when the replacement happens in the same second and has exactly the same
/// length.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct FileIdentity {
    device: u64,
    inode: u64,
    modified_nanos: i128,
    len: u64,
}

impl FileIdentity {
    #[cfg(unix)]
    async fn of(path: &Path) -> io::Result<FileIdentity> {
        use std::os::unix::fs::MetadataExt;

        let metadata = tokio::fs::metadata(path).await?;
        Ok(FileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
            modified_nanos: i128::from(metadata.mtime()) * 1_000_000_000
                + i128::from(metadata.mtime_nsec()),
            len: metadata.len(),
        })
    }

    /// Everywhere else there is no inode to consult, so only the backstop re-read
    /// bounds how long a same-length same-instant replacement can hide. The service
    /// ships as a Linux container; this arm exists so the crate still builds and is
    /// honest about being weaker.
    #[cfg(not(unix))]
    async fn of(path: &Path) -> io::Result<FileIdentity> {
        let metadata = tokio::fs::metadata(path).await?;
        let modified_nanos = metadata
            .modified()?
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| since.as_nanos() as i128)
            .unwrap_or(0);
        Ok(FileIdentity {
            device: 0,
            inode: 0,
            modified_nanos,
            len: metadata.len(),
        })
    }
}
