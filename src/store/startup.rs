//! Opening and recovering the data directory (SPEC §10).
//!
//! Two failure classes, kept apart because the specification answers them
//! differently:
//!
//! * the directory cannot be created, or another instance holds its lock. Nothing
//!   about this instance is usable and nothing can be diagnosed from inside it, so
//!   `serve` reports it and exits.
//! * the database cannot be opened, is not in the mode this build requires, or
//!   carries another schema. SPEC §10: "If database recovery fails, keep readiness
//!   false and stop package delivery; never silently recreate the database". The
//!   process therefore starts, answers `/health/live`, refuses every package request
//!   and leaves the bytes on disk exactly as they were.
//!
//! Nothing in this file deletes, truncates or replaces a database file. The only
//! creation is `turso`'s own creation of a database that is not there at all, which
//! is a first start rather than a recreation.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use turso::Connection;

use crate::store::lock::{self, DataDirLock, LockError};
use crate::store::schema::{self, SchemaError};

/// The database file, under `state/` so an operator can back up one subdirectory
/// (SPEC §10: "the stopped service's complete `state/` directory").
const STATE_DIR: &str = "state";
const DATABASE_FILE: &str = "firewall.db";

/// What `open_and_recover` produces: the lock is held either way, so a database
/// this instance could not open cannot be opened by a second instance behind its
/// back either.
pub struct Opened {
    pub lock: DataDirLock,
    pub connection: Result<Connection, RecoveryError>,
}

/// Creates the data directory, takes its exclusive lock, opens the database, puts
/// it in the durability mode SPEC §10 requires, and verifies the schema row.
pub async fn open_and_recover(data_dir: &Path) -> Result<Opened, StartupError> {
    let state_dir = data_dir.join(STATE_DIR);
    std::fs::create_dir_all(&state_dir).map_err(|source| StartupError::Directory {
        path: state_dir.clone(),
        source,
    })?;

    let lock = lock::acquire(data_dir).map_err(StartupError::Lock)?;

    let connection = open_database(&state_dir.join(DATABASE_FILE)).await;
    if let Err(err) = &connection {
        tracing::error!(
            data_dir = %data_dir.display(),
            error = %err,
            "the database could not be recovered: readiness stays false and every package \
             request is refused; the database is left untouched"
        );
    }

    Ok(Opened { lock, connection })
}

/// Opens one connection and brings it to the state every later statement assumes.
///
/// The two pragmas are set **and read back**. Setting a pragma an engine does not
/// implement is silently harmless, which is the failure this build must not have:
/// SPEC §10 rests on WAL recovery and on a commit being durable before its snapshot
/// is published, and both are properties of the mode, not of the statement that
/// asked for it.
async fn open_database(path: &Path) -> Result<Connection, RecoveryError> {
    // A database that is absent or empty while its write-ahead log still holds frames
    // is damage, not a first start: a truncating copy, a half-restored backup, an
    // interrupted `cp`. Opening it lets the engine lay down a fresh database and
    // rewrite the log, which destroys committed state that was still salvageable —
    // one blocklist revision here, and first-seen times and permanent digest pins on
    // this same path once slices 5 and 7 write them. SPEC §10 forbids exactly that.
    //
    // An absent database with no log beside it is still an ordinary first start.
    let log = log_path(path);
    let log_bytes = std::fs::metadata(&log).map(|meta| meta.len()).unwrap_or(0);
    // An unreadable database counts as empty here: with a populated log beside it,
    // refusing is the answer either way.
    let database_bytes = std::fs::metadata(path).map(|meta| meta.len()).unwrap_or(0);
    if log_bytes > 0 && database_bytes == 0 {
        return Err(RecoveryError::OrphanedLog {
            database: path.to_path_buf(),
            log,
            log_bytes,
        });
    }

    let path_text = path
        .to_str()
        .ok_or_else(|| RecoveryError::Path(path.to_path_buf()))?;

    let database = turso::Builder::new_local(path_text)
        .build()
        .await
        .map_err(RecoveryError::Database)?;
    // Opening is where the engine replays a write-ahead log left by a process that
    // died before its pages reached the database file.
    let mut connection = database.connect().map_err(RecoveryError::Database)?;

    connection
        .pragma_update("journal_mode", "WAL")
        .await
        .map_err(RecoveryError::Database)?;
    let journal_mode = read_pragma(&connection, "journal_mode").await?;
    let journal_mode = journal_mode
        .as_text()
        .cloned()
        .unwrap_or_else(|| format!("{journal_mode:?}"));
    if !journal_mode.eq_ignore_ascii_case("wal") {
        return Err(RecoveryError::Pragma {
            pragma: "journal_mode",
            expected: "wal".to_owned(),
            found: journal_mode,
        });
    }

    connection
        .pragma_update("synchronous", "FULL")
        .await
        .map_err(RecoveryError::Database)?;
    let synchronous = read_pragma(&connection, "synchronous").await?;
    // The engine answers `PRAGMA synchronous` with the numeric mode, as SQLite does:
    // 0 off, 1 normal, 2 full.
    const SYNCHRONOUS_FULL: i64 = 2;
    if synchronous.as_integer().copied() != Some(SYNCHRONOUS_FULL) {
        return Err(RecoveryError::Pragma {
            pragma: "synchronous",
            expected: format!("{SYNCHRONOUS_FULL} (full)"),
            found: format!("{synchronous:?}"),
        });
    }

    schema::ensure(&mut connection)
        .await
        .map_err(RecoveryError::Schema)?;

    Ok(connection)
}

/// The engine's write-ahead log sits beside the database under the same name plus
/// `-wal`, so it is built by appending rather than by replacing an extension.
fn log_path(database: &Path) -> PathBuf {
    let mut name = database.as_os_str().to_owned();
    name.push("-wal");
    PathBuf::from(name)
}

async fn read_pragma(
    connection: &Connection,
    pragma: &'static str,
) -> Result<turso::Value, RecoveryError> {
    let mut value = None;
    connection
        .pragma_query(pragma, |row| {
            if value.is_none() {
                value = row.get_value(0).ok();
            }
            Ok(())
        })
        .await
        .map_err(RecoveryError::Database)?;

    value.ok_or(RecoveryError::Pragma {
        pragma,
        expected: "a value".to_owned(),
        found: "nothing".to_owned(),
    })
}

/// A failure that leaves nothing to run: `serve` reports it and exits.
#[derive(Debug)]
pub enum StartupError {
    Directory { path: PathBuf, source: io::Error },
    Lock(LockError),
}

impl fmt::Display for StartupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StartupError::Directory { path, source } => {
                write!(f, "cannot create {}: {source}", path.display())
            }
            StartupError::Lock(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for StartupError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            StartupError::Directory { source, .. } => Some(source),
            StartupError::Lock(err) => Some(err),
        }
    }
}

/// A failure that leaves the process running with readiness false and the database
/// on disk untouched.
#[derive(Debug)]
pub enum RecoveryError {
    Path(PathBuf),
    /// The database is gone or empty but its write-ahead log is not. Refusing keeps
    /// the log intact for an operator to salvage; opening would overwrite it.
    OrphanedLog {
        database: PathBuf,
        log: PathBuf,
        log_bytes: u64,
    },
    Database(turso::Error),
    Pragma {
        pragma: &'static str,
        expected: String,
        found: String,
    },
    Schema(SchemaError),
}

impl fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecoveryError::Path(path) => {
                write!(f, "the database path {} is not valid UTF-8", path.display())
            }
            RecoveryError::OrphanedLog {
                database,
                log,
                log_bytes,
            } => write!(
                f,
                "{} is missing or empty while its write-ahead log {} still holds {log_bytes} \
                 bytes; refusing to open, because opening would overwrite the log and lose \
                 what is still in it. Restore the pair together, or move both aside to start \
                 fresh deliberately",
                database.display(),
                log.display()
            ),
            RecoveryError::Database(err) => write!(f, "{err}"),
            RecoveryError::Pragma {
                pragma,
                expected,
                found,
            } => write!(f, "{pragma} is {found}, not {expected}"),
            RecoveryError::Schema(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for RecoveryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            RecoveryError::Database(err) => Some(err),
            RecoveryError::Schema(err) => Some(err),
            RecoveryError::Path(_)
            | RecoveryError::OrphanedLog { .. }
            | RecoveryError::Pragma { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The durability mode this whole design rests on, read back off the connection
    /// `open_and_recover` actually hands out.
    ///
    /// Without this, inverting either comparison in `open_database` leaves every
    /// other test green while the guarantee quietly disappears: a database opened in
    /// rollback-journal mode or at `synchronous=NORMAL` serves every request exactly
    /// as well, right up to the crash.
    #[tokio::test]
    async fn the_connection_is_in_wal_mode_at_synchronous_full() {
        let dir = tempfile::tempdir().expect("a temporary data directory");
        let opened = open_and_recover(dir.path())
            .await
            .expect("the data directory opens");
        let connection = opened.connection.expect("a fresh database recovers");

        let journal_mode = read_pragma(&connection, "journal_mode")
            .await
            .expect("journal_mode is readable");
        assert_eq!(
            journal_mode.as_text().map(String::as_str),
            Some("wal"),
            "recovery after a crash is a property of the mode, not of the statement \
             that asked for it"
        );

        let synchronous = read_pragma(&connection, "synchronous")
            .await
            .expect("synchronous is readable");
        assert_eq!(
            synchronous.as_integer().copied(),
            Some(2),
            "2 is FULL: a commit reaches the disk before it is reported committed, \
             which is what lets the poller publish only after committing"
        );
    }
}
