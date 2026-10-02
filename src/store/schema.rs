//! The schema: its DDL, its version, the engine version this build recorded, and
//! the startup refusal when the database on disk was written by a different schema.
//!
//! SPEC §10 requires a schema record carrying "schema version and the Turso
//! engine/crate version used by this build". The two are treated differently on
//! purpose:
//!
//! * a **schema version** mismatch is refused. This release cannot read another
//!   schema's rows, and SPEC §10 forbids recreating the database to get past that,
//!   so the only safe answer is to keep the bytes and report why the store is
//!   unusable.
//! * an **engine version** change is recorded and logged rather than refused. The
//!   pinned engine is pre-1.0 and will move; refusing to open a database after a
//!   dependency bump would turn every upgrade into an outage, while losing the note
//!   of which engine wrote the file would remove exactly the diagnosis SPEC §10 asks
//!   the record to keep.

use turso::Connection;

use std::fmt;

/// The version of the tables below. Slices that add tables bump it, and a database
/// written by a different version is refused rather than migrated: there is no
/// deployed database to migrate (SPEC §10), and the first release that needs one
/// will add a real migration step here.
pub const SCHEMA_VERSION: i64 = 4;

/// The `turso` release this build was compiled against, recorded so a diagnosis can
/// tell which engine wrote the file. Kept in step with `Cargo.toml` by
/// `recorded_engine_version_matches_the_pinned_dependency` below.
pub const TURSO_CRATE_VERSION: &str = "0.7.2";

/// Slice 3 persisted the schema row and the last accepted blocklist; slice 5 added
/// the project snapshot and the artifact reference; slice 7 adds the permanent
/// digest pins (SPEC §15, STATE-01) and the content table of SPEC §10; slice 15 adds
/// `projects.fetched_at_micros`.
///
/// `fetched_at_micros` is the last FULL fetch, which is the only age SPEC rev 3
/// §10's maximum-age ceiling reads. It is a column of its own rather than a reuse of
/// `validated_at_micros` because a `304` advances validation and must leave the full
/// fetch where it is — collapsing the two would delete the ceiling while leaving
/// every visible behaviour identical.
///
/// `artifact_references` rather than `references`, which is a reserved word.
/// `CHECK (length(filename) > 0)` is not decoration: a reference with no filename
/// cannot be served and must not be committed, and having the database say so is
/// what makes the project/reference transaction's rollback observable.
///
/// The pins are columns of the reference rather than of the content row on purpose:
/// SPEC §9 says eviction "removes bytes and their content mapping, not these pins",
/// so they must outlive every content row that ever described them.
const DDL: &str = "\
CREATE TABLE IF NOT EXISTS schema_meta (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    schema_version INTEGER NOT NULL,
    engine_version TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS blocklist (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    revision INTEGER NOT NULL,
    generated_at_micros INTEGER NOT NULL,
    expires_at_micros INTEGER NOT NULL,
    snapshot BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS projects (
    ecosystem TEXT NOT NULL,
    name TEXT NOT NULL,
    payload BLOB NOT NULL,
    etag TEXT,
    last_modified TEXT,
    validated_at_micros INTEGER NOT NULL,
    fetched_at_micros INTEGER NOT NULL,
    generation INTEGER NOT NULL,
    digest_generation INTEGER NOT NULL,
    PRIMARY KEY (ecosystem, name)
);
CREATE TABLE IF NOT EXISTS artifact_references (
    id BLOB PRIMARY KEY,
    ecosystem TEXT NOT NULL,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    filename TEXT NOT NULL CHECK (length(filename) > 0),
    upstream_url TEXT NOT NULL,
    expected TEXT NOT NULL,
    publication_micros INTEGER,
    first_seen_micros INTEGER,
    pinned_sha256 BLOB,
    pinned_sha512 BLOB,
    pinned_size INTEGER,
    content_key BLOB
);
CREATE INDEX IF NOT EXISTS artifact_references_by_project
    ON artifact_references (ecosystem, name);
CREATE TABLE IF NOT EXISTS content (
    key BLOB PRIMARY KEY,
    sha512 BLOB NOT NULL,
    size INTEGER NOT NULL,
    created_micros INTEGER NOT NULL,
    accessed_micros INTEGER NOT NULL
);
";

/// Creates the tables if they are absent and checks the recorded schema version.
///
/// Everything happens in one transaction, so a crash here leaves either the schema
/// this build expects or nothing at all — never half of it.
pub async fn ensure(connection: &mut Connection) -> Result<(), SchemaError> {
    let transaction = connection
        .transaction()
        .await
        .map_err(SchemaError::Database)?;

    // `execute_batch` is not available on a transaction, so the statements are
    // issued one at a time inside it.
    for statement in DDL.split_inclusive(';').filter(|s| !s.trim().is_empty()) {
        transaction
            .execute(statement, ())
            .await
            .map_err(SchemaError::Database)?;
    }

    let mut rows = transaction
        .query(
            "SELECT schema_version, engine_version FROM schema_meta WHERE id = 1",
            (),
        )
        .await
        .map_err(SchemaError::Database)?;

    let recorded = match rows.next().await.map_err(SchemaError::Database)? {
        Some(row) => {
            let version = row
                .get_value(0)
                .ok()
                .and_then(|value| value.as_integer().copied())
                .ok_or_else(|| SchemaError::Corrupt("schema_meta.schema_version".to_owned()))?;
            let engine = row
                .get_value(1)
                .ok()
                .and_then(|value| value.as_text().cloned())
                .ok_or_else(|| SchemaError::Corrupt("schema_meta.engine_version".to_owned()))?;
            Some((version, engine))
        }
        None => None,
    };
    drop(rows);

    match recorded {
        // A database this build did not write. Refuse, and change nothing: the
        // transaction is rolled back on the way out.
        Some((version, _)) if version != SCHEMA_VERSION => {
            return Err(SchemaError::Mismatch {
                found: version,
                expected: SCHEMA_VERSION,
            });
        }
        Some((_, engine)) if engine != TURSO_CRATE_VERSION => {
            tracing::warn!(
                previous = %engine,
                current = TURSO_CRATE_VERSION,
                "the database was written by a different engine release; recording the current one"
            );
            transaction
                .execute(
                    "UPDATE schema_meta SET engine_version = ?1 WHERE id = 1",
                    (TURSO_CRATE_VERSION,),
                )
                .await
                .map_err(SchemaError::Database)?;
        }
        Some(_) => {}
        None => {
            transaction
                .execute(
                    "INSERT INTO schema_meta (id, schema_version, engine_version) VALUES (1, ?1, ?2)",
                    (SCHEMA_VERSION, TURSO_CRATE_VERSION),
                )
                .await
                .map_err(SchemaError::Database)?;
        }
    }

    transaction.commit().await.map_err(SchemaError::Database)
}

#[derive(Debug)]
pub enum SchemaError {
    Database(turso::Error),
    /// The database on disk carries another schema version. It is left exactly as it
    /// is: SPEC §10 forbids recreating it, because that would lose first-seen times,
    /// digest pins and the blocklist revision.
    Mismatch {
        found: i64,
        expected: i64,
    },
    /// The schema row exists but a column does not hold what this build wrote.
    Corrupt(String),
}

impl fmt::Display for SchemaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SchemaError::Database(err) => write!(f, "{err}"),
            SchemaError::Mismatch { found, expected } => write!(
                f,
                "the database carries schema version {found}, this build understands {expected}; \
                 it is left untouched"
            ),
            SchemaError::Corrupt(column) => write!(f, "unreadable {column}"),
        }
    }
}

impl std::error::Error for SchemaError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SchemaError::Database(err) => Some(err),
            SchemaError::Mismatch { .. } | SchemaError::Corrupt(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn open(path: &std::path::Path) -> Connection {
        turso::Builder::new_local(path.to_str().expect("a UTF-8 path"))
            .build()
            .await
            .expect("the database opens")
            .connect()
            .expect("a connection")
    }

    /// The refusal SPEC §10 requires: a database written by another schema is
    /// reported, and it is left exactly as it was rather than recreated.
    #[tokio::test]
    async fn another_schema_version_is_refused_and_the_rows_are_left_alone() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("firewall.db");

        let mut connection = open(&path).await;
        ensure(&mut connection).await.expect("the first open");
        connection
            .execute(
                "INSERT INTO blocklist (id, revision, generated_at_micros, expires_at_micros, snapshot) \
                 VALUES (1, 42, 1, 2, ?1)",
                (vec![7u8, 8, 9],),
            )
            .await
            .expect("a row that must survive the refusal");
        connection
            .execute(
                "UPDATE schema_meta SET schema_version = 999 WHERE id = 1",
                (),
            )
            .await
            .expect("the schema row is aged by hand");

        let refused = ensure(&mut connection).await;
        assert!(
            matches!(
                refused,
                Err(SchemaError::Mismatch {
                    found: 999,
                    expected: SCHEMA_VERSION
                })
            ),
            "a database this build does not understand is refused: {refused:?}"
        );

        let mut rows = connection
            .query("SELECT schema_version FROM schema_meta WHERE id = 1", ())
            .await
            .expect("the schema row is still there");
        let row = rows.next().await.expect("a row").expect("exactly one row");
        assert_eq!(
            row.get_value(0).expect("a value").as_integer().copied(),
            Some(999),
            "the refusal changed nothing: the recorded version is still the one on disk"
        );

        let mut rows = connection
            .query("SELECT revision FROM blocklist WHERE id = 1", ())
            .await
            .expect("the blocklist row is still there");
        let row = rows.next().await.expect("a row").expect("exactly one row");
        assert_eq!(
            row.get_value(0).expect("a value").as_integer().copied(),
            Some(42),
            "and the records the refusal exists to protect are untouched"
        );
    }

    /// A different engine release is a note to record, not an outage: the pinned
    /// engine is pre-1.0 and will move.
    #[tokio::test]
    async fn another_engine_version_is_recorded_rather_than_refused() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("firewall.db");

        let mut connection = open(&path).await;
        ensure(&mut connection).await.expect("the first open");
        connection
            .execute(
                "UPDATE schema_meta SET engine_version = '0.0.0-previous' WHERE id = 1",
                (),
            )
            .await
            .expect("the engine version is aged by hand");

        ensure(&mut connection)
            .await
            .expect("a different engine release still opens");

        let mut rows = connection
            .query("SELECT engine_version FROM schema_meta WHERE id = 1", ())
            .await
            .expect("the schema row");
        let row = rows.next().await.expect("a row").expect("exactly one row");
        assert_eq!(
            row.get_value(0).expect("a value").as_text().cloned(),
            Some(TURSO_CRATE_VERSION.to_owned()),
            "the engine that opened it is what the record now names"
        );
    }

    /// The recorded engine version is a hand-written constant, so it can drift from
    /// the dependency it claims to describe. It cannot drift silently.
    #[test]
    fn recorded_engine_version_matches_the_pinned_dependency() {
        let manifest = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
            .expect("the manifest is readable");
        let declared = manifest
            .lines()
            .find_map(|line| line.strip_prefix("turso = "))
            .expect("Cargo.toml declares turso")
            .trim()
            .trim_matches('"')
            .to_owned();

        assert_eq!(
            declared, TURSO_CRATE_VERSION,
            "TURSO_CRATE_VERSION is recorded in every database this build writes and must \
             name the dependency actually compiled in"
        );
    }
}
