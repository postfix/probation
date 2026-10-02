//! Row types and their column mappings.
//!
//! One type per persisted record of SPEC §10. Slice 3 persisted the blocklist; slice
//! 5 adds the project snapshot and the artifact reference, which is what makes a
//! first-seen time durable; slice 7 adds the permanent digest pins and the content
//! mapping.
//!
//! [`ReferenceId`] and [`ArtifactReference`] were built here, because slice 5 needed
//! them before `src/artifacts/` existed. They now live in
//! [`crate::artifacts::reference`] and are re-exported from here, so every call site
//! that learned the old path keeps working.

use std::sync::Arc;

use turso::Row;
use url::Url;

use crate::artifacts::content::ContentKey;
use crate::policy::{Digest, Ecosystem, HashAlgorithm, PublicationTime};
use crate::store::StoreError;
use crate::upstream::UpstreamValidators;

pub use crate::artifacts::reference::{ArtifactReference, InvalidReferenceId, ReferenceId};

/// The last accepted blocklist, as SPEC §10 requires it: revision, window, and the
/// complete validated snapshot exactly as it was accepted.
///
/// The snapshot is stored as the bytes that were validated rather than as a
/// re-serialisation of the parsed form, so a restart re-validates the same document
/// the producer wrote and the changed-content-at-the-same-revision rule keeps
/// working across a restart.
#[derive(Clone, Debug)]
pub struct BlocklistRow {
    pub revision: u64,
    pub generated_at_micros: i64,
    pub expires_at_micros: i64,
    pub snapshot: Arc<[u8]>,
}

impl BlocklistRow {
    /// Columns in the order `SELECT_BLOCKLIST` asks for them.
    pub(crate) fn from_row(row: &Row) -> Result<BlocklistRow, StoreError> {
        let revision = integer(row, 0, "blocklist.revision")?;
        let revision = u64::try_from(revision).map_err(|_| {
            StoreError::Corrupt(format!("blocklist.revision is negative: {revision}"))
        })?;

        Ok(BlocklistRow {
            revision,
            generated_at_micros: integer(row, 1, "blocklist.generated_at_micros")?,
            expires_at_micros: integer(row, 2, "blocklist.expires_at_micros")?,
            snapshot: blob(row, 3, "blocklist.snapshot")?,
        })
    }
}

/// How many times this project's snapshot has been replaced. SPEC §10 makes it one
/// of the five conditions a rendered response is reusable under.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct Generation(pub u64);

/// The stored project snapshot: the exact upstream payload plus what is needed to
/// decide whether it is still fresh and whether anything rendered from it still is.
#[derive(Clone, Debug)]
pub struct ProjectRow {
    pub ecosystem: Ecosystem,
    pub name: String,
    /// Exact upstream bytes. Filtering re-parses these; nothing re-serialises them.
    pub payload: Arc<[u8]>,
    /// Never forwarded downstream (SPEC §10) — kept only for the conditional
    /// request that revalidates this snapshot.
    pub validators: UpstreamValidators,
    pub validated_at_micros: i64,
    /// When this snapshot's payload was last fetched IN FULL. A `304` advances
    /// `validated_at_micros` and carries this one forward unchanged, which is what
    /// makes SPEC rev 3 §10's maximum-age ceiling a bound on the copy's real age
    /// rather than on how recently upstream was asked about it.
    pub fetched_at_micros: i64,
    pub generation: Generation,
    /// Bumped when a download teaches us a digest upstream never advertised, which
    /// invalidates every response rendered from this project (SPEC §9). Slice 5
    /// only ever reads it; the artifact slice is what raises it.
    pub digest_generation: u64,
}

impl ProjectRow {
    /// Columns in the order `SELECT_PROJECT` asks for them.
    pub(crate) fn from_row(row: &Row) -> Result<ProjectRow, StoreError> {
        let ecosystem = text(row, 0, "projects.ecosystem")?;
        let ecosystem = Ecosystem::from_tag(&ecosystem)
            .ok_or_else(|| StoreError::Corrupt(format!("unknown ecosystem `{ecosystem}`")))?;

        Ok(ProjectRow {
            ecosystem,
            name: text(row, 1, "projects.name")?,
            payload: blob(row, 2, "projects.payload")?,
            validators: UpstreamValidators {
                etag: optional_text(row, 3),
                last_modified: optional_text(row, 4),
            },
            validated_at_micros: integer(row, 5, "projects.validated_at_micros")?,
            fetched_at_micros: integer(row, 6, "projects.fetched_at_micros")?,
            generation: Generation(unsigned(row, 7, "projects.generation")?),
            digest_generation: unsigned(row, 8, "projects.digest_generation")?,
        })
    }
}

/// The stored reference. `publication_micros` and `first_seen_micros` are kept
/// apart, never collapsed on write, because SPEC §5 says upstream wins as soon as it
/// appears and that decision has to be re-made on every read.
///
/// The three pinned fields are SPEC §15's STATE-01: once the first complete,
/// integrity-verified download has written them they are permanent, survive eviction
/// of the bytes they describe, and every later download of this reference must match
/// them.
#[derive(Clone, Debug)]
pub struct ReferenceRow {
    pub id: ReferenceId,
    pub reference: ArtifactReference,
    pub publication_micros: Option<i64>,
    pub first_seen_micros: Option<i64>,
    pub pinned_sha256: Option<[u8; 32]>,
    pub pinned_sha512: Option<[u8; 64]>,
    pub pinned_size: Option<u64>,
    /// The verified bytes currently in the content cache, when there are any.
    /// Cleared by eviction and by a missing or wrong-sized file; the pins above are
    /// not.
    pub content_key: Option<ContentKey>,
}

impl ReferenceRow {
    /// The digests this instance computed itself, in the shape `policy::evaluate`
    /// takes them. A block on one of these denies bytes upstream never described
    /// (SPEC §9).
    pub fn pinned_digests(&self) -> Vec<Digest> {
        let mut digests = Vec::with_capacity(2);
        if let Some(sha256) = self.pinned_sha256 {
            digests.push(Digest {
                algorithm: HashAlgorithm::Sha256,
                bytes: Box::from(sha256.as_slice()),
            });
        }
        if let Some(sha512) = self.pinned_sha512 {
            digests.push(Digest {
                algorithm: HashAlgorithm::Sha512,
                bytes: Box::from(sha512.as_slice()),
            });
        }
        digests
    }

    /// SPEC §5: "If a valid upstream timestamp later appears, use it." A malformed
    /// upstream value is not stored at all — `npm::document` turns it into
    /// [`PublicationTime::Malformed`] before it ever reaches a row — so a row with
    /// neither field is the `Unknown` case, which is never eligible.
    pub fn publication_time(&self) -> PublicationTime {
        match (self.publication_micros, self.first_seen_micros) {
            (Some(micros), _) => PublicationTime::Upstream(micros),
            (None, Some(micros)) => PublicationTime::FirstSeen(micros),
            (None, None) => PublicationTime::Unknown,
        }
    }

    /// Columns in the order `SELECT_REFERENCE` asks for them.
    pub(crate) fn from_row(row: &Row) -> Result<ReferenceRow, StoreError> {
        let id = blob(row, 0, "artifact_references.id")?;
        let id: [u8; 32] = id.as_ref().try_into().map_err(|_| {
            StoreError::Corrupt("artifact_references.id is not 32 bytes".to_owned())
        })?;

        let ecosystem = text(row, 1, "artifact_references.ecosystem")?;
        let ecosystem = Ecosystem::from_tag(&ecosystem)
            .ok_or_else(|| StoreError::Corrupt(format!("unknown ecosystem `{ecosystem}`")))?;
        let upstream_url = text(row, 5, "artifact_references.upstream_url")?;
        let upstream_url = Url::parse(&upstream_url).map_err(|err| {
            StoreError::Corrupt(format!("artifact_references.upstream_url: {err}"))
        })?;

        Ok(ReferenceRow {
            id: ReferenceId::from_bytes(id),
            reference: ArtifactReference {
                ecosystem,
                name: text(row, 2, "artifact_references.name")?,
                version: text(row, 3, "artifact_references.version")?,
                filename: text(row, 4, "artifact_references.filename")?,
                upstream_url,
                expected: decode_digests(&text(row, 6, "artifact_references.expected")?)?,
            },
            publication_micros: optional_integer(row, 7),
            first_seen_micros: optional_integer(row, 8),
            pinned_sha256: optional_digest(row, 9, "artifact_references.pinned_sha256")?,
            pinned_sha512: optional_digest(row, 10, "artifact_references.pinned_sha512")?,
            pinned_size: optional_integer(row, 11)
                .map(|size| {
                    u64::try_from(size).map_err(|_| {
                        StoreError::Corrupt(format!(
                            "artifact_references.pinned_size is negative: {size}"
                        ))
                    })
                })
                .transpose()?,
            content_key: optional_digest::<32>(row, 12, "artifact_references.content_key")?
                .map(ContentKey::from_sha256),
        })
    }
}

/// A fixed-length digest column that may be absent. A present column of the wrong
/// length is corruption, never something to pad or truncate into shape.
fn optional_digest<const N: usize>(
    row: &Row,
    index: usize,
    column: &'static str,
) -> Result<Option<[u8; N]>, StoreError> {
    let Some(bytes) = row
        .get_value(index)
        .ok()
        .and_then(|value| value.as_blob().cloned())
    else {
        return Ok(None);
    };
    <[u8; N]>::try_from(bytes.as_slice())
        .map(Some)
        .map_err(|_| StoreError::Corrupt(format!("{column} is not {N} bytes")))
}

/// One project's whole refresh: the snapshot, every reference it advertises, and the
/// first-seen times for the references that have no upstream timestamp. SPEC §10
/// commits all three together, before the new generation is published.
#[derive(Clone, Debug)]
pub struct ProjectRefresh {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub payload: Arc<[u8]>,
    pub validators: UpstreamValidators,
    pub validated_at_micros: i64,
    /// The last FULL fetch. A `200` sets it to `now`; a `304` passes the stored
    /// value straight back in, which is the whole of SPEC rev 3 §10's ceiling.
    pub fetched_at_micros: i64,
    pub references: Vec<ReferenceUpsert>,
}

#[derive(Clone, Debug)]
pub struct ReferenceUpsert {
    pub id: ReferenceId,
    pub reference: ArtifactReference,
    pub publication_micros: Option<i64>,
    /// The `now` this refresh would record if this reference has no upstream time
    /// and no committed first-seen yet. An existing value is never overwritten.
    pub first_seen_micros: Option<i64>,
}

/// `<algorithm>-<hex>`, space separated, so a stored reference reads the same way it
/// prints in a log line.
pub(crate) fn encode_digests(digests: &[Digest]) -> String {
    digests
        .iter()
        .map(|digest| digest.to_string())
        .collect::<Vec<_>>()
        .join(" ")
}

pub(crate) fn decode_digests(text: &str) -> Result<Vec<Digest>, StoreError> {
    text.split_whitespace()
        .map(|entry| {
            let (name, hex_text) = entry.split_once('-').ok_or_else(|| {
                StoreError::Corrupt(format!("`{entry}` is not an `<algorithm>-<hex>` digest"))
            })?;
            let algorithm = HashAlgorithm::from_name(name).ok_or_else(|| {
                StoreError::Corrupt(format!("unknown stored hash algorithm `{name}`"))
            })?;
            Digest::parse_hex(algorithm, hex_text)
                .map_err(|err| StoreError::Corrupt(format!("stored digest: {err}")))
        })
        .collect()
}

fn integer(row: &Row, index: usize, column: &'static str) -> Result<i64, StoreError> {
    optional_integer(row, index)
        .ok_or_else(|| StoreError::Corrupt(format!("{column} is not an integer")))
}

fn optional_integer(row: &Row, index: usize) -> Option<i64> {
    row.get_value(index)
        .ok()
        .and_then(|value| value.as_integer().copied())
}

fn unsigned(row: &Row, index: usize, column: &'static str) -> Result<u64, StoreError> {
    let value = integer(row, index, column)?;
    u64::try_from(value).map_err(|_| StoreError::Corrupt(format!("{column} is negative: {value}")))
}

fn text(row: &Row, index: usize, column: &'static str) -> Result<String, StoreError> {
    optional_text(row, index).ok_or_else(|| StoreError::Corrupt(format!("{column} is not text")))
}

fn optional_text(row: &Row, index: usize) -> Option<String> {
    row.get_value(index)
        .ok()
        .and_then(|value| value.as_text().cloned())
}

fn blob(row: &Row, index: usize, column: &'static str) -> Result<Arc<[u8]>, StoreError> {
    row.get_value(index)
        .ok()
        .and_then(|value| value.as_blob().map(|bytes| Arc::from(bytes.as_slice())))
        .ok_or_else(|| StoreError::Corrupt(format!("{column} is not a blob")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference() -> ArtifactReference {
        ArtifactReference {
            ecosystem: Ecosystem::Npm,
            name: "left-pad".to_owned(),
            version: "1.3.0".to_owned(),
            filename: "left-pad-1.3.0.tgz".to_owned(),
            upstream_url: Url::parse("https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz")
                .expect("a test URL"),
            expected: vec![
                Digest::parse_hex(HashAlgorithm::Sha512, &"ab".repeat(64)).expect("a digest"),
            ],
        }
    }

    #[test]
    fn digests_round_trip_through_their_stored_spelling() {
        let digests = reference().expected;
        assert_eq!(
            decode_digests(&encode_digests(&digests)).expect("stored digests parse"),
            digests
        );
    }

    /// SPEC §5: "If a valid upstream timestamp later appears, use it."
    #[test]
    fn an_upstream_timestamp_supersedes_a_committed_first_seen() {
        let mut row = ReferenceRow {
            id: ReferenceId::compute(&reference()),
            reference: reference(),
            publication_micros: None,
            first_seen_micros: Some(500),
            pinned_sha256: None,
            pinned_sha512: None,
            pinned_size: None,
            content_key: None,
        };
        assert_eq!(row.publication_time(), PublicationTime::FirstSeen(500));

        row.publication_micros = Some(100);
        assert_eq!(row.publication_time(), PublicationTime::Upstream(100));

        row.first_seen_micros = None;
        row.publication_micros = None;
        assert_eq!(row.publication_time(), PublicationTime::Unknown);
    }
}
