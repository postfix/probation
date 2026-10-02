//! The shape of an npm package document, and the artifact references in it.
//!
//! The document is split into the four parts filtering touches — `name`, `versions`,
//! `time`, `dist-tags` — and everything else, which is carried through untouched. An
//! upstream field this release has never heard of therefore survives filtering
//! unedited, which is what SPEC §6's "preserve dependency, optional dependency, peer
//! dependency, platform, and engine information" needs in order to keep being true
//! when npm adds a field.
//!
//! Nothing here lifts `serde_json`'s recursion limit, so a deeply nested document is
//! a parse error rather than a stack overflow (Gate 3 dependency note 5).

use std::fmt;

use serde_json::{Map, Value};
use url::Url;

use crate::policy::{Digest, Ecosystem, PublicationTime};
use crate::store::rows::{ArtifactReference, ReferenceId};

/// The two `time` keys that are not versions.
const TIME_METADATA_KEYS: [&str; 2] = ["created", "modified"];

pub struct PackageDocument {
    pub name: String,
    pub versions: Map<String, Value>,
    pub time: Map<String, Value>,
    pub dist_tags: Map<String, Value>,
    /// Every other top-level field, exactly as upstream wrote it.
    pub rest: Map<String, Value>,
}

impl PackageDocument {
    pub fn parse(bytes: &[u8]) -> Result<PackageDocument, DocumentError> {
        let value: Value = serde_json::from_slice(bytes).map_err(DocumentError::Json)?;
        let Value::Object(mut object) = value else {
            return Err(DocumentError::NotAnObject);
        };

        let name = match object.remove("name") {
            Some(Value::String(name)) => name,
            _ => return Err(DocumentError::MissingName),
        };
        let versions = take_object(&mut object, "versions")?;
        let time = take_object(&mut object, "time")?;
        let dist_tags = take_object(&mut object, "dist-tags")?;

        Ok(PackageDocument {
            name,
            versions,
            time,
            dist_tags,
            rest: object,
        })
    }

    /// One entry per version the document advertises.
    ///
    /// A version whose artifact cannot be identified — no `dist.tarball`, a tarball
    /// that is not a URL, no filename in it, or an integrity field that does not
    /// decode — is **excluded and logged** rather than guessed at (SPEC §11: "Log
    /// exclusions that cannot be represented in an ecosystem listing"). It is never
    /// served, because a reference this instance cannot name is a reference it cannot
    /// check.
    pub fn entries(&self, max_references: u32) -> Result<Vec<VersionEntry>, DocumentError> {
        if self.versions.len() > max_references as usize {
            return Err(DocumentError::TooManyReferences {
                count: self.versions.len(),
                limit: max_references,
            });
        }

        let mut entries = Vec::with_capacity(self.versions.len());
        for (version, record) in &self.versions {
            match self.entry(version, record) {
                Ok(entry) => entries.push(entry),
                Err(reason) => tracing::warn!(
                    package = %self.name,
                    version = %version,
                    %reason,
                    "excluding a version whose artifact identity cannot be established"
                ),
            }
        }
        Ok(entries)
    }

    fn entry(&self, version: &str, record: &Value) -> Result<VersionEntry, UnusableVersion> {
        let dist = record
            .get("dist")
            .and_then(Value::as_object)
            .ok_or(UnusableVersion::NoDist)?;
        let tarball = dist
            .get("tarball")
            .and_then(Value::as_str)
            .ok_or(UnusableVersion::NoTarball)?;
        let upstream_url = Url::parse(tarball).map_err(|_| UnusableVersion::TarballNotAUrl)?;
        let filename = upstream_url
            .path_segments()
            .and_then(|mut segments| segments.next_back())
            .filter(|segment| !segment.is_empty())
            .ok_or(UnusableVersion::NoFilename)?
            .to_owned();

        let reference = ArtifactReference {
            ecosystem: Ecosystem::Npm,
            name: self.name.clone(),
            version: version.to_owned(),
            filename,
            upstream_url,
            expected: advertised_digests(dist)?,
        };

        Ok(VersionEntry {
            id: ReferenceId::compute(&reference),
            reference,
            publication: self.publication_time(version),
            record: record.clone(),
        })
    }

    /// SPEC §5: a value we cannot parse is `Malformed` and denies; no value at all is
    /// `Unknown`, which the caller resolves into a committed first-seen time before
    /// it decides anything.
    fn publication_time(&self, version: &str) -> PublicationTime {
        match self.time.get(version) {
            None => PublicationTime::Unknown,
            Some(Value::String(text)) => match text.parse::<jiff::Timestamp>() {
                Ok(timestamp) => PublicationTime::Upstream(timestamp.as_microsecond()),
                Err(_) => PublicationTime::Malformed,
            },
            Some(_) => PublicationTime::Malformed,
        }
    }
}

/// One version, its artifact reference, and where its age comes from.
pub struct VersionEntry {
    pub id: ReferenceId,
    pub reference: ArtifactReference,
    pub publication: PublicationTime,
    /// The per-version object exactly as upstream wrote it. Rendering copies it and
    /// rewrites `dist.tarball`; nothing else in it is ever edited.
    pub record: Value,
}

impl VersionEntry {
    pub fn version(&self) -> &str {
        &self.reference.version
    }
}

/// `dist.integrity` holds one or more SRI entries; `dist.shasum` is npm's legacy
/// hexadecimal SHA-1, kept only because old releases carry nothing stronger
/// (SPEC §3).
///
/// A malformed entry excludes the version rather than being skipped: a digest we
/// silently dropped is a digest a blocklist could not match on.
fn advertised_digests(dist: &Map<String, Value>) -> Result<Vec<Digest>, UnusableVersion> {
    let mut digests = Vec::new();
    if let Some(integrity) = dist.get("integrity") {
        let integrity = integrity
            .as_str()
            .ok_or(UnusableVersion::MalformedIntegrity)?;
        for entry in integrity.split_whitespace() {
            digests.push(
                Digest::parse_sri_entry(entry).map_err(|_| UnusableVersion::MalformedIntegrity)?,
            );
        }
    }
    if let Some(shasum) = dist.get("shasum") {
        let shasum = shasum.as_str().ok_or(UnusableVersion::MalformedIntegrity)?;
        digests.push(
            Digest::parse_hex(crate::policy::HashAlgorithm::Sha1, shasum)
                .map_err(|_| UnusableVersion::MalformedIntegrity)?,
        );
    }
    Ok(digests)
}

fn take_object(
    object: &mut Map<String, Value>,
    key: &'static str,
) -> Result<Map<String, Value>, DocumentError> {
    match object.remove(key) {
        None | Some(Value::Null) => Ok(Map::new()),
        Some(Value::Object(inner)) => Ok(inner),
        Some(_) => Err(DocumentError::NotAnObjectAt(key)),
    }
}

/// Which `time` entries survive when `keep` is the set of versions that did.
pub fn prune_time(time: &Map<String, Value>, keep: impl Fn(&str) -> bool) -> Map<String, Value> {
    time.iter()
        .filter(|(key, _)| TIME_METADATA_KEYS.contains(&key.as_str()) || keep(key))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

#[derive(Debug)]
pub enum DocumentError {
    Json(serde_json::Error),
    NotAnObject,
    NotAnObjectAt(&'static str),
    MissingName,
    /// TM-1: one pathological document would otherwise hold the single storage task
    /// for the length of one very large transaction, delaying every other operation
    /// including an urgent blocklist commit.
    TooManyReferences {
        count: usize,
        limit: u32,
    },
}

impl fmt::Display for DocumentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DocumentError::Json(err) => write!(f, "the document is not usable JSON: {err}"),
            DocumentError::NotAnObject => f.write_str("the document is not a JSON object"),
            DocumentError::NotAnObjectAt(key) => write!(f, "`{key}` is not a JSON object"),
            DocumentError::MissingName => f.write_str("the document carries no `name`"),
            DocumentError::TooManyReferences { count, limit } => write!(
                f,
                "the document advertises {count} versions, above the {limit} this instance \
                 commits in one transaction"
            ),
        }
    }
}

impl std::error::Error for DocumentError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DocumentError::Json(err) => Some(err),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum UnusableVersion {
    NoDist,
    NoTarball,
    TarballNotAUrl,
    NoFilename,
    MalformedIntegrity,
}

impl fmt::Display for UnusableVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            UnusableVersion::NoDist => "no `dist` object",
            UnusableVersion::NoTarball => "no `dist.tarball`",
            UnusableVersion::TarballNotAUrl => "`dist.tarball` is not a URL",
            UnusableVersion::NoFilename => "`dist.tarball` carries no filename",
            UnusableVersion::MalformedIntegrity => "the advertised integrity does not decode",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOCUMENT: &str = r#"{
        "name": "widget",
        "unknown-future-field": {"kept": [1, 2, 3]},
        "dist-tags": {"latest": "1.0.0"},
        "versions": {
            "1.0.0": {
                "name": "widget", "version": "1.0.0",
                "dependencies": {"left-pad": "^1.3.0"},
                "dist": {
                    "tarball": "https://npm.invalid/widget/-/widget-1.0.0.tgz",
                    "integrity": "sha512-Ky+7uDR6YC9cEIbfCn6zqL7lgs8mBiPQrVtxnmWNbpjHSJnMLJUEGwlxYLLDEBpotoKp9GOwWEYYCQaB7+Jsug==",
                    "shasum": "0123456789abcdef0123456789abcdef01234567"
                }
            },
            "1.1.0": {
                "name": "widget", "version": "1.1.0",
                "dist": {"tarball": "not a url"}
            }
        },
        "time": {
            "created": "2026-01-01T00:00:00.000Z",
            "1.0.0": "2026-01-02T00:00:00.000Z",
            "1.1.0": "yesterday"
        }
    }"#;

    #[test]
    fn the_four_filtered_parts_come_out_and_everything_else_stays_whole() {
        let document = PackageDocument::parse(DOCUMENT.as_bytes()).expect("a valid document");
        assert_eq!(document.name, "widget");
        assert_eq!(document.versions.len(), 2);
        assert_eq!(document.dist_tags["latest"], Value::from("1.0.0"));
        assert_eq!(
            document.rest["unknown-future-field"]["kept"],
            Value::from(vec![1, 2, 3]),
            "a field this release has never heard of survives untouched"
        );
        assert!(!document.rest.contains_key("versions"));
    }

    /// A version we cannot name is a version we cannot check, so it leaves the
    /// listing instead of being served on a guess.
    #[test]
    fn a_version_without_a_usable_tarball_is_excluded() {
        let document = PackageDocument::parse(DOCUMENT.as_bytes()).expect("a valid document");
        let entries = document.entries(100).expect("the entries");

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].version(), "1.0.0");
        assert_eq!(entries[0].reference.filename, "widget-1.0.0.tgz");
        assert_eq!(
            entries[0].reference.expected.len(),
            2,
            "the SRI sha512 and the legacy shasum are both kept"
        );
        assert_eq!(
            entries[0].publication,
            PublicationTime::Upstream(
                "2026-01-02T00:00:00Z"
                    .parse::<jiff::Timestamp>()
                    .expect("a timestamp")
                    .as_microsecond()
            )
        );
    }

    /// SPEC §5 separates the two: a value we could not parse denies, and no value at
    /// all waits for a committed first-seen time.
    #[test]
    fn malformed_and_absent_publication_times_are_different_answers() {
        let document = PackageDocument::parse(DOCUMENT.as_bytes()).expect("a valid document");
        assert_eq!(
            document.publication_time("1.1.0"),
            PublicationTime::Malformed
        );
        assert_eq!(document.publication_time("9.9.9"), PublicationTime::Unknown);
    }

    #[test]
    fn the_reference_cap_is_a_document_error_not_a_truncation() {
        let document = PackageDocument::parse(DOCUMENT.as_bytes()).expect("a valid document");
        assert!(matches!(
            document.entries(1),
            Err(DocumentError::TooManyReferences { count: 2, limit: 1 })
        ));
    }

    #[test]
    fn a_deeply_nested_document_is_a_parse_error_not_a_crash() {
        let deep = format!("{}{}", "[".repeat(100_000), "]".repeat(100_000));
        assert!(matches!(
            PackageDocument::parse(deep.as_bytes()),
            Err(DocumentError::Json(_))
        ));
    }
}
