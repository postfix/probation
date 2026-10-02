//! The blocklist snapshot (SPEC §8): parsing, whole-candidate validation, and the
//! immutable lookup sets a decision is made against.
//!
//! Validation is all-or-nothing. A candidate with one unsupported algorithm or one
//! malformed record is rejected entirely rather than partially applied, because a
//! partially applied snapshot silently drops blocks — exactly the failure SPEC §8
//! forbids when it says never to substitute an empty blocklist.

use std::array;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use serde::Deserialize;

use crate::policy::Ecosystem;
use crate::policy::digest::{Digest, HashAlgorithm};

/// The only schema this release understands (SPEC §8).
const SUPPORTED_SCHEMA_VERSION: u64 = 1;

/// The cap `check-blocklist` reads with. `serve` uses `max_blocklist_bytes` from the
/// configuration instead; the command is handed a path and no configuration, so it
/// applies the value SPEC §4 documents as the sample.
pub const DEFAULT_MAX_BLOCKLIST_BYTES: u64 = 134_217_728;

/// A validated, immutable snapshot. Every field needed to make a decision is
/// computed once, here, off the request path.
#[derive(Debug)]
pub struct BlocklistSnapshot {
    pub revision: u64,
    pub generated_at_micros: i64,
    pub expires_at_micros: i64,
    /// The exact validated bytes, for the persistence slice and for the
    /// changed-content-at-the-same-revision rule.
    pub raw: Arc<[u8]>,
    /// Lookup tables are per ecosystem rather than keyed by `(Ecosystem, String)`, so
    /// the warm path can look a name up as a `&str`. A tuple key would force a
    /// `String` allocation on every miss, which is the common case and the one
    /// SPEC §12's warm-denial target cares about.
    packages: [HashSet<String>; ECOSYSTEMS],
    versions: [HashMap<String, Vec<BlockedVersion>>; ECOSYSTEMS],
    digests: HashSet<Digest>,
    entry_count: usize,
}

const ECOSYSTEMS: usize = 2;

/// A blocked version keeps its upstream spelling for an exact match and, where the
/// ecosystem's rules allow it, the parsed form. SPEC §7 requires PyPI blocks to match
/// by PEP 440 equality including equivalent spellings, which a string alone cannot do.
#[derive(Debug)]
struct BlockedVersion {
    raw: String,
    canonical: Option<CanonicalVersion>,
}

#[derive(Debug)]
enum CanonicalVersion {
    Npm(Box<nodejs_semver::Version>),
    PyPi(Box<pep440_rs::Version>),
}

impl BlocklistSnapshot {
    /// Validates the entire candidate: schema version, the window, every package
    /// record and every digest. Rejects unsupported algorithms and malformed records
    /// rather than skipping them.
    pub fn parse_and_validate(
        bytes: &[u8],
        now_utc_micros: i64,
    ) -> Result<BlocklistSnapshot, BlocklistError> {
        // The schema version is read first, with everything else ignored, so a
        // future schema is refused by version rather than by whatever field of it
        // happens to fail to deserialise against this one.
        #[derive(Deserialize)]
        struct SchemaProbe {
            schema_version: u64,
        }

        let probe: SchemaProbe = serde_json::from_slice(bytes).map_err(BlocklistError::Syntax)?;
        if probe.schema_version != SUPPORTED_SCHEMA_VERSION {
            return Err(BlocklistError::UnsupportedSchemaVersion(
                probe.schema_version,
            ));
        }

        let raw: RawSnapshot = serde_json::from_slice(bytes).map_err(BlocklistError::Syntax)?;

        let generated_at_micros = parse_timestamp(
            &raw.generated_at,
            "generated_at is not an RFC 3339 timestamp",
        )?;
        let expires_at_micros =
            parse_timestamp(&raw.expires_at, "expires_at is not an RFC 3339 timestamp")?;

        if generated_at_micros >= expires_at_micros {
            return Err(BlocklistError::Window {
                reason: "generated_at is not before expires_at",
            });
        }
        if generated_at_micros > now_utc_micros {
            return Err(BlocklistError::Window {
                reason: "generated_at is in the future",
            });
        }
        if now_utc_micros >= expires_at_micros {
            return Err(BlocklistError::Window {
                reason: "the snapshot has expired",
            });
        }

        let mut packages: [HashSet<String>; ECOSYSTEMS] = array::from_fn(|_| HashSet::new());
        let mut versions: [HashMap<String, Vec<BlockedVersion>>; ECOSYSTEMS] =
            array::from_fn(|_| HashMap::new());
        let mut entry_count = 0usize;

        for (index, record) in raw.blocked_packages.iter().enumerate() {
            let ecosystem = Ecosystem::from_tag(&record.ecosystem).ok_or_else(|| {
                malformed(
                    index,
                    format!("unknown ecosystem `{}`", record.ecosystem),
                    "blocked_packages",
                )
            })?;
            if record.name.is_empty() || record.name.trim() != record.name {
                return Err(malformed(
                    index,
                    "the name is empty or padded with whitespace".to_owned(),
                    "blocked_packages",
                ));
            }
            if record.reason.trim().is_empty() {
                return Err(malformed(
                    index,
                    "the reason is empty".to_owned(),
                    "blocked_packages",
                ));
            }

            entry_count += 1;
            match &record.version {
                None => {
                    packages[ecosystem.index()].insert(record.name.clone());
                }
                Some(version) => {
                    if version.is_empty() || version.trim() != version {
                        return Err(malformed(
                            index,
                            "the version is empty or padded with whitespace".to_owned(),
                            "blocked_packages",
                        ));
                    }
                    versions[ecosystem.index()]
                        .entry(record.name.clone())
                        .or_default()
                        .push(BlockedVersion {
                            raw: version.clone(),
                            canonical: canonical_version(ecosystem, version),
                        });
                }
            }
        }

        let mut digests = HashSet::new();
        for (index, record) in raw.blocked_hashes.iter().enumerate() {
            // SPEC §8 accepts SHA-256 and SHA-512 only. SHA-1 is representable in this
            // crate because npm still advertises it, but it is never blockable: a
            // 20-byte digest is too weak to deny bytes on.
            let algorithm = match HashAlgorithm::from_name(&record.algorithm) {
                Some(HashAlgorithm::Sha256) => HashAlgorithm::Sha256,
                Some(HashAlgorithm::Sha512) => HashAlgorithm::Sha512,
                _ => {
                    return Err(BlocklistError::UnsupportedAlgorithm(
                        record.algorithm.clone(),
                    ));
                }
            };
            if record.reason.trim().is_empty() {
                return Err(malformed(
                    index,
                    "the reason is empty".to_owned(),
                    "blocked_hashes",
                ));
            }
            let digest = Digest::parse_hex(algorithm, &record.digest).map_err(|_| {
                BlocklistError::MalformedDigest {
                    algorithm: record.algorithm.clone(),
                }
            })?;
            entry_count += 1;
            digests.insert(digest);
        }

        Ok(BlocklistSnapshot {
            revision: raw.revision,
            generated_at_micros,
            expires_at_micros,
            raw: Arc::from(bytes),
            packages,
            versions,
            digests,
            entry_count,
        })
    }

    /// SPEC §8's window, re-checked on every decision: expiry needs no poller, and a
    /// snapshot that has expired is not a policy at all.
    pub fn is_valid_at(&self, now_utc_micros: i64) -> bool {
        self.generated_at_micros <= now_utc_micros && now_utc_micros < self.expires_at_micros
    }

    pub fn blocks_package(&self, ecosystem: Ecosystem, name: &str) -> bool {
        self.packages[ecosystem.index()].contains(name)
    }

    pub fn blocks_version(&self, ecosystem: Ecosystem, name: &str, version: &str) -> bool {
        let Some(blocked) = self.versions[ecosystem.index()].get(name) else {
            // The common case: no version of this package is blocked at all, answered
            // by one hash lookup.
            return false;
        };
        if blocked.iter().any(|entry| entry.raw == version) {
            return true;
        }
        let Some(candidate) = canonical_version(ecosystem, version) else {
            return false;
        };
        blocked
            .iter()
            .any(|entry| match (&entry.canonical, &candidate) {
                (Some(CanonicalVersion::Npm(blocked)), CanonicalVersion::Npm(candidate)) => {
                    blocked == candidate
                }
                (Some(CanonicalVersion::PyPi(blocked)), CanonicalVersion::PyPi(candidate)) => {
                    blocked == candidate
                }
                _ => false,
            })
    }

    pub fn blocks_digest(&self, digest: &Digest) -> bool {
        self.digests.contains(digest)
    }

    pub fn entry_count(&self) -> usize {
        self.entry_count
    }
}

/// npm compares by semver precedence, PyPI by PEP 440 equality. A version the
/// ecosystem's parser rejects keeps only its exact spelling, which still matches an
/// identical entry — a producer's odd spelling narrows a block, it never widens one.
fn canonical_version(ecosystem: Ecosystem, version: &str) -> Option<CanonicalVersion> {
    match ecosystem {
        Ecosystem::Npm => nodejs_semver::Version::parse(version)
            .ok()
            .map(|parsed| CanonicalVersion::Npm(Box::new(parsed))),
        Ecosystem::PyPi => pep440_rs::Version::from_str(version)
            .ok()
            .map(|parsed| CanonicalVersion::PyPi(Box::new(parsed))),
    }
}

fn parse_timestamp(text: &str, malformed: &'static str) -> Result<i64, BlocklistError> {
    jiff::Timestamp::from_str(text)
        .map(|timestamp| timestamp.as_microsecond())
        .map_err(|_| BlocklistError::Window { reason: malformed })
}

fn malformed(index: usize, reason: String, array: &'static str) -> BlocklistError {
    BlocklistError::MalformedRecord {
        index,
        reason: format!("{array}[{index}]: {reason}"),
    }
}

/// What SPEC §8 step 3 says to do with a validated candidate, given the snapshot
/// currently in force.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Replacement {
    /// Strictly newer: commit it, then publish it.
    Accept,
    /// Identical revision and identical bytes: nothing to do.
    NoOp,
}

/// SPEC §8 step 3: require a strictly increasing revision for changed contents,
/// treat identical revision and content as a no-op, and reject both a rollback and
/// changed contents carrying an unchanged revision.
pub fn check_replacement(
    accepted: Option<&BlocklistSnapshot>,
    candidate: &BlocklistSnapshot,
) -> Result<Replacement, BlocklistError> {
    let Some(accepted) = accepted else {
        return Ok(Replacement::Accept);
    };
    if candidate.revision > accepted.revision {
        return Ok(Replacement::Accept);
    }
    if candidate.revision < accepted.revision {
        return Err(BlocklistError::NotNewer {
            accepted: accepted.revision,
            candidate: candidate.revision,
        });
    }
    if accepted.raw == candidate.raw {
        Ok(Replacement::NoOp)
    } else {
        Err(BlocklistError::ChangedWithoutRevisionBump {
            revision: candidate.revision,
        })
    }
}

/// Reads a candidate file within `max_bytes` and validates the whole snapshot.
///
/// Shared by `serve`'s startup load and `check-blocklist` so the two cannot diverge,
/// the same way `Config` is shared by `serve` and `check-config`. The cap is applied
/// to the read itself, so an oversized file is never buffered whole.
pub fn load_file(
    path: &Path,
    max_bytes: u64,
    now_utc_micros: i64,
) -> Result<BlocklistSnapshot, BlocklistError> {
    let read_error = |source: io::Error| BlocklistError::Read {
        path: path.to_path_buf(),
        source,
    };

    let file = File::open(path).map_err(read_error)?;
    let mut bytes = Vec::new();
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(read_error)?;
    if bytes.len() as u64 > max_bytes {
        return Err(BlocklistError::TooLarge { limit: max_bytes });
    }

    BlocklistSnapshot::parse_and_validate(&bytes, now_utc_micros)
}

/// The file as written. Unknown fields are rejected at every level: a record this
/// release does not understand is a malformed record, not one to apply partially.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSnapshot {
    // Read by the schema probe before this struct is built; it is declared here
    // because `deny_unknown_fields` would otherwise reject the key it validated.
    #[allow(dead_code)]
    schema_version: u64,
    revision: u64,
    generated_at: String,
    expires_at: String,
    blocked_packages: Vec<RawPackage>,
    blocked_hashes: Vec<RawHash>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPackage {
    ecosystem: String,
    name: String,
    /// `null` or absent both mean "every release of this package".
    #[serde(default)]
    version: Option<String>,
    reason: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawHash {
    algorithm: String,
    digest: String,
    reason: String,
}

#[derive(Debug)]
pub enum BlocklistError {
    /// Not part of the Gate 3 enum: `load_file` is shared by `serve` and
    /// `check-blocklist`, and both need to report an unreadable file by name.
    Read {
        path: PathBuf,
        source: io::Error,
    },
    TooLarge {
        limit: u64,
    },
    Syntax(serde_json::Error),
    UnsupportedSchemaVersion(u64),
    UnsupportedAlgorithm(String),
    MalformedDigest {
        algorithm: String,
    },
    MalformedRecord {
        index: usize,
        reason: String,
    },
    Window {
        reason: &'static str,
    },
    NotNewer {
        accepted: u64,
        candidate: u64,
    },
    ChangedWithoutRevisionBump {
        revision: u64,
    },
}

impl fmt::Display for BlocklistError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlocklistError::Read { path, source } => {
                write!(f, "cannot read {}: {source}", path.display())
            }
            BlocklistError::TooLarge { limit } => {
                write!(f, "the blocklist is larger than the {limit} byte limit")
            }
            BlocklistError::Syntax(err) => write!(f, "invalid JSON: {err}"),
            BlocklistError::UnsupportedSchemaVersion(version) => write!(
                f,
                "unsupported schema_version {version}; this release understands {SUPPORTED_SCHEMA_VERSION}"
            ),
            BlocklistError::UnsupportedAlgorithm(algorithm) => write!(
                f,
                "unsupported hash algorithm `{algorithm}`; only sha256 and sha512 can block"
            ),
            BlocklistError::MalformedDigest { algorithm } => {
                write!(f, "malformed {algorithm} digest")
            }
            BlocklistError::MalformedRecord { reason, .. } => {
                write!(f, "malformed record: {reason}")
            }
            BlocklistError::Window { reason } => write!(f, "invalid validity window: {reason}"),
            BlocklistError::NotNewer {
                accepted,
                candidate,
            } => write!(
                f,
                "revision {candidate} is not newer than the accepted revision {accepted}"
            ),
            BlocklistError::ChangedWithoutRevisionBump { revision } => write!(
                f,
                "the contents changed while revision stayed at {revision}"
            ),
        }
    }
}

impl std::error::Error for BlocklistError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            BlocklistError::Read { source, .. } => Some(source),
            BlocklistError::Syntax(err) => Some(err),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Candidate, Decision, DenyReason, PublicationTime, evaluate};

    /// `sha256("hello")`, in the two spellings SPEC §8 says must reach the same
    /// digest bytes.
    const HELLO_SHA256_HEX: &str =
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
    const HELLO_SHA256_SRI: &str = "sha256-LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=";
    const HELLO_SHA512_HEX: &str = "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043";
    const HELLO_SHA512_SRI: &str = "sha512-m3HSJL1i83hdltRq0+o9czGb+8KJDKra4t/3JRlnPKcjI8PZm6XBHXx6zG4UuMXaDEZjR1wuXDre9G9zvN7AQw==";

    fn at(rfc3339: &str) -> i64 {
        jiff::Timestamp::from_str(rfc3339)
            .expect("a test timestamp")
            .as_microsecond()
    }

    fn now() -> i64 {
        at("2026-09-17T00:00:00Z")
    }

    fn document(revision: u64, packages: &str, hashes: &str) -> String {
        format!(
            r#"{{"schema_version":1,"revision":{revision},
                 "generated_at":"2020-01-01T00:00:00Z","expires_at":"2099-01-01T00:00:00Z",
                 "blocked_packages":[{packages}],"blocked_hashes":[{hashes}]}}"#
        )
    }

    fn parse(json: &str) -> Result<BlocklistSnapshot, BlocklistError> {
        BlocklistSnapshot::parse_and_validate(json.as_bytes(), now())
    }

    fn valid(json: &str) -> BlocklistSnapshot {
        parse(json).expect("the candidate is valid")
    }

    #[test]
    fn pep440_equivalent_spellings_match() {
        let snapshot = valid(&document(
            1,
            r#"{"ecosystem":"pypi","name":"example","version":"1.0","reason":"malware"},
               {"ecosystem":"npm","name":"example","version":"1.0.0","reason":"malware"}"#,
            "",
        ));

        assert!(snapshot.blocks_version(Ecosystem::PyPi, "example", "1.0"));
        assert!(
            snapshot.blocks_version(Ecosystem::PyPi, "example", "1.0.0"),
            "PEP 440 equality: a block on 1.0 denies the 1.0.0 spelling of the same release"
        );
        assert!(snapshot.blocks_version(Ecosystem::PyPi, "example", "1.0.0.0"));
        assert!(
            !snapshot.blocks_version(Ecosystem::PyPi, "example", "1.0.1"),
            "a different release is not the blocked one"
        );
        assert!(
            !snapshot.blocks_version(Ecosystem::PyPi, "example", "1.0.0.post1"),
            "a post-release is a different release under PEP 440"
        );

        assert!(snapshot.blocks_version(Ecosystem::Npm, "example", "1.0.0"));
        assert!(
            !snapshot.blocks_version(Ecosystem::Npm, "example", "1.0"),
            "npm has no equivalent-spelling rule: 1.0 is not a semver version at all"
        );
        assert!(
            !snapshot.blocks_version(Ecosystem::PyPi, "other", "1.0"),
            "the block is scoped to its own package"
        );

        // And the same rule through the decision, not only the lookup.
        let old = PublicationTime::Upstream(now() - 10 * 24 * 3600 * 1_000_000);
        assert_eq!(
            evaluate(
                Some(&snapshot),
                now(),
                86_400,
                &Candidate {
                    ecosystem: Ecosystem::PyPi,
                    name: "example",
                    version: "1.0.0",
                    publication: old,
                    advertised_digests: &[],
                    pinned_digests: &[],
                },
                false,
            ),
            Decision::Deny(DenyReason::BlockedVersion)
        );
    }

    #[test]
    fn sri_base64_and_hex_reach_the_same_digest() {
        let snapshot = valid(&document(
            1,
            "",
            &format!(
                r#"{{"algorithm":"sha256","digest":"{HELLO_SHA256_HEX}","reason":"malware"}},
                   {{"algorithm":"sha512","digest":"{HELLO_SHA512_HEX}","reason":"malware"}}"#
            ),
        ));

        let from_sri = Digest::parse_sri_entry(HELLO_SHA256_SRI).expect("a valid SRI entry");
        let from_hex =
            Digest::parse_hex(HashAlgorithm::Sha256, HELLO_SHA256_HEX).expect("a valid hex digest");
        assert_eq!(from_sri, from_hex);
        assert!(
            snapshot.blocks_digest(&from_sri),
            "a block written in hex denies an artifact advertised only as SRI base64"
        );

        let sha512 = Digest::parse_sri_entry(HELLO_SHA512_SRI).expect("a valid SRI entry");
        assert_eq!(
            sha512.to_hex_lowercase(),
            HELLO_SHA512_HEX,
            "base64 and hex decode to the same bytes"
        );
        assert!(snapshot.blocks_digest(&sha512));

        // Case is normalised, so an upper-case producer entry is the same digest.
        let upper = Digest::parse_hex(HashAlgorithm::Sha256, &HELLO_SHA256_HEX.to_uppercase())
            .expect("upper-case hex is accepted and normalised");
        assert_eq!(upper, from_hex);

        // And malformed integrity from untrusted upstream metadata is an error, not
        // a panic and not a digest that could miss a block.
        assert!(Digest::parse_sri_entry("sha256-not!base64!").is_err());
        assert!(
            Digest::parse_sri_entry("sha256-LPJNul+wow4m6DsqxbninhsWHlwfp0Jec=").is_err(),
            "a short payload is not a sha256 digest"
        );
        assert!(Digest::parse_sri_entry("md5-LPJNul+wow4=").is_err());
        assert!(Digest::parse_sri_entry("2cf24dba").is_err());
        assert!(
            Digest::parse_sri_entry("sha256-LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCR=").is_err(),
            "a non-canonical spelling — trailing bits a permissive decoder would drop, \
             giving a second base64 string for the very same digest — is rejected, so \
             malformed upstream integrity is reported rather than quietly accepted"
        );
    }

    #[test]
    fn rejects_unsupported_algorithm_and_malformed_records() {
        // One good record and one bad one: the whole candidate is rejected, so the
        // good record never takes effect on its own.
        let mixed = parse(&document(
            1,
            r#"{"ecosystem":"npm","name":"good","version":null,"reason":"malware"},
               {"ecosystem":"cargo","name":"bad","version":null,"reason":"malware"}"#,
            "",
        ));
        assert!(matches!(
            mixed,
            Err(BlocklistError::MalformedRecord { index: 1, .. })
        ));

        let sha1 = parse(&document(
            1,
            "",
            r#"{"algorithm":"sha1","digest":"0123456789abcdef0123456789abcdef01234567","reason":"weak"}"#,
        ));
        assert!(
            matches!(sha1, Err(BlocklistError::UnsupportedAlgorithm(ref name)) if name == "sha1"),
            "SPEC §8 accepts sha256 and sha512 only: got {sha1:?}"
        );

        let md5 = parse(&document(
            1,
            "",
            r#"{"algorithm":"md5","digest":"0123456789abcdef0123456789abcdef","reason":"x"}"#,
        ));
        assert!(matches!(md5, Err(BlocklistError::UnsupportedAlgorithm(_))));

        let short = parse(&document(
            1,
            "",
            r#"{"algorithm":"sha256","digest":"2cf24dba","reason":"malware"}"#,
        ));
        assert!(
            matches!(short, Err(BlocklistError::MalformedDigest { .. })),
            "a digest of the wrong length is malformed, never padded to fit"
        );

        let not_hex = parse(&document(
            1,
            "",
            &format!(
                r#"{{"algorithm":"sha256","digest":"{}zz","reason":"malware"}}"#,
                &HELLO_SHA256_HEX[..62]
            ),
        ));
        assert!(matches!(
            not_hex,
            Err(BlocklistError::MalformedDigest { .. })
        ));

        let empty_reason = parse(&document(
            1,
            r#"{"ecosystem":"npm","name":"bad","version":null,"reason":"  "}"#,
            "",
        ));
        assert!(matches!(
            empty_reason,
            Err(BlocklistError::MalformedRecord { index: 0, .. })
        ));

        let empty_name = parse(&document(
            1,
            r#"{"ecosystem":"npm","name":"","version":null,"reason":"malware"}"#,
            "",
        ));
        assert!(matches!(
            empty_name,
            Err(BlocklistError::MalformedRecord { index: 0, .. })
        ));

        let unknown_field = parse(&document(
            1,
            r#"{"ecosystem":"npm","name":"bad","version":null,"reason":"malware","severity":9}"#,
            "",
        ));
        assert!(
            matches!(unknown_field, Err(BlocklistError::Syntax(_))),
            "a record carrying a field this release does not understand is refused, \
             not applied with the field ignored"
        );

        let missing_field = parse(&document(1, r#"{"ecosystem":"npm","name":"bad"}"#, ""));
        assert!(matches!(missing_field, Err(BlocklistError::Syntax(_))));

        assert!(matches!(
            parse("not json at all"),
            Err(BlocklistError::Syntax(_))
        ));
    }

    #[test]
    fn rejects_an_unsupported_schema_version() {
        let json = document(1, "", "").replace(r#""schema_version":1"#, r#""schema_version":2"#);
        assert!(matches!(
            parse(&json),
            Err(BlocklistError::UnsupportedSchemaVersion(2))
        ));
    }

    #[test]
    fn rejects_rollback_and_changed_content_at_same_revision() {
        let accepted = valid(&document(
            7,
            r#"{"ecosystem":"npm","name":"one","version":null,"reason":"malware"}"#,
            "",
        ));

        let older = valid(&document(6, "", ""));
        assert!(matches!(
            check_replacement(Some(&accepted), &older),
            Err(BlocklistError::NotNewer {
                accepted: 7,
                candidate: 6
            })
        ));

        let changed = valid(&document(
            7,
            r#"{"ecosystem":"npm","name":"two","version":null,"reason":"malware"}"#,
            "",
        ));
        assert!(matches!(
            check_replacement(Some(&accepted), &changed),
            Err(BlocklistError::ChangedWithoutRevisionBump { revision: 7 })
        ));

        let identical = valid(&document(
            7,
            r#"{"ecosystem":"npm","name":"one","version":null,"reason":"malware"}"#,
            "",
        ));
        assert!(
            matches!(
                check_replacement(Some(&accepted), &identical),
                Ok(Replacement::NoOp)
            ),
            "identical revision and identical bytes is a no-op, not an error"
        );

        let newer = valid(&document(8, "", ""));
        assert!(matches!(
            check_replacement(Some(&accepted), &newer),
            Ok(Replacement::Accept)
        ));
        assert!(matches!(
            check_replacement(None, &newer),
            Ok(Replacement::Accept)
        ));

        // The rejections are decisions about a candidate; the snapshot in force is
        // untouched by them.
        assert!(accepted.blocks_package(Ecosystem::Npm, "one"));
    }

    #[test]
    fn window_rules() {
        let window = |generated: &str, expires: &str| {
            let json = format!(
                r#"{{"schema_version":1,"revision":1,"generated_at":"{generated}",
                     "expires_at":"{expires}","blocked_packages":[],"blocked_hashes":[]}}"#
            );
            parse(&json)
        };

        assert!(
            matches!(
                window("2026-09-18T00:00:00Z", "2026-09-19T00:00:00Z"),
                Err(BlocklistError::Window { .. })
            ),
            "generated_at after now is refused"
        );
        assert!(
            matches!(
                window("2026-09-10T00:00:00Z", "2026-09-16T00:00:00Z"),
                Err(BlocklistError::Window { .. })
            ),
            "now at or after expires_at is refused"
        );
        assert!(
            matches!(
                window("2026-09-17T00:00:00Z", "2026-09-17T00:00:00Z"),
                Err(BlocklistError::Window { .. })
            ),
            "generated_at equal to expires_at is refused"
        );
        assert!(
            matches!(
                window("2026-09-18T00:00:00Z", "2026-09-17T00:00:00Z"),
                Err(BlocklistError::Window { .. })
            ),
            "expires_at before generated_at is refused"
        );
        assert!(matches!(
            window("not a timestamp", "2099-01-01T00:00:00Z"),
            Err(BlocklistError::Window { .. })
        ));

        let accepted = window("2026-09-16T00:00:00Z", "2026-09-18T00:00:00Z")
            .expect("generated_at <= now < expires_at is accepted");
        assert!(accepted.is_valid_at(now()));
        assert!(
            !accepted.is_valid_at(accepted.expires_at_micros),
            "expiry is exclusive: at expires_at the snapshot is no longer in force"
        );
        assert!(accepted.is_valid_at(accepted.expires_at_micros - 1));
        assert!(!accepted.is_valid_at(accepted.generated_at_micros - 1));
    }

    #[test]
    fn valid_empty_snapshot_is_accepted() {
        let snapshot = valid(&document(1, "", ""));
        assert_eq!(snapshot.entry_count(), 0);
        assert!(!snapshot.blocks_package(Ecosystem::Npm, "left-pad"));
        assert!(!snapshot.blocks_version(Ecosystem::Npm, "left-pad", "1.3.0"));
        assert!(!snapshot.blocks_digest(
            &Digest::parse_hex(HashAlgorithm::Sha256, HELLO_SHA256_HEX).expect("a digest")
        ));

        // Only cooldown then applies: an old release is eligible, a fresh one waits.
        let candidate = |publication| Candidate {
            ecosystem: Ecosystem::Npm,
            name: "left-pad",
            version: "1.3.0",
            publication,
            advertised_digests: &[],
            pinned_digests: &[],
        };
        assert_eq!(
            evaluate(
                Some(&snapshot),
                now(),
                86_400,
                &candidate(PublicationTime::Upstream(
                    now() - 10 * 24 * 3600 * 1_000_000
                )),
                false,
            ),
            Decision::Allow
        );
        assert!(matches!(
            evaluate(
                Some(&snapshot),
                now(),
                86_400,
                &candidate(PublicationTime::Upstream(now() - 1_000_000)),
                false,
            ),
            Decision::Hold { .. }
        ));
    }

    #[test]
    fn deeply_nested_blocklist_is_rejected_not_a_crash() {
        const DEPTH: usize = 100_000;

        // Two shapes: one where the nesting stands where a scalar is expected, and one
        // where the parser must skip the nested value to reach the fields it wants.
        // The second is the one serde_json's depth limit answers.
        let in_a_scalar = format!(
            r#"{{"schema_version":{}{}}}"#,
            "[".repeat(DEPTH),
            "]".repeat(DEPTH)
        );
        let in_a_skipped_value = format!(
            r#"{{"schema_version":1,"revision":1,"generated_at":"2020-01-01T00:00:00Z",
                 "expires_at":"2099-01-01T00:00:00Z","blocked_packages":{}{},
                 "blocked_hashes":[]}}"#,
            "[".repeat(DEPTH),
            "]".repeat(DEPTH)
        );

        for candidate in [in_a_scalar, in_a_skipped_value] {
            // A deliberately small stack: a parser that recursed once per level would
            // overflow here rather than passing on a test thread's generous stack.
            let outcome = std::thread::Builder::new()
                .stack_size(512 * 1024)
                .spawn(move || {
                    BlocklistSnapshot::parse_and_validate(candidate.as_bytes(), now())
                        .map(|snapshot| snapshot.revision)
                })
                .expect("a test thread")
                .join()
                .expect("the parser returns an error instead of exhausting the stack");

            assert!(
                matches!(outcome, Err(BlocklistError::Syntax(_))),
                "a deeply nested candidate is rejected: {outcome:?}"
            );
        }
    }
}
