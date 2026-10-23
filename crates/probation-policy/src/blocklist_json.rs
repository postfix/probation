//! Today's blocklist file (SPEC §8, `blocklist.sample.json`) in and out of a layer's
//! blocks (C86, C119). Import ignores `revision`, `generated_at` and `expires_at`: the
//! server keeps its own revisions. Names are checked later, by `check_edit`.

use serde::{Deserialize, Serialize};

use crate::{Block, DigestAlgorithm, Ecosystem};

/// What an export writes for a block that has no reason: today's format requires one.
pub const NO_REASON: &str = "Blocked in Probation";

#[derive(Serialize, Deserialize)]
struct File {
    schema_version: u32,
    #[serde(default, skip_deserializing)]
    revision: u64,
    #[serde(default, skip_deserializing)]
    generated_at: String,
    #[serde(default, skip_deserializing)]
    expires_at: String,
    #[serde(default)]
    blocked_packages: Vec<Package>,
    #[serde(default)]
    blocked_hashes: Vec<Hash>,
}

#[derive(Serialize, Deserialize)]
struct Package {
    ecosystem: String,
    name: String,
    version: Option<String>,
    #[serde(default)]
    reason: String,
}

#[derive(Serialize, Deserialize)]
struct Hash {
    algorithm: String,
    digest: String,
    #[serde(default)]
    reason: String,
}

/// The blocks of a blocklist file, in file order: packages, then hashes. A blank reason
/// is kept as none.
pub fn import(text: &str) -> Result<Vec<Block>, String> {
    let file: File =
        serde_json::from_str(text).map_err(|err| format!("not a blocklist file: {err}"))?;
    if file.schema_version != 1 {
        return Err(format!("schema_version {} is not 1", file.schema_version));
    }
    let reason = |text: String| Some(text.trim().to_owned()).filter(|text| !text.is_empty());
    let mut blocks = Vec::with_capacity(file.blocked_packages.len() + file.blocked_hashes.len());
    for (index, record) in file.blocked_packages.into_iter().enumerate() {
        let ecosystem = Ecosystem::from_tag(&record.ecosystem).ok_or_else(|| {
            format!(
                "blocked_packages[{index}]: `{}` is not npm or pypi",
                record.ecosystem
            )
        })?;
        blocks.push(match record.version {
            Some(version) => Block::Version {
                ecosystem,
                name: record.name,
                version,
                reason: reason(record.reason),
            },
            None => Block::Package {
                ecosystem,
                name: record.name,
                reason: reason(record.reason),
            },
        });
    }
    for (index, record) in file.blocked_hashes.into_iter().enumerate() {
        let (algorithm, length) = match record.algorithm.as_str() {
            "sha256" => (DigestAlgorithm::Sha256, 64),
            "sha512" => (DigestAlgorithm::Sha512, 128),
            other => {
                return Err(format!(
                    "blocked_hashes[{index}]: `{other}` is not sha256 or sha512"
                ));
            }
        };
        let digest = record.digest.to_ascii_lowercase();
        if digest.len() != length || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(format!(
                "blocked_hashes[{index}]: not a {} digest in hex",
                record.algorithm
            ));
        }
        blocks.push(Block::File {
            algorithm,
            digest,
            reason: reason(record.reason),
        });
    }
    Ok(blocks)
}

/// `blocks` as a blocklist file with the given header values.
pub fn export(blocks: &[Block], revision: u64, generated_at: &str, expires_at: &str) -> String {
    let reason = |reason: &Option<String>| reason.clone().unwrap_or_else(|| NO_REASON.to_owned());
    let mut file = File {
        schema_version: 1,
        revision,
        generated_at: generated_at.to_owned(),
        expires_at: expires_at.to_owned(),
        blocked_packages: Vec::new(),
        blocked_hashes: Vec::new(),
    };
    for block in blocks {
        match block {
            Block::Package {
                ecosystem,
                name,
                reason: why,
            } => file.blocked_packages.push(Package {
                ecosystem: ecosystem.as_tag().to_owned(),
                name: name.clone(),
                version: None,
                reason: reason(why),
            }),
            Block::Version {
                ecosystem,
                name,
                version,
                reason: why,
            } => file.blocked_packages.push(Package {
                ecosystem: ecosystem.as_tag().to_owned(),
                name: name.clone(),
                version: Some(version.clone()),
                reason: reason(why),
            }),
            Block::File {
                algorithm,
                digest,
                reason: why,
            } => file.blocked_hashes.push(Hash {
                algorithm: match algorithm {
                    DigestAlgorithm::Sha256 => "sha256",
                    DigestAlgorithm::Sha512 => "sha512",
                }
                .to_owned(),
                digest: digest.clone(),
                reason: reason(why),
            }),
        }
    }
    serde_json::to_string_pretty(&file).expect("a blocklist file encodes")
}
