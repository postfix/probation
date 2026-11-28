//! The persisted matched OSV entries of a managed endpoint (LS-F11, C1031): a small text
//! file under the data directory so a restart during a server outage keeps refusing
//! known-malicious packages.
//!
//! Line 1 is [`HEADER`]; every other line is one JSON record of at most
//! [`MAX_RECORD`] bytes `{"e":..,"n":..,"v":..,"x":<expiry unix seconds>,"c":<crc32>}`.
//! Each line is validated on its own, so one bad record never costs the rest. The CRC
//! detects accidental corruption only; the file is mode 0600 and trusted.

use std::collections::HashMap;
use std::io::Write as _;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use probation_policy::Ecosystem;
use probation_policy::osv_key::osv_key;
use serde::Deserialize;

pub const HEADER: &str = "probation-osv-matches v1";
pub const MAX_ENTRIES: usize = 100_000;
pub const MAX_BYTES: usize = 16 << 20;
/// A record carries a name and a version of up to 1024 bytes each (osv_key's limits).
pub const MAX_RECORD: usize = 2304;

/// One persisted match.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Match {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: String,
    /// Absolute wall-clock expiry, unix seconds.
    pub expiry_unix: u64,
}

#[derive(Default, Debug)]
pub struct LoadedMatches {
    pub entries: Vec<Match>,
    /// Invalid lines, for `osv_matches_records_skipped`.
    pub skipped: u64,
    /// False for a missing or unknown header (the whole file loads empty).
    pub header_ok: bool,
}

pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    e: String,
    n: String,
    v: String,
    x: u64,
    c: String,
}

fn checksum(eco: &str, name: &str, version: &str, x: u64) -> String {
    format!(
        "{:08x}",
        crc32(format!("{eco}|{name}|{version}|{x}").as_bytes())
    )
}

/// Parses `bytes` (the caller reads at most [`MAX_BYTES`]). Expired records are pruned,
/// expiries are clamped to `now + window`, a later duplicate wins and records beyond
/// [`MAX_ENTRIES`] drop the nearest expiry.
pub fn load_matches(bytes: &[u8], now: SystemTime, window: Duration) -> LoadedMatches {
    let mut loaded = LoadedMatches::default();
    let Some(newline) = bytes.iter().position(|b| *b == b'\n') else {
        return loaded;
    };
    if &bytes[..newline] != HEADER.as_bytes() {
        return loaded;
    }
    loaded.header_ok = true;
    let now_unix = now.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let ceiling = now_unix.saturating_add(window.as_secs());
    let mut by_key: HashMap<(Ecosystem, String, String), u64> = HashMap::new();
    let mut rest = &bytes[newline + 1..];
    while !rest.is_empty() {
        let (line, terminated) = match rest.iter().position(|b| *b == b'\n') {
            Some(end) => {
                let line = &rest[..end];
                rest = &rest[end + 1..];
                (line, true)
            }
            None => {
                let line = rest;
                rest = &[];
                (line, false)
            }
        };
        let record = (|| {
            if !terminated || line.len() > MAX_RECORD {
                return None;
            }
            let record: Record = serde_json::from_slice(line).ok()?;
            let ecosystem = Ecosystem::from_tag(&record.e)?;
            osv_key(ecosystem, &record.n, &record.v).ok()?;
            (checksum(&record.e, &record.n, &record.v, record.x) == record.c)
                .then_some((ecosystem, record.n, record.v, record.x))
        })();
        match record {
            None => loaded.skipped += 1,
            Some((ecosystem, name, version, x)) => {
                if x > now_unix {
                    by_key.insert((ecosystem, name, version), x.min(ceiling));
                }
            }
        }
    }
    let mut entries: Vec<Match> = by_key
        .into_iter()
        .map(|((ecosystem, name, version), expiry_unix)| Match {
            ecosystem,
            name,
            version,
            expiry_unix,
        })
        .collect();
    entries.sort_by(|a, b| {
        b.expiry_unix
            .cmp(&a.expiry_unix)
            .then_with(|| a.name.cmp(&b.name))
    });
    entries.truncate(MAX_ENTRIES);
    loaded.entries = entries;
    loaded
}

pub struct Rendered {
    pub bytes: Vec<u8>,
    /// Entries left out because the file would exceed its bounds.
    pub dropped: usize,
}

/// The file for `entries`, dropping the nearest expiry first when over the entry or byte cap.
pub fn render_matches(entries: &[(Ecosystem, String, String, u64)]) -> Rendered {
    let mut sorted: Vec<&(Ecosystem, String, String, u64)> = entries.iter().collect();
    sorted.sort_by_key(|entry| std::cmp::Reverse(entry.3));
    let mut bytes = format!("{HEADER}\n").into_bytes();
    let mut kept = 0;
    for (ecosystem, name, version, x) in sorted {
        let tag = ecosystem.as_tag();
        let line = format!(
            r#"{{"e":"{tag}","n":{},"v":{},"x":{x},"c":"{}"}}"#,
            serde_json::Value::from(name.as_str()),
            serde_json::Value::from(version.as_str()),
            checksum(tag, name, version, *x)
        ) + "\n";
        if kept >= MAX_ENTRIES || bytes.len() + line.len() > MAX_BYTES || line.len() > MAX_RECORD {
            continue;
        }
        bytes.extend_from_slice(line.as_bytes());
        kept += 1;
    }
    Rendered {
        bytes,
        dropped: entries.len() - kept,
    }
}

/// Temp file in the same directory, owner-only (0600 on Unix, the directory's restricted ACL on Windows), fsync, rename,
/// directory fsync (a documented no-op on Windows, `crate::config::sync_directory`).
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    // A name of its own per write, so two writers can never share an inode.
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let unique = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let temp = dir.join(format!(".osv-matches.{}.{unique}.tmp", std::process::id()));
    let result = (|| {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        let mut file = crate::delivery::owner_only(&mut options).open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&temp, path)?;
        crate::config::sync_directory(dir)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

/// The file's content if it can be read within the size bound, else `None` (unreadable,
/// absent or over [`MAX_BYTES`]).
pub fn read_bounded(path: &Path) -> Option<Vec<u8>> {
    use std::io::Read as _;
    let file = std::fs::File::open(path).ok()?;
    let mut bytes = Vec::new();
    file.take(MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    (bytes.len() <= MAX_BYTES).then_some(bytes)
}
