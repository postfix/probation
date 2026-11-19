//! The Cargo sparse index: path rules, one JSON line per version, and the `config.json` of the
//! registry. A filter keeps every line it does not drop byte for byte (the `cksum`, `features`,
//! `features2`, `yanked`, `rust_version` and `deps` fields are never re-encoded).

use serde::Deserialize;
use url::Url;

use crate::policy::{Digest, HashAlgorithm};

/// The largest crate name routed (crates.io itself allows 64).
pub const MAX_NAME: usize = 128;

/// A crate name as the index spells a path: `[A-Za-z0-9_-]`, bounded (LS-F6).
pub fn valid_crate_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= MAX_NAME && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

/// The path segments of the index file of `lower` (already lower case): `1/a`, `2/ab`,
/// `3/a/abc` and `ab/cd/abcd`.
pub fn index_segments(lower: &str) -> Vec<String> {
    match lower.len() {
        1 => vec!["1".to_owned(), lower.to_owned()],
        2 => vec!["2".to_owned(), lower.to_owned()],
        3 => vec!["3".to_owned(), lower[..1].to_owned(), lower.to_owned()],
        _ => vec![lower[..2].to_owned(), lower[2..4].to_owned(), lower.to_owned()],
    }
}

/// The crate name an index path names, or `None` when the path is not exactly the one the
/// sparse layout builds for a lower-case name: Cargo always lower-cases, so an upper-case
/// spelling or a prefix that does not belong to the name is no index file at all.
pub fn name_of_path(segments: &[&str]) -> Option<String> {
    let name = *segments.last()?;
    if !valid_crate_name(name) || name.bytes().any(|b| b.is_ascii_uppercase()) {
        return None;
    }
    (index_segments(name).iter().map(String::as_str).eq(segments.iter().copied())).then(|| name.to_owned())
}

/// One line of an index file: a version of one crate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The crate name as the line spells it (case and `-`/`_` exactly as published).
    pub name: String,
    /// The version as published, build metadata included: the archive and its file name carry it.
    pub vers: String,
    pub cksum: [u8; 32],
    pub yanked: bool,
    /// `pubtime` (crates.io) or `created_at`: the registry's own publication time. When both
    /// are present the later one is used, so a disagreement can only hold a version longer.
    pub published_micros: Option<i64>,
    /// The line as upstream wrote it, without its newline.
    pub line: String,
}

impl Entry {
    /// The version policy and OSV see: SemVer with the build metadata dropped (LS-F6).
    pub fn policy_version(&self) -> String {
        strip_build(&self.vers).to_owned()
    }

    /// `{name}-{vers}.crate`, the archive's identity.
    pub fn filename(&self) -> String {
        format!("{}-{}.crate", self.name, self.vers)
    }

    pub fn expected(&self) -> Vec<Digest> {
        vec![Digest { algorithm: HashAlgorithm::Sha256, bytes: Box::from(self.cksum.as_slice()) }]
    }
}

/// `1.0.0-rc.1+build` -> `1.0.0-rc.1`.
pub fn strip_build(vers: &str) -> &str {
    vers.split_once('+').map_or(vers, |(head, _)| head)
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum IndexError {
    NotUtf8,
    /// Two lines name the same version.
    Duplicate,
    TooMany,
    /// A document with lines, none of which is usable.
    NothingUsable,
    /// A line names another crate than the file does.
    OtherCrate,
}

#[derive(Deserialize)]
struct Line {
    name: String,
    vers: String,
    cksum: String,
    yanked: bool,
    #[serde(default)]
    pubtime: Option<String>,
    #[serde(default)]
    created_at: Option<String>,
}

fn micros(text: &Option<String>) -> Option<i64> {
    text.as_deref().and_then(|text| text.parse::<jiff::Timestamp>().ok()).map(|t| t.as_microsecond())
}

/// Parses an index file for the crate whose lower-case name is `lower`. A line that is not a
/// well-formed entry (not JSON, an unknown shape, a version that is not SemVer, a checksum that
/// is not 64 hex digits) is dropped, never delivered; the same line fails in Cargo. The document
/// is refused when no line is usable, when two lines name one version, when a line names another
/// crate, or when it has more than `max_entries` lines.
pub fn parse_index(body: &[u8], lower: &str, max_entries: usize) -> Result<Vec<Entry>, IndexError> {
    let text = std::str::from_utf8(body).map_err(|_| IndexError::NotUtf8)?;
    let mut entries: Vec<Entry> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut lines = 0usize;
    for raw in text.split('\n') {
        let raw = raw.strip_suffix('\r').unwrap_or(raw);
        if raw.trim().is_empty() {
            continue;
        }
        lines += 1;
        if lines > max_entries {
            return Err(IndexError::TooMany);
        }
        let Ok(parsed) = serde_json::from_str::<Line>(raw) else { continue };
        let mut cksum = [0u8; 32];
        if parsed.cksum.len() != 64 || hex::decode_to_slice(&parsed.cksum, &mut cksum).is_err() || semver::Version::parse(&parsed.vers).is_err() {
            continue;
        }
        if !valid_crate_name(&parsed.name) {
            continue;
        }
        if !parsed.name.eq_ignore_ascii_case(lower) {
            return Err(IndexError::OtherCrate);
        }
        if !seen.insert(parsed.vers.clone()) {
            return Err(IndexError::Duplicate);
        }
        let published_micros = match (micros(&parsed.pubtime), micros(&parsed.created_at)) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        };
        entries.push(Entry { name: parsed.name, vers: parsed.vers, cksum, yanked: parsed.yanked, published_micros, line: raw.to_owned() });
    }
    if lines > 0 && entries.is_empty() {
        return Err(IndexError::NothingUsable);
    }
    Ok(entries)
}

/// The index file of the kept entries: each kept line unchanged and newline-terminated.
pub fn render_index<'a>(kept: impl IntoIterator<Item = &'a Entry>) -> Vec<u8> {
    let mut out = String::new();
    for entry in kept {
        out.push_str(&entry.line);
        out.push('\n');
    }
    out.into_bytes()
}

/// `config.json` of a registry: where the archives live and, optionally, the API root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpstreamConfig {
    pub dl: String,
    pub api: Option<String>,
    pub auth_required: bool,
}

#[derive(Deserialize)]
struct RawConfig {
    dl: String,
    #[serde(default)]
    api: Option<String>,
    #[serde(default, rename = "auth-required")]
    auth_required: bool,
}

pub fn parse_config(body: &[u8]) -> Option<UpstreamConfig> {
    let raw: RawConfig = serde_json::from_slice(body).ok()?;
    (raw.dl.len() <= 2048 && raw.api.as_ref().is_none_or(|api| api.len() <= 2048))
        .then_some(UpstreamConfig { dl: raw.dl, api: raw.api, auth_required: raw.auth_required })
}

/// The URL of one archive from the registry's `dl`: the cargo markers `{crate}`, `{version}`,
/// `{prefix}`, `{lowerprefix}` and `{sha256-checksum}` are replaced, and a `dl` with none of
/// them gets `/{crate}/{version}/download` appended. `None` for a value that is not an absolute
/// http(s) URL, or one that carries userinfo, a query or a fragment.
pub fn archive_url(dl: &str, name: &str, vers: &str, cksum_hex: &str) -> Option<Url> {
    const MARKERS: [&str; 5] = ["{crate}", "{version}", "{prefix}", "{lowerprefix}", "{sha256-checksum}"];
    // The directory part only: `ab/cd` for `abcd...`, `3/a` for `abc`, `1` and `2` for short names.
    let directory = |name: &str| {
        let mut segments = index_segments(name);
        segments.pop();
        segments.join("/")
    };
    let (prefix, lowerprefix) = (directory(name), directory(&name.to_ascii_lowercase()));
    let text = if MARKERS.iter().any(|marker| dl.contains(marker)) {
        dl.replace("{crate}", name)
            .replace("{version}", vers)
            .replace("{prefix}", &prefix)
            .replace("{lowerprefix}", &lowerprefix)
            .replace("{sha256-checksum}", cksum_hex)
    } else {
        format!("{}/{name}/{vers}/download", dl.trim_end_matches('/'))
    };
    let url = Url::parse(&text).ok()?;
    (matches!(url.scheme(), "http" | "https") && url.host_str().is_some() && url.username().is_empty() && url.password().is_none() && url.query().is_none() && url.fragment().is_none()).then_some(url)
}
