//! The RubyGems compact index (`/info/{gem}`): parsing, filtering and the gem file name
//! rules. Plaintext, so a filter keeps every line it does not drop byte for byte and
//! never re-encodes one (native encodings and the per-version `checksum:` stay intact).

use std::collections::BTreeMap;

use url::Url;

use crate::policy::{Digest, HashAlgorithm};

/// One line of an info file: a version (and platform) of one gem.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub version: String,
    /// `None` is the `ruby` platform, which the compact index leaves out of the line.
    pub platform: Option<String>,
    /// The line as upstream wrote it, without its newline.
    pub line: String,
    pub sha256: Option<[u8; 32]>,
    /// `created_at:` in the requirements part, when the registry provides it (rubygems.org does).
    pub created_micros: Option<i64>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum InfoError {
    NotUtf8,
    /// The first line is not `---`.
    Header,
    /// A line whose version or platform is not a valid RubyGems spelling, with the 1-based line.
    Line(usize),
    /// Two lines name the same version and platform.
    Duplicate,
    TooMany,
}

fn version_ok(v: &str) -> bool {
    let mut parts = v.split('.');
    let first = parts.next().unwrap_or("");
    !first.is_empty()
        && first.bytes().all(|b| b.is_ascii_digit())
        && parts.all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_alphanumeric()))
}

fn platform_ok(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= 128
        && p.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

impl Entry {
    /// `{name}-{version}[-{platform}].gem`, the file the client asks for.
    pub fn gem_filename(&self, name: &str) -> String {
        match &self.platform {
            Some(platform) => format!("{name}-{}-{platform}.gem", self.version),
            None => format!("{name}-{}.gem", self.version),
        }
    }

    /// The text after the name in a file name: `version` or `version-platform`.
    pub fn suffix(&self) -> String {
        match &self.platform {
            Some(platform) => format!("{}-{platform}", self.version),
            None => self.version.clone(),
        }
    }

    pub fn expected(&self) -> Vec<Digest> {
        self.sha256
            .map(|bytes| Digest {
                algorithm: HashAlgorithm::Sha256,
                bytes: Box::from(bytes.as_slice()),
            })
            .into_iter()
            .collect()
    }
}

/// Parses an info file. `max_entries` bounds the work one document can cause (the
/// `max_references_per_project` setting).
pub fn parse_info(body: &[u8], max_entries: usize) -> Result<Vec<Entry>, InfoError> {
    let text = std::str::from_utf8(body).map_err(|_| InfoError::NotUtf8)?;
    let mut lines = text.split('\n');
    if lines.next() != Some("---") {
        return Err(InfoError::Header);
    }
    let mut entries = Vec::new();
    let mut seen = BTreeMap::new();
    for (index, line) in lines.enumerate() {
        if line.is_empty() {
            continue;
        }
        let bad = || InfoError::Line(index + 2);
        let (head, rest) = line.split_once(' ').ok_or_else(bad)?;
        let (version, platform) = match head.split_once('-') {
            Some((version, platform)) => (version, Some(platform)),
            None => (head, None),
        };
        if !version_ok(version) || platform.is_some_and(|p| !platform_ok(p)) {
            return Err(bad());
        }
        let (mut sha256, mut created_micros) = (None, None);
        if let Some((_, requirements)) = rest.split_once('|') {
            for token in requirements.split(',') {
                match token.split_once(':') {
                    Some(("checksum", hex)) => {
                        let mut bytes = [0u8; 32];
                        if hex::decode_to_slice(hex, &mut bytes).is_ok() {
                            sha256 = Some(bytes);
                        }
                    }
                    Some(("created_at", at)) => {
                        created_micros = at
                            .parse::<jiff::Timestamp>()
                            .ok()
                            .map(|t| t.as_microsecond());
                    }
                    _ => {}
                }
            }
        }
        if seen.insert((version, platform), ()).is_some() {
            return Err(InfoError::Duplicate);
        }
        if entries.len() >= max_entries {
            return Err(InfoError::TooMany);
        }
        entries.push(Entry {
            version: version.to_owned(),
            platform: platform.map(str::to_owned),
            line: line.to_owned(),
            sha256,
            created_micros,
        });
    }
    Ok(entries)
}

/// The info file of the kept entries: the header and each kept line unchanged.
pub fn render_info<'a>(kept: impl IntoIterator<Item = &'a Entry>) -> Vec<u8> {
    let mut out = String::from("---\n");
    for entry in kept {
        out.push_str(&entry.line);
        out.push('\n');
    }
    out.into_bytes()
}

/// Gem names as RubyGems spells them (LS-F6 charset) and bounded.
pub fn valid_gem_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && !name.starts_with(['-', '.'])
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Every way a file name `{name}-{rest}.gem` can split into a gem name and a
/// `version[-platform]` suffix: at each `-` whose right side starts with a digit. The
/// caller resolves which split is real against the index and refuses when more than one
/// is (ambiguity refuses, it never guesses).
pub fn filename_candidates(filename: &str) -> Vec<(String, String)> {
    let Some(stem) = filename.strip_suffix(".gem") else {
        return Vec::new();
    };
    stem.match_indices('-')
        .filter(|(at, _)| stem[at + 1..].starts_with(|c: char| c.is_ascii_digit()) && *at > 0)
        .map(|(at, _)| (stem[..at].to_owned(), stem[at + 1..].to_owned()))
        .filter(|(name, rest)| {
            let version = rest.split('-').next().unwrap_or("");
            valid_gem_name(name)
                && rest.len() <= 160
                && version_ok(version)
                && rest
                    .split_once('-')
                    .is_none_or(|(_, platform)| platform_ok(platform))
        })
        .collect()
}

/// The upstream URL of a gem file under `origin` (`{origin}/gems/{file}`).
pub fn gem_url(origin: &Url, filename: &str) -> Option<Url> {
    let mut url = origin.clone();
    url.path_segments_mut()
        .ok()?
        .pop_if_empty()
        .push("gems")
        .push(filename);
    Some(url)
}
