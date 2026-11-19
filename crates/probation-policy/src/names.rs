//! The one name and version normaliser (T6), shared by the firewall, the management
//! server and the policy merge, so a block written as `Foo_Bar` lands where `foo-bar` is
//! looked up on every side.

use std::str::FromStr;

use crate::Ecosystem;

/// npm's and PyPI's own limit on a name.
const MAX_NAME_LENGTH: usize = 214;
/// Cargo's routing bound (crates.io itself allows 64): generous so no registry's valid name is refused.
const MAX_CARGO_NAME_LENGTH: usize = 128;

/// PEP 503: lowercase, and each run of `-`, `_` or `.` becomes a single `-`.
pub fn normalize(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut in_separator = false;
    for c in raw.chars() {
        if matches!(c, '-' | '_' | '.') {
            if !in_separator {
                out.push('-');
                in_separator = true;
            }
        } else {
            in_separator = false;
            out.extend(c.to_lowercase());
        }
    }
    out
}

/// The spelling a name is stored and judged under: PEP 503 for PyPI. npm names are
/// identifiers and are kept exactly as written.
pub fn canonical_name(ecosystem: Ecosystem, name: &str) -> String {
    match ecosystem {
        Ecosystem::Npm => name.to_owned(),
        Ecosystem::PyPi => normalize(name),
        // rubygems.org answers `/info/Rack` with the index of `rack` (checked 2026-11-19), so
        // the registry namespace is case-insensitive and policy must be too.
        Ecosystem::RubyGems => name.to_ascii_lowercase(),
        // crates.io: names are case-insensitive and `-` and `_` are the same character (the
        // registry refuses a second crate that differs only in them). OSV answers both spellings.
        Ecosystem::Cargo => name.to_ascii_lowercase().replace('_', "-"),
    }
}

/// Whether `name` is a name the ecosystem could have published. PyPI uses PEP 508's
/// name rule. npm gets the checks that matter for a stored policy row (non-empty,
/// bounded, no padding or control characters); the firewall's route validator stays
/// the stricter gate on what reaches upstream.
pub fn valid_name(ecosystem: Ecosystem, name: &str) -> bool {
    let limit = if ecosystem == Ecosystem::Cargo { MAX_CARGO_NAME_LENGTH } else { MAX_NAME_LENGTH };
    if name.is_empty() || name.len() > limit {
        return false;
    }
    match ecosystem {
        Ecosystem::Npm => name.trim() == name && !name.chars().any(char::is_control),
        Ecosystem::PyPi => {
            let edge = |c: Option<char>| c.is_some_and(|c| c.is_ascii_alphanumeric());
            edge(name.chars().next())
                && edge(name.chars().next_back())
                && name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        }
        // The charset of LS-F6 for RubyGems: one validator for what is judged and what is queried.
        Ecosystem::RubyGems => name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_')),
        // LS-F6 for Cargo: `[A-Za-z0-9_-]`. Deliberately not crates.io's stricter publishing rules
        // (first character, 64 bytes): a block must be accepted for any name a registry could hold.
        Ecosystem::Cargo => name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')),
    }
}

/// A version in the form its ecosystem compares by: npm by semver precedence, PyPI by
/// PEP 440 equality, so equivalent spellings match (SPEC §7).
#[derive(Debug, PartialEq)]
pub enum CanonicalVersion {
    Npm(Box<nodejs_semver::Version>),
    PyPi(Box<pep440_rs::Version>),
    RubyGems(Vec<GemSegment>),
    /// SemVer 2 with the build metadata dropped (it takes no part in precedence or identity here).
    Cargo(Box<semver::Version>),
}

/// One segment of a `Gem::Version` (`Gem::Version#canonical_segments`). Numbers are kept as
/// digit strings without leading zeros, so no segment length is out of range.
#[derive(Debug, PartialEq, Eq)]
pub enum GemSegment {
    Num(String),
    Str(String),
}

/// A version the ecosystem's parser rejects has no canonical form and keeps only its
/// exact spelling — an odd spelling narrows a match, it never widens one.
pub fn canonical_version(ecosystem: Ecosystem, version: &str) -> Option<CanonicalVersion> {
    match ecosystem {
        Ecosystem::Npm => nodejs_semver::Version::parse(version)
            .ok()
            .map(|parsed| CanonicalVersion::Npm(Box::new(parsed))),
        Ecosystem::PyPi => pep440_rs::Version::from_str(version)
            .ok()
            .map(|parsed| CanonicalVersion::PyPi(Box::new(parsed))),
        Ecosystem::RubyGems => gem_segments(version).map(CanonicalVersion::RubyGems),
        Ecosystem::Cargo => semver::Version::parse(version).ok().map(|mut parsed| {
            parsed.build = semver::BuildMetadata::EMPTY;
            CanonicalVersion::Cargo(Box::new(parsed))
        }),
    }
}

/// Ruby's own `Gem::Version.correct?` pattern
/// `\A\s*([0-9]+(?>\.[0-9a-zA-Z]+)*(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?)?\s*\z`, an empty
/// string excluded (it is not a version a rule can name).
fn gem_version_correct(text: &str) -> bool {
    let alnum = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric());
    let (head, tail) = match text.split_once('-') {
        Some((head, tail)) => (head, Some(tail)),
        None => (text, None),
    };
    let mut parts = head.split('.');
    let first = parts.next().unwrap_or("");
    let head_ok = !first.is_empty() && first.bytes().all(|b| b.is_ascii_digit()) && parts.all(alnum);
    let tail_ok = tail.is_none_or(|t| t.split('.').all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')));
    head_ok && tail_ok
}

/// `Gem::Version#canonical_segments`: every `-` becomes `.pre.`, segments are the runs of
/// digits or letters (letters keep their case, as Ruby compares them), and trailing zeros
/// are dropped from the numeric part and from the part after the first letter segment.
fn gem_segments(version: &str) -> Option<Vec<GemSegment>> {
    let text = version.trim();
    if !gem_version_correct(text) {
        return None;
    }
    let text = text.replace('-', ".pre.");
    let mut numeric: Vec<GemSegment> = Vec::new();
    let mut rest: Vec<GemSegment> = Vec::new();
    for piece in text.split('.') {
        let mut remaining = piece;
        while !remaining.is_empty() {
            let digits = remaining.starts_with(|c: char| c.is_ascii_digit());
            let end = remaining.find(|c: char| c.is_ascii_digit() != digits).unwrap_or(remaining.len());
            let (head, tail) = remaining.split_at(end);
            let seg = if digits {
                let trimmed = head.trim_start_matches('0');
                GemSegment::Num(if trimmed.is_empty() { "0".to_owned() } else { trimmed.to_owned() })
            } else {
                GemSegment::Str(head.to_owned())
            };
            if !rest.is_empty() || matches!(seg, GemSegment::Str(_)) {
                rest.push(seg);
            } else {
                numeric.push(seg);
            }
            remaining = tail;
        }
    }
    let zero = |s: &GemSegment| matches!(s, GemSegment::Num(n) if n == "0");
    while numeric.last().is_some_and(zero) {
        numeric.pop();
    }
    while rest.last().is_some_and(zero) {
        rest.pop();
    }
    numeric.extend(rest);
    Some(numeric)
}

/// The same release: an identical spelling, or equal canonical forms.
pub fn same_version(ecosystem: Ecosystem, a: &str, b: &str) -> bool {
    a == b
        || matches!(
            (canonical_version(ecosystem, a), canonical_version(ecosystem, b)),
            (Some(a), Some(b)) if a == b
        )
}
