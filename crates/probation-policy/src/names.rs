//! The one name and version normaliser (T6), shared by the firewall, the management
//! server and the policy merge, so a block written as `Foo_Bar` lands where `foo-bar` is
//! looked up on every side.

use std::str::FromStr;

use crate::Ecosystem;

/// npm's and PyPI's own limit on a name.
const MAX_NAME_LENGTH: usize = 214;

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
    }
}

/// Whether `name` is a name the ecosystem could have published. PyPI uses PEP 508's
/// name rule. npm gets the checks that matter for a stored policy row (non-empty,
/// bounded, no padding or control characters); the firewall's route validator stays
/// the stricter gate on what reaches upstream.
pub fn valid_name(ecosystem: Ecosystem, name: &str) -> bool {
    if name.is_empty() || name.len() > MAX_NAME_LENGTH {
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
    }
}

/// A version in the form its ecosystem compares by: npm by semver precedence, PyPI by
/// PEP 440 equality, so equivalent spellings match (SPEC §7).
#[derive(Debug, PartialEq)]
pub enum CanonicalVersion {
    Npm(Box<nodejs_semver::Version>),
    PyPi(Box<pep440_rs::Version>),
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
    }
}

/// The same release: an identical spelling, or equal canonical forms.
pub fn same_version(ecosystem: Ecosystem, a: &str, b: &str) -> bool {
    a == b
        || matches!(
            (canonical_version(ecosystem, a), canonical_version(ecosystem, b)),
            (Some(a), Some(b)) if a == b
        )
}
