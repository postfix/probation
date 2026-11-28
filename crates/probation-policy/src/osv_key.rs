//! LS-F6: the one OSV key function. The client calls it when building a query and the
//! server when validating one, so neither side is stricter than the other. It validates
//! and never normalises (PEP 503 and PEP 440 normalisation stay in the adapters).

use crate::Ecosystem;

/// The ecosystems' real maxima, not tighter: a publisher must not be able to pick a name or
/// version this function refuses and so skip the OSV check (SEC-1; npm names 214, npm
/// versions 256). PyPI (pypi/warehouse, researched 2026-11-18): `MAX_VERSION_LENGTH` is 128 after
/// PEP 440 normalisation in forklift/metadata.py, enforced for new uploads only (the database
/// column is `Text`, so older or backfilled releases may exceed 128); project names have no
/// explicit length limit in code (only the `projects_valid_name` regex and a `Text` column),
/// but an upload with a name in its filename is bounded by the filesystem ("Filename is too
/// long" is rejected). 1024 therefore covers every new upload; a key beyond it is counted and
/// visible (`osv_keys_refused`), not held.
pub const MAX_NAME: usize = 1024;
pub const MAX_VERSION: usize = 1024;
pub const MAX_ECOSYSTEM: usize = 32;

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct OsvKey {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: String,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OsvKeyError {
    Name,
    Version,
}

fn name_ok(ecosystem: Ecosystem, name: &str) -> bool {
    if name.is_empty() || name.len() > MAX_NAME {
        return false;
    }
    match ecosystem {
        Ecosystem::Npm => {
            let plain = |s: &str| {
                !s.is_empty()
                    && s.bytes().all(|b| {
                        b.is_ascii_alphanumeric()
                            || matches!(
                                b,
                                b'.' | b'_' | b'~' | b'-' | b'!' | b'\'' | b'(' | b')' | b'*'
                            )
                    })
            };
            match name.strip_prefix('@') {
                Some(scoped) => scoped
                    .split_once('/')
                    .is_some_and(|(scope, rest)| plain(scope) && plain(rest)),
                None => plain(name),
            }
        }
        Ecosystem::PyPi => name
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-')),
        // LS-F6: gem name `[A-Za-z0-9._-]`, case kept (validated, never normalised).
        Ecosystem::RubyGems => name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')),
        // LS-F6: crate name `[A-Za-z0-9_-]`, validated and never normalised.
        Ecosystem::Cargo => name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-')),
        // LS-F6: decoded module path `[A-Za-z0-9._~/-]`, case kept; the `!`-escaped proxy form is a key error.
        Ecosystem::Go => name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'-' | b'/')),
        // LS-F6: package id `[A-Za-z0-9._-]`, validated and never normalised (OSV answers any case).
        Ecosystem::NuGet => name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')),
        // LS-F6: `groupId:artifactId`, each part `[A-Za-z0-9._-]`, exactly one `:`, case kept.
        Ecosystem::Maven => crate::names::valid_maven_name(name),
        // LS-F6: the package name, `[A-Za-z0-9_][A-Za-z0-9_+.-]*`, case kept (OSV's `ConanCenter` ecosystem keys by name).
        Ecosystem::Conan => crate::names::valid_conan_part(name),
        // OSV has no image ecosystem: no key is ever made; the repository name rule is the one validator.
        Ecosystem::Oci => crate::names::valid_oci_name(name),
    }
}

/// Printable ASCII without spaces, 1 to `MAX_VERSION` (1024) bytes.
fn version_ok(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= MAX_VERSION
        && version.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

pub fn osv_key(ecosystem: Ecosystem, name: &str, version: &str) -> Result<OsvKey, OsvKeyError> {
    if !name_ok(ecosystem, name) {
        return Err(OsvKeyError::Name);
    }
    if !version_ok(version) {
        return Err(OsvKeyError::Version);
    }
    Ok(OsvKey {
        ecosystem,
        name: name.to_owned(),
        version: version.to_owned(),
    })
}
