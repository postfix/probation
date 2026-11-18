//! LS-F6: the one OSV key function. The client calls it when building a query and the
//! server when validating one, so neither side is stricter than the other. It validates
//! and never normalises (PEP 503 and PEP 440 normalisation stay in the adapters).

use crate::Ecosystem;

/// The ecosystems' real maxima, not tighter: a publisher must not be able to pick a name or
/// version this function refuses and so skip the OSV check (SEC-1; npm names 214, npm
/// versions 256, PyPI has no practical cap).
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
                !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'-' | b'!' | b'\'' | b'(' | b')' | b'*'))
            };
            match name.strip_prefix('@') {
                Some(scoped) => scoped.split_once('/').is_some_and(|(scope, rest)| plain(scope) && plain(rest)),
                None => plain(name),
            }
        }
        Ecosystem::PyPi => name.bytes().all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-')),
    }
}

/// Printable ASCII without spaces, 1 to 128 bytes.
fn version_ok(version: &str) -> bool {
    !version.is_empty() && version.len() <= MAX_VERSION && version.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

pub fn osv_key(ecosystem: Ecosystem, name: &str, version: &str) -> Result<OsvKey, OsvKeyError> {
    if !name_ok(ecosystem, name) {
        return Err(OsvKeyError::Name);
    }
    if !version_ok(version) {
        return Err(OsvKeyError::Version);
    }
    Ok(OsvKey { ecosystem, name: name.to_owned(), version: version.to_owned() })
}
