//! What names an artifact: the exact reference of SPEC §5, and the lookup key
//! SPEC §9 derives from it.
//!
//! Slice 5 built both of these in `src/store/rows.rs`, because a rewritten tarball
//! URL *is* a reference id and `src/artifacts/` did not exist yet. They live here
//! now, where Gate 3 put them, and `store::rows` re-exports them so every call site
//! that learned the old path keeps working.

use std::fmt;

use sha2::{Digest as _, Sha256};
use url::Url;

use crate::policy::{Digest, Ecosystem};

/// One artifact, named exactly as SPEC §5 requires: "ecosystem, normalized package
/// name, upstream version, filename, upstream URL, and expected integrity digests".
/// Change any of them and it is a different reference, never the same one with new
/// bytes behind it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactReference {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: String,
    pub filename: String,
    pub upstream_url: Url,
    pub expected: Vec<Digest>,
}

/// A lookup key — not a content hash, and not an authorization token (SPEC §9).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct ReferenceId([u8; 32]);

impl ReferenceId {
    /// SHA-256 over a length-prefixed encoding of the exact reference: for each part
    /// a `u32` big-endian byte length followed by the bytes, in the fixed order
    /// ecosystem tag, name, version, filename, upstream URL, then the count of
    /// expected digests and each (algorithm name, digest bytes) sorted by algorithm
    /// and bytes.
    ///
    /// Length prefixes rather than separators, so no concatenation of two fields can
    /// impersonate a different split of the same bytes.
    pub fn compute(reference: &ArtifactReference) -> ReferenceId {
        fn part(hasher: &mut Sha256, bytes: &[u8]) {
            hasher.update((bytes.len() as u32).to_be_bytes());
            hasher.update(bytes);
        }

        let mut hasher = Sha256::new();
        part(&mut hasher, reference.ecosystem.as_tag().as_bytes());
        part(&mut hasher, reference.name.as_bytes());
        part(&mut hasher, reference.version.as_bytes());
        part(&mut hasher, reference.filename.as_bytes());
        part(&mut hasher, reference.upstream_url.as_str().as_bytes());

        let mut digests: Vec<&Digest> = reference.expected.iter().collect();
        digests.sort_by(|left, right| {
            left.algorithm
                .name()
                .cmp(right.algorithm.name())
                .then_with(|| left.bytes.cmp(&right.bytes))
        });
        hasher.update((digests.len() as u32).to_be_bytes());
        for digest in digests {
            part(&mut hasher, digest.algorithm.name().as_bytes());
            part(&mut hasher, &digest.bytes);
        }

        ReferenceId(hasher.finalize().into())
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn parse_hex(text: &str) -> Result<ReferenceId, InvalidReferenceId> {
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(text, &mut bytes).map_err(|_| InvalidReferenceId)?;
        Ok(ReferenceId(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Rebuilds an id from the bytes a row holds. Not a constructor for a *new* id:
    /// [`ReferenceId::compute`] is the only thing that decides what a reference is.
    pub(crate) fn from_bytes(bytes: [u8; 32]) -> ReferenceId {
        ReferenceId(bytes)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct InvalidReferenceId;

impl fmt::Display for InvalidReferenceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a reference id is 64 hexadecimal characters")
    }
}

impl std::error::Error for InvalidReferenceId {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::HashAlgorithm;

    fn reference() -> ArtifactReference {
        ArtifactReference {
            ecosystem: Ecosystem::Npm,
            name: "left-pad".to_owned(),
            version: "1.3.0".to_owned(),
            filename: "left-pad-1.3.0.tgz".to_owned(),
            upstream_url: Url::parse("https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz")
                .expect("a test URL"),
            expected: vec![
                Digest::parse_hex(HashAlgorithm::Sha512, &"ab".repeat(64)).expect("a digest"),
            ],
        }
    }

    /// The length prefix is the whole point: without it, moving a character from the
    /// end of one field to the start of the next would leave the id unchanged, and
    /// two different artifacts would share one reference.
    #[test]
    fn a_field_boundary_shift_is_a_different_reference() {
        let original = ReferenceId::compute(&reference());

        let mut shifted = reference();
        shifted.name = "left-pa".to_owned();
        shifted.version = "d1.3.0".to_owned();

        assert_ne!(
            original,
            ReferenceId::compute(&shifted),
            "the same concatenated bytes split differently must not collide"
        );
    }

    /// SPEC §5: changed expected digests constitute a new reference. The order they
    /// arrive in must not, or the same artifact would get two ids.
    #[test]
    fn digest_order_does_not_change_the_id_but_digest_content_does() {
        let sha512 = Digest::parse_hex(HashAlgorithm::Sha512, &"ab".repeat(64)).expect("a digest");
        let sha1 = Digest::parse_hex(HashAlgorithm::Sha1, &"cd".repeat(20)).expect("a digest");

        let mut forwards = reference();
        forwards.expected = vec![sha512.clone(), sha1.clone()];
        let mut backwards = reference();
        backwards.expected = vec![sha1, sha512.clone()];
        assert_eq!(
            ReferenceId::compute(&forwards),
            ReferenceId::compute(&backwards)
        );

        // Two digests of one algorithm are ordered by their bytes, so their arrival
        // order does not matter either.
        let other_sha512 =
            Digest::parse_hex(HashAlgorithm::Sha512, &"ef".repeat(64)).expect("a digest");
        forwards.expected = vec![sha512.clone(), other_sha512.clone()];
        backwards.expected = vec![other_sha512, sha512];
        assert_eq!(
            ReferenceId::compute(&forwards),
            ReferenceId::compute(&backwards),
            "two digests of one algorithm, in either order"
        );

        let mut changed = reference();
        changed.expected =
            vec![Digest::parse_hex(HashAlgorithm::Sha512, &"ac".repeat(64)).expect("a digest")];
        assert_ne!(
            ReferenceId::compute(&reference()),
            ReferenceId::compute(&changed),
            "new expected digests are a new reference, never the same one with new bytes"
        );
    }
}
