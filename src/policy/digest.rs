//! Digest identity (SPEC §8).
//!
//! One artifact digest has exactly one representation in this crate: an algorithm
//! and its raw bytes. Hexadecimal blocklist entries and npm's SRI base64 both decode
//! into that same value, so a block written in hex denies an artifact whose upstream
//! metadata only ever advertised base64.
//!
//! The base64 decoder below is ours rather than `ssri`'s on purpose. `ssri` parses an
//! integrity string without validating its payload (`Hash::from_str` documents that it
//! does not check the digest length) and `Integrity::to_hex` decodes with an
//! `unwrap()`, so feeding it an upstream-supplied malformed entry would panic the
//! process. Upstream metadata is untrusted input, so it is decoded here, strictly, and
//! `ssri` is left for slice 7's verification of bytes we have already downloaded.

use std::fmt;

/// The algorithms this crate can hold a digest for. SPEC §8 allows only SHA-256 and
/// SHA-512 in a blocklist; SHA-1 exists because npm still advertises it for old
/// releases that carry no stronger integrity field, and it is never a blockable
/// algorithm — `blocklist.rs` rejects it.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum HashAlgorithm {
    Sha256,
    Sha512,
    Sha1,
}

impl HashAlgorithm {
    /// The exact length a digest of this algorithm has. A value of any other length
    /// is malformed, never truncated or padded to fit.
    pub const fn digest_len(self) -> usize {
        match self {
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Sha512 => 64,
            HashAlgorithm::Sha1 => 20,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            HashAlgorithm::Sha256 => "sha256",
            HashAlgorithm::Sha512 => "sha512",
            HashAlgorithm::Sha1 => "sha1",
        }
    }

    /// Case-insensitive, because SPEC §8 normalises case and an operator's producer
    /// may well write `SHA256`.
    pub fn from_name(name: &str) -> Option<HashAlgorithm> {
        [
            HashAlgorithm::Sha256,
            HashAlgorithm::Sha512,
            HashAlgorithm::Sha1,
        ]
        .into_iter()
        .find(|algorithm| name.eq_ignore_ascii_case(algorithm.name()))
    }
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// An algorithm and the exact digest bytes. Comparison is over the bytes, so the
/// spelling a digest arrived in never affects whether it matches.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Digest {
    pub algorithm: HashAlgorithm,
    pub bytes: Box<[u8]>,
}

impl Digest {
    /// A hexadecimal digest of exactly the algorithm's length, in either case.
    pub fn parse_hex(algorithm: HashAlgorithm, hex_text: &str) -> Result<Digest, InvalidDigest> {
        let bytes = hex::decode(hex_text).map_err(|_| InvalidDigest::Encoding {
            algorithm,
            form: "hexadecimal",
        })?;
        Digest::from_bytes(algorithm, bytes)
    }

    /// One SRI entry, `sha512-<base64>` (SPEC §8: npm SRI base64 decodes to the same
    /// digest bytes before comparison). An integrity field holding several
    /// whitespace-separated entries is split by its caller; this parses one.
    pub fn parse_sri_entry(entry: &str) -> Result<Digest, InvalidDigest> {
        let entry = entry.trim();
        let (name, rest) = entry
            .split_once('-')
            .ok_or_else(|| InvalidDigest::NotAnSriEntry(entry.to_owned()))?;
        let algorithm = HashAlgorithm::from_name(name)
            .ok_or_else(|| InvalidDigest::UnsupportedAlgorithm(name.to_owned()))?;

        // SRI permits `?options` after the digest. They are not part of the digest,
        // and npm does not emit them.
        let base64_text = rest.split_once('?').map_or(rest, |(digest, _)| digest);
        let bytes = decode_base64(base64_text).ok_or(InvalidDigest::Encoding {
            algorithm,
            form: "base64",
        })?;
        Digest::from_bytes(algorithm, bytes)
    }

    fn from_bytes(algorithm: HashAlgorithm, bytes: Vec<u8>) -> Result<Digest, InvalidDigest> {
        if bytes.len() != algorithm.digest_len() {
            return Err(InvalidDigest::Length {
                algorithm,
                expected: algorithm.digest_len(),
                found: bytes.len(),
            });
        }
        Ok(Digest {
            algorithm,
            bytes: bytes.into_boxed_slice(),
        })
    }

    pub fn to_hex_lowercase(&self) -> String {
        hex::encode(&self.bytes)
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}", self.algorithm, self.to_hex_lowercase())
    }
}

/// Strict standard-alphabet base64. Returns `None` for anything that is not exactly
/// one canonical encoding: an unknown character, data after padding, padding other
/// than the count the final group needs (none missing, none extra), a trailing
/// partial character, or non-zero bits left over from a truncated final group. Strictness matters because two spellings decoding to the
/// same bytes would let one of them miss a blocked digest.
fn decode_base64(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let mut accumulator: u32 = 0;
    let mut bits: u32 = 0;
    let mut padding = 0usize;

    for &byte in text.as_bytes() {
        if byte == b'=' {
            padding += 1;
            continue;
        }
        if padding > 0 {
            return None;
        }
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32;

        accumulator = (accumulator << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((accumulator >> bits) as u8);
            accumulator &= (1 << bits) - 1;
        }
    }

    // A final group of two characters carries 4 spare bits and needs `==`, one of
    // three carries 2 and needs `=`; a whole group needs none.
    let required = match bits {
        0 => 0,
        4 => 2,
        2 => 1,
        _ => return None,
    };
    if padding != required || accumulator != 0 {
        return None;
    }
    Some(out)
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum InvalidDigest {
    UnsupportedAlgorithm(String),
    NotAnSriEntry(String),
    Length {
        algorithm: HashAlgorithm,
        expected: usize,
        found: usize,
    },
    Encoding {
        algorithm: HashAlgorithm,
        form: &'static str,
    },
}

impl fmt::Display for InvalidDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InvalidDigest::UnsupportedAlgorithm(name) => {
                write!(f, "unsupported hash algorithm `{name}`")
            }
            InvalidDigest::NotAnSriEntry(entry) => {
                write!(f, "`{entry}` is not an `<algorithm>-<base64>` SRI entry")
            }
            InvalidDigest::Length {
                algorithm,
                expected,
                found,
            } => write!(
                f,
                "a {algorithm} digest is {expected} bytes, but this one decodes to {found}"
            ),
            InvalidDigest::Encoding { algorithm, form } => {
                write!(f, "the {algorithm} digest is not valid {form}")
            }
        }
    }
}

impl std::error::Error for InvalidDigest {}
