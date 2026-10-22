//! The firewall sync API's wire types, so the firewall's client and the server's
//! handlers name one definition (02-architecture.md § Endpoints). Lists on the wire are
//! named structs.

use std::fmt;
use std::num::NonZeroU32;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};

use crate::{Layer, PlaceRef};

/// The SHA-256 of an API key (C99): the only form of a key the firewall sends or keeps,
/// and the only one the server stores. Lowercase hex on the wire. Its `Debug` prints
/// nothing, so a stray `{:?}` cannot put it in a log line (T19).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyHash(pub [u8; 32]);

impl KeyHash {
    pub fn of(key: &str) -> KeyHash {
        KeyHash(Sha256::digest(key.as_bytes()).into())
    }
}

impl fmt::Debug for KeyHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KeyHash(..)")
    }
}

impl Serialize for KeyHash {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let hex: String = self.0.iter().map(|byte| format!("{byte:02x}")).collect();
        serializer.serialize_str(&hex)
    }
}

impl<'de> Deserialize<'de> for KeyHash {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<KeyHash, D::Error> {
        let text = String::deserialize(deserializer)?;
        let invalid = || D::Error::custom("a key hash is 64 lowercase hex characters");
        if text.len() != 64 {
            return Err(invalid());
        }
        let nibble = |c: u8| match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        };
        let mut bytes = [0u8; 32];
        for (byte, pair) in bytes.iter_mut().zip(text.as_bytes().chunks(2)) {
            let (high, low) = nibble(pair[0]).zip(nibble(pair[1])).ok_or_else(invalid)?;
            *byte = high << 4 | low;
        }
        Ok(KeyHash(bytes))
    }
}

/// The server's id of a key, for activity rows. Never the key or its hash.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct KeyId(pub u64);

/// The server's id of an organisation.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct OrgId(pub u32);

/// Which `limits` row an account's rate limit came from (C28, C67).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LimitSource {
    Default,
    Override,
}

/// `POST /api/v1/sync/lookup`.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct KeyLookupRequest {
    pub key_hash: KeyHash,
}

/// One place of a key's chain and the revision of its layer.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ChainLink {
    pub place: PlaceRef,
    pub layer_revision: u64,
}

/// The answer to a lookup. `revision` is the change-log revision it was read at.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum KeyLookup {
    Known {
        key_id: KeyId,
        /// `None` for a personal account's key.
        org: Option<OrgId>,
        /// The organisation or personal account the rate limit counts against.
        account: PlaceRef,
        /// Platform first, the key's own place last.
        place_chain: Vec<ChainLink>,
        /// Requests per minute, counted on each firewall.
        rate_limit: Option<NonZeroU32>,
        rate_limit_source: LimitSource,
        revision: u64,
    },
    Revoked {
        key_id: KeyId,
        place: PlaceRef,
        place_chain: Vec<ChainLink>,
        revision: u64,
    },
    Suspended {
        key_id: KeyId,
        place: PlaceRef,
        place_chain: Vec<ChainLink>,
        revision: u64,
    },
    Unknown {
        revision: u64,
    },
}

/// `POST /api/v1/sync/layers`.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct LayersRequest {
    pub places: Vec<PlaceRef>,
}

/// One place's own layer and its revision.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct PlaceLayer {
    pub place: PlaceRef,
    pub layer: Layer,
    pub revision: u64,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct LayersResponse {
    pub layers: Vec<PlaceLayer>,
    /// The change-log revision the answer was read at.
    pub revision: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LayerKind;

    /// T-sync-api-contract's firewall half: the hash travels as hex and round-trips, and
    /// a lookup answer is tagged by its status.
    #[test]
    fn lookup_types_round_trip() {
        let hash = KeyHash::of("prb_example");
        let request = serde_json::to_string(&KeyLookupRequest { key_hash: hash }).unwrap();
        assert_eq!(request.len(), r#"{"key_hash":""}"#.len() + 64);
        let back: KeyLookupRequest = serde_json::from_str(&request).unwrap();
        assert_eq!(back.key_hash, hash);
        assert_eq!(format!("{hash:?}"), "KeyHash(..)");

        let platform = PlaceRef {
            kind: LayerKind::Platform,
            id: 1,
        };
        let answer = KeyLookup::Known {
            key_id: KeyId(7),
            org: Some(OrgId(2)),
            account: platform,
            place_chain: vec![ChainLink {
                place: platform,
                layer_revision: 3,
            }],
            rate_limit: NonZeroU32::new(600),
            rate_limit_source: LimitSource::Default,
            revision: 9,
        };
        let text = serde_json::to_string(&answer).unwrap();
        assert!(text.starts_with(r#"{"status":"known""#), "{text}");
        assert_eq!(serde_json::from_str::<KeyLookup>(&text).unwrap(), answer);
    }

    #[test]
    fn a_malformed_hash_is_refused() {
        for text in [
            "\"abc\"",
            &format!("\"{}\"", "A".repeat(64)),
            &format!("\"{}\"", "zz".repeat(32)),
            // `from_str_radix` alone would read `+f` as fifteen.
            &format!("\"{}\"", "+f".repeat(32)),
            &format!("\"{}{}\"", "-1", "0".repeat(62)),
        ] {
            assert!(serde_json::from_str::<KeyHash>(text).is_err(), "{text}");
        }
    }
}
