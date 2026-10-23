//! The firewall sync API's wire types, so the firewall's client and the server's
//! handlers name one definition (02-architecture.md § Endpoints). Lists on the wire are
//! named structs.

use std::fmt;
use std::net::IpAddr;
use std::num::NonZeroU32;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};

use crate::{Ecosystem, Layer, LayerKind, PlaceRef};

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

/// `POST /api/v1/sync/changes`: what changed since `since`, with this firewall's report
/// and the activity it has queued.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ChangesRequest {
    pub since: u64,
    pub report: FirewallReport,
    pub activity: Vec<ActivityEvent>,
    pub activity_dropped: Vec<DroppedCount>,
}

/// How a firewall is doing, sent with every `changes` call (C22, C69, C105).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct FirewallReport {
    /// The settings push in effect; `0` before the first.
    pub settings_revision: u64,
    /// Why the last push or sync could not be applied, cut to 2 KiB.
    pub last_apply_error: Option<String>,
    pub status: ReportStatus,
    /// The sync period this firewall runs at, so the server can tell a late check-in.
    pub effective_period_seconds: u64,
    pub version: String,
    /// The settings push the firewall refused, which `last_apply_error` is about. Absent
    /// from an older firewall's report, and left out when there is none, so older
    /// firewalls and servers read each other's reports (S7-14).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed_revision: Option<u64>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ReportStatus {
    pub upstreams: Upstreams,
}

/// Whether each upstream answered in the last sync period (C69).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Upstreams {
    pub npm: Reachability,
    pub pypi: Reachability,
    pub osv: Reachability,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reachability {
    Ok,
    Unreachable,
}

/// One blocked, held or would-have-blocked decision, or a refused known key (C23, C55,
/// C92). Never the key or its hash.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ActivityEvent {
    /// Unique per firewall, so a batch sent twice is stored once.
    pub event_id: String,
    pub key_id: KeyId,
    pub place: PlaceRef,
    /// `None` on a refusal made before the request's package was known.
    pub ecosystem: Option<Ecosystem>,
    pub package: Option<String>,
    pub version: Option<String>,
    pub result: ActivityResult,
    pub rule: String,
    pub layer: ActivityLayer,
    /// Only on `refused_network` (C92).
    pub client_ip: Option<IpAddr>,
    /// RFC 3339, holds only (C56).
    pub eligible_at: Option<String>,
    /// RFC 3339 UTC: when the firewall saw it, so a batch re-sent after an outage keeps
    /// its time. Left out by older firewalls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivityResult {
    Blocked,
    Held,
    WouldBlock,
    RefusedRevoked,
    RefusedSuspended,
    RefusedNetwork,
}

/// The layer behind an activity row: a policy layer, the network lock, or none (a
/// revoked or suspended key). One lowercase word on the wire.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ActivityLayer {
    Layer(LayerKind),
    Network,
    None,
}

impl ActivityLayer {
    const WORDS: [(&str, ActivityLayer); 7] = [
        ("platform", ActivityLayer::Layer(LayerKind::Platform)),
        ("org", ActivityLayer::Layer(LayerKind::Org)),
        ("group", ActivityLayer::Layer(LayerKind::Group)),
        ("user", ActivityLayer::Layer(LayerKind::User)),
        ("personal", ActivityLayer::Layer(LayerKind::Personal)),
        ("network", ActivityLayer::Network),
        ("none", ActivityLayer::None),
    ];
}

impl Serialize for ActivityLayer {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let (word, _) = ActivityLayer::WORDS
            .iter()
            .find(|(_, layer)| layer == self)
            .expect("every layer has a word");
        serializer.serialize_str(word)
    }
}

impl<'de> Deserialize<'de> for ActivityLayer {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<ActivityLayer, D::Error> {
        let text = String::deserialize(deserializer)?;
        ActivityLayer::WORDS
            .iter()
            .find(|(word, _)| *word == text)
            .map(|(_, layer)| *layer)
            .ok_or_else(|| D::Error::custom(format!("unknown activity layer {text:?}")))
    }
}

/// Events one account lost to its cap or to a rejected batch (T18).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct DroppedCount {
    pub account: PlaceRef,
    pub count: u64,
}

/// The one answer to `changes` (02-architecture.md § Endpoints).
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct ChangesResponse {
    /// The change-log revision this answer brings the firewall to.
    pub revision: u64,
    pub changed_keys: Vec<KeyId>,
    pub changed_layers: Vec<PlaceRef>,
    pub changed_places: Vec<PlaceRef>,
    pub changed_limits: Vec<LimitChange>,
    /// The whole table, sent when a `ranges` row is in the delta, on `since = 0` and on
    /// every reset; `None` keeps the table held.
    pub network_lock: Option<Vec<LockRange>>,
    pub settings: Option<SettingsPush>,
    /// The cursor is older than the retained change log: drop every cache.
    pub reset: bool,
    pub retired: bool,
}

/// Which accounts a `limits` row covers.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountKind {
    Org,
    Personal,
}

/// A `limits` row: the default of an account kind (`scope_id` `None`) or one account's
/// own rate. Deleting an override sends that account's row with the default's rate and
/// `source = default`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct LimitChange {
    pub scope_kind: AccountKind,
    pub scope_id: Option<u32>,
    pub rate_per_min: Option<NonZeroU32>,
    pub source: LimitSource,
}

/// An approved network-lock range and the organisation it belongs to (C30, C77).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct LockRange {
    /// `192.0.2.0/24` or `2001:db8::/32`.
    pub cidr: String,
    pub org: OrgId,
}

/// This firewall's own settings, sent when their revision differs from the reported
/// one (C105).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct SettingsPush {
    pub revision: u64,
    pub toml: String,
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// The changes call's lists are named structs on the wire, and an activity row's
    /// layer is one lowercase word.
    #[test]
    fn changes_types_round_trip() {
        let acme = PlaceRef {
            kind: LayerKind::Org,
            id: 10,
        };
        let request = ChangesRequest {
            since: 4,
            report: FirewallReport {
                settings_revision: 0,
                last_apply_error: None,
                status: ReportStatus {
                    upstreams: Upstreams {
                        npm: Reachability::Ok,
                        pypi: Reachability::Unreachable,
                        osv: Reachability::Ok,
                    },
                },
                effective_period_seconds: 55,
                version: "0.2.2".to_owned(),
                failed_revision: None,
            },
            activity: vec![ActivityEvent {
                event_id: "1-1".to_owned(),
                key_id: KeyId(7),
                place: acme,
                ecosystem: None,
                package: None,
                version: None,
                result: ActivityResult::RefusedNetwork,
                rule: "network_lock".to_owned(),
                layer: ActivityLayer::Network,
                client_ip: Some([192, 0, 2, 7].into()),
                eligible_at: None,
                at: None,
            }],
            activity_dropped: vec![DroppedCount {
                account: acme,
                count: 3,
            }],
        };
        let text = serde_json::to_string(&request).unwrap();
        for expected in [
            r#""layer":"network""#,
            r#""result":"refused_network""#,
            r#""pypi":"unreachable""#,
            r#""activity_dropped":[{"account""#,
        ] {
            assert!(text.contains(expected), "{expected} in {text}");
        }
        assert_eq!(
            serde_json::from_str::<ChangesRequest>(&text).unwrap(),
            request
        );
        // An older firewall's report has no `failed_revision`: it still parses, and a
        // report without one leaves the key out, so an older server reads it (S7-14).
        assert!(!text.contains("failed_revision"), "{text}");
        let older = text.replace(r#","version":"0.2.2""#, r#","version":"0.2.1""#);
        let parsed = serde_json::from_str::<ChangesRequest>(&older).unwrap();
        assert_eq!(parsed.report.failed_revision, None);
        let mut failed = request.report.clone();
        failed.failed_revision = Some(9);
        assert!(
            serde_json::to_string(&failed)
                .unwrap()
                .contains(r#""failed_revision":9"#)
        );
        assert!(
            !text.contains("\"at\""),
            "an event with no time leaves it out"
        );
        let mut timed = request.activity[0].clone();
        timed.at = Some("2026-04-06T12:00:10.000000Z".to_owned());
        let timed_text = serde_json::to_string(&timed).unwrap();
        assert!(timed_text.contains(r#""at":"2026-04-06T12:00:10.000000Z""#));
        assert_eq!(
            serde_json::from_str::<ActivityEvent>(&timed_text).unwrap(),
            timed
        );
        for (layer, word) in [
            (ActivityLayer::Layer(LayerKind::Personal), "\"personal\""),
            (ActivityLayer::None, "\"none\""),
        ] {
            assert_eq!(serde_json::to_string(&layer).unwrap(), word);
            assert_eq!(serde_json::from_str::<ActivityLayer>(word).unwrap(), layer);
        }
        assert!(serde_json::from_str::<ActivityLayer>("\"Org\"").is_err());

        let answer = ChangesResponse {
            revision: 9,
            network_lock: Some(vec![LockRange {
                cidr: "192.0.2.0/24".to_owned(),
                org: OrgId(10),
            }]),
            ..ChangesResponse::default()
        };
        let text = serde_json::to_string(&answer).unwrap();
        assert_eq!(
            serde_json::from_str::<ChangesResponse>(&text).unwrap(),
            answer
        );
    }
}
