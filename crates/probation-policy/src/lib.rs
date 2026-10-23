//! The policy rules the probation firewall and its management server share, compiled
//! into both so they cannot drift (C95): the merge of a layer chain into the policy one
//! request is decided under, and the check a layer edit must pass.
//!
//! The invariant this crate owns is C8's: a looser setting takes effect only where
//! every layer above allows it. It holds no state and does no I/O.

pub mod api;
pub mod blocklist_json;
mod edit;
pub mod names;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub use edit::{CheckedEdit, EditRefusal, EditTarget, Loosening, check_edit};

/// The firewall settings a push may never set (C35, C118, T5): they stay in the
/// firewall's own `config.toml`, so a bad value cannot cut it off from its server, move
/// its state, or redirect its download links and decision records. The server refuses a
/// push naming one before it is stored; the firewall refuses it again before it writes.
pub const LOCAL_ONLY_SETTINGS: &[&str] = &[
    "management",
    "listen",
    "data_dir",
    "tls_cert_path",
    "tls_key_path",
    "public_url",
    "siem_url",
    "siem_auth_header",
];

/// Where a layer sits. Declared top to bottom, so `Ord` is chain order: platform ->
/// organisation -> group -> user, or platform -> personal account (C9).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub enum LayerKind {
    Platform,
    Org,
    Group,
    User,
    Personal,
}

/// A place a layer belongs to: its kind and the server's 32-bit id (C107).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct PlaceRef {
    pub kind: LayerKind,
    pub id: u32,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub enum Ecosystem {
    Npm,
    PyPi,
}

impl Ecosystem {
    /// The spelling used in the blocklist file (SPEC §8) and in log lines.
    pub const fn as_tag(self) -> &'static str {
        match self {
            Ecosystem::Npm => "npm",
            Ecosystem::PyPi => "pypi",
        }
    }

    pub fn from_tag(tag: &str) -> Option<Ecosystem> {
        match tag {
            "npm" => Some(Ecosystem::Npm),
            "pypi" => Some(Ecosystem::PyPi),
            _ => None,
        }
    }
}

/// OSV's three values (C81). Declared loosest first, so `Ord` is strictness.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub enum OsvSetting {
    Off,
    /// Allow, and record "would have blocked".
    LogOnly,
    On,
}

/// What the layer directly below may loosen (C11).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default, Serialize, Deserialize)]
pub struct Switches {
    pub exceptions: bool,
    pub osv_off: bool,
    pub shorter_freeze: bool,
}

impl Switches {
    pub const ALL: Switches = Switches {
        exceptions: true,
        osv_off: true,
        shorter_freeze: true,
    };

    pub fn get(self, switch: SwitchName) -> bool {
        match switch {
            SwitchName::Exceptions => self.exceptions,
            SwitchName::OsvOff => self.osv_off,
            SwitchName::ShorterFreeze => self.shorter_freeze,
        }
    }

    fn and(self, other: Switches) -> Switches {
        Switches {
            exceptions: self.exceptions && other.exceptions,
            osv_off: self.osv_off && other.osv_off,
            shorter_freeze: self.shorter_freeze && other.shorter_freeze,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize)]
pub enum SwitchName {
    Exceptions,
    OsvOff,
    ShorterFreeze,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub enum DigestAlgorithm {
    Sha256,
    Sha512,
}

/// What a block points at (C17). A file block carries only its digest, as today's
/// blocklist format does (C119). `reason` is the blocklist file's own (C86); it is left
/// out of the encoding when absent, so a policy without reasons keeps its fingerprint.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub enum Block {
    Package {
        ecosystem: Ecosystem,
        name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    Version {
        ecosystem: Ecosystem,
        name: String,
        version: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    File {
        algorithm: DigestAlgorithm,
        /// Lowercase hex.
        digest: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
}

/// Which checks an exception lifts (C16).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default, Serialize, Deserialize)]
pub struct Lifts {
    pub block: bool,
    pub freeze: bool,
    pub osv: bool,
}

/// An exception for a whole package (`version: None`, every release including future
/// ones) or one exact version (C17).
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct Exception {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: Option<String>,
    pub lifts: Lifts,
}

/// One layer's own settings. `None` means "inherit from the layer above".
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Layer {
    pub kind: LayerKind,
    /// The freeze (cooldown). Shorter than the layer above is a loosening.
    pub freeze_seconds: Option<u64>,
    /// `LogOnly` and `Off` below `On` are loosenings (C81).
    pub osv: Option<OsvSetting>,
    pub blocks: Vec<Block>,
    pub exceptions: Vec<Exception>,
    /// What the layer directly below may loosen (C11). Platform's are set by global
    /// admins.
    pub allow: Switches,
}

impl Layer {
    /// A layer that sets nothing and allows nothing.
    pub fn empty(kind: LayerKind) -> Layer {
        Layer {
            kind,
            freeze_seconds: None,
            osv: None,
            blocks: Vec::new(),
            exceptions: Vec::new(),
            allow: Switches::default(),
        }
    }
}

/// A block's position in its `BlockSet`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize)]
pub struct BlockId(pub u32);

/// A block tagged with the layer that owns it.
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct OwnedBlock {
    pub id: BlockId,
    pub owner: LayerKind,
    pub block: Block,
}

/// An exception tagged with the layer that set it, holding only the lifts every
/// ancestor allowed (C46).
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct OwnedException {
    pub owner: LayerKind,
    pub exception: Exception,
}

pub type BlockSet = Vec<OwnedBlock>;
pub type ExceptionSet = Vec<OwnedException>;

/// One chain layer's own freeze, OSV and switches.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize)]
pub struct LayerSettings {
    pub kind: LayerKind,
    pub freeze_seconds: Option<u64>,
    pub osv: Option<OsvSetting>,
    pub allow: Switches,
}

/// SHA-256 of the canonical encoding of an effective policy (C103).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct PolicyFingerprint(pub [u8; 32]);

/// The merged policy one request is decided under. Immutable; share it through `Arc`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct EffectivePolicy {
    /// Each chain layer's own values, top to bottom. A value a layer keeps under C47
    /// but may not use is dropped by the merge in `rules_for`, never here, because an
    /// exception that lifts the layer above can make it the strictest one left.
    pub chain: Vec<LayerSettings>,
    /// Every layer's blocks, names canonical (T6).
    pub blocks: BlockSet,
    /// Only the lifts every ancestor's switches allowed (C46), names canonical.
    pub exceptions: ExceptionSet,
    /// The AND of every chain layer's `allow`: what the layer below may loosen.
    pub allow: Switches,
    pub fingerprint: PolicyFingerprint,
}

/// The rules one candidate is decided under.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CandidateRules {
    /// The merge over unlifted layers; 0 when every freeze is lifted or none is set.
    pub freeze_seconds: u64,
    /// The layer whose value the merge ended on.
    pub freeze_from: Option<LayerKind>,
    /// The merge over unlifted layers; `Off` when every OSV setting is lifted or none
    /// is set. Also gates the OSV query.
    pub osv: OsvSetting,
    pub osv_from: Option<LayerKind>,
    /// Blocks an exception lifts for this candidate.
    pub lifted_blocks: Vec<BlockId>,
}

/// Merges `chain`, top to bottom and starting with Platform, into one effective policy.
///
/// A stricter value always wins. A looser one is kept only where every ancestor's
/// matching switch is on, otherwise the value above applies — defence in depth when a
/// stored layer is out of step with its parents (C8, C11, C46, C47).
pub fn resolve(chain: &[Layer]) -> EffectivePolicy {
    debug_assert!(
        c9_shape(chain),
        "C9: a chain is a prefix of platform -> org -> group -> user, platform -> org -> user, or platform -> personal"
    );

    let mut blocks = BlockSet::new();
    let mut exceptions = ExceptionSet::new();
    // What the layers above the current one allow; the root above Platform allows all.
    let mut above = Switches::ALL;
    for layer in chain {
        for block in &layer.blocks {
            blocks.push(OwnedBlock {
                id: BlockId(blocks.len() as u32),
                owner: layer.kind,
                block: canonical_block(block),
            });
        }
        for exception in &layer.exceptions {
            // Each lift needs its own switch from every layer above (C16, C46).
            let lifts = Lifts {
                block: exception.lifts.block && above.exceptions,
                freeze: exception.lifts.freeze && above.shorter_freeze,
                osv: exception.lifts.osv && above.osv_off,
            };
            if lifts != Lifts::default() {
                exceptions.push(OwnedException {
                    owner: layer.kind,
                    exception: Exception {
                        name: names::canonical_name(exception.ecosystem, &exception.name),
                        lifts,
                        ..exception.clone()
                    },
                });
            }
        }
        above = above.and(layer.allow);
    }

    let chain: Vec<LayerSettings> = chain
        .iter()
        .map(|layer| LayerSettings {
            kind: layer.kind,
            freeze_seconds: layer.freeze_seconds,
            osv: layer.osv,
            allow: layer.allow,
        })
        .collect();
    let encoding = serde_json::to_vec(&(&chain, &blocks, &exceptions, above))
        .expect("policy values always serialise");
    EffectivePolicy {
        chain,
        blocks,
        exceptions,
        allow: above,
        fingerprint: PolicyFingerprint(Sha256::digest(&encoding).into()),
    }
}

/// C9's chain shapes (and the empty chain above Platform), with C10's user in no
/// group directly under the organisation.
fn c9_shape(chain: &[Layer]) -> bool {
    let kinds: Vec<LayerKind> = chain.iter().map(|layer| layer.kind).collect();
    is_chain(&kinds)
}

/// Whether `kinds`, top to bottom, is a chain `resolve` accepts (C9, C10). The firewall
/// checks a server's answer with this before it resolves it.
pub fn is_chain(kinds: &[LayerKind]) -> bool {
    use LayerKind::*;
    [Platform, Org, Group, User].starts_with(kinds)
        || kinds == [Platform, Org, User]
        || kinds == [Platform, Personal]
}

fn canonical_block(block: &Block) -> Block {
    match block {
        Block::Package {
            ecosystem,
            name,
            reason,
        } => Block::Package {
            ecosystem: *ecosystem,
            name: names::canonical_name(*ecosystem, name),
            reason: reason.clone(),
        },
        Block::Version {
            ecosystem,
            name,
            version,
            reason,
        } => Block::Version {
            ecosystem: *ecosystem,
            name: names::canonical_name(*ecosystem, name),
            version: version.clone(),
            reason: reason.clone(),
        },
        Block::File {
            algorithm,
            digest,
            reason,
        } => Block::File {
            algorithm: *algorithm,
            digest: digest.to_ascii_lowercase(),
            reason: reason.clone(),
        },
    }
}

/// C8's merge of one value down the chain, skipping `lifted` layers: a stricter value
/// replaces the one above, a looser one only when every layer above allows it, and
/// `None` inherits. Returns the value and the layer it came from.
pub(crate) fn merge<T: Ord + Copy>(
    chain: &[LayerSettings],
    value: impl Fn(&LayerSettings) -> Option<T>,
    switch: SwitchName,
    lifted: impl Fn(LayerKind) -> bool,
) -> Option<(T, LayerKind)> {
    let mut merged: Option<(T, LayerKind)> = None;
    let mut allowed = true;
    for layer in chain {
        if let Some(own) = value(layer).filter(|_| !lifted(layer.kind)) {
            let replaces = match merged {
                None => true,
                Some((above, _)) => own > above || (own < above && allowed),
            };
            if replaces {
                merged = Some((own, layer.kind));
            }
        }
        allowed &= layer.allow.get(switch);
    }
    merged
}

impl EffectivePolicy {
    /// The parent of the platform layer: no blocks, every switch on (C9).
    pub fn root() -> EffectivePolicy {
        resolve(&[])
    }

    /// The rules one candidate is decided under (C16, C17, C46, C106). `name` is
    /// already canonical. An exception set at layer E lifts only rules owned at or
    /// above E. Each exception applies on its own: a whole-package exception lifts
    /// package and version blocks, an exact-version one also lifts file blocks.
    pub fn rules_for(&self, ecosystem: Ecosystem, name: &str, version: &str) -> CandidateRules {
        let matching: Vec<&OwnedException> = self
            .exceptions
            .iter()
            .filter(|owned| {
                let exception = &owned.exception;
                exception.ecosystem == ecosystem
                    && exception.name == name
                    && exception
                        .version
                        .as_deref()
                        .is_none_or(|exact| names::same_version(ecosystem, exact, version))
            })
            .collect();
        // Whether an exception lifting `lift` sits at or below `owner`.
        let lifted_at = |owner: LayerKind, lift: fn(&Lifts) -> bool| {
            matching
                .iter()
                .any(|owned| owned.owner >= owner && lift(&owned.exception.lifts))
        };

        let lifted_blocks = self
            .blocks
            .iter()
            .filter(|owned| match &owned.block {
                Block::Package {
                    ecosystem: blocked,
                    name: blocked_name,
                    ..
                }
                | Block::Version {
                    ecosystem: blocked,
                    name: blocked_name,
                    ..
                } => {
                    *blocked == ecosystem
                        && blocked_name == name
                        && lifted_at(owned.owner, |l| l.block)
                }
                // A file block targets known-bad bytes, so only an exact-version
                // exception lifts it (C106).
                Block::File { .. } => matching.iter().any(|exception| {
                    exception.owner >= owned.owner
                        && exception.exception.lifts.block
                        && exception.exception.version.is_some()
                }),
            })
            .map(|owned| owned.id)
            .collect();

        let freeze = merge(
            &self.chain,
            |layer| layer.freeze_seconds,
            SwitchName::ShorterFreeze,
            |kind| lifted_at(kind, |l| l.freeze),
        );
        let osv = merge(
            &self.chain,
            |layer| layer.osv,
            SwitchName::OsvOff,
            |kind| lifted_at(kind, |l| l.osv),
        );
        CandidateRules {
            freeze_seconds: freeze.map_or(0, |(seconds, _)| seconds),
            freeze_from: freeze.map(|(_, from)| from),
            osv: osv.map_or(OsvSetting::Off, |(setting, _)| setting),
            osv_from: osv.map(|(_, from)| from),
            lifted_blocks,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: u64 = 86_400;

    fn layer(kind: LayerKind) -> Layer {
        Layer::empty(kind)
    }

    fn package_exception(ecosystem: Ecosystem, name: &str, version: Option<&str>) -> Exception {
        Exception {
            ecosystem,
            name: name.to_owned(),
            version: version.map(str::to_owned),
            lifts: Lifts {
                block: true,
                freeze: false,
                osv: false,
            },
        }
    }

    /// T-resolve-empty-platform (C125): a platform left empty, alone or above layers
    /// that set nothing, means freeze 0 and OSV Off, from no layer. The user's
    /// fail-open choice; nothing forces a value.
    #[test]
    fn t_resolve_empty_platform() {
        let chains = [
            vec![layer(LayerKind::Platform)],
            vec![
                layer(LayerKind::Platform),
                layer(LayerKind::Org),
                layer(LayerKind::User),
            ],
        ];
        for chain in chains {
            let policy = resolve(&chain);
            for (ecosystem, name, version) in [
                (Ecosystem::Npm, "left-pad", "1.3.0"),
                (Ecosystem::PyPi, "requests", "2.0"),
            ] {
                let rules = policy.rules_for(ecosystem, name, version);
                assert_eq!(rules.freeze_seconds, 0, "{chain:?}");
                assert_eq!(rules.osv, OsvSetting::Off, "{chain:?}");
                assert_eq!(rules.freeze_from, None, "{chain:?}");
                assert_eq!(rules.osv_from, None, "{chain:?}");
            }
        }
    }

    /// T-names-normalised (T6): a block on `Foo_Bar` reaches `foo-bar`, and an
    /// exception on `Requests==2.0` lifts a block for `requests` 2.0 and its equivalent
    /// spelling 2.0.0, but not 2.1.
    #[test]
    fn t_names_normalised() {
        let platform = Layer {
            blocks: vec![
                Block::Package {
                    ecosystem: Ecosystem::PyPi,
                    name: "Foo_Bar".to_owned(),
                    reason: None,
                },
                Block::Package {
                    ecosystem: Ecosystem::PyPi,
                    name: "requests".to_owned(),
                    reason: None,
                },
            ],
            allow: Switches::ALL,
            ..layer(LayerKind::Platform)
        };
        let org = Layer {
            exceptions: vec![package_exception(Ecosystem::PyPi, "Requests", Some("2.0"))],
            ..layer(LayerKind::Org)
        };
        let policy = resolve(&[platform, org]);

        assert_eq!(
            policy.blocks[0].block,
            Block::Package {
                ecosystem: Ecosystem::PyPi,
                name: "foo-bar".to_owned(),
                reason: None,
            },
            "the block is stored under its PEP 503 name"
        );
        assert_eq!(
            policy
                .rules_for(Ecosystem::PyPi, "foo-bar", "1.0")
                .lifted_blocks,
            vec![],
            "nothing lifts the foo-bar block"
        );
        assert_eq!(
            policy
                .rules_for(Ecosystem::PyPi, "requests", "2.0")
                .lifted_blocks,
            vec![BlockId(1)]
        );
        assert_eq!(
            policy
                .rules_for(Ecosystem::PyPi, "requests", "2.0.0")
                .lifted_blocks,
            vec![BlockId(1)],
            "PEP 440 equality: 2.0.0 is 2.0"
        );
        assert_eq!(
            policy
                .rules_for(Ecosystem::PyPi, "requests", "2.1")
                .lifted_blocks,
            vec![]
        );
        assert_eq!(
            policy
                .rules_for(Ecosystem::Npm, "requests", "2.0")
                .lifted_blocks,
            vec![],
            "an exception names its ecosystem (C31)"
        );
    }

    /// T-resolve-stricter: a child's longer freeze and stricter OSV win with every
    /// switch off.
    #[test]
    fn t_resolve_stricter() {
        let platform = Layer {
            freeze_seconds: Some(DAY),
            osv: Some(OsvSetting::LogOnly),
            ..layer(LayerKind::Platform)
        };
        let org = Layer {
            freeze_seconds: Some(7 * DAY),
            osv: Some(OsvSetting::On),
            ..layer(LayerKind::Org)
        };
        let rules = resolve(&[platform, org]).rules_for(Ecosystem::Npm, "left-pad", "1.0.0");
        assert_eq!(rules.freeze_seconds, 7 * DAY);
        assert_eq!(rules.freeze_from, Some(LayerKind::Org));
        assert_eq!(rules.osv, OsvSetting::On);
        assert_eq!(rules.osv_from, Some(LayerKind::Org));
    }

    /// T-resolve-looser-blocked: a child's shorter freeze and OSV off take effect only
    /// while the parent's switches are on.
    #[test]
    fn t_resolve_looser_blocked() {
        let chain = |allow: Switches| {
            resolve(&[
                Layer {
                    freeze_seconds: Some(7 * DAY),
                    osv: Some(OsvSetting::On),
                    allow,
                    ..layer(LayerKind::Platform)
                },
                Layer {
                    freeze_seconds: Some(DAY),
                    osv: Some(OsvSetting::Off),
                    ..layer(LayerKind::Personal)
                },
            ])
            .rules_for(Ecosystem::Npm, "left-pad", "1.0.0")
        };

        let off = chain(Switches::default());
        assert_eq!(off.freeze_seconds, 7 * DAY);
        assert_eq!(off.freeze_from, Some(LayerKind::Platform));
        assert_eq!(off.osv, OsvSetting::On);
        assert_eq!(off.osv_from, Some(LayerKind::Platform));

        let on = chain(Switches::ALL);
        assert_eq!(on.freeze_seconds, DAY);
        assert_eq!(on.freeze_from, Some(LayerKind::Personal));
        assert_eq!(on.osv, OsvSetting::Off);
        assert_eq!(on.osv_from, Some(LayerKind::Personal));

        // A switch is passed down only by a layer that holds it (C45, C46): the user
        // layer's shorter freeze needs the platform's switch as well as the group's.
        let policy = resolve(&[
            Layer {
                freeze_seconds: Some(7 * DAY),
                ..layer(LayerKind::Platform)
            },
            layer(LayerKind::Org),
            Layer {
                allow: Switches::ALL,
                ..layer(LayerKind::Group)
            },
            Layer {
                freeze_seconds: Some(DAY),
                ..layer(LayerKind::User)
            },
        ]);
        assert_eq!(policy.allow, Switches::default());
        assert_eq!(
            policy
                .rules_for(Ecosystem::Npm, "left-pad", "1.0.0")
                .freeze_seconds,
            7 * DAY
        );

        // C10: a user in no group sits directly under the organisation, whose switch
        // then governs the user's freeze.
        let user_under_org = |shorter_freeze| {
            resolve(&[
                Layer {
                    allow: Switches::ALL,
                    ..layer(LayerKind::Platform)
                },
                Layer {
                    freeze_seconds: Some(7 * DAY),
                    allow: Switches {
                        shorter_freeze,
                        ..Switches::default()
                    },
                    ..layer(LayerKind::Org)
                },
                Layer {
                    freeze_seconds: Some(DAY),
                    ..layer(LayerKind::User)
                },
            ])
            .rules_for(Ecosystem::Npm, "left-pad", "1.0.0")
        };
        let closed = user_under_org(false);
        assert_eq!(
            (closed.freeze_seconds, closed.freeze_from),
            (7 * DAY, Some(LayerKind::Org))
        );
        let open = user_under_org(true);
        assert_eq!(
            (open.freeze_seconds, open.freeze_from),
            (DAY, Some(LayerKind::User))
        );
    }

    /// A chain outside C9's shapes is a programming error (debug builds).
    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "C9")]
    fn t_resolve_rejects_a_chain_outside_c9() {
        resolve(&[
            layer(LayerKind::Platform),
            layer(LayerKind::Org),
            layer(LayerKind::Personal),
        ]);
    }

    pub(crate) mod properties {
        use super::*;
        use proptest::prelude::*;

        use LayerKind::{Group, Org, Personal, Platform, User};

        /// Every chain shape C9 and C10 allow, the empty chain above Platform included.
        pub(crate) const SHAPES: [&[LayerKind]; 7] = [
            &[],
            &[Platform],
            &[Platform, Org],
            &[Platform, Org, Group],
            &[Platform, Org, Group, User],
            &[Platform, Org, User],
            &[Platform, Personal],
        ];

        fn osv() -> impl Strategy<Value = Option<OsvSetting>> {
            prop::option::of(prop_oneof![
                Just(OsvSetting::Off),
                Just(OsvSetting::LogOnly),
                Just(OsvSetting::On)
            ])
        }

        fn switches() -> impl Strategy<Value = Switches> {
            (any::<bool>(), any::<bool>(), any::<bool>()).prop_map(
                |(exceptions, osv_off, shorter_freeze)| Switches {
                    exceptions,
                    osv_off,
                    shorter_freeze,
                },
            )
        }

        /// 0..=3 exceptions on `pkg` at this layer: whole-package, the candidates'
        /// version 1.0.0 or another, with duplicate targets allowed.
        fn exceptions() -> impl Strategy<Value = Vec<Exception>> {
            prop::collection::vec(
                (
                    prop_oneof![Just(None), Just(Some("1.0.0")), Just(Some("2.0.0"))],
                    any::<bool>(),
                    any::<bool>(),
                    any::<bool>(),
                ),
                0..=3,
            )
            .prop_map(|exceptions| {
                exceptions
                    .into_iter()
                    .map(|(version, block, freeze, osv)| Exception {
                        ecosystem: Ecosystem::Npm,
                        name: "pkg".to_owned(),
                        version: version.map(str::to_owned),
                        lifts: Lifts { block, freeze, osv },
                    })
                    .collect()
            })
        }

        /// One layer of `kind` with random values, over the small domain the
        /// properties need: one package `pkg`, freezes 0..10.
        pub(crate) fn layer_of(kind: LayerKind) -> impl Strategy<Value = Layer> {
            (
                prop::option::of(0..10u64),
                osv(),
                any::<bool>(),
                exceptions(),
                switches(),
            )
                .prop_map(move |(freeze, osv, blocks, exceptions, allow)| Layer {
                    kind,
                    freeze_seconds: freeze,
                    osv,
                    blocks: if blocks {
                        vec![Block::Package {
                            ecosystem: Ecosystem::Npm,
                            name: "pkg".to_owned(),
                            reason: None,
                        }]
                    } else {
                        Vec::new()
                    },
                    exceptions,
                    allow,
                })
        }

        /// A chain of random layers of the given kinds.
        pub(crate) fn chain_of(kinds: &[LayerKind]) -> Vec<impl Strategy<Value = Layer> + use<>> {
            kinds.iter().map(|&kind| layer_of(kind)).collect()
        }

        /// A chain of any C9/C10 shape.
        fn chain() -> impl Strategy<Value = Vec<Layer>> {
            prop::sample::select(SHAPES.to_vec()).prop_flat_map(chain_of)
        }

        proptest! {
            /// P-resolve-never-looser-than-allowed (C8, C46, T6): below a layer whose
            /// switch is off, nothing is looser than any value set at or below it;
            /// and a block is lifted only by an exception at or below its owner with
            /// the exceptions switch on in every layer above the exception.
            #[test]
            fn p_resolve_never_looser_than_allowed(chain in chain()) {
                let policy = resolve(&chain);
                let none = policy.rules_for(Ecosystem::Npm, "other", "1.0.0");
                let pkg = policy.rules_for(Ecosystem::Npm, "pkg", "1.0.0");

                let mut freeze_closed = false;
                let mut osv_closed = false;
                for layer in &chain {
                    freeze_closed |= !layer.allow.shorter_freeze;
                    osv_closed |= !layer.allow.osv_off;
                    // `closed` covers this layer's own switch, which governs the layers
                    // below it: from here down, nothing may loosen past this value.
                    if let (true, Some(freeze)) = (freeze_closed, layer.freeze_seconds) {
                        prop_assert!(none.freeze_seconds >= freeze);
                    }
                    if let (true, Some(osv)) = (osv_closed, layer.osv) {
                        prop_assert!(none.osv >= osv);
                    }
                }

                for block in &policy.blocks {
                    if pkg.lifted_blocks.contains(&block.id) {
                        let lifted_by_allowed = chain.iter().enumerate().any(|(at, layer)| {
                            layer.kind >= block.owner
                                && layer.exceptions.iter().any(|e| {
                                    e.lifts.block && e.version.as_deref().is_none_or(|v| v == "1.0.0")
                                })
                                && chain[..at].iter().all(|above| above.allow.exceptions)
                        });
                        prop_assert!(lifted_by_allowed, "block {:?} lifted without leave", block);
                    }
                }
            }
        }
    }
}
