//! Accept or refuse a proposed layer against the effective policy above it.

use crate::{
    Block, DigestAlgorithm, Ecosystem, EffectivePolicy, Exception, Layer, LayerKind, Lifts,
    OsvSetting, PlaceRef, SwitchName, merge, names,
};

/// A layer edit that passed `check_edit`. Its fields are private and so is its
/// constructor, so nothing outside this module can build one:
///
/// ```compile_fail,E0624
/// use probation_policy::{CheckedEdit, EditTarget, Layer, LayerKind, PlaceRef};
///
/// let target = EditTarget { place: PlaceRef { kind: LayerKind::Org, id: 1 }, expected_revision: 1 };
/// let forged = CheckedEdit::accepted(target, Layer::empty(LayerKind::Org));
/// ```
#[derive(Debug)]
pub struct CheckedEdit {
    target: EditTarget,
    layer: Layer,
}

/// The place an edit targets and the layer revision the form was loaded at.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EditTarget {
    pub place: PlaceRef,
    pub expected_revision: u64,
}

impl CheckedEdit {
    fn accepted(target: EditTarget, layer: Layer) -> Self {
        Self { target, layer }
    }

    pub fn layer(&self) -> &Layer {
        &self.layer
    }

    pub fn place(&self) -> PlaceRef {
        self.target.place
    }

    pub fn layer_kind(&self) -> LayerKind {
        self.layer.kind
    }

    pub fn expected_revision(&self) -> u64 {
        self.target.expected_revision
    }
}

/// A looser setting an edit adds or widens.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Loosening {
    ShorterFreeze {
        seconds: u64,
    },
    Osv(OsvSetting),
    /// An exception lifting what the refusal's `switch` governs.
    Exception {
        ecosystem: Ecosystem,
        name: String,
        version: Option<String>,
    },
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum EditRefusal {
    /// The edit loosens `what`, and the layer above has `switch` off.
    NotAllowedByParent { what: Loosening, switch: SwitchName },
    /// The layer passes down a switch it does not have itself (C45).
    GrantNotHeld { switch: SwitchName },
    /// Malformed input, such as a package name its ecosystem could not publish.
    Invalid(String),
}

/// Accept `proposed` only if every loosening or grant it adds or widens compared with
/// the stored `current` layer is allowed by `parent` (C8, C11, C45). Unchanged kept
/// settings pass and stay not in effect through `resolve` (C47).
pub fn check_edit(
    parent: &EffectivePolicy,
    current: &Layer,
    target: EditTarget,
    proposed: Layer,
) -> Result<CheckedEdit, EditRefusal> {
    if target.place.kind != proposed.kind {
        return Err(EditRefusal::Invalid(format!(
            "a {:?} layer cannot be saved to a {:?} place",
            proposed.kind, target.place.kind
        )));
    }
    if let Some(refusal) = find_loosening(parent, current, &proposed) {
        return Err(refusal);
    }
    Ok(CheckedEdit::accepted(target, proposed))
}

/// The first problem with `proposed`: malformed input, then a looser value or a grant
/// it adds or widens compared with `current` that `parent` does not allow.
fn find_loosening(
    parent: &EffectivePolicy,
    current: &Layer,
    proposed: &Layer,
) -> Option<EditRefusal> {
    if let Some(invalid) = find_invalid(current, proposed) {
        return Some(EditRefusal::Invalid(invalid));
    }
    let refuse = |what, switch| {
        (!parent.allow.get(switch)).then_some(EditRefusal::NotAllowedByParent { what, switch })
    };

    // Looser than the parent's merged value, and not already stored (C47).
    let above = merge(
        &parent.chain,
        |layer| layer.freeze_seconds,
        SwitchName::ShorterFreeze,
        |_| false,
    );
    if let Some(seconds) = proposed.freeze_seconds
        && current.freeze_seconds.is_none_or(|stored| seconds < stored)
        && above.is_some_and(|(above, _)| seconds < above)
        && let Some(refusal) = refuse(
            Loosening::ShorterFreeze { seconds },
            SwitchName::ShorterFreeze,
        )
    {
        return Some(refusal);
    }
    let above = merge(
        &parent.chain,
        |layer| layer.osv,
        SwitchName::OsvOff,
        |_| false,
    );
    if let Some(osv) = proposed.osv
        && current.osv.is_none_or(|stored| osv < stored)
        && above.is_some_and(|(above, _)| osv < above)
        && let Some(refusal) = refuse(Loosening::Osv(osv), SwitchName::OsvOff)
    {
        return Some(refusal);
    }

    for exception in &proposed.exceptions {
        // What the stored entries already lift for this target between them (C47). A
        // stored whole-package entry also covers an exact version's freeze and OSV
        // lifts, but not its block lift: an exact-version exception also lifts that
        // version's file blocks (C106), which a whole-package one never did.
        let stored = current
            .exceptions
            .iter()
            .fold(Lifts::default(), |had, stored| {
                let narrowed = stored.version.is_none()
                    && exception.version.is_some()
                    && same_package(stored, exception);
                if same_target(stored, exception) {
                    Lifts {
                        block: had.block || stored.lifts.block,
                        freeze: had.freeze || stored.lifts.freeze,
                        osv: had.osv || stored.lifts.osv,
                    }
                } else if narrowed {
                    Lifts {
                        freeze: had.freeze || stored.lifts.freeze,
                        osv: had.osv || stored.lifts.osv,
                        ..had
                    }
                } else {
                    had
                }
            });
        for (wanted, had, switch) in [
            (exception.lifts.block, stored.block, SwitchName::Exceptions),
            (
                exception.lifts.freeze,
                stored.freeze,
                SwitchName::ShorterFreeze,
            ),
            (exception.lifts.osv, stored.osv, SwitchName::OsvOff),
        ] {
            let what = Loosening::Exception {
                ecosystem: exception.ecosystem,
                name: exception.name.clone(),
                version: exception.version.clone(),
            };
            if wanted
                && !had
                && let Some(refusal) = refuse(what, switch)
            {
                return Some(refusal);
            }
        }
    }

    [
        SwitchName::Exceptions,
        SwitchName::OsvOff,
        SwitchName::ShorterFreeze,
    ]
    .into_iter()
    .find(|&switch| {
        proposed.allow.get(switch) && !current.allow.get(switch) && !parent.allow.get(switch)
    })
    .map(|switch| EditRefusal::GrantNotHeld { switch })
}

fn same_package(a: &Exception, b: &Exception) -> bool {
    a.ecosystem == b.ecosystem
        && names::canonical_name(a.ecosystem, &a.name)
            == names::canonical_name(b.ecosystem, &b.name)
}

fn same_target(a: &Exception, b: &Exception) -> bool {
    same_package(a, b)
        && match (&a.version, &b.version) {
            (None, None) => true,
            (Some(a_version), Some(b_version)) => {
                names::same_version(a.ecosystem, a_version, b_version)
            }
            _ => false,
        }
}

fn find_invalid(current: &Layer, proposed: &Layer) -> Option<String> {
    if proposed.kind != current.kind {
        return Some(format!(
            "a {:?} layer cannot replace a {:?} layer",
            proposed.kind, current.kind
        ));
    }
    // A layer may shrink back under the cap, never grow past it (T24).
    if proposed.blocks.len() > crate::MAX_LAYER_BLOCKS
        && proposed.blocks.len() > current.blocks.len()
    {
        return Some(format!(
            "a layer holds at most {} blocks",
            crate::MAX_LAYER_BLOCKS
        ));
    }
    let bad_version = |version: &str| version.is_empty() || version.trim() != version;
    for exception in &proposed.exceptions {
        if !names::valid_name(exception.ecosystem, &exception.name) {
            return Some(format!("`{}` is not a package name", exception.name));
        }
        if exception.version.as_deref().is_some_and(bad_version) {
            return Some(format!(
                "the exception on `{}` has an empty or padded version",
                exception.name
            ));
        }
    }
    proposed.blocks.iter().find_map(|block| match block {
        Block::Package {
            ecosystem, name, ..
        }
        | Block::Version {
            ecosystem, name, ..
        } if !names::valid_name(*ecosystem, name) => {
            Some(format!("`{name}` is not a package name"))
        }
        Block::Version { name, version, .. } if bad_version(version) => Some(format!(
            "the block on `{name}` has an empty or padded version"
        )),
        Block::File {
            algorithm, digest, ..
        } => {
            let length = match algorithm {
                DigestAlgorithm::Sha256 => 64,
                DigestAlgorithm::Sha512 => 128,
            };
            (digest.len() != length || !digest.chars().all(|c| c.is_ascii_hexdigit()))
                .then(|| format!("`{digest}` is not a {algorithm:?} digest in hex"))
        }
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::properties::{SHAPES, chain_of, layer_of};
    use crate::{Switches, resolve};
    use proptest::prelude::*;

    const DAY: u64 = 86_400;

    fn target(kind: LayerKind) -> EditTarget {
        EditTarget {
            place: PlaceRef { kind, id: 7 },
            expected_revision: 3,
        }
    }

    /// Platform: 7-day freeze, OSV on, every switch off.
    fn strict_parent() -> EffectivePolicy {
        resolve(&[Layer {
            freeze_seconds: Some(7 * DAY),
            osv: Some(OsvSetting::On),
            ..Layer::empty(LayerKind::Platform)
        }])
    }

    fn exception(lifts: Lifts) -> Exception {
        Exception {
            ecosystem: Ecosystem::Npm,
            name: "left-pad".to_owned(),
            version: Some("1.3.0".to_owned()),
            lifts,
        }
    }

    /// T-edit-refuses-loosening (C8, C45): each loosening names the switch that is off.
    #[test]
    fn t_edit_refuses_loosening() {
        let parent = strict_parent();
        let current = Layer::empty(LayerKind::Org);
        let refused = |proposed: Layer| {
            check_edit(&parent, &current, target(LayerKind::Org), proposed)
                .expect_err("a loosening the parent does not allow")
        };

        assert_eq!(
            refused(Layer {
                freeze_seconds: Some(DAY),
                ..current.clone()
            }),
            EditRefusal::NotAllowedByParent {
                what: Loosening::ShorterFreeze { seconds: DAY },
                switch: SwitchName::ShorterFreeze
            }
        );
        for osv in [OsvSetting::LogOnly, OsvSetting::Off] {
            assert_eq!(
                refused(Layer {
                    osv: Some(osv),
                    ..current.clone()
                }),
                EditRefusal::NotAllowedByParent {
                    what: Loosening::Osv(osv),
                    switch: SwitchName::OsvOff
                }
            );
        }
        let lifted = Loosening::Exception {
            ecosystem: Ecosystem::Npm,
            name: "left-pad".to_owned(),
            version: Some("1.3.0".to_owned()),
        };
        for (lifts, switch) in [
            (
                Lifts {
                    block: true,
                    ..Lifts::default()
                },
                SwitchName::Exceptions,
            ),
            (
                Lifts {
                    freeze: true,
                    ..Lifts::default()
                },
                SwitchName::ShorterFreeze,
            ),
            (
                Lifts {
                    osv: true,
                    ..Lifts::default()
                },
                SwitchName::OsvOff,
            ),
        ] {
            assert_eq!(
                refused(Layer {
                    exceptions: vec![exception(lifts)],
                    ..current.clone()
                }),
                EditRefusal::NotAllowedByParent {
                    what: lifted.clone(),
                    switch
                }
            );
        }
        assert_eq!(
            refused(Layer {
                allow: Switches {
                    osv_off: true,
                    ..Switches::default()
                },
                ..current.clone()
            }),
            EditRefusal::GrantNotHeld {
                switch: SwitchName::OsvOff
            }
        );
        assert!(matches!(
            refused(Layer {
                exceptions: vec![Exception {
                    ecosystem: Ecosystem::PyPi,
                    name: "bad name".to_owned(),
                    ..exception(Lifts::default())
                }],
                ..current.clone()
            }),
            EditRefusal::Invalid(_)
        ));

        // The layer must be the kind of the place it is saved to (code review).
        assert!(matches!(
            check_edit(
                &parent,
                &Layer::empty(LayerKind::Group),
                target(LayerKind::Org),
                Layer::empty(LayerKind::Group)
            ),
            Err(EditRefusal::Invalid(_))
        ));

        // An exact-version block exception also lifts that version's file blocks
        // (C106), which a whole-package one never did, so it is new even beside one.
        let block = Lifts {
            block: true,
            ..Lifts::default()
        };
        let stored_whole_block = Layer {
            exceptions: vec![Exception {
                version: None,
                ..exception(block)
            }],
            ..current.clone()
        };
        assert_eq!(
            check_edit(
                &parent,
                &stored_whole_block,
                target(LayerKind::Org),
                Layer {
                    exceptions: vec![exception(block)],
                    ..current.clone()
                }
            )
            .err(),
            Some(EditRefusal::NotAllowedByParent {
                what: lifted.clone(),
                switch: SwitchName::Exceptions
            })
        );

        // A stored exact-version freeze exception widened to the whole package is a new
        // lift, not the stored one (C47 covers only what is already stored).
        let exact = Layer {
            exceptions: vec![exception(Lifts {
                freeze: true,
                ..Lifts::default()
            })],
            ..current.clone()
        };
        let whole = Layer {
            exceptions: vec![Exception {
                version: None,
                ..exception(Lifts {
                    freeze: true,
                    ..Lifts::default()
                })
            }],
            ..current.clone()
        };
        assert_eq!(
            check_edit(&parent, &exact, target(LayerKind::Org), whole).err(),
            Some(EditRefusal::NotAllowedByParent {
                what: Loosening::Exception {
                    ecosystem: Ecosystem::Npm,
                    name: "left-pad".to_owned(),
                    version: None
                },
                switch: SwitchName::ShorterFreeze
            })
        );
    }

    /// T-edit-accepts-stricter: stricter values and an extra block pass with every
    /// switch off.
    #[test]
    fn t_edit_accepts_stricter() {
        let parent = strict_parent();
        let current = Layer::empty(LayerKind::Org);
        let proposed = Layer {
            freeze_seconds: Some(14 * DAY),
            osv: Some(OsvSetting::On),
            blocks: vec![Block::Package {
                ecosystem: Ecosystem::Npm,
                name: "left-pad".to_owned(),
                reason: None,
            }],
            ..current.clone()
        };
        let checked = check_edit(&parent, &current, target(LayerKind::Org), proposed.clone())
            .expect("a stricter edit is always accepted");
        assert_eq!(checked.layer(), &proposed);
        assert_eq!(
            checked.place(),
            PlaceRef {
                kind: LayerKind::Org,
                id: 7
            }
        );
        assert_eq!(checked.layer_kind(), LayerKind::Org);
        assert_eq!(checked.expected_revision(), 3);

        // A shorter freeze already stored under C47 is not re-checked by an unrelated
        // save: an urgent block still goes through.
        let kept = Layer {
            freeze_seconds: Some(DAY),
            ..current.clone()
        };
        let urgent = Layer {
            blocks: proposed.blocks.clone(),
            ..kept.clone()
        };
        assert!(check_edit(&parent, &kept, target(LayerKind::Org), urgent).is_ok());

        // The same for a kept OSV off.
        let kept_osv = Layer {
            osv: Some(OsvSetting::Off),
            ..current.clone()
        };
        let urgent = Layer {
            blocks: proposed.blocks.clone(),
            ..kept_osv.clone()
        };
        assert!(check_edit(&parent, &kept_osv, target(LayerKind::Org), urgent).is_ok());

        // C47 with two stored exceptions on one target: their lifts together are what
        // is stored, so re-saving the layer unchanged, or with one more block, passes.
        let whole = |lifts| Exception {
            version: None,
            ..exception(lifts)
        };
        let two = Layer {
            exceptions: vec![
                whole(Lifts {
                    freeze: true,
                    ..Lifts::default()
                }),
                whole(Lifts {
                    block: true,
                    ..Lifts::default()
                }),
            ],
            ..current.clone()
        };
        let all_off = resolve(&[Layer::empty(LayerKind::Platform)]);
        assert!(check_edit(&all_off, &two, target(LayerKind::Org), two.clone()).is_ok());
        let one_more_block = Layer {
            blocks: proposed.blocks.clone(),
            ..two.clone()
        };
        assert!(check_edit(&all_off, &two, target(LayerKind::Org), one_more_block).is_ok());

        // Narrowing a stored whole-package freeze exception to one version, in place of
        // it or beside it, widens nothing.
        let freeze = Lifts {
            freeze: true,
            ..Lifts::default()
        };
        let stored_whole = Layer {
            exceptions: vec![whole(freeze)],
            ..current.clone()
        };
        for exceptions in [
            vec![exception(freeze)],
            vec![whole(freeze), exception(freeze)],
        ] {
            let narrowed = Layer {
                exceptions,
                ..stored_whole.clone()
            };
            assert!(check_edit(&parent, &stored_whole, target(LayerKind::Org), narrowed).is_ok());
        }
    }

    /// A parent chain and two layers of the kind below it, over every C9/C10 shape
    /// with a child (Personal under Platform and User under Org included): the stored
    /// layer, and a proposal that takes each field from it or from a fresh one, so
    /// unchanged re-saves (C47) are as common as edits.
    fn edit_case() -> impl Strategy<Value = (Vec<Layer>, Layer, Layer)> {
        prop::sample::select(SHAPES[2..].to_vec()).prop_flat_map(|shape| {
            let (&kind, parents) = shape.split_last().expect("a shape with a child");
            (
                chain_of(parents),
                layer_of(kind),
                layer_of(kind),
                prop::array::uniform5(any::<bool>()),
            )
                .prop_map(move |(parents, current, other, keep)| {
                    let proposed = Layer {
                        kind,
                        freeze_seconds: if keep[0] {
                            current.freeze_seconds
                        } else {
                            other.freeze_seconds
                        },
                        osv: if keep[1] { current.osv } else { other.osv },
                        blocks: if keep[2] {
                            current.blocks.clone()
                        } else {
                            other.blocks
                        },
                        exceptions: if keep[3] {
                            current.exceptions.clone()
                        } else {
                            other.exceptions
                        },
                        allow: if keep[4] { current.allow } else { other.allow },
                    };
                    (parents, current, proposed)
                })
        })
    }

    proptest! {
        // More than the default 256: the narrowing cases (C106) need a stored
        // whole-package entry and a proposed exact one on the same package.
        #![proptest_config(ProptestConfig::with_cases(2048))]

        /// P-check-edit-agrees-with-resolve: an edit is accepted exactly when `resolve`,
        /// with the proposal under its parents, keeps every value the proposal adds or
        /// widens compared with the stored layer.
        #[test]
        fn p_check_edit_agrees_with_resolve((parents, current, proposed) in edit_case()) {
            let parent = resolve(&parents);
            let accepted = check_edit(&parent, &current, target(proposed.kind), proposed.clone()).is_ok();

            let mut chain = parents.clone();
            chain.push(proposed.clone());
            let full = resolve(&chain);
            let rules = full.rules_for(Ecosystem::Npm, "other", "1.0.0");

            let mut kept = true;
            if let Some(freeze) = proposed.freeze_seconds
                && current.freeze_seconds.is_none_or(|stored| freeze < stored)
            {
                kept &= rules.freeze_seconds == freeze;
            }
            if let Some(osv) = proposed.osv
                && current.osv.is_none_or(|stored| osv < stored)
            {
                kept &= rules.osv == osv;
            }
            for exception in &proposed.exceptions {
                // Every stored entry on the same target counts (C47).
                let same = |other: &Exception| {
                    (&other.ecosystem, &other.name, &other.version)
                        == (&exception.ecosystem, &exception.name, &exception.version)
                };
                // A stored whole-package entry covers an exact version's freeze and
                // OSV lifts, never its block lift (C106: file blocks).
                let stored = |lift: fn(&Lifts) -> bool, whole_covers: bool| {
                    current.exceptions.iter().any(|stored| {
                        let covers = same(stored)
                            || (whole_covers
                                && stored.version.is_none()
                                && exception.version.is_some()
                                && (&stored.ecosystem, &stored.name) == (&exception.ecosystem, &exception.name));
                        covers && lift(&stored.lifts)
                    })
                };
                let in_force = |lift: fn(&Lifts) -> bool| {
                    full.exceptions.iter().any(|owned| {
                        owned.owner == proposed.kind && same(&owned.exception) && lift(&owned.exception.lifts)
                    })
                };
                let block: fn(&Lifts) -> bool = |l| l.block;
                let freeze: fn(&Lifts) -> bool = |l| l.freeze;
                let osv: fn(&Lifts) -> bool = |l| l.osv;
                for (wanted, had, has) in [
                    (exception.lifts.block, stored(block, false), in_force(block)),
                    (exception.lifts.freeze, stored(freeze, true), in_force(freeze)),
                    (exception.lifts.osv, stored(osv, true), in_force(osv)),
                ] {
                    if wanted && !had {
                        kept &= has;
                    }
                }
            }
            for switch in [SwitchName::Exceptions, SwitchName::OsvOff, SwitchName::ShorterFreeze] {
                if proposed.allow.get(switch) && !current.allow.get(switch) {
                    kept &= full.allow.get(switch);
                }
            }
            prop_assert_eq!(accepted, kept);
        }
    }
}
