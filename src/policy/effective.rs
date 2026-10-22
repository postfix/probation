//! Decide one request against the compiled policy it runs under.
//!
//! Standalone compiles one policy from `cooldown_seconds`, `osv_mode` and the blocklist
//! file, at start and on every blocklist reload, so its answers are today's (C12).

use std::sync::Arc;

use probation_policy::{
    Block, CandidateRules, DigestAlgorithm, EffectivePolicy, Layer, LayerKind, OsvSetting, names,
    resolve,
};

use super::{BlocklistSnapshot, Candidate, Decision, DenyReason, Digest, HashAlgorithm, evaluate};
use crate::osv::OsvMode;

/// An effective policy plus the firewall's block snapshot built from it. Standalone holds
/// the loaded blocklist file's snapshot, with its expiry, so `Unavailable` answers stay
/// identical.
pub struct CompiledPolicy {
    pub policy: EffectivePolicy,
    pub snapshot: Option<Arc<BlocklistSnapshot>>,
}

impl CompiledPolicy {
    /// The one policy a standalone instance decides under: its cooldown and OSV mode as
    /// the platform layer, and the blocklist file's snapshot, expiry included.
    pub fn standalone(
        cooldown_seconds: u64,
        osv_mode: OsvMode,
        snapshot: Arc<BlocklistSnapshot>,
    ) -> CompiledPolicy {
        let osv = match osv_mode {
            OsvMode::Enforce => OsvSetting::On,
            OsvMode::Diagnostic => OsvSetting::LogOnly,
            OsvMode::Off => OsvSetting::Off,
        };
        let platform = Layer {
            freeze_seconds: Some(cooldown_seconds),
            osv: Some(osv),
            ..Layer::empty(LayerKind::Platform)
        };
        CompiledPolicy {
            policy: resolve(&[platform]),
            snapshot: Some(snapshot),
        }
    }

    /// A managed policy, its blocks compiled into a snapshot with no expiry.
    pub fn managed(policy: EffectivePolicy) -> CompiledPolicy {
        let snapshot = BlocklistSnapshot::from_blocks(&policy.blocks);
        CompiledPolicy {
            policy,
            snapshot: Some(Arc::new(snapshot)),
        }
    }
}

/// Today's decision, plus the layer that caused it and the OSV log-only mark (C23, C81,
/// C92).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PolicyVerdict {
    pub decision: Decision,
    pub layer: Option<LayerKind>,
    pub would_block: bool,
}

/// The arguments today's `evaluate` takes, with every check an exception lifts removed.
struct Rules {
    snapshot: Option<Arc<BlocklistSnapshot>>,
    cooldown_seconds: u64,
    osv_matched: bool,
    would_block: bool,
    own: CandidateRules,
}

/// Decides one candidate under `compiled`, and reads nothing else: exceptions lift rules
/// before today's `evaluate` runs them. Called as `osv::evaluate` does (C110): first with
/// `osv_matched = false`, and again with OSV's answer only on an `Allow` whose rules do
/// not turn OSV off.
#[rustfmt::skip] // the two statements below are matched verbatim by an SMTC control
pub fn decide(compiled: &CompiledPolicy, candidate: &Candidate<'_>, now_utc_micros: i64, osv_matched: bool) -> PolicyVerdict {
    let rules = apply_exceptions(compiled, candidate, osv_matched);
    let decision = evaluate(rules.snapshot.as_deref(), now_utc_micros, rules.cooldown_seconds, candidate, rules.osv_matched);
    attribute(compiled, candidate, decision, &rules)
}

fn apply_exceptions(
    compiled: &CompiledPolicy,
    candidate: &Candidate<'_>,
    osv_matched: bool,
) -> Rules {
    // Per candidate: an exception at layer E lifts only rules owned at or above E (C8,
    // C46); freeze and OSV are the C8 merge over the unlifted layers (C11).
    let own = compiled
        .policy
        .rules_for(candidate.ecosystem, candidate.name, candidate.version);
    Rules {
        snapshot: compiled
            .snapshot
            .as_ref()
            .map(|snapshot| snapshot.without(&own.lifted_blocks)),
        cooldown_seconds: own.freeze_seconds,
        osv_matched: osv_matched && own.osv == OsvSetting::On,
        would_block: osv_matched && own.osv == OsvSetting::LogOnly,
        own,
    }
}

/// Names the layer behind a Deny or Hold from the rules that survived the lift: the
/// highest unlifted block owner matching the candidate, `freeze_from`, or `osv_from`
/// (C23, C92).
fn attribute(
    compiled: &CompiledPolicy,
    candidate: &Candidate<'_>,
    decision: Decision,
    rules: &Rules,
) -> PolicyVerdict {
    let own = &rules.own;
    // A log-only match only marks what was otherwise allowed (C81).
    let would_block = rules.would_block && decision == Decision::Allow;
    let blocked_by = |matches: &dyn Fn(&Block) -> bool| {
        compiled
            .policy
            .blocks
            .iter()
            .filter(|owned| !own.lifted_blocks.contains(&owned.id) && matches(&owned.block))
            .map(|owned| owned.owner)
            .min()
    };
    let layer = match decision {
        Decision::Deny(DenyReason::BlockedPackage) => blocked_by(&|block| {
            matches!(block, Block::Package { ecosystem, name }
                if *ecosystem == candidate.ecosystem && name == candidate.name)
        }),
        Decision::Deny(DenyReason::BlockedVersion) => blocked_by(&|block| {
            matches!(block, Block::Version { ecosystem, name, version }
                if *ecosystem == candidate.ecosystem
                    && name == candidate.name
                    && names::same_version(*ecosystem, version, candidate.version))
        }),
        Decision::Deny(DenyReason::BlockedDigest) => blocked_by(&|block| {
            let Block::File { algorithm, digest } = block else {
                return false;
            };
            let algorithm = match algorithm {
                DigestAlgorithm::Sha256 => HashAlgorithm::Sha256,
                DigestAlgorithm::Sha512 => HashAlgorithm::Sha512,
            };
            Digest::parse_hex(algorithm, digest).is_ok_and(|blocked| {
                candidate
                    .advertised_digests
                    .iter()
                    .chain(candidate.pinned_digests)
                    .any(|digest| *digest == blocked)
            })
        }),
        Decision::Deny(DenyReason::BlockedByOsv) => own.osv_from,
        Decision::Hold { .. } => own.freeze_from,
        Decision::Allow if would_block => own.osv_from,
        _ => None,
    };
    PolicyVerdict {
        decision,
        layer,
        would_block,
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use probation_policy::{
        Block, DigestAlgorithm, Ecosystem as PolicyEcosystem, Exception, Layer, Lifts, OsvSetting,
        Switches, resolve,
    };

    use super::*;
    use crate::osv::OsvMode;
    use crate::policy::{DenyReason, Digest, Ecosystem, HashAlgorithm, PublicationTime};

    const SECOND: i64 = 1_000_000;
    const DAY_SECONDS: u64 = 86_400;
    const DAY: i64 = 86_400 * SECOND;
    const SHA256: &str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

    fn at(rfc3339: &str) -> i64 {
        jiff::Timestamp::from_str(rfc3339)
            .expect("a test timestamp")
            .as_microsecond()
    }

    fn now() -> i64 {
        at("2026-09-17T00:00:00Z")
    }

    fn snapshot_with(records: &str, hashes: &str) -> Arc<BlocklistSnapshot> {
        let json = format!(
            r#"{{"schema_version":1,"revision":7,
                 "generated_at":"2020-01-01T00:00:00Z","expires_at":"2099-01-01T00:00:00Z",
                 "blocked_packages":[{records}],"blocked_hashes":[{hashes}]}}"#
        );
        Arc::new(
            BlocklistSnapshot::parse_and_validate(json.as_bytes(), now())
                .expect("the test snapshot is valid"),
        )
    }

    fn candidate<'a>(
        name: &'a str,
        version: &'a str,
        publication: PublicationTime,
        advertised: &'a [Digest],
    ) -> Candidate<'a> {
        Candidate {
            ecosystem: Ecosystem::Npm,
            name,
            version,
            publication,
            advertised_digests: advertised,
            pinned_digests: &[],
        }
    }

    fn old() -> PublicationTime {
        PublicationTime::Upstream(now() - 10 * DAY)
    }

    fn sha256() -> Digest {
        Digest::parse_hex(HashAlgorithm::Sha256, SHA256).expect("a digest")
    }

    fn layer(kind: LayerKind) -> Layer {
        Layer {
            allow: Switches::ALL,
            ..Layer::empty(kind)
        }
    }

    fn package(name: &str) -> Block {
        Block::Package {
            ecosystem: PolicyEcosystem::Npm,
            name: name.to_owned(),
        }
    }

    fn exception(name: &str, version: Option<&str>, lifts: Lifts) -> Exception {
        Exception {
            ecosystem: PolicyEcosystem::Npm,
            name: name.to_owned(),
            version: version.map(str::to_owned),
            lifts,
        }
    }

    const BLOCK: Lifts = Lifts {
        block: true,
        freeze: false,
        osv: false,
    };
    const FREEZE: Lifts = Lifts {
        block: false,
        freeze: true,
        osv: false,
    };
    const OSV: Lifts = Lifts {
        block: false,
        freeze: false,
        osv: true,
    };

    fn compiled(chain: &[Layer]) -> CompiledPolicy {
        CompiledPolicy::managed(resolve(chain))
    }

    /// T-decide-matches-standalone (C12): every case of the existing `policy` tests,
    /// decided through the standalone policy, gives the same `Decision`.
    #[test]
    fn t_decide_matches_standalone() {
        let now = now();
        let published = at("2026-09-16T00:00:00Z");
        let eligible = published + DAY;
        let fresh = PublicationTime::Upstream(now - SECOND);
        let clear = snapshot_with("", "");
        let package_blocked = snapshot_with(
            r#"{"ecosystem":"npm","name":"left-pad","version":null,"reason":"malware"},
               {"ecosystem":"npm","name":"left-pad","version":"1.3.0","reason":"malware"}"#,
            "",
        );
        let version_blocked = snapshot_with(
            r#"{"ecosystem":"npm","name":"left-pad","version":"1.3.0","reason":"malware"}"#,
            "",
        );
        let sha256_blocked = snapshot_with(
            "",
            &format!(r#"{{"algorithm":"sha256","digest":"{SHA256}","reason":"malware"}}"#),
        );
        let sha512 = "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043";
        let sha512_blocked = snapshot_with(
            "",
            &format!(r#"{{"algorithm":"sha512","digest":"{sha512}","reason":"malware"}}"#),
        );
        let blocked_sha512 = [Digest::parse_hex(HashAlgorithm::Sha512, sha512).expect("a digest")];
        let other_sha512 =
            [Digest::parse_hex(HashAlgorithm::Sha512, &"a".repeat(128)).expect("a digest")];
        let expired = Arc::new(
            BlocklistSnapshot::parse_and_validate(
                br#"{"schema_version":1,"revision":1,
                     "generated_at":"2026-09-10T00:00:00Z","expires_at":"2026-09-11T00:00:00Z",
                     "blocked_packages":[{"ecosystem":"npm","name":"left-pad","version":null,"reason":"malware"}],
                     "blocked_hashes":[]}"#,
                at("2026-09-10T12:00:00Z"),
            )
            .expect("valid inside its own window"),
        );
        let pinned = [sha256()];
        let none: &[Digest] = &[];
        let almost_max = (i64::MAX / SECOND) as u64;

        // (snapshot, now, cooldown, publication, advertised, pinned, osv_matched, expected)
        #[allow(clippy::type_complexity)]
        let cases: Vec<(
            Option<&Arc<BlocklistSnapshot>>,
            i64,
            u64,
            PublicationTime,
            &[Digest],
            &[Digest],
            bool,
            Decision,
        )> = vec![
            // cooldown_before_at_and_after_threshold
            (
                Some(&clear),
                eligible - 1,
                DAY_SECONDS,
                PublicationTime::Upstream(published),
                none,
                none,
                false,
                Decision::Hold {
                    eligible_at_micros: eligible,
                },
            ),
            (
                Some(&clear),
                eligible,
                DAY_SECONDS,
                PublicationTime::Upstream(published),
                none,
                none,
                false,
                Decision::Allow,
            ),
            (
                Some(&clear),
                eligible + SECOND,
                DAY_SECONDS,
                PublicationTime::Upstream(published),
                none,
                none,
                false,
                Decision::Allow,
            ),
            // zero_cooldown_disables_only_the_age_rule
            (
                Some(&clear),
                now,
                0,
                PublicationTime::Upstream(now),
                none,
                none,
                false,
                Decision::Allow,
            ),
            (
                Some(&package_blocked),
                now,
                0,
                PublicationTime::Upstream(now),
                none,
                none,
                false,
                Decision::Deny(DenyReason::BlockedPackage),
            ),
            // malformed_and_future_timestamps_deny
            (
                Some(&clear),
                now,
                DAY_SECONDS,
                PublicationTime::Malformed,
                none,
                none,
                false,
                Decision::Deny(DenyReason::MalformedTimestamp),
            ),
            (
                Some(&clear),
                now,
                DAY_SECONDS,
                PublicationTime::Upstream(now + SECOND),
                none,
                none,
                false,
                Decision::Deny(DenyReason::FutureTimestamp),
            ),
            (
                Some(&clear),
                now,
                0,
                PublicationTime::Upstream(now + 1),
                none,
                none,
                false,
                Decision::Deny(DenyReason::FutureTimestamp),
            ),
            // unknown_timestamp_denies
            (
                Some(&clear),
                now,
                DAY_SECONDS,
                PublicationTime::Unknown,
                none,
                none,
                false,
                Decision::Deny(DenyReason::NoTimestamp),
            ),
            (
                Some(&clear),
                now,
                0,
                PublicationTime::Unknown,
                none,
                none,
                false,
                Decision::Deny(DenyReason::NoTimestamp),
            ),
            (
                Some(&clear),
                now,
                DAY_SECONDS,
                PublicationTime::FirstSeen(now - 10 * DAY),
                none,
                none,
                false,
                Decision::Allow,
            ),
            // check_order_is_unavailable_deny_hold_allow
            (
                Some(&expired),
                now,
                DAY_SECONDS,
                old(),
                none,
                none,
                false,
                Decision::Unavailable,
            ),
            (
                Some(&package_blocked),
                now,
                DAY_SECONDS,
                fresh,
                none,
                none,
                false,
                Decision::Deny(DenyReason::BlockedPackage),
            ),
            (
                Some(&version_blocked),
                now,
                DAY_SECONDS,
                old(),
                none,
                none,
                false,
                Decision::Deny(DenyReason::BlockedVersion),
            ),
            (
                Some(&sha256_blocked),
                now,
                DAY_SECONDS,
                old(),
                none,
                &pinned,
                false,
                Decision::Deny(DenyReason::BlockedDigest),
            ),
            (
                Some(&clear),
                now,
                DAY_SECONDS,
                fresh,
                none,
                none,
                false,
                Decision::Hold {
                    eligible_at_micros: now - SECOND + DAY,
                },
            ),
            (
                Some(&clear),
                now,
                DAY_SECONDS,
                old(),
                none,
                none,
                false,
                Decision::Allow,
            ),
            (
                None,
                now,
                DAY_SECONDS,
                old(),
                none,
                none,
                false,
                Decision::Unavailable,
            ),
            (
                Some(&clear),
                now,
                DAY_SECONDS,
                fresh,
                none,
                none,
                true,
                Decision::Deny(DenyReason::BlockedByOsv),
            ),
            // osv_matched_true_denies_before_digest_check
            (
                Some(&clear),
                now,
                DAY_SECONDS,
                old(),
                none,
                none,
                true,
                Decision::Deny(DenyReason::BlockedByOsv),
            ),
            // evaluate_never_lets_osv_unblock_a_producer_deny
            (
                Some(&package_blocked),
                now,
                DAY_SECONDS,
                old(),
                none,
                none,
                false,
                Decision::Deny(DenyReason::BlockedPackage),
            ),
            // blocked_digest_matches_pinned_and_advertised
            (
                Some(&sha512_blocked),
                now,
                DAY_SECONDS,
                old(),
                &blocked_sha512,
                none,
                false,
                Decision::Deny(DenyReason::BlockedDigest),
            ),
            (
                Some(&sha512_blocked),
                now,
                DAY_SECONDS,
                old(),
                &other_sha512,
                &blocked_sha512,
                false,
                Decision::Deny(DenyReason::BlockedDigest),
            ),
            (
                Some(&sha512_blocked),
                now,
                DAY_SECONDS,
                old(),
                &other_sha512,
                none,
                false,
                Decision::Allow,
            ),
            // deadline_arithmetic_is_checked
            (
                Some(&clear),
                now,
                u64::MAX,
                PublicationTime::Upstream(now - SECOND),
                none,
                none,
                false,
                Decision::Hold {
                    eligible_at_micros: i64::MAX,
                },
            ),
            (
                Some(&clear),
                now,
                almost_max,
                PublicationTime::Upstream(now - SECOND),
                none,
                none,
                false,
                Decision::Hold {
                    eligible_at_micros: i64::MAX,
                },
            ),
            (
                Some(&clear),
                now,
                DAY_SECONDS,
                PublicationTime::Upstream(i64::MAX),
                none,
                none,
                false,
                Decision::Deny(DenyReason::FutureTimestamp),
            ),
        ];

        for (index, (snapshot, now, cooldown, publication, advertised, pinned, osv, expected)) in
            cases.into_iter().enumerate()
        {
            let compiled = CompiledPolicy {
                snapshot: snapshot.cloned(),
                ..CompiledPolicy::standalone(cooldown, OsvMode::Enforce, Arc::clone(&clear))
            };
            let candidate = Candidate {
                pinned_digests: pinned,
                ..candidate("left-pad", "1.3.0", publication, advertised)
            };
            let verdict = decide(&compiled, &candidate, now, osv);
            assert_eq!(verdict.decision, expected, "case {index}");
            assert!(!verdict.would_block, "case {index}");
        }

        // `osv_mode = "diagnostic"` (LogOnly) marks a match "would have blocked" only on
        // an Allow (C81): never on a deny, a hold or an expired blocklist.
        let diagnostic = |snapshot: &Arc<BlocklistSnapshot>| {
            CompiledPolicy::standalone(DAY_SECONDS, OsvMode::Diagnostic, Arc::clone(snapshot))
        };
        for (snapshot, publication, expected) in [
            (
                &package_blocked,
                old(),
                Decision::Deny(DenyReason::BlockedPackage),
            ),
            (
                &clear,
                fresh,
                Decision::Hold {
                    eligible_at_micros: now - SECOND + DAY,
                },
            ),
            (&expired, old(), Decision::Unavailable),
        ] {
            let candidate = candidate("left-pad", "1.3.0", publication, none);
            let verdict = decide(&diagnostic(snapshot), &candidate, now, true);
            assert_eq!(verdict.decision, expected);
            assert!(!verdict.would_block, "{expected:?} is not a would-block");
        }

        // C12 parity through `decide`: diagnostic allows a match and marks it, Off
        // ignores it.
        let candidate = candidate("left-pad", "1.3.0", old(), none);
        assert_eq!(
            decide(&diagnostic(&clear), &candidate, now, true),
            PolicyVerdict {
                decision: Decision::Allow,
                layer: Some(LayerKind::Platform),
                would_block: true
            }
        );
        let off = CompiledPolicy::standalone(DAY_SECONDS, OsvMode::Off, Arc::clone(&clear));
        assert_eq!(
            decide(&off, &candidate, now, true),
            PolicyVerdict {
                decision: Decision::Allow,
                layer: None,
                would_block: false
            }
        );
    }

    /// T-decide-exception-lifts (C8, C16, C17, C46, C106): an exception lifts only the
    /// rules it names, owned at or above its own layer.
    #[test]
    fn t_decide_exception_lifts() {
        let now = now();
        let decide_old = |chain: &[Layer], version: &str, advertised: &[Digest], osv: bool| {
            decide(
                &compiled(chain),
                &candidate("left-pad", version, old(), advertised),
                now,
                osv,
            )
        };
        let org_exception = |lifts| Layer {
            exceptions: vec![exception("left-pad", None, lifts)],
            ..layer(LayerKind::Org)
        };

        // (a) An org exception does not lift a group block.
        let verdict = decide_old(
            &[
                layer(LayerKind::Platform),
                org_exception(BLOCK),
                Layer {
                    blocks: vec![package("left-pad")],
                    ..layer(LayerKind::Group)
                },
            ],
            "1.0.0",
            &[],
            false,
        );
        assert_eq!(verdict.decision, Decision::Deny(DenyReason::BlockedPackage));
        assert_eq!(verdict.layer, Some(LayerKind::Group));

        // (b) It lifts a platform block.
        let platform_block = Layer {
            blocks: vec![package("left-pad")],
            ..layer(LayerKind::Platform)
        };
        let verdict = decide_old(
            &[platform_block.clone(), org_exception(BLOCK)],
            "1.0.0",
            &[],
            false,
        );
        assert_eq!(verdict.decision, Decision::Allow);
        assert_eq!(verdict.layer, None);

        // (c) An org whole-package freeze exception lifts the org's own freeze and the
        // platform's: a release published an hour ago is eligible.
        let verdict = decide(
            &compiled(&[
                Layer {
                    freeze_seconds: Some(DAY_SECONDS),
                    ..layer(LayerKind::Platform)
                },
                Layer {
                    freeze_seconds: Some(2 * DAY_SECONDS),
                    exceptions: vec![exception("@acme/ui-kit", None, FREEZE)],
                    ..layer(LayerKind::Org)
                },
            ]),
            &candidate(
                "@acme/ui-kit",
                "3.1.0",
                PublicationTime::Upstream(now - 3_600 * SECOND),
                &[],
            ),
            now,
            false,
        );
        assert_eq!(verdict.decision, Decision::Allow);

        // (d) It does not lift a group freeze below it.
        let published = now - 2 * DAY;
        let verdict = decide(
            &compiled(&[
                Layer {
                    freeze_seconds: Some(7 * DAY_SECONDS),
                    ..layer(LayerKind::Platform)
                },
                org_exception(FREEZE),
                Layer {
                    freeze_seconds: Some(7 * DAY_SECONDS),
                    ..layer(LayerKind::Group)
                },
            ]),
            &candidate(
                "left-pad",
                "1.0.0",
                PublicationTime::Upstream(published),
                &[],
            ),
            now,
            false,
        );
        assert_eq!(
            verdict.decision,
            Decision::Hold {
                eligible_at_micros: published + 7 * DAY
            }
        );
        assert_eq!(verdict.layer, Some(LayerKind::Group));

        // (e) Nor a group OSV setting below it.
        let osv_on = |kind| Layer {
            osv: Some(OsvSetting::On),
            ..layer(kind)
        };
        let verdict = decide_old(
            &[
                osv_on(LayerKind::Platform),
                org_exception(OSV),
                osv_on(LayerKind::Group),
            ],
            "1.0.0",
            &[],
            true,
        );
        assert_eq!(verdict.decision, Decision::Deny(DenyReason::BlockedByOsv));
        assert_eq!(verdict.layer, Some(LayerKind::Group));
        // Without the group's setting the exception lifts the platform's.
        let verdict = decide_old(
            &[osv_on(LayerKind::Platform), org_exception(OSV)],
            "1.0.0",
            &[],
            true,
        );
        assert_eq!(verdict.decision, Decision::Allow);

        // (f) Applied one by one: an org exact-version exception sits above a group file
        // block, and a user whole-package exception never lifts a file block (C106).
        let file_block = Block::File {
            algorithm: DigestAlgorithm::Sha256,
            digest: SHA256.to_owned(),
        };
        let verdict = decide_old(
            &[
                layer(LayerKind::Platform),
                Layer {
                    exceptions: vec![exception("left-pad", Some("1.0.0"), BLOCK)],
                    ..layer(LayerKind::Org)
                },
                Layer {
                    blocks: vec![file_block.clone()],
                    ..layer(LayerKind::Group)
                },
                Layer {
                    exceptions: vec![exception("left-pad", None, BLOCK)],
                    ..layer(LayerKind::User)
                },
            ],
            "1.0.0",
            &[sha256()],
            false,
        );
        assert_eq!(verdict.decision, Decision::Deny(DenyReason::BlockedDigest));
        assert_eq!(verdict.layer, Some(LayerKind::Group));

        // An exception lifts only what it names. An exact version lifts that version
        // only.
        let exact = [
            platform_block.clone(),
            Layer {
                exceptions: vec![exception("left-pad", Some("1.0.0"), BLOCK)],
                ..layer(LayerKind::Org)
            },
        ];
        assert_eq!(
            decide_old(&exact, "1.0.0", &[], false).decision,
            Decision::Allow
        );
        assert_eq!(
            decide_old(&exact, "1.1.0", &[], false).decision,
            Decision::Deny(DenyReason::BlockedPackage)
        );
        // A block lift leaves the freeze, and a freeze lift leaves the block.
        let fresh = candidate(
            "left-pad",
            "1.0.0",
            PublicationTime::Upstream(now - DAY),
            &[],
        );
        let frozen_and_blocked = |lifts| {
            compiled(&[
                Layer {
                    freeze_seconds: Some(7 * DAY_SECONDS),
                    ..platform_block.clone()
                },
                org_exception(lifts),
            ])
        };
        assert!(matches!(
            decide(&frozen_and_blocked(BLOCK), &fresh, now, false).decision,
            Decision::Hold { .. }
        ));
        assert_eq!(
            decide(&frozen_and_blocked(FREEZE), &fresh, now, false).decision,
            Decision::Deny(DenyReason::BlockedPackage)
        );
        // C106: a whole-package exception leaves a file block in force, an exact-version
        // one lifts it.
        let platform_file_block = Layer {
            blocks: vec![file_block],
            ..layer(LayerKind::Platform)
        };
        assert_eq!(
            decide_old(
                &[platform_file_block.clone(), org_exception(BLOCK)],
                "1.0.0",
                &[sha256()],
                false
            )
            .decision,
            Decision::Deny(DenyReason::BlockedDigest)
        );
        assert_eq!(
            decide_old(
                &[
                    platform_file_block,
                    Layer {
                        exceptions: vec![exception("left-pad", Some("1.0.0"), BLOCK)],
                        ..layer(LayerKind::Org)
                    }
                ],
                "1.0.0",
                &[sha256()],
                false
            )
            .decision,
            Decision::Allow
        );

        // C16, C46: with the platform's switches off, an org exception lifts nothing.
        let verdict = decide_old(
            &[
                Layer {
                    blocks: vec![package("left-pad")],
                    ..Layer::empty(LayerKind::Platform)
                },
                org_exception(Lifts {
                    block: true,
                    freeze: true,
                    osv: true,
                }),
            ],
            "1.0.0",
            &[],
            false,
        );
        assert_eq!(verdict.decision, Decision::Deny(DenyReason::BlockedPackage));
        assert_eq!(verdict.layer, Some(LayerKind::Platform));

        // PyPI names and versions are compared in canonical form (T6).
        let pypi = |exceptions| {
            compiled(&[
                Layer {
                    blocks: vec![
                        Block::Package {
                            ecosystem: PolicyEcosystem::PyPi,
                            name: "Foo_Bar".to_owned(),
                        },
                        Block::Version {
                            ecosystem: PolicyEcosystem::PyPi,
                            name: "Zope.Interface".to_owned(),
                            version: "5.0".to_owned(),
                        },
                    ],
                    ..layer(LayerKind::Platform)
                },
                Layer {
                    exceptions,
                    ..layer(LayerKind::Org)
                },
            ])
        };
        let pypi_candidate = |name| Candidate {
            ecosystem: Ecosystem::PyPi,
            ..candidate(name, "5.0", old(), &[])
        };
        let excepted = pypi(vec![Exception {
            ecosystem: PolicyEcosystem::PyPi,
            name: "zope_interface".to_owned(),
            version: Some("5.0.0".to_owned()),
            lifts: BLOCK,
        }]);
        let verdict = decide(&excepted, &pypi_candidate("foo-bar"), now, false);
        assert_eq!(verdict.decision, Decision::Deny(DenyReason::BlockedPackage));
        assert_eq!(verdict.layer, Some(LayerKind::Platform));
        assert_eq!(
            decide(&excepted, &pypi_candidate("zope-interface"), now, false).decision,
            Decision::Allow
        );
        let verdict = decide(
            &pypi(Vec::new()),
            &pypi_candidate("zope-interface"),
            now,
            false,
        );
        assert_eq!(verdict.decision, Decision::Deny(DenyReason::BlockedVersion));
        assert_eq!(verdict.layer, Some(LayerKind::Platform));

        // C47 kept values stay in the chain and the merge drops them, which is
        // stricter: once the org's exception lifts the platform freeze, the group's kept
        // one-day freeze is the strictest left; for any other package the platform's
        // seven days apply.
        let kept = compiled(&[
            Layer {
                freeze_seconds: Some(7 * DAY_SECONDS),
                ..layer(LayerKind::Platform)
            },
            Layer {
                exceptions: vec![exception("left-pad", None, FREEZE)],
                ..Layer::empty(LayerKind::Org)
            },
            Layer {
                freeze_seconds: Some(DAY_SECONDS),
                ..layer(LayerKind::Group)
            },
        ]);
        let published = now - DAY / 2;
        let verdict = decide(
            &kept,
            &candidate(
                "left-pad",
                "1.0.0",
                PublicationTime::Upstream(published),
                &[],
            ),
            now,
            false,
        );
        assert_eq!(
            verdict.decision,
            Decision::Hold {
                eligible_at_micros: published + DAY
            }
        );
        assert_eq!(verdict.layer, Some(LayerKind::Group));
        let verdict = decide(
            &kept,
            &candidate("other", "1.0.0", PublicationTime::Upstream(published), &[]),
            now,
            false,
        );
        assert_eq!(
            verdict.decision,
            Decision::Hold {
                eligible_at_micros: published + 7 * DAY
            }
        );
        assert_eq!(verdict.layer, Some(LayerKind::Platform));
    }

    /// T-decide-allowed-looser (C8, C11): a looser value the layer above allows takes
    /// effect; one it does not is ignored.
    #[test]
    fn t_decide_allowed_looser() {
        let now = now();
        let published = now - 2 * DAY;
        let two_days_old = candidate(
            "left-pad",
            "1.0.0",
            PublicationTime::Upstream(published),
            &[],
        );
        let freeze = |shorter_freeze| {
            compiled(&[
                Layer {
                    freeze_seconds: Some(7 * DAY_SECONDS),
                    allow: Switches {
                        shorter_freeze,
                        ..Switches::default()
                    },
                    ..Layer::empty(LayerKind::Platform)
                },
                Layer {
                    freeze_seconds: Some(DAY_SECONDS),
                    ..Layer::empty(LayerKind::Org)
                },
            ])
        };

        // (a) Allowed: the org's one-day freeze applies.
        assert_eq!(
            decide(&freeze(true), &two_days_old, now, false).decision,
            Decision::Allow
        );
        // (b) Not allowed: the platform's seven days apply.
        let verdict = decide(&freeze(false), &two_days_old, now, false);
        assert_eq!(
            verdict.decision,
            Decision::Hold {
                eligible_at_micros: published + 7 * DAY
            }
        );
        assert_eq!(verdict.layer, Some(LayerKind::Platform));

        // (c) The org turns OSV off where the platform allows it: a match does not deny,
        // and the OSV gate says not to ask.
        let osv_off = compiled(&[
            Layer {
                osv: Some(OsvSetting::On),
                allow: Switches {
                    osv_off: true,
                    ..Switches::default()
                },
                ..Layer::empty(LayerKind::Platform)
            },
            Layer {
                osv: Some(OsvSetting::Off),
                ..Layer::empty(LayerKind::Org)
            },
        ]);
        let candidate = candidate("left-pad", "1.0.0", old(), &[]);
        assert_eq!(
            osv_off
                .policy
                .rules_for(PolicyEcosystem::Npm, "left-pad", "1.0.0")
                .osv,
            OsvSetting::Off
        );
        let verdict = decide(&osv_off, &candidate, now, true);
        assert_eq!(verdict.decision, Decision::Allow);
        assert!(!verdict.would_block);
    }

    /// T-decide-reports-layer (C23, C92): the decision names the layer behind it.
    #[test]
    fn t_decide_reports_layer() {
        let now = now();
        let policy = compiled(&[
            Layer {
                blocks: vec![package("a"), package("c")],
                ..layer(LayerKind::Platform)
            },
            Layer {
                freeze_seconds: Some(7 * DAY_SECONDS),
                blocks: vec![Block::Version {
                    ecosystem: PolicyEcosystem::Npm,
                    name: "d".to_owned(),
                    version: "1.0.0".to_owned(),
                }],
                exceptions: vec![exception("c", None, BLOCK)],
                ..layer(LayerKind::Org)
            },
            Layer {
                osv: Some(OsvSetting::LogOnly),
                blocks: vec![package("c")],
                ..layer(LayerKind::Group)
            },
        ]);

        let verdict = decide(&policy, &candidate("a", "1.0.0", old(), &[]), now, false);
        assert_eq!(verdict.decision, Decision::Deny(DenyReason::BlockedPackage));
        assert_eq!(verdict.layer, Some(LayerKind::Platform));

        let published = now - DAY;
        let verdict = decide(
            &policy,
            &candidate("b", "1.0.0", PublicationTime::Upstream(published), &[]),
            now,
            false,
        );
        assert_eq!(
            verdict.decision,
            Decision::Hold {
                eligible_at_micros: published + 7 * DAY
            }
        );
        assert_eq!(verdict.layer, Some(LayerKind::Org));

        let verdict = decide(&policy, &candidate("b", "1.0.0", old(), &[]), now, true);
        assert_eq!(verdict.decision, Decision::Allow);
        assert!(verdict.would_block);
        assert_eq!(verdict.layer, Some(LayerKind::Group));

        let verdict = decide(&policy, &candidate("c", "1.0.0", old(), &[]), now, false);
        assert_eq!(verdict.decision, Decision::Deny(DenyReason::BlockedPackage));
        assert_eq!(verdict.layer, Some(LayerKind::Group));

        // A version block names its layer too, matched by semver precedence.
        let verdict = decide(
            &policy,
            &candidate("d", "1.0.0+build", old(), &[]),
            now,
            false,
        );
        assert_eq!(verdict.decision, Decision::Deny(DenyReason::BlockedVersion));
        assert_eq!(verdict.layer, Some(LayerKind::Org));

        // The highest owner is named when two layers block the same package, and an
        // equal freeze below does not take the attribution from the layer above.
        let twice = compiled(&[
            Layer {
                freeze_seconds: Some(7 * DAY_SECONDS),
                blocks: vec![package("e")],
                ..layer(LayerKind::Platform)
            },
            Layer {
                freeze_seconds: Some(7 * DAY_SECONDS),
                ..layer(LayerKind::Org)
            },
            Layer {
                blocks: vec![package("e")],
                ..layer(LayerKind::Group)
            },
        ]);
        let verdict = decide(&twice, &candidate("e", "1.0.0", old(), &[]), now, false);
        assert_eq!(verdict.decision, Decision::Deny(DenyReason::BlockedPackage));
        assert_eq!(verdict.layer, Some(LayerKind::Platform));
        let verdict = decide(
            &twice,
            &candidate("f", "1.0.0", PublicationTime::Upstream(published), &[]),
            now,
            false,
        );
        assert!(matches!(verdict.decision, Decision::Hold { .. }));
        assert_eq!(verdict.layer, Some(LayerKind::Platform));
    }
}
