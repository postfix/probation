//! The pure rule block of SPEC §5: no I/O, no clock, no configuration lookup.
//!
//! `evaluate` is handed one `now` and one blocklist snapshot, so a decision cannot
//! be made from two different readings of either.

pub mod blocklist;
pub mod digest;

pub use blocklist::{BlocklistError, BlocklistSnapshot, Replacement, check_replacement};
pub use digest::{Digest, HashAlgorithm, InvalidDigest};

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
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

    /// Indexes the per-ecosystem lookup tables in `blocklist.rs`.
    pub(crate) const fn index(self) -> usize {
        match self {
            Ecosystem::Npm => 0,
            Ecosystem::PyPi => 1,
        }
    }
}

/// Where the age of a candidate comes from. `Malformed` and `Unknown` are distinct
/// because SPEC §5 denies the first and forbids serving the second before it is
/// persisted.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PublicationTime {
    Upstream(i64),
    /// Already committed to storage.
    FirstSeen(i64),
    /// Upstream supplied a value we could not parse.
    Malformed,
    /// No upstream value and no committed first-seen yet.
    Unknown,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Decision {
    /// No valid blocklist is in force.
    Unavailable,
    Deny(DenyReason),
    Hold {
        eligible_at_micros: i64,
    },
    Allow,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DenyReason {
    BlockedPackage,
    BlockedVersion,
    BlockedDigest,
    MalformedTimestamp,
    FutureTimestamp,
    NoTimestamp,
    /// A confirmed OSV `MAL-*` match (`osv_matched: true` on `evaluate`). Checked at
    /// the same tier as the producer package/version checks, before the digest check.
    BlockedByOsv,
}

/// One thing being judged: an npm version, or one PyPI file.
pub struct Candidate<'a> {
    pub ecosystem: Ecosystem,
    /// Normalised name.
    pub name: &'a str,
    /// Upstream spelling of the version.
    pub version: &'a str,
    pub publication: PublicationTime,
    /// Digests upstream advertised for these bytes.
    pub advertised_digests: &'a [Digest],
    /// Digests we computed ourselves and pinned permanently (SPEC §15, STATE-01).
    /// A block on one of these denies bytes upstream never described.
    pub pinned_digests: &'a [Digest],
}

/// SPEC §5, in its fixed order, with one `now` and one snapshot.
///
/// ```text
/// if blocklist is missing or expired: UNAVAILABLE
/// if package or package/version is blocked: DENY
/// if any known artifact digest is blocked: DENY
/// if publication time is malformed or in the future: DENY
/// if now < effective_publication_time + cooldown: HOLD(until)
/// otherwise: ALLOW
/// ```
pub fn evaluate(
    snapshot: Option<&BlocklistSnapshot>,
    now_utc_micros: i64,
    cooldown_seconds: u64,
    candidate: &Candidate<'_>,
    osv_matched: bool,
) -> Decision {
    let Some(snapshot) = snapshot else {
        return Decision::Unavailable;
    };
    if !snapshot.is_valid_at(now_utc_micros) {
        return Decision::Unavailable;
    }

    if snapshot.blocks_package(candidate.ecosystem, candidate.name) {
        return Decision::Deny(DenyReason::BlockedPackage);
    }
    if snapshot.blocks_version(candidate.ecosystem, candidate.name, candidate.version) {
        return Decision::Deny(DenyReason::BlockedVersion);
    }
    // Checked at the same tier as the producer package/version checks, before the
    // digest check (Gate 2 Fit table) — and never resolved here: the caller
    // (`osv::evaluate`) is the only place OSV is ever asked, so this function stays
    // pure. `osv_matched: false` contributes no block, which is what keeps OSV an
    // OR-only signal (C1): it can only ever add a deny, never remove one already
    // decided above.
    if osv_matched {
        return Decision::Deny(DenyReason::BlockedByOsv);
    }
    // Advertised and pinned alike: known malware always overrides age, and a digest
    // we computed ourselves is as conclusive as one upstream published.
    if candidate
        .advertised_digests
        .iter()
        .chain(candidate.pinned_digests)
        .any(|digest| snapshot.blocks_digest(digest))
    {
        return Decision::Deny(DenyReason::BlockedDigest);
    }

    let published_at_micros = match candidate.publication {
        PublicationTime::Upstream(micros) | PublicationTime::FirstSeen(micros) => micros,
        PublicationTime::Malformed => return Decision::Deny(DenyReason::MalformedTimestamp),
        // Defensive: every caller resolves `Unknown` into a committed `FirstSeen`
        // before evaluating. This branch exists so a future caller that forgets
        // cannot make an untimed artifact eligible.
        PublicationTime::Unknown => return Decision::Deny(DenyReason::NoTimestamp),
    };
    if published_at_micros > now_utc_micros {
        return Decision::Deny(DenyReason::FutureTimestamp);
    }

    // Checked throughout: a cooldown that cannot be represented, or a deadline past
    // the end of the epoch, saturates to `i64::MAX` and stays a `Hold`. It must never
    // wrap into a past deadline, which would read as `Allow`.
    let cooldown_micros = i64::try_from(cooldown_seconds)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1_000_000))
        .unwrap_or(i64::MAX);
    let eligible_at_micros = published_at_micros.saturating_add(cooldown_micros);

    if now_utc_micros < eligible_at_micros {
        Decision::Hold { eligible_at_micros }
    } else {
        Decision::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    const SECOND: i64 = 1_000_000;
    const DAY_SECONDS: u64 = 86_400;

    fn at(rfc3339: &str) -> i64 {
        jiff::Timestamp::from_str(rfc3339)
            .expect("a test timestamp")
            .as_microsecond()
    }

    /// A snapshot whose window covers every `now` these tests use.
    fn snapshot_with(records: &str, hashes: &str) -> BlocklistSnapshot {
        let json = format!(
            r#"{{"schema_version":1,"revision":7,
                 "generated_at":"2020-01-01T00:00:00Z","expires_at":"2099-01-01T00:00:00Z",
                 "blocked_packages":[{records}],"blocked_hashes":[{hashes}]}}"#
        );
        BlocklistSnapshot::parse_and_validate(json.as_bytes(), at("2026-09-17T00:00:00Z"))
            .expect("the test snapshot is valid")
    }

    fn empty_snapshot() -> BlocklistSnapshot {
        snapshot_with("", "")
    }

    fn candidate<'a>(publication: PublicationTime, digests: &'a [Digest]) -> Candidate<'a> {
        Candidate {
            ecosystem: Ecosystem::Npm,
            name: "left-pad",
            version: "1.3.0",
            publication,
            advertised_digests: digests,
            pinned_digests: &[],
        }
    }

    #[test]
    fn cooldown_before_at_and_after_threshold() {
        let snapshot = empty_snapshot();
        let published = at("2026-09-16T00:00:00Z");
        let eligible = published + (DAY_SECONDS as i64) * SECOND;
        let candidate = candidate(PublicationTime::Upstream(published), &[]);

        assert_eq!(
            evaluate(
                Some(&snapshot),
                eligible - 1,
                DAY_SECONDS,
                &candidate,
                false
            ),
            Decision::Hold {
                eligible_at_micros: eligible
            },
            "one microsecond before the threshold is still held"
        );
        assert_eq!(
            evaluate(Some(&snapshot), eligible, DAY_SECONDS, &candidate, false),
            Decision::Allow,
            "exactly at the threshold is allowed: the boundary is inclusive-allow"
        );
        assert_eq!(
            evaluate(
                Some(&snapshot),
                eligible + SECOND,
                DAY_SECONDS,
                &candidate,
                false
            ),
            Decision::Allow
        );
    }

    #[test]
    fn zero_cooldown_disables_only_the_age_rule() {
        let now = at("2026-09-17T00:00:00Z");
        let just_published = candidate(PublicationTime::Upstream(now), &[]);

        assert_eq!(
            evaluate(Some(&empty_snapshot()), now, 0, &just_published, false),
            Decision::Allow,
            "a release published this instant is eligible when the cooldown is zero"
        );

        let blocked = snapshot_with(
            r#"{"ecosystem":"npm","name":"left-pad","version":null,"reason":"malware"}"#,
            "",
        );
        assert_eq!(
            evaluate(Some(&blocked), now, 0, &just_published, false),
            Decision::Deny(DenyReason::BlockedPackage),
            "a zero cooldown disables the age rule only, never a block"
        );
    }

    #[test]
    fn malformed_and_future_timestamps_deny() {
        let snapshot = empty_snapshot();
        let now = at("2026-09-17T00:00:00Z");

        assert_eq!(
            evaluate(
                Some(&snapshot),
                now,
                DAY_SECONDS,
                &candidate(PublicationTime::Malformed, &[]),
                false
            ),
            Decision::Deny(DenyReason::MalformedTimestamp)
        );
        assert_eq!(
            evaluate(
                Some(&snapshot),
                now,
                DAY_SECONDS,
                &candidate(PublicationTime::Upstream(now + SECOND), &[]),
                false
            ),
            Decision::Deny(DenyReason::FutureTimestamp)
        );
        assert_eq!(
            evaluate(
                Some(&snapshot),
                now,
                0,
                &candidate(PublicationTime::Upstream(now + 1), &[]),
                false
            ),
            Decision::Deny(DenyReason::FutureTimestamp),
            "a zero cooldown does not excuse a timestamp in the future"
        );
    }

    #[test]
    fn unknown_timestamp_denies() {
        let snapshot = empty_snapshot();
        let now = at("2026-09-17T00:00:00Z");

        assert_eq!(
            evaluate(
                Some(&snapshot),
                now,
                DAY_SECONDS,
                &candidate(PublicationTime::Unknown, &[]),
                false
            ),
            Decision::Deny(DenyReason::NoTimestamp)
        );
        assert_eq!(
            evaluate(
                Some(&snapshot),
                now,
                0,
                &candidate(PublicationTime::Unknown, &[]),
                false
            ),
            Decision::Deny(DenyReason::NoTimestamp),
            "an untimed artifact is never eligible, cooldown or not"
        );
        assert_eq!(
            evaluate(
                Some(&snapshot),
                now,
                DAY_SECONDS,
                &candidate(
                    PublicationTime::FirstSeen(now - 10 * 24 * 3600 * SECOND),
                    &[]
                ),
                false
            ),
            Decision::Allow,
            "a committed first-seen time is a real age"
        );
    }

    #[test]
    fn check_order_is_unavailable_deny_hold_allow() {
        let now = at("2026-09-17T00:00:00Z");
        let old = PublicationTime::Upstream(now - 10 * 24 * 3600 * SECOND);
        let fresh = PublicationTime::Upstream(now - SECOND);

        // An expired snapshot beats a block: with no policy in force nothing is
        // judged at all, not even something the expired snapshot named.
        let expired = BlocklistSnapshot::parse_and_validate(
            br#"{"schema_version":1,"revision":1,
                 "generated_at":"2026-09-10T00:00:00Z","expires_at":"2026-09-11T00:00:00Z",
                 "blocked_packages":[{"ecosystem":"npm","name":"left-pad","version":null,"reason":"malware"}],
                 "blocked_hashes":[]}"#,
            at("2026-09-10T12:00:00Z"),
        )
        .expect("valid inside its own window");
        assert_eq!(
            evaluate(
                Some(&expired),
                now,
                DAY_SECONDS,
                &candidate(old, &[]),
                false
            ),
            Decision::Unavailable
        );

        // A block beats a hold, and a package block is reported before a version one.
        let package_blocked = snapshot_with(
            r#"{"ecosystem":"npm","name":"left-pad","version":null,"reason":"malware"},
               {"ecosystem":"npm","name":"left-pad","version":"1.3.0","reason":"malware"}"#,
            "",
        );
        assert_eq!(
            evaluate(
                Some(&package_blocked),
                now,
                DAY_SECONDS,
                &candidate(fresh, &[]),
                false
            ),
            Decision::Deny(DenyReason::BlockedPackage)
        );

        let version_blocked = snapshot_with(
            r#"{"ecosystem":"npm","name":"left-pad","version":"1.3.0","reason":"malware"}"#,
            "",
        );
        assert_eq!(
            evaluate(
                Some(&version_blocked),
                now,
                DAY_SECONDS,
                &candidate(old, &[]),
                false
            ),
            Decision::Deny(DenyReason::BlockedVersion),
            "a block denies a release that age alone would allow"
        );

        // A pinned-digest block denies a release age would allow.
        let sha256 = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        let digest_blocked = snapshot_with(
            "",
            &format!(r#"{{"algorithm":"sha256","digest":"{sha256}","reason":"malware"}}"#),
        );
        let pinned = [Digest::parse_hex(HashAlgorithm::Sha256, sha256).expect("a digest")];
        let pinned_candidate = Candidate {
            pinned_digests: &pinned,
            ..candidate(old, &[])
        };
        assert_eq!(
            evaluate(
                Some(&digest_blocked),
                now,
                DAY_SECONDS,
                &pinned_candidate,
                false
            ),
            Decision::Deny(DenyReason::BlockedDigest)
        );

        // Hold beats allow, and with nothing left to object to the answer is allow.
        let clear = empty_snapshot();
        assert!(matches!(
            evaluate(
                Some(&clear),
                now,
                DAY_SECONDS,
                &candidate(fresh, &[]),
                false
            ),
            Decision::Hold { .. }
        ));
        assert_eq!(
            evaluate(Some(&clear), now, DAY_SECONDS, &candidate(old, &[]), false),
            Decision::Allow
        );
        assert_eq!(
            evaluate(None, now, DAY_SECONDS, &candidate(old, &[]), false),
            Decision::Unavailable,
            "no snapshot at all is the same refusal as an expired one"
        );

        // OSV is interleaved at the producer package/version tier, before the digest
        // check: an otherwise-clean, fresh candidate that OSV alone matches is
        // denied rather than allowed or held.
        assert_eq!(
            evaluate(Some(&clear), now, DAY_SECONDS, &candidate(fresh, &[]), true),
            Decision::Deny(DenyReason::BlockedByOsv)
        );
    }

    #[test]
    fn osv_matched_true_denies_before_digest_check() {
        let now = at("2026-09-17T00:00:00Z");
        let snapshot = empty_snapshot();
        let old = PublicationTime::Upstream(now - 10 * 24 * 3600 * SECOND);

        assert_eq!(
            evaluate(
                Some(&snapshot),
                now,
                DAY_SECONDS,
                &candidate(old, &[]),
                true
            ),
            Decision::Deny(DenyReason::BlockedByOsv),
            "an otherwise-clean candidate OSV matches is denied, not allowed"
        );
    }

    #[test]
    fn evaluate_never_lets_osv_unblock_a_producer_deny() {
        let now = at("2026-09-17T00:00:00Z");
        let old = PublicationTime::Upstream(now - 10 * 24 * 3600 * SECOND);
        let package_blocked = snapshot_with(
            r#"{"ecosystem":"npm","name":"left-pad","version":null,"reason":"malware"}"#,
            "",
        );

        // `osv_matched: false` must not undo a producer-tier block (C1, OR-only
        // merge): the reason stays the producer's own, not `BlockedByOsv` and not
        // `Allow`.
        assert_eq!(
            evaluate(
                Some(&package_blocked),
                now,
                DAY_SECONDS,
                &candidate(old, &[]),
                false
            ),
            Decision::Deny(DenyReason::BlockedPackage),
            "OSV cannot unblock what the producer's own snapshot already denies"
        );
    }

    /// `osv_matched: false` is a no-op at every tier: one representative case per
    /// pre-slice `Decision` shape, all asserting the exact result that tier's own
    /// dedicated test above already established, so today's behavior (before this
    /// parameter existed) is provably unchanged by its addition.
    #[test]
    fn osv_matched_false_is_indistinguishable_from_todays_behavior() {
        let now = at("2026-09-17T00:00:00Z");
        let old = PublicationTime::Upstream(now - 10 * 24 * 3600 * SECOND);
        let fresh = PublicationTime::Upstream(now - SECOND);

        let package_blocked = snapshot_with(
            r#"{"ecosystem":"npm","name":"left-pad","version":null,"reason":"malware"}"#,
            "",
        );
        assert_eq!(
            evaluate(
                Some(&package_blocked),
                now,
                DAY_SECONDS,
                &candidate(old, &[]),
                false
            ),
            Decision::Deny(DenyReason::BlockedPackage)
        );

        let clear = empty_snapshot();
        assert!(matches!(
            evaluate(
                Some(&clear),
                now,
                DAY_SECONDS,
                &candidate(fresh, &[]),
                false
            ),
            Decision::Hold { .. }
        ));
        assert_eq!(
            evaluate(Some(&clear), now, DAY_SECONDS, &candidate(old, &[]), false),
            Decision::Allow
        );
        assert_eq!(
            evaluate(None, now, DAY_SECONDS, &candidate(old, &[]), false),
            Decision::Unavailable
        );
    }

    #[test]
    fn blocked_digest_matches_pinned_and_advertised() {
        let now = at("2026-09-17T00:00:00Z");
        let old = PublicationTime::Upstream(now - 10 * 24 * 3600 * SECOND);
        let sha512 = "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043";
        let snapshot = snapshot_with(
            "",
            &format!(r#"{{"algorithm":"sha512","digest":"{sha512}","reason":"malware"}}"#),
        );
        let blocked = [Digest::parse_hex(HashAlgorithm::Sha512, sha512).expect("a digest")];
        let other = [Digest::parse_hex(HashAlgorithm::Sha512, &"a".repeat(128)).expect("a digest")];

        assert_eq!(
            evaluate(
                Some(&snapshot),
                now,
                DAY_SECONDS,
                &candidate(old, &blocked),
                false
            ),
            Decision::Deny(DenyReason::BlockedDigest),
            "advertised by upstream"
        );
        assert_eq!(
            evaluate(
                Some(&snapshot),
                now,
                DAY_SECONDS,
                &Candidate {
                    pinned_digests: &blocked,
                    ..candidate(old, &other)
                },
                false
            ),
            Decision::Deny(DenyReason::BlockedDigest),
            "computed by us and never advertised upstream"
        );
        assert_eq!(
            evaluate(
                Some(&snapshot),
                now,
                DAY_SECONDS,
                &candidate(old, &other),
                false
            ),
            Decision::Allow,
            "a digest that is not blocked does not deny"
        );
    }

    #[test]
    fn deadline_arithmetic_is_checked() {
        let snapshot = empty_snapshot();
        let now = at("2026-09-17T00:00:00Z");
        let published = now - SECOND;

        let saturated = evaluate(
            Some(&snapshot),
            now,
            u64::MAX,
            &candidate(PublicationTime::Upstream(published), &[]),
            false,
        );
        assert_eq!(
            saturated,
            Decision::Hold {
                eligible_at_micros: i64::MAX
            },
            "a cooldown too large to represent saturates to a hold, it never wraps"
        );

        let almost_max = (i64::MAX / 1_000_000) as u64;
        assert_eq!(
            evaluate(
                Some(&snapshot),
                now,
                almost_max,
                &candidate(PublicationTime::Upstream(published), &[]),
                false
            ),
            Decision::Hold {
                eligible_at_micros: i64::MAX
            },
            "a deadline past the end of the representable range saturates to a hold"
        );

        assert_eq!(
            evaluate(
                Some(&snapshot),
                now,
                DAY_SECONDS,
                &candidate(PublicationTime::Upstream(i64::MAX), &[]),
                false
            ),
            Decision::Deny(DenyReason::FutureTimestamp),
            "a timestamp at the end of the range denies rather than overflowing"
        );
    }
}
