//! The tag rules of SPEC §6, in one place, because the `latest` fallback is the one
//! npm rule most likely to be argued about.
//!
//! ```text
//! Preserve a tag unchanged if its target is eligible.
//! If `latest` targets an excluded version, select the highest eligible stable
//!   version whose npm version precedence is no greater than that target.
//! If no such version exists, omit `latest`.
//! If another tag targets an excluded version, omit it. Do not guess another
//!   channel member.
//! If upstream `latest` is absent or invalid, do not invent it.
//! ```
//!
//! Only `latest` ever moves, and only downwards to a stable release. Everything else
//! is kept as upstream wrote it or dropped — never remapped, because a `beta` tag
//! silently pointing somewhere the publisher never pointed it is worse than no
//! `beta` tag at all.
//!
//! Precedence is `nodejs-semver`'s, which
//! `npm_metadata::npm_version_precedence_matches_a_published_corpus` asserts against
//! npm's own specification rather than assuming.

use std::collections::BTreeSet;

use nodejs_semver::Version;
use serde_json::{Map, Value};

/// npm's default tag, and the only one this filter will move.
pub const LATEST: &str = "latest";

/// The `dist-tags` object a filtered document carries.
pub fn resolve(dist_tags: &Map<String, Value>, eligible: &BTreeSet<String>) -> Map<String, Value> {
    let mut resolved = Map::new();

    for (tag, target) in dist_tags {
        let Some(target) = target.as_str() else {
            // Not a version string at all. Dropping it is the "do not invent"
            // rule applied to a tag we cannot even read.
            tracing::warn!(%tag, "dropping a dist-tag whose target is not a version string");
            continue;
        };

        if eligible.contains(target) {
            resolved.insert(tag.clone(), Value::from(target));
            continue;
        }

        if tag != LATEST {
            tracing::debug!(
                %tag,
                %target,
                "omitting a tag whose target is excluded; another channel member is not a guess \
                 this proxy makes"
            );
            continue;
        }

        match highest_eligible_stable_at_or_below(target, eligible) {
            Some(fallback) => {
                tracing::debug!(
                    original = %target,
                    %fallback,
                    "latest falls back to the highest eligible stable release at or below it"
                );
                resolved.insert(tag.clone(), Value::from(fallback));
            }
            None => tracing::debug!(
                original = %target,
                "omitting latest: no eligible stable release at or below it"
            ),
        }
    }

    resolved
}

/// The fallback rule on its own, so it can be reasoned about — and tested — without
/// a document around it.
///
/// `None` when `target` is not a version npm precedence can order, and `None` when
/// nothing eligible is at or below it. A prerelease is never chosen: SPEC §6 says
/// *stable*, and moving `latest` onto a release candidate would hand every plain
/// `npm install` a prerelease the publisher never defaulted to.
pub fn highest_eligible_stable_at_or_below(
    target: &str,
    eligible: &BTreeSet<String>,
) -> Option<String> {
    let target = Version::parse(target).ok()?;

    eligible
        .iter()
        .filter_map(|spelling| {
            let parsed = Version::parse(spelling).ok()?;
            (!parsed.is_prerelease() && parsed <= target).then_some((parsed, spelling))
        })
        .max_by(|left, right| left.0.cmp(&right.0))
        .map(|(_, spelling)| spelling.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eligible(versions: &[&str]) -> BTreeSet<String> {
        versions.iter().map(|v| (*v).to_owned()).collect()
    }

    fn tags(pairs: &[(&str, &str)]) -> Map<String, Value> {
        pairs
            .iter()
            .map(|(tag, target)| ((*tag).to_owned(), Value::from(*target)))
            .collect()
    }

    #[test]
    fn an_eligible_target_is_preserved_unchanged() {
        let resolved = resolve(
            &tags(&[("latest", "1.2.0"), ("next", "2.0.0-rc.1")]),
            &eligible(&["1.2.0", "2.0.0-rc.1"]),
        );
        assert_eq!(resolved["latest"], Value::from("1.2.0"));
        assert_eq!(
            resolved["next"],
            Value::from("2.0.0-rc.1"),
            "a tag deliberately pointing at an eligible prerelease stays where it is"
        );
    }

    #[test]
    fn latest_falls_back_past_a_prerelease_to_a_stable_release() {
        let resolved = resolve(
            &tags(&[("latest", "2.0.0")]),
            &eligible(&["1.9.0", "2.0.0-rc.2", "1.10.0"]),
        );
        assert_eq!(
            resolved["latest"],
            Value::from("1.10.0"),
            "1.10.0 outranks 1.9.0 by npm precedence, and the eligible rc is not stable"
        );
    }

    #[test]
    fn latest_is_omitted_rather_than_moved_upwards_or_invented() {
        assert!(
            !resolve(&tags(&[("latest", "1.0.0")]), &eligible(&["2.0.0"])).contains_key("latest"),
            "the fallback never moves latest up to a version the publisher had not shipped there"
        );
        assert!(!resolve(&tags(&[("latest", "1.0.0")]), &eligible(&[])).contains_key("latest"));
        assert!(
            !resolve(&tags(&[("latest", "not-a-version")]), &eligible(&["1.0.0"]))
                .contains_key("latest"),
            "an invalid upstream latest is not replaced with a guess"
        );
    }

    #[test]
    fn a_custom_tag_on_an_excluded_version_is_dropped_never_remapped() {
        let resolved = resolve(
            &tags(&[("beta", "2.0.0-beta.3"), ("latest", "1.0.0")]),
            &eligible(&["1.0.0", "2.0.0-beta.1", "2.0.0-beta.2"]),
        );
        assert!(
            !resolved.contains_key("beta"),
            "beta.1 and beta.2 are eligible channel members, and neither is what beta meant"
        );
        assert_eq!(resolved["latest"], Value::from("1.0.0"));
    }

    #[test]
    fn the_fallback_is_at_or_below_inclusive() {
        let set = eligible(&["1.0.0"]);
        assert_eq!(
            highest_eligible_stable_at_or_below("1.0.0", &set).as_deref(),
            Some("1.0.0"),
            "`no greater than that target` includes the target itself"
        );
        assert_eq!(
            highest_eligible_stable_at_or_below("1.0.0+build.7", &set).as_deref(),
            Some("1.0.0"),
            "build metadata is not part of npm precedence"
        );
        assert_eq!(highest_eligible_stable_at_or_below("0.9.9", &set), None);
    }
}
