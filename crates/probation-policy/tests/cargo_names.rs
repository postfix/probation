//! Row 18: the Cargo identity. crates.io treats names case-insensitively and `-` and `_` as
//! the same character, so the policy key folds both; SemVer 2 equality ignores build metadata
//! (crates.io refuses two versions that differ only in it).

use probation_policy::Ecosystem;
use probation_policy::names::{canonical_name, canonical_version, same_version, valid_name};

#[test]
fn cargo_names_fold_case_and_underscore() {
    for spelling in ["serde-json", "Serde_Json", "SERDE_JSON", "serde_json"] {
        assert_eq!(
            canonical_name(Ecosystem::Cargo, spelling),
            "serde-json",
            "{spelling}"
        );
    }
    assert_eq!(
        canonical_name(Ecosystem::Cargo, "a--b"),
        "a--b",
        "runs are not collapsed: only the character is folded"
    );
}

#[test]
fn cargo_valid_names_follow_ls_f6() {
    for ok in ["a", "serde_json", "Foo-Bar_2", "x86", "1password", "_a"] {
        assert!(valid_name(Ecosystem::Cargo, ok), "{ok}");
    }
    for bad in ["", "a.b", "a/b", "a b", "ünï", "a\n"] {
        assert!(!valid_name(Ecosystem::Cargo, bad), "{bad:?}");
    }
    assert!(!valid_name(Ecosystem::Cargo, &"a".repeat(129)));
    assert!(valid_name(Ecosystem::Cargo, &"a".repeat(128)));
}

#[test]
fn cargo_versions_are_semver_two_without_build_metadata() {
    assert!(same_version(Ecosystem::Cargo, "1.0.0", "1.0.0+build.5"));
    assert!(same_version(
        Ecosystem::Cargo,
        "1.0.0-rc.1+a",
        "1.0.0-rc.1+b"
    ));
    assert!(!same_version(Ecosystem::Cargo, "1.0.0", "1.0.1"));
    assert!(!same_version(Ecosystem::Cargo, "1.0.0-rc.1", "1.0.0"));
    assert!(
        canonical_version(Ecosystem::Cargo, "1.0").is_none(),
        "two components are not SemVer"
    );
    assert!(
        canonical_version(Ecosystem::Cargo, "01.0.0").is_none(),
        "leading zeros are refused"
    );
    assert!(canonical_version(Ecosystem::Cargo, "v1.0.0").is_none());
}
