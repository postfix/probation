//! Row 19: the Go modules identity. A module path is case-sensitive and is the policy key as the
//! decoded path (the `!`-escaped spelling is a transport form only); a version is full SemVer with
//! a leading `v`, and the policy spelling drops the `v` and keeps `+incompatible` (LS-F6).

use probation_policy::Ecosystem;
use probation_policy::names::{canonical_name, canonical_version, same_version, valid_name};

#[test]
fn go_names_are_case_sensitive_and_kept_exactly() {
    assert_eq!(canonical_name(Ecosystem::Go, "github.com/Azure/azure-sdk-for-go"), "github.com/Azure/azure-sdk-for-go");
    assert_ne!(canonical_name(Ecosystem::Go, "github.com/azure/x"), canonical_name(Ecosystem::Go, "github.com/Azure/x"));
}

#[test]
fn go_valid_names_follow_ls_f6() {
    for ok in ["github.com/a/b", "golang.org/x/net", "gopkg.in/yaml.v3", "example.com/A~b_c-d.e", "rsc.io/quote/v3", "example.com"] {
        assert!(valid_name(Ecosystem::Go, ok), "{ok}");
    }
    for bad in ["", "github.com/!azure/x", "a b/c", "github.com//x", "/github.com/x", "github.com/x/", "github.com/../x", "github.com/./x", "github.com/ü/x", "a\n", "github.com/x?y"] {
        assert!(!valid_name(Ecosystem::Go, bad), "{bad:?}");
    }
    assert!(valid_name(Ecosystem::Go, &format!("example.com/{}", "a".repeat(1000))));
    assert!(!valid_name(Ecosystem::Go, &format!("example.com/{}", "a".repeat(1100))));
}

#[test]
fn go_versions_are_semver_with_or_without_v_and_keep_incompatible() {
    assert!(same_version(Ecosystem::Go, "v1.2.3", "1.2.3"), "a rule may be written with or without the v");
    assert!(same_version(Ecosystem::Go, "v2.0.0+incompatible", "2.0.0+incompatible"));
    assert!(same_version(Ecosystem::Go, "v2.0.0+incompatible", "v2.0.0"), "a block written 2.0.0 matches the proxy's 2.0.0+incompatible and the reverse");
    assert!(same_version(Ecosystem::Go, "2.0.0", "2.0.0+incompatible"));
    assert!(!same_version(Ecosystem::Go, "v2.0.1+incompatible", "v2.0.0"));
    assert!(same_version(Ecosystem::Go, "v0.0.0-20250101120000-abcdef123456", "0.0.0-20250101120000-abcdef123456"));
    assert!(!same_version(Ecosystem::Go, "v1.0.0-rc.1", "v1.0.0"));
    assert!(canonical_version(Ecosystem::Go, "v1.0").is_none(), "two components are not a Go version");
    assert!(canonical_version(Ecosystem::Go, "v01.0.0").is_none());
}

#[test]
fn go_tag_and_serde_spelling() {
    assert_eq!(Ecosystem::Go.as_tag(), "go");
    assert_eq!(Ecosystem::from_tag("go"), Some(Ecosystem::Go));
    assert!(Ecosystem::ALL.contains(&Ecosystem::Go));
    assert_eq!(serde_json::to_string(&Ecosystem::Go).unwrap(), "\"Go\"");
    assert_eq!(serde_json::from_str::<Ecosystem>("\"Go\"").unwrap(), Ecosystem::Go);
}
