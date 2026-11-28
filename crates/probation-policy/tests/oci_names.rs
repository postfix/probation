//! Row 24, LS-F6: an OCI repository name is the distribution spec's own (lower-case `[a-z0-9]` components joined by one `.`, one or two `_`
//! or any run of `-`, separated by `/`, at most 255 bytes); policy sees it exactly as written; a version is a tag or a digest and has no
//! canonical form (the exact text is the identity).

use probation_policy::Ecosystem;
use probation_policy::names::{canonical_name, canonical_version, same_version, valid_name};

#[test]
fn oci_names_are_the_distribution_specs_repository_names() {
    for good in [
        "alpine",
        "library/alpine",
        "team/app",
        "a/b/c/d",
        "my-app",
        "my--app",
        "my.app",
        "my_app",
        "my__app",
        "a1/b2",
        "0/0",
        "ghcr/org/img-2.x_y",
        &"a".repeat(255),
    ] {
        assert!(valid_name(Ecosystem::Oci, good), "{good}");
        assert_eq!(
            canonical_name(Ecosystem::Oci, good),
            good,
            "kept exactly as written"
        );
    }
    for bad in [
        "",
        "Alpine",
        "a/B",
        "-a",
        "a-",
        ".a",
        "a.",
        "a..b",
        "a___b",
        "a._b",
        "a-.b",
        "a//b",
        "/a",
        "a/",
        "a b",
        "a:b",
        "a@b",
        "a%2fb",
        "ä",
        &"a".repeat(256),
        "a/./b",
        "a/../b",
    ] {
        assert!(!valid_name(Ecosystem::Oci, bad), "{bad:?}");
    }
}

#[test]
fn a_tag_or_digest_has_no_canonical_form_so_only_the_exact_spelling_matches() {
    for version in [
        "latest",
        "v1.0",
        "1.0.0-rc1",
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ] {
        assert!(
            canonical_version(Ecosystem::Oci, version).is_none(),
            "{version}"
        );
    }
    assert!(same_version(Ecosystem::Oci, "1.0", "1.0"));
    assert!(!same_version(Ecosystem::Oci, "1.0", "1.0.0"));
}

#[test]
fn the_tag_is_oci_and_every_table_sized_by_all_has_a_slot_for_it() {
    assert_eq!(Ecosystem::Oci.as_tag(), "oci");
    assert_eq!(Ecosystem::ALL.len(), 9);
    assert_eq!(
        Ecosystem::ALL
            .iter()
            .filter(|e| e.as_tag() == "oci")
            .count(),
        1
    );
    assert_eq!(
        serde_json::to_string(&Ecosystem::Oci).unwrap(),
        "\"Oci\"",
        "the wire spelling is the variant's own, as Conan's"
    );
}
