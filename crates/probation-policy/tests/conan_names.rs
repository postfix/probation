//! Row 23, LS-F6: a Conan package name is `[A-Za-z0-9_][A-Za-z0-9_+.-]*` (what the Conan 2 client accepts; ConanCenter
//! publishes lower case only), a remote may fold case, so policy judges lower case, and a recipe version keeps its native spelling (exact match only).

use probation_policy::Ecosystem;
use probation_policy::names::{canonical_name, canonical_version, same_version, valid_name};

#[test]
fn conan_names_are_the_clients_charset_and_case_is_identity() {
    for good in ["zlib", "openssl", "boost", "libtiff", "a", "7zip", "c-ares", "libc++", "_private", "Mixed_Case.pkg+x", "gtest"] {
        assert!(valid_name(Ecosystem::Conan, good), "{good}");
        assert_eq!(canonical_name(Ecosystem::Conan, good), good.to_ascii_lowercase(), "policy sees the lower-case name");
    }
    for bad in ["", ".hidden", "-x", "+x", "a b", "a/b", "a@b", "a#b", "a:b", "a\n", "ä", "a;b", "x".repeat(300).as_str()] {
        assert!(!valid_name(Ecosystem::Conan, bad), "{bad:?}");
    }
}

#[test]
fn a_conan_version_has_no_canonical_form_so_only_the_exact_spelling_matches() {
    for version in ["1.3.1", "1.0", "3.0.0-rc1", "2024.1", "cci.20230301", "1.0+build.5", "system"] {
        assert!(canonical_version(Ecosystem::Conan, version).is_none(), "{version}");
    }
    assert!(same_version(Ecosystem::Conan, "1.3", "1.3"));
    assert!(!same_version(Ecosystem::Conan, "1.3", "1.3.0"), "the recipe's version text is the identity");
}
