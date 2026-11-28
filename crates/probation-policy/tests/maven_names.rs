//! Row 21, LS-F6: a Maven coordinate is `groupId:artifactId` (each part `[A-Za-z0-9._-]`, exactly one `:`), case is identity,
//! a version keeps its native spelling and only the exact text matches.

use probation_policy::Ecosystem;
use probation_policy::names::{
    canonical_name, canonical_version, same_version, valid_maven_name, valid_name,
};

#[test]
fn maven_names_are_group_and_artifact_with_one_colon_and_case_kept() {
    for good in [
        "org.apache.maven:maven-core",
        "junit:junit",
        "Org.Example:Lib_2",
        "a:b",
        "com.fasterxml.jackson.core:jackson-databind",
        "a-b_c.d:e.f-g_h",
    ] {
        assert!(valid_name(Ecosystem::Maven, good), "{good}");
        assert!(valid_maven_name(good), "{good}");
        assert_eq!(
            canonical_name(Ecosystem::Maven, good),
            good,
            "case and spelling are identity"
        );
    }
    for bad in [
        "",
        "junit",
        "a:b:c",
        ":b",
        "a:",
        ":",
        "a b:c",
        "a:b c",
        "a/b:c",
        "a:b/c",
        "a..b:c",
        ".a:b",
        "a:.b",
        "a.:b",
        "a:b\n",
        "ä:b",
        "a:b;c",
        "x".repeat(600).as_str(),
    ] {
        assert!(!valid_name(Ecosystem::Maven, bad), "{bad:?}");
    }
    assert!(
        valid_name(
            Ecosystem::Maven,
            &format!("{}:{}", "g".repeat(200), "a".repeat(200))
        ),
        "real coordinates are far below the bound"
    );
}

#[test]
fn a_maven_version_has_no_canonical_form_so_only_the_exact_spelling_matches() {
    for version in [
        "1.0",
        "1.0.0",
        "1.0-SNAPSHOT",
        "2.0.0.Final",
        "1.0-RC1",
        "3.0+build.5",
        "20200101",
    ] {
        assert!(
            canonical_version(Ecosystem::Maven, version).is_none(),
            "{version}"
        );
    }
    assert!(same_version(Ecosystem::Maven, "1.0", "1.0"));
    assert!(
        !same_version(Ecosystem::Maven, "1.0", "1.0.0"),
        "native tools decide ordering, identity is the spelling"
    );
    assert!(!same_version(Ecosystem::Maven, "1.0-RC1", "1.0-rc1"));
}
