//! Row 20: the NuGet identity. A package id is case-insensitive and policy keys it lower-cased
//! (the flat container and registration URLs are lower-case; OSV answers either case, checked
//! against api.osv.dev); a version is NuGet's own: one to four numeric parts, an optional
//! release label compared case-insensitively, build metadata ignored, a zero fourth part and
//! missing trailing parts equal to a shorter spelling (LS-F6, the NuGet.Versioning rules).

use probation_policy::Ecosystem;
use probation_policy::names::{
    canonical_name, canonical_version, nuget_version, same_version, valid_name,
};

#[test]
fn nuget_names_are_lower_cased() {
    assert_eq!(
        canonical_name(Ecosystem::NuGet, "Newtonsoft.Json"),
        "newtonsoft.json"
    );
    assert_eq!(canonical_name(Ecosystem::NuGet, "My_Pkg-2"), "my_pkg-2");
}

#[test]
fn nuget_valid_names_follow_ls_f6() {
    for ok in [
        "Newtonsoft.Json",
        "a",
        "Microsoft.Extensions.Logging",
        "My_Pkg-2",
        "7z.Net",
        &"a".repeat(128),
    ] {
        assert!(valid_name(Ecosystem::NuGet, ok), "{ok}");
    }
    for bad in [
        "",
        ".",
        "..",
        ".a",
        "a.",
        "...",
        "a b",
        "a/b",
        "a:b",
        "ü",
        "a\n",
        "a?b",
        "a@1",
        &"a".repeat(129),
    ] {
        assert!(!valid_name(Ecosystem::NuGet, bad), "{bad:?}");
    }
}

#[test]
fn nuget_versions_compare_the_way_nuget_does() {
    for (a, b) in [
        ("1.0", "1.0.0"),
        ("1", "1.0.0"),
        ("1.0.0.0", "1.0.0"),
        ("01.00.0", "1.0.0"),
        ("1.0.0-Beta", "1.0.0-beta"),
        ("1.0.0+abc", "1.0.0"),
        ("1.0.0-rc.1+a", "1.0.0-RC.1+b"),
        ("2.0.0.1", "2.0.0.1"),
        ("1.2.3.0-x", "1.2.3-X"),
    ] {
        assert!(same_version(Ecosystem::NuGet, a, b), "{a} == {b}");
    }
    for (a, b) in [
        ("1.0.0.1", "1.0.0"),
        ("1.0.0-beta", "1.0.0"),
        ("1.0.1", "1.0.0"),
        ("1.0.0-beta.1", "1.0.0-beta.2"),
        ("1.2", "1.0.2"),
    ] {
        assert!(!same_version(Ecosystem::NuGet, a, b), "{a} != {b}");
    }
    for bad in [
        "",
        "1.a",
        "1.0.0-",
        "1.0.0-be ta",
        "1.2.3.4.5",
        ">1",
        "v1.0.0",
        "1..0",
        "-1.0.0",
        "1.0.0+",
        "1.0.0-a..b",
        "2147483648.0.0",
        " 1.0.0",
    ] {
        assert!(
            canonical_version(Ecosystem::NuGet, bad).is_none(),
            "{bad:?}"
        );
    }
}

#[test]
fn nuget_policy_version_is_the_flat_container_spelling() {
    assert_eq!(nuget_version("1.0").as_deref(), Some("1.0.0"));
    assert_eq!(
        nuget_version("1.0.0.0-Beta+meta").as_deref(),
        Some("1.0.0-beta")
    );
    assert_eq!(nuget_version("01.2.3.4").as_deref(), Some("1.2.3.4"));
    assert_eq!(nuget_version("13.0.3").as_deref(), Some("13.0.3"));
    assert_eq!(nuget_version("1.0.0-RC.1").as_deref(), Some("1.0.0-rc.1"));
    assert_eq!(nuget_version("not a version"), None);
    assert_eq!(
        nuget_version(&format!("1.0.0-{}", "a".repeat(300))),
        None,
        "a version longer than 256 bytes is no NuGet version"
    );
}

#[test]
fn nuget_tag_and_serde_spelling() {
    assert_eq!(Ecosystem::NuGet.as_tag(), "nuget");
    assert_eq!(Ecosystem::from_tag("nuget"), Some(Ecosystem::NuGet));
    assert!(Ecosystem::ALL.contains(&Ecosystem::NuGet));
    assert_eq!(
        serde_json::to_string(&Ecosystem::NuGet).unwrap(),
        "\"NuGet\""
    );
    assert_eq!(
        serde_json::from_str::<Ecosystem>("\"NuGet\"").unwrap(),
        Ecosystem::NuGet
    );
}

mod properties {
    use probation_policy::Ecosystem;
    use probation_policy::names::{nuget_version, same_version};
    use proptest::prelude::*;

    /// A NuGet version spelled the ways clients write it: one to four numeric parts (with leading zeros), an
    /// optional release label in any case, optional build metadata.
    fn spelling() -> impl Strategy<Value = String> {
        (
            proptest::collection::vec(0u32..=2_000, 1..=4),
            proptest::bool::ANY,
            proptest::option::of("[0-9A-Za-z-]{1,6}(\\.[0-9A-Za-z-]{1,4}){0,2}"),
            proptest::option::of("[0-9A-Za-z-]{1,6}(\\.[0-9A-Za-z-]{1,4}){0,2}"),
        )
            .prop_map(|(numbers, padded, release, metadata)| {
                let parts: Vec<String> = numbers
                    .iter()
                    .map(|n| {
                        if padded {
                            format!("{n:04}")
                        } else {
                            n.to_string()
                        }
                    })
                    .collect();
                let mut text = parts.join(".");
                if let Some(release) = release {
                    text.push('-');
                    text.push_str(&release);
                }
                if let Some(metadata) = metadata {
                    text.push('+');
                    text.push_str(&metadata);
                }
                text
            })
    }

    proptest! {
        /// The one spelling is a fixed point (the flat container's own spelling parses back to itself), and
        /// `same_version` is exactly equality of that spelling: the invariant every URL, block and OSV key rests on.
        #[test]
        fn the_policy_spelling_is_idempotent_and_decides_equality(a in spelling(), b in spelling()) {
            let normal = nuget_version(&a).expect("every generated spelling is a NuGet version");
            let again = nuget_version(&normal);
            prop_assert_eq!(again.as_deref(), Some(normal.as_str()));
            prop_assert_eq!(normal.clone(), normal.to_ascii_lowercase());
            prop_assert!(!normal.contains('+'));
            let other = nuget_version(&b).unwrap();
            prop_assert_eq!(same_version(Ecosystem::NuGet, &a, &b), normal == other);
        }

        /// Trailing zero parts and a zero fourth part never change a version; a non-zero one always does.
        #[test]
        fn padding_with_zero_parts_is_the_same_version(major in 0u32..500, minor in 0u32..500, patch in 0u32..500, revision in 1u32..500) {
            let short = format!("{major}.{minor}.{patch}");
            let zero_revision = format!("{short}.0");
            let two_part = format!("{major}.{minor}");
            let two_part_padded = format!("{major}.{minor}.0.0");
            let with_revision = format!("{short}.{revision}");
            prop_assert!(same_version(Ecosystem::NuGet, &short, &zero_revision));
            prop_assert!(same_version(Ecosystem::NuGet, &two_part, &two_part_padded));
            prop_assert!(!same_version(Ecosystem::NuGet, &short, &with_revision));
        }
    }
}
