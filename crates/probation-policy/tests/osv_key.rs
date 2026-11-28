//! LS-F6: one key function shared by the client (building a query) and the server
//! (validating one). Names validate and are never normalised.

use probation_policy::Ecosystem;
use probation_policy::osv_key::{OsvKeyError, osv_key};

#[test]
fn osv_key_valid_names_pass_for_every_family() {
    for eco in Ecosystem::ALL {
        let (name, version) = match eco {
            Ecosystem::Npm => ("@scope/left-pad", "1.3.0-beta.1+build.5"),
            Ecosystem::PyPi => ("requests-oauthlib", "2.0.post1"),
            Ecosystem::RubyGems => ("Rack_Test.rb-2", "7.1.0.rc1"),
            Ecosystem::Cargo => ("serde_json-2", "1.0.0-rc.1"),
            Ecosystem::Go => ("github.com/Azure/x~1", "1.2.3+incompatible"),
            Ecosystem::NuGet => ("Newtonsoft.Json_2-x", "13.0.3-beta.1"),
            Ecosystem::Maven => ("org.example:Lib_2-x", "1.0.0.Final"),
            Ecosystem::Conan => ("zlib", "1.3.1"),
            Ecosystem::Oci => (
                "library/alpine",
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
        };
        let key = osv_key(eco, name, version).expect("a valid key");
        assert_eq!((key.name.as_str(), key.version.as_str()), (name, version));
    }
    assert!(osv_key(Ecosystem::Npm, "left-pad", "1.3.0").is_ok());
    assert!(
        osv_key(Ecosystem::Npm, "Left_Pad.js~x", "1.0.0").is_ok(),
        "validate, never normalise"
    );
}

/// The shapes the batcher's producers send today (npm names from registry metadata,
/// PEP 503 names, versions as upstream spells them), so no checked key becomes
/// unchecked.
#[test]
fn osv_key_accepts_all_keys_current_batcher_sends() {
    let golden: &[(Ecosystem, &str, &str)] = &[
        (Ecosystem::Npm, "left-pad", "1.3.0"),
        (Ecosystem::Npm, "@types/node", "20.11.0"),
        (Ecosystem::Npm, "lodash.merge", "4.6.2"),
        (Ecosystem::Npm, "osv-widget", "1.0.0-rc.1"),
        (Ecosystem::Npm, "a", "0.0.0"),
        (Ecosystem::PyPi, "requests", "2.31.0"),
        (Ecosystem::PyPi, "zope-interface", "6.1"),
        (Ecosystem::PyPi, "foo-bar", "1.0.dev0"),
        (Ecosystem::PyPi, "numpy", "1!2.0.0rc1"),
    ];
    for (eco, name, version) in golden {
        assert!(osv_key(*eco, name, version).is_ok(), "{name}@{version}");
    }
}

#[test]
fn osv_key_rejects_what_the_charset_and_bounds_forbid() {
    let long = "a".repeat(1025);
    let cases: &[(Ecosystem, &str, &str, OsvKeyError)] = &[
        (Ecosystem::Npm, "", "1.0.0", OsvKeyError::Name),
        (Ecosystem::Npm, "bad name", "1.0.0", OsvKeyError::Name),
        (Ecosystem::Npm, "@scope", "1.0.0", OsvKeyError::Name),
        (Ecosystem::Npm, "@a/b/c", "1.0.0", OsvKeyError::Name),
        (Ecosystem::Npm, "ünï", "1.0.0", OsvKeyError::Name),
        (Ecosystem::Npm, "ok\u{7}", "1.0.0", OsvKeyError::Name),
        (Ecosystem::Npm, &long, "1.0.0", OsvKeyError::Name),
        (Ecosystem::PyPi, "Requests", "1.0", OsvKeyError::Name),
        (Ecosystem::PyPi, "a_b", "1.0", OsvKeyError::Name),
        (Ecosystem::Npm, "left-pad", "", OsvKeyError::Version),
        (Ecosystem::Npm, "left-pad", "1.0 0", OsvKeyError::Version),
        (Ecosystem::Npm, "left-pad", "1.0\n0", OsvKeyError::Version),
        (
            Ecosystem::Npm,
            "left-pad",
            &"1".repeat(1025),
            OsvKeyError::Version,
        ),
    ];
    for (eco, name, version, want) in cases {
        assert_eq!(
            osv_key(*eco, name, version).unwrap_err(),
            *want,
            "{name:?} {version:?}"
        );
    }
    // At the limit is accepted.
    assert!(osv_key(Ecosystem::Npm, &"a".repeat(1024), &"1".repeat(1024)).is_ok());
}

/// SEC-1: a publisher must not be able to pick a version or name the key function refuses
/// and so skip OSV. The limits are the ecosystems' real maxima (npm versions 256, names 214;
/// PyPI has no practical cap), and a key refused anyway is counted by the caller.
#[test]
fn osv_key_accepts_real_world_maxima_and_legacy_npm_names() {
    let prerelease = format!("1.0.0-{}", "a".repeat(200));
    assert!(osv_key(Ecosystem::Npm, "left-pad", &prerelease).is_ok());
    assert!(osv_key(Ecosystem::Npm, &"n".repeat(214), &"1".repeat(256)).is_ok());
    assert!(
        osv_key(
            Ecosystem::PyPi,
            &"a-".repeat(300),
            &format!("1.0+{}", "x".repeat(300))
        )
        .is_ok()
    );
    // Historic npm names carry `!'()*`.
    for name in ["a!b", "it's", "(paren)", "star*", "@scope/we!rd"] {
        assert!(osv_key(Ecosystem::Npm, name, "1.0.0").is_ok(), "{name}");
    }
    assert!(osv_key(Ecosystem::Npm, "a b", "1.0.0").is_err());
}

#[test]
fn osv_key_rubygems_charset_is_ls_f6() {
    // LS-F6: gem name [A-Za-z0-9._-], case kept; the platform suffix is removed by the caller.
    assert!(osv_key(Ecosystem::RubyGems, "nokogiri", "1.16.5").is_ok());
    assert!(
        osv_key(Ecosystem::RubyGems, "Rails.Gem_x-1", "7.0.0.pre").is_ok(),
        "validate, never normalise"
    );
    for bad in [
        "",
        "rack/x",
        "rack x",
        "ra:ck",
        "@scope/rack",
        "räck",
        "rack\n",
    ] {
        assert_eq!(
            osv_key(Ecosystem::RubyGems, bad, "1.0.0"),
            Err(OsvKeyError::Name),
            "{bad:?}"
        );
    }
    assert_eq!(
        osv_key(Ecosystem::RubyGems, "rack", ""),
        Err(OsvKeyError::Version)
    );
}

/// Row 18, LS-F6: a crate name is `[A-Za-z0-9_-]`; a dot or a slash is a key error, never normalised.
#[test]
fn osv_key_cargo_charset_is_ls_f6() {
    assert!(
        osv_key(Ecosystem::Cargo, "Serde_Json-2", "1.0.0").is_ok(),
        "case and underscore are kept"
    );
    for bad in ["serde.json", "serde/json", "serde json", "sérde", ""] {
        assert_eq!(
            osv_key(Ecosystem::Cargo, bad, "1.0.0"),
            Err(OsvKeyError::Name),
            "{bad:?}"
        );
    }
}

/// Row 19, LS-F6: a Go module path is the decoded `[A-Za-z0-9._~/-]` form, case kept; the
/// `!`-escaped proxy form is a key error, never normalised.
#[test]
fn osv_key_go_charset_is_ls_f6_and_never_the_escaped_form() {
    assert!(
        osv_key(
            Ecosystem::Go,
            "github.com/Azure/azure-sdk_x~1.v2",
            "1.2.3+incompatible"
        )
        .is_ok()
    );
    for bad in [
        "github.com/!azure/x",
        "github.com/a b",
        "github.com/ü",
        "github.com/a?b",
        "github.com/a@b",
        "",
    ] {
        assert_eq!(
            osv_key(Ecosystem::Go, bad, "1.0.0"),
            Err(OsvKeyError::Name),
            "{bad:?}"
        );
    }
}

/// Row 20, LS-F6: a NuGet id is `[A-Za-z0-9._-]`, case kept (OSV answers any case, canary 2026-11-19);
/// a slash, a colon or a space is a key error, never normalised.
#[test]
fn osv_key_nuget_charset_is_ls_f6() {
    assert!(osv_key(Ecosystem::NuGet, "Newtonsoft.Json", "13.0.3").is_ok());
    assert!(osv_key(Ecosystem::NuGet, "newtonsoft.json", "12.0.3-Beta.1").is_ok());
    for bad in ["new/tonsoft", "a b", "a:b", "ü", "a@1", ""] {
        assert_eq!(
            osv_key(Ecosystem::NuGet, bad, "1.0.0"),
            Err(OsvKeyError::Name),
            "{bad:?}"
        );
    }
}

/// Row 21, LS-F6: a Maven key is `groupId:artifactId`, each part `[A-Za-z0-9._-]`, exactly one `:`, case kept.
#[test]
fn maven_keys_are_group_and_artifact_with_one_colon() {
    assert!(osv_key(Ecosystem::Maven, "org.apache.maven:maven-core", "3.9.0").is_ok());
    assert!(osv_key(Ecosystem::Maven, "Org.Example:Lib_2", "1.0-SNAPSHOT").is_ok());
    for bad in [
        "maven-core",
        "a:b:c",
        ":b",
        "a:",
        "a b:c",
        "a:b/c",
        "a..b:c",
        ".a:c",
        "a:.c",
        "a:c\n",
    ] {
        assert_eq!(
            osv_key(Ecosystem::Maven, bad, "1.0.0"),
            Err(OsvKeyError::Name),
            "{bad:?}"
        );
    }
}

/// Row 23, LS-F6: a Conan key is the package name, `[A-Za-z0-9_][A-Za-z0-9_+.-]*`, case kept.
#[test]
fn conan_keys_are_the_package_name() {
    assert!(osv_key(Ecosystem::Conan, "zlib", "1.3.1").is_ok());
    assert!(osv_key(Ecosystem::Conan, "libc++", "cci.20230301").is_ok());
    for bad in ["", ".x", "a b", "a/b", "a@b", "a:b", "a\n", "a#b"] {
        assert_eq!(
            osv_key(Ecosystem::Conan, bad, "1.0.0"),
            Err(OsvKeyError::Name),
            "{bad:?}"
        );
    }
}
