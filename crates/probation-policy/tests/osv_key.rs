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
        };
        let key = osv_key(eco, name, version).expect("a valid key");
        assert_eq!((key.name.as_str(), key.version.as_str()), (name, version));
    }
    assert!(osv_key(Ecosystem::Npm, "left-pad", "1.3.0").is_ok());
    assert!(osv_key(Ecosystem::Npm, "Left_Pad.js~x", "1.0.0").is_ok(), "validate, never normalise");
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
        (Ecosystem::Npm, "left-pad", &"1".repeat(1025), OsvKeyError::Version),
    ];
    for (eco, name, version, want) in cases {
        assert_eq!(osv_key(*eco, name, version).unwrap_err(), *want, "{name:?} {version:?}");
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
    assert!(osv_key(Ecosystem::PyPi, &"a-".repeat(300), &format!("1.0+{}", "x".repeat(300))).is_ok());
    // Historic npm names carry `!'()*`.
    for name in ["a!b", "it's", "(paren)", "star*", "@scope/we!rd"] {
        assert!(osv_key(Ecosystem::Npm, name, "1.0.0").is_ok(), "{name}");
    }
    assert!(osv_key(Ecosystem::Npm, "a b", "1.0.0").is_err());
}
