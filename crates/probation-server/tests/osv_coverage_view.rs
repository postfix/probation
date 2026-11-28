//! Row 27: the portal's OSV coverage view is produced from the shared `osv_ecosystem` mapping
//! (03-program-design.md "Central OSV lookup", LS-F12, item (p)2), and each registry's line shows its
//! effective `osv_scope`. The page that renders these lines is exercised in portal_places.rs
//! (`t_registry_catalog_shows_osv_coverage_and_scope`); this file needs no database.

use probation::osv::osv_ecosystem;
use probation_policy::Ecosystem;
use probation_policy::api::OsvScope;
use probation_server::osv_view::{
    self, NOT_APPLICABLE, PUBLIC_REGISTRY, PUBLIC_REGISTRY_PRIVATE_IGNORED, QUERIED_SHARED,
};

/// Every member of `Ecosystem::ALL` is in the view, with the mapping's spelling or none; a family added
/// to `ALL` without a mapping arm cannot compile (`osv_ecosystem` is an exhaustive match: the compiler is the first guard), and one added
/// with an arm has no row in the expected table below, so this test fails until that table is edited deliberately.
#[test]
fn osv_coverage_view_matches_mapping() {
    let rows = osv_view::coverage();
    assert_eq!(
        rows.len(),
        Ecosystem::ALL.len(),
        "one row per delivered family, no more"
    );
    for ecosystem in Ecosystem::ALL {
        let row = rows
            .iter()
            .find(|row| row.ecosystem == ecosystem)
            .unwrap_or_else(|| panic!("{ecosystem:?} is missing from the coverage view"));
        assert_eq!(row.tag, ecosystem.as_tag());
        assert_eq!(
            row.osv,
            osv_ecosystem(ecosystem),
            "{ecosystem:?}: the view must use the shared mapping"
        );
        let label = osv_view::coverage_label(row);
        match osv_ecosystem(ecosystem) {
            Some(spelling) => assert!(label.contains(spelling), "{ecosystem:?}: {label}"),
            None => assert_eq!(
                label, NOT_APPLICABLE,
                "{ecosystem:?}: an unmapped family is listed as OSV absent"
            ),
        }
    }
    // The 03 mapping table, as an oracle independent of the code under test, DRIVEN FROM `Ecosystem::ALL`: a family with no row here fails
    // (so a tenth family or a changed spelling is a deliberate edit of this table), and the table has no row for a family that is gone.
    let table = [
        ("npm", Some("npm")),
        ("pypi", Some("PyPI")),
        ("rubygems", Some("RubyGems")),
        ("cargo", Some("crates.io")),
        ("go", Some("Go")),
        ("nuget", Some("NuGet")),
        ("maven", Some("Maven")),
        ("conan", Some("ConanCenter")),
        ("oci", None),
    ];
    assert_eq!(
        table.len(),
        Ecosystem::ALL.len(),
        "the oracle table lists exactly the delivered families"
    );
    for ecosystem in Ecosystem::ALL {
        let (_, spelling) = table.iter().find(|(tag, _)| *tag == ecosystem.as_tag()).unwrap_or_else(|| panic!("{ecosystem:?} has no row in the expected-OSV-ecosystem table: add it with OSV's own spelling"));
        let row = rows.iter().find(|row| row.ecosystem == ecosystem).unwrap();
        assert_eq!(row.osv, *spelling, "{ecosystem:?}");
        assert!(
            !row.name.is_empty(),
            "{ecosystem:?} has a name for the Add-registry form"
        );
    }
    assert!(
        osv_view::coverage_label(rows.iter().find(|row| row.tag == "oci").unwrap())
            .contains("not applicable")
    );
}

/// The registry view (LS-F12): a custom target with effective scope Public says its names reach the
/// shared server, a Private one says OSV does not apply, and an OCI registry says OSV does not apply
/// whatever its scope.
#[test]
fn osv_coverage_view_shows_scope() {
    assert_eq!(QUERIED_SHARED, "OSV queried: names reach the shared server");
    assert_eq!(NOT_APPLICABLE, "OSV not applicable");
    for ecosystem in Ecosystem::ALL {
        let custom = Some("https://mirror.corp.example/");
        let line = |target, explicit| osv_view::registry_line(ecosystem, target, explicit);
        if osv_ecosystem(ecosystem).is_none() {
            for explicit in [None, Some(OsvScope::Public), Some(OsvScope::Private)] {
                assert_eq!(
                    line(custom, explicit),
                    NOT_APPLICABLE,
                    "{ecosystem:?} {explicit:?}: no mapping, so never queried"
                );
            }
            assert_eq!(
                line(None, None),
                NOT_APPLICABLE,
                "{ecosystem:?} on its own default target"
            );
            continue;
        }
        assert_eq!(
            line(custom, None),
            QUERIED_SHARED,
            "{ecosystem:?}: the default for a custom target is Public"
        );
        assert_eq!(
            line(custom, Some(OsvScope::Public)),
            QUERIED_SHARED,
            "{ecosystem:?}"
        );
        assert_eq!(
            line(custom, Some(OsvScope::Private)),
            NOT_APPLICABLE,
            "{ecosystem:?}: the operator opted out"
        );
    }
    // A registry on its family's fixed public source is queried whatever the field says, and it is not
    // reported as an internal registry whose names reach the shared server.
    let npm = Ecosystem::Npm;
    assert_eq!(
        osv_view::registry_line(npm, Some("https://registry.npmjs.org/"), None),
        PUBLIC_REGISTRY
    );
    // A stored Private scope on such a registry is explained, not silently contradicted by the form that shows it selected.
    assert_eq!(
        osv_view::registry_line(
            npm,
            Some("https://registry.npmjs.org/"),
            Some(OsvScope::Private)
        ),
        PUBLIC_REGISTRY_PRIVATE_IGNORED
    );
    assert!(PUBLIC_REGISTRY_PRIVATE_IGNORED.contains("Private scope has no effect"));
    assert_eq!(osv_view::registry_line(npm, None, None), PUBLIC_REGISTRY);
    // The explicit field is echoed for the form: absent, public and private are three states.
    assert_eq!(osv_view::scope_value(None), "");
    assert_eq!(osv_view::scope_value(Some(OsvScope::Public)), "public");
    assert_eq!(osv_view::scope_value(Some(OsvScope::Private)), "private");
}
