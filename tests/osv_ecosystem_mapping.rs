//! Row 30: the shared OSV ecosystem mapping. One entry per delivered family; rows 17-24
//! each add their own `Ecosystem` variant, `Ecosystem::ALL` entry, mapping arm and one
//! case here that names `Ecosystem::<Variant>` (so it cannot compile before its row).

use probation::osv::osv_ecosystem;
use probation_policy::Ecosystem;

/// The mapping table of 03-program-design.md "Central OSV lookup", for the delivered
/// families. A wrong spelling fails here; an unmapped variant is a compile error.
const TABLE: &[(Ecosystem, Option<&str>)] = &[
    (Ecosystem::Npm, Some("npm")),
    (Ecosystem::PyPi, Some("PyPI")),
    (Ecosystem::RubyGems, Some("RubyGems")),
];

#[test]
fn osv_ecosystem_mapping_matches_the_table_for_every_delivered_family() {
    for eco in Ecosystem::ALL {
        let row = TABLE.iter().find(|(e, _)| *e == eco).expect("every member of ALL has a table row");
        assert_eq!(osv_ecosystem(eco), row.1, "{eco:?}");
    }
    assert_eq!(TABLE.len(), Ecosystem::ALL.len(), "no table row for a family absent from ALL");
}

#[test]
fn osv_ecosystem_mapping_per_family_npm_and_pypi() {
    assert_eq!(osv_ecosystem(Ecosystem::Npm), Some("npm"));
    assert_eq!(osv_ecosystem(Ecosystem::PyPi), Some("PyPI"), "OSV spells it PyPI, the blocklist tag is pypi");
}

/// Row 17: names `Ecosystem::RubyGems`, so it does not compile before this row adds the variant.
#[test]
fn osv_ecosystem_mapping_per_family_rubygems() {
    assert_eq!(osv_ecosystem(Ecosystem::RubyGems), Some("RubyGems"));
    assert_eq!(Ecosystem::RubyGems.as_tag(), "rubygems");
    assert_eq!(Ecosystem::from_tag("rubygems"), Some(Ecosystem::RubyGems));
    assert!(Ecosystem::ALL.contains(&Ecosystem::RubyGems));
}
