//! The portal's OSV coverage view (row 27, LS-F12, 03 item (p)2): which families the shared
//! `osv_ecosystem` mapping covers, and what each registry's effective `osv_scope` means for the names
//! it sends. Everything here derives from `probation::osv::osv_ecosystem` and
//! `probation::osv::effective_scope`, so the view cannot disagree with the enforcer.

use probation::osv::{effective_scope, osv_ecosystem};
use probation_policy::Ecosystem;
use probation_policy::api::OsvScope;

/// A covered registry whose package names reach the shared policy server and api.osv.dev.
pub const QUERIED_SHARED: &str = "OSV queried: names reach the shared server";
/// A registry the enforcer never asks OSV about (Private scope, or a family OSV has no ecosystem for).
pub const NOT_APPLICABLE: &str = "OSV not applicable";
/// A registry on its family's fixed public source: queried, and nothing private is sent.
pub const PUBLIC_REGISTRY: &str = "OSV queried: public registry";
/// The same registry with a stored `Private` scope: the form says Private, but a fixed public source is always queried (nothing
/// private is sent), so the line says why the choice has no effect.
pub const PUBLIC_REGISTRY_PRIVATE_IGNORED: &str = "OSV queried: public registry (the stored Private scope has no effect on a public source)";

/// One family of the coverage table.
#[derive(Clone, Copy, Debug)]
pub struct CoverageRow {
    pub ecosystem: Ecosystem,
    pub tag: &'static str,
    /// The family as the portal's forms print it ("PyPI", "Go"): an exhaustive match, so a new family cannot reach the Add-registry form without one.
    pub name: &'static str,
    /// OSV's spelling, or `None` for a family OSV does not cover.
    pub osv: Option<&'static str>,
}

/// One row for every delivered family, in `Ecosystem::ALL` order.
pub fn coverage() -> Vec<CoverageRow> {
    Ecosystem::ALL.into_iter().map(|ecosystem| CoverageRow { ecosystem, tag: ecosystem.as_tag(), name: display_name(ecosystem), osv: osv_ecosystem(ecosystem) }).collect()
}

fn display_name(ecosystem: Ecosystem) -> &'static str {
    match ecosystem {
        Ecosystem::Npm => "npm",
        Ecosystem::PyPi => "PyPI",
        Ecosystem::RubyGems => "RubyGems",
        Ecosystem::Cargo => "Cargo",
        Ecosystem::Go => "Go",
        Ecosystem::NuGet => "NuGet",
        Ecosystem::Maven => "Maven",
        Ecosystem::Conan => "Conan",
        Ecosystem::Oci => "OCI",
    }
}

/// The text beside a family: its OSV ecosystem, or that OSV is absent.
pub fn coverage_label(row: &CoverageRow) -> String {
    match row.osv {
        Some(spelling) => format!("OSV ecosystem {spelling}"),
        None => NOT_APPLICABLE.to_owned(),
    }
}

/// What a registry's effective scope means (LS-F12). A family with no OSV ecosystem is never queried,
/// whatever the field says; a registry on its family's fixed public source is `Public` whatever the
/// field says (asking `effective_scope` with an explicit `Private` shows which rule decided).
pub fn registry_line(ecosystem: Ecosystem, target_url: Option<&str>, explicit: Option<OsvScope>) -> &'static str {
    if osv_ecosystem(ecosystem).is_none() {
        return NOT_APPLICABLE;
    }
    match effective_scope(ecosystem, target_url, explicit) {
        OsvScope::Private => NOT_APPLICABLE,
        OsvScope::Public if effective_scope(ecosystem, target_url, Some(OsvScope::Private)) == OsvScope::Public => {
            if explicit == Some(OsvScope::Private) { PUBLIC_REGISTRY_PRIVATE_IGNORED } else { PUBLIC_REGISTRY }
        }
        OsvScope::Public => QUERIED_SHARED,
    }
}

/// The stored field as the form's value: empty for the default rule.
pub fn scope_value(explicit: Option<OsvScope>) -> &'static str {
    match explicit {
        None => "",
        Some(OsvScope::Public) => "public",
        Some(OsvScope::Private) => "private",
    }
}
