//! PEP 503 name normalisation and route validation (SPEC §7).
//!
//! Unlike npm, a PyPI project name *is* rewritten: "Normalize project names by
//! lowercasing and replacing each run of `-`, `_`, or `.` with `-`." The normalised
//! spelling is the one this instance stores under, asks upstream for, and judges
//! against the blocklist; the spelling the client used is kept only to decide
//! whether the request needs a local `301` to the canonical form.
//!
//! The route component arrives percent-decoded by the router, so anything that is
//! not a name PyPI could have published is refused here rather than carried into an
//! upstream URL.

use std::fmt;

/// PyPI's own limit on a project name.
const MAX_LENGTH: usize = 214;

/// A validated project name in both spellings it is needed in.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct ProjectName {
    requested: String,
    normalized: String,
}

impl ProjectName {
    /// One route component, already percent-decoded.
    ///
    /// The admitted set is PEP 508's name rule — `^([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9._-]*[A-Za-z0-9])$`
    /// — which by construction excludes `/`, `\`, `%`, `:`, whitespace, control
    /// characters, and the `.` and `..` that would address a different resource.
    pub fn parse_route(raw: &str) -> Result<ProjectName, InvalidProjectName> {
        if raw.is_empty() {
            return Err(InvalidProjectName::Empty);
        }
        if raw.len() > MAX_LENGTH {
            return Err(InvalidProjectName::TooLong { length: raw.len() });
        }

        let mut characters = raw.chars();
        let first = characters.next().unwrap_or('\0');
        let last = raw.chars().next_back().unwrap_or('\0');
        if !first.is_ascii_alphanumeric() || !last.is_ascii_alphanumeric() {
            return Err(InvalidProjectName::Boundary);
        }
        if let Some(bad) = raw
            .chars()
            .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')))
        {
            return Err(InvalidProjectName::Character(bad));
        }

        Ok(ProjectName {
            normalized: normalize(raw),
            requested: raw.to_owned(),
        })
    }

    /// A name that is already known to be well formed — the `name` a stored project
    /// row carries, for instance.
    pub fn from_normalized(normalized: &str) -> Option<ProjectName> {
        let parsed = ProjectName::parse_route(normalized).ok()?;
        parsed.is_canonical().then_some(parsed)
    }

    /// The normalised spelling: the store key, the upstream segment, and the name
    /// `policy::evaluate` judges.
    pub fn as_str(&self) -> &str {
        &self.normalized
    }

    /// The spelling the client asked with.
    pub fn requested(&self) -> &str {
        &self.requested
    }

    /// Whether the request already used the canonical spelling. When it did not, the
    /// handler answers a local `301` rather than serving two URLs for one project.
    pub fn is_canonical(&self) -> bool {
        self.requested == self.normalized
    }
}

/// PEP 503: lowercase, and each run of `-`, `_` or `.` becomes a single `-`.
pub fn normalize(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut in_separator = false;
    for c in raw.chars() {
        if matches!(c, '-' | '_' | '.') {
            if !in_separator {
                out.push('-');
                in_separator = true;
            }
        } else {
            in_separator = false;
            out.extend(c.to_lowercase());
        }
    }
    out
}

impl fmt::Display for ProjectName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.normalized)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InvalidProjectName {
    Empty,
    TooLong {
        length: usize,
    },
    /// A name begins and ends with a letter or a digit.
    Boundary,
    Character(char),
}

impl fmt::Display for InvalidProjectName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InvalidProjectName::Empty => f.write_str("a project name cannot be empty"),
            InvalidProjectName::TooLong { length } => write!(
                f,
                "a project name is at most {MAX_LENGTH} characters, this is {length}"
            ),
            InvalidProjectName::Boundary => {
                f.write_str("a project name begins and ends with a letter or a digit")
            }
            InvalidProjectName::Character(c) => {
                write!(f, "`{c}` cannot appear in a project name")
            }
        }
    }
}

impl std::error::Error for InvalidProjectName {}

#[cfg(test)]
mod tests {
    use super::*;

    /// The worked example from the packaging specification, plus the runs the rule
    /// exists for.
    #[test]
    fn normalisation_collapses_runs_and_lowercases() {
        for (raw, expected) in [
            ("friendly-bard", "friendly-bard"),
            ("Friendly-Bard", "friendly-bard"),
            ("FRIENDLY-BARD", "friendly-bard"),
            ("friendly.bard", "friendly-bard"),
            ("friendly_bard", "friendly-bard"),
            ("friendly--bard", "friendly-bard"),
            ("FrIeNdLy-._.-bArD", "friendly-bard"),
            ("zope.interface", "zope-interface"),
            ("a", "a"),
        ] {
            assert_eq!(normalize(raw), expected, "normalising `{raw}`");
        }
    }

    #[test]
    fn a_canonical_name_is_recognised_as_one() {
        let canonical = ProjectName::parse_route("friendly-bard").expect("a valid name");
        assert!(canonical.is_canonical());
        assert_eq!(canonical.as_str(), "friendly-bard");

        let requested = ProjectName::parse_route("Friendly.Bard").expect("a valid name");
        assert!(!requested.is_canonical());
        assert_eq!(requested.as_str(), "friendly-bard");
        assert_eq!(requested.requested(), "Friendly.Bard");
    }

    /// Each of these would either address a different resource or leave the origin
    /// if it survived into an upstream URL.
    #[test]
    fn hostile_route_components_are_refused() {
        for raw in [
            "",
            ".",
            "..",
            "../etc/passwd",
            "/requests",
            "requests/",
            "a/b",
            "https://evil.invalid/x",
            "req uests",
            " requests",
            "requests ",
            "_leading",
            "-leading",
            "trailing_",
            "trailing.",
            "req%2Fuests",
            "req\nuests",
            "req\u{0}uests",
            "requests@1",
            "requêtes",
        ] {
            assert!(
                ProjectName::parse_route(raw).is_err(),
                "`{raw}` must not be admitted as a project name"
            );
        }

        assert!(ProjectName::parse_route(&"a".repeat(MAX_LENGTH + 1)).is_err());
        assert!(ProjectName::parse_route(&"a".repeat(MAX_LENGTH)).is_ok());
    }
}
