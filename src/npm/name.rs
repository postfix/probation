//! Route-component validation for npm package names (SPEC §6).
//!
//! The route component arrives percent-decoded by the router, so npm's scoped
//! spelling `@scope%2fname` and the plain `@scope/name` reach this function as the
//! same string. Everything else is untrusted text: a name is admitted only if it is
//! one npm could actually have published, and the admitted form is what the upstream
//! URL builder is handed as a single path segment.

use std::fmt;

/// npm's own limit, from `validate-npm-package-name`.
const MAX_LENGTH: usize = 214;

/// Characters npm forbids outright, plus the ones that would change the meaning of a
/// URL if they survived into one. `/` is handled separately, because exactly one is
/// allowed and only as the scope separator.
const FORBIDDEN: &[char] = &[
    '~', ')', '(', '\'', '!', '*', '"', '\\', ':', '?', '#', '[', ']', '<', '>', '|', '^', '`',
    '{', '}', ';', ',', '=', '&', '+', '$', '%', ' ',
];

/// A validated npm package name, in the spelling upstream uses.
///
/// npm names are not case-folded: the registry still serves legacy names that carry
/// capitals, and lowercasing one here would ask upstream for a package that does not
/// exist. "Normalise" for npm therefore means "decoded and validated", not "changed".
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct PackageName {
    name: String,
}

impl PackageName {
    /// One route component, already percent-decoded.
    pub fn parse_route(raw: &str) -> Result<PackageName, InvalidPackageName> {
        if raw.is_empty() {
            return Err(InvalidPackageName::Empty);
        }
        if raw.len() > MAX_LENGTH {
            return Err(InvalidPackageName::TooLong { length: raw.len() });
        }
        if raw.trim() != raw {
            return Err(InvalidPackageName::Surrounding);
        }

        let (scope, bare) = match raw.strip_prefix('@') {
            Some(rest) => {
                let (scope, bare) = rest
                    .split_once('/')
                    .ok_or(InvalidPackageName::IncompleteScope)?;
                (Some(scope), bare)
            }
            None => (None, raw),
        };

        if let Some(scope) = scope {
            check_part(scope)?;
        }
        check_part(bare)?;

        Ok(PackageName {
            name: raw.to_owned(),
        })
    }

    pub fn as_str(&self) -> &str {
        &self.name
    }

    /// npm addresses a package with its whole name as one path component, scoped or
    /// not. `OriginSet::url_for` percent-encodes the `/` of a scope, which is exactly
    /// the `@scope%2fname` form the registry expects.
    pub fn upstream_segment(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for PackageName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)
    }
}

fn check_part(part: &str) -> Result<(), InvalidPackageName> {
    if part.is_empty() {
        return Err(InvalidPackageName::Empty);
    }
    if part.starts_with('.') || part.starts_with('_') {
        return Err(InvalidPackageName::LeadingCharacter);
    }
    if part.contains('/') || part.contains('@') {
        return Err(InvalidPackageName::Separator);
    }
    if let Some(bad) = part
        .chars()
        .find(|c| c.is_control() || FORBIDDEN.contains(c))
    {
        return Err(InvalidPackageName::Character(bad));
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InvalidPackageName {
    Empty,
    TooLong {
        length: usize,
    },
    /// Leading or trailing whitespace.
    Surrounding,
    /// A `@` with no `/scope` separator after it.
    IncompleteScope,
    /// More than one `/`, or a `@` anywhere but the front.
    Separator,
    LeadingCharacter,
    Character(char),
}

impl fmt::Display for InvalidPackageName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InvalidPackageName::Empty => f.write_str("a package name cannot be empty"),
            InvalidPackageName::TooLong { length } => {
                write!(
                    f,
                    "a package name is at most {MAX_LENGTH} characters, this is {length}"
                )
            }
            InvalidPackageName::Surrounding => {
                f.write_str("a package name cannot begin or end with whitespace")
            }
            InvalidPackageName::IncompleteScope => f.write_str("a scoped name is `@scope/name`"),
            InvalidPackageName::Separator => {
                f.write_str("a package name holds at most one `/`, after its `@scope`")
            }
            InvalidPackageName::LeadingCharacter => {
                f.write_str("a package name cannot begin with `.` or `_`")
            }
            InvalidPackageName::Character(c) => {
                write!(f, "`{c}` cannot appear in a package name")
            }
        }
    }
}

impl std::error::Error for InvalidPackageName {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_and_scoped_names_are_admitted_unchanged() {
        for name in ["left-pad", "@babel/core", "Base64", "a", "lodash.merge"] {
            let parsed = PackageName::parse_route(name).unwrap_or_else(|err| {
                panic!("`{name}` is a real npm name, but: {err}");
            });
            assert_eq!(parsed.as_str(), name, "a valid name is never rewritten");
        }
    }

    /// Every one of these is a name that would either address the wrong resource or
    /// leave the origin if it survived into an upstream URL.
    #[test]
    fn hostile_route_components_are_refused() {
        for name in [
            "",
            ".",
            "..",
            "../etc/passwd",
            "/left-pad",
            "left-pad/",
            "a/b/c",
            "@scope",
            "@/name",
            "@scope/",
            "https://evil.invalid/x",
            "left pad",
            " left-pad",
            "left-pad ",
            "_hidden",
            ".hidden",
            "a@b",
            "left\npad",
            "left\u{0}pad",
            "left%2fpad",
        ] {
            assert!(
                PackageName::parse_route(name).is_err(),
                "`{name}` must not be admitted as a package name"
            );
        }

        assert!(PackageName::parse_route(&"a".repeat(MAX_LENGTH + 1)).is_err());
        assert!(PackageName::parse_route(&"a".repeat(MAX_LENGTH)).is_ok());
    }
}
