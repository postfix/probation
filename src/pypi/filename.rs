//! Filename → `(project, PEP 440 version)`, and the rule that governs it:
//! **a filename whose identity cannot be established is excluded and logged, never
//! guessed** (SPEC §7).
//!
//! This is a hand-rolled PEP 427/625 splitter because no maintained crate publishes
//! this half — Gate 3 dependency note 1 checked, and delegated only the *version* to
//! `pep440_rs`. It is therefore threat TM-2: a misattributed filename would be judged
//! as some other version, and a version-specific block would be escaped. Three things
//! make that structurally hard rather than merely tested:
//!
//! * **The project is an input, not an output.** Identity is only ever *confirmed*
//!   against the project whose listing is being served, so the project half cannot be
//!   misread — at worst the file is excluded.
//! * **Every split must be exact.** A wheel name has a fixed component count; an
//!   sdist name is split only where the left half normalises to exactly the expected
//!   project *and* the right half is a whole PEP 440 version.
//! * **More than one such split is an exclusion**, not a choice between them. There
//!   is no "closest match", no longest-prefix preference, and no fallback.

use std::fmt;
use std::str::FromStr;

use crate::pypi::name::normalize;

/// The sdist archive extensions this release can name. Anything else — an egg, an
/// installer, an unusual compression — is excluded and logged rather than guessed at.
const SDIST_EXTENSIONS: [&str; 5] = [".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".zip"];

const WHEEL_EXTENSION: &str = ".whl";

/// One file's established identity. `version` is the filename's own spelling, which
/// SPEC §7 requires be preserved in client-facing metadata; equality against the
/// blocklist is done on the parsed PEP 440 form, not on this string.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FileIdentity {
    /// The normalised project name. Equal to the project it was confirmed against,
    /// by construction.
    pub project: String,
    pub version: String,
}

/// Establishes `filename`'s identity, or refuses to.
///
/// `project` is the *normalised* name of the project whose listing is being built.
/// A filename that does not name that project is refused rather than reinterpreted.
pub fn file_identity(filename: &str, project: &str) -> Result<FileIdentity, UnsupportedFilename> {
    if filename.is_empty() {
        return Err(UnsupportedFilename::Empty);
    }
    if let Some(bad) = filename
        .chars()
        .find(|c| c.is_control() || matches!(c, '/' | '\\'))
    {
        return Err(UnsupportedFilename::Character(bad));
    }

    if let Some(stem) = filename.strip_suffix(WHEEL_EXTENSION) {
        return wheel_identity(stem, project);
    }
    for extension in SDIST_EXTENSIONS {
        if let Some(stem) = filename.strip_suffix(extension) {
            return sdist_identity(stem, project);
        }
    }
    Err(UnsupportedFilename::UnknownExtension)
}

/// PEP 427: `{distribution}-{version}(-{build tag})?-{python}-{abi}-{platform}.whl`,
/// where the distribution and version are escaped so that neither can contain a `-`.
/// The component count is therefore exactly five or six, and six only when the third
/// component is a build tag — which PEP 427 requires to start with a digit.
///
/// Any other shape is ambiguous, and an ambiguous wheel name is excluded.
fn wheel_identity(stem: &str, project: &str) -> Result<FileIdentity, UnsupportedFilename> {
    let parts: Vec<&str> = stem.split('-').collect();
    let (distribution, version) = match parts.as_slice() {
        [distribution, version, _python, _abi, _platform] => (*distribution, *version),
        [distribution, version, build, _python, _abi, _platform]
            if build.starts_with(|c: char| c.is_ascii_digit()) =>
        {
            (*distribution, *version)
        }
        _ => {
            return Err(UnsupportedFilename::WheelShape {
                components: parts.len(),
            });
        }
    };
    confirm(distribution, version, project)
}

/// PEP 625 escapes an sdist's name the way a wheel does, but the archives predating
/// it do not — so `a-b-1.0.tar.gz` could be `a-b` at `1.0` or `a` at `b-1.0`, and the
/// filename alone cannot say which.
///
/// The expected project is what decides it: a split is a candidate only when its left
/// half normalises to exactly that project and its right half is a whole PEP 440
/// version. Exactly one candidate is an identity; none, or more than one, is an
/// exclusion.
fn sdist_identity(stem: &str, project: &str) -> Result<FileIdentity, UnsupportedFilename> {
    let mut identity: Option<FileIdentity> = None;

    for (index, _) in stem.match_indices('-') {
        let (name, version) = (&stem[..index], &stem[index + 1..]);
        if name.is_empty() || version.is_empty() {
            continue;
        }
        if normalize(name) != project {
            continue;
        }
        if parse_version(version).is_none() {
            continue;
        }
        if identity.is_some() {
            // Two readings of one name. Choosing either would be a guess, and a guess
            // is precisely what lets a version-specific block be escaped (TM-2).
            //
            // DEFENSIVE, and deliberately so: no validated project name can reach
            // this branch today. A second candidate would need a longer prefix that
            // still normalises to the same project, which means the text between the
            // two prefixes is nothing but separators — so the *first* candidate's
            // version would have to begin with a `-`, `_` or `.`, which
            // `parse_version` refuses. The proof spans two functions, so the guard
            // stays rather than collapsing to "the first split wins".
            return Err(UnsupportedFilename::AmbiguousSplit);
        }
        identity = Some(FileIdentity {
            project: project.to_owned(),
            version: version.to_owned(),
        });
    }

    identity.ok_or(UnsupportedFilename::NoIdentity)
}

fn confirm(
    distribution: &str,
    version: &str,
    project: &str,
) -> Result<FileIdentity, UnsupportedFilename> {
    if distribution.is_empty() {
        return Err(UnsupportedFilename::NoIdentity);
    }
    let normalized = normalize(distribution);
    if normalized != project {
        return Err(UnsupportedFilename::OtherProject { named: normalized });
    }
    if parse_version(version).is_none() {
        return Err(UnsupportedFilename::UnparsableVersion);
    }
    Ok(FileIdentity {
        project: normalized,
        version: version.to_owned(),
    })
}

/// A whole PEP 440 version and nothing else.
///
/// `pep440_rs` is the maintained half of this parser, but it is deliberately
/// permissive about spellings PEP 440 calls non-normal, so the text is first held to
/// the shape a version actually has: no surrounding whitespace, and a first character
/// that can begin one (a digit, an epoch, or the tolerated `v` prefix). Without this,
/// a name fragment could be read as a version and a file would be attributed to a
/// release it is not part of.
fn parse_version(text: &str) -> Option<pep440_rs::Version> {
    if text.trim() != text {
        return None;
    }
    let first = text.chars().next()?;
    if !(first.is_ascii_digit() || first == 'v' || first == 'V') {
        return None;
    }
    pep440_rs::Version::from_str(text).ok()
}

/// Why a file was left out of a listing. Every variant is logged with the filename
/// (SPEC §11: "Log exclusions that cannot be represented in an ecosystem listing").
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum UnsupportedFilename {
    Empty,
    Character(char),
    UnknownExtension,
    /// Not five or six `-`-separated components, or a six-component name whose third
    /// component is not a build tag.
    WheelShape {
        components: usize,
    },
    /// The filename names a different project from the one being served.
    OtherProject {
        named: String,
    },
    UnparsableVersion,
    /// No split of an sdist name yields this project and a PEP 440 version.
    NoIdentity,
    /// More than one split does. Choosing one would be a guess.
    AmbiguousSplit,
}

impl fmt::Display for UnsupportedFilename {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UnsupportedFilename::Empty => f.write_str("the filename is empty"),
            UnsupportedFilename::Character(c) => {
                write!(f, "`{}` cannot appear in a filename", c.escape_default())
            }
            UnsupportedFilename::UnknownExtension => {
                f.write_str("the archive extension is not one this release can name")
            }
            UnsupportedFilename::WheelShape { components } => write!(
                f,
                "a wheel name has five or six components, this has {components}"
            ),
            UnsupportedFilename::OtherProject { named } => {
                write!(f, "the filename names the project `{named}`")
            }
            UnsupportedFilename::UnparsableVersion => {
                f.write_str("the version is not a PEP 440 version")
            }
            UnsupportedFilename::NoIdentity => {
                f.write_str("no split of the name yields this project and a version")
            }
            UnsupportedFilename::AmbiguousSplit => {
                f.write_str("the name splits into this project and a version in more than one way")
            }
        }
    }
}

impl std::error::Error for UnsupportedFilename {}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(filename: &str, project: &str) -> Option<String> {
        file_identity(filename, project)
            .ok()
            .map(|found| found.version)
    }

    #[test]
    fn wheel_names_split_on_their_fixed_component_count() {
        assert_eq!(
            identity("friendly_bard-1.0-py3-none-any.whl", "friendly-bard").as_deref(),
            Some("1.0")
        );
        assert_eq!(
            identity("friendly_bard-1.0-7-py3-none-any.whl", "friendly-bard").as_deref(),
            Some("1.0"),
            "a build tag is the sixth component and does not move the version"
        );
        assert_eq!(
            identity(
                "friendly_bard-1.0+ubuntu_1-py3-none-any.whl",
                "friendly-bard"
            )
            .as_deref(),
            Some("1.0+ubuntu_1"),
            "a local version label is part of the version, not a component of its own"
        );
    }

    /// A six-component name whose third component is not a build tag has no reading
    /// PEP 427 sanctions, so it is excluded rather than read as one.
    #[test]
    fn an_unsanctioned_wheel_shape_is_excluded() {
        assert!(matches!(
            file_identity("bard-1.0-extra-py3-none-any.whl", "bard"),
            Err(UnsupportedFilename::WheelShape { components: 6 })
        ));
        assert!(matches!(
            file_identity("bard-1.0-py3-none.whl", "bard"),
            Err(UnsupportedFilename::WheelShape { components: 4 })
        ));
    }

    /// The heart of TM-2: a filename that names a different project is refused, never
    /// reinterpreted as a version of the project being served.
    #[test]
    fn a_filename_naming_another_project_is_never_reinterpreted() {
        assert!(matches!(
            file_identity("bard_1.0-2.0-py3-none-any.whl", "bard"),
            Err(UnsupportedFilename::OtherProject { .. })
        ));
        assert!(matches!(
            file_identity("other-1.0.tar.gz", "bard"),
            Err(UnsupportedFilename::NoIdentity)
        ));
    }

    #[test]
    fn an_sdist_split_must_yield_this_project_and_a_whole_version() {
        assert_eq!(identity("bard-1.0.tar.gz", "bard").as_deref(), Some("1.0"));
        assert_eq!(
            identity("friendly-bard-1.0.tar.gz", "friendly-bard").as_deref(),
            Some("1.0"),
            "a legacy unescaped name is split at the point that names this project"
        );
        assert_eq!(
            identity("friendly_bard-1.0.zip", "friendly-bard").as_deref(),
            Some("1.0")
        );
        assert!(
            matches!(
                file_identity("friendly-bard-notaversion.tar.gz", "friendly-bard"),
                Err(UnsupportedFilename::NoIdentity)
            ),
            "the right half has to be a version, not merely the rest of the name"
        );
    }

    #[test]
    fn unusable_filenames_are_refused_rather_than_parsed() {
        assert!(matches!(
            file_identity("", "bard"),
            Err(UnsupportedFilename::Empty)
        ));
        assert!(matches!(
            file_identity("../../etc/passwd", "bard"),
            Err(UnsupportedFilename::Character('/'))
        ));
        assert!(matches!(
            file_identity("bard-1.0.egg", "bard"),
            Err(UnsupportedFilename::UnknownExtension)
        ));
        assert!(matches!(
            file_identity("bard-1.0.tar.gz\u{0}", "bard"),
            Err(UnsupportedFilename::Character('\u{0}'))
        ));
    }

    /// A version is a whole version. Without this, a fragment of a project name could
    /// be read as one and the file attributed to a release it is not part of.
    #[test]
    fn a_version_must_be_a_whole_pep_440_version() {
        assert!(parse_version("1.0").is_some());
        assert!(parse_version("1.0.0rc1").is_some());
        assert!(parse_version("2!1.0").is_some());
        assert!(parse_version("v1.0").is_some());
        assert!(parse_version("1.0+local.1").is_some());

        assert!(parse_version("").is_none());
        assert!(parse_version(" 1.0").is_none());
        assert!(parse_version("1.0 ").is_none());
        assert!(parse_version("bard-1.0").is_none());
        assert!(parse_version("notaversion").is_none());
    }
}
