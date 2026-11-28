//! The Conan 2 REST layout (`v2/conans/{name}/{version}/{user}/{channel}/...`), parsed once and strictly: a reference, a
//! revision, a package id and a file name have one spelling, and anything else has no meaning here (a 404 before any
//! admission or upstream call). No I/O.
//!
//! Identity: `name/version@user/channel` (a missing user and channel are `_/_` in the URL), the recipe revision (`rrev`), the
//! package id (`pkgid`) and the package revision (`prev`). Policy sees the name and the recipe version; the revisions are what
//! the firewall dates.

use probation_policy::names::valid_conan_part;

/// A revision, a package id: the remote's own hash text (md5 or sha1 hex on every real remote), bounded.
const MAX_ID: usize = 128;
const MAX_FILE_SEGMENTS: usize = 16;
const MAX_FILE_SEGMENT: usize = 128;
const MAX_FILE: usize = 512;
const MAX_QUERY: usize = 200;

/// A recipe reference. `user` and `channel` are `_` together or are both real.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Rref {
    pub name: String,
    pub version: String,
    pub user: String,
    pub channel: String,
}

impl Rref {
    /// `name/version@user/channel`, the spelling a client types (`_/_` is left out).
    pub fn display(&self) -> String {
        if self.user == "_" {
            format!("{}/{}", self.name, self.version)
        } else {
            format!(
                "{}/{}@{}/{}",
                self.name, self.version, self.user, self.channel
            )
        }
    }

    /// The four path segments below `v2/conans`.
    pub fn segments(&self) -> Vec<String> {
        vec![
            self.name.clone(),
            self.version.clone(),
            self.user.clone(),
            self.channel.clone(),
        ]
    }
}

/// One recipe revision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recipe {
    pub rref: Rref,
    pub rrev: String,
}

/// One package id of a recipe revision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Package {
    pub recipe: Recipe,
    pub pkgid: String,
}

/// One package revision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageRev {
    pub package: Package,
    pub prev: String,
}

/// What a request names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Parsed {
    Ping,
    Authenticate,
    CheckCredentials,
    /// `v2/conans/search?q=...` (the validated pattern, and whether the client asked for case-insensitive matching).
    Search {
        pattern: String,
        ignorecase: Option<bool>,
    },
    Latest(Rref),
    Revisions(Rref),
    RecipeFiles(Recipe),
    RecipeFile(Recipe, String),
    PackageSearch(Recipe),
    PackageLatest(Package),
    PackageRevisions(Package),
    PackageFiles(PackageRev),
    PackageFile(PackageRev, String),
    /// A directory of the layout (a recipe, a revision, the packages of a revision, a package, a package revision): not a read, only
    /// the target of a `DELETE`. Carries the segments below `v2/conans`.
    Directory(Vec<String>),
}

/// A revision or a package id.
pub fn id_ok(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_ID
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

/// A file of a revision (`conanfile.py`, `conan_export.tgz`, `metadata/logs/linux x86/build log.txt`): any canonical relative path of at most
/// sixteen segments and 512 bytes whose segments are not empty, not `.` or `..`, and hold no control character, `\` or `%`... A name is
/// percent-encoded wherever it becomes a URL, so spaces and dot-leading segments are ordinary names.
pub fn file_ok(file: &str) -> bool {
    file.len() <= MAX_FILE
        && file.split('/').count() <= MAX_FILE_SEGMENTS
        && file.split('/').all(|part| {
            !part.is_empty()
                && part.len() <= MAX_FILE_SEGMENT
                && part != "."
                && part != ".."
                && !part
                    .chars()
                    .any(|c| c.is_control() || matches!(c, '\\' | '?' | '#'))
        })
}

fn rref_of(parts: &[&str]) -> Option<Rref> {
    let [name, version, user, channel] = parts else {
        return None;
    };
    let named = |value: &str| valid_conan_part(value);
    // A recipe with neither user nor channel is `_/_`; one of the two alone is no reference.
    let user_channel = (*user == "_" && *channel == "_")
        || (*user != "_" && *channel != "_" && named(user) && named(channel));
    (named(name) && named(version) && user_channel).then(|| Rref {
        name: (*name).to_owned(),
        version: (*version).to_owned(),
        user: (*user).to_owned(),
        channel: (*channel).to_owned(),
    })
}

/// Parses the path after the family root (`v2/...`) and the raw query. `None` is a 404.
pub fn parse(path: &str, query: Option<&str>) -> Option<Parsed> {
    if path.len() > 1024 {
        return None;
    }
    let parts: Vec<&str> = path.split('/').collect();
    match parts.as_slice() {
        // The Conan 2 client probes `v1/ping` for capabilities (ConanCenter answers both); nothing else of the v1 tree is routed.
        ["v1" | "v2", "ping"] if query.is_none() => return Some(Parsed::Ping),
        ["v2", "users", "authenticate"] if query.is_none() => return Some(Parsed::Authenticate),
        ["v2", "users", "check_credentials"] if query.is_none() => {
            return Some(Parsed::CheckCredentials);
        }
        ["v2", "conans", "search"] => return parse_search(query?),
        _ => {}
    }
    if query.is_some() {
        return None;
    }
    let ["v2", "conans", rest @ ..] = parts.as_slice() else {
        return None;
    };
    if rest.len() < 4 {
        return None;
    }
    let rref = rref_of(&rest[..4])?;
    let tail = &rest[4..];
    let directory = || {
        Some(Parsed::Directory(
            rest.iter().map(|part| (*part).to_owned()).collect(),
        ))
    };
    let recipe = |rrev: &str| {
        id_ok(rrev).then(|| Recipe {
            rref: rref.clone(),
            rrev: rrev.to_owned(),
        })
    };
    match tail {
        [] => directory(),
        ["latest"] => Some(Parsed::Latest(rref)),
        ["revisions"] => Some(Parsed::Revisions(rref)),
        ["revisions", rrev] => recipe(rrev).and_then(|_| directory()),
        ["revisions", rrev, "files"] => recipe(rrev).map(Parsed::RecipeFiles),
        ["revisions", rrev, "files", file @ ..] if !file.is_empty() => {
            let file = file.join("/");
            (file_ok(&file))
                .then(|| recipe(rrev))
                .flatten()
                .map(|recipe| Parsed::RecipeFile(recipe, file))
        }
        ["revisions", rrev, "search"] => recipe(rrev).map(Parsed::PackageSearch),
        ["revisions", rrev, "packages"] => recipe(rrev).and_then(|_| directory()),
        ["revisions", rrev, "packages", pkgid, more @ ..] => {
            let package = Package {
                recipe: recipe(rrev)?,
                pkgid: (*pkgid).to_owned(),
            };
            if !id_ok(pkgid) {
                return None;
            }
            match more {
                [] => directory(),
                ["latest"] => Some(Parsed::PackageLatest(package)),
                ["revisions"] => Some(Parsed::PackageRevisions(package)),
                ["revisions", prev] => id_ok(prev).then(directory).flatten(),
                ["revisions", prev, "files"] => id_ok(prev).then(|| {
                    Parsed::PackageFiles(PackageRev {
                        package,
                        prev: (*prev).to_owned(),
                    })
                }),
                ["revisions", prev, "files", file @ ..] if !file.is_empty() => {
                    let file = file.join("/");
                    (id_ok(prev) && file_ok(&file)).then(|| {
                        Parsed::PackageFile(
                            PackageRev {
                                package,
                                prev: (*prev).to_owned(),
                            },
                            file,
                        )
                    })
                }
                _ => None,
            }
        }
        _ => None,
    }
}

fn parse_search(query: &str) -> Option<Parsed> {
    let (mut pattern, mut ignorecase) = (None, None);
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=')?;
        let value = percent_encoding::percent_decode_str(value)
            .decode_utf8()
            .ok()?;
        match key {
            "q" if pattern.is_none() => pattern = Some(value.into_owned()),
            "ignorecase" if ignorecase.is_none() => {
                ignorecase = Some(match value.as_ref() {
                    "True" | "true" => true,
                    "False" | "false" => false,
                    _ => return None,
                })
            }
            _ => return None,
        }
    }
    let pattern = pattern?;
    let ok = !pattern.is_empty()
        && pattern.len() <= MAX_QUERY
        && pattern.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'_' | b'+'
                        | b'.'
                        | b'-'
                        | b'*'
                        | b'@'
                        | b'/'
                        | b'#'
                        | b'['
                        | b']'
                        | b'<'
                        | b'>'
                        | b'='
                        | b'~'
                        | b'^'
                        | b','
                        | b'?'
                        | b'!'
                )
        });
    ok.then_some(Parsed::Search {
        pattern,
        ignorecase,
    })
}

/// The segments below `v2/conans` of a parsed revision-level path (so a URL is built from the parsed identity, never from the
/// client's text).
pub fn recipe_segments(recipe: &Recipe) -> Vec<String> {
    let mut segments = recipe.rref.segments();
    segments.extend(["revisions".to_owned(), recipe.rrev.clone()]);
    segments
}

pub fn package_rev_segments(package: &PackageRev) -> Vec<String> {
    let mut segments = recipe_segments(&package.package.recipe);
    segments.extend([
        "packages".to_owned(),
        package.package.pkgid.clone(),
        "revisions".to_owned(),
        package.prev.clone(),
    ]);
    segments
}

/// The URL path segments (below the remote root) of a request's file, as the remote lays them out.
pub fn upstream_segments(below_conans: &[String]) -> Vec<String> {
    let mut segments = vec!["v2".to_owned(), "conans".to_owned()];
    segments.extend(below_conans.iter().cloned());
    segments
}

/// The name a reference row carries for a file: the path below `v2/conans`, starting with the remote's own spelling of the name and the version
/// (which is everything that tells two files of two revisions apart, and what membership rebuilds the unit from).
pub fn row_file_name(rref: &Rref, rest: &[String], file: &str) -> String {
    let mut parts = vec![
        rref.name.clone(),
        rref.version.clone(),
        rref.user.clone(),
        rref.channel.clone(),
    ];
    parts.extend(rest.iter().skip(4).cloned());
    parts.push("files".to_owned());
    parts.push(file.to_owned());
    parts.join("/")
}

/// The anchor file every revision has: its manifest (the row that carries the revision's date).
pub const ANCHOR: &str = "conanmanifest.txt";

#[cfg(test)]
mod tests {
    use super::*;

    fn rref() -> Rref {
        Rref {
            name: "zlib".into(),
            version: "1.3.1".into(),
            user: "_".into(),
            channel: "_".into(),
        }
    }

    #[test]
    fn the_read_routes_of_the_conan_2_client_parse() {
        let base = "v2/conans/zlib/1.3.1/_/_";
        assert_eq!(parse("v2/ping", None), Some(Parsed::Ping));
        assert_eq!(parse("v1/ping", None), Some(Parsed::Ping));
        assert_eq!(
            parse("v2/users/authenticate", None),
            Some(Parsed::Authenticate)
        );
        assert_eq!(
            parse("v2/users/check_credentials", None),
            Some(Parsed::CheckCredentials)
        );
        assert_eq!(
            parse("v2/conans/search", Some("q=zlib/*&ignorecase=False")),
            Some(Parsed::Search {
                pattern: "zlib/*".into(),
                ignorecase: Some(false)
            })
        );
        // fnmatch's own characters are part of a pattern (`?`, `[!seq]`), so a valid search is never refused.
        assert_eq!(
            parse("v2/conans/search", Some("q=zli%3F/%5B!a%5D*")),
            Some(Parsed::Search {
                pattern: "zli?/[!a]*".into(),
                ignorecase: None
            })
        );
        assert_eq!(
            parse(&format!("{base}/latest"), None),
            Some(Parsed::Latest(rref()))
        );
        assert_eq!(
            parse(&format!("{base}/revisions"), None),
            Some(Parsed::Revisions(rref()))
        );
        let recipe = Recipe {
            rref: rref(),
            rrev: "abc123".into(),
        };
        assert_eq!(
            parse(&format!("{base}/revisions/abc123/files"), None),
            Some(Parsed::RecipeFiles(recipe.clone()))
        );
        assert_eq!(
            parse(&format!("{base}/revisions/abc123/files/conanfile.py"), None),
            Some(Parsed::RecipeFile(recipe.clone(), "conanfile.py".into()))
        );
        assert_eq!(
            parse(&format!("{base}/revisions/abc123/search"), None),
            Some(Parsed::PackageSearch(recipe.clone()))
        );
        let package = Package {
            recipe,
            pkgid: "b647c4".into(),
        };
        assert_eq!(
            parse(
                &format!("{base}/revisions/abc123/packages/b647c4/latest"),
                None
            ),
            Some(Parsed::PackageLatest(package.clone()))
        );
        assert_eq!(
            parse(
                &format!("{base}/revisions/abc123/packages/b647c4/revisions"),
                None
            ),
            Some(Parsed::PackageRevisions(package.clone()))
        );
        let rev = PackageRev {
            package,
            prev: "fee20b".into(),
        };
        assert_eq!(
            parse(
                &format!("{base}/revisions/abc123/packages/b647c4/revisions/fee20b/files"),
                None
            ),
            Some(Parsed::PackageFiles(rev.clone()))
        );
        assert_eq!(
            parse(
                &format!(
                    "{base}/revisions/abc123/packages/b647c4/revisions/fee20b/files/conan_package.tgz"
                ),
                None
            ),
            Some(Parsed::PackageFile(rev, "conan_package.tgz".into()))
        );
        let user = parse("v2/conans/mylib/2.0-rc1/acme/stable/latest", None);
        assert_eq!(
            user,
            Some(Parsed::Latest(Rref {
                name: "mylib".into(),
                version: "2.0-rc1".into(),
                user: "acme".into(),
                channel: "stable".into()
            }))
        );
    }

    #[test]
    fn one_path_is_one_identity() {
        for bad in [
            "v2/conans/zlib/1.3.1/_/latest",
            "v2/conans/zlib/1.3.1/acme/_/latest",
            "v2/conans/zlib/1.3.1/_/stable/latest",
            "v2/conans/zlib/1.3.1/_/_/revisions/a%2Fb/files",
            "v2/conans/zlib/../1.3.1/_/_/latest",
            "v2/conans/zlib/1.3.1/_/_/revisions/abc/files/../x",
            "v2/conans/zlib/1.3.1/_/_/revisions/abc/files/a/../x",
            "v2/conans/zlib/1.3.1/_/_/revisions/abc/files/",
            "v2/conans/.zlib/1.3.1/_/_/latest",
            "v2/conans/zlib/1.3.1/_/_/latest/extra",
            "v2/conans/zlib/1.3.1/_/_/revisions/abc/packages/p/revisions/r/files/x/../y",
            "v1/conans/zlib/1.3.1/_/_/download_urls",
            "v1/users/authenticate",
            "v1/conans/search",
            "v2/conans/zlib/1.3.1/_/_/download_urls",
            "v2/conans/zlib/1.3.1/_/_/packages/p/download_urls",
            "v2/unknown",
            "",
        ] {
            assert_eq!(parse(bad, None), None, "{bad}");
        }
        assert_eq!(
            parse("v2/conans/zlib/1.3.1/_/_/latest", Some("x=1")),
            None,
            "no query on a layout route"
        );
        assert_eq!(parse("v2/conans/search", Some("q=a&evil=1")), None);
        assert_eq!(parse("v2/conans/search", Some("q=a&q=b")), None);
        assert_eq!(parse("v2/conans/search", Some("ignorecase=True")), None);
        assert_eq!(parse("v2/conans/search", Some("q=a%00")), None);
        assert_eq!(parse("v2/conans/search", None), None);
    }

    #[test]
    fn a_directory_is_only_a_delete_target() {
        assert!(matches!(
            parse("v2/conans/zlib/1.3.1/_/_", None),
            Some(Parsed::Directory(_))
        ));
        assert!(matches!(
            parse("v2/conans/zlib/1.3.1/_/_/revisions/abc", None),
            Some(Parsed::Directory(_))
        ));
        assert!(matches!(
            parse("v2/conans/zlib/1.3.1/_/_/revisions/abc/packages", None),
            Some(Parsed::Directory(_))
        ));
        assert!(matches!(
            parse("v2/conans/zlib/1.3.1/_/_/revisions/abc/packages/p", None),
            Some(Parsed::Directory(_))
        ));
        assert!(matches!(
            parse(
                "v2/conans/zlib/1.3.1/_/_/revisions/abc/packages/p/revisions/r",
                None
            ),
            Some(Parsed::Directory(_))
        ));
    }

    #[test]
    fn a_row_file_name_tells_every_revision_and_file_apart() {
        let r = Rref {
            name: "zlib".into(),
            version: "1".into(),
            user: "_".into(),
            channel: "_".into(),
        };
        let recipe = Recipe {
            rref: r.clone(),
            rrev: "R".into(),
        };
        let name = row_file_name(&r, &recipe_segments(&recipe), "conanfile.py");
        assert_eq!(name, "zlib/1/_/_/revisions/R/files/conanfile.py");
        let package = PackageRev {
            package: Package {
                recipe,
                pkgid: "P".into(),
            },
            prev: "V".into(),
        };
        assert_eq!(
            row_file_name(&r, &package_rev_segments(&package), "conan_package.tgz"),
            "zlib/1/_/_/revisions/R/packages/P/revisions/V/files/conan_package.tgz"
        );
    }
}
