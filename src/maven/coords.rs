//! The Maven repository layout (`{group as directories}/{artifact}/{version}/{artifact}-{version}[-{classifier}].{ext}`),
//! parsed once and strictly, with no I/O.
//!
//! One path is one identity. A group is its directories joined by `.` and a directory is never allowed to contain a
//! `.` itself (`a.b/c/1/c-1.jar` and `a/b/c/1/c-1.jar` would otherwise be two spellings of one coordinate); every name is
//! compared as written (case is part of the identity on every repository), so the upstream URL, the policy key
//! `groupId:artifactId`, the version and the file name are all rebuilt from what was parsed and compared exactly.
//! Anything else is a 404 before any upstream call.

use md5::Md5;
use sha1::Sha1;
use sha2::{Digest as _, Sha256, Sha512};

/// The checksum sidecars a repository publishes next to every file and every `maven-metadata.xml`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sum {
    Md5,
    Sha1,
    Sha256,
    Sha512,
}

impl Sum {
    pub const ALL: [Sum; 4] = [Sum::Md5, Sum::Sha1, Sum::Sha256, Sum::Sha512];

    pub fn ext(self) -> &'static str {
        match self {
            Sum::Md5 => "md5",
            Sum::Sha1 => "sha1",
            Sum::Sha256 => "sha256",
            Sum::Sha512 => "sha512",
        }
    }

    pub fn from_ext(ext: &str) -> Option<Sum> {
        Sum::ALL.into_iter().find(|sum| sum.ext() == ext)
    }

    /// The lower-case hex digest of `body`, as a repository writes it in a `.{ext}` file (no newline, no file name).
    pub fn hex(self, body: &[u8]) -> String {
        match self {
            Sum::Md5 => hex::encode(Md5::digest(body)),
            Sum::Sha1 => hex::encode(Sha1::digest(body)),
            Sum::Sha256 => hex::encode(Sha256::digest(body)),
            Sum::Sha512 => hex::encode(Sha512::digest(body)),
        }
    }
}

/// What follows a document's name: itself, its checksum, its detached signature, or the checksum of its signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Doc,
    Sum(Sum),
    Asc,
    AscSum(Sum),
}

impl Side {
    /// The suffix of `name` that makes it this side's file name.
    pub fn suffix(self) -> String {
        match self {
            Side::Doc => String::new(),
            Side::Sum(sum) => format!(".{}", sum.ext()),
            Side::Asc => ".asc".to_owned(),
            Side::AscSum(sum) => format!(".asc.{}", sum.ext()),
        }
    }

    fn of(file: &str, base: &str) -> Option<Side> {
        let tail = file.strip_prefix(base)?;
        if tail.is_empty() {
            return Some(Side::Doc);
        }
        let tail = tail.strip_prefix('.')?;
        if tail == "asc" {
            return Some(Side::Asc);
        }
        if let Some(sum) = Sum::from_ext(tail) {
            return Some(Side::Sum(sum));
        }
        Some(Side::AscSum(Sum::from_ext(tail.strip_prefix("asc.")?)?))
    }
}

pub const METADATA: &str = "maven-metadata.xml";
pub const CATALOG: &str = "archetype-catalog.xml";

/// What a request path names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Parsed {
    /// `{dirs}/maven-metadata.xml` and its sidecars. A document whose last directory is a `-SNAPSHOT` version is that
    /// version's (`Level::Snapshot`); any other is an artifact's or, for plugin prefixes, a group's (`Level::Artifact`,
    /// the document itself says which).
    Metadata { dirs: Vec<String>, level: Level, side: Side },
    /// The repository's `archetype-catalog.xml` (at the root) and its sidecars.
    Catalog(Side),
    /// A file of one version (the sidecars of a file are files of the same version).
    File(FileRef),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    Artifact,
    Snapshot,
}

/// A file below a version directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileRef {
    pub group: String,
    pub artifact: String,
    /// The version directory (a snapshot's is `1.0-SNAPSHOT`, whatever the build in the file name).
    pub version: String,
    pub file: String,
    /// The build (`20200101.120000-1`) of a timestamped snapshot file; `None` for a release or a literal `-SNAPSHOT` file.
    pub build: Option<String>,
}

impl FileRef {
    /// The policy and OSV key.
    pub fn name(&self) -> String {
        format!("{}:{}", self.group, self.artifact)
    }

    /// The unit whose age every file of it shares: the version, or one snapshot build of it.
    pub fn unit(&self) -> Unit {
        Unit { version: self.version.clone(), build: self.build.clone() }
    }
}

/// A release version, or one build of a snapshot version: the thing that has a publication time.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Unit {
    pub version: String,
    pub build: Option<String>,
}

impl Unit {
    /// A key for the in-memory tables.
    pub fn key(&self) -> String {
        match &self.build {
            Some(build) => format!("{}@{build}", self.version),
            None => self.version.clone(),
        }
    }

    /// The version as it appears in file names of this unit (`1.0-20200101.120000-1` for a build of `1.0-SNAPSHOT`).
    pub fn file_version(&self) -> String {
        match &self.build {
            Some(build) => format!("{}-{build}", self.version.strip_suffix("-SNAPSHOT").unwrap_or(&self.version)),
            None => self.version.clone(),
        }
    }

    /// The POM of the unit: the file whose `Last-Modified` dates it.
    pub fn anchor(&self, artifact: &str) -> String {
        format!("{artifact}-{}.pom", self.file_version())
    }
}

const MAX_SEGMENTS: usize = 64;
const MAX_SEGMENT: usize = 200;
pub const MAX_VERSION: usize = 128;
const MAX_TAIL: usize = 128;

/// A directory of the group part: `[A-Za-z0-9_-]`, never a dot (so one group has one path).
pub fn group_dir_ok(segment: &str) -> bool {
    !segment.is_empty() && segment.len() <= MAX_SEGMENT && segment.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

pub fn artifact_ok(segment: &str) -> bool {
    !segment.is_empty() && segment.len() <= MAX_SEGMENT && !segment.starts_with('.') && segment.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// A version directory: `[A-Za-z0-9._+~-]`, starting with an alphanumeric, at most 128 bytes.
pub fn version_ok(segment: &str) -> bool {
    !segment.is_empty()
        && segment.len() <= MAX_VERSION
        && segment.as_bytes()[0].is_ascii_alphanumeric()
        && segment.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'~' | b'-'))
}

/// `groupId:artifactId` of directories, when every one is valid.
pub fn name_of(dirs: &[String], artifact: &str) -> Option<(String, String)> {
    if dirs.is_empty() || !dirs.iter().all(|dir| group_dir_ok(dir)) || !artifact_ok(artifact) {
        return None;
    }
    let group = dirs.join(".");
    let name = format!("{group}:{artifact}");
    probation_policy::names::valid_name(probation_policy::Ecosystem::Maven, &name).then_some((group, artifact.to_owned()))
}

/// What may follow `{artifact}-{version}`: `.ext`, or `-{classifier}.ext`, in the repository's own charset.
fn tail_ok(tail: &str) -> bool {
    if tail.len() > MAX_TAIL || !tail.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-')) || tail.contains("..") {
        return false;
    }
    let mut chars = tail.chars();
    let (Some(first), Some(second)) = (chars.next(), chars.next()) else { return false };
    // `.ext` or `-classifier.ext`: a classifier does not start with a dot or a dash.
    if !matches!(first, '.' | '-') || !second.is_ascii_alphanumeric() {
        return false;
    }
    // The extension (what follows the last `.`) is not empty and starts with an alphanumeric.
    match tail.rsplit_once('.') {
        Some((_, ext)) => !ext.is_empty() && ext.as_bytes()[0].is_ascii_alphanumeric(),
        None => false,
    }
}

/// Splits a file name of `artifact`'s `version` directory: the optional build of a snapshot file, or `None` when the
/// name is no file of that directory. A sidecar (`.sha1`, `.md5`, `.sha256`, `.sha512`, `.asc` and the checksums of a
/// signature) is a file of the version like its subject.
fn split_file(artifact: &str, version: &str, file: &str) -> Option<Option<String>> {
    let mut core = file;
    for _ in 0..2 {
        let Some((head, ext)) = core.rsplit_once('.') else { break };
        if ext == "asc" || Sum::from_ext(ext).is_some() {
            core = head;
        } else {
            break;
        }
    }
    let rest = core.strip_prefix(artifact)?.strip_prefix('-')?;
    if let Some(tail) = rest.strip_prefix(version)
        && tail_ok(tail)
    {
        return Some(None);
    }
    let base = version.strip_suffix("-SNAPSHOT")?;
    let after = rest.strip_prefix(base)?.strip_prefix('-')?;
    // `YYYYMMDD.HHMMSS-N`.
    let b = after.as_bytes();
    if b.len() < 17 || !b[..8].iter().all(u8::is_ascii_digit) || b[8] != b'.' || !b[9..15].iter().all(u8::is_ascii_digit) || b[15] != b'-' {
        return None;
    }
    let digits = b[16..].iter().take_while(|c| c.is_ascii_digit()).count();
    if digits == 0 || digits > 9 {
        return None;
    }
    let (token, tail) = after.split_at(16 + digits);
    tail_ok(tail).then(|| Some(token.to_owned()))
}

/// Parses a path below the repository root. `None` is a 404.
pub fn parse(path: &str) -> Option<Parsed> {
    if path.is_empty() || path.len() > 4096 || path.starts_with('/') || path.ends_with('/') {
        return None;
    }
    let segments: Vec<&str> = path.split('/').collect();
    if segments.len() > MAX_SEGMENTS || segments.iter().any(|s| s.is_empty() || s.len() > MAX_SEGMENT + MAX_TAIL) {
        return None;
    }
    let (file, dirs) = segments.split_last()?;
    if dirs.is_empty() {
        let side = Side::of(file, CATALOG)?;
        return Some(Parsed::Catalog(side));
    }
    if let Some(side) = Side::of(file, METADATA) {
        let dirs: Vec<String> = dirs.iter().map(|s| (*s).to_owned()).collect();
        if dirs.len() > 2 && dirs.last().is_some_and(|last| last.ends_with("-SNAPSHOT")) {
            let (version, above) = dirs.split_last()?;
            let (artifact, group) = above.split_last()?;
            version_ok(version).then_some(())?;
            name_of(group, artifact)?;
            return Some(Parsed::Metadata { dirs, level: Level::Snapshot, side });
        }
        // The identity pre-check of the handler needs a valid artifact and group (or, for plugin prefixes, a group).
        if !dirs.iter().all(|dir| group_dir_ok(dir) || artifact_ok(dir)) || !dirs[..dirs.len() - 1].iter().all(|dir| group_dir_ok(dir)) {
            return None;
        }
        return Some(Parsed::Metadata { dirs, level: Level::Artifact, side });
    }
    if dirs.len() < 3 {
        return None;
    }
    let (version, above) = dirs.split_last()?;
    let (artifact, group) = above.split_last()?;
    let group: Vec<String> = group.iter().map(|s| (*s).to_owned()).collect();
    let (group, artifact) = name_of(&group, artifact)?;
    version_ok(version).then_some(())?;
    let build = split_file(&artifact, version, file)?;
    Some(Parsed::File(FileRef { group, artifact, version: (*version).to_owned(), file: (*file).to_owned(), build }))
}

/// A directory of the layout (`{group}/{artifact}/` or `{group}/{artifact}/{version}/`, trailing slash optional): the segments,
/// each validated as a group directory, an artifact id and a version. Only a clean-up (`DELETE`) names one.
pub fn parse_dir(path: &str) -> Option<Vec<String>> {
    let trimmed = path.strip_suffix('/').unwrap_or(path);
    let segments: Vec<&str> = trimmed.split('/').collect();
    if segments.len() < 2 || segments.len() > MAX_SEGMENTS || trimmed.len() > 4096 {
        return None;
    }
    let as_artifact = |groups: &[&str], artifact: &str| groups.iter().all(|dir| group_dir_ok(dir)) && artifact_ok(artifact);
    let n = segments.len();
    let artifact_dir = as_artifact(&segments[..n - 1], segments[n - 1]);
    let version_dir = n >= 3 && as_artifact(&segments[..n - 2], segments[n - 2]) && version_ok(segments[n - 1]);
    (artifact_dir || version_dir).then(|| segments.iter().map(|s| (*s).to_owned()).collect())
}

/// The path segments below the repository root of a file.
pub fn file_segments(file: &FileRef) -> Vec<String> {
    let mut segments: Vec<String> = file.group.split('.').map(str::to_owned).collect();
    segments.push(file.artifact.clone());
    segments.push(file.version.clone());
    segments.push(file.file.clone());
    segments
}

/// The path segments of a metadata document of `dirs`.
pub fn metadata_segments(dirs: &[String], side: Side) -> Vec<String> {
    let mut segments = dirs.to_vec();
    segments.push(format!("{METADATA}{}", side.suffix()));
    segments
}

/// The artifact-level identity of a metadata path: its last directory is the artifact, the ones above are the group.
pub fn artifact_of(dirs: &[String]) -> Option<(String, String)> {
    let (artifact, group) = dirs.split_last()?;
    name_of(group, artifact)
}

/// The snapshot version-level identity: `(group, artifact, version directory)`.
pub fn snapshot_of(dirs: &[String]) -> Option<(String, String, String)> {
    let (version, above) = dirs.split_last()?;
    let (group, artifact) = artifact_of(above)?;
    Some((group, artifact, version.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(path: &str) -> FileRef {
        match parse(path) {
            Some(Parsed::File(file)) => file,
            other => panic!("{path}: {other:?}"),
        }
    }

    #[test]
    fn files_of_a_release_version_parse_with_every_classifier_extension_and_sidecar() {
        for path in [
            "org/apache/maven/maven-core/3.9.0/maven-core-3.9.0.jar",
            "org/apache/maven/maven-core/3.9.0/maven-core-3.9.0.pom",
            "org/apache/maven/maven-core/3.9.0/maven-core-3.9.0-sources.jar",
            "org/apache/maven/maven-core/3.9.0/maven-core-3.9.0-bin.tar.gz",
            "org/apache/maven/maven-core/3.9.0/maven-core-3.9.0.module",
            "org/apache/maven/maven-core/3.9.0/maven-core-3.9.0.jar.sha1",
            "org/apache/maven/maven-core/3.9.0/maven-core-3.9.0.jar.asc",
            "org/apache/maven/maven-core/3.9.0/maven-core-3.9.0.jar.asc.sha256",
            "org/apache/maven/maven-core/3.9.0/maven-core-3.9.0.pom.md5",
        ] {
            let parsed = file(path);
            assert_eq!(parsed.name(), "org.apache.maven:maven-core", "{path}");
            assert_eq!(parsed.version, "3.9.0");
            assert_eq!(parsed.build, None);
        }
        assert_eq!(file("a/b/c.d/1/c.d-1.jar").artifact, "c.d", "an artifact id may carry dots");
        assert_eq!(file("com/foo/Bar_Baz/1.0+build.5/Bar_Baz-1.0+build.5.jar").version, "1.0+build.5");
    }

    #[test]
    fn snapshot_builds_resolve_to_their_timestamp_and_number() {
        let build = file("com/foo/lib/1.0-SNAPSHOT/lib-1.0-20200101.120000-17.jar");
        assert_eq!(build.build.as_deref(), Some("20200101.120000-17"));
        assert_eq!(build.unit().file_version(), "1.0-20200101.120000-17");
        assert_eq!(build.unit().anchor("lib"), "lib-1.0-20200101.120000-17.pom");
        assert_eq!(file("com/foo/lib/1.0-SNAPSHOT/lib-1.0-20200101.120000-3-sources.jar.sha1").build.as_deref(), Some("20200101.120000-3"));
        assert_eq!(file("com/foo/lib/1.0-SNAPSHOT/lib-1.0-SNAPSHOT.jar").build, None, "the literal name is its own unit");
        assert_eq!(file("com/foo/lib/1.0-SNAPSHOT/lib-1.0-SNAPSHOT.jar").unit().anchor("lib"), "lib-1.0-SNAPSHOT.pom");
        assert!(parse("com/foo/lib/1.0-SNAPSHOT/lib-1.0-2020.jar").is_none(), "no timestamp, no build");
        assert!(parse("com/foo/lib/1.0/lib-1.0-20200101.120000-17.jar").is_some(), "on a release a build-looking tail is a classifier");
    }

    #[test]
    fn metadata_paths_are_artifact_group_or_snapshot_level() {
        assert!(matches!(parse("junit/junit/maven-metadata.xml"), Some(Parsed::Metadata { level: Level::Artifact, side: Side::Doc, .. })));
        assert!(matches!(parse("org/apache/maven/plugins/maven-metadata.xml.sha1"), Some(Parsed::Metadata { side: Side::Sum(Sum::Sha1), .. })));
        assert!(matches!(parse("junit/junit/maven-metadata.xml.asc.md5"), Some(Parsed::Metadata { side: Side::AscSum(Sum::Md5), .. })));
        assert!(matches!(parse("com/foo/lib/1.0-SNAPSHOT/maven-metadata.xml"), Some(Parsed::Metadata { level: Level::Snapshot, .. })));
        assert!(matches!(parse("archetype-catalog.xml"), Some(Parsed::Catalog(Side::Doc))));
        assert!(matches!(parse("archetype-catalog.xml.sha1"), Some(Parsed::Catalog(Side::Sum(Sum::Sha1)))));
        assert!(parse("maven-metadata.xml").is_none(), "the root has no metadata");
        assert!(parse("junit/junit/maven-metadata.xml.bad").is_none());
    }

    #[test]
    fn one_path_is_one_identity() {
        for path in [
            "a.b/c/1/c-1.jar",            // a dot in a group directory (two spellings of group a.b)
            "a/b/c/1/c-2.jar",            // the file is not of the directory's version
            "a/b/d/1/c-1.jar",            // not of the directory's artifact
            "a/b/c/1/c-1",                // no extension
            "a/b/c/1/c-1.",               // empty extension
            "a/b/c/1/c-1..jar",
            "a/b/c/1/c-1-.jar",
            "a/b/c/../1/c-1.jar",
            "a/b//c/1/c-1.jar",
            "/a/b/c/1/c-1.jar",
            "a/b/c/1/c-1.jar/",
            "a/B c/c/1/c-1.jar",
            "a/b/.c/1/.c-1.jar",
            "a/b/c/.1/c-.1.jar",
            "c/1/c-1.jar",                 // no group
            "a/b/c/1/c-1.jar%2f",
            "a/b/c/1/c-1.jar:x",
        ] {
            assert!(parse(path).is_none(), "{path}");
        }
        // Case is identity: these are different artifacts, not one.
        assert_ne!(file("a/b/C/1/C-1.jar").name(), file("a/b/c/1/c-1.jar").name());
    }

    #[test]
    fn a_directory_of_the_layout_is_an_artifact_or_a_version_directory() {
        assert_eq!(parse_dir("org/demo/lib/1.0/").unwrap(), ["org", "demo", "lib", "1.0"]);
        assert_eq!(parse_dir("org/demo/lib").unwrap(), ["org", "demo", "lib"]);
        for bad in ["lib", "", "org/../lib/1.0/", "org//lib/1.0", "a.b/lib/1.0/", "org/demo/lib/.1/", "org/demo/lib/1.0/x y/"] {
            assert!(parse_dir(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn checksums_are_the_repositorys_own_hex() {
        assert_eq!(Sum::Md5.hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(Sum::Sha1.hex(b"abc"), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(Sum::Sha256.hex(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(Sum::Sha512.hex(b"abc").len(), 128);
    }
}
