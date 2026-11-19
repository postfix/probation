//! Row 21 fixtures shared by tests/maven_*.rs: a fake Maven repository's documents (the shapes Maven Central writes, with
//! its `Last-Modified` dating each POM), a real (stored) jar, and the checksum hex a repository publishes.
#![allow(dead_code)]

use super::{FakeAnswer, FakeRegistry};
use std::sync::Arc;

/// The origin the fake repository sits on (it has a path, as Maven Central's `maven2` does).
pub const REPO: &str = "https://maven.invalid/maven2";
pub const PUBLISH: &str = "https://maven-deploy.invalid/repo";
pub const ROOT: &str = "/maven2";

/// `Last-Modified` as a repository writes it.
pub fn http_date(rfc3339: &str) -> String {
    let at: jiff::Timestamp = rfc3339.parse().expect("a timestamp");
    jiff::fmt::rfc2822::to_string(&at.in_tz("UTC").expect("UTC")).expect("an RFC 2822 date").replace("+0000", "GMT")
}

pub fn pom(group: &str, artifact: &str, version: &str) -> String {
    format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n  <modelVersion>4.0.0</modelVersion>\n  <groupId>{group}</groupId>\n  <artifactId>{artifact}</artifactId>\n  <version>{version}</version>\n</project>\n")
}

/// `maven-metadata.xml` of an artifact, written the way Maven Central writes it.
pub fn metadata(group: &str, artifact: &str, latest: &str, release: &str, versions: &[&str]) -> String {
    let list: String = versions.iter().map(|v| format!("      <version>{v}</version>\n")).collect();
    format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<metadata>\n  <groupId>{group}</groupId>\n  <artifactId>{artifact}</artifactId>\n  <versioning>\n    <latest>{latest}</latest>\n    <release>{release}</release>\n    <versions>\n{list}    </versions>\n    <lastUpdated>20260405120000</lastUpdated>\n  </versioning>\n</metadata>\n")
}

/// A snapshot version's `maven-metadata.xml` naming `builds` (`20260101.120000-1`), the last one the newest.
pub fn snapshot_metadata(group: &str, artifact: &str, version: &str, builds: &[&str]) -> String {
    let base = version.trim_end_matches("-SNAPSHOT");
    let (newest_stamp, newest_number) = builds.last().and_then(|b| b.split_once('-')).expect("a build");
    let entries: String = builds.iter().map(|build| format!("        <snapshotVersion>\n          <extension>jar</extension>\n          <value>{base}-{build}</value>\n          <updated>20260101120000</updated>\n        </snapshotVersion>\n")).collect();
    format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<metadata modelVersion=\"1.1.0\">\n  <groupId>{group}</groupId>\n  <artifactId>{artifact}</artifactId>\n  <version>{version}</version>\n  <versioning>\n    <snapshot>\n      <timestamp>{newest_stamp}</timestamp>\n      <buildNumber>{newest_number}</buildNumber>\n    </snapshot>\n    <lastUpdated>20260101120000</lastUpdated>\n    <snapshotVersions>\n{entries}    </snapshotVersions>\n  </versioning>\n</metadata>\n")
}

pub fn plugin_metadata(plugins: &[(&str, &str, &str)]) -> String {
    let list: String = plugins.iter().map(|(name, prefix, artifact)| format!("  <plugin>\n    <name>{name}</name>\n    <prefix>{prefix}</prefix>\n    <artifactId>{artifact}</artifactId>\n  </plugin>\n")).collect();
    format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<metadata>\n<plugins>\n{list}</plugins>\n</metadata>\n")
}

/// A real jar (a stored zip with a manifest), so `javac` and `mvn` can open it.
pub fn jar(artifact: &str, version: &str) -> Vec<u8> {
    let files: Vec<(String, Vec<u8>)> = vec![
        ("META-INF/MANIFEST.MF".to_owned(), format!("Manifest-Version: 1.0\r\nImplementation-Title: {artifact}\r\nImplementation-Version: {version}\r\n\r\n").into_bytes()),
        (format!("{artifact}.txt"), format!("{artifact} {version}").into_bytes()),
    ];
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, data) in &files {
        let (crc, size) = (super::go::crc32(data), data.len() as u32);
        let offset = out.len() as u32;
        out.extend_from_slice(&[0x50, 0x4b, 0x03, 0x04, 20, 0, 0, 0, 0, 0, 0, 0, 0x21, 0]);
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(data);
        central.extend_from_slice(&[0x50, 0x4b, 0x01, 0x02, 20, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0x21, 0]);
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&(name.len() as u16).to_le_bytes());
        central.extend_from_slice(&[0; 12]);
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name.as_bytes());
    }
    let start = out.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(&[0x50, 0x4b, 0x05, 0x06, 0, 0]);
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&(files.len() as u16).to_le_bytes());
    out.extend_from_slice(&(files.len() as u16).to_le_bytes());
    out.extend_from_slice(&(central.len() as u32).to_le_bytes());
    out.extend_from_slice(&start.to_le_bytes());
    out.extend_from_slice(&[0, 0]);
    out
}

/// The path a layout path has on the fake repository.
pub fn at(path: &str) -> String {
    format!("{ROOT}/{path}")
}

/// A version on the fake repository: its POM (dated `published`), jar, sources jar and checksum files.
pub fn serve_version(registry: &Arc<FakeRegistry>, group: &str, artifact: &str, version: &str, published: Option<&str>) {
    let dir = format!("{}/{artifact}/{version}", group.replace('.', "/"));
    let answer = |body: Vec<u8>| match published {
        Some(date) => FakeAnswer::Dated { body, last_modified: http_date(date) },
        None => FakeAnswer::Bytes(body),
    };
    registry.answer(&at(&format!("{dir}/{artifact}-{version}.pom")), answer(pom(group, artifact, version).into_bytes()));
    registry.answer(&at(&format!("{dir}/{artifact}-{version}.jar")), answer(jar(artifact, version)));
    registry.answer(&at(&format!("{dir}/{artifact}-{version}-sources.jar")), answer(jar(&format!("{artifact}-sources"), version)));
    registry.answer(&at(&format!("{dir}/{artifact}-{version}.jar.sha1")), FakeAnswer::Body(sha1_hex(&jar(artifact, version))));
}

pub fn sha1_hex(body: &[u8]) -> String {
    use sha1::Digest;
    hex::encode(sha1::Sha1::digest(body))
}
