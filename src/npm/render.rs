//! Full, abbreviated and single-version serialisation from one snapshot.
//!
//! All three forms are built from the same filtered entry list and the same resolved
//! tags, which is what SPEC §6's "derive the abbreviated install response from that
//! same snapshot" means in practice: there is no second filtering pass that could
//! disagree with the first.
//!
//! Exactly one field of a version record is ever edited — `dist.tarball`, rewritten
//! to this instance's artifact URL. Dependency, optional-dependency,
//! peer-dependency, platform and engine fields are copied through as upstream wrote
//! them (SPEC §6: "Never edit dependency constraints").

use serde_json::{Map, Value};
use url::Url;

use crate::npm::document::{PackageDocument, VersionEntry, prune_time};
use crate::policy::Ecosystem;
use crate::store::rows::ReferenceId;

/// The npm abbreviated ("install") document's per-version field set. Anything not
/// named here is left out of the abbreviated form, and nothing named here is edited.
const ABBREVIATED_FIELDS: &[&str] = &[
    "name",
    "version",
    "dist",
    "dependencies",
    "optionalDependencies",
    "devDependencies",
    "bundleDependencies",
    "peerDependencies",
    "peerDependenciesMeta",
    "acceptDependencies",
    "directories",
    "bin",
    "engines",
    "cpu",
    "os",
    "libc",
    "funding",
    "deprecated",
    "hasInstallScript",
    "_hasShrinkwrap",
];

pub const FULL_CONTENT_TYPE: &str = "application/json";
pub const ABBREVIATED_CONTENT_TYPE: &str = "application/vnd.npm.install-v1+json; charset=utf-8";

/// The full filtered document: every top-level field upstream sent, with `versions`,
/// `time` and `dist-tags` replaced by their filtered forms.
pub fn full(
    document: &PackageDocument,
    kept: &[&VersionEntry],
    tags: &Map<String, Value>,
    public_url: &Url,
) -> Vec<u8> {
    let mut out = document.rest.clone();
    out.insert("name".to_owned(), Value::from(document.name.clone()));
    out.insert("dist-tags".to_owned(), Value::Object(tags.clone()));
    out.insert(
        "versions".to_owned(),
        Value::Object(rewritten_versions(kept, public_url)),
    );
    out.insert(
        "time".to_owned(),
        Value::Object(prune_time(&document.time, |version| {
            kept.iter().any(|entry| entry.version() == version)
        })),
    );

    serialise(&Value::Object(out))
}

/// The abbreviated install document, derived from the same snapshot.
pub fn abbreviated(
    document: &PackageDocument,
    kept: &[&VersionEntry],
    tags: &Map<String, Value>,
    public_url: &Url,
) -> Vec<u8> {
    let mut versions = Map::new();
    for entry in kept {
        let mut record = rewritten_record(entry, public_url);
        if let Value::Object(object) = &mut record {
            object.retain(|key, _| ABBREVIATED_FIELDS.contains(&key.as_str()));
        }
        versions.insert(entry.version().to_owned(), record);
    }

    let mut out = Map::new();
    out.insert("name".to_owned(), Value::from(document.name.clone()));
    out.insert("dist-tags".to_owned(), Value::Object(tags.clone()));
    if let Some(modified) = document.time.get("modified") {
        out.insert("modified".to_owned(), modified.clone());
    }
    out.insert("versions".to_owned(), Value::Object(versions));

    serialise(&Value::Object(out))
}

/// One version's record, as `GET /npm/{package}/{version-or-tag}` answers it.
pub fn single_version(entry: &VersionEntry, public_url: &Url) -> Vec<u8> {
    serialise(&rewritten_record(entry, public_url))
}

fn rewritten_versions(kept: &[&VersionEntry], public_url: &Url) -> Map<String, Value> {
    kept.iter()
        .map(|entry| {
            (
                entry.version().to_owned(),
                rewritten_record(entry, public_url),
            )
        })
        .collect()
}

/// A copy of the upstream record with `dist.tarball` pointing here instead. Upstream
/// integrity fields are preserved beside it (SPEC §9: "Preserve upstream integrity
/// fields in client metadata").
fn rewritten_record(entry: &VersionEntry, public_url: &Url) -> Value {
    let mut record = entry.record.clone();
    if let Some(dist) = record.get_mut("dist").and_then(Value::as_object_mut) {
        dist.insert(
            "tarball".to_owned(),
            Value::from(artifact_url(
                public_url,
                entry.reference.ecosystem,
                &entry.id,
                &entry.reference.filename,
            )),
        );
    }
    record
}

/// `{public_url}/{ecosystem}/artifacts/{reference_id}/{filename}`.
///
/// Under the *ecosystem's own* root, not a root of its own: npm 12 defaults
/// `allow-remote` to `none` and exempts a registry's own tarballs only when the
/// tarball URL shares both the origin and the path prefix of the configured registry
/// (`/npm/` here). An artifact at `/artifacts/…` matched the origin, failed the
/// prefix, and was refused as a remote dependency. PyPI moves with it for symmetry.
///
/// `ecosystem` comes from the reference itself rather than from the caller's context,
/// so the advertised root and the stored row agree by construction — which is the
/// assertion `artifacts::serve_artifact` checks on the way back in.
///
/// Built segment by segment rather than by formatting, because the filename comes
/// from an upstream document and is untrusted text. `push` percent-encodes it, and
/// `public_url` is validated at startup to carry no path, query or fragment.
pub fn artifact_url(
    public_url: &Url,
    ecosystem: Ecosystem,
    id: &ReferenceId,
    filename: &str,
) -> String {
    let mut url = public_url.clone();
    if let Ok(mut path) = url.path_segments_mut() {
        path.pop_if_empty();
        path.push(ecosystem.as_tag());
        path.push("artifacts");
        path.push(&id.to_hex());
        path.push(filename);
    }
    url.to_string()
}

fn serialise(value: &Value) -> Vec<u8> {
    // Infallible for a value that came out of a parsed document: there is no map with
    // a non-string key and no non-finite number in it.
    serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOCUMENT: &str = r##"{
        "name": "widget",
        "readme": "# widget",
        "dist-tags": {"latest": "1.0.0"},
        "versions": {
            "1.0.0": {
                "name": "widget", "version": "1.0.0",
                "dependencies": {"left-pad": "^1.3.0"},
                "peerDependencies": {"react": ">=16.8.0 <19.0.0"},
                "engines": {"node": ">=18"},
                "_npmUser": {"name": "someone"},
                "dist": {
                    "tarball": "https://npm.invalid/widget/-/widget-1.0.0.tgz",
                    "shasum": "0123456789abcdef0123456789abcdef01234567"
                }
            },
            "0.9.0": {
                "name": "widget", "version": "0.9.0",
                "dist": {"tarball": "https://npm.invalid/widget/-/widget-0.9.0.tgz"}
            }
        },
        "time": {
            "created": "2026-01-01T00:00:00.000Z",
            "modified": "2026-01-03T00:00:00.000Z",
            "0.9.0": "2026-01-01T00:00:00.000Z",
            "1.0.0": "2026-01-02T00:00:00.000Z"
        }
    }"##;

    fn public_url() -> Url {
        Url::parse("https://packages.example.org").expect("a public URL")
    }

    fn rendered_full(keep: &[&str]) -> Value {
        let document = PackageDocument::parse(DOCUMENT.as_bytes()).expect("a valid document");
        let entries = document.entries(100).expect("the entries");
        let kept: Vec<&VersionEntry> = entries
            .iter()
            .filter(|entry| keep.contains(&entry.version()))
            .collect();
        let tags = Map::new();
        serde_json::from_slice(&full(&document, &kept, &tags, &public_url()))
            .expect("the rendered document parses")
    }

    #[test]
    fn an_excluded_version_leaves_both_the_version_map_and_the_time_map() {
        let rendered = rendered_full(&["1.0.0"]);
        assert!(rendered["versions"].get("0.9.0").is_none());
        assert!(rendered["time"].get("0.9.0").is_none());
        assert!(rendered["time"].get("1.0.0").is_some());
        assert!(
            rendered["time"].get("created").is_some() && rendered["time"].get("modified").is_some(),
            "created and modified are not versions and are not pruned"
        );
        assert_eq!(
            rendered["readme"],
            Value::from("# widget"),
            "a field filtering does not touch is carried through"
        );
    }

    #[test]
    fn only_the_tarball_is_edited() {
        let rendered = rendered_full(&["1.0.0"]);
        let version = &rendered["versions"]["1.0.0"];

        assert_eq!(version["dependencies"]["left-pad"], Value::from("^1.3.0"));
        assert_eq!(
            version["peerDependencies"]["react"],
            Value::from(">=16.8.0 <19.0.0")
        );
        assert_eq!(version["engines"]["node"], Value::from(">=18"));
        assert_eq!(
            version["dist"]["shasum"],
            Value::from("0123456789abcdef0123456789abcdef01234567"),
            "the upstream integrity field is preserved beside the rewritten URL"
        );

        let tarball = version["dist"]["tarball"].as_str().expect("a tarball URL");
        assert!(
            tarball.starts_with("https://packages.example.org/npm/artifacts/"),
            "the tarball points here, not upstream: {tarball}"
        );
        assert!(tarball.ends_with("/widget-1.0.0.tgz"));
    }

    #[test]
    fn the_abbreviated_form_drops_only_fields_outside_the_documented_set() {
        let document = PackageDocument::parse(DOCUMENT.as_bytes()).expect("a valid document");
        let entries = document.entries(100).expect("the entries");
        let kept: Vec<&VersionEntry> = entries.iter().collect();
        let rendered: Value =
            serde_json::from_slice(&abbreviated(&document, &kept, &Map::new(), &public_url()))
                .expect("the abbreviated document parses");

        let version = &rendered["versions"]["1.0.0"];
        assert_eq!(version["dependencies"]["left-pad"], Value::from("^1.3.0"));
        assert!(version.get("_npmUser").is_none());
        assert!(rendered.get("readme").is_none());
        assert_eq!(
            rendered["modified"],
            Value::from("2026-01-03T00:00:00.000Z")
        );
    }

    /// The filename is upstream's text. It must not be able to add a path segment,
    /// a query, or an authority to the URL this instance advertises.
    #[test]
    fn an_untrusted_filename_cannot_escape_the_artifact_path() {
        let id = ReferenceId::parse_hex(&"ab".repeat(32)).expect("a reference id");
        for filename in [
            "../../etc/passwd",
            "a/b",
            "x?y=1",
            "x#y",
            "//evil.invalid/x",
        ] {
            let url = artifact_url(&public_url(), Ecosystem::Npm, &id, filename);
            let parsed = Url::parse(&url).expect("the built URL parses");
            assert_eq!(parsed.host_str(), Some("packages.example.org"));
            assert!(parsed.query().is_none() && parsed.fragment().is_none());
            assert_eq!(
                parsed.path_segments().map(Iterator::count),
                Some(4),
                "the ecosystem root, `artifacts`, the id, and exactly one filename \
                 segment: {url}"
            );
        }
    }
}
