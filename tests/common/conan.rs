//! Row 23 fixtures shared by tests/conan_*.rs: a fake Conan 2 remote's documents (the shapes ConanCenter and Artifactory write:
//! revision lists newest first with `+0000` times, file lists with empty values, package searches), and the files of a recipe
//! and of a package.
#![allow(dead_code)]

use super::{FakeAnswer, FakeRegistry};
use std::sync::Arc;

/// The origin the fake remote sits on (an Artifactory repository has a path, ConanCenter has none).
pub const REMOTE: &str = "https://conan.invalid/artifactory/api/conan/repo";
pub const PUBLISH: &str = "https://conan-upload.invalid/up";
pub const ROOT: &str = "/artifactory/api/conan/repo";

/// The path a layout path has on the fake remote.
pub fn at(path: &str) -> String {
    format!("{ROOT}/{path}")
}

/// `2025-01-01T00:00:00Z` as a Conan server writes a time.
pub fn conan_time(rfc3339: &str) -> String {
    let at: jiff::Timestamp = rfc3339.parse().expect("a timestamp");
    at.strftime("%Y-%m-%dT%H:%M:%S.000+0000").to_string()
}

/// `v2/conans/{name}/{version}/_/_` (no user, no channel).
pub fn base(name: &str, version: &str) -> String {
    format!("v2/conans/{name}/{version}/_/_")
}

/// A revision list as the remote writes it; `time` is an RFC 3339 text, `None` leaves it out. `head` is `reference` or
/// `packageReference`.
pub fn revisions_doc(head: (&str, &str), revisions: &[(&str, Option<&str>)]) -> String {
    let list: Vec<serde_json::Value> = revisions
        .iter()
        .map(|(revision, time)| match time {
            Some(time) => serde_json::json!({ "revision": revision, "time": conan_time(time) }),
            None => serde_json::json!({ "revision": revision }),
        })
        .collect();
    serde_json::to_string_pretty(&serde_json::json!({ head.0: head.1, "revisions": list })).unwrap()
}

pub fn latest_doc(revision: &str, time: &str) -> String {
    serde_json::to_string_pretty(
        &serde_json::json!({ "revision": revision, "time": conan_time(time) }),
    )
    .unwrap()
}

pub fn files_doc(names: &[&str]) -> String {
    let files: serde_json::Map<String, serde_json::Value> = names
        .iter()
        .map(|name| ((*name).to_owned(), serde_json::json!({})))
        .collect();
    serde_json::to_string_pretty(&serde_json::json!({ "files": files })).unwrap()
}

pub fn conanfile(name: &str, version: &str) -> String {
    format!(
        "from conan import ConanFile\n\n\nclass {}Conan(ConanFile):\n    name = \"{name}\"\n    version = \"{version}\"\n    settings = \"os\", \"arch\", \"compiler\", \"build_type\"\n",
        name.replace(['-', '.', '+'], "_")
    )
}

pub fn manifest(rev: &str) -> String {
    format!("1700000000\nconanfile.py: md5-of-{rev}\n")
}

pub fn tgz(label: &str) -> Vec<u8> {
    let mut bytes = vec![0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0, 3];
    bytes.extend_from_slice(label.as_bytes());
    bytes
}

/// A recipe `name/version@_/_` with these revisions (newest first, as the remote lists them): the list, `latest`, and per
/// revision its file list and four files.
pub fn serve_recipe(
    registry: &Arc<FakeRegistry>,
    name: &str,
    version: &str,
    revisions: &[(&str, &str)],
) {
    let base = base(name, version);
    let listed: Vec<(&str, Option<&str>)> = revisions
        .iter()
        .map(|(rev, time)| (*rev, Some(*time)))
        .collect();
    registry.answer(
        &at(&format!("{base}/revisions")),
        FakeAnswer::Body(revisions_doc(
            ("reference", &format!("{name}/{version}@_/_")),
            &listed,
        )),
    );
    if let Some((rev, time)) = revisions.first() {
        registry.answer(
            &at(&format!("{base}/latest")),
            FakeAnswer::Body(latest_doc(rev, time)),
        );
    }
    for (rev, _) in revisions {
        serve_recipe_files(registry, name, version, rev);
    }
}

pub fn serve_recipe_files(registry: &Arc<FakeRegistry>, name: &str, version: &str, rev: &str) {
    let dir = format!("{}/revisions/{rev}", base(name, version));
    registry.answer(
        &at(&format!("{dir}/files")),
        FakeAnswer::Body(files_doc(&[
            "conanfile.py",
            "conanmanifest.txt",
            "conan_export.tgz",
            "conan_sources.tgz",
        ])),
    );
    registry.answer(
        &at(&format!("{dir}/files/conanfile.py")),
        FakeAnswer::Body(conanfile(name, version)),
    );
    registry.answer(
        &at(&format!("{dir}/files/conanmanifest.txt")),
        FakeAnswer::Body(manifest(rev)),
    );
    registry.answer(
        &at(&format!("{dir}/files/conan_export.tgz")),
        FakeAnswer::Bytes(tgz(&format!("export {name} {version} {rev}"))),
    );
    registry.answer(
        &at(&format!("{dir}/files/conan_sources.tgz")),
        FakeAnswer::Bytes(tgz(&format!("sources {name} {version} {rev}"))),
    );
}

/// One package id of a recipe revision with these package revisions (newest first).
pub fn serve_package(
    registry: &Arc<FakeRegistry>,
    name: &str,
    version: &str,
    rrev: &str,
    pkgid: &str,
    revisions: &[(&str, &str)],
) {
    let dir = format!("{}/revisions/{rrev}/packages/{pkgid}", base(name, version));
    let listed: Vec<(&str, Option<&str>)> = revisions
        .iter()
        .map(|(rev, time)| (*rev, Some(*time)))
        .collect();
    registry.answer(
        &at(&format!("{dir}/revisions")),
        FakeAnswer::Body(revisions_doc(
            (
                "packageReference",
                &format!("{name}/{version}@_/_#{rrev}:{pkgid}"),
            ),
            &listed,
        )),
    );
    if let Some((rev, time)) = revisions.first() {
        registry.answer(
            &at(&format!("{dir}/latest")),
            FakeAnswer::Body(latest_doc(rev, time)),
        );
    }
    for (prev, _) in revisions {
        let pdir = format!("{dir}/revisions/{prev}");
        registry.answer(
            &at(&format!("{pdir}/files")),
            FakeAnswer::Body(files_doc(&[
                "conaninfo.txt",
                "conanmanifest.txt",
                "conan_package.tgz",
            ])),
        );
        registry.answer(
            &at(&format!("{pdir}/files/conaninfo.txt")),
            FakeAnswer::Body(format!(
                "[settings]\n    os=Linux\n[recipe_hash]\n    {rrev}\n"
            )),
        );
        registry.answer(
            &at(&format!("{pdir}/files/conanmanifest.txt")),
            FakeAnswer::Body(manifest(prev)),
        );
        registry.answer(
            &at(&format!("{pdir}/files/conan_package.tgz")),
            FakeAnswer::Bytes(tgz(&format!("package {name} {version} {pkgid} {prev}"))),
        );
    }
}

/// `v2/conans/{rrev}/search` of a recipe revision: package ids with the info Conan prints.
pub fn package_search_doc(ids: &[&str]) -> String {
    let map: serde_json::Map<String, serde_json::Value> = ids
        .iter()
        .map(|id| ((*id).to_owned(), serde_json::json!({ "settings": { "os": "Linux", "arch": "x86_64" }, "options": { "shared": "False" }, "requires": [] })))
        .collect();
    serde_json::to_string_pretty(&serde_json::Value::Object(map)).unwrap()
}

pub fn search_doc(references: &[&str]) -> String {
    serde_json::to_string_pretty(&serde_json::json!({ "results": references })).unwrap()
}

/// Loads a directory a real `conan upload` left behind (tests/e2e/fixtures/conan_recorder.py: `name/version/user/channel/revisions/{rrev}/...`
/// and `.../packages/{pkgid}/revisions/{prev}/...`) into the fake remote, naming each revision's time with `time_of(name/version, pkgid)`
/// (`None` for a recipe revision). Returns the references it served.
pub fn serve_store(
    registry: &Arc<FakeRegistry>,
    store: &std::path::Path,
    time_of: &dyn Fn(&str, Option<&str>) -> String,
) -> Vec<String> {
    let names = |dir: &std::path::Path| -> Vec<String> {
        let mut found: Vec<String> = std::fs::read_dir(dir)
            .map(|entries| {
                entries
                    .filter_map(|e| e.ok())
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        found.sort();
        found
    };
    let mut references = Vec::new();
    for name in names(store) {
        for version in names(&store.join(&name)) {
            for user in names(&store.join(&name).join(&version)) {
                for channel in names(&store.join(&name).join(&version).join(&user)) {
                    let base = format!("v2/conans/{name}/{version}/{user}/{channel}");
                    let dir = store
                        .join(&name)
                        .join(&version)
                        .join(&user)
                        .join(&channel)
                        .join("revisions");
                    let rrevs = names(&dir);
                    let reference = format!("{name}/{version}@{user}/{channel}");
                    references.push(reference.clone());
                    let key = format!("{name}/{version}");
                    let time = time_of(&key, None);
                    let listed: Vec<(&str, Option<&str>)> = rrevs
                        .iter()
                        .map(|rev| (rev.as_str(), Some(time.as_str())))
                        .collect();
                    registry.answer(
                        &at(&format!("{base}/revisions")),
                        FakeAnswer::Body(revisions_doc(("reference", &reference), &listed)),
                    );
                    if let Some(rev) = rrevs.first() {
                        registry.answer(
                            &at(&format!("{base}/latest")),
                            FakeAnswer::Body(latest_doc(rev, &time)),
                        );
                    }
                    for rrev in &rrevs {
                        let rdir = dir.join(rrev);
                        serve_files_of(registry, &format!("{base}/revisions/{rrev}"), &rdir);
                        let pkgids = names(&rdir.join("packages"));
                        registry.answer(
                            &at(&format!("{base}/revisions/{rrev}/search")),
                            FakeAnswer::Body(package_search_doc(
                                &pkgids.iter().map(String::as_str).collect::<Vec<_>>(),
                            )),
                        );
                        for pkgid in &pkgids {
                            let pdir = rdir.join("packages").join(pkgid).join("revisions");
                            let prevs = names(&pdir);
                            let ptime = time_of(&key, Some(pkgid));
                            let plisted: Vec<(&str, Option<&str>)> = prevs
                                .iter()
                                .map(|prev| (prev.as_str(), Some(ptime.as_str())))
                                .collect();
                            let pbase = format!("{base}/revisions/{rrev}/packages/{pkgid}");
                            registry.answer(
                                &at(&format!("{pbase}/revisions")),
                                FakeAnswer::Body(revisions_doc(
                                    ("packageReference", &format!("{reference}#{rrev}:{pkgid}")),
                                    &plisted,
                                )),
                            );
                            if let Some(prev) = prevs.first() {
                                registry.answer(
                                    &at(&format!("{pbase}/latest")),
                                    FakeAnswer::Body(latest_doc(prev, &ptime)),
                                );
                            }
                            for prev in &prevs {
                                serve_files_of(
                                    registry,
                                    &format!("{pbase}/revisions/{prev}"),
                                    &pdir.join(prev),
                                );
                            }
                        }
                    }
                }
            }
        }
    }
    registry.answer(
        &at("v2/conans/search"),
        FakeAnswer::Body(search_doc(
            &references.iter().map(String::as_str).collect::<Vec<_>>(),
        )),
    );
    references
}

fn serve_files_of(registry: &Arc<FakeRegistry>, base: &str, dir: &std::path::Path) {
    let mut files: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    files.sort();
    registry.answer(
        &at(&format!("{base}/files")),
        FakeAnswer::Body(files_doc(
            &files.iter().map(String::as_str).collect::<Vec<_>>(),
        )),
    );
    for file in &files {
        registry.answer(
            &at(&format!("{base}/files/{file}")),
            FakeAnswer::Bytes(std::fs::read(dir.join(file)).unwrap()),
        );
    }
}
