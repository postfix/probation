//! `maven-metadata.xml` and `archetype-catalog.xml`: what the firewall reads from them and how a filtered copy is cut.
//!
//! Reading is one pass over the strict scanner of `xml.rs`; the result is byte spans. A filtered document is the
//! original text with the spans of the entries the policy withholds cut out and the few values the policy changes
//! (`latest`, `release`, the snapshot pointer) replaced: every element, comment and attribute this firewall does not
//! understand is passed on exactly as the repository wrote it.

use crate::maven::xml::{self, Event, XmlError, decode};

/// A leaf element's text and the byte span of the text between its tags.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Text {
    pub value: String,
    pub inner: (usize, usize),
}

/// One repeated entry (`<version>`, `<snapshotVersion>`, `<plugin>`, `<archetype>`): its value and the span of the whole
/// element (start of `<tag>` to the end of `</tag>`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub value: String,
    pub span: (usize, usize),
    /// `artifactId` of a plugin or an archetype, `groupId`, `version` and `classifier`/`extension` of the others.
    pub fields: Vec<(String, String)>,
}

impl Entry {
    pub fn field(&self, name: &str) -> Option<&str> {
        self.fields.iter().find(|(key, _)| key == name).map(|(_, value)| value.as_str())
    }
}

#[derive(Debug, Default)]
pub struct Meta {
    pub root: String,
    pub group_id: Option<Text>,
    pub artifact_id: Option<Text>,
    pub version: Option<Text>,
    pub latest: Option<Text>,
    pub release: Option<Text>,
    pub last_updated: Option<Text>,
    pub versions: Vec<Entry>,
    /// The `<versions>` element is there (an artifact-level document, even with no version in it).
    pub has_versions: bool,
    pub snapshot_timestamp: Option<Text>,
    pub snapshot_build: Option<Text>,
    /// The span of `<snapshot>...</snapshot>`.
    pub snapshot_span: Option<(usize, usize)>,
    pub snapshot_versions: Vec<Entry>,
    /// The span of `<snapshotVersions>...</snapshotVersions>`.
    pub snapshot_versions_span: Option<(usize, usize)>,
    pub plugins: Vec<Entry>,
    pub has_plugins: bool,
    pub archetypes: Vec<Entry>,
    /// The spans of every `<repository>` an archetype names: another repository's URL, which no client of this firewall may be
    /// handed (the entry is listed, the repository is not).
    pub archetype_repositories: Vec<(usize, usize)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetaError {
    Xml(XmlError),
    /// The root element is not the one this document type has.
    Root,
    /// More entries than the bound.
    TooMany,
    /// A document no strict reader would read as one thing: a version, `latest`, `release` or a build with a child element,
    /// a singleton (`latest`, `release`, `lastUpdated`, `snapshot`, `versions`, `plugins`...) repeated, `plugins` beside
    /// `versions`, or a prefixed element name. Refused (never filtered and passed on) because the firewall would edit one reading
    /// and the client use another.
    Malformed,
}

impl From<XmlError> for MetaError {
    fn from(error: XmlError) -> Self {
        MetaError::Xml(error)
    }
}

struct Frame<'a> {
    name: &'a str,
    start: usize,
    inner_start: usize,
    children: bool,
    /// Leaf fields of an entry under construction.
    fields: Vec<(String, String)>,
}

/// Reads `doc`. `max_entries` bounds every repeated list (a document with more is `TooMany`).
pub fn read(doc: &[u8], max_entries: usize) -> Result<Meta, MetaError> {
    let text = std::str::from_utf8(doc).map_err(|_| XmlError::NotUtf8)?;
    let mut meta = Meta::default();
    let mut stack: Vec<Frame<'_>> = Vec::new();
    let mut too_many = false;
    let mut root_bad = false;
    let mut bad = false;
    let single = |previous: Option<Text>, new: Option<Text>, bad: &mut bool| {
        if previous.is_some() || new.is_none() {
            *bad = true;
        }
        new.or(previous)
    };
    xml::scan(doc, |event| match event {
        Event::Start { name, start, end, depth, .. } => {
            // A prefixed name is the same element to a namespace-aware reader and a different one to this: refused.
            bad |= name.contains(':');
            if let Some(parent) = stack.last_mut() {
                parent.children = true;
            }
            if depth == 1 {
                meta.root = name.to_owned();
                root_bad = !matches!(name, "metadata" | "archetype-catalog");
            }
            stack.push(Frame { name, start, inner_start: end, children: false, fields: Vec::new() });
        }
        Event::Text { .. } => {}
        Event::End { name, start, end, .. } => {
            let Some(frame) = stack.pop() else { return };
            debug_assert_eq!(frame.name, name);
            let path: Vec<&str> = stack.iter().map(|f| f.name).chain(std::iter::once(name)).collect();
            let leaf = || {
                (!frame.children).then(|| {
                    let inner = (frame.inner_start, start);
                    Text { value: decode(&text[inner.0..inner.1]).trim().to_owned(), inner }
                })
            };
            let span = (frame.start, end);
            match path.as_slice() {
                ["metadata", "groupId"] => meta.group_id = single(meta.group_id.take(), leaf(), &mut bad),
                ["metadata", "artifactId"] => meta.artifact_id = single(meta.artifact_id.take(), leaf(), &mut bad),
                ["metadata", "version"] => meta.version = single(meta.version.take(), leaf(), &mut bad),
                ["metadata", "versioning", "latest"] => meta.latest = single(meta.latest.take(), leaf(), &mut bad),
                ["metadata", "versioning", "release"] => meta.release = single(meta.release.take(), leaf(), &mut bad),
                ["metadata", "versioning", "lastUpdated"] => meta.last_updated = single(meta.last_updated.take(), leaf(), &mut bad),
                ["metadata", "versioning", "versions"] => {
                    bad |= meta.has_versions;
                    meta.has_versions = true;
                }
                ["metadata", "versioning", "versions", "version"] => {
                    match leaf() {
                        Some(_) if meta.versions.len() >= max_entries => too_many = true,
                        Some(item) => meta.versions.push(Entry { value: item.value, span, fields: Vec::new() }),
                        None => bad = true,
                    }
                }
                ["metadata", "versioning", "snapshot", "timestamp"] => meta.snapshot_timestamp = single(meta.snapshot_timestamp.take(), leaf(), &mut bad),
                ["metadata", "versioning", "snapshot", "buildNumber"] => meta.snapshot_build = single(meta.snapshot_build.take(), leaf(), &mut bad),
                ["metadata", "versioning", "snapshot"] => {
                    bad |= meta.snapshot_span.is_some();
                    meta.snapshot_span = Some(span);
                }
                ["metadata", "versioning", "snapshotVersions"] => {
                    bad |= meta.snapshot_versions_span.is_some();
                    meta.snapshot_versions_span = Some(span);
                }
                ["metadata", "versioning", "snapshotVersions", "snapshotVersion", field] => {
                    match (leaf(), stack.last_mut()) {
                        (Some(item), Some(parent)) => parent.fields.push(((*field).to_owned(), item.value)),
                        // A field the firewall reads must be text; any other (a description with markup) is passed on untouched.
                        (None, _) if matches!(*field, "groupId" | "artifactId" | "version" | "value" | "extension" | "classifier" | "name" | "prefix") => bad = true,
                        _ => {}
                    }
                }
                ["metadata", "versioning", "snapshotVersions", "snapshotVersion"] => {
                    if meta.snapshot_versions.len() >= max_entries {
                        too_many = true;
                    } else {
                        let value = frame.fields.iter().find(|(key, _)| key == "value").map(|(_, v)| v.clone()).unwrap_or_default();
                        meta.snapshot_versions.push(Entry { value, span, fields: frame.fields });
                    }
                }
                ["metadata", "plugins"] => {
                    bad |= meta.has_plugins;
                    meta.has_plugins = true;
                }
                ["metadata", "plugins", "plugin", field] => {
                    match (leaf(), stack.last_mut()) {
                        (Some(item), Some(parent)) => parent.fields.push(((*field).to_owned(), item.value)),
                        // A field the firewall reads must be text; any other (a description with markup) is passed on untouched.
                        (None, _) if matches!(*field, "groupId" | "artifactId" | "version" | "value" | "extension" | "classifier" | "name" | "prefix") => bad = true,
                        _ => {}
                    }
                }
                ["metadata", "plugins", "plugin"] => {
                    if meta.plugins.len() >= max_entries {
                        too_many = true;
                    } else {
                        let value = frame.fields.iter().find(|(key, _)| key == "artifactId").map(|(_, v)| v.clone()).unwrap_or_default();
                        meta.plugins.push(Entry { value, span, fields: frame.fields });
                    }
                }
                ["archetype-catalog", "archetypes", "archetype", "repository"] => {
                    if meta.archetype_repositories.len() >= max_entries {
                        too_many = true;
                    } else {
                        meta.archetype_repositories.push(span);
                    }
                }
                ["archetype-catalog", "archetypes", "archetype", field] => {
                    match (leaf(), stack.last_mut()) {
                        (Some(item), Some(parent)) => parent.fields.push(((*field).to_owned(), item.value)),
                        // A field the firewall reads must be text; any other (a description with markup) is passed on untouched.
                        (None, _) if matches!(*field, "groupId" | "artifactId" | "version" | "value" | "extension" | "classifier" | "name" | "prefix") => bad = true,
                        _ => {}
                    }
                }
                ["archetype-catalog", "archetypes", "archetype"] => {
                    if meta.archetypes.len() >= max_entries {
                        too_many = true;
                    } else {
                        let value = frame.fields.iter().find(|(key, _)| key == "artifactId").map(|(_, v)| v.clone()).unwrap_or_default();
                        meta.archetypes.push(Entry { value, span, fields: frame.fields });
                    }
                }
                _ => {}
            }
        }
    })?;
    if root_bad {
        return Err(MetaError::Root);
    }
    let versioned = meta.has_versions || !meta.versions.is_empty() || meta.snapshot_span.is_some() || !meta.snapshot_versions.is_empty();
    if bad || (meta.has_plugins && versioned) {
        return Err(MetaError::Malformed);
    }
    if too_many {
        return Err(MetaError::TooMany);
    }
    Ok(meta)
}

/// One replacement of a byte range.
pub struct Edit {
    pub start: usize,
    pub end: usize,
    pub with: String,
}

/// Removal of a whole element: when it stands alone on its line the whole line goes.
pub fn cut(doc: &[u8], span: (usize, usize)) -> Edit {
    let (mut start, mut end) = span;
    let mut before = start;
    while before > 0 && matches!(doc[before - 1], b' ' | b'\t') {
        before -= 1;
    }
    let line_start = before == 0 || doc[before - 1] == b'\n';
    let mut after = end;
    while after < doc.len() && matches!(doc[after], b' ' | b'\t') {
        after += 1;
    }
    let line_end = after == doc.len() || matches!(doc[after], b'\n' | b'\r');
    if line_start && line_end {
        start = before;
        end = after;
        if doc.get(end) == Some(&b'\r') {
            end += 1;
        }
        if doc.get(end) == Some(&b'\n') {
            end += 1;
        }
    }
    Edit { start, end, with: String::new() }
}

/// The text between two tags replaced (the value is XML-escaped here).
pub fn replace_text(text: &Text, value: &str) -> Edit {
    Edit { start: text.inner.0, end: text.inner.1, with: escape(value) }
}

pub fn escape(value: &str) -> String {
    value.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// Applies `edits` (any order, never overlapping) to `doc`.
pub fn apply(doc: &[u8], mut edits: Vec<Edit>) -> Vec<u8> {
    edits.sort_by_key(|edit| edit.start);
    let mut out = Vec::with_capacity(doc.len());
    let mut at = 0;
    for edit in edits {
        debug_assert!(edit.start >= at, "overlapping edits");
        if edit.start < at {
            continue;
        }
        out.extend_from_slice(&doc[at..edit.start]);
        out.extend_from_slice(edit.with.as_bytes());
        at = edit.end;
    }
    out.extend_from_slice(&doc[at..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOC: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<metadata>\n  <groupId>g</groupId>\n  <artifactId>a</artifactId>\n  <versioning>\n    <latest>3</latest>\n    <release>3</release>\n    <versions>\n      <version>1</version>\n      <version>2</version>\n      <version>3</version>\n    </versions>\n    <lastUpdated>20200101000000</lastUpdated>\n  </versioning>\n</metadata>\n";

    #[test]
    fn an_artifact_document_is_read_and_a_version_is_cut_with_its_line() {
        let meta = read(DOC.as_bytes(), 100).unwrap();
        assert_eq!(meta.group_id.as_ref().unwrap().value, "g");
        assert_eq!(meta.versions.iter().map(|v| v.value.as_str()).collect::<Vec<_>>(), ["1", "2", "3"]);
        assert!(meta.has_versions);
        let cut2 = cut(DOC.as_bytes(), meta.versions[1].span);
        let release = replace_text(meta.release.as_ref().unwrap(), "2");
        let latest = replace_text(meta.latest.as_ref().unwrap(), "2");
        let cut3 = cut(DOC.as_bytes(), meta.versions[2].span);
        let out = String::from_utf8(apply(DOC.as_bytes(), vec![cut3, release, latest])).unwrap();
        assert!(out.contains("<latest>2</latest>") && out.contains("<release>2</release>"));
        assert!(!out.contains("<version>3</version>") && out.contains("<version>2</version>"));
        assert!(!out.contains("\n\n"), "the cut left no blank line: {out}");
        assert!(read(out.as_bytes(), 100).is_ok(), "the filtered document is still the same strict format");
        let _ = cut2;
    }

    #[test]
    fn plugins_snapshots_and_catalogs_are_read() {
        let plugins = "<metadata><plugins><plugin><name>Compiler</name><prefix>compiler</prefix><artifactId>maven-compiler-plugin</artifactId></plugin></plugins></metadata>";
        let meta = read(plugins.as_bytes(), 10).unwrap();
        assert!(meta.has_plugins);
        assert_eq!(meta.plugins[0].value, "maven-compiler-plugin");
        let snapshot = "<metadata><groupId>g</groupId><artifactId>a</artifactId><version>1.0-SNAPSHOT</version><versioning><snapshot><timestamp>20200101.120000</timestamp><buildNumber>7</buildNumber></snapshot><snapshotVersions><snapshotVersion><extension>jar</extension><value>1.0-20200101.120000-7</value><updated>20200101120000</updated></snapshotVersion></snapshotVersions></versioning></metadata>";
        let meta = read(snapshot.as_bytes(), 10).unwrap();
        assert_eq!(meta.snapshot_timestamp.unwrap().value, "20200101.120000");
        assert_eq!(meta.snapshot_versions[0].value, "1.0-20200101.120000-7");
        assert_eq!(meta.snapshot_versions[0].field("extension"), Some("jar"));
        let catalog = "<archetype-catalog><archetypes><archetype><groupId>g</groupId><artifactId>a</artifactId><version>1</version><description>d</description></archetype></archetypes></archetype-catalog>";
        let meta = read(catalog.as_bytes(), 10).unwrap();
        assert_eq!(meta.archetypes[0].field("groupId"), Some("g"));
    }

    #[test]
    fn documents_no_strict_reader_would_read_as_one_thing_are_refused() {
        let doc = |inner: &str| format!("<metadata><versioning>{inner}</versioning></metadata>");
        for (what, text) in [
            ("a child element in a version", doc("<versions><version>2.0<x/></version></versions>")),
            ("a child element in latest", doc("<latest>2.0<x/></latest>")),
            ("a repeated latest", doc("<latest>1</latest><latest>2</latest>")),
            ("a repeated release", doc("<release>1</release><release>2</release>")),
            ("a repeated lastUpdated", doc("<lastUpdated>1</lastUpdated><lastUpdated>2</lastUpdated>")),
            ("two versions elements", doc("<versions/><versions/>")),
            ("a prefixed element", doc("<m:versions xmlns:m=\"x\"><version>1</version></m:versions>")),
            ("plugins beside versions", "<metadata><plugins/><versioning><versions><version>1</version></versions></versioning></metadata>".to_owned()),
            ("a snapshot build with markup", doc("<snapshotVersions><snapshotVersion><value>1<b/></value></snapshotVersion></snapshotVersions>")),
        ] {
            assert_eq!(read(text.as_bytes(), 10).err(), Some(MetaError::Malformed), "{what}");
        }
        let catalog = "<archetype-catalog><archetypes><archetype><groupId>g</groupId><artifactId>a</artifactId><version>1</version><repository>x</repository><repository>y</repository></archetype></archetypes></archetype-catalog>";
        assert_eq!(read(catalog.as_bytes(), 1).err(), Some(MetaError::TooMany), "repositories are bounded like archetypes");
        assert!(read(catalog.as_bytes(), 2).is_ok());
        assert!(read(doc("<latest>1</latest><release>1</release><versions><version>1</version></versions>").as_bytes(), 10).is_ok());
    }

    #[test]
    fn the_wrong_root_an_entity_and_too_many_entries_are_refused() {
        assert_eq!(read(b"<html/>", 10).err(), Some(MetaError::Root));
        assert!(matches!(read(b"<!DOCTYPE metadata [<!ENTITY a 'b'>]><metadata/>", 10), Err(MetaError::Xml(XmlError::Declaration))));
        let many = format!("<metadata><versioning><versions>{}</versions></versioning></metadata>", "<version>1</version>".repeat(11));
        assert_eq!(read(many.as_bytes(), 10).err(), Some(MetaError::TooMany));
    }
}
