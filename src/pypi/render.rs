//! Simple API HTML and JSON, built from one already-filtered file list.
//!
//! Both forms are rendered from the same `ListedFile` slice, which is what makes
//! "HTML and JSON list the same files" a property of the shape of this module rather
//! than of two code paths agreeing. SPEC §7's omissions are honoured here and only
//! here: no `data-dist-info-metadata`, no `data-core-metadata`, no provenance link,
//! and no upstream auxiliary URL of any kind survives into the response.
//!
//! **Everything upstream supplies is untrusted text** (SPEC §11). A filename, a
//! `requires-python` marker and a yank reason are all attacker-controlled by anyone
//! who can publish a public package, so every one of them is escaped on the way into
//! the HTML — text content and attribute values by different rules, because they are
//! different contexts.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

/// PEP 629 aliases `text/html` to the v1 HTML serialisation, and every client that
/// understands the Simple API accepts it.
pub const HTML_CONTENT_TYPE: &str = "text/html; charset=utf-8";
pub const JSON_CONTENT_TYPE: &str = "application/vnd.pypi.simple.v1+json";

/// The repository version PEP 629 makes the HTML form declare.
const HTML_REPOSITORY_VERSION: &str = "1.0";

/// PEP 700: `versions` is required from 1.1, which is what lets a client see the
/// recomputed version list SPEC §7 asks for.
const JSON_API_VERSION: &str = "1.1";

/// One file that survived filtering, with its URL already rewritten through this
/// instance.
#[derive(Clone, Debug)]
pub struct ListedFile {
    pub filename: String,
    pub url: String,
    /// Upstream's hashes, kept exactly as advertised (SPEC §7: "preserve file hash
    /// information"). Ordered so two renderings of one file are byte-identical.
    pub hashes: BTreeMap<String, String>,
    pub requires_python: Option<String>,
    /// `None` when the file is not yanked; `Some(reason)` when it is, with an empty
    /// reason meaning "yanked, no reason given" (PEP 592).
    pub yanked: Option<String>,
    pub size: Option<u64>,
}

impl ListedFile {
    /// PEP 503's optional `#<hashname>=<hashvalue>` fragment, which is how a client
    /// in hash-checking mode learns the digest from the HTML form.
    fn href(&self) -> String {
        match self.hashes.get("sha256") {
            Some(digest) => format!("{}#sha256={digest}", self.url),
            None => self.url.clone(),
        }
    }
}

/// `GET /pypi/simple/{project}/`, HTML.
pub fn project_html(project: &str, files: &[ListedFile]) -> Vec<u8> {
    let mut out = String::with_capacity(512 + files.len() * 160);
    out.push_str("<!DOCTYPE html>\n<html>\n  <head>\n");
    out.push_str(&format!(
        "    <meta name=\"pypi:repository-version\" content=\"{HTML_REPOSITORY_VERSION}\">\n"
    ));
    out.push_str(&format!(
        "    <title>Links for {}</title>\n  </head>\n  <body>\n",
        escape_text(project)
    ));
    out.push_str(&format!(
        "    <h1>Links for {}</h1>\n",
        escape_text(project)
    ));

    for file in files {
        out.push_str("    <a href=\"");
        out.push_str(&escape_attribute(&file.href()));
        out.push('"');
        if let Some(requires_python) = &file.requires_python {
            out.push_str(" data-requires-python=\"");
            out.push_str(&escape_attribute(requires_python));
            out.push('"');
        }
        if let Some(reason) = &file.yanked {
            out.push_str(" data-yanked=\"");
            out.push_str(&escape_attribute(reason));
            out.push('"');
        }
        out.push('>');
        out.push_str(&escape_text(&file.filename));
        out.push_str("</a><br>\n");
    }

    out.push_str("  </body>\n</html>\n");
    out.into_bytes()
}

/// `GET /pypi/simple/{project}/`, JSON (PEP 691 with PEP 700's `versions`).
pub fn project_json(project: &str, files: &[ListedFile], versions: &[String]) -> Vec<u8> {
    let mut out = Map::new();
    out.insert("meta".to_owned(), meta());
    out.insert("name".to_owned(), Value::from(project));
    out.insert(
        "versions".to_owned(),
        Value::from(
            versions
                .iter()
                .map(|version| Value::from(version.as_str()))
                .collect::<Vec<_>>(),
        ),
    );
    out.insert(
        "files".to_owned(),
        Value::from(files.iter().map(json_file).collect::<Vec<_>>()),
    );
    serialise(&Value::Object(out))
}

/// `GET /pypi/simple/`, HTML. This instance's known projects, not a PyPI mirror.
pub fn index_html(projects: &[String]) -> Vec<u8> {
    let mut out = String::with_capacity(256 + projects.len() * 48);
    out.push_str("<!DOCTYPE html>\n<html>\n  <head>\n");
    out.push_str(&format!(
        "    <meta name=\"pypi:repository-version\" content=\"{HTML_REPOSITORY_VERSION}\">\n"
    ));
    out.push_str("    <title>Simple index</title>\n  </head>\n  <body>\n");
    for project in projects {
        out.push_str(&format!(
            "    <a href=\"{}/\">{}</a><br>\n",
            escape_attribute(project),
            escape_text(project)
        ));
    }
    out.push_str("  </body>\n</html>\n");
    out.into_bytes()
}

/// `GET /pypi/simple/`, JSON.
pub fn index_json(projects: &[String]) -> Vec<u8> {
    let mut out = Map::new();
    out.insert("meta".to_owned(), meta());
    out.insert(
        "projects".to_owned(),
        Value::from(
            projects
                .iter()
                .map(|name| {
                    let mut entry = Map::new();
                    entry.insert("name".to_owned(), Value::from(name.as_str()));
                    Value::Object(entry)
                })
                .collect::<Vec<_>>(),
        ),
    );
    serialise(&Value::Object(out))
}

fn meta() -> Value {
    let mut meta = Map::new();
    meta.insert("api-version".to_owned(), Value::from(JSON_API_VERSION));
    Value::Object(meta)
}

fn json_file(file: &ListedFile) -> Value {
    let mut out = Map::new();
    out.insert("filename".to_owned(), Value::from(file.filename.as_str()));
    out.insert("url".to_owned(), Value::from(file.url.as_str()));
    out.insert(
        "hashes".to_owned(),
        Value::Object(
            file.hashes
                .iter()
                .map(|(name, digest)| (name.clone(), Value::from(digest.as_str())))
                .collect(),
        ),
    );
    if let Some(requires_python) = &file.requires_python {
        out.insert(
            "requires-python".to_owned(),
            Value::from(requires_python.as_str()),
        );
    }
    // PEP 592: absent or `false` when not yanked; the reason when there is one, and
    // `true` when the file is yanked without one.
    out.insert(
        "yanked".to_owned(),
        match &file.yanked {
            None => Value::Bool(false),
            Some(reason) if reason.is_empty() => Value::Bool(true),
            Some(reason) => Value::from(reason.as_str()),
        },
    );
    if let Some(size) = file.size {
        out.insert("size".to_owned(), Value::from(size));
    }
    Value::Object(out)
}

/// HTML text content: the three characters that could start markup.
fn escape_text(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(c),
        }
    }
    out
}

/// A double-quoted attribute value. Both quote characters are escaped as well, so a
/// value can neither close its own attribute nor open a new one.
fn escape_attribute(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    out
}

fn serialise(value: &Value) -> Vec<u8> {
    // Infallible for a map with string keys and no non-finite number in it.
    serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hostile() -> ListedFile {
        ListedFile {
            filename: "bard-1.0-py3-none-any.whl\"><script>alert(1)</script>".to_owned(),
            url: "https://packages.example.org/artifacts/ab/x".to_owned(),
            hashes: BTreeMap::from([("sha256".to_owned(), "aa".repeat(32))]),
            requires_python: Some(">=3.7\"><script>".to_owned()),
            yanked: Some("bad & '<wrong>'".to_owned()),
            size: Some(12),
        }
    }

    /// SPEC §11: upstream filenames and attribute values are untrusted data. Neither
    /// may close an attribute or open an element.
    #[test]
    fn upstream_text_cannot_escape_its_html_context() {
        let html = String::from_utf8(project_html("bard", &[hostile()])).expect("utf-8");

        assert!(
            !html.contains("<script>"),
            "an upstream `<script>` reached the document unescaped: {html}"
        );
        assert!(
            html.contains("&lt;script&gt;"),
            "and it is present in escaped form: {html}"
        );
        assert!(
            html.contains("data-requires-python=\"&gt;=3.7&quot;&gt;&lt;script&gt;\""),
            "the attribute value neither closes its quote nor opens an element: {html}"
        );
        assert!(
            html.contains("data-yanked=\"bad &amp; &#x27;&lt;wrong&gt;&#x27;\""),
            "and an ampersand and both quote characters are escaped too: {html}"
        );
    }

    /// The HTML escaping must not leak into the JSON form, where quoting is serde's
    /// job and a doubly escaped filename would no longer match the artifact URL.
    #[test]
    fn the_json_form_carries_the_filename_verbatim() {
        let json: Value =
            serde_json::from_slice(&project_json("bard", &[hostile()], &["1.0".to_owned()]))
                .expect("the rendered listing parses");

        assert_eq!(
            json["files"][0]["filename"],
            Value::from(hostile().filename)
        );
        assert_eq!(json["files"][0]["yanked"], Value::from("bad & '<wrong>'"));
        assert_eq!(json["versions"][0], Value::from("1.0"));
        assert_eq!(json["meta"]["api-version"], Value::from("1.1"));
    }

    #[test]
    fn a_yank_without_a_reason_is_true_and_no_yank_is_false() {
        let mut yanked_without_reason = hostile();
        yanked_without_reason.yanked = Some(String::new());
        let mut not_yanked = hostile();
        not_yanked.yanked = None;

        let json: Value = serde_json::from_slice(&project_json(
            "bard",
            &[yanked_without_reason, not_yanked],
            &[],
        ))
        .expect("the rendered listing parses");

        assert_eq!(json["files"][0]["yanked"], Value::Bool(true));
        assert_eq!(json["files"][1]["yanked"], Value::Bool(false));
    }

    #[test]
    fn an_empty_listing_is_a_valid_document_in_both_forms() {
        let html = String::from_utf8(project_html("bard", &[])).expect("utf-8");
        assert!(html.contains("pypi:repository-version"));
        assert!(!html.contains("<a href"));

        let json: Value =
            serde_json::from_slice(&project_json("bard", &[], &[])).expect("valid JSON");
        assert_eq!(json["files"], Value::from(Vec::<Value>::new()));
        assert_eq!(json["name"], Value::from("bard"));
    }
}
