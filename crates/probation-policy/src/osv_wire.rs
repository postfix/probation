//! LS-F2 and LS-F5: the osv.dev-compatible wire the central OSV route speaks, shared by
//! the client that parses an answer and the server that parses a request and renders an
//! answer. Both sides detect duplicate JSON object keys (`serde_json` alone keeps the
//! last one) and ignore unknown fields only where the contract says so.

use std::collections::HashSet;

use serde::de::{Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};

/// The envelope version this build speaks.
pub const WIRE_VERSION: u64 = 1;
/// LS-F7: most vuln refs one result carries, id and modified lengths, per-result bytes.
pub const MAX_VULN_REFS: usize = 32;
pub const MAX_ID: usize = 128;
pub const MAX_MODIFIED: usize = 40;
pub const MAX_RESULT_BYTES: usize = 8192;
/// LS-F7: nesting a request may have.
pub const MAX_REQUEST_DEPTH: usize = 8;

/// A JSON value that remembers whether any object in it repeated a key.
enum Node {
    Null,
    Bool(bool),
    Num,
    Str(String),
    Arr(Vec<Node>),
    Obj {
        fields: Vec<(String, Node)>,
        dup: bool,
    },
}

impl<'de> Deserialize<'de> for Node {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Node, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Node;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("any JSON value")
            }
            fn visit_unit<E>(self) -> Result<Node, E> {
                Ok(Node::Null)
            }
            fn visit_bool<E>(self, v: bool) -> Result<Node, E> {
                Ok(Node::Bool(v))
            }
            fn visit_i64<E>(self, _: i64) -> Result<Node, E> {
                Ok(Node::Num)
            }
            fn visit_u64<E>(self, _: u64) -> Result<Node, E> {
                Ok(Node::Num)
            }
            fn visit_f64<E>(self, _: f64) -> Result<Node, E> {
                Ok(Node::Num)
            }
            fn visit_str<E>(self, v: &str) -> Result<Node, E> {
                Ok(Node::Str(v.to_owned()))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Node, A::Error> {
                let mut items = Vec::new();
                while let Some(item) = seq.next_element::<Node>()? {
                    items.push(item);
                }
                Ok(Node::Arr(items))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Node, A::Error> {
                let mut fields = Vec::new();
                let mut seen = HashSet::new();
                let mut dup = false;
                while let Some(key) = map.next_key::<String>()? {
                    dup |= !seen.insert(key.clone());
                    fields.push((key, map.next_value::<Node>()?));
                }
                Ok(Node::Obj { fields, dup })
            }
        }
        d.deserialize_any(V)
    }
}

impl Node {
    fn has_dup(&self) -> bool {
        match self {
            Node::Arr(items) => items.iter().any(Node::has_dup),
            Node::Obj { fields, dup } => *dup || fields.iter().any(|(_, v)| v.has_dup()),
            _ => false,
        }
    }

    fn depth(&self) -> usize {
        match self {
            Node::Arr(items) => 1 + items.iter().map(Node::depth).max().unwrap_or(0),
            Node::Obj { fields, .. } => {
                1 + fields.iter().map(|(_, v)| v.depth()).max().unwrap_or(0)
            }
            _ => 0,
        }
    }

    fn field(&self, name: &str) -> Option<&Node> {
        match self {
            Node::Obj { fields, .. } => fields.iter().find(|(k, _)| k == name).map(|(_, v)| v),
            _ => None,
        }
    }

    fn only_fields(&self, allowed: &[&str]) -> bool {
        match self {
            Node::Obj { fields, .. } => fields.iter().all(|(k, _)| allowed.contains(&k.as_str())),
            _ => false,
        }
    }

    fn string(&self) -> Option<&str> {
        match self {
            Node::Str(s) => Some(s),
            _ => None,
        }
    }
}

fn parse_node(body: &[u8]) -> Option<Node> {
    serde_json::from_slice::<Node>(body).ok()
}

/// What the endpoint concludes about one query.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OsvOutcome {
    Matched,
    NoMatch,
    Degraded,
}

/// Whole-batch failures: the answer is unreached and nothing is stored.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AnswerError {
    Oversize,
    NotJson,
    LengthMismatch,
    MissingEnvelopeMeta,
    UnsupportedVersion,
    DuplicateKey,
}

/// A parsed central answer: the envelope's `upstream_ok` and one outcome per query.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CentralAnswer {
    pub upstream_ok: bool,
    pub outcomes: Vec<OsvOutcome>,
}

/// The central server's answer for `queries` queries. See LS-F2.
pub fn parse_central_answer(body: &[u8], queries: usize) -> Result<Vec<OsvOutcome>, AnswerError> {
    parse_central(body, queries).map(|answer| answer.outcomes)
}

/// [`parse_central_answer`] that also reports `upstream_ok`, which decides whether OSV
/// counts as reached (T9-7).
pub fn parse_central(body: &[u8], queries: usize) -> Result<CentralAnswer, AnswerError> {
    if body.len() > queries * MAX_RESULT_BYTES + 4096 {
        return Err(AnswerError::Oversize);
    }
    let root = parse_node(body).ok_or(AnswerError::NotJson)?;
    if !matches!(root, Node::Obj { .. }) {
        return Err(AnswerError::NotJson);
    }
    if root.has_dup() {
        return Err(AnswerError::DuplicateKey);
    }
    let meta = root
        .field("probation_osv")
        .ok_or(AnswerError::MissingEnvelopeMeta)?;
    let version = match meta.field("v") {
        Some(Node::Num) => serde_json::from_slice::<serde_json::Value>(body)
            .ok()
            .and_then(|v| v["probation_osv"]["v"].as_u64()),
        _ => None,
    };
    let upstream_ok = match meta.field("upstream_ok") {
        Some(Node::Bool(ok)) => *ok,
        _ => return Err(AnswerError::MissingEnvelopeMeta),
    };
    match version {
        Some(WIRE_VERSION) => {}
        Some(_) => return Err(AnswerError::UnsupportedVersion),
        None => return Err(AnswerError::MissingEnvelopeMeta),
    }
    let Some(Node::Arr(results)) = root.field("results") else {
        return Err(AnswerError::LengthMismatch);
    };
    if results.len() != queries {
        return Err(AnswerError::LengthMismatch);
    }
    let outcomes = results
        .iter()
        .map(|result| {
            if !matches!(result, Node::Obj { .. }) {
                return OsvOutcome::Degraded;
            }
            let degraded = matches!(result.field("probation_degraded"), Some(Node::Bool(true)));
            let matched = match result.field("vulns") {
                Some(Node::Arr(vulns)) => vulns.iter().any(|v| {
                    v.field("id")
                        .and_then(Node::string)
                        .is_some_and(|id| id.starts_with("MAL-"))
                }),
                _ => false,
            };
            match (degraded, matched, upstream_ok) {
                (true, _, _) => OsvOutcome::Degraded,
                (false, true, _) => OsvOutcome::Matched,
                (false, false, true) => OsvOutcome::NoMatch,
                // A no-match inside an answer whose upstream failed is not confirmed.
                (false, false, false) => OsvOutcome::Degraded,
            }
        })
        .collect();
    Ok(CentralAnswer {
        upstream_ok,
        outcomes,
    })
}

/// One result to render.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum RenderedResult {
    NoMatch,
    /// `(id, modified)` refs.
    Matched(Vec<(String, Option<String>)>),
    Degraded,
}

/// The server's own minimal answer (it never relays upstream bytes).
pub fn render_answer(results: &[RenderedResult], upstream_ok: bool) -> Vec<u8> {
    let results: Vec<serde_json::Value> = results
        .iter()
        .map(|result| match result {
            RenderedResult::NoMatch => serde_json::json!({}),
            RenderedResult::Degraded => serde_json::json!({"probation_degraded": true}),
            RenderedResult::Matched(refs) => {
                let vulns: Vec<serde_json::Value> = refs
                    .iter()
                    .take(MAX_VULN_REFS)
                    .map(|(id, modified)| {
                        let id = truncate(id, MAX_ID);
                        match modified {
                            Some(m) => {
                                serde_json::json!({"id": id, "modified": truncate(m, MAX_MODIFIED)})
                            }
                            None => serde_json::json!({"id": id}),
                        }
                    })
                    .collect();
                serde_json::json!({"vulns": vulns})
            }
        })
        .collect();
    serde_json::to_vec(&serde_json::json!({
        "results": results,
        "probation_osv": {"v": WIRE_VERSION, "upstream_ok": upstream_ok},
    }))
    .expect("a JSON value always serializes")
}

fn truncate(s: &str, max: usize) -> &str {
    let mut end = s.len().min(max);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Defects that fail the whole request (LS-F5 first row).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EnvelopeError {
    NotJson,
    NotAnObject,
    QueriesMissing,
    DuplicateKey,
    TooDeep,
}

/// A defect in one query: that query alone is degraded.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct QueryDefect;

/// Stage 1 and 2 of LS-F5: the envelope, then each query, each one `(ecosystem, name,
/// version)` as written (charset and ecosystem allow-list are the server's next step).
/// One parsed query: `(ecosystem, name, version)` or its defect.
pub type ParsedQuery = Result<(String, String, String), QueryDefect>;

pub fn parse_request(body: &[u8]) -> Result<Vec<ParsedQuery>, EnvelopeError> {
    let root = parse_node(body).ok_or(EnvelopeError::NotJson)?;
    if root.depth() > MAX_REQUEST_DEPTH {
        return Err(EnvelopeError::TooDeep);
    }
    let Node::Obj { fields, dup } = &root else {
        return Err(EnvelopeError::NotAnObject);
    };
    if *dup {
        return Err(EnvelopeError::DuplicateKey);
    }
    let Some((_, Node::Arr(queries))) = fields.iter().find(|(k, _)| k == "queries") else {
        return Err(EnvelopeError::QueriesMissing);
    };
    Ok(queries.iter().map(query).collect())
}

fn query(node: &Node) -> Result<(String, String, String), QueryDefect> {
    if node.has_dup() || !node.only_fields(&["package", "version"]) {
        return Err(QueryDefect);
    }
    let package = node.field("package").ok_or(QueryDefect)?;
    if !package.only_fields(&["name", "ecosystem"]) {
        return Err(QueryDefect);
    }
    let name = package
        .field("name")
        .and_then(Node::string)
        .ok_or(QueryDefect)?;
    let ecosystem = package
        .field("ecosystem")
        .and_then(Node::string)
        .ok_or(QueryDefect)?;
    let version = node
        .field("version")
        .and_then(Node::string)
        .filter(|v| !v.is_empty())
        .ok_or(QueryDefect)?;
    Ok((ecosystem.to_owned(), name.to_owned(), version.to_owned()))
}
