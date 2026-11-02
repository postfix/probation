//! T-authorization-read-once (T19, C123): every use of the `Authorization` header
//! is reviewed. Managed API authentication reads it in `Managed::authenticate`;
//! certificate-protected registry reads use it for canonical token packuments,
//! named whoami, authenticated actions and selected PyPI uploads. A saved read
//! credential is sent to the selected upstream only for ordinary reads.
//!
//! This SMTC build cannot select a Rust call by its argument, so no analyzer spec can
//! hold the rule (C123). This is a token scan instead. Comments are stripped first;
//! `#[cfg(test)]` code is scanned. A hit is the identifier `AUTHORIZATION`, the
//! identifier `siem_auth_header` (an alias the configuration can point at the same
//! header), a string or byte-string literal equal to `authorization` in any case, or
//! the path segment `Authorization`. String literals are unescaped before they are
//! compared. Each hit is keyed by (file, nearest preceding `fn`, `struct`, `enum`,
//! `impl` or `mod` header, the call it is an argument of or else the token itself); a
//! `use` item is keyed by its full text alone. The hits must equal [`ALLOWED`] as a multiset, exact counts.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const ROOTS: [&str; 2] = ["src", "crates/probation-policy/src"];

/// (file, enclosing item, key, count). Anything else, or any count that differs,
/// fails. The managed API read and its import; the canonical npm token classifier,
/// guard, whoami/action reads and selected upstream sends; the SIEM header name's fields,
/// parsing and default; and the SIEM sink setup that sends it. The enclosing item is the nearest
/// preceding `fn`, `struct`, `enum`, `impl` or `mod` header; a `use` item has none.
const ALLOWED: &[(&str, &str, &str, usize)] = &[
    (
        "src/managed/mod.rs",
        "",
        "useaxum::http::header::AUTHORIZATION;",
        1,
    ),
    (
        "src/managed/mod.rs",
        "fn authenticate",
        "get(AUTHORIZATION)",
        1,
    ),
    ("src/http/registry_routes.rs", "fn package", "contains_key(header::AUTHORIZATION)", 1),
    ("src/http/registry_routes.rs", "fn named_read", "get(header::AUTHORIZATION)", 1),
    ("src/http/registry_routes.rs", "fn unsupported_artifact_delete", "get(header::AUTHORIZATION)", 1),
    ("src/http/token_packument.rs", "fn check_canonical_token_packument", "get(header::AUTHORIZATION)", 1),
    ("src/http/registry_action.rs", "fn admit_publish_request", "get(header::AUTHORIZATION)", 2),
    ("src/http/pypi_routes.rs", "fn selected_upload", "get(header::AUTHORIZATION)", 1),
    ("src/upstream/reqwest_transport.rs", "fn fetch_named_read", "header(header::AUTHORIZATION,value)", 1),
    ("src/upstream/reqwest_transport.rs", "fn fetch_token_packument", "header(header::AUTHORIZATION,authorization)", 1),
    ("src/upstream/reqwest_transport.rs", "fn send_action", "header(header::AUTHORIZATION,HeaderValue::from_str(&authorization).map_err(|_|UpstreamError::Status(400))?)", 1),
    ("src/upstream/reqwest_transport.rs", "fn fetch_metadata", "header(header::AUTHORIZATION,HeaderValue::from_str(&authorization).map_err(|_|UpstreamError::Status(400))?)", 1),
    ("src/upstream/reqwest_transport.rs", "fn open_artifact", "header(header::AUTHORIZATION,HeaderValue::from_str(&value).map_err(|_|UpstreamError::Status(400))?)", 1),
    ("src/config.rs", "struct Config", "siem_auth_header", 1),
    ("src/config.rs", "struct RawConfig", "siem_auth_header", 1),
    ("src/config.rs", "fn validate", "siem_auth_header", 4),
    ("src/config.rs", "fn validate", "header::AUTHORIZATION", 1),
    ("src/delivery/mod.rs", "fn build", "siem_auth_header", 4),
    (
        "src/delivery/mod.rs",
        "fn build",
        "siem_auth(&config.siem_auth_header)",
        1,
    ),
];

type Key = (String, String, String);

/// Every hit under `repo`'s scan roots, with the lines it was found on.
fn scan(repo: &Path) -> BTreeMap<Key, Vec<usize>> {
    let mut hits = BTreeMap::new();
    for root in ROOTS {
        for file in rust_files(&repo.join(root)) {
            let relative = file
                .strip_prefix(repo)
                .expect("under the repository")
                .to_string_lossy()
                .into_owned();
            let text = std::fs::read(&file).expect("a source file");
            for (fn_name, key, line) in hits_in(&text) {
                hits.entry((relative.clone(), fn_name, key))
                    .or_insert_with(Vec::new)
                    .push(line);
            }
        }
    }
    hits
}

fn rust_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return files;
    };
    for entry in entries {
        let path = entry.expect("a directory entry").path();
        if path.is_dir() {
            files.extend(rust_files(&path));
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            files.push(path);
        }
    }
    files.sort();
    files
}

/// The hits differ from [`ALLOWED`]: each extra or missing key, with file:line.
fn mismatches(hits: &BTreeMap<Key, Vec<usize>>) -> Vec<String> {
    let mut allowed: BTreeMap<Key, usize> = BTreeMap::new();
    for (file, fn_name, key, count) in ALLOWED {
        allowed.insert(
            ((*file).to_owned(), (*fn_name).to_owned(), (*key).to_owned()),
            *count,
        );
    }
    let mut problems = Vec::new();
    for ((file, fn_name, key), lines) in hits {
        let expected = allowed
            .get(&(file.clone(), fn_name.clone(), key.clone()))
            .copied()
            .unwrap_or(0);
        if lines.len() != expected {
            for line in lines {
                problems.push(format!(
                    "{file}:{line}: `{key}` in `{fn_name}`: {} found, {expected} allowed",
                    lines.len()
                ));
            }
        }
    }
    for ((file, fn_name, key), count) in &allowed {
        if !hits.contains_key(&(file.clone(), fn_name.clone(), key.clone())) {
            problems.push(format!(
                "{file}: `{key}` in `{fn_name}`: 0 found, {count} allowed"
            ));
        }
    }
    problems
}

/// The source with comments blanked (`stripped`), and the same with string and char
/// literals blanked too (`code`), byte for byte, newlines kept; plus every string
/// literal's offset and content.
struct Lexed {
    stripped: Vec<u8>,
    code: Vec<u8>,
    literals: Vec<(usize, usize, String)>,
}

fn is_ident(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn lex(source: &[u8]) -> Lexed {
    let n = source.len();
    let mut stripped = source.to_vec();
    let mut code = source.to_vec();
    let mut literals = Vec::new();
    let blank = |buffer: &mut Vec<u8>, from: usize, to: usize| {
        for byte in &mut buffer[from..to] {
            if *byte != b'\n' {
                *byte = b' ';
            }
        }
    };
    let mut i = 0;
    while i < n {
        let previous_ident = i > 0 && is_ident(source[i - 1]);
        if source[i..].starts_with(b"//") {
            let end = source[i..]
                .iter()
                .position(|&b| b == b'\n')
                .map_or(n, |p| i + p);
            blank(&mut stripped, i, end);
            blank(&mut code, i, end);
            i = end;
        } else if source[i..].starts_with(b"/*") {
            let mut depth = 0;
            let mut j = i;
            while j < n {
                if source[j..].starts_with(b"/*") {
                    depth += 1;
                    j += 2;
                } else if source[j..].starts_with(b"*/") {
                    depth -= 1;
                    j += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    j += 1;
                }
            }
            blank(&mut stripped, i, j);
            blank(&mut code, i, j);
            i = j;
        } else if !previous_ident && (source[i] == b'r' || source[i..].starts_with(b"br")) {
            // A raw string, or else a raw identifier or an ordinary one.
            let start = i;
            let mut j = i + if source[i] == b'b' { 2 } else { 1 };
            let hashes = source[j..].iter().take_while(|&&b| b == b'#').count();
            j += hashes;
            if j < n && source[j] == b'"' {
                let mut close = b"\"".to_vec();
                close.extend(std::iter::repeat_n(b'#', hashes));
                let content_start = j + 1;
                let content_end = source[content_start..]
                    .windows(close.len())
                    .position(|w| w == close.as_slice())
                    .map_or(n, |p| content_start + p);
                let end = (content_end + close.len()).min(n);
                literals.push((
                    start,
                    end,
                    String::from_utf8_lossy(&source[content_start..content_end]).into_owned(),
                ));
                blank(&mut code, start, end);
                i = end;
            } else {
                i += 1;
            }
        } else if source[i] == b'"' || (!previous_ident && source[i..].starts_with(b"b\"")) {
            let start = i;
            let mut j = i + if source[i] == b'b' { 2 } else { 1 };
            let content_start = j;
            while j < n && source[j] != b'"' {
                j += if source[j] == b'\\' { 2 } else { 1 };
            }
            let content_end = j.min(n);
            let end = (j + 1).min(n);
            literals.push((
                start,
                end,
                unescape(&String::from_utf8_lossy(
                    &source[content_start..content_end],
                )),
            ));
            blank(&mut code, start, end);
            i = end;
        } else if source[i] == b'\'' {
            // A char literal, or a lifetime.
            let end = if source.get(i + 1) == Some(&b'\\') {
                source[i + 2..]
                    .iter()
                    .position(|&b| b == b'\'')
                    .map(|p| i + 2 + p + 1)
            } else {
                (2..=5)
                    .find(|&k| {
                        source.get(i + k) == Some(&b'\'')
                            && std::str::from_utf8(&source[i + 1..i + k])
                                .is_ok_and(|c| c.chars().count() == 1)
                    })
                    .map(|k| i + k + 1)
            };
            match end {
                Some(end) => {
                    blank(&mut code, i, end);
                    i = end;
                }
                None => i += 1,
            }
        } else {
            i += 1;
        }
    }
    Lexed {
        stripped,
        code,
        literals,
    }
}

/// A string literal's value: `\x61` and `\u{41}` are letters like any other, so
/// `"\x61uthorization"` names the header too.
fn unescape(raw: &str) -> String {
    let mut value = String::new();
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            value.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => value.push('\n'),
            Some('r') => value.push('\r'),
            Some('t') => value.push('\t'),
            Some('0') => value.push('\0'),
            Some('x') => {
                let hex: String = chars.by_ref().take(2).collect();
                if let Some(c) = u8::from_str_radix(&hex, 16).ok().map(char::from) {
                    value.push(c);
                }
            }
            Some('u') => {
                let hex: String = chars
                    .by_ref()
                    .skip_while(|&c| c == '{')
                    .take_while(|&c| c != '}')
                    .collect();
                if let Some(c) = u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32) {
                    value.push(c);
                }
            }
            // A line continuation drops the newline and the next line's indent.
            Some('\n') => while chars.next_if(|c| c.is_whitespace()).is_some() {},
            Some(other) => value.push(other),
            None => {}
        }
    }
    value
}

/// Word-bounded occurrences of `word` in `code`.
fn words(code: &[u8], word: &str) -> Vec<usize> {
    let word = word.as_bytes();
    let mut found = Vec::new();
    let mut i = 0;
    while let Some(p) = code[i..].windows(word.len()).position(|w| w == word) {
        let at = i + p;
        let before = at > 0 && is_ident(code[at - 1]);
        let after = code.get(at + word.len()).is_some_and(|&b| is_ident(b));
        if !before && !after {
            found.push(at);
        }
        i = at + word.len();
        if i >= code.len() {
            break;
        }
    }
    found
}

fn squeeze(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join("")
}

/// Every hit in one file: (enclosing fn, key, line).
fn hits_in(source: &[u8]) -> Vec<(String, String, usize)> {
    let lexed = lex(source);
    let code = &lexed.code;
    let mut spans: Vec<(usize, usize)> = Vec::new();
    for word in ["AUTHORIZATION", "siem_auth_header", "Authorization"] {
        spans.extend(
            words(code, word)
                .into_iter()
                .map(|at| (at, at + word.len())),
        );
    }
    for (start, end, content) in &lexed.literals {
        if content.eq_ignore_ascii_case("authorization") {
            spans.push((*start, *end));
        }
    }
    spans.sort();

    let uses: Vec<(usize, usize)> = words(code, "use")
        .into_iter()
        .map(|at| {
            let end = code[at..]
                .iter()
                .position(|&b| b == b';')
                .map_or(code.len(), |p| at + p + 1);
            (at, end)
        })
        .collect();
    let mut items: Vec<(usize, &str)> = Vec::new();
    for keyword in ["fn", "struct", "enum", "impl", "mod"] {
        items.extend(
            words(code, keyword)
                .into_iter()
                .filter(|&at| at_item_position(code, at, keyword))
                .map(|at| (at, keyword)),
        );
    }
    items.sort();

    // Code pulled in from outside the scan roots is code this scan never read: a
    // `path = …` anywhere inside an attribute (`cfg_attr` included), an attribute a
    // macro fills in (`$` inside it), and every `include` token, whatever follows it
    // (`use std::include as inc;` too).
    for (open, close) in attribute_spans(code) {
        let attribute = &code[open..close];
        // `#[$($a)*]` or `#[$m]`: a macro writes the attribute, so the scan cannot see
        // whether it is `path = …`.
        if attribute.contains(&b'$') {
            spans.push((open, open + 1));
            continue;
        }
        for at in words(attribute, "path") {
            if attribute[at + "path".len()..]
                .trim_ascii_start()
                .starts_with(b"=")
            {
                spans.push((open + at, open + at + "path".len()));
            }
        }
    }
    for at in words(code, "include") {
        spans.push((at, at + "include".len()));
    }
    spans.sort();

    spans
        .into_iter()
        .map(|(start, end)| {
            let line = source[..start].iter().filter(|&&b| b == b'\n').count() + 1;
            let item = items
                .iter()
                .rev()
                .find(|(at, _)| *at < start)
                .map(|&(at, keyword)| item_header(code, at, keyword))
                .unwrap_or_default();
            // A `use` item is keyed by its full text alone, wherever it sits.
            match uses.iter().find(|(from, to)| *from <= start && start < *to) {
                Some((from, to)) => (String::new(), squeeze(&lexed.stripped[*from..*to]), line),
                None => (item, call_or_token(&lexed, start, end), line),
            }
        })
        .collect()
}

/// Every `#[…]` and `#![…]` attribute, as the byte range of its brackets.
fn attribute_spans(code: &[u8]) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    for (at, _) in code.iter().enumerate().filter(|&(_, b)| *b == b'#') {
        let mut open = at + 1;
        if code.get(open) == Some(&b'!') {
            open += 1;
        }
        while code.get(open).is_some_and(|b| b.is_ascii_whitespace()) {
            open += 1;
        }
        if code.get(open) != Some(&b'[') {
            continue;
        }
        let mut depth = 0;
        let close = (open..code.len()).find(|&i| {
            match code[i] {
                b'[' => depth += 1,
                b']' => depth -= 1,
                _ => {}
            }
            depth == 0
        });
        spans.push((open, close.map_or(code.len(), |close| close + 1)));
    }
    spans
}

/// Whether the `fn` or `impl` at `at` starts an item rather than naming a type: only
/// when the previous significant token is `}`, `;`, `{`, the `]` closing an attribute,
/// or the start of the file, optionally after `pub`, `pub(…)`, `unsafe`, `default`,
/// `async`, `const` or `extern "…"`. Anything else — `:`, `&`, `&mut`, `&'a`, `[`, `->`,
/// `dyn`, `=` — makes it part of a type.
fn at_item_position(code: &[u8], at: usize, keyword: &str) -> bool {
    if !matches!(keyword, "fn" | "impl") {
        return true;
    }
    let mut before = code[..at].trim_ascii_end();
    loop {
        let qualifier = ["pub", "unsafe", "default", "async", "const", "extern"]
            .iter()
            .find(|word| {
                before.ends_with(word.as_bytes())
                    && !before
                        .len()
                        .checked_sub(word.len() + 1)
                        .is_some_and(|i| is_ident(before[i]))
            });
        if let Some(word) = qualifier {
            before = before[..before.len() - word.len()].trim_ascii_end();
            continue;
        }
        // `pub(crate)`, `pub(in path)`; the `extern "C"` string is already blanked.
        if before.ends_with(b")") {
            let open = before.iter().rposition(|&b| b == b'(');
            if let Some(open) = open
                && before[..open].trim_ascii_end().ends_with(b"pub")
            {
                before = before[..open].trim_ascii_end();
                continue;
            }
        }
        break;
    }
    match before.last() {
        None | Some(b'}' | b';' | b'{') => true,
        Some(b']') => attribute_spans(before)
            .last()
            .is_some_and(|&(_, close)| close == before.len()),
        Some(_) => false,
    }
}

/// `keyword name`: the item header at `at`, up to its generics, parameters or body.
fn item_header(code: &[u8], at: usize, keyword: &str) -> String {
    let mut rest = &code[at + keyword.len()..];
    // `impl<T> Name`: the generics are not the name.
    if keyword == "impl" && rest.first() == Some(&b'<') {
        let mut depth = 0;
        let close = rest
            .iter()
            .position(|&b| {
                match b {
                    b'<' => depth += 1,
                    b'>' => depth -= 1,
                    _ => {}
                }
                depth == 0
            })
            .unwrap_or(0);
        rest = &rest[close + 1..];
    }
    let end = rest
        .iter()
        .position(|&b| matches!(b, b'{' | b'(' | b';' | b'<'))
        .unwrap_or(rest.len());
    let name = String::from_utf8_lossy(&rest[..end])
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    format!("{keyword} {name}")
}

/// The call the hit is an argument of, as `name(args)`, or else the hit's own path.
fn call_or_token(lexed: &Lexed, start: usize, end: usize) -> String {
    let code = &lexed.code;
    let path_start = (0..start)
        .rev()
        .take_while(|&i| is_ident(code[i]) || code[i] == b':')
        .last()
        .unwrap_or(start);
    let token = squeeze(&lexed.stripped[path_start..end]);
    // Back to the unbalanced `(` that opens the argument list, if there is one.
    let mut depth = 0i32;
    let mut i = path_start;
    while i > 0 {
        i -= 1;
        match code[i] {
            b')' | b']' => depth += 1,
            b'(' if depth == 0 => {
                let name_end = (0..i).rev().find(|&j| !code[j].is_ascii_whitespace());
                let Some(name_end) = name_end.filter(|&j| is_ident(code[j])) else {
                    return token;
                };
                let name_start = (0..=name_end)
                    .rev()
                    .take_while(|&j| is_ident(code[j]))
                    .last()
                    .unwrap_or(name_end);
                let mut close_depth = 0;
                let close = (i..code.len())
                    .find(|&j| {
                        match code[j] {
                            b'(' => close_depth += 1,
                            b')' => close_depth -= 1,
                            _ => {}
                        }
                        close_depth == 0
                    })
                    .unwrap_or(code.len() - 1);
                return squeeze(&lexed.stripped[name_start..=close]);
            }
            b'(' | b'[' if depth > 0 => depth -= 1,
            b'[' | b';' | b'{' | b'}' if depth == 0 => return token,
            _ => {}
        }
    }
    token
}

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The scan roots copied to a temporary repository, `edit` applied to one file.
fn mutated(file: &str, edit: impl FnOnce(String) -> String) -> tempfile::TempDir {
    let copy = tempfile::tempdir().expect("a temporary directory");
    for root in ROOTS {
        for source in rust_files(&repo().join(root)) {
            let relative = source.strip_prefix(repo()).expect("under the repository");
            let target = copy.path().join(relative);
            std::fs::create_dir_all(target.parent().expect("a parent")).expect("a directory");
            std::fs::copy(&source, &target).expect("a copy");
        }
    }
    let path = copy.path().join(file);
    let text = std::fs::read_to_string(&path).expect("the file to mutate");
    let edited = edit(text.clone());
    assert_ne!(edited, text, "the mutation applies to {file}");
    std::fs::write(&path, edited).expect("the mutated file");
    copy
}

/// Replaces the one occurrence of `anchor` in `text` with `with`.
fn replace_once(text: &str, anchor: &str, with: &str) -> String {
    assert_eq!(text.matches(anchor).count(), 1, "anchor {anchor:?}");
    text.replacen(anchor, with, 1)
}

#[test]
fn the_tree_as_built_uses_authorization_only_at_reviewed_sites() {
    let hits = scan(&repo());
    let problems = mismatches(&hits);
    assert!(
        problems.is_empty(),
        "hits outside the allowlist:\n{}\nall hits: {hits:#?}",
        problems.join("\n")
    );
}

const READ: &str =
    "        let presented = headers.get(AUTHORIZATION).ok_or(Refusal::Unauthenticated)?;\n";
const NPM_HANDLER: &str = "    let (_permit, principal) = super::admit(&app, &headers).await?;\n    let name = parse_name(&package)?;\n";
const ADMIT: &str = "    let Some(managed) = app.managed() else {\n";

/// One mutation of one file's text.
type Edit = Box<dyn FnOnce(String) -> String>;

#[test]
fn each_mutated_copy_fails_and_names_the_extra_hit() {
    let cases: Vec<(&str, &str, Edit)> = vec![
        (
            "a second read in an http handler",
            "src/http/npm_routes.rs",
            Box::new(|text| {
                replace_once(
                    &text,
                    NPM_HANDLER,
                    &format!(
                        "    let _ = headers.get(axum::http::header::AUTHORIZATION);\n{NPM_HANDLER}"
                    ),
                )
            }),
        ),
        (
            "an aliased import read through the alias",
            "src/managed/mod.rs",
            Box::new(|text| {
                let text = replace_once(
                    &text,
                    "use axum::http::header::AUTHORIZATION;\n",
                    "use axum::http::header::AUTHORIZATION;\nuse axum::http::header::AUTHORIZATION as A;\n",
                );
                replace_once(
                    &text,
                    READ,
                    &format!("        let _ = headers.get(A);\n{READ}"),
                )
            }),
        ),
        (
            "the header named by a literal",
            "src/managed/mod.rs",
            Box::new(|text| {
                replace_once(
                    &text,
                    READ,
                    &format!("        let _ = headers.get(\"authorization\");\n{READ}"),
                )
            }),
        ),
        (
            "a UFCS read",
            "src/managed/mod.rs",
            Box::new(|text| {
                replace_once(
                    &text,
                    READ,
                    &format!("        let _ = HeaderMap::get(&headers, AUTHORIZATION);\n{READ}"),
                )
            }),
        ),
        (
            "a module from outside the roots",
            "src/managed/mod.rs",
            Box::new(|text| {
                replace_once(
                    &text,
                    "mod cache;\n",
                    "mod cache;\n#[path = \"../../outside.rs\"]\nmod outside;\n",
                )
            }),
        ),
        (
            "code included from outside the roots",
            "src/managed/mod.rs",
            Box::new(|text| {
                replace_once(
                    &text,
                    "mod cache;\n",
                    "mod cache;\ninclude!(\"../../outside.rs\");\n",
                )
            }),
        ),
        (
            "a path attribute inside cfg_attr",
            "src/managed/mod.rs",
            Box::new(|text| {
                replace_once(
                    &text,
                    "mod cache;\n",
                    "mod cache;\n#[cfg_attr(all(), path = \"../../outside.rs\")]\nmod outside;\n",
                )
            }),
        ),
        (
            "a path attribute built by a macro from token trees",
            "src/managed/mod.rs",
            Box::new(|text| {
                replace_once(
                    &text,
                    "mod cache;\n",
                    "mod cache;\nmacro_rules! m {\n    ($($a:tt)*) => {\n        #[$($a)*]\n        mod outside;\n    };\n}\nm!(path = \"../../outside.rs\");\n",
                )
            }),
        ),
        (
            "a path attribute built by a macro from a meta",
            "src/managed/mod.rs",
            Box::new(|text| {
                replace_once(
                    &text,
                    "mod cache;\n",
                    "mod cache;\nmacro_rules! m {\n    ($m:meta) => {\n        #[$m]\n        mod outside;\n    };\n}\nm!(path = \"../../outside.rs\");\n",
                )
            }),
        ),
        (
            "include through an alias",
            "src/managed/mod.rs",
            Box::new(|text| {
                replace_once(
                    &text,
                    "mod cache;\n",
                    "mod cache;\nuse std::include as inc;\ninc!(\"../../outside.rs\");\n",
                )
            }),
        ),
        (
            "another accessor",
            "src/managed/mod.rs",
            Box::new(|text| {
                replace_once(
                    &text,
                    READ,
                    &format!("        let _ = headers.clone().remove(AUTHORIZATION);\n{READ}"),
                )
            }),
        ),
        (
            "the header named by a literal with a hex escape",
            "src/managed/mod.rs",
            Box::new(|text| {
                replace_once(
                    &text,
                    READ,
                    &format!("        let _ = headers.get(\"\\x61uthorization\");\n{READ}"),
                )
            }),
        ),
        (
            "the header named by a literal with a unicode escape",
            "src/managed/mod.rs",
            Box::new(|text| {
                replace_once(
                    &text,
                    READ,
                    &format!("        let _ = headers.get(\"\\u{{41}}uthorization\");\n{READ}"),
                )
            }),
        ),
        (
            "the configured SIEM header name read in a handler",
            "src/http/npm_routes.rs",
            Box::new(|text| {
                replace_once(
                    &text,
                    NPM_HANDLER,
                    &format!(
                        "    let _ = headers.get(&app.config.siem_auth_header);\n{NPM_HANDLER}"
                    ),
                )
            }),
        ),
    ];
    for (what, file, edit) in cases {
        let copy = mutated(file, edit);
        let problems = mismatches(&scan(copy.path()));
        assert!(!problems.is_empty(), "{what}: the scan passed");
        assert!(
            problems
                .iter()
                .any(|problem| problem.starts_with(&format!("{file}:"))),
            "{what}: no problem names {file}: {problems:#?}"
        );
    }

    // The read moved into `admit`: the read leaves `authenticate` and appears there.
    let copy = mutated("src/managed/mod.rs", |text| {
        replace_once(
            &text,
            READ,
            "        let presented = headers.values().next().ok_or(Refusal::Unauthenticated)?;\n",
        )
    });
    let admit = copy.path().join("src/http/mod.rs");
    let text = std::fs::read_to_string(&admit).expect("http/mod.rs");
    std::fs::write(
        &admit,
        replace_once(
            &text,
            ADMIT,
            &format!("    let _ = headers.get(axum::http::header::AUTHORIZATION);\n{ADMIT}"),
        ),
    )
    .expect("the mutated file");
    let problems = mismatches(&scan(copy.path()));
    assert!(
        problems.iter().any(|p| p.starts_with("src/http/mod.rs:"))
            && problems.iter().any(|p| p.contains("0 found")),
        "the moved read: {problems:#?}"
    );
}

/// Edits that move no hit keep the scan passing: a new `fn` above a struct whose field
/// is a hit, and a new method after the `fn` a struct's hits used to follow.
#[test]
fn harmless_edits_keep_the_scan_passing() {
    let copy = mutated("src/config.rs", |text| {
        replace_once(
            &text,
            "/// The file as written, before validation.",
            "fn default_x() -> u64 {\n    1\n}\n\n/// The file as written, before validation.",
        )
    });
    let problems = mismatches(&scan(copy.path()));
    assert!(problems.is_empty(), "a fn above RawConfig: {problems:#?}");

    let copy = mutated("src/config.rs", |text| {
        replace_once(
            &text,
            "        (prefix <= bits).then_some(Cidr { addr, prefix })\n    }\n",
            "        (prefix <= bits).then_some(Cidr { addr, prefix })\n    }\n\n    pub fn contains(&self, ip: IpAddr) -> bool {\n        self.addr == ip\n    }\n",
        )
    });
    let problems = mismatches(&scan(copy.path()));
    assert!(
        problems.is_empty(),
        "Cidr::contains after parse: {problems:#?}"
    );

    // `fn` and `impl` in a type are not item headers.
    let copy = mutated("src/managed/mod.rs", |text| {
        let text = replace_once(
            &text,
            "        peer: IpAddr,\n    ) -> Result<Principal, Refusal> {",
            "        peer: IpAddr,\n        _label: impl Into<String>,\n    ) -> Result<Principal, Refusal> {",
        );
        replace_once(
            &text,
            READ,
            &format!("        let _f: fn(&str) -> bool = str::is_empty;\n{READ}"),
        )
    });
    let problems = mismatches(&scan(copy.path()));
    assert!(
        problems.is_empty(),
        "an impl parameter and a fn-pointer local: {problems:#?}"
    );

    let copy = mutated("src/config.rs", |text| {
        replace_once(
            &text,
            "    fn validate(self) -> Result<Config, ConfigError> {",
            "    fn validate(self) -> impl Into<Result<Config, ConfigError>> {",
        )
    });
    let problems = mismatches(&scan(copy.path()));
    assert!(problems.is_empty(), "an `-> impl` return: {problems:#?}");

    // `impl Trait` behind a reference, a lifetime or a slice is a type, not an item.
    let copy = mutated("src/managed/mod.rs", |text| {
        replace_once(
            &text,
            "        peer: IpAddr,\n    ) -> Result<Principal, Refusal> {",
            "        peer: IpAddr,\n        _out: &mut impl std::io::Write,\n        _name: &'a impl AsRef<str>,\n        _all: &[impl std::fmt::Debug],\n    ) -> Result<Principal, Refusal> {",
        )
    });
    let problems = mismatches(&scan(copy.path()));
    assert!(
        problems.is_empty(),
        "impl behind &mut, &'a and &[: {problems:#?}"
    );
}

#[test]
fn a_comment_naming_the_header_is_not_a_hit() {
    let copy = mutated("src/managed/mod.rs", |text| {
        replace_once(
            &text,
            READ,
            &format!("{}// AUTHORIZATION\n", READ.trim_end_matches('\n')),
        )
    });
    let problems = mismatches(&scan(copy.path()));
    assert!(problems.is_empty(), "{problems:#?}");
}
