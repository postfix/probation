//! A strict, bounded scanner for the XML documents a Maven repository serves (`maven-metadata.xml`,
//! `archetype-catalog.xml`) and nothing more.
//!
//! What it refuses, because no repository document needs it: a document type declaration or any entity
//! declaration (so there is no entity to expand and no external subset to fetch), a processing instruction other
//! than the XML declaration at the very start, an entity reference other than the five predefined ones and numeric
//! character references, a bare `&`, control characters, a document that is not UTF-8, mismatched or unclosed tags,
//! more than one root element, text outside the root, and nesting deeper than `MAX_DEPTH`. It is a scanner, not a
//! tree: the caller walks the events once and keeps byte spans, so a document the firewall rewrites is edited in place
//! (everything it does not understand is passed on byte for byte) and an 18 MB archetype catalog costs no tree.
//!
//! The decoder never builds a string longer than the input and never recurses.

use std::borrow::Cow;

/// Deeper than any repository document (metadata nests four levels, a catalog three).
pub const MAX_DEPTH: usize = 24;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XmlError {
    NotUtf8,
    /// `<!DOCTYPE`, `<!ENTITY` or any other declaration.
    Declaration,
    /// A processing instruction other than the XML declaration at the very start.
    Instruction,
    /// An entity reference that is not one of the five predefined or a numeric character reference, or a bare `&`.
    Entity,
    Control,
    Malformed,
    Mismatch,
    TooDeep,
    /// No root element, or text/tags after it.
    Root,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Event<'a> {
    /// `<name ...>`; `end` is the byte after `>`. A self-closing tag is a `Start` (self_closing) then its `End`.
    Start {
        name: &'a str,
        start: usize,
        end: usize,
        self_closing: bool,
        depth: usize,
    },
    /// `</name>` (or the synthetic end of a self-closing tag, whose `start == end`); `end` is the byte after `>`.
    End {
        name: &'a str,
        start: usize,
        end: usize,
        depth: usize,
    },
    /// Character data (CDATA sections included, entity references not yet decoded): the raw bytes `start..end`.
    Text {
        start: usize,
        end: usize,
        depth: usize,
    },
}

/// The document as UTF-8 text: a UTF-8 document as it is, a document that declares ISO-8859-1 (and is not UTF-8) transcoded
/// byte for byte with the declaration naming UTF-8. Any other declared encoding is refused unless the bytes are UTF-8 (an
/// undeclared non-UTF-8 document is `NotUtf8`). The output is at most twice the input.
pub fn to_utf8(doc: &[u8]) -> Result<Cow<'_, [u8]>, XmlError> {
    if std::str::from_utf8(doc).is_ok() {
        return Ok(Cow::Borrowed(doc));
    }
    let head: String = doc.iter().take(256).map(|b| char::from(*b)).collect();
    let declared = head
        .strip_prefix("<?xml")
        .and_then(|rest| rest.split("?>").next())
        .and_then(|declaration| {
            let at = declaration.find("encoding")? + "encoding".len();
            let rest = declaration[at..]
                .trim_start()
                .strip_prefix('=')?
                .trim_start();
            let quote = rest.chars().next().filter(|c| matches!(c, '"' | '\''))?;
            let value = rest[1..].split(quote).next()?;
            Some(value.to_owned())
        })
        .ok_or(XmlError::NotUtf8)?;
    if !matches!(
        declared.to_ascii_lowercase().as_str(),
        "iso-8859-1" | "iso_8859-1" | "latin1" | "latin-1" | "l1"
    ) {
        return Err(XmlError::NotUtf8);
    }
    let mut text: String = doc.iter().map(|b| char::from(*b)).collect();
    // The declaration is the first thing in the document: its encoding now says what the bytes are.
    let end = text.find("?>").ok_or(XmlError::NotUtf8)?;
    let (declaration, rest) = text.split_at(end);
    let renamed = declaration.replacen(declared.as_str(), "UTF-8", 1);
    text = format!("{renamed}{rest}");
    Ok(Cow::Owned(text.into_bytes()))
}

/// Decodes the character data of `raw` (a slice of the scanned document): the five predefined entities and numeric
/// character references, and CDATA sections unwrapped. Everything else was refused by the scanner.
pub fn decode(raw: &str) -> Cow<'_, str> {
    if !raw.contains('&') && !raw.contains("<![CDATA[") {
        return Cow::Borrowed(raw);
    }
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(i) = rest.find(['&', '<']) {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        if let Some(inner) = rest.strip_prefix("<![CDATA[") {
            let Some(j) = inner.find("]]>") else { break };
            out.push_str(&inner[..j]);
            rest = &inner[j + 3..];
        } else if rest.starts_with('&') {
            let Some(j) = rest.find(';') else { break };
            match entity(&rest[1..j]) {
                Some(c) => out.push(c),
                None => break,
            }
            rest = &rest[j + 1..];
        } else {
            // A `<` inside text can only be a comment the scanner skipped; the scanner never reports one as text.
            break;
        }
    }
    out.push_str(rest);
    Cow::Owned(out)
}

fn entity(name: &str) -> Option<char> {
    match name {
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        _ => {
            let digits = name.strip_prefix('#')?;
            let code = match digits.strip_prefix(['x', 'X']) {
                Some(hex) if !hex.is_empty() && hex.len() <= 6 => {
                    u32::from_str_radix(hex, 16).ok()?
                }
                None if !digits.is_empty()
                    && digits.len() <= 7
                    && digits.bytes().all(|b| b.is_ascii_digit()) =>
                {
                    digits.parse().ok()?
                }
                _ => return None,
            };
            char::from_u32(code).filter(|c| xml_char(*c))
        }
    }
}

/// The XML 1.0 `Char` production.
fn xml_char(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r' | ' '..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..='\u{10FFFF}')
}

fn name_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_' || b == b':'
}

fn name_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b':' | b'-' | b'.')
}

/// Walks `doc` once, calling `visit` for every event. Returns the first error; the events seen before it are not to be
/// trusted by the caller (it returns the error and drops what it collected).
pub fn scan<'a>(doc: &'a [u8], mut visit: impl FnMut(Event<'a>)) -> Result<(), XmlError> {
    let text = std::str::from_utf8(doc).map_err(|_| XmlError::NotUtf8)?;
    let bytes = text.as_bytes();
    let mut i = if text.starts_with('\u{feff}') { 3 } else { 0 };
    let mut stack: Vec<&'a str> = Vec::new();
    let mut roots = 0usize;
    let mut first = true;
    while i < bytes.len() {
        if bytes[i] != b'<' {
            // Character data up to the next tag.
            let end = bytes[i..]
                .iter()
                .position(|b| *b == b'<')
                .map_or(bytes.len(), |p| i + p);
            check_text(&bytes[i..end])?;
            if stack.is_empty() {
                if !bytes[i..end]
                    .iter()
                    .all(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
                {
                    return Err(XmlError::Root);
                }
            } else {
                visit(Event::Text {
                    start: i,
                    end,
                    depth: stack.len(),
                });
            }
            i = end;
            first = false;
            continue;
        }
        let rest = &text[i..];
        if let Some(instruction) = rest.strip_prefix("<?") {
            // Only the XML declaration, only at the very start (after a byte-order mark).
            let at_start = first && (i == 0 || i == 3);
            let close = rest.find("?>").ok_or(XmlError::Malformed)?;
            let declaration = instruction
                .strip_prefix("xml")
                .is_some_and(|r| r.starts_with([' ', '\t', '\r', '\n', '?']));
            if !(at_start && declaration) {
                return Err(XmlError::Instruction);
            }
            check_text(&bytes[i..i + close + 2])?;
            i += close + 2;
            first = false;
            continue;
        }
        first = false;
        if let Some(comment) = rest.strip_prefix("<!--") {
            let close = comment.find("-->").ok_or(XmlError::Malformed)?;
            // A comment is not character data: an ampersand in it is only text (`<!-- R&D -->`).
            check_text_raw(&bytes[i..i + 4 + close + 3])?;
            i += 4 + close + 3;
            continue;
        }
        if rest.starts_with("<![CDATA[") {
            if stack.is_empty() {
                return Err(XmlError::Root);
            }
            let close = rest.find("]]>").ok_or(XmlError::Malformed)?;
            check_text_raw(&bytes[i + 9..i + close])?;
            visit(Event::Text {
                start: i,
                end: i + close + 3,
                depth: stack.len(),
            });
            i += close + 3;
            continue;
        }
        if rest.starts_with("<!") {
            return Err(XmlError::Declaration);
        }
        if let Some(tail) = rest.strip_prefix("</") {
            let close = tail.find('>').ok_or(XmlError::Malformed)?;
            let name = tail[..close].trim_end_matches([' ', '\t', '\r', '\n']);
            let open = stack.pop().ok_or(XmlError::Mismatch)?;
            if name != open {
                return Err(XmlError::Mismatch);
            }
            let end = i + 2 + close + 1;
            visit(Event::End {
                name: open,
                start: i,
                end,
                depth: stack.len() + 1,
            });
            i = end;
            continue;
        }
        // A start tag.
        let b = &bytes[i + 1..];
        if b.is_empty() || !name_start(b[0]) {
            return Err(XmlError::Malformed);
        }
        let name_len = b.iter().position(|c| !name_char(*c)).unwrap_or(b.len());
        let name = &text[i + 1..i + 1 + name_len];
        let mut j = i + 1 + name_len;
        let mut seen: Vec<&str> = Vec::new();
        let self_closing;
        loop {
            while j < bytes.len() && matches!(bytes[j], b' ' | b'\t' | b'\r' | b'\n') {
                j += 1;
            }
            match bytes.get(j) {
                Some(b'>') => {
                    self_closing = false;
                    j += 1;
                    break;
                }
                Some(b'/') if bytes.get(j + 1) == Some(&b'>') => {
                    self_closing = true;
                    j += 2;
                    break;
                }
                Some(c) if name_start(*c) => {
                    let len = bytes[j..]
                        .iter()
                        .position(|c| !name_char(*c))
                        .unwrap_or(bytes.len() - j);
                    let attribute = &text[j..j + len];
                    if seen.contains(&attribute) || seen.len() >= 32 {
                        return Err(XmlError::Malformed);
                    }
                    seen.push(attribute);
                    j += len;
                    while j < bytes.len() && matches!(bytes[j], b' ' | b'\t' | b'\r' | b'\n') {
                        j += 1;
                    }
                    if bytes.get(j) != Some(&b'=') {
                        return Err(XmlError::Malformed);
                    }
                    j += 1;
                    while j < bytes.len() && matches!(bytes[j], b' ' | b'\t' | b'\r' | b'\n') {
                        j += 1;
                    }
                    let quote = *bytes
                        .get(j)
                        .filter(|q| matches!(q, b'"' | b'\''))
                        .ok_or(XmlError::Malformed)?;
                    let close = bytes[j + 1..]
                        .iter()
                        .position(|c| *c == quote)
                        .ok_or(XmlError::Malformed)?;
                    let value = &bytes[j + 1..j + 1 + close];
                    if value.contains(&b'<') {
                        return Err(XmlError::Malformed);
                    }
                    check_text(value)?;
                    j += close + 2;
                }
                _ => return Err(XmlError::Malformed),
            }
        }
        if stack.is_empty() {
            roots += 1;
            if roots > 1 {
                return Err(XmlError::Root);
            }
        }
        if stack.len() >= MAX_DEPTH {
            return Err(XmlError::TooDeep);
        }
        stack.push(name);
        visit(Event::Start {
            name,
            start: i,
            end: j,
            self_closing,
            depth: stack.len(),
        });
        if self_closing {
            stack.pop();
            visit(Event::End {
                name,
                start: j,
                end: j,
                depth: stack.len() + 1,
            });
        }
        i = j;
    }
    if !stack.is_empty() || roots != 1 {
        return Err(XmlError::Root);
    }
    Ok(())
}

/// Control characters other than tab, CR and LF are not XML; entity references are the five predefined and numeric ones.
fn check_text(raw: &[u8]) -> Result<(), XmlError> {
    check_text_raw(raw)?;
    let text = std::str::from_utf8(raw).map_err(|_| XmlError::NotUtf8)?;
    let mut rest = text;
    while let Some(i) = rest.find('&') {
        let tail = &rest[i + 1..];
        let end = tail
            .find(';')
            .filter(|e| *e <= 10)
            .ok_or(XmlError::Entity)?;
        entity(&tail[..end]).ok_or(XmlError::Entity)?;
        rest = &tail[end + 1..];
    }
    Ok(())
}

fn check_text_raw(raw: &[u8]) -> Result<(), XmlError> {
    if raw
        .iter()
        .any(|b| *b < 0x20 && !matches!(b, b'\t' | b'\n' | b'\r'))
    {
        return Err(XmlError::Control);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn events(doc: &str) -> Result<Vec<String>, XmlError> {
        let mut out = Vec::new();
        scan(doc.as_bytes(), |e| {
            out.push(match e {
                Event::Start { name, depth, .. } => format!("<{name}>{depth}"),
                Event::End { name, depth, .. } => format!("</{name}>{depth}"),
                Event::Text { start, end, .. } => format!("t:{}", decode(&doc[start..end])),
            })
        })?;
        Ok(out)
    }

    #[test]
    fn a_metadata_document_is_scanned_with_its_declaration_comments_and_cdata() {
        let doc = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!-- c -->\n<metadata a='1'>\n  <v>1&amp;2</v><w/><x><![CDATA[<k>]]></x>\n</metadata>\n";
        let got = events(doc).unwrap();
        assert!(got.contains(&"t:1&2".to_owned()), "{got:?}");
        assert!(got.contains(&"t:<k>".to_owned()), "{got:?}");
        assert_eq!(got.iter().filter(|e| e.starts_with("<w>")).count(), 1);
        assert_eq!(
            got.iter().filter(|e| e.starts_with("</w>")).count(),
            1,
            "a self-closing tag has its end"
        );
    }

    #[test]
    fn declarations_entities_and_instructions_are_refused() {
        for (doc, error) in [
            (
                "<!DOCTYPE m [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><m>&x;</m>",
                XmlError::Declaration,
            ),
            ("<m>&x;</m>", XmlError::Entity),
            ("<m>&amp</m>", XmlError::Entity),
            ("<m>&#xD800;</m>", XmlError::Entity),
            ("<m>a & b</m>", XmlError::Entity),
            ("<m a=\"&bad;\"/>", XmlError::Entity),
            ("<m/><?php x ?>", XmlError::Instruction),
            ("<?xml-stylesheet href='x'?><m/>", XmlError::Instruction),
            ("<m><?pi x?></m>", XmlError::Instruction),
            ("<m>\u{0}</m>", XmlError::Control),
            ("<m><a></m>", XmlError::Mismatch),
            ("<m></m><m/>", XmlError::Root),
            ("text<m/>", XmlError::Root),
            ("<m/>text", XmlError::Root),
            ("", XmlError::Root),
            ("<m", XmlError::Malformed),
            ("<m a=1/>", XmlError::Malformed),
            ("<m a='1' a='2'/>", XmlError::Malformed),
        ] {
            assert_eq!(events(doc).err(), Some(error), "{doc:?}");
        }
        assert_eq!(scan(&[0xff, 0xfe], |_| {}), Err(XmlError::NotUtf8));
    }

    /// Nesting is bounded and the scanner does not recurse: a document a million levels deep is refused at depth 24.
    #[test]
    fn nesting_is_bounded_without_recursion() {
        let ok = format!("{}{}", "<a>".repeat(MAX_DEPTH), "</a>".repeat(MAX_DEPTH));
        assert!(events(&ok).is_ok());
        let deep = format!(
            "{}{}",
            "<a>".repeat(MAX_DEPTH + 1),
            "</a>".repeat(MAX_DEPTH + 1)
        );
        assert_eq!(events(&deep).err(), Some(XmlError::TooDeep));
        let huge = "<a>".repeat(1_000_000);
        assert_eq!(events(&huge).err(), Some(XmlError::TooDeep));
    }

    #[test]
    fn a_comment_may_hold_an_ampersand_and_latin1_documents_are_transcoded() {
        assert!(events("<m><!-- R&D --><v>1</v></m>").is_ok());
        assert_eq!(
            events("<m>a&b</m>").err(),
            Some(XmlError::Entity),
            "character data still may not"
        );
        let latin1 = b"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n<m><d>caf\xe9</d></m>";
        assert_eq!(
            scan(latin1, |_| {}),
            Err(XmlError::NotUtf8),
            "the scanner itself takes UTF-8 only"
        );
        let utf8 = to_utf8(latin1).unwrap();
        assert_eq!(
            std::str::from_utf8(&utf8).unwrap(),
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<m><d>caf\u{e9}</d></m>"
        );
        assert!(scan(&utf8, |_| {}).is_ok());
        assert!(matches!(
            to_utf8(b"<?xml version=\"1.0\" encoding=\"UTF-16\"?><m>\xff</m>"),
            Err(XmlError::NotUtf8)
        ));
        assert!(
            matches!(to_utf8(b"<m>\xe9</m>"), Err(XmlError::NotUtf8)),
            "undeclared"
        );
        assert!(matches!(to_utf8(b"<m>ok</m>"), Ok(Cow::Borrowed(_))));
    }

    #[test]
    fn numeric_references_decode() {
        assert_eq!(decode("&#65;&#x42;&lt;"), "AB<");
    }
}
