//! LS-F13: the bounded, typed Ruby Marshal 4.8 reader for RubyGems metadata. No Ruby
//! object is ever loaded and no code runs: every value is either a plain typed value or a
//! tag the allow-list names, and everything else refuses.
//!
//! Two contracts share one parser:
//!
//! * (A) tuple indexes (`specs.4.8`, `latest_specs.4.8`, `prerelease_specs.4.8`): an array
//!   of `[name, Gem::Version, platform]`. The filter parses one tuple at a time, asks the
//!   caller whether to keep it, and re-renders the kept tuples from the typed values (never
//!   splices input bytes).
//! * (B) quick gemspecs: a validating pass over a `Gem::Specification` stream, including
//!   the nested Marshal stream its `_dump` payload holds. It does not re-render, so the
//!   caller serves the original bytes unchanged after the pass.

use std::collections::HashMap;
use std::rc::Rc;

/// Memory is charged per retained typed node at this size, its real size rather than the
/// 64 B nominal of 03 (an `Rc<Str>`, its slot and allocator overhead are about 150 B, measured
/// against the real index; 03 LS-F13 is to be read as "real size") (LS-F13); nodes that are parsed
/// and dropped (the tuple in flight, a gemspec value) are bounded by the node cap instead.
pub const NODE_COST: u64 = 160;
/// The longest array or hash an index tuple can hold (a tuple has three slots).
const MAX_CONTAINER: usize = 3;

/// A link-table slot that holds no typed value: the size of the slot itself.
pub const SLOT_COST: u64 = 40;

/// The numeric bounds of one stream (and, for a quick gemspec, of the outer stream plus
/// every nested one).
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_depth: usize,
    pub max_nodes: u64,
    /// Bytes: retained string bytes, `NODE_COST` (160) per retained node, `SLOT_COST` (40) per table slot, symbol bytes and
    /// the re-rendered output buffer.
    pub memory_budget: u64,
}

impl Limits {
    /// Tuple indexes: depth 32, 20,000,000 nodes, 512 MiB (DEFAULT - confirm).
    pub const TUPLE_INDEX: Limits = Limits {
        max_depth: 32,
        max_nodes: 20_000_000,
        memory_budget: 512 * 1024 * 1024,
    };
    /// Quick gemspecs: depth 32, 1,000,000 nodes, 64 MiB.
    pub const GEMSPEC: Limits = Limits {
        max_depth: 32,
        max_nodes: 1_000_000,
        memory_budget: 64 * 1024 * 1024,
    };
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum MarshalError {
    Truncated,
    BadHeader,
    TrailingData,
    /// A type tag outside the allow-list.
    UnknownTypeTag(u8),
    /// A class name outside the allow-list.
    DisallowedClass(String),
    /// A class on the allow-list that arrived in the wrong payload kind.
    WrongPayloadKind(String),
    /// A `u:` payload that has to be a Marshal stream but is not one.
    NotAStream,
    BadSymbolLink,
    /// An object link to an index not seen yet, or to an object a typed re-render cannot share.
    BadLink,
    Depth,
    Nodes,
    Memory,
    /// Valid Marshal of a shape the contract does not cover (not a tuple, unsupported ivar).
    Shape(&'static str),
    BadInteger,
}

impl std::fmt::Display for MarshalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// A class's payload kind (LS-F13 B).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    /// `u:` whose String payload is a complete Marshal stream.
    NestedStream,
    /// `o:` or `U:`, an ordinary Marshal object parsed in place.
    InlineObject,
    /// `u:` with exactly 8 binary bytes, never parsed as a stream.
    Binary8,
}

fn kind_of(class: &str) -> Option<Kind> {
    match class {
        "Gem::Specification" => Some(Kind::NestedStream),
        "Gem::Version" | "Gem::Requirement" | "Gem::Dependency" | "Gem::Platform" => {
            Some(Kind::InlineObject)
        }
        "Time" => Some(Kind::Binary8),
        _ => None,
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
enum Enc {
    Binary,
    Utf8,
    UsAscii,
    Named(Vec<u8>),
}

#[derive(Debug)]
struct Str {
    bytes: Vec<u8>,
    enc: Enc,
}

/// A typed value. Only the leaf kinds a tuple needs are shared (`Rc`); containers are
/// owned by the tuple being built. Integers, symbols and hash pairs are kept typed so a
/// future family of the allow-list can render them; the tuple contract reads only the rest.
#[allow(dead_code)]
#[derive(Clone, Debug)]
enum V {
    Nil,
    True,
    False,
    Int(i128),
    Str(Rc<Str>),
    Sym(Rc<str>),
    Array(Vec<V>),
    Hash(Vec<(V, V)>),
    /// `Gem::Version` user-marshal; the payload is `[String]`.
    Version(Rc<V>),
    /// Validation mode: the value was checked and dropped.
    Opaque,
}

#[derive(Clone)]
enum Slot {
    Leaf(V),
    /// Registered but not shareable by a typed re-render (container, object, float...).
    Marker,
}

/// Shared by the outer stream and every nested one.
struct Budget {
    limits: Limits,
    nodes: u64,
    memory: u64,
}

impl Budget {
    fn node(&mut self) -> Result<(), MarshalError> {
        self.nodes += 1;
        if self.nodes > self.limits.max_nodes {
            return Err(MarshalError::Nodes);
        }
        Ok(())
    }
    fn charge(&mut self, bytes: u64) -> Result<(), MarshalError> {
        self.memory = self.memory.saturating_add(bytes);
        if self.memory > self.limits.memory_budget {
            return Err(MarshalError::Memory);
        }
        Ok(())
    }
}

struct Parser<'a, 'b> {
    input: &'a [u8],
    pos: usize,
    budget: &'b mut Budget,
    symbols: Vec<Rc<str>>,
    objects: Vec<Slot>,
    /// Typed values are kept (tuple index) or dropped after checking (gemspec).
    keep: bool,
    /// Gemspec mode accepts Float and the class allow-list; tuple mode only Gem::Version.
    spec: bool,
}

impl<'a, 'b> Parser<'a, 'b> {
    fn new(
        input: &'a [u8],
        budget: &'b mut Budget,
        keep: bool,
        spec: bool,
    ) -> Result<Self, MarshalError> {
        if input.len() < 2 || input[0] != 4 || input[1] != 8 {
            return Err(MarshalError::BadHeader);
        }
        Ok(Parser {
            input,
            pos: 2,
            budget,
            symbols: Vec::new(),
            objects: Vec::new(),
            keep,
            spec,
        })
    }

    fn byte(&mut self) -> Result<u8, MarshalError> {
        let b = *self.input.get(self.pos).ok_or(MarshalError::Truncated)?;
        self.pos += 1;
        Ok(b)
    }

    fn remaining(&self) -> usize {
        self.input.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], MarshalError> {
        if n > self.remaining() {
            return Err(MarshalError::Truncated);
        }
        let slice = &self.input[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    /// Marshal's packed integer.
    fn long(&mut self) -> Result<i64, MarshalError> {
        let c = self.byte()? as i8;
        Ok(match c {
            0 => 0,
            5..=127 => i64::from(c) - 5,
            -128..=-5 => i64::from(c) + 5,
            1..=4 => {
                let mut value: i64 = 0;
                for i in 0..c as usize {
                    value |= i64::from(self.byte()?) << (8 * i);
                }
                value
            }
            _ => {
                let n = (-c) as usize;
                let mut value: i64 = -1;
                for i in 0..n {
                    value &= !(0xff << (8 * i));
                    value |= i64::from(self.byte()?) << (8 * i);
                }
                value
            }
        })
    }

    /// A length: never negative, never more than the bytes left (every element or byte
    /// takes at least one input byte), so a declared length allocates nothing up front.
    fn length(&mut self, per_item: usize) -> Result<usize, MarshalError> {
        let n = self.long()?;
        let n = usize::try_from(n).map_err(|_| MarshalError::BadInteger)?;
        if n.checked_mul(per_item)
            .is_none_or(|need| need > self.remaining())
        {
            return Err(MarshalError::Truncated);
        }
        Ok(n)
    }

    fn register(&mut self, slot: Slot) -> Result<usize, MarshalError> {
        // A retained typed value costs 64 B plus its bytes (LS-F13); a slot that only holds a
        // place in the link table costs what the slot itself occupies.
        self.budget.charge(match slot {
            Slot::Leaf(_) => NODE_COST,
            Slot::Marker => SLOT_COST,
        })?;
        self.objects.push(slot);
        Ok(self.objects.len() - 1)
    }

    fn symbol(&mut self) -> Result<Rc<str>, MarshalError> {
        match self.byte()? {
            b':' => {
                let n = self.length(1)?;
                let bytes = self.take(n)?;
                let text: Rc<str> = Rc::from(String::from_utf8_lossy(bytes).as_ref());
                self.budget.charge(n as u64 + NODE_COST)?;
                self.symbols.push(Rc::clone(&text));
                Ok(text)
            }
            b';' => {
                let index =
                    usize::try_from(self.long()?).map_err(|_| MarshalError::BadSymbolLink)?;
                self.symbols
                    .get(index)
                    .cloned()
                    .ok_or(MarshalError::BadSymbolLink)
            }
            other => Err(MarshalError::UnknownTypeTag(other)),
        }
    }

    fn value(&mut self, depth: usize) -> Result<V, MarshalError> {
        if depth > self.budget.limits.max_depth {
            return Err(MarshalError::Depth);
        }
        self.budget.node()?;
        let tag = self.byte()?;
        match tag {
            b'0' => Ok(V::Nil),
            b'T' => Ok(V::True),
            b'F' => Ok(V::False),
            b'i' => Ok(V::Int(i128::from(self.long()?))),
            b'l' => {
                let negative = match self.byte()? {
                    b'+' => false,
                    b'-' => true,
                    _ => return Err(MarshalError::BadInteger),
                };
                let shorts = self.length(2)?;
                if shorts > 4 {
                    return Err(MarshalError::BadInteger); // wider than 64 bits
                }
                let bytes = self.take(shorts * 2)?;
                let mut magnitude: i128 = 0;
                for (i, b) in bytes.iter().enumerate() {
                    magnitude |= i128::from(*b) << (8 * i);
                }
                self.register(Slot::Marker)?;
                Ok(V::Int(if negative { -magnitude } else { magnitude }))
            }
            b'f' if self.spec => {
                let n = self.length(1)?;
                self.take(n)?;
                self.register(Slot::Marker)?;
                Ok(V::Opaque)
            }
            b'"' => self.string(Enc::Binary),
            b'I' => self.with_ivars(depth),
            b':' | b';' => {
                self.pos -= 1;
                Ok(V::Sym(self.symbol()?))
            }
            b'[' => {
                let n = self.length(1)?;
                // A tuple, a Gem::Version payload or a platform: nothing in an index is longer.
                // Refused before one child is collected, so a hostile container never grows a Vec.
                if self.keep && n > MAX_CONTAINER {
                    return Err(MarshalError::Shape(
                        "a container too long for an index tuple",
                    ));
                }
                self.register(Slot::Marker)?;
                let mut items = Vec::new();
                for _ in 0..n {
                    let item = self.value(depth + 1)?;
                    if self.keep {
                        items.push(item);
                    }
                }
                Ok(if self.keep {
                    V::Array(items)
                } else {
                    V::Opaque
                })
            }
            b'{' => {
                let n = self.length(2)?;
                if self.keep && n > MAX_CONTAINER {
                    return Err(MarshalError::Shape(
                        "a container too long for an index tuple",
                    ));
                }
                self.register(Slot::Marker)?;
                let mut pairs = Vec::new();
                for _ in 0..n {
                    let key = self.value(depth + 1)?;
                    let value = self.value(depth + 1)?;
                    if self.keep {
                        pairs.push((key, value));
                    }
                }
                Ok(if self.keep { V::Hash(pairs) } else { V::Opaque })
            }
            b'@' => {
                let index = usize::try_from(self.long()?).map_err(|_| MarshalError::BadLink)?;
                match self.objects.get(index) {
                    Some(Slot::Leaf(value)) => Ok(value.clone()),
                    // Already seen, so valid; a validating pass needs no value.
                    Some(Slot::Marker) if !self.keep => Ok(V::Opaque),
                    Some(Slot::Marker) => Err(MarshalError::BadLink),
                    None => Err(MarshalError::BadLink),
                }
            }
            b'U' => {
                let class = self.symbol()?;
                self.user_marshal(&class, depth)
            }
            b'o' => {
                let class = self.symbol()?;
                self.object(&class, depth)
            }
            b'u' => {
                let class = self.symbol()?;
                self.user_defined(&class, depth, None)
            }
            other => Err(MarshalError::UnknownTypeTag(other)),
        }
    }

    fn string(&mut self, enc: Enc) -> Result<V, MarshalError> {
        let n = self.length(1)?;
        let bytes = self.take(n)?;
        self.budget.charge(n as u64)?;
        let rc = Rc::new(Str {
            bytes: if self.keep {
                bytes.to_vec()
            } else {
                Vec::new()
            },
            enc,
        });
        let value = if self.keep {
            V::Str(Rc::clone(&rc))
        } else {
            V::Opaque
        };
        self.register(if self.keep {
            Slot::Leaf(value.clone())
        } else {
            Slot::Marker
        })?;
        Ok(value)
    }

    /// `I` wraps a String, or a `u:` payload, with instance variables. Only the encoding
    /// ivars (`E`, `encoding`) are accepted on a String.
    fn with_ivars(&mut self, depth: usize) -> Result<V, MarshalError> {
        match self.byte()? {
            b'"' => {
                let n = self.length(1)?;
                let bytes = self.take(n)?;
                self.budget.charge(n as u64)?;
                let at = self.objects.len();
                // The String is registered before its ivars, as Ruby numbers it.
                self.register(Slot::Marker)?;
                let enc = self.string_ivars(depth)?;
                let rc = Rc::new(Str {
                    bytes: if self.keep {
                        bytes.to_vec()
                    } else {
                        Vec::new()
                    },
                    enc,
                });
                let value = if self.keep { V::Str(rc) } else { V::Opaque };
                if self.keep {
                    self.objects[at] = Slot::Leaf(value.clone());
                    self.budget.charge(NODE_COST - SLOT_COST)?;
                }
                Ok(value)
            }
            b'u' => {
                let class = self.symbol()?;
                self.user_defined(&class, depth, Some(()))
            }
            other => Err(MarshalError::UnknownTypeTag(other)),
        }
    }

    fn string_ivars(&mut self, depth: usize) -> Result<Enc, MarshalError> {
        let count = self.length(2)?;
        let mut enc = Enc::Binary;
        for _ in 0..count {
            let name = self.symbol()?;
            match &*name {
                "E" => {
                    enc = match self.byte()? {
                        b'T' => Enc::Utf8,
                        b'F' => Enc::UsAscii,
                        other => return Err(MarshalError::UnknownTypeTag(other)),
                    };
                    self.budget.node()?;
                }
                "encoding" => {
                    let value = self.value(depth + 1)?;
                    enc = match value {
                        V::Str(s) => Enc::Named(s.bytes.clone()),
                        V::Opaque => Enc::Binary,
                        _ => return Err(MarshalError::Shape("encoding ivar is not a string")),
                    };
                }
                _ => return Err(MarshalError::Shape("string ivar other than the encoding")),
            }
        }
        Ok(enc)
    }

    fn ivar_pairs(&mut self, depth: usize) -> Result<(), MarshalError> {
        let count = self.length(2)?;
        for _ in 0..count {
            self.symbol()?;
            self.value(depth + 1)?;
        }
        Ok(())
    }

    fn user_marshal(&mut self, class: &str, depth: usize) -> Result<V, MarshalError> {
        match kind_of(class) {
            Some(Kind::InlineObject) => {}
            Some(_) => return Err(MarshalError::WrongPayloadKind(class.to_owned())),
            None => return Err(MarshalError::DisallowedClass(class.to_owned())),
        }
        if !self.spec && class != "Gem::Version" {
            return Err(MarshalError::DisallowedClass(class.to_owned()));
        }
        self.register(Slot::Marker)?; // the user-marshal object, before its payload
        let at = self.objects.len() - 1;
        let payload = self.value(depth + 1)?;
        if class == "Gem::Version" && self.keep {
            let ok = matches!(&payload, V::Array(items) if items.len() == 1 && matches!(items[0], V::Str(_)));
            if !ok {
                return Err(MarshalError::Shape("Gem::Version payload is not [String]"));
            }
            let value = V::Version(Rc::new(payload));
            self.objects[at] = Slot::Leaf(value.clone());
            self.budget.charge(NODE_COST - SLOT_COST)?;
            return Ok(value);
        }
        Ok(V::Opaque)
    }

    fn object(&mut self, class: &str, depth: usize) -> Result<V, MarshalError> {
        match kind_of(class) {
            Some(Kind::InlineObject) if self.spec => {}
            Some(Kind::InlineObject) | None => {
                return Err(MarshalError::DisallowedClass(class.to_owned()));
            }
            Some(_) => return Err(MarshalError::WrongPayloadKind(class.to_owned())),
        }
        self.register(Slot::Marker)?;
        self.ivar_pairs(depth)?;
        Ok(V::Opaque)
    }

    /// `u:` payloads: NestedStream (Gem::Specification) or Binary8 (Time). `ivars` is set
    /// when an `I` wrapper puts instance variables after the payload.
    fn user_defined(
        &mut self,
        class: &str,
        depth: usize,
        ivars: Option<()>,
    ) -> Result<V, MarshalError> {
        if !self.spec {
            return Err(MarshalError::DisallowedClass(class.to_owned()));
        }
        let kind = kind_of(class).ok_or_else(|| MarshalError::DisallowedClass(class.to_owned()))?;
        let len = self.length(1)?;
        let payload = self.take(len)?;
        self.budget.charge(0)?;
        match kind {
            Kind::NestedStream => {
                if payload.len() < 2 || payload[0] != 4 || payload[1] != 8 {
                    return Err(MarshalError::NotAStream);
                }
                // The nested stream has its own tables and the same budgets; depth is cumulative.
                let mut inner = Parser::new(payload, self.budget, false, true)?;
                inner.value(depth + 1)?;
                if inner.pos != inner.input.len() {
                    return Err(MarshalError::TrailingData);
                }
            }
            Kind::Binary8 => {
                if payload.len() != 8 {
                    return Err(MarshalError::WrongPayloadKind(class.to_owned()));
                }
            }
            Kind::InlineObject => return Err(MarshalError::WrongPayloadKind(class.to_owned())),
        }
        if ivars.is_some() {
            // `I` ... ivars of the payload String (its encoding) or of the loaded object.
            let count = self.length(2)?;
            for _ in 0..count {
                self.symbol()?;
                self.value(depth + 1)?;
            }
        }
        self.register(Slot::Marker)?;
        Ok(V::Opaque)
    }
}

/// Validates a quick gemspec stream (LS-F13 B): allow-listed classes, payload kinds,
/// recursion into nested streams and inline objects, cumulative depth, shared budgets.
/// It re-renders nothing; the caller serves the original bytes after `Ok`.
pub fn validate_gemspec(raw: &[u8], limits: Limits) -> Result<(), MarshalError> {
    let mut budget = Budget {
        limits,
        nodes: 0,
        memory: 0,
    };
    let mut parser = Parser::new(raw, &mut budget, false, true)?;
    parser.value(0)?;
    if parser.pos != raw.len() {
        return Err(MarshalError::TrailingData);
    }
    Ok(())
}

/// Memory the last [`filter_tuple_index`] run charged, for the evidence record.
#[derive(Clone, Copy, Debug, Default)]
pub struct FilterStats {
    pub tuples: u64,
    pub kept: u64,
    pub nodes: u64,
    pub charged_bytes: u64,
}

/// LS-F13 A. `keep(name, version, platform)` decides each tuple. A stream that is not an
/// array of `[String, Gem::Version, String]` tuples refuses; it is never passed through.
pub fn filter_tuple_index(
    raw: &[u8],
    limits: Limits,
    mut keep: impl FnMut(&str, &str, &str) -> bool,
) -> Result<(Vec<u8>, FilterStats), MarshalError> {
    let mut budget = Budget {
        limits,
        nodes: 0,
        memory: 0,
    };
    let mut parser = Parser::new(raw, &mut budget, true, false)?;
    parser.budget.node()?;
    if parser.byte()? != b'[' {
        return Err(MarshalError::Shape("the index is not an array"));
    }
    let total = parser.length(1)?;
    parser.register(Slot::Marker)?; // the top array is object 0
    let mut writer = Writer::new();
    let mut kept: u64 = 0;
    for _ in 0..total {
        let tuple = parser.value(1)?;
        let (name, version, platform) = tuple_parts(&tuple)?;
        let (n, v, p) = (
            text(name)?,
            text(version_string(version)?)?,
            text(platform)?,
        );
        if keep(n, v, p) {
            writer.tuple(name, version, platform);
            kept += 1;
        }
        // The output buffer counts against the same budget as it grows.
        let used = writer.body.len() as u64;
        if used > writer.charged {
            let delta = used - writer.charged;
            writer.charged = used;
            parser.budget.charge(delta)?;
        }
    }
    if parser.pos != raw.len() {
        return Err(MarshalError::TrailingData);
    }
    let stats = FilterStats {
        tuples: total as u64,
        kept,
        nodes: parser.budget.nodes,
        charged_bytes: parser.budget.memory,
    };
    Ok((writer.finish(kept), stats))
}

fn text(s: &Str) -> Result<&str, MarshalError> {
    std::str::from_utf8(&s.bytes)
        .map_err(|_| MarshalError::Shape("a name, version or platform is not UTF-8"))
}

fn version_string(v: &Rc<V>) -> Result<&Str, MarshalError> {
    match &**v {
        V::Array(items) => match items.first() {
            Some(V::Str(s)) => Ok(s),
            _ => Err(MarshalError::Shape("Gem::Version payload")),
        },
        _ => Err(MarshalError::Shape("Gem::Version payload")),
    }
}

type TupleParts<'a> = (&'a Rc<Str>, &'a Rc<V>, &'a Rc<Str>);

fn tuple_parts(tuple: &V) -> Result<TupleParts<'_>, MarshalError> {
    let V::Array(items) = tuple else {
        return Err(MarshalError::Shape("an index entry is not an array"));
    };
    match items.as_slice() {
        [V::Str(name), V::Version(version), V::Str(platform)] => Ok((name, version, platform)),
        _ => Err(MarshalError::Shape(
            "an index entry is not [name, Gem::Version, platform]",
        )),
    }
}

/// Renders typed tuples as Marshal 4.8, sharing a String or version already written the
/// way the input shared it (Ruby loads shared objects as one).
struct Writer {
    body: Vec<u8>,
    charged: u64,
    symbols: HashMap<String, usize>,
    objects: usize,
    written: HashMap<usize, usize>,
}

impl Writer {
    fn new() -> Writer {
        Writer {
            body: Vec::new(),
            charged: 0,
            symbols: HashMap::new(),
            objects: 1,
            written: HashMap::new(),
        }
    }

    fn long(out: &mut Vec<u8>, n: i64) {
        match n {
            0 => out.push(0),
            1..=122 => out.push((n + 5) as u8),
            -123..=-1 => out.push(((n - 5) as i8) as u8),
            _ => {
                let mut bytes = [0u8; 8];
                let mut x = n;
                let mut len = 0;
                for slot in bytes.iter_mut().take(4) {
                    *slot = (x & 0xff) as u8;
                    x >>= 8;
                    len += 1;
                    if x == 0 || x == -1 {
                        break;
                    }
                }
                out.push(if n < 0 {
                    (-(len as i8)) as u8
                } else {
                    len as u8
                });
                out.extend_from_slice(&bytes[..len]);
            }
        }
    }

    fn symbol(&mut self, name: &str) {
        if let Some(index) = self.symbols.get(name) {
            self.body.push(b';');
            Self::long(&mut self.body, *index as i64);
        } else {
            let index = self.symbols.len();
            self.symbols.insert(name.to_owned(), index);
            self.body.push(b':');
            Self::long(&mut self.body, name.len() as i64);
            self.body.extend_from_slice(name.as_bytes());
        }
    }

    fn string(&mut self, s: &Rc<Str>) {
        let key = Rc::as_ptr(s) as usize;
        if let Some(index) = self.written.get(&key) {
            self.body.push(b'@');
            Self::long(&mut self.body, *index as i64);
            return;
        }
        self.written.insert(key, self.objects);
        self.objects += 1;
        let ivars = !matches!(s.enc, Enc::Binary);
        if ivars {
            self.body.push(b'I');
        }
        self.body.push(b'"');
        Self::long(&mut self.body, s.bytes.len() as i64);
        self.body.extend_from_slice(&s.bytes);
        match &s.enc {
            Enc::Binary => {}
            Enc::Utf8 | Enc::UsAscii => {
                Self::long(&mut self.body, 1);
                self.symbol("E");
                self.body.push(if s.enc == Enc::Utf8 { b'T' } else { b'F' });
            }
            Enc::Named(name) => {
                Self::long(&mut self.body, 1);
                self.symbol("encoding");
                self.objects += 1; // the encoding name is a String object of its own
                self.body.push(b'"');
                Self::long(&mut self.body, name.len() as i64);
                self.body.extend_from_slice(name);
            }
        }
    }

    fn tuple(&mut self, name: &Rc<Str>, version: &Rc<V>, platform: &Rc<Str>) {
        self.body.push(b'[');
        Self::long(&mut self.body, 3);
        self.objects += 1; // the tuple array
        self.string(name);
        let key = Rc::as_ptr(version) as usize;
        if let Some(index) = self.written.get(&key) {
            self.body.push(b'@');
            Self::long(&mut self.body, *index as i64);
        } else {
            self.written.insert(key, self.objects);
            self.objects += 2; // the user-marshal object and its payload array
            self.body.push(b'U');
            self.symbol("Gem::Version");
            self.body.push(b'[');
            Self::long(&mut self.body, 1);
            if let V::Array(items) = &**version
                && let Some(V::Str(s)) = items.first()
            {
                self.string(s);
            }
        }
        self.string(platform);
    }

    fn finish(self, kept: u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.body.len() + 16);
        out.extend_from_slice(&[4, 8, b'[']);
        Self::long(&mut out, kept as i64);
        out.extend_from_slice(&self.body);
        out
    }
}
