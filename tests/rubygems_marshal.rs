//! Row 17, LS-F13/LS-F7: the bounded Marshal codec and the compressed-input caps.
//! Fixtures under tests/fixtures/rubygems are real: quick gemspecs fetched from
//! rubygems.org and a slice of its live full index re-dumped by Ruby 3.3.

use std::io::Write;

use probation::rubygems::inflate::{self, InflateError};
use probation::rubygems::marshal::{Limits, MarshalError, filter_tuple_index, validate_gemspec};

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/tests/fixtures/rubygems/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

fn gemspecs() -> Vec<(String, Vec<u8>)> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(format!("{}/tests/fixtures/rubygems", env!("CARGO_MANIFEST_DIR"))).unwrap() {
        let name = entry.unwrap().file_name().into_string().unwrap();
        if name.ends_with(".gemspec.rz") {
            let raw = inflate::inflate(&fixture(&name), true, inflate::GEMSPEC_CAP).unwrap();
            found.push((name, raw));
        }
    }
    assert!(found.len() >= 5);
    found
}

// ---- a tiny Marshal builder for hostile and edge streams ----

#[derive(Default)]
struct M(Vec<u8>);

impl M {
    fn new() -> M {
        M(vec![4, 8])
    }
    fn raw(mut self, bytes: &[u8]) -> M {
        self.0.extend_from_slice(bytes);
        self
    }
    fn long(mut self, n: i64) -> M {
        match n {
            0 => self.0.push(0),
            1..=122 => self.0.push((n + 5) as u8),
            -123..=-1 => self.0.push((n - 5) as u8),
            _ => {
                let bytes = (n as u32).to_le_bytes();
                let len = if n < 1 << 8 { 1 } else if n < 1 << 16 { 2 } else if n < 1 << 24 { 3 } else { 4 };
                self.0.push(len as u8);
                self.0.extend_from_slice(&bytes[..len]);
            }
        }
        self
    }
    fn sym(self, name: &str) -> M {
        self.raw(b":").long(name.len() as i64).raw(name.as_bytes())
    }
    fn nil(self) -> M {
        self.raw(b"0")
    }
    fn utf8(self, text: &str) -> M {
        self.raw(b"I\"").long(text.len() as i64).raw(text.as_bytes()).long(1).sym("E").raw(b"T")
    }
    fn array(self, n: i64) -> M {
        self.raw(b"[").long(n)
    }
    fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

/// `Gem::Version` as Ruby dumps it: `U:Gem::Version[ "1.0" ]`.
fn version(m: M, text: &str) -> M {
    m.raw(b"U").sym("Gem::Version").array(1).utf8(text)
}

fn tuple(m: M, name: &str, ver: &str, platform: &str) -> M {
    let m = m.array(3).utf8(name);
    version(m, ver).utf8(platform)
}

fn index(tuples: &[(&str, &str, &str)]) -> Vec<u8> {
    let mut m = M::new().array(tuples.len() as i64);
    for (n, v, p) in tuples {
        m = tuple(m, n, v, p);
    }
    m.into_bytes()
}

fn keep_all(_: &str, _: &str, _: &str) -> bool {
    true
}

const TUPLE: Limits = Limits::TUPLE_INDEX;
const SPEC: Limits = Limits::GEMSPEC;

/// A `Gem::Specification` user-defined object whose String payload is `nested`.
fn spec_around(nested: &[u8]) -> Vec<u8> {
    let m = M::new().raw(b"I").raw(b"u").sym("Gem::Specification").long(nested.len() as i64).raw(nested);
    m.long(1).sym("E").raw(b"F").into_bytes()
}

// ---------------------------------------------------------------- real fixtures

#[test]
fn quick_gemspec_real_fixtures_validate() {
    for (name, raw) in gemspecs() {
        validate_gemspec(&raw, SPEC).unwrap_or_else(|e| panic!("{name}: {e}"));
    }
}

/// The real-client witness at codec level: Ruby 3.3 itself loads what the filter rendered.
#[test]
fn marshal_filter_real_slice_is_loaded_by_ruby_with_the_denied_tuples_gone() {
    let raw = inflate::inflate(&fixture("full-index-slice.4.8.gz"), false, inflate::TUPLE_INDEX_CAP).unwrap();
    let (out, stats) = filter_tuple_index(&raw, TUPLE, |name, version, platform| !(name == "rack" || (name == "rake" && version.starts_with("13")) || platform.contains("mswin"))).unwrap();
    assert!(stats.kept < stats.tuples && stats.kept > 1000, "{stats:?}");
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("in.marshal"), &raw).unwrap();
    std::fs::write(dir.path().join("out.marshal"), &out).unwrap();
    let script = r#"
      require 'rubygems'
      load = ->(f) { Marshal.load(File.binread(f)).map { |n, v, p| [n, v.to_s, p] } }
      a = load.(ARGV[0]); b = load.(ARGV[1])
      expected = a.reject { |n, v, p| n == "rack" || (n == "rake" && v.start_with?("13")) || p.include?("mswin") }
      abort "mismatch: #{expected.size} vs #{b.size}" unless expected == b
      puts "ok #{b.size}"
    "#;
    let result = std::process::Command::new("ruby")
        .args(["-e", script, "--"])
        .arg(dir.path().join("in.marshal"))
        .arg(dir.path().join("out.marshal"))
        .output()
        .expect("ruby 3.x is the native baseline of this row");
    assert!(result.status.success(), "{}{}", String::from_utf8_lossy(&result.stdout), String::from_utf8_lossy(&result.stderr));
}

#[test]
fn marshal_filter_keeping_everything_preserves_every_tuple() {
    let raw = inflate::inflate(&fixture("full-index-slice.4.8.gz"), false, inflate::TUPLE_INDEX_CAP).unwrap();
    let (out, stats) = filter_tuple_index(&raw, TUPLE, keep_all).unwrap();
    assert_eq!(stats.kept, stats.tuples);
    // Ruby wrote the input canonically, so re-rendering with the same sharing is byte-identical.
    assert_eq!(out, raw, "sharing and numbering are preserved");
}

// ---------------------------------------------------------------- filter contract

#[test]
fn marshal_filter_output_is_rerendered_not_spliced() {
    // The array length is written as a 1-byte positive long (`\x01\x02`) instead of the
    // canonical `\x07`; a splice would keep it, a re-render canonicalises it.
    let mut raw = vec![4, 8, b'[', 1, 2];
    raw.extend(tuple(M::default(), "a", "1.0", "ruby").into_bytes());
    raw.extend(tuple(M::default(), "b", "2.0", "ruby").into_bytes());
    let (out, _) = filter_tuple_index(&raw, TUPLE, |n, _, _| n == "b").unwrap();
    assert_ne!(out, raw);
    assert_eq!(&out[..4], &[4, 8, b'[', 6], "a canonical one-entry length");
    assert!(!out.windows(1).any(|w| w == b"a") || out[4..].iter().filter(|b| **b == b'a').count() == 0, "the dropped tuple's name is gone");
    let (again, stats) = filter_tuple_index(&out, TUPLE, keep_all).unwrap();
    assert_eq!((again, stats.kept), (out, 1));
}

#[test]
fn marshal_filter_refuses_unknown_type_tag() {
    for (label, body) in [
        ("float", M::new().array(1).raw(b"f").long(3).raw(b"1.5")),
        ("regexp", M::new().array(1).raw(b"/").long(1).raw(b"a").raw(&[0])),
        ("struct", M::new().array(1).raw(b"S").sym("Evil").long(0)),
        ("extended", M::new().array(1).raw(b"e").sym("Kernel").nil()),
        ("class", M::new().array(1).raw(b"c").long(6).raw(b"Kernel")),
        ("hash with default", M::new().array(1).raw(b"}").long(0).nil()),
        ("user class", M::new().array(1).raw(b"C").sym("X").raw(b"\"").long(0)),
        ("data", M::new().array(1).raw(b"d").sym("X").nil()),
    ] {
        let err = filter_tuple_index(&body.into_bytes(), TUPLE, keep_all).unwrap_err();
        assert!(matches!(err, MarshalError::UnknownTypeTag(_)), "{label}: {err:?}");
    }
    // A tag in the allow-list, in a place a tuple cannot hold, is a shape refusal, not a pass-through.
    let err = filter_tuple_index(&M::new().array(1).raw(b"T").into_bytes(), TUPLE, keep_all).unwrap_err();
    assert!(matches!(err, MarshalError::Shape(_)), "{err:?}");
}

#[test]
fn marshal_filter_refuses_other_classes_and_malformed_shapes() {
    let hostile = M::new().array(1).array(3).utf8("a").raw(b"o").sym("Kernel").long(0).utf8("ruby").into_bytes();
    assert!(matches!(filter_tuple_index(&hostile, TUPLE, keep_all), Err(MarshalError::DisallowedClass(c)) if c == "Kernel"));
    // Gem::Requirement is allow-listed for gemspecs only; a tuple index has no place for it.
    let req = M::new().array(1).array(3).utf8("a").raw(b"o").sym("Gem::Requirement").long(0).utf8("ruby").into_bytes();
    assert!(matches!(filter_tuple_index(&req, TUPLE, keep_all), Err(MarshalError::DisallowedClass(_))));
    // Not an array, a tuple of two, a tuple whose version is a plain String.
    assert!(filter_tuple_index(&M::new().nil().into_bytes(), TUPLE, keep_all).is_err());
    let short = M::new().array(1).array(2).utf8("a").utf8("b").into_bytes();
    assert!(matches!(filter_tuple_index(&short, TUPLE, keep_all), Err(MarshalError::Shape(_))));
    let plain = M::new().array(1).array(3).utf8("a").utf8("1.0").utf8("ruby").into_bytes();
    assert!(matches!(filter_tuple_index(&plain, TUPLE, keep_all), Err(MarshalError::Shape(_))));
    // Trailing bytes and every truncation of a valid stream refuse; nothing is passed through.
    let valid = index(&[("a", "1.0", "ruby"), ("b", "2.0", "java")]);
    let mut trailing = valid.clone();
    trailing.push(0);
    assert_eq!(filter_tuple_index(&trailing, TUPLE, keep_all).unwrap_err(), MarshalError::TrailingData);
    for cut in 0..valid.len() {
        assert!(filter_tuple_index(&valid[..cut], TUPLE, keep_all).is_err(), "prefix of {cut} bytes");
    }
    assert_eq!(filter_tuple_index(&[1, 2, 3], TUPLE, keep_all).unwrap_err(), MarshalError::BadHeader);
}

#[test]
fn marshal_filter_depth_and_object_caps() {
    // 40 nested arrays inside a tuple slot refuse at depth 32 before any tuple check.
    let mut m = M::new().array(1).array(3);
    for _ in 0..40 {
        m = m.array(1);
    }
    assert_eq!(filter_tuple_index(&m.nil().into_bytes(), TUPLE, keep_all).unwrap_err(), MarshalError::Depth);
    // Node cap: three tuples are well over 10 nodes.
    let three = index(&[("a", "1", "ruby"), ("b", "1", "ruby"), ("c", "1", "ruby")]);
    let tight = Limits { max_nodes: 10, ..TUPLE };
    assert_eq!(filter_tuple_index(&three, tight, keep_all).unwrap_err(), MarshalError::Nodes);
    // And the real bounds hold the documented values.
    assert_eq!((TUPLE.max_depth, TUPLE.max_nodes, TUPLE.memory_budget), (32, 20_000_000, 512 << 20));
    assert_eq!((SPEC.max_depth, SPEC.max_nodes, SPEC.memory_budget), (32, 1_000_000, 64 << 20));
}

#[test]
fn marshal_filter_memory_budget_refuses() {
    let raw = index(&[("a-long-enough-gem-name", "1.0.0", "ruby"), ("b-long-enough-gem-name", "2.0.0", "ruby")]);
    let tiny = Limits { memory_budget: 200, ..TUPLE };
    assert_eq!(filter_tuple_index(&raw, tiny, keep_all).unwrap_err(), MarshalError::Memory);
    assert!(filter_tuple_index(&raw, TUPLE, keep_all).is_ok());
}

#[test]
fn marshal_filter_bad_link_refused() {
    // A link to an object index that has not been seen.
    let forward = M::new().array(1).array(3).raw(b"@").long(9).nil().nil().into_bytes();
    assert_eq!(filter_tuple_index(&forward, TUPLE, keep_all).unwrap_err(), MarshalError::BadLink);
    // A link to a container, which a typed re-render cannot share.
    let to_array = M::new().array(2).array(3).utf8("a").raw(b"@").long(1).into_bytes();
    assert_eq!(filter_tuple_index(&to_array, TUPLE, keep_all).unwrap_err(), MarshalError::BadLink);
    // A symbol link past the table.
    let symlink = M::new().array(1).array(3).raw(b"I\"").long(1).raw(b"a").long(1).raw(b";").long(5).raw(b"T").into_bytes();
    assert_eq!(filter_tuple_index(&symlink, TUPLE, keep_all).unwrap_err(), MarshalError::BadSymbolLink);
}

/// A declared length of 2^30 in a tiny stream must allocate nothing up front and refuse at
/// once as truncated, not as a memory overrun after a huge allocation.
#[test]
fn marshal_filter_length_prefix_no_prealloc() {
    let huge = M::new().raw(b"[").raw(&[4, 0, 0, 0, 0x40]).into_bytes(); // 2^30 as a 4-byte long
    let started = std::time::Instant::now();
    assert_eq!(filter_tuple_index(&huge, TUPLE, keep_all).unwrap_err(), MarshalError::Truncated);
    let nested = M::new().array(1).raw(b"[").raw(&[4, 0, 0, 0, 0x40]).into_bytes();
    assert_eq!(filter_tuple_index(&nested, TUPLE, keep_all).unwrap_err(), MarshalError::Truncated);
    let string = M::new().array(1).array(3).raw(b"\"").raw(&[4, 0, 0, 0, 0x40]).into_bytes();
    assert_eq!(filter_tuple_index(&string, TUPLE, keep_all).unwrap_err(), MarshalError::Truncated);
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
    assert_eq!(validate_gemspec(&huge, SPEC).unwrap_err(), MarshalError::Truncated);
}

#[test]
fn marshal_filter_symbol_and_link_tables_count_against_budget() {
    // The tuple reader refuses a long container before it reads a child (below), so the tables
    // are exercised through the gemspec reader, which shares the parser and the budget.
    // Many distinct symbols: the symbol table is charged (name bytes plus a slot each, ~160 KB).
    let mut m = M::new().array(2000);
    for i in 0..2000 {
        m = m.sym(&format!("symbol-number-{i}"));
    }
    let symbols = m.into_bytes();
    let limits = Limits { memory_budget: 140_000, ..SPEC };
    assert_eq!(validate_gemspec(&symbols, limits).unwrap_err(), MarshalError::Memory);
    validate_gemspec(&symbols, SPEC).expect("within the real bound");
    // Object (link) table slots are charged too: 2000 empty arrays hold 2000 slots and nothing else.
    let mut m = M::new().array(2000);
    for _ in 0..2000 {
        m = m.array(0);
    }
    let arrays = m.into_bytes();
    let limits = Limits { memory_budget: 50_000, ..SPEC };
    assert_eq!(validate_gemspec(&arrays, limits).unwrap_err(), MarshalError::Memory);
    validate_gemspec(&arrays, SPEC).expect("within the real bound");
}

// ---------------------------------------------------------------- quick gemspec contract

#[test]
fn quick_gemspec_hostile_class_refused() {
    for class in ["Kernel", "Gem::Installer", "Gem::StubSpecification", "Gem::Package::TarReader", "Object", "Gem::Command"] {
        let raw = M::new().raw(b"o").sym(class).long(0).into_bytes();
        assert!(matches!(validate_gemspec(&raw, SPEC), Err(MarshalError::DisallowedClass(c)) if c == class), "{class}");
        let u = M::new().raw(b"U").sym(class).nil().into_bytes();
        assert!(matches!(validate_gemspec(&u, SPEC), Err(MarshalError::DisallowedClass(_))), "{class} as user-marshal");
    }
}

/// The class is placed only inside the nested Gem::Specification stream, where an
/// outer-only scan would never see it.
#[test]
fn quick_gemspec_hostile_class_in_nested_stream_refused() {
    let nested = M::new().array(1).raw(b"o").sym("Gem::Installer").long(0).into_bytes();
    assert!(matches!(validate_gemspec(&spec_around(&nested), SPEC), Err(MarshalError::DisallowedClass(c)) if c == "Gem::Installer"));
    let clean = M::new().array(2).utf8("name").nil().into_bytes();
    validate_gemspec(&spec_around(&clean), SPEC).expect("a clean nested stream passes");
    // Inside an inline object of the nested stream as well.
    let deep = M::new().array(1).raw(b"o").sym("Gem::Requirement").long(1).sym("@requirements").array(1).raw(b"o").sym("Kernel").long(0).into_bytes();
    assert!(matches!(validate_gemspec(&spec_around(&deep), SPEC), Err(MarshalError::DisallowedClass(c)) if c == "Kernel"));
}

#[test]
fn quick_gemspec_nested_payload_counts_against_budgets() {
    let mut nested = M::new().array(3000);
    for _ in 0..3000 {
        nested = nested.nil();
    }
    let raw = spec_around(&nested.into_bytes());
    let mut strings = M::new().array(3000);
    for _ in 0..3000 {
        strings = strings.raw(b"\"").long(2).raw(b"ab");
    }
    let retained = spec_around(&strings.into_bytes());
    let nodes = Limits { max_nodes: 1000, ..SPEC };
    assert_eq!(validate_gemspec(&raw, nodes).unwrap_err(), MarshalError::Nodes, "nested nodes share the outer budget");
    // 3000 retained strings cost about 3000 * (32 + 2) B, over this budget, in the NESTED stream.
    let memory = Limits { memory_budget: 20_000, ..SPEC };
    assert_eq!(validate_gemspec(&retained, memory).unwrap_err(), MarshalError::Memory, "nested memory shares the outer budget");
    validate_gemspec(&raw, SPEC).expect("within the real bounds");
    validate_gemspec(&retained, SPEC).expect("within the real bounds");
}

#[test]
fn quick_gemspec_time_payload_not_parsed_as_stream() {
    // Eight binary bytes that look like the start of a stream naming a forbidden class.
    let looks_like_stream = [4u8, 8, b'o', b':', 5, b'E', b'v', b'i'];
    let time = |payload: &[u8]| {
        M::new().raw(b"I").raw(b"u").sym("Time").long(payload.len() as i64).raw(payload).long(1).sym("offset").raw(b"i").long(0).into_bytes()
    };
    validate_gemspec(&time(&looks_like_stream), SPEC).expect("Time is Binary8, never parsed as a stream");
    for wrong in [&looks_like_stream[..7], &[0u8; 9][..], &[][..]] {
        assert!(matches!(validate_gemspec(&time(wrong), SPEC), Err(MarshalError::WrongPayloadKind(_))), "{} bytes", wrong.len());
    }
}

#[test]
fn quick_gemspec_nested_depth_is_cumulative() {
    let chain = |levels: usize, leaf: M| {
        let mut m = M::new().array(1);
        for _ in 1..levels {
            m = m.array(1);
        }
        leaf_into(m, leaf).into_bytes()
    };
    fn leaf_into(m: M, leaf: M) -> M {
        m.raw(&leaf.0)
    }
    // 20 levels alone pass; 20 outer plus a nested stream of 20 exceeds 32 in total.
    let twenty = chain(20, M::default().nil());
    validate_gemspec(&twenty, SPEC).expect("20 deep alone");
    let nested = chain(20, M::default().nil());
    let outer = {
        let mut m = M::new();
        for _ in 0..20 {
            m = m.array(1);
        }
        m.raw(b"I").raw(b"u").sym("Gem::Specification").long(nested.len() as i64).raw(&nested).long(1).sym("E").raw(b"F").into_bytes()
    };
    assert_eq!(validate_gemspec(&outer, SPEC).unwrap_err(), MarshalError::Depth);
    // The same shape with a shallow outer passes.
    let shallow = {
        let mut m = M::new();
        for _ in 0..5 {
            m = m.array(1);
        }
        m.raw(b"I").raw(b"u").sym("Gem::Specification").long(nested.len() as i64).raw(&nested).long(1).sym("E").raw(b"F").into_bytes()
    };
    validate_gemspec(&shallow, SPEC).expect("5 outer + 20 nested");
}

#[test]
fn quick_gemspec_nested_header_and_tables_checked() {
    // No Marshal 4.8 header on the nested payload.
    let headerless = [b'[', 6, b'0'];
    let raw = M::new().raw(b"I").raw(b"u").sym("Gem::Specification").long(3).raw(&headerless).long(1).sym("E").raw(b"F").into_bytes();
    assert_eq!(validate_gemspec(&raw, SPEC).unwrap_err(), MarshalError::NotAStream);
    // The nested stream has its own symbol table: a symlink to the outer table's index is bad.
    let outer_symbol = M::new().array(2).sym("outer").raw(&[b'[', 6, b';', 5]);
    let nested = M::new().array(1).raw(b";").long(0).into_bytes();
    let _ = outer_symbol;
    assert_eq!(validate_gemspec(&spec_around(&nested), SPEC).unwrap_err(), MarshalError::BadSymbolLink);
    // And its own object table: a link to an index only the outer stream has.
    let nested_link = M::new().array(1).raw(b"@").long(7).into_bytes();
    assert_eq!(validate_gemspec(&spec_around(&nested_link), SPEC).unwrap_err(), MarshalError::BadLink);
    // Trailing bytes inside the nested stream refuse.
    let mut padded = M::new().array(0).into_bytes();
    padded.push(0);
    assert_eq!(validate_gemspec(&spec_around(&padded), SPEC).unwrap_err(), MarshalError::TrailingData);
}

#[test]
fn quick_gemspec_non_stream_payload_refused() {
    // The payload of Gem::Specification must be a stream; the other kinds refuse in the wrong form.
    let junk = M::new().raw(b"u").sym("Gem::Specification").long(4).raw(b"junk").into_bytes();
    assert_eq!(validate_gemspec(&junk, SPEC).unwrap_err(), MarshalError::NotAStream);
    let requirement_as_u = M::new().raw(b"u").sym("Gem::Requirement").long(2).raw(&[4, 8]).into_bytes();
    assert!(matches!(validate_gemspec(&requirement_as_u, SPEC), Err(MarshalError::WrongPayloadKind(_))));
    let time_as_o = M::new().raw(b"o").sym("Time").long(0).into_bytes();
    assert!(matches!(validate_gemspec(&time_as_o, SPEC), Err(MarshalError::WrongPayloadKind(_))));
    let spec_as_o = M::new().raw(b"o").sym("Gem::Specification").long(0).into_bytes();
    assert!(matches!(validate_gemspec(&spec_as_o, SPEC), Err(MarshalError::WrongPayloadKind(_))));
    let unknown_u = M::new().raw(b"u").sym("Gem::Nothing").long(0).into_bytes();
    assert!(matches!(validate_gemspec(&unknown_u, SPEC), Err(MarshalError::DisallowedClass(_))));
}

#[test]
fn quick_gemspec_bounds_and_memory_budget() {
    // Depth 32 passes and 33 refuses for a plain nested array.
    let at = |levels: usize| {
        let mut m = M::new();
        for _ in 0..levels {
            m = m.array(1);
        }
        m.nil().into_bytes()
    };
    validate_gemspec(&at(31), SPEC).expect("depth 32");
    assert_eq!(validate_gemspec(&at(40), SPEC).unwrap_err(), MarshalError::Depth);
    // Platform forms named up front: Gem::Platform object and the plain string form.
    let platform = M::new().array(2).raw(b"o").sym("Gem::Platform").long(2).sym("@cpu").utf8("x86_64").sym("@os").utf8("linux");
    validate_gemspec(&platform.utf8("ruby").into_bytes(), SPEC).expect("Gem::Platform and the string form");
    // A huge String is bounded by the budget rather than the 4 MiB inflate cap alone.
    let big = M::new().raw(b"\"").long(5000).raw(&vec![b'a'; 5000]).into_bytes();
    assert_eq!(validate_gemspec(&big, Limits { memory_budget: 1000, ..SPEC }).unwrap_err(), MarshalError::Memory);
}

// ---------------------------------------------------------------- compressed inputs (LS-F7)

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gz.write_all(data).unwrap();
    gz.finish().unwrap()
}

#[test]
fn gzip_ratio_and_size_cap_refuse_bomb() {
    // 300 MiB of zeros is about 300 KiB compressed: over 100:1 after the first MiB.
    let bomb = gzip(&vec![0u8; 300 * 1024 * 1024]);
    assert_eq!(inflate::inflate(&bomb, false, inflate::TUPLE_INDEX_CAP).unwrap_err(), InflateError::Ratio);
    // Size cap: incompressible data just over the cap refuses with the size error, at the cap passes.
    let mut seed = 0x9E3779B97F4A7C15u64;
    let noise: Vec<u8> = (0..(4 * 1024 * 1024 + 1)).map(|_| { seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17; (seed >> 24) as u8 }).collect();
    let over = gzip(&noise);
    assert_eq!(inflate::inflate(&over, false, inflate::GEMSPEC_CAP).unwrap_err(), InflateError::TooLarge);
    let at = gzip(&noise[..4 * 1024 * 1024]);
    assert_eq!(inflate::inflate(&at, false, inflate::GEMSPEC_CAP).unwrap().len(), 4 * 1024 * 1024);
    // Concatenated members are inflated as one; bytes after the last member are refused.
    let two = [gzip(b"abc"), gzip(b"def")].concat();
    assert_eq!(inflate::inflate(&two, false, 1024).unwrap(), b"abcdef");
    let mut trailing = gzip(b"abc");
    trailing.extend_from_slice(b"garbage");
    assert_eq!(inflate::inflate(&trailing, false, 1024).unwrap_err(), InflateError::Malformed);
    assert_eq!(inflate::inflate(b"not gzip at all", false, 1024).unwrap_err(), InflateError::Malformed);
    // zlib (quick gemspecs) shares the rule.
    let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
    z.write_all(&noise).unwrap();
    assert_eq!(inflate::inflate(&z.finish().unwrap(), true, inflate::GEMSPEC_CAP).unwrap_err(), InflateError::TooLarge);
    let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
    z.write_all(&vec![0u8; 8 * 1024 * 1024]).unwrap();
    assert_eq!(inflate::inflate(&z.finish().unwrap(), true, inflate::GEMSPEC_CAP).unwrap_err(), InflateError::Ratio, "ratio wins when both apply");
    assert_eq!(inflate::inflate(&[0x78, 0x9c, 1, 2, 3], true, 1024).unwrap_err(), InflateError::Malformed);
    // Bytes after the zlib stream are refused as after the last gzip member (CR F3, SR17-3).
    let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
    z.write_all(b"quick gemspec").unwrap();
    let valid = z.finish().unwrap();
    assert_eq!(inflate::inflate(&valid, true, 1024).unwrap(), b"quick gemspec");
    for tail in [&b"x"[..], &[0u8; 16][..], &vec![7u8; 40_000][..]] {
        let mut padded = valid.clone();
        padded.extend_from_slice(tail);
        assert_eq!(inflate::inflate(&padded, true, 1024).unwrap_err(), InflateError::Malformed, "{} trailing bytes", tail.len());
    }
}

// ---------------------------------------------------------------- real-corpus measurement

/// Measurement and allow-list check against a local corpus of real RubyGems files (not
/// committed: the full index is 6 MB compressed). Run with
/// `PROBATION_RUBYGEMS_CORPUS=<dir> cargo test --test rubygems_marshal -- --ignored --nocapture`
/// where `<dir>` holds `specs.gz`, `latest.gz`, `pre.gz` and `corpus/*.gemspec.rz`.
#[test]
#[ignore = "measurement against a local corpus of real rubygems.org files"]
fn real_corpus_measurement() {
    let dir = std::path::PathBuf::from(std::env::var("PROBATION_RUBYGEMS_CORPUS").expect("PROBATION_RUBYGEMS_CORPUS"));
    let mut refused = Vec::new();
    let mut count = 0;
    for entry in std::fs::read_dir(dir.join("corpus")).unwrap() {
        let path = entry.unwrap().path();
        if path.file_name().unwrap().to_string_lossy().starts_with("info-") {
            // Real compact-index files (CR U3): one malformed-looking line would 502 a whole gem.
            let text = std::fs::read(&path).unwrap();
            let entries = probation::rubygems::info::parse_info(&text, 1_000_000).unwrap_or_else(|e| panic!("{path:?}: {e:?}"));
            println!("{:?}: {} lines parsed, {} dated, {} checksummed", path.file_name().unwrap(), entries.len(), entries.iter().filter(|e| e.created_micros.is_some()).count(), entries.iter().filter(|e| e.sha256.is_some()).count());
            continue;
        }
        let compressed = std::fs::read(&path).unwrap();
        let raw = inflate::inflate(&compressed, true, inflate::GEMSPEC_CAP).unwrap();
        count += 1;
        if let Err(err) = validate_gemspec(&raw, SPEC) {
            refused.push((path.file_name().unwrap().to_owned(), err));
        }
    }
    println!("gemspecs validated: {count}, refused: {refused:?}");
    assert!(refused.is_empty(), "a valid real gemspec was refused: widen the allow-list with a stated reason");
    for name in ["specs.gz", "latest.gz", "pre.gz"] {
        let compressed = std::fs::read(dir.join(name)).unwrap();
        let raw = inflate::inflate(&compressed, false, inflate::TUPLE_INDEX_CAP).unwrap();
        let started = std::time::Instant::now();
        let (out, stats) = filter_tuple_index(&raw, TUPLE, |n, _, _| n != "rack").unwrap();
        println!(
            "{name}: compressed {} B, inflated {} B (ratio {:.1}:1), tuples {}, kept {}, nodes {}, charged {} B, output {} B, {:?}",
            compressed.len(), raw.len(), raw.len() as f64 / compressed.len() as f64, stats.tuples, stats.kept, stats.nodes, stats.charged_bytes, out.len(), started.elapsed()
        );
    }
}

// ---------------------------------------------------------------- in-flight memory (SR17-2b, CR F6)

/// A container of millions of small items inside a tuple slot is refused as soon as its length
/// is read, before one child is collected (no `Vec` of children grows while the charge stays
/// near zero), and the same holds for a hash.
#[test]
fn marshal_filter_refuses_oversized_in_flight_containers_before_collecting_children() {
    let ints = |n: usize| {
        let mut m = M::new().array(1).array(3).raw(b"[").long(n as i64);
        for _ in 0..n {
            m = m.raw(b"i").long(1);
        }
        m.into_bytes()
    };
    let started = std::time::Instant::now();
    let err = filter_tuple_index(&ints(200_000), TUPLE, keep_all).unwrap_err();
    assert!(matches!(err, MarshalError::Shape(_)), "{err:?}");
    // The tuple budget decides before the children are read: a tiny budget sees no growth either.
    let tiny = Limits { memory_budget: 4096, ..TUPLE };
    assert!(matches!(filter_tuple_index(&ints(200_000), tiny, keep_all).unwrap_err(), MarshalError::Shape(_) | MarshalError::Memory));
    let mut hash = M::new().array(1).array(3).raw(b"{").long(100_000);
    for _ in 0..100_000 {
        hash = hash.raw(b"i").long(1).raw(b"i").long(2);
    }
    assert!(matches!(filter_tuple_index(&hash.into_bytes(), TUPLE, keep_all).unwrap_err(), MarshalError::Shape(_)));
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
}

/// Retained values are charged at their real size: 20,000 distinct names of 40 bytes exceed a
/// budget that the old 64-byte nominal charge would have fitted.
#[test]
fn marshal_filter_charges_retained_values_at_real_size() {
    let names: Vec<String> = (0..20_000).map(|i| format!("gem-number-{i:030}")).collect();
    let tuples: Vec<(&str, &str, &str)> = names.iter().map(|n| (n.as_str(), "1.0.0", "ruby")).collect();
    let raw = index(&tuples);
    let (_, stats) = filter_tuple_index(&raw, TUPLE, keep_all).unwrap();
    // 20,000 tuples hold 20,000 names + versions + platform links; real cost is well over 64 B each.
    assert!(stats.charged_bytes > 20_000 * 300, "charged {}", stats.charged_bytes);
    let tight = Limits { memory_budget: stats.charged_bytes / 2, ..TUPLE };
    assert_eq!(filter_tuple_index(&raw, tight, keep_all).unwrap_err(), MarshalError::Memory);
}
