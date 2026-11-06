# Isolated Marshal codec capability probe — PASS (limited scope)

All writes are confined to `.scratch/marshal-codec-probe/`. No product manifest, lockfile, or source changed.

Toolchain actually run: `rustc 1.96.0 (ac68faa20 2026-05-25)` and `cargo 1.96.0 (30a34c682 2026-05-25)`.

Dependency: `marshal-rs = { git = "https://github.com/savannstm/marshal-rs", rev = "100a7edaa8b7c063d40cef67fc63ae2bfdf88714", default-features = false }`. Package version 4.0.1. Its pinned manifest declares Rust 1.81.0 minimum and WTFPL license. This is compile evidence under 1.96.0 only.

Resolved graph (seven packages beyond the probe): marshal-rs 4.0.1, thiserror 2.0.21, thiserror-impl 2.0.21, syn 3.0.9, proc-macro2 1.0.107, quote 1.0.47, unicode-ident 1.0.27. No marshal-rs std/alloc/serde feature or serde dependency enabled. Relative to the proposed baseline thiserror 2.0.20, the manifest requires at least 2.0.21; this standalone lock resolved 2.0.21 plus the listed macro dependencies. The product workspace dependency resolution was not tested or changed.

Fixture: Ruby 3.3.8 (`ruby --disable-gems`) ran only the exact RubyGems pin's `version.rb` and required `deprecate.rb`, loaded from local public-source reference copies. `Marshal.dump` serialized two locally constructed tuples: `["probe", Gem::Version.new("1.0.0"), "ruby"]` and the same identity/platform with version 2.0.0. No Marshal.load was executed. Installed RubyGems 3.6.7 was disabled; this fixture uses the supplied RubyGems pin 8a2a14d63da701e980f856d8772d273fd448b8a1 serializer code. The 82-byte fixture includes UTF-8 string instance-variable wrappers, symbol references, shared name/platform object references, and the Gem::Version user-marshal array payload.

The Rust self-check uses the default-free token Reader, a caller-owned 64-slot symbol table, and fixed-slice Writer. It decoded that genuine fixture; regenerated and decoded both tuples; filtered version 2.0.0; regenerated and decoded the remaining tuple; and asserted older name/version/platform bytes and encoding annotations unchanged. The filtered output is 61 bytes. This is semantic tuple-value preservation; output bytes and Ruby object-reference identity need not match the input.

Actual final output (exit 0):

```text
PASS: pinned codec compiled without default features; genuine pinned-serializer 82-byte fixture decoded; two-tuple semantic roundtrip; denied 2.0.0 removed and older name/version/platform/encoding retained; 82 truncations, trailing bytes, input/tuple bounds, invalid link/schema/tag, fixed output overflow rejected
```

Reproduction from repository root, after public dependencies are cached:

```sh
ruby --disable-gems .scratch/marshal-codec-probe/generate-fixture.rb
TMPDIR="$PWD/.scratch/marshal-codec-probe/tmp" CARGO_HOME="$PWD/.scratch/marshal-codec-probe/cargo-home" CARGO_TARGET_DIR="$PWD/.scratch/marshal-codec-probe/target" cargo run --locked --offline --manifest-path .scratch/marshal-codec-probe/Cargo.toml
```

Initial online bootstrap used the same scratch environment and `cargo build --manifest-path .scratch/marshal-codec-probe/Cargo.toml`; narrow public network escalation was approved. Both source and dependencies are retained in scratch. `validation.log` contains the final offline result. The original bootstrap network-denial log is retained separately as `build.log` and is not the final result.

Bounds belong to the probe schema wrapper: at most 1024 decompressed bytes, eight tuples, 64 ASCII bytes per string, 64 objects, 64 symbols, fixed schema depth; only one `E` boolean encoding ivar, exactly Gem::Version user-marshal containing a one-element string array. The wrapper explicitly rejects unsupported schema/object references and trailing data. The writer uses caller-supplied finite output storage and returns an overflow error when insufficient. Probe encode unwraps after selecting a sufficient fixed buffer; production code must propagate writer errors.

The low-level Reader validates wire header/payload lengths and symbol references, but does not track object identity or count nested children for the caller. It is not itself a bounded tuple-index validator: the application must implement container counts, object tables, schema/type restrictions, limits, full consumption, and errors. The Rust wrapper uses bounded Vec allocations; only the codec token layer is allocation-free.

This is not a production parser. It rejects shared Gem::Version/payload/tuple objects, non-ASCII strings and named encodings rather than claiming full RubyGems format coverage. No gzip decompression/recompression, downloaded upstream index corpus, Ruby-load of regenerated output, RubyGems/Bundler native-client request, HTTP/proxy route, policy integration, fuzzing, workspace dependency graph resolution or production resource-limit calibration was tested. These remain required before claiming end-to-end support.

SHA-256:

- Cargo.lock: d56329eae38484945fd0a814ba74014884cf008bed8a4e9d97ccea75351ff387
- tuple-index.marshal: ae58d9bd68e8d6bc3fefa5cac28853d459c7a2f6a8ec5223c1ea0080eb0ee6ef
- filtered.marshal: 346a4964ffe0ec68304bb10ee6ca2b331d689355728f8962782ebe821f4447ce

Primary sources inspected:

- https://github.com/savannstm/marshal-rs/blob/100a7edaa8b7c063d40cef67fc63ae2bfdf88714/Cargo.toml
- https://github.com/savannstm/marshal-rs/blob/100a7edaa8b7c063d40cef67fc63ae2bfdf88714/src/reader.rs
- https://github.com/savannstm/marshal-rs/blob/100a7edaa8b7c063d40cef67fc63ae2bfdf88714/src/writer.rs
- https://github.com/rubygems/rubygems/blob/8a2a14d63da701e980f856d8772d273fd448b8a1/lib/rubygems/version.rb#L282-L294
- https://github.com/rubygems/rubygems/blob/8a2a14d63da701e980f856d8772d273fd448b8a1/lib/rubygems/deprecate.rb
