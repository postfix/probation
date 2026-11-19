//! The identity forms of the Go proxy protocol. A module path and a version travel in URLs with
//! each upper-case ASCII letter written as `!` and its lower-case letter (`github.com/Azure` is
//! `github.com/!azure`), so a case-insensitive file system or CDN never merges two modules. The
//! policy key is the decoded form; the escaped form is a transport spelling only. Decoding is
//! strict (the rule of `golang.org/x/mod/module.UnescapePath`): there is exactly one escaped
//! spelling of every path, so decode and encode round-trip exactly and a second spelling of one
//! module is a 404 before any upstream call, never a second identity.

use probation_policy::names::valid_go_path;

/// The longest module path and version routed (the LS-F6 bound of the OSV key).
pub const MAX_PATH: usize = 1024;
pub const MAX_VERSION: usize = 256;

/// `!`-escapes a decoded string: `A` becomes `!a`. `None` when it holds a non-ASCII byte or a `!`.
pub fn escape(decoded: &str) -> Option<String> {
    let mut out = String::with_capacity(decoded.len() + 4);
    for c in decoded.chars() {
        match c {
            'A'..='Z' => {
                out.push('!');
                out.push(c.to_ascii_lowercase());
            }
            '!' => return None,
            c if c.is_ascii() => out.push(c),
            _ => return None,
        }
    }
    Some(out)
}

/// The inverse of [`escape`]: `!` must be followed by a lower-case ASCII letter, an upper-case
/// letter is not a valid escaped spelling, and so is any non-ASCII byte.
pub fn unescape(escaped: &str) -> Option<String> {
    let mut out = String::with_capacity(escaped.len());
    let mut bang = false;
    for c in escaped.chars() {
        if !c.is_ascii() {
            return None;
        }
        if bang {
            if !c.is_ascii_lowercase() {
                return None;
            }
            out.push(c.to_ascii_uppercase());
            bang = false;
            continue;
        }
        match c {
            '!' => bang = true,
            'A'..='Z' => return None,
            c => out.push(c),
        }
    }
    (!bang).then_some(out)
}

/// A decoded module path a proxy could serve: LS-F6 charset and element rules, bounded, and a dot in
/// the first element (`go` itself refuses a path without one before it asks any proxy, and that
/// keeps `sumdb/...` from ever being a module path).
pub fn valid_module_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= MAX_PATH
        && valid_go_path(path)
        && path.split('/').next().is_some_and(|first| first.contains('.') && !first.starts_with('.') && !first.ends_with('.'))
}

/// A decoded module path from its escaped URL spelling, or `None`.
pub fn module_of(escaped: &str) -> Option<String> {
    let decoded = unescape(escaped)?;
    valid_module_path(&decoded).then_some(decoded)
}

/// A canonical Go module version: `v` + full SemVer 2 whose build metadata is empty or exactly
/// `incompatible` (so `v1.2.3+incompatible`, a pseudo-version `v0.0.0-2025...-abc...`, `v2.0.0-rc.1`).
pub fn valid_version(version: &str) -> bool {
    if version.is_empty() || version.len() > MAX_VERSION {
        return false;
    }
    let Some(rest) = version.strip_prefix('v') else { return false };
    match semver::Version::parse(rest) {
        Ok(parsed) => (parsed.build.is_empty() || parsed.build.as_str() == "incompatible") && parsed.to_string() == rest,
        Err(_) => false,
    }
}

/// The decoded version from its escaped file-name stem, or `None`.
pub fn version_of(escaped: &str) -> Option<String> {
    let decoded = unescape(escaped)?;
    valid_version(&decoded).then_some(decoded)
}

/// The longest revision token routed (a full git hash is 64 hex digits with SHA-256).
pub const MAX_REV: usize = 128;

/// A revision query token (`main`, `v1`, `abc1234`, `v1.2`): `go get mod@rev` asks `@v/{rev}.info` and expects the
/// canonical version in the answer. Bounded charset and length, checked before any upstream call; a canonical
/// version is not a revision (it takes the normal path), and a leading `.` or `-`, `..` or `@` is never one.
pub fn valid_rev(rev: &str) -> bool {
    !rev.is_empty()
        && rev.len() <= MAX_REV
        && !valid_version(rev)
        && !rev.starts_with(['.', '-'])
        && !rev.contains("..")
        && rev.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'+'))
}

/// The decoded revision from its escaped file-name stem, or `None`.
pub fn rev_of(escaped: &str) -> Option<String> {
    let decoded = unescape(escaped)?;
    valid_rev(&decoded).then_some(decoded)
}

/// What policy, blocks and OSV see (LS-F6): the version without its leading `v`, `+incompatible` kept.
pub fn policy_version(version: &str) -> &str {
    version.strip_prefix('v').unwrap_or(version)
}

/// The escaped path segments of a module (the URL path below the proxy base, before `@v`).
pub fn module_segments(module: &str) -> Option<Vec<String>> {
    Some(escape(module)?.split('/').map(str::to_owned).collect())
}
