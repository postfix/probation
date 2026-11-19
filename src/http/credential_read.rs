//! Credential-bearing read detection (C1028, LS-F4): a read is cache-eligible only when every part
//! of it is on an explicit allow-list; anything else is request-scoped.

use axum::http::{HeaderMap, Uri};

/// Proof that a read carries no credential and may use the shared caches. Only
/// [`classify_read`] constructs it.
#[derive(Debug)]
pub struct CacheToken(());

#[cfg(feature = "test-support")]
impl CacheToken {
    /// A token for tests that drive a cache directly. Absent from release builds.
    pub fn for_test_support() -> CacheToken {
        CacheToken(())
    }
}

#[derive(Debug)]
pub enum ReadClass {
    CacheEligible(CacheToken),
    RequestScoped,
}

pub struct RequestParts<'a> {
    pub uri: &'a Uri,
    pub headers: &'a HeaderMap,
    /// HTTP/2 pseudo-headers other than `:authority` the request carried.
    pub extra_pseudo_headers: &'a [&'a str],
}

pub struct FamilyReadRules {
    pub headers: &'static [&'static str],
    pub query_keys: &'static [&'static str],
}

/// The token a request may write shared caches with: `None` for a request-scoped
/// (credential-bearing) read in shared-service mode. Standalone and certificate-managed
/// modes forward no caller credential on reads, so every read is eligible there.
pub fn cache_token(app: &crate::App) -> Option<CacheToken> {
    // Shared-service mode fails closed: with no request context there is no classification,
    // so no token (a background task cannot write a shared cache on a request's behalf).
    if app.service_policy().is_some() && (!super::logging::in_request() || super::logging::request_scoped()) {
        None
    } else {
        Some(CacheToken(()))
    }
}

impl FamilyReadRules {
    /// npm clients' own non-secret headers (LS-F4).
    pub const NPM: FamilyReadRules = FamilyReadRules {
        headers: &["npm-session", "npm-scope", "npm-command", "pacote-version", "pacote-req-type", "pacote-pkg-id", "referer"],
        query_keys: &[],
    };
    /// PyPI clients send only common headers.
    pub const PYPI: FamilyReadRules = FamilyReadRules { headers: &[], query_keys: &[] };
    /// RubyGems (`gem`, Bundler) sends only the common headers on a plain read; a credential
    /// travels as `Authorization` or URL userinfo, both request-scoped. No path or query token.
    /// Cargo's plain reads add `Cargo-Protocol: version=1` and, over plain http, libcurl's h2c
    /// upgrade pair `Upgrade` and `HTTP2-Settings` (all observed from cargo 1.96, tests/cargo_native.rs);
    /// none carries a credential. Its registry token travels as `Authorization`, a credential,
    /// and never in the path or query of this firewall's routes.
    pub const CARGO: FamilyReadRules = FamilyReadRules { headers: &["cargo-protocol", "upgrade", "http2-settings"], query_keys: &[] };
    /// Go's `go` command sends only the common headers on a plain read (measured with go 1.26.0,
    /// tests/go_native.rs): a credential travels as `Authorization` (Basic from `.netrc` or the GOPROXY
    /// userinfo, or `GOAUTH`), both request-scoped. No route of this firewall takes a token in its
    /// path or query.
    pub const GO: FamilyReadRules = FamilyReadRules { headers: &[], query_keys: &[] };
    /// NuGet's search and autocomplete read carry only these non-secret query keys (the protocol's own);
    /// a credential travels as `Authorization` (Basic or Bearer), or as `X-NuGet-ApiKey` on a write, both
    /// request-scoped. No route takes a token in its path. The headers are the real client's own non-secret ones
    /// (measured with dotnet 8.0.416, tests/nuget_native.rs).
    pub const NUGET: FamilyReadRules = FamilyReadRules {
        headers: &["x-nuget-session-id", "x-nuget-client-version"],
        query_keys: &["q", "id", "skip", "take", "prerelease", "semVerLevel", "packageType", "supportedFramework"],
    };
    /// Maven reads carry no query and no non-secret header beyond the common ones (`mvn` sends `User-Agent`, `Accept`,
    /// `Accept-Encoding`, `Host` and conditional headers on a metadata read, all common); a credential travels as
    /// `Authorization` (Basic from `settings.xml`, or a bearer token), request-scoped, and no route takes one in its path.
    pub const MAVEN: FamilyReadRules = FamilyReadRules { headers: &[], query_keys: &[] };
    pub const RUBYGEMS: FamilyReadRules = FamilyReadRules { headers: &["keep-alive"], query_keys: &[] };
}

/// Header names every family may send without credential meaning (LS-F4).
const COMMON_HEADERS: &[&str] = &[
    "host", "accept", "accept-encoding", "accept-language", "user-agent", "range", "if-range", "if-none-match",
    "if-modified-since", "if-match", "if-unmodified-since", "cache-control", "pragma", "connection",
];

/// `CacheEligible` only when there is no URL userinfo, every header instance (header names
/// are case-insensitive and repeats are all checked) and every query key is on the
/// allow-list, and no pseudo-header other than `:authority` is present. An unknown header
/// costs cache hits only, never confidentiality.
pub fn classify_read(parts: &RequestParts<'_>, rules: &FamilyReadRules) -> ReadClass {
    let userinfo = parts.uri.authority().is_some_and(|authority| authority.as_str().contains('@'));
    let headers_ok = parts.headers.keys().all(|name| {
        let name = name.as_str();
        COMMON_HEADERS.contains(&name) || rules.headers.contains(&name)
    });
    let query_ok = parts.uri.query().is_none_or(|query| {
        query.split('&').filter(|pair| !pair.is_empty()).all(|pair| {
            let key = pair.split_once('=').map_or(pair, |(key, _)| key);
            rules.query_keys.contains(&key)
        })
    });
    if userinfo || !headers_ok || !query_ok || !parts.extra_pseudo_headers.is_empty() {
        ReadClass::RequestScoped
    } else {
        ReadClass::CacheEligible(CacheToken(()))
    }
}
