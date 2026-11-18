//! Listener admission for the shared service (LS-F10, T1).

use std::net::IpAddr;

use ipnet::IpNet;
use url::Url;

/// What the request says about its own host: every `Host` header instance, the HTTP/2
/// `:authority` and the authority of an absolute-form request target.
#[derive(Default, Debug, Clone)]
pub struct HostInput {
    pub host_headers: Vec<String>,
    pub authority: Option<String>,
    pub target_authority: Option<String>,
}

/// Canonical `(host, port)` of an authority: lowercase ASCII (punycode), IPv6 in bracketed
/// canonical form, one trailing dot stripped, the scheme's default port elided. `None` for
/// anything that is not a bare authority (userinfo, path, query, fragment).
fn canonical(scheme: &str, authority: &str) -> Option<(String, Option<u16>)> {
    let url = Url::parse(&format!("{scheme}://{authority}/")).ok()?;
    if !url.username().is_empty() || url.password().is_some() || url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
        return None;
    }
    let host = url.host_str()?;
    let host = host.strip_suffix('.').unwrap_or(host);
    Some((host.to_owned(), url.port()))
}

/// LS-F10: exactly one Host, equal to the public URL after normalisation; an HTTP/2
/// `:authority` and an absolute-form target authority must each equal it.
pub fn host_matches(public_url: &Url, host: &HostInput) -> bool {
    let [only] = host.host_headers.as_slice() else { return false };
    let scheme = public_url.scheme();
    let expected = (public_url.host_str().map(|h| h.strip_suffix('.').unwrap_or(h).to_owned()), public_url.port());
    let matches = |text: &str| canonical(scheme, text).is_some_and(|(h, p)| (Some(h), p) == expected);
    matches(only)
        && host.authority.as_deref().is_none_or(matches)
        && host.target_authority.as_deref().is_none_or(matches)
}

/// The actual TCP peer is admitted when it is loopback or inside an allowed CIDR, after
/// IPv4-mapped normalisation. Forwarding headers are never an input.
pub fn peer_admitted(peer: IpAddr, allowed: &[IpNet]) -> bool {
    let peer = peer.to_canonical();
    peer.is_loopback() || allowed.iter().any(|cidr| cidr.contains(&peer))
}

/// The machine's own names: `127.0.0.1`, `[::1]` and `localhost`, each with the listener's
/// own port. Same normalising comparison as [`host_matches`] (trailing dot, case).
pub fn local_host_matches(port: u16, host: &HostInput) -> bool {
    ["127.0.0.1", "[::1]", "localhost"].iter().any(|name| {
        Url::parse(&format!("http://{name}:{port}")).is_ok_and(|own| host_matches(&own, host))
    })
}
