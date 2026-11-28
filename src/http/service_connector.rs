//! The single outbound denylist for snapshot-sourced registries (LS-F9, D5).
//!
//! A descriptor target is parsed once with the `url` crate (which canonicalises decimal,
//! hex, octal and short IPv4 spellings and a trailing dot), IP literals are unwrapped to
//! a fixpoint and compared with [`Denylist`], and a hostname is resolved exactly once with
//! every answer checked ([`resolve_checked`]); the caller connects to the returned
//! addresses, never to a second resolution. Scope: only registries whose descriptor comes
//! from the shared-service policy snapshot. Standalone and legacy managed targets keep
//! their own gate in `upstream::resolver`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use ipnet::IpNet;
use url::{Host, Url};

#[derive(Clone, Debug, Default)]
pub struct Denylist {
    /// The enforcer's own listener address and port.
    pub listener: Option<SocketAddr>,
    /// Deployment-supplied cluster control-plane ranges (`control_plane_cidrs`).
    pub control_plane_cidrs: Vec<IpNet>,
    /// Test seam: when set, replaces the built-in ranges. Absent from release builds.
    #[cfg(feature = "test-support")]
    builtin_override: Option<Vec<IpNet>>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum TargetError {
    Scheme,
    Userinfo,
    Fragment,
    NoHost,
    Denied(IpAddr),
    Unresolved,
}

/// Loopback, unspecified and "this network", link-local, and the cloud metadata addresses.
const BUILTIN: &[&str] = &[
    "127.0.0.0/8",
    "::1/128",
    "0.0.0.0/8",
    "::/128",
    "169.254.0.0/16",
    "fe80::/10",
    "169.254.169.254/32",
    "169.254.170.2/32",
    "fd00:ec2::254/128",
    "100.100.100.200/32",
    "192.0.0.192/32",
    // Teredo hides its address, so it is denied outright rather than unwrapped.
    "2001::/32",
];

impl Denylist {
    pub fn new(listener: Option<SocketAddr>, control_plane_cidrs: Vec<IpNet>) -> Denylist {
        // The `test-support` build has one more field; a release build (and `cargo clippy --lib`) has none to default.
        #[allow(clippy::needless_update)]
        Denylist {
            listener,
            control_plane_cidrs,
            ..Denylist::default()
        }
    }

    /// Test seam: only `ranges` are denied (no built-in ranges), so a loopback fake can be
    /// reached while one chosen address stays denied.
    #[cfg(feature = "test-support")]
    pub fn only(ranges: Vec<IpNet>) -> Denylist {
        Denylist {
            builtin_override: Some(ranges),
            ..Denylist::default()
        }
    }

    /// Whether `ip`, or any IPv4 address it embeds, is denied.
    pub fn denies(&self, ip: IpAddr) -> bool {
        let mut ip = ip;
        // Unwrap embedded forms to a fixpoint, rechecking each layer.
        for _ in 0..8 {
            if self.denies_literal(ip) {
                return true;
            }
            match ip {
                IpAddr::V6(v6) => match embedded_v4(v6) {
                    Some(v4) => ip = IpAddr::V4(v4),
                    None => return false,
                },
                IpAddr::V4(_) => return false,
            }
        }
        true
    }

    /// The address and port of a dial: the built-in ranges on any port, and the enforcer's
    /// own listener on its port. A listener bound to a wildcard owns every address of this
    /// host (loopback included), so any local address on the listener port is denied.
    pub fn denies_endpoint(&self, ip: IpAddr, port: u16) -> bool {
        self.denies(ip) || self.is_own_listener(ip, port)
    }

    fn is_own_listener(&self, ip: IpAddr, port: u16) -> bool {
        let Some(listener) = self.listener else {
            return false;
        };
        if listener.port() != port {
            return false;
        }
        let mut ip = ip;
        for _ in 0..8 {
            let own = if listener.ip().is_unspecified() {
                ip.is_loopback() || is_local_address(ip)
            } else {
                canonical(listener.ip()) == canonical(ip)
            };
            if own {
                return true;
            }
            match ip {
                IpAddr::V6(v6) => match embedded_v4(v6) {
                    Some(v4) => ip = IpAddr::V4(v4),
                    None => return false,
                },
                IpAddr::V4(_) => return false,
            }
        }
        true
    }

    fn denies_literal(&self, ip: IpAddr) -> bool {
        #[cfg(feature = "test-support")]
        if let Some(ranges) = &self.builtin_override {
            return ranges
                .iter()
                .chain(&self.control_plane_cidrs)
                .any(|net| net.contains(&ip));
        }
        BUILTIN
            .iter()
            .any(|net| net.parse::<IpNet>().is_ok_and(|net| net.contains(&ip)))
            || self.control_plane_cidrs.iter().any(|net| net.contains(&ip))
    }
}

/// IPv4-mapped, IPv4-compatible, NAT64 `64:ff9b::/96`, local-use NAT64 `64:ff9b:1::/48`,
/// 6to4 `2002::/16` and ISATAP (`...:0:5efe:a.b.c.d`).
fn embedded_v4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let (s, o) = (ip.segments(), ip.octets());
    if let Some(v4) = ip.to_ipv4_mapped() {
        return Some(v4);
    }
    if s[..6] == [0; 6] && (s[6] != 0 || s[7] > 1) {
        return Some(Ipv4Addr::new(o[12], o[13], o[14], o[15]));
    }
    if s[0] == 0x64 && s[1] == 0xff9b {
        if s[2..6] == [0; 4] {
            return Some(Ipv4Addr::new(o[12], o[13], o[14], o[15]));
        }
        if s[2] == 1 {
            // RFC 6052 /48: the IPv4 address skips the reserved octet 8.
            return Some(Ipv4Addr::new(o[6], o[7], o[9], o[10]));
        }
    }
    if s[0] == 0x2002 {
        return Some(Ipv4Addr::new(o[2], o[3], o[4], o[5]));
    }
    if s[4] & 0xfcff == 0 && s[5] == 0x5efe {
        return Some(Ipv4Addr::new(o[12], o[13], o[14], o[15]));
    }
    None
}

/// Activation-time check of a descriptor `target_url`: userinfo, fragment and non-http(s)
/// schemes are refused; an IP literal is checked against the denylist (a hostname is
/// checked when it is resolved, at connect time).
pub fn check_target(url: &Url, deny: &Denylist) -> Result<(), TargetError> {
    if !matches!(url.scheme(), "http" | "https") {
        return Err(TargetError::Scheme);
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(TargetError::Userinfo);
    }
    if url.fragment().is_some() {
        return Err(TargetError::Fragment);
    }
    let ip = match url.host().ok_or(TargetError::NoHost)? {
        Host::Ipv4(ip) => IpAddr::V4(ip),
        Host::Ipv6(ip) => IpAddr::V6(ip),
        Host::Domain(_) => return Ok(()),
    };
    if deny.denies(ip) {
        return Err(TargetError::Denied(ip));
    }
    if url
        .port_or_known_default()
        .is_some_and(|port| deny.is_own_listener(ip, port))
    {
        return Err(TargetError::Denied(ip));
    }
    Ok(())
}

fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        _ => ip,
    }
}

/// Whether `ip` is an address of this host: a socket can be bound to it only if so
/// (EADDRNOTAVAIL otherwise). Port 0 binds nothing that outlives the call.
fn is_local_address(ip: IpAddr) -> bool {
    std::net::UdpSocket::bind((ip, 0)).is_ok()
}

/// Resolve `host` exactly once and require every answer to pass. A second resolution is
/// never made, so DNS rebinding between check and connect cannot change the address.
pub fn resolve_checked(
    host: &str,
    lookup: &mut dyn FnMut(&str) -> Vec<IpAddr>,
    deny: &Denylist,
) -> Result<Vec<IpAddr>, TargetError> {
    let answers = lookup(host);
    if answers.is_empty() {
        return Err(TargetError::Unresolved);
    }
    match answers.iter().find(|ip| deny.denies(**ip)) {
        Some(ip) => Err(TargetError::Denied(*ip)),
        None => Ok(answers),
    }
}

/// [`resolve_checked`] for a known destination port: an answer equal to the enforcer's own
/// listener (address and port) is refused too.
pub fn resolve_checked_on(
    host: &str,
    port: u16,
    lookup: &mut dyn FnMut(&str) -> Vec<IpAddr>,
    deny: &Denylist,
) -> Result<Vec<IpAddr>, TargetError> {
    let answers = lookup(host);
    if answers.is_empty() {
        return Err(TargetError::Unresolved);
    }
    match answers.iter().find(|ip| deny.denies_endpoint(**ip, port)) {
        Some(ip) => Err(TargetError::Denied(*ip)),
        None => Ok(answers),
    }
}
