//! The second outbound gate: a DNS answer is judged before a connection is made.
//!
//! [`OriginSet::admit`](super::OriginSet::admit) can only check the name. A name on
//! a configured origin that resolves to `127.0.0.1`, `10.0.0.1` or `169.254.169.254`
//! is still an internal address, and by the time a connection error would tell us,
//! the packet has left. So the resolver answers first (SPEC §11: "Reject … addresses
//! resolving to loopback/private/link-local networks").
//!
//! Like the origin check, this gate is constructor-controlled: it reads
//! `allow_private_addresses`, which only `OriginSet::for_tests` can set.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};

use crate::upstream::UpstreamError;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

pub struct GuardedResolver {
    allow_private_addresses: bool,
}

impl GuardedResolver {
    pub fn new(allow_private_addresses: bool) -> Arc<GuardedResolver> {
        Arc::new(GuardedResolver {
            allow_private_addresses,
        })
    }
}

impl Resolve for GuardedResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let allow_private_addresses = self.allow_private_addresses;
        let host = name.as_str().to_owned();
        Box::pin(async move {
            // Port 0: reqwest substitutes the URL's port, or the scheme's default.
            let resolved: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
                .await
                .map_err(|source| {
                    let reason = format!("cannot resolve {host}: {source}");
                    Box::new(UpstreamError::Transport(reason)) as BoxError
                })?
                .collect();

            if !allow_private_addresses {
                // One bad answer refuses the whole name. Returning the rest instead
                // would let a host that resolves to both a public and an internal
                // address decide which one we connect to.
                if let Some(addr) = resolved.iter().find(|addr| !is_public(addr.ip())) {
                    let rejected = UpstreamError::RejectedAddress { addr: addr.ip() };
                    return Err(Box::new(rejected) as BoxError);
                }
            }

            Ok(Box::new(resolved.into_iter()) as Addrs)
        })
    }
}

/// Whether `ip` is an ordinary public unicast address.
///
/// Written out rather than deferred to `std`, because the `IpAddr` predicates that
/// would cover the shared, benchmarking and reserved ranges are still unstable, and
/// a gate that silently omits `100.64.0.0/10` is not a gate.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_v4(ip),
        IpAddr::V6(ip) => is_public_v6(ip),
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    !(ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        // 0.0.0.0/8, "this network" (RFC 1122). `is_unspecified` matches only the
        // single all-zero address, so the rest of the block needs saying: on Linux
        // 0.x.y.z is routed to the local host.
        || a == 0
        || ip.is_unspecified()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_documentation()
        // 100.64.0.0/10, carrier-grade NAT.
        || (a == 100 && (64..128).contains(&b))
        // 192.0.0.0/24, IETF protocol assignments.
        || (a == 192 && b == 0 && ip.octets()[2] == 0)
        // 198.18.0.0/15, benchmarking.
        || (a == 198 && (b == 18 || b == 19))
        // 240.0.0.0/4, reserved.
        || a >= 240)
}

/// An allowlist, not a blocklist, because a blocklist here has now been wrong twice.
///
/// Only `2000::/3` is global unicast, so one clause refuses `::/128`, `::1/128`,
/// `100::/64`, `5f00::/16`, `fc00::/7`, `fe80::/10`, `fec0::/10`, `ff00::/8` and
/// every unassigned block at once — including whatever IANA assigns next. Only the
/// special-purpose blocks that sit *inside* global unicast have to be named, and
/// that list is short and bounded.
///
/// Embedded IPv4 is handled first, so the IPv4 list is reused rather than restated:
/// an address is not public merely because its outer sixteen bytes look global.
fn is_public_v6(ip: Ipv6Addr) -> bool {
    if let Some(embedded) = embedded_v4(ip) {
        return is_public_v4(embedded);
    }

    let segments = ip.segments();
    // 2000::/3, global unicast. Everything else is refused by this one clause.
    if segments[0] & 0xe000 != 0x2000 {
        return false;
    }

    // 2001::/23, IETF protocol assignments. Covers Teredo (2001::/32), benchmarking
    // (2001:2::/48), ORCHIDv2, AMT and the anycast singletons in one range, which is
    // how IANA delegates it; none of them is an ordinary public host.
    let protocol_assignments = segments[0] == 0x2001 && segments[1] & 0xfe00 == 0;
    // 2001:db8::/32 and 3fff::/20, the two documentation ranges (RFC 3849, RFC 9637).
    let documentation = (segments[0] == 0x2001 && segments[1] == 0x0db8)
        || (segments[0] == 0x3fff && segments[1] & 0xf000 == 0);
    // 2620:4f:8000::/48, AS112-v6 direct delegation.
    let as112 = segments[0] == 0x2620 && segments[1] == 0x004f && segments[2] == 0x8000;

    !(protocol_assignments || documentation || as112)
}

/// The IPv4 address an IPv6 address carries, for the three forms that carry one.
///
/// Decoding beats excluding: the embedded address is judged by [`is_public_v4`], so
/// a NAT64 or 6to4 wrapper around a public host stays usable while the same wrapper
/// around `127.0.0.1` or `10.0.0.1` is refused for the right reason.
fn embedded_v4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let segments = ip.segments();
    let octets = ip.octets();

    // ::ffff:0:0/96 (IPv4-mapped) and ::/96 (the deprecated IPv4-compatible form).
    // `::` and `::1` decode to 0.0.0.0 and 0.0.0.1, which `is_public_v4` refuses
    // under 0.0.0.0/8 — so unspecified and loopback stay covered.
    #[allow(deprecated)]
    if let Some(v4) = ip.to_ipv4() {
        return Some(v4);
    }
    // 64:ff9b::/96, the well-known NAT64 prefix (RFC 6052). The local-use prefix
    // 64:ff9b:1::/48 is deliberately not decoded: its embedding depends on the
    // prefix length, and being outside 2000::/3 it is refused wholesale anyway.
    if segments[0] == 0x0064 && segments[1] == 0xff9b && segments[2..6] == [0, 0, 0, 0] {
        return Some(Ipv4Addr::new(
            octets[12], octets[13], octets[14], octets[15],
        ));
    }
    // 2002::/16, 6to4 (RFC 3056): the IPv4 address sits in bits 16-48.
    if segments[0] == 0x2002 {
        return Some(Ipv4Addr::new(octets[2], octets[3], octets[4], octets[5]));
    }
    None
}
