//! The network lock (C30, C77) and the client address it is checked against (C113).
//! CIDR matching uses `std::net` only.

use std::net::IpAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use axum::http::HeaderMap;
use probation_policy::api::{LockRange, OrgId};

use crate::config::Cidr;

/// Approved network-lock ranges, fleet-wide: range -> org. Replaced whole on every
/// change, and read with no lock on the request path.
#[derive(Default)]
pub struct NetworkLock {
    ranges: ArcSwap<Vec<(Cidr, OrgId)>>,
}

impl NetworkLock {
    /// Replaces the table with `ranges` when one was sent; `None` keeps it. A range is
    /// read as every address it names: one in IPv4-mapped form as its IPv4 range, and
    /// an IPv6 range wide enough to hold the whole mapped block as all of IPv4 too, so
    /// the lock never reads narrower than written (C113). A range that does not parse
    /// at all is left out and logged: the server validated it, so this is a version
    /// skew, not a client's doing.
    pub fn adopt(&self, ranges: Option<&[LockRange]>) {
        let Some(ranges) = ranges else {
            return;
        };
        let mut parsed = Vec::new();
        for range in ranges {
            let read = lock_ranges(&range.cidr);
            if read.is_empty() {
                tracing::error!(cidr = %range.cidr, "the server sent a network-lock range this firewall cannot read; leaving it out");
            }
            parsed.extend(read.into_iter().map(|cidr| (cidr, range.org)));
        }
        self.ranges.store(Arc::new(parsed));
    }

    /// Whether a key of `org` (`None` for a personal account) is refused from `client`:
    /// the address is inside some organisation's approved range, and that organisation
    /// is not the key's. An organisation's own keys work from anywhere.
    pub fn refuses(&self, client: IpAddr, org: Option<OrgId>) -> bool {
        let client = client.to_canonical();
        self.ranges
            .load()
            .iter()
            .any(|(range, owner)| Some(*owner) != org && within(range, client))
    }

    /// The table as the snapshot keeps it.
    pub fn ranges(&self) -> Vec<LockRange> {
        self.ranges
            .load()
            .iter()
            .map(|(range, org)| LockRange {
                cidr: format!("{}/{}", range.addr, range.prefix),
                org: *org,
            })
            .collect()
    }
}

/// The ranges one network-lock entry covers; empty when it does not parse.
fn lock_ranges(text: &str) -> Vec<Cidr> {
    const ALL_OF_IPV4: Cidr = Cidr {
        addr: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        prefix: 0,
    };
    let raw = text.split_once('/').and_then(|(addr, prefix)| {
        Some((addr.parse::<IpAddr>().ok()?, prefix.parse::<u8>().ok()?))
    });
    let Some((addr, prefix)) = raw else {
        return Vec::new();
    };
    let mut read: Vec<Cidr> = Cidr::parse(text).into_iter().collect();
    // An IPv6 range holding all of `::ffff:0:0/96` holds every IPv4 client too.
    if let IpAddr::V6(v6) = addr
        && prefix <= 96
        && same_prefix(u128::from(v6), 0xffff_0000_0000, prefix, 128)
    {
        if read.is_empty() {
            read.push(Cidr { addr, prefix });
        }
        read.push(ALL_OF_IPV4);
    }
    read
}

/// Peers whose `X-Forwarded-For` is believed (C113).
pub struct TrustedProxies {
    proxies: Vec<Cidr>,
}

/// The header a listed proxy names the client in.
const FORWARDED_FOR: &str = "x-forwarded-for";

impl TrustedProxies {
    pub fn new(proxies: Vec<Cidr>) -> TrustedProxies {
        TrustedProxies { proxies }
    }

    /// The client address the network lock and the lookup allowance use: the peer, or,
    /// when the peer is a listed proxy, the rightmost `X-Forwarded-For` entry that is not
    /// one. Every header line is read, in order. `None` when that entry does not parse:
    /// the request is refused rather than judged by the proxy's address.
    pub fn client(&self, peer: IpAddr, headers: &HeaderMap) -> Option<IpAddr> {
        let peer = peer.to_canonical();
        if !self.trusts(peer) {
            return Some(peer);
        }
        let mut entries = Vec::new();
        for line in headers.get_all(FORWARDED_FOR) {
            let line = line.to_str().ok()?;
            entries.extend(line.split(',').map(str::trim));
        }
        for entry in entries.into_iter().rev() {
            let address = entry.parse::<IpAddr>().ok()?.to_canonical();
            if !self.trusts(address) {
                return Some(address);
            }
        }
        Some(peer)
    }

    fn trusts(&self, address: IpAddr) -> bool {
        self.proxies.iter().any(|proxy| within(proxy, address))
    }
}

/// Whether `ip` (already canonical) is inside `range`. An IPv4 range never holds an
/// IPv6 address, and an IPv4-mapped address was folded to IPv4 before it got here.
pub(crate) fn within(range: &Cidr, ip: IpAddr) -> bool {
    match (range.addr.to_canonical(), ip) {
        (IpAddr::V4(range_addr), IpAddr::V4(ip)) => same_prefix(
            u32::from(range_addr).into(),
            u32::from(ip).into(),
            range.prefix,
            32,
        ),
        (IpAddr::V6(range_addr), IpAddr::V6(ip)) => {
            same_prefix(range_addr.into(), ip.into(), range.prefix, 128)
        }
        _ => false,
    }
}

fn same_prefix(a: u128, b: u128, prefix: u8, bits: u8) -> bool {
    let prefix = u32::from(prefix.min(bits));
    if prefix == 0 {
        return true;
    }
    let shift = u32::from(bits) - prefix;
    a >> shift == b >> shift
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cidr(text: &str) -> Cidr {
        Cidr::parse(text).expect("a range")
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("an address")
    }

    #[test]
    fn a_range_holds_exactly_its_prefix() {
        assert!(within(&cidr("192.0.2.0/24"), ip("192.0.2.255")));
        assert!(!within(&cidr("192.0.2.0/24"), ip("192.0.3.0")));
        assert!(within(&cidr("0.0.0.0/0"), ip("203.0.113.9")));
        assert!(within(&cidr("10.0.0.5/32"), ip("10.0.0.5")));
        assert!(!within(&cidr("10.0.0.5/32"), ip("10.0.0.4")));
        assert!(within(&cidr("2001:db8::/32"), ip("2001:db8:ffff::1")));
        assert!(!within(&cidr("2001:db8::/32"), ip("2001:db9::1")));
        assert!(!within(&cidr("192.0.2.0/24"), ip("2001:db8::1")));
    }

    #[test]
    fn only_a_foreign_key_inside_a_range_is_refused() {
        let lock = NetworkLock::default();
        lock.adopt(Some(&[LockRange {
            cidr: "192.0.2.0/24".to_owned(),
            org: OrgId(10),
        }]));
        assert!(lock.refuses(ip("192.0.2.7"), Some(OrgId(20))));
        assert!(lock.refuses(ip("192.0.2.7"), None), "a personal key");
        assert!(lock.refuses(ip("::ffff:192.0.2.7"), None), "mapped");
        assert!(!lock.refuses(ip("192.0.2.7"), Some(OrgId(10))));
        assert!(!lock.refuses(ip("198.51.100.1"), None));
        lock.adopt(None);
        assert!(lock.refuses(ip("192.0.2.7"), None), "None keeps the table");
        lock.adopt(Some(&[]));
        assert!(!lock.refuses(ip("192.0.2.7"), None));
    }

    #[test]
    fn a_listed_proxy_names_the_rightmost_untrusted_entry() {
        let proxies = TrustedProxies::new(vec![cidr("10.0.0.0/8")]);
        let mut headers = HeaderMap::new();
        headers.append(FORWARDED_FOR, "198.51.100.9, 192.0.2.7".parse().unwrap());
        assert_eq!(
            proxies.client(ip("10.0.0.5"), &headers),
            Some(ip("192.0.2.7"))
        );
        assert_eq!(
            proxies.client(ip("198.51.100.1"), &headers),
            Some(ip("198.51.100.1")),
            "an unlisted peer's header is ignored"
        );
        headers.append(FORWARDED_FOR, "10.0.0.9".parse().unwrap());
        assert_eq!(
            proxies.client(ip("10.0.0.5"), &headers),
            Some(ip("192.0.2.7")),
            "lines are joined in order and trusted entries skipped"
        );
        assert_eq!(
            proxies.client(ip("10.0.0.5"), &HeaderMap::new()),
            Some(ip("10.0.0.5"))
        );
        let mut forged = HeaderMap::new();
        forged.append(FORWARDED_FOR, "192.0.2.7, junk".parse().unwrap());
        assert_eq!(proxies.client(ip("10.0.0.5"), &forged), None);
    }

    /// M1: a range written in IPv4-mapped form holds its whole IPv4 range; one wider
    /// than the mapped block holds all of IPv4; a mapped trusted proxy range too.
    #[test]
    fn a_mapped_range_is_read_at_its_full_width() {
        let lock = NetworkLock::default();
        let range = |cidr: &str| LockRange {
            cidr: cidr.to_owned(),
            org: OrgId(10),
        };
        lock.adopt(Some(&[range("::ffff:198.51.100.0/120")]));
        assert!(lock.refuses(ip("198.51.100.77"), None));
        assert!(!lock.refuses(ip("198.51.101.1"), None));
        lock.adopt(Some(&[range("::ffff:0:0/80")]));
        assert!(
            lock.refuses(ip("203.0.113.9"), None),
            "wider than the mapped block"
        );
        assert!(lock.refuses(ip("::ffff:203.0.113.9"), None));
        lock.adopt(Some(&[range("::/0")]));
        assert!(lock.refuses(ip("203.0.113.9"), None));
        assert!(lock.refuses(ip("2001:db8::1"), None));
        lock.adopt(Some(&[range("2001:db8::/32")]));
        assert!(!lock.refuses(ip("203.0.113.9"), None));
        lock.adopt(Some(&[range("not a range")]));
        assert!(!lock.refuses(ip("203.0.113.9"), None));

        assert_eq!(cidr("::ffff:127.0.9.0/120"), cidr("127.0.9.0/24"));
        assert_eq!(
            Cidr::parse("::ffff:0:0/80"),
            None,
            "refused as a proxy range"
        );
        let proxies = TrustedProxies::new(vec![cidr("::ffff:10.0.0.0/104")]);
        let mut headers = HeaderMap::new();
        headers.append(FORWARDED_FOR, "192.0.2.7".parse().unwrap());
        assert_eq!(
            proxies.client(ip("10.9.9.9"), &headers),
            Some(ip("192.0.2.7"))
        );
    }
}
