//! The one place an upload is spooled to disk before it is forwarded (npm publish, PyPI upload, `gem push`,
//! `cargo publish`, `dotnet nuget push`). The body is read to an unnamed temporary file so the policy snapshot can be
//! rechecked before the first byte goes upstream; that file is bounded here for every forwarder alike: at most
//! `SPOOLS` uploads at once, the bytes of all of them together within one budget, and a deadline on the body. A caller
//! whose key the registry would refuse (the value is not validated here) therefore cannot pin more than the budget.

use std::time::Duration;

use axum::body::Body;
use futures_util::StreamExt;
use tokio::io::{AsyncSeekExt, AsyncWriteExt};

use crate::App;
use crate::http::error::ApiError;
use crate::http::limits::{Owner, SPOOL_BUDGET_WAIT, SpoolReservation, SpoolSeat};

/// How long one upload body may take to arrive, and how long it may stall between two chunks.
pub const BODY_DEADLINE: Duration = Duration::from_secs(15 * 60);
/// A stall between two chunks of a body that has started.
pub const BODY_IDLE: Duration = Duration::from_secs(15);
/// The wait for the FIRST chunk (a slow-starting client is not cut at the mid-body limit).
pub const FIRST_CHUNK_WAIT: Duration = Duration::from_secs(60);
/// A body with no declared length may hold a place this long at most; a declared one `RATE_GRACE + 2 * length / MIN_RATE` (never more
/// than `BODY_DEADLINE`): a slow body of a small upload cannot hold a place for the whole 15 minutes.
pub const UNDECLARED_DEADLINE: Duration = Duration::from_secs(5 * 60);
/// After `RATE_GRACE` a body must average at least `MIN_RATE` bytes a second: a trickle (one byte just inside the idle limit)
/// holds a place for the whole body deadline otherwise. A client on a real link sends far more.
pub const RATE_GRACE: Duration = Duration::from_secs(20);
pub const MIN_RATE: u64 = 16 * 1024;

/// Who an upload's place and bytes are counted against (see [`Owner`]): only REAL identities, never a credential alone.
/// In certificate and managed mode that is the caller's account (the firewall has authenticated it). In shared-service mode the
/// firewall cannot tell a valid credential from junk (the registry decides), so it is the client network address: the peer, or,
/// behind a proxy listed in `[service_policy] trusted_proxies`, the client that proxy names in `X-Forwarded-For`; a header from
/// any other peer is never read. The presented credential is the second, separately capped count. Callers behind one NAT share
/// an address and so a share.
pub fn owner_of(app: &App, principal: &crate::managed::Principal, headers: &axum::http::HeaderMap) -> Owner {
    owner_in(app.config.service_policy.as_ref(), crate::http::logging::peer(), principal, headers)
}

static FORWARDED_WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn short(hash: sha2::Sha256) -> u64 {
    use sha2::Digest;
    u64::from_be_bytes(hash.finalize()[..8].try_into().expect("eight bytes"))
}

/// [`owner_of`] with the mode and the connection's peer given.
pub(crate) fn owner_in(
    service: Option<&crate::config::ServicePolicyConfig>,
    peer: Option<std::net::IpAddr>,
    principal: &crate::managed::Principal,
    headers: &axum::http::HeaderMap,
) -> Owner {
    use sha2::{Digest, Sha256};
    let mut identity = Sha256::new();
    match service {
        Some(service) => {
            identity.update(b"address");
            if let Some(peer) = peer {
                // An unreadable forwarded entry from a listed proxy falls back to the proxy's own address: shared, never free.
                let client = crate::managed::TrustedProxies::new(service.trusted_proxies.clone()).client(peer, headers).unwrap_or(peer).to_canonical();
                if client == peer.to_canonical() && headers.contains_key("x-forwarded-for") && !FORWARDED_WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                    tracing::warn!(%peer, "an upload came with X-Forwarded-For from a peer that is not in [service_policy] trusted_proxies: behind a reverse proxy every caller is counted as the proxy's address (docs/operations.md, who a spool share belongs to)");
                }
                match client {
                    std::net::IpAddr::V4(v4) => identity.update(v4.octets()),
                    // A /64 is one owner: one machine holds a whole /64 of addresses.
                    std::net::IpAddr::V6(v6) => identity.update(&v6.octets()[..8]),
                }
            }
        }
        None => {
            identity.update(b"account");
            identity.update([principal.account.kind as u8]);
            identity.update(principal.account.id.to_be_bytes());
        }
    }
    let mut credential = Sha256::new();
    for name in ["authorization", "x-nuget-apikey", "x-api-key", "cookie", "otp"] {
        for value in headers.get_all(name) {
            credential.update(name.as_bytes());
            credential.update(value.as_bytes());
            credential.update([0]);
        }
    }
    Owner { key: short(identity), credential: short(credential) }
}

/// The longest a body may take to arrive: see [`UNDECLARED_DEADLINE`].
pub fn body_deadline(declared: Option<u64>) -> Duration {
    match declared {
        None => UNDECLARED_DEADLINE.min(BODY_DEADLINE),
        Some(length) => (RATE_GRACE + Duration::from_secs(length.saturating_mul(2) / MIN_RATE)).min(BODY_DEADLINE),
    }
}

/// A spooled body, rewound; its place and bytes are returned when it is dropped (after the upstream send).
pub struct Spool {
    pub file: tokio::fs::File,
    pub length: u64,
    _slot: Option<SpoolSeat>,
    _reservation: SpoolReservation,
    _turn: Option<crate::http::limits::SpoolTurn>,
}

pub enum Spooled {
    Body(Box<Spool>),
    TooLarge,
}

/// Reads `body` to a temporary file, at most `cap` bytes. A declared length over `cap` or over the whole budget is
/// `TooLarge` before anything is taken; no free place (or a key already holding its share of them) is `Overloaded`, and
/// so is a budget still taken after `SPOOL_BUDGET_WAIT` (an upload that finds it taken waits for the others first); bytes are reserved as they arrive
/// (never the declared length whole), a body that stalls for `BODY_IDLE` or takes `BODY_DEADLINE` is refused, and an
/// empty body takes no place.
pub async fn spool(app: &App, owner: impl Into<Owner>, declared: Option<u64>, cap: u64, body: Body) -> Result<Spooled, ApiError> {
    spool_paced(app, owner, declared, cap, body, BODY_IDLE, body_deadline(declared), RATE_GRACE, FIRST_CHUNK_WAIT).await
}

pub async fn spool_with(app: &App, owner: impl Into<Owner>, declared: Option<u64>, cap: u64, body: Body, idle: Duration, deadline: Duration) -> Result<Spooled, ApiError> {
    spool_paced(app, owner, declared, cap, body, idle, deadline, RATE_GRACE, idle).await
}

/// [`spool_with`] with the grace period before the `MIN_RATE` floor applies (tests drive it short).
#[allow(clippy::too_many_arguments)]
pub async fn spool_paced(
    app: &App,
    owner: impl Into<Owner>,
    declared: Option<u64>,
    cap: u64,
    body: Body,
    idle: Duration,
    deadline: Duration,
    grace: Duration,
    first: Duration,
) -> Result<Spooled, ApiError> {
    let owner = owner.into();
    let cap = cap.min(app.limits.spool_budget_total() / 2);
    if declared.is_some_and(|length| length > cap) {
        return Ok(Spooled::TooLarge);
    }
    // Two big uploads of one owner would each hold part of the owner's half and wait for the other: they take turns instead.
    let turn = if declared.is_some_and(|length| length > app.limits.spool_budget_total() / 4) {
        Some(app.limits.spool_turn(owner, SPOOL_BUDGET_WAIT).await.ok_or(ApiError::Overloaded)?)
    } else {
        None
    };
    let slot = if declared == Some(0) { None } else { Some(app.limits.spool_seat(owner).ok_or(ApiError::Overloaded)?) };
    let mut reservation = app.limits.spool_reservation(owner);
    let file = tempfile::tempfile_in(&app.config.data_dir).map_err(|_| ApiError::StorageUnusable)?;
    let mut file = tokio::fs::File::from_std(file);
    let mut length = 0u64;
    // The rate clock starts at the FIRST chunk (the wait for it is `first`, not part of the rate), and a window of `grace`
    // bounds how long a body that burst early may then trickle on its credit.
    let mut began: Option<std::time::Instant> = None;
    let (mut window_start, mut window_bytes) = (std::time::Instant::now(), 0u64);
    let window = grace.max(Duration::from_secs(1));
    let mut stream = body.into_data_stream();
    let read = async {
        loop {
            let chunk = match tokio::time::timeout(if length == 0 { first } else { idle }, stream.next()).await {
                Err(_) => return Err(ApiError::InvalidInput("the upload stalled")),
                Ok(None) => return Ok(true),
                Ok(Some(chunk)) => chunk.map_err(|_| ApiError::InvalidInput("upload is incomplete"))?,
            };
            length = length.saturating_add(chunk.len() as u64);
            let now = std::time::Instant::now();
            let elapsed = now - *began.get_or_insert_with(|| {
                (window_start, window_bytes) = (now, 0);
                now
            });
            window_bytes += chunk.len() as u64;
            let slow = |bytes: u64, over: Duration| u128::from(bytes) * 1000 < u128::from(MIN_RATE) * over.as_millis();
            if elapsed > grace && slow(length, elapsed) {
                return Err(ApiError::InvalidInput("the upload is too slow"));
            }
            if now - window_start >= window {
                if slow(window_bytes, now - window_start) {
                    return Err(ApiError::InvalidInput("the upload is too slow"));
                }
                (window_start, window_bytes) = (now, 0);
            }
            if length > cap {
                return Ok(false);
            }
            let waiting = std::time::Instant::now();
            if !reservation.grow_waiting(chunk.len() as u64, SPOOL_BUDGET_WAIT).await {
                return Err(ApiError::Overloaded);
            }
            // Our own wait for bytes is not the client's slowness: the rate clock and the window stop during it.
            let waited = waiting.elapsed();
            began = began.map(|start| start + waited);
            window_start += waited;
            file.write_all(&chunk).await.map_err(|_| ApiError::StorageUnusable)?;
        }
    };
    match tokio::time::timeout(deadline + first, read).await {
        Err(_) => return Err(ApiError::InvalidInput("the upload took too long")),
        Ok(Err(error)) => return Err(error),
        Ok(Ok(false)) => return Ok(Spooled::TooLarge),
        Ok(Ok(true)) => {}
    }
    file.flush().await.map_err(|_| ApiError::StorageUnusable)?;
    file.seek(std::io::SeekFrom::Start(0)).await.map_err(|_| ApiError::StorageUnusable)?;
    Ok(Spooled::Body(Box::new(Spool { file, length, _slot: slot, _reservation: reservation, _turn: turn })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::http::limits::{Limits, SPOOLS_PER_OWNER};
    use crate::managed::Principal;
    use probation_policy::{Layer, LayerKind, PlaceRef, api::{KeyId, LimitSource, OrgId}};
    use std::sync::Arc;

    fn principal(account: u32) -> Principal {
        let platform = PlaceRef { kind: LayerKind::Platform, id: 1 };
        let place = PlaceRef { kind: LayerKind::Org, id: account };
        Principal {
            authority: None, place, key_id: KeyId(0),
            policy: Arc::new(crate::policy::CompiledPolicy::managed(probation_policy::resolve(&[Layer::empty(LayerKind::Platform), Layer::empty(LayerKind::Org)]))),
            account: place, rate_limit: None, rate_limit_source: LimitSource::Default,
            org: Some(OrgId(account)), chain: Arc::from([platform, place]), registry_origin: None, registry_archive_origin: None,
            registry_resource_prefix: None, registry_token_origin: None, registry_read_authorization: None, registry_trusted: false,
            registry_private_cidrs: vec![], deletion_scopes: vec![],
        }
    }

    fn headers(credential: &str) -> axum::http::HeaderMap {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-api-key", credential.parse().unwrap());
        headers
    }

    /// N1, certificate and managed mode: every principal carries `KeyId(0)`, so the places are counted per ACCOUNT. Account A
    /// holds its half of the places (whatever credentials it presents); account B still gets a place and its bytes.
    #[test]
    fn in_certificate_mode_one_account_cannot_take_the_places_or_bytes_of_another() {
        let limits = Limits::new(&Config::load(std::path::Path::new("config.sample.toml")).expect("the shipped sample"));
        let a: Vec<_> = (0..SPOOLS_PER_OWNER).map(|n| limits.spool_seat(owner_in(None, None, &principal(10), &headers(&format!("Basic a{n}")))).expect("A's share")).collect();
        assert!(limits.spool_seat(owner_in(None, None, &principal(10), &headers("Basic a-more"))).is_none(), "A is at its share, with a fresh credential too");
        let b = limits.spool_seat(owner_in(None, None, &principal(11), &headers("Basic b"))).expect("B still deploys");
        let mut bytes = limits.spool_reservation(owner_in(None, None, &principal(10), &headers("Basic a0")));
        assert!(bytes.grow(limits.spool_budget_total() / 2));
        assert!(!bytes.grow(1), "A holds half of the bytes");
        assert!(limits.spool_reservation(owner_in(None, None, &principal(11), &headers("Basic b"))).grow(1 << 20), "B still reserves bytes");
        drop((a, b));
    }

    /// Service mode counts the client address, and reads `X-Forwarded-For` only from a listed proxy.
    #[test]
    fn in_service_mode_the_address_is_the_peer_unless_a_listed_proxy_names_the_client() {
        use crate::config::Cidr;
        let service = |proxies: Vec<Cidr>| crate::config::ServicePolicyConfig {
            server_url: "https://policy.example".parse().unwrap(),
            service_key_file: "/k".into(),
            service_key: crate::config::FirewallToken::new("prb_01234567890123456789012345678901".into()),
            sync_interval_seconds: std::num::NonZeroU64::new(60).unwrap(),
            trusted_proxies: proxies,
        };
        let peer: std::net::IpAddr = "192.0.2.1".parse().unwrap();
        let mut forged = headers("Basic x");
        forged.insert("x-forwarded-for", "198.51.100.7".parse().unwrap());
        let plain = headers("Basic x");
        let p = principal(10);
        let untrusted = service(vec![]);
        assert_eq!(owner_in(Some(&untrusted), Some(peer), &p, &forged), owner_in(Some(&untrusted), Some(peer), &p, &plain), "a header from an unlisted peer is never read");
        let trusted = service(vec![Cidr::parse("192.0.2.0/24").unwrap()]);
        assert_ne!(owner_in(Some(&trusted), Some(peer), &p, &forged).key, owner_in(Some(&trusted), Some(peer), &p, &plain).key, "a listed proxy names the client");
        let other: std::net::IpAddr = "192.0.2.99".parse().unwrap();
        assert_ne!(owner_in(Some(&untrusted), Some(peer), &p, &plain).key, owner_in(Some(&untrusted), Some(other), &p, &plain).key, "another address, another share");
        assert_ne!(owner_in(Some(&untrusted), Some(peer), &p, &plain).key, owner_in(None, Some(peer), &p, &plain).key, "the two modes never share a count");
    }

    /// R3-6: the credential is its own dimension: it is capped across accounts, and it differs for each value presented.
    #[test]
    fn the_credential_is_a_second_dimension_capped_apart_from_the_account() {
        let limits = Limits::new(&Config::load(std::path::Path::new("config.sample.toml")).expect("the shipped sample"));
        let (a, b) = (owner_in(None, None, &principal(10), &headers("one")), owner_in(None, None, &principal(10), &headers("two")));
        assert_eq!(a.key, b.key, "one account");
        assert_ne!(a.credential, b.credential, "two credentials");
        let held: Vec<_> = (10..10 + SPOOLS_PER_OWNER as u32).map(|account| limits.spool_seat(owner_in(None, None, &principal(account), &headers("same"))).expect("a place")).collect();
        assert!(limits.spool_seat(owner_in(None, None, &principal(99), &headers("same"))).is_none(), "one credential from five accounts holds four places");
        assert!(limits.spool_seat(owner_in(None, None, &principal(99), &headers("other"))).is_some(), "another credential does not");
        drop(held);
    }

    /// R3-1: an IPv6 client is counted by its /64; IPv4-mapped addresses count as IPv4.
    #[test]
    fn an_ipv6_client_is_counted_by_its_64_and_a_mapped_address_as_ipv4() {
        let service = crate::config::ServicePolicyConfig {
            server_url: "https://policy.example".parse().unwrap(),
            service_key_file: "/k".into(),
            service_key: crate::config::FirewallToken::new("prb_01234567890123456789012345678901".into()),
            sync_interval_seconds: std::num::NonZeroU64::new(60).unwrap(),
            trusted_proxies: vec![],
        };
        let of = |peer: &str| owner_in(Some(&service), Some(peer.parse().unwrap()), &principal(10), &headers("x")).key;
        assert_eq!(of("2001:db8:1:2::1"), of("2001:db8:1:2:ffff::9"), "one /64 is one owner");
        assert_ne!(of("2001:db8:1:2::1"), of("2001:db8:1:3::1"), "another /64 is another");
        assert_eq!(of("::ffff:192.0.2.1"), of("192.0.2.1"), "a mapped address is the IPv4 one");
    }
}
