//! Managed mode: turn a request's API key into its compiled policy.
//!
//! The `Authorization` header is read here and nowhere else (T19). Only its SHA-256
//! leaves this module; neither the key nor its hash reaches a record or a log line.
//!
//! Until slice 3 there is no sync loop: an entry lives for one TTL and is then looked
//! up again, and a lookup that fails answers `401` rather than serving it stale.

mod cache;
pub mod client;

use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, HeaderValue};
use probation_policy::PlaceRef;
use probation_policy::api::{ChainLink, KeyHash, KeyId, KeyLookup, LimitSource, OrgId};

use self::cache::{Budget, KeyCache, Policies, Standing, UNKNOWN_FOR, Unresolved};
use self::client::{CallError, SyncClient};
use crate::clock::Clock;
use crate::concurrency::{Resolution, SingleFlight};
use crate::config::ManagementConfig;
use crate::policy::CompiledPolicy;

/// Who a request runs as. Never holds the key or its hash.
#[derive(Clone)]
pub struct Principal {
    /// The key's own place, the last of `chain`.
    pub place: PlaceRef,
    /// The server's id, for activity rows.
    pub key_id: KeyId,
    /// Interned by fingerprint, so every key with the same effective policy shares it.
    pub policy: Arc<CompiledPolicy>,
    /// The organisation or personal account the rate limit counts against (C28).
    pub account: PlaceRef,
    /// The account's requests per minute on this firewall (C66, C114).
    pub rate_limit: Option<NonZeroU32>,
    pub rate_limit_source: LimitSource,
    /// `None` for a personal account.
    pub org: Option<OrgId>,
    /// Platform -> … -> place.
    pub chain: Arc<[PlaceRef]>,
}

/// Why `authenticate` refused. The network lock (403) and the rate limit (429) arrive
/// in slice 3.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Refusal {
    /// Missing, malformed, unknown, revoked or suspended, or no answer from the server
    /// for a key with no live entry: `401` with one fixed message (C13).
    Unauthenticated,
    /// `503 LOOKUP_BUSY`: the lookup budget is spent or the server answered `429`, so a
    /// valid key is told to retry rather than that it is wrong.
    Busy,
}

/// The managed half of `App`, present only when `[management]` is set.
pub struct Managed {
    cache: KeyCache,
    budget: Budget,
    policies: Policies,
    lookups: SingleFlight<KeyHash, Result<Principal, Refusal>>,
    client: SyncClient,
    /// Set once this firewall is retired (C72, slice 3); checked before anything else.
    retired: AtomicBool,
}

/// The longest `Authorization` value decoded. A key is 36 characters; anything this
/// long is refused before a byte of it is decoded (T19).
const MAX_CREDENTIALS_BYTES: usize = 1024;

impl Managed {
    pub fn new(config: &ManagementConfig, clock: Arc<dyn Clock>) -> Managed {
        Managed {
            cache: KeyCache::new(
                config.key_cache_max_entries.get(),
                Duration::from_secs(config.key_cache_ttl_seconds.get()),
                Arc::clone(&clock),
            ),
            budget: Budget::new(
                config.lookup_budget_per_second.get(),
                config.client_lookup_allowance_per_second.get(),
                clock,
            ),
            policies: Policies::default(),
            lookups: SingleFlight::new(),
            client: SyncClient::new(config),
            retired: AtomicBool::new(false),
        }
    }

    /// How many requests share the lookup in flight for `hash`; zero when none is.
    /// **Compiled only under `test-support`**, so a test can wait for a burst to join
    /// rather than sleep.
    #[cfg(feature = "test-support")]
    pub fn waiting_on(&self, hash: &KeyHash) -> usize {
        self.lookups.waiting_on(hash)
    }

    /// The only reader of the `Authorization` header. Only the key's SHA-256 leaves.
    /// `peer` is the address the per-client lookup allowance is counted against.
    pub async fn authenticate(
        &self,
        headers: &HeaderMap,
        peer: IpAddr,
    ) -> Result<Principal, Refusal> {
        if self.retired.load(Ordering::Acquire) {
            return Err(Refusal::Unauthenticated);
        }
        let presented = headers.get(AUTHORIZATION).ok_or(Refusal::Unauthenticated)?;
        let hash = key_hash(presented)?;
        let principal = match self.cache.fresh(&hash) {
            Some(principal) => principal,
            None => self.look_up(&hash, peer).await?,
        };
        Ok(principal)
    }

    /// Single-flighted per hash: a burst of requests with one new key makes one lookup,
    /// and only the request that makes it is charged to the budget.
    async fn look_up(&self, hash: &KeyHash, peer: IpAddr) -> Result<Principal, Refusal> {
        let (slot, leader, _waiter) = self.lookups.join(*hash);
        if !leader {
            return slot.wait().await.unwrap_or(Err(Refusal::Busy));
        }
        let mut resolution = Resolution::new(
            self.lookups.clone(),
            *hash,
            Arc::clone(&slot),
            Err(Refusal::Busy),
            // Never the hash: it does not go in a log line.
            "a key lookup".to_owned(),
        );
        let answer = self.ask(hash, peer).await;
        resolution.answer(answer.clone());
        answer
    }

    async fn ask(&self, hash: &KeyHash, peer: IpAddr) -> Result<Principal, Refusal> {
        let standing = self.cache.standing(hash);
        if standing == Standing::Refused {
            return Err(Refusal::Unauthenticated);
        }
        if !self.budget.take(peer, standing == Standing::Expired) {
            return Err(Refusal::Busy);
        }
        let answer = self.client.lookup(*hash).await.map_err(refusal)?;
        let (key_id, org, account, chain, rate_limit, rate_limit_source) = match answer {
            KeyLookup::Known {
                key_id,
                org,
                account,
                place_chain,
                rate_limit,
                rate_limit_source,
                ..
            } => (
                key_id,
                org,
                account,
                place_chain,
                rate_limit,
                rate_limit_source,
            ),
            KeyLookup::Unknown { .. } => {
                self.cache.refuse(*hash, Some(UNKNOWN_FOR));
                return Err(Refusal::Unauthenticated);
            }
            KeyLookup::Revoked { .. } | KeyLookup::Suspended { .. } => {
                self.cache.refuse(*hash, None);
                return Err(Refusal::Unauthenticated);
            }
        };
        let policy = self.policy_of(&chain).await?;
        let found = Principal {
            place: chain
                .last()
                .map(|link| link.place)
                .ok_or(Refusal::Unauthenticated)?,
            key_id,
            policy,
            account,
            rate_limit,
            rate_limit_source,
            org,
            chain: chain.iter().map(|link| link.place).collect(),
        };
        self.cache.insert(*hash, found.clone());
        Ok(found)
    }

    /// The compiled policy of a key's chain, fetching the layers this firewall does not
    /// hold at the revisions the chain names.
    async fn policy_of(&self, chain: &[ChainLink]) -> Result<Arc<CompiledPolicy>, Refusal> {
        let missing = self.policies.missing(chain);
        if !missing.is_empty() {
            let answer = self.client.layers(missing).await.map_err(refusal)?;
            self.policies.store(answer.layers);
        }
        self.policies
            .compile(chain)
            .map_err(|unresolved| match unresolved {
                // A valid key that cannot be checked yet is told to retry, never refused.
                Unresolved::Behind => {
                    tracing::warn!(
                        "the management server's layers answer holds a layer older than its \
                         chain names, or none; answering busy"
                    );
                    Refusal::Busy
                }
                Unresolved::Inconsistent => {
                    tracing::error!(
                        "the management server answered a lookup with a chain whose layers \
                     this firewall cannot resolve; refusing the request"
                    );
                    Refusal::Unauthenticated
                }
            })
    }
}

/// What a failed call to the server tells the client. A request with no live entry is
/// refused when the server cannot be asked (C96's stale serving arrives in slice 3).
fn refusal(error: CallError) -> Refusal {
    match error {
        CallError::Busy => Refusal::Busy,
        CallError::Unreachable => {
            tracing::warn!("the management server could not be asked about a key");
            Refusal::Unauthenticated
        }
        CallError::TokenRefused => {
            tracing::error!("the management server refused this firewall's token");
            Refusal::Unauthenticated
        }
    }
}

fn key_hash(presented: &HeaderValue) -> Result<KeyHash, Refusal> {
    let key = bearer_or_basic_password(presented).ok_or(Refusal::Unauthenticated)?;
    Ok(KeyHash::of(&key))
}

/// The key from `Bearer <key>` (npm) or the password of `Basic <user:key>` (pip, uv,
/// Poetry; any username), if it has a key's shape. Format is checked before hashing.
fn bearer_or_basic_password(value: &HeaderValue) -> Option<String> {
    if value.len() > MAX_CREDENTIALS_BYTES {
        return None;
    }
    let (scheme, credentials) = value.to_str().ok()?.split_once(' ')?;
    let credentials = credentials.trim();
    let key = if scheme.eq_ignore_ascii_case("bearer") {
        credentials.to_owned()
    } else if scheme.eq_ignore_ascii_case("basic") {
        let decoded = String::from_utf8(base64_decode(credentials)?).ok()?;
        decoded.split_once(':')?.1.to_owned()
    } else {
        return None;
    };
    let shaped = key
        .strip_prefix("prb_")
        .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_graphic()));
    shaped.then_some(key)
}

/// Standard-alphabet base64 with padding, the form RFC 7617 puts in a Basic header.
/// The caller has already bounded `text`.
fn base64_decode(text: &str) -> Option<Vec<u8>> {
    if text.is_empty() || !text.len().is_multiple_of(4) {
        return None;
    }
    let chunks = text.len() / 4;
    let mut out = Vec::with_capacity(chunks * 3);
    for (index, chunk) in text.as_bytes().chunks(4).enumerate() {
        let mut bits = 0u32;
        let mut padding = 0;
        for (position, &c) in chunk.iter().enumerate() {
            let value = match c {
                b'A'..=b'Z' => c - b'A',
                b'a'..=b'z' => c - b'a' + 26,
                b'0'..=b'9' => c - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                b'=' if position >= 2 && index == chunks - 1 => {
                    padding += 1;
                    0
                }
                _ => return None,
            };
            if padding > 0 && c != b'=' {
                return None;
            }
            bits = bits << 6 | u32::from(value);
        }
        out.extend_from_slice(&bits.to_be_bytes()[1..4 - padding]);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_decodes_what_rfc_4648_encodes() {
        assert_eq!(base64_decode("Zm9vYmFy").as_deref(), Some(&b"foobar"[..]));
        assert_eq!(base64_decode("Zm9vYg==").as_deref(), Some(&b"foob"[..]));
        assert_eq!(base64_decode("Zm9vYmE=").as_deref(), Some(&b"fooba"[..]));
        for bad in ["", "Zm9", "Zm=v", "Zg==Zm9v", "Zm9v!A==", "Z==="] {
            assert_eq!(base64_decode(bad), None, "{bad}");
        }
    }

    #[test]
    fn only_a_key_shaped_credential_is_hashed() {
        let header = |text: &str| HeaderValue::from_str(text).unwrap();
        assert_eq!(
            bearer_or_basic_password(&header("bearer prb_abc")).as_deref(),
            Some("prb_abc")
        );
        for refused in [
            "Bearer prb_",
            "Bearer prb_a b",
            "Bearer abc",
            "Digest prb_abc",
        ] {
            assert_eq!(
                bearer_or_basic_password(&header(refused)),
                None,
                "{refused}"
            );
        }
        // "user" with no colon.
        assert_eq!(bearer_or_basic_password(&header("Basic dXNlcg==")), None);
    }
}
