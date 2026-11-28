//! OCI distribution delivery on the shared firewall machinery.
//!
//! Identity. Policy sees the repository name (`library/alpine`) and, as the version, the digest of a manifest (`sha256:...`); a
//! block may also name a tag and then applies to every request that names it. A manifest is judged as the exact bytes a registry
//! answered: the firewall hashes them, compares the digest the client asked for (or the registry's `Docker-Content-Digest`), and
//! serves those bytes with that digest. Blobs (the config and the layers) and the child manifests of an index are rows of the
//! repository made when the manifest that names them is allowed; a blob is delivered through the verified artifact pipeline (the
//! whole blob is hashed and compared with its digest before the first byte leaves) and a blob nobody vouched for is judged as a
//! direct request: its own first-seen time starts its cooldown.
//!
//! Dates. A registry's v2 API carries no publication time, and the `created` of a config or an annotation is chosen by whoever
//! pushed the image: it never releases an image early. The age of a manifest digest is its committed first-seen time (the clock
//! starts when the firewall first sees the digest, never earlier), and a child (an index's manifest, a layer, a config) takes the
//! date of the manifest that named it. A tag is only a name: every request for one asks the registry for its manifest and judges the
//! digest it names now.
//!
//! URLs. Every upstream URL is rebuilt from the parsed identity. A `Link` header, an upload `Location` and a token realm that
//! leave the registry's origin are refused (or, for the one realm table, allowed by name), so no URL of a registry leads a client
//! around the firewall.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::http::Method;
use bytes::Bytes;
use serde::Deserialize;
use url::Url;

use crate::App;
use crate::artifacts::ArtifactReference;
use crate::http::error::{ApiError, storage_error};
use crate::managed::Principal;
use crate::managed::report::Call;
use crate::oci::coords::{self, Algorithm, Digest, Reference};
use crate::policy::{Candidate, Decision, DenyReason, Ecosystem, PublicationTime};
use crate::store::cache::Advertised;
use crate::store::rows::{ProjectRefresh, ReferenceId, ReferenceUpsert};
use crate::upstream::{
    OciRequest, OciResponse, OriginKind, OriginSet, UpstreamError, UpstreamValidators,
};

/// A manifest or an index: twice the 4 MiB the distribution spec says a registry must accept (the largest real ones measured on Docker Hub,
/// 2026-11-20, are an 11 KB index of 18 platforms and a 2.3 KB image manifest of 7 layers).
const MANIFEST_CAP: u64 = 8 << 20;
/// A tag list, a catalog or a referrers index is read to `max(max_metadata_bytes, DOC_FLOOR)`.
const DOC_FLOOR: u64 = 16 << 20;
const TOKEN_CAP: u64 = 64 << 10;
/// Entries of one list document.
const MAX_ENTRIES: usize = 500_000;
/// Descriptors of one manifest or index (a real image has under 130 layers, a real index a few hundred manifests).
const MAX_CHILDREN: usize = 20_000;
const ROWS_FACTOR: u64 = 5;
const PLACES_PER_REGISTRY: usize = 8;
/// One owner (the account on a key route, the client address /64 in a shared service) holds at most this many of a registry's places
/// and at most half of the process's: a credential is chosen by the client, so it is only a second count.
const PLACES_PER_OWNER: usize = 4;
const PLACES_PER_CREDENTIAL: usize = 2;
const MAX_TOKENS_PER_OWNER: usize = 32;
/// Pages of a referrers list followed for one answer.
const MAX_PAGES: usize = 64;
const UPLOAD_QUEUE_WAIT: Duration = Duration::from_secs(600);
/// Requests of one owner that may wait for an upload lane (the rest are refused at once).
const LANE_WAITERS: usize = 6;
const REPOSITORY_COUNT_TTL: Duration = Duration::from_secs(60);
const MAX_HEADS: usize = 1_024;
const HEAD_TTL: Duration = Duration::from_secs(30);
const PLACE_WAIT: Duration = Duration::from_secs(30);
const MAX_PLACE_TABLE: usize = 1_024;
pub const DEADLINE: Duration = Duration::from_secs(120);
const REALM_TTL: Duration = Duration::from_secs(600);
const TOKEN_FLOOR: Duration = Duration::from_secs(30);
const TOKEN_CEIL: Duration = Duration::from_secs(240);
const MAX_TOKENS: usize = 256;
const MAX_REALMS: usize = 64;
const MAX_MANIFESTS: usize = 256;
const MANIFEST_TTL: Duration = Duration::from_secs(60);
const EXISTS_TTL: Duration = Duration::from_secs(30);
const MAX_EXISTS: usize = 4_096;
const MAX_REGISTERED: usize = 4_096;
const MAX_GATES: usize = 1_024;

/// Registries whose token service is a host of their own (the public registries').
const REALM_TABLE: &[(&str, &str)] = &[
    ("registry-1.docker.io", "auth.docker.io"),
    ("index.docker.io", "auth.docker.io"),
    ("gcr.io", "gcr.io"),
    ("ghcr.io", "ghcr.io"),
    ("quay.io", "quay.io"),
    ("public.ecr.aws", "public.ecr.aws"),
];

#[derive(Clone, Debug)]
pub enum Challenge {
    Bearer { realm: Url, service: Option<String> },
    Basic,
}

struct Token {
    value: String,
    until: Instant,
    made: Instant,
    owner: u64,
}

type Tokens = std::sync::Mutex<HashMap<(String, String), Token>>;
type OwnerPlaces = std::sync::Mutex<HashMap<(u64, u64), Arc<tokio::sync::Semaphore>>>;
type OwnerLane = std::sync::Mutex<HashMap<u64, Arc<tokio::sync::Semaphore>>>;
type Heads =
    std::sync::Mutex<HashMap<(u64, String, String, String), (Instant, Digest, String, u64)>>;
type CredentialPlaces = std::sync::Mutex<HashMap<(u64, [u8; 8]), Arc<tokio::sync::Semaphore>>>;
type RowGates = std::sync::Mutex<HashMap<(u64, String), Arc<tokio::sync::Mutex<()>>>>;
type Manifests = std::sync::Mutex<HashMap<(u64, String, String, String), (Instant, Bytes, String)>>;

pub struct Shared {
    /// Keys the firewall's own tokens (see [`mint_local_token`]); random at start, never stored.
    token_secret: [u8; 32],
    tokens: Tokens,
    realms: std::sync::Mutex<HashMap<String, (Option<Challenge>, Instant)>>,
    per_registry: std::sync::Mutex<HashMap<u64, Arc<tokio::sync::Semaphore>>>,
    per_credential: CredentialPlaces,
    per_owner: OwnerPlaces,
    owner_lane: OwnerLane,
    upload_lanes: std::sync::Mutex<HashMap<u64, Arc<Lane>>>,
    global: Arc<tokio::sync::Semaphore>,
    global_places: usize,
    heads: Heads,
    repositories: std::sync::Mutex<HashMap<u64, (Instant, u64)>>,
    repository_gate: tokio::sync::Mutex<()>,
    row_gates: RowGates,
    manifests: Manifests,
    exists: std::sync::Mutex<HashMap<(u64, String, ReferenceId), Instant>>,
    registered: std::sync::Mutex<HashMap<(u64, String, String), Instant>>,
}

impl Default for Shared {
    fn default() -> Self {
        Shared::new(32)
    }
}

impl Shared {
    pub fn new(max_upstream_requests: usize) -> Shared {
        let mut token_secret = [0u8; 32];
        // (a process that cannot get randomness has no tokens that verify: the secret stays zero only if the system refuses, which the start-up key reads would have failed on first)
        getrandom::fill(&mut token_secret).expect("the system's randomness");
        Shared {
            token_secret,
            tokens: Default::default(),
            realms: Default::default(),
            per_registry: Default::default(),
            per_credential: Default::default(),
            per_owner: Default::default(),
            owner_lane: Default::default(),
            upload_lanes: Default::default(),
            global: Arc::new(tokio::sync::Semaphore::new(
                (max_upstream_requests / 2).clamp(4, 32),
            )),
            global_places: (max_upstream_requests / 2).clamp(4, 32),
            heads: Default::default(),
            repositories: Default::default(),
            repository_gate: Default::default(),
            row_gates: Default::default(),
            manifests: Default::default(),
            exists: Default::default(),
            registered: Default::default(),
        }
    }
}

/// The sizes of the bounded process tables (tokens, realms, places, credential places, gates, manifests, existence memo, registered).
pub fn table_sizes(app: &App) -> [usize; 8] {
    let s = &app.oci;
    [
        lock(&s.tokens).len(),
        lock(&s.realms).len(),
        lock(&s.per_registry).len(),
        lock(&s.per_credential).len(),
        lock(&s.row_gates).len(),
        lock(&s.manifests).len(),
        lock(&s.exists).len(),
        lock(&s.registered).len(),
    ]
}

tokio::task_local! {
    static OWNER: u64;
}

/// Runs `work` for `owner` (the key `spool::owner_of` gives: the account on a key route, the client address /64 in a shared service; for a
/// standalone firewall, the peer's own): every registry exchange it makes counts against that owner's share of the places.
pub async fn with_owner<F: std::future::Future>(owner: u64, work: F) -> F::Output {
    OWNER.scope(owner, work).await
}

/// The standalone firewall has no principal: its owner is the peer address (a /64 for IPv6).
pub fn owner_of_peer(peer: Option<std::net::IpAddr>) -> u64 {
    use sha2::Digest as _;
    let mut hash = sha2::Sha256::new();
    hash.update(b"peer");
    match peer.map(|ip| ip.to_canonical()) {
        Some(std::net::IpAddr::V4(v4)) => hash.update(v4.octets()),
        Some(std::net::IpAddr::V6(v6)) => hash.update(&v6.octets()[..8]),
        None => {}
    }
    u64::from_be_bytes(hash.finalize()[..8].try_into().expect("8 bytes"))
}

fn current_owner() -> u64 {
    OWNER.try_with(|owner| *owner).unwrap_or(0)
}

/// Makes room for one more entry by dropping the OLDEST ones (never the whole table: one client cannot flush everyone else's entries).
fn make_room<K: Clone + Eq + std::hash::Hash, V>(
    map: &mut HashMap<K, V>,
    cap: usize,
    stamp: impl Fn(&V) -> Instant,
) {
    while map.len() >= cap {
        let Some(oldest) = map
            .iter()
            .min_by_key(|(_, value)| stamp(value))
            .map(|(key, _)| key.clone())
        else {
            break;
        };
        map.remove(&oldest);
    }
}

fn lock<T>(mutex: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn digest_of_text(text: &str) -> [u8; 8] {
    use sha2::Digest as _;
    sha2::Sha256::digest(text.as_bytes())[..8]
        .try_into()
        .expect("8 bytes")
}

// ------------------------------------------------------------------ origins and the upstream exchange

struct Origins {
    set: OriginSet,
    kind: OriginKind,
    /// The registry's own origin as the transport's `origin` argument (None: the process's default registry).
    selected: Option<Url>,
    /// The private ranges the registry's descriptor allows its address to be in.
    cidrs: Vec<ipnet::IpNet>,
    /// The token origin the registry's descriptor declares, if any.
    token_origin: Option<Url>,
}

fn origins_for(app: &App, principal: Option<&Principal>) -> Result<Origins, ApiError> {
    match principal.and_then(|p| p.registry_origin.as_ref()) {
        Some(origin) => Ok(Origins {
            set: OriginSet::selected_npm_with_private(
                origin.clone(),
                principal.map_or(Vec::new(), |p| p.registry_private_cidrs.clone()),
            )
            .map_err(|_| ApiError::NotFound)?,
            kind: OriginKind::NpmMetadata,
            selected: Some(origin.clone()),
            cidrs: principal.map_or(Vec::new(), |p| p.registry_private_cidrs.clone()),
            token_origin: principal.and_then(|p| p.registry_token_origin.clone()),
        }),
        None => Ok(Origins {
            set: app.origins.clone(),
            kind: OriginKind::OciRegistry,
            selected: None,
            cidrs: Vec::new(),
            token_origin: app.config.oci_token_url.clone(),
        }),
    }
}

impl Origins {
    fn root(&self) -> &Url {
        self.set.origin(self.kind)
    }

    fn url(&self, segments: &[&str], query: &[(String, String)]) -> Result<Url, ApiError> {
        // (a repository name is several URL segments)
        let mut all = vec!["v2"];
        all.extend(segments.iter().flat_map(|segment| segment.split('/')));
        let mut url = self
            .set
            .url_for(self.kind, &all)
            .map_err(|_| ApiError::NotFound)?;
        if segments.is_empty() {
            // The API's root is `/v2/` (a registry may redirect `/v2`, or not).
            let path = format!("{}/", url.path().trim_end_matches('/'));
            url.set_path(&path);
        }
        if !query.is_empty() {
            url.query_pairs_mut()
                .extend_pairs(query.iter().map(|(k, v)| (k.as_str(), v.as_str())));
        }
        Ok(url)
    }
}

fn caller(principal: Option<&Principal>) -> Option<&str> {
    principal.and_then(|p| p.registry_read_authorization.as_deref())
}

fn status_error(app: &App, status: u16) -> ApiError {
    match status {
        404 | 410 => ApiError::NotFound,
        401 if app.service_policy().is_some() => ApiError::UpstreamUnauthenticated,
        403 if app.service_policy().is_some() => ApiError::UpstreamDenied,
        429 => ApiError::Overloaded,
        other => {
            tracing::warn!(
                status = other,
                "the OCI registry answered with a status this firewall does not serve"
            );
            ApiError::UpstreamFailure
        }
    }
}

fn upstream_error(app: &App, error: UpstreamError) -> ApiError {
    match error {
        UpstreamError::Status(code) => status_error(app, code),
        UpstreamError::Timeout => ApiError::UpstreamTimeout,
        other => {
            tracing::warn!(error = %other, "the OCI registry exchange failed");
            ApiError::UpstreamFailure
        }
    }
}

struct Places {
    _owner_registry: tokio::sync::OwnedSemaphorePermit,
    _owner_global: tokio::sync::OwnedSemaphorePermit,
    _credential: Option<tokio::sync::OwnedSemaphorePermit>,
    _registry: tokio::sync::OwnedSemaphorePermit,
    _global: tokio::sync::OwnedSemaphorePermit,
}

/// One exchange holds a place of its owner (at most `PLACES_PER_OWNER` of the registry's and half of the process's), of its caller's
/// credential (at most two of the registry's eight: a second count, since a client can present any number of junk credentials), of the
/// registry, and of the process. Anonymous callers have an owner too (their address).
async fn places(app: &App, registry_id: u64, credential: Option<&str>) -> Result<Places, ApiError> {
    let owner = current_owner();
    tokio::time::timeout(PLACE_WAIT, async {
        let owned = {
            let mut map = lock(&app.oci.per_owner);
            if map.len() >= MAX_PLACE_TABLE && !map.contains_key(&(registry_id, owner)) {
                map.retain(|_, semaphore| Arc::strong_count(semaphore) > 1);
            }
            Arc::clone(
                map.entry((registry_id, owner))
                    .or_insert_with(|| Arc::new(tokio::sync::Semaphore::new(PLACES_PER_OWNER))),
            )
        };
        let owner_registry = owned
            .acquire_owned()
            .await
            .map_err(|_| ApiError::InternalFailure)?;
        let lane = {
            let mut map = lock(&app.oci.owner_lane);
            if map.len() >= MAX_PLACE_TABLE && !map.contains_key(&owner) {
                map.retain(|_, semaphore| Arc::strong_count(semaphore) > 1);
            }
            Arc::clone(map.entry(owner).or_insert_with(|| {
                Arc::new(tokio::sync::Semaphore::new(
                    (app.oci.global_places / 2).max(2),
                ))
            }))
        };
        let owner_global = lane
            .acquire_owned()
            .await
            .map_err(|_| ApiError::InternalFailure)?;
        let share =
            credential.map(|text| {
                let mut map = lock(&app.oci.per_credential);
                let key = (registry_id, digest_of_text(text));
                if map.len() >= MAX_PLACE_TABLE && !map.contains_key(&key) {
                    map.retain(|_, semaphore| Arc::strong_count(semaphore) > 1);
                }
                Arc::clone(map.entry(key).or_insert_with(|| {
                    Arc::new(tokio::sync::Semaphore::new(PLACES_PER_CREDENTIAL))
                }))
            });
        let credential = match share {
            Some(semaphore) => Some(
                semaphore
                    .acquire_owned()
                    .await
                    .map_err(|_| ApiError::InternalFailure)?,
            ),
            None => None,
        };
        let own = {
            let mut map = lock(&app.oci.per_registry);
            if map.len() >= MAX_PLACE_TABLE && !map.contains_key(&registry_id) {
                map.retain(|_, semaphore| Arc::strong_count(semaphore) > 1);
            }
            Arc::clone(
                map.entry(registry_id)
                    .or_insert_with(|| Arc::new(tokio::sync::Semaphore::new(PLACES_PER_REGISTRY))),
            )
        };
        let registry = own
            .acquire_owned()
            .await
            .map_err(|_| ApiError::InternalFailure)?;
        let global = Arc::clone(&app.oci.global)
            .acquire_owned()
            .await
            .map_err(|_| ApiError::InternalFailure)?;
        Ok::<_, ApiError>(Places {
            _owner_registry: owner_registry,
            _owner_global: owner_global,
            _credential: credential,
            _registry: registry,
            _global: global,
        })
    })
    .await
    .map_err(|_| ApiError::UpstreamTimeout)?
}

/// `WWW-Authenticate: Bearer realm="...",service="...",scope="..."` (the first Bearer challenge, else Basic).
fn parse_challenge(values: &[&str]) -> Option<(Challenge, Option<String>)> {
    let mut basic = false;
    for value in values {
        let value = value.trim();
        let Some((scheme, rest)) = value.split_once(' ').or(Some((value, ""))) else {
            continue;
        };
        if scheme.eq_ignore_ascii_case("basic") {
            basic = true;
        }
        if !scheme.eq_ignore_ascii_case("bearer") {
            continue;
        }
        let (mut realm, mut service, mut scope) = (None, None, None);
        let mut rest = rest.trim();
        while !rest.is_empty() {
            let (key, after) = rest.split_once('=')?;
            let after = after.trim_start();
            let (text, remaining) = if let Some(quoted) = after.strip_prefix('"') {
                let end = quoted.find('"')?;
                (&quoted[..end], &quoted[end + 1..])
            } else {
                let end = after.find(',').unwrap_or(after.len());
                (&after[..end], &after[end..])
            };
            match key.trim().to_ascii_lowercase().as_str() {
                "realm" => realm = Some(text.to_owned()),
                "service" => service = Some(text.to_owned()),
                "scope" => scope = Some(text.to_owned()),
                _ => {}
            }
            rest = remaining.trim_start_matches([',', ' ']);
        }
        let realm = Url::parse(&realm?).ok()?;
        return Some((Challenge::Bearer { realm, service }, scope));
    }
    basic.then_some((Challenge::Basic, None))
}

/// A realm the firewall may send a credential to: the registry's own origin, or the token host the registry is known by.
fn realm_allowed(registry: &Url, realm: &Url, declared: Option<&Url>) -> bool {
    if !realm.username().is_empty() || realm.password().is_some() || realm.fragment().is_some() {
        return false;
    }
    // The token origin the registry's descriptor declares (https only): exactly that origin.
    if declared.is_some_and(|declared| {
        declared.scheme() == "https" && realm.scheme() == "https" && same_origin(declared, realm)
    }) {
        return true;
    }
    let same_origin = realm.scheme() == registry.scheme()
        && realm.host_str() == registry.host_str()
        && realm.port_or_known_default() == registry.port_or_known_default();
    if same_origin {
        return true;
    }
    realm.scheme() == "https"
        && realm.port().is_none()
        && registry.host_str().is_some_and(|host| {
            REALM_TABLE.iter().any(|(registry_host, auth)| {
                *registry_host == host && realm.host_str() == Some(*auth)
            })
        })
}

fn same_origin(a: &Url, b: &Url) -> bool {
    a.scheme() == b.scheme()
        && a.host_str() == b.host_str()
        && a.port_or_known_default() == b.port_or_known_default()
}

#[derive(Deserialize)]
struct TokenDoc {
    token: Option<String>,
    access_token: Option<String>,
    expires_in: Option<u64>,
}

fn token_text_ok(text: &str) -> bool {
    !text.is_empty() && text.len() <= 8192 && text.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

/// Asks a realm for a token with the given credential (the caller's Basic, or none for an anonymous one).
async fn fetch_token(
    app: &App,
    origins: &Origins,
    realm: &Url,
    service: Option<&str>,
    scopes: &[String],
    basic: Option<&str>,
) -> Result<(String, Duration), ApiError> {
    let registry = origins.root();
    if !realm_allowed(registry, realm, origins.token_origin.as_ref()) {
        tracing::warn!(realm = %realm, "a token realm outside the registry's origin and the realm table is never asked");
        return Err(ApiError::UpstreamFailure);
    }
    let mut url = realm.clone();
    {
        let mut query = url.query_pairs_mut();
        query.clear();
        if let Some(service) = service {
            query.append_pair("service", service);
        }
        for scope in scopes {
            query.append_pair("scope", scope);
        }
    }
    // A realm on the registry's own origin is asked through the registry's own route; another is its own origin.
    let origin = if same_origin(registry, realm) {
        origins.selected.clone()
    } else {
        let mut root = realm.clone();
        root.set_path("/");
        root.set_query(None);
        Some(root)
    };
    let response = app
        .transport
        .fetch_oci(OciRequest {
            url,
            origin,
            private_cidrs: origins.cidrs.clone(),
            method: Method::GET,
            authorization: basic.map(str::to_owned),
            accept: Some("application/json".to_owned()),
            content_type: None,
            content_range: None,
            body: None,
            max_bytes: TOKEN_CAP,
        })
        .await;
    app.upstreams.record_upstream(
        Call::Oci,
        &response.as_ref().map(|_| ()).map_err(Clone::clone),
    );
    let response = response.map_err(|error| upstream_error(app, error))?;
    if response.status != 200 {
        return Err(status_error(app, response.status));
    }
    let doc: TokenDoc =
        serde_json::from_slice(&response.body).map_err(|_| ApiError::UpstreamInvalid)?;
    let value = doc
        .token
        .or(doc.access_token)
        .filter(|text| token_text_ok(text))
        .ok_or(ApiError::UpstreamInvalid)?;
    let life = Duration::from_secs(doc.expires_in.unwrap_or(60)).clamp(TOKEN_FLOOR, TOKEN_CEIL);
    Ok((value, life))
}

/// What the registry asks of an unauthenticated caller (`None`: nothing), read from its `/v2/` and remembered.
async fn discover(app: &App, origins: &Origins) -> Result<Option<Challenge>, ApiError> {
    let key = origins.root().to_string();
    if let Some((found, at)) = lock(&app.oci.realms).get(&key).cloned()
        && at.elapsed() < REALM_TTL
    {
        return Ok(found);
    }
    let response = app
        .transport
        .fetch_oci(OciRequest {
            url: origins.url(&[], &[])?,
            origin: origins.selected.clone(),
            private_cidrs: origins.cidrs.clone(),
            method: Method::GET,
            authorization: None,
            accept: Some("application/json".to_owned()),
            content_type: None,
            content_range: None,
            body: None,
            max_bytes: TOKEN_CAP,
        })
        .await;
    app.upstreams.record_upstream(
        Call::Oci,
        &response.as_ref().map(|_| ()).map_err(Clone::clone),
    );
    let response = response.map_err(|error| upstream_error(app, error))?;
    let found = match response.status {
        401 => {
            let values: Vec<&str> = response.headers_all("www-authenticate").collect();
            parse_challenge(&values).map(|(challenge, _)| challenge)
        }
        200 | 404 => None,
        other => return Err(status_error(app, other)),
    };
    let mut realms = lock(&app.oci.realms);
    if !realms.contains_key(&key) {
        make_room(&mut realms, MAX_REALMS, |(_, at)| *at);
    }
    realms.insert(key, (found.clone(), Instant::now()));
    Ok(found)
}

fn anonymous_cached(app: &App, origin: &str, scope: &str) -> Option<String> {
    lock(&app.oci.tokens)
        .get(&(origin.to_owned(), scope.to_owned()))
        .filter(|token| token.until > Instant::now())
        .map(|token| token.value.clone())
}

/// The anonymous token of one scope (a public image needs one even from nobody): shared by every anonymous caller of the registry.
async fn anonymous_token(
    app: &App,
    origins: &Origins,
    scope: &str,
) -> Result<Option<String>, ApiError> {
    let origin = origins.root().to_string();
    if let Some(value) = anonymous_cached(app, &origin, scope) {
        return Ok(Some(value));
    }
    let Some(Challenge::Bearer { realm, service }) = discover(app, origins).await? else {
        return Ok(None);
    };
    let (value, life) = fetch_token(
        app,
        origins,
        &realm,
        service.as_deref(),
        &[scope.to_owned()],
        None,
    )
    .await?;
    let owner = current_owner();
    let mut tokens = lock(&app.oci.tokens);
    tokens.retain(|_, token| token.until > Instant::now());
    // One owner may keep at most `MAX_TOKENS_PER_OWNER` entries (its own oldest go first), and the table drops its oldest entry, never everyone's.
    let key = (origin, scope.to_owned());
    while tokens.values().filter(|token| token.owner == owner).count() >= MAX_TOKENS_PER_OWNER {
        let Some(oldest) = tokens
            .iter()
            .filter(|(_, token)| token.owner == owner)
            .min_by_key(|(_, token)| token.made)
            .map(|(key, _)| key.clone())
        else {
            break;
        };
        tokens.remove(&oldest);
    }
    if !tokens.contains_key(&key) {
        make_room(&mut tokens, MAX_TOKENS, |token| token.made);
    }
    tokens.insert(
        key,
        Token {
            value: value.clone(),
            until: Instant::now() + life,
            made: Instant::now(),
            owner,
        },
    );
    Ok(Some(value))
}

/// The credential an upstream exchange for `scope` carries. The caller's Bearer token goes as it is (to the registry's origin only);
/// the caller's Basic credential is exchanged for a token when the registry wants one (the credential goes to the registry's origin
/// and to an allowed realm, nowhere else); a caller with none gets the shared anonymous token.
async fn authorization(
    app: &App,
    origins: &Origins,
    principal: Option<&Principal>,
    scope: &str,
) -> Result<Option<String>, ApiError> {
    match caller(principal) {
        Some(value) if value.starts_with("Basic ") => match discover(app, origins).await? {
            Some(Challenge::Bearer { realm, service }) => {
                let (token, _) = fetch_token(
                    app,
                    origins,
                    &realm,
                    service.as_deref(),
                    &[scope.to_owned()],
                    Some(value),
                )
                .await?;
                Ok(Some(format!("Bearer {token}")))
            }
            _ => Ok(Some(value.to_owned())),
        },
        Some(value) => Ok(Some(value.to_owned())),
        None => Ok(anonymous_token(app, origins, scope)
            .await?
            .map(|token| format!("Bearer {token}"))),
    }
}

fn origins_of(
    app: &App,
    origin: Option<&Url>,
    private_cidrs: &[ipnet::IpNet],
    registry_id: u64,
) -> Result<Origins, UpstreamError> {
    // (The blob transfer runs in a task of its own with no principal: the registry's declared token origin is read from the snapshot.)
    let token_origin = app
        .service_policy()
        .and_then(|service| service.snapshot())
        .and_then(|snapshot| {
            snapshot
                .registries
                .iter()
                .find(|r| r.registry.0 == registry_id)
                .and_then(|r| r.token_origin.as_deref().and_then(|text| text.parse().ok()))
        });
    match origin {
        Some(origin) => Ok(Origins {
            set: OriginSet::selected_npm_with_private(origin.clone(), private_cidrs.to_vec())
                .map_err(UpstreamError::RejectedUrl)?,
            kind: OriginKind::NpmMetadata,
            selected: Some(origin.clone()),
            cidrs: private_cidrs.to_vec(),
            token_origin,
        }),
        None => Ok(Origins {
            set: app.origins.clone(),
            kind: OriginKind::OciRegistry,
            selected: None,
            cidrs: Vec::new(),
            token_origin: app.config.oci_token_url.clone(),
        }),
    }
}

/// The authorization a blob transfer carries when the caller has none: the shared anonymous token of the repository (for the
/// artifact pipeline, which owns the redirect handling and drops it at the first hop that leaves the registry).
pub async fn ambient_authorization(
    app: &App,
    reference: &ArtifactReference,
    registry_id: u64,
    origin: Option<&Url>,
    private_cidrs: &[ipnet::IpNet],
    read_authorization: Option<String>,
) -> Result<Option<String>, UpstreamError> {
    if reference.ecosystem != Ecosystem::Oci {
        return Ok(read_authorization);
    }
    // No credential, not even the firewall's own anonymous token, goes to a foreign layer's host.
    if !same_origin(
        &reference.upstream_url,
        origins_of(app, origin, private_cidrs, registry_id)?.root(),
    ) {
        return Ok(None);
    }
    if let Some(basic) = read_authorization
        .as_deref()
        .filter(|value| value.starts_with("Basic "))
    {
        // A Basic credential (the caller's own, or a registry's stored read credential) is exchanged at the registry's allowed realm for the
        // token a registry that wants tokens takes; one that takes Basic directly gets it as it is.
        let origins = origins_of(app, origin, private_cidrs, registry_id)?;
        let scope = format!("repository:{}:pull", reference.name);
        let status = |error: ApiError| {
            if matches!(error, ApiError::UpstreamTimeout) {
                UpstreamError::Timeout
            } else {
                UpstreamError::Status(401)
            }
        };
        return match discover(app, &origins).await.map_err(status)? {
            Some(Challenge::Bearer { realm, service }) => {
                let (token, _) = fetch_token(
                    app,
                    &origins,
                    &realm,
                    service.as_deref(),
                    &[scope],
                    Some(basic),
                )
                .await
                .map_err(status)?;
                Ok(Some(format!("Bearer {token}")))
            }
            _ => Ok(read_authorization),
        };
    }
    if read_authorization.is_some() {
        return Ok(read_authorization);
    }
    let origins = origins_of(app, origin, private_cidrs, registry_id)?;
    let scope = format!("repository:{}:pull", reference.name);
    match anonymous_token(app, &origins, &scope).await {
        Ok(token) => Ok(token.map(|token| format!("Bearer {token}"))),
        Err(ApiError::UpstreamTimeout) => Err(UpstreamError::Timeout),
        Err(_) => Err(UpstreamError::Status(401)),
    }
}

struct Call2<'a> {
    method: Method,
    url: Url,
    accept: Option<&'a str>,
    scope: String,
    max_bytes: u64,
    content_type: Option<String>,
    content_range: Option<String>,
    body: Option<(tokio::fs::File, u64)>,
}

/// One exchange with the registry: a place, the credential for the scope, the request. A read the registry answers `401` to with
/// an anonymous token that went stale is made once more with a new one.
async fn exchange(
    app: &App,
    principal: Option<&Principal>,
    registry_id: u64,
    origins: &Origins,
    mut call: Call2<'_>,
) -> Result<OciResponse, ApiError> {
    let _places = places(app, registry_id, caller(principal)).await?;
    let mut retried = false;
    loop {
        let authorization = authorization(app, origins, principal, &call.scope).await?;
        let anonymous = caller(principal).is_none() && authorization.is_some();
        let body = call.body.take();
        let replay = body.is_none();
        let response = app
            .transport
            .fetch_oci(OciRequest {
                url: call.url.clone(),
                origin: origins.selected.clone(),
                private_cidrs: origins.cidrs.clone(),
                method: call.method.clone(),
                authorization,
                accept: call.accept.map(str::to_owned),
                content_type: call.content_type.clone(),
                content_range: call.content_range.clone(),
                body,
                max_bytes: call.max_bytes,
            })
            .await;
        app.upstreams.record_upstream(
            Call::Oci,
            &response.as_ref().map(|_| ()).map_err(Clone::clone),
        );
        let response = response.map_err(|error| upstream_error(app, error))?;
        if response.status == 401 && anonymous && replay && !retried {
            lock(&app.oci.tokens).remove(&(origins.root().to_string(), call.scope.clone()));
            retried = true;
            continue;
        }
        return Ok(response);
    }
}

// ------------------------------------------------------------------ policy

fn check_policy(
    app: &App,
    principal: Option<&Principal>,
) -> Result<(Arc<crate::policy::CompiledPolicy>, i64), ApiError> {
    let now = app.clock.now_utc_micros();
    let policy = app
        .policy_for(principal)
        .ok_or(ApiError::PolicyUnavailable)?;
    if !policy
        .snapshot
        .as_deref()
        .is_some_and(|snapshot| snapshot.is_valid_at(now))
    {
        return Err(ApiError::PolicyUnavailable);
    }
    Ok((policy, now))
}

fn blocked_outright(
    policy: &crate::policy::CompiledPolicy,
    now: i64,
    name: &str,
    version: Option<&str>,
) -> Option<Decision> {
    let candidate = Candidate {
        ecosystem: Ecosystem::Oci,
        name,
        version: version.unwrap_or(""),
        publication: PublicationTime::Unknown,
        advertised_digests: &[],
        pinned_digests: &[],
    };
    match crate::policy::decide(policy, &candidate, now, false).decision {
        decision @ Decision::Deny(DenyReason::BlockedPackage | DenyReason::BlockedVersion) => {
            Some(decision)
        }
        _ => None,
    }
}

/// One place of an owner's upload lane (see [`upload_lane`]).
/// (It holds the lane itself too: the table's clean-up drops lanes nobody holds, and a streaming layer is holding this one.)
pub struct UploadLane(
    #[allow(dead_code)] tokio::sync::OwnedSemaphorePermit,
    #[allow(dead_code)] Arc<Lane>,
);

/// An owner's lane: the layers it may spool at once, and how many requests are waiting for one.
pub struct Lane {
    seats: Arc<tokio::sync::Semaphore>,
    waiting: std::sync::atomic::AtomicUsize,
}

struct Waiting(Arc<Lane>);

impl Drop for Waiting {
    fn drop(&mut self) {
        self.0
            .waiting
            .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

/// An owner's turn to spool a layer: it pushes as many layers at once as its share of the spool budget holds at the largest size a layer may
/// have (two by default), and the next ones WAIT their turn in order (at most `LANE_WAITERS` of them per owner, the rest are a 503 at once, and
/// a wait ends in a 503 after ten minutes, before any byte of the body is read: docker retries a layer upload) instead of failing in the middle
/// of their stream. Only a request whose body can be large takes it (see `oci_routes::big_body`); the caller holds no active-request permit while it waits.
pub async fn upload_lane(app: &App, owner: u64) -> Result<UploadLane, ApiError> {
    let permits = ((app.limits.spool_budget_total() / 2)
        / app.config.max_artifact_bytes.get().max(1))
    .clamp(1, 4) as usize;
    let lane = {
        let mut map = lock(&app.oci.upload_lanes);
        if map.len() >= MAX_PLACE_TABLE && !map.contains_key(&owner) {
            map.retain(|_, lane| Arc::strong_count(lane) > 1);
        }
        Arc::clone(map.entry(owner).or_insert_with(|| {
            Arc::new(Lane {
                seats: Arc::new(tokio::sync::Semaphore::new(permits)),
                waiting: Default::default(),
            })
        }))
    };
    if let Ok(permit) = Arc::clone(&lane.seats).try_acquire_owned() {
        return Ok(UploadLane(permit, lane));
    }
    if lane
        .waiting
        .fetch_add(1, std::sync::atomic::Ordering::AcqRel)
        >= LANE_WAITERS
    {
        lane.waiting
            .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
        return Err(ApiError::Overloaded);
    }
    let _waiting = Waiting(Arc::clone(&lane));
    let permit = tokio::time::timeout(UPLOAD_QUEUE_WAIT, Arc::clone(&lane.seats).acquire_owned())
        .await
        .map_err(|_| ApiError::Overloaded)?
        .map_err(|_| ApiError::InternalFailure)?;
    Ok(UploadLane(permit, lane))
}

/// A repository, tag or digest a policy blocks outright is refused without asking any registry anything (PERF-01).
pub fn locally_blocked(
    app: &App,
    principal: Option<&Principal>,
    name: &str,
    version: Option<&str>,
) -> Result<(), ApiError> {
    let (policy, now) = check_policy(app, principal)?;
    // A digest blocked under any repository is blocked in every one.
    let anywhere = version
        .filter(|text| text.contains(':'))
        .and_then(|text| blocked_anywhere(&policy, now, text));
    if let Some(decision) = blocked_outright(&policy, now, name, version).or(anywhere) {
        if let (Some(principal), Some(managed)) = (principal, app.managed()) {
            let candidate = Candidate {
                ecosystem: Ecosystem::Oci,
                name,
                version: version.unwrap_or(""),
                publication: PublicationTime::Unknown,
                advertised_digests: &[],
                pinned_digests: &[],
            };
            managed.record_refused(
                principal,
                &policy,
                now,
                &candidate,
                decision,
                version.is_some(),
            );
        }
        return Err(crate::artifacts::decision_error(decision, now));
    }
    Ok(())
}

fn cooldown_only(decision: &Decision) -> bool {
    matches!(decision, Decision::Hold { .. })
}

fn url_hex(digest: &Digest) -> String {
    digest.to_string()
}

fn policy_digest(digest: &Digest) -> crate::policy::Digest {
    crate::policy::Digest {
        algorithm: if digest.algorithm == Algorithm::Sha256 {
            crate::policy::HashAlgorithm::Sha256
        } else {
            crate::policy::HashAlgorithm::Sha512
        },
        bytes: Box::from(digest.raw().as_slice()),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Manifest,
    Blob,
}

fn reference_of(
    origins: &Origins,
    registry_id: u64,
    name: &str,
    kind: Kind,
    digest: &Digest,
) -> Option<(ReferenceId, ArtifactReference)> {
    let text = url_hex(digest);
    let url = origins
        .url(
            &[
                name,
                if kind == Kind::Manifest {
                    "manifests"
                } else {
                    "blobs"
                },
                &text,
            ],
            &[],
        )
        .ok()?;
    let reference = ArtifactReference {
        ecosystem: Ecosystem::Oci,
        name: name.to_owned(),
        version: text.clone(),
        filename: format!(
            "{}/{text}",
            if kind == Kind::Manifest {
                "manifests"
            } else {
                "blobs"
            }
        ),
        upstream_url: url,
        // A digest names its bytes: the pipeline verifies them before the first one leaves.
        expected: vec![policy_digest(digest)],
    };
    Some((
        ReferenceId::compute_in_registry(registry_id, &reference),
        reference,
    ))
}

fn row_limit(app: &App) -> u64 {
    ROWS_FACTOR * u64::from(app.config.max_references_per_project.get())
}

async fn row_gate(app: &App, registry_id: u64, name: &str) -> tokio::sync::OwnedMutexGuard<()> {
    let gate = {
        let mut gates = lock(&app.oci.row_gates);
        let key = (registry_id, name.to_owned());
        if gates.len() >= MAX_GATES && !gates.contains_key(&key) {
            gates.retain(|_, gate| Arc::strong_count(gate) > 1);
        }
        Arc::clone(gates.entry(key).or_default())
    };
    gate.lock_owned().await
}

/// A repository may hold at most `ROWS_FACTOR` times `max_references_per_project` rows: past it a new row is a 503 and nothing is
/// committed. The caller holds the repository's row gate from this check to the commit it guards.
async fn within_row_bound(
    app: &App,
    registry_id: u64,
    name: &str,
    extra: u64,
) -> Result<(), ApiError> {
    let rows = app
        .store()
        .count_project_references_in(registry_id, Ecosystem::Oci, name)
        .await
        .map_err(storage_error)?;
    if rows.saturating_add(extra) > row_limit(app) {
        tracing::warn!(repository = %name, rows, "a repository is at its reference row bound: one more row is refused");
        return Err(ApiError::Overloaded);
    }
    Ok(())
}

/// Commits rows (identity and first-seen times, never a response) and returns the committed first-seen times.
async fn commit_rows(
    app: &App,
    registry_id: u64,
    name: &str,
    references: Vec<ReferenceUpsert>,
) -> Result<HashMap<ReferenceId, i64>, ApiError> {
    let now = app.clock.now_utc_micros();
    let committed = app
        .store()
        .commit_request_references_in(
            registry_id,
            ProjectRefresh {
                ecosystem: Ecosystem::Oci,
                name: name.to_owned(),
                payload: Arc::from(&[][..]),
                validators: UpstreamValidators::default(),
                validated_at_micros: now,
                fetched_at_micros: now,
                references,
            },
        )
        .await
        .map_err(storage_error)?;
    Ok(committed.first_seen)
}

// ------------------------------------------------------------------ manifests

#[derive(Deserialize)]
struct Desc {
    digest: Option<String>,
    /// A "foreign" layer's own download URLs (Windows base layers): the client would fetch them itself, outside the firewall.
    urls: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct FsLayer {
    #[serde(rename = "blobSum")]
    blob_sum: Option<String>,
}

#[derive(Deserialize)]
struct ManifestDoc {
    #[serde(rename = "mediaType")]
    media_type: Option<String>,
    config: Option<Desc>,
    layers: Option<Vec<Desc>>,
    blobs: Option<Vec<Desc>>,
    manifests: Option<Vec<Desc>>,
    #[serde(rename = "fsLayers")]
    fs_layers: Option<Vec<FsLayer>>,
}

struct Children {
    /// Layers that name download URLs of their own: digest -> the first URL (already admitted).
    foreign: HashMap<Digest, Url>,
    blobs: Vec<Digest>,
    manifests: Vec<Digest>,
    media_type: Option<String>,
}

/// The digests a manifest or an index names, read strictly: one that cannot be read as a digest fails the manifest (502), because
/// the firewall could not vouch for what it names.
fn read_children(body: &[u8], origins: &OriginSet) -> Result<Children, ApiError> {
    let doc: ManifestDoc = serde_json::from_slice(body).map_err(|_| ApiError::UpstreamInvalid)?;
    let parse = |text: Option<&String>| {
        text.and_then(|text| Digest::parse(text))
            .ok_or(ApiError::UpstreamInvalid)
    };
    let mut blobs = Vec::new();
    let mut manifests = Vec::new();
    let mut foreign: HashMap<Digest, Url> = HashMap::new();
    if let Some(config) = &doc.config {
        blobs.push(parse(config.digest.as_ref())?);
    }
    for list in [&doc.layers, &doc.blobs].into_iter().flatten() {
        for layer in list {
            // A foreign layer (Windows base layers) names download URLs of its own. Each must be https, without userinfo, on the operator's host
            // list (`oci_foreign_layer_hosts`); the manifest is judged with its digest like any other, and the firewall serves the layer at the
            // registry blob route from the first URL (a client that fetches the URLs itself does so outside the firewall: docs/operations.md).
            if let Some(urls) = layer.urls.as_ref().filter(|urls| !urls.is_empty()) {
                let mut first = None;
                for text in urls.iter().take(16) {
                    let url = Url::parse(text)
                        .ok()
                        .filter(|url| origins.admits_foreign(url));
                    first = first.or(Some(url.ok_or(ApiError::Blocked { reason: "a layer names a download URL that is not https on the allowed foreign-layer hosts" })?));
                }
                if urls.len() > 16 {
                    return Err(ApiError::Blocked {
                        reason: "a layer names more than sixteen download URLs",
                    });
                }
                let digest = parse(layer.digest.as_ref())?;
                if let Some(first) = first {
                    foreign.entry(digest).or_insert(first);
                }
            }
            blobs.push(parse(layer.digest.as_ref())?);
        }
    }
    for layer in doc.fs_layers.iter().flatten() {
        blobs.push(parse(layer.blob_sum.as_ref())?);
    }
    for child in doc.manifests.iter().flatten() {
        manifests.push(parse(child.digest.as_ref())?);
    }
    if blobs.len() + manifests.len() > MAX_CHILDREN {
        return Err(ApiError::UpstreamInvalid);
    }
    for list in [&mut blobs, &mut manifests] {
        let mut seen = std::collections::HashSet::new();
        list.retain(|digest| seen.insert(digest.clone()));
    }
    Ok(Children {
        blobs,
        manifests,
        foreign,
        media_type: doc.media_type,
    })
}

fn media_type_ok(text: &str) -> bool {
    let essence = text.split(';').next().unwrap_or("");
    text.len() <= 128
        && essence.split_once('/').is_some_and(|(a, b)| {
            !a.is_empty()
                && !b.is_empty()
                && essence.bytes().all(|c| {
                    c.is_ascii_alphanumeric()
                        || matches!(
                            c,
                            b'/' | b'.' | b'+' | b'-' | b'_' | b'!' | b'#' | b'$' | b'&' | b'^'
                        )
                })
        })
}

pub struct Manifest {
    /// The exact bytes (empty for an answer made from the registry's own `HEAD`).
    pub body: Bytes,
    pub length: u64,
    /// Only a manifest or index media type is ever served as the `Content-Type`; anything else is `application/json`.
    pub media_type: String,
    /// The policy identity: the sha256 of the bytes, whatever algorithm the client addressed them by.
    pub digest: Digest,
    /// The digest in the algorithm the client asked with (what `Docker-Content-Digest` must say).
    pub served: Digest,
    /// Whether the exact bytes were read and hashed (a `GET`), or the registry's `HEAD` answer was relayed.
    pub verified: bool,
}

fn default_accept() -> &'static str {
    "application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.v1+prettyjws, application/json"
}

/// The media types a manifest or an index may be served under; anything else a registry sends is served as `application/json`.
pub fn served_media_type(text: &str) -> String {
    let essence = text.split(';').next().unwrap_or("").trim();
    let ok = essence == "application/json"
        || ((essence.starts_with("application/vnd.oci.")
            || essence.starts_with("application/vnd.docker."))
            && (essence.ends_with("+json")
                || essence.ends_with("+prettyjws")
                || essence.ends_with(".v2+json")));
    if ok {
        essence.to_owned()
    } else {
        "application/json".to_owned()
    }
}

/// The tag a registry without the referrers API keeps a subject's referrers under (`sha256-<hex>`).
fn is_referrers_fallback_tag(tag: &str) -> bool {
    tag.strip_prefix("sha256-").is_some_and(|hex| {
        hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    })
}

/// A `HEAD` the registry answered (no bytes): the digest it names, the type and the size. Only used when it names a sha256 digest (and, for a
/// digest reference, the one asked for); anything else is a `GET`.
#[allow(clippy::too_many_arguments)]
async fn head_manifest(
    app: &App,
    principal: Option<&Principal>,
    registry_id: u64,
    origins: &Origins,
    name: &str,
    reference: &Reference,
    accept: Option<&str>,
    shareable: bool,
) -> Result<Option<Manifest>, ApiError> {
    let text = reference.text();
    let key = (
        registry_id,
        origins.root().to_string(),
        name.to_owned(),
        text.clone(),
    );
    let manifest = |digest: Digest, media: &str, length: u64| Manifest {
        body: Bytes::new(),
        length,
        media_type: served_media_type(media),
        served: digest.clone(),
        digest,
        verified: false,
    };
    if shareable
        && let Some((at, digest, media, length)) = lock(&app.oci.heads).get(&key).cloned()
        && at.elapsed() < HEAD_TTL
    {
        return Ok(Some(manifest(digest, &media, length)));
    }
    let url = origins.url(&[name, "manifests", &text], &[])?;
    let response = exchange(
        app,
        principal,
        registry_id,
        origins,
        Call2 {
            method: Method::HEAD,
            url,
            accept: Some(accept.unwrap_or(default_accept())),
            scope: format!("repository:{name}:pull"),
            max_bytes: 1,
            content_type: None,
            content_range: None,
            body: None,
        },
    )
    .await?;
    match response.status {
        200 => {}
        404 | 410 => return Err(ApiError::NotFound),
        // A registry that does not answer a HEAD as it does a GET: the bytes decide.
        405 | 501 => return Ok(None),
        other => return Err(status_error(app, other)),
    }
    let digest = response
        .header("docker-content-digest")
        .and_then(Digest::parse)
        .filter(|digest| digest.algorithm == Algorithm::Sha256);
    let length = response
        .header("content-length")
        .and_then(|text| text.parse::<u64>().ok())
        .filter(|length| (1..=MANIFEST_CAP).contains(length));
    let media = response
        .header("content-type")
        .filter(|text| media_type_ok(text));
    let (Some(digest), Some(length), Some(media)) = (digest, length, media) else {
        return Ok(None);
    };
    if let Reference::Digest(asked) = reference
        && *asked != digest
    {
        return Ok(None);
    }
    if shareable {
        let mut heads = lock(&app.oci.heads);
        if !heads.contains_key(&key) {
            make_room(&mut heads, MAX_HEADS, |(at, ..)| *at);
        }
        heads.insert(
            key,
            (Instant::now(), digest.clone(), media.to_owned(), length),
        );
    }
    Ok(Some(manifest(digest, media, length)))
}

/// What a manifest request is judged as, and the headers' truth: the exact bytes, their digest, their type.
#[allow(clippy::too_many_arguments)]
async fn fetch_manifest(
    app: &App,
    principal: Option<&Principal>,
    registry_id: u64,
    origins: &Origins,
    name: &str,
    reference: &Reference,
    accept: Option<&str>,
    head: bool,
) -> Result<Manifest, ApiError> {
    // C1028: only a read the allow-list of LS-F4 classed cache-eligible (no credential, no header it does not know) reads or fills a shared memo.
    let shareable =
        caller(principal).is_none() && crate::http::credential_read::cache_token(app).is_some();
    // A client's HEAD is the registry's HEAD (Docker Hub counts a manifest GET as a pull and a HEAD as none): the digest it names is judged, and
    // no byte is delivered. The bytes are read (and hashed) only for a GET.
    if head
        && !matches!(reference, Reference::Digest(digest) if digest.algorithm != Algorithm::Sha256)
        && let Some(answer) = head_manifest(
            app,
            principal,
            registry_id,
            origins,
            name,
            reference,
            accept,
            shareable,
        )
        .await?
    {
        return Ok(answer);
    }
    let key = match reference {
        Reference::Digest(digest) if shareable => Some((
            registry_id,
            origins.root().to_string(),
            name.to_owned(),
            digest.to_string(),
        )),
        _ => None,
    };
    if let Some(key) = &key
        && let Some((at, body, media)) = lock(&app.oci.manifests).get(key).cloned()
        && at.elapsed() < MANIFEST_TTL
        && let Reference::Digest(digest) = reference
    {
        let canonical = if digest.algorithm == Algorithm::Sha256 {
            digest.clone()
        } else {
            Digest::of(Algorithm::Sha256, &body)
        };
        return Ok(Manifest {
            length: body.len() as u64,
            body,
            media_type: served_media_type(&media),
            digest: canonical,
            served: digest.clone(),
            verified: true,
        });
    }
    let text = reference.text();
    let url = origins.url(&[name, "manifests", &text], &[])?;
    let response = exchange(
        app,
        principal,
        registry_id,
        origins,
        Call2 {
            method: Method::GET,
            url,
            accept: Some(accept.unwrap_or(default_accept())),
            scope: format!("repository:{name}:pull"),
            max_bytes: MANIFEST_CAP,
            content_type: None,
            content_range: None,
            body: None,
        },
    )
    .await?;
    if response.status != 200 {
        return Err(status_error(app, response.status));
    }
    let algorithm = match reference {
        Reference::Digest(digest) => digest.algorithm,
        Reference::Tag(_) => Algorithm::Sha256,
    };
    let served = Digest::of(algorithm, &response.body);
    // The bytes are the identity: the digest a client asked for, and the one the registry says, must be the bytes' own.
    if let Reference::Digest(asked) = reference
        && *asked != served
    {
        tracing::warn!(repository = %name, "a registry answered a manifest whose bytes are not the digest asked for");
        return Err(ApiError::UpstreamInvalid);
    }
    if let Some(claimed) = response.header("docker-content-digest")
        && Digest::parse(claimed)
            .is_none_or(|claimed| claimed.algorithm == served.algorithm && claimed != served)
    {
        tracing::warn!(repository = %name, "a registry's Docker-Content-Digest is not its manifest's digest");
        return Err(ApiError::UpstreamInvalid);
    }
    // One policy identity per manifest: its sha256, whatever spelling the client used (a block names that one).
    let digest = if served.algorithm == Algorithm::Sha256 {
        served.clone()
    } else {
        Digest::of(Algorithm::Sha256, &response.body)
    };
    let children = read_children(&response.body, &app.origins)?;
    let media = response
        .header("content-type")
        .filter(|text| media_type_ok(text))
        .map(str::to_owned)
        .or(children.media_type.filter(|text| media_type_ok(text)))
        .ok_or(ApiError::UpstreamInvalid)?;
    if let Some(key) = key {
        let mut cache = lock(&app.oci.manifests);
        if !cache.contains_key(&key) {
            make_room(&mut cache, MAX_MANIFESTS, |(at, ..)| *at);
        }
        cache.insert(key, (Instant::now(), response.body.clone(), media.clone()));
    }
    Ok(Manifest {
        length: response.body.len() as u64,
        body: response.body,
        media_type: served_media_type(&media),
        digest,
        served,
        verified: true,
    })
}

/// `GET|HEAD /v2/{name}/manifests/{reference}`. The decision is made on the bytes the registry answered (a HEAD: on the digest it named), after
/// they are in hand, and the policy it is made under is read after that (a block published meanwhile wins).
#[allow(clippy::too_many_arguments)]
pub async fn serve_manifest(
    app: &App,
    principal: Option<&Principal>,
    registry_id: u64,
    name: &str,
    reference: &Reference,
    accept: Option<&str>,
    head: bool,
) -> Result<Manifest, ApiError> {
    locally_blocked(app, principal, name, None)?;
    locally_blocked(app, principal, name, Some(&reference.text()))?;
    let origins = origins_for(app, principal)?;
    let manifest = fetch_manifest(
        app,
        principal,
        registry_id,
        &origins,
        name,
        reference,
        accept,
        head,
    )
    .await?;
    // A HEAD with a credential in a shared service, to a registry that asked for one, is an existence check (a push asks before it uploads):
    // it delivers no content, so the cooldown does not hold it back; a block or a flagged digest still does. A registry that asked for
    // nothing proves nothing about the credential, so there the cooldown applies; so it does on a key route, which has no push.
    let mut exempt = head
        && app.service_policy().is_some()
        && caller(principal).is_some()
        && matches!(discover(app, &origins).await, Ok(Some(_)));
    // The referrers fallback tag of a registry without the referrers API is an index of descriptors (no config, no layer): it carries no
    // content, every descriptor it names is judged when it is asked for, and a new signature would otherwise be held a whole cooldown.
    if let Reference::Tag(tag) = reference
        && is_referrers_fallback_tag(tag)
        && manifest.verified
        && read_children(&manifest.body, &app.origins)
            .is_ok_and(|children| children.blobs.is_empty())
    {
        exempt = true;
    }
    judge(
        app,
        principal,
        registry_id,
        &origins,
        name,
        &manifest,
        exempt,
    )
    .await?;
    Ok(manifest)
}

/// A digest a policy blocks under ANY name is blocked in every repository (an image re-hosted by a mount or a push elsewhere is the same bytes).
pub(crate) fn blocked_anywhere(
    policy: &crate::policy::CompiledPolicy,
    now: i64,
    digest_text: &str,
) -> Option<Decision> {
    let snapshot = policy.snapshot.as_deref()?;
    snapshot
        .names_blocking_exact_version(Ecosystem::Oci, digest_text)
        .iter()
        .find_map(|name| blocked_outright(policy, now, name, Some(digest_text)))
}

async fn judge(
    app: &App,
    principal: Option<&Principal>,
    registry_id: u64,
    origins: &Origins,
    name: &str,
    manifest: &Manifest,
    exempt: bool,
) -> Result<(), ApiError> {
    let (id, row) = reference_of(origins, registry_id, name, Kind::Manifest, &manifest.digest)
        .ok_or(ApiError::NotFound)?;
    // (A manifest answered by the registry's HEAD has no bytes to read the children of: they are registered by the GET that follows.)
    let children = if manifest.verified {
        Some(read_children(&manifest.body, &app.origins)?)
    } else {
        None
    };
    let existing = app.store().get_reference(id).await.map_err(storage_error)?;
    // A row that exists already holds the first-seen time and the date: nothing is written, no gate is taken (every pull reads, none writes).
    let (first_seen, date) = match &existing {
        Some(found) => (
            found
                .first_seen_micros
                .unwrap_or_else(|| app.clock.now_utc_micros()),
            found.publication_micros,
        ),
        None => {
            let _gate = row_gate(app, registry_id, name).await;
            let rows = app
                .store()
                .count_project_references_in(registry_id, Ecosystem::Oci, name)
                .await
                .map_err(storage_error)?;
            if rows == 0 {
                new_repository_allowed(app, registry_id).await?;
            }
            within_row_bound(app, registry_id, name, 1).await?;
            let now = app.clock.now_utc_micros();
            let upsert = ReferenceUpsert {
                id,
                reference: row.clone(),
                publication_micros: None,
                first_seen_micros: Some(now),
            };
            (
                commit_rows(app, registry_id, name, vec![upsert])
                    .await?
                    .get(&id)
                    .copied()
                    .unwrap_or(now),
                None,
            )
        }
    };
    let publication = match date {
        Some(micros) => PublicationTime::Upstream(micros),
        None => PublicationTime::FirstSeen(first_seen),
    };
    // The policy is read now, after everything that took time.
    let (policy, now) = check_policy(app, principal)?;
    let pinned = [policy_digest(&manifest.digest)];
    let candidate = Candidate {
        ecosystem: Ecosystem::Oci,
        name,
        version: &row.version,
        publication,
        advertised_digests: &[],
        pinned_digests: &pinned,
    };
    // Every digest the manifest names, a foreign layer's included (it never makes a blob request of its own), is checked against the blocks now:
    // a manifest that names a blocked digest is refused.
    if let Some(children) = &children {
        for (kind, digest) in children
            .blobs
            .iter()
            .map(|d| (Kind::Blob, d))
            .chain(children.manifests.iter().map(|d| (Kind::Manifest, d)))
        {
            let mut texts = vec![digest.to_string()];
            // A child named by sha512 has a sha256 once its bytes have been hashed (the stored pin): that is the identity a block names.
            if digest.algorithm == Algorithm::Sha512
                && let Some((child_id, _)) = reference_of(origins, registry_id, name, kind, digest)
                && let Some(pinned) = app
                    .store()
                    .get_reference(child_id)
                    .await
                    .map_err(storage_error)?
                    .and_then(|row| row.pinned_sha256)
            {
                texts.push(format!("sha256:{}", hex::encode(pinned)));
            }
            for text in texts {
                if let Some(blocked) = blocked_outright(&policy, now, name, Some(&text))
                    .or_else(|| blocked_anywhere(&policy, now, &text))
                {
                    if let (Some(principal), Some(managed)) = (principal, app.managed()) {
                        let child = Candidate {
                            ecosystem: Ecosystem::Oci,
                            name,
                            version: &text,
                            publication: PublicationTime::Unknown,
                            advertised_digests: &[],
                            pinned_digests: &[],
                        };
                        managed.record_refused(principal, &policy, now, &child, blocked, true);
                    }
                    return Err(crate::artifacts::decision_error(blocked, now));
                }
            }
        }
    }
    let decision = match blocked_anywhere(&policy, now, &row.version) {
        Some(blocked) => blocked,
        None => {
            crate::osv::evaluate_scoped(
                &app.osv,
                &policy,
                now,
                &candidate,
                app.osv_scope(registry_id),
            )
            .await
        }
    };
    if !(matches!(decision, Decision::Allow) || (exempt && cooldown_only(&decision))) {
        if let (Some(principal), Some(managed)) = (principal, app.managed()) {
            managed.record_refused(principal, &policy, now, &candidate, decision, true);
        }
        return Err(crate::artifacts::decision_error(decision, now));
    }
    if matches!(decision, Decision::Allow)
        && let Some(children) = &children
    {
        register_children(
            app,
            registry_id,
            origins,
            name,
            &manifest.digest,
            first_seen,
            children,
        )
        .await?;
    }
    Ok(())
}

/// A new repository (one with no row yet) is refused past `ROWS_FACTOR` times `max_references_per_project` repositories per registry: rows grow with repository NAMES, and the per-repository
/// bound alone caps nothing across them. The count is one query a minute at most, plus the repositories made since.
async fn new_repository_allowed(app: &App, registry_id: u64) -> Result<(), ApiError> {
    // One at a time across the whole process: the count is read, compared and raised under this gate, so concurrent first requests of different
    // new repositories cannot each see room for the same last one.
    let _gate = app.oci.repository_gate.lock().await;
    let known = lock(&app.oci.repositories)
        .get(&registry_id)
        .copied()
        .filter(|(at, _)| at.elapsed() < REPOSITORY_COUNT_TTL);
    let count = match known {
        Some((_, count)) => count,
        None => app
            .store()
            .count_registry_projects_in(registry_id, Ecosystem::Oci)
            .await
            .map_err(storage_error)?,
    };
    if count >= row_limit(app) {
        tracing::warn!(
            registry_id,
            count,
            "a registry is at its repository bound: one more repository is refused"
        );
        return Err(ApiError::Overloaded);
    }
    let mut table = lock(&app.oci.repositories);
    if !table.contains_key(&registry_id) {
        make_room(&mut table, MAX_PLACE_TABLE, |(at, _)| *at);
    }
    let at = known.map_or_else(Instant::now, |(at, _)| at);
    table.insert(registry_id, (at, count + 1));
    Ok(())
}

/// The children of an allowed manifest become rows of the repository, dated as the manifest is: a layer is never younger than the
/// image that names it, and never older (a date only ever gets later).
async fn register_children(
    app: &App,
    registry_id: u64,
    origins: &Origins,
    name: &str,
    parent: &Digest,
    first_seen: i64,
    children: &Children,
) -> Result<(), ApiError> {
    let key = (registry_id, name.to_owned(), parent.to_string());
    if lock(&app.oci.registered)
        .get(&key)
        .is_some_and(|at| at.elapsed() < Duration::from_secs(3600))
    {
        return Ok(());
    }
    let mut upserts = Vec::with_capacity(children.blobs.len() + children.manifests.len());
    for (kind, list) in [
        (Kind::Blob, &children.blobs),
        (Kind::Manifest, &children.manifests),
    ] {
        for digest in list {
            let (id, mut reference) =
                reference_of(origins, registry_id, name, kind, digest).ok_or(ApiError::NotFound)?;
            // A foreign layer keeps the identity of the registry blob route (`/v2/<name>/blobs/<digest>`) and is fetched from the URL its manifest names.
            if kind == Kind::Blob
                && let Some(url) = children.foreign.get(digest)
            {
                reference.upstream_url = url.clone();
            }
            upserts.push(ReferenceUpsert {
                id,
                reference,
                publication_micros: Some(first_seen),
                first_seen_micros: Some(first_seen),
            });
        }
    }
    {
        let _gate = row_gate(app, registry_id, name).await;
        // Only the children without a row count against the bound (a re-registration of an allowed manifest adds none).
        let stored = app
            .store()
            .list_project_first_seen_in(registry_id, Ecosystem::Oci, name)
            .await
            .map_err(storage_error)?;
        let new = upserts
            .iter()
            .filter(|upsert| !stored.contains_key(&upsert.id))
            .count() as u64;
        if new > 0 && (stored.len() as u64).saturating_add(new) > row_limit(app) {
            tracing::warn!(repository = %name, rows = stored.len(), "a repository is at its reference row bound: the children of one more manifest are refused");
            return Err(ApiError::Overloaded);
        }
        for chunk in upserts.chunks(1_000) {
            commit_rows(app, registry_id, name, chunk.to_vec()).await?;
        }
    }
    let mut registered = lock(&app.oci.registered);
    if !registered.contains_key(&key) {
        make_room(&mut registered, MAX_REGISTERED, |at| *at);
    }
    registered.insert(key, Instant::now());
    Ok(())
}

// ------------------------------------------------------------------ blobs

/// The reference a `GET|HEAD .../blobs/{digest}` names. A blob the allowed manifests named has its row; any other is judged as a
/// direct request: it must exist, and its own first-seen time starts its cooldown. A made-up digest makes no row.
pub async fn reference_for_blob(
    app: &App,
    principal: Option<&Principal>,
    registry_id: u64,
    name: &str,
    digest: &Digest,
) -> Result<(ReferenceId, String), ApiError> {
    locally_blocked(app, principal, name, None)?;
    locally_blocked(app, principal, name, Some(&digest.to_string()))?;
    let origins = origins_for(app, principal)?;
    let (id, reference) =
        reference_of(&origins, registry_id, name, Kind::Blob, digest).ok_or(ApiError::NotFound)?;
    let filename = reference.filename.clone();
    if app
        .store()
        .get_reference(id)
        .await
        .map_err(storage_error)?
        .is_some()
    {
        return Ok((id, filename));
    }
    if !exists(app, principal, registry_id, &origins, name, &reference, &id).await? {
        return Err(ApiError::NotFound);
    }
    let _gate = row_gate(app, registry_id, name).await;
    if app
        .store()
        .count_project_references_in(registry_id, Ecosystem::Oci, name)
        .await
        .map_err(storage_error)?
        == 0
    {
        new_repository_allowed(app, registry_id).await?;
    }
    within_row_bound(app, registry_id, name, 1).await?;
    let now = app.clock.now_utc_micros();
    commit_rows(
        app,
        registry_id,
        name,
        vec![ReferenceUpsert {
            id,
            reference,
            publication_micros: None,
            first_seen_micros: Some(now),
        }],
    )
    .await?;
    Ok((id, filename))
}

/// Whether the registry has the blob (for this caller): a HEAD, never followed to a storage host, remembered for a moment when the
/// caller has no credential of its own.
async fn exists(
    app: &App,
    principal: Option<&Principal>,
    registry_id: u64,
    origins: &Origins,
    name: &str,
    reference: &ArtifactReference,
    id: &ReferenceId,
) -> Result<bool, ApiError> {
    let key = (registry_id, origins.root().to_string(), *id);
    let shared =
        caller(principal).is_none() && crate::http::credential_read::cache_token(app).is_some();
    if shared
        && lock(&app.oci.exists)
            .get(&key)
            .is_some_and(|at| at.elapsed() < EXISTS_TTL)
    {
        return Ok(true);
    }
    let response = exchange(
        app,
        principal,
        registry_id,
        origins,
        Call2 {
            method: Method::HEAD,
            url: reference.upstream_url.clone(),
            accept: None,
            scope: format!("repository:{name}:pull"),
            max_bytes: 1,
            content_type: None,
            content_range: None,
            body: None,
        },
    )
    .await?;
    match response.status {
        200 | 301 | 302 | 303 | 307 | 308 => {
            if shared {
                let mut table = lock(&app.oci.exists);
                if !table.contains_key(&key) {
                    make_room(&mut table, MAX_EXISTS, |at| *at);
                }
                table.insert(key, Instant::now());
            }
            Ok(true)
        }
        404 | 410 => Ok(false),
        other => Err(status_error(app, other)),
    }
}

/// SPEC §9 membership: the reference is advertised while the registry still has the digest (for this caller).
pub async fn ensure_fresh_project_in(
    app: &App,
    reference: &ArtifactReference,
    registry_id: u64,
    principal: Option<&Principal>,
) -> Result<Arc<Advertised>, ApiError> {
    let origins = origins_for(app, principal)?;
    let digest = Digest::parse(&reference.version).ok_or(ApiError::NotFound)?;
    let kind = if reference.filename.starts_with("manifests/") {
        Kind::Manifest
    } else {
        Kind::Blob
    };
    let (id, own) = reference_of(&origins, registry_id, &reference.name, kind, &digest)
        .ok_or(ApiError::NotFound)?;
    // A foreign layer is advertised by the manifest that named it (its row says where it lives); the registry is not asked for it.
    if reference.upstream_url != own.upstream_url
        && app.origins.admits_foreign(&reference.upstream_url)
    {
        return Ok(Arc::new(Advertised::new([(id, own.filename.as_str())])));
    }
    if !exists(
        app,
        principal,
        registry_id,
        &origins,
        &reference.name,
        &own,
        &id,
    )
    .await?
    {
        return Err(ApiError::NotFound);
    }
    Ok(Arc::new(Advertised::new([(id, own.filename.as_str())])))
}

/// Whether a reference's bytes live on the registry itself (not at a foreign layer's own URL).
pub fn on_registry(app: &App, principal: Option<&Principal>, url: &Url) -> bool {
    origins_for(app, principal).is_ok_and(|origins| same_origin(url, origins.root()))
}

/// A credentialed HEAD of a blob: existence, size and digest from the registry, no bytes (a block still refuses).
pub async fn head_blob(
    app: &App,
    principal: Option<&Principal>,
    registry_id: u64,
    name: &str,
    digest: &Digest,
) -> Result<(Option<String>, String), ApiError> {
    locally_blocked(app, principal, name, None)?;
    locally_blocked(app, principal, name, Some(&digest.to_string()))?;
    let origins = origins_for(app, principal)?;
    let url = origins.url(&[name, "blobs", &digest.to_string()], &[])?;
    let response = exchange(
        app,
        principal,
        registry_id,
        &origins,
        Call2 {
            method: Method::HEAD,
            url,
            accept: None,
            scope: format!("repository:{name}:pull"),
            max_bytes: 1,
            content_type: None,
            content_range: None,
            body: None,
        },
    )
    .await?;
    match response.status {
        200 | 307 | 302 | 303 | 308 => Ok((
            response.header("content-length").map(str::to_owned),
            digest.to_string(),
        )),
        other => Err(status_error(app, other)),
    }
}

// ------------------------------------------------------------------ lists

/// Where a rewritten `Link` points: the client's own namespace.
pub struct Prefix(pub String);

#[derive(Deserialize)]
struct TagsDoc {
    tags: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct CatalogDoc {
    repositories: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct ReferrersDoc {
    manifests: Option<Vec<Referrer>>,
}

#[derive(Deserialize, serde::Serialize)]
struct Referrer {
    #[serde(rename = "mediaType")]
    media_type: String,
    digest: String,
    size: u64,
    #[serde(rename = "artifactType", skip_serializing_if = "Option::is_none")]
    artifact_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    annotations: Option<HashMap<String, String>>,
}

pub struct Document {
    pub body: Bytes,
    pub content_type: &'static str,
    pub link: Option<String>,
    pub filters_applied: Option<String>,
}

fn doc_cap(app: &App) -> u64 {
    app.config.max_metadata_bytes.get().max(DOC_FLOOR)
}

/// A pagination `Link` of the registry's, as the same request in the client's namespace. Only `n`, `last` (and the filter of a
/// referrers list) survive; a target outside the registry's origin or a different path is no link at all.
/// The URL a `rel="next"` link names, when it is on the registry's origin and is the same list (`path` below `/v2/`).
fn link_url(origins: &Origins, path: &str, link: Option<&str>) -> Option<Url> {
    let text = link?;
    let target = text.trim().strip_prefix('<')?.split_once('>')?.0;
    if !text.contains("rel=\"next\"") && !text.contains("rel=next") {
        return None;
    }
    let url = origins.root().join(target).ok()?;
    if !same_origin(&url, origins.root()) {
        return None;
    }
    let base = origins.root().path().trim_end_matches('/');
    let rest = url.path().strip_prefix(base)?;
    (rest == format!("/v2/{path}") || rest == format!("/v2/{path}/")).then_some(url)
}

fn rewrite_link(
    origins: &Origins,
    prefix: &Prefix,
    path: &str,
    link: Option<&str>,
    keys: &[&str],
) -> Option<String> {
    let url = link_url(origins, path, link)?;
    let pairs: Vec<(String, String)> = url
        .query_pairs()
        .filter(|(key, _)| keys.contains(&key.as_ref()))
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    let mut out = Url::parse("http://x/").ok()?;
    out.query_pairs_mut().extend_pairs(&pairs);
    Some(format!(
        "<{}/v2/{path}?{}>; rel=\"next\"",
        prefix.0,
        out.query().unwrap_or("")
    ))
}

fn page_query(query: &[(String, String)]) -> Vec<(String, String)> {
    query
        .iter()
        .filter(|(key, _)| matches!(key.as_str(), "n" | "last" | "artifactType"))
        .cloned()
        .collect()
}

pub async fn serve_tags(
    app: &App,
    principal: Option<&Principal>,
    registry_id: u64,
    prefix: &Prefix,
    name: &str,
    query: &[(String, String)],
) -> Result<Document, ApiError> {
    locally_blocked(app, principal, name, None)?;
    let origins = origins_for(app, principal)?;
    let page = page_query(query);
    let url = origins.url(&[name, "tags", "list"], &page)?;
    let response = exchange(
        app,
        principal,
        registry_id,
        &origins,
        Call2 {
            method: Method::GET,
            url,
            accept: Some("application/json"),
            scope: format!("repository:{name}:pull"),
            max_bytes: doc_cap(app),
            content_type: None,
            content_range: None,
            body: None,
        },
    )
    .await?;
    if response.status != 200 {
        return Err(status_error(app, response.status));
    }
    let doc: TagsDoc =
        serde_json::from_slice(&response.body).map_err(|_| ApiError::UpstreamInvalid)?;
    let tags = doc.tags.unwrap_or_default();
    if tags.len() > MAX_ENTRIES {
        return Err(ApiError::UpstreamInvalid);
    }
    let (policy, now) = check_policy(app, principal)?;
    let kept: Vec<String> = tags
        .into_iter()
        .filter(|tag| {
            coords::valid_tag(tag) && blocked_outright(&policy, now, name, Some(tag)).is_none()
        })
        .collect();
    let body = serde_json::to_vec(&serde_json::json!({"name": name, "tags": kept}))
        .map_err(|_| ApiError::InternalFailure)?;
    let link = rewrite_link(
        &origins,
        prefix,
        &format!("{name}/tags/list"),
        response.header("link"),
        &["n", "last"],
    );
    Ok(Document {
        body: body.into(),
        content_type: "application/json",
        link,
        filters_applied: None,
    })
}

pub async fn serve_catalog(
    app: &App,
    principal: Option<&Principal>,
    registry_id: u64,
    prefix: &Prefix,
    query: &[(String, String)],
) -> Result<Document, ApiError> {
    let origins = origins_for(app, principal)?;
    let page = page_query(query);
    let url = origins.url(&["_catalog"], &page)?;
    let response = exchange(
        app,
        principal,
        registry_id,
        &origins,
        Call2 {
            method: Method::GET,
            url,
            accept: Some("application/json"),
            scope: "registry:catalog:*".to_owned(),
            max_bytes: doc_cap(app),
            content_type: None,
            content_range: None,
            body: None,
        },
    )
    .await?;
    if response.status != 200 {
        return Err(status_error(app, response.status));
    }
    let doc: CatalogDoc =
        serde_json::from_slice(&response.body).map_err(|_| ApiError::UpstreamInvalid)?;
    let names = doc.repositories.unwrap_or_default();
    if names.len() > MAX_ENTRIES {
        return Err(ApiError::UpstreamInvalid);
    }
    let (policy, now) = check_policy(app, principal)?;
    let kept: Vec<String> = names
        .into_iter()
        .filter(|name| {
            probation_policy::names::valid_oci_name(name)
                && blocked_outright(&policy, now, name, None).is_none()
        })
        .collect();
    let body = serde_json::to_vec(&serde_json::json!({ "repositories": kept }))
        .map_err(|_| ApiError::InternalFailure)?;
    let link = rewrite_link(
        &origins,
        prefix,
        "_catalog",
        response.header("link"),
        &["n", "last"],
    );
    Ok(Document {
        body: body.into(),
        content_type: "application/json",
        link,
        filters_applied: None,
    })
}

/// The referrers of a digest: an index rebuilt from the descriptors that are well formed (their digests are only names; every one
/// is a manifest the client asks this firewall for, and is judged then).
pub async fn serve_referrers(
    app: &App,
    principal: Option<&Principal>,
    registry_id: u64,
    name: &str,
    digest: &Digest,
    query: &[(String, String)],
) -> Result<Document, ApiError> {
    locally_blocked(app, principal, name, None)?;
    locally_blocked(app, principal, name, Some(&digest.to_string()))?;
    let origins = origins_for(app, principal)?;
    let mut page: Vec<(String, String)> = query
        .iter()
        .filter(|(key, _)| key == "artifactType")
        .cloned()
        .collect();
    let path = format!("{name}/referrers/{digest}");
    let mut entries: Vec<Referrer> = Vec::new();
    let mut filters_applied = None;
    // The registry's pages are followed here (same origin, same list, bounded) and answered as ONE index, so a long list is never cut short and
    // no pagination link of the registry reaches the client.
    for page_number in 0..MAX_PAGES {
        let url = origins.url(&[name, "referrers", &digest.to_string()], &page)?;
        let response = exchange(
            app,
            principal,
            registry_id,
            &origins,
            Call2 {
                method: Method::GET,
                url,
                accept: Some("application/vnd.oci.image.index.v1+json"),
                scope: format!("repository:{name}:pull"),
                max_bytes: doc_cap(app),
                content_type: None,
                content_range: None,
                body: None,
            },
        )
        .await?;
        if response.status != 200 {
            // A first page the registry does not have is the registry's answer (an empty list for a client that knows the tag fallback).
            if page_number == 0 || response.status != 404 {
                return Err(status_error(app, response.status));
            }
            break;
        }
        let doc: ReferrersDoc =
            serde_json::from_slice(&response.body).map_err(|_| ApiError::UpstreamInvalid)?;
        entries.extend(doc.manifests.unwrap_or_default());
        if entries.len() > MAX_ENTRIES {
            return Err(ApiError::UpstreamInvalid);
        }
        if page_number == 0 {
            filters_applied = response
                .header("oci-filters-applied")
                .filter(|text| text.len() <= 64 && text.bytes().all(|b| b.is_ascii_alphanumeric()))
                .map(str::to_owned);
        }
        let Some(next) = link_url(&origins, &path, response.header("link")) else {
            break;
        };
        let pairs: Vec<(String, String)> = next
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        if pairs.len() > 8 || pairs.iter().any(|(k, v)| k.len() > 64 || v.len() > 512) {
            return Err(ApiError::UpstreamInvalid);
        }
        if pairs == page {
            // The same page again is a loop, not a list.
            return Err(ApiError::UpstreamInvalid);
        }
        page = pairs;
        if page_number + 1 == MAX_PAGES {
            return Err(ApiError::UpstreamInvalid);
        }
    }
    let (policy, now) = check_policy(app, principal)?;
    let kept: Vec<Referrer> = entries
        .into_iter()
        .filter(|entry| {
            Digest::parse(&entry.digest).is_some()
                && media_type_ok(&entry.media_type)
                && blocked_outright(&policy, now, name, Some(&entry.digest)).is_none()
                && blocked_anywhere(&policy, now, &entry.digest).is_none()
        })
        .map(|mut entry| {
            entry.annotations = entry.annotations.filter(|map| {
                map.len() <= 64 && map.iter().all(|(k, v)| k.len() <= 256 && v.len() <= 4096)
            });
            entry.artifact_type = entry.artifact_type.filter(|text| media_type_ok(text));
            entry
        })
        .collect();
    let body = serde_json::to_vec(&serde_json::json!({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": kept})).map_err(|_| ApiError::InternalFailure)?;
    Ok(Document {
        body: body.into(),
        content_type: "application/vnd.oci.image.index.v1+json",
        link: None,
        filters_applied,
    })
}

// ------------------------------------------------------------------ the token endpoint

/// A scope a client may ask a token for: `repository:{name}:{actions}` or `registry:catalog:*`.
fn scope_ok(scope: &str) -> bool {
    if scope == "registry:catalog:*" {
        return true;
    }
    let Some(rest) = scope.strip_prefix("repository:") else {
        return false;
    };
    let Some((name, actions)) = rest.rsplit_once(':') else {
        return false;
    };
    probation_policy::names::valid_oci_name(name)
        && !actions.is_empty()
        && actions
            .split(',')
            .all(|action| matches!(action, "pull" | "push" | "delete" | "*"))
}

/// The scopes of a token request, each checked for shape (at most eight); any other query key is no route.
fn token_scopes(query: &str) -> Result<Vec<String>, ApiError> {
    let mut scopes = Vec::new();
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        match key.as_ref() {
            "scope" if scope_ok(&value) && scopes.len() < 8 => scopes.push(value.into_owned()),
            "service" | "account" | "client_id" | "offline_token" => {}
            // The realm a plain-root client was given names its registry (the route has already chosen it): checked for its shape only.
            "ns" if value.len() <= 255
                && value.bytes().all(|b| {
                    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'_')
                }) => {}
            _ => return Err(ApiError::NotFound),
        }
    }
    Ok(scopes)
}

/// The token a certificate-managed firewall hands out: its own, opaque, pull-only, meaningful to nobody else. It is never a registry token
/// and never the registry's stored credential (the firewall adds that itself, server-side, on its own requests): a certificate holder asked
/// for push, delete or `*` and is given a token that grants none of them (a token may grant less than was asked), and a scope naming a
/// repository its policy blocks is left out.
pub fn local_token(
    app: &App,
    principal: Option<&Principal>,
    registry_id: u64,
    query: &str,
) -> Result<Bytes, ApiError> {
    let scopes = token_scopes(query)?;
    let granted: Vec<String> = scopes
        .iter()
        .filter_map(|scope| {
            let (name, actions) = scope.strip_prefix("repository:")?.rsplit_once(':')?;
            actions
                .split(',')
                .any(|action| action == "pull")
                .then_some(name)
        })
        .filter(|name| locally_blocked(app, principal, name, None).is_ok())
        .map(|name| format!("repository:{name}:pull"))
        .collect();
    let now = u64::try_from(app.clock.now_utc_micros() / 1_000_000).unwrap_or(0);
    let token = mint_local_token(
        &app.oci.token_secret,
        now,
        &principal_text(principal),
        registry_id,
    );
    serde_json::to_vec(&serde_json::json!({"token": token, "access_token": token, "expires_in": LOCAL_TOKEN_LIFE, "scope": granted.join(" ")})).map(Bytes::from).map_err(|_| ApiError::InternalFailure)
}

/// What every token of the firewall's own begins with.
pub const LOCAL_TOKEN_PREFIX: &str = "probation-pull-";

/// How long a token of the firewall's own is valid, in seconds (what `expires_in` says).
const LOCAL_TOKEN_LIFE: u64 = 300;

/// HMAC-SHA256 (RFC 2104), by hand: the one MAC this needs, on the sha2 crate the firewall already has.
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    use sha2::Digest as _;
    let mut block = [0u8; 64];
    if key.len() > 64 {
        block[..32].copy_from_slice(&sha2::Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let pad = |byte: u8| block.map(|b| b ^ byte);
    let mut inner = sha2::Sha256::new();
    inner.update(pad(0x36));
    inner.update(message);
    let mut outer = sha2::Sha256::new();
    outer.update(pad(0x5c));
    outer.update(inner.finalize());
    outer.finalize().into()
}

fn local_token_message(expires: u64, principal: &str, registry: u64) -> String {
    format!("probation-oci-token\n{expires}\n{principal}\n{registry}")
}

/// A token for `principal` (its place) and `registry`, valid for [`LOCAL_TOKEN_LIFE`] seconds from `now`: `probation-pull-<expiry>.<hmac>`.
fn mint_local_token(secret: &[u8; 32], now: u64, principal: &str, registry: u64) -> String {
    let expires = now.saturating_add(LOCAL_TOKEN_LIFE);
    format!(
        "{LOCAL_TOKEN_PREFIX}{expires}.{}",
        hex::encode(hmac_sha256(
            secret,
            local_token_message(expires, principal, registry).as_bytes()
        ))
    )
}

/// The shape of a token of the firewall's own: `probation-pull-<expiry digits>.<64 hex>`.
fn local_token_shaped(token: &str) -> bool {
    token
        .strip_prefix(LOCAL_TOKEN_PREFIX)
        .and_then(|rest| rest.split_once('.'))
        .is_some_and(|(expiry, tag)| {
            !expiry.is_empty()
                && expiry.len() <= 20
                && expiry.bytes().all(|b| b.is_ascii_digit())
                && tag.len() == 64
                && tag.bytes().all(|b| b.is_ascii_hexdigit())
        })
}

fn principal_text(principal: Option<&Principal>) -> String {
    principal.map_or_else(
        || "none".to_owned(),
        |principal| format!("{:?}:{}", principal.place.kind, principal.place.id),
    )
}

/// A request in a certificate-managed firewall that presents a token of the firewall's own (`Bearer probation-pull-...`) presents a well-formed one,
/// else it is the challenge again (a client asks for a new token). The token authorises nothing (admission is by the client certificate), so one
/// minted by another instance or an earlier process is as good as this one's: a balancer may send a client's requests to any instance, and a
/// restart must not turn every client's token into a failure. A request that presents no token is admitted by its certificate too.
pub fn check_local_token(authorization: Option<&str>) -> Result<(), ApiError> {
    match authorization
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|token| token.starts_with(LOCAL_TOKEN_PREFIX))
    {
        Some(token) if !local_token_shaped(token) => Err(ApiError::Unauthenticated),
        _ => Ok(()),
    }
}

/// The token endpoint of a shared service: the registry's own token service, asked with the credential the CALLER sent (`own`: its own Basic
/// credential; never anything stored) through the allowed realm; the answer is rebuilt as `{"token": ..., "expires_in": ...}`. A certificate-managed
/// firewall never reaches this (see [`local_token`]).
pub async fn serve_token(
    app: &App,
    principal: Option<&Principal>,
    registry_id: u64,
    query: &str,
    own: Option<&str>,
) -> Result<Bytes, ApiError> {
    if app.service_policy().is_none() {
        return local_token(app, principal, registry_id, query);
    }
    let scopes = token_scopes(query)?;
    let origins = origins_for(app, principal)?;
    let _places = places(app, registry_id, own).await?;
    let basic = own.filter(|value| value.starts_with("Basic "));
    match discover(app, &origins).await? {
        Some(Challenge::Bearer { realm, service }) => {
            let (token, life) =
                fetch_token(app, &origins, &realm, service.as_deref(), &scopes, basic).await?;
            serde_json::to_vec(&serde_json::json!({"token": token, "access_token": token, "expires_in": life.as_secs()})).map(Bytes::from).map_err(|_| ApiError::InternalFailure)
        }
        // A registry with no token service takes the caller's credential directly: the token is the caller's own credential's text.
        _ => {
            let value = basic.ok_or(ApiError::Unauthenticated)?;
            let encoded = value.strip_prefix("Basic ").unwrap_or(value);
            serde_json::to_vec(&serde_json::json!({"token": encoded}))
                .map(Bytes::from)
                .map_err(|_| ApiError::InternalFailure)
        }
    }
}

/// Whether the registry asks an anonymous caller for a credential (read from its `/v2/` and remembered).
pub async fn registry_requires_auth(
    app: &App,
    principal: Option<&Principal>,
) -> Result<bool, ApiError> {
    let origins = origins_for(app, principal)?;
    Ok(discover(app, &origins).await?.is_some())
}

/// What the registry asks of an anonymous caller (read through the same remembered probe as the token flow).
pub async fn registry_challenge(
    app: &App,
    principal: Option<&Principal>,
    probe: bool,
) -> Result<Option<Challenge>, ApiError> {
    let origins = origins_for(app, principal)?;
    if !probe {
        return Ok(lock(&app.oci.realms)
            .get(&origins.root().to_string())
            .and_then(|(found, _)| found.clone()));
    }
    discover(app, &origins).await
}

/// What this firewall's `/v2/` answers: the registry's own, as an anonymous caller sees it (a client learns from the ping whether it must
/// sign in, and a client that is told "open" never presents a credential, so a push would meet a 401 it does not act on). `Ok(None)` is an
/// open registry or a caller that already carries a credential; `Some` is the challenge the client must be told.
pub async fn ping(
    app: &App,
    principal: Option<&Principal>,
    registry_id: u64,
) -> Result<Option<Challenge>, ApiError> {
    let origins = origins_for(app, principal)?;
    let _places = places(app, registry_id, caller(principal)).await?;
    match discover(app, &origins).await? {
        None => Ok(None),
        Some(_) if caller(principal).is_some() => Ok(None),
        Some(challenge) => Ok(Some(challenge)),
    }
}

// ------------------------------------------------------------------ writes

pub struct PublishTarget {
    pub url: Url,
    pub origin: Option<Url>,
}

/// Where a write of `segments` (below `/v2/`) goes: the registry's own origin, or the process's default registry.
pub fn publish_target(
    app: &App,
    principal: &Principal,
    segments: &[&str],
    query: Option<&str>,
) -> Result<PublishTarget, ApiError> {
    let origins = origins_for(app, Some(principal))?;
    let mut url = origins.url(segments, &[])?;
    if let Some(query) = query {
        if query.len() > 4096 || query.bytes().any(|b| b <= 0x20 || b >= 0x7f) {
            return Err(ApiError::NotFound);
        }
        url.set_query(Some(query));
    }
    Ok(PublishTarget {
        url,
        origin: origins.selected,
    })
}

/// An upload `Location` or any other URL a registry hands back, as the same resource in the client's namespace; one that leaves the
/// registry's origin (or its path) is none.
pub fn client_location(
    app: &App,
    principal: &Principal,
    prefix: &Prefix,
    location: &str,
) -> Option<String> {
    let origins = origins_for(app, Some(principal)).ok()?;
    let url = origins.root().join(location).ok()?;
    if !same_origin(&url, origins.root()) {
        return None;
    }
    let base = origins.root().path().trim_end_matches('/');
    let rest = url.path().strip_prefix(base)?;
    if !rest.starts_with("/v2/") || rest.contains("/../") {
        return None;
    }
    Some(format!(
        "{}{}{}",
        prefix.0,
        rest,
        url.query()
            .map(|query| format!("?{query}"))
            .unwrap_or_default()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// S24-F1: the certificate-managed firewall's own token is not a constant: it differs by principal, registry and moment.
    #[test]
    fn a_local_token_is_not_a_constant_and_differs_by_principal_registry_and_moment() {
        let secret = [7u8; 32];
        let token = mint_local_token(&secret, 1_000, "org:10", 4);
        assert!(
            token.starts_with(LOCAL_TOKEN_PREFIX)
                && token != LOCAL_TOKEN_PREFIX
                && local_token_shaped(&token),
            "{token}"
        );
        assert_ne!(token, mint_local_token(&secret, 1_000, "user:11", 4));
        assert_ne!(token, mint_local_token(&secret, 1_000, "org:10", 5));
        assert_ne!(token, mint_local_token(&secret, 2_000, "org:10", 4));
        assert_ne!(token, mint_local_token(&[8u8; 32], 1_000, "org:10", 4));
    }

    /// N1: the token authorises nothing (admission is by the client certificate), so a well-formed token minted by ANOTHER instance or an
    /// earlier process is accepted (a balancer sends a client's requests to any instance); a malformed one is not.
    #[test]
    fn a_well_formed_token_of_another_instance_is_accepted_and_a_malformed_one_is_not() {
        let other_instance = mint_local_token(&[9u8; 32], 5_000, "org:10", 4);
        assert!(local_token_shaped(&other_instance), "{other_instance}");
        for bad in [
            LOCAL_TOKEN_PREFIX.to_owned(),
            format!("{LOCAL_TOKEN_PREFIX}x.{}", "0".repeat(64)),
            format!("{LOCAL_TOKEN_PREFIX}1.{}", "0".repeat(63)),
            format!("{LOCAL_TOKEN_PREFIX}1.{}g", "0".repeat(63)),
            format!("{other_instance}0"),
        ] {
            assert!(!local_token_shaped(&bad), "{bad}");
        }
    }

    #[test]
    fn hmac_sha256_matches_the_rfc_4231_vectors() {
        let tag = hmac_sha256(&[0x0b; 20], b"Hi There");
        assert_eq!(
            hex::encode(tag),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        let tag = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            hex::encode(tag),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn a_challenge_is_read_strictly() {
        let (challenge, scope) = parse_challenge(&["Bearer realm=\"https://auth.docker.io/token\",service=\"registry.docker.io\",scope=\"repository:library/alpine:pull\""]).unwrap();
        assert!(
            matches!(challenge, Challenge::Bearer { ref realm, ref service } if realm.as_str() == "https://auth.docker.io/token" && service.as_deref() == Some("registry.docker.io"))
        );
        assert_eq!(scope.as_deref(), Some("repository:library/alpine:pull"));
        assert!(matches!(
            parse_challenge(&["Basic realm=\"x\""]).unwrap().0,
            Challenge::Basic
        ));
        assert!(
            parse_challenge(&["Bearer service=\"x\""]).is_none(),
            "a Bearer challenge without a realm is no challenge"
        );
        assert!(parse_challenge(&["Negotiate"]).is_none());
    }

    #[test]
    fn a_realm_is_the_registrys_own_origin_or_its_named_token_host() {
        let hub = Url::parse("https://registry-1.docker.io").unwrap();
        assert!(realm_allowed(
            &hub,
            &Url::parse("https://auth.docker.io/token").unwrap(),
            None
        ));
        assert!(realm_allowed(
            &hub,
            &Url::parse("https://registry-1.docker.io/token").unwrap(),
            None
        ));
        for bad in [
            "https://evil.example/token",
            "http://auth.docker.io/token",
            "https://auth.docker.io:8443/token",
            "https://user:pw@auth.docker.io/token",
            "https://auth.docker.io.evil.example/token",
        ] {
            assert!(
                !realm_allowed(&hub, &Url::parse(bad).unwrap(), None),
                "{bad}"
            );
        }
        let own = Url::parse("https://registry.example.org").unwrap();
        assert!(realm_allowed(
            &own,
            &Url::parse("https://registry.example.org/auth").unwrap(),
            None
        ));
        assert!(
            !realm_allowed(
                &own,
                &Url::parse("https://auth.docker.io/token").unwrap(),
                None
            ),
            "the table is for its own registries"
        );
        // A token origin the registry's descriptor declares is exactly that origin, over https.
        let declared = Url::parse("https://gitlab.example.org").unwrap();
        assert!(realm_allowed(
            &own,
            &Url::parse("https://gitlab.example.org/jwt/auth").unwrap(),
            Some(&declared)
        ));
        for bad in [
            "https://gitlab.example.org:8443/jwt/auth",
            "http://gitlab.example.org/jwt/auth",
            "https://evil.example/jwt/auth",
            "https://gitlab.example.org.evil.example/x",
            "https://u:p@gitlab.example.org/x",
        ] {
            assert!(
                !realm_allowed(&own, &Url::parse(bad).unwrap(), Some(&declared)),
                "{bad}"
            );
        }
        assert!(
            !realm_allowed(
                &own,
                &Url::parse("https://gitlab.example.org/jwt/auth").unwrap(),
                None
            ),
            "no declaration, no other host"
        );
    }

    #[test]
    fn a_manifest_names_its_children_or_is_refused() {
        let d = |c: char| format!("sha256:{}", c.to_string().repeat(64));
        let image = format!(
            r#"{{"schemaVersion":2,"config":{{"digest":"{}","size":1}},"layers":[{{"digest":"{}"}},{{"digest":"{}"}},{{"digest":"{}"}}]}}"#,
            d('a'),
            d('b'),
            d('c'),
            d('b')
        );
        let children = read_children(image.as_bytes(), &OriginSet::production()).unwrap();
        assert_eq!(children.blobs.len(), 3, "a repeated layer is one blob");
        let index = format!(
            r#"{{"manifests":[{{"digest":"{}"}},{{"digest":"{}"}}]}}"#,
            d('d'),
            d('e')
        );
        assert_eq!(
            read_children(index.as_bytes(), &OriginSet::production())
                .unwrap()
                .manifests
                .len(),
            2
        );
        let legacy = format!(
            r#"{{"schemaVersion":1,"fsLayers":[{{"blobSum":"{}"}}]}}"#,
            d('f')
        );
        assert_eq!(
            read_children(legacy.as_bytes(), &OriginSet::production())
                .unwrap()
                .blobs
                .len(),
            1
        );
        for bad in [
            r#"[]"#,
            r#"{"config":{"digest":"sha256:short"}}"#,
            r#"{"layers":[{}]}"#,
            r#"{"manifests":[{"digest":"md5:aa"}]}"#,
            "not json",
        ] {
            assert!(
                read_children(bad.as_bytes(), &OriginSet::production()).is_err(),
                "{bad}"
            );
        }
        assert!(
            read_children(b"{}", &OriginSet::production())
                .unwrap()
                .blobs
                .is_empty(),
            "an artifact with nothing to name is still a manifest"
        );
    }

    #[test]
    fn a_media_type_is_a_token() {
        assert!(media_type_ok("application/vnd.oci.image.manifest.v1+json"));
        assert!(media_type_ok(
            "application/vnd.docker.distribution.manifest.v1+prettyjws; charset=utf-8"
        ));
        for bad in ["", "text", "a b/c", "text/html\r\nX: y", &"a/".repeat(100)] {
            assert!(!media_type_ok(bad), "{bad:?}");
        }
    }

    #[test]
    fn a_link_stays_on_the_registry_and_on_the_same_list() {
        let origins = Origins {
            set: OriginSet::selected_npm_with_private(
                Url::parse("https://reg.example.org/").unwrap(),
                Vec::new(),
            )
            .unwrap(),
            kind: OriginKind::NpmMetadata,
            selected: None,
            cidrs: Vec::new(),
            token_origin: None,
        };
        let prefix = Prefix(String::new());
        let ok = rewrite_link(
            &origins,
            &prefix,
            "a/tags/list",
            Some("</v2/a/tags/list?last=x&n=5>; rel=\"next\""),
            &["n", "last"],
        )
        .unwrap();
        assert_eq!(ok, "</v2/a/tags/list?last=x&n=5>; rel=\"next\"");
        let absolute = rewrite_link(
            &origins,
            &prefix,
            "a/tags/list",
            Some("<https://reg.example.org/v2/a/tags/list?n=5&last=y&token=SECRET>; rel=\"next\""),
            &["n", "last"],
        )
        .unwrap();
        assert_eq!(
            absolute, "</v2/a/tags/list?n=5&last=y>; rel=\"next\"",
            "only the paging keys survive"
        );
        for bad in [
            "<https://evil.example/v2/a/tags/list?n=5>; rel=\"next\"",
            "</v2/other/tags/list?n=5>; rel=\"next\"",
            "</v2/a/tags/list?n=5>; rel=\"prev\"",
            "garbage",
        ] {
            assert!(
                rewrite_link(&origins, &prefix, "a/tags/list", Some(bad), &["n", "last"]).is_none(),
                "{bad}"
            );
        }
    }

    #[test]
    fn a_scope_is_a_repository_and_its_actions() {
        assert!(scope_ok("repository:library/alpine:pull"));
        assert!(scope_ok("repository:a/b:pull,push"));
        assert!(scope_ok("registry:catalog:*"));
        for bad in [
            "repository:A/b:pull",
            "repository:a:evil",
            "repository::pull",
            "registry:other:*",
            "repository:a/b:pull\n",
        ] {
            assert!(!scope_ok(bad), "{bad:?}");
        }
    }
}
