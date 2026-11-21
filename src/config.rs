//! The configuration file (SPEC §4).
//!
//! Every rejection rule lives here, so `serve` and the validation commands cannot
//! diverge: both build the same `Config` through the same conversion.

use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::num::{NonZeroU32, NonZeroU64, NonZeroUsize};
use std::path::{Path, PathBuf};

use reqwest::header::{self, HeaderName};
use serde::Deserialize;
use url::{Host, Url};

use crate::{delivery, osv};

/// The validated configuration. The `NonZero*` types make "zero polling intervals
/// and zero capacity limits are invalid" a type error rather than a check someone
/// can forget; `cooldown_seconds`, `metadata_ttl_seconds` and
/// `metadata_max_age_seconds` stay plain `u64` because zero is meaningful for all
/// three.
#[derive(Clone, Debug)]
pub struct Config {
    pub listen: SocketAddr,
    pub public_url: Url,
    pub data_dir: PathBuf,
    /// Empty in managed mode when the file leaves it out: a managed firewall ignores
    /// its local blocklist (C109).
    pub blocklist_file: PathBuf,
    pub cooldown_seconds: u64,
    pub metadata_ttl_seconds: u64,
    /// SPEC rev 3 §10: how old a stored project snapshot may become since its last
    /// FULL fetch, whatever upstream keeps answering `304` to. Zero disables the
    /// ceiling and restores unbounded revalidation.
    ///
    /// Not a `NonZeroU64` even though zero is the "off" value: the rule that makes
    /// it safe is a relation to `metadata_ttl_seconds`, and a type cannot express a
    /// cross-field relation.
    pub metadata_max_age_seconds: u64,
    pub blocklist_poll_seconds: NonZeroU64,
    pub cache_max_bytes: NonZeroU64,
    pub memory_cache_max_bytes: NonZeroU64,
    pub max_artifact_bytes: NonZeroU64,
    pub max_metadata_bytes: NonZeroU64,
    pub max_blocklist_bytes: NonZeroU64,
    pub max_upstream_requests: NonZeroU32,
    pub max_artifact_downloads: NonZeroU32,
    /// How long a cold artifact request waits for a download permit before `503`;
    /// 0 refuses at once (decision 2026-10-23).
    pub download_wait_seconds: u64,
    /// How many requests may wait for a download permit at once; a request past it is
    /// refused at once. 0 means none waits.
    pub max_download_waiters: u32,
    pub max_active_requests: NonZeroU32,
    pub max_references_per_project: NonZeroU32,
    /// Where decision records are appended as NDJSON, if anywhere. Absent means off:
    /// no file is opened and no delivery task is spawned.
    pub log_file_path: Option<PathBuf>,
    /// The effective ceiling on that file, defaulted at validation. Disk use is
    /// bounded at twice this, because one rollover generation is kept.
    pub log_file_max_bytes: NonZeroU64,
    /// The collector decision records are `POST`ed to, if anywhere. Absent means off:
    /// no HTTP client is constructed and no delivery task is spawned.
    pub siem_url: Option<Url>,
    /// The header the credential is sent under, defaulted at validation. Only the
    /// *name* lives here: the value is read from `PROBATION_SIEM_AUTH` inside
    /// `delivery::build` and never placed on this struct, which derives `Debug`.
    pub siem_auth_header: HeaderName,
    /// Whether a delivered record carries the peer address of the connection that
    /// asked. False unless an operator turns it on, and refused unless at least one
    /// sink is configured to receive what it records.
    pub log_consumer_identification: bool,
    /// How much memory the log file sink's queue may hold, defaulted at validation.
    /// A memory budget rather than a record count, the same shape as
    /// `memory_cache_max_bytes`, and additive to it.
    pub log_queue_max_bytes: NonZeroU64,
    /// The same budget for the SIEM sink's queue. Two sinks are two queues, so a
    /// deployment with both configured pays both.
    pub siem_queue_max_bytes: NonZeroU64,
    /// How long an OSV lookup's answer is trusted before it is asked again (C13).
    pub osv_cache_ttl_seconds: NonZeroU64,
    /// How long one OSV batch flush's outbound call may take before it fails open
    /// (C12c/C14). The same figure bounds both the outbound call and each waiter's
    /// reply, so there is one knob rather than two that could drift apart.
    pub osv_request_timeout_ms: NonZeroU64,
    /// How long a matched OSV entry keeps refusing after its TTL while the policy server
    /// cannot be asked (C1031). Managed and shared-service mode only.
    pub osv_stale_match_seconds: u64,
    /// Whether OSV enforcement denies, only logs, or is skipped entirely (C16-C18b,
    /// D5/D6). Defaults to `Enforce` — today's behaviour — when absent.
    pub osv_mode: osv::OsvMode,
    /// The certificate `serve` terminates TLS with, if it terminates TLS itself at
    /// all. `None` unless both this and `tls_key_path` are set: `serve` then binds
    /// plain HTTP, exactly as before this pair of keys existed, and a reverse proxy
    /// is still the one terminating TLS, per SPEC §3.
    pub tls_cert_path: Option<PathBuf>,
    /// The private key paired with `tls_cert_path`. Both or neither; see there.
    pub tls_key_path: Option<PathBuf>,
    /// How often a managed firewall asks the management server for changes (C22).
    /// Read only in managed mode.
    pub sync_interval_seconds: NonZeroU64,
    /// Present only in managed mode: every key's policy comes from the management
    /// server. A broken section refuses to start rather than run standalone (T20).
    pub management: Option<ManagementConfig>,
    pub service_policy: Option<ServicePolicyConfig>,
    pub allowed_peer_cidrs: Vec<ipnet::IpNet>,
    /// LS-F16: optional bounds on credential-bearing read temporary files. Absent by
    /// default, so the disk itself is the limit and no function is lost.
    pub credential_temp_max_request_bytes: Option<u64>,
    pub credential_temp_max_total_bytes: Option<u64>,
    /// Slice 26 (sec F11): start on a data directory that is on a network file system (NFS, CIFS, FUSE and the like, where the
    /// exclusive lock is not reliable across hosts) only when this is true. Default false: refuse.
    pub allow_network_data_dir: bool,
    /// LS-F9: deployment-supplied cluster control-plane ranges a snapshot registry may
    /// never name or dial.
    pub control_plane_cidrs: Vec<ipnet::IpNet>,
    /// The three upstream origins, each replacing SPEC §11's fixed one when set (C35):
    /// `https`, no credentials, query, fragment or path, and never a private address.
    pub npm_upstream_url: Option<Url>,
    pub pypi_upstream_url: Option<Url>,
    pub pypi_artifacts_url: Option<Url>,
    /// RubyGems upstream (rubygems.org by default), same rules as the origins above.
    pub rubygems_upstream_url: Option<Url>,
    /// Cargo sparse index (index.crates.io by default) and the crate files its `config.json` names
    /// (static.crates.io by default), same rules as the origins above.
    pub cargo_upstream_url: Option<Url>,
    pub cargo_artifacts_url: Option<Url>,
    /// Go module proxy (proxy.golang.org by default) and the checksum database the `/go/sumdb/` route
    /// forwards to (sum.golang.org by default), same rules as the origins above.
    pub go_upstream_url: Option<Url>,
    pub go_sumdb_url: Option<Url>,
    /// The origin a Go proxy's zip redirect may land on (https://storage.googleapis.com/proxy-golang-org-prod by default).
    pub go_artifacts_url: Option<Url>,
    /// NuGet: the host of the service index, flat container, registration and vulnerability/signature
    /// documents (api.nuget.org by default), the search host (azuresearch-usnc.nuget.org) and the publish
    /// host (www.nuget.org), same rules as the origins above. A resource the registry's service index
    /// names on any other origin is not used.
    pub nuget_upstream_url: Option<Url>,
    pub nuget_search_url: Option<Url>,
    pub nuget_publish_url: Option<Url>,
    /// Maven: the public repository (https://repo.maven.apache.org/maven2 by default; an origin AND a path prefix, as a
    /// mirror lays it out) and the one URL `mvn deploy` is forwarded to for the public registry (none by default: Maven
    /// Central has no deploy endpoint of its own, a registry with a target of its own is deployed to at that target).
    pub maven_upstream_url: Option<Url>,
    pub maven_publish_url: Option<Url>,
    /// Conan: the public remote (https://center2.conan.io by default; an origin AND a path prefix, as an Artifactory remote lays it
    /// out) and the one URL `conan upload` is forwarded to for the public registry (none by default: ConanCenter takes no uploads).
    pub conan_upstream_url: Option<Url>,
    pub conan_publish_url: Option<Url>,
    /// OCI: the default registry (https://registry-1.docker.io; an origin, and a path prefix for a mirror that has one) and the one
    /// storage origin a blob's redirect on it may land on (https://production.cloudfront.docker.com).
    pub oci_upstream_url: Option<Url>,
    pub oci_artifacts_url: Option<Url>,
    /// The token service of the default OCI registry when it is not the registry's own host (an https origin).
    pub oci_token_url: Option<Url>,
    /// The hosts a layer's own download `urls` (a foreign layer) may name: an exact host, or `*.suffix` for every host below a suffix.
    pub oci_foreign_layer_hosts: Vec<String>,
    /// The file this configuration was read from, as written: a settings push is
    /// validated merged over it (C105).
    pub local: LocalText,
}

impl Config {
    /// The policy server a managed or shared-service endpoint asks for OSV answers, with
    /// the credential it already uses for that server (C1030). There is no key that
    /// selects direct api.osv.dev in these modes; standalone returns `None`.
    pub fn osv_central_server(&self) -> Option<(&Url, &FirewallToken)> {
        match (&self.management, &self.service_policy) {
            (Some(management), _) => Some((&management.url, &management.token)),
            (None, Some(service)) => Some((&service.server_url, &service.service_key)),
            (None, None) => None,
        }
    }
}

/// A configuration file's text. Its `Debug` prints nothing, because `Config` is
/// printed whole.
#[derive(Clone, Default)]
pub struct LocalText(pub std::sync::Arc<str>);

impl fmt::Debug for LocalText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LocalText(..)")
    }
}

/// `[management]`. None of it can be pushed from the portal (C35).
#[derive(Clone, Debug)]
pub struct ManagementConfig {
    /// The management server's base URL.
    pub url: Url,
    /// Read from `token_file` at load, never from configuration text.
    pub token: FirewallToken,
    /// Kept so a settings push can never write over it (T5).
    pub token_file: PathBuf,
    pub key_cache_ttl_seconds: NonZeroU64,
    pub key_cache_max_entries: NonZeroUsize,
    /// Lookups a second this firewall may send for keys it has no live entry for (T10).
    pub lookup_budget_per_second: NonZeroU32,
    /// The share of that budget one client address may use for keys with no entry
    /// (C120).
    pub client_lookup_allowance_per_second: NonZeroU32,
    pub request_timeout_seconds: NonZeroU64,
    pub sync_margin_seconds: NonZeroU64,
    /// Peers whose `X-Forwarded-For` is believed (C113).
    pub trusted_proxies: Vec<Cidr>,
}

/// Shared-service authority. The secret has the same redacted representation as a sync token.
#[derive(Clone, Debug)]
pub struct ServicePolicyConfig {
    pub server_url: Url,
    pub service_key_file: PathBuf,
    pub service_key: FirewallToken,
    pub sync_interval_seconds: NonZeroU64,
    /// Peers whose `X-Forwarded-For` names the client address an upload's spool place is counted against.
    pub trusted_proxies: Vec<Cidr>,
}

/// The firewall's credential for the sync API. Its `Debug` prints nothing, because
/// `Config` is printed whole.
#[derive(Clone, PartialEq, Eq)]
pub struct FirewallToken(String);

impl FirewallToken {
    pub fn new(token: String) -> FirewallToken {
        FirewallToken(token)
    }

    pub(crate) fn expose(&self) -> &str {
        &self.0
    }

    /// The secret, for a test that checks which credential a mode uses. **Compiled only
    /// under `test-support`.**
    #[cfg(feature = "test-support")]
    pub fn expose_for_test_support(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for FirewallToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FirewallToken(..)")
    }
}

/// An address range, `192.0.2.0/24` or `2001:db8::/32`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Cidr {
    pub addr: IpAddr,
    pub prefix: u8,
}

impl Cidr {
    /// An IPv4-mapped IPv6 range (inside `::ffff:0:0/96`) is read as the IPv4 range it
    /// is, so it holds every address it names (C113). One wider than `/96` mixes IPv4
    /// and IPv6 and is refused.
    pub fn parse(text: &str) -> Option<Cidr> {
        let (addr, prefix) = text.split_once('/')?;
        let addr: IpAddr = addr.parse().ok()?;
        let prefix: u8 = prefix.parse().ok()?;
        let (addr, prefix) = Cidr::unmapped(addr, prefix)?;
        let bits = if addr.is_ipv4() { 32 } else { 128 };
        (prefix <= bits).then_some(Cidr { addr, prefix })
    }

    /// `addr/prefix`, with an IPv4-mapped range as its IPv4 range.
    pub fn unmapped(addr: IpAddr, prefix: u8) -> Option<(IpAddr, u8)> {
        match addr {
            IpAddr::V6(v6) if u128::from(v6) >> 32 == 0xffff => {
                let v4 = v6.to_ipv4_mapped()?;
                Some((IpAddr::V4(v4), prefix.checked_sub(96)?))
            }
            _ => Some((addr, prefix)),
        }
    }
}

/// The default for the one key SPEC §4 does not list. It is a Gate 3 addition
/// adopted from threat TM-1: a reference count cap bounds the duration of a single
/// project-refresh transaction independently of the byte cap.
const DEFAULT_MAX_REFERENCES_PER_PROJECT: u32 = 20_000;

/// A cold artifact request waits this long for a download permit (decision
/// 2026-10-23): npm opens 15 connections by default, more than the 8 permits.
const DEFAULT_DOWNLOAD_WAIT_SECONDS: u64 = 5;
/// The longest wait a file may set: well inside a client's own timeout, so a wait is
/// always a short one.
const MAX_DOWNLOAD_WAIT_SECONDS: u64 = 60;
/// Eight waiters for each of the default 8 permits.
const DEFAULT_MAX_DOWNLOAD_WAITERS: u32 = 64;

/// The ceiling a file that predates SPEC revision 3 gets: one day, which is what
/// `config.sample.toml` ships. A file with no opinion inherits a bound rather than
/// the unbounded staleness the ceiling exists to close.
const DEFAULT_METADATA_MAX_AGE_SECONDS: u64 = 86_400;

/// Ten years. A longer cooldown is not a stricter policy but a deadline past what an
/// `eligible_at` can carry: a hold would saturate to the end of time and lose the
/// date SPEC §11 promises the client.
const MAX_COOLDOWN_SECONDS: u64 = 10 * 365 * 86_400;

/// What a decision log file costs when the operator names one and says nothing about
/// its size: 100 MiB live, so 200 MiB including the one rollover generation.
const DEFAULT_LOG_FILE_MAX_BYTES: NonZeroU64 = NonZeroU64::new(100 * 1024 * 1024).unwrap();

/// What a delivery queue costs when the operator says nothing about it. The figure
/// belongs to `delivery`, which also divides by it: a budget the operator writes and
/// the record size it is divided by must come from one place or they can disagree.
const DEFAULT_QUEUE_MAX_BYTES: NonZeroU64 =
    NonZeroU64::new(delivery::DEFAULT_QUEUE_MAX_BYTES).unwrap();

/// D4: 5 minutes, so a repeat lookup for the same version is answered from cache
/// rather than re-asked on every request.
const DEFAULT_OSV_CACHE_TTL_SECONDS: NonZeroU64 = NonZeroU64::new(300).unwrap();

/// D4: an architect's estimate (not sourced from OSV's documented SLA — Gate 3
/// least-confident-decision 3), short enough to keep C12c's outbound-call bound and
/// C14's per-waiter reply bound both tight.
const DEFAULT_OSV_REQUEST_TIMEOUT_MS: NonZeroU64 = NonZeroU64::new(2000).unwrap();

/// C1031: the stale-match window and its bounds (default 24 h, floor 1 h, ceiling 7 d).
const DEFAULT_OSV_STALE_MATCH_SECONDS: u64 = 86_400;
const MIN_OSV_STALE_MATCH_SECONDS: u64 = 3_600;
const MAX_OSV_STALE_MATCH_SECONDS: u64 = 604_800;

/// The policy server answers OSV at a 1500 ms deadline (user decision, measured api.osv.dev
/// latency); a managed endpoint's timeout must
/// stay strictly above it (03 "Per-query semantics and timing").
const MIN_MANAGED_OSV_REQUEST_TIMEOUT_MS: u64 = 1600;

/// The longest `sync_interval_seconds` or `key_cache_ttl_seconds`: a day. Both are
/// added to clock readings, and a value past what an `Instant` can hold would panic
/// there rather than fail here.
const MAX_MANAGEMENT_SECONDS: u64 = 86_400;

/// C22's default: changes reach a managed firewall within a minute.
const DEFAULT_SYNC_INTERVAL_SECONDS: NonZeroU64 = NonZeroU64::new(60).unwrap();

/// C112: the round trip is taken out of the interval, so a change applies within it.
const DEFAULT_SYNC_MARGIN_SECONDS: NonZeroU64 = NonZeroU64::new(5).unwrap();

/// How long one call to the management server may take.
const DEFAULT_REQUEST_TIMEOUT_SECONDS: NonZeroU64 = NonZeroU64::new(2).unwrap();

/// The file as written, before validation. Unknown keys are rejected so a typo in
/// an operator's configuration is an error rather than a silently ignored line.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    listen: String,
    public_url: String,
    data_dir: PathBuf,
    blocklist_file: Option<PathBuf>,
    cooldown_seconds: u64,
    metadata_ttl_seconds: u64,
    #[serde(default = "default_metadata_max_age_seconds")]
    metadata_max_age_seconds: u64,
    blocklist_poll_seconds: Option<u64>,
    cache_max_bytes: u64,
    memory_cache_max_bytes: u64,
    max_artifact_bytes: u64,
    max_metadata_bytes: u64,
    max_blocklist_bytes: u64,
    max_upstream_requests: u32,
    max_artifact_downloads: u32,
    #[serde(default = "default_download_wait_seconds")]
    download_wait_seconds: u64,
    #[serde(default = "default_max_download_waiters")]
    max_download_waiters: u32,
    max_active_requests: u32,
    #[serde(default = "default_max_references_per_project")]
    max_references_per_project: u32,
    log_file_path: Option<PathBuf>,
    log_file_max_bytes: Option<u64>,
    log_queue_max_bytes: Option<u64>,
    siem_queue_max_bytes: Option<u64>,
    siem_url: Option<String>,
    siem_auth_header: Option<String>,
    #[serde(default)]
    log_consumer_identification: bool,
    osv_cache_ttl_seconds: Option<u64>,
    osv_request_timeout_ms: Option<u64>,
    osv_stale_match_seconds: Option<u64>,
    osv_mode: Option<String>,
    tls_cert_path: Option<PathBuf>,
    tls_key_path: Option<PathBuf>,
    sync_interval_seconds: Option<u64>,
    management: Option<RawManagement>,
    service_policy: Option<RawServicePolicy>,
    #[serde(default)]
    allowed_peer_cidrs: Vec<String>,
    credential_temp_max_request_bytes: Option<u64>,
    credential_temp_max_total_bytes: Option<u64>,
    #[serde(default)]
    allow_network_data_dir: bool,
    #[serde(default)]
    control_plane_cidrs: Vec<String>,
    npm_upstream_url: Option<String>,
    pypi_upstream_url: Option<String>,
    pypi_artifacts_url: Option<String>,
    rubygems_upstream_url: Option<String>,
    cargo_upstream_url: Option<String>,
    cargo_artifacts_url: Option<String>,
    go_upstream_url: Option<String>,
    go_sumdb_url: Option<String>,
    go_artifacts_url: Option<String>,
    nuget_upstream_url: Option<String>,
    nuget_search_url: Option<String>,
    nuget_publish_url: Option<String>,
    maven_upstream_url: Option<String>,
    maven_publish_url: Option<String>,
    conan_upstream_url: Option<String>,
    conan_publish_url: Option<String>,
    oci_upstream_url: Option<String>,
    oci_artifacts_url: Option<String>,
    oci_token_url: Option<String>,
    #[serde(default = "default_foreign_layer_hosts")]
    oci_foreign_layer_hosts: Vec<String>,
}

/// `[management]` as written. `url` and `token_file` are optional here only so their
/// absence is reported by name.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawManagement {
    url: Option<String>,
    token_file: Option<PathBuf>,
    key_cache_ttl_seconds: Option<u64>,
    key_cache_max_entries: Option<usize>,
    lookup_budget_per_second: Option<u32>,
    client_lookup_allowance_per_second: Option<u32>,
    request_timeout_seconds: Option<u64>,
    sync_margin_seconds: Option<u64>,
    #[serde(default)]
    trusted_proxies: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawServicePolicy {
    server_url: String,
    service_key_file: PathBuf,
    sync_interval_seconds: Option<u64>,
    #[serde(default)]
    trusted_proxies: Vec<String>,
}

/// What a Windows base image's foreign layers are served from (the `*.data` host is where its redirects land).
fn default_foreign_layer_hosts() -> Vec<String> {
    ["mcr.microsoft.com", "*.data.mcr.microsoft.com", "go.microsoft.com", "download.microsoft.com"].map(str::to_owned).to_vec()
}

/// An exact host or `*.suffix`, lower case, letters, digits, `-` and `.` only; at most 64 entries (an empty list allows no foreign layer).
fn foreign_layer_hosts(hosts: Vec<String>) -> Result<Vec<String>, ConfigError> {
    let bad = |why: &str| invalid("oci_foreign_layer_hosts", why.to_owned());
    if hosts.len() > 64 {
        return Err(bad("at most 64 hosts"));
    }
    for host in &hosts {
        let name = host.strip_prefix("*.").unwrap_or(host);
        let labels_ok = !name.is_empty() && name.len() <= 253 && name.split('.').all(|label| !label.is_empty() && label.len() <= 63 && !label.starts_with('-') && !label.ends_with('-') && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'));
        if !labels_ok || name.split('.').count() < 2 {
            return Err(bad("each entry is a lower-case host (`mcr.microsoft.com`) or `*.` and a lower-case domain (`*.data.mcr.microsoft.com`)"));
        }
    }
    Ok(hosts)
}

fn default_download_wait_seconds() -> u64 {
    DEFAULT_DOWNLOAD_WAIT_SECONDS
}

fn default_max_download_waiters() -> u32 {
    DEFAULT_MAX_DOWNLOAD_WAITERS
}

fn default_max_references_per_project() -> u32 {
    DEFAULT_MAX_REFERENCES_PER_PROJECT
}

fn default_metadata_max_age_seconds() -> u64 {
    DEFAULT_METADATA_MAX_AGE_SECONDS
}

/// The keys every configuration file must carry, in the order SPEC §4 lists them.
/// They are named here as well as in `RawConfig` so that a missing key and an
/// unknown one can be reported as themselves: serde reports both as a
/// deserialisation failure, and "invalid TOML" is not a reason an operator can act
/// on. `tests/config_validation.rs` deletes each key of the shipped sample in turn,
/// so this list cannot silently drift from `RawConfig`.
const REQUIRED_KEYS: &[&str] = &[
    "listen",
    "public_url",
    "data_dir",
    "blocklist_file",
    "cooldown_seconds",
    "metadata_ttl_seconds",
    "blocklist_poll_seconds",
    "cache_max_bytes",
    "memory_cache_max_bytes",
    "max_artifact_bytes",
    "max_metadata_bytes",
    "max_blocklist_bytes",
    "max_upstream_requests",
    "max_artifact_downloads",
    "max_active_requests",
];

/// Keys with a default, which a file may leave out.
const OPTIONAL_KEYS: &[&str] = &[
    "max_references_per_project",
    "download_wait_seconds",
    "max_download_waiters",
    "metadata_max_age_seconds",
    "log_file_path",
    "log_file_max_bytes",
    "log_queue_max_bytes",
    "siem_url",
    "siem_queue_max_bytes",
    "siem_auth_header",
    "log_consumer_identification",
    "osv_cache_ttl_seconds",
    "osv_request_timeout_ms",
    "osv_stale_match_seconds",
    "osv_mode",
    "tls_cert_path",
    "tls_key_path",
    "sync_interval_seconds",
    "management",
    "service_policy",
    "allowed_peer_cidrs",
    "credential_temp_max_request_bytes",
    "credential_temp_max_total_bytes",
    "allow_network_data_dir",
    "control_plane_cidrs",
    "npm_upstream_url",
    "pypi_upstream_url",
    "pypi_artifacts_url",
    "rubygems_upstream_url",
    "cargo_upstream_url",
    "cargo_artifacts_url",
    "go_upstream_url",
    "go_sumdb_url",
    "go_artifacts_url",
    "nuget_upstream_url",
    "nuget_search_url",
    "nuget_publish_url",
    "maven_upstream_url",
    "maven_publish_url",
    "conan_upstream_url",
    "conan_publish_url",
    "oci_upstream_url",
    "oci_artifacts_url",
    "oci_token_url",
    "oci_foreign_layer_hosts",
];

/// The keys a managed firewall may leave out, because it ignores its local blocklist
/// (C109).
const STANDALONE_ONLY_KEYS: &[&str] = &["blocklist_file", "blocklist_poll_seconds"];

/// What `blocklist_poll_seconds` is when a managed firewall leaves it out. Never read:
/// the poller does not run in managed mode.
const IGNORED_POLL_SECONDS: NonZeroU64 = NonZeroU64::new(60).unwrap();

impl Config {
    pub fn from_toml_str(text: &str) -> Result<Config, ConfigError> {
        // Three stages, so each failure keeps its own name: the document must be
        // TOML, then its key set must be exactly ours, then its values must convert.
        let table: toml::Table = toml::from_str(text).map_err(ConfigError::Syntax)?;
        check_keys(&table)?;
        let raw: RawConfig = toml::from_str(text).map_err(ConfigError::Syntax)?;
        let mut config = raw.validate()?;
        config.local = LocalText(text.into());
        Ok(config)
    }

    pub fn load(path: &Path) -> Result<Config, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        Config::from_toml_str(&text)
    }
}

impl RawConfig {
    fn validate(self) -> Result<Config, ConfigError> {
        let listen = self
            .listen
            .parse::<SocketAddr>()
            .map_err(|err| invalid("listen", err.to_string()))?;

        let public_url =
            Url::parse(&self.public_url).map_err(|err| invalid("public_url", err.to_string()))?;
        if public_url.scheme() != "https" {
            return Err(invalid(
                "public_url",
                "must use the https scheme".to_owned(),
            ));
        }
        // The base of every rewritten artifact URL, so a credential here would be
        // handed to every client.
        if has_userinfo(&public_url) {
            return Err(invalid(
                "public_url",
                "must not carry a username or password".to_owned(),
            ));
        }
        if public_url.query().is_some() || public_url.fragment().is_some() {
            return Err(invalid(
                "public_url",
                "must not carry a query or fragment".to_owned(),
            ));
        }
        if public_url.path() != "/" && !public_url.path().is_empty() {
            return Err(invalid(
                "public_url",
                "must not carry a path prefix".to_owned(),
            ));
        }

        if !self.data_dir.is_absolute() {
            return Err(invalid("data_dir", "must be an absolute path".to_owned()));
        }
        // `check_keys` let these two be absent only in managed mode.
        let blocklist_file = self.blocklist_file.unwrap_or_default();
        if self.management.is_none() && self.service_policy.is_none() && !blocklist_file.is_absolute() {
            return Err(invalid(
                "blocklist_file",
                "must be an absolute path".to_owned(),
            ));
        }
        let blocklist_poll_seconds = match self.blocklist_poll_seconds {
            Some(value) => nonzero_u64("blocklist_poll_seconds", value)?,
            None => IGNORED_POLL_SECONDS,
        };
        let npm_upstream_url = upstream_origin("npm_upstream_url", self.npm_upstream_url)?;
        let pypi_upstream_url = upstream_origin("pypi_upstream_url", self.pypi_upstream_url)?;
        let pypi_artifacts_url = upstream_origin("pypi_artifacts_url", self.pypi_artifacts_url)?;
        let rubygems_upstream_url = upstream_origin("rubygems_upstream_url", self.rubygems_upstream_url)?;
        let cargo_upstream_url = upstream_origin("cargo_upstream_url", self.cargo_upstream_url)?;
        let cargo_artifacts_url = upstream_origin("cargo_artifacts_url", self.cargo_artifacts_url)?;
        let go_upstream_url = upstream_origin("go_upstream_url", self.go_upstream_url)?;
        let go_sumdb_url = upstream_origin("go_sumdb_url", self.go_sumdb_url)?;
        let go_artifacts_url = upstream_origin_with("go_artifacts_url", self.go_artifacts_url, true)?;
        let nuget_upstream_url = upstream_origin("nuget_upstream_url", self.nuget_upstream_url)?;
        let nuget_search_url = upstream_origin("nuget_search_url", self.nuget_search_url)?;
        let nuget_publish_url = upstream_origin("nuget_publish_url", self.nuget_publish_url)?;
        let maven_upstream_url = upstream_origin_with("maven_upstream_url", self.maven_upstream_url, true)?;
        let maven_publish_url = upstream_origin_with("maven_publish_url", self.maven_publish_url, true)?;
        let conan_upstream_url = upstream_origin_with("conan_upstream_url", self.conan_upstream_url, true)?;
        let conan_publish_url = upstream_origin_with("conan_publish_url", self.conan_publish_url, true)?;
        let oci_upstream_url = upstream_origin_with("oci_upstream_url", self.oci_upstream_url, true)?;
        let oci_artifacts_url = upstream_origin("oci_artifacts_url", self.oci_artifacts_url)?;
        let oci_token_url = upstream_origin("oci_token_url", self.oci_token_url)?;
        let oci_foreign_layer_hosts = foreign_layer_hosts(self.oci_foreign_layer_hosts)?;

        if self.cooldown_seconds > MAX_COOLDOWN_SECONDS {
            return Err(invalid(
                "cooldown_seconds",
                format!("must not exceed {MAX_COOLDOWN_SECONDS} (ten years)"),
            ));
        }

        // SPEC rev 3 §10. A ceiling beneath the revalidation interval would expire
        // every copy before it could ever be revalidated: a configuration that looks
        // stricter and is in fact a self-inflicted outage. Zero is the "off" value
        // and is exempt.
        if self.metadata_max_age_seconds != 0
            && self.metadata_max_age_seconds < self.metadata_ttl_seconds
        {
            return Err(invalid(
                "metadata_max_age_seconds",
                format!(
                    "must not be below metadata_ttl_seconds ({}); use 0 to disable the ceiling",
                    self.metadata_ttl_seconds
                ),
            ));
        }

        if self.download_wait_seconds > MAX_DOWNLOAD_WAIT_SECONDS {
            return Err(invalid(
                "download_wait_seconds",
                format!("must not exceed {MAX_DOWNLOAD_WAIT_SECONDS}"),
            ));
        }

        let cache_max_bytes = nonzero_u64("cache_max_bytes", self.cache_max_bytes)?;
        let max_artifact_bytes = nonzero_u64("max_artifact_bytes", self.max_artifact_bytes)?;
        if max_artifact_bytes > cache_max_bytes {
            return Err(invalid(
                "max_artifact_bytes",
                "must not exceed cache_max_bytes".to_owned(),
            ));
        }

        // A size with nowhere to write is an operator who thinks delivery is on and
        // is getting nothing, which is worth a refusal rather than a silent no-op.
        if self.log_file_max_bytes.is_some() && self.log_file_path.is_none() {
            return Err(invalid(
                "log_file_max_bytes",
                "has no effect without log_file_path".to_owned(),
            ));
        }
        let log_file_max_bytes = match self.log_file_max_bytes {
            Some(value) => NonZeroU64::new(value).ok_or_else(|| {
                invalid("log_file_max_bytes", "must be greater than zero".to_owned())
            })?,
            None => DEFAULT_LOG_FILE_MAX_BYTES,
        };
        // Read before the struct literal moves the path out of `self`.
        let log_file_path_set = self.log_file_path.is_some();
        let siem_url_set = self.siem_url.is_some();

        // Same rule, same reason: a credential header with no collector to send it to
        // is an operator who believes delivery is on and is getting nothing.
        if self.siem_auth_header.is_some() && self.siem_url.is_none() {
            return Err(invalid(
                "siem_auth_header",
                "has no effect without siem_url".to_owned(),
            ));
        }
        let siem_url = match &self.siem_url {
            Some(text) => {
                let url = Url::parse(text)
                    .map_err(|_| invalid("siem_url", "must be a valid URL".to_owned()))?;
                // The credential belongs in `PROBATION_SIEM_AUTH`, which is kept off
                // this struct; one embedded here would be printed with it.
                if has_userinfo(&url) {
                    return Err(invalid(
                        "siem_url",
                        "must not carry a username or password; use PROBATION_SIEM_AUTH".to_owned(),
                    ));
                }
                // The credential and every decision record travel this URL. Plaintext
                // is allowed only where the traffic cannot leave the machine.
                if url.scheme() != "https" && !is_loopback(&url) {
                    return Err(invalid(
                        "siem_url",
                        "must use https unless the host is loopback".to_owned(),
                    ));
                }
                Some(url)
            }
            None => None,
        };
        let siem_auth_header = match &self.siem_auth_header {
            Some(name) => HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
                invalid(
                    "siem_auth_header",
                    "must be a valid HTTP header name".to_owned(),
                )
            })?,
            None => header::AUTHORIZATION,
        };

        // Both or neither: a cert with no key (or a key with no cert) cannot start
        // TLS, so it is refused up front rather than failing later at bind time with
        // a less specific error.
        match (&self.tls_cert_path, &self.tls_key_path) {
            (Some(_), None) => {
                return Err(invalid(
                    "tls_cert_path",
                    "requires tls_key_path to also be set".to_owned(),
                ));
            }
            (None, Some(_)) => {
                return Err(invalid(
                    "tls_key_path",
                    "requires tls_cert_path to also be set".to_owned(),
                ));
            }
            _ => {}
        }

        // Peer addresses recorded with no sink configured would reach only the
        // console — which the host keeps on disk under systemd or a container runtime,
        // but which is not a destination the operator chose. Refused by name rather
        // than silently collected.
        if self.log_consumer_identification
            && self.log_file_path.is_none()
            && self.siem_url.is_none()
        {
            return Err(invalid(
                "log_consumer_identification",
                "requires log_file_path or siem_url, so recorded peer addresses reach a \
                 durable destination the operator chose"
                    .to_owned(),
            ));
        }

        let sync_interval_seconds = match self.sync_interval_seconds {
            Some(value) => bounded_seconds("sync_interval_seconds", value)?,
            None => DEFAULT_SYNC_INTERVAL_SECONDS,
        };
        if self.management.is_some() && self.service_policy.is_some() {
            return Err(invalid("service_policy", "cannot be combined with management".to_owned()));
        }
        let service_policy = self.service_policy.map(RawServicePolicy::validate).transpose()?;
        let allowed_peer_cidrs = self.allowed_peer_cidrs.iter().map(|text| {
            let cidr = text.parse::<ipnet::IpNet>().map_err(|_| invalid("allowed_peer_cidrs", "must contain valid CIDRs".to_owned()))?;
            // LS-F10: at least /8 for IPv4 and /32 for IPv6.
            let floor = if cidr.addr().is_ipv4() { 8 } else { 32 };
            if cidr.prefix_len() < floor {
                return Err(invalid("allowed_peer_cidrs", format!("must not be wider than /{floor} ({})", if cidr.addr().is_ipv4() { "IPv4" } else { "IPv6" })));
            }
            Ok(cidr)
        }).collect::<Result<Vec<_>, ConfigError>>()?;
        // The own-listener denial needs the configured port (a descriptor must never point back).
        if service_policy.is_some() && listen.port() == 0 {
            return Err(invalid("listen", "must name a fixed port when [service_policy] is set".to_owned()));
        }
        if service_policy.is_some() && !listen.ip().to_canonical().is_loopback()
            && (self.tls_cert_path.is_none() || self.tls_key_path.is_none() || allowed_peer_cidrs.is_empty()) {
            return Err(invalid("service_policy", "a non-loopback listener requires TLS and allowed_peer_cidrs".to_owned()));
        }
        for (key, value) in [
            ("credential_temp_max_request_bytes", self.credential_temp_max_request_bytes),
            ("credential_temp_max_total_bytes", self.credential_temp_max_total_bytes),
        ] {
            if value == Some(0) {
                return Err(invalid(key, "must be positive when set".to_owned()));
            }
        }
        let control_plane_cidrs = self.control_plane_cidrs.iter().map(|text| {
            text.parse::<ipnet::IpNet>().map_err(|_| invalid("control_plane_cidrs", "must contain valid CIDRs".to_owned()))
        }).collect::<Result<Vec<_>, ConfigError>>()?;
        let management = self
            .management
            .map(|raw| raw.validate(sync_interval_seconds))
            .transpose()?;

        let managed_osv = management.is_some() || service_policy.is_some();
        let osv_request_timeout_ms = match self.osv_request_timeout_ms {
            Some(value) => nonzero_u64("osv_request_timeout_ms", value)?,
            None => DEFAULT_OSV_REQUEST_TIMEOUT_MS,
        };
        if managed_osv && osv_request_timeout_ms.get() < MIN_MANAGED_OSV_REQUEST_TIMEOUT_MS {
            return Err(invalid(
                "osv_request_timeout_ms",
                format!("must be at least {MIN_MANAGED_OSV_REQUEST_TIMEOUT_MS} in managed and shared-service mode"),
            ));
        }
        let osv_stale_match_seconds = match self.osv_stale_match_seconds {
            Some(_) if !managed_osv => {
                return Err(invalid(
                    "osv_stale_match_seconds",
                    "applies only with [management] or [service_policy]".to_owned(),
                ));
            }
            Some(value) if !(MIN_OSV_STALE_MATCH_SECONDS..=MAX_OSV_STALE_MATCH_SECONDS).contains(&value) => {
                return Err(invalid(
                    "osv_stale_match_seconds",
                    format!("must be between {MIN_OSV_STALE_MATCH_SECONDS} and {MAX_OSV_STALE_MATCH_SECONDS}"),
                ));
            }
            Some(value) => value,
            None => DEFAULT_OSV_STALE_MATCH_SECONDS,
        };

        Ok(Config {
            listen,
            public_url,
            data_dir: self.data_dir,
            blocklist_file,
            cooldown_seconds: self.cooldown_seconds,
            metadata_ttl_seconds: self.metadata_ttl_seconds,
            metadata_max_age_seconds: self.metadata_max_age_seconds,
            blocklist_poll_seconds,
            cache_max_bytes,
            memory_cache_max_bytes: nonzero_u64(
                "memory_cache_max_bytes",
                self.memory_cache_max_bytes,
            )?,
            max_artifact_bytes,
            max_metadata_bytes: nonzero_u64("max_metadata_bytes", self.max_metadata_bytes)?,
            max_blocklist_bytes: nonzero_u64("max_blocklist_bytes", self.max_blocklist_bytes)?,
            max_upstream_requests: nonzero_u32(
                "max_upstream_requests",
                self.max_upstream_requests,
            )?,
            max_artifact_downloads: nonzero_u32(
                "max_artifact_downloads",
                self.max_artifact_downloads,
            )?,
            download_wait_seconds: self.download_wait_seconds,
            max_download_waiters: self.max_download_waiters,
            max_active_requests: nonzero_u32("max_active_requests", self.max_active_requests)?,
            max_references_per_project: nonzero_u32(
                "max_references_per_project",
                self.max_references_per_project,
            )?,
            log_file_path: self.log_file_path,
            log_file_max_bytes,
            siem_url,
            siem_auth_header,
            log_consumer_identification: self.log_consumer_identification,
            log_queue_max_bytes: queue_budget(
                "log_queue_max_bytes",
                self.log_queue_max_bytes,
                "log_file_path",
                log_file_path_set,
            )?,
            siem_queue_max_bytes: queue_budget(
                "siem_queue_max_bytes",
                self.siem_queue_max_bytes,
                "siem_url",
                siem_url_set,
            )?,
            osv_cache_ttl_seconds: match self.osv_cache_ttl_seconds {
                Some(value) => nonzero_u64("osv_cache_ttl_seconds", value)?,
                None => DEFAULT_OSV_CACHE_TTL_SECONDS,
            },
            osv_request_timeout_ms,
            osv_stale_match_seconds,
            osv_mode: match self.osv_mode {
                Some(value) => match value.to_lowercase().as_str() {
                    "enforce" => osv::OsvMode::Enforce,
                    "diagnostic" => osv::OsvMode::Diagnostic,
                    "off" => osv::OsvMode::Off,
                    _ => {
                        return Err(invalid(
                            "osv_mode",
                            format!("must be one of enforce, diagnostic, off, got {value:?}"),
                        ));
                    }
                },
                None => osv::OsvMode::Enforce,
            },
            tls_cert_path: self.tls_cert_path,
            tls_key_path: self.tls_key_path,
            sync_interval_seconds,
            management,
            service_policy,
            allowed_peer_cidrs,
            credential_temp_max_request_bytes: self.credential_temp_max_request_bytes,
            credential_temp_max_total_bytes: self.credential_temp_max_total_bytes,
            allow_network_data_dir: self.allow_network_data_dir,
            control_plane_cidrs,
            npm_upstream_url,
            pypi_upstream_url,
            pypi_artifacts_url,
            rubygems_upstream_url,
            cargo_upstream_url,
            cargo_artifacts_url,
            go_upstream_url,
            go_sumdb_url,
            go_artifacts_url,
            nuget_upstream_url,
            nuget_search_url,
            nuget_publish_url,
            maven_upstream_url,
            maven_publish_url,
            conan_upstream_url,
            conan_publish_url,
            oci_upstream_url,
            oci_artifacts_url,
            oci_token_url,
            oci_foreign_layer_hosts,
            local: LocalText::default(),
        })
    }
}

/// One of the three upstream origin keys (C35, TEST-01 as amended): an `https` origin
/// with no credentials, query, fragment or path prefix. An address literal must be a
/// public one: no DNS answer is checked for it at connect time, so it is checked here.
fn upstream_origin(key: &'static str, text: Option<String>) -> Result<Option<Url>, ConfigError> {
    upstream_origin_with(key, text, false)
}

/// `allow_path`: the one key (`go_artifacts_url`) whose value is an origin AND a path prefix (a storage
/// bucket's name), admitted by whole path segments.
fn upstream_origin_with(key: &'static str, text: Option<String>, allow_path: bool) -> Result<Option<Url>, ConfigError> {
    let Some(text) = text else {
        return Ok(None);
    };
    let url = Url::parse(&text).map_err(|_| invalid(key, "must be a valid URL".to_owned()))?;
    if url.scheme() != "https" {
        return Err(invalid(key, "must use https".to_owned()));
    }
    if has_userinfo(&url) || url.query().is_some() || url.fragment().is_some() {
        return Err(invalid(
            key,
            "must not carry a username, password, query or fragment".to_owned(),
        ));
    }
    if url.path() != "/" && !allow_path {
        return Err(invalid(key, "must not carry a path prefix".to_owned()));
    }
    if url.path().split('/').any(|segment| segment == "." || segment == ".." || segment.contains('%')) {
        return Err(invalid(key, "must not carry dot or encoded path segments".to_owned()));
    }
    let literal = match url.host() {
        Some(Host::Ipv4(addr)) => Some(IpAddr::V4(addr)),
        Some(Host::Ipv6(addr)) => Some(IpAddr::V6(addr)),
        Some(Host::Domain(_)) => None,
        None => return Err(invalid(key, "must name a host".to_owned())),
    };
    if literal.is_some_and(|addr| !crate::upstream::resolver::is_public(addr)) {
        return Err(invalid(
            key,
            "must not be a private, loopback or link-local address".to_owned(),
        ));
    }
    Ok(Some(url))
}

impl RawServicePolicy {
    fn validate(self) -> Result<ServicePolicyConfig, ConfigError> {
        use std::io::Read;
        let server_url = Url::parse(&self.server_url)
            .map_err(|_| invalid("service_policy.server_url", "must be a valid URL".to_owned()))?;
        if server_url.scheme() != "https" || server_url.host().is_none() || has_userinfo(&server_url)
            || server_url.query().is_some() || server_url.fragment().is_some()
            || !matches!(server_url.path(), "" | "/") {
            return Err(invalid("service_policy.server_url", "requires an HTTPS origin: no path, credentials, query or fragment".to_owned()));
        }
        if !self.service_key_file.is_absolute() {
            return Err(invalid("service_policy.service_key_file", "must be an absolute path".to_owned()));
        }
        let file = std::fs::File::open(&self.service_key_file)
            .map_err(|_| invalid("service_policy.service_key_file", "cannot be read".to_owned()))?;
        let metadata = file.metadata().map_err(|_| invalid("service_policy.service_key_file", "cannot read permissions".to_owned()))?;
        #[cfg(unix)]
        let shared = {
            use std::os::unix::fs::PermissionsExt;
            metadata.permissions().mode() & 0o077 != 0
        };
        // Windows: the DACL of the file must grant nobody but SYSTEM, the Administrators and the account running the service.
        #[cfg(windows)]
        let shared = crate::key_acl::is_shared(&self.service_key_file);
        #[cfg(not(any(unix, windows)))]
        let shared = false;
        if !metadata.is_file() || shared {
            return Err(invalid("service_policy.service_key_file", "requires a private regular file".to_owned()));
        }
        let mut key = String::new();
        file.take(1025).read_to_string(&mut key)
            .map_err(|_| invalid("service_policy.service_key_file", "cannot be read".to_owned()))?;
        // LS-F15: exactly one trailing newline is trimmed; every byte is printable ASCII.
        let key = key.strip_suffix("\r\n").or_else(|| key.strip_suffix('\n')).unwrap_or(&key);
        if key.len() > 512 || !key.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
            return Err(invalid("service_policy.service_key_file", "must hold one printable ASCII key of at most 512 bytes".to_owned()));
        }
        if key.len() != 36 || !key.starts_with("prb_") || !key[4..].bytes().all(|byte| byte.is_ascii_alphanumeric()) {
            return Err(invalid("service_policy.service_key_file", "requires a service API key".to_owned()));
        }
        Ok(ServicePolicyConfig {
            server_url, service_key_file: self.service_key_file, service_key: FirewallToken::new(key.to_owned()),
            sync_interval_seconds: bounded_seconds("service_policy.sync_interval_seconds", self.sync_interval_seconds.unwrap_or(60))?,
            trusted_proxies: self
                .trusted_proxies
                .iter()
                .map(|text| Cidr::parse(text).ok_or_else(|| invalid("service_policy.trusted_proxies", format!("{text:?} is not an address range"))))
                .collect::<Result<_, _>>()?,
        })
    }
}

impl RawManagement {
    fn validate(self, sync_interval: NonZeroU64) -> Result<ManagementConfig, ConfigError> {
        let url = self.url.ok_or(ConfigError::MissingKey("management.url"))?;
        let url = Url::parse(&url)
            .map_err(|_| invalid("management.url", "must be a valid URL".to_owned()))?;
        // The firewall token and every key hash travel this URL: https only (C34),
        // loopback included. A test reaches its plain-HTTP fake server by building
        // `ManagementConfig` itself, never through this file.
        if url.scheme() != "https" {
            return Err(invalid("management.url", "must use https".to_owned()));
        }
        if has_userinfo(&url) || url.query().is_some() || url.fragment().is_some() {
            return Err(invalid(
                "management.url",
                "must not carry a username, password, query or fragment".to_owned(),
            ));
        }

        let token_file = self
            .token_file
            .ok_or(ConfigError::MissingKey("management.token_file"))?;
        let token = std::fs::read_to_string(&token_file)
            .map_err(|err| invalid("management.token_file", format!("cannot be read: {err}")))?;
        let token = token.trim();
        if token.is_empty() {
            return Err(invalid(
                "management.token_file",
                "holds no token".to_owned(),
            ));
        }
        // It is sent as a header value, so visible ASCII only: no inner whitespace,
        // line break or control character can split or smuggle a header.
        if !token.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(invalid(
                "management.token_file",
                "the token holds a character outside visible ASCII".to_owned(),
            ));
        }

        let sync_margin_seconds = match self.sync_margin_seconds {
            Some(value) => nonzero_u64("management.sync_margin_seconds", value)?,
            None => DEFAULT_SYNC_MARGIN_SECONDS.min(half(sync_interval)),
        };
        // C112: the margin is at most half the interval.
        if sync_margin_seconds > half(sync_interval) {
            return Err(invalid(
                "management.sync_margin_seconds",
                "must be at most half of sync_interval_seconds".to_owned(),
            ));
        }
        let request_timeout_seconds = match self.request_timeout_seconds {
            Some(value) => nonzero_u64("management.request_timeout_seconds", value)?,
            None => DEFAULT_REQUEST_TIMEOUT_SECONDS.min(sync_margin_seconds),
        };
        if request_timeout_seconds > sync_margin_seconds {
            return Err(invalid(
                "management.request_timeout_seconds",
                "must not exceed management.sync_margin_seconds".to_owned(),
            ));
        }

        let trusted_proxies = self
            .trusted_proxies
            .iter()
            .map(|text| {
                Cidr::parse(text).ok_or_else(|| {
                    invalid(
                        "management.trusted_proxies",
                        format!("{text:?} is not an address range"),
                    )
                })
            })
            .collect::<Result<_, _>>()?;

        Ok(ManagementConfig {
            url,
            token: FirewallToken(token.to_owned()),
            token_file,
            key_cache_ttl_seconds: bounded_seconds(
                "management.key_cache_ttl_seconds",
                self.key_cache_ttl_seconds.unwrap_or(300),
            )?,
            key_cache_max_entries: NonZeroUsize::new(self.key_cache_max_entries.unwrap_or(100_000))
                .ok_or_else(|| {
                    invalid(
                        "management.key_cache_max_entries",
                        "must not be zero".to_owned(),
                    )
                })?,
            lookup_budget_per_second: nonzero_u32(
                "management.lookup_budget_per_second",
                self.lookup_budget_per_second.unwrap_or(50),
            )?,
            client_lookup_allowance_per_second: nonzero_u32(
                "management.client_lookup_allowance_per_second",
                self.client_lookup_allowance_per_second.unwrap_or(5),
            )?,
            request_timeout_seconds,
            sync_margin_seconds,
            trusted_proxies,
        })
    }
}

/// A non-zero duration of at most [`MAX_MANAGEMENT_SECONDS`]. The margin and the request
/// timeout are bounded by the interval, so this bounds them too.
fn bounded_seconds(key: &'static str, value: u64) -> Result<NonZeroU64, ConfigError> {
    if value > MAX_MANAGEMENT_SECONDS {
        return Err(invalid(
            key,
            format!("must not exceed {MAX_MANAGEMENT_SECONDS} (one day)"),
        ));
    }
    nonzero_u64(key, value)
}

fn half(interval: NonZeroU64) -> NonZeroU64 {
    NonZeroU64::new(interval.get() / 2).unwrap_or(NonZeroU64::MIN)
}

fn has_userinfo(url: &Url) -> bool {
    !url.username().is_empty() || url.password().is_some()
}

/// Whether `url`'s host is this machine. `localhost` counts by name as well as by
/// address, because that is what an operator running a collector in a sidecar writes.
fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Ipv4(addr)) => addr.is_loopback(),
        Some(Host::Ipv6(addr)) => addr.is_loopback(),
        Some(Host::Domain(name)) => name == "localhost",
        None => false,
    }
}

/// An unknown key is reported before a missing one: a typo produces both, and the
/// misspelling is the half an operator can fix.
fn check_keys(table: &toml::Table) -> Result<(), ConfigError> {
    for key in table.keys() {
        let known = REQUIRED_KEYS.contains(&key.as_str()) || OPTIONAL_KEYS.contains(&key.as_str());
        if !known {
            return Err(ConfigError::UnknownKey(key.clone()));
        }
    }
    let managed = table.contains_key("management") || table.contains_key("service_policy");
    for key in REQUIRED_KEYS {
        let optional = managed && STANDALONE_ONLY_KEYS.contains(key);
        if !optional && !table.contains_key(*key) {
            return Err(ConfigError::MissingKey(key));
        }
    }
    Ok(())
}

fn invalid(key: &'static str, reason: String) -> ConfigError {
    ConfigError::Invalid { key, reason }
}

/// One delivery queue budget: defaulted when absent, checked when present.
///
/// The two keys share every rule, so the rules are written once — two copies are two
/// chances to change only one. The lower bound is decided by calling the same
/// `capacity_for` the queue is actually built with, rather than by restating its
/// division here, so the refusal and the arithmetic cannot disagree.
fn queue_budget(
    key: &'static str,
    value: Option<u64>,
    sink_key: &'static str,
    sink_configured: bool,
) -> Result<NonZeroU64, ConfigError> {
    // An absent key takes the default whether or not its sink is on: the two rules are
    // independent, and a default conditioned on the sink would leave the shipped
    // sample — which configures neither — with no budget at all.
    let Some(value) = value else {
        return Ok(DEFAULT_QUEUE_MAX_BYTES);
    };
    if !sink_configured {
        return Err(invalid(key, format!("has no effect without {sink_key}")));
    }
    let value = nonzero_u64(key, value)?;
    match delivery::capacity_for(value.get()) {
        Ok(_) if value.get() <= delivery::MAX_QUEUE_MAX_BYTES => Ok(value),
        Err(delivery::CapacityError::TooSmall) => Err(invalid(
            key,
            format!(
                "must be at least {} bytes, which is one decision record",
                delivery::BYTES_PER_RECORD
            ),
        )),
        // Above the operator ceiling, or above what a channel can hold. The ceiling's
        // quotient is far below the channel's limit on every target, so in practice
        // it is always the ceiling that refuses; one arm says so for both.
        Ok(_) | Err(delivery::CapacityError::TooLarge) => Err(invalid(
            key,
            format!("must not exceed {} bytes", delivery::MAX_QUEUE_MAX_BYTES),
        )),
    }
}

fn nonzero_u64(key: &'static str, value: u64) -> Result<NonZeroU64, ConfigError> {
    NonZeroU64::new(value).ok_or_else(|| invalid(key, "must not be zero".to_owned()))
}

fn nonzero_u32(key: &'static str, value: u32) -> Result<NonZeroU32, ConfigError> {
    NonZeroU32::new(value).ok_or_else(|| invalid(key, "must not be zero".to_owned()))
}

#[derive(Debug)]
pub enum ConfigError {
    Read {
        path: PathBuf,
        source: io::Error,
    },
    Syntax(toml::de::Error),
    /// A key this release does not know. SPEC §11's TEST-01 rule depends on this
    /// refusal: no configuration key can relax a decision, so a key that looks like
    /// one must not be quietly ignored.
    UnknownKey(String),
    MissingKey(&'static str),
    Invalid {
        key: &'static str,
        reason: String,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Read { path, source } => {
                write!(f, "cannot read {}: {source}", path.display())
            }
            ConfigError::Syntax(err) => write!(f, "invalid TOML: {err}"),
            ConfigError::UnknownKey(key) => write!(f, "unknown key `{key}`"),
            ConfigError::MissingKey(key) => write!(f, "missing key `{key}`"),
            ConfigError::Invalid { key, reason } => write!(f, "invalid `{key}`: {reason}"),
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ConfigError::Read { source, .. } => Some(source),
            ConfigError::Syntax(err) => Some(err),
            ConfigError::UnknownKey(_)
            | ConfigError::MissingKey(_)
            | ConfigError::Invalid { .. } => None,
        }
    }
}

/// The keys a settings push may never set: the one list the management server checks a
/// push against too, so the two cannot drift (C35, C118, T5).
const LOCAL_ONLY_KEYS: &[&str] = probation_policy::LOCAL_ONLY_SETTINGS;

/// The path keys a push may set, each confined under `data_dir`.
const PUSHED_PATH_KEYS: &[&str] = &["log_file_path", "blocklist_file"];

/// The pushed settings in effect, merged over `config.toml` at start (C105).
pub const SETTINGS_OVERLAY: &str = "managed-settings.toml";
/// The overlay before the last push, restored when that push fails at start (C71).
pub const PREVIOUS_SETTINGS_OVERLAY: &str = "managed-settings.prev.toml";
const SETTINGS_STATE: &str = "managed-settings.state";

impl Config {
    /// `pushed` merged over this firewall's own file and checked as start-up checks it,
    /// every path confined under `data_dir`. The local-only settings are this
    /// configuration's whatever the push says, so they are byte-equal after any push.
    pub fn with_overlay(&self, pushed: &str) -> Result<Config, String> {
        let overlay: toml::Table = toml::from_str(pushed)
            .map_err(|err| format!("the pushed settings are not TOML: {err}"))?;
        if let Some(key) = overlay
            .keys()
            .find(|key| LOCAL_ONLY_KEYS.contains(&key.as_str()))
        {
            return Err(format!(
                "`{key}` is set on the firewall only and cannot be pushed"
            ));
        }
        for key in PUSHED_PATH_KEYS {
            if let Some(value) = overlay.get(*key) {
                let path = value
                    .as_str()
                    .ok_or_else(|| format!("`{key}` must be a path"))?;
                self.confined(key, Path::new(path))?;
            }
        }
        let overlay_sets_log_file = overlay.contains_key("log_file_path");
        let mut merged: toml::Table = toml::from_str(&self.local.0)
            .map_err(|err| format!("the local configuration is not TOML: {err}"))?;
        merged.extend(overlay);
        let text = toml::to_string(&merged).map_err(|err| err.to_string())?;
        let mut config = Config::from_toml_str(&text).map_err(|err| err.to_string())?;
        config.listen = self.listen;
        config.public_url = self.public_url.clone();
        config.data_dir = self.data_dir.clone();
        config.tls_cert_path = self.tls_cert_path.clone();
        config.tls_key_path = self.tls_key_path.clone();
        config.siem_url = self.siem_url.clone();
        config.management = self.management.clone();
        config.local = self.local.clone();
        // `check_delivery` leaves the log file out. Start-up refuses one it cannot open
        // only with consumer identification on, and otherwise warns and drops records:
        // the same rule here, and a log file the push itself names is checked too (B2).
        if let Some(path) = &config.log_file_path
            && (config.log_consumer_identification || overlay_sets_log_file)
        {
            openable(path).map_err(|err| format!("`log_file_path` cannot be opened: {err}"))?;
        }
        Ok(config)
    }

    /// A pushed path: absolute, not a symlink, under `data_dir` once resolved, and
    /// nothing the firewall keeps there itself, nor its token (T5).
    fn confined(&self, key: &str, path: &Path) -> Result<(), String> {
        let refused = || format!("`{key}` must name a file of its own under data_dir");
        // Read before anything resolves it: canonicalising follows the link.
        let link = std::fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink());
        let walks = path
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir));
        if link || walks || !path.is_absolute() {
            return Err(refused());
        }
        let resolved = match path.parent().map(std::fs::canonicalize) {
            Some(Ok(parent)) => parent.join(path.file_name().ok_or_else(refused)?),
            _ => path.to_path_buf(),
        };
        let data_dir =
            std::fs::canonicalize(&self.data_dir).unwrap_or_else(|_| self.data_dir.clone());
        let inside = resolved.strip_prefix(&data_dir).map_err(|_| refused())?;
        let top = inside
            .components()
            .next()
            .and_then(|part| part.as_os_str().to_str())
            .unwrap_or_default();
        let token_file = self.management.as_ref().map(|management| {
            std::fs::canonicalize(&management.token_file)
                .unwrap_or_else(|_| management.token_file.clone())
        });
        if top.is_empty()
            || FIREWALL_OWNED.contains(&top)
            || top.starts_with("managed-")
            || top.starts_with("firewall.db")
            || top.starts_with(".tmp")
            || token_file.is_some_and(|token_file| token_file == resolved)
        {
            return Err(refused());
        }
        Ok(())
    }
}

/// What the firewall keeps directly under `data_dir`, besides its `managed-*` files and
/// the `.tmp*` files they are written through: the data-directory lock, the store's
/// directory and the content store. A push may name nothing inside them (T5).
const FIREWALL_OWNED: &[&str] = &["lock", "state", "content"];

/// Whether start-up can open `path` to append to it, creating nothing.
fn openable(path: &Path) -> io::Result<()> {
    if path.exists() {
        return std::fs::OpenOptions::new()
            .append(true)
            .open(path)
            .map(drop);
    }
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::other("a file with no directory"))?;
    tempfile::NamedTempFile::new_in(dir).map(drop)
}

/// What `<data_dir>/managed-settings.state` keeps across restarts, so the server never
/// re-sends an applied push and a failed one is never applied again (C105, C71).
#[derive(Clone, Default, Debug, PartialEq, Eq, Deserialize, serde::Serialize)]
pub struct SettingsState {
    /// The push the overlay holds; `0` before the first.
    pub settings_revision: u64,
    /// The push the previous overlay held.
    pub previous_revision: u64,
    pub failed_revision: Option<u64>,
    pub last_apply_error: Option<String>,
}

impl SettingsState {
    pub fn load(data_dir: &Path) -> SettingsState {
        std::fs::read(data_dir.join(SETTINGS_STATE))
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, data_dir: &Path) -> io::Result<()> {
        let bytes = serde_json::to_vec(self).map_err(io::Error::other)?;
        write_atomically(&data_dir.join(SETTINGS_STATE), &bytes, None)
    }
}

/// Writes `bytes` to a temporary file beside `path`, syncs it and renames it over
/// `path`, so a crash leaves the old file or the new one and never half of either. The
/// file it replaces becomes `previous` when one is named.
pub(crate) fn write_atomically(
    path: &Path,
    bytes: &[u8],
    previous: Option<&Path>,
) -> io::Result<()> {
    use std::io::Write as _;

    let dir = path
        .parent()
        .ok_or_else(|| io::Error::other("a file with no directory"))?;
    let mut temp = tempfile::NamedTempFile::new_in(dir)?;
    temp.write_all(bytes)?;
    temp.as_file().sync_all()?;
    if let Some(previous) = previous
        && path.exists()
    {
        std::fs::rename(path, previous)?;
    }
    temp.persist(path).map_err(|err| err.error)?;
    sync_directory(dir)
}

/// Makes a change of directory entries (a rename or a removal inside `dir`) durable: `fsync` on the directory on Unix.
/// Windows cannot open a directory like a file for `FlushFileBuffers` (access denied), and NTFS journals directory metadata
/// itself, so there the call is a documented no-op: the files involved are already `sync_all`ed before they are renamed
/// into place, and only the durability of the directory entry itself is left to the file system.
///
/// NTFS journaling gives metadata CONSISTENCY, not durability: the directory sync is a no-op there, so a crash inside the
/// NTFS log-flush window right after the refusal marker is written could lose the rename of `service-policy.refused` and
/// re-admit the refused grant for one restart plus one poll interval. The durable explicit-refusal guarantee is therefore
/// narrowed on Windows (it never held there before: the service did not start). Possible hardening: open the directory with
/// FILE_FLAG_BACKUP_SEMANTICS and `sync_all`, or use MOVEFILE_WRITE_THROUGH on the rename.
pub(crate) fn sync_directory(dir: &Path) -> io::Result<()> {
    sync_directory_with(dir, |d| std::fs::File::open(d), cfg!(windows))
}

fn sync_directory_with(
    dir: &Path,
    open: impl FnOnce(&Path) -> io::Result<std::fs::File>,
    directory_sync_unsupported: bool,
) -> io::Result<()> {
    if directory_sync_unsupported {
        return Ok(());
    }
    open(dir)?.sync_all()
}

#[cfg(test)]
mod directory_sync_tests {
    use super::sync_directory_with;
    use std::cell::Cell;
    use std::io;

    fn refused(_: &std::path::Path) -> io::Result<std::fs::File> {
        Err(io::Error::from(io::ErrorKind::PermissionDenied)) // what Windows answers to File::open on a directory
    }

    /// Windows cannot open a directory for FlushFileBuffers, so a directory sync there is a no-op: the file itself was
    /// fsynced before the rename. (Hosted run: `/health/ready` stayed 503 forever because the marker removal failed here.)
    #[test]
    fn a_platform_without_directory_sync_does_not_open_the_directory() {
        let opened = Cell::new(false);
        let outcome = sync_directory_with(std::path::Path::new("."), |path| { opened.set(true); refused(path) }, true);
        assert!(outcome.is_ok(), "no directory sync, no error: {outcome:?}");
        assert!(!opened.get(), "the directory is not even opened");
    }

    /// Unix keeps its durability guarantee: a failing directory open or sync is an error, never swallowed.
    #[test]
    fn unix_still_fails_when_the_directory_cannot_be_synced() {
        let error = sync_directory_with(std::path::Path::new("."), refused, false).expect_err("the failure is reported");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn a_real_directory_is_synced_on_this_platform() {
        let dir = tempfile::tempdir().unwrap();
        super::sync_directory(dir.path()).expect("the directory syncs (or is a documented no-op on Windows)");
        assert!(super::sync_directory(&dir.path().join("missing")).is_ok() == cfg!(windows), "a missing directory is an error where the sync is real");
    }
}
