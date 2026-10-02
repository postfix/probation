//! The configuration file (SPEC §4).
//!
//! Every rejection rule lives here, so `serve` and the validation commands cannot
//! diverge: both build the same `Config` through the same conversion.

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::num::{NonZeroU32, NonZeroU64};
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
    /// Whether OSV enforcement denies, only logs, or is skipped entirely (C16-C18b,
    /// D5/D6). Defaults to `Enforce` — today's behaviour — when absent.
    pub osv_mode: osv::OsvMode,
}

/// The default for the one key SPEC §4 does not list. It is a Gate 3 addition
/// adopted from threat TM-1: a reference count cap bounds the duration of a single
/// project-refresh transaction independently of the byte cap.
const DEFAULT_MAX_REFERENCES_PER_PROJECT: u32 = 20_000;

/// The ceiling a file that predates SPEC revision 3 gets: one day, which is what
/// `config.sample.toml` ships. A file with no opinion inherits a bound rather than
/// the unbounded staleness the ceiling exists to close.
const DEFAULT_METADATA_MAX_AGE_SECONDS: u64 = 86_400;

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
const DEFAULT_OSV_REQUEST_TIMEOUT_MS: NonZeroU64 = NonZeroU64::new(500).unwrap();

/// The file as written, before validation. Unknown keys are rejected so a typo in
/// an operator's configuration is an error rather than a silently ignored line.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    listen: String,
    public_url: String,
    data_dir: PathBuf,
    blocklist_file: PathBuf,
    cooldown_seconds: u64,
    metadata_ttl_seconds: u64,
    #[serde(default = "default_metadata_max_age_seconds")]
    metadata_max_age_seconds: u64,
    blocklist_poll_seconds: u64,
    cache_max_bytes: u64,
    memory_cache_max_bytes: u64,
    max_artifact_bytes: u64,
    max_metadata_bytes: u64,
    max_blocklist_bytes: u64,
    max_upstream_requests: u32,
    max_artifact_downloads: u32,
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
    osv_mode: Option<String>,
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
    "osv_mode",
];

impl Config {
    pub fn from_toml_str(text: &str) -> Result<Config, ConfigError> {
        // Three stages, so each failure keeps its own name: the document must be
        // TOML, then its key set must be exactly ours, then its values must convert.
        let table: toml::Table = toml::from_str(text).map_err(ConfigError::Syntax)?;
        check_keys(&table)?;
        let raw: RawConfig = toml::from_str(text).map_err(ConfigError::Syntax)?;
        raw.validate()
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
        if !self.blocklist_file.is_absolute() {
            return Err(invalid(
                "blocklist_file",
                "must be an absolute path".to_owned(),
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

        Ok(Config {
            listen,
            public_url,
            data_dir: self.data_dir,
            blocklist_file: self.blocklist_file,
            cooldown_seconds: self.cooldown_seconds,
            metadata_ttl_seconds: self.metadata_ttl_seconds,
            metadata_max_age_seconds: self.metadata_max_age_seconds,
            blocklist_poll_seconds: nonzero_u64(
                "blocklist_poll_seconds",
                self.blocklist_poll_seconds,
            )?,
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
            osv_request_timeout_ms: match self.osv_request_timeout_ms {
                Some(value) => nonzero_u64("osv_request_timeout_ms", value)?,
                None => DEFAULT_OSV_REQUEST_TIMEOUT_MS,
            },
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
        })
    }
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
    for key in REQUIRED_KEYS {
        if !table.contains_key(*key) {
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
    if value.get() > delivery::MAX_QUEUE_MAX_BYTES {
        return Err(invalid(
            key,
            format!("must not exceed {} bytes", delivery::MAX_QUEUE_MAX_BYTES),
        ));
    }
    match delivery::capacity_for(value.get()) {
        Ok(_) => Ok(value),
        Err(delivery::CapacityError::TooSmall) => Err(invalid(
            key,
            format!(
                "must be at least {} bytes, which is one decision record",
                delivery::BYTES_PER_RECORD
            ),
        )),
        Err(delivery::CapacityError::TooLarge) => Err(invalid(
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
