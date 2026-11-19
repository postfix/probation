//! The three upstream origins, the URL builder, and the admission check.
//!
//! Two independent defences, deliberately not one. [`OriginSet::url_for`] builds a
//! URL by cloning an origin and appending each name-derived segment with
//! [`url::PathSegmentsMut::push`], which percent-encodes the segment and cannot
//! escape the path — `Url::join` resolves its argument as a *reference*, so a
//! segment beginning `//` or carrying a scheme would replace the host, and string
//! concatenation is worse. [`OriginSet::admit`] then re-validates the finished URL,
//! so a mistake in either one is caught by the other.
//!
//! One thing `push` does not do is encode a segment that is exactly `.` or `..`: it
//! **drops** it (`url-2.5.8/src/path_segments.rs` matches the two and `continue`s).
//! Not a pop, and not text — the segment simply never appears. With every origin at
//! path `/` a drop and a pop are indistinguishable, which is why this is easy to
//! misread; they diverge the moment an origin has a path prefix. Because a dropped
//! segment leaves a URL that `admit` is right to accept — nothing was appended, so
//! nothing escaped — the check cannot live in `admit`. `url_for` refuses those two
//! names itself, before a byte moves.
//!
//! `allow_private_addresses` is settable only by [`OriginSet::for_tests`]. No
//! configuration key, command-line flag or environment variable reaches it, and
//! nothing under `src/` outside this file names `for_tests` — that is invariant
//! TEST-01, and `origin_guard::no_config_key_or_env_var_relaxes_origins` is what
//! says so. Three configuration keys may replace the origins themselves (C35,
//! [`OriginSet::configured`]); every rule here still applies to what they name.

use std::fmt;
use std::net::IpAddr;

use ipnet::IpNet;
use url::Url;

/// SPEC §11's origins, used unless configuration names another. Registry and artifact
/// hosts are separate because PyPI serves its files from a different host than its
/// index.
const NPM_METADATA: &str = "https://registry.npmjs.org";
const PYPI_METADATA: &str = "https://pypi.org";
const PYPI_ARTIFACTS: &str = "https://files.pythonhosted.org";
/// RubyGems serves its indexes, quick gemspecs and gems from one host.
const RUBYGEMS: &str = "https://rubygems.org";
/// Cargo's sparse index and its crate files (the `dl` of its `config.json`) are two hosts.
const CARGO_INDEX: &str = "https://index.crates.io";
const CARGO_ARTIFACTS: &str = "https://static.crates.io";
/// The Go module proxy and the checksum database it forwards (`/sumdb/...`) are two hosts.
const GO_PROXY: &str = "https://proxy.golang.org";
const GO_SUMDB: &str = "https://sum.golang.org";
/// proxy.golang.org answers a large module's `.zip` with a `302` to its signed storage bucket (measured
/// 2026-11-19: k8s.io/kubernetes v1.30.0, 18.6 MB; small zips are a direct `200`). That bucket is the
/// proxy's archive origin: admitted as the target of an archive redirect from the proxy and nowhere else.
const GO_ARCHIVES: &str = "https://storage.googleapis.com/proxy-golang-org-prod";
/// NuGet's service index, flat container, registration, vulnerability and signature documents are one host
/// (api.nuget.org); its search service and its publish endpoint are two more (measured 2026-11-19).
const NUGET_INDEX: &str = "https://api.nuget.org";
const NUGET_SEARCH: &str = "https://azuresearch-usnc.nuget.org";
const NUGET_PUBLISH: &str = "https://www.nuget.org";
/// Maven Central, as the repository layout is rooted (the directory `maven2`; repo1.maven.org serves the same tree).
const MAVEN_REPO: &str = "https://repo.maven.apache.org/maven2";
/// Where a deploy to the public registry goes when the operator names one (there is no default: Central has none).
const MAVEN_PUBLISH: &str = "https://maven-publish.invalid";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OriginKind {
    NpmMetadata,
    PypiMetadata,
    PypiArtifacts,
    RubygemsMetadata,
    CargoIndex,
    CargoArtifacts,
    GoProxy,
    GoSumdb,
    GoArchives,
    NugetIndex,
    NugetSearch,
    NugetPublish,
    MavenRepo,
    MavenPublish,
}

impl OriginKind {
    pub const ALL: [OriginKind; 14] = [
        OriginKind::NpmMetadata,
        OriginKind::PypiMetadata,
        OriginKind::PypiArtifacts,
        OriginKind::RubygemsMetadata,
        OriginKind::CargoIndex,
        OriginKind::CargoArtifacts,
        OriginKind::GoProxy,
        OriginKind::GoSumdb,
        OriginKind::GoArchives,
        OriginKind::NugetIndex,
        OriginKind::NugetSearch,
        OriginKind::NugetPublish,
        OriginKind::MavenRepo,
        OriginKind::MavenPublish,
    ];
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UrlRejection {
    Scheme,
    Host,
    Port,
    Credentials,
    /// The host is one of ours, but not the one this request is for.
    ForeignOrigin,
    PathEscape,
}

impl fmt::Display for UrlRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reason = match self {
            UrlRejection::Scheme => "the scheme is not https",
            UrlRejection::Host => "the host is not a configured upstream origin",
            UrlRejection::Port => "the port is not the configured origin's port",
            UrlRejection::Credentials => "the URL carries credentials",
            UrlRejection::ForeignOrigin => "the host belongs to a different upstream origin",
            UrlRejection::PathEscape => "the path leaves the configured origin's path",
        };
        f.write_str(reason)
    }
}

#[derive(Clone, Debug)]
pub struct OriginSet {
    npm_metadata: Url,
    pypi_metadata: Url,
    pypi_artifacts: Url,
    rubygems: Url,
    cargo_index: Url,
    cargo_artifacts: Url,
    go_proxy: Url,
    go_sumdb: Url,
    go_archives: Url,
    nuget_index: Url,
    nuget_search: Url,
    nuget_publish: Url,
    maven_repo: Url,
    maven_publish: Url,
    /// A selected Go registry that declared an archive origin: redirects from its own origin may land there.
    go_selected: bool,
    allow_private_addresses: bool,
    private_cidrs: Vec<IpNet>,
    /// LS-F9: absolute denylist of a snapshot-sourced registry; its own private CIDRs
    /// cannot unlock a denied address.
    deny: Option<std::sync::Arc<crate::http::service_connector::Denylist>>,
}

impl OriginSet {
    /// A catalog npm target supplies the request's origin, never a process-wide
    /// fallback. The same URL builder and redirect admission protect its path prefix.
    pub fn selected_npm(target: Url) -> Result<OriginSet, UrlRejection> {
        Self::selected_npm_with_private(target, Vec::new())
    }

    pub fn selected_npm_with_private(target: Url, private_cidrs: Vec<IpNet>) -> Result<OriginSet, UrlRejection> {
        if target.scheme() != "https" {
            return Err(UrlRejection::Scheme);
        }
        if target.host_str().is_none() {
            return Err(UrlRejection::Host);
        }
        if !target.username().is_empty() || target.password().is_some() {
            return Err(UrlRejection::Credentials);
        }
        if target.query().is_some() || target.fragment().is_some() {
            return Err(UrlRejection::PathEscape);
        }
        let mut origins = Self::production();
        // A private registry has no second origin: its zips come from its own (a redirect elsewhere is refused).
        origins.go_archives = target.clone();
        origins.npm_metadata = target;
        origins.private_cidrs = private_cidrs;
        origins.admit(origins.origin(OriginKind::NpmMetadata), OriginKind::NpmMetadata)?;
        if let Some(url::Host::Ipv4(ip)) = origins.npm_metadata.host()
            && !origins.allows_address(IpAddr::V4(ip)) { return Err(UrlRejection::Host); }
        if let Some(url::Host::Ipv6(ip)) = origins.npm_metadata.host()
            && !origins.allows_address(IpAddr::V6(ip)) { return Err(UrlRejection::Host); }
        Ok(origins)
    }

    /// The only constructor `main.rs` calls: HTTPS, default ports, private
    /// addresses rejected.
    pub fn production() -> OriginSet {
        OriginSet {
            npm_metadata: parse_origin(NPM_METADATA),
            pypi_metadata: parse_origin(PYPI_METADATA),
            pypi_artifacts: parse_origin(PYPI_ARTIFACTS),
            rubygems: parse_origin(RUBYGEMS),
            cargo_index: parse_origin(CARGO_INDEX),
            cargo_artifacts: parse_origin(CARGO_ARTIFACTS),
            go_proxy: parse_origin(GO_PROXY),
            go_sumdb: parse_origin(GO_SUMDB),
            go_archives: parse_origin(GO_ARCHIVES),
            nuget_index: parse_origin(NUGET_INDEX),
            nuget_search: parse_origin(NUGET_SEARCH),
            nuget_publish: parse_origin(NUGET_PUBLISH),
            maven_repo: parse_origin(MAVEN_REPO),
            maven_publish: parse_origin(MAVEN_PUBLISH),
            go_selected: false,
            allow_private_addresses: false,
            private_cidrs: Vec::new(),
            deny: None,
        }
    }

    /// The production rules with each origin `config` names in place of the default
    /// one (C35). `config` validated each as an `https` origin with no credentials,
    /// query, fragment or path, and no private address literal; a DNS answer in a
    /// private range is still refused at connect time.
    pub fn configured(config: &crate::config::Config) -> OriginSet {
        let production = OriginSet::production();
        let pick = |configured: &Option<Url>, default: Url| configured.clone().unwrap_or(default);
        OriginSet {
            npm_metadata: pick(&config.npm_upstream_url, production.npm_metadata),
            pypi_metadata: pick(&config.pypi_upstream_url, production.pypi_metadata),
            pypi_artifacts: pick(&config.pypi_artifacts_url, production.pypi_artifacts),
            rubygems: pick(&config.rubygems_upstream_url, production.rubygems),
            cargo_index: pick(&config.cargo_upstream_url, production.cargo_index),
            cargo_artifacts: pick(&config.cargo_artifacts_url, production.cargo_artifacts),
            go_proxy: pick(&config.go_upstream_url, production.go_proxy),
            go_sumdb: pick(&config.go_sumdb_url, production.go_sumdb),
            go_archives: pick(&config.go_artifacts_url, production.go_archives),
            nuget_index: pick(&config.nuget_upstream_url, production.nuget_index),
            nuget_search: pick(&config.nuget_search_url, production.nuget_search),
            nuget_publish: pick(&config.nuget_publish_url, production.nuget_publish),
            maven_repo: pick(&config.maven_upstream_url, production.maven_repo),
            maven_publish: pick(&config.maven_publish_url, production.maven_publish),
            go_selected: false,
            allow_private_addresses: false,
            private_cidrs: Vec::new(),
            deny: None,
        }
    }

    /// Tests only, and the single place `allow_private_addresses` is ever set. Not
    /// reachable from configuration, the command line, or the environment — TEST-01's
    /// no-bypass rule. A test origin is usually a loopback `http` socket, which is
    /// exactly what the production set exists to refuse, so relaxing both gates is
    /// the whole point of this constructor and the reason it has no other caller.
    pub fn for_tests(npm: Url, pypi: Url, artifacts: Url) -> OriginSet {
        OriginSet {
            npm_metadata: npm,
            pypi_metadata: pypi,
            pypi_artifacts: artifacts,
            rubygems: parse_origin(RUBYGEMS),
            cargo_index: parse_origin(CARGO_INDEX),
            cargo_artifacts: parse_origin(CARGO_ARTIFACTS),
            go_proxy: parse_origin(GO_PROXY),
            go_sumdb: parse_origin(GO_SUMDB),
            go_archives: parse_origin(GO_ARCHIVES),
            nuget_index: parse_origin(NUGET_INDEX),
            nuget_search: parse_origin(NUGET_SEARCH),
            nuget_publish: parse_origin(NUGET_PUBLISH),
            maven_repo: parse_origin(MAVEN_REPO),
            maven_publish: parse_origin(MAVEN_PUBLISH),
            go_selected: false,
            allow_private_addresses: true,
            private_cidrs: Vec::new(),
            deny: None,
        }
    }

    /// Tests only: where this set sends RubyGems calls (the upstream fake).
    pub fn with_rubygems(mut self, rubygems: Url) -> OriginSet {
        self.rubygems = rubygems;
        self
    }

    /// Tests only: where this set sends Go module proxy and checksum database calls (the upstream fake).
    pub fn with_go(mut self, proxy: Url, sumdb: Url) -> OriginSet {
        self.go_proxy = proxy;
        self.go_sumdb = sumdb;
        self
    }

    /// Tests only: where this set sends NuGet service index, search and publish calls (the upstream fake).
    pub fn with_nuget(mut self, index: Url, search: Url, publish: Url) -> OriginSet {
        self.nuget_index = index;
        self.nuget_search = search;
        self.nuget_publish = publish;
        self
    }

    /// Tests only: where this set sends Maven repository and deploy calls (the upstream fake).
    pub fn with_maven(mut self, repo: Url, publish: Url) -> OriginSet {
        self.maven_repo = repo;
        self.maven_publish = publish;
        self
    }

    /// Tests only: the origin a Go proxy's archive redirects may land on.
    pub fn with_go_archives(mut self, archives: Url) -> OriginSet {
        self.go_archives = archives;
        self
    }

    /// Whether a redirect from a hop on `from` to `to` is one of the fixed second origins: a Go proxy's
    /// archive redirect to its archive origin (path prefix included). Nothing else crosses origins.
    pub fn admits_archive_redirect(&self, from: OriginKind, to: &Url) -> bool {
        (from == OriginKind::GoProxy || (self.go_selected && from == OriginKind::NpmMetadata)) && self.admit(to, OriginKind::GoArchives).is_ok()
    }

    /// A selected Go, NuGet or Maven registry's declared archive origin (a snapshot descriptor field, already checked at
    /// activation): a redirect of its zip or nupkg may land there, and nowhere else.
    pub fn with_selected_archive(mut self, archive: Url) -> OriginSet {
        self.go_archives = archive;
        self.go_selected = true;
        self
    }

    /// Tests only: where this set sends Cargo index and crate-file calls (the upstream fake).
    pub fn with_cargo(mut self, index: Url, artifacts: Url) -> OriginSet {
        self.cargo_index = index;
        self.cargo_artifacts = artifacts;
        self
    }

    /// The same origins with both gates closed again: `https` only, and a DNS answer
    /// in a private range refused, exactly as [`OriginSet::production`] has them.
    /// One-way — nothing can open a gate this closes — so a test can point the
    /// production rules at a name it controls, such as `localhost`.
    pub fn refusing_private_addresses(mut self) -> OriginSet {
        self.allow_private_addresses = false;
        self
    }

    /// Addresses this set may never dial, whatever its private CIDRs say (LS-F9).
    pub fn with_denylist(mut self, deny: std::sync::Arc<crate::http::service_connector::Denylist>) -> OriginSet {
        self.deny = Some(deny);
        self
    }

    pub fn denylist(&self) -> Option<std::sync::Arc<crate::http::service_connector::Denylist>> {
        self.deny.clone()
    }

    pub fn origin(&self, kind: OriginKind) -> &Url {
        match kind {
            OriginKind::NpmMetadata => &self.npm_metadata,
            OriginKind::PypiMetadata => &self.pypi_metadata,
            OriginKind::PypiArtifacts => &self.pypi_artifacts,
            OriginKind::RubygemsMetadata => &self.rubygems,
            OriginKind::CargoIndex => &self.cargo_index,
            OriginKind::CargoArtifacts => &self.cargo_artifacts,
            OriginKind::GoProxy => &self.go_proxy,
            OriginKind::GoSumdb => &self.go_sumdb,
            OriginKind::GoArchives => &self.go_archives,
            OriginKind::NugetIndex => &self.nuget_index,
            OriginKind::NugetSearch => &self.nuget_search,
            OriginKind::NugetPublish => &self.nuget_publish,
            OriginKind::MavenRepo => &self.maven_repo,
            OriginKind::MavenPublish => &self.maven_publish,
        }
    }

    /// Whether a deploy URL for the public registry is configured (there is no default: Maven Central has no deploy endpoint).
    pub fn maven_publish_configured(&self) -> bool {
        self.maven_publish.host_str() != Some("maven-publish.invalid")
    }

    /// Read by the resolver and by the admission check. There is no setter.
    pub fn allows_private_addresses(&self) -> bool {
        self.allow_private_addresses
    }

    pub fn private_cidrs(&self) -> &[IpNet] { &self.private_cidrs }

    /// The connected peer of a request: the address rules plus the own-listener check,
    /// which needs the peer's port.
    pub fn allows_endpoint(&self, peer: std::net::SocketAddr) -> bool {
        !self.deny.as_ref().is_some_and(|deny| deny.denies_endpoint(peer.ip(), peer.port())) && self.allows_address(peer.ip())
    }

    pub fn allows_address(&self, ip: IpAddr) -> bool {
        if self.deny.as_ref().is_some_and(|deny| deny.denies(ip)) {
            return false;
        }
        self.allow_private_addresses || super::resolver::is_public(ip)
            || self.private_cidrs.iter().any(|cidr| cidr.contains(&ip))
    }

    /// Which configured origin `url` belongs to, if any. A URL matching none of the
    /// three never reaches the network.
    pub fn kind_of(&self, url: &Url) -> Option<OriginKind> {
        OriginKind::ALL
            .into_iter()
            .find(|kind| same_origin(url, self.origin(*kind)))
    }

    /// The only way an upstream URL is built in this crate.
    ///
    /// Each segment is appended with `PathSegmentsMut::push`, so a segment
    /// containing `/`, `//`, `:` or a whole `https://…` URL becomes one
    /// percent-encoded path segment of the origin rather than a new authority. The
    /// finished URL is then handed to [`OriginSet::admit`], which is the second,
    /// independent defence.
    pub fn url_for(&self, kind: OriginKind, segments: &[&str]) -> Result<Url, UrlRejection> {
        // `PathSegmentsMut::push` silently *drops* a segment that is exactly `.` or
        // `..` — `url-2.5.8/src/path_segments.rs` matches them and `continue`s. It is
        // not a pop and not text: the segment vanishes. Dropping it would leave the
        // bare origin, which `admit` then passes because nothing was appended, and a
        // request for the wrong resource would leave the process. So the name is
        // refused here, which is the only layer that can still tell it apart.
        if segments
            .iter()
            .any(|segment| matches!(*segment, "." | ".."))
        {
            return Err(UrlRejection::PathEscape);
        }

        let mut url = self.origin(kind).clone();
        {
            // `cannot_be_a_base` is false for every origin this type holds, because
            // both constructors take a parsed https/http URL with a host.
            let mut path = url
                .path_segments_mut()
                .map_err(|()| UrlRejection::PathEscape)?;
            path.pop_if_empty();
            for segment in segments {
                path.push(segment);
            }
        }
        self.admit(&url, kind)?;
        Ok(url)
    }

    /// A URL below `base`, a resource URL a registry's own document named (NuGet's flat container, registration
    /// and search bases): `base` must itself be admitted for `kind` (the same origin the kind names, no
    /// credentials, no query or fragment), each segment is appended with `PathSegmentsMut::push` (`.` and `..` are
    /// refused, as in [`OriginSet::url_for`]), and the finished URL is admitted again.
    pub fn url_below(&self, kind: OriginKind, base: &Url, segments: &[&str]) -> Result<Url, UrlRejection> {
        if segments.iter().any(|segment| matches!(*segment, "." | "..")) || base.query().is_some() || base.fragment().is_some() {
            return Err(UrlRejection::PathEscape);
        }
        self.admit(base, kind)?;
        let mut url = base.clone();
        {
            let mut path = url.path_segments_mut().map_err(|()| UrlRejection::PathEscape)?;
            path.pop_if_empty();
            for segment in segments {
                path.push(segment);
            }
        }
        self.admit(&url, kind)?;
        Ok(url)
    }

    /// Runs before any request and again on every redirect hop.
    ///
    /// The path check is what stops a `..` segment — which `PathSegmentsMut::push`
    /// treats as a pop rather than as text — from walking out of an origin that has
    /// a path prefix.
    pub fn admit(&self, url: &Url, kind: OriginKind) -> Result<(), UrlRejection> {
        if !self.permits_scheme(url.scheme()) {
            return Err(UrlRejection::Scheme);
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(UrlRejection::Credentials);
        }

        let origin = self.origin(kind);
        // Exactly one of the other two configured origins. A hop from npm to PyPI is
        // as cross-origin as a hop to anywhere else, and naming it apart from an
        // unrelated host is what makes the log line worth reading.
        if !same_origin(url, origin) && self.kind_of(url).is_some() {
            return Err(UrlRejection::ForeignOrigin);
        }
        if url.host_str() != origin.host_str() {
            return Err(UrlRejection::Host);
        }
        if url.port_or_known_default() != origin.port_or_known_default() {
            return Err(UrlRejection::Port);
        }
        // `permits_scheme` allows `http` for a test origin set; this pins the URL to
        // the scheme its own origin was configured with, so the relaxation is per
        // origin rather than per process.
        if url.scheme() != origin.scheme() {
            return Err(UrlRejection::Scheme);
        }
        if !path_is_under(url.path(), origin.path()) {
            return Err(UrlRejection::PathEscape);
        }
        Ok(())
    }

    /// Admits `url` against whichever configured origin it belongs to.
    ///
    /// This is what runs before a request, where the caller has a URL rather than a
    /// kind. A URL belonging to no origin is refused — but it is refused by running
    /// the check against the origin that comes closest, so the reason names what is
    /// actually wrong (an unexpected port, say) instead of always saying "host".
    pub fn admit_any(&self, url: &Url) -> Result<OriginKind, UrlRejection> {
        if let Some(kind) = self.kind_of(url) {
            self.admit(url, kind)?;
            return Ok(kind);
        }
        let closest = OriginKind::ALL
            .into_iter()
            .find(|kind| self.origin(*kind).host_str() == url.host_str())
            .unwrap_or(OriginKind::NpmMetadata);
        // `admit` cannot succeed here: `kind_of` and `admit` agree on scheme, host
        // and port, so a URL that passes one passes the other.
        Err(self.admit(url, closest).err().unwrap_or(UrlRejection::Host))
    }

    /// `https` always; `http` only for a test origin, which is the only way
    /// `allow_private_addresses` is ever true.
    fn permits_scheme(&self, scheme: &str) -> bool {
        scheme == "https" || (self.allow_private_addresses && scheme == "http")
    }
}

fn parse_origin(text: &str) -> Url {
    // A compile-time constant of this file. A panic here is a build mistake, not a
    // runtime condition, and there is no configuration path that can reach it.
    Url::parse(text).expect("a fixed upstream origin parses")
}

fn same_origin(url: &Url, origin: &Url) -> bool {
    url.scheme() == origin.scheme()
        && url.host_str() == origin.host_str()
        && url.port_or_known_default() == origin.port_or_known_default()
}

/// `path` stays under `prefix`, comparing whole segments so `/prefixed` is not read
/// as being under `/prefix`.
///
/// Both come out of `Url`, which resolves dot segments when it parses, and `url_for`
/// refuses a `.`/`..` name outright rather than letting `push` drop it. So a `..`
/// surviving into this function means the URL arrived from somewhere else — a
/// redirect `Location`, say — and is malformed rather than a walk. It is refused
/// anyway, because this is the layer that does not get to assume where a URL came
/// from.
fn path_is_under(path: &str, prefix: &str) -> bool {
    if path.split('/').any(|segment| segment == "..") {
        return false;
    }
    let prefix = prefix.trim_end_matches('/');
    if prefix.is_empty() {
        return true;
    }
    path == prefix || path.starts_with(&format!("{prefix}/"))
}
