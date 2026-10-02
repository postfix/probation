//! The three fixed upstream origins, the URL builder, and the admission check.
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
//! says so.

use std::fmt;

use url::Url;

/// SPEC §11's fixed origins. Registry and artifact hosts are separate because PyPI
/// serves its files from a different host than its index.
const NPM_METADATA: &str = "https://registry.npmjs.org";
const PYPI_METADATA: &str = "https://pypi.org";
const PYPI_ARTIFACTS: &str = "https://files.pythonhosted.org";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OriginKind {
    NpmMetadata,
    PypiMetadata,
    PypiArtifacts,
}

impl OriginKind {
    pub const ALL: [OriginKind; 3] = [
        OriginKind::NpmMetadata,
        OriginKind::PypiMetadata,
        OriginKind::PypiArtifacts,
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
    allow_private_addresses: bool,
}

impl OriginSet {
    /// The only constructor `main.rs` calls: HTTPS, default ports, private
    /// addresses rejected.
    pub fn production() -> OriginSet {
        OriginSet {
            npm_metadata: parse_origin(NPM_METADATA),
            pypi_metadata: parse_origin(PYPI_METADATA),
            pypi_artifacts: parse_origin(PYPI_ARTIFACTS),
            allow_private_addresses: false,
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
            allow_private_addresses: true,
        }
    }

    pub fn origin(&self, kind: OriginKind) -> &Url {
        match kind {
            OriginKind::NpmMetadata => &self.npm_metadata,
            OriginKind::PypiMetadata => &self.pypi_metadata,
            OriginKind::PypiArtifacts => &self.pypi_artifacts,
        }
    }

    /// Read by the resolver and by the admission check. There is no setter.
    pub fn allows_private_addresses(&self) -> bool {
        self.allow_private_addresses
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
