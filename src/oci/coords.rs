//! The layout of the OCI distribution API (`/v2/...`): one path has exactly one spelling and one meaning. Parsed once, strictly,
//! before any admission or upstream call; a path that is not one of these is a 404 and nothing is asked of any registry.

use probation_policy::names::valid_oci_name;

/// A content digest as the firewall can verify it: `sha256:` (64 lower-case hex) or `sha512:` (128).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Digest {
    pub algorithm: Algorithm,
    pub hex: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Algorithm {
    Sha256,
    Sha512,
}

impl Digest {
    pub fn parse(text: &str) -> Option<Digest> {
        let (algorithm, hex) = text.split_once(':')?;
        let (algorithm, length) = match algorithm {
            "sha256" => (Algorithm::Sha256, 64),
            "sha512" => (Algorithm::Sha512, 128),
            _ => return None,
        };
        (hex.len() == length && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))).then(|| Digest { algorithm, hex: hex.to_owned() })
    }

    /// The digest of `bytes` in this digest's algorithm.
    pub fn of(algorithm: Algorithm, bytes: &[u8]) -> Digest {
        use sha2::Digest as _;
        let hex = match algorithm {
            Algorithm::Sha256 => hex::encode(sha2::Sha256::digest(bytes)),
            Algorithm::Sha512 => hex::encode(sha2::Sha512::digest(bytes)),
        };
        Digest { algorithm, hex }
    }

    pub fn raw(&self) -> Vec<u8> {
        hex::decode(&self.hex).unwrap_or_default()
    }
}

impl std::fmt::Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", if self.algorithm == Algorithm::Sha256 { "sha256" } else { "sha512" }, self.hex)
    }
}

/// What a manifest request names: a tag or a digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reference {
    Tag(String),
    Digest(Digest),
}

impl Reference {
    pub fn parse(text: &str) -> Option<Reference> {
        if text.contains(':') {
            return Digest::parse(text).map(Reference::Digest);
        }
        valid_tag(text).then(|| Reference::Tag(text.to_owned()))
    }

    pub fn text(&self) -> String {
        match self {
            Reference::Tag(tag) => tag.clone(),
            Reference::Digest(digest) => digest.to_string(),
        }
    }
}

/// `[A-Za-z0-9_][A-Za-z0-9._-]{0,127}`.
pub fn valid_tag(tag: &str) -> bool {
    let mut bytes = tag.bytes();
    tag.len() <= 128 && bytes.next().is_some_and(|b| b.is_ascii_alphanumeric() || b == b'_') && bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

/// An upload session id: what a registry puts in a `Location` (a UUID, or any token of these characters).
pub fn valid_session(id: &str) -> bool {
    !id.is_empty() && id.len() <= 256 && id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'=' | b'+'))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Parsed {
    /// `GET /v2/`.
    Ping,
    /// `GET /v2/token`: the firewall's own token endpoint.
    Token,
    /// `GET /v2/_catalog`.
    Catalog,
    Manifest { name: String, reference: Reference },
    Blob { name: String, digest: Digest },
    Tags { name: String },
    Referrers { name: String, digest: Digest },
    /// `POST /v2/{name}/blobs/uploads/`.
    UploadStart { name: String },
    /// `GET|PATCH|PUT|DELETE /v2/{name}/blobs/uploads/{session}`.
    Upload { name: String, session: String },
}

/// `path` is what follows `v2` (no leading slash; empty for the ping). `query` is the raw query string.
pub fn parse(path: &str) -> Option<Parsed> {
    if path.is_empty() {
        return Some(Parsed::Ping);
    }
    match path {
        "token" => return Some(Parsed::Token),
        "_catalog" => return Some(Parsed::Catalog),
        _ => {}
    }
    if path.len() > 1024 {
        return None;
    }
    let segments: Vec<&str> = path.split('/').collect();
    let name = |count: usize| {
        let name = segments[..count].join("/");
        valid_oci_name(&name).then_some(name)
    };
    let n = segments.len();
    // `blobs/uploads/` ends in an empty segment.
    if n >= 4 && segments[n - 3] == "blobs" && segments[n - 2] == "uploads" && segments[n - 1].is_empty() {
        return Some(Parsed::UploadStart { name: name(n - 3)? });
    }
    if n >= 4 && segments[n - 3] == "blobs" && segments[n - 2] == "uploads" && valid_session(segments[n - 1]) {
        return Some(Parsed::Upload { name: name(n - 3)?, session: segments[n - 1].to_owned() });
    }
    if n >= 3 && segments[n - 2] == "manifests" {
        return Some(Parsed::Manifest { name: name(n - 2)?, reference: Reference::parse(segments[n - 1])? });
    }
    // A blob by sha256 or sha512. The bytes are verified in the algorithm asked for, and judged under their sha256 (computed while they stream
    // in), so a block by digest cannot be sidestepped by another spelling.
    if n >= 3 && segments[n - 2] == "blobs" {
        return Some(Parsed::Blob { name: name(n - 2)?, digest: Digest::parse(segments[n - 1])? });
    }
    if n >= 3 && segments[n - 2] == "referrers" {
        return Some(Parsed::Referrers { name: name(n - 2)?, digest: Digest::parse(segments[n - 1])? });
    }
    if n >= 3 && segments[n - 2] == "tags" && segments[n - 1] == "list" {
        return Some(Parsed::Tags { name: name(n - 2)? });
    }
    None
}

/// The query keys a read takes, each at most once with a bounded value. `ns` names the registry a client was asked to pull from
/// (containerd and the Docker daemon send it to a mirror); the others are the list parameters of the distribution spec.
pub fn read_query(query: Option<&str>, keys: &[&str]) -> Option<Vec<(String, String)>> {
    let Some(query) = query else { return Some(Vec::new()) };
    if query.len() > 2048 {
        return None;
    }
    let mut out: Vec<(String, String)> = Vec::new();
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        if !keys.contains(&key.as_ref()) || value.len() > 512 || out.iter().any(|(seen, _)| *seen == key) || value.chars().any(char::is_control) {
            return None;
        }
        out.push((key.into_owned(), value.into_owned()));
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const D: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn a_path_has_one_meaning_and_everything_else_is_nothing() {
        assert_eq!(parse(""), Some(Parsed::Ping));
        assert_eq!(parse("library/alpine/manifests/latest"), Some(Parsed::Manifest { name: "library/alpine".into(), reference: Reference::Tag("latest".into()) }));
        assert!(matches!(parse(&format!("a/b/c/manifests/{D}")), Some(Parsed::Manifest { reference: Reference::Digest(_), .. })));
        assert!(matches!(parse(&format!("alpine/blobs/{D}")), Some(Parsed::Blob { .. })));
        assert!(matches!(parse(&format!("alpine/referrers/{D}")), Some(Parsed::Referrers { .. })));
        assert_eq!(parse("alpine/tags/list"), Some(Parsed::Tags { name: "alpine".into() }));
        assert_eq!(parse("alpine/blobs/uploads/"), Some(Parsed::UploadStart { name: "alpine".into() }));
        assert_eq!(parse("a/blobs/blobs/uploads/abc-1"), Some(Parsed::Upload { name: "a/blobs".into(), session: "abc-1".into() }));
        for bad in [
            "Alpine/manifests/latest",
            "alpine/manifests/",
            "alpine/manifests/-bad",
            "alpine/manifests/a:b",
            "alpine/blobs/md5:aaaa",
            "alpine/blobs/sha256:AAAA",
            "alpine//manifests/latest",
            "alpine/../manifests/latest",
            "alpine/./blobs/uploads/x",
            "alpine/blobs/uploads/x/y",
            "alpine/manifests/latest/extra",
            "alpine",
            "alpine/tags",
            "%2e/manifests/x",
            "a b/manifests/x",
        ] {
            assert!(parse(bad).is_none(), "{bad}");
        }
        assert!(parse(&format!("{}/manifests/latest", "a/".repeat(600))).is_none(), "name over 255 bytes");
    }

    #[test]
    fn a_digest_is_verified_in_its_own_algorithm() {
        assert_eq!(Digest::of(Algorithm::Sha256, b"").to_string(), "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(Digest::parse(&Digest::of(Algorithm::Sha512, b"x").to_string()).unwrap().algorithm, Algorithm::Sha512);
        assert!(Digest::parse("sha256:abc").is_none());
    }

    #[test]
    fn query_keys_are_a_known_list_once() {
        assert!(read_query(Some("ns=docker.io&n=5"), &["ns", "n"]).is_some());
        assert!(read_query(Some("ns=a&ns=b"), &["ns"]).is_none());
        assert!(read_query(Some("token=x"), &["ns"]).is_none());
        assert!(read_query(None, &[]).unwrap().is_empty());
    }
}
