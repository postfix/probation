//! The NuGet v3 documents, decoded strictly and rendered back with every URL pointing at this
//! firewall. Nothing here does I/O. An upstream document is parsed into `serde_json::Value`
//! (depth-limited by serde_json, size-limited by the transport cap before it gets here), only the
//! fields a decision needs are read, every other field is carried through unchanged, and every URL
//! a client could follow is either rewritten to a route of this firewall or left as the plain
//! identifier it is (catalog entries, licence and project pages).

use std::cmp::Ordering;

use probation_policy::names::nuget_version;
use serde_json::{Map, Value};
use url::Url;

/// The one place the service index types are named.
const REGISTRATION_TYPES: &[&str] = &[
    "RegistrationsBaseUrl/Versioned",
    "RegistrationsBaseUrl/3.6.0",
    "RegistrationsBaseUrl/3.4.0",
    "RegistrationsBaseUrl",
    "RegistrationsBaseUrl/3.0.0-rc",
    "RegistrationsBaseUrl/3.0.0-beta",
];
const SEARCH_TYPES: &[&str] = &[
    "SearchQueryService/3.5.0",
    "SearchQueryService",
    "SearchQueryService/3.0.0-rc",
    "SearchQueryService/3.0.0-beta",
];
const AUTOCOMPLETE_TYPES: &[&str] = &[
    "SearchAutocompleteService/3.5.0",
    "SearchAutocompleteService",
    "SearchAutocompleteService/3.0.0-rc",
    "SearchAutocompleteService/3.0.0-beta",
];
/// What this firewall advertises under each name it serves (a client picks by type).
const REGISTRATION_ADVERTISED: &[&str] = &[
    "RegistrationsBaseUrl",
    "RegistrationsBaseUrl/3.0.0-beta",
    "RegistrationsBaseUrl/3.0.0-rc",
    "RegistrationsBaseUrl/3.4.0",
    "RegistrationsBaseUrl/3.6.0",
    "RegistrationsBaseUrl/Versioned",
];
const SEARCH_ADVERTISED: &[&str] = &[
    "SearchQueryService",
    "SearchQueryService/3.0.0-beta",
    "SearchQueryService/3.0.0-rc",
    "SearchQueryService/3.5.0",
];
const AUTOCOMPLETE_ADVERTISED: &[&str] = &[
    "SearchAutocompleteService",
    "SearchAutocompleteService/3.0.0-beta",
    "SearchAutocompleteService/3.0.0-rc",
    "SearchAutocompleteService/3.5.0",
];

/// Entries of a vulnerability index (it names `base` and `update`).
const MAX_VULNERABILITY_FILES: usize = 16;
/// Certificates of a repository signature index.
const MAX_CERTIFICATES: usize = 64;

/// What a resource of the service index is used for. The caller admits each URL against the origin
/// that kind belongs to, so a resource on an unconfigured origin is never used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceKind {
    Flat,
    Registration,
    Search,
    Autocomplete,
    Publish,
    SymbolPublish,
    Signatures,
    Vulnerabilities,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Resources {
    pub flat: Option<Url>,
    pub registration: Option<Url>,
    pub search: Option<Url>,
    pub autocomplete: Option<Url>,
    pub publish: Option<Url>,
    pub symbol_publish: Option<Url>,
    /// `(version, url)` of each `RepositorySignatures/{version}` the registry offers.
    pub signatures: Vec<(String, Url)>,
    pub vulnerabilities: Option<Url>,
    /// The registry has a `ReadmeUriTemplate`.
    pub readme: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DocError {
    /// Not JSON, or not the document shape the protocol names.
    Shape,
    /// The registry offers no flat container: the family cannot restore from it.
    NoFlatContainer,
    TooMany,
}

fn types_of(resource: &Value) -> Vec<&str> {
    match resource.get("@type") {
        Some(Value::String(text)) => vec![text.as_str()],
        Some(Value::Array(list)) => list.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    }
}

fn plain_url(text: &str) -> Option<Url> {
    let url = Url::parse(text).ok()?;
    (matches!(url.scheme(), "https" | "http")
        && url.has_host()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none())
    .then_some(url)
}

/// A version suffix of a `RepositorySignatures/{x.y.z}` type.
fn signature_version(kind: &str) -> Option<&str> {
    let version = kind.strip_prefix("RepositorySignatures/")?;
    let parts: Vec<&str> = version.split('.').collect();
    (parts.len() == 3
        && version.len() <= 16
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit())))
    .then_some(version)
}

/// The service index of a registry (`/v3/index.json`). `admit` says whether a resource of a kind may live at a URL:
/// the first resource of a family that is admitted is used, and a resource on an unconfigured origin is skipped,
/// never used. A document that is not a service index, or names no flat container, is an error.
pub fn parse_service_index(
    body: &[u8],
    max_resources: usize,
    admit: &dyn Fn(ResourceKind, &Url) -> bool,
) -> Result<Resources, DocError> {
    let value: Value = serde_json::from_slice(body).map_err(|_| DocError::Shape)?;
    let object = value.as_object().ok_or(DocError::Shape)?;
    if !object
        .get("version")
        .and_then(Value::as_str)
        .is_some_and(|version| version.starts_with("3."))
    {
        return Err(DocError::Shape);
    }
    let list = object
        .get("resources")
        .and_then(Value::as_array)
        .ok_or(DocError::Shape)?;
    if list.len() > max_resources {
        return Err(DocError::TooMany);
    }
    // (type, url) of every well-formed resource, in document order.
    let mut found: Vec<(&str, Url)> = Vec::new();
    for resource in list {
        let Some(url) = resource
            .get("@id")
            .and_then(Value::as_str)
            .and_then(plain_url)
        else {
            continue;
        };
        for kind in types_of(resource) {
            found.push((kind, url.clone()));
        }
    }
    let first = |kind: ResourceKind, types: &[&str]| -> Option<Url> {
        types.iter().find_map(|wanted| {
            found
                .iter()
                .find(|(have, url)| have == wanted && admit(kind, url))
                .map(|(_, url)| url.clone())
        })
    };
    let mut signatures: Vec<(String, Url)> = Vec::new();
    for (kind, url) in &found {
        if let Some(version) = signature_version(kind)
            && admit(ResourceKind::Signatures, url)
            && !signatures.iter().any(|(have, _)| have == version)
        {
            signatures.push((version.to_owned(), url.clone()));
        }
    }
    let resources = Resources {
        flat: first(ResourceKind::Flat, &["PackageBaseAddress/3.0.0"]),
        registration: first(ResourceKind::Registration, REGISTRATION_TYPES),
        search: first(ResourceKind::Search, SEARCH_TYPES),
        autocomplete: first(ResourceKind::Autocomplete, AUTOCOMPLETE_TYPES),
        publish: first(ResourceKind::Publish, &["PackagePublish/2.0.0"]),
        symbol_publish: first(ResourceKind::SymbolPublish, &["SymbolPackagePublish/4.9.0"]),
        signatures,
        vulnerabilities: first(ResourceKind::Vulnerabilities, &["VulnerabilityInfo/6.7.0"]),
        readme: found
            .iter()
            .any(|(kind, _)| *kind == "ReadmeUriTemplate/6.13.0"),
    };
    if resources.flat.is_none() {
        return Err(DocError::NoFlatContainer);
    }
    Ok(resources)
}

/// The service index this firewall serves for a registry whose resources are `resources`: every resource it can
/// protect, each at a route under `root` (`{public}/nuget/` or the selected registry's). `writes` adds the publish
/// endpoints (the shared service forwards them with the caller's own key); resources it does not serve (the legacy
/// gallery, staging, the catalog, the web-page URI templates) are not advertised.
pub fn render_service_index(resources: &Resources, root: &Url, writes: bool) -> Vec<u8> {
    let join = |tail: &str| {
        root.join(tail)
            .map(|url| url.to_string())
            .unwrap_or_default()
    };
    let mut list: Vec<Value> = Vec::new();
    let mut add =
        |kind: &str, url: String| list.push(serde_json::json!({ "@id": url, "@type": kind }));
    if resources.search.is_some() {
        for kind in SEARCH_ADVERTISED {
            add(kind, join("v3/query"));
        }
    }
    if resources.autocomplete.is_some() {
        for kind in AUTOCOMPLETE_ADVERTISED {
            add(kind, join("v3/autocomplete"));
        }
    }
    if resources.registration.is_some() {
        for kind in REGISTRATION_ADVERTISED {
            add(kind, join("v3/registration/"));
        }
    }
    add("PackageBaseAddress/3.0.0", join("v3-flatcontainer/"));
    if resources.readme {
        // A URI template: the braces are the client's own placeholders and must not be percent-encoded.
        add(
            "ReadmeUriTemplate/6.13.0",
            format!(
                "{}v3-flatcontainer/{{lower_id}}/{{lower_version}}/readme",
                root.as_str()
            ),
        );
    }
    if writes {
        if resources.publish.is_some() {
            add("PackagePublish/2.0.0", join("api/v2/package"));
        }
        if resources.symbol_publish.is_some() {
            add("SymbolPackagePublish/4.9.0", join("api/v2/symbolpackage"));
        }
    }
    // NuGet refuses a RepositorySignatures resource that is not served over https (NU1301, measured with dotnet
    // 8.0.416 against a plain http firewall), so over http it is not advertised and package signatures are
    // verified by the client alone.
    for (version, _) in resources
        .signatures
        .iter()
        .filter(|_| root.scheme() == "https")
    {
        add(
            &format!("RepositorySignatures/{version}"),
            join(&format!("v3/repository-signatures/{version}/index.json")),
        );
    }
    // Audit data is advertised over plain http too (a development setup with `allowInsecureConnections` keeps its
    // NuGetAudit); that it is unauthenticated for an on-path attacker there is the operator's choice of public URL.
    if resources.vulnerabilities.is_some() {
        add(
            "VulnerabilityInfo/6.7.0",
            join("v3/vulnerabilities/index.json"),
        );
    }
    serde_json::to_vec(&serde_json::json!({ "version": "3.0.0", "resources": list }))
        .unwrap_or_default()
}

// ------------------------------------------------------------------ flat container

/// The `versions` of a flat container `index.json`, each in the one spelling policy uses (normalised, lower
/// case, build metadata dropped); an entry that is no NuGet version is dropped, never delivered, and a repeat is
/// kept once. More than `max` versions is an error.
pub fn parse_flat(body: &[u8], max: usize) -> Result<Vec<String>, DocError> {
    let value: Value = serde_json::from_slice(body).map_err(|_| DocError::Shape)?;
    let versions = value
        .get("versions")
        .and_then(Value::as_array)
        .ok_or(DocError::Shape)?;
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for version in versions {
        let Some(normal) = version.as_str().and_then(nuget_version) else {
            continue;
        };
        if !seen.insert(normal.clone()) {
            continue;
        }
        if out.len() >= max {
            return Err(DocError::TooMany);
        }
        out.push(normal);
    }
    Ok(out)
}

pub fn render_flat<'a>(versions: impl Iterator<Item = &'a str>) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({ "versions": versions.collect::<Vec<_>>() }))
        .unwrap_or_default()
}

// ------------------------------------------------------------------ registration

/// What a registration leaf says about one version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegEntry {
    /// The policy spelling (normalised, lower case).
    pub version: String,
    /// The registry's own publication time, `None` when absent, unparseable or the unlisted sentinel.
    pub published: Option<i64>,
    pub listed: bool,
}

/// An `xsd:dateTime` as microseconds since the epoch. NuGet writes `1900-01-01T00:00:00+00:00` for an unlisted
/// package (the sentinel): that, anything before 1970 and anything that does not parse is "no date", so the
/// version waits on the committed first-seen time and is never dated by invention.
pub fn published_micros(text: &str) -> Option<i64> {
    let at: jiff::Timestamp = text.trim().parse().ok()?;
    (at.as_second() > 0).then(|| at.as_microsecond())
}

fn string_field<'a>(object: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    object.get(key).and_then(Value::as_str)
}

/// The facts of one leaf of a registration page (`catalogEntry` is an object there; a leaf document names
/// `listed` and `published` at its own top level).
pub fn entry_of(leaf: &Value) -> Option<RegEntry> {
    let object = leaf.as_object()?;
    let catalog = object.get("catalogEntry").and_then(Value::as_object);
    let version = catalog
        .and_then(|c| string_field(c, "version"))
        .or_else(|| string_field(object, "version"))
        .and_then(nuget_version)?;
    let published = catalog
        .and_then(|c| string_field(c, "published"))
        .or_else(|| string_field(object, "published"))
        .and_then(published_micros);
    let listed = catalog
        .and_then(|c| c.get("listed"))
        .or_else(|| object.get("listed"))
        .and_then(Value::as_bool)
        .unwrap_or(true);
    Some(RegEntry {
        version,
        published,
        listed,
    })
}

/// One page of a registration index as the index names it: the page's own bounds (policy spelling) and, when the
/// index only links it, the URL to fetch (`None`: its leaves are inline in the index).
pub struct PageDesc {
    pub bounds: Option<(String, String)>,
    pub link: Option<String>,
}

/// The pages of a registration index document, in order.
pub fn index_page_descs(index: &Value, max_pages: usize) -> Result<Vec<PageDesc>, DocError> {
    let pages = index
        .get("items")
        .and_then(Value::as_array)
        .ok_or(DocError::Shape)?;
    if pages.len() > max_pages {
        return Err(DocError::TooMany);
    }
    pages
        .iter()
        .map(|page| {
            let bound = |key: &str| {
                page.get(key)
                    .and_then(Value::as_str)
                    .and_then(nuget_version)
            };
            let bounds = bound("lower").zip(bound("upper"));
            match page.get("items").and_then(Value::as_array) {
                Some(_) => Ok(PageDesc { bounds, link: None }),
                None => page
                    .get("@id")
                    .and_then(Value::as_str)
                    .map(|id| PageDesc {
                        bounds,
                        link: Some(id.to_owned()),
                    })
                    .ok_or(DocError::Shape),
            }
        })
        .collect()
}

/// The inline leaves of page `n` of a registration index.
pub fn inline_leaves(index: &Value, n: usize) -> Result<&[Value], DocError> {
    index
        .get("items")
        .and_then(Value::as_array)
        .and_then(|pages| pages.get(n))
        .and_then(|page| page.get("items"))
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or(DocError::Shape)
}

/// The leaves of a fetched registration page document.
pub fn page_leaves(page: &Value) -> Result<Vec<Value>, DocError> {
    page.get("items")
        .and_then(Value::as_array)
        .cloned()
        .ok_or(DocError::Shape)
}

/// The URLs of this firewall a rendered document points at.
pub struct Links<'a> {
    /// `{root}v3/registration/`
    pub registration: &'a Url,
    /// `{root}v3-flatcontainer/`
    pub flat: &'a Url,
    /// The origin whose flat container icon links are replaced (the registry's own).
    pub upstream: &'a Url,
}

impl Links<'_> {
    fn under(&self, base: &Url, segments: &[&str]) -> String {
        let mut url = base.clone();
        if let Ok(mut path) = url.path_segments_mut() {
            path.pop_if_empty();
            for segment in segments {
                path.push(segment);
            }
        }
        url.to_string()
    }
    pub fn index(&self, id: &str) -> String {
        self.under(self.registration, &[id, "index.json"])
    }
    pub fn leaf(&self, id: &str, version: &str) -> String {
        self.under(self.registration, &[id, &format!("{version}.json")])
    }
    pub fn nupkg(&self, id: &str, version: &str) -> String {
        self.under(self.flat, &[id, version, &format!("{id}.{version}.nupkg")])
    }
    pub fn icon(&self, id: &str, version: &str) -> String {
        self.under(self.flat, &[id, version, "icon"])
    }
    pub fn readme(&self, id: &str, version: &str) -> String {
        self.under(self.flat, &[id, version, "readme"])
    }
    /// A page of the registration this firewall serves, named by the registry page's own bounds.
    pub fn page(&self, id: &str, lower: &str, upper: &str) -> String {
        self.under(
            self.registration,
            &[id, "page", lower, &format!("{upper}.json")],
        )
    }
    /// A URL on the registry's own origin (a catalog entry or one of its fragments) becomes a route of this firewall
    /// that is not served (`v3/catalog/...`, 404): an identifier that cannot lead a client around the firewall.
    fn scrub_url(&self, text: &str) -> String {
        let Ok(url) = Url::parse(text) else {
            return text.to_owned();
        };
        if url.scheme() != self.upstream.scheme()
            || url.host_str() != self.upstream.host_str()
            || url.port_or_known_default() != self.upstream.port_or_known_default()
        {
            return text.to_owned();
        }
        let base = self
            .registration
            .join("../catalog/")
            .map(|u| u.to_string())
            .unwrap_or_default();
        let fragment = url.fragment().map(|f| format!("#{f}")).unwrap_or_default();
        format!("{base}{}{fragment}", url.path().trim_start_matches('/'))
    }

    fn scrub(&self, value: &mut Value) {
        match value {
            Value::String(text) => *text = self.scrub_url(text),
            Value::Array(list) => list.iter_mut().for_each(|item| self.scrub(item)),
            Value::Object(object) => object.values_mut().for_each(|item| self.scrub(item)),
            _ => {}
        }
    }

    /// `iconUrl` of a package on the registry's own origin becomes this firewall's icon route; any other URL is
    /// the packager's own and stays.
    fn readme_url(&self, current: &str, id: &str, version: &str) -> String {
        match Url::parse(current) {
            Ok(url)
                if url.scheme() == self.upstream.scheme()
                    && url.host_str() == self.upstream.host_str()
                    && url.port_or_known_default() == self.upstream.port_or_known_default() =>
            {
                self.readme(id, version)
            }
            _ => current.to_owned(),
        }
    }

    fn icon_url(&self, current: &str, id: &str, version: &str) -> String {
        match Url::parse(current) {
            Ok(url)
                if url.scheme() == self.upstream.scheme()
                    && url.host_str() == self.upstream.host_str()
                    && url.port_or_known_default() == self.upstream.port_or_known_default() =>
            {
                self.icon(id, version)
            }
            _ => current.to_owned(),
        }
    }
}

fn set_string(object: &mut Map<String, Value>, key: &str, value: String) {
    if object.contains_key(key) {
        object.insert(key.to_owned(), Value::String(value));
    }
}

/// A leaf of a registration page or document with its URLs rewritten.
fn rewrite_leaf(leaf: &mut Value, links: &Links<'_>, id: &str, version: &str) {
    let Some(object) = leaf.as_object_mut() else {
        return;
    };
    set_string(object, "@id", links.leaf(id, version));
    set_string(object, "packageContent", links.nupkg(id, version));
    set_string(object, "registration", links.index(id));
    // A dependency's `registration` link is this firewall's registration of that id, never the registry's own.
    if let Some(Value::Object(catalog)) = object.get_mut("catalogEntry") {
        for group in catalog
            .get_mut("dependencyGroups")
            .and_then(Value::as_array_mut)
            .into_iter()
            .flatten()
        {
            for dependency in group
                .get_mut("dependencies")
                .and_then(Value::as_array_mut)
                .into_iter()
                .flatten()
            {
                let Some(dependency) = dependency.as_object_mut() else {
                    continue;
                };
                let id = dependency
                    .get("id")
                    .and_then(Value::as_str)
                    .filter(|id| {
                        probation_policy::names::valid_name(probation_policy::Ecosystem::NuGet, id)
                    })
                    .map(str::to_ascii_lowercase);
                match id {
                    Some(id) => set_string(dependency, "registration", links.index(&id)),
                    None => {
                        dependency.remove("registration");
                    }
                }
            }
        }
        for (key, value) in catalog.iter_mut() {
            if !matches!(key.as_str(), "packageContent" | "iconUrl" | "readmeUrl") {
                links.scrub(value);
            }
        }
    }
    if let Some(Value::String(entry)) = object.get_mut("catalogEntry") {
        *entry = links.scrub_url(entry);
    }
    if let Some(Value::Object(catalog)) = object.get_mut("catalogEntry") {
        set_string(catalog, "packageContent", links.nupkg(id, version));
        if let Some(icon) = catalog
            .get("iconUrl")
            .and_then(Value::as_str)
            .map(|current| links.icon_url(current, id, version))
        {
            catalog.insert("iconUrl".to_owned(), Value::String(icon));
        }
        // `readmeUrl` on the registry's own host is the flat container's readme, which this firewall serves (judged with
        // the version); any other host's is the packager's own and stays.
        if let Some(readme) = catalog
            .get("readmeUrl")
            .and_then(Value::as_str)
            .map(|current| links.readme_url(current, id, version))
        {
            catalog.insert("readmeUrl".to_owned(), Value::String(readme));
        }
    }
}

/// One page of a registration as the renderer is given it.
pub struct PageView<'a> {
    /// The leaves, when the registry's index carried them inline.
    pub inline: Option<&'a [Value]>,
    /// The registry page's own bounds (the key of the firewall's page route for a linked page).
    pub bounds: Option<(&'a str, &'a str)>,
    /// The versions of the page's leaves in order.
    pub versions: &'a [String],
}

/// The leaves `keep` accepts, rewritten, with their versions.
fn kept_leaves(
    leaves: &[Value],
    links: &Links<'_>,
    id: &str,
    keep: &dyn Fn(&str) -> bool,
) -> Vec<(String, Value)> {
    let mut kept = Vec::new();
    for leaf in leaves {
        let Some(entry) = entry_of(leaf) else {
            continue;
        };
        if !keep(&entry.version) {
            continue;
        }
        let mut leaf = leaf.clone();
        rewrite_leaf(&mut leaf, links, id, &entry.version);
        kept.push((entry.version, leaf));
    }
    kept
}

fn page_object(
    at: String,
    parent: String,
    first: String,
    last: String,
    count: usize,
    items: Option<Vec<Value>>,
) -> Value {
    let mut page = Map::new();
    page.insert("@id".to_owned(), Value::String(at));
    page.insert(
        "@type".to_owned(),
        Value::String("catalog:CatalogPage".to_owned()),
    );
    page.insert("count".to_owned(), Value::from(count));
    if let Some(items) = items {
        page.insert("items".to_owned(), Value::Array(items));
    }
    page.insert("lower".to_owned(), Value::String(first));
    page.insert("parent".to_owned(), Value::String(parent));
    page.insert("upper".to_owned(), Value::String(last));
    Value::Object(page)
}

/// The registration index this firewall serves: a page the registry inlined stays inline (only the leaves `keep`
/// accepts), a page it only linked is linked to this firewall's page route; `count`, `lower` and `upper` are
/// recomputed, a page with no leaf left is dropped, every URL is rewritten. No response holds every leaf of a project.
pub fn render_registration(
    index: &Value,
    pages: &[PageView<'_>],
    links: &Links<'_>,
    id: &str,
    keep: &dyn Fn(&str) -> bool,
) -> Value {
    let mut rendered_pages = Vec::new();
    for page in pages {
        let first_last =
            |first: Option<&String>, last: Option<&String>| first.cloned().zip(last.cloned());
        match (page.inline, page.bounds) {
            (Some(leaves), _) => {
                let kept = kept_leaves(leaves, links, id, keep);
                let Some((first, last)) =
                    first_last(kept.first().map(|(v, _)| v), kept.last().map(|(v, _)| v))
                else {
                    continue;
                };
                let count = kept.len();
                rendered_pages.push(page_object(
                    format!("{}#page/{first}/{last}", links.index(id)),
                    links.index(id),
                    first,
                    last,
                    count,
                    Some(kept.into_iter().map(|(_, leaf)| leaf).collect()),
                ));
            }
            (None, Some((lower, upper))) => {
                let kept: Vec<&String> = page
                    .versions
                    .iter()
                    .filter(|version| keep(version))
                    .collect();
                let Some((first, last)) = first_last(kept.first().copied(), kept.last().copied())
                else {
                    continue;
                };
                rendered_pages.push(page_object(
                    links.page(id, lower, upper),
                    links.index(id),
                    first,
                    last,
                    kept.len(),
                    None,
                ));
            }
            (None, None) => continue,
        }
    }
    let mut document = index.as_object().cloned().unwrap_or_default();
    document.insert("@id".to_owned(), Value::String(links.index(id)));
    document.insert("count".to_owned(), Value::from(rendered_pages.len()));
    document.insert("items".to_owned(), Value::Array(rendered_pages));
    Value::Object(document)
}

/// One linked page of the registration as this firewall serves it (`v3/registration/{id}/page/{lower}/{upper}.json`):
/// the leaves `keep` accepts, rewritten. `None` when no leaf is left.
pub fn render_page(
    leaves: &[Value],
    links: &Links<'_>,
    id: &str,
    bounds: (&str, &str),
    keep: &dyn Fn(&str) -> bool,
) -> Option<Value> {
    let kept = kept_leaves(leaves, links, id, keep);
    let (first, last) = (kept.first()?.0.clone(), kept.last()?.0.clone());
    let count = kept.len();
    Some(page_object(
        links.page(id, bounds.0, bounds.1),
        links.index(id),
        first,
        last,
        count,
        Some(kept.into_iter().map(|(_, leaf)| leaf).collect()),
    ))
}

/// A registration leaf document with its URLs rewritten.
pub fn render_leaf(mut leaf: Value, links: &Links<'_>, id: &str, version: &str) -> Value {
    rewrite_leaf(&mut leaf, links, id, version);
    leaf
}

// ------------------------------------------------------------------ search and autocomplete

/// A package id of a search result, valid as NuGet spells it.
fn result_id(item: &Value) -> Option<String> {
    let id = item.get("id")?.as_str()?;
    probation_policy::names::valid_name(probation_policy::Ecosystem::NuGet, id)
        .then(|| id.to_ascii_lowercase())
}

/// The ids a search document names (the lower-cased id of each valid result), at most `max`.
pub fn search_ids(doc: &Value, max: usize) -> Result<Vec<String>, DocError> {
    let data = doc
        .get("data")
        .and_then(Value::as_array)
        .ok_or(DocError::Shape)?;
    // A registry that ignores `take` is not a reason to refuse the search or to judge every result: the first `max`
    // are judged and the rest are never shown (a result nobody judged is not shown, `render_search`).
    Ok(data.iter().filter_map(result_id).take(max).collect())
}

/// NuGet's own ordering of two policy spellings (numeric parts, a release before the same numbers without one,
/// release labels piecewise: numbers by value before words, words case-insensitively).
pub fn compare(a: &str, b: &str) -> Ordering {
    let key = |version: &str| {
        let (numbers, release) = match version.split_once('-') {
            Some((numbers, release)) => (numbers, Some(release)),
            None => (version, None),
        };
        let mut parts = [0u64; 4];
        for (slot, part) in parts.iter_mut().zip(numbers.split('.')) {
            *slot = part.parse().unwrap_or(0);
        }
        (parts, release.map(str::to_owned))
    };
    let ((pa, ra), (pb, rb)) = (key(a), key(b));
    pa.cmp(&pb).then_with(|| match (ra, rb) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        (Some(ra), Some(rb)) => {
            let (la, lb): (Vec<&str>, Vec<&str>) =
                (ra.split('.').collect(), rb.split('.').collect());
            for (x, y) in la.iter().zip(&lb) {
                let ord = match (x.parse::<u64>(), y.parse::<u64>()) {
                    (Ok(x), Ok(y)) => x.cmp(&y),
                    (Ok(_), Err(_)) => Ordering::Less,
                    (Err(_), Ok(_)) => Ordering::Greater,
                    (Err(_), Err(_)) => x.to_ascii_lowercase().cmp(&y.to_ascii_lowercase()),
                };
                if ord != Ordering::Equal {
                    return ord;
                }
            }
            la.len().cmp(&lb.len())
        }
    })
}

/// The best of `versions` for a search result's headline `version`: the highest release, else the highest of all.
fn headline(versions: &[String]) -> Option<&String> {
    fn best<'a>(list: impl Iterator<Item = &'a String>) -> Option<&'a String> {
        list.max_by(|a, b| compare(a, b))
    }
    best(versions.iter().filter(|v| !v.contains('-'))).or_else(|| best(versions.iter()))
}

/// The search document this firewall serves: results of a package no version of which `allowed` returns are dropped,
/// the others keep only their allowed versions (the headline `version` becomes the best allowed one when it is not
/// allowed itself), and every URL of the registry's own origin is replaced by a route here. `allowed(id)` is the set
/// of versions a client may see, `None` when the package cannot be judged (it is then dropped).
pub fn render_search(
    mut doc: Value,
    links: &Links<'_>,
    allowed: &dyn Fn(&str) -> Option<Vec<String>>,
) -> Result<Value, DocError> {
    let data = doc
        .get_mut("data")
        .and_then(Value::as_array_mut)
        .ok_or(DocError::Shape)?;
    let mut out = Vec::with_capacity(data.len());
    for mut item in std::mem::take(data) {
        let Some(id) = result_id(&item) else { continue };
        let Some(allowed) = allowed(&id) else {
            continue;
        };
        let Some(object) = item.as_object_mut() else {
            continue;
        };
        let listed: Vec<Value> = object
            .get("versions")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let kept: Vec<Value> = listed
            .into_iter()
            .filter_map(|mut entry| {
                let version = entry
                    .get("version")
                    .and_then(Value::as_str)
                    .and_then(nuget_version)?;
                allowed.contains(&version).then(|| {
                    if let Some(object) = entry.as_object_mut() {
                        set_string(object, "@id", links.leaf(&id, &version));
                    }
                    entry
                })
            })
            .collect();
        let shown: Vec<String> = kept
            .iter()
            .filter_map(|e| {
                e.get("version")
                    .and_then(Value::as_str)
                    .and_then(nuget_version)
            })
            .collect();
        if shown.is_empty() {
            continue;
        }
        let current = object
            .get("version")
            .and_then(Value::as_str)
            .and_then(nuget_version);
        let version = match current {
            Some(current) if shown.contains(&current) => current,
            _ => headline(&shown).cloned().unwrap_or_default(),
        };
        object.insert("versions".to_owned(), Value::Array(kept));
        object.insert("version".to_owned(), Value::String(version.clone()));
        set_string(object, "@id", links.index(&id));
        set_string(object, "registration", links.index(&id));
        if let Some(icon) = object
            .get("iconUrl")
            .and_then(Value::as_str)
            .map(|current| links.icon_url(current, &id, &version))
        {
            object.insert("iconUrl".to_owned(), Value::String(icon));
        }
        out.push(item);
    }
    doc["data"] = Value::Array(out);
    // The document's JSON-LD base names the registry's registration base: it is this firewall's now.
    if let Some(Value::Object(context)) = doc.get_mut("@context") {
        set_string(context, "@base", links.registration.to_string());
    }
    Ok(doc)
}

/// Autocomplete of versions (`?id=`): only allowed versions. `data` is a list of version strings.
pub fn render_autocomplete_versions(mut doc: Value, allowed: &[String]) -> Result<Value, DocError> {
    let data = doc
        .get_mut("data")
        .and_then(Value::as_array_mut)
        .ok_or(DocError::Shape)?;
    data.retain(|version| {
        version
            .as_str()
            .and_then(nuget_version)
            .is_some_and(|v| allowed.contains(&v))
    });
    Ok(doc)
}

/// Autocomplete of ids (`?q=`): ids `blocked` names are removed. `data` is a list of ids.
pub fn render_autocomplete_ids(
    mut doc: Value,
    blocked: &dyn Fn(&str) -> bool,
) -> Result<Value, DocError> {
    let data = doc
        .get_mut("data")
        .and_then(Value::as_array_mut)
        .ok_or(DocError::Shape)?;
    data.retain(|id| {
        id.as_str().is_some_and(|id| {
            probation_policy::names::valid_name(probation_policy::Ecosystem::NuGet, id)
                && !blocked(&id.to_ascii_lowercase())
        })
    });
    Ok(doc)
}

// ------------------------------------------------------------------ vulnerability and signature documents

/// The `@name` and `@id` of each file of a `VulnerabilityInfo` index (`base`, `update`): `@id` must be a plain URL.
pub fn parse_vulnerability_index(body: &[u8]) -> Result<Vec<(String, Url)>, DocError> {
    let value: Value = serde_json::from_slice(body).map_err(|_| DocError::Shape)?;
    let list = value.as_array().ok_or(DocError::Shape)?;
    if list.len() > MAX_VULNERABILITY_FILES {
        return Err(DocError::TooMany);
    }
    Ok(list
        .iter()
        .filter_map(|file| {
            let name = file.get("@name")?.as_str()?;
            let url = plain_url(file.get("@id")?.as_str()?)?;
            (matches!(name, "base" | "update")).then(|| (name.to_owned(), url))
        })
        .collect())
}

/// The vulnerability index with each `@id` pointing at `{root}v3/vulnerabilities/{name}.json`.
pub fn render_vulnerability_index(body: &[u8], root: &Url) -> Result<Vec<u8>, DocError> {
    let mut value: Value = serde_json::from_slice(body).map_err(|_| DocError::Shape)?;
    let list = value.as_array_mut().ok_or(DocError::Shape)?;
    if list.len() > MAX_VULNERABILITY_FILES {
        return Err(DocError::TooMany);
    }
    list.retain(|file| {
        file.get("@name")
            .and_then(Value::as_str)
            .is_some_and(|name| matches!(name, "base" | "update"))
            && file
                .get("@id")
                .and_then(Value::as_str)
                .and_then(plain_url)
                .is_some()
    });
    for file in list.iter_mut() {
        let name = file
            .get("@name")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        if let (Some(object), Ok(url)) = (
            file.as_object_mut(),
            root.join(&format!("v3/vulnerabilities/{name}.json")),
        ) {
            object.insert("@id".to_owned(), Value::String(url.to_string()));
        }
    }
    serde_json::to_vec(&value).map_err(|_| DocError::Shape)
}

/// The SHA-256 fingerprint OID the repository signature index keys its fingerprints by.
const SHA256_OID: &str = "2.16.840.1.101.3.4.2.1";

fn certificate_fingerprint(certificate: &Value) -> Option<&str> {
    let fingerprint = certificate.get("fingerprints")?.get(SHA256_OID)?.as_str()?;
    (fingerprint.len() == 64
        && fingerprint
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
    .then_some(fingerprint)
}

/// `(fingerprint, contentUrl)` of each certificate of a repository signature index.
pub fn parse_signature_index(body: &[u8]) -> Result<Vec<(String, Url)>, DocError> {
    let value: Value = serde_json::from_slice(body).map_err(|_| DocError::Shape)?;
    let list = value
        .get("signingCertificates")
        .and_then(Value::as_array)
        .ok_or(DocError::Shape)?;
    if list.len() > MAX_CERTIFICATES {
        return Err(DocError::TooMany);
    }
    Ok(list
        .iter()
        .filter_map(|certificate| {
            Some((
                certificate_fingerprint(certificate)?.to_owned(),
                plain_url(certificate.get("contentUrl")?.as_str()?)?,
            ))
        })
        .collect())
}

/// The repository signature index with each `contentUrl` pointing at this firewall's route for that fingerprint.
pub fn render_signature_index(body: &[u8], root: &Url) -> Result<Vec<u8>, DocError> {
    let mut value: Value = serde_json::from_slice(body).map_err(|_| DocError::Shape)?;
    let list = value
        .get_mut("signingCertificates")
        .and_then(Value::as_array_mut)
        .ok_or(DocError::Shape)?;
    if list.len() > MAX_CERTIFICATES {
        return Err(DocError::TooMany);
    }
    list.retain(|certificate| {
        certificate_fingerprint(certificate).is_some()
            && certificate
                .get("contentUrl")
                .and_then(Value::as_str)
                .and_then(plain_url)
                .is_some()
    });
    for certificate in list.iter_mut() {
        let fingerprint = certificate_fingerprint(certificate)
            .unwrap_or_default()
            .to_owned();
        if let (Some(object), Ok(url)) = (
            certificate.as_object_mut(),
            root.join(&format!(
                "v3/repository-signatures/certificates/{fingerprint}.crt"
            )),
        ) {
            object.insert("contentUrl".to_owned(), Value::String(url.to_string()));
        }
    }
    serde_json::to_vec(&value).map_err(|_| DocError::Shape)
}
