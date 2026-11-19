//! Row 20 fixtures shared by tests/nuget_registry.rs, tests/nuget_native.rs and the service tests: a fake
//! registry's service index, flat container index, registration pages and leaves, and a real (stored)
//! `.nupkg` zip a `dotnet restore` unpacks.
#![allow(dead_code)]

use serde_json::{Value, json};

pub const INDEX_ORIGIN: &str = "https://nuget-index.invalid";
pub const SEARCH_ORIGIN: &str = "https://nuget-search.invalid";
pub const PUBLISH_ORIGIN: &str = "https://nuget-publish.invalid";
pub const FLAT: &str = "/v3-flatcontainer/";
pub const REG: &str = "/v3/registration5-gz-semver2/";

/// A service index the way api.nuget.org writes one (several types per URL, a secondary search host, and the
/// resources this firewall does not serve), plus whatever extra `(type, url)` entries a test adds.
pub fn service_index(extra: &[(&str, &str)]) -> String {
    let mut resources = vec![
        json!({"@id": format!("{SEARCH_ORIGIN}/query"), "@type": "SearchQueryService"}),
        json!({"@id": "https://secondary.invalid/query", "@type": "SearchQueryService"}),
        json!({"@id": format!("{SEARCH_ORIGIN}/query"), "@type": "SearchQueryService/3.5.0"}),
        json!({"@id": format!("{SEARCH_ORIGIN}/autocomplete"), "@type": "SearchAutocompleteService"}),
        json!({"@id": format!("{INDEX_ORIGIN}/v3/registration5-semver1/"), "@type": "RegistrationsBaseUrl"}),
        json!({"@id": format!("{INDEX_ORIGIN}{REG}"), "@type": "RegistrationsBaseUrl/3.6.0"}),
        json!({"@id": format!("{INDEX_ORIGIN}{REG}"), "@type": "RegistrationsBaseUrl/Versioned"}),
        json!({"@id": format!("{INDEX_ORIGIN}{FLAT}"), "@type": "PackageBaseAddress/3.0.0"}),
        json!({"@id": format!("{PUBLISH_ORIGIN}/api/v2/package"), "@type": "PackagePublish/2.0.0"}),
        json!({"@id": format!("{PUBLISH_ORIGIN}/api/v2/symbolpackage"), "@type": "SymbolPackagePublish/4.9.0"}),
        json!({"@id": format!("{INDEX_ORIGIN}/v3-index/repository-signatures/5.0.0/index.json"), "@type": "RepositorySignatures/5.0.0"}),
        json!({"@id": format!("{INDEX_ORIGIN}/v3/vulnerabilities/index.json"), "@type": "VulnerabilityInfo/6.7.0"}),
        json!({"@id": format!("{INDEX_ORIGIN}{FLAT}{{lower_id}}/{{lower_version}}/readme"), "@type": "ReadmeUriTemplate/6.13.0"}),
        // Resources the firewall does not serve.
        json!({"@id": "https://www.nuget.org/api/v2", "@type": "LegacyGallery"}),
        json!({"@id": format!("{INDEX_ORIGIN}/v3/catalog0/index.json"), "@type": "Catalog/3.0.0"}),
        json!({"@id": "https://www.nuget.org/packages/{id}/{version}/ReportAbuse", "@type": "ReportAbuseUriTemplate/3.0.0-rc"}),
    ];
    for (kind, url) in extra {
        resources.push(json!({"@id": url, "@type": kind}));
    }
    json!({"version": "3.0.0", "resources": resources}).to_string()
}

pub fn flat_index(versions: &[&str]) -> String {
    json!({"versions": versions}).to_string()
}

/// One leaf of a registration page, as nuget.org writes it (`catalogEntry` an object).
pub fn leaf(id: &str, version: &str, published: Option<&str>, listed: bool) -> Value {
    let lower = version.to_ascii_lowercase();
    let mut entry = json!({
        "@id": format!("{INDEX_ORIGIN}/v3/catalog0/data/2024.01.01.00.00.00/{id}.{lower}.json"),
        "@type": "PackageDetails",
        "authors": "someone",
        "id": id,
        "version": version,
        "listed": listed,
        "packageContent": format!("{INDEX_ORIGIN}{FLAT}{id}/{lower}/{id}.{lower}.nupkg"),
        "iconUrl": format!("{INDEX_ORIGIN}{FLAT}{id}/{lower}/icon"),
        "licenseUrl": "https://licenses.invalid/mit",
        // The fields a nuget.org catalog entry carries beyond the ones above (shape from api.nuget.org's registration
        // leaves, written from memory: no network in this lab); `readmeUrl` names the flat container's own readme.
        "readmeUrl": format!("{INDEX_ORIGIN}{FLAT}{id}/{lower}/readme"),
        "projectUrl": "https://project.invalid/home",
        "licenseExpression": "MIT",
        "isPrerelease": version.contains('-'),
        "requireLicenseAcceptance": false,
        "summary": "",
        "tags": ["a", "b"],
        "title": "",
        "copyright": "",
        "language": "",
        "minClientVersion": "",
        "dependencyGroups": [{"@id": "urn:x", "@type": "PackageDependencyGroup", "targetFramework": ".NETStandard2.0"}],
    });
    if let Some(published) = published {
        entry["published"] = json!(published);
    }
    json!({
        "@id": format!("{INDEX_ORIGIN}{REG}{id}/{lower}.json"),
        "@type": "Package",
        "commitId": "c1",
        "commitTimeStamp": "2024-01-01T00:00:00+00:00",
        "catalogEntry": entry,
        "packageContent": format!("{INDEX_ORIGIN}{FLAT}{id}/{lower}/{id}.{lower}.nupkg"),
        "registration": format!("{INDEX_ORIGIN}{REG}{id}/index.json"),
    })
}

/// A registration index of `pages` (each a list of leaves). Inline pages carry their leaves; `linked`
/// pages are written as links and returned as `(path, document)` to be served separately.
pub fn registration(id: &str, pages: &[Vec<Value>], linked: &[usize]) -> (String, Vec<(String, String)>) {
    let mut separate = Vec::new();
    let mut items = Vec::new();
    for (n, page) in pages.iter().enumerate() {
        let lower = page.first().and_then(|l| l["catalogEntry"]["version"].as_str()).unwrap_or("0").to_ascii_lowercase();
        let upper = page.last().and_then(|l| l["catalogEntry"]["version"].as_str()).unwrap_or("0").to_ascii_lowercase();
        let page_url = format!("{INDEX_ORIGIN}{REG}{id}/page/{lower}/{upper}.json");
        let mut object = json!({"@id": page_url, "@type": "catalog:CatalogPage", "count": page.len(), "lower": lower, "upper": upper});
        if linked.contains(&n) {
            let document = json!({"@id": page_url, "@type": "catalog:CatalogPage", "count": page.len(), "lower": lower, "upper": upper, "parent": format!("{INDEX_ORIGIN}{REG}{id}/index.json"), "items": page});
            separate.push((format!("{REG}{id}/page/{lower}/{upper}.json"), document.to_string()));
        } else {
            object["items"] = json!(page);
        }
        items.push(object);
    }
    let index = json!({
        "@id": format!("{INDEX_ORIGIN}{REG}{id}/index.json"),
        "@type": ["catalog:CatalogRoot", "PackageRegistration", "catalog:Permalink"],
        "commitId": "c1", "commitTimeStamp": "2024-01-01T00:00:00+00:00",
        "count": pages.len(), "items": items,
    });
    (index.to_string(), separate)
}

pub fn nuspec(id: &str, version: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?><package xmlns=\"http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd\"><metadata><id>{id}</id><version>{version}</version><authors>x</authors><description>d</description><dependencies><group targetFramework=\".NETStandard2.0\" /></dependencies></metadata></package>"
    )
}

/// A stored (uncompressed) zip with the entries a NuGet package needs, CRC32 set.
pub fn nupkg(id: &str, version: &str) -> Vec<u8> {
    let files: Vec<(String, Vec<u8>)> = vec![
        ("[Content_Types].xml".to_owned(), br#"<?xml version="1.0" encoding="utf-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml" /><Default Extension="nuspec" ContentType="application/octet" /><Default Extension="dll" ContentType="application/octet" /><Default Extension="psmdcp" ContentType="application/vnd.openxmlformats-package.core-properties+xml" /></Types>"#.to_vec()),
        ("_rels/.rels".to_owned(), format!(r#"<?xml version="1.0" encoding="utf-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Type="http://schemas.microsoft.com/packaging/2010/07/manifest" Target="/{id}.nuspec" Id="R1" /></Relationships>"#).into_bytes()),
        (format!("{id}.nuspec"), nuspec(id, version).into_bytes()),
        (format!("lib/netstandard2.0/{id}.dll"), format!("not a real assembly: {id} {version}").into_bytes()),
    ];
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, data) in &files {
        let (crc, size) = (super::go::crc32(data), data.len() as u32);
        let offset = out.len() as u32;
        out.extend_from_slice(&[0x50, 0x4b, 0x03, 0x04, 20, 0, 0, 0, 0, 0, 0, 0, 0x21, 0]);
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(data);
        central.extend_from_slice(&[0x50, 0x4b, 0x01, 0x02, 20, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0x21, 0]);
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&(name.len() as u16).to_le_bytes());
        central.extend_from_slice(&[0; 12]);
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name.as_bytes());
    }
    let start = out.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(&[0x50, 0x4b, 0x05, 0x06, 0, 0, 0, 0]);
    out.extend_from_slice(&(files.len() as u16).to_le_bytes());
    out.extend_from_slice(&(files.len() as u16).to_le_bytes());
    out.extend_from_slice(&(central.len() as u32).to_le_bytes());
    out.extend_from_slice(&start.to_le_bytes());
    out.extend_from_slice(&[0, 0]);
    out
}
