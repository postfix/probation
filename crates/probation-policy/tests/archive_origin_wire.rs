//! Row 18: `RegistryDescriptor.archive_origin` is additive and optional. A descriptor without it reads
//! as before, one without a value never writes the key, and an older reader (a struct that does not
//! know the field) reads a descriptor that carries it.

use probation_policy::Ecosystem;
use probation_policy::api::{RegistryDescriptor, RegistryId};

fn descriptor(archive_origin: Option<&str>) -> RegistryDescriptor {
    RegistryDescriptor {
        registry: RegistryId(7), ecosystem: Ecosystem::Cargo, target_url: Some("https://reg.example/index/".into()), trusted: false,
        registry_private_cidrs: vec![], deletion_scopes: vec![], osv_scope: None, archive_origin: archive_origin.map(str::to_owned), resource_path_prefix: None, token_origin: None,
    }
}

/// Row 20 (security review F3): `resource_path_prefix` is additive and optional in the same way.
#[test]
fn the_resource_path_prefix_is_additive_and_ignored_by_an_older_reader() {
    let mut descriptor = descriptor(None);
    descriptor.ecosystem = Ecosystem::NuGet;
    let old = serde_json::to_string(&descriptor).unwrap();
    assert!(!old.contains("resource_path_prefix"), "an absent value is not written: {old}");
    descriptor.resource_path_prefix = Some("/org-a/_packaging".into());
    let text = serde_json::to_string(&descriptor).unwrap();
    assert!(text.contains(r#""resource_path_prefix":"/org-a/_packaging""#), "{text}");
    #[derive(serde::Deserialize)]
    struct Older {
        registry: RegistryId,
        trusted: bool,
    }
    let older: Older = serde_json::from_str(&text).unwrap();
    assert_eq!((older.registry, older.trusted), (RegistryId(7), false));
    let back: RegistryDescriptor = serde_json::from_str(&text).unwrap();
    assert_eq!(back.resource_path_prefix.as_deref(), Some("/org-a/_packaging"));
    let before: RegistryDescriptor = serde_json::from_str(r#"{"registry":7,"ecosystem":"NuGet","target_url":"https://x/","trusted":false,"registry_private_cidrs":[],"deletion_scopes":[]}"#).unwrap();
    assert_eq!(before.resource_path_prefix, None);
}

#[test]
fn a_descriptor_written_before_the_field_reads_with_none_and_none_is_never_written() {
    let old = r#"{"registry":7,"ecosystem":"Cargo","target_url":"https://reg.example/index/","trusted":false,"registry_private_cidrs":[],"deletion_scopes":[]}"#;
    let read: RegistryDescriptor = serde_json::from_str(old).unwrap();
    assert_eq!(read, descriptor(None));
    assert!(!serde_json::to_string(&read).unwrap().contains("archive_origin"), "an absent value is not written");
}

#[test]
fn an_older_reader_ignores_the_field_and_the_value_round_trips() {
    let text = serde_json::to_string(&descriptor(Some("https://reg.example/crates"))).unwrap();
    assert!(text.contains(r#""archive_origin":"https://reg.example/crates""#), "{text}");
    #[derive(serde::Deserialize)]
    struct Older {
        registry: RegistryId,
        target_url: Option<String>,
        trusted: bool,
    }
    let older: Older = serde_json::from_str(&text).unwrap();
    assert_eq!((older.registry, older.target_url.as_deref(), older.trusted), (RegistryId(7), Some("https://reg.example/index/"), false));
    let back: RegistryDescriptor = serde_json::from_str(&text).unwrap();
    assert_eq!(back.archive_origin.as_deref(), Some("https://reg.example/crates"));
}

/// Row 24 (code review F5): `token_origin` is additive and optional in the same way.
#[test]
fn the_token_origin_is_additive_and_ignored_by_an_older_reader() {
    let mut descriptor = descriptor(None);
    descriptor.ecosystem = Ecosystem::Oci;
    assert!(!serde_json::to_string(&descriptor).unwrap().contains("token_origin"), "an absent value is not written");
    descriptor.token_origin = Some("https://gitlab.example".into());
    let text = serde_json::to_string(&descriptor).unwrap();
    assert!(text.contains(r#""token_origin":"https://gitlab.example""#), "{text}");
    #[derive(serde::Deserialize)]
    struct Older {
        registry: RegistryId,
    }
    assert_eq!(serde_json::from_str::<Older>(&text).unwrap().registry, RegistryId(7));
    assert_eq!(serde_json::from_str::<RegistryDescriptor>(&text).unwrap().token_origin.as_deref(), Some("https://gitlab.example"));
    let before: RegistryDescriptor = serde_json::from_str(r#"{"registry":7,"ecosystem":"Oci","target_url":"https://x/","trusted":false,"registry_private_cidrs":[],"deletion_scopes":[]}"#).unwrap();
    assert_eq!(before.token_origin, None);
}

/// Row 24 (R2): a certificate admission carries `token_origin` the same way: absent is not written and an older answer (no field) reads as none.
#[test]
fn a_certificate_admission_carries_the_token_origin_additively() {
    use probation_policy::api::{CertificateAdmission, LimitSource, MemberCertificateId, OrgId};
    use probation_policy::{LayerKind, PlaceRef};
    let place = PlaceRef { kind: LayerKind::User, id: 3 };
    let make = |token_origin: Option<&str>| CertificateAdmission::Granted {
        registry: RegistryId(4), target_url: None, read_authorization: None, trusted: false, registry_private_cidrs: vec![], deletion_scopes: vec![], enterprise_status: None,
        org: OrgId(1), member: MemberCertificateId("m".into()), place, layers: vec![], rate_limit: None, rate_limit_source: LimitSource::Default, token_origin: token_origin.map(str::to_owned),
    };
    let none = serde_json::to_string(&make(None)).unwrap();
    assert!(!none.contains("token_origin"), "an absent value is not written: {none}");
    let some = serde_json::to_string(&make(Some("https://gitlab.example"))).unwrap();
    assert!(some.contains(r#""token_origin":"https://gitlab.example""#), "{some}");
    assert_eq!(serde_json::from_str::<CertificateAdmission>(&some).unwrap(), make(Some("https://gitlab.example")));
    assert_eq!(serde_json::from_str::<CertificateAdmission>(&none).unwrap(), make(None), "an answer without the field reads as none");
}
