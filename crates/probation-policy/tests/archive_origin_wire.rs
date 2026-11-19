//! Row 18: `RegistryDescriptor.archive_origin` is additive and optional. A descriptor without it reads
//! as before, one without a value never writes the key, and an older reader (a struct that does not
//! know the field) reads a descriptor that carries it.

use probation_policy::Ecosystem;
use probation_policy::api::{RegistryDescriptor, RegistryId};

fn descriptor(archive_origin: Option<&str>) -> RegistryDescriptor {
    RegistryDescriptor {
        registry: RegistryId(7), ecosystem: Ecosystem::Cargo, target_url: Some("https://reg.example/index/".into()), trusted: false,
        registry_private_cidrs: vec![], deletion_scopes: vec![], osv_scope: None, archive_origin: archive_origin.map(str::to_owned),
    }
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
