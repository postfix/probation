//! The Windows service-key file check (row 25 fix round): a service key file whose DACL lets anyone but SYSTEM, the
//! Administrators and the account the service runs as read it is refused, like a 0644 file on Unix. The parser of the
//! security-descriptor string is platform independent so it is tested here; the Windows reader of the real DACL is compiled by
//! `cargo check --target x86_64-pc-windows-gnu` and runs only on a Windows runner.

use probation::key_acl::{allowed_for, private_violations, private_violations_resolved, service_name, service_sid, trustees_outside};

const SERVICE: &str = "S-1-5-80-1234-5678-9";

#[test]
fn only_system_administrators_and_the_service_account_are_accepted() {
    let sddl = "O:BAG:SYD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;S-1-5-80-1234-5678-9)";
    assert_eq!(trustees_outside(sddl, SERVICE), Vec::<String>::new());
}

#[test]
fn users_everyone_and_authenticated_users_are_named() {
    for (ace, name) in [("(A;;FR;;;BU)", "BU"), ("(A;;FR;;;WD)", "WD"), ("(A;;GR;;;AU)", "AU"), ("(A;OICI;FA;;;S-1-5-21-1-2-3-1001)", "S-1-5-21-1-2-3-1001")] {
        let sddl = format!("O:BAG:SYD:PAI(A;;FA;;;SY){ace}");
        assert_eq!(trustees_outside(&sddl, SERVICE), vec![name.to_owned()], "{ace}");
    }
}

#[test]
fn deny_entries_and_the_other_parts_of_the_descriptor_are_not_grants() {
    // The owner and group sit outside the DACL; a deny of Users takes nothing from the file.
    let sddl = "O:S-1-5-21-1-2-3-1001G:BUD:PAI(D;;FR;;;BU)(A;;FA;;;SY)(A;;FA;;;BA)S:(AU;SA;FA;;;WD)";
    assert_eq!(trustees_outside(sddl, SERVICE), Vec::<String>::new());
}

#[test]
fn an_object_ace_and_a_missing_dacl_fail_closed() {
    assert_eq!(trustees_outside("O:BAG:SYD:(OA;;CC;guid;guid;BU)", SERVICE), vec!["BU".to_owned()]);
    // No DACL at all means everyone has access.
    assert_eq!(trustees_outside("O:BAG:SY", SERVICE), vec!["(no DACL: everyone)".to_owned()]);
    assert_eq!(trustees_outside("garbage", SERVICE), vec!["(no DACL: everyone)".to_owned()]);
}

#[test]
fn a_null_dacl_written_as_an_empty_acl_grants_nothing() {
    assert_eq!(trustees_outside("O:BAG:SYD:P", SERVICE), Vec::<String>::new());
}

// ---- recheck 1: NULL DACL, owner, the service's own SID, inherited and deny entries
const ALLOWED: &[&str] = &["S-1-5-21-1-2-3-500", "S-1-5-80-1234-5678-9"];

#[test]
fn a_null_dacl_is_not_private() {
    for sddl in ["O:BAG:SYD:NO_ACCESS_CONTROL", "O:BAG:SYD:PNO_ACCESS_CONTROL", "O:BAG:SY"] {
        let found = private_violations(sddl, ALLOWED);
        assert_eq!(found.len(), 1, "{sddl}: {found:?}");
        assert!(found[0].contains("everyone"), "{found:?}");
    }
}

#[test]
fn the_owner_must_be_system_administrators_or_an_allowed_account() {
    assert!(private_violations("O:BAG:SYD:PAI(A;;FA;;;SY)", ALLOWED).is_empty());
    assert!(private_violations("O:SYG:SYD:PAI(A;;FA;;;SY)", ALLOWED).is_empty());
    assert!(private_violations("O:S-1-5-80-1234-5678-9G:SYD:PAI(A;;FA;;;SY)", ALLOWED).is_empty());
    assert_eq!(private_violations("O:BUG:SYD:PAI(A;;FA;;;SY)", ALLOWED), vec!["owner BU".to_owned()]);
    assert_eq!(private_violations("O:S-1-5-21-1-2-3-1001G:SYD:PAI(A;;FA;;;SY)", ALLOWED), vec!["owner S-1-5-21-1-2-3-1001".to_owned()]);
    assert_eq!(private_violations("G:SYD:PAI(A;;FA;;;SY)", ALLOWED), vec!["(no owner)".to_owned()]);
}

#[test]
fn the_services_virtual_account_sid_is_derived_from_its_name() {
    // The documented value of NT SERVICE\TrustedInstaller: SHA-1 of the upper-cased name in UTF-16LE, five little-endian words.
    assert_eq!(service_sid("TrustedInstaller"), "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");
    assert_eq!(service_sid("trustedinstaller"), service_sid("TRUSTEDINSTALLER"));
    let probation = service_sid("Probation");
    assert!(probation.starts_with("S-1-5-80-") && probation.split('-').count() == 9, "{probation}");
    // An elevated check-config (an upgrade) sees that SID in the key's DACL and accepts it.
    let sddl = format!("O:BAG:SYD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;{probation})");
    assert!(private_violations(&sddl, &["S-1-5-21-1-2-3-500", &probation]).is_empty());
    assert_eq!(private_violations(&sddl, &["S-1-5-21-1-2-3-500"]), vec![probation]);
}

#[test]
fn inherited_entries_count_like_any_other_and_a_deny_grants_nothing() {
    // ID = inherited: the flags field changes nothing about who is granted access.
    let inherited = "O:BAG:SYD:PAI(A;ID;FR;;;BU)(A;ID;FA;;;SY)";
    assert_eq!(private_violations(inherited, ALLOWED), vec!["BU".to_owned()]);
    assert!(private_violations("O:BAG:SYD:PAI(D;;FR;;;BU)(A;;FA;;;SY)(A;ID;FA;;;BA)", ALLOWED).is_empty());
}

// ---- recheck 2: the service name comes from the installer, not a constant
#[test]
fn the_allowed_accounts_are_the_process_user_and_the_named_services_virtual_account() {
    let allowed = allowed_for("S-1-5-21-1-2-3-500", "Probation-b");
    assert_eq!(allowed, vec!["S-1-5-21-1-2-3-500".to_owned(), service_sid("Probation-b")]);
    assert_ne!(service_sid("Probation-b"), service_sid("Probation"));
    // A key readable by the OTHER service's account is refused for this one.
    let sddl = format!("O:BAG:SYD:PAI(A;;FA;;;SY)(A;;FR;;;{})", service_sid("Probation"));
    let refs: Vec<&str> = allowed.iter().map(String::as_str).collect();
    assert_eq!(private_violations(&sddl, &refs), vec![service_sid("Probation")]);
}

#[test]
fn the_service_name_is_read_from_the_environment_the_installer_sets() {
    assert_eq!(service_name(None), "Probation");
    assert_eq!(service_name(Some("Probation-b".to_owned())), "Probation-b");
    assert_eq!(service_name(Some("bad name; rm".to_owned())), "Probation", "an odd value is not used");
    assert_eq!(service_name(Some(String::new())), "Probation");
}

// ---- W1: aliases are compared by SID identity (hosted run 45473729183: the runner is RID 500, printed as `LA`)
/// A stand-in for the OS resolver: well-known aliases to SIDs, `LA` to the machine's RID-500 account, anything else unknown.
fn resolve(alias: &str) -> Option<String> {
    let sid = match alias {
        "SY" => "S-1-5-18",
        "BA" => "S-1-5-32-544",
        "LA" => "S-1-5-21-1-2-3-500",
        "LG" => "S-1-5-21-1-2-3-501",
        "WD" => "S-1-1-0",
        "BU" => "S-1-5-32-545",
        "AU" => "S-1-5-11",
        sid if sid.starts_with("S-1-") => sid,
        _ => return None,
    };
    Some(sid.to_owned())
}

#[test]
fn an_alias_of_the_process_user_is_accepted_and_of_anyone_else_is_not() {
    let sddl = "O:BAG:S-1-5-21-1-2-3-513D:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;LA)";
    assert!(private_violations_resolved(sddl, &["S-1-5-21-1-2-3-500", SERVICE], &resolve).is_empty());
    // The same DACL on a machine where the process user is another account: `LA` is an outsider.
    assert_eq!(private_violations_resolved(sddl, &["S-1-5-21-1-2-3-1001", SERVICE], &resolve), vec!["LA".to_owned()]);
    // An owner written as an alias is resolved the same way.
    assert!(private_violations_resolved("O:LAG:SYD:PAI(A;;FA;;;SY)", &["S-1-5-21-1-2-3-500"], &resolve).is_empty());
    assert_eq!(private_violations_resolved("O:LGG:SYD:PAI(A;;FA;;;SY)", &["S-1-5-21-1-2-3-500"], &resolve), vec!["owner LG".to_owned()]);
}

#[test]
fn broad_groups_and_unknown_aliases_stay_rejected_when_resolved() {
    for alias in ["WD", "BU", "AU", "LG", "ZZ"] {
        let sddl = format!("O:BAG:SYD:PAI(A;;FA;;;SY)(A;;FR;;;{alias})");
        assert_eq!(private_violations_resolved(&sddl, &["S-1-5-21-1-2-3-500"], &resolve), vec![alias.to_owned()], "{alias}");
    }
}

#[test]
fn the_runner_descriptor_is_private_once_la_is_resolved_and_was_not_by_spelling() {
    let sddl = "O:BAG:S-1-5-21-3414932011-3134797172-3625386099-513D:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;LA)";
    let user = ["S-1-5-21-3414932011-3134797172-3625386099-500"];
    let spelled = |t: &str| Some(t.to_owned()); // the pre-fix comparison
    assert_eq!(private_violations_resolved(sddl, &user, &spelled), vec!["LA".to_owned()], "by spelling `LA` is an outsider (the W1 defect)");
    let os = |t: &str| Some(if t == "LA" { user[0].to_owned() } else { t.to_owned() });
    assert!(private_violations_resolved(sddl, &user, &os).is_empty());
}
