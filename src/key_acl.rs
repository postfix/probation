//! Who may read the service key file on Windows (row 25 fix round; `config.rs` `RawServicePolicy::validate`). Unix refuses a key
//! file with group or other mode bits; Windows has no mode bits, so the file's DACL is read as a security-descriptor string and
//! every access-allowed entry for a trustee other than SYSTEM, the Administrators and the account the service runs as is
//! named. The string parser is platform independent (tests/key_acl.rs); the reader of the real DACL is `cfg(windows)`.

/// Trustees granted access by `sddl` that are not SYSTEM, Administrators or `service_sid`. A descriptor with no DACL
/// (everyone has access) is reported as `(no DACL: everyone)`; a DACL with no entries grants nothing.
pub fn trustees_outside(sddl: &str, service_sid: &str) -> Vec<String> {
    dacl_trustees(sddl, &[service_sid])
}

const SYSTEM_TRUSTEES: [&str; 4] = ["SY", "BA", "S-1-5-18", "S-1-5-32-544"];

/// Everything that makes the key file not private: a NULL or missing DACL (everyone has access), an owner that is not SYSTEM,
/// the Administrators or one of `allowed` (the account running the service, its virtual account `NT SERVICE\Probation`), and every
/// access-allowed entry for a trustee outside those. Deny entries and inherited flags change nothing: an entry grants what it names.
pub fn private_violations(sddl: &str, allowed: &[&str]) -> Vec<String> {
    let mut found = Vec::new();
    match owner(sddl) {
        None => found.push("(no owner)".to_owned()),
        Some(owner) if !SYSTEM_TRUSTEES.contains(&owner.as_str()) && !allowed.contains(&owner.as_str()) => found.push(format!("owner {owner}")),
        Some(_) => {}
    }
    match dacl_start(sddl) {
        Some(start) if sddl[start..].split('(').next().is_some_and(|flags| flags.contains("NO_ACCESS_CONTROL")) => found.push("(NULL DACL: everyone)".to_owned()),
        Some(_) => found.extend(dacl_trustees(sddl, allowed)),
        None => found.push("(NULL DACL: everyone)".to_owned()),
    }
    found
}

fn owner(sddl: &str) -> Option<String> {
    let rest = sddl.strip_prefix("O:")?;
    let end = ["G:", "D:", "S:"].iter().filter_map(|m| rest.find(m)).min().unwrap_or(rest.len());
    let owner = &rest[..end];
    (!owner.is_empty()).then(|| owner.to_owned())
}

/// The accounts that may own and read the key: the account this process runs as and the virtual account of the service named by the
/// installer (`PROBATION_SERVICE_NAME`, set in the service's environment and for the installer's own `check-config`, which runs as an
/// administrator: Administrators are always accepted, so that check passes for a key the installer made).
pub fn allowed_for(user_sid: &str, service_name: &str) -> Vec<String> {
    vec![user_sid.to_owned(), service_sid(service_name)]
}

/// The service name from `PROBATION_SERVICE_NAME`; anything that is not a plain name falls back to the default `Probation`.
pub fn service_name(value: Option<String>) -> String {
    match value {
        Some(name) if !name.is_empty() && name.len() <= 64 && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')) => name,
        _ => "Probation".to_owned(),
    }
}

/// The SID of the virtual account `NT SERVICE\<name>`: SHA-1 of the upper-cased name in UTF-16LE, read as five little-endian words
/// under `S-1-5-80`.
pub fn service_sid(name: &str) -> String {
    use sha1::{Digest, Sha1};
    let bytes: Vec<u8> = name.to_uppercase().encode_utf16().flat_map(u16::to_le_bytes).collect();
    let digest = Sha1::digest(&bytes);
    let words: Vec<String> = digest.chunks(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]).to_string()).collect();
    format!("S-1-5-80-{}", words.join("-"))
}

fn dacl_trustees(sddl: &str, allowed_sids: &[&str]) -> Vec<String> {
    let Some(start) = dacl_start(sddl) else {
        return vec!["(no DACL: everyone)".to_owned()];
    };
    let mut outside = Vec::new();
    let (mut depth, mut ace) = (0, String::new());
    let mut rest = sddl[start..].chars().peekable();
    while let Some(c) = rest.next() {
        match c {
            '(' if depth == 0 => depth = 1,
            ')' if depth == 1 => {
                depth = 0;
                if let Some(trustee) = granted_trustee(&ace) {
                    let allowed = SYSTEM_TRUSTEES.contains(&trustee.as_str()) || allowed_sids.contains(&trustee.as_str());
                    if !allowed && !outside.contains(&trustee) {
                        outside.push(trustee);
                    }
                }
                ace.clear();
            }
            'S' if depth == 0 && rest.peek() == Some(&':') => break, // the SACL starts: not part of the DACL
            c if depth == 1 => ace.push(c),
            _ => {}
        }
    }
    outside
}

/// The byte offset just after `D:` and its flags, for the first `D:` that starts the DACL section.
fn dacl_start(sddl: &str) -> Option<usize> {
    let mut from = 0;
    while let Some(found) = sddl[from..].find("D:") {
        let after = from + found + 2;
        let flags_end = sddl[after..].find(|c: char| c == '(' || c == 'S' && sddl[after..].starts_with("S:")).map_or(sddl.len(), |n| after + n);
        let flags = &sddl[after..flags_end];
        if flags.chars().all(|c| c.is_ascii_uppercase() || c == '_') {
            return Some(after);
        }
        from = after;
    }
    None
}

/// The trustee of an access-allowed entry `type;flags;rights;object;inherit;sid`, or `None` for deny, audit and other entries.
fn granted_trustee(ace: &str) -> Option<String> {
    let fields: Vec<&str> = ace.split(';').collect();
    (fields.len() >= 6 && matches!(fields[0], "A" | "OA" | "XA" | "ZA")).then(|| fields[5].to_owned())
}

/// True when the DACL of `path` grants access beyond SYSTEM, Administrators and the current account.
#[cfg(windows)]
pub fn is_shared(path: &std::path::Path) -> bool {
    match windows_reader::descriptor_and_user(path) {
        Ok((sddl, user)) => {
            // The account running this process and the service's own virtual account (an elevated `check-config` at upgrade runs as
            // an administrator and finds the service's SID in the key's DACL).
            let allowed = allowed_for(&user, &service_name(std::env::var("PROBATION_SERVICE_NAME").ok()));
            let allowed: Vec<&str> = allowed.iter().map(String::as_str).collect();
            !private_violations(&sddl, &allowed).is_empty()
        }
        Err(_) => true, // not readable: not provably private
    }
}

#[cfg(windows)]
mod windows_reader {
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    use windows_sys::Win32::Foundation::{LocalFree, HANDLE};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW, GetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{GetTokenInformation, TokenUser, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, TOKEN_QUERY, TOKEN_USER};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    fn text(pointer: *mut u16) -> String {
        // SAFETY: `pointer` is a NUL-terminated wide string the system allocated for this call.
        let len = (0..).take_while(|&n| unsafe { *pointer.add(n) } != 0).count();
        String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(pointer, len) })
    }

    pub fn descriptor_and_user(path: &Path) -> Result<(String, String), u32> {
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        // SAFETY: plain Win32 calls with valid out-pointers; every system allocation is freed with LocalFree.
        unsafe {
            let mut descriptor = std::ptr::null_mut();
            let status = GetNamedSecurityInfoW(wide.as_ptr(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), &mut descriptor);
            if status != 0 {
                return Err(status);
            }
            let mut sddl = std::ptr::null_mut();
            let converted = ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor, SDDL_REVISION_1, DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION, &mut sddl, std::ptr::null_mut());
            let sddl_text = (converted != 0).then(|| text(sddl));
            LocalFree(sddl.cast());
            LocalFree(descriptor);
            let sddl_text = sddl_text.ok_or(1u32)?;

            let mut token: HANDLE = std::ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return Err(2);
            }
            let mut needed = 0u32;
            GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed);
            let mut buffer = vec![0u8; needed as usize];
            let got = GetTokenInformation(token, TokenUser, buffer.as_mut_ptr().cast(), needed, &mut needed);
            if got == 0 {
                return Err(3);
            }
            // The byte buffer has no alignment guarantee: read the struct out of it unaligned.
            let user = std::ptr::read_unaligned(buffer.as_ptr().cast::<TOKEN_USER>());
            let mut sid_text = std::ptr::null_mut();
            if ConvertSidToStringSidW(user.User.Sid, &mut sid_text) == 0 {
                return Err(4);
            }
            let sid = text(sid_text);
            LocalFree(sid_text.cast());
            Ok((sddl_text, sid))
        }
    }
}
