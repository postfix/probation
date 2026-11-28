//! Row 19 fixtures shared by tests/go_modules.rs and tests/go_native.rs: a real (stored) module zip,
//! `.info` documents and the `.mod` text of the fake Go proxy.
#![allow(dead_code)]

pub fn info(version: &str, time: Option<&str>) -> String {
    match time {
        Some(time) => format!(r#"{{"Version":"{version}","Time":"{time}"}}"#),
        None => format!(r#"{{"Version":"{version}"}}"#),
    }
}

pub fn mod_text(module: &str) -> String {
    format!("module {module}\n\ngo 1.21\n")
}

pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// A stored (uncompressed) zip of `module@version/go.mod` and `module@version/{package}.go`, the layout
/// `go mod download` unpacks and verifies (every name under the `module@version/` prefix, CRC32 set).
pub fn module_zip(module: &str, version: &str, source: &str) -> Vec<u8> {
    let files = [("go.mod", mod_text(module)), ("demo.go", source.to_owned())];
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (file, text) in &files {
        let name = format!("{module}@{version}/{file}");
        let data = text.as_bytes();
        let (crc, size) = (crc32(data), data.len() as u32);
        let offset = out.len() as u32;
        out.extend_from_slice(&[0x50, 0x4b, 0x03, 0x04, 20, 0, 0, 0, 0, 0, 0, 0, 0x21, 0]);
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(data);
        central.extend_from_slice(&[
            0x50, 0x4b, 0x01, 0x02, 20, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0x21, 0,
        ]);
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
    out.extend_from_slice(&[0x50, 0x4b, 0x05, 0x06, 0, 0, 0, 0, 2, 0, 2, 0]);
    out.extend_from_slice(&(central.len() as u32).to_le_bytes());
    out.extend_from_slice(&start.to_le_bytes());
    out.extend_from_slice(&[0, 0]);
    out
}
