//! What a Windows service leaves behind when it fails before its log sink exists (an invalid configuration, a start that cannot
//! happen, a log directory it cannot open): a documented exit code, and one small text file in the access-controlled log directory
//! that the next failure replaces, so it never grows. Platform independent; the Windows service host uses it.

use std::io::Write;
use std::path::Path;

/// The file is never larger than this.
pub const MAX_BYTES: u64 = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureKind {
    /// The configuration was refused (sysexits EX_CONFIG).
    InvalidConfig,
    /// The service could not start (EX_SOFTWARE).
    CannotStart,
    /// The log directory or file could not be used (EX_CANTCREAT).
    LogUnavailable,
}

impl FailureKind {
    /// The process exit code the service ends with, documented in docs/operations.md.
    pub fn code(self) -> u8 {
        match self {
            FailureKind::InvalidConfig => 78,
            FailureKind::CannotStart => 70,
            FailureKind::LogUnavailable => 73,
        }
    }
    fn label(self) -> &'static str {
        match self {
            FailureKind::InvalidConfig => "invalid configuration",
            FailureKind::CannotStart => "cannot start",
            FailureKind::LogUnavailable => "log unavailable",
        }
    }
}

/// Replaces `<dir>/service-failure.txt` with a bounded description of the failure.
pub fn record(dir: &Path, kind: FailureKind, message: &str) -> std::io::Result<()> {
    let mut text = format!("probation service failed: {} (exit code {})\n{}\n", kind.label(), kind.code(), message);
    if text.len() as u64 > MAX_BYTES {
        let mut cut = MAX_BYTES as usize;
        while !text.is_char_boundary(cut) {
            cut -= 1;
        }
        text.truncate(cut);
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    let mut file = crate::delivery::owner_only(&mut options).open(dir.join("service-failure.txt"))?;
    file.write_all(text.as_bytes())?;
    file.sync_all()
}
